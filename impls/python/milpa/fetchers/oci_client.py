"""OciRegistryClient — the native OCI Distribution v2 pull client (slice S5).

RFC: docs/rfc-native-oci-fetch.md §3.2 (client design), §3.6 (token cache),
§3.7/§4 (canned-transport fixture + unit test matrix).

This module is the generic OCI Distribution client layer described in the
RFC as two deep modules plus a pure policy function:

  - ``OciRegistryClient`` — registry-/artifact-agnostic: token acquisition
    (RFC-7235 Bearer challenge), manifest fetch + digest verification +
    manifest-list rejection, blob fetch + streaming cap + digest
    verification.  Generic OCI hygiene lives HERE.
  - ``select_source_layer`` — milpa's own artifact-shape policy, a PURE
    function over a parsed ``Manifest``.  The ONE place the "exactly one
    milpa source-tarball layer" predicate lives.
  - ``tokenize_www_authenticate`` / ``select_bearer_challenge`` — the
    RFC-7235 challenge tokenizer, a pure function tested exhaustively on
    its own.
  - ``TokenCache`` — per-``(registry, scope)`` striped-lock cache with
    expiry and explicit invalidation (RFC §3.6).

This IS wired in as ``OciFetcher``'s default transport (slice S6,
``milpa.fetchers.oci``) — ``OciPull``/``make_oras_pull`` and the redundant
filename-suffix tarball scan have been deleted from that module.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import threading
import time
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol

from milpa.bounded_http import HttpResponse
from milpa.errors import (
    FETCH_DOWNLOAD_FAILED,
    FETCH_OCI_AMBIGUOUS_TARBALL,
    FETCH_OCI_DIGEST_MISMATCH,
    FETCH_OCI_NO_TARBALL,
    FETCH_OCI_PULL_FAILED,
    MilpaError,
)
from milpa.fetchers.tarball import MAX_COMPRESSED_BYTES, sha256_of_file

# ---------------------------------------------------------------------------
# Constants — the fixed milpa OCI artifact shape (RFC §1, §3.2 step 3)
# ---------------------------------------------------------------------------

#: Small fixed cap for token + manifest responses (RFC §3.2 step 1/2) — these
#: are always small JSON documents; never an unbounded stream.
TOKEN_OR_MANIFEST_CAP: int = 1 << 20  # 1 MiB

#: The one artifactType milpa publishes (defense-in-depth check in
#: ``select_source_layer`` — milpa fully owns this format).
SOURCE_ARTIFACT_TYPE: str = "application/vnd.milpa.source.v1"

#: The one config mediaType milpa publishes — an empty descriptor.
EMPTY_CONFIG_MEDIA_TYPE: str = "application/vnd.oci.empty.v1+json"

#: The one layer mediaType that carries the actual source tarball.
SOURCE_LAYER_MEDIA_TYPE: str = "application/vnd.milpa.source.v1.tar+gzip"

#: ``Accept`` header sent on the manifest GET — the OCI + docker manifest set
#: (RFC §3.2 step 2).
MANIFEST_ACCEPT: str = ", ".join(
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)


# ---------------------------------------------------------------------------
# Transport seam — a Protocol alias for bounded_http.request's shape
# ---------------------------------------------------------------------------


class OciHttpTransport(Protocol):
    """The minimal transport ``OciRegistryClient`` depends on.

    This is a **structural alias** for ``bounded_http.request``'s signature
    (RFC §3.2: "``OciHttpTransport`` is a local alias for bounded_http's
    transport type ... not a distinct OCI-only transport").  Production
    code passes ``bounded_http.request`` directly — it already satisfies
    this Protocol, so no adapter class is needed.  Tests pass a fixture-
    replaying fake with the same shape.
    """

    def __call__(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        cap: int,
        sink: BinaryIO | Path,
        timeout: float = ...,
    ) -> HttpResponse: ...


# ---------------------------------------------------------------------------
# Parsed manifest shape
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Layer:
    """One layer descriptor from a parsed OCI manifest."""

    media_type: str
    digest: str
    size: int


@dataclass(frozen=True)
class Manifest:
    """A parsed, generically-validated OCI manifest (single-manifest shape).

    ``manifest()`` never returns this for a manifest **list**/index — that
    shape is rejected before construction (RFC §3.2 step 3).
    """

    media_type: str
    artifact_type: str | None
    layers: tuple[Layer, ...]
    config_media_type: str | None = None


# ---------------------------------------------------------------------------
# WWW-Authenticate tokenizer (RFC §3.2 step 1) — pure, fail-closed
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthChallenge:
    """One parsed challenge from an RFC-7235 ``WWW-Authenticate`` header."""

    scheme: str
    params: Mapping[str, str]


def _split_top_level_commas(header: str) -> list[str]:
    """Split ``header`` on commas that are NOT inside a quoted string.

    Handles ``\\"``-escapes inside quotes so a comma embedded in a quoted
    param value (or an escaped quote) never splits a challenge/param in two.
    """
    segments: list[str] = []
    buf: list[str] = []
    in_quotes = False
    i = 0
    n = len(header)
    while i < n:
        ch = header[i]
        if in_quotes:
            if ch == "\\" and i + 1 < n:
                buf.append(ch)
                buf.append(header[i + 1])
                i += 2
                continue
            if ch == '"':
                in_quotes = False
            buf.append(ch)
            i += 1
            continue
        if ch == '"':
            in_quotes = True
            buf.append(ch)
            i += 1
            continue
        if ch == ",":
            segments.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return segments


#: Matches a bare scheme token, optionally followed by whitespace + more text
#: (that "more text" is the challenge's first inline param when present).
_SCHEME_START_RE = re.compile(r"^([A-Za-z][A-Za-z0-9._-]*)(?:\s+(.*))?$")

#: Matches one ``key=value`` param, value either a quoted string (with
#: possible ``\"``/``\\`` escapes) or an unquoted token.
_PARAM_RE = re.compile(r'^([A-Za-z][A-Za-z0-9._-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))$')


def _unescape_quoted(raw: str) -> str:
    out: list[str] = []
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if ch == "\\" and i + 1 < n:
            out.append(raw[i + 1])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _parse_param(text: str) -> tuple[str, str] | None:
    m = _PARAM_RE.match(text.strip())
    if not m:
        return None
    key = m.group(1)
    if m.group(2) is not None:
        return key, _unescape_quoted(m.group(2))
    return key, m.group(3)


def tokenize_www_authenticate(header: str) -> list[AuthChallenge]:
    """Parse an RFC-7235 ``WWW-Authenticate`` header into ordered challenges.

    Handles multiple challenges in one header (``Basic realm="x", Bearer
    realm="y",service="z"``), unordered/quoted params, ``\\"``-escapes, and
    commas embedded inside quoted values.  A segment is a NEW challenge iff
    it starts with a bare scheme token (no ``=`` immediately after it);
    anything else is a continuation param of the current challenge.  A
    malformed leading param with no preceding scheme is dropped — the
    caller (``select_bearer_challenge``) fails closed downstream rather than
    this function guessing.
    """
    segments = [s.strip() for s in _split_top_level_commas(header)]
    challenges: list[AuthChallenge] = []
    current_scheme: str | None = None
    current_params: dict[str, str] = {}

    def flush() -> None:
        nonlocal current_scheme, current_params
        if current_scheme is not None:
            challenges.append(AuthChallenge(scheme=current_scheme, params=dict(current_params)))
        current_scheme = None
        current_params = {}

    for seg in segments:
        if not seg:
            continue
        m = _SCHEME_START_RE.match(seg)
        starts_new_scheme = m is not None and (m.group(2) is None or "=" in m.group(2))
        if starts_new_scheme and m is not None:
            flush()
            current_scheme = m.group(1)
            rest = m.group(2)
            if rest:
                parsed = _parse_param(rest)
                if parsed:
                    current_params[parsed[0]] = parsed[1]
            continue
        if current_scheme is None:
            # A param with no preceding scheme token — malformed header.
            # Dropped; downstream "no Bearer challenge" / "missing realm"
            # checks fail closed rather than this function guessing intent.
            continue
        parsed = _parse_param(seg)
        if parsed:
            current_params[parsed[0]] = parsed[1]
    flush()
    return challenges


def select_bearer_challenge(challenges: Sequence[AuthChallenge]) -> AuthChallenge:
    """Return the ``Bearer`` challenge, or fail closed with a distinguishable error.

    Never runs Bearer logic against a ``Basic`` (or other non-Bearer)
    challenge's params — a self-hosted ``Basic``-only registry is
    out of scope for v1 (RFC §2) and must fail cleanly, not silently
    misbehave.
    """
    for challenge in challenges:
        if challenge.scheme.lower() == "bearer":
            return challenge
    raise MilpaError(
        FETCH_OCI_PULL_FAILED,
        "registry advertised no Bearer challenge in WWW-Authenticate "
        f"(unsupported auth scheme; got {[c.scheme for c in challenges]!r})",
        phase="token",
    )


# ---------------------------------------------------------------------------
# select_source_layer — milpa's artifact policy, the ONE tarball gate
# ---------------------------------------------------------------------------


def select_source_layer(manifest: Manifest) -> Layer:
    """Select the single milpa source-tarball layer from a parsed ``Manifest``.

    Requires (RFC §3.2 step 3):
      - single-manifest shape (already enforced by ``OciRegistryClient.manifest``
        rejecting a manifest list before this is ever called);
      - ``artifactType`` is either absent or exactly ``SOURCE_ARTIFACT_TYPE``
        (defense-in-depth on a format milpa fully owns);
      - the config descriptor's mediaType is either absent or exactly the
        empty-config media type (same rationale);
      - exactly one layer of ``SOURCE_LAYER_MEDIA_TYPE``.

    An artifactType/config mismatch is treated as "no [valid milpa] tarball
    present" rather than a separate error code — there is no dedicated slug
    for a shape mismatch, and semantically it IS the no-tarball case.

    Raises:
        MilpaError(FETCH_OCI_NO_TARBALL): zero matching layers (incl. a
            wrong artifactType/config shape).
        MilpaError(FETCH_OCI_AMBIGUOUS_TARBALL): more than one matching layer.
    """
    artifact_type_ok = (
        manifest.artifact_type is None or manifest.artifact_type == SOURCE_ARTIFACT_TYPE
    )
    config_ok = (
        manifest.config_media_type is None or manifest.config_media_type == EMPTY_CONFIG_MEDIA_TYPE
    )
    shape_ok = artifact_type_ok and config_ok
    tarballs = (
        [layer for layer in manifest.layers if layer.media_type == SOURCE_LAYER_MEDIA_TYPE]
        if shape_ok
        else []
    )
    if not tarballs:
        raise MilpaError(
            FETCH_OCI_NO_TARBALL,
            "OCI artifact contained no milpa source-tarball layer "
            f"(artifactType={manifest.artifact_type!r}, "
            f"configMediaType={manifest.config_media_type!r}, "
            f"layers={[layer.media_type for layer in manifest.layers]!r})",
            artifact_type=manifest.artifact_type,
            config_media_type=manifest.config_media_type,
        )
    if len(tarballs) > 1:
        raise MilpaError(
            FETCH_OCI_AMBIGUOUS_TARBALL,
            f"OCI artifact has {len(tarballs)} milpa source-tarball layers; ambiguous",
            count=len(tarballs),
        )
    return tarballs[0]


# ---------------------------------------------------------------------------
# TokenCache — per-(registry, scope) striped locking, expiry, invalidation
# ---------------------------------------------------------------------------

#: A token fetcher: returns ``(token, expires_in_seconds | None)``.
TokenFetch = Callable[[], "tuple[str, float | None]"]


@dataclass
class _CachedToken:
    value: str
    expires_at: float | None  # a ``_clock()`` timestamp; None = no expiry given


class TokenCache:
    """Per-``(registry, scope)`` token cache with striped locking (RFC §3.6).

    Lock granularity is per-key, not one coarse mutex: concurrent misses on
    DIFFERENT keys proceed in parallel; concurrent misses on the SAME key
    coalesce into exactly one fetch (double-checked locking under a
    short-held outer lock that only guards get-or-create of the per-key
    lock, never the HTTP round-trip itself).

    Expiry is respected (an expired entry reads as a miss); callers that
    observe a 401 from a live request MUST call ``invalidate()`` before
    retrying — a token can be rejected by the registry before its
    self-reported ``expires_in`` elapses, and the cache has no way to know
    that on its own.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._entries: dict[tuple[str, str], _CachedToken] = {}
        self._entries_lock = threading.Lock()
        self._key_locks: dict[tuple[str, str], threading.Lock] = {}
        self._key_locks_lock = threading.Lock()

    def _lock_for(self, key: tuple[str, str]) -> threading.Lock:
        with self._key_locks_lock:
            lock = self._key_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[key] = lock
            return lock

    def _peek(self, key: tuple[str, str]) -> str | None:
        with self._entries_lock:
            entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expires_at is not None and self._clock() >= entry.expires_at:
            return None
        return entry.value

    def get_or_fetch(self, key: tuple[str, str], fetch: TokenFetch) -> str:
        """Return the cached token for ``key``, fetching on a miss or expiry.

        ``fetch()`` is called at most once per miss even under concurrent
        callers on the same ``key`` (double-checked locking).
        """
        cached = self._peek(key)
        if cached is not None:
            return cached
        lock = self._lock_for(key)
        with lock:
            cached = self._peek(key)
            if cached is not None:
                return cached
            token, expires_in = fetch()
            expires_at = None if expires_in is None else self._clock() + expires_in
            with self._entries_lock:
                self._entries[key] = _CachedToken(value=token, expires_at=expires_at)
            return token

    def invalidate(self, key: tuple[str, str]) -> None:
        """Drop the cached entry for ``key``, forcing the next ``get_or_fetch`` to refetch."""
        with self._entries_lock:
            self._entries.pop(key, None)


# ---------------------------------------------------------------------------
# OciRegistryClient — token / manifest / blob
# ---------------------------------------------------------------------------


def _scope_for(repository: str) -> str:
    """The pull scope string for a repository — single source of truth.

    Used identically by ``token()`` (to request the scope) and by the
    401-invalidate-and-refetch path (to invalidate the right cache key).
    """
    return f"repository:{repository}:pull"


class OciRegistryClient:
    """Generic OCI Distribution v2 client: token → manifest → blob.

    Registry-/artifact-agnostic — milpa's own artifact-shape policy lives
    in ``select_source_layer``, not here (RFC §3.2).  One instance is
    intended to live for one resolve (the ``TokenCache`` is a field, not a
    global, RFC §3.6).
    """

    def __init__(self, http: OciHttpTransport, token_cache: TokenCache) -> None:
        self._http = http
        self._token_cache = token_cache

    # -- token -----------------------------------------------------------

    def token(self, registry: str, repository: str, *, scheme: str = "https") -> str:
        """Acquire (or reuse a cached) Bearer token for ``repository`` pulls.

        Anonymous — no credentials are sent on the challenge GET; ghcr and
        similar registries still require a token exchange for public pulls.
        Cached per ``(registry, scope)`` for the life of this client.
        """
        scope = _scope_for(repository)
        key = (registry, scope)

        def _fetch() -> tuple[str, float | None]:
            return self._acquire_token(registry, repository, scope, scheme)

        return self._token_cache.get_or_fetch(key, _fetch)

    def _acquire_token(
        self, registry: str, repository: str, scope: str, scheme: str
    ) -> tuple[str, float | None]:
        challenge_url = f"{scheme}://{registry}/v2/"
        sink = io.BytesIO()
        # M1 phase-wrap: routed through the same `_transport_request` helper
        # `manifest()`/`blob()` use (via `_get_with_auth_retry`) — single
        # source of truth for "raw FETCH_DOWNLOAD_FAILED -> FETCH_OCI_PULL_FAILED
        # phase=<phase>" (audit-for-duplication; this call site previously
        # duplicated the try/except inline).
        resp = self._transport_request(
            challenge_url,
            headers={},
            cap=TOKEN_OR_MANIFEST_CAP,
            sink=sink,
            registry=registry,
            repository=repository,
            phase="token",
        )
        www_auth = resp.headers.get("WWW-Authenticate")
        if not www_auth:
            raise MilpaError(
                FETCH_OCI_PULL_FAILED,
                f"registry {registry!r} did not present a WWW-Authenticate "
                f"challenge (status {resp.status})",
                phase="token",
                registry=registry,
                status=resp.status,
            )
        challenges = tokenize_www_authenticate(www_auth)
        bearer = select_bearer_challenge(challenges)
        realm = bearer.params.get("realm")
        service = bearer.params.get("service")
        if not realm or not service:
            raise MilpaError(
                FETCH_OCI_PULL_FAILED,
                f"Bearer challenge missing realm or service (params={dict(bearer.params)!r})",
                phase="token",
                registry=registry,
            )
        # C1 (confirmed critical finding): ``realm`` is attacker-controlled —
        # it comes straight from the registry's ``WWW-Authenticate`` header,
        # and a hostile/MITM registry can put anything in it. Without this
        # check, ``token_url`` below is built directly from ``realm`` and
        # handed to the transport: a ``file://`` realm is a local-file-read
        # primitive, an ``ftp://``/internal-``http://`` realm an SSRF /
        # credential-exfiltration primitive. Validate BEFORE building
        # ``token_url`` — never forward an unvalidated scheme into the next
        # request (RFC §3.2 step 1's "fail closed" contract already applies
        # this discipline to a missing/malformed realm; this is the same
        # discipline applied to a well-formed-but-hostile one).
        realm_scheme = urllib.parse.urlsplit(realm).scheme
        if realm_scheme not in ("http", "https"):
            raise MilpaError(
                FETCH_OCI_PULL_FAILED,
                f"Bearer challenge realm has unsupported scheme {realm_scheme!r} "
                f"(realm={realm!r}); only http/https are permitted",
                phase="token",
                registry=registry,
            )
        query = urllib.parse.urlencode({"scope": scope, "service": service})
        token_url = f"{realm}?{query}"
        token_sink = io.BytesIO()
        token_resp = self._transport_request(
            token_url,
            headers={},
            cap=TOKEN_OR_MANIFEST_CAP,
            sink=token_sink,
            registry=registry,
            repository=repository,
            phase="token",
        )
        if token_resp.status != 200:
            raise MilpaError(
                FETCH_OCI_PULL_FAILED,
                f"token endpoint returned status {token_resp.status}",
                phase="token",
                registry=registry,
                status=token_resp.status,
            )
        try:
            payload = json.loads(token_sink.getvalue())
        except json.JSONDecodeError as exc:
            raise MilpaError(
                FETCH_OCI_PULL_FAILED,
                f"token response was not valid JSON: {exc}",
                phase="token",
                registry=registry,
            ) from exc
        token = payload.get("token") or payload.get("access_token")
        if not token:
            raise MilpaError(
                FETCH_OCI_PULL_FAILED,
                "token response had neither 'token' nor 'access_token'",
                phase="token",
                registry=registry,
            )
        expires_in_raw = payload.get("expires_in")
        expires_in = float(expires_in_raw) if isinstance(expires_in_raw, int | float) else None
        return token, expires_in

    # -- shared 401-invalidate-and-refetch-once retry ---------------------

    def _get_with_auth_retry(
        self,
        *,
        registry: str,
        repository: str,
        url: str,
        base_headers: Mapping[str, str],
        cap: int,
        sink_factory: Callable[[], BinaryIO | Path],
        token: str,
        phase: str,
        scheme: str = "https",
    ) -> tuple[HttpResponse, BinaryIO | Path]:
        """GET ``url`` with a Bearer token, retrying once on a 401.

        A 401 invalidates the cached token for this ``(registry, scope)``
        and reacquires one (ignoring the possibly-stale ``token`` the
        caller passed in) before the single retry — this is how an
        expired-mid-resolve token self-heals transparently instead of
        surfacing an opaque auth failure (RFC §3.6).

        ``scheme`` is the scheme the caller's ``url`` was built with
        (``manifest()``/``blob()`` forward their own ``scheme``) and MUST be
        threaded into the retry's token reacquisition — reacquiring over a
        different scheme than the original request could contact a
        registry endpoint that doesn't even serve that scheme (mirrors
        Rust's ``get_with_auth_retry``, which already threads ``scheme``
        into its retry token call).

        ``phase`` (``"manifest"`` or ``"blob"``) tags a raw transport
        failure (DNS/reset/timeout — ``bounded_http.request``'s bare
        ``FETCH_DOWNLOAD_FAILED``) with this call's phase context before
        re-raising as ``FETCH_OCI_PULL_FAILED`` (M1); a status-driven or
        digest-mismatch raise the caller makes afterward is untouched.
        """
        scope = _scope_for(repository)
        current_token = token
        sink = sink_factory()
        headers = {**base_headers, "Authorization": f"Bearer {current_token}"}
        resp = self._transport_request(
            url, headers=headers, cap=cap, sink=sink, registry=registry, repository=repository, phase=phase
        )
        if resp.status != 401:
            return resp, sink
        self._token_cache.invalidate((registry, scope))
        current_token = self.token(registry, repository, scheme=scheme)
        sink = sink_factory()
        headers = {**base_headers, "Authorization": f"Bearer {current_token}"}
        resp = self._transport_request(
            url, headers=headers, cap=cap, sink=sink, registry=registry, repository=repository, phase=phase
        )
        return resp, sink

    def _transport_request(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        cap: int,
        sink: BinaryIO | Path,
        registry: str,
        repository: str,
        phase: str,
    ) -> HttpResponse:
        try:
            return self._http("GET", url, headers=headers, cap=cap, sink=sink)
        except MilpaError as exc:
            if exc.slug != FETCH_DOWNLOAD_FAILED:
                raise
            raise MilpaError(
                FETCH_OCI_PULL_FAILED,
                f"{phase} request to {url!r} failed: {exc}",
                phase=phase,
                registry=registry,
                repository=repository,
            ) from exc

    # -- manifest ----------------------------------------------------------

    def manifest(
        self, registry: str, repository: str, digest: str, token: str, *, scheme: str = "https"
    ) -> Manifest:
        """Fetch + verify + parse the manifest at ``digest``.

        Verifies ``sha256(bytes) == digest`` BEFORE parsing (fetch is
        digest-pinned).  Rejects a manifest **list**/index outright — never
        an uncaught ``layers[0]`` ``KeyError``.
        """
        url = f"{scheme}://{registry}/v2/{repository}/manifests/{digest}"
        resp, sink = self._get_with_auth_retry(
            registry=registry,
            repository=repository,
            url=url,
            base_headers={"Accept": MANIFEST_ACCEPT},
            cap=TOKEN_OR_MANIFEST_CAP,
            sink_factory=io.BytesIO,
            token=token,
            phase="manifest",
            scheme=scheme,
        )
        if resp.status != 200:
            raise MilpaError(
                FETCH_OCI_PULL_FAILED,
                f"manifest fetch for {digest!r} returned status {resp.status}",
                phase="manifest",
                registry=registry,
                repository=repository,
                digest=digest,
                status=resp.status,
            )
        assert isinstance(sink, io.BytesIO)
        body = sink.getvalue()
        actual_digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
        if actual_digest != digest:
            raise MilpaError(
                FETCH_OCI_DIGEST_MISMATCH,
                f"manifest digest mismatch: expected {digest!r}, got {actual_digest!r}",
                phase="manifest",
                expected=digest,
                actual=actual_digest,
            )
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise MilpaError(
                FETCH_OCI_PULL_FAILED,
                f"manifest body was not valid JSON: {exc}",
                phase="manifest",
                registry=registry,
                repository=repository,
                digest=digest,
            ) from exc
        if not isinstance(payload, dict):
            raise MilpaError(
                FETCH_OCI_PULL_FAILED,
                f"manifest body was not a JSON object (got {type(payload).__name__})",
                phase="manifest",
                registry=registry,
                repository=repository,
                digest=digest,
            )
        if "manifests" in payload and "layers" not in payload:
            raise MilpaError(
                FETCH_OCI_PULL_FAILED,
                "registry returned a manifest list/index, not a single manifest",
                phase="manifest",
                registry=registry,
                repository=repository,
                digest=digest,
            )
        layers = tuple(
            Layer(
                media_type=entry.get("mediaType", ""),
                digest=entry.get("digest", ""),
                size=entry.get("size", 0),
            )
            for entry in payload.get("layers", [])
        )
        config = payload.get("config") or {}
        return Manifest(
            media_type=payload.get("mediaType", ""),
            artifact_type=payload.get("artifactType"),
            config_media_type=config.get("mediaType"),
            layers=layers,
        )

    # -- blob ----------------------------------------------------------

    def blob(
        self,
        registry: str,
        repository: str,
        digest: str,
        size: int | None,
        token: str,
        *,
        dest: Path,
        scheme: str = "https",
    ) -> None:
        """Fetch ``digest`` into ``dest``, verifying its sha256 internally.

        ``size`` (when present AND positive) only tightens the cap via
        ``min(size, MAX_COMPRESSED_BYTES)`` to fail fast on an oversized
        declared size; absent/zero/negative falls back to the fixed cap
        alone (a publish-side ``size: 0`` bug must not reject a legitimate
        pull).  The fixed ceiling always applies regardless — a lying-small
        ``size`` cannot smuggle more bytes past it, and the SOLE way this
        method returns successfully is after the digest check below passes;
        no caller can forget it.
        """
        if isinstance(size, int) and size > 0:
            cap = min(size, MAX_COMPRESSED_BYTES)
        else:
            cap = MAX_COMPRESSED_BYTES
        url = f"{scheme}://{registry}/v2/{repository}/blobs/{digest}"
        resp, sink = self._get_with_auth_retry(
            registry=registry,
            repository=repository,
            url=url,
            base_headers={},
            cap=cap,
            sink_factory=lambda: dest,
            token=token,
            phase="blob",
            scheme=scheme,
        )
        if resp.status != 200:
            raise MilpaError(
                FETCH_OCI_PULL_FAILED,
                f"blob fetch for {digest!r} returned status {resp.status}",
                phase="blob",
                registry=registry,
                repository=repository,
                digest=digest,
                status=resp.status,
            )
        # N1: sha256_of_file is hoisted into tarball.py (single source of
        # truth shared with the tarball archive-digest path) — mirrors how
        # MAX_COMPRESSED_BYTES already flows from there into this module.
        actual_digest = f"sha256:{sha256_of_file(dest)}"
        if actual_digest != digest:
            raise MilpaError(
                FETCH_OCI_DIGEST_MISMATCH,
                f"blob digest mismatch: expected {digest!r}, got {actual_digest!r}",
                phase="blob",
                expected=digest,
                actual=actual_digest,
            )
