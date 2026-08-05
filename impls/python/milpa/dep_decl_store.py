"""DepDeclStore protocol + FileDepDeclStore + HttpDepDeclStore (S3b).

spec/dep-decl.md §3.5 — fetch-or-cache + hash-verify as one sealed unit.

Design
------
``DepDeclStore`` is the single sealed responsibility for:
    1. Fetching artifact bytes (from disk or HTTP).
    2. Verifying ``sha256(bytes) == dep_decl_hash`` (the ONE hash-verify site).
    3. Caching immutably, forever, no TTL (§3.3.1 NORMATIVE).

This file defines:

``FileDepDeclStore(dir: Path)``
    Selected when ``MILPA_DEP_DECL_DIR`` is set.  Reads
    ``<dir>/<sha256_hex>.kdl`` — no network; still hash-verifies the bytes.

``HttpDepDeclStore(base_url: str, cache_dir: Path)``
    Production.  Artifact URL = ``<base_url>/dep-decl/<sha256_hex>.kdl``.
    Caches immutably by hash (no TTL).  Uses ``bounded_http.request`` (same
    native transport as ``index_cache.py``) — no bespoke network machinery.

``index_base_url(milpa_index_url: str) -> str``
    §3.3 normative URL-derivation: remove last segment if it matches
    ``*.kdl`` or ``index*``; else append ``/``.

SECURITY INVARIANT (NORMATIVE):
    ``TNG-DEPDECL-HASH-MISMATCH`` and ``TNG-DEPDECL-FETCH-FAILED`` are
    raised HERE and ONLY HERE.  No caller is permitted to silently fall
    back when ``get`` raises — integrity failures are always hard errors.

Cache notes:
    - ``HttpDepDeclStore`` cache lives in a **separate** directory from the
      source-tree CAS (e.g. ``~/.cache/milpa/dep-decl/``).
    - ``milpa clean`` MUST NOT remove it (enforced by the CLI, not here).
    - No GC; entries are content-addressed, immutable, and small.

Spec authority: spec/dep-decl.md §3.5; docs/rfc-content-addressed-metadata.md
§3.3 + §3.3.1.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
from pathlib import Path
from typing import Callable, Protocol

from milpa import bounded_http
from milpa.atomic_cache import atomic_write_bytes, read_verified_or_self_heal
from milpa.dep_decl import dep_decl_hash
from milpa.errors import (
    TNG_DEPDECL_FETCH_FAILED,
    TNG_DEPDECL_HASH_MISMATCH,
    MilpaError,
)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class DepDeclStore(Protocol):
    """Sealed fetch-or-cache + hash-verify seam for DepDecl artifacts.

    ``get`` is the ONE site where ``sha256(bytes) == dep_decl_hash`` is
    verified.  Two hard-error codes can be raised here:

    ``TNG-DEPDECL-FETCH-FAILED``
        Artifact not found / not reachable (file missing, HTTP error).
        S5 refines the policy for this code (strict vs. non-strict fallback);
        in S3b the code is always raised as a hard error from ``get``.

    ``TNG-DEPDECL-HASH-MISMATCH``
        ``sha256(bytes) != dep_decl_hash`` — bytes don't match the hash
        pointer.  Always a hard error (SECURITY INVARIANT — no fallback).

    ``is_cached(dep_decl_hash) -> bool`` is a local-only probe (no network);
    used by §3.7.2 offline-verify (S6).
    """

    def get(self, dep_decl_hash_str: str) -> bytes: ...
    def is_cached(self, dep_decl_hash_str: str) -> bool: ...


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hex_from_hash(dep_decl_hash_str: str) -> str:
    """Extract the lowercase-hex digest from a ``sha256:<hex>`` string.

    Raises ``ValueError`` if the string is not in the expected form.
    """
    if not dep_decl_hash_str.startswith("sha256:"):
        raise ValueError(
            f"dep_decl_hash {dep_decl_hash_str!r} does not start with 'sha256:'"
        )
    return dep_decl_hash_str[len("sha256:"):]


def _verify(artifact_bytes: bytes, dep_decl_hash_str: str) -> None:
    """Verify ``sha256(artifact_bytes) == dep_decl_hash_str``.

    This is the ONE hash-verify site (SECURITY INVARIANT).  Raises
    ``MilpaError(TNG-DEPDECL-HASH-MISMATCH)`` on mismatch.
    """
    computed = dep_decl_hash(artifact_bytes)
    if computed != dep_decl_hash_str:
        raise MilpaError(
            TNG_DEPDECL_HASH_MISMATCH,
            f"DepDecl artifact hash mismatch: expected {dep_decl_hash_str!r} "
            f"but computed {computed!r} — artifact may be corrupted or tampered",
            expected=dep_decl_hash_str,
            computed=computed,
        )


# ---------------------------------------------------------------------------
# FileDepDeclStore
# ---------------------------------------------------------------------------


class FileDepDeclStore:
    """Reads ``<dir>/<sha256_hex>.kdl`` — no network, still hash-verifies.

    Selected when ``MILPA_DEP_DECL_DIR`` is set.  Used by the conformance
    harness (S3a) and any air-gapped / local-mirror deployment.

    File naming: the stored file is named ``<sha256_hex>.kdl`` where
    ``sha256_hex`` is the 64-character lowercase hex digest extracted from
    the ``sha256:<hex>`` hash pointer.

    The file's bytes are hash-verified on every read (not just on first
    cache-miss) so that a corrupted local file raises ``HASH-MISMATCH``
    rather than being silently passed to the parser.
    """

    def __init__(self, dir: Path) -> None:
        self._dir = dir

    def get(self, dep_decl_hash_str: str) -> bytes:
        """Read artifact bytes, verify hash, return bytes.

        Raises:
            MilpaError(TNG-DEPDECL-FETCH-FAILED): File not found.
            MilpaError(TNG-DEPDECL-HASH-MISMATCH): Hash mismatch (one
                verify site — SECURITY INVARIANT).
        """
        hex_digest = _hex_from_hash(dep_decl_hash_str)
        artifact_path = self._dir / f"{hex_digest}.kdl"
        try:
            artifact_bytes = artifact_path.read_bytes()
        except FileNotFoundError:
            raise MilpaError(
                TNG_DEPDECL_FETCH_FAILED,
                f"DepDecl artifact not found at {artifact_path} "
                f"(hash {dep_decl_hash_str!r}) — check MILPA_DEP_DECL_DIR",
                hash=dep_decl_hash_str,
                path=str(artifact_path),
            )
        except OSError as exc:
            raise MilpaError(
                TNG_DEPDECL_FETCH_FAILED,
                f"DepDecl artifact unreadable at {artifact_path}: {exc}",
                hash=dep_decl_hash_str,
                path=str(artifact_path),
            ) from exc

        _verify(artifact_bytes, dep_decl_hash_str)
        return artifact_bytes

    def is_cached(self, dep_decl_hash_str: str) -> bool:
        """Return True iff the artifact file exists locally (no network)."""
        try:
            hex_digest = _hex_from_hash(dep_decl_hash_str)
        except ValueError:
            return False
        return (self._dir / f"{hex_digest}.kdl").is_file()


# ---------------------------------------------------------------------------
# ContentAddressedHttpArtifactStore — the generic fetch-or-cache + hash-
# verify shape shared by every HTTP artifact store in milpa (issue #201).
# ---------------------------------------------------------------------------


class ContentAddressedHttpArtifactStore:
    """Generic content-addressed fetch-or-cache + hash-verify HTTP store.

    ``HttpDepDeclStore`` (below) and ``HttpEntryBundleStore``
    (``entry_bundle_store.py``) are both thin instantiations of this class.
    They were previously two hand-written, structurally identical copies of
    this exact fetch-or-cache + hash-verify sequence — unify them here
    (CLAUDE.md: "Duplicate code paths are bugs ... unify them" — issue
    #201). What varies per artifact kind (URL sub-path, cache file
    extension, size cap, the hash-verify predicate, and the concrete
    fetch-failed error) is supplied by the caller; everything else —
    cache-first read with self-heal, cache-miss GET via ``bounded_http``,
    HTTP-status-error handling, verify-before-cache, atomic cache write —
    lives here once.

    Sequence (identical across artifact kinds):
        1. Cache-first read, self-healing a locally-corrupt cache entry
           (``atomic_cache.read_verified_or_self_heal`` — CR16).
        2. Cache miss: ``GET`` via ``bounded_http.request`` under ``max_bytes``.
        3. A transport error or HTTP status >= 400 is remapped through
           ``make_fetch_failed_error`` — the ONE fetch-failure contract for
           this artifact kind, regardless of cause.
        4. Verify the freshly-fetched bytes via ``verify`` BEFORE caching —
           a mismatch here is always a hard error (never self-healed; see
           ``read_verified_or_self_heal``'s docstring for why freshly-fetched
           bytes must never be routed through the self-heal path).
        5. Atomic, best-effort cache write (``atomic_cache.atomic_write_bytes``).

    ``url_token`` (the first argument to ``get``/``is_cached``) is the
    caller-resolved filename/URL segment — e.g. a bare hex digest for
    DepDecl, a bare-hex bundle pin for attestation bundles. ``report_key``
    (optional, defaults to ``url_token``) is what gets passed to ``verify``
    and ``make_fetch_failed_error`` instead — this exists because
    ``HttpDepDeclStore``'s public hash pointer (``sha256:<hex>``) differs
    from the bare-hex token used in the URL/cache filename, and error
    messages/kwargs must report the original, caller-facing pointer, not
    the derived token. ``HttpEntryBundleStore``'s bundle pin has no such
    split (the pin itself IS the URL token), so it never passes
    ``report_key``.
    """

    def __init__(
        self,
        base_url: str,
        cache_dir: Path,
        *,
        subpath: str,
        extension: str,
        max_bytes: int,
        verify: "Callable[[bytes, str], None]",
        make_fetch_failed_error: "Callable[[str, str, str], MilpaError]",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._cache_dir = cache_dir
        self._subpath = subpath
        self._extension = extension
        self._max_bytes = max_bytes
        self._verify = verify
        self._make_fetch_failed_error = make_fetch_failed_error

    def _artifact_url(self, url_token: str) -> str:
        return f"{self._base_url}/{self._subpath}/{url_token}{self._extension}"

    def _cache_path(self, url_token: str) -> Path:
        return self._cache_dir / f"{url_token}{self._extension}"

    def get(self, url_token: str, report_key: str | None = None) -> bytes:
        """Fetch artifact bytes (cache-first), verify hash, return bytes.

        ``report_key`` defaults to ``url_token`` — pass it explicitly when
        the caller's public hash pointer differs from the URL/cache-filename
        token (see class docstring).

        Raises:
            The fetch-failed error built by ``make_fetch_failed_error`` on a
                network / file / status error.
            Whatever ``verify`` raises on a hash mismatch (always a hard
                error — SECURITY INVARIANT, see class docstring).
        """
        if report_key is None:
            report_key = url_token

        cache_path = self._cache_path(url_token)
        cached_bytes = read_verified_or_self_heal(
            cache_path, lambda b: self._verify(b, report_key)
        )
        if cached_bytes is not None:
            return cached_bytes

        # Cache miss: fetch from network.
        artifact_url = self._artifact_url(url_token)
        sink = io.BytesIO()
        try:
            resp = bounded_http.request(
                "GET", artifact_url, cap=self._max_bytes, sink=sink
            )
        except MilpaError as exc:
            # bounded_http.request itself raises MilpaError for both a
            # transport failure and a cap breach (FETCH-DOWNLOAD-SIZE-
            # EXCEEDED) — remap unconditionally so every fetch failure
            # surfaces the ONE contract this artifact kind documents on its
            # own store's ``get``, regardless of cause.
            raise self._make_fetch_failed_error(report_key, artifact_url, exc.message) from exc
        except Exception as exc:
            raise self._make_fetch_failed_error(report_key, artifact_url, str(exc)) from exc

        # file:// responses carry no HTTP status (bounded_http leaves it
        # None) — only a genuine HTTP error status is a failure here.
        if resp.status is not None and resp.status >= 400:
            raise self._make_fetch_failed_error(report_key, artifact_url, f"HTTP {resp.status}")
        fetched_bytes = sink.getvalue()

        # Verify before caching — don't persist a corrupt/tampered artifact.
        self._verify(fetched_bytes, report_key)

        # Atomic write to cache (unique-per-write temp sibling + os.replace —
        # registry-protocol §3.5.2 NORMATIVE (concurrency); see atomic_cache.py).
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            atomic_write_bytes(cache_path, fetched_bytes)
            # Cache write failure is non-fatal; the bytes were already verified.

        return fetched_bytes

    def is_cached(self, url_token: str) -> bool:
        """Return True iff the artifact is in the local cache (no network)."""
        return self._cache_path(url_token).is_file()


# ---------------------------------------------------------------------------
# HttpDepDeclStore
# ---------------------------------------------------------------------------

#: DepDecl cache sub-directory under ``~/.cache/milpa/``.
_DEP_DECL_CACHE_SUBDIR = "dep-decl"

#: Maximum size of a DepDecl artifact fetched over HTTP (§3.3.1 NORMATIVE).
#:
#: A legitimate DepDecl is KDL text with one dep_decl_schema_version, one
#: src_dir, and O(dozens) of require lines — comfortably under 10 KiB in
#: practice.  1 MiB is a generous-but-safe ceiling that admits any plausible
#: future growth while bounding the resource-exhaustion surface: a compromised
#: or misconfigured index can point dep_decl at an arbitrary URL, so we must
#: never buffer an unbounded response body.
#:
#: Enforcement: the transport (``bounded_http.request``, RFC docs/rfc-native-
#: oci-fetch.md §3.3) streams the body and rejects as soon as the cumulative
#: byte count exceeds the cap — the full response is never buffered past it.
#: A pre-flight Content-Length-header early reject was possible under the
#: old direct ``urllib.request.urlopen`` call; ``bounded_http.request`` is a
#: single atomic ``(cap, sink)`` call with no header-peek hook, so that
#: optimization is gone (NAMED behavior change — see
#: test_http_store_lying_content_length_no_longer_pre_rejected).  The actual-
#: bytes-cap enforcement, and therefore the security property, is unchanged.
#:
#: On exceed: raises ``TNG-DEPDECL-FETCH-FAILED`` (non-strict fallback is
#: possible; strict mode is a hard fail — same policy as other fetch failures).
_DEP_DECL_MAX_ARTIFACT_BYTES: int = 1024 * 1024  # 1 MiB


def _default_dep_decl_cache_dir() -> Path:
    """Return the platform-appropriate DepDecl cache directory.

    ``$XDG_CACHE_HOME/milpa/dep-decl/`` (default ``~/.cache/milpa/dep-decl/``).
    Mirrors ``index_cache._default_cache_dir`` with a different sub-dir so
    the two caches don't collide (spec §3.3.1 NORMATIVE: separate cache
    roots for source-tree CAS vs. DepDecl artifacts).
    """
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "milpa" / _DEP_DECL_CACHE_SUBDIR


def _dep_decl_fetch_failed_error(dep_decl_hash_str: str, artifact_url: str, detail: str) -> MilpaError:
    """Build the ``TNG-DEPDECL-FETCH-FAILED`` error for a fetch failure.

    Passed to ``ContentAddressedHttpArtifactStore`` as
    ``make_fetch_failed_error`` — this is the ONE place that builds this
    error, regardless of whether the failure was a transport exception, a
    cap breach, or an HTTP error status (``detail`` carries the specifics).
    """
    return MilpaError(
        TNG_DEPDECL_FETCH_FAILED,
        f"Failed to fetch DepDecl artifact from {artifact_url!r}: {detail}",
        hash=dep_decl_hash_str,
        url=artifact_url,
    )


class HttpDepDeclStore:
    """Production DepDecl store: fetch from HTTP + immutable cache.

    Artifact URL = ``<base_url>/dep-decl/<sha256_hex>.kdl``.
    Cache is ``<cache_dir>/<sha256_hex>.kdl`` — immutable forever, no TTL
    (spec §3.3.1 NORMATIVE: content-addressed artifact can never change).

    Cache writes are atomic (tmp-sibling + ``os.replace``), mirroring the
    index cache.  Concurrent readers never observe a partial write.

    OCI base URLs (``oci://…``): not supported.  If the base URL starts
    with ``oci://``, ``get`` raises ``TNG-DEPDECL-FETCH-FAILED`` with a
    clear message instructing the caller to set ``MILPA_DEP_DECL_DIR``
    (spec §3.3 NOTE on OCI).

    Transport: ``bounded_http.request`` (RFC docs/rfc-native-oci-fetch.md
    §3.3 — the single native in-process transport every consumer HTTP call
    site converges on).  Supports ``http://``, ``https://``, and ``file://``
    (air-gapped / local-mirror) schemes.
    """

    def __init__(self, base_url: str, cache_dir: Path | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._cache_dir = cache_dir if cache_dir is not None else _default_dep_decl_cache_dir()
        self._core = ContentAddressedHttpArtifactStore(
            self._base_url,
            self._cache_dir,
            subpath="dep-decl",
            extension=".kdl",
            max_bytes=_DEP_DECL_MAX_ARTIFACT_BYTES,
            verify=_verify,
            make_fetch_failed_error=_dep_decl_fetch_failed_error,
        )

    def get(self, dep_decl_hash_str: str) -> bytes:
        """Fetch artifact bytes (cache-first), verify hash, return bytes.

        Cache-first: if the artifact is already cached (by hash), return it
        without any network access.  On a cache miss, fetch from the network,
        verify, write to cache, return.

        Raises:
            MilpaError(TNG-DEPDECL-FETCH-FAILED): Network / file error.
            MilpaError(TNG-DEPDECL-HASH-MISMATCH): Hash mismatch.
        """
        # OCI: not supported — direct caller to MILPA_DEP_DECL_DIR.  This is
        # a dep_decl-only pre-check (HttpEntryBundleStore has no OCI-base
        # concept), so it stays here rather than in the shared
        # ContentAddressedHttpArtifactStore core.
        if self._base_url.startswith("oci://"):
            hex_digest = _hex_from_hash(dep_decl_hash_str)
            raise MilpaError(
                TNG_DEPDECL_FETCH_FAILED,
                f"OCI index base URLs ({self._base_url!r}) do not support the "
                f"DepDecl URL template — set MILPA_DEP_DECL_DIR to a local "
                f"directory containing {hex_digest}.kdl",
                hash=dep_decl_hash_str,
                base_url=self._base_url,
            )

        hex_digest = _hex_from_hash(dep_decl_hash_str)
        return self._core.get(hex_digest, dep_decl_hash_str)

    def is_cached(self, dep_decl_hash_str: str) -> bool:
        """Return True iff the artifact is in the local cache (no network)."""
        try:
            hex_digest = _hex_from_hash(dep_decl_hash_str)
        except ValueError:
            return False
        return self._core.is_cached(hex_digest)


# ---------------------------------------------------------------------------
# §3.3 URL derivation — index_base_url
# ---------------------------------------------------------------------------

#: Regex matching a KDL-file-like last segment: ``*.kdl`` or ``index*``.
_KDL_OR_INDEX_SEGMENT = re.compile(r"^(?:.*\.kdl|index.*)$", re.IGNORECASE)


def index_base_url(milpa_index_url: str) -> str:
    """Derive ``<index_base_url>`` from ``MILPA_INDEX_URL`` (§3.3 NORMATIVE).

    Rule: remove the last path segment of the URL iff that segment matches
    ``*.kdl`` or ``index*`` (case-insensitive); otherwise append ``/``.

    Examples (from the RFC):
        ``…/tianguis/main/index.kdl``  →  ``…/tianguis/main/``
        ``https://example.com/registry/v2``  →  ``https://example.com/registry/v2/``
        ``file:///home/user/conformance/index.kdl``  →  ``file:///home/user/conformance/``

    ``file://`` URIs are handled correctly: the path is extracted from the
    URI, the last segment is examined, and the result is re-composed.

    Note: The ``oci://`` scheme is NOT supported — see ``HttpDepDeclStore``
    docstring for policy.
    """
    # Split on the last ``/`` to get (prefix, last_segment).
    # Handle the edge case where the URL ends with ``/`` (no last segment).
    stripped = milpa_index_url.rstrip("/")
    slash_pos = stripped.rfind("/")
    if slash_pos == -1:
        # No slash at all — can't identify a segment; just append /.
        return milpa_index_url.rstrip("/") + "/"

    prefix = stripped[:slash_pos + 1]  # includes the trailing /
    last_segment = stripped[slash_pos + 1:]

    if _KDL_OR_INDEX_SEGMENT.match(last_segment):
        # Remove the last segment (keep prefix which includes the /).
        return prefix
    else:
        # The URL doesn't end in a KDL-filename-like segment; append /.
        return stripped + "/"


def make_dep_decl_store(milpa_index_url: str | None = None) -> "HttpDepDeclStore":
    """Build an ``HttpDepDeclStore`` from the runtime index URL.

    Reads ``MILPA_INDEX_URL`` from the environment when ``milpa_index_url``
    is not provided.  Derives ``<index_base_url>`` per §3.3.

    This is the production factory called by the CLI when
    ``MILPA_DEP_DECL_DIR`` is NOT set.
    """
    index_url = milpa_index_url or os.environ.get("MILPA_INDEX_URL", "").strip()
    if not index_url:
        from milpa.index_cache import DEFAULT_INDEX_URL
        index_url = DEFAULT_INDEX_URL
    base = index_base_url(index_url)
    return HttpDepDeclStore(base_url=base)


def dep_decl_store_from_paths(
    dep_decl_dir: "Path | None",
    index_url: "str | None",
    no_index: bool = False,
) -> "FileDepDeclStore | HttpDepDeclStore | None":
    """Select the DepDeclStore given resolved paths/URLs — the SINGLE priority
    definition shared by the CLI and the in-process conformance adapter.

    Priority (matches cli.py::_build_dep_decl_store and
    test_conformance::_build_env, H1 unification):

    0. ``no_index`` → ``None`` (no index ⇒ DepDecl path unreachable).
    1. ``dep_decl_dir`` not None and is_dir → ``FileDepDeclStore(dep_decl_dir)``.
    2. ``index_url`` non-empty → ``HttpDepDeclStore`` derived via ``index_base_url``.
    3. ``index_url`` is ``None`` or empty → ``None`` (no index configured).

    Callers are responsible for resolving their inputs to canonical form:
    - CLI: reads MILPA_DEP_DECL_DIR / MILPA_INDEX_URL from env; passes absent
      MILPA_INDEX_URL as ``DEFAULT_INDEX_URL`` (three-way semantics).
    - Conformance adapter: checks fixture_dir/dep-decl/ and fixture_dir/index.kdl;
      passes the file:// URL for the index or None when absent.
    """
    if no_index:
        return None
    if dep_decl_dir is not None and dep_decl_dir.is_dir():
        return FileDepDeclStore(dep_decl_dir)
    if index_url:
        base = index_base_url(index_url)
        return HttpDepDeclStore(base_url=base)
    return None
