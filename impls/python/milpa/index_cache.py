"""tianguis index acquisition — four-state freshness cache + bundle verification (S5).

Mirrors ``impls/rust/crates/milpa-core/src/index_cache.rs``.

The HTTP transport and clock are injected (``HttpGet`` / ``now_unix``) so all
four cache states are unit-testable without a network or a real wall-clock.
Production callers pass ``urllib_http_get`` and ``time.time`` (cast to ``int``).

Four states (registry-protocol §6 NORMATIVE; RFC registry-trust-federation §7.2):
  1. **Fresh cache** (age < TTL) → serve cached bytes + bundle sidecar, no network.
     Crypto-verified on EVERY read; freshness NOT re-asserted on pure cache reads
     (offline/air-gapped safety — spec §3.4.4 step 3).
  2. **Stale cache** (age ≥ TTL) → re-fetch index + bundle, overwrite, serve fresh.
     Crypto-verified AND freshness asserted (network-fetch path).
  3. **Network failure with stale-but-present cache** → serve the stale cache as
     an offline fallback; emit a warning.  Crypto-verified; freshness NOT asserted.
  4. **Network failure with no cache** → raise ``MILPA-INDEX-UNREACHABLE``.

Bundle sidecar files (RFC §7.2):
  ``<key>.index.kdl``         ← index content
  ``<key>.index.kdl.at``      ← fetch-time stamp
  ``<key>.index.kdl.bundle``  ← Sigstore bundle (NEW S5)
  ``<key>.index.kdl.no-bundle`` ← degraded marker (warn only; bundle 404)

Append-only ratchet baseline sidecars (registry-protocol §3.5.2/§6, RFC
registry-append-only.md A2d — a SECOND, independent sidecar pair, gated by
the ``index-history`` policy axis rather than ``index-trust``):
  ``<key>.index.kdl.baseline``      ← last index that passed the ratchet cleanly
  ``<key>.index.kdl.baseline.meta`` ← established_at / reported_digest / reported_at

Crash recovery (RFC §7.2 — bounded):
  On a cache READ, a digest-mismatch or missing bundle sidecar → delete both
  sidecars + refetch ONCE.  If the refetch ALSO fails verification → hard-fail
  regardless of policy (active-adversary signal).  The append-only ratchet gate
  (below) runs identically on this bounded refetch as on an ordinary State-2
  fetch — a candidate arriving via crash recovery is exactly as untrusted.

``MILPA_INDEX_URL``, when set to a non-empty string, overrides the default
index URL for every index-fetching operation in that invocation.  Supports
the ``file://`` scheme so air-gapped / harness deployments can substitute a
private or local index (``cli-contract.md`` §8.1 NORMATIVE).

Cache writes are atomic: write bundle sidecar first, then atomic-rename index
file, then (only on a clean ratchet diff) the baseline pair.  Every write in
this module — bundle, index, baseline, ``.baseline.meta`` — goes through a
per-write-unique temp sibling name (``_unique_temp_path``, PID + random
suffix) before ``os.replace``, so two concurrent writers can never interleave
partial writes through a shared fixed ``.tmp`` name (registry-protocol §3.5.2
NORMATIVE (concurrency)). Concurrent readers that observe a half-written pair
trigger crash-recovery (digest mismatch → single bounded refetch), which is
safe and self-correcting.

The append-only ratchet gate (``index_ratchet_seam.py`` — pure parse/diff/
decide; this module owns all I/O) runs AFTER Layer-1 bundle verification
succeeds and BEFORE any cache mutation, including the bundle sidecar write:
parse-at-gate means an unparseable candidate can never clobber a good cache,
and a ``index-history "strict"`` violation aborts before any write at all.
See registry-protocol §3.5.2 for the full policy/write-ordering contract.

Spec authority: ``spec/registry-protocol.md`` §6, §3.5; ``spec/cli-contract.md``
§8; ``docs/rfc-registry-trust-federation.md`` §4, §6.5, §7;
``docs/rfc-registry-append-only.md`` §2.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

from milpa.atomic_cache import atomic_write_bytes as _atomic_write_bytes
from milpa.atomic_cache import unique_temp_path as _unique_temp_path
from milpa.errors import MILPA_INDEX_UNREACHABLE, MilpaError

if TYPE_CHECKING:
    from milpa.epoch_commitment import EpochCommitmentStatus
    from milpa.index_ratchet_seam import BaselineMeta, GateDecision
    from milpa.index_trust import IndexBundleVerifier, IndexTrustConfig, TrustBundle
    from milpa.registry import Index

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: The live tianguis index URL (the federation seam — one URL for now).
#: Conformant implementations MUST use this URL when no override is configured
#: (registry-protocol §1 NORMATIVE).
DEFAULT_INDEX_URL: str = (
    "https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl"
)

#: Default TTL — 24h: generous enough to avoid hammering tianguis on every
#: invocation, short enough that the vendor-en-absentia daily pass is visible.
DEFAULT_TTL_SECONDS: int = 24 * 60 * 60

# Sentinel for bundle HTTP get: raised to signal a 404 (bundle not found).
_BUNDLE_404_SENTINEL = "BUNDLE-404"

# ---------------------------------------------------------------------------
# Transport types
# ---------------------------------------------------------------------------

#: A fetch transport for the index: maps a URL string to body bytes, or raises.
#: Signature: ``(url: str) -> bytes``
#: On error: raise ``Exception`` (any subclass).
HttpGet = Callable[[str], bytes]

#: A fetch transport for the bundle sidecar: maps a URL string to body bytes,
#: or raises on network error.  Raise ``_BundleNotFound`` on HTTP 404.
#: Injected separately from ``http_get`` so each can be faked independently in tests.
BundleHttpGet = Callable[[str], bytes]


class _BundleNotFound(Exception):
    """Raised by ``bundle_http_get`` when the bundle URL returns HTTP 404."""


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def index_url_from_env() -> str:
    """Return ``MILPA_INDEX_URL`` if set to a non-empty string, else ``DEFAULT_INDEX_URL``.

    Registry-protocol §1 NORMATIVE; cli-contract.md §8.1 NORMATIVE.
    Supports the ``file://`` scheme for air-gapped / harness deployments.

    NOTE: This helper is for callers that have already decided to load an
    index. It does NOT implement the three-way "absent vs empty" gate.
    The three-way gate (absent→default, empty→no-index, non-empty→that-URL)
    lives in ``cli._load_index_for_verb``. Call ``index_url_from_env()`` only
    after confirming ``MILPA_INDEX_URL`` is not present-but-empty.
    """
    override = os.environ.get("MILPA_INDEX_URL", "").strip()
    return override if override else DEFAULT_INDEX_URL


def _default_cache_dir() -> Path:
    """Return the platform-appropriate index cache directory.

    ``$XDG_CACHE_HOME/milpa/index/`` (default ``~/.cache/milpa/index/``).
    """
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "milpa" / "index"


def _derive_sidecar_url(index_url: str, suffix: str) -> str:
    """Shared path-suffix derivation for every index sidecar URL (index
    bundle §3.4.2/§7.3, epoch-commitment sidecar §3.4.9): strip query string
    and fragment from ``index_url``; append *suffix* to the URL PATH; then
    reattach the original query string and fragment.  Naive string suffixing
    breaks ``?ref=main`` and trailing-slash URLs (e.g.
    ``https://host/index.kdl?ref=main.bundle`` is wrong) — the ONE
    implementation both ``derive_bundle_url`` and ``derive_commitment_url``
    delegate to (single source of truth for this derivation rule)."""
    parsed = urlparse(index_url)
    new_path = parsed.path + suffix
    return urlunparse(parsed._replace(path=new_path))


def derive_bundle_url(index_url: str) -> str:
    """Derive the bundle sidecar URL from the index URL (RFC §7.3 NORMATIVE).

    Derivation: strip query string and fragment from ``index_url``; append
    ``.bundle`` to the URL PATH; then reattach the original query string and
    fragment.  Naive string suffixing breaks ``?ref=main`` and trailing-slash
    URLs (e.g. ``https://host/index.kdl?ref=main.bundle`` is wrong).

    Example (default index URL):
        ``https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl``
        → ``https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl.bundle``
    """
    return _derive_sidecar_url(index_url, ".bundle")


def derive_commitment_url(index_url: str) -> str:
    """Derive the epoch-commitment sidecar URL from the index URL
    (registry-protocol §3.4.9 NORMATIVE): identical derivation to
    ``derive_bundle_url``, substituting the ``.epoch-commitment`` suffix for
    ``.bundle``.

    Example (default index URL):
        ``https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl``
        → ``https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl.epoch-commitment``
    """
    return _derive_sidecar_url(index_url, ".epoch-commitment")


# ---------------------------------------------------------------------------
# Cache path + stamp helpers
# ---------------------------------------------------------------------------


def cache_path_for(url: str, cache_dir: Path) -> Path:
    """Return the stable per-URL cache file path for *url* under *cache_dir*.

    Cache key: first 16 hex characters of ``sha256(url.encode("utf-8"))``
    (registry-protocol §6 NORMATIVE: deterministic so two concurrent
    invocations share the same entry and ``MILPA_INDEX_URL`` substitution
    caches the substitute correctly).
    """
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return cache_dir / f"{digest[:16]}.index.kdl"


def _stamp_path(cache_file: Path) -> Path:
    """Sidecar fetch-time stamp: ``<cache_file>.at``."""
    return cache_file.with_suffix(".kdl.at")


def _bundle_path(cache_file: Path) -> Path:
    """Sidecar Sigstore bundle: ``<cache_file>.bundle`` (RFC §7.2 naming)."""
    return Path(str(cache_file) + ".bundle")


def _no_bundle_marker_path(cache_file: Path) -> Path:
    """Degraded-marker sidecar (warn only): ``<cache_file>.no-bundle`` (RFC §7.2)."""
    return Path(str(cache_file) + ".no-bundle")


def _baseline_path(cache_file: Path) -> Path:
    """Append-only ratchet baseline sidecar: ``<cache_file>.baseline`` — a
    full copy of the last index that passed the ratchet cleanly
    (registry-protocol §3.5.2, §6)."""
    return Path(str(cache_file) + ".baseline")


def _baseline_meta_path(cache_file: Path) -> Path:
    """Ratchet baseline metadata sidecar: ``<cache_file>.baseline.meta``
    (registry-protocol §3.5.2, §6) — ``established_at`` / ``reported_digest``
    / ``reported_at``, one file, written atomically as a unit."""
    return Path(str(cache_file) + ".baseline.meta")


def baseline_sidecar_paths(url: str, cache_dir: Path) -> tuple[Path, Path]:
    """Public accessor for the ratchet baseline sidecar pair's paths for
    *url* — the ONE naming authority both the ordinary ratchet-gated fetch
    path (``_run_ratchet_gate`` / ``_apply_ratchet_writes``, above) and
    ``milpa index status``/``accept`` (``cli.py``, RFC
    registry-append-only.md A2e) use, so the two never drift (registry-
    protocol §6 NORMATIVE: "``status``/``accept`` are the only commands that
    read or write the baseline sidecar pair outside the ordinary
    ratchet-gated fetch path")."""
    cache_file = cache_path_for(url, cache_dir)
    return _baseline_path(cache_file), _baseline_meta_path(cache_file)


def _read_stamp(stamp_file: Path) -> int | None:
    """Read a sidecar stamp file and return its unix-second value, or ``None``."""
    try:
        raw = stamp_file.read_text().strip()
        return int(raw)
    except (OSError, ValueError):
        return None


def _write_stamp(stamp_file: Path, now_unix: int) -> None:
    """Write the fetch time (unix seconds) to the sidecar stamp file."""
    with contextlib.suppress(OSError):
        stamp_file.write_text(str(now_unix))  # non-fatal: worst case the next invocation re-fetches


# ---------------------------------------------------------------------------
# Bundle verification helpers
# ---------------------------------------------------------------------------


def _verify_and_enforce(
    index_bytes: bytes,
    bundle_bytes: bytes | None,
    config: "IndexTrustConfig",
    verifier: "IndexBundleVerifier",
    index_url: str,
    is_network_fetch: bool,
) -> None:
    """Verify the bundle against index_bytes and enforce the configured policy.

    Args:
        index_bytes: Raw bytes of the index (single-read invariant — the same
            object MUST be passed to parse_index; no second disk read between
            verification and parsing).
        bundle_bytes: Raw bytes of the Sigstore bundle sidecar, or ``None``
            when the bundle is absent (bundle-404 or missing sidecar).
        config: IndexTrustConfig carrying policy, trust_bundle, expected_signer,
            max_age_seconds.
        verifier: Injected IndexBundleVerifier (SigstoreVerifier in production;
            MockVerifier in tests).
        index_url: The index URL being loaded (for warn dedup key and error msgs).
        is_network_fetch: True on network-fetch paths (States 2 + recovery
            refetch) — freshness assertion fires.  False on pure cache reads
            (States 1 and 3) — freshness NOT asserted (offline safety).
    """
    from milpa.index_trust import BundleMissing, enforce_index_trust, verify_index_bundle

    if config.policy == "off":
        return

    if bundle_bytes is None:
        result = BundleMissing
    else:
        max_age = config.max_age_seconds if is_network_fetch else None
        result = verifier.verify(
            index_bytes=index_bytes,
            bundle_bytes=bundle_bytes,
            trust_bundle=config.trust_bundle,
            expected_signer=config.expected_signer,
            max_age_seconds=max_age,
        )

    enforce_index_trust(result, config.policy, index_url)


def reverify_cached_index(
    url: str,
    cache_dir: Path,
    config: "IndexTrustConfig | None",
    verifier: "IndexBundleVerifier | None",
) -> None:
    """Re-verify the ALREADY-CACHED index attestation bundle, fully offline (Sv).

    Reads the on-disk cached ``index.kdl`` + ``index.kdl.bundle`` and re-runs bundle
    verification + policy enforcement with freshness DISABLED (``is_network_fetch=False``,
    spec §3.4.4 step 3) — the offline post-incident audit path ``milpa verify`` is meant to
    provide (Part-1 §7.5). It **never** touches the network and does **not** go through the
    cache state machine (no fetch, no TTL, no stale-refresh) — so it cannot change any Part-1
    cache behavior.

    No-op when there is nothing to enforce or nothing cached: ``policy=off``, no
    ``config``/``verifier``, or no cache file for ``url``. When the cache holds a bundle, a
    tampered/invalid one raises the mapped ``TNG-INDEX-*`` slug under ``strict`` (warns under
    ``warn``); a recorded bundle-404 (no-bundle marker) enforces ``BundleMissing`` the same way.
    """
    if config is None or verifier is None or config.policy == "off":
        return
    cache_file = cache_path_for(url, cache_dir)
    if not cache_file.exists():
        return  # nothing cached to reverify — and we must not fetch here
    index_bytes = cache_file.read_bytes()
    if _no_bundle_marker_path(cache_file).exists():
        bundle_bytes: bytes | None = None
    else:
        bundle_file = _bundle_path(cache_file)
        bundle_bytes = bundle_file.read_bytes() if bundle_file.exists() else None
    _verify_and_enforce(
        index_bytes, bundle_bytes, config, verifier, url, is_network_fetch=False
    )


def fetch_verified_candidate_text(
    url: str,
    http_get: HttpGet,
    bundle_http_get: "BundleHttpGet | None",
    config: "IndexTrustConfig | None",
    verifier: "IndexBundleVerifier | None",
) -> str:
    """Force a network fetch of *url* and verify it under the effective
    index-trust policy — WITHOUT any cache mutation (no bundle sidecar, no
    index write, no freshness stamp, no ratchet baseline touched).

    This is the shared fetch-and-verify primitive for ``milpa index status
    --refresh`` / ``milpa index accept`` (cli-contract.md §5.12, RFC
    registry-append-only.md A2e): both need "what would a forced refresh
    find" as plain text to diff against the local baseline, without any of
    ``load_index``'s State-2 cache side effects — the ``--refresh-index``
    precedent (§2.9) applied to a read-only probe. Reuses
    ``_verify_and_enforce`` (the SAME trust-enforcement call site
    ``load_index``'s State-2 body uses) and ``_get_bundle_url`` rather than
    re-implementing policy dispatch — only the "then write it to cache" tail
    of ``load_index`` is intentionally NOT here.

    Raises whatever ``http_get``/``bundle_http_get`` raise on network
    failure (the caller wraps this as ``MILPA-INDEX-UNREACHABLE``, mirroring
    ``load_index``'s State-4 framing), or the mapped ``TNG-INDEX-*`` slug on
    a trust-gate failure (e.g. under ``strict`` with a missing/invalid
    bundle) — both propagate BEFORE any cache mutation, since none is ever
    attempted by this function.
    """
    fetched_bytes = http_get(url)

    if config is not None and verifier is not None:
        fetched_bundle: bytes | None = None
        if bundle_http_get is not None:
            bundle_url = _get_bundle_url(url)
            try:
                fetched_bundle = bundle_http_get(bundle_url)
            except _BundleNotFound:
                fetched_bundle = None
            except Exception:
                fetched_bundle = None
        if fetched_bundle is None:
            from milpa.index_trust import BundleMissing, enforce_index_trust
            enforce_index_trust(BundleMissing, config.policy, url)
        else:
            _verify_and_enforce(
                index_bytes=fetched_bytes,
                bundle_bytes=fetched_bundle,
                config=config,
                verifier=verifier,
                index_url=url,
                is_network_fetch=True,
            )

    try:
        return fetched_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        from milpa.errors import TNG_KDL_SYNTAX
        raise MilpaError(
            TNG_KDL_SYNTAX,
            f"index bytes from {url!r} are not valid UTF-8: {exc}",
            url=url,
        ) from exc


def write_baseline_pair(
    url: str,
    cache_dir: Path,
    candidate_bytes: bytes,
    meta: "BaselineMeta",
) -> None:
    """Atomically swap the ratchet baseline pair for *url* — the ONLY
    mutation ``milpa index accept`` performs (cli-contract.md §5.12;
    registry-protocol §6 NORMATIVE). Each sidecar goes through the same
    per-write-unique-temp-name atomic writer (``_atomic_write_bytes``) the
    ordinary ratchet gate uses (§3.5.2 NORMATIVE (concurrency)) — write
    order is baseline then ``.meta``, matching ``_apply_ratchet_writes``.

    Raises ``MilpaError(TNG_INDEX_BASELINE_WRITE_FAILED)`` — loud and
    distinct, never a silent no-op — wrapping any ``OSError``. Because each
    write is atomic (temp + rename) and the baseline is attempted first, a
    failure creating/renaming the FIRST temp file leaves the previous pair
    completely untouched; a failure on the second (``.meta``) write after a
    successful baseline swap is covered by ``.meta``'s documented
    advisory/self-healing semantics (registry-protocol §3.5.2 NORMATIVE:
    ".baseline.meta is advisory... if it is missing or stale relative to
    .baseline... treat the reported-violation-set as unset").
    """
    from milpa.errors import TNG_INDEX_BASELINE_WRITE_FAILED

    baseline_path, meta_path = baseline_sidecar_paths(url, cache_dir)
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write_bytes(baseline_path, candidate_bytes)
        _atomic_write_bytes(meta_path, meta.render().encode("utf-8"))
    except OSError as exc:
        raise MilpaError(
            TNG_INDEX_BASELINE_WRITE_FAILED,
            f"failed to write the append-only ratchet baseline for {url!r}: {exc} "
            "— the previous baseline pair (if any) is left intact",
            url=url,
        ) from exc


# ---------------------------------------------------------------------------
# Epoch-commitment sidecar acquisition (registry-protocol §3.4.9;
# rfc-attestation-v1-normative.md §6 S-EpochCommitment sub-slice 3).
#
# Mirrors the whole-index bundle's fetch+cache class above, with ONE
# structural difference: the bundle sidecar is cached by URL (one fixed
# slot per index URL, overwritten on every refresh); this sidecar is
# CONTENT-ADDRESSED, cached by the commitment digest ``C`` itself
# (registry-protocol §3.4.9 NORMATIVE: "cached as an immutable
# content-addressed artifact keyed by C ... no TTL, no staleness concept").
# A new ``C`` (a re-arm, or a different registry) is simply a cache miss —
# there is no "stale key" comparison to perform, unlike the single-slot
# bundle cache.  This is the SAME content-addressed-by-hash-pin shape
# ``entry_bundle_store.py`` uses for per-entry attestation bundles.
# ---------------------------------------------------------------------------

#: Epoch-commitment sidecar cache sub-directory under ``~/.cache/milpa/``.
_EPOCH_COMMITMENT_CACHE_SUBDIR = "epoch-commitment"


def _default_epoch_commitment_cache_dir() -> Path:
    """``$XDG_CACHE_HOME/milpa/epoch-commitment/`` (default
    ``~/.cache/milpa/epoch-commitment/``) — mirrors
    ``entry_bundle_store._default_entry_bundle_cache_dir`` with a dedicated
    sub-directory (the store's native content-address key, ``C``)."""
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "milpa" / _EPOCH_COMMITMENT_CACHE_SUBDIR


def _epoch_commitment_cache_path(pointer: str, cache_dir: Path) -> Path:
    """``<cache_dir>/<C>.epoch-commitment`` — the content-addressed cache
    file for the commitment sidecar whose digest is *pointer*."""
    return cache_dir / f"{pointer}.epoch-commitment"


#: A fetch transport for the epoch-commitment sidecar: maps a URL string to
#: body bytes, or raises on any failure (network error, 404 — this artifact
#: class has no degraded "missing sidecar, proceed anyway" mode: the
#: on-index pointer being present is itself the unconditional trigger,
#: registry-protocol §3.4.9).
EpochCommitmentHttpGet = Callable[[str], bytes]


def read_cached_epoch_commitment_pointer(
    index_url: str, cache_dir: "Path | None" = None
) -> "str | None":
    """Read the ``attestation-epoch-commitment`` pointer off the CACHED
    index text for *index_url* (registry-protocol §3.4.8's typed pointer).

    ``load_index`` returns only the parsed, validated ``Index`` — it does
    not surface document-root free-text fields (the same reason
    ``index_ratchet_seam.py`` exists as a re-walk seam for
    ``attestation-epoch``: ``registry.parse_index`` never sees fields
    outside a ``package`` node). This is a SECOND read of the same cached
    file ``load_index`` just wrote or verified moments earlier — a
    pragmatic simplification over threading the pointer through every
    branch of ``load_index``'s four-state machine; safe because by the
    time a caller reaches this function, ``load_index`` has already
    completed Layer-1 verification for this invocation, so the cached
    bytes are the same trusted bytes already served.

    Returns ``None`` when there is no cache file yet, or the file cannot be
    decoded/parsed as KDL (mirrors ``_raw_attestation_epoch``'s posture:
    absence is not itself an error at this call site — a malformed index
    would already have raised earlier, inside ``load_index``'s own parse).
    """
    from milpa.index_ratchet_seam import _raw_attestation_epoch_commitment
    from milpa.kdl_io import parse_kdl

    effective_cache_dir = cache_dir if cache_dir is not None else _default_cache_dir()
    cache_file = cache_path_for(index_url, effective_cache_dir)
    try:
        text = cache_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        doc = parse_kdl(text, context="registry")
    except MilpaError:
        return None
    return _raw_attestation_epoch_commitment(doc)


def load_epoch_commitment_status(
    *,
    index_url: str,
    pointer: "str | None",
    cache_dir: "Path | None" = None,
    http_get: "EpochCommitmentHttpGet | None" = None,
    verifier: "IndexBundleVerifier",
    trust_bundle: "TrustBundle",
    expected_signer: str,
) -> "EpochCommitmentStatus":
    """The full acquisition + composed-verification orchestration for the
    S-EpochCommitment index-gate phase (registry-protocol §3.4.8/§3.4.9).

    Thin I/O wrapper over ``epoch_commitment.evaluate_epoch_commitment``
    (pure): this function's ONLY job is "get the sidecar bytes from the
    content-addressed cache or the network, exactly like every other
    sidecar in this module" — the parse/digest/crypto logic lives in
    ``epoch_commitment.py``, not here (mirrors the
    ``index_ratchet_seam.py`` / ``index_cache.py`` split).

    Acquisition:
      1. ``pointer is None`` → no fetch attempted at all (``Unarmed``,
         computed by the pure function with ``sidecar_bytes=None,
         fetch_failed=False``).
      2. Cache hit (``<cache_dir>/<pointer>.epoch-commitment`` exists) →
         serve cached bytes, no network (D2: content-addressed, no TTL, no
         re-verification against a wall-clock bound).
      3. Cache miss → ONE fetch attempt via *http_get* at
         ``derive_commitment_url(index_url)``. A raised exception maps to
         ``fetch_failed=True`` (→ ``ArmingInvalid``) — this function MUST
         NOT loop or retry (registry-protocol §3.4.9 NORMATIVE).

    Persistence: the fetched bytes are cached ONLY when verification
    produces ``Armed`` (never persist bytes that failed to verify — an
    ``ArmingInvalid`` sidecar must be re-fetched, not remembered, so a
    transient/attacker-served bad sidecar self-corrects on the next
    invocation once the registry is fixed).
    """
    from milpa.epoch_commitment import Armed, evaluate_epoch_commitment

    effective_cache_dir = cache_dir if cache_dir is not None else _default_epoch_commitment_cache_dir()
    effective_http_get = http_get if http_get is not None else urllib_bundle_http_get

    if pointer is None:
        return evaluate_epoch_commitment(
            pointer=None,
            sidecar_bytes=None,
            fetch_failed=False,
            verifier=verifier,
            trust_bundle=trust_bundle,
            expected_signer=expected_signer,
        )

    cache_path = _epoch_commitment_cache_path(pointer, effective_cache_dir)
    sidecar_bytes: bytes | None = None
    fetch_failed = False
    try:
        sidecar_bytes = cache_path.read_bytes()
    except OSError:
        sidecar_url = derive_commitment_url(index_url)
        try:
            sidecar_bytes = effective_http_get(sidecar_url)
        except Exception:
            sidecar_bytes = None
            fetch_failed = True

    status = evaluate_epoch_commitment(
        pointer=pointer,
        sidecar_bytes=sidecar_bytes,
        fetch_failed=fetch_failed,
        verifier=verifier,
        trust_bundle=trust_bundle,
        expected_signer=expected_signer,
    )

    if isinstance(status, Armed) and sidecar_bytes is not None:
        effective_cache_dir.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            _atomic_write_bytes(cache_path, sidecar_bytes)

    return status


# ---------------------------------------------------------------------------
# load_index — main entry point (S5: new signature with trust gate)
# ---------------------------------------------------------------------------


def load_index(
    url: str,
    cache_dir: Path,
    http_get: HttpGet,
    ttl_seconds: int,
    now_unix: int,
    # S5 additions — trust gate seam:
    config: "IndexTrustConfig | None" = None,
    verifier: "IndexBundleVerifier | None" = None,
    bundle_http_get: "BundleHttpGet | None" = None,
    refresh: bool = False,
    # A2d addition — append-only ratchet seam:
    index_history_policy: str = "off",
) -> "Index":
    """Fetch + cache + parse the ``index.kdl`` at *url*.

    S5 trust gate: when ``config`` is provided (not None), the Sigstore
    bundle is fetched/cached and verified BEFORE parsing.  The single-read
    invariant is maintained: the same ``index_bytes`` object is passed to
    both ``verifier.verify`` and ``parse_index`` — no second disk read.

    Arguments:
        url:         Index URL to fetch.  Supports ``http://``, ``https://``,
                     and ``file://`` schemes.
        cache_dir:   Directory where the cached ``*.index.kdl`` and sidecar
                     ``*.index.kdl.at``, ``*.index.kdl.bundle`` files are stored.
        http_get:    Injected transport for index bytes.  Receives the URL,
                     returns raw bytes.  On failure raises any ``Exception``.
        ttl_seconds: Cache TTL in seconds.  Pass ``DEFAULT_TTL_SECONDS`` for
                     the normative 24h value.
        now_unix:    Current time (unix seconds).  Injected for test
                     determinism; production callers pass ``int(time.time())``.
        config:      ``IndexTrustConfig`` carrying policy + trust_bundle +
                     expected_signer + max_age_seconds.  ``None`` disables the
                     trust gate (legacy callers / ``--no-index`` path).
        verifier:    ``IndexBundleVerifier`` implementation.  REQUIRED when
                     ``config`` is not None.  ``SigstoreVerifier()`` in
                     production; ``MockVerifier(result)`` in tests.
        bundle_http_get:
                     Injected transport for bundle bytes (separate from
                     ``http_get`` so per-URL mock state is independent).
                     Returns raw bytes; raises ``_BundleNotFound`` on 404.
        refresh:     When True, bypass cache TTL and force a fresh index+bundle
                     fetch (``--refresh-index``).
        index_history_policy:
                     ``"off" | "warn" | "strict"`` (registry-protocol §3.5.2)
                     — the append-only ratchet's own policy axis, orthogonal
                     to ``index-trust``. Runs on EVERY network-fetch path
                     (this function's State 2 body, and the bounded
                     crash-recovery refetch), never on a pure cache read.
                     Defaults to ``"off"`` (disabled) — production callers
                     (``load_default_index`` / ``cli.py``) pass the resolved
                     manifest/env policy explicitly; this default only
                     preserves this low-level function's pre-A2d behavior
                     for callers that don't opt in.

    Returns:
        Parsed ``Index``.

    Raises:
        ``MilpaError(MILPA_INDEX_UNREACHABLE)`` — network failure with no
        usable cache (state 4).
        ``MilpaError(TNG-INDEX-*)`` — trust gate failure under strict policy.
        ``MilpaError(TNG-INDEX-ROOT-MUTATED | TNG-INDEX-ROLLBACK |
        TNG-ENTRY-MUTATED)`` — append-only ratchet violation under
        ``index_history_policy="strict"``.
        ``MilpaError(TNG-INDEX-BASELINE-CORRUPT)`` — an existing baseline
        sidecar is unparseable, regardless of ``index_history_policy``
        (except ``"off"``, which never reads it).
        Any ``MilpaError(TNG-*)`` raised by ``parse_index`` — propagate unchanged.
    """
    from milpa.registry import parse_index  # local import to avoid circular at module level

    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_path_for(url, cache_dir)
    stamp_file = _stamp_path(cache_file)
    bundle_file = _bundle_path(cache_file)
    no_bundle_marker = _no_bundle_marker_path(cache_file)

    # Determine whether the trust gate is active.
    trust_active = config is not None and verifier is not None

    # -------------------------------------------------------------------------
    # State 1: Fresh cache (age < TTL) → serve without network.
    # When trust gate is active: crypto-verify on EVERY read; freshness NOT
    # re-asserted on pure cache reads (offline/air-gapped safety — spec §3.4.4 step 3).
    # -------------------------------------------------------------------------
    fetched_at = _read_stamp(stamp_file)
    if fetched_at is not None and not refresh:
        age = now_unix - fetched_at
        if age < ttl_seconds:
            index_bytes = cache_file.read_bytes()
            if trust_active:
                assert config is not None and verifier is not None  # type narrowing
                if bundle_file.is_file():
                    bundle_bytes_cached = bundle_file.read_bytes()
                    # Consistency check: empty bundle bytes = interrupted write.
                    if not _cache_bundle_looks_ok(bundle_bytes_cached, bundle_file):
                        _delete_bundle_sidecars(bundle_file, no_bundle_marker)
                        return _refetch_with_recovery(
                            url=url, cache_dir=cache_dir, cache_file=cache_file,
                            stamp_file=stamp_file, bundle_file=bundle_file,
                            no_bundle_marker=no_bundle_marker,
                            http_get=http_get, bundle_http_get=bundle_http_get,
                            config=config, verifier=verifier,
                            now_unix=now_unix, is_recovery=True,
                            index_history_policy=index_history_policy,
                        )
                    # is_network_fetch=False: freshness NOT re-asserted on cache reads.
                    _verify_and_enforce(
                        index_bytes=index_bytes,
                        bundle_bytes=bundle_bytes_cached,
                        config=config,
                        verifier=verifier,
                        index_url=url,
                        is_network_fetch=False,
                    )
                elif no_bundle_marker.is_file():
                    # Degraded mode: bundle transport previously returned 404 (RFC §7.2).
                    # Enforce BundleMissing per policy; the marker is preserved — this is
                    # NOT a crash state (H4 fix: the pre-fix code mis-classified this as
                    # crash → _cache_bundle_looks_ok(None, absent_file) → False → recovery).
                    from milpa.index_trust import BundleMissing, enforce_index_trust
                    enforce_index_trust(BundleMissing, config.policy, url)
                    # warn: execution continues to parse_index below.
                    # strict: enforce_index_trust raises; we never reach here.
                else:
                    # No bundle AND no degraded marker: pre-RFC cache or interrupted write.
                    # Trigger bounded crash recovery (one refetch).
                    _delete_bundle_sidecars(bundle_file, no_bundle_marker)
                    return _refetch_with_recovery(
                        url=url, cache_dir=cache_dir, cache_file=cache_file,
                        stamp_file=stamp_file, bundle_file=bundle_file,
                        no_bundle_marker=no_bundle_marker,
                        http_get=http_get, bundle_http_get=bundle_http_get,
                        config=config, verifier=verifier,
                        now_unix=now_unix, is_recovery=True,
                        index_history_policy=index_history_policy,
                    )
            try:
                return parse_index(index_bytes.decode("utf-8"))
            except UnicodeDecodeError as exc:
                # Non-UTF-8 index bytes (e.g. a tianguis encoding bug over a
                # validly-signed blob) → surface via index-parse error path.
                from milpa.errors import TNG_KDL_SYNTAX
                raise MilpaError(
                    TNG_KDL_SYNTAX,
                    f"index bytes from {url!r} are not valid UTF-8: {exc}",
                    url=url,
                ) from exc

    # -------------------------------------------------------------------------
    # State 2 / 3 / 4: Stale or missing → attempt to fetch.
    # -------------------------------------------------------------------------
    fetch_error: str | None = None
    fetched_bytes: bytes | None = None

    try:
        fetched_bytes = http_get(url)
    except Exception as exc:
        fetch_error = str(exc)

    if fetch_error is not None:
        # Network failed.
        if cache_file.is_file():
            # State 3: offline fallback — serve stale cache.
            # Warning MUST NOT contain a ``milpa-error:`` line (R3).
            print(
                f"[milpa] warning: failed to refresh index from {url!r} "
                f"({fetch_error}) — using cached (possibly out-of-date) index",
                file=sys.stderr,
            )
            index_bytes = cache_file.read_bytes()
            if trust_active:
                assert config is not None and verifier is not None  # type narrowing
                if bundle_file.is_file():
                    bundle_bytes_stale = bundle_file.read_bytes()
                    # Consistency check: empty bundle bytes = interrupted write.
                    if not _cache_bundle_looks_ok(bundle_bytes_stale, bundle_file):
                        # Cannot refetch — network is down.  Hard-fail.
                        _delete_bundle_sidecars(bundle_file, no_bundle_marker)
                        raise MilpaError(
                            MILPA_INDEX_UNREACHABLE,
                            f"failed to load index from {url!r}: {fetch_error} "
                            "(cache bundle missing/corrupt and network unavailable for recovery)",
                            url=url,
                        )
                    # is_network_fetch=False: stale offline fallback — no freshness.
                    _verify_and_enforce(
                        index_bytes=index_bytes,
                        bundle_bytes=bundle_bytes_stale,
                        config=config,
                        verifier=verifier,
                        index_url=url,
                        is_network_fetch=False,
                    )
                elif no_bundle_marker.is_file():
                    # Degraded mode: serve cached index under BundleMissing policy.
                    # Marker preserved; cannot refetch (network down) — not a crash state
                    # (H4 fix: pre-fix code mis-classified this as crash → hard-fail).
                    from milpa.index_trust import BundleMissing, enforce_index_trust
                    enforce_index_trust(BundleMissing, config.policy, url)
                    # warn: execution continues to parse_index below.
                    # strict: enforce_index_trust raises; we never reach here.
                else:
                    # No bundle AND no marker: crash state; network down, cannot recover.
                    _delete_bundle_sidecars(bundle_file, no_bundle_marker)
                    raise MilpaError(
                        MILPA_INDEX_UNREACHABLE,
                        f"failed to load index from {url!r}: {fetch_error} "
                        "(cache bundle missing/corrupt and network unavailable for recovery)",
                        url=url,
                    )
            try:
                return parse_index(index_bytes.decode("utf-8"))
            except UnicodeDecodeError as exc:
                from milpa.errors import TNG_KDL_SYNTAX
                raise MilpaError(
                    TNG_KDL_SYNTAX,
                    f"index bytes from {url!r} are not valid UTF-8: {exc}",
                    url=url,
                ) from exc

        # State 4: no usable cache — hard failure.
        raise MilpaError(
            MILPA_INDEX_UNREACHABLE,
            f"failed to load index from {url!r}: {fetch_error}",
            url=url,
        )

    assert fetched_bytes is not None  # type narrowing: fetch_error is None implies success

    # State 2: network fetch succeeded.
    # -------------------------------------------------------------------------
    # Fetch bundle sidecar (S5 trust gate) — BEFORE writing index to cache.
    # Atomic write order: bundle first, then index rename (RFC §7.2).
    # -------------------------------------------------------------------------
    fetched_bundle: bytes | None = None
    bundle_was_404 = False       # genuine HTTP 404 (_BundleNotFound)
    bundle_transport_error = False  # other transport failure (500, reset, etc.)

    if trust_active and bundle_http_get is not None:
        bundle_url = _get_bundle_url(url)
        try:
            fetched_bundle = bundle_http_get(bundle_url)
        except _BundleNotFound:
            bundle_was_404 = True
        except Exception:
            # Non-404 transport error: slug stays BUNDLE-MISSING (bytes never
            # arrived) but the .no-bundle degraded marker MUST NOT be written —
            # transient failures should not settle into degraded mode.
            bundle_transport_error = True

    # Verify BEFORE caching (is_network_fetch=True → freshness asserted).
    if trust_active:
        assert config is not None and verifier is not None  # type narrowing
        if bundle_was_404 or bundle_transport_error:
            # Bundle unavailable under strict: hard-fail; do NOT cache partial state.
            # Under warn: cache index; write degraded marker only on genuine 404.
            from milpa.index_trust import enforce_index_trust, BundleMissing
            if config.policy == "strict":
                enforce_index_trust(BundleMissing, config.policy, url)
                # strict raises in enforce_index_trust; we never reach here.
            else:
                # warn: proceed; marker written below (only for genuine 404).
                enforce_index_trust(BundleMissing, config.policy, url)
        else:
            _verify_and_enforce(
                index_bytes=fetched_bytes,
                bundle_bytes=fetched_bundle,
                config=config,
                verifier=verifier,
                index_url=url,
                is_network_fetch=True,  # freshness ASSERTED on network-fetch path
            )

    # -------------------------------------------------------------------------
    # Append-only ratchet gate (registry-protocol §3.5.2, RFC
    # registry-append-only.md §2) — runs regardless of index-trust (its own
    # `index-history` axis), AFTER Layer-1 verification succeeds and BEFORE
    # any cache mutation begins, including the bundle sidecar write below.
    # Parse-at-gate: an unparseable candidate raises here and NEVER reaches
    # the writes that follow, so a good cache is never clobbered. Under
    # `strict`, a ratchet violation also raises here — no bundle write, no
    # index write, no stamp advance (fail closed).
    # -------------------------------------------------------------------------
    gate_decision = _run_ratchet_gate(
        policy=index_history_policy,
        cache_file=cache_file,
        candidate_bytes=fetched_bytes,
        now_unix=now_unix,
        url=url,
    )

    # -------------------------------------------------------------------------
    # Atomic write: bundle sidecar first, then index rename (RFC §7.2).
    # -------------------------------------------------------------------------
    # Write bundle sidecar first so a reader that sees the index always has its bundle.
    if trust_active:
        assert config is not None  # type narrowing
        if fetched_bundle is not None and config.policy != "off":
            _atomic_write_bytes(bundle_file, fetched_bundle)
        elif bundle_was_404 and config.policy != "strict":
            # warn policy + genuine 404: write degraded marker.
            # Transient transport errors (bundle_transport_error) do NOT write the
            # marker — the next fresh-cache read should try to re-fetch the bundle
            # via crash-recovery rather than staying in degraded mode indefinitely.
            with contextlib.suppress(OSError):
                no_bundle_marker.write_bytes(b"")
            # Remove any stale bundle sidecar.
            with contextlib.suppress(OSError):
                bundle_file.unlink(missing_ok=True)
        # Under strict+bundle_was_404/bundle_transport_error: enforce_index_trust already raised.

    # Atomic write of the index (unique temp sibling + os.replace).
    _atomic_write_bytes(cache_file, fetched_bytes)

    # Record fetch time to the sidecar (governs freshness, not fs mtime).
    _write_stamp(stamp_file, now_unix)

    # Sticky-advance the ratchet baseline (only on a clean diff / TOFU —
    # write ordering steps 5-6, strictly after the index write above so the
    # baseline only ever reflects content actually served).
    _apply_ratchet_writes(cache_file, gate_decision, fetched_bytes)

    return gate_decision.index


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_bundle_url(index_url: str) -> str:
    """Return the bundle URL: ``MILPA_INDEX_BUNDLE_URL`` override or derived URL."""
    override = os.environ.get("MILPA_INDEX_BUNDLE_URL", "").strip()
    return override if override else derive_bundle_url(index_url)


def _cache_bundle_looks_ok(bundle_bytes: bytes | None, bundle_file: Path) -> bool:
    """Return True if the bundle state is consistent (present-and-non-empty, or file absent).

    Returns False when:
    - The caller expected a bundle file but it's gone (interrupted write).
    - The bundle file exists but reads as empty bytes.
    This triggers crash recovery (RFC §7.2).
    """
    if bundle_bytes is None and not bundle_file.is_file():
        # No bundle file, and no degraded-marker was found either.  Could be a
        # pre-RFC cache or an interrupted write.  Caller checks which.
        return False
    if bundle_bytes is not None and len(bundle_bytes) == 0:
        return False  # Empty bundle sidecar: interrupted write.
    return True


def _delete_bundle_sidecars(bundle_file: Path, no_bundle_marker: Path) -> None:
    """Delete the bundle sidecar and degraded marker (RFC §7.2 crash recovery)."""
    with contextlib.suppress(OSError):
        bundle_file.unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        no_bundle_marker.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Append-only ratchet gate (registry-protocol §3.5.2, RFC
# registry-append-only.md §2/§3, slice A2d).  ``index_ratchet_seam.py`` is
# pure computation (no I/O); this module owns every read/write of the
# baseline sidecar pair, mirroring how it already owns the bundle/index/
# stamp sidecars.
# ---------------------------------------------------------------------------


def _run_ratchet_gate(
    *,
    policy: str,
    cache_file: Path,
    candidate_bytes: bytes,
    now_unix: int,
    url: str,
) -> "GateDecision":
    """Parse-at-gate + the append-only ratchet check.  Reads the baseline
    sidecar pair (when *policy* is not ``"off"``); performs NO writes.

    Raises ``MilpaError`` — decode/parse failure on the candidate (any
    policy), ``TNG-INDEX-BASELINE-CORRUPT`` (any policy except ``"off"``),
    or the primary violation's slug under ``"strict"`` — in every case
    BEFORE the caller has written anything to the cache.
    """
    from milpa.errors import TNG_KDL_SYNTAX
    from milpa.index_ratchet_seam import BaselineMeta, evaluate_gate, parse_baseline_meta

    try:
        candidate_text = candidate_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MilpaError(
            TNG_KDL_SYNTAX,
            f"index bytes from {url!r} are not valid UTF-8: {exc}",
            url=url,
        ) from exc

    baseline_path = _baseline_path(cache_file)
    meta_path = _baseline_meta_path(cache_file)

    baseline_text: str | None = None
    if policy != "off" and baseline_path.is_file():
        raw = baseline_path.read_bytes()
        try:
            baseline_text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            from milpa.errors import TNG_INDEX_BASELINE_CORRUPT
            raise MilpaError(
                TNG_INDEX_BASELINE_CORRUPT,
                f"baseline sidecar at {baseline_path} is not valid UTF-8: {exc}; "
                "re-establish the trust anchor via `milpa index accept`",
            ) from exc

    existing_meta = BaselineMeta()
    if policy != "off" and meta_path.is_file():
        # .meta is advisory (§3.5.2 NORMATIVE): a decode failure here is
        # self-healing (treated as unset), never an error — mirrors
        # parse_baseline_meta's own try/except for KDL-level corruption.
        try:
            meta_text = meta_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            meta_text = ""
        existing_meta = parse_baseline_meta(meta_text)

    return evaluate_gate(
        policy=policy,
        candidate_text=candidate_text,
        baseline_text=baseline_text,
        existing_meta=existing_meta,
        now_unix=now_unix,
        url=url,
    )


def _apply_ratchet_writes(cache_file: Path, decision: "GateDecision", candidate_bytes: bytes) -> None:
    """Write the baseline sidecar pair per *decision* (write ordering steps
    5-6 — MUST be called strictly after the index file write), then print
    the pending warn diagnostic (if any).

    Writes: TOFU establishment and clean-diff sticky-advance always set
    ``advance``; a ``warn``-dirty new-digest report sets only ``new_meta``.
    Neither write fires for ``"off"`` policy or a recurring warn (both leave
    ``advance`` false and ``new_meta`` ``None``).

    Diagnostic: ``decision.warn_message`` (set on EVERY warn-dirty outcome,
    recurring or not — ``index_ratchet_seam.evaluate_gate`` stays pure on
    this path and hands the pre-formatted text back here) is printed to
    stderr AFTER the writes above, per its own docstring and the
    warn-serves-the-new-index convention elsewhere in this module. This is
    the ONE place production code prints it — evaluate_gate itself no
    longer does."""
    if decision.advance:
        # Full copy of the candidate bytes ACTUALLY SERVED (never a
        # re-serialization) — §3.5.2 NORMATIVE (write ordering).
        _atomic_write_bytes(_baseline_path(cache_file), candidate_bytes)
    if decision.new_meta is not None:
        _atomic_write_bytes(
            _baseline_meta_path(cache_file), decision.new_meta.render().encode("utf-8")
        )
    if decision.warn_message is not None:
        print(decision.warn_message, file=sys.stderr)


def _refetch_with_recovery(
    *,
    url: str,
    cache_dir: Path,
    cache_file: Path,
    stamp_file: Path,
    bundle_file: Path,
    no_bundle_marker: Path,
    http_get: HttpGet,
    bundle_http_get: "BundleHttpGet | None",
    config: "IndexTrustConfig",
    verifier: "IndexBundleVerifier",
    now_unix: int,
    is_recovery: bool,
    index_history_policy: str = "off",
) -> "Index":
    """Bounded crash-recovery refetch (RFC §7.2).

    Called when a CACHE READ detects a missing/corrupt bundle sidecar (interrupted
    write scenario).  Performs ONE network refetch.  If the refetch ALSO fails
    verification, hard-fail regardless of policy (active-adversary signal).

    A candidate arriving via this path is exactly as untrusted as an
    ordinary State-2 fetch — the append-only ratchet gate (registry-protocol
    §3.5.2) runs here identically, after Layer-1 verification succeeds and
    before any write, so forced cache corruption can't smuggle a history
    rewrite past the ratchet.
    """
    # Attempt one recovery refetch.
    fetch_error: str | None = None
    fetched_bytes: bytes | None = None

    try:
        fetched_bytes = http_get(url)
    except Exception as exc:
        fetch_error = str(exc)

    if fetch_error is not None:
        raise MilpaError(
            MILPA_INDEX_UNREACHABLE,
            f"crash-recovery refetch failed for {url!r}: {fetch_error}",
            url=url,
        )

    assert fetched_bytes is not None

    # Fetch bundle for recovery path.
    fetched_bundle: bytes | None = None
    bundle_was_404 = False       # genuine HTTP 404 (_BundleNotFound)
    bundle_transport_error = False  # other transport failure (500, reset, etc.)

    if bundle_http_get is not None:
        bundle_url = _get_bundle_url(url)
        try:
            fetched_bundle = bundle_http_get(bundle_url)
        except _BundleNotFound:
            bundle_was_404 = True
        except Exception:
            bundle_transport_error = True

    # Verify recovery fetch (is_network_fetch=True — freshness asserted).
    if bundle_was_404 or bundle_transport_error:
        from milpa.index_trust import enforce_index_trust, BundleMissing
        # Second consecutive miss: hard-fail regardless of policy (RFC §7.2).
        if is_recovery:
            raise MilpaError(
                MILPA_INDEX_UNREACHABLE,
                f"crash-recovery: second consecutive bundle mismatch for {url!r} — "
                "hard-fail (active adversary signal per RFC §7.2)",
                url=url,
            )
        enforce_index_trust(BundleMissing, config.policy, url)
    else:
        # On recovery, ALWAYS hard-fail if verification fails (not policy-gated).
        from milpa.index_trust import (
            BundleMissing as _BM, Trusted,
            enforce_index_trust, VerificationResult,
        )
        max_age = config.max_age_seconds  # recovery = network fetch → freshness checked
        result = verifier.verify(
            index_bytes=fetched_bytes,
            bundle_bytes=fetched_bundle if fetched_bundle is not None else b"",
            trust_bundle=config.trust_bundle,
            expected_signer=config.expected_signer,
            max_age_seconds=max_age,
        )
        if result is not Trusted:
            # Second consecutive mismatch after a recovery refetch: hard-fail.
            raise MilpaError(
                MILPA_INDEX_UNREACHABLE,
                f"crash-recovery: verification still failed after refetch for {url!r} "
                f"(result={result.value!r}) — hard-fail (active adversary signal per RFC §7.2)",
                url=url,
            )

    # Append-only ratchet gate — after Layer-1 verification succeeds, before
    # any write (registry-protocol §3.5.2; same placement as the ordinary
    # State-2 body in ``load_index``). Parse-at-gate + strict-violation both
    # raise here, before "Write recovered state" below runs.
    gate_decision = _run_ratchet_gate(
        policy=index_history_policy,
        cache_file=cache_file,
        candidate_bytes=fetched_bytes,
        now_unix=now_unix,
        url=url,
    )

    # Write recovered state.
    if fetched_bundle is not None:
        _atomic_write_bytes(bundle_file, fetched_bundle)
    elif bundle_was_404 and config.policy != "strict":
        # Genuine 404: write degraded marker so TTL governs re-fetch cadence.
        # Transient transport errors (bundle_transport_error) do NOT write the
        # marker — let the next read try crash-recovery refetch instead.
        with contextlib.suppress(OSError):
            no_bundle_marker.write_bytes(b"")
        with contextlib.suppress(OSError):
            bundle_file.unlink(missing_ok=True)

    _atomic_write_bytes(cache_file, fetched_bytes)
    _write_stamp(stamp_file, now_unix)
    _apply_ratchet_writes(cache_file, gate_decision, fetched_bytes)

    return gate_decision.index


# ---------------------------------------------------------------------------
# Default production HTTP transport (handles file:// too)
# ---------------------------------------------------------------------------


def urllib_http_get(url: str) -> bytes:
    """Production ``HttpGet`` transport using ``urllib``.

    Supports ``http://``, ``https://``, and ``file://`` schemes.
    Returns raw bytes (index_cache.py now uses bytes throughout).
    On any error raises an exception whose ``str()`` is used in the
    ``MILPA-INDEX-UNREACHABLE`` message.
    """
    with urllib.request.urlopen(url) as resp:  # noqa: S310 — URL is user-controlled; known risk
        return resp.read()


def urllib_bundle_http_get(url: str) -> bytes:
    """Production ``BundleHttpGet`` transport using ``urllib``.

    Raises ``_BundleNotFound`` on HTTP 404; raises other ``Exception`` on
    other network errors.
    """
    try:
        with urllib.request.urlopen(url) as resp:  # noqa: S310
            return resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise _BundleNotFound(f"bundle not found at {url!r}: HTTP 404") from exc
        raise


# ---------------------------------------------------------------------------
# High-level convenience: load_default_index
# ---------------------------------------------------------------------------


def load_default_index(
    *,
    cache_dir: Path | None = None,
    http_get: HttpGet | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now_unix: int | None = None,
    config: "IndexTrustConfig | None" = None,
    verifier: "IndexBundleVerifier | None" = None,
    bundle_http_get: "BundleHttpGet | None" = None,
    refresh: bool = False,
    index_history_policy: str = "off",
) -> "Index":
    """Load the index from ``MILPA_INDEX_URL`` (or the default URL).

    Convenience wrapper over ``load_index`` for production callers:

    - ``cache_dir``:   defaults to the XDG cache dir.
    - ``http_get``:    defaults to ``urllib_http_get`` (returns bytes).
    - ``ttl_seconds``: defaults to ``DEFAULT_TTL_SECONDS``.
    - ``now_unix``:    defaults to the real wall clock (``int(time.time())``).
    - ``config``:      ``IndexTrustConfig`` for the trust gate; ``None`` disables.
    - ``verifier``:    ``IndexBundleVerifier``; REQUIRED when config is not None.
    - ``bundle_http_get``: defaults to ``urllib_bundle_http_get`` when config set.
    - ``refresh``:     force re-fetch bypassing TTL (``--refresh-index``).
    - ``index_history_policy``: the append-only ratchet's policy axis
      (``"off" | "warn" | "strict"``, registry-protocol §3.5.2); orthogonal
      to ``config``/``verifier`` (index-trust). Defaults to ``"off"``;
      ``cli.py`` passes the resolved manifest/env policy.
    """
    import time

    effective_bundle_get = bundle_http_get
    if config is not None and effective_bundle_get is None:
        effective_bundle_get = urllib_bundle_http_get

    return load_index(
        url=index_url_from_env(),
        cache_dir=cache_dir if cache_dir is not None else _default_cache_dir(),
        http_get=http_get if http_get is not None else urllib_http_get,
        ttl_seconds=ttl_seconds,
        now_unix=now_unix if now_unix is not None else int(time.time()),
        config=config,
        verifier=verifier,
        bundle_http_get=effective_bundle_get,
        refresh=refresh,
        index_history_policy=index_history_policy,
    )
