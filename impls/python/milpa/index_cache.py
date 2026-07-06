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

Crash recovery (RFC §7.2 — bounded):
  On a cache READ, a digest-mismatch or missing bundle sidecar → delete both
  sidecars + refetch ONCE.  If the refetch ALSO fails verification → hard-fail
  regardless of policy (active-adversary signal).

``MILPA_INDEX_URL``, when set to a non-empty string, overrides the default
index URL for every index-fetching operation in that invocation.  Supports
the ``file://`` scheme so air-gapped / harness deployments can substitute a
private or local index (``cli-contract.md`` §8.1 NORMATIVE).

Cache writes are atomic: write bundle sidecar first, then atomic-rename index
file.  Concurrent readers that observe a half-written pair trigger crash-recovery
(digest mismatch → single bounded refetch), which is safe and self-correcting.

Spec authority: ``spec/registry-protocol.md`` §6; ``spec/cli-contract.md`` §8;
``docs/rfc-registry-trust-federation.md`` §4, §6.5, §7.
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

from milpa.errors import MILPA_INDEX_UNREACHABLE, MilpaError

if TYPE_CHECKING:
    from milpa.index_trust import IndexBundleVerifier, IndexTrustConfig
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
    parsed = urlparse(index_url)
    # Append .bundle to the path component only.
    new_path = parsed.path + ".bundle"
    # Reattach query and fragment (if any).
    return urlunparse(parsed._replace(path=new_path))


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

    Returns:
        Parsed ``Index``.

    Raises:
        ``MilpaError(MILPA_INDEX_UNREACHABLE)`` — network failure with no
        usable cache (state 4).
        ``MilpaError(TNG-INDEX-*)`` — trust gate failure under strict policy.
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

    # Atomic write of the index (temp sibling + os.replace).
    tmp_file = cache_file.with_suffix(f".kdl.tmp.{now_unix}")
    try:
        tmp_file.write_bytes(fetched_bytes)
        os.replace(tmp_file, cache_file)
    except OSError:
        with contextlib.suppress(OSError):
            tmp_file.unlink(missing_ok=True)
        raise

    # Record fetch time to the sidecar (governs freshness, not fs mtime).
    _write_stamp(stamp_file, now_unix)

    try:
        return parse_index(fetched_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        from milpa.errors import TNG_KDL_SYNTAX
        raise MilpaError(
            TNG_KDL_SYNTAX,
            f"index bytes from {url!r} are not valid UTF-8: {exc}",
            url=url,
        ) from exc


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
) -> "Index":
    """Bounded crash-recovery refetch (RFC §7.2).

    Called when a CACHE READ detects a missing/corrupt bundle sidecar (interrupted
    write scenario).  Performs ONE network refetch.  If the refetch ALSO fails
    verification, hard-fail regardless of policy (active-adversary signal).
    """
    from milpa.registry import parse_index

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

    tmp_file = cache_file.with_suffix(f".kdl.tmp.recovery.{now_unix}")
    try:
        tmp_file.write_bytes(fetched_bytes)
        os.replace(tmp_file, cache_file)
    except OSError:
        with contextlib.suppress(OSError):
            tmp_file.unlink(missing_ok=True)
        raise

    _write_stamp(stamp_file, now_unix)

    try:
        return parse_index(fetched_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        from milpa.errors import TNG_KDL_SYNTAX
        raise MilpaError(
            TNG_KDL_SYNTAX,
            f"index bytes from {url!r} are not valid UTF-8: {exc}",
            url=url,
        ) from exc


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically (sibling tmp + os.replace)."""
    tmp = Path(str(path) + ".tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise


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
    )
