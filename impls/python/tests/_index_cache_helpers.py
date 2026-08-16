"""Test-only helper: bare-``Index`` unwrap over ``load_index_gated``.

Mirrors the Rust impl's pattern (a PRIVATE test helper inside
``index_cache_tests.rs``) — the production gate module
(``milpa/index_cache.py``) exposes ONLY ``load_index_gated`` / ``acquire`` /
``load_default_index``, all of which return or consume ``GatedIndex``. The
low-level cache-mechanics test suites (``test_index_cache.py``,
``test_index_history_ratchet.py``) predate the gate and only ever assert on
bare ``Index`` fields (``.packages``) — never the trust/gate axis — so this
helper lets them keep doing that without threading a ``GatedIndex`` through
~150 call sites.

NOT part of the resolver-consumption boundary. Production code must go
through ``load_default_index`` / ``load_index_gated`` / ``acquire`` instead —
never this function.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from milpa.index_cache import BundleHttpGet, HttpGet, load_index_gated

if TYPE_CHECKING:
    from milpa.index_trust import IndexBundleVerifier, IndexTrustConfig
    from milpa.registry import Index


def load_index(
    url: str,
    cache_dir: Path,
    http_get: HttpGet,
    ttl_seconds: int,
    now_unix: int,
    config: "IndexTrustConfig | None" = None,
    verifier: "IndexBundleVerifier | None" = None,
    bundle_http_get: "BundleHttpGet | None" = None,
    refresh: bool = False,
    index_history_policy: str = "off",
) -> "Index":
    """Fetch + cache + parse the ``index.kdl`` at *url*; returns the bare
    ``Index`` (unwrapped). See ``load_index_gated`` for the full contract —
    this is a thin ``.index`` unwrap over it, kept for the low-level
    cache-mechanics test suites."""
    return load_index_gated(
        url,
        cache_dir,
        http_get,
        ttl_seconds,
        now_unix,
        config=config,
        verifier=verifier,
        bundle_http_get=bundle_http_get,
        refresh=refresh,
        index_history_policy=index_history_policy,
    ).index
