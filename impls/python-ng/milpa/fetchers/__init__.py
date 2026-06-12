"""milpa.fetchers — pluggable fetcher abstraction.

Public surface:
  - ``Provenance``        — base descriptor; carries ``cas_admissible``
  - ``ProvenanceReceipt`` — abstract; concrete subclasses record transport evidence
  - ``FetchResult``       — uniform registry output (name + path + identity + receipt)
  - ``Fetcher``           — ABC for transport implementations
  - ``FetcherRegistry``   — unique-match dispatch + post-fetch identity computation
  - ``FetcherConfig``     — v1 shape per plugin-contract.md §7.1
  - ``FetchError``        — raised on fetch failures
  - ``CasAdmittingFetcher`` — wraps FetcherRegistry with CAS gating
  - ``mocked_registry``   — test/conformance factory for all four mocked fetchers
  - ``url_key``           — SSOT fixture-dir key encoder

  Concrete Provenance / Receipt types (SSOT — defined in transport modules):
  - ``GitProvenance`` / ``GitReceipt``
  - ``TarballProvenance`` / ``TarballReceipt``
  - ``LocalProvenance`` / ``LocalReceipt``
  - ``OciProvenance`` / ``OciReceipt``

  Concrete fetchers:
  - ``GitFetcher``, ``TarballFetcher``, ``LocalFetcher``, ``OciFetcher``

  Safe-extract utilities:
  - ``extract_tar``, ``Limits``

  - ``build_registry()``          — production registry with built-in fetchers + plugins
  - ``_build_default_registry()`` — bare built-ins only (no plugin discovery)

See docs/rfc-python-clean-room-rewrite.md slices 7a + 7e,
    spec/plugin-contract.md for the plugin protocol.
"""

from __future__ import annotations

import importlib.metadata
import logging
from collections.abc import Callable

from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.git import GitFetcher, GitProvenance, GitReceipt
from milpa.fetchers.local import LocalFetcher, LocalProvenance, LocalReceipt
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.fetchers.oci import OciFetcher, OciProvenance, OciReceipt
from milpa.fetchers.safe_extract import Limits, extract_tar
from milpa.fetchers.tarball import TarballFetcher, TarballProvenance, TarballReceipt
from milpa.fetchers.types import (
    FETCH_UNCODED_INVARIANTS,
    Fetcher,
    FetcherConfig,
    FetcherRegistry,
    FetchError,
    FetchResult,
    Provenance,
    ProvenanceReceipt,
)

_log = logging.getLogger(__name__)

_ENTRY_POINT_GROUP = "milpa.fetchers"

# ---------------------------------------------------------------------------
# Built-in factory seam — one (config: FetcherConfig) -> Fetcher per kind
# ---------------------------------------------------------------------------
# 7d-2 (safe_extract) is standalone and NOT registered here — it has no
# Fetcher protocol.  CasAdmittingFetcher and mocked fetchers are NOT
# built-ins (wrapper / test-infra respectively).
_BUILTIN_FACTORIES: list[Callable[[FetcherConfig], Fetcher]] = [
    lambda _c: GitFetcher(),       # 7d-1
    lambda _c: TarballFetcher(),   # 7d-3
    lambda _c: LocalFetcher(),     # 7d-4
    lambda _c: OciFetcher(),       # 7d-5
]


def _build_default_registry() -> FetcherRegistry:
    """Return a ``FetcherRegistry`` pre-populated with the four built-in fetchers.

    No plugin discovery.  Useful in tests that need real fetchers but want to
    bypass the entry-point machinery.
    """
    registry = FetcherRegistry()
    cfg = FetcherConfig()
    for factory in _BUILTIN_FACTORIES:
        registry.register(factory(cfg))
    return registry


def build_registry() -> FetcherRegistry:
    """Build a ``FetcherRegistry`` with built-in fetchers plus discovered plugins.

    Entry-point group: ``milpa.fetchers``.  Each entry point must resolve to a
    one-arg factory ``(config: FetcherConfig) -> Fetcher`` (plugin-contract.md §7).

    Exclusive dispatch is preserved: a plugin claiming a built-in's provenance kind
    will trigger the ambiguity error at dispatch time (§5 NORMATIVE).

    Plugin loading failures are logged as warnings and the plugin is skipped;
    a missing plugin is not a fatal error (defense-in-depth for deployment).

    Built-in fetchers are registered before plugins, in the order listed in
    ``_BUILTIN_FACTORIES`` (readability order; dispatch is exclusive so order
    never resolves ambiguity).
    """
    registry = FetcherRegistry()
    cfg = FetcherConfig()  # v1: empty config passed to every factory

    # Register built-ins first (seam — populated as 7d-* slices land).
    for factory in _BUILTIN_FACTORIES:
        fetcher = factory(cfg)
        registry.register(fetcher)
        _log.debug("milpa.fetchers: registered built-in %s", type(fetcher).__name__)

    # Discover and register third-party plugins via entry points.
    eps = importlib.metadata.entry_points(group=_ENTRY_POINT_GROUP)
    for ep in eps:
        try:
            factory_fn = ep.load()
            fetcher = factory_fn(cfg)
            registry.register(fetcher)
            _log.debug(
                "milpa.fetchers: registered plugin %r → %s",
                ep.name,
                type(fetcher).__name__,
            )
        except Exception as exc:
            _log.warning(
                "milpa.fetchers: failed to load plugin %r from %r: %s — skipping",
                ep.name,
                ep.value,
                exc,
            )

    return registry


__all__ = [
    # Base types
    "FETCH_UNCODED_INVARIANTS",
    "FetchError",
    "FetcherConfig",
    "FetcherRegistry",
    "FetchResult",
    "Fetcher",
    "Provenance",
    "ProvenanceReceipt",
    # CAS wrapper
    "CasAdmittingFetcher",
    # Concrete Provenance + Receipt types (SSOT in transport modules)
    "GitProvenance",
    "GitReceipt",
    "TarballProvenance",
    "TarballReceipt",
    "LocalProvenance",
    "LocalReceipt",
    "OciProvenance",
    "OciReceipt",
    # Concrete fetchers
    "GitFetcher",
    "TarballFetcher",
    "LocalFetcher",
    "OciFetcher",
    # Safe-extract utilities
    "extract_tar",
    "Limits",
    # Mocked-transport helpers
    "mocked_registry",
    "url_key",
    # Registry factories
    "build_registry",
    "_build_default_registry",
]
