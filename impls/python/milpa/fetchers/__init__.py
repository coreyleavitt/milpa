"""Pluggable fetcher abstraction.

Public surface:
  - `FetcherRegistry` — dispatches Provenance to Fetcher, computes identity
  - `Provenance` / `ProvenanceReceipt` — base classes for transports
  - `FetchResult` — uniform fetch output
  - `Fetcher` — protocol for transport implementations
  - `FetchError` — raised on fetch failures + unhandled provenance kinds
  - `FetcherConfig` — config struct passed to every plugin factory

  - `default_registry` — module-global registry with built-in fetchers
    pre-registered first, then plugins discovered via the
    `milpa.fetchers` entry-point group. Production code uses this;
    tests construct isolated FetcherRegistry instances.

See docs/rfc-pluggable-fetchers.md for the design and
spec/plugin-contract.md for the plugin protocol.
"""

import importlib.metadata
import logging

from ..cas import default_store
from .git import GitFetcher, GitProvenance, GitReceipt
from .local import LocalFetcher, LocalProvenance, LocalReceipt
from .oci import OciFetcher, OciProvenance, OciReceipt
from .tarball import TarballFetcher, TarballProvenance, TarballReceipt
from .types import (
    FetcherConfig,
    FetcherRegistry,
    FetchError,
    FetchResult,
    Fetcher,
    Provenance,
    ProvenanceReceipt,
)

_log = logging.getLogger(__name__)

_ENTRY_POINT_GROUP = "milpa.fetchers"


def _build_default_registry() -> FetcherRegistry:
    """Build the default registry: built-ins first, then discovered plugins.

    Entry-point group: ``milpa.fetchers``.  Each entry point must resolve
    to a one-arg factory ``(config: FetcherConfig) -> Fetcher``.  Exclusive
    dispatch is preserved — a plugin claiming a built-in's provenance kind
    will trigger the ambiguity error at dispatch time (spec §5).
    """
    registry = FetcherRegistry(store=default_store())

    # Built-ins registered first (readability order; dispatch is exclusive
    # so order never resolves ambiguity).
    registry.register(GitFetcher())
    registry.register(LocalFetcher())
    registry.register(TarballFetcher())
    # OCI last for readable specificity order.
    registry.register(OciFetcher())

    # Discover and register plugins via entry points.
    cfg = FetcherConfig()  # v1: empty config, passed to every factory
    eps = importlib.metadata.entry_points(group=_ENTRY_POINT_GROUP)
    for ep in eps:
        try:
            factory = ep.load()
            fetcher = factory(cfg)
            registry.register(fetcher)
            _log.debug("milpa.fetchers: registered plugin %r → %s", ep.name, type(fetcher).__name__)
        except Exception as exc:
            _log.warning(
                "milpa.fetchers: failed to load plugin %r from %r: %s — skipping",
                ep.name, ep.value, exc,
            )

    return registry


default_registry = _build_default_registry()


__all__ = [
    "Fetcher",
    "FetcherConfig",
    "FetchError",
    "FetchResult",
    "FetcherRegistry",
    "GitFetcher",
    "GitProvenance",
    "GitReceipt",
    "LocalFetcher",
    "LocalProvenance",
    "LocalReceipt",
    "OciFetcher",
    "OciProvenance",
    "OciReceipt",
    "Provenance",
    "ProvenanceReceipt",
    "TarballFetcher",
    "TarballProvenance",
    "TarballReceipt",
    "default_registry",
]
