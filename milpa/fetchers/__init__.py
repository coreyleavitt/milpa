"""Pluggable fetcher abstraction.

Public surface:
  - `FetcherRegistry` — dispatches Provenance to Fetcher, computes identity
  - `Provenance` / `ProvenanceReceipt` — base classes for transports
  - `FetchResult` — uniform fetch output
  - `Fetcher` — protocol for transport implementations
  - `FetchError` — raised on fetch failures + unhandled provenance kinds

  - `default_registry` — module-global registry with built-in fetchers
    (GitFetcher today). Production code uses this; tests construct
    isolated FetcherRegistry instances.

See docs/rfc-pluggable-fetchers.md for the design.
"""

from .git import GitFetcher, GitProvenance, GitReceipt
from .local import LocalFetcher, LocalProvenance, LocalReceipt
from .tarball import TarballFetcher, TarballProvenance, TarballReceipt
from .types import (
    FetcherRegistry,
    FetchError,
    FetchResult,
    Fetcher,
    Provenance,
    ProvenanceReceipt,
)


default_registry = FetcherRegistry()
default_registry.register(GitFetcher())
default_registry.register(LocalFetcher())
default_registry.register(TarballFetcher())


__all__ = [
    "Fetcher",
    "FetchError",
    "FetchResult",
    "FetcherRegistry",
    "GitFetcher",
    "GitProvenance",
    "GitReceipt",
    "LocalFetcher",
    "LocalProvenance",
    "LocalReceipt",
    "Provenance",
    "ProvenanceReceipt",
    "TarballFetcher",
    "TarballProvenance",
    "TarballReceipt",
    "default_registry",
]
