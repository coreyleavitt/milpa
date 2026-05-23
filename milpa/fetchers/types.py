"""Pluggable fetcher abstraction — types and registry.

Per docs/rfc-pluggable-fetchers.md. Three core types:

  - `Provenance`     : descriptor for how to obtain a source tree.
                       Subclasses carry transport-specific fields
                       (GitProvenance.url, GitProvenance.ref, future
                       TarballProvenance.url + .expected_sha256, etc.).
  - `ProvenanceReceipt`: per-fetch record the transport produced
                       (GitReceipt.commit_sha, future
                       TarballReceipt.archive_sha256, etc.). Descriptive
                       metadata; NOT identity.
  - `FetchResult`    : what callers see — name + path + content_hash
                       (IDENTITY, milpa-computed) + receipt.

## The load-bearing invariant

Identity (sha256 of the materialized source tree) is computed by the
*registry*, never by individual fetchers. Fetchers return only a
ProvenanceReceipt; the registry walks the dest tree itself and produces
the content_hash. This means no fetcher — buggy, malicious, or
mistaken — can influence the identity claim. See
test_fetchers.test_registry_computes_identity_externally for the pin.

This is sharper than the RFC's sketched signature (which returned
FetchResult from the fetcher); the tightened types enforce the
invariant structurally.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..identity import compute_content_hash


@dataclass(frozen=True)
class Provenance:
    """Base class for provenance descriptors. Subclasses carry
    transport-specific fields (URL, ref, digest, path, etc.)."""


@dataclass(frozen=True)
class ProvenanceReceipt:
    """Base class for per-fetch receipts. Subclasses record what the
    transport actually delivered (commit SHA, archive hash, etc.).
    Receipts are *descriptive* — they do NOT establish identity."""


@dataclass(frozen=True)
class FetchResult:
    """The uniform output of any fetch.

    `content_hash` is milpa-computed (sha256 of the source tree); the
    fetcher never gets a chance to populate it. `receipt` is whatever
    the transport recorded about the fetch operation itself.
    """
    name: str
    path: Path
    content_hash: str
    receipt: ProvenanceReceipt


class FetchError(Exception):
    """Raised when a fetch cannot complete or no fetcher can handle a
    given provenance kind."""


@runtime_checkable
class Fetcher(Protocol):
    """A transport-specific source-tree producer.

    `fetch` materializes the tree at `dest/` and returns the
    transport-specific ProvenanceReceipt. It must NOT return identity
    — identity is the registry's job, computed post-fetch from `dest`.
    """

    def can_handle(self, p: Provenance) -> bool: ...
    def fetch(self, name: str, p: Provenance, *, dest: Path) -> ProvenanceReceipt: ...


class FetcherRegistry:
    """Dispatches a Provenance to the first registered Fetcher whose
    `can_handle` accepts it, then computes identity externally and
    wraps the receipt into a FetchResult.

    Order of registration matters: first match wins. A production setup
    pre-registers the built-in fetchers (GitFetcher today); tests can
    construct empty registries for isolation.
    """

    def __init__(self) -> None:
        self._fetchers: list[Fetcher] = []

    def register(self, fetcher: Fetcher) -> None:
        self._fetchers.append(fetcher)

    def fetch(
        self,
        name: str,
        provenance: Provenance,
        *,
        dest: Path,
    ) -> FetchResult:
        for f in self._fetchers:
            if f.can_handle(provenance):
                receipt = f.fetch(name, provenance, dest=dest)
                content_hash = compute_content_hash(dest)
                return FetchResult(
                    name=name,
                    path=dest,
                    content_hash=content_hash,
                    receipt=receipt,
                )
        raise FetchError(
            f"no registered fetcher handles provenance kind "
            f"{type(provenance).__name__}"
        )
