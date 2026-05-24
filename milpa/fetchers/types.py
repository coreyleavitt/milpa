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

import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from ..identity import compute_content_hash

if TYPE_CHECKING:
    from ..cas import CAStore


@dataclass(frozen=True)
class Provenance:
    """Base class for provenance descriptors. Subclasses carry
    transport-specific fields (URL, ref, digest, path, etc.).

    `cas_admissible` (class attribute, not dataclass field) controls
    whether the fetched bytes get admitted to the global content-
    addressed store (#35). True for immutable sources (git, tarball —
    bytes are pinned by ref or hash). False for editable sources
    (local paths — admission would silently freeze user edits).
    Subclasses override by re-declaring the class attribute."""

    cas_admissible: ClassVar[bool] = True


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
    identity: str            # multihash-encoded (#34); was content_hash (#33 rename)
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

    def __init__(self, store: "CAStore | None" = None) -> None:
        self._fetchers: list[Fetcher] = []
        self._store = store

    def register(self, fetcher: Fetcher) -> None:
        self._fetchers.append(fetcher)

    def fetch(
        self,
        name: str,
        provenance: Provenance,
        *,
        dest: Path,
    ) -> FetchResult:
        fetcher = self._select(provenance)
        if self._store is None or not provenance.cas_admissible:
            # No CAS, or this provenance opts out (editable source —
            # local path, workspace member). Fetch directly to dest.
            receipt = fetcher.fetch(name, provenance, dest=dest)
            identity = compute_content_hash(dest)
            return FetchResult(
                name=name, path=dest, identity=identity, receipt=receipt,
            )

        # CAS path: fetch into a scratch dir under the store, compute
        # identity, admit, then link dest → CAS entry. Scratch lives
        # under the CAS root so rename(scratch, canonical) stays
        # intra-filesystem (atomic).
        scratch_root = self._store.root / "_scratch"
        scratch_root.mkdir(parents=True, exist_ok=True)
        scratch = scratch_root / uuid.uuid4().hex
        try:
            receipt = fetcher.fetch(name, provenance, dest=scratch)
            identity = compute_content_hash(scratch)
            canonical = self._store.admit(scratch, identity)
        except BaseException:
            if scratch.exists():
                shutil.rmtree(scratch, ignore_errors=True)
            raise

        dest.parent.mkdir(parents=True, exist_ok=True)
        self._store.link(identity, dest)
        return FetchResult(
            name=name, path=dest, identity=identity, receipt=receipt,
        )

    def _select(self, provenance: Provenance) -> "Fetcher":
        for f in self._fetchers:
            if f.can_handle(provenance):
                return f
        raise FetchError(
            f"no registered fetcher handles provenance kind "
            f"{type(provenance).__name__}"
        )
