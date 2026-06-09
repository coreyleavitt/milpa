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
import sys
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from ..fsutil import clear_dest
from ..identity import compute_content_hash

if TYPE_CHECKING:
    from ..cas import CAStore


@dataclass(frozen=True)
class FetcherConfig:
    """Configuration passed to every plugin factory.

    v1 shape (spec §7.1): no required fields; one optional forward hook
    `mirror_urls` reserved for future mirror-candidate passing. Factories
    MUST accept exactly one positional `FetcherConfig` argument — the slot
    is reserved so future spec versions can add fields without a signature
    change (e.g. timeouts, credential tokens).

    v1 fetchers MAY ignore mirror_urls. The field is here to pin the
    factory signature today at zero cost.
    """
    mirror_urls: list[str] = field(default_factory=list)


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


class ProvenanceReceipt(ABC):
    """Abstract base class for per-fetch receipts. Subclasses record what the
    transport actually delivered (commit SHA, archive hash, etc.).
    Receipts are *descriptive* — they do NOT establish identity.

    Every concrete subclass MUST implement `transport_fields()` returning
    a non-empty dict of transport-pinning fields (spec §3.2). A receipt
    with no transport-specific information provides no provenance evidence
    and is rejected at admission time with FETCH-RECEIPT-EMPTY.
    """

    @abstractmethod
    def transport_fields(self) -> dict[str, str]:
        """Return a non-empty dict mapping field-name → str-value for every
        transport-pinning field this receipt carries (e.g. commit SHA,
        archive digest, local path). The registry validates non-emptiness
        after fetch; returning {} triggers FETCH-RECEIPT-EMPTY."""
        ...


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

    def __init__(self, message: str = "", *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


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
    """Dispatches a Provenance to exactly one registered Fetcher whose
    `can_handle` accepts it, then computes identity externally and
    wraps the receipt into a FetchResult.

    Dispatch is **exclusive**: `_select` collects ALL fetchers whose
    `can_handle` returns True and raises FetchError if more than one
    matches (ambiguity error) or if none match. Registration order is
    for readability only — it confers no priority. A production setup
    pre-registers the four built-in fetchers (Git, Local, Tarball, OCI);
    tests can construct empty registries for isolation.
    """

    def __init__(self, store: "CAStore | None" = None) -> None:
        self._fetchers: list[Fetcher] = []
        self._store = store

    @property
    def store(self) -> "CAStore | None":
        """The CAStore this registry routes through, if any."""
        return self._store

    @property
    def fetchers(self) -> tuple[Fetcher, ...]:
        """Registered fetchers in declaration order — useful for cloning
        a registry with a different store while preserving fetcher set."""
        return tuple(self._fetchers)

    def with_store(self, store: "CAStore") -> "FetcherRegistry":
        """Return a new registry with the same fetchers but a different
        CAS. Enables per-project CAS overrides (cas { dir "..." }) without
        mutating the global default_registry singleton."""
        new = FetcherRegistry(store=store)
        for f in self._fetchers:
            new.register(f)
        return new

    def register(self, fetcher: Fetcher) -> None:
        self._fetchers.append(fetcher)

    @staticmethod
    def _validate_receipt(name: str, receipt: "ProvenanceReceipt") -> None:
        """Raise FetchError(code='FETCH-RECEIPT-EMPTY') if the receipt's
        transport_fields() is empty.  A receipt with no transport-specific
        fields provides no provenance evidence — spec §3.2 forbids it."""
        if not receipt.transport_fields():
            raise FetchError(
                f"fetcher for {name!r} returned a receipt with empty "
                f"transport_fields() — no provenance evidence recorded; "
                f"receipt type: {type(receipt).__name__!r}",
                code="FETCH-RECEIPT-EMPTY",
            )

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
            self._validate_receipt(name, receipt)
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
            self._validate_receipt(name, receipt)
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

    def fetch_any(
        self,
        name: str,
        candidates: "Sequence[Provenance]",
        *,
        dest: Path,
        expected_identity: str | None = None,
    ) -> FetchResult:
        """Try each candidate provenance in order; return the first
        successful FetchResult. Raises FetchError if every candidate
        fails (composite message lists each underlying failure).

        Used for multi-provenance fall-through (#37): primary +
        mirrors. Single-candidate calls are equivalent to fetch().

        When `expected_identity` is set, each candidate's bytes must
        hash to it. Candidates that produce mismatched bytes are
        treated as failures — the bytes are dropped and the next
        candidate is tried. This is the structural guarantee that a
        hostile mirror cannot substitute itself for the locked dep.
        """
        if not candidates:
            # Programmer-invariant: callers must supply at least one candidate.
            # This is a call-site bug, not user input, so no catalog code.
            raise FetchError(
                f"fetch_any({name!r}): no candidates provided"
            )
        failures: list[str] = []
        for p in candidates:
            try:
                result = self.fetch(name, p, dest=dest)
            except Exception as e:
                failures.append(f"{type(p).__name__}: {e}")
                continue
            if expected_identity is not None and result.identity != expected_identity:
                failures.append(
                    f"{type(p).__name__}: identity mismatch "
                    f"(expected {expected_identity[:23]}..., "
                    f"got {result.identity[:23]}...)"
                )
                # A candidate returning mismatched bytes is not the same as a
                # candidate being down: it's a possible supply-chain signal
                # (a primary serving substituted content). Falling through to
                # a mirror that happens to match would mask it, so warn loudly
                # naming the candidate + expected/actual identity (#102).
                print(
                    f"warning: {name}: provenance {type(p).__name__} returned "
                    f"bytes that do not match the expected identity "
                    f"(expected {expected_identity[:23]}..., "
                    f"got {result.identity[:23]}...); discarding and trying "
                    f"the next candidate",
                    file=sys.stderr,
                )
                # Drop the mismatched bytes so the next candidate's
                # fetch sees a clean destination.
                clear_dest(dest)
                continue
            return result
        raise FetchError(
            f"fetch_any({name!r}): all {len(candidates)} candidates failed:\n  "
            + "\n  ".join(failures),
            code="FETCH-ALL-FAILED",
        )

    def _select(self, provenance: Provenance) -> "Fetcher":
        matches = [f for f in self._fetchers if f.can_handle(provenance)]
        if len(matches) > 1:
            # Programmer-invariant: a registration bug, not user input.
            raise FetchError(
                f"ambiguous fetcher dispatch for provenance kind "
                f"{type(provenance).__name__!r}: "
                f"{len(matches)} registered fetchers all claim can_handle — "
                f"registrations: {[type(f).__name__ for f in matches]}"
            )
        if not matches:
            # Programmer-invariant: caller built a registry without the
            # fetcher needed for this provenance kind.
            raise FetchError(
                f"no registered fetcher handles provenance kind "
                f"{type(provenance).__name__}"
            )
        return matches[0]
