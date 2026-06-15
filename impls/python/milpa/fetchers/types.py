"""Pluggable fetcher abstraction — base types, registry, dispatch, config.

Slices 7a + 7e per docs/rfc-python-clean-room-rewrite.md.

Public surface:
  - ``Provenance``        — base descriptor; carries ``cas_admissible``
  - ``ProvenanceReceipt`` — abstract; concrete subclasses record transport evidence
  - ``FetchResult``       — uniform registry output (name + path + identity + receipt)
  - ``Fetcher``           — ABC for transport implementations (claim / materialize / receipt)
  - ``FetcherRegistry``   — unique-match dispatch + post-fetch identity computation
  - ``FetcherConfig``     — v1 shape per plugin-contract.md §7.1
  - ``FetchError``        — raised on fetch failures; uncoded invariants carry ``code=None``

Invariants enforced here:
  1. ``Fetcher`` implementations MUST NOT compute identity (tree hash).
     The registry computes identity from ``dest`` after every successful
     ``fetch`` call (plugin-contract.md §3.3 NORMATIVE).
  2. ``ProvenanceReceipt`` subclasses MUST implement ``transport_fields()``
     returning a non-empty dict; registry validates at admission time
     (``FETCH-RECEIPT-EMPTY``).
  3. Unique-match dispatch: exactly one registered fetcher may claim a
     given provenance; ambiguity → uncoded ``FetchError``; no-handler →
     uncoded ``FetchError`` (§5.1 catalog exemption → ``FETCH_UNCODED_INVARIANTS``).
  4. ``FetcherConfig`` has no required fields in v1 (§7.1 NORMATIVE).
  5. ``cas_admissible`` is a ``ClassVar[bool]`` on every ``Provenance`` subclass;
     editable sources (local / member) MUST declare ``False`` (§4 NORMATIVE).

``CasAdmittingFetcher`` (7b) wraps a ``FetcherRegistry``; it is NOT
implemented here.  The built-in fetchers (git / tarball / local / oci)
are NOT imported here.  ``_build_default_registry`` in ``__init__.py``
wires the built-ins; this module owns only the protocol types.

``fetch_any`` (7e §8a) implements the three-part ordered candidate list:
  1. Primary provenance
  2. Dep-block mirrors
  3. Prior-lockfile self-mirrors
All three parts are supplied by the caller as a flat ``Sequence[Provenance]``
already ordered.  ``fetch_any`` tries each in order, applies the identity gate
when ``expected_identity`` is set, and raises ``FETCH-ALL-FAILED`` if every
candidate fails or mismatches.
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from milpa.errors import FETCH_ALL_FAILED, FETCH_RECEIPT_EMPTY, MilpaError
from milpa.identity import compute_content_hash

if TYPE_CHECKING:
    pass  # no forward imports needed here; CAS types live in cas_admitting.py


# ---------------------------------------------------------------------------
# FETCH_UNCODED_INVARIANTS — catalog exemption (plugin-contract.md §5.1)
# ---------------------------------------------------------------------------

#: Three programmer-invariants that carry NO catalog slug.
#: They signal a registration bug or call-site bug — never a condition
#: reachable from user input. Exempt from the error-catalog bijection lint.
#: Identified by condition (not message text):
#:   - "ambiguous dispatch"   — two+ fetchers claim can_handle for one descriptor
#:   - "no handler"           — zero fetchers claim can_handle for one descriptor
#:   - "no candidates"        — fetch_any() called with an empty candidate list
FETCH_UNCODED_INVARIANTS: frozenset[str] = frozenset(
    {"ambiguous dispatch", "no handler", "no candidates"}
)


# ---------------------------------------------------------------------------
# FetcherConfig — v1 shape (plugin-contract.md §7.1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FetcherConfig:
    """Configuration passed to every plugin factory.

    v1 shape (plugin-contract.md §7.1 NORMATIVE): no required fields;
    one optional forward hook ``mirror_urls`` reserved for future mirror-
    candidate passing.

    Factory signature MUST be ``(config: FetcherConfig) -> Fetcher``
    (one positional argument, no others).  v1 fetchers MAY ignore
    ``mirror_urls``; the slot exists so a future spec version can pass
    mirror candidates without a breaking signature change.
    """

    mirror_urls: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Provenance — base class (plugin-contract.md §4)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Provenance:
    """Base class for provenance descriptors.

    Subclasses carry transport-specific fields (URL, ref, digest, path …).

    ``cas_admissible`` (ClassVar, not a dataclass field) declares whether
    bytes fetched under this provenance may be admitted to the global CAS:

    - ``True``  (default) — immutable sources: git (all refs, per §4
      NORMATIVE rationale), tarball.  Admission is gated on the post-fetch
      identity check; mutable refs that advance are detected and rejected.
    - ``False`` — editable sources: local-path, workspace-member.  Admission
      would silently freeze user edits; MUST NOT be admitted.

    Subclasses MUST override ``cas_admissible`` explicitly when they
    represent an editable source.
    """

    cas_admissible: ClassVar[bool] = True


# ---------------------------------------------------------------------------
# ProvenanceReceipt — abstract base (plugin-contract.md §3.2)
# ---------------------------------------------------------------------------


class ProvenanceReceipt(ABC):
    """Abstract base class for per-fetch receipts.

    Concrete subclasses record what the transport actually delivered
    (commit SHA, archive hash, local path …).  Receipts are descriptive —
    they do NOT establish identity (tree hash is forbidden; see §3.1).

    Every concrete subclass MUST implement ``transport_fields()`` returning
    a non-empty dict of transport-pinning fields.  A receipt with no
    transport-specific information provides no provenance evidence and is
    rejected at admission time with ``FETCH-RECEIPT-EMPTY`` (§3.2).
    """

    @abstractmethod
    def transport_fields(self) -> dict[str, str]:
        """Return a non-empty dict mapping field-name → str-value for every
        transport-pinning field this receipt carries.

        Examples of permitted fields (plugin-contract.md §3.1):
          - ``GitReceipt.commit_sha``      — identifies the git object
          - ``TarballReceipt.archive_sha256`` — identifies the downloaded archive
          - ``OciReceipt.layer_digest``    — identifies the OCI blob
          - ``LocalReceipt.resolved_path`` — records the filesystem path used

        Returning an empty dict triggers ``FETCH-RECEIPT-EMPTY`` at the
        registry's admission check.  The registry calls this method after
        every successful ``fetch`` — the fetcher must NOT return a subclass
        whose ``transport_fields()`` can be empty.
        """
        ...


# ---------------------------------------------------------------------------
# FetchResult — uniform registry output (plugin-contract.md §3.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FetchResult:
    """Uniform output of a successful fetch.

    ``identity`` is the milpa-computed content hash (computed by the
    registry from the materialized tree at ``dest``; the fetcher never
    sees or influences it — plugin-contract.md §3.3 NORMATIVE).

    For CAS-admissible provenances (git, tarball, oci) ``identity`` is a
    ``sha256:<hex>`` string.  For non-admissible (local/member) provenances
    ``identity`` is ``None`` — local trees are live and editable; hashing them
    at fetch time would produce a snapshot that is immediately stale
    (lockfile-schema.md §4.3 NORMATIVE: local records carry no identity field).

    ``receipt`` is the transport-specific record the fetcher returned.
    """

    name: str
    path: Path
    identity: str | None    # sha256:<hex> for CAS deps; None for local/member
    receipt: ProvenanceReceipt


# ---------------------------------------------------------------------------
# Fetcher ABC (plugin-contract.md §1)
# ---------------------------------------------------------------------------


class Fetcher(ABC):
    """Abstract base class for transport-specific source-tree producers.

    A conformant fetcher satisfies three obligations (plugin-contract.md §1):

    1. **Claim** (§1.1): ``can_handle(provenance) -> bool``.
       MUST return ``True`` for exactly the provenance kinds declared;
       MUST NOT return ``True`` for any other kind.

    2. **Materialize** (§1.2): ``fetch(name, provenance, *, dest) -> ProvenanceReceipt``.
       On success, the source tree MUST be present under ``dest/``.
       MUST NOT compute, hash, or assert identity.

    3. **Receipt** (§1.3): return a ``ProvenanceReceipt`` subclass instance
       recording transport-pinning fields.  MUST NOT contain any field
       whose value is a function of the materialized tree bytes (§3.1).

    Failure is signalled by raising ``MilpaError`` with an appropriate
    ``FETCH-*`` slug; cleanup of ``dest`` is the **registry's responsibility**
    (§2 NORMATIVE).
    """

    @abstractmethod
    def can_handle(self, p: Provenance) -> bool:
        """Return True iff this fetcher can fully materialize ``p``."""
        ...

    @abstractmethod
    def fetch(self, name: str, p: Provenance, *, dest: Path) -> ProvenanceReceipt:
        """Materialize ``p`` under ``dest/`` and return the transport receipt.

        ``dest`` is provided by the registry.  The fetcher MUST write the
        tree under ``dest/``; MUST NOT rename ``dest`` or create parallel paths.

        On failure: raise ``MilpaError(FETCH_*_FAILED, …)``.  Do NOT clean
        up ``dest`` — the registry calls ``clear_dest(dest)`` on failure.
        """
        ...


# ---------------------------------------------------------------------------
# FetcherRegistry — dispatch + identity computation (plugin-contract.md §5, §3.3)
# ---------------------------------------------------------------------------


class FetcherRegistry:
    """Dispatches a Provenance to exactly one registered Fetcher whose
    ``can_handle`` accepts it, then computes identity externally and
    wraps the receipt into a ``FetchResult``.

    Dispatch is **exclusive** (plugin-contract.md §5 NORMATIVE):
    ``_select`` collects ALL fetchers whose ``can_handle`` returns ``True``
    and raises an uncoded ``FetchError`` if more than one matches (ambiguity
    error) or if none match (no-handler error).  Registration order is for
    readability only — it confers no priority.

    Identity computation is always done by the registry, never delegated to
    the fetcher (§3.3 NORMATIVE).  ``fetch`` calls ``compute_content_hash``
    on the materialized tree AFTER the fetcher returns; the fetcher cannot
    influence the ``identity`` field of ``FetchResult``.

    Note: CAS admission is NOT handled here — that is the responsibility
    of ``CasAdmittingFetcher`` (7b), which wraps a ``FetcherRegistry``.
    This registry always fetches directly to ``dest``.
    """

    def __init__(self) -> None:
        self._fetchers: list[Fetcher] = []

    @property
    def fetchers(self) -> tuple[Fetcher, ...]:
        """Registered fetchers in declaration order."""
        return tuple(self._fetchers)

    def register(self, fetcher: Fetcher) -> None:
        """Add a fetcher to the registry.

        The fetcher is appended to the list; registration order is for
        readability only (does not resolve dispatch ambiguity).
        """
        self._fetchers.append(fetcher)

    def _select(self, p: Provenance) -> Fetcher:
        """Return the unique fetcher that claims ``p``.

        Raises an uncoded ``FetchError`` (no catalog slug) on ambiguity or
        no-handler — both are programmer-invariants per plugin-contract.md §5.1.
        """
        matches = [f for f in self._fetchers if f.can_handle(p)]
        if len(matches) > 1:
            # Uncoded programmer-invariant: registration bug, not user input.
            names = [type(f).__name__ for f in matches]
            raise FetchError(
                f"ambiguous fetcher dispatch for provenance kind "
                f"{type(p).__name__!r}: {len(matches)} registered fetchers "
                f"all claim can_handle — registrations: {names}",
                code=None,
            )
        if not matches:
            # Uncoded programmer-invariant: call-site bug, not user input.
            raise FetchError(
                f"no handler: no registered fetcher handles provenance kind "
                f"{type(p).__name__!r}",
                code=None,
            )
        return matches[0]

    @staticmethod
    def _validate_receipt(name: str, receipt: ProvenanceReceipt) -> None:
        """Raise ``MilpaError(FETCH_RECEIPT_EMPTY)`` if ``transport_fields()`` is empty.

        Enforces plugin-contract.md §3.2 NORMATIVE: every concrete receipt
        MUST provide at least one transport-pinning field.
        """
        if not receipt.transport_fields():
            raise MilpaError(
                FETCH_RECEIPT_EMPTY,
                f"fetcher for {name!r} returned a receipt with empty "
                f"transport_fields() — no provenance evidence recorded; "
                f"receipt type: {type(receipt).__name__!r}",
                dep=name,
                receipt_type=type(receipt).__name__,
            )

    def fetch(
        self,
        name: str,
        provenance: Provenance,
        *,
        dest: Path,
    ) -> FetchResult:
        """Fetch ``provenance`` into ``dest/``, compute identity, return ``FetchResult``.

        Steps:
          1. Dispatch to unique fetcher (§5 exclusive dispatch).
          2. Call ``fetcher.fetch(name, provenance, dest=dest)`` → ``ProvenanceReceipt``.
          3. Validate receipt non-empty (§3.2).
          4. Compute ``content_hash(dest)`` — registry computes identity (§3.3).
          5. Return ``FetchResult``.

        On failure from the fetcher: the exception propagates; the caller
        (``fetch_any`` or the resolver) is responsible for cleaning up ``dest``.
        """
        fetcher = self._select(provenance)
        receipt = fetcher.fetch(name, provenance, dest=dest)
        self._validate_receipt(name, receipt)
        # Local (non-admissible) provenances carry no identity: they are live,
        # editable source trees. Hashing them at fetch time would produce a
        # snapshot that is immediately stale and meaningless as a pinning anchor.
        # The lockfile §4.3 NORMATIVE: local records have no identity field.
        # CAS-admissible provenances (git, tarball, oci) always get a hash.
        if provenance.cas_admissible:
            identity: str | None = compute_content_hash(dest)
        else:
            identity = None
        return FetchResult(name=name, path=dest, identity=identity, receipt=receipt)

    def fetch_any(
        self,
        name: str,
        candidates: Sequence[Provenance],
        *,
        dest: Path,
        expected_identity: str | None = None,
    ) -> FetchResult:
        """Try each candidate provenance in order; return the first success.

        Implements resolver-semantics.md §8a mirror fallback.  The caller
        supplies the three-part ordered candidate list already flattened:
          1. Primary provenance (from the manifest dep block)
          2. Dep-block mirrors (``mirror`` entries from the dep block)
          3. Prior-lockfile declared mirror provenances (origin="declared" from the prior lock)

        When ``expected_identity`` is set, each candidate's materialized tree
        MUST hash to it.  A candidate producing different bytes is skipped
        with a stderr warning (not an error) — the identity gate is the trust
        boundary (plugin-contract.md §6 NORMATIVE).

        Raises ``MilpaError(FETCH_ALL_FAILED)`` if every candidate fails
        (network error OR identity mismatch).  The composite error message
        folds each underlying failure.

        ``dest`` must be clean before the first call.  Between candidates
        ``fetch_any`` clears ``dest`` internally so each candidate sees a
        clean destination.

        The "no candidates provided" path is a programmer-invariant (call-site
        bug; not user-reachable) — raises uncoded ``FetchError`` (§5.1).
        """
        return _fetch_any(name, candidates, dest=dest, expected_identity=expected_identity, fetch_one=self.fetch)


# ---------------------------------------------------------------------------
# FetchError — transport-level exception
# ---------------------------------------------------------------------------


class FetchError(Exception):
    """Raised when a fetch cannot complete.

    For coded errors (user-reachable conditions), ``code`` is a ``FETCH-*``
    slug from ``milpa.errors``.

    For programmer-invariants (ambiguous dispatch, no-handler, no-candidates
    per §5.1), ``code`` is ``None`` — these carry NO catalog slug.
    """

    def __init__(self, message: str = "", *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------


def _clear_dest(dest: Path) -> None:
    """Remove and recreate ``dest/`` so the next candidate sees a clean directory.

    Symlink safety: if ``dest`` is a symlink (e.g. a prior CAS symlink or a
    local-path link), only the symlink itself is removed — never the target
    directory.  ``dest.exists()`` follows symlinks, so using ``rmtree`` on a
    symlink-to-dir would destroy the user's source tree.  We guard with
    ``dest.is_symlink()`` first (lstat semantics, does NOT follow).
    """
    import shutil

    if dest.is_symlink():
        dest.unlink()
    elif dest.exists():
        # Do NOT ignore errors: a failed rmtree leaves stale content that the
        # next candidate would write on top of — silent corruption.  Propagate
        # so the caller can surface it.  Matches Rust clear_dest behaviour.
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# FetchOneProtocol — typed seam for the fetch_one callable
# ---------------------------------------------------------------------------


@runtime_checkable
class FetchOneProtocol(Protocol):
    """Protocol for the ``fetch_one`` callable accepted by ``_fetch_any``.

    Captures the exact argument shape of ``FetcherRegistry.fetch`` (and
    ``CasAdmittingFetcher.fetch``): ``(name, provenance, *, dest) -> FetchResult``.

    Using a typed Protocol instead of ``Callable[..., FetchResult]`` makes the
    seam explicit — a caller passing a wrong callable is caught at static
    analysis time rather than at CAS-corruption time.
    """

    def __call__(
        self,
        name: str,
        provenance: Provenance,
        *,
        dest: Path,
    ) -> FetchResult: ...


# ---------------------------------------------------------------------------
# _fetch_any — shared candidate-loop (single source of truth)
# ---------------------------------------------------------------------------

def _fetch_any(
    name: str,
    candidates: Sequence[Provenance],
    *,
    dest: Path,
    expected_identity: str | None = None,
    fetch_one: FetchOneProtocol,
) -> FetchResult:
    """Ordered-candidate loop shared by ``FetcherRegistry`` and ``CasAdmittingFetcher``.

    SSOT for the mirror-fallback algorithm (resolver-semantics.md §8a).
    Both callers pass their own ``fetch_one`` callable (``registry.fetch`` or
    ``cas_admitting_fetcher.fetch``); the loop body is identical for both.

    Parameters
    ----------
    name:
        Dependency name (used in error messages).
    candidates:
        Non-empty ordered list of provenances to try.  Programmer-invariant:
        callers MUST supply at least one candidate.
    dest:
        Target path.  Must be clean on entry; cleared between candidates
        by this function via ``_clear_dest``.
    expected_identity:
        When set, each successful fetch is compared against this hash.
        A mismatch is treated as a failure (warning to stderr; try next).
        ``None`` disables the identity gate.
    fetch_one:
        Callable with signature ``(name, provenance, dest) -> FetchResult``.
        Receives the same ``name`` and ``dest`` on each iteration; the
        provenance cycles through ``candidates``.

    Raises
    ------
    FetchError (code=None):
        ``candidates`` is empty — programmer-invariant, no catalog slug.
    MilpaError(FETCH_ALL_FAILED):
        Every candidate failed (network error or identity mismatch).
    """
    if not candidates:
        raise FetchError(
            f"fetch_any({name!r}): no candidates provided",
            code=None,
        )

    failures: list[str] = []
    for i, p in enumerate(candidates):
        # Clean dest before each candidate (except the first — arrives clean).
        if i > 0:
            _clear_dest(dest)
        try:
            result = fetch_one(name, p, dest=dest)
        except (MilpaError, FetchError, Exception) as exc:
            failures.append(f"{type(p).__name__}: {exc}")
            continue

        if expected_identity is not None and result.identity != expected_identity:
            got_prefix = (result.identity or "<none>")[:23]
            failures.append(
                f"{type(p).__name__}: identity mismatch "
                f"(expected {expected_identity[:23]}..., "
                f"got {got_prefix}...)"
            )
            # Warn loudly: a primary delivering substituted content is a
            # supply-chain signal; falling through to a mirror silently would
            # mask it.  Log to stderr, drop the result, try next candidate.
            print(
                f"warning: {name}: provenance {type(p).__name__} returned "
                f"bytes that do not match the expected identity "
                f"(expected {expected_identity[:23]}..., "
                f"got {got_prefix}...); "
                f"discarding and trying the next candidate",
                file=sys.stderr,
            )
            continue

        return result

    raise MilpaError(
        FETCH_ALL_FAILED,
        f"fetch_any({name!r}): all {len(candidates)} candidates failed:\n  "
        + "\n  ".join(failures),
        dep=name,
        candidate_count=len(candidates),
        failures=failures,
    )
