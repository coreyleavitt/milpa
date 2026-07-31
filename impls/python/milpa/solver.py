"""PubGrub-based version solver — teaching-clean port from the frozen impl.

Ported verbatim from ``impls/python/milpa/solver.py`` (algorithm-identical).
Types modernised to fully-annotated mypy-strict style; no design changes.

The solver knows nothing about fetching, .nimble files, or registries.
It operates on a ``PackageProvider`` abstraction that, given a package
name and version, returns the package's dependencies as ``Term``s. The
production provider (resolver.py, S9) is built from milpa's fetcher +
registry + nimble_parse pieces; test providers are synthetic dicts.

Key concepts:
  - Term:             a positive/negative version-set constraint on a package
  - Incompatibility:  conjunction of Terms that must NOT all hold
  - PartialSolution:  ordered list of Assignments (decisions or derivations)
  - solve():          main loop — unit-propagate, decide, conflict-resolve

The algorithm:
  1. Seed with one incompatibility: "root is NOT at root_version" — a
     contradiction (root MUST be at root_version).
  2. Loop:
     a. Unit propagation: for each incompatibility, if all-but-one term
        is satisfied by the partial solution, the remaining term must be
        the opposite — add its negation as a derivation. Repeat until
        nothing changes or a conflict (fully-satisfied incompatibility).
     b. On conflict: emit SolverError narrating the chain. (Full PubGrub
        would do conflict-driven incompatibility learning + backjumping;
        we ship the simpler form for v0. Tracked at #28.)
     c. Otherwise: pick an undecided package + version, add it as a
        decision, encode its dependencies as new incompatibilities.
  3. When all packages with positive constraints are decided, extract
     and return the solution.

Result certificate (resolver-semantics §5):
  - On success: ``SolveSuccess`` carrying ``resolved`` + ``witness``
    entries whose validity predicate is checkable in O(n·constraints).
  - On failure: ``SolverError`` with a ``ConflictChain`` and a
    ``refutation`` property returning the weak UNSAT core (§5.2).
  - Serialiser: ``certificate_to_json(result)`` — SSOT for both the
    in-process conformance adapter (S10b) and the future CLI flag.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from .errors import SOLVE_CONFLICT
from .version import Strategy, Version, VersionSet, format_version_str

# ---------------------------------------------------------------------------
# Conflict narration structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConflictStep:
    """One step in a PubGrub conflict derivation.

    consequent_package:     the package whose version space is exhausted.
    consequent_description: human-readable description of what happened.
    antecedents:            depender Terms (positive, from dep-constraint
                            incompatibilities) that introduce conflicting
                            requirements on the consequent package.
    antecedent_constraints: constraint Terms for the consequent package
                            from each dep-incompatibility (parallel to
                            ``antecedents``).
    cause_tag:              raw cause string from the triggering incompat.
    """

    consequent_package: str
    consequent_description: str
    antecedents: tuple[Term, ...]
    antecedent_constraints: tuple[Term, ...]
    cause_tag: str


@dataclass(frozen=True)
class ConflictChain:
    """Ordered list of ConflictStep records — one valid failure refutation.

    ``render_conflict_chain`` produces human-readable prose.
    ``steps`` is the structured form for tests and the §5.2 refutation.
    """

    steps: tuple[ConflictStep, ...]


# ---------------------------------------------------------------------------
# Term + Incompatibility
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Term:
    """A version-set constraint on a single package.

    ``positive=True``  → "this package's version must be in ``versions``"
    ``positive=False`` → "this package's version must NOT be in ``versions``"
    """

    package: str
    positive: bool
    versions: VersionSet

    @classmethod
    def require(cls, package: str, versions: VersionSet) -> Term:
        return cls(package=package, positive=True, versions=versions)

    @classmethod
    def forbid(cls, package: str, versions: VersionSet) -> Term:
        return cls(package=package, positive=False, versions=versions)

    def negate(self) -> Term:
        return Term(self.package, not self.positive, self.versions)


@dataclass(frozen=True)
class Incompatibility:
    """A conjunction of Terms that must NOT all simultaneously hold.

    ``cause`` is a human-readable string used in error messages —
    ``"root"``, ``"dependency:<pkg>@<version>"``, ``"no-versions-of-<pkg>"``, etc.
    """

    terms: tuple[Term, ...]
    cause: str


# ---------------------------------------------------------------------------
# PartialSolution: ordered assignments + relation queries
# ---------------------------------------------------------------------------


class TermRelation(Enum):
    SATISFIES = "satisfies"
    CONTRADICTS = "contradicts"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Assignment:
    term: Term
    kind: str  # "decision" | "derivation"
    cause: Incompatibility | None  # derivations only
    decision_level: int = 0


@dataclass
class PartialSolution:
    assignments: list[Assignment] = field(default_factory=list)
    decision_level: int = 0
    # Cache: effective positive constraint per package after intersection.
    _effective_cache: dict[str, VersionSet] = field(default_factory=dict)

    def add_decision(self, package: str, version: Version) -> None:
        self.decision_level += 1
        self.assignments.append(
            Assignment(
                term=Term.require(package, VersionSet.eq(version)),
                kind="decision",
                cause=None,
                decision_level=self.decision_level,
            )
        )
        self._effective_cache.pop(package, None)

    def add_derivation(self, term: Term, cause: Incompatibility) -> None:
        self.assignments.append(
            Assignment(
                term=term,
                kind="derivation",
                cause=cause,
                decision_level=self.decision_level,
            )
        )
        self._effective_cache.pop(term.package, None)

    def backtrack_to(self, level: int) -> Assignment | None:
        """Drop every assignment whose decision_level > ``level``.

        Returns the most recent decision that was undone (None if none).
        """
        undone_decision: Assignment | None = None
        kept: list[Assignment] = []
        for a in self.assignments:
            if a.decision_level <= level:
                kept.append(a)
            else:
                if a.kind == "decision":
                    undone_decision = a
        self.assignments = kept
        self.decision_level = level
        self._effective_cache.clear()
        return undone_decision

    def decisions(self) -> dict[str, Version]:
        out: dict[str, Version] = {}
        for a in self.assignments:
            if a.kind == "decision":
                # Decision term is require(pkg, eq(version)): closed point
                # interval (v, v, True, True) — lo is the chosen version.
                iv = a.term.versions.intervals[0]
                out[a.term.package] = iv[0]  # type: ignore[assignment]
        return out

    def effective_set(self, package: str) -> VersionSet:
        """Intersection of all positive constraints on ``package``,
        intersected with the complement of negative constraints.

        Returns the set of versions still allowed under the partial solution.
        """
        cached = self._effective_cache.get(package)
        if cached is not None:
            return cached
        result = VersionSet.full()
        for a in self.assignments:
            if a.term.package != package:
                continue
            if a.term.positive:
                result = result.intersect(a.term.versions)
            else:
                result = result.intersect(a.term.versions.complement())
        self._effective_cache[package] = result
        return result

    def has_decision(self, package: str) -> bool:
        return any(
            a.kind == "decision" and a.term.package == package
            for a in self.assignments
        )

    def relation_to(self, incompat: Incompatibility) -> TermRelation:
        """How does the partial solution relate to this incompatibility?

        - SATISFIES:    every term satisfied (incompat fully active — CONFLICT)
        - CONTRADICTS:  at least one term contradicted (incompat can't fire)
        - INCONCLUSIVE: some term is neither satisfied nor contradicted
        """
        almost: Term | None = None
        for term in incompat.terms:
            rel = self._term_relation(term)
            if rel == TermRelation.CONTRADICTS:
                return TermRelation.CONTRADICTS
            if rel == TermRelation.INCONCLUSIVE:
                if almost is not None:
                    return TermRelation.INCONCLUSIVE
                almost = term
        return (
            TermRelation.INCONCLUSIVE if almost is not None else TermRelation.SATISFIES
        )

    def unit_term(self, incompat: Incompatibility) -> Term | None:
        """If ``incompat`` is "almost satisfied" (all-but-one term satisfied,
        the remaining inconclusive), return the remaining term. Else None.
        """
        unit: Term | None = None
        for term in incompat.terms:
            rel = self._term_relation(term)
            if rel == TermRelation.CONTRADICTS:
                return None
            if rel == TermRelation.INCONCLUSIVE:
                if unit is not None:
                    return None
                unit = term
        return unit

    def _term_relation(self, term: Term) -> TermRelation:
        # No information about this package → inconclusive.
        if not any(a.term.package == term.package for a in self.assignments):
            return TermRelation.INCONCLUSIVE
        current = self.effective_set(term.package)
        allowed = term.versions if term.positive else term.versions.complement()
        if current.is_subset_of(allowed):
            return TermRelation.SATISFIES
        if current.intersect(allowed).is_empty():
            return TermRelation.CONTRADICTS
        return TermRelation.INCONCLUSIVE


# ---------------------------------------------------------------------------
# Provider protocol + internal conflict sentinel
# ---------------------------------------------------------------------------


class PackageProvider(Protocol):
    """Abstraction over the dep universe — queries the solver makes.

    The production provider (resolver.py, S9) is fetch-backed.
    Test providers are synthetic in-memory dicts.
    """

    def versions(self, package: str) -> list[Version]: ...

    def dependencies(self, package: str, version: Version) -> list[Term]: ...


class _Conflict(Exception):
    """Internal: a conflict the solver may resolve via backtracking."""

    def __init__(self, incompat: Incompatibility) -> None:
        self.incompat = incompat


# ---------------------------------------------------------------------------
# Result certificate types (resolver-semantics §5)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WitnessEntry:
    """One entry in the success witness (§5.1).

    Validity predicate:
        ``VersionSet.from_constraint(constraint).contains(parse_version(version))``
    """

    package: str
    version: str
    constraint: str
    satisfied_by: str  # name of the consuming package that declared the constraint


@dataclass(frozen=True)
class SolveSuccess:
    """Success certificate (resolver-semantics §5.1).

    ``resolved``: every ``(package, version)`` in the solution.
    ``witness``:  one entry per declared constraint, proving each version
                  satisfies its constraint.

    Validity:
        1. Every ``(package, version)`` in ``resolved`` is in the candidate set.
        2. For every ``WitnessEntry``:
           ``VersionSet.from_constraint(e.constraint).contains(parse_version(e.version))``
           holds, and ``e.satisfied_by`` names the consuming package.
        3. Every declared constraint is represented by exactly one entry.
    """

    resolved: tuple[tuple[str, str], ...]  # (package, version_str)
    witness: tuple[WitnessEntry, ...]


@dataclass(frozen=True)
class RefutationEntry:
    """One named incompatibility in a failure refutation (§5.2)."""

    package: str
    constraint: str


# ---------------------------------------------------------------------------
# SolverError
# ---------------------------------------------------------------------------


class SolverError(Exception):
    """Raised when no solution exists (SOLVE-CONFLICT).

    Carries a structured ``ConflictChain`` (``chain`` attribute) rendered as
    prose via ``render_conflict_chain``.  ``str(err)`` returns the prose so
    existing log/print sites keep working.

    ``code`` is always ``SOLVE_CONFLICT`` — there is exactly one
    user-facing solver-error condition.

    ``refutation`` (§5.2): the weak UNSAT core — every incompatibility that
    contributed to the conflict, named as a ``(package, constraint)`` set.
    The set is genuinely unsatisfiable (checkable in O(n·constraints)).
    """

    code: str = SOLVE_CONFLICT

    def __init__(
        self,
        chain: ConflictChain,
        all_incompats: list[Incompatibility] | None = None,
    ) -> None:
        self.chain = chain
        self._all_incompats = all_incompats or []
        super().__init__(render_conflict_chain(chain))

    @property
    def refutation(self) -> tuple[RefutationEntry, ...]:
        """Weak UNSAT core (§5.2): named set of incompatibilities.

        Collects every dep-constraint incompatibility from ``all_incompats``
        that contributed a constraint on any package named in the conflict
        chain.  The set is genuinely unsatisfiable — all conflicted packages
        are represented.
        """
        conflicted_pkgs = {step.consequent_package for step in self.chain.steps}
        entries: list[RefutationEntry] = []
        seen: set[tuple[str, str]] = set()
        for ic in self._all_incompats:
            if not ic.cause.startswith("dependency:"):
                continue
            for t in ic.terms:
                if not t.positive and t.package in conflicted_pkgs:
                    # Negative term = Term.forbid(pkg, required_vs): the incompat
                    # says "depender@ver AND pkg NOT IN required_vs cannot both hold",
                    # meaning depender requires pkg IN required_vs.
                    # The required range is t.versions directly (NOT its complement).
                    required = t.versions
                    # D-A2: a full() requirement (e.g. a git/url/local/tarball
                    # dep's full() self-term) is never violated by any candidate,
                    # so it can never contribute to *why* a conflict is
                    # unsatisfiable — including it would just be noise in the
                    # weak-UNSAT core.  Skip it.
                    if required.is_full():
                        continue
                    # Use constraint-string form for §5.2 checkability.
                    constraint_str = _vs_to_constraint_str(required)
                    key = (t.package, constraint_str)
                    if key not in seen:
                        seen.add(key)
                        entries.append(
                            RefutationEntry(package=t.package, constraint=constraint_str)
                        )
        return tuple(entries)


class VersionUnknownConstrained(Exception):
    """Raised by ``_make_decision`` for A4's version-unknown partition
    (resolver-semantics RFC §3 Axis A (c) / §6 D-A1).

    A version-unknown package (``provider.is_version_unknown(package)``) is
    scheduled with strictly lowest decision priority (``_next_undecided``), so
    by the time it is decided, every potential constrainer — including a
    named/index dep whose own floor only materializes lazily, mid-solve — has
    already been expanded and its floor is in the accumulated range. If that
    range is still ``full()``, the package is unconstrained and the existing
    sentinel decision proceeds normally (no exception). If the range is
    non-``full()``, this is raised INSTEAD of returning any candidate to the
    solver — never a generic ``SolverError``/``SOLVE-CONFLICT``, and never an
    out-of-range value.

    Deliberately NOT a ``MilpaError`` subclass: ``solver.py`` stays
    domain-agnostic (it doesn't know about manifests, root authority, or error
    slugs). The resolver catches this alongside ``SolverError`` and builds
    ``RES-VERSION-UNKNOWN-CONSTRAINED`` with the root-authority-aware
    branching remedy text (something only the resolver can determine).

    ``constrainers``: every ``(consumer, constraint_str)`` pair that
    contributed a non-``full()`` term on ``package`` — enumerated in full
    (the amoxtli incident floored two packages at once; a serial
    fail-fix-rerun loop is exactly the papercut this RFC avoids).
    """

    def __init__(self, package: str, constrainers: tuple[tuple[str, str], ...]) -> None:
        self.package = package
        self.constrainers = constrainers
        super().__init__(
            f"{package!r} is version-unknown but constrained by: {constrainers!r}"
        )


def _accumulated_constrainers(
    incompats: list[Incompatibility], target_pkg: str, partial: PartialSolution
) -> tuple[tuple[str, str], ...]:
    """Every ``(consumer, constraint_str)`` pair placing a non-``full()``
    constraint on ``target_pkg``, read from the incompatibilities recorded so
    far (mirrors ``SolverError.refutation``'s own walk, but keyed by consumer
    name rather than collapsed to the target package alone — A4 needs to name
    *who* imposed each constraint, not just what the constraint was).

    Only ``"dependency:"``-caused incompatibilities are considered (skips the
    synthetic ``"conflict-blocks:"``/``"root"`` incompats the backtracking
    loop adds — those are solver bookkeeping, not real dep-graph facts).

    R8b (phantom constrainer after backtrack): incompatibilities are
    append-only and RETAINED across backtracking — they're permanent learned
    facts, not undone when a decision is. So an incompat recorded when some
    consumer ``C`` was speculatively decided at version ``v1`` survives even
    after ``C`` is backtracked and re-decided at a different ``v2``. Only the
    consumer's FINAL decided version (``partial.decisions()``, the live
    partial-solution state) may name a constrainer — a stale incompat whose
    consumer term doesn't match ``C``'s final version is a constraint from a
    version that is NOT in the solution, and must be skipped.
    """
    final_decisions = partial.decisions()
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for ic in incompats:
        if not ic.cause.startswith("dependency:"):
            continue
        target_term: Term | None = None
        consumer_term: Term | None = None
        for t in ic.terms:
            if not t.positive and t.package == target_pkg:
                target_term = t
            elif t.positive:
                consumer_term = t
        if target_term is None or consumer_term is None:
            continue
        required = target_term.versions
        if required.is_full():
            continue
        # R8b: the consumer term is always a decision-point singleton
        # (`Term.require(package, VersionSet.eq(chosen))` — see the
        # `dependency:` incompat built in `_make_decision`), same shape
        # `PartialSolution.decisions()` extracts from. Skip this incompat
        # unless the consumer is STILL finally decided at exactly that
        # version — otherwise it's a stale fact from a backtracked-away
        # decision and would name a phantom constrainer.
        consumer_pkg = consumer_term.package
        final_version = final_decisions.get(consumer_pkg)
        if final_version is None:
            continue
        consumer_version = consumer_term.versions.intervals[0][0]
        if consumer_version != final_version:
            continue
        constraint_str = _vs_to_constraint_str(required)
        key = (consumer_pkg, constraint_str)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return tuple(out)


# ---------------------------------------------------------------------------
# Main solve() entry point
# ---------------------------------------------------------------------------


def solve(
    provider: PackageProvider,
    root: str,
    root_version: Version,
    *,
    strategy: Strategy = Strategy.MAXVER,
) -> dict[str, Version]:
    """Resolve a dep graph starting from ``(root, root_version)``.

    Returns ``{package: chosen_version}`` for every package in the closure.
    Raises ``SolverError`` on unsatisfiable constraints.

    ``strategy`` controls candidate selection when multiple versions satisfy
    the current constraint (URL deps with one version are unaffected).
    See ``Strategy`` for the semantics of each mode.
    """
    solution, _ = _solve_internal(provider, root, root_version, strategy=strategy)
    return solution


def solve_with_cert(
    provider: PackageProvider,
    root: str,
    root_version: Version,
    *,
    strategy: Strategy = Strategy.MAXVER,
) -> tuple[dict[str, Version], SolveSuccess]:
    """Like ``solve()``, but also returns the §5.1 success certificate.

    Used by the resolver when ``--certificate`` is active.  Raises
    ``SolverError`` on unsatisfiable constraints (the caller is responsible
    for building the §5.2 failure certificate from the error's ``refutation``).
    """
    solution, incompats = _solve_internal(provider, root, root_version, strategy=strategy)
    cert = build_success_certificate(solution, incompats, root)
    return solution, cert


def _solve_internal(
    provider: PackageProvider,
    root: str,
    root_version: Version,
    *,
    strategy: Strategy = Strategy.MAXVER,
) -> tuple[dict[str, Version], list[Incompatibility]]:
    """Inner solve loop — returns (solution, all_incompats).

    Shared implementation used by both ``solve()`` and ``solve_with_cert()``.
    Raises ``SolverError`` on unsatisfiable constraints.
    """
    incompats: list[Incompatibility] = [
        Incompatibility(
            terms=(Term.forbid(root, VersionSet.eq(root_version)),),
            cause="root",
        ),
    ]
    partial = PartialSolution()
    next_package: str | None = root
    # Track conflicts whose cause is a real dep-graph fact (vs the
    # "conflict-blocks:" incompats we synthesise during backtracking).
    root_cause_conflicts: list[Incompatibility] = []

    iterations = 0
    while True:
        iterations += 1
        if iterations > 10_000:
            raise SolverError(
                ConflictChain(
                    steps=(
                        ConflictStep(
                            consequent_package="<solver>",
                            consequent_description="solver did not converge — likely a bug",
                            antecedents=(),
                            antecedent_constraints=(),
                            cause_tag="convergence-limit",
                        ),
                    )
                ),
                incompats,
            )
        try:
            _unit_propagate(next_package or root, incompats, partial)
            next_package = _make_decision(
                provider,
                incompats,
                partial,
                strategy=strategy,
            )
            if next_package is None:
                return partial.decisions(), incompats
        except _Conflict as conflict:
            if not conflict.incompat.cause.startswith("conflict-blocks:"):
                root_cause_conflicts.append(conflict.incompat)
            # Backtrack one decision level; learn a "don't re-pick" incompat
            # for the undone decision. (Teaching-clean: always one level.
            # Full PubGrub does conflict-driven learning + backjumping. #28.)
            if partial.decision_level == 0:
                raise SolverError(
                    build_conflict_chain(
                        root_cause_conflicts, conflict.incompat, incompats
                    ),
                    incompats,
                ) from None
            target_level = partial.decision_level - 1
            undone = partial.backtrack_to(target_level)
            if undone is None:
                raise SolverError(
                    build_conflict_chain(
                        root_cause_conflicts, conflict.incompat, incompats
                    ),
                    incompats,
                ) from None
            decided_pkg = undone.term.package
            decided_version_raw = undone.term.versions.intervals[0][0]
            assert isinstance(
                decided_version_raw, Version
            ), "decision term lo must be a Version"
            decided_version: Version = decided_version_raw
            incompats.append(
                Incompatibility(
                    terms=(
                        Term.require(decided_pkg, VersionSet.eq(decided_version)),
                    ),
                    cause=f"conflict-blocks:{decided_pkg}@{_v(decided_version)}",
                )
            )
            next_package = decided_pkg


def _unit_propagate(
    starting: str,
    incompats: list[Incompatibility],
    partial: PartialSolution,
) -> None:
    """Process every incompatibility touching ``starting`` (cascading derivations).

    Raises ``_Conflict`` on a fully-satisfied incompatibility.
    """
    changed: set[str] = {starting}
    while changed:
        pkg = changed.pop()
        for incompat in list(incompats):
            if not any(t.package == pkg for t in incompat.terms):
                continue
            rel = partial.relation_to(incompat)
            if rel == TermRelation.SATISFIES:
                raise _Conflict(incompat)
            if rel == TermRelation.CONTRADICTS:
                continue
            unit = partial.unit_term(incompat)
            if unit is None:
                continue
            partial.add_derivation(unit.negate(), cause=incompat)
            changed.add(unit.package)


def _make_decision(
    provider: PackageProvider,
    incompats: list[Incompatibility],
    partial: PartialSolution,
    *,
    strategy: Strategy = Strategy.MAXVER,
) -> str | None:
    """Pick an undecided package, choose a version, add it as a decision,
    and encode its dependencies as new incompatibilities.

    Returns the decided package name, or ``None`` if the solution is complete.
    Raises ``_Conflict`` if the chosen package has no satisfying version.
    Raises ``VersionUnknownConstrained`` (A4) if ``package`` is version-unknown
    and its accumulated range is non-``full()`` at this (last-scheduled)
    decision point.
    """
    package = _next_undecided(partial, provider)
    if package is None:
        return None

    allowed = partial.effective_set(package)

    # A4 (resolver-semantics RFC §3 Axis A (c)): classify a version-unknown
    # package at its own decision point — `_next_undecided` guarantees this is
    # the LAST such package decided, so `allowed` is the complete accumulated
    # range (every constrainer, including a lazily-materialized named/index
    # dep, has already been expanded). `full()` → unconstrained, fall through
    # to the ordinary pick below (the sentinel is trivially in-range). Non-
    # `full()` → hard error, raised BEFORE any candidate is returned — no
    # out-of-range value, no generic SOLVE-CONFLICT.
    if _is_version_unknown(provider, package) and not allowed.is_full():
        raise VersionUnknownConstrained(
            package, _accumulated_constrainers(incompats, package, partial)
        )

    # C2 (resolver-semantics RFC §3 Axis C / §4 stage 4, D-C2): resolve the
    # configured ``strategy`` — which may be the surface-only
    # ``LOWEST_DIRECT`` — to a concrete per-package strategy BEFORE the pick.
    # ``_pick_version`` never sees ``LOWEST_DIRECT``.
    effective_strategy = _effective_strategy_for(provider, package, strategy)

    available = provider.versions(package)
    candidates = [v for v in available if allowed.contains(v)]
    if not candidates:
        raise _Conflict(
            Incompatibility(
                terms=(Term.require(package, allowed),),
                cause=f"no-versions-of-{package}",
            )
        )

    # B2 (resolver-semantics RFC §4 stage 4): the provider assembles the
    # preference from ``params.prior`` (an O(1) lookup, per-package) — the
    # pick itself never learns about lockfiles. A provider with no
    # prior-lock concept (in-memory test fakes) falls through to ``None``
    # via ``_preference_for``'s optional-hook default, so pre-B2 callers are
    # unaffected.
    preference = _preference_for(provider, package)
    chosen = _pick_version(
        candidates, allowed, effective_strategy, package, preference=preference
    )

    for dep_term in provider.dependencies(package, chosen):
        if not dep_term.positive:
            continue
        incompats.append(
            Incompatibility(
                terms=(
                    Term.require(package, VersionSet.eq(chosen)),
                    dep_term.negate(),
                ),
                cause=f"dependency:{package}@{_v(chosen)}",
            )
        )

    partial.add_decision(package, chosen)
    return package


# Axis B (resolver-semantics RFC §4 stage 4): a plain preference value
# threaded into the pure pick. ``None`` means no preference (today's
# behavior). A non-``None`` value is the RFC's ``FromLock(v)`` — the prior
# lockfile's recorded version for this package, assembled *upstream* (B2)
# from ``params.prior``. The picker never learns about lockfiles, manifests,
# or provenance; it only ever sees this plain value.
Preference = Version | None


def _pick_version(
    candidates: list[Version],
    allowed: VersionSet,
    strategy: Strategy,
    package: str,
    preference: Preference = None,
) -> Version:
    """Pick a version from ``candidates`` according to ``strategy``.

    All candidates are guaranteed to satisfy the accumulated constraint
    (already filtered by ``allowed.contains``).

    ``preference`` (Axis B, RFC §4 stage 4) short-circuits the strategy
    ordering — NOT a candidate reorder, which would be inert against the
    order-independent ``max``/lower-bound pick below. If ``preference`` is
    ``FromLock(v)`` (i.e. not ``None``) and ``v`` survived the constraint
    filter (``v in candidates``, which already implies ``v`` is in
    ``allowed``), it wins outright. Otherwise fall through to the ordinary
    strategy pick, unchanged.

    ``strategy`` is always a concrete ``MAXVER``/``MINVER``/``SEMVER`` value
    (C2, resolver-semantics RFC §4 stage 4, D-C2) — ``LowestDirect`` is a
    surface-only value the provider resolves to one of these three, per
    package, BEFORE calling this function (``_effective_strategy_for``). This
    ``match`` deliberately has no ``LowestDirect`` case and never will; the
    trailing ``raise`` documents (and enforces) that invariant rather than
    silently falling through.
    """
    if preference is not None and preference in candidates:
        return preference
    match strategy:
        case Strategy.MAXVER:
            return max(candidates)
        case Strategy.MINVER:
            return min(candidates)
        case Strategy.SEMVER:
            return _pick_semver(candidates, allowed, package)
    raise AssertionError(
        f"_pick_version received {strategy!r}; LowestDirect (and any other "
        "non-concrete strategy) must be resolved to Minver/Maxver/Semver by "
        "_effective_strategy_for before reaching the picker (D-C2)"
    )


def _pick_semver(
    candidates: list[Version],
    allowed: VersionSet,
    package: str,
) -> Version:
    """SemVer: highest candidate within the same major as the constraint's
    lower bound.  If unbounded below, fall back to MaxVer.  If a lower bound
    exists but no candidate shares its major, raise — the constraint can only
    be satisfied by crossing a major boundary, which SemVer refuses.
    """
    lower_bound = _lower_bound_of(allowed)
    if lower_bound is None:
        return max(candidates)
    target_major = lower_bound.major
    same_major = [v for v in candidates if v.major == target_major]
    if not same_major:
        raise _Conflict(
            Incompatibility(
                terms=(Term.require(package, allowed),),
                cause=f"semver-no-same-major-{package}-at-{target_major}",
            )
        )
    return max(same_major)


def _lower_bound_of(vs: VersionSet) -> Version | None:
    """Lowest inclusive lower bound across all intervals; None if any
    interval is unbounded below.
    """
    if not vs.intervals:
        return None
    bounds = [iv[0] for iv in vs.intervals]
    if any(b is None for b in bounds):
        return None
    return min(b for b in bounds if b is not None)


def _is_version_unknown(provider: PackageProvider, package: str) -> bool:
    """A4: query the provider's optional ``is_version_unknown`` hook.

    Not part of the ``PackageProvider`` Protocol's required shape — synthetic
    test providers (e.g. ``DictProvider``) never implement it and correctly
    default to ``False`` (no version-unknown concept exists for them). Only
    the resolver's production provider (which knows about git/url/local/
    tarball candidate labeling) implements it for real.
    """
    checker = getattr(provider, "is_version_unknown", None)
    if checker is None:
        return False
    return bool(checker(package))


def _preference_for(provider: PackageProvider, package: str) -> "Preference":
    """B2: query the provider's optional ``preference`` hook.

    Not part of the ``PackageProvider`` Protocol's required shape — mirrors
    ``_is_version_unknown``'s optional-hook pattern. Synthetic test providers
    (e.g. ``DictProvider``) never implement it and correctly default to
    ``None`` (no prior-lock concept exists for them). Only the resolver's
    production provider (which knows about ``params.prior``) implements it
    for real, returning the prior lockfile's recorded version for ``package``
    (a solver_var string) when one exists — the RFC's ``FromLock(v)``.
    """
    getter = getattr(provider, "preference", None)
    if getter is None:
        return None
    return getter(package)


def _is_root_direct(provider: PackageProvider, package: str) -> bool:
    """C2 (resolver-semantics RFC §3 Axis C): query the provider's optional
    ``is_root_direct`` hook.

    Mirrors ``_is_version_unknown``'s optional-hook pattern — not part of the
    ``PackageProvider`` Protocol's required shape, so synthetic test providers
    with no root-authority concept correctly default to ``False`` (every
    package is treated as transitive). Only the resolver's production
    provider (which knows the manifest's ``root_authority`` set) implements
    it for real.
    """
    checker = getattr(provider, "is_root_direct", None)
    if checker is None:
        return False
    return bool(checker(package))


def _effective_strategy_for(
    provider: PackageProvider, package: str, strategy: Strategy
) -> Strategy:
    """C2 (resolver-semantics RFC §3 Axis C / §4 stage 4, D-C2): resolve the
    configured ``strategy`` to a concrete per-package strategy.

    ``LowestDirect`` is NOT a picker case — it is *exactly* ``MINVER`` for a
    root-direct package (``_is_root_direct``) and ``MAXVER`` otherwise. This
    is the provider-level effective-strategy precompute the RFC's design
    deepening calls for: it is the ONLY place ``Strategy.LOWEST_DIRECT`` is
    ever interpreted. Every other configured strategy passes through
    unchanged. ``_pick_version`` — called only with this function's return
    value — never sees ``Strategy.LOWEST_DIRECT``, and its ``match`` has no
    case for it.
    """
    if strategy is not Strategy.LOWEST_DIRECT:
        return strategy
    return Strategy.MINVER if _is_root_direct(provider, package) else Strategy.MAXVER


def _next_undecided(partial: PartialSolution, provider: PackageProvider) -> str | None:
    """Find a package with positive constraints but no decision yet.

    A4 (resolver-semantics RFC §3 Axis A (c)): version-unknown packages are
    scheduled STRICTLY LAST — deferred to a second pass — so that by the time
    one is decided, every potential constrainer (including a lazily-
    materialized named/index dep) has already been expanded and its floor is
    already in the accumulated range (`effective_set`). This is NOT a static
    pre-classification: `is_version_unknown` is queried fresh on each call, in
    the SAME insertion-order scan this function has always used (fixture-063
    is NORMATIVE on that order) — just gated into two passes. When no
    version-unknown package is in play (the common case — including every
    fixture that predates A4), the deferred list stays empty and this is
    byte-for-byte the original single-pass scan: same order, no behavior
    change.
    """
    seen: set[str] = set()
    deferred: list[str] = []
    for a in partial.assignments:
        pkg = a.term.package
        if pkg in seen:
            continue
        seen.add(pkg)
        if partial.has_decision(pkg):
            continue
        if partial.effective_set(pkg).is_empty():
            continue
        if _is_version_unknown(provider, pkg):
            deferred.append(pkg)
            continue
        return pkg
    return deferred[0] if deferred else None


# ---------------------------------------------------------------------------
# Certificate builder (resolver-semantics §5)
# ---------------------------------------------------------------------------


def build_success_certificate(
    solution: dict[str, Version],
    all_incompats: list[Incompatibility],
    root: str,
) -> SolveSuccess:
    """Build a §5.1 success certificate from a completed solve.

    ``resolved``: every (package, version_str) in the solution (root excluded
    from the witness — it has no external constraint).
    ``witness``:  one WitnessEntry per dep-constraint incompatibility, proving
    each chosen version satisfies the constraint the depender declared.

    The root package itself has no external constraint, so it has no witness
    entries.  Each other package may have one or more entries (one per consumer).
    """
    resolved = tuple(
        (pkg, format_version_str(ver)) for pkg, ver in sorted(solution.items())
    )

    entries: list[WitnessEntry] = []
    seen_keys: set[tuple[str, str, str]] = set()

    for ic in all_incompats:
        if not ic.cause.startswith("dependency:"):
            continue
        # cause = "dependency:<depender>@<version>"
        dep_part = ic.cause[len("dependency:"):]
        at_idx = dep_part.rfind("@")
        depender_pkg = dep_part[:at_idx] if at_idx != -1 else dep_part

        # Positive term = the depender at its chosen version.
        # Negative term(s) = the required package's constraint.
        pos_terms = [t for t in ic.terms if t.positive]
        neg_terms = [t for t in ic.terms if not t.positive]

        for neg_t in neg_terms:
            pkg = neg_t.package
            chosen_version = solution.get(pkg)
            if chosen_version is None:
                continue
            # neg_t is Term.forbid(pkg, required_vs): the incompatibility says
            # "depender@ver AND pkg NOT IN required_vs cannot both hold", meaning
            # depender@ver requires pkg IN required_vs.  The required range is
            # neg_t.versions directly — NOT its complement.
            required_vs = neg_t.versions
            # Use constraint string form so §5.1 predicate can be verified:
            # VersionSet.from_constraint(constraint_str).contains(version).
            constraint_str = _vs_to_constraint_str(required_vs)
            version_str = format_version_str(chosen_version)

            key = (pkg, constraint_str, depender_pkg)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            # Satisfied-by = the depender package (from positive term or cause).
            satisfied_by = pos_terms[0].package if pos_terms else depender_pkg
            entries.append(
                WitnessEntry(
                    package=pkg,
                    version=version_str,
                    constraint=constraint_str,
                    satisfied_by=satisfied_by,
                )
            )

    # Sort witness per spec §2.5.1: lexicographic by package (same order as
    # resolved), then by satisfied_by within the same package.
    entries.sort(key=lambda e: (e.package, e.satisfied_by))

    return SolveSuccess(resolved=resolved, witness=tuple(entries))


# ---------------------------------------------------------------------------
# Error formatting
# ---------------------------------------------------------------------------


def build_conflict_chain(
    root_causes: list[Incompatibility],
    final_incompat: Incompatibility,
    all_incompats: list[Incompatibility],
) -> ConflictChain:
    """Build a structured ConflictChain from the solver's collected conflicts.

    Algorithm (ported verbatim from frozen impl):
    - Build a term-package index: {package → list[Incompatibility]} keyed on
      each package appearing in an incompat's terms. This answers "which
      incompatibilities constrain package X?"
    - The root_cause_conflicts identify which packages triggered conflicts.
      For each such incompat, find the constrained package (negative term) and
      look it up in the index to get ALL dep-incompats that constrain it.
    - Each unique constrained package becomes one ConflictStep.
    """
    term_pkg_index: dict[str, list[Incompatibility]] = {}
    for incompat in all_incompats:
        if not incompat.cause.startswith("dependency:"):
            continue
        for term in incompat.terms:
            term_pkg_index.setdefault(term.package, []).append(incompat)

    steps: list[ConflictStep] = []
    seen_consequents: set[str] = set()

    def _emit_step_for_package(pkg: str, cause_tag: str) -> None:
        if pkg in seen_consequents:
            return
        seen_consequents.add(pkg)

        dep_incompats = term_pkg_index.get(pkg, [])

        depender_terms: list[Term] = []
        constraint_terms: list[Term] = []
        seen_constraints: set[str] = set()

        for dep_ic in dep_incompats:
            pos_terms = [t for t in dep_ic.terms if t.positive and t.package != pkg]
            neg_terms = [t for t in dep_ic.terms if not t.positive and t.package == pkg]
            if not neg_terms:
                continue
            constraint_t = neg_terms[0]
            ck = _term_str(constraint_t)
            if ck in seen_constraints:
                continue
            seen_constraints.add(ck)
            depender_t = pos_terms[0] if pos_terms else constraint_t
            depender_terms.append(depender_t)
            constraint_terms.append(constraint_t)

        if not constraint_terms:
            steps.append(
                ConflictStep(
                    consequent_package=pkg,
                    consequent_description=f"{pkg} has no satisfying version",
                    antecedents=(),
                    antecedent_constraints=(),
                    cause_tag=cause_tag,
                )
            )
            return

        steps.append(
            ConflictStep(
                consequent_package=pkg,
                consequent_description=f"{pkg} has no satisfying version",
                antecedents=tuple(depender_terms),
                antecedent_constraints=tuple(constraint_terms),
                cause_tag=cause_tag,
            )
        )

    real_causes = [
        ic
        for ic in root_causes + [final_incompat]
        if not ic.cause.startswith("conflict-blocks:")
    ]

    for incompat in real_causes:
        if incompat.cause.startswith("dependency:"):
            neg_terms = [t for t in incompat.terms if not t.positive]
            for neg_t in neg_terms:
                _emit_step_for_package(neg_t.package, incompat.cause)
        elif incompat.cause.startswith("no-versions"):
            pos_terms = [t for t in incompat.terms if t.positive]
            for pos_t in pos_terms:
                _emit_step_for_package(pos_t.package, incompat.cause)
        elif incompat.cause.startswith("semver-"):
            pos_terms = [t for t in incompat.terms if t.positive]
            for pos_t in pos_terms:
                cause_tail = incompat.cause
                at_idx = cause_tail.rfind("-at-")
                if at_idx != -1:
                    required_major = cause_tail[at_idx + 4 :]
                    desc = (
                        f"{pos_t.package} has no version with major {required_major} "
                        f"(SEMVER strategy requires same-major as constraint lower bound)"
                    )
                else:
                    desc = (
                        f"{pos_t.package} has no satisfying version "
                        f"(SEMVER major-version constraint)"
                    )
                steps.append(
                    ConflictStep(
                        consequent_package=pos_t.package,
                        consequent_description=desc,
                        antecedents=(pos_t,),
                        antecedent_constraints=(pos_t,),
                        cause_tag=incompat.cause,
                    )
                )

    if not steps:
        terms = list(final_incompat.terms)
        pkg = terms[0].package if terms else "unknown"
        cause = final_incompat.cause
        steps.append(
            ConflictStep(
                consequent_package=pkg,
                consequent_description=f"{pkg} has no satisfying version",
                antecedents=(),
                antecedent_constraints=tuple(terms),
                cause_tag=cause,
            )
        )

    return ConflictChain(steps=tuple(steps))


def render_conflict_chain(chain: ConflictChain) -> str:
    """Render a ConflictChain as human-readable English prose.

    Produces the PubGrub-style derivation:
      "Because a ≥1.0.0 requires shared ≥1.0.0 and b ≥1.0.0 requires
       shared <1.0.0, shared has no satisfying version."

    Human-readable prose is NOT byte-normative (resolver-semantics §5.2).
    """
    if not chain.steps:
        return "version solving failed"

    lines: list[str] = []
    for step in chain.steps:
        dependers = step.antecedents
        constraints = step.antecedent_constraints
        if dependers and constraints:
            clauses: list[str] = []
            for dep_t, con_t in zip(dependers, constraints, strict=True):
                dep_str = _format_set(dep_t.versions)
                con_str = _format_constraint_as_requirement(con_t)
                if dep_t.package == con_t.package:
                    clauses.append(con_str)
                else:
                    clauses.append(
                        f"{dep_t.package} {dep_str} requires"
                        f" {con_t.package} {con_str}"
                    )
            because_str = " and ".join(clauses)
            lines.append(f"  Because {because_str},")
            lines.append(f"    {step.consequent_description}.")
        elif constraints:
            con_strs = " and ".join(_term_str(t) for t in constraints)
            lines.append(f"  Because {con_strs},")
            lines.append(f"    {step.consequent_description}.")
        else:
            lines.append(f"  {step.consequent_description}.")

    return "version solving failed\n" + "\n".join(lines)


def _format_constraint_as_requirement(term: Term) -> str:
    """Render a negative Term as the requirement it encodes.

    In a dep-constraint incompatibility, ``Term.forbid(pkg, vs)`` means
    "pkg NOT IN vs" — the incompatibility fires when this is true.  The
    dep-incompat says that (depender@X AND pkg NOT IN vs) is impossible,
    so the depender *requires* pkg IN vs.  We display ``vs`` directly.
    """
    return _format_set(term.versions)


def _term_str(term: Term) -> str:
    sign = "must be in" if term.positive else "must NOT be in"
    return f"{term.package!r} {sign} {_format_set(term.versions)}"


def _format_set(vs: VersionSet) -> str:
    """Human-readable display of a VersionSet (NOT a parseable constraint string).

    Used only for conflict narration prose (render_conflict_chain) where
    readability matters.  For the §5 certificate's ``constraint`` field,
    use ``_vs_to_constraint_str`` which produces a ``from_constraint``-
    parseable string.
    """
    if not vs.intervals:
        return "(empty)"
    parts: list[str] = []
    for lo, hi, lo_c, hi_c in vs.intervals:
        if lo is None and hi is None:
            parts.append("any")
        elif lo is None and hi is not None:
            end = "]" if hi_c else ")"
            parts.append(f"(-∞, {_v(hi)}{end}")
        elif lo is not None and hi is None:
            start = "[" if lo_c else "("
            parts.append(f"{start}{_v(lo)}, +∞)")
        elif lo is not None and hi is not None and lo == hi and lo_c and hi_c:
            parts.append(f"{{{_v(lo)}}}")
        elif lo is not None and hi is not None:
            start = "[" if lo_c else "("
            end = "]" if hi_c else ")"
            parts.append(f"{start}{_v(lo)}, {_v(hi)}{end}")
    return " ∪ ".join(parts)


def _vs_to_constraint_str(vs: VersionSet) -> str:
    """Convert a ``VersionSet`` to a constraint string parseable by ``VersionSet.from_constraint``.

    Used for the §5 certificate's ``constraint`` field — the result MUST round-trip
    through ``VersionSet.from_constraint`` and produce an equivalent ``VersionSet``.

    Each interval becomes a conjunction of ``>=``/``>``/``<=``/``<``/``==`` clauses
    joined by ``&``; multiple intervals are joined by ``|``.

    Special cases:
      - Empty → ``<0.0.0 & >=0.0.0``  (always-empty expression; the actual
        VersionSet.empty() has no intervals so there are no clauses — represented
        as the empty string is not parseable, so we use a canonical always-empty form)
      - Full (None, None) → ``any version``
    """
    if vs.is_empty():
        return ">0.0.0 & <0.0.0"  # canonical empty expression
    arms: list[str] = []
    for lo, hi, lo_c, hi_c in vs.intervals:
        clauses: list[str] = []
        if lo is None and hi is None:
            return "any version"  # full range
        if lo is not None:
            op = ">=" if lo_c else ">"
            clauses.append(f"{op}{_v(lo)}")
        if hi is not None:
            op = "<=" if hi_c else "<"
            clauses.append(f"{op}{_v(hi)}")
        if not clauses:
            # Should not happen (both None caught above), but be safe.
            return "any version"
        arms.append(" & ".join(clauses))
    return " | ".join(arms)


def _v(v: Version | tuple[int, int, int]) -> str:
    if isinstance(v, Version):
        return format_version_str(v)
    # Plain 3-tuple from interval lo endpoint
    return f"{v[0]}.{v[1]}.{v[2]}"


# ---------------------------------------------------------------------------
# Certificate JSON serialiser — SSOT (resolver-semantics §5 + CLI S10b)
# ---------------------------------------------------------------------------


def certificate_to_json(result: SolveSuccess | SolverError | None) -> str:
    """Serialise a solve result to the §5 certificate JSON schema.

    Success schema::

        {
          "kind": "success",
          "resolved": [{"package": str, "version": str}, ...],
          "witness": [{"package": str, "version": str,
                       "constraint": str, "satisfied_by": str}, ...]
        }

    Failure schema::

        {
          "kind": "failure",
          "message": str | null,   # human-readable prose (NOT byte-normative);
                                   # null for non-solver failures (e.g. RES-UNATTESTED-METADATA)
          "refutation": [{"package": str, "constraint": str}, ...]
        }

    ``result=None`` is the sentinel for a non-solver MilpaError failure
    (e.g. RES-UNATTESTED-METADATA).  Rust emits ``FailureCert { message: "",
    refutation: [] }`` for these cases, which serialises as
    ``{"kind": "failure", "message": null, "refutation": []}``.  Pass None
    when the error is not a SOLVE-CONFLICT and no solver-level refutation is
    available.

    This function is the single serialisation point used by both the
    in-process conformance adapter (S10b) and the ``--certificate`` CLI flag
    (cli-contract.md §2.5).  Do not duplicate serialisation logic elsewhere.
    """
    if result is None:
        # Non-solver failure: kind:failure, message:null, empty refutation.
        # Matches Rust resolve_with_cert's FailureCert { message: "", refutation: [] }
        # which serialises message as null when the string is empty.
        doc: dict[str, object] = {
            "kind": "failure",
            "message": None,
            "refutation": [],
        }
        return json.dumps(doc, indent=2)
    if isinstance(result, SolveSuccess):
        doc: dict[str, object] = {
            "kind": "success",
            "resolved": [
                {"package": pkg, "version": ver} for pkg, ver in result.resolved
            ],
            "witness": [
                {
                    "package": e.package,
                    "version": e.version,
                    "constraint": e.constraint,
                    "satisfied_by": e.satisfied_by,
                }
                for e in result.witness
            ],
        }
    else:
        doc = {
            "kind": "failure",
            "message": str(result),
            "refutation": [
                {"package": e.package, "constraint": e.constraint}
                for e in result.refutation
            ],
        }
    return json.dumps(doc, indent=2)
