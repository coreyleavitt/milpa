"""PubGrub-based version solver.

Teaching-clean form of the algorithm from Natalie Weizenbaum's
"PubGrub: Next-Generation Version Solving". Correct semantics, omits
some performance optimizations (full backjumping, decision-level
caching) tracked at issue #28.

The solver knows nothing about fetching, .nimble files, or registries.
It operates on a `PackageProvider` abstraction that, given a package
name and version, returns the package's dependencies as `Term`s. The
production provider (resolver.py) is built from milpa's fetcher +
registry + nimble_parse pieces; test providers are synthetic dicts.

Key concepts:
  - Term:           a positive/negative version-set constraint on a package
  - Incompatibility: conjunction of Terms that must NOT all hold (i.e. a
                    constraint of the form "these can't all be true")
  - PartialSolution: ordered list of Assignments (decisions or derivations)
  - solve():         main loop: unit-propagate, decide, conflict-resolve

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
        we ship the simpler form for v0.)
     c. Otherwise: pick an undecided package + version, add it as a
        decision, encode its dependencies as new incompatibilities.
  3. When all packages with positive constraints are decided, extract
     and return the solution.
"""

from dataclasses import dataclass, field
from enum import Enum, StrEnum
from typing import Protocol
import re


class Strategy(StrEnum):
    """How the solver picks among candidates satisfying the current
    constraint. Only affects packages with multiple satisfying
    versions; URL deps (singleton-version) are unaffected.

    - MAXVER: highest version (default; good for applications)
    - MINVER: lowest version (good for libraries — locks against the
      declared floor; surfaces accidental use of newer features)
    - SEMVER: highest within same-major as the constraint's lower
      bound (protects against accidental cross-major upgrades)
    """
    MAXVER = "maxver"
    MINVER = "minver"
    SEMVER = "semver"


Version = tuple[int, int, int]


_VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")


def parse_version(text: str) -> Version | None:
    """Parse a version string to a (major, minor, patch) triple.

    Accepts an optional `v` prefix (`v0.5.1` and `0.5.1` both parse).
    Returns `None` for tags milpa v0 doesn't model — prereleases,
    build metadata, non-canonical prefixes (`nimble-1.2.3`). Callers
    decide whether to skip silently or treat as error.

    This is the canonical version parser used by both the solver
    (for constraint clause parsing) and the registry (for filtering
    available tags). Single source of truth across milpa.
    """
    if text is None:
        return None
    m = _VERSION_RE.fullmatch(text.strip())
    if m is None:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


# ---------------------------------------------------------------------------
# VersionSet — union of disjoint half-open intervals over Version.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VersionSet:
    """Union of disjoint half-open intervals [lo, hi). `None` means
    unbounded on that side. Intervals sorted by lo, non-overlapping,
    no zero-width intervals."""

    intervals: tuple[tuple[Version | None, Version | None], ...]

    @classmethod
    def full(cls) -> "VersionSet":
        return cls(intervals=((None, None),))

    @classmethod
    def empty(cls) -> "VersionSet":
        return cls(intervals=())

    @classmethod
    def gte(cls, v: Version) -> "VersionSet":
        return cls(intervals=((v, None),))

    @classmethod
    def gt(cls, v: Version) -> "VersionSet":
        return cls.gte(v).intersect(cls.eq(v).complement())

    @classmethod
    def lt(cls, v: Version) -> "VersionSet":
        return cls(intervals=((None, v),))

    @classmethod
    def lte(cls, v: Version) -> "VersionSet":
        return cls.lt(v).union(cls.eq(v))

    @classmethod
    def eq(cls, v: Version) -> "VersionSet":
        """Single point [v, v_next)."""
        v_next = (v[0], v[1], v[2] + 1)
        return cls(intervals=((v, v_next),))

    @classmethod
    def from_constraint(cls, constraint: str | None) -> "VersionSet":
        if constraint is None or constraint.strip() in ("", "any version"):
            return cls.full()
        clauses = [c.strip() for c in constraint.split("&")]
        result = cls.full()
        for clause in clauses:
            result = result.intersect(cls._parse_clause(clause))
        return result

    @classmethod
    def _parse_clause(cls, clause: str) -> "VersionSet":
        parts = clause.split(None, 1)
        if len(parts) != 2:
            raise ValueError(f"unparseable constraint clause: {clause!r}")
        op, ver_str = parts[0], parts[1]
        v = parse_version(ver_str)
        if v is None:
            raise ValueError(f"unparseable version in constraint: {ver_str!r}")
        match op:
            case ">=": return cls.gte(v)
            case "<=": return cls.lte(v)
            case ">":  return cls.gt(v)
            case "<":  return cls.lt(v)
            case "==": return cls.eq(v)
            case _:
                raise ValueError(f"unknown comparison op {op!r}")

    def contains(self, v: Version) -> bool:
        for lo, hi in self.intervals:
            if lo is not None and v < lo:
                continue
            if hi is not None and v >= hi:
                continue
            return True
        return False

    def is_empty(self) -> bool:
        return not self.intervals

    def intersect(self, other: "VersionSet") -> "VersionSet":
        out: list[tuple[Version | None, Version | None]] = []
        for a_lo, a_hi in self.intervals:
            for b_lo, b_hi in other.intervals:
                lo = _max_lo(a_lo, b_lo)
                hi = _min_hi(a_hi, b_hi)
                if _interval_nonempty(lo, hi):
                    out.append((lo, hi))
        return VersionSet(intervals=tuple(_normalize_intervals(out)))

    def union(self, other: "VersionSet") -> "VersionSet":
        return VersionSet(
            intervals=tuple(_normalize_intervals(
                list(self.intervals) + list(other.intervals)
            ))
        )

    def complement(self) -> "VersionSet":
        if not self.intervals:
            return VersionSet.full()
        out: list[tuple[Version | None, Version | None]] = []
        first_lo = self.intervals[0][0]
        if first_lo is not None:
            out.append((None, first_lo))
        for i in range(len(self.intervals) - 1):
            _, hi = self.intervals[i]
            next_lo, _ = self.intervals[i + 1]
            out.append((hi, next_lo))
        last_hi = self.intervals[-1][1]
        if last_hi is not None:
            out.append((last_hi, None))
        return VersionSet(intervals=tuple(out))

    def is_subset_of(self, other: "VersionSet") -> bool:
        """`self` ⊆ `other` iff `self ∩ other^c = ∅`."""
        return self.intersect(other.complement()).is_empty()


def _max_lo(a: Version | None, b: Version | None) -> Version | None:
    if a is None: return b
    if b is None: return a
    return max(a, b)


def _min_hi(a: Version | None, b: Version | None) -> Version | None:
    if a is None: return b
    if b is None: return a
    return min(a, b)


def _interval_nonempty(lo: Version | None, hi: Version | None) -> bool:
    if lo is None or hi is None:
        return True
    return lo < hi


def _normalize_intervals(
    intervals: list[tuple[Version | None, Version | None]],
) -> list[tuple[Version | None, Version | None]]:
    def lo_key(iv):
        return (0,) if iv[0] is None else (1, iv[0])
    sorted_ivs = sorted(intervals, key=lo_key)
    merged: list[tuple[Version | None, Version | None]] = []
    for lo, hi in sorted_ivs:
        if not _interval_nonempty(lo, hi):
            continue
        if merged:
            prev_lo, prev_hi = merged[-1]
            # Overlap conditions (any one of):
            #   - prev extends to +∞ (prev_hi is None)
            #   - current starts at -∞ (lo is None) — always overlaps a
            #     non-empty prev. Found by Hypothesis 2026-05-22 in #63:
            #     prior code only checked `lo is not None and lo <= prev_hi`
            #     so two `lo=None` intervals failed to merge, breaking the
            #     union-with-full identity property.
            #   - current's lo is at or before prev's upper bound
            if prev_hi is None or lo is None or lo <= prev_hi:
                new_hi = (None if (prev_hi is None or hi is None)
                          else max(prev_hi, hi))
                merged[-1] = (prev_lo, new_hi)
                continue
        merged.append((lo, hi))
    return merged


# ---------------------------------------------------------------------------
# Term + Incompatibility
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Term:
    """A version-set constraint on a single package.

    positive=True  → "this package's version must be in `versions`"
    positive=False → "this package's version must NOT be in `versions`"
    """
    package: str
    positive: bool
    versions: VersionSet

    @classmethod
    def require(cls, package: str, versions: VersionSet) -> "Term":
        return cls(package=package, positive=True, versions=versions)

    @classmethod
    def forbid(cls, package: str, versions: VersionSet) -> "Term":
        return cls(package=package, positive=False, versions=versions)

    def negate(self) -> "Term":
        return Term(self.package, not self.positive, self.versions)


@dataclass(frozen=True)
class Incompatibility:
    """A conjunction of Terms that must NOT all simultaneously hold.

    cause is a human-readable string used in error messages — "root",
    "dependency:<pkg>@<version>", "no-versions", etc.
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
    kind: str   # "decision" | "derivation"
    cause: Incompatibility | None   # for derivations only
    decision_level: int = 0


@dataclass
class PartialSolution:
    assignments: list[Assignment] = field(default_factory=list)
    decision_level: int = 0
    # Cache of effective positive Term per package after intersect of all
    # positive constraints; cleared on each new assignment.
    _effective_cache: dict[str, VersionSet] = field(default_factory=dict)

    def add_decision(self, package: str, version: Version) -> None:
        self.decision_level += 1
        self.assignments.append(Assignment(
            term=Term.require(package, VersionSet.eq(version)),
            kind="decision",
            cause=None,
            decision_level=self.decision_level,
        ))
        self._effective_cache.pop(package, None)

    def add_derivation(self, term: Term, cause: Incompatibility) -> None:
        self.assignments.append(Assignment(
            term=term, kind="derivation", cause=cause,
            decision_level=self.decision_level,
        ))
        self._effective_cache.pop(term.package, None)

    def backtrack_to(self, level: int) -> Assignment | None:
        """Drop every assignment whose decision_level > `level`. Returns the
        most recent decision that was undone (None if no decision was undone).
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
                # The decision term is `require(pkg, eq(version))` — the
                # single version in `versions` is the chosen one.
                iv = a.term.versions.intervals[0]
                out[a.term.package] = iv[0]   # type: ignore[assignment]
        return out

    def effective_set(self, package: str) -> VersionSet:
        """Intersection of all positive constraints on `package`,
        intersected with complement of negative constraints. The set
        of versions still allowed under the partial solution.
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
        return any(a.kind == "decision" and a.term.package == package
                   for a in self.assignments)

    def relation_to(self, incompat: Incompatibility) -> TermRelation:
        """How does the partial solution relate to this incompatibility?

        - SATISFIES: every term is satisfied (incompat is fully active —
          this is a CONFLICT because the incompat says these can't all hold)
        - CONTRADICTS: at least one term is contradicted (incompat
          can't fire)
        - INCONCLUSIVE: some term is neither satisfied nor contradicted
        """
        almost = None
        for term in incompat.terms:
            rel = self._term_relation(term)
            if rel == TermRelation.CONTRADICTS:
                return TermRelation.CONTRADICTS
            if rel == TermRelation.INCONCLUSIVE:
                if almost is not None:
                    # Two inconclusive terms → not unit yet
                    return TermRelation.INCONCLUSIVE
                almost = term
        return TermRelation.INCONCLUSIVE if almost is not None else TermRelation.SATISFIES

    def unit_term(self, incompat: Incompatibility) -> Term | None:
        """If `incompat` is "almost satisfied" (all but one term satisfied
        and the remaining is inconclusive), return the remaining term.
        Otherwise None."""
        unit = None
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
        # If we have NO information about this package, the term is
        # inconclusive — we can't prove it satisfied or contradicted.
        # PubGrub's effective_set treating absence as full() would
        # confuse e.g. `forbid(foo, full())` (which means "foo has no
        # valid version") as contradicted, when it's actually
        # inconclusive until foo gets a constraint.
        if not any(a.term.package == term.package for a in self.assignments):
            return TermRelation.INCONCLUSIVE
        current = self.effective_set(term.package)
        if term.positive:
            allowed = term.versions
        else:
            allowed = term.versions.complement()
        if current.is_subset_of(allowed):
            return TermRelation.SATISFIES
        if current.intersect(allowed).is_empty():
            return TermRelation.CONTRADICTS
        return TermRelation.INCONCLUSIVE


# ---------------------------------------------------------------------------
# Provider protocol + Solver
# ---------------------------------------------------------------------------

class PackageProvider(Protocol):
    def versions(self, package: str) -> list[Version]: ...
    def dependencies(self, package: str, version: Version) -> list[Term]: ...


class SolverError(Exception):
    """Raised when no solution exists.

    The message includes the constraint chain that produced the
    contradiction.
    """


class _Conflict(Exception):
    """Internal: a conflict that the solver may resolve via backtracking."""
    def __init__(self, incompat: Incompatibility):
        self.incompat = incompat


def solve(
    provider: PackageProvider,
    root: str,
    root_version: Version,
    *,
    strategy: Strategy = Strategy.MAXVER,
) -> dict[str, Version]:
    """Resolve a dep graph starting from `(root, root_version)`.

    Returns `{package: chosen_version}` for every package in the closure.
    Raises SolverError on unsatisfiable constraints (after exhausting
    backtracking).

    `strategy` controls how candidates are picked when multiple
    satisfy the current constraint (URL deps with one version are
    unaffected). See `Strategy` for the semantics of each mode.
    """
    incompats: list[Incompatibility] = [
        Incompatibility(
            terms=(Term.forbid(root, VersionSet.eq(root_version)),),
            cause="root",
        ),
    ]
    partial = PartialSolution()
    next_package = root
    # Track conflicts whose cause is a real dep-graph fact (vs the
    # "conflict-blocks:" incompats we synthesize during backtracking).
    # On final failure we narrate the original conflicts, not just the
    # last-blocked-decision incompat.
    root_cause_conflicts: list[Incompatibility] = []

    iterations = 0
    while True:
        iterations += 1
        if iterations > 10_000:
            raise SolverError("solver did not converge — likely a bug")
        try:
            _unit_propagate(next_package, incompats, partial)
            next_package = _make_decision(
                provider, incompats, partial, strategy=strategy,
            )
            if next_package is None:
                return partial.decisions()
        except _Conflict as conflict:
            if not conflict.incompat.cause.startswith("conflict-blocks:"):
                root_cause_conflicts.append(conflict.incompat)
            # Backtrack one decision level, learn a "don't re-pick" incompat
            # for the undone decision. (Teaching-clean: always one level.
            # Full PubGrub does conflict-driven incompatibility learning +
            # multi-level backjumping. Tracked at #28.)
            if partial.decision_level == 0:
                raise SolverError(_format_conflict_chain(
                    root_cause_conflicts, conflict.incompat, partial
                ))
            target_level = partial.decision_level - 1
            undone = partial.backtrack_to(target_level)
            if undone is None:
                raise SolverError(_format_conflict_chain(
                    root_cause_conflicts, conflict.incompat, partial
                ))
            decided_pkg = undone.term.package
            decided_version = undone.term.versions.intervals[0][0]
            incompats.append(Incompatibility(
                terms=(Term.require(decided_pkg, VersionSet.eq(decided_version)),),
                cause=f"conflict-blocks:{decided_pkg}@{_v(decided_version)}",
            ))
            next_package = decided_pkg


def _unit_propagate(
    starting: str,
    incompats: list[Incompatibility],
    partial: PartialSolution,
) -> None:
    """Process every incompatibility touching `starting` (and any packages
    derivations cascade into). Raises `_Conflict` on satisfied incompat."""
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
    """Pick a package with positive constraints but no decision yet,
    choose a version, add it as a decision, and encode its dependencies
    as new incompatibilities. Returns the package name decided, or None
    if no package needs deciding (= solution complete). Raises `_Conflict`
    if the chosen package has no satisfying version."""
    package = _next_undecided(partial)
    if package is None:
        return None

    allowed = partial.effective_set(package)
    available = provider.versions(package)
    candidates = [v for v in available if allowed.contains(v)]
    if not candidates:
        raise _Conflict(Incompatibility(
            terms=(Term.require(package, allowed),),
            cause=f"no-versions-of-{package}",
        ))

    chosen = _pick_version(candidates, allowed, strategy, package)

    for dep_term in provider.dependencies(package, chosen):
        if not dep_term.positive:
            continue
        incompats.append(Incompatibility(
            terms=(
                Term.require(package, VersionSet.eq(chosen)),
                dep_term.negate(),
            ),
            cause=f"dependency:{package}@{_v(chosen)}",
        ))

    partial.add_decision(package, chosen)
    return package


def _pick_version(
    candidates: list[Version],
    allowed: VersionSet,
    strategy: Strategy,
    package: str,
) -> Version:
    """Pick a version from `candidates` according to `strategy`.

    All candidates are guaranteed to satisfy the accumulated constraint
    (already filtered by `allowed.contains`).
    """
    match strategy:
        case Strategy.MAXVER:
            return max(candidates)
        case Strategy.MINVER:
            return min(candidates)
        case Strategy.SEMVER:
            return _pick_semver(candidates, allowed, package)


def _pick_semver(
    candidates: list[Version],
    allowed: VersionSet,
    package: str,
) -> Version:
    """SemVer: highest candidate within the same major as the
    constraint's lower bound. If no lower bound exists (unbounded
    below), fall back to MaxVer. If a lower bound exists but no
    candidate shares its major, raise — the constraint can only be
    satisfied by crossing a major boundary, which SemVer refuses."""
    lower_bound = _lower_bound_of(allowed)
    if lower_bound is None:
        return max(candidates)
    target_major = lower_bound[0]
    same_major = [v for v in candidates if v[0] == target_major]
    if not same_major:
        raise _Conflict(Incompatibility(
            terms=(Term.require(package, allowed),),
            cause=f"semver-no-same-major-{package}-at-{target_major}",
        ))
    return max(same_major)


def _lower_bound_of(vs: VersionSet) -> Version | None:
    """Lowest inclusive lower bound across all intervals; None if any
    interval is unbounded below."""
    if not vs.intervals:
        return None
    bounds = [lo for lo, _ in vs.intervals]
    if any(b is None for b in bounds):
        return None
    return min(b for b in bounds if b is not None)


def _next_undecided(partial: PartialSolution) -> str | None:
    """Find a package with positive constraints in the partial solution
    that hasn't been decided yet."""
    seen: set[str] = set()
    for a in partial.assignments:
        pkg = a.term.package
        if pkg in seen:
            continue
        seen.add(pkg)
        if partial.has_decision(pkg):
            continue
        if not partial.effective_set(pkg).is_empty():
            return pkg
    return None


# ---------------------------------------------------------------------------
# Error formatting
# ---------------------------------------------------------------------------

def _format_conflict_chain(
    root_causes: list[Incompatibility],
    final_incompat: Incompatibility,
    partial: PartialSolution,
) -> str:
    """Produce a multi-conflict narration covering every real dep-graph
    contradiction the solver hit before giving up."""
    lines = ["version solving failed"]
    # De-duplicate root causes by their string representation.
    seen: set[str] = set()
    for incompat in root_causes + [final_incompat]:
        if incompat.cause.startswith("conflict-blocks:"):
            continue
        key = "|".join(_term_str(t) for t in incompat.terms)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"  conflict ({incompat.cause}):")
        for term in incompat.terms:
            lines.append(f"    {_term_str(term)}")
    return "\n".join(lines)


def _term_str(term: Term) -> str:
    sign = "must be in" if term.positive else "must NOT be in"
    return f"{term.package!r} {sign} {_format_set(term.versions)}"


def _format_set(vs: VersionSet) -> str:
    if not vs.intervals:
        return "(empty)"
    parts: list[str] = []
    for lo, hi in vs.intervals:
        if lo is None and hi is None:
            parts.append("any")
        elif lo is None:
            parts.append(f"< {_v(hi)}")
        elif hi is None:
            parts.append(f">= {_v(lo)}")
        else:
            parts.append(f"[{_v(lo)}, {_v(hi)})")
    return " ∪ ".join(parts)


def _v(v: Version) -> str:
    return f"{v[0]}.{v[1]}.{v[2]}"
