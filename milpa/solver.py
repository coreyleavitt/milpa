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
from functools import total_ordering
from typing import Protocol
import re


# ---------------------------------------------------------------------------
# Conflict narration structures (P3.4)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConflictStep:
    """One step in a PubGrub conflict derivation.

    consequent_package: the package whose version space is constrained
      (or exhausted) by this step.
    consequent_description: human-readable description of what happened
      to the consequent (e.g. "has no satisfying version").
    antecedents: the *depender* Terms (positive terms from dep-constraint
      incompatibilities) that introduce conflicting requirements on the
      consequent package.  E.g. for "a@1.0.0 requires shared ≥1.0.0",
      the antecedent Term is the positive ``a`` term.  Each antecedent
      pairs with the corresponding entry in ``antecedent_constraints``.
    antecedent_constraints: the constraint Terms for the consequent
      package from each dep-incompatibility (the negative terms, i.e.
      what the depender *requires* of the consequent).  Parallel to
      ``antecedents`` — same length.
    cause_tag: the raw cause string from the incompatibility that
      triggered this step (e.g. "dependency:a@1.0.0").
    """
    consequent_package: str
    consequent_description: str
    antecedents: tuple["Term", ...]
    antecedent_constraints: tuple["Term", ...]
    cause_tag: str


@dataclass(frozen=True)
class ConflictChain:
    """Structured PubGrub conflict derivation — an ordered list of steps.

    The chain is ordered from root causes to final conclusion.  Each
    step names the package whose resolution fails and the antecedent
    Terms (dependency requirements) that force the failure.

    Use ``render_conflict_chain`` to produce human-readable prose; use
    the ``steps`` field directly for structural assertions in tests.
    """
    steps: tuple[ConflictStep, ...]


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


@total_ordering
class Version:
    """Semantic version with semver-2.0 total order (P3.1b).

    Carries major/minor/patch as ints, pre as a tuple of (int | str)
    identifiers (empty = release), and build as a str (empty = none).
    Build metadata is parsed and stored for round-trip but IGNORED for
    equality and ordering per semver 2.0.

    Backward-compat drop-in for bare 3-tuples (P3.1a invariant):
      - Version(1,0,0) == (1,0,0) and hash(Version(1,0,0)) == hash((1,0,0))
        so existing dict[(x,y,z)] lookups and equality checks with bare
        tuples continue to work without modification.
      - v[0]/v[1]/v[2] index access is preserved via __getitem__.
      - Version(1,0,0,pre=('alpha',)) != (1,0,0) (different pre ≠ release).

    Prerelease total order (semver 2.0 §11):
      1. Pre-release version has lower precedence than the release it
         annotates: 1.0.0-alpha < 1.0.0.
      2. Pre-release identifiers compared left-to-right:
         - Numeric identifiers compared numerically.
         - Alphanumeric identifiers compared in ASCII order.
         - Numeric identifiers always have lower precedence than
           alphanumeric identifiers.
      3. A larger set of identifiers has higher precedence than a smaller
         set (when all preceding identifiers are equal).
    """

    __slots__ = ("major", "minor", "patch", "pre", "build")

    def __init__(
        self,
        major: int,
        minor: int,
        patch: int,
        pre: tuple = (),
        build: str = "",
    ) -> None:
        object.__setattr__(self, "major", major)
        object.__setattr__(self, "minor", minor)
        object.__setattr__(self, "patch", patch)
        object.__setattr__(self, "pre", pre)
        object.__setattr__(self, "build", build)

    def __setattr__(self, name, value):
        raise AttributeError("Version is immutable")

    def __getitem__(self, index: int) -> int:
        """Support v[0]/v[1]/v[2] index access for backward compat."""
        if index == 0:
            return self.major
        if index == 1:
            return self.minor
        if index == 2:
            return self.patch
        raise IndexError(f"Version index {index} out of range (0-2)")

    def __iter__(self):
        """Support iteration / unpacking for backward compat.

        Yields only (major, minor, patch) — the 3-element tuple that
        existing code expects. Build metadata and prerelease are not
        yielded so that `tuple(v)` == `(major, minor, patch)` and
        dict[(x,y,z)] lookups continue to work.
        """
        yield self.major
        yield self.minor
        yield self.patch

    def __len__(self) -> int:
        return 3

    def _precedence_key(self):
        """Comparison key for semver precedence (build ignored).

        Returns (major, minor, patch, is_release, pre_key) where:
          - is_release=1 for releases (no prerelease, sorts above pre)
          - is_release=0 for prereleases
          - pre_key is the semver-ordered prerelease key
        """
        if not self.pre:
            return (self.major, self.minor, self.patch, 1, ())
        # Per semver: numeric identifiers sort before alphanumeric.
        # Represent each identifier as (0, n) for numeric or (1, s) for alpha.
        pre_key = tuple(
            (0, id_) if isinstance(id_, int) else (1, id_)
            for id_ in self.pre
        )
        return (self.major, self.minor, self.patch, 0, pre_key)

    def __eq__(self, other) -> bool:
        """Equality ignores build metadata (semver 2.0).

        For release versions (empty pre), also equals a plain 3-tuple
        (major, minor, patch) for backward compat with existing code
        that uses bare tuples as dict keys and in equality checks.
        """
        if isinstance(other, Version):
            return self._precedence_key() == other._precedence_key()
        if isinstance(other, tuple) and len(other) == 3:
            # Compare as a release version: this works correctly for
            # prerelease versions too — Version(1,0,0,pre=('alpha',)) has
            # precedence_key (1,0,0,0,...) which != (1,0,0) so they won't
            # equal.
            # We compare by constructing a release Version from the tuple.
            return self._precedence_key() == Version(other[0], other[1], other[2])._precedence_key()
        return NotImplemented

    def __hash__(self) -> int:
        """Hash consistent with __eq__.

        Release versions (empty pre) hash identically to the plain
        3-tuple (major, minor, patch) so that existing dict[(x,y,z)]
        lookups hit entries keyed by Version(x,y,z) and vice versa.
        """
        if not self.pre:
            return hash((self.major, self.minor, self.patch))
        # Prerelease versions: hash the full precedence key so that
        # Version(1,0,0,pre=('alpha',)) != Version(1,0,0) in sets/dicts.
        return hash(self._precedence_key())

    def __lt__(self, other) -> bool:
        if isinstance(other, Version):
            return self._precedence_key() < other._precedence_key()
        if isinstance(other, tuple) and len(other) == 3:
            return self._precedence_key() < Version(other[0], other[1], other[2])._precedence_key()
        return NotImplemented

    def __le__(self, other) -> bool:
        if isinstance(other, Version):
            return self._precedence_key() <= other._precedence_key()
        if isinstance(other, tuple) and len(other) == 3:
            return self._precedence_key() <= Version(other[0], other[1], other[2])._precedence_key()
        return NotImplemented

    def __gt__(self, other) -> bool:
        if isinstance(other, Version):
            return self._precedence_key() > other._precedence_key()
        if isinstance(other, tuple) and len(other) == 3:
            return self._precedence_key() > Version(other[0], other[1], other[2])._precedence_key()
        return NotImplemented

    def __ge__(self, other) -> bool:
        if isinstance(other, Version):
            return self._precedence_key() >= other._precedence_key()
        if isinstance(other, tuple) and len(other) == 3:
            return self._precedence_key() >= Version(other[0], other[1], other[2])._precedence_key()
        return NotImplemented

    def __repr__(self) -> str:
        s = f"Version({self.major}, {self.minor}, {self.patch}"
        if self.pre:
            s += f", pre={self.pre!r}"
        if self.build:
            s += f", build={self.build!r}"
        s += ")"
        return s

    def __str__(self) -> str:
        return _format_version_str(self)


def _format_version_str(v: "Version") -> str:
    """Format a Version as a semver string (major.minor.patch[-pre][+build])."""
    s = f"{v.major}.{v.minor}.{v.patch}"
    if v.pre:
        s += "-" + ".".join(str(id_) for id_ in v.pre)
    if v.build:
        s += "+" + v.build
    return s


# Semver regex: optional v-prefix, M.m.p, optional -pre, optional +build.
# Pre-release identifiers: dot-separated alphanumeric+hyphen identifiers.
# Build metadata: dot-separated alphanumeric+hyphen identifiers.
_VERSION_RE = re.compile(
    r"v?(\d+)\.(\d+)\.(\d+)"
    r"(?:-([0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*))?"
    r"(?:\+([0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*))?"
    r"\Z"
)


def _parse_pre_identifiers(pre_str: str) -> tuple:
    """Parse a semver prerelease string into a tuple of (int | str) identifiers.

    Per semver 2.0: identifiers consisting entirely of digits are parsed
    as integers (no leading zeros). Others remain strings.
    """
    ids = []
    for part in pre_str.split("."):
        if part.isdigit():
            ids.append(int(part))
        else:
            ids.append(part)
    return tuple(ids)


def parse_version(text: str) -> "Version | None":
    """Parse a semver string to a Version.

    Accepts an optional `v` prefix (`v0.5.1` and `0.5.1` both parse).
    Parses prerelease identifiers (stored in `pre`) and build metadata
    (stored in `build`). Build metadata is preserved for round-trip but
    ignored for ordering and equality per semver 2.0.

    Returns `None` for non-canonical tags (e.g., `nimble-1.2.3`).
    Callers decide whether to skip silently or treat as error.

    This is the canonical version parser used by both the solver
    (for constraint clause parsing) and the registry (for filtering
    available tags). Single source of truth across milpa.
    """
    if text is None:
        return None
    m = _VERSION_RE.fullmatch(text.strip())
    if m is None:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3))
    pre_str = m.group(4)
    build_str = m.group(5)
    pre = _parse_pre_identifiers(pre_str) if pre_str else ()
    build = build_str if build_str else ""
    return Version(major, minor, patch, pre=pre, build=build)


# ---------------------------------------------------------------------------
# VersionSet — union of disjoint generalized intervals over Version.
#
# P3.1b interval representation: each interval is a 4-tuple
#   (lo, hi, lo_closed, hi_closed)
# where:
#   lo = Version | None (None = -∞, always exclusive)
#   hi = Version | None (None = +∞, always exclusive)
#   lo_closed = bool: True → lo is inclusive (lo <= v), False → exclusive (lo < v)
#   hi_closed = bool: True → hi is inclusive (v <= hi), False → exclusive (v < hi)
#
# Existing half-open [lo, hi) intervals are (lo, hi, True, False).
# Closed singletons {v} used by eq(v) are (v, v, True, True).
# Open-left intervals (v, +∞) used by complement of {v} are (v, None, False, True).
# ---------------------------------------------------------------------------

# Type alias for the 4-tuple interval representation.
_Interval = tuple  # (lo, hi, lo_closed, hi_closed) — all 4 elements


@dataclass(frozen=True)
class VersionSet:
    """Union of disjoint generalized intervals over Version.

    Each interval is a 4-tuple (lo, hi, lo_closed, hi_closed):
      - lo/hi: Version endpoints (None = unbounded)
      - lo_closed: True → lo inclusive ([lo,...), False → exclusive ((lo,...))
      - hi_closed: True → hi inclusive (...,hi]), False → exclusive (...,hi))

    Canonical form: intervals sorted by lo, non-overlapping, no empty
    intervals, adjacent intervals merged when they share a common point
    that is inclusive on at least one side.

    eq(v) is the true singleton {v} = (v, v, True, True). This is the
    P3.1b fix: the old [v, v_next) half-open representation admitted
    prerelease versions of v_next because prereleases sort below their
    release. The closed-point form is structurally exact.
    """

    intervals: tuple

    @classmethod
    def full(cls) -> "VersionSet":
        return cls(intervals=((None, None, True, False),))

    @classmethod
    def empty(cls) -> "VersionSet":
        return cls(intervals=())

    @classmethod
    def gte(cls, v: Version) -> "VersionSet":
        return cls(intervals=((v, None, True, False),))

    @classmethod
    def gt(cls, v: Version) -> "VersionSet":
        return cls.gte(v).intersect(cls.eq(v).complement())

    @classmethod
    def lt(cls, v: Version) -> "VersionSet":
        return cls(intervals=((None, v, True, False),))

    @classmethod
    def lte(cls, v: Version) -> "VersionSet":
        return cls.lt(v).union(cls.eq(v))

    @classmethod
    def eq(cls, v: Version) -> "VersionSet":
        """True singleton {v} — the P3.1b closed-point representation.

        (v, v, True, True) is a closed-closed interval meaning exactly
        {v}. This is structurally correct: no other version can satisfy
        both lo <= w <= hi when lo == hi == v.

        Prior to P3.1b this used [v, v_next) which admitted prerelease
        versions of v_next (since e.g. 1.0.1-rc.1 < 1.0.1, the interval
        [1.0.0, 1.0.1) wrongly contained 1.0.1-rc.1).
        """
        return cls(intervals=((v, v, True, True),))

    @classmethod
    def from_constraint(cls, constraint: str | None) -> "VersionSet":
        if constraint is None or constraint.strip() in ("", "any version"):
            return cls.full()
        # OR has lower precedence than AND: split on || or | first, then
        # each arm is a conjunction of &-separated clauses.
        arms = re.split(r"\|\|?", constraint)
        result = cls.empty()
        for arm in arms:
            arm_clauses = [c.strip() for c in arm.split("&")]
            arm_result = cls.full()
            for clause in arm_clauses:
                arm_result = arm_result.intersect(cls._parse_clause(clause))
            result = result.union(arm_result)
        return result

    @classmethod
    def _parse_clause(cls, clause: str) -> "VersionSet":
        clause = clause.strip()
        # Match longest operators first to avoid prefix collisions
        # (>= before >, <= before <, == and != before =).
        for op in (">=", "<=", "==", "!=", ">", "<", "~", "^", "="):
            if clause.startswith(op):
                ver_str = clause[len(op):].strip()
                v = parse_version(ver_str)
                if v is None:
                    raise ValueError(
                        f"unparseable version in constraint: {ver_str!r}"
                    )
                match op:
                    case ">=": return cls.gte(v)
                    case "<=": return cls.lte(v)
                    case ">":  return cls.gt(v)
                    case "<":  return cls.lt(v)
                    case "==" | "=": return cls.eq(v)
                    case "!=": return cls.eq(v).complement()
                    case "~":  return cls._tilde(v)
                    case "^":  return cls._caret(v)
        raise ValueError(f"unparseable constraint clause: {clause!r}")

    @classmethod
    def _tilde(cls, v: "Version") -> "VersionSet":
        """Tilde operator: allow patch-level changes within the specified
        minor (or minor-level changes within the specified major when
        patch and minor are both zero).

        ~M.m.p → >=M.m.p <M.(m+1).0
        ~M.m.0 → >=M.m.0 <M.(m+1).0  (same rule when patch is 0)
        ~M.0.0 → >=M.0.0 <(M+1).0.0  (when minor is also 0, bump major)
        """
        lo = cls.gte(v)
        if v.minor == 0 and v.patch == 0:
            # ~M.0.0 — bump major for the upper bound
            hi = cls.lt(Version(v.major + 1, 0, 0))
        else:
            # ~M.m.p — bump minor for the upper bound
            hi = cls.lt(Version(v.major, v.minor + 1, 0))
        return lo.intersect(hi)

    @classmethod
    def _caret(cls, v: "Version") -> "VersionSet":
        """Caret operator: compatible-with — bump the left-most non-zero
        component for the upper bound.

        ^M.m.p (M>0) → >=M.m.p <(M+1).0.0
        ^0.m.p (m>0) → >=0.m.p <0.(m+1).0
        ^0.0.p       → >=0.0.p <0.0.(p+1)
        ^0.0.0       → >=0.0.0 <0.1.0
        """
        lo = cls.gte(v)
        if v.major > 0:
            hi = cls.lt(Version(v.major + 1, 0, 0))
        elif v.minor > 0:
            hi = cls.lt(Version(0, v.minor + 1, 0))
        elif v.patch > 0:
            hi = cls.lt(Version(0, 0, v.patch + 1))
        else:
            # ^0.0.0 — no non-zero component; treat as ^0.0 → <0.1.0
            hi = cls.lt(Version(0, 1, 0))
        return lo.intersect(hi)

    def contains(self, v) -> bool:
        # Accept both Version and plain 3-tuples (backward compat).
        if not isinstance(v, Version):
            v = Version(v[0], v[1], v[2])
        for lo, hi, lo_c, hi_c in self.intervals:
            if lo is not None:
                if lo_c:
                    if v < lo:
                        continue
                else:
                    if v <= lo:
                        continue
            if hi is not None:
                if hi_c:
                    if v > hi:
                        continue
                else:
                    if v >= hi:
                        continue
            return True
        return False

    def is_empty(self) -> bool:
        return not self.intervals

    def intersect(self, other: "VersionSet") -> "VersionSet":
        out: list = []
        for a_lo, a_hi, a_lc, a_hc in self.intervals:
            for b_lo, b_hi, b_lc, b_hc in other.intervals:
                lo, lo_c = _max_lo_with_closed(a_lo, a_lc, b_lo, b_lc)
                hi, hi_c = _min_hi_with_closed(a_hi, a_hc, b_hi, b_hc)
                if _interval_nonempty(lo, hi, lo_c, hi_c):
                    out.append((lo, hi, lo_c, hi_c))
        return VersionSet(intervals=tuple(_normalize_intervals(out)))

    def union(self, other: "VersionSet") -> "VersionSet":
        return VersionSet(
            intervals=tuple(_normalize_intervals(
                list(self.intervals) + list(other.intervals)
            ))
        )

    def complement(self) -> "VersionSet":
        """Complement of the VersionSet.

        For each interval (lo, hi, lo_c, hi_c):
          - If lo is not None: the left gap endpoint is (None, lo) where
            the hi-side of the gap is open iff lo was closed (complement
            inverts the endpoint's closedness).
          - Between intervals i and i+1: gap from hi_i to lo_{i+1} where
            the gap's lo_c = not hi_c_i and hi_c = not lo_c_{i+1}.
          - If hi is not None: the right tail is (hi, None) where the
            lo-side is open iff hi was closed.
        """
        if not self.intervals:
            return VersionSet.full()
        out: list = []
        lo0, _, lo0_c, _ = self.intervals[0]
        if lo0 is not None:
            # Left gap: (-∞, lo0) with hi openness = not lo0_c
            out.append((None, lo0, True, not lo0_c))
        for i in range(len(self.intervals) - 1):
            _, hi_i, _, hi_c_i = self.intervals[i]
            lo_n, _, lo_c_n, _ = self.intervals[i + 1]
            # Gap between interval i's hi and interval i+1's lo
            out.append((hi_i, lo_n, not hi_c_i, not lo_c_n))
        _, last_hi, _, last_hi_c = self.intervals[-1]
        if last_hi is not None:
            # Right tail: (last_hi, +∞) with lo openness = not last_hi_c
            # hi=None means +∞ (always exclusive), so hi_closed=False.
            out.append((last_hi, None, not last_hi_c, False))
        return VersionSet(intervals=tuple(_normalize_intervals(out)))

    def is_subset_of(self, other: "VersionSet") -> bool:
        """`self` ⊆ `other` iff `self ∩ other^c = ∅`."""
        return self.intersect(other.complement()).is_empty()


def _max_lo_with_closed(
    a: "Version | None", a_c: bool,
    b: "Version | None", b_c: bool,
) -> tuple:
    """Return the larger of two lower bounds, preserving closedness.

    When both bounds are equal, prefer open (False) over closed (True)
    because the intersection of [lo, ...) and (lo, ...) is (lo, ...).
    """
    if a is None:
        return b, b_c
    if b is None:
        return a, a_c
    if a > b:
        return a, a_c
    if b > a:
        return b, b_c
    # Equal bounds: intersection is open iff either is open
    return a, (a_c and b_c)


def _min_hi_with_closed(
    a: "Version | None", a_c: bool,
    b: "Version | None", b_c: bool,
) -> tuple:
    """Return the smaller of two upper bounds, preserving closedness.

    When both bounds are equal, prefer open (False) for the same reason.
    """
    if a is None:
        return b, b_c
    if b is None:
        return a, a_c
    if a < b:
        return a, a_c
    if b < a:
        return b, b_c
    # Equal bounds: intersection is open iff either is open
    return a, (a_c and b_c)


def _interval_nonempty(
    lo: "Version | None", hi: "Version | None", lo_c: bool, hi_c: bool
) -> bool:
    if lo is None or hi is None:
        return True
    if lo < hi:
        return True
    if lo == hi and lo_c and hi_c:
        return True  # closed point [v, v] = {v}
    return False


def _normalize_intervals(intervals: list) -> list:
    """Sort + merge a list of 4-tuple intervals into canonical form.

    Two intervals can merge if they overlap OR are adjacent at a point
    that is closed on at least one side. Returns sorted, non-overlapping,
    non-degenerate intervals.
    """
    def lo_sort_key(iv):
        lo, _, lo_c, _ = iv
        if lo is None:
            return (0,)
        # Sort by lo value; when equal, closed comes before open
        # (closed interval starts "earlier" in the inclusive sense)
        return (1, lo, 0 if lo_c else 1)

    def canonical(iv):
        lo, hi, lo_c, hi_c = iv
        # Unbounded endpoints: lo=None is always exclusive (irrelevant),
        # canonicalize to lo_closed=True; hi=None is always exclusive,
        # canonicalize to hi_closed=False.
        if lo is None:
            lo_c = True
        if hi is None:
            hi_c = False
        return (lo, hi, lo_c, hi_c)

    sorted_ivs = sorted(intervals, key=lo_sort_key)
    merged: list = []
    for raw_iv in sorted_ivs:
        iv = canonical(raw_iv)
        lo, hi, lo_c, hi_c = iv
        if not _interval_nonempty(lo, hi, lo_c, hi_c):
            continue
        if not merged:
            merged.append((lo, hi, lo_c, hi_c))
            continue
        prev_lo, prev_hi, prev_lo_c, prev_hi_c = merged[-1]
        if _intervals_connectable(prev_lo, prev_hi, prev_lo_c, prev_hi_c,
                                   lo, hi, lo_c, hi_c):
            new_hi, new_hi_c = _max_bound(prev_hi, prev_hi_c, hi, hi_c)
            merged[-1] = (prev_lo, new_hi, prev_lo_c, new_hi_c)
        else:
            merged.append((lo, hi, lo_c, hi_c))
    return merged


def _intervals_connectable(
    a_lo, a_hi, a_lo_c, a_hi_c,
    b_lo, b_hi, b_lo_c, b_hi_c,
) -> bool:
    """True if intervals A and B should be merged (overlap or adjacent).

    Assumes A is sorted before B (a_lo <= b_lo semantically).
    """
    # A extends to +∞ → always overlaps
    if a_hi is None:
        return True
    # B starts at -∞ → always overlaps a non-empty A
    if b_lo is None:
        return True
    # a_hi < b_lo: definitely separate (gap exists)
    if a_hi < b_lo:
        return False
    # a_hi > b_lo: definitely overlap
    if a_hi > b_lo:
        return True
    # a_hi == b_lo: connectable iff either endpoint is closed
    # (i.e., the shared point is included by at least one interval)
    return a_hi_c or b_lo_c


def _max_bound(
    a: "Version | None", a_c: bool,
    b: "Version | None", b_c: bool,
) -> tuple:
    """Return the larger of two upper bounds for a merged interval."""
    if a is None:
        return a, a_c
    if b is None:
        return b, b_c
    if a > b:
        return a, a_c
    if b > a:
        return b, b_c
    # Equal: keep closed if either is closed (union is closed)
    return a, (a_c or b_c)


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

    Carries a structured ``ConflictChain`` (the ``chain`` attribute) that
    can be rendered with ``render_conflict_chain``.  ``str(err)`` returns
    the rendered prose so existing log/print sites keep working.
    """

    def __init__(self, chain: "ConflictChain") -> None:
        self.chain = chain
        super().__init__(render_conflict_chain(chain))


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
            raise SolverError(ConflictChain(steps=(ConflictStep(
                consequent_package="<solver>",
                consequent_description="solver did not converge — likely a bug",
                antecedents=(),
                antecedent_constraints=(),
                cause_tag="convergence-limit",
            ),)))
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
                raise SolverError(build_conflict_chain(
                    root_cause_conflicts, conflict.incompat, incompats
                ))
            target_level = partial.decision_level - 1
            undone = partial.backtrack_to(target_level)
            if undone is None:
                raise SolverError(build_conflict_chain(
                    root_cause_conflicts, conflict.incompat, incompats
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
    bounds = [iv[0] for iv in vs.intervals]
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
# Error formatting (P3.4: structured ConflictChain + rendered prose)
# ---------------------------------------------------------------------------

def build_conflict_chain(
    root_causes: list[Incompatibility],
    final_incompat: Incompatibility,
    all_incompats: list[Incompatibility],
) -> ConflictChain:
    """Build a structured ConflictChain from the solver's collected conflicts.

    Algorithm (per spec):
    - Build a term-package index: {package → list[Incompatibility]} keyed
      on each package appearing in an incompat's terms (NOT its cause).
      This answers "which incompatibilities constrain package X?" and is
      the correct index for finding antecedents.
    - The root_cause_conflicts identify which packages triggered conflicts.
      For each such incompat, find the *constrained* package (the one that
      appears as a negative term — the package the dependency *requires*).
      Then look it up in the term-package index to get ALL dep-incompats
      that constrain it, producing the full antecedent set.
    - Each unique constrained package becomes one ConflictStep.
    """
    # Build the term-package index over all known incompatibilities.
    # Key = package name appearing in any term; value = list of dep-constraint
    # incompatibilities (cause starts with "dependency:") whose terms contain
    # that package.  This is keyed on *terms*, NOT on cause.
    term_pkg_index: dict[str, list[Incompatibility]] = {}
    for incompat in all_incompats:
        if not incompat.cause.startswith("dependency:"):
            continue
        for term in incompat.terms:
            term_pkg_index.setdefault(term.package, []).append(incompat)

    steps: list[ConflictStep] = []
    seen_consequents: set[str] = set()

    def _emit_step_for_package(pkg: str, cause_tag: str) -> None:
        """Emit one ConflictStep for a conflicted package, using the
        term-package index to find all dep-constraint antecedents.

        For each dep-incompat that constrains `pkg`, collect:
        - The positive term (the depender — who requires `pkg`).
        - The negative term (the constraint on `pkg` — what version range
          the depender requires of `pkg`).
        These are stored as parallel tuples: ``antecedents`` (dependers)
        and ``antecedent_constraints`` (what they require of `pkg`).
        """
        if pkg in seen_consequents:
            return
        seen_consequents.add(pkg)

        # Look up all dep-incompatibilities that constrain this package.
        dep_incompats = term_pkg_index.get(pkg, [])

        depender_terms: list[Term] = []
        constraint_terms: list[Term] = []
        seen_constraints: set[str] = set()

        for dep_ic in dep_incompats:
            # Each dep-incompat has terms like:
            #   [positive: depender@ver, negative: pkg NOT in constraint]
            pos_terms = [t for t in dep_ic.terms if t.positive and t.package != pkg]
            neg_terms = [t for t in dep_ic.terms if not t.positive and t.package == pkg]
            if not neg_terms:
                continue
            constraint_t = neg_terms[0]
            ck = _term_str(constraint_t)
            if ck in seen_constraints:
                continue
            seen_constraints.add(ck)
            # Use first positive (depender) term, or create a synthetic one
            # if none (e.g. root-level requirement).
            depender_t = pos_terms[0] if pos_terms else constraint_t
            depender_terms.append(depender_t)
            constraint_terms.append(constraint_t)

        if not constraint_terms:
            # No dep-index entry: e.g. package is missing from provider.
            steps.append(ConflictStep(
                consequent_package=pkg,
                consequent_description=f"{pkg} has no satisfying version",
                antecedents=(),
                antecedent_constraints=(),
                cause_tag=cause_tag,
            ))
            return

        steps.append(ConflictStep(
            consequent_package=pkg,
            consequent_description=f"{pkg} has no satisfying version",
            antecedents=tuple(depender_terms),
            antecedent_constraints=tuple(constraint_terms),
            cause_tag=cause_tag,
        ))

    # Process real (non-conflict-blocks) root causes to find the
    # packages whose constraints are directly contradictory.
    real_causes = [
        ic for ic in root_causes + [final_incompat]
        if not ic.cause.startswith("conflict-blocks:")
    ]

    for incompat in real_causes:
        if incompat.cause.startswith("dependency:"):
            # A dependency-constraint incompat: terms = [positive:depender,
            # negative:required_pkg]. The *required* package (the negative
            # term) is the one being constrained — look it up in the index.
            neg_terms = [t for t in incompat.terms if not t.positive]
            for neg_t in neg_terms:
                # Only emit if this package has ≥2 antecedents (diamond) OR
                # if it has no satisfying versions at all (missing dep).
                _emit_step_for_package(neg_t.package, incompat.cause)
        elif incompat.cause.startswith("no-versions"):
            # A "no versions" incompat: the single positive term is the
            # package that ran out of versions. Emit it.
            pos_terms = [t for t in incompat.terms if t.positive]
            for pos_t in pos_terms:
                _emit_step_for_package(pos_t.package, incompat.cause)
        elif incompat.cause.startswith("semver-"):
            # A SEMVER strategy conflict: the cause encodes the package and
            # required major as `semver-no-same-major-{pkg}-at-{major}`.
            # The single positive term is the package whose major-version
            # constraint could not be satisfied. Emit it directly with a
            # description that names the major constraint, rather than
            # falling through to the bare uninformative fallback step.
            pos_terms = [t for t in incompat.terms if t.positive]
            for pos_t in pos_terms:
                # Parse the required major from the cause tag (best effort;
                # fall back gracefully if the tag format changes).
                cause_tail = incompat.cause  # e.g. "semver-no-same-major-foo-at-1"
                at_idx = cause_tail.rfind("-at-")
                if at_idx != -1:
                    required_major = cause_tail[at_idx + 4:]
                    desc = (
                        f"{pos_t.package} has no version with major {required_major} "
                        f"(SEMVER strategy requires same-major as constraint lower bound)"
                    )
                else:
                    desc = (
                        f"{pos_t.package} has no satisfying version "
                        f"(SEMVER major-version constraint)"
                    )
                steps.append(ConflictStep(
                    consequent_package=pos_t.package,
                    consequent_description=desc,
                    antecedents=(pos_t,),
                    antecedent_constraints=(pos_t,),
                    cause_tag=incompat.cause,
                ))

    if not steps:
        # Final fallback: emit something useful from the final incompat.
        terms = list(final_incompat.terms)
        pkg = terms[0].package if terms else "unknown"
        cause = final_incompat.cause
        steps.append(ConflictStep(
            consequent_package=pkg,
            consequent_description=f"{pkg} has no satisfying version",
            antecedents=(),
            antecedent_constraints=tuple(terms),
            cause_tag=cause,
        ))

    return ConflictChain(steps=tuple(steps))


def render_conflict_chain(chain: ConflictChain) -> str:
    """Render a ConflictChain as human-readable English prose.

    Produces the PubGrub-style derivation:
      "Because a ≥1.0.0 requires shared ≥1.0.0 and b ≥1.0.0 requires
       shared <1.0.0, shared has no satisfying version."

    Each step is indented on its own line so the derivation reads as a
    proof, not one wrapped sentence.  The CLI prints this multi-line so
    it reads as a derivation tree, not one wrapped paragraph.
    """
    if not chain.steps:
        return "version solving failed"

    lines: list[str] = []
    for step in chain.steps:
        dependers = step.antecedents
        constraints = step.antecedent_constraints
        if dependers and constraints:
            # Produce "X requires Y" clauses for each antecedent pair.
            clauses: list[str] = []
            for dep_t, con_t in zip(dependers, constraints):
                dep_str = _format_set(dep_t.versions)
                con_str = _format_constraint_as_requirement(con_t)
                if dep_t.package == con_t.package:
                    # Degenerate: depender and constraint are the same package
                    # (root-level or fallback). Just describe the constraint.
                    clauses.append(con_str)
                else:
                    clauses.append(
                        f"{dep_t.package} {dep_str} requires {con_t.package} {con_str}"
                    )
            because_str = " and ".join(clauses)
            lines.append(f"  Because {because_str},")
            lines.append(f"    {step.consequent_description}.")
        elif constraints:
            # No dependers (fallback), show raw constraints.
            con_strs = " and ".join(_term_str(t) for t in constraints)
            lines.append(f"  Because {con_strs},")
            lines.append(f"    {step.consequent_description}.")
        else:
            lines.append(f"  {step.consequent_description}.")

    return "version solving failed\n" + "\n".join(lines)


def _format_constraint_as_requirement(term: Term) -> str:
    """Render a negative Term as the requirement it encodes.

    A negative Term ``pkg NOT in [1.0, +∞)`` in a dependency incompat
    means the depender *requires* pkg in [1.0, +∞).  We negate the
    VersionSet to get the actual requirement range and format that.
    """
    # Negate the forbidden set to get the required set.
    required = term.versions.complement()
    return _format_set(required)


def _term_str(term: Term) -> str:
    sign = "must be in" if term.positive else "must NOT be in"
    return f"{term.package!r} {sign} {_format_set(term.versions)}"


def _format_set(vs: VersionSet) -> str:
    if not vs.intervals:
        return "(empty)"
    parts: list[str] = []
    for lo, hi, lo_c, hi_c in vs.intervals:
        if lo is None and hi is None:
            parts.append("any")
        elif lo is None:
            end = "]" if hi_c else ")"
            parts.append(f"(-∞, {_v(hi)}{end}")
        elif hi is None:
            start = "[" if lo_c else "("
            parts.append(f"{start}{_v(lo)}, +∞)")
        elif lo == hi and lo_c and hi_c:
            parts.append(f"{{{_v(lo)}}}")
        else:
            start = "[" if lo_c else "("
            end = "]" if hi_c else ")"
            parts.append(f"{start}{_v(lo)}, {_v(hi)}{end}")
    return " ∪ ".join(parts)


def _v(v: "Version | tuple") -> str:
    if isinstance(v, Version):
        return _format_version_str(v)
    return f"{v[0]}.{v[1]}.{v[2]}"
