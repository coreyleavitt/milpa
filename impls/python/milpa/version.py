"""Version algebra for milpa — the single source of truth for version semantics.

This module owns:
  - ``Version`` — immutable semver 2.0 value type
  - ``PreId``   — type alias: ``int | str`` (one prerelease identifier)
  - ``parse_version``     — str → Version | None
  - ``format_version_str`` — Version → str
  - ``Strategy``          — version-pick enum (MAXVER / MINVER / SEMVER)
  - ``VersionSet``        — union of disjoint generalized intervals
  - ``from_constraint``   — milpa.kdl constraint string → VersionSet
  - ``from_nimble_constraint`` — .nimble constraint form → VersionSet

Design constraints (RFC §4.1):
  - Pure computation only. No KDL, no fetcher, no solver imports.
  - Must be importable by manifest.py, lockfile.py, and the solver.
  - No non-stdlib imports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

# ---------------------------------------------------------------------------
# PreId — one semver prerelease identifier
# ---------------------------------------------------------------------------

#: A single semver prerelease identifier: ``int`` for all-digit identifiers
#: (compared numerically, no leading zeros), ``str`` for alphanumeric ones.
PreId = int | str


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------


class Version:
    """Immutable semver 2.0 value type with full total order.

    Carries major/minor/patch as ints, ``pre`` as a tuple of ``PreId``
    (empty = release), and ``build`` as a ``str`` (empty = none).
    Build metadata is stored for round-trip but **ignored** for equality
    and ordering per semver 2.0 §10.

    Prerelease total order (semver 2.0 §11):
      1. Pre-release has lower precedence than the release it annotates:
         ``1.0.0-alpha < 1.0.0``.
      2. Pre-release identifiers compared left-to-right:
         - Numeric identifiers compared numerically.
         - Alphanumeric identifiers compared in ASCII order.
         - Numeric identifiers always have lower precedence than
           alphanumeric identifiers.
      3. A larger set of identifiers has higher precedence than a smaller
         set (when all preceding identifiers are equal).
    """

    __slots__ = ("major", "minor", "patch", "pre", "build")
    major: int
    minor: int
    patch: int
    pre: tuple[PreId, ...]
    build: str

    def __init__(
        self,
        major: int,
        minor: int,
        patch: int,
        pre: tuple[PreId, ...] = (),
        build: str = "",
    ) -> None:
        object.__setattr__(self, "major", major)
        object.__setattr__(self, "minor", minor)
        object.__setattr__(self, "patch", patch)
        object.__setattr__(self, "pre", pre)
        object.__setattr__(self, "build", build)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Version is immutable")

    def _precedence_key(
        self,
    ) -> tuple[int, int, int, int, tuple[tuple[int, int | str], ...]]:
        """Comparison key per semver 2.0 §10/11 (build ignored)."""
        if not self.pre:
            return (self.major, self.minor, self.patch, 1, ())
        # Numeric identifiers sort before alphanumeric:
        # represent each as (0, n) for int or (1, s) for str.
        pre_key: tuple[tuple[int, int | str], ...] = tuple(
            (0, id_) if isinstance(id_, int) else (1, id_)
            for id_ in self.pre
        )
        return (self.major, self.minor, self.patch, 0, pre_key)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Version):
            return self._precedence_key() == other._precedence_key()
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._precedence_key())

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Version):
            return self._precedence_key() < other._precedence_key()
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Version):
            return self._precedence_key() <= other._precedence_key()
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, Version):
            return self._precedence_key() > other._precedence_key()
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, Version):
            return self._precedence_key() >= other._precedence_key()
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
        return format_version_str(self)


# ---------------------------------------------------------------------------
# DepKey — resolver identity key (S1, rfc-resolver-correctness.md)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DepKey:
    """A resolver-level dep identity key.

    ``name`` is the canonical bare name (always present).
    ``namespace`` is ``None`` for unqualified (default) deps; populated by S5b
    when the manifest grammar supports namespace-qualified ``NamedDep`` refs.

    Used as a dict key in ``_locked_index`` (frozen.py) and ``seen_named``
    (resolver.py, S5a).  A named type — not a tuple — gives call-site
    guardrails and forces Python and Rust to converge on the same shape.

    Spec: ``spec/resolver-semantics.md`` DepKey fields+ordering clause.
    """

    name: str
    namespace: str | None = None

    def solver_var(self) -> str:
        """Canonical PubGrub solver-variable string for this dep.

        ``namespace=None`` → bare name (backward-compatible with all
        pre-S5b deps; the solver key is unchanged from before S5a).
        ``namespace='ns'`` → ``'ns::name'`` — a distinct key from the bare
        name and from every other namespace, so ``(ns1, foo)`` and ``(ns2, foo)``
        become distinct solver variables.

        Agreed with ``seen_named`` (``set[DepKey]``): both uniquely identify the
        same dep, and neither can collapse two different namespaces to one key.

        SOLVER-INTERNAL ONLY. This string MUST NOT be written to disk,
        the lockfile, or _deps/ paths.  Use ``dep_dir_name()`` for filesystem
        layout and ``LockedDep.name``/``LockedDep.namespace`` for lockfile.
        """
        if self.namespace is None:
            return self.name
        return f"{self.namespace}::{self.name}"

    @classmethod
    def from_solver_var(cls, s: str) -> "DepKey":
        """Parse a solver-variable string back into a DepKey.

        This is the SOLE site that decomposes a ``::``-joined solver variable
        back into (namespace, name) components.  Splits on the FIRST ``::``::

            ``"bar"``      → ``DepKey(name="bar")``
            ``"ns::bar"``  → ``DepKey(name="bar", namespace="ns")``

        Use this at every call-site that receives a solver_var string and
        needs a structured DepKey (e.g. ``_on_transitive_named``,
        ``_build_graph``).  Never split on ``::`` inline.
        """
        if "::" in s:
            ns, _, name = s.partition("::")
            return cls(name=name, namespace=ns)
        return cls(name=s)


class SolverKey(str):
    """The PubGrub solver variable, carrying its display ``DepKey`` inline.

    origin-as-identity RFC §4.4 (DE1, genericized key): the solver keys every
    variable by ``canonical(source_id)`` — a trust-independent, kind-free
    origin string.  ``SolverKey`` **is** that string (it subclasses ``str``, so
    its value is exactly ``canonical(source_id)``), which means it renders,
    hashes, compares, and serializes identically to the bare canonical string
    the solver used before — every solver diagnostic f-string, dict key, and
    ``==`` is byte-for-byte unchanged.

    What it adds is ``display``: the ``DepKey`` (name + optional namespace) this
    origin should be *labelled* with in user-facing output — the lockfile
    ``requires`` list, the ``nim.cfg`` search path, the §5 resolution
    certificate.  ``display`` is BFS-first: the FIRST ``DepKey`` bound to a
    given origin wins (two labels for one origin collapse to the first-
    discovered name), so it is deliberately NOT part of identity — two
    ``SolverKey``s with the same origin string are equal and hash-equal
    regardless of ``display`` (inherited ``str`` semantics).

    This replaces the origin-as-identity S5-rekey's ``canonical → DepKey``
    reverse map (``BindingResolver._canonical_index`` / ``depkey_for_canonical``)
    and the scatter of ``_depkey_for_solved_name(pkg, binding_resolver)``
    projection call sites: wherever a consumer holds a solver variable, it reads
    ``pkg.display`` directly — no reverse lookup, no ``binding_resolver``
    threading.  Interning at the single mint point (``BindingResolver`` /
    ``SolverKey.for_depkey``) guarantees every instance for one origin is the
    same object, so ``display`` is deterministic.

    SOLVER-INTERNAL as a *string*: the raw origin value MUST NOT be written to
    disk (use ``display`` → ``LockedDep.name``/``namespace`` for the lockfile,
    ``dep_dir_name`` for ``_deps/`` layout).
    """

    __slots__ = ("display",)
    display: DepKey

    def __new__(cls, identity: str, display: DepKey) -> "SolverKey":
        obj = super().__new__(cls, identity)
        obj.display = display
        return obj

    @classmethod
    def for_depkey(cls, key: DepKey) -> "SolverKey":
        """Mint a ``SolverKey`` whose origin string is the DepKey's own
        ``solver_var()`` (the identity == label case: git/tarball/local/member
        deps, and any dep not routed through a ``source_id`` binding).  The
        ``display`` is the key itself."""
        return cls(key.solver_var(), key)


# ---------------------------------------------------------------------------
# dep_dir_name — SSOT for _deps/ layout (C1, rfc-resolver-correctness.md)
# ---------------------------------------------------------------------------


def dep_dir_name(name: str, namespace: str | None) -> str:
    """Canonical ``_deps/`` entry name for a dep.

    Bare dep (``namespace=None``): ``"<name>"``  → ``_deps/<name>``
    Qualified dep (``namespace="ns"``): ``"@<ns>/<name>"`` → ``_deps/@ns/<name>``

    The ``@<ns>/`` prefix (npm-scope form) is:
    - Windows-safe (no ``:`` or ``*`` forbidden characters)
    - Collision-free with bare names (bare names cannot start with ``@``)
    - Human-readable (analogous to npm ``@scope/pkg`` convention)

    Collocated with ``DepKey`` (the Rust impl does the same in milpa-types),
    because ``dep_dir_name`` is a pure function of (name, namespace) — the same
    fields that define a ``DepKey``.  Call it from:
    ``rebuild_deps_view``, ``_materialize_named``, ``nimcfg._path_for``,
    ``frozen._locked_index``, ``lockfile.verify_lockfile_against_deps``.
    """
    if namespace is None:
        return name
    return f"@{namespace}/{name}"


# ---------------------------------------------------------------------------
# Strategy
# ---------------------------------------------------------------------------


class Strategy(StrEnum):
    """How the solver picks among candidates satisfying the current constraint.

    URL/local/member deps have exactly one canonical version; ``Strategy``
    only affects named deps with multiple satisfying versions.

    - ``MAXVER``: highest version (default; good for applications).
    - ``MINVER``: lowest version (good for libraries — locks against the
      declared floor; surfaces accidental use of newer features).
    - ``SEMVER``: highest version within the same major as the constraint's
      lower bound (protects against accidental cross-major upgrades).
    - ``LOWEST_DIRECT`` (resolver-semantics RFC §3 Axis C, #111; wire string
      ``lowest-direct``, matching uv's ``--resolution lowest-direct``): applies
      ``MINVER`` to root-direct deps and ``MAXVER`` to everything else — the
      practical way to test that advertised lower bounds actually build. This
      is a **surface value only** (CLI flag / lockfile ``strategy`` node): the
      provider resolves it to a concrete per-package ``MINVER``/``MAXVER``
      *before* the pick ever runs (``_effective_strategy_for``, D-C2) —
      ``_pick_version``'s ``strategy`` argument, and its ``match``, never see
      this value.
    """

    MAXVER = "maxver"
    MINVER = "minver"
    SEMVER = "semver"
    LOWEST_DIRECT = "lowest-direct"


# ---------------------------------------------------------------------------
# VersionSource — Axis A (b) / A5 (resolution-semantics RFC §3 Axis A, §5)
# ---------------------------------------------------------------------------


class VersionSource(StrEnum):
    """Which precedence branch produced a git/url/local/tarball/member dep's
    declared-version label (``declared_version_for``, ``edge_sources.py``).

    ``manifest`` names the *role* — "this package's own manifest" — not the
    literal file syntax of the day, so the wire value in the lockfile survives
    a future manifest-format evolution. The four values mirror the precedence
    steps 1-4 exactly:

    - ``MANIFEST``: the fetched package's own ``milpa.kdl version`` field (step 1).
    - ``NIMBLE``: the fetched package's ``.nimble version`` (step 2, A1 scanner).
    - ``TAG``: a version-shaped git ref tag, ``v?X.Y.Z`` (step 3, A3).
    - ``ANNOTATION``: the dep declaration's ``version=`` annotation, or an
      ``overrides { … version= }`` rule's (step 4, A3b).

    A version-unknown dep (no step matched) carries no ``VersionSource`` at
    all — ``declared_version_source`` is ``None`` (Option, not a 5th member;
    §5 NORMATIVE: the lockfile pairs ``0.0.0`` + absent source for that case,
    a combination no ``Known`` case ever produces since a ``Known`` version
    always names its source).
    """

    MANIFEST = "manifest"
    NIMBLE = "nimble"
    TAG = "tag"
    ANNOTATION = "annotation"


# ---------------------------------------------------------------------------
# parse_version / format_version_str
# ---------------------------------------------------------------------------

# Semver regex: optional v-prefix, M.m.p, optional -pre, optional +build.
_VERSION_RE = re.compile(
    r"v?(\d+)\.(\d+)\.(\d+)"
    r"(?:-([0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*))?"
    r"(?:\+([0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*))?"
    r"\Z"
)


#: Upper bound for a parsed release-component value — mirrors Rust's
#: ``parse_numeric_component`` (``s.parse::<u64>()``), so a value that
#: overflows ``u64`` is rejected in Python too (cross-impl parity).
_U64_MAX = (1 << 64) - 1


def _parse_numeric_component(digits: str) -> int | None:
    """Parse one release-component digit run into an ``int``, or ``None``.

    Total by construction — never raises. Two distinct hazards, both
    reachable from attacker-controlled input (a crafted git tag, a
    ``.nimble``/``milpa.kdl`` ``version=`` string, a registry index entry):

    - CPython >=3.11 caps int<->str conversion at ~4300 digits; a bare
      ``int()`` call on an oversized digit run raises ``ValueError``. Caught
      here so ``parse_version`` stays total, matching its documented
      "returns None for non-canonical" contract.
    - A digit run that parses fine as a Python ``int`` but exceeds
      ``u64::MAX`` would silently diverge from Rust's
      ``parse_numeric_component``, which rejects it via
      ``str::parse::<u64>()``. Bounding here keeps both impls in agreement.
    """
    try:
        value = int(digits)
    except ValueError:
        return None
    if value > _U64_MAX:
        return None
    return value


def _parse_pre_identifiers(pre_str: str) -> tuple[PreId, ...]:
    """Parse a semver prerelease string into typed identifiers.

    Per semver 2.0: identifiers consisting entirely of digits are parsed as
    integers (no leading zeros). Others remain strings.

    Total by construction — never raises. Mirrors Rust's
    ``parse_pre_identifiers``, which normalizes an all-digit identifier via
    ``str::parse::<u64>()`` and, on overflow, "fall[s] back to Alpha so
    parsing never panics". Two hazards apply here just as they do to
    ``_parse_numeric_component`` (RR6 — the sibling was previously exempt,
    which was the bug):

    - CPython >=3.11 caps int<->str conversion at ~4300 digits; a bare
      ``int()`` call on an oversized all-digit identifier (e.g. a crafted
      git tag) raises ``ValueError``.
    - A digit run that parses fine as a Python ``int`` but exceeds
      ``u64::MAX`` would silently diverge from Rust's classification.

    Either hazard falls back to keeping the identifier as its plain STRING
    (alphanumeric) form — exactly Rust's ``PreId::Alpha`` fallback — rather
    than raising or silently accepting more than Rust does.
    """
    parts: list[PreId] = []
    for part in pre_str.split("."):
        value: PreId = part
        if part.isdigit():
            try:
                n = int(part)
            except ValueError:
                n = None
            if n is not None and n <= _U64_MAX:
                value = n
        parts.append(value)
    return tuple(parts)


def parse_version(text: str | None) -> Version | None:
    """Parse a semver string to a ``Version``.

    Accepts an optional ``v`` prefix (``v0.5.1`` and ``0.5.1`` both parse).
    Returns ``None`` for non-canonical tags (e.g. ``nimble-1.2.3``) or
    ``None`` input. Callers decide whether to skip silently or raise.
    """
    if text is None:
        return None
    m = _VERSION_RE.fullmatch(text.strip())
    if m is None:
        return None
    major = _parse_numeric_component(m.group(1))
    minor = _parse_numeric_component(m.group(2))
    patch = _parse_numeric_component(m.group(3))
    if major is None or minor is None or patch is None:
        return None
    pre_str = m.group(4)
    build_str = m.group(5)
    pre = _parse_pre_identifiers(pre_str) if pre_str else ()
    build = build_str if build_str else ""
    return Version(major, minor, patch, pre=pre, build=build)


def format_version_str(v: Version) -> str:
    """Format a ``Version`` as a canonical semver string.

    ``major.minor.patch[-pre][+build]``
    """
    s = f"{v.major}.{v.minor}.{v.patch}"
    if v.pre:
        s += "-" + ".".join(str(id_) for id_ in v.pre)
    if v.build:
        s += "+" + v.build
    return s


# ---------------------------------------------------------------------------
# VersionSet — union of disjoint generalized intervals over Version
#
# Each interval is a 4-tuple (lo, hi, lo_closed, hi_closed):
#   lo / hi:       Version | None  (None = unbounded)
#   lo_closed:     True → inclusive ([lo, ...), False → exclusive ((lo, ...))
#   hi_closed:     True → inclusive (..., hi]), False → exclusive (..., hi))
#
# Canonical form: intervals sorted by lo, non-overlapping, no empty
# intervals, adjacent intervals merged when they share a common point that
# is inclusive on at least one side.
# ---------------------------------------------------------------------------

_Interval = tuple[
    "Version | None", "Version | None", bool, bool
]  # (lo, hi, lo_closed, hi_closed)


def _interval_nonempty(
    lo: Version | None, hi: Version | None, lo_c: bool, hi_c: bool
) -> bool:
    """True iff the interval is non-empty (contains at least one point)."""
    if lo is None or hi is None:
        return True
    if lo < hi:
        return True
    # lo == hi: non-empty iff both endpoints are closed (point interval {v})
    return lo == hi and lo_c and hi_c


def _max_lo(
    a: Version | None,
    a_c: bool,
    b: Version | None,
    b_c: bool,
) -> tuple[Version | None, bool]:
    """Return the tighter (larger) of two lower bounds.

    When equal, prefer open (False) — intersection of [lo,...) and (lo,...)
    is (lo,...).
    """
    if a is None:
        return b, b_c
    if b is None:
        return a, a_c
    if a > b:
        return a, a_c
    if b > a:
        return b, b_c
    # Equal: intersection is open iff either bound is open
    return a, (a_c and b_c)


def _min_hi(
    a: Version | None,
    a_c: bool,
    b: Version | None,
    b_c: bool,
) -> tuple[Version | None, bool]:
    """Return the tighter (smaller) of two upper bounds.

    When equal, prefer open — same reasoning as ``_max_lo``.
    """
    if a is None:
        return b, b_c
    if b is None:
        return a, a_c
    if a < b:
        return a, a_c
    if b < a:
        return b, b_c
    # Equal: intersection is open iff either bound is open
    return a, (a_c and b_c)


def _max_hi(
    a: Version | None,
    a_c: bool,
    b: Version | None,
    b_c: bool,
) -> tuple[Version | None, bool]:
    """Return the wider (larger) of two upper bounds for merging."""
    if a is None:
        return a, a_c
    if b is None:
        return b, b_c
    if a > b:
        return a, a_c
    if b > a:
        return b, b_c
    # Equal: union is closed iff either is closed
    return a, (a_c or b_c)


def _connectable(
    a_lo: Version | None,
    a_hi: Version | None,
    a_lo_c: bool,
    a_hi_c: bool,
    b_lo: Version | None,
    _b_hi: Version | None,
    b_lo_c: bool,
    _b_hi_c: bool,
) -> bool:
    """True iff A and B should be merged (overlap or adjacent at closed point).

    Assumes A is sorted before or equal to B by lower bound.
    """
    if a_hi is None:
        return True  # A extends to +∞
    if b_lo is None:
        return True  # B starts at -∞ (only reached when A is non-empty)
    if a_hi < b_lo:
        return False  # definite gap
    if a_hi > b_lo:
        return True   # definite overlap
    # a_hi == b_lo: connectable iff the shared point is included by at least one
    return a_hi_c or b_lo_c


def _normalize(ivs: list[_Interval]) -> list[_Interval]:
    """Sort and merge intervals into canonical disjoint form.

    KEY FIX vs the frozen impl's lo=None merge gap: the sort key must
    handle ``lo=None`` correctly as -∞ so that two unbounded-below intervals
    (e.g. from ``lt(v).union(full())``) are always placed together and merged.
    Using ``(0,)`` for ``lo=None`` achieves this — any finite lo sorts as
    ``(1, lo, ...)`` which is always > ``(0,)``.
    """

    def lo_sort_key(iv: _Interval) -> tuple[object, ...]:
        lo, _, lo_c, _ = iv
        if lo is None:
            # -∞: sorts before everything; both None-lo intervals are equal
            # and will be adjacent after sorting, enabling the merge.
            return (0,)
        # Closed lo sorts before open lo at the same version (starts "earlier")
        closed_key: tuple[object, ...] = (0,) if lo_c else (1,)
        return (1,) + lo._precedence_key() + closed_key

    def canonicalize(iv: _Interval) -> _Interval:
        lo, hi, lo_c, hi_c = iv
        # Unbounded endpoints: lo=None is always exclusive (irrelevant);
        # canonicalize lo_closed=True.  hi=None is always exclusive;
        # canonicalize hi_closed=False.
        if lo is None:
            lo_c = True
        if hi is None:
            hi_c = False
        return (lo, hi, lo_c, hi_c)

    sorted_ivs = sorted(ivs, key=lo_sort_key)
    merged: list[_Interval] = []

    for raw_iv in sorted_ivs:
        iv = canonicalize(raw_iv)
        lo, hi, lo_c, hi_c = iv
        if not _interval_nonempty(lo, hi, lo_c, hi_c):
            continue
        if not merged:
            merged.append(iv)
            continue
        prev_lo, prev_hi, prev_lo_c, prev_hi_c = merged[-1]
        if _connectable(
            prev_lo, prev_hi, prev_lo_c, prev_hi_c,
            lo, hi, lo_c, hi_c,
        ):
            new_hi, new_hi_c = _max_hi(prev_hi, prev_hi_c, hi, hi_c)
            merged[-1] = (prev_lo, new_hi, prev_lo_c, new_hi_c)
        else:
            merged.append(iv)

    return merged


@dataclass(frozen=True)
class VersionSet:
    """Union of disjoint generalized intervals over ``Version``.

    Canonical form: intervals sorted by lower bound, non-overlapping, no
    empty intervals, adjacent closed points merged.

    ``eq(v)`` is a true closed singleton ``{v} = (v, v, True, True)``.
    This is structurally exact: no other version ``w`` can satisfy
    ``lo ≤ w ≤ hi`` when ``lo == hi == v``.  The old half-open
    ``[v, v_next)`` form was wrong because prerelease versions of
    ``v_next`` sort below ``v_next`` and thus fell inside the interval.
    """

    intervals: tuple[_Interval, ...]

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def full(cls) -> VersionSet:
        """The set of all versions."""
        return cls(intervals=((None, None, True, False),))

    @classmethod
    def empty(cls) -> VersionSet:
        """The empty set."""
        return cls(intervals=())

    @classmethod
    def gte(cls, v: Version) -> VersionSet:
        """``[v, +∞)``"""
        return cls(intervals=((v, None, True, False),))

    @classmethod
    def gt(cls, v: Version) -> VersionSet:
        """``(v, +∞)``"""
        return cls.gte(v).intersect(cls.eq(v).complement())

    @classmethod
    def lt(cls, v: Version) -> VersionSet:
        """``(-∞, v)``"""
        return cls(intervals=((None, v, True, False),))

    @classmethod
    def lte(cls, v: Version) -> VersionSet:
        """``(-∞, v]``"""
        return cls.lt(v).union(cls.eq(v))

    @classmethod
    def eq(cls, v: Version) -> VersionSet:
        """True singleton ``{v}`` — closed-point representation."""
        return cls(intervals=((v, v, True, True),))

    # ------------------------------------------------------------------
    # Algebra
    # ------------------------------------------------------------------

    def contains(self, v: Version) -> bool:
        """True iff ``v`` is a member of this set."""
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
        return len(self.intervals) == 0

    def is_full(self) -> bool:
        """True iff this set is the unbounded ``(-∞, +∞)`` set (§4 D-A2 use:
        a ``full()`` self-term is never violated, so it never belongs in a
        refutation / weak-UNSAT core — see ``SolverError.refutation``).

        Checks semantic fullness (both bounds unset), not literal equality
        with ``full()``'s canonical tuple — the closed-ness flags on an
        unbounded (``None``) endpoint are never consulted by ``contains``
        (see above), so they must not be consulted here either.
        """
        return len(self.intervals) == 1 and self.intervals[0][0] is None and self.intervals[0][1] is None

    def intersect(self, other: VersionSet) -> VersionSet:
        """``self ∩ other``"""
        out: list[_Interval] = []
        for a_lo, a_hi, a_lc, a_hc in self.intervals:
            for b_lo, b_hi, b_lc, b_hc in other.intervals:
                lo, lo_c = _max_lo(a_lo, a_lc, b_lo, b_lc)
                hi, hi_c = _min_hi(a_hi, a_hc, b_hi, b_hc)
                if _interval_nonempty(lo, hi, lo_c, hi_c):
                    out.append((lo, hi, lo_c, hi_c))
        return VersionSet(intervals=tuple(_normalize(out)))

    def union(self, other: VersionSet) -> VersionSet:
        """``self ∪ other``"""
        combined: list[_Interval] = list(self.intervals) + list(other.intervals)
        return VersionSet(intervals=tuple(_normalize(combined)))

    def complement(self) -> VersionSet:
        """``self^c`` — set-theoretic complement."""
        if not self.intervals:
            return VersionSet.full()
        out: list[_Interval] = []
        lo0, _, lo0_c, _ = self.intervals[0]
        if lo0 is not None:
            # Left gap: (-∞, lo0) with hi openness = NOT lo0_c
            out.append((None, lo0, True, not lo0_c))
        for i in range(len(self.intervals) - 1):
            _, hi_i, _, hi_c_i = self.intervals[i]
            lo_n, _, lo_c_n, _ = self.intervals[i + 1]
            out.append((hi_i, lo_n, not hi_c_i, not lo_c_n))
        _, last_hi, _, last_hi_c = self.intervals[-1]
        if last_hi is not None:
            out.append((last_hi, None, not last_hi_c, False))
        return VersionSet(intervals=tuple(_normalize(out)))

    def is_subset_of(self, other: VersionSet) -> bool:
        """``self ⊆ other`` iff ``self ∩ other^c = ∅``."""
        return self.intersect(other.complement()).is_empty()

    # ------------------------------------------------------------------
    # Constraint parsers
    # ------------------------------------------------------------------

    @classmethod
    def from_constraint(cls, constraint: str | None) -> VersionSet:
        """Parse a milpa.kdl constraint string to a ``VersionSet``.

        OR has lower precedence than AND:
          ``>= 1.0.0 & < 2.0.0 | >= 3.0.0`` is
          ``(>= 1.0.0 AND < 2.0.0) OR >= 3.0.0``.

        Raises ``ValueError`` for unparseable input.
        """
        if constraint is None or constraint.strip() in ("", "any version"):
            return cls.full()
        # Split on || or | (OR), then each arm is AND-separated clauses.
        arms = re.split(r"\|\|?", constraint)
        result = cls.empty()
        for arm in arms:
            arm_result = cls.full()
            for clause in arm.split("&"):
                arm_result = arm_result.intersect(cls._parse_clause(clause.strip()))
            result = result.union(arm_result)
        return result

    @classmethod
    def from_nimble_constraint(cls, constraint: str | None) -> VersionSet:
        """Parse a .nimble constraint string to a ``VersionSet``.

        .nimble uses the same syntax as milpa.kdl constraints (nimble's
        ``requires`` uses ``>=``, ``<``, ``==``, etc.).  Delegates to
        ``from_constraint`` — the grammar is identical.

        The caller is responsible for mapping ``ValueError`` to the
        appropriate ``MAN-NIMBLE-CONSTRAINT`` error slug.
        """
        return cls.from_constraint(constraint)

    @classmethod
    def _parse_clause(cls, clause: str) -> VersionSet:
        """Parse a single constraint clause (one comparison operator + version)."""
        clause = clause.strip()
        # Match longest operators first to avoid prefix collisions.
        for op in (">=", "<=", "==", "!=", ">", "<", "~", "^", "="):
            if clause.startswith(op):
                ver_str = clause[len(op):].strip()
                v = parse_version(ver_str)
                if v is None:
                    raise ValueError(
                        f"unparseable version in constraint clause: {ver_str!r}"
                    )
                match op:
                    case ">=":
                        return cls.gte(v)
                    case "<=":
                        return cls.lte(v)
                    case ">":
                        return cls.gt(v)
                    case "<":
                        return cls.lt(v)
                    case "==" | "=":
                        return cls.eq(v)
                    case "!=":
                        return cls.eq(v).complement()
                    case "~":
                        return cls._tilde(v)
                    case "^":
                        return cls._caret(v)
        raise ValueError(f"unparseable constraint clause: {clause!r}")

    @classmethod
    def _tilde(cls, v: Version) -> VersionSet:
        """Tilde: allow patch-level changes (or minor when patch==minor==0).

        ``~M.m.p`` → ``>=M.m.p <M.(m+1).0``
        ``~M.0.0``  → ``>=M.0.0 <(M+1).0.0``
        """
        lo = cls.gte(v)
        if v.minor == 0 and v.patch == 0:
            hi = cls.lt(Version(v.major + 1, 0, 0))
        else:
            hi = cls.lt(Version(v.major, v.minor + 1, 0))
        return lo.intersect(hi)

    @classmethod
    def _caret(cls, v: Version) -> VersionSet:
        """Caret: compatible — bump the left-most non-zero component.

        ``^M.m.p`` (M>0) → ``>=M.m.p <(M+1).0.0``
        ``^0.m.p`` (m>0) → ``>=0.m.p <0.(m+1).0``
        ``^0.0.p``       → ``>=0.0.p <0.0.(p+1)``
        ``^0.0.0``       → ``>=0.0.0 <0.1.0``
        """
        lo = cls.gte(v)
        if v.major > 0:
            hi = cls.lt(Version(v.major + 1, 0, 0))
        elif v.minor > 0:
            hi = cls.lt(Version(0, v.minor + 1, 0))
        elif v.patch > 0:
            hi = cls.lt(Version(0, 0, v.patch + 1))
        else:
            hi = cls.lt(Version(0, 1, 0))
        return lo.intersect(hi)

    # ------------------------------------------------------------------
    # Formatting helpers (used by the solver's error narration)
    # ------------------------------------------------------------------

    def format_set(self) -> str:
        """Human-readable interval notation for this set."""
        if not self.intervals:
            return "(empty)"
        parts: list[str] = []
        for lo, hi, lo_c, hi_c in self.intervals:
            if lo is None and hi is None:
                parts.append("any")
            elif lo is None:
                end = "]" if hi_c else ")"
                assert hi is not None
                parts.append(f"(-∞, {format_version_str(hi)}{end}")
            elif hi is None:
                start = "[" if lo_c else "("
                parts.append(f"{start}{format_version_str(lo)}, +∞)")
            elif lo == hi and lo_c and hi_c:
                parts.append(f"{{{format_version_str(lo)}}}")
            else:
                start = "[" if lo_c else "("
                end = "]" if hi_c else ")"
                parts.append(
                    f"{start}{format_version_str(lo)}, {format_version_str(hi)}{end}"
                )
        return " ∪ ".join(parts)
