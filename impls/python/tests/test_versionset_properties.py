"""Property-based tests for milpa.solver.VersionSet algebra.

Per docs/rfc-property-based-testing.md Tier A. These tests verify
algebraic laws (commutativity, associativity, idempotency, identity,
De Morgan, etc.) over randomly-generated VersionSets.

The Hypothesis strategy builds VersionSets bottom-up via the class-
method constructors (full, empty, gte, lt, lte, eq, gt) and composes
them through intersect / union / complement. All paths produce
canonical normalized form, so dataclass-equality reflects semantic
equality.

Version space is intentionally bounded to [0, 9] per component to keep
shrinking fast and edge cases concentrated.
"""

from hypothesis import given, strategies as st

from milpa.solver import Version, VersionSet


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

@st.composite
def version_tuple(draw):
    """A single Version (major, minor, patch) ∈ [0,9]^3.
    Bounded space keeps generation + shrinking fast while preserving
    boundary-case coverage. Emits the new Version NamedTuple so
    VersionSet algebra receives the correct element type."""
    return Version(
        draw(st.integers(min_value=0, max_value=9)),
        draw(st.integers(min_value=0, max_value=9)),
        draw(st.integers(min_value=0, max_value=9)),
    )


@st.composite
def primitive_set(draw):
    """One VersionSet from a class-method constructor.
    Canonical by construction — every output is normalized."""
    kind = draw(st.sampled_from(["full", "empty", "gte", "lt", "lte", "eq", "gt"]))
    if kind == "full":
        return VersionSet.full()
    if kind == "empty":
        return VersionSet.empty()
    v = draw(version_tuple())
    return {
        "gte": VersionSet.gte,
        "lt":  VersionSet.lt,
        "lte": VersionSet.lte,
        "eq":  VersionSet.eq,
        "gt":  VersionSet.gt,
    }[kind](v)


@st.composite
def version_set(draw):
    """A VersionSet built by composing 0-3 algebraic operations on
    primitive sets. The depth bound keeps shrinking tractable."""
    s = draw(primitive_set())
    for _ in range(draw(st.integers(min_value=0, max_value=3))):
        op = draw(st.sampled_from(["intersect", "union", "complement"]))
        if op == "complement":
            s = s.complement()
        else:
            other = draw(primitive_set())
            s = s.intersect(other) if op == "intersect" else s.union(other)
    return s


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------

@given(version_set())
def test_intersect_idempotent(a):
    """a ∩ a == a — the simplest non-trivial algebraic law."""
    assert a.intersect(a) == a


@given(version_set(), version_set())
def test_intersect_commutative(a, b):
    """a ∩ b == b ∩ a"""
    assert a.intersect(b) == b.intersect(a)


@given(version_set(), version_set(), version_set())
def test_intersect_associative(a, b, c):
    """(a ∩ b) ∩ c == a ∩ (b ∩ c)"""
    assert a.intersect(b).intersect(c) == a.intersect(b.intersect(c))


@given(version_set())
def test_intersect_with_full_is_identity(a):
    """a ∩ full() == a"""
    assert a.intersect(VersionSet.full()) == a


@given(version_set())
def test_intersect_with_empty_is_empty(a):
    """a ∩ empty() == empty()"""
    assert a.intersect(VersionSet.empty()) == VersionSet.empty()


@given(version_set())
def test_union_idempotent(a):
    """a ∪ a == a"""
    assert a.union(a) == a


@given(version_set(), version_set())
def test_union_commutative(a, b):
    """a ∪ b == b ∪ a"""
    assert a.union(b) == b.union(a)


@given(version_set(), version_set(), version_set())
def test_union_associative(a, b, c):
    """(a ∪ b) ∪ c == a ∪ (b ∪ c)"""
    assert a.union(b).union(c) == a.union(b.union(c))


@given(version_set())
def test_union_with_empty_is_identity(a):
    """a ∪ empty() == a"""
    assert a.union(VersionSet.empty()) == a


@given(version_set())
def test_union_with_full_is_universe(a):
    """a ∪ full() == full()"""
    assert a.union(VersionSet.full()) == VersionSet.full()


@given(version_set())
def test_double_complement_is_identity(a):
    """(a^c)^c == a — involution law."""
    assert a.complement().complement() == a


@given(version_set(), version_set())
def test_de_morgan_intersect(a, b):
    """(a ∩ b)^c == a^c ∪ b^c"""
    lhs = a.intersect(b).complement()
    rhs = a.complement().union(b.complement())
    assert lhs == rhs


@given(version_set(), version_set())
def test_de_morgan_union(a, b):
    """(a ∪ b)^c == a^c ∩ b^c"""
    lhs = a.union(b).complement()
    rhs = a.complement().intersect(b.complement())
    assert lhs == rhs


@given(version_set(), version_tuple())
def test_contains_via_intersect_with_eq(a, v):
    """a.contains(v) ⇔ a ∩ eq(v) ≠ empty()

    Two paths in the algebra computing the same predicate must agree."""
    via_contains = a.contains(v)
    via_intersect = not a.intersect(VersionSet.eq(v)).is_empty()
    assert via_contains == via_intersect


@given(version_set(), version_set())
def test_is_subset_of_via_intersect(a, b):
    """a ⊆ b ⇔ a ∩ b == a

    The intersect form is the definitional one; is_subset_of is
    optimized — they must agree."""
    via_is_subset = a.is_subset_of(b)
    via_intersect = (a.intersect(b) == a)
    assert via_is_subset == via_intersect
