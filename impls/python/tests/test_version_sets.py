"""Slice-1c tests: VersionSet interval algebra, from_constraint, from_nimble_constraint.

Includes:
  - Basic algebra unit tests
  - Pinned regression: lo=None merge gap (Hypothesis issue #63 / 2026-05-22)
  - Property tests (De Morgan, idempotence, totality, contains consistency)

TDD: run with `uv run pytest tests/test_version_sets.py -x`.
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from milpa.version import Version, VersionSet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def V(major: int, minor: int, patch: int) -> Version:
    return Version(major, minor, patch)


# ---------------------------------------------------------------------------
# Basic constructor sanity
# ---------------------------------------------------------------------------


def test_full_contains_any_version() -> None:
    assert VersionSet.full().contains(V(0, 0, 0))
    assert VersionSet.full().contains(V(9, 9, 9))
    assert VersionSet.full().contains(V(0, 0, 1))


def test_empty_contains_nothing() -> None:
    assert not VersionSet.empty().contains(V(0, 0, 0))
    assert not VersionSet.empty().contains(V(1, 2, 3))


def test_gte_contains_boundary_and_above() -> None:
    s = VersionSet.gte(V(1, 0, 0))
    assert s.contains(V(1, 0, 0))
    assert s.contains(V(2, 0, 0))
    assert not s.contains(V(0, 9, 9))


def test_gt_excludes_boundary() -> None:
    s = VersionSet.gt(V(1, 0, 0))
    assert not s.contains(V(1, 0, 0))
    assert s.contains(V(1, 0, 1))


def test_lt_excludes_boundary() -> None:
    s = VersionSet.lt(V(1, 0, 0))
    assert s.contains(V(0, 9, 9))
    assert not s.contains(V(1, 0, 0))


def test_lte_includes_boundary() -> None:
    s = VersionSet.lte(V(1, 0, 0))
    assert s.contains(V(1, 0, 0))
    assert not s.contains(V(1, 0, 1))


def test_eq_exact_singleton() -> None:
    s = VersionSet.eq(V(1, 2, 3))
    assert s.contains(V(1, 2, 3))
    assert not s.contains(V(1, 2, 4))
    assert not s.contains(V(1, 2, 2))


def test_eq_excludes_prerelease_of_next_version() -> None:
    """eq(1.0.1) must NOT contain 1.0.1-rc.1.

    The old [v, v_next) half-open representation admitted pre-releases of
    v_next because e.g. 1.0.1-rc.1 < 1.0.1. The closed-point form {v}
    fixes this structurally.
    """
    s = VersionSet.eq(V(1, 0, 1))
    pre = Version(1, 0, 1, pre=("rc", 1))
    assert not s.contains(pre)


# ---------------------------------------------------------------------------
# Complement
# ---------------------------------------------------------------------------


def test_complement_of_full_is_empty() -> None:
    assert VersionSet.full().complement() == VersionSet.empty()


def test_complement_of_empty_is_full() -> None:
    assert VersionSet.empty().complement() == VersionSet.full()


def test_complement_of_gte() -> None:
    s = VersionSet.gte(V(1, 0, 0))
    c = s.complement()
    assert c.contains(V(0, 9, 9))
    assert not c.contains(V(1, 0, 0))
    assert not c.contains(V(2, 0, 0))


def test_complement_of_range() -> None:
    # [0.5.0, 1.0.0) complement is (-∞, 0.5.0) ∪ [1.0.0, +∞)
    s = VersionSet.gte(V(0, 5, 0)).intersect(VersionSet.lt(V(1, 0, 0)))
    c = s.complement()
    assert c.contains(V(0, 4, 9))
    assert c.contains(V(1, 0, 0))
    assert c.contains(V(2, 0, 0))
    assert not c.contains(V(0, 5, 0))
    assert not c.contains(V(0, 9, 9))


# ---------------------------------------------------------------------------
# Intersect
# ---------------------------------------------------------------------------


def test_intersect_range() -> None:
    s = VersionSet.gte(V(0, 5, 0)).intersect(VersionSet.lt(V(1, 0, 0)))
    assert s.contains(V(0, 5, 0))
    assert s.contains(V(0, 9, 9))
    assert not s.contains(V(1, 0, 0))
    assert not s.contains(V(0, 4, 9))


def test_intersect_disjoint_is_empty() -> None:
    a = VersionSet.lt(V(1, 0, 0))
    b = VersionSet.gte(V(2, 0, 0))
    assert a.intersect(b) == VersionSet.empty()


def test_intersect_with_full_is_identity() -> None:
    s = VersionSet.gte(V(1, 0, 0))
    assert s.intersect(VersionSet.full()) == s


def test_intersect_with_empty_is_empty() -> None:
    s = VersionSet.gte(V(1, 0, 0))
    assert s.intersect(VersionSet.empty()) == VersionSet.empty()


# ---------------------------------------------------------------------------
# Union
# ---------------------------------------------------------------------------


def test_union_with_empty_is_identity() -> None:
    s = VersionSet.gte(V(1, 0, 0))
    assert s.union(VersionSet.empty()) == s


def test_union_with_full_is_full() -> None:
    s = VersionSet.lt(V(1, 0, 0))
    assert s.union(VersionSet.full()) == VersionSet.full()


def test_union_adjacent_merges() -> None:
    a = VersionSet.lt(V(1, 0, 0))
    b = VersionSet.gte(V(1, 0, 0))
    assert a.union(b) == VersionSet.full()


# ---------------------------------------------------------------------------
# PINNED REGRESSION: lo=None merge gap (Hypothesis issue #63, 2026-05-22)
#
# The frozen impl's _normalize_intervals used (0,) for lo=None but the sort
# comparison mixed (0,) with (1, Version, ...) tuples — this happened to work
# for single-None-lo intervals but when TWO lo=None intervals appeared in the
# same call (e.g. lt(v).union(full())), the canonical form of full() is
# (None, None, True, False) which also sorts as (0,) and both land adjacent.
# The root fix: the new impl's _normalize uses a fully-typed lo_sort_key that
# reliably places both None-lo intervals together and merges them.
# ---------------------------------------------------------------------------


def test_regression_lo_none_merge_gap_lt_union_full() -> None:
    """Regression: lt(v).union(full()) must equal full().

    Hypothesis found (issue #63, 2026-05-22) that the frozen impl produced
    a non-canonical VersionSet with two intervals both starting at -∞.
    Observable: result != full() because the redundant second interval
    caused a structural inequality even though the set was semantically full.
    """
    v = V(0, 0, 0)
    result = VersionSet.lt(v).union(VersionSet.full())
    assert result == VersionSet.full()


def test_regression_lo_none_merge_gap_full_union_lt() -> None:
    """Symmetric: full().union(lt(v)) must also equal full()."""
    v = V(1, 0, 0)
    result = VersionSet.full().union(VersionSet.lt(v))
    assert result == VersionSet.full()


def test_regression_lo_none_two_unbounded_intervals() -> None:
    """Any union of two unbounded-below intervals must produce at most one.

    This is the structural invariant that the lo=None merge gap violated.
    """
    a = VersionSet.lt(V(1, 0, 0))
    b = VersionSet.lt(V(2, 0, 0))
    result = a.union(b)
    # The result must have exactly one interval (the larger of the two)
    assert len(result.intervals) == 1
    # And that interval is (-∞, 2.0.0)
    assert result == VersionSet.lt(V(2, 0, 0))


def test_regression_complement_double_none() -> None:
    """Complement of eq(v) then union with full must be full.

    Exercises the path where complement produces two None-bounded pieces
    and then unioning with full() must still collapse correctly.
    """
    s = VersionSet.eq(V(0, 1, 0)).complement()  # (-∞, 0.1.0) ∪ (0.1.0, +∞)
    result = s.union(VersionSet.full())
    assert result == VersionSet.full()


# ---------------------------------------------------------------------------
# from_constraint — milpa.kdl constraint strings
# ---------------------------------------------------------------------------


def test_from_constraint_none_is_full() -> None:
    assert VersionSet.from_constraint(None) == VersionSet.full()


def test_from_constraint_empty_string_is_full() -> None:
    assert VersionSet.from_constraint("") == VersionSet.full()


def test_from_constraint_any_version_is_full() -> None:
    assert VersionSet.from_constraint("any version") == VersionSet.full()


def test_from_constraint_gte() -> None:
    s = VersionSet.from_constraint(">= 1.0.0")
    assert s.contains(V(1, 0, 0))
    assert s.contains(V(2, 0, 0))
    assert not s.contains(V(0, 9, 9))


def test_from_constraint_gt() -> None:
    s = VersionSet.from_constraint("> 1.0.0")
    assert not s.contains(V(1, 0, 0))
    assert s.contains(V(1, 0, 1))


def test_from_constraint_lt() -> None:
    s = VersionSet.from_constraint("< 1.0.0")
    assert s.contains(V(0, 9, 9))
    assert not s.contains(V(1, 0, 0))


def test_from_constraint_lte() -> None:
    s = VersionSet.from_constraint("<= 1.0.0")
    assert s.contains(V(1, 0, 0))
    assert not s.contains(V(1, 0, 1))


def test_from_constraint_eq_double_equals() -> None:
    s = VersionSet.from_constraint("== 1.2.3")
    assert s.contains(V(1, 2, 3))
    assert not s.contains(V(1, 2, 4))


def test_from_constraint_eq_single_equals() -> None:
    s = VersionSet.from_constraint("= 1.2.3")
    assert s.contains(V(1, 2, 3))
    assert not s.contains(V(1, 2, 4))


def test_from_constraint_neq() -> None:
    s = VersionSet.from_constraint("!= 1.0.0")
    assert not s.contains(V(1, 0, 0))
    assert s.contains(V(1, 0, 1))
    assert s.contains(V(0, 9, 9))


def test_from_constraint_and() -> None:
    s = VersionSet.from_constraint(">= 0.5.0 & < 1.0.0")
    assert s.contains(V(0, 5, 0))
    assert s.contains(V(0, 9, 9))
    assert not s.contains(V(1, 0, 0))
    assert not s.contains(V(0, 4, 9))


def test_from_constraint_or_double_pipe() -> None:
    s = VersionSet.from_constraint("< 1.0.0 || >= 2.0.0")
    assert s.contains(V(0, 9, 9))
    assert not s.contains(V(1, 5, 0))
    assert s.contains(V(2, 0, 0))


def test_from_constraint_or_single_pipe() -> None:
    s = VersionSet.from_constraint("< 1.0.0 | >= 2.0.0")
    assert s.contains(V(0, 9, 9))
    assert not s.contains(V(1, 5, 0))
    assert s.contains(V(2, 0, 0))


def test_from_constraint_tilde_patch() -> None:
    # ~1.2.3 → >= 1.2.3 < 1.3.0
    s = VersionSet.from_constraint("~1.2.3")
    assert s.contains(V(1, 2, 3))
    assert s.contains(V(1, 2, 9))
    assert not s.contains(V(1, 3, 0))
    assert not s.contains(V(1, 2, 2))


def test_from_constraint_tilde_minor_zero() -> None:
    # ~1.0.0: minor=0 AND patch=0 → bump major → [1.0.0, 2.0.0)
    s = VersionSet.from_constraint("~1.0.0")
    assert s.contains(V(1, 0, 0))
    assert s.contains(V(1, 9, 9))
    assert not s.contains(V(2, 0, 0))
    assert not s.contains(V(0, 9, 9))


def test_from_constraint_tilde_nonzero_minor() -> None:
    # ~1.2.0: minor=2 (nonzero) → bump minor → [1.2.0, 1.3.0)
    s = VersionSet.from_constraint("~1.2.0")
    assert s.contains(V(1, 2, 0))
    assert s.contains(V(1, 2, 9))
    assert not s.contains(V(1, 3, 0))


def test_from_constraint_tilde_major_bump() -> None:
    # ~2.0.0: minor=0, patch=0 → bump major → [2.0.0, 3.0.0)
    s = VersionSet.from_constraint("~2.0.0")
    assert s.contains(V(2, 0, 0))
    assert s.contains(V(2, 9, 9))
    assert not s.contains(V(3, 0, 0))


def test_from_constraint_caret_normal() -> None:
    # ^1.2.3 → >= 1.2.3 < 2.0.0
    s = VersionSet.from_constraint("^1.2.3")
    assert s.contains(V(1, 2, 3))
    assert s.contains(V(1, 9, 9))
    assert not s.contains(V(2, 0, 0))
    assert not s.contains(V(1, 2, 2))


def test_from_constraint_caret_zero_major() -> None:
    # ^0.2.3 → >= 0.2.3 < 0.3.0
    s = VersionSet.from_constraint("^0.2.3")
    assert s.contains(V(0, 2, 3))
    assert s.contains(V(0, 2, 9))
    assert not s.contains(V(0, 3, 0))


def test_from_constraint_caret_zero_major_minor() -> None:
    # ^0.0.3 → >= 0.0.3 < 0.0.4
    s = VersionSet.from_constraint("^0.0.3")
    assert s.contains(V(0, 0, 3))
    assert not s.contains(V(0, 0, 4))


def test_from_constraint_caret_all_zeros() -> None:
    # ^0.0.0 → >= 0.0.0 < 0.1.0
    s = VersionSet.from_constraint("^0.0.0")
    assert s.contains(V(0, 0, 0))
    assert not s.contains(V(0, 1, 0))


def test_from_constraint_invalid_raises() -> None:
    with pytest.raises(ValueError):
        VersionSet.from_constraint(">= not-a-version")


def test_from_constraint_unknown_op_raises() -> None:
    with pytest.raises(ValueError):
        VersionSet.from_constraint("??1.0.0")


# ---------------------------------------------------------------------------
# from_nimble_constraint
# ---------------------------------------------------------------------------


def test_from_nimble_constraint_none_is_full() -> None:
    assert VersionSet.from_nimble_constraint(None) == VersionSet.full()


def test_from_nimble_constraint_gte() -> None:
    s = VersionSet.from_nimble_constraint(">= 0.5.0")
    assert s.contains(V(0, 5, 0))
    assert not s.contains(V(0, 4, 9))


def test_from_nimble_constraint_and() -> None:
    s = VersionSet.from_nimble_constraint(">= 1.0.0 & < 2.0.0")
    assert s.contains(V(1, 0, 0))
    assert not s.contains(V(2, 0, 0))


def test_from_nimble_constraint_invalid_raises() -> None:
    with pytest.raises(ValueError):
        VersionSet.from_nimble_constraint(">= bad-version")


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------


@st.composite
def version_st(draw: st.DrawFn) -> Version:
    """Bounded version in [0,9]^3 with occasional prerelease."""
    major = draw(st.integers(min_value=0, max_value=9))
    minor = draw(st.integers(min_value=0, max_value=9))
    patch = draw(st.integers(min_value=0, max_value=9))
    pre: tuple[int | str, ...] = ()
    if draw(st.booleans()):
        num_ids = draw(st.integers(min_value=1, max_value=3))
        ids: list[int | str] = []
        for _ in range(num_ids):
            if draw(st.booleans()):
                ids.append(draw(st.integers(min_value=0, max_value=9)))
            else:
                alpha = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=6)
                ids.append(draw(alpha))
        pre = tuple(ids)
    return Version(major, minor, patch, pre=pre)


@st.composite
def primitive_set_st(draw: st.DrawFn) -> VersionSet:
    kind = draw(st.sampled_from(["full", "empty", "gte", "lt", "lte", "eq", "gt"]))
    if kind == "full":
        return VersionSet.full()
    if kind == "empty":
        return VersionSet.empty()
    v = draw(version_st())
    return {
        "gte": VersionSet.gte,
        "lt": VersionSet.lt,
        "lte": VersionSet.lte,
        "eq": VersionSet.eq,
        "gt": VersionSet.gt,
    }[kind](v)


@st.composite
def version_set_st(draw: st.DrawFn) -> VersionSet:
    """A VersionSet built by composing 0–3 algebraic operations."""
    s = draw(primitive_set_st())
    for _ in range(draw(st.integers(min_value=0, max_value=3))):
        op = draw(st.sampled_from(["intersect", "union", "complement"]))
        if op == "complement":
            s = s.complement()
        else:
            other = draw(primitive_set_st())
            s = s.intersect(other) if op == "intersect" else s.union(other)
    return s


# ---------------------------------------------------------------------------
# Algebraic property tests
# ---------------------------------------------------------------------------


@given(version_set_st())
def test_prop_intersect_idempotent(a: VersionSet) -> None:
    """a ∩ a == a"""
    assert a.intersect(a) == a


@given(version_set_st(), version_set_st())
def test_prop_intersect_commutative(a: VersionSet, b: VersionSet) -> None:
    """a ∩ b == b ∩ a"""
    assert a.intersect(b) == b.intersect(a)


@given(version_set_st(), version_set_st(), version_set_st())
def test_prop_intersect_associative(a: VersionSet, b: VersionSet, c: VersionSet) -> None:
    """(a ∩ b) ∩ c == a ∩ (b ∩ c)"""
    assert a.intersect(b).intersect(c) == a.intersect(b.intersect(c))


@given(version_set_st())
def test_prop_intersect_with_full(a: VersionSet) -> None:
    """a ∩ full == a"""
    assert a.intersect(VersionSet.full()) == a


@given(version_set_st())
def test_prop_intersect_with_empty(a: VersionSet) -> None:
    """a ∩ empty == empty"""
    assert a.intersect(VersionSet.empty()) == VersionSet.empty()


@given(version_set_st())
def test_prop_union_idempotent(a: VersionSet) -> None:
    """a ∪ a == a"""
    assert a.union(a) == a


@given(version_set_st(), version_set_st())
def test_prop_union_commutative(a: VersionSet, b: VersionSet) -> None:
    """a ∪ b == b ∪ a"""
    assert a.union(b) == b.union(a)


@given(version_set_st(), version_set_st(), version_set_st())
def test_prop_union_associative(a: VersionSet, b: VersionSet, c: VersionSet) -> None:
    """(a ∪ b) ∪ c == a ∪ (b ∪ c)"""
    assert a.union(b).union(c) == a.union(b.union(c))


@given(version_set_st())
def test_prop_union_with_empty(a: VersionSet) -> None:
    """a ∪ empty == a"""
    assert a.union(VersionSet.empty()) == a


@given(version_set_st())
def test_prop_union_with_full(a: VersionSet) -> None:
    """a ∪ full == full"""
    assert a.union(VersionSet.full()) == VersionSet.full()


@given(version_set_st())
def test_prop_double_complement(a: VersionSet) -> None:
    """(a^c)^c == a — involution law."""
    assert a.complement().complement() == a


@given(version_set_st(), version_set_st())
def test_prop_de_morgan_intersect(a: VersionSet, b: VersionSet) -> None:
    """(a ∩ b)^c == a^c ∪ b^c"""
    assert a.intersect(b).complement() == a.complement().union(b.complement())


@given(version_set_st(), version_set_st())
def test_prop_de_morgan_union(a: VersionSet, b: VersionSet) -> None:
    """(a ∪ b)^c == a^c ∩ b^c"""
    assert a.union(b).complement() == a.complement().intersect(b.complement())


@given(version_set_st(), version_st())
def test_prop_contains_via_intersect(a: VersionSet, v: Version) -> None:
    """a.contains(v) ⇔ a ∩ eq(v) ≠ ∅ — two paths computing same predicate."""
    via_contains = a.contains(v)
    via_intersect = not a.intersect(VersionSet.eq(v)).is_empty()
    assert via_contains == via_intersect


@given(version_set_st(), version_set_st())
def test_prop_is_subset_via_intersect(a: VersionSet, b: VersionSet) -> None:
    """a ⊆ b ⇔ a ∩ b == a"""
    assert a.is_subset_of(b) == (a.intersect(b) == a)


# ---------------------------------------------------------------------------
# Version total-order properties (round-trip, antisymmetry, transitivity)
# ---------------------------------------------------------------------------


@given(version_st())
def test_prop_version_roundtrip(v: Version) -> None:
    """parse_version(format_version_str(v)) == v for release versions.

    Build metadata is excluded from round-trip because format_version_str
    emits it but the property test only generates release+pre versions.
    """
    from milpa.version import format_version_str, parse_version

    s = format_version_str(v)
    parsed = parse_version(s)
    assert parsed is not None
    assert parsed == v


@given(version_st(), version_st())
def test_prop_version_antisymmetry(a: Version, b: Version) -> None:
    """a <= b and b <= a ⇒ a == b (antisymmetry of total order)."""
    if a <= b and b <= a:
        assert a == b


@given(version_st(), version_st(), version_st())
@settings(max_examples=200)
def test_prop_version_transitivity(a: Version, b: Version, c: Version) -> None:
    """a <= b and b <= c ⇒ a <= c (transitivity)."""
    if a <= b and b <= c:
        assert a <= c


@given(version_st(), version_st())
def test_prop_version_totality(a: Version, b: Version) -> None:
    """a <= b or b <= a (totality — total order)."""
    assert a <= b or b <= a
