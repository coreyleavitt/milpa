"""P3.1b — prerelease ordering, eq() singleton soundness, opt-in, lockfile round-trip.

Tests are written RED-first. Each section maps to a requirement from the P3.1b slice.
"""

import pytest

from milpa.solver import Version, VersionSet, parse_version


# ---------------------------------------------------------------------------
# (1) Version construction + field access
# ---------------------------------------------------------------------------


def test_version_release_fields():
    v = Version(1, 2, 3)
    assert v.major == 1
    assert v.minor == 2
    assert v.patch == 3


def test_version_prerelease_fields():
    v = Version(1, 0, 0, pre=("alpha", 1))
    assert v.major == 1
    assert v.minor == 0
    assert v.patch == 0
    assert v.pre == ("alpha", 1)
    assert v.build == ""


def test_version_build_metadata():
    v = Version(1, 0, 0, build="build.5")
    assert v.build == "build.5"


def test_version_release_index_access_preserved():
    """v[0]/v[1]/v[2] must still work for all release versions."""
    v = Version(3, 4, 5)
    assert v[0] == 3
    assert v[1] == 4
    assert v[2] == 5


def test_version_prerelease_index_access_preserved():
    """v[0]/v[1]/v[2] must still work for prerelease versions."""
    v = Version(1, 0, 0, pre=("alpha",))
    assert v[0] == 1
    assert v[1] == 0
    assert v[2] == 0


# ---------------------------------------------------------------------------
# (2) Release version backward-compat equality — the drop-in invariant
# ---------------------------------------------------------------------------


def test_version_release_equals_plain_3tuple():
    """Version(x,y,z) == (x,y,z) — the critical drop-in invariant from P3.1a."""
    v = Version(1, 0, 0)
    assert v == (1, 0, 0)
    assert (1, 0, 0) == v


def test_version_release_hash_equals_tuple_hash():
    """hash(Version(x,y,z)) == hash((x,y,z)) so dict[tuple] lookup still works."""
    v = Version(1, 0, 0)
    assert hash(v) == hash((1, 0, 0))


def test_version_release_dict_lookup_by_tuple():
    """DictProvider uses bare tuples as keys; Version lookup must hit them."""
    d = {(1, 0, 0): "found"}
    assert d[Version(1, 0, 0)] == "found"


def test_version_release_ordering_preserved():
    """Release version ordering is lexicographic on (major, minor, patch)."""
    assert Version(1, 0, 0) < Version(1, 0, 1)
    assert Version(0, 9, 9) < Version(1, 0, 0)
    assert Version(1, 0, 0) == Version(1, 0, 0)
    # Ordering vs plain tuples preserved
    assert Version(1, 0, 0) < (1, 0, 1)
    assert not (Version(1, 0, 0) < (1, 0, 0))


def test_version_prerelease_not_equal_to_release():
    """1.0.0-alpha != 1.0.0."""
    assert Version(1, 0, 0, pre=("alpha",)) != Version(1, 0, 0)
    assert Version(1, 0, 0, pre=("alpha",)) != (1, 0, 0)


def test_version_build_metadata_ignored_for_equality():
    """1.0.0+a == 1.0.0+b per semver (build is ignored for precedence)."""
    assert Version(1, 0, 0, build="a") == Version(1, 0, 0, build="b")
    assert Version(1, 0, 0, build="a") == Version(1, 0, 0)
    assert Version(1, 0, 0, build="a") == (1, 0, 0)


# ---------------------------------------------------------------------------
# (2) Full semver-2.0 prerelease total ordering
# ---------------------------------------------------------------------------


_SEMVER_ORDERING_TABLE = [
    # (smaller, larger) pairs in strict ascending semver order
    (Version(0, 9, 0),                   Version(1, 0, 0, pre=("alpha",))),
    (Version(1, 0, 0, pre=("alpha",)),   Version(1, 0, 0, pre=("alpha", 1))),
    (Version(1, 0, 0, pre=("alpha", 1)), Version(1, 0, 0, pre=("alpha", 2))),
    (Version(1, 0, 0, pre=("alpha", 2)), Version(1, 0, 0, pre=("beta",))),
    (Version(1, 0, 0, pre=("beta",)),    Version(1, 0, 0, pre=("beta", 2))),
    (Version(1, 0, 0, pre=("beta", 2)),  Version(1, 0, 0, pre=("rc", 1))),
    (Version(1, 0, 0, pre=("rc", 1)),    Version(1, 0, 0)),                  # release is greatest
    (Version(1, 0, 0),                   Version(1, 0, 1, pre=("alpha",))),
    (Version(1, 0, 1, pre=("alpha",)),   Version(1, 0, 1)),
    # numeric identifier < alphanumeric identifier (per semver)
    (Version(1, 0, 0, pre=(1,)),         Version(1, 0, 0, pre=("alpha",))),
    # more identifiers > fewer when all preceding equal
    (Version(1, 0, 0, pre=("alpha",)),   Version(1, 0, 0, pre=("alpha", 0))),
]


@pytest.mark.parametrize("smaller,larger", _SEMVER_ORDERING_TABLE)
def test_semver_ordering_table(smaller, larger):
    """Each row: smaller < larger strictly."""
    assert smaller < larger
    assert not larger < smaller
    assert smaller != larger


def test_build_metadata_ignored_for_ordering():
    """Build metadata must NOT affect ordering."""
    a = Version(1, 0, 0, build="build.1")
    b = Version(1, 0, 0, build="build.2")
    assert not (a < b)
    assert not (b < a)
    assert a == b  # equal precedence


# ---------------------------------------------------------------------------
# (3) THE CRITICAL FIX — VersionSet.eq(v) is a true singleton {v}
# ---------------------------------------------------------------------------


def test_eq_contains_only_itself_release():
    """eq(1.0.0) contains 1.0.0 and nothing else (spot checks)."""
    v = Version(1, 0, 0)
    eq_v = VersionSet.eq(v)
    assert eq_v.contains(v)
    assert not eq_v.contains(Version(1, 0, 1))
    assert not eq_v.contains(Version(0, 9, 9))


def test_eq_excludes_prerelease_of_next_patch_REGRESSION():
    """REGRESSION: old [1.0.0, 1.0.1) wrongly admitted 1.0.1-rc.1.

    This is the named regression case from the P3.1b brief.
    eq(1.0.0) must NOT contain 1.0.1-rc.1.
    """
    release = Version(1, 0, 0)
    prerelease_next = Version(1, 0, 1, pre=("rc", "1"))
    assert VersionSet.eq(release).contains(prerelease_next) is False


def test_eq_excludes_prerelease_of_same_version():
    """eq(1.0.0) must NOT contain 1.0.0-alpha (which is below 1.0.0)."""
    release = Version(1, 0, 0)
    pre = Version(1, 0, 0, pre=("alpha",))
    assert VersionSet.eq(release).contains(pre) is False


def test_eq_singleton_property_release():
    """eq(v).contains(w) ⟺ w == v for all release versions."""
    versions = [
        Version(0, 0, 0), Version(1, 0, 0), Version(1, 2, 3),
        Version(0, 9, 9), Version(1, 0, 1),
    ]
    for v in versions:
        eq_v = VersionSet.eq(v)
        for w in versions:
            assert eq_v.contains(w) == (w == v), (
                f"eq({v}).contains({w}) = {eq_v.contains(w)}, expected {w == v}"
            )


def test_eq_singleton_property_prerelease():
    """eq(1.0.0-alpha).contains(w) ⟺ w == 1.0.0-alpha."""
    v = Version(1, 0, 0, pre=("alpha",))
    eq_v = VersionSet.eq(v)
    assert eq_v.contains(v) is True
    assert eq_v.contains(Version(1, 0, 0)) is False          # release is above
    assert eq_v.contains(Version(1, 0, 0, pre=("beta",))) is False  # different pre
    assert eq_v.contains(Version(0, 9, 9)) is False


def test_eq_contains_consistent_with_intersect():
    """eq(v).contains(w) ⟺ eq(v) ∩ eq(w) ≠ ∅ — the algebra is consistent."""
    versions = [
        Version(1, 0, 0),
        Version(1, 0, 0, pre=("alpha",)),
        Version(1, 0, 1, pre=("rc", "1")),
        Version(1, 0, 1),
    ]
    for v in versions:
        for w in versions:
            via_contains = VersionSet.eq(v).contains(w)
            via_intersect = not VersionSet.eq(v).intersect(VersionSet.eq(w)).is_empty()
            assert via_contains == via_intersect, (
                f"eq({v}).contains({w}): contains={via_contains}, intersect={via_intersect}"
            )


# ---------------------------------------------------------------------------
# (4) Opt-in via constraint floor — NO predicate on contains()
# ---------------------------------------------------------------------------


def test_gte_release_excludes_prereleases_of_that_version():
    """>=1.0.0 excludes 1.0.0-rc.1 (rc.1 < 1.0.0 in semver ordering)."""
    vs = VersionSet.gte(Version(1, 0, 0))
    assert not vs.contains(Version(1, 0, 0, pre=("rc", "1")))
    assert not vs.contains(Version(1, 0, 0, pre=("alpha",)))


def test_gte_release_includes_release_and_above():
    """>=1.0.0 includes 1.0.0 and any later release."""
    vs = VersionSet.gte(Version(1, 0, 0))
    assert vs.contains(Version(1, 0, 0))
    assert vs.contains(Version(1, 0, 1))
    assert vs.contains(Version(2, 0, 0))


def test_gte_prerelease_admits_prereleases_at_or_above():
    """>=1.0.0-alpha admits 1.0.0-alpha, 1.0.0-beta, 1.0.0, 1.0.1-rc, ..."""
    vs = VersionSet.gte(Version(1, 0, 0, pre=("alpha",)))
    assert vs.contains(Version(1, 0, 0, pre=("alpha",)))
    assert vs.contains(Version(1, 0, 0, pre=("beta",)))
    assert vs.contains(Version(1, 0, 0))
    assert vs.contains(Version(1, 0, 1, pre=("rc", "1")))
    assert vs.contains(Version(1, 0, 1))
    # But NOT below alpha
    assert not vs.contains(Version(0, 9, 0))


def test_gt_prerelease_excludes_that_prerelease_and_below():
    """>1.0.0-rc.1 admits later rc's, the release, and higher."""
    vs = VersionSet.gt(Version(1, 0, 0, pre=("rc", "1")))
    # strictly below rc.1
    assert not vs.contains(Version(1, 0, 0, pre=("alpha",)))
    assert not vs.contains(Version(1, 0, 0, pre=("rc", "1")))  # excluded (strict)
    # at or above rc.1
    assert vs.contains(Version(1, 0, 0, pre=("rc", "2")))
    assert vs.contains(Version(1, 0, 0))
    assert vs.contains(Version(1, 0, 1))


def test_lt_excludes_prereleases_below_floor():
    """<1.0.0 excludes 0.9.0, includes 0.9.0-rc (wait — 0.9.0-rc < 0.9.0).

    <1.0.0 means strictly less than 1.0.0. Since prereleases of 1.0.0
    are below 1.0.0, they are included by <1.0.0."""
    vs = VersionSet.lt(Version(1, 0, 0))
    assert vs.contains(Version(0, 9, 0))
    assert vs.contains(Version(1, 0, 0, pre=("rc", "1")))  # rc.1 < 1.0.0
    assert not vs.contains(Version(1, 0, 0))
    assert not vs.contains(Version(1, 0, 1))


# ---------------------------------------------------------------------------
# (5) Lockfile round-trip — prerelease + build metadata lossless
# ---------------------------------------------------------------------------


def test_parse_version_parses_prerelease():
    """parse_version handles semver prerelease syntax: 1.2.3-alpha.1"""
    v = parse_version("1.2.3-alpha.1")
    assert v is not None
    assert v.major == 1
    assert v.minor == 2
    assert v.patch == 3
    assert v.pre == ("alpha", 1)


def test_parse_version_parses_build_metadata():
    """parse_version handles build metadata: 1.0.0+build.5"""
    v = parse_version("1.0.0+build.5")
    assert v is not None
    assert v.major == 1
    assert v.minor == 0
    assert v.patch == 0
    assert v.build == "build.5"


def test_parse_version_parses_prerelease_and_build():
    """parse_version handles both: 1.2.3-alpha.1+build.5"""
    v = parse_version("1.2.3-alpha.1+build.5")
    assert v is not None
    assert v.pre == ("alpha", 1)
    assert v.build == "build.5"


def test_parse_version_prerelease_numeric_identifiers():
    """Numeric prerelease identifiers are parsed as ints, not strings."""
    v = parse_version("1.0.0-0.3.7")
    assert v is not None
    assert v.pre == (0, 3, 7)


def test_parse_version_release_unchanged():
    """parse_version("1.2.3") still returns Version(1,2,3) with empty pre/build."""
    v = parse_version("1.2.3")
    assert v is not None
    assert v == Version(1, 2, 3)
    assert v.pre == ()
    assert v.build == ""


def test_lockfile_format_version_includes_prerelease():
    """_format_version emits prerelease and build-metadata components."""
    from milpa.lockfile import _format_version
    v = Version(1, 2, 3, pre=("alpha", 1), build="build.5")
    s = _format_version(v)
    assert "1.2.3" in s
    assert "alpha.1" in s
    assert "build.5" in s


def test_lockfile_format_version_roundtrip_prerelease():
    """parse_version(_format_version(v)) == v for a prerelease+build version."""
    from milpa.lockfile import _format_version
    v = Version(1, 2, 3, pre=("alpha", 1), build="build.5")
    s = _format_version(v)
    v2 = parse_version(s)
    assert v2 is not None
    # Full equality including build (build is ignored for ordering but preserved in string)
    assert v2.major == v.major
    assert v2.minor == v.minor
    assert v2.patch == v.patch
    assert v2.pre == v.pre
    assert v2.build == v.build


def test_lockfile_format_version_release_unchanged():
    """_format_version on a release Version still emits "M.m.p"."""
    from milpa.lockfile import _format_version
    v = Version(1, 2, 3)
    assert _format_version(v) == "1.2.3"


# ---------------------------------------------------------------------------
# Hypothesis property: eq(v).contains(w) ⟺ w == v  (mixed release+prerelease)
# ---------------------------------------------------------------------------

from hypothesis import given, settings, strategies as st


@st.composite
def release_version(draw):
    return Version(
        draw(st.integers(min_value=0, max_value=9)),
        draw(st.integers(min_value=0, max_value=9)),
        draw(st.integers(min_value=0, max_value=9)),
    )


@st.composite
def prerelease_version(draw):
    n_ids = draw(st.integers(min_value=1, max_value=3))
    ids = []
    for _ in range(n_ids):
        if draw(st.booleans()):
            ids.append(draw(st.integers(min_value=0, max_value=9)))
        else:
            ids.append(draw(st.text(alphabet=st.characters(
                whitelist_categories=("Ll", "Lu"), min_codepoint=97, max_codepoint=122
            ), min_size=1, max_size=5)))
    return Version(
        draw(st.integers(min_value=0, max_value=9)),
        draw(st.integers(min_value=0, max_value=9)),
        draw(st.integers(min_value=0, max_value=9)),
        pre=tuple(ids),
    )


@st.composite
def any_version(draw):
    return draw(st.one_of(release_version(), prerelease_version()))


@given(any_version(), any_version())
@settings(max_examples=200)
def test_eq_singleton_hypothesis(v, w):
    """eq(v).contains(w) ⟺ w == v — over release + prerelease versions."""
    assert VersionSet.eq(v).contains(w) == (w == v)
