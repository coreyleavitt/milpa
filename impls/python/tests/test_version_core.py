"""Slice-1b tests: Version, PreId, parse_version, format_version_str, Strategy.

TDD: run with `uv run pytest tests/test_version_core.py -x`.
"""

from milpa.version import (
    PreId,
    Strategy,
    Version,
    format_version_str,
    parse_version,
)

# ---------------------------------------------------------------------------
# parse_version / format_version_str round-trip
# ---------------------------------------------------------------------------


def test_parse_simple() -> None:
    v = parse_version("1.2.3")
    assert v is not None
    assert v.major == 1
    assert v.minor == 2
    assert v.patch == 3
    assert v.pre == ()
    assert v.build == ""


def test_parse_v_prefix() -> None:
    v = parse_version("v0.5.1")
    assert v is not None
    assert (v.major, v.minor, v.patch) == (0, 5, 1)


def test_parse_prerelease_alpha() -> None:
    v = parse_version("1.0.0-alpha")
    assert v is not None
    assert v.pre == ("alpha",)


def test_parse_prerelease_numeric() -> None:
    v = parse_version("1.0.0-1")
    assert v is not None
    assert v.pre == (1,)  # numeric → int


def test_parse_prerelease_mixed() -> None:
    v = parse_version("1.0.0-rc.1")
    assert v is not None
    assert v.pre == ("rc", 1)


def test_parse_build_metadata() -> None:
    v = parse_version("1.0.0+build.007")
    assert v is not None
    assert v.build == "build.007"
    assert v.pre == ()


def test_parse_prerelease_and_build() -> None:
    v = parse_version("1.0.0-alpha.1+exp.sha.5114f85")
    assert v is not None
    assert v.pre == ("alpha", 1)
    assert v.build == "exp.sha.5114f85"


def test_parse_invalid_returns_none() -> None:
    assert parse_version("not-a-version") is None
    assert parse_version("1.2") is None
    assert parse_version("1.2.3.4") is None
    assert parse_version("nimble-1.2.3") is None


def test_parse_none_returns_none() -> None:
    # type: ignore[arg-type]  — intentional runtime test
    assert parse_version(None) is None  # type: ignore[arg-type]


def test_parse_oversized_digit_run_returns_none_not_raises() -> None:
    """R10: CPython >=3.11 caps int<->str conversion at ~4300 digits; a
    crafted tag/version with an oversized numeric component (e.g. an
    attacker-controlled git ref) must still hit ``parse_version``'s
    documented "non-canonical -> None" contract, never an uncaught
    ``ValueError`` from the bare ``int()`` call."""
    huge = "9" * 6000
    assert parse_version(f"v{huge}.0.0") is None
    assert parse_version(f"1.{huge}.0") is None
    assert parse_version(f"1.0.{huge}") is None


def test_parse_component_exceeding_u64_returns_none() -> None:
    """Parity with Rust's ``parse_numeric_component`` (``s.parse::<u64>()``):
    a component that fits Python's own int type but overflows a u64 must
    still parse to ``None`` in Python, so both impls agree on what counts as
    a valid version rather than Python silently accepting more than Rust."""
    too_big = str(2**64)  # one past u64::MAX
    assert parse_version(f"{too_big}.0.0") is None


def test_parse_component_at_u64_max_still_parses() -> None:
    """The u64 boundary itself is still a valid (if absurd) component."""
    u64_max = 2**64 - 1
    v = parse_version(f"{u64_max}.0.0")
    assert v is not None
    assert v.major == u64_max


# ---------------------------------------------------------------------------
# RR6: oversized/overflowing prerelease identifiers must not raise, and must
# classify the same way Rust's ``parse_pre_identifiers`` does (fall back to
# the alphanumeric/string form rather than crash or silently reject).
# ---------------------------------------------------------------------------


def test_parse_prerelease_oversized_digit_run_becomes_alpha_not_raises() -> None:
    """RR6: unlike a release component, an oversized all-digit *prerelease*
    identifier (e.g. a crafted git ref/tag) must not propagate the bare
    ``int()`` call's ``ValueError`` (CPython's ~4300-digit int<->str
    conversion cap). Rust's ``parse_pre_identifiers`` falls back to
    ``PreId::Alpha`` for exactly this case ("fall back to Alpha so parsing
    never panics") — Python must match: parse succeeds, the identifier is
    kept as the plain string."""
    huge = "9" * 6000
    v = parse_version(f"1.0.0-{huge}")
    assert v is not None
    assert v.pre == (huge,)


def test_parse_prerelease_component_exceeding_u64_becomes_alpha() -> None:
    """An all-digit prerelease identifier that overflows u64 but is still a
    small, ordinary Python int (no CPython cap involved) must ALSO fall back
    to the string/Alpha form — parity with Rust's ``parse::<u64>()`` overflow
    fallback, not just the CPython-cap edge case."""
    too_big = str(2**64)  # one past u64::MAX
    v = parse_version(f"1.0.0-{too_big}")
    assert v is not None
    assert v.pre == (too_big,)


def test_parse_prerelease_ordinary_numeric_ids_unaffected() -> None:
    """No regression: ordinary numeric prerelease identifiers still classify
    as NUMERIC (int), not string, and still compare/sort correctly."""
    v1 = parse_version("1.0.0-1")
    v2 = parse_version("1.0.0-2")
    v_dotted = parse_version("1.0.0-0.3.7")
    assert v1 is not None and v2 is not None and v_dotted is not None
    assert v1.pre == (1,)
    assert v2.pre == (2,)
    assert v_dotted.pre == (0, 3, 7)
    assert v1 < v2  # numeric compare, not string compare


def test_parse_prerelease_rc_dot_numeric_unaffected() -> None:
    """No regression on the common ``-rc.N`` shape (mixed alpha + numeric)."""
    v = parse_version("1.0.0-rc.2")
    assert v is not None
    assert v.pre == ("rc", 2)


def test_format_simple() -> None:
    v = Version(1, 2, 3)
    assert format_version_str(v) == "1.2.3"


def test_format_prerelease() -> None:
    v = Version(1, 0, 0, pre=("alpha", 1))
    assert format_version_str(v) == "1.0.0-alpha.1"


def test_format_build() -> None:
    v = Version(1, 0, 0, build="20130313144700")
    assert format_version_str(v) == "1.0.0+20130313144700"


def test_format_prerelease_and_build() -> None:
    v = Version(1, 0, 0, pre=("beta", 11), build="exp.sha")
    assert format_version_str(v) == "1.0.0-beta.11+exp.sha"


def test_round_trip_simple() -> None:
    v = Version(0, 1, 0)
    assert parse_version(format_version_str(v)) == v


def test_round_trip_prerelease() -> None:
    v = Version(2, 3, 4, pre=("rc", 1))
    assert parse_version(format_version_str(v)) == v


# ---------------------------------------------------------------------------
# Version total order per semver §10/11
# ---------------------------------------------------------------------------


def test_order_basic() -> None:
    assert Version(1, 0, 0) < Version(2, 0, 0)
    assert Version(1, 0, 0) < Version(1, 1, 0)
    assert Version(1, 0, 0) < Version(1, 0, 1)


def test_prerelease_less_than_release() -> None:
    """semver §11.1: prerelease < release for the same M.m.p."""
    pre = Version(1, 0, 0, pre=("alpha",))
    rel = Version(1, 0, 0)
    assert pre < rel


def test_prerelease_order_numeric_vs_alpha() -> None:
    """semver §11.4.4: numeric < alphanumeric identifiers."""
    num = Version(1, 0, 0, pre=(1,))
    alpha = Version(1, 0, 0, pre=("alpha",))
    assert num < alpha


def test_prerelease_order_numeric() -> None:
    """semver §11.4.1: numeric identifiers compared numerically."""
    v1 = Version(1, 0, 0, pre=(1,))
    v2 = Version(1, 0, 0, pre=(2,))
    assert v1 < v2


def test_prerelease_order_alpha() -> None:
    """semver §11.4.2: alphanumeric compared in ASCII order."""
    v1 = Version(1, 0, 0, pre=("alpha",))
    v2 = Version(1, 0, 0, pre=("beta",))
    assert v1 < v2


def test_prerelease_longer_has_higher_precedence() -> None:
    """semver §11.4.4: larger set of identifiers beats smaller (when all preceding are equal)."""
    short = Version(1, 0, 0, pre=("alpha",))
    longer = Version(1, 0, 0, pre=("alpha", 1))
    assert short < longer


def test_build_metadata_ignored_for_ordering() -> None:
    """semver §10: build metadata MUST be ignored."""
    v1 = Version(1, 0, 0, build="build.1")
    v2 = Version(1, 0, 0, build="build.2")
    assert v1 == v2


def test_equality_ignores_build() -> None:
    assert Version(1, 0, 0) == Version(1, 0, 0, build="anything")


def test_inequality_prerelease() -> None:
    assert Version(1, 0, 0, pre=("alpha",)) != Version(1, 0, 0)


def test_comparison_operators() -> None:
    a = Version(1, 0, 0)
    b = Version(2, 0, 0)
    assert a < b
    assert a <= b
    assert b > a
    assert b >= a
    assert a <= a
    assert a >= a


def test_version_equality() -> None:
    assert Version(1, 2, 3) == Version(1, 2, 3)
    assert Version(1, 2, 3) != Version(1, 2, 4)


def test_version_hash_consistent_with_eq() -> None:
    v1 = Version(1, 2, 3)
    v2 = Version(1, 2, 3, build="ignored")
    assert v1 == v2
    assert hash(v1) == hash(v2)


# ---------------------------------------------------------------------------
# PreId type alias
# ---------------------------------------------------------------------------


def test_preid_int() -> None:
    p: PreId = 42
    assert isinstance(p, int)


def test_preid_str() -> None:
    p: PreId = "alpha"
    assert isinstance(p, str)


# ---------------------------------------------------------------------------
# Strategy enum
# ---------------------------------------------------------------------------


def test_strategy_values() -> None:
    assert Strategy.MAXVER == "maxver"
    assert Strategy.MINVER == "minver"
    assert Strategy.SEMVER == "semver"


def test_strategy_is_str_enum() -> None:
    assert str(Strategy.MAXVER) == "maxver"
