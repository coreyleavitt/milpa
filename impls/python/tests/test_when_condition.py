"""Tests for ``parse_when_condition`` in ``milpa.nimble`` (RFC §3.1 S1).

Coverage (grouped by TDD cycle):
  C1 — platform tokens + aliases
  C2 — arch tokens
  C3 — ``not`` negation
  C4 — single ``NimMajor OP X`` form
  C5 — tuple ``(NimMajor, NimMinor) OP (X, Y)`` and three-component form + operators
  C6 — two-sided range ``and`` form
  C7 — UNRECOGNIZED battery (posix, unknown defined(), compound or/and, blank)

Postcondition (asserted in every positive case): the returned tuple is non-empty.
"""

from __future__ import annotations

import pytest

from milpa.manifest import Predicate
from milpa.nimble import parse_when_condition


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _plat(name: str, *, negated: bool = False) -> Predicate:
    return Predicate(name="platform", values=(name,), negated=negated)


def _arch(name: str, *, negated: bool = False) -> Predicate:
    return Predicate(name="arch", values=(name,), negated=negated)


def _nim(constraint: str, *, negated: bool = False) -> Predicate:
    return Predicate(name="nim", values=(constraint,), negated=negated)


def _assert_recognized(cond: str, expected: tuple[Predicate, ...]) -> None:
    result = parse_when_condition(cond)
    assert result is not None, f"Expected recognized, got None for: {cond!r}"
    assert len(result) > 0, f"Recognized condition returned empty tuple for: {cond!r}"
    assert result == expected, f"For {cond!r}: got {result!r}, want {expected!r}"


def _assert_unrecognized(cond: str) -> None:
    result = parse_when_condition(cond)
    assert result is None, f"Expected None (unrecognized), got {result!r} for: {cond!r}"


# ---------------------------------------------------------------------------
# C1 — platform tokens + aliases
# ---------------------------------------------------------------------------


class TestPlatformTokens:
    def test_linux(self):
        _assert_recognized("defined(linux)", (_plat("linux"),))

    def test_macosx(self):
        _assert_recognized("defined(macosx)", (_plat("macosx"),))

    def test_windows(self):
        _assert_recognized("defined(windows)", (_plat("windows"),))

    def test_freebsd(self):
        _assert_recognized("defined(freebsd)", (_plat("freebsd"),))

    def test_openbsd(self):
        _assert_recognized("defined(openbsd)", (_plat("openbsd"),))

    def test_netbsd(self):
        _assert_recognized("defined(netbsd)", (_plat("netbsd"),))

    def test_alias_win_maps_to_windows(self):
        _assert_recognized("defined(win)", (_plat("windows"),))

    def test_alias_macos_maps_to_macosx(self):
        _assert_recognized("defined(macos)", (_plat("macosx"),))

    def test_whitespace_tolerance_spaces_inside_parens(self):
        _assert_recognized("defined( linux )", (_plat("linux"),))

    def test_whitespace_tolerance_leading_trailing(self):
        _assert_recognized("  defined(linux)  ", (_plat("linux"),))


# ---------------------------------------------------------------------------
# C2 — arch tokens
# ---------------------------------------------------------------------------


class TestArchTokens:
    def test_amd64(self):
        _assert_recognized("defined(amd64)", (_arch("amd64"),))

    def test_arm64(self):
        _assert_recognized("defined(arm64)", (_arch("arm64"),))

    def test_i386(self):
        _assert_recognized("defined(i386)", (_arch("i386"),))

    def test_whitespace_tolerance(self):
        _assert_recognized("defined( amd64 )", (_arch("amd64"),))


# ---------------------------------------------------------------------------
# C3 — ``not`` negation
# ---------------------------------------------------------------------------


class TestNotNegation:
    def test_not_linux(self):
        _assert_recognized("not defined(linux)", (_plat("linux", negated=True),))

    def test_not_windows(self):
        _assert_recognized("not defined(windows)", (_plat("windows", negated=True),))

    def test_not_amd64(self):
        _assert_recognized("not defined(amd64)", (_arch("amd64", negated=True),))

    def test_not_with_extra_space(self):
        _assert_recognized("not  defined(linux)", (_plat("linux", negated=True),))

    def test_not_alias_win(self):
        _assert_recognized("not defined(win)", (_plat("windows", negated=True),))

    def test_not_unrecognized_inner_yields_none(self):
        # Inner is unrecognized → the whole thing is unrecognized.
        _assert_unrecognized("not defined(posix)")

    def test_not_two_sided_range_yields_none(self):
        # Inner yields 2 predicates → not applicable.
        _assert_unrecognized(
            "not (NimMajor, NimMinor) >= (1, 4) and (NimMajor, NimMinor) < (2, 0)"
        )


# ---------------------------------------------------------------------------
# C4 — single ``NimMajor OP X`` form
# ---------------------------------------------------------------------------


class TestNimMajorSingle:
    def test_gte(self):
        _assert_recognized("NimMajor >= 1", (_nim(">=1.0.0"),))

    def test_gt(self):
        _assert_recognized("NimMajor > 1", (_nim(">1.0.0"),))

    def test_lt(self):
        _assert_recognized("NimMajor < 2", (_nim("<2.0.0"),))

    def test_lte(self):
        _assert_recognized("NimMajor <= 1", (_nim("<=1.0.0"),))

    def test_eq(self):
        _assert_recognized("NimMajor == 1", (_nim("==1.0.0"),))

    def test_no_spaces(self):
        _assert_recognized("NimMajor>=1", (_nim(">=1.0.0"),))

    def test_leading_trailing_whitespace(self):
        _assert_recognized("  NimMajor >= 2  ", (_nim(">=2.0.0"),))

    def test_minor_and_patch_are_zero(self):
        result = parse_when_condition("NimMajor >= 2")
        assert result == (_nim(">=2.0.0"),)

    def test_larger_major(self):
        _assert_recognized("NimMajor >= 10", (_nim(">=10.0.0"),))


# ---------------------------------------------------------------------------
# C5 — tuple (NimMajor, NimMinor) OP (X, Y) and three-component form
# ---------------------------------------------------------------------------


class TestNimTupleForms:
    def test_two_component_gte(self):
        _assert_recognized("(NimMajor, NimMinor) >= (1, 4)", (_nim(">=1.4.0"),))

    def test_two_component_lt(self):
        _assert_recognized("(NimMajor, NimMinor) < (2, 0)", (_nim("<2.0.0"),))

    def test_two_component_gt(self):
        _assert_recognized("(NimMajor, NimMinor) > (1, 6)", (_nim(">1.6.0"),))

    def test_two_component_lte(self):
        _assert_recognized("(NimMajor, NimMinor) <= (1, 9)", (_nim("<=1.9.0"),))

    def test_two_component_eq(self):
        _assert_recognized("(NimMajor, NimMinor) == (2, 0)", (_nim("==2.0.0"),))

    def test_three_component_gte(self):
        _assert_recognized(
            "(NimMajor, NimMinor, NimPatch) >= (1, 6, 0)", (_nim(">=1.6.0"),)
        )

    def test_three_component_lt(self):
        _assert_recognized(
            "(NimMajor, NimMinor, NimPatch) < (2, 0, 1)", (_nim("<2.0.1"),)
        )

    def test_no_spaces(self):
        _assert_recognized("(NimMajor,NimMinor)>=(1,4)", (_nim(">=1.4.0"),))

    def test_mixed_spacing(self):
        _assert_recognized("(NimMajor, NimMinor) >= (1,4)", (_nim(">=1.4.0"),))

    def test_patch_component_nonzero(self):
        _assert_recognized(
            "(NimMajor, NimMinor, NimPatch) == (1, 6, 14)", (_nim("==1.6.14"),)
        )


# ---------------------------------------------------------------------------
# C6 — two-sided range ``and`` form
# ---------------------------------------------------------------------------


class TestTwoSidedRange:
    def test_basic_range(self):
        _assert_recognized(
            "(NimMajor, NimMinor) >= (1, 4) and (NimMajor, NimMinor) < (2, 0)",
            (_nim(">=1.4.0"), _nim("<2.0.0")),
        )

    def test_range_no_spaces(self):
        _assert_recognized(
            "(NimMajor,NimMinor)>=(1,4)and(NimMajor,NimMinor)<(2,0)",
            (_nim(">=1.4.0"), _nim("<2.0.0")),
        )

    def test_range_three_component(self):
        _assert_recognized(
            "(NimMajor, NimMinor, NimPatch) >= (1, 6, 0) and (NimMajor, NimMinor, NimPatch) < (2, 0, 0)",
            (_nim(">=1.6.0"), _nim("<2.0.0")),
        )

    def test_and_with_non_nim_tuple_yields_none(self):
        # ``and`` with a platform condition is unrecognized.
        _assert_unrecognized("defined(linux) and defined(macosx)")

    def test_and_one_side_not_nim_tuple_yields_none(self):
        _assert_unrecognized("defined(linux) and (NimMajor, NimMinor) < (2, 0)")


# ---------------------------------------------------------------------------
# C7 — UNRECOGNIZED battery
# ---------------------------------------------------------------------------


class TestUnrecognized:
    def test_empty_string(self):
        _assert_unrecognized("")

    def test_blank_string(self):
        _assert_unrecognized("   ")

    def test_posix_is_deliberately_unrecognized(self):
        _assert_unrecognized("defined(posix)")

    def test_unknown_token_release(self):
        _assert_unrecognized("defined(release)")

    def test_unknown_token_js(self):
        _assert_unrecognized("defined(js)")

    def test_unknown_token_solaris(self):
        _assert_unrecognized("defined(solaris)")

    def test_unknown_token_custom(self):
        _assert_unrecognized("defined(custom)")

    def test_compound_or_is_unrecognized(self):
        _assert_unrecognized("defined(linux) or defined(macosx)")

    def test_compound_and_non_nim_is_unrecognized(self):
        _assert_unrecognized("defined(linux) and defined(windows)")

    def test_unknown_nimscript_expression(self):
        _assert_unrecognized("system.hostOS == \"linux\"")

    def test_case_sensitive_defined(self):
        # "Linux" (capital L) is not in the vocabulary.
        _assert_unrecognized("defined(Linux)")

    def test_case_sensitive_windows(self):
        _assert_unrecognized("defined(Windows)")

    def test_defined_no_arg(self):
        _assert_unrecognized("defined()")

    def test_not_case_sensitive_NimMajor(self):
        # lowercase nimmajor is not the NimMajor keyword.
        _assert_unrecognized("nimmajor >= 1")

    def test_arch_token_not_platform(self):
        # amd64 is arch, not platform — should be arch predicate, already tested.
        # But make sure it's not accidentally returning a platform predicate.
        result = parse_when_condition("defined(amd64)")
        assert result is not None
        assert result[0].name == "arch"

    def test_unknown_operator(self):
        _assert_unrecognized("NimMajor != 1")

    def test_nim_tuple_wrong_order(self):
        # Reversed tuple components — not in grammar.
        _assert_unrecognized("(NimMinor, NimMajor) >= (4, 1)")
