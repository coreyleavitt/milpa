"""Tests for ``parse_when_branches`` in ``milpa.nimble`` (RFC §3.2 S3a).

This is the standalone branch-tracker state machine. It is NOT wired into
``parse_nimble`` this slice — the existing ``TestWhenBlockPolicy`` tests remain
green (warning still fires as today; S3b wires the scanner).

Coverage (grouped by TDD cycle):
  C1 — simple when (single branch, single/multi require)
  C2 — elif/else negation algebra
  C3 — single-line colon form
  C4 — poison (unrecognized condition)
  C5 — nested when → UNRECOGNIZED
  C6 — requires outside any when (omitted)
  C7 — nim range (recognized multi-pred, no negation needed)
  C8 — elif after multi-pred when → poison
  C9 — else after single when → negation
  C10 — when with no requires → omitted
  C11 — comments stripped on header and requires lines
  C12 — not defined (negated predicate)

The 13 normative cases from the RFC spec table are all pinned here.
"""

from __future__ import annotations

import pytest

from milpa.nimble import WhenBranch, parse_when_branches
from milpa.predicate import Predicate


# ---------------------------------------------------------------------------
# Helpers — shorthand constructors mirroring the RFC spec table notation
# ---------------------------------------------------------------------------


def plat(name: str, *, negated: bool = False) -> Predicate:
    return Predicate(name="platform", values=(name,), negated=negated)


def notplat(name: str) -> Predicate:
    return plat(name, negated=True)


def arch(name: str, *, negated: bool = False) -> Predicate:
    return Predicate(name="arch", values=(name,), negated=negated)


def nim(constraint: str) -> Predicate:
    return Predicate(name="nim", values=(constraint,), negated=False)


def _lines(text: str) -> list[str]:
    """Split a newline-joined string into a list of lines (no trailing newline needed)."""
    return text.split("\n")


# ---------------------------------------------------------------------------
# C1 — simple when (single branch, single/multi require)
# ---------------------------------------------------------------------------


class TestSimpleWhen:
    def test_case_1_single_require(self):
        """RFC normative case 1: when defined(linux) + one require."""
        lines = _lines("when defined(linux):\n  requires \"a\"")
        result = parse_when_branches(lines)
        assert result == [WhenBranch(predicates=(plat("linux"),), require_lines=(1,))]

    def test_case_2_multi_require(self):
        """RFC normative case 2: when defined(linux) + two requires."""
        lines = _lines(
            "when defined(linux):\n"
            "  requires \"a\"\n"
            "  requires \"b >= 1.0\""
        )
        result = parse_when_branches(lines)
        assert result == [WhenBranch(predicates=(plat("linux"),), require_lines=(1, 2))]

    def test_arch_predicate(self):
        """arch token resolves to arch predicate."""
        lines = _lines("when defined(amd64):\n  requires \"simdpkg\"")
        result = parse_when_branches(lines)
        assert result == [WhenBranch(predicates=(arch("amd64"),), require_lines=(1,))]


# ---------------------------------------------------------------------------
# C2 — elif/else negation algebra
# ---------------------------------------------------------------------------


class TestElifElseNegation:
    def test_case_3_when_elif_else(self):
        """RFC normative case 3: when/elif/else with negation algebra."""
        lines = _lines(
            "when defined(linux):\n"
            "  requires \"a\"\n"
            "elif defined(macosx):\n"
            "  requires \"b\"\n"
            "else:\n"
            "  requires \"c\""
        )
        result = parse_when_branches(lines)
        assert result == [
            WhenBranch(predicates=(plat("linux"),), require_lines=(1,)),
            WhenBranch(predicates=(plat("macosx"), notplat("linux")), require_lines=(3,)),
            WhenBranch(predicates=(notplat("linux"), notplat("macosx")), require_lines=(5,)),
        ]

    def test_case_10_else_after_single_when(self):
        """RFC normative case 10: when/else negation."""
        lines = _lines(
            "when defined(windows):\n"
            "  requires \"a\"\n"
            "else:\n"
            "  requires \"b\""
        )
        result = parse_when_branches(lines)
        assert result == [
            WhenBranch(predicates=(plat("windows"),), require_lines=(1,)),
            WhenBranch(predicates=(notplat("windows"),), require_lines=(3,)),
        ]

    def test_multiple_elif(self):
        """Three elif branches with accumulated negations."""
        lines = _lines(
            "when defined(linux):\n"
            "  requires \"a\"\n"
            "elif defined(macosx):\n"
            "  requires \"b\"\n"
            "elif defined(windows):\n"
            "  requires \"c\""
        )
        result = parse_when_branches(lines)
        assert result == [
            WhenBranch(predicates=(plat("linux"),), require_lines=(1,)),
            WhenBranch(
                predicates=(plat("macosx"), notplat("linux")),
                require_lines=(3,),
            ),
            WhenBranch(
                predicates=(plat("windows"), notplat("linux"), notplat("macosx")),
                require_lines=(5,),
            ),
        ]


# ---------------------------------------------------------------------------
# C3 — single-line colon form
# ---------------------------------------------------------------------------


class TestSingleLineColonForm:
    def test_case_4_single_line_colon(self):
        """RFC normative case 4: when defined(arm64): requires 'neon'."""
        lines = _lines("when defined(arm64): requires \"neon\"")
        result = parse_when_branches(lines)
        assert result == [WhenBranch(predicates=(arch("arm64"),), require_lines=(0,))]

    def test_colon_form_index_is_header_line(self):
        """Index of colon-form require is the header line, not line+1."""
        lines = _lines(
            "requires \"always\"\n"
            "when defined(linux): requires \"linuxpkg\""
        )
        result = parse_when_branches(lines)
        assert result == [WhenBranch(predicates=(plat("linux"),), require_lines=(1,))]


# ---------------------------------------------------------------------------
# C4 — poison (unrecognized condition degrades whole chain)
# ---------------------------------------------------------------------------


class TestPoison:
    def test_case_5_unrecognized_condition_poisons_chain(self):
        """RFC normative case 5: compound 'or' condition → both branches None."""
        lines = _lines(
            "when defined(linux) or defined(macosx):\n"
            "  requires \"a\"\n"
            "elif defined(windows):\n"
            "  requires \"b\""
        )
        result = parse_when_branches(lines)
        assert result == [
            WhenBranch(predicates=None, require_lines=(1,)),
            WhenBranch(predicates=None, require_lines=(3,)),
        ]

    def test_unrecognized_elif_poisons_whole_chain(self):
        """An unrecognized condition anywhere in the chain poisons all branches."""
        lines = _lines(
            "when defined(linux):\n"
            "  requires \"a\"\n"
            "elif defined(posix):\n"
            "  requires \"b\""
        )
        result = parse_when_branches(lines)
        assert result == [
            WhenBranch(predicates=None, require_lines=(1,)),
            WhenBranch(predicates=None, require_lines=(3,)),
        ]


# ---------------------------------------------------------------------------
# C5 — nested when → UNRECOGNIZED subtree
# ---------------------------------------------------------------------------


class TestNestedWhen:
    def test_case_6_nested_when(self):
        """RFC normative case 6: nested when → inner branch gets None predicates."""
        lines = _lines(
            "when defined(linux):\n"
            "  requires \"a\"\n"
            "  when defined(arm64):\n"
            "    requires \"b\""
        )
        result = parse_when_branches(lines)
        assert result == [
            WhenBranch(predicates=(plat("linux"),), require_lines=(1,)),
            WhenBranch(predicates=None, require_lines=(3,)),
        ]

    def test_nested_outer_unaffected(self):
        """Outer branch predicates are NOT poisoned by the nested when."""
        lines = _lines(
            "when defined(linux):\n"
            "  requires \"outer\"\n"
            "  when defined(arm64):\n"
            "    requires \"inner\""
        )
        result = parse_when_branches(lines)
        outer = result[0]
        inner = result[1]
        assert outer.predicates == (plat("linux"),)
        assert inner.predicates is None

    def test_deeply_nested_when_is_none(self):
        """Any depth ≥ 1 → None predicates on all branches in that subtree."""
        lines = _lines(
            "when defined(linux):\n"
            "  when defined(arm64):\n"
            "    when defined(amd64):\n"
            "      requires \"deep\""
        )
        result = parse_when_branches(lines)
        # All inner branches (at depth ≥ 1) get None
        for branch in result:
            assert branch.predicates is None


# ---------------------------------------------------------------------------
# C6 — requires outside any when (not reported)
# ---------------------------------------------------------------------------


class TestRequiresOutsideWhen:
    def test_case_7_requires_outside_when_not_reported(self):
        """RFC normative case 7: unconditional requires are not in the result."""
        lines = _lines(
            "requires \"a\"\n"
            "when defined(linux):\n"
            "  requires \"b\""
        )
        result = parse_when_branches(lines)
        assert result == [WhenBranch(predicates=(plat("linux"),), require_lines=(2,))]

    def test_only_unconditional_requires_yields_empty(self):
        """No when blocks → empty result."""
        lines = _lines("requires \"a\"\nrequires \"b\"")
        result = parse_when_branches(lines)
        assert result == []


# ---------------------------------------------------------------------------
# C7 — nim range (recognized multi-pred, no negation; no elif needed)
# ---------------------------------------------------------------------------


class TestNimRange:
    def test_case_8_two_sided_nim_range(self):
        """RFC normative case 8: two-sided nim range → multi-pred tuple."""
        lines = _lines(
            "when (NimMajor, NimMinor) >= (1, 4) and (NimMajor, NimMinor) < (2, 0):\n"
            "  requires \"a\""
        )
        result = parse_when_branches(lines)
        assert result == [
            WhenBranch(
                predicates=(nim(">=1.4.0"), nim("<2.0.0")),
                require_lines=(1,),
            )
        ]


# ---------------------------------------------------------------------------
# C8 — elif after multi-pred when → poison (can't negate multi-pred)
# ---------------------------------------------------------------------------


class TestMultiPredPoisonWithElif:
    def test_case_9_elif_after_multi_pred_when(self):
        """RFC normative case 9: multi-pred when + elif → whole chain is None."""
        lines = _lines(
            "when (NimMajor, NimMinor) >= (1, 4) and (NimMajor, NimMinor) < (2, 0):\n"
            "  requires \"a\"\n"
            "elif defined(linux):\n"
            "  requires \"b\""
        )
        result = parse_when_branches(lines)
        assert result == [
            WhenBranch(predicates=None, require_lines=(1,)),
            WhenBranch(predicates=None, require_lines=(3,)),
        ]

    def test_single_when_multi_pred_no_elif_not_poisoned(self):
        """A standalone multi-pred when (no elif/else) is NOT poisoned."""
        lines = _lines(
            "when (NimMajor, NimMinor) >= (1, 4) and (NimMajor, NimMinor) < (2, 0):\n"
            "  requires \"a\""
        )
        result = parse_when_branches(lines)
        assert result == [
            WhenBranch(
                predicates=(nim(">=1.4.0"), nim("<2.0.0")),
                require_lines=(1,),
            )
        ]


# ---------------------------------------------------------------------------
# C9 — else after single when (already covered in C2; alias for clarity)
# ---------------------------------------------------------------------------


class TestElseAfterSingleWhen:
    def test_else_negates_single_condition(self):
        """The else branch carries not(when_condition)."""
        lines = _lines(
            "when defined(freebsd):\n"
            "  requires \"bsdfoo\"\n"
            "else:\n"
            "  requires \"otherfoo\""
        )
        result = parse_when_branches(lines)
        assert result == [
            WhenBranch(predicates=(plat("freebsd"),), require_lines=(1,)),
            WhenBranch(predicates=(notplat("freebsd"),), require_lines=(3,)),
        ]


# ---------------------------------------------------------------------------
# C10 — when with no requires in body → omitted
# ---------------------------------------------------------------------------


class TestWhenWithNoRequires:
    def test_case_11_when_no_requires_omitted(self):
        """RFC normative case 11: body has no requires → branch not reported."""
        lines = _lines("when defined(linux):\n  srcDir = \"src\"")
        result = parse_when_branches(lines)
        assert result == []

    def test_when_body_has_only_non_requires_statements(self):
        """Only srcDir and comments in the when body → empty result."""
        lines = _lines(
            "when defined(linux):\n"
            "  srcDir = \"src\"  # not a dep\n"
            "  # another comment\n"
        )
        result = parse_when_branches(lines)
        assert result == []


# ---------------------------------------------------------------------------
# C11 — comments stripped on header and requires lines
# ---------------------------------------------------------------------------


class TestCommentStripping:
    def test_case_13_comments_stripped_on_header_and_requires(self):
        """RFC normative case 13: inline comments on header and requires lines."""
        lines = _lines(
            "when defined(linux):  # only linux\n"
            "  requires \"a\"  # dep"
        )
        result = parse_when_branches(lines)
        assert result == [WhenBranch(predicates=(plat("linux"),), require_lines=(1,))]

    def test_comment_only_lines_in_body_skipped(self):
        """Comment-only lines between requires in the body don't affect line indices."""
        lines = _lines(
            "when defined(linux):\n"
            "  requires \"a\"\n"
            "  # this is a comment\n"
            "  requires \"b\""
        )
        result = parse_when_branches(lines)
        assert result == [WhenBranch(predicates=(plat("linux"),), require_lines=(1, 3))]


# ---------------------------------------------------------------------------
# C12 — not defined (negated predicate)
# ---------------------------------------------------------------------------


class TestNotDefined:
    def test_case_12_not_defined(self):
        """RFC normative case 12: not defined(windows) → negated predicate."""
        lines = _lines("when not defined(windows):\n  requires \"a\"")
        result = parse_when_branches(lines)
        assert result == [WhenBranch(predicates=(notplat("windows"),), require_lines=(1,))]

    def test_not_defined_else_double_negation(self):
        """not defined(windows) + else → else gets negated-of-negated = positive."""
        lines = _lines(
            "when not defined(windows):\n"
            "  requires \"a\"\n"
            "else:\n"
            "  requires \"b\""
        )
        result = parse_when_branches(lines)
        # else: NOT(not defined(windows)) = defined(windows) → plat("windows", negated=False)
        assert result == [
            WhenBranch(predicates=(notplat("windows"),), require_lines=(1,)),
            WhenBranch(predicates=(plat("windows"),), require_lines=(3,)),
        ]


# ---------------------------------------------------------------------------
# WhenBranch dataclass properties
# ---------------------------------------------------------------------------


class TestWhenBranchDataclass:
    def test_frozen(self):
        """WhenBranch is frozen (immutable)."""
        b = WhenBranch(predicates=(plat("linux"),), require_lines=(1,))
        with pytest.raises(Exception):
            b.require_lines = (2,)  # type: ignore[misc]

    def test_equality(self):
        b1 = WhenBranch(predicates=(plat("linux"),), require_lines=(1,))
        b2 = WhenBranch(predicates=(plat("linux"),), require_lines=(1,))
        assert b1 == b2

    def test_none_predicates_equality(self):
        b1 = WhenBranch(predicates=None, require_lines=(1,))
        b2 = WhenBranch(predicates=None, require_lines=(1,))
        assert b1 == b2

    def test_none_vs_empty_predicates_differ(self):
        """None (UNRECOGNIZED) is distinct from an empty tuple (shouldn't happen
        in practice, but the dataclass distinguishes them)."""
        b1 = WhenBranch(predicates=None, require_lines=(1,))
        b2 = WhenBranch(predicates=(), require_lines=(1,))
        assert b1 != b2


# ---------------------------------------------------------------------------
# Edge cases for total function guarantee
# ---------------------------------------------------------------------------


class TestTotalFunction:
    def test_empty_lines(self):
        assert parse_when_branches([]) == []

    def test_empty_string_line(self):
        assert parse_when_branches([""]) == []

    def test_elif_with_no_matching_when_is_ignored(self):
        """A bare elif with no matching when at its indent → ignored."""
        lines = _lines("elif defined(linux):\n  requires \"a\"")
        # No when at the same indent → the elif is unattached → ignored
        result = parse_when_branches(lines)
        assert result == []

    def test_else_with_no_matching_when_is_ignored(self):
        """A bare else with no matching when → ignored."""
        lines = _lines("else:\n  requires \"a\"")
        result = parse_when_branches(lines)
        assert result == []

    def test_multiline_continuation_require_start_index_recorded(self):
        """Multi-line requires: only the STARTING line index is recorded."""
        lines = _lines(
            "when defined(linux):\n"
            "  requires \"a\",\n"
            "    \"b\"\n"
            "  requires \"c\""
        )
        result = parse_when_branches(lines)
        # Line 1 is the start of the multi-line requires
        # Line 3 is the single-line requires
        assert result == [WhenBranch(predicates=(plat("linux"),), require_lines=(1, 3))]

    def test_two_independent_when_chains(self):
        """Two independent when blocks at top level → two independent branches."""
        lines = _lines(
            "when defined(linux):\n"
            "  requires \"a\"\n"
            "when defined(macosx):\n"
            "  requires \"b\""
        )
        result = parse_when_branches(lines)
        assert result == [
            WhenBranch(predicates=(plat("linux"),), require_lines=(1,)),
            WhenBranch(predicates=(plat("macosx"),), require_lines=(3,)),
        ]
