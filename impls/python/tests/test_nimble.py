"""Tests for milpa.nimble — the ``.nimble`` line-scanner.

Coverage:
  - The four ``requires`` forms (§5.1): single-line, comma-separated,
    multi-line continuation, multiple ``requires`` statements.
  - URL-vs-named classification (§5.1 classification rule).
  - ``srcDir`` extraction (§5.2).
  - ``when``-block warning (§5.3).
  - ``nim`` requirement filtering (§5.4).
  - File I/O error codes (§5.5) — these tests now live here but call the
    workspace-layer helper (``workspace._load_nimble_file``) which raises
    ``MilpaError``, not the old ``NimbleParseError``.  ``load_nimble`` and
    ``NimbleParseError`` were deleted as part of the nimble-cleanup (9a).
  - Total-never-raises design (total-scan).
  - Property test: ``parse_nimble`` never raises on arbitrary input.
"""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from milpa.dep_decl import NamedRequire, UrlRequire
from milpa.errors import MilpaError
from milpa.manifest import NamedDep, UrlDep
from milpa.nimble import (
    NimbleManifest,
    _collect_direct_requires,
    _skip_continuation,
    parse_nimble,
)
from milpa.predicate import Predicate
from milpa.workspace import _load_nimble_file

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _names(m: NimbleManifest) -> list[str]:
    """Return dep names in order."""
    return [d.name for d in m.deps]


def _constraints(m: NimbleManifest) -> list[str | None]:
    """Return constraint strings in order."""
    result: list[str | None] = []
    for d in m.deps:
        if isinstance(d, NamedDep):
            result.append(d.constraint)
        else:
            result.append(None)
    return result


# ---------------------------------------------------------------------------
# §5.1 Form 1 — single-line ``requires``
# ---------------------------------------------------------------------------


class TestForm1SingleLine:
    def test_single_named_no_constraint(self) -> None:
        m = parse_nimble('requires "foo"')
        assert _names(m) == ["foo"]
        assert isinstance(m.deps[0], NamedDep)
        assert m.deps[0].constraint is None

    def test_single_named_with_constraint(self) -> None:
        m = parse_nimble('requires "foo >= 1.0.0"')
        assert _names(m) == ["foo"]
        assert isinstance(m.deps[0], NamedDep)
        assert m.deps[0].constraint == ">= 1.0.0"

    def test_constraint_set_is_typed(self) -> None:
        """constraint_set is pre-typed at parse boundary (§121)."""
        m = parse_nimble('requires "foo >= 2.0.0"')
        dep = m.deps[0]
        assert isinstance(dep, NamedDep)
        assert dep.constraint_set is not None
        from milpa.version import Version

        assert dep.constraint_set.contains(Version(2, 0, 0))
        assert not dep.constraint_set.contains(Version(1, 9, 9))

    def test_single_url_no_ref(self) -> None:
        url = "https://github.com/user/pkg"
        m = parse_nimble(f'requires "{url}"')
        assert len(m.deps) == 1
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.git == url
        assert dep.ref == "HEAD"

    def test_single_url_with_ref(self) -> None:
        url = "https://github.com/user/pkg"
        m = parse_nimble(f'requires "{url}#v1.2.3"')
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.git == url
        assert dep.ref == "v1.2.3"

    def test_url_name_derived_from_path(self) -> None:
        m = parse_nimble('requires "https://github.com/user/mylib.git"')
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.name == "mylib"

    def test_url_name_no_git_suffix(self) -> None:
        m = parse_nimble('requires "https://github.com/user/mylib"')
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.name == "mylib"

    def test_ssh_url_scheme(self) -> None:
        url = "ssh://git@github.com/user/pkg"
        m = parse_nimble(f'requires "{url}"')
        assert isinstance(m.deps[0], UrlDep)

    def test_git_url_scheme(self) -> None:
        url = "git://github.com/user/repo.git"
        m = parse_nimble(f'requires "{url}"')
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.name == "repo"

    def test_file_url_scheme(self) -> None:
        url = "file:///home/user/mylibrary"
        m = parse_nimble(f'requires "{url}"')
        assert isinstance(m.deps[0], UrlDep)


# ---------------------------------------------------------------------------
# §5.1 Form 2 — comma-separated ``requires``
# ---------------------------------------------------------------------------


class TestForm2CommaSeparated:
    def test_two_on_one_line(self) -> None:
        m = parse_nimble('requires "foo", "bar"')
        assert _names(m) == ["foo", "bar"]
        assert all(isinstance(d, NamedDep) for d in m.deps)

    def test_three_on_one_line(self) -> None:
        m = parse_nimble('requires "a", "b", "c"')
        assert _names(m) == ["a", "b", "c"]

    def test_comma_separated_with_constraints(self) -> None:
        m = parse_nimble('requires "foo >= 1.0.0", "bar < 2.0.0"')
        assert _names(m) == ["foo", "bar"]
        assert m.deps[0].constraint == ">= 1.0.0"  # type: ignore[union-attr]
        assert m.deps[1].constraint == "< 2.0.0"   # type: ignore[union-attr]

    def test_mixed_named_and_url(self) -> None:
        m = parse_nimble('requires "foo", "https://github.com/user/pkg"')
        assert isinstance(m.deps[0], NamedDep)
        assert isinstance(m.deps[1], UrlDep)


# ---------------------------------------------------------------------------
# §5.1 Form 3 — multi-line continuation
# ---------------------------------------------------------------------------


class TestForm3MultiLineContinuation:
    def test_two_line_continuation(self) -> None:
        text = 'requires "foo >= 1.0.0",\n  "bar"\n'
        m = parse_nimble(text)
        assert _names(m) == ["foo", "bar"]

    def test_three_line_continuation(self) -> None:
        text = 'requires "a",\n  "b",\n  "c"\n'
        m = parse_nimble(text)
        assert _names(m) == ["a", "b", "c"]

    def test_continuation_stops_at_no_trailing_comma(self) -> None:
        text = 'requires "a",\n  "b"\nrequires "c"\n'
        m = parse_nimble(text)
        # "a", "b" from first requires; "c" from second
        assert _names(m) == ["a", "b", "c"]

    def test_continuation_with_inline_comment_on_continuation_line(self) -> None:
        text = 'requires "foo",\n  "bar" # some comment\n'
        m = parse_nimble(text)
        assert _names(m) == ["foo", "bar"]


# ---------------------------------------------------------------------------
# §5.1 Form 4 — multiple ``requires`` statements
# ---------------------------------------------------------------------------


class TestForm4MultipleRequires:
    def test_two_separate_requires(self) -> None:
        text = 'requires "foo"\nrequires "bar"\n'
        m = parse_nimble(text)
        assert _names(m) == ["foo", "bar"]

    def test_multiple_requires_interspersed_with_other_lines(self) -> None:
        text = (
            'version = "1.0"\n'
            'requires "a"\n'
            'author = "Me"\n'
            'requires "b"\n'
        )
        m = parse_nimble(text)
        assert _names(m) == ["a", "b"]

    def test_empty_text(self) -> None:
        m = parse_nimble("")
        assert m.deps == ()
        assert m.src_dir is None


# ---------------------------------------------------------------------------
# §5.2 srcDir extraction
# ---------------------------------------------------------------------------


class TestSrcDir:
    def test_srcdir_quoted(self) -> None:
        m = parse_nimble('srcDir = "src"')
        assert m.src_dir == "src"

    def test_srcdir_unquoted(self) -> None:
        m = parse_nimble("srcDir = src")
        assert m.src_dir == "src"

    def test_srcdir_with_tabs(self) -> None:
        m = parse_nimble('\tsrcDir\t=\t"lib"')
        assert m.src_dir == "lib"

    def test_srcdir_last_assignment_wins(self) -> None:
        """When srcDir appears twice, the LAST value wins (NimScript assignment semantics).

        Spec §7.3: "Only the last srcDir assignment is used (NimScript assignment
        semantics: a later assignment overwrites an earlier one)."
        Rust already implements last-wins; Python must match.
        """
        m = parse_nimble('srcDir = "first"\nsrcDir = "second"\n')
        assert m.src_dir == "second"

    def test_no_srcdir_is_none(self) -> None:
        m = parse_nimble('requires "foo"\n')
        assert m.src_dir is None


# ---------------------------------------------------------------------------
# §5.3 ``when``-block policy
# ---------------------------------------------------------------------------


def _plat(name: str) -> Predicate:
    return Predicate(name="platform", values=(name,))


def _notplat(name: str) -> Predicate:
    return Predicate(name="platform", values=(name,), negated=True)


def _arch(name: str) -> Predicate:
    return Predicate(name="arch", values=(name,))


def _preds(m: NimbleManifest, dep_name: str) -> tuple[Predicate, ...]:
    """Return dep_predicates for the first dep with the given name."""
    for i, dep in enumerate(m.deps):
        if dep.name == dep_name:
            if i < len(m.dep_predicates):
                return m.dep_predicates[i]
            return ()
    raise KeyError(dep_name)


class TestWhenBlockPolicy:
    # --- original tests (warning-flip updated) ---

    def test_when_block_emits_user_warning(self) -> None:
        """UNRECOGNIZED when (compound/release) still fires the warning."""
        text = (
            'when defined(release):\n'
            '  requires "relpkg"\n'
            'requires "common"\n'
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            parse_nimble(text)
        assert any(issubclass(w.category, UserWarning) for w in caught)
        warn_msgs = [str(w.message) for w in caught if issubclass(w.category, UserWarning)]
        assert any("when" in msg for msg in warn_msgs)

    def test_when_block_includes_all_requires_unconditionally(self) -> None:
        """All requires inside and outside when are included (dep SET unchanged)."""
        text = (
            'requires "always"\n'
            'when defined(windows):\n'
            '  requires "winpkg"\n'
        )
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            m = parse_nimble(text)
        names = _names(m)
        assert "always" in names
        assert "winpkg" in names

    def test_no_when_block_no_warning(self) -> None:
        text = 'requires "foo"\n'
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            parse_nimble(text)
        user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
        assert len(user_warnings) == 0

    def test_when_keyword_mid_line_does_not_trigger(self) -> None:
        """``when`` only triggers on lines where it is the first non-ws token."""
        text = 'requires "whenpkg"\n'
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            m = parse_nimble(text)
        user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
        assert len(user_warnings) == 0
        assert _names(m) == ["whenpkg"]

    # --- S3b: new warning-flip + predicate tests ---

    def test_recognized_when_block_no_warning(self) -> None:
        """Recognized when (linux) → NO warning."""
        text = 'when defined(linux):\n  requires "x"\n'
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            parse_nimble(text)
        user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
        assert len(user_warnings) == 0

    # T1: colon form recognized
    def test_t1_colon_form_recognized(self) -> None:
        """when defined(arm64): requires "neon" → dep present; no warning; preds=(arch(arm64),)."""
        text = 'when defined(arm64): requires "neon"\n'
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            m = parse_nimble(text)
        assert "neon" in _names(m)
        user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
        assert len(user_warnings) == 0
        assert _preds(m, "neon") == (_arch("arm64"),)

    # T2: block recognized
    def test_t2_block_recognized(self) -> None:
        """when defined(linux): block → linuxpkg preds=(plat(linux),); common preds=()."""
        text = (
            'when defined(linux):\n'
            '  requires "linuxpkg"\n'
            'requires "common"\n'
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            m = parse_nimble(text)
        assert "linuxpkg" in _names(m)
        assert "common" in _names(m)
        user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
        assert len(user_warnings) == 0
        assert _preds(m, "linuxpkg") == (_plat("linux"),)
        assert _preds(m, "common") == ()

    # T3: unrecognized → dep present, WARNING fires, preds=()
    def test_t3_unrecognized_warns_and_includes(self) -> None:
        """when defined(release) → dep present; WARNING; preds=()."""
        text = 'when defined(release):\n  requires "relpkg"\n'
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            m = parse_nimble(text)
        assert "relpkg" in _names(m)
        user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
        assert len(user_warnings) == 1
        assert _preds(m, "relpkg") == ()

    # T4: poisoned chain (or compound) → dep present, WARNING, preds=()
    def test_t4_poisoned_chain(self) -> None:
        """when defined(linux) or defined(macosx) → dep present; WARNING; preds=()."""
        text = 'when defined(linux) or defined(macosx):\n  requires "a"\n'
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            m = parse_nimble(text)
        assert "a" in _names(m)
        user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
        assert len(user_warnings) == 1
        assert _preds(m, "a") == ()

    # T5: elif/else propagation
    def test_t5_elif_else_predicates(self) -> None:
        """Full when/elif/else chain propagates predicates correctly; no warning."""
        text = (
            'when defined(linux):\n'
            '  requires "a"\n'
            'elif defined(macosx):\n'
            '  requires "b"\n'
            'else:\n'
            '  requires "c"\n'
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            m = parse_nimble(text)
        user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
        assert len(user_warnings) == 0
        assert _preds(m, "a") == (_plat("linux"),)
        assert _preds(m, "b") == (_plat("macosx"), _notplat("linux"))
        assert _preds(m, "c") == (_notplat("linux"), _notplat("macosx"))

    # T6: no when → no warning, preds=()
    def test_t6_no_when_no_preds(self) -> None:
        """Unconditional requires → preds=()."""
        text = 'requires "foo"\n'
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            m = parse_nimble(text)
        user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
        assert len(user_warnings) == 0
        assert _preds(m, "foo") == ()

    # T7: same dep in two when branches — spec §7.1 no-dedup rule (C1 fix)
    def test_t7_same_dep_two_branches_both_included(self) -> None:
        """Same dep name in two independent when blocks → both entries present.

        Spec §7.1: 'no deduplication is performed'.  The scanner MUST include
        'foo' twice — once with platform=linux, once with platform=macosx.
        Python dedup (seen_named set) was silently dropping the second entry.
        """
        text = (
            'when defined(linux):\n'
            '  requires "foo"\n'
            'when defined(macosx):\n'
            '  requires "foo"\n'
        )
        m = parse_nimble(text)
        # Both entries must be present (no dedup)
        assert len(m.deps) == 2
        assert m.deps[0].name == "foo"
        assert m.deps[1].name == "foo"
        assert len(m.dep_predicates) == 2
        # First entry: linux predicate; second: macosx predicate
        assert m.dep_predicates[0] == (_plat("linux"),)
        assert m.dep_predicates[1] == (_plat("macosx"),)

    def test_t8_mixed_conditional_unconditional_alignment(self) -> None:
        """Mixed conditional + unconditional; dep_predicates stays index-aligned.

        Exercises the coverage agent's case:
          requires "common1"
          when defined(linux):  requires "x"
          requires "common2"
          when defined(macosx): requires "y"
        Each dep must get the right predicate set.
        """
        text = (
            'requires "common1"\n'
            'when defined(linux):\n'
            '  requires "x"\n'
            'requires "common2"\n'
            'when defined(macosx):\n'
            '  requires "y"\n'
        )
        m = parse_nimble(text)
        names = _names(m)
        assert names == ["common1", "x", "common2", "y"]
        assert _preds(m, "common1") == ()
        assert _preds(m, "x") == (_plat("linux"),)
        assert _preds(m, "common2") == ()
        assert _preds(m, "y") == (_plat("macosx"),)

    def test_t9_same_url_dep_two_branches_both_included(self) -> None:
        """Same URL dep in two when branches → both entries present (no URL dedup).

        Spec §7.1 applies to URL deps as well.
        """
        url = "https://github.com/example/foo.git"
        text = (
            f'when defined(linux):\n'
            f'  requires "{url}#v1"\n'
            f'when defined(macosx):\n'
            f'  requires "{url}#v1"\n'
        )
        m = parse_nimble(text)
        assert len(m.deps) == 2
        assert all(isinstance(d, UrlDep) for d in m.deps)
        assert m.dep_predicates[0] == (_plat("linux"),)
        assert m.dep_predicates[1] == (_plat("macosx"),)


# ---------------------------------------------------------------------------
# §5.4 ``nim`` requirement filtering
# ---------------------------------------------------------------------------


class TestNimFiltering:
    def test_nim_requirement_dropped(self) -> None:
        m = parse_nimble('requires "nim >= 1.6.0"')
        assert m.deps == ()

    def test_nim_alongside_others(self) -> None:
        m = parse_nimble('requires "nim >= 1.6.0", "foo >= 1.0.0"')
        assert _names(m) == ["foo"]

    def test_nim_in_multiple_requires(self) -> None:
        text = 'requires "nim"\nrequires "bar"\n'
        m = parse_nimble(text)
        assert _names(m) == ["bar"]


# ---------------------------------------------------------------------------
# §5.5 / file-I/O errors
# ---------------------------------------------------------------------------


class TestFileIOErrors:
    def test_load_nimble_file_not_found(self, tmp_path: Path) -> None:
        """_load_nimble_file raises MilpaError(NIMBLE-FILE-NOT-FOUND) (9a cleanup)."""
        missing = tmp_path / "nonexistent.nimble"
        with pytest.raises(MilpaError) as exc_info:
            _load_nimble_file(missing)
        assert exc_info.value.slug == "NIMBLE-FILE-NOT-FOUND"
        assert str(missing) in exc_info.value.message

    def test_load_nimble_file_success(self, tmp_path: Path) -> None:
        """_load_nimble_file returns text; parse_nimble handles the content."""
        f = tmp_path / "pkg.nimble"
        f.write_text('requires "foo"\nsrcDir = "src"\n', encoding="utf-8")
        text = _load_nimble_file(f)
        m = parse_nimble(text, src_path=f)
        assert _names(m) == ["foo"]
        assert m.src_dir == "src"


# ---------------------------------------------------------------------------
# Total-never-raises: miscellaneous edge cases
# ---------------------------------------------------------------------------


class TestTotalNeverRaises:
    def test_empty_requires(self) -> None:
        m = parse_nimble("requires\n")
        assert m.deps == ()

    def test_unparseable_constraint_preserved_with_none_set(self) -> None:
        """A garbled constraint → dep preserved with constraint_set=None (total-scan).

        The scanner does NOT drop the dep; it preserves the raw constraint
        string so the EdgeSource layer can escalate (NimbleEdgeSource raises
        MAN-NIMBLE-CONSTRAINT) or widen (MilpaKdl/DepDecl → VersionSet.full()).
        """
        from milpa.manifest import NamedDep
        m = parse_nimble('requires "foo NOTANOP version"')
        assert len(m.deps) == 1
        dep = m.deps[0]
        assert isinstance(dep, NamedDep)
        assert dep.name == "foo"
        assert dep.constraint == "NOTANOP version"
        assert dep.constraint_set is None

    def test_unquoted_line_not_confused_with_requires(self) -> None:
        m = parse_nimble("requiresAnonymous = true\n")
        assert m.deps == ()

    def test_comment_only_file(self) -> None:
        m = parse_nimble("# This is a comment\n# Another comment\n")
        assert m.deps == ()
        assert m.src_dir is None

    def test_requires_with_comment(self) -> None:
        m = parse_nimble('requires "foo" # this is a comment\n')
        assert _names(m) == ["foo"]

    def test_no_deduplication_both_occurrences_preserved(self) -> None:
        """Spec §7.1: no deduplication — same name in two requires → both kept.

        Each occurrence is preserved in authored file order, carrying its own
        constraint and predicate annotation.  The old 'first-wins' dedup was
        a spec violation (C1 bug fix).
        """
        text = 'requires "foo >= 1.0.0"\nrequires "foo >= 2.0.0"\n'
        m = parse_nimble(text)
        names = _names(m)
        assert names.count("foo") == 2
        assert isinstance(m.deps[0], NamedDep)
        assert m.deps[0].constraint == ">= 1.0.0"
        assert isinstance(m.deps[1], NamedDep)
        assert m.deps[1].constraint == ">= 2.0.0"

    def test_whitespace_only_spec_ignored(self) -> None:
        m = parse_nimble('requires "  "\n')
        # Empty-or-whitespace-only spec after strip → dep name is blank → dropped
        assert m.deps == ()

    def test_url_with_no_path_component(self) -> None:
        """Edge case: URL with only scheme+host; name fallback to full URL."""
        m = parse_nimble('requires "https://github.com"')
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.name == "github.com"

    def test_realistic_nimble_file(self) -> None:
        """Integration: a realistic-looking ``.nimble`` file."""
        text = """\
# Package

version       = "1.0.0"
author        = "Some Author"
description   = "A library"
license       = "MIT"
srcDir        = "src"

# Dependencies

requires "nim >= 1.6.0"
requires "chronos >= 3.0.0", "results >= 0.15.0"
requires "https://github.com/user/mylib.git#v1.0"
"""
        m = parse_nimble(text)
        assert m.src_dir == "src"
        names = _names(m)
        # "nim" is dropped; rest are included
        assert "nim" not in names
        assert "chronos" in names
        assert "results" in names
        assert "mylib" in names
        # Verify url dep has correct ref
        url_deps = [d for d in m.deps if isinstance(d, UrlDep)]
        assert len(url_deps) == 1
        assert url_deps[0].ref == "v1.0"


# ---------------------------------------------------------------------------
# M2: depth-DoS regression — deeply-nested when blocks must complete fast
# ---------------------------------------------------------------------------


def test_deep_when_nesting_completes_fast() -> None:
    """Depth-400 nested when blocks complete in well under 1 second.

    Without the depth guard, depth-300 ≈ 2.2 s, depth-500 ≈ 18.6 s (O(n³)).
    With the guard (bail-out at MAX_DEPTH, linear scan below), depth-400 < 0.1 s.

    The inner ``requires "inner"`` must still appear in the output (over-include
    rule: all requires are recorded, predicates are None for deep nesting).
    """
    import time

    DEPTH = 400
    # Build: when defined(linux):\n  when defined(linux):\n    ... requires "inner"
    lines = []
    for d in range(DEPTH):
        lines.append("  " * d + "when defined(linux):")
    lines.append("  " * DEPTH + 'requires "inner"')
    text = "\n".join(lines)

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        t0 = time.monotonic()
        m = parse_nimble(text)
        elapsed = time.monotonic() - t0

    assert elapsed < 1.0, f"depth-{DEPTH} took {elapsed:.2f}s — O(n³) regression"
    # Over-include: "inner" must still be in the dep set
    assert "inner" in _names(m), "inner requires must survive the depth guard"
    # Deep nesting → predicates must be None/empty (unrecognized / over-include)
    inner_idx = _names(m).index("inner")
    assert m.dep_predicates[inner_idx] == (), \
        "deeply-nested dep must have empty predicates (over-include annotation)"


# ---------------------------------------------------------------------------
# _skip_continuation — unit tests for the shared continuation helper
# ---------------------------------------------------------------------------


class TestSkipContinuation:
    """_skip_continuation is the single source of truth for multi-line requires.

    Both ``_linear_scan_requires`` (depth-guard fallback) and
    ``_collect_direct_requires`` (per-branch collector) delegate to it.
    These tests verify the shared helper directly AND via both call sites
    so that any future drift is caught immediately.
    """

    def test_no_continuation_returns_same_index(self) -> None:
        """A line with no trailing comma: helper returns the same index."""
        lines = ['requires "a"']
        assert _skip_continuation(lines, 0, len(lines), lines[0]) == 0

    def test_single_continuation_advances_index(self) -> None:
        """One trailing comma: helper advances to index 1."""
        lines = ['requires "a",', '  "b"']
        result = _skip_continuation(lines, 0, len(lines), lines[0])
        assert result == 1

    def test_two_continuations_advance_to_index_2(self) -> None:
        """Two trailing commas: helper advances to index 2."""
        lines = ['requires "a",', '  "b",', '  "c"']
        result = _skip_continuation(lines, 0, len(lines), lines[0])
        assert result == 2

    def test_continuation_clamps_at_end(self) -> None:
        """Trailing comma on the last line: helper clamps at end, does not raise."""
        lines = ['requires "a",']
        result = _skip_continuation(lines, 0, len(lines), lines[0])
        assert result >= len(lines) - 1  # did not go negative or raise

    def test_via_linear_scan_when_body_multi_line(self) -> None:
        """_skip_continuation path via _linear_scan_requires (depth-guard fallback).

        A deeply-nested ``requires "a", "b"`` continuation inside a ``when``
        body must collect "a" as the start-line AND skip the continuation so
        that "b" (on the continuation line) does NOT create a spurious
        second require entry.

        The result set must be the same as a shallow (non-deep) block: both
        "a" and "b" are in the dep set, appearing exactly once each (they are
        on the same logical requires statement; only the start line is recorded
        per ``_collect_direct_requires`` / ``_linear_scan_requires`` contract).
        """
        DEPTH = 400  # forces depth guard → _linear_scan_requires path
        lines = []
        for d in range(DEPTH):
            lines.append("  " * d + "when defined(linux):")
        # Multi-line continuation at the innermost level
        lines.append("  " * DEPTH + 'requires "a",')
        lines.append("  " * DEPTH + '  "b"')
        text = "\n".join(lines)

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            m = parse_nimble(text)

        names = _names(m)
        assert "a" in names, "continuation start dep must be present"
        assert "b" in names, "continuation dep must be present"
        # "b" is on the continuation line — parse_nimble collects it via
        # the outer _QUOTED_RE scan in parse_nimble itself (the start line
        # recorded by _linear_scan_requires spans both "a" and "b").
        # Verify no duplicate entries for a/b via the branch tracker.
        assert names.count("a") == 1
        assert names.count("b") == 1

    def test_via_collect_direct_requires_when_body_multi_line(self) -> None:
        """_skip_continuation path via _collect_direct_requires (shallow when body).

        A shallow ``when defined(linux):`` block containing a multi-line
        ``requires "a", \\n "b"`` continuation must yield the same result
        as if written on a single line.  The start line is recorded once;
        the continuation line is skipped by _skip_continuation so it is not
        re-examined as a new requires statement.
        """
        text = (
            'when defined(linux):\n'
            '  requires "a",\n'
            '    "b"\n'
            'requires "c"\n'
        )
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            m = parse_nimble(text)

        names = _names(m)
        assert "a" in names
        assert "b" in names
        assert "c" in names
        assert names.count("a") == 1
        assert names.count("b") == 1


# ---------------------------------------------------------------------------
# Property test: parse_nimble never raises on arbitrary input
# ---------------------------------------------------------------------------


@given(st.text())
@settings(max_examples=500)
def test_parse_nimble_never_raises(text: str) -> None:
    """Total-scan property: ``parse_nimble`` never raises for any input text.

    Mirrors the Rust reference's total-scan design: a ``.nimble`` file can
    never be a "parse error"; we extract what we can and ignore the rest.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = parse_nimble(text)
    assert isinstance(result, NimbleManifest)
    assert isinstance(result.deps, tuple)
    assert result.src_dir is None or isinstance(result.src_dir, str)


@given(st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "Z"),
        whitelist_characters='"=_-./:#\n ',
    )
))
@settings(max_examples=300)
def test_parse_nimble_never_raises_printable(text: str) -> None:
    """Variant with a printable-heavy alphabet typical of real ``.nimble`` files."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = parse_nimble(text)
    assert isinstance(result, NimbleManifest)


@given(
    deps=st.lists(
        st.one_of(
            # Named dep with optional constraint
            st.builds(
                lambda name, op, major, minor, patch: (
                    f'requires "{name} {op} {major}.{minor}.{patch}"'
                    if op
                    else f'requires "{name}"'
                ),
                name=st.text(
                    alphabet="abcdefghijklmnopqrstuvwxyz_-",
                    min_size=1,
                    max_size=15,
                ).filter(lambda s: s.strip()),
                op=st.sampled_from([">=", "<=", "==", ">", "<", ""]),
                major=st.integers(0, 9),
                minor=st.integers(0, 9),
                patch=st.integers(0, 9),
            ),
            # URL dep
            st.builds(
                lambda repo, ref: (
                    f'requires "https://github.com/user/{repo}.git#{ref}"'
                    if ref
                    else f'requires "https://github.com/user/{repo}.git"'
                ),
                repo=st.text(
                    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-",
                    min_size=1,
                    max_size=20,
                ).filter(lambda s: s.strip()),
                ref=st.one_of(st.just(""), st.text(
                    alphabet="abcdefghijklmnopqrstuvwxyz0123456789._-",
                    min_size=1,
                    max_size=15,
                )),
            ),
        ),
        min_size=0,
        max_size=10,
    ),
    src_dir=st.one_of(
        st.just(None),
        st.text(
            alphabet="abcdefghijklmnopqrstuvwxyz/._-",
            min_size=1,
            max_size=20,
        ),
    ),
)
@settings(max_examples=200)
def test_parse_nimble_roundtrip_structure(
    deps: list[str],
    src_dir: str | None,
) -> None:
    """Structural property: generated ``.nimble`` snippets produce well-typed output.

    For each generated requires line:
    - Every dep in the output is a UrlDep or NamedDep.
    - NamedDep.constraint_set is None iff constraint is None.
    - NamedDep.constraint_set is non-None when constraint is non-None.
    - No dep named "nim" survives.
    - URL deps have a non-empty ``git`` and ``ref``.
    """
    lines = list(deps)
    if src_dir is not None:
        lines.append(f'srcDir = "{src_dir}"')
    text = "\n".join(lines)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        m = parse_nimble(text)

    assert isinstance(m, NimbleManifest)
    for dep in m.deps:
        if isinstance(dep, NamedDep):
            assert dep.name != "nim"
            if dep.constraint is None:
                assert dep.constraint_set is None
            else:
                assert dep.constraint_set is not None
        else:
            assert isinstance(dep, UrlDep)
            assert dep.git
            assert dep.ref

    if src_dir is not None and lines.count(f'srcDir = "{src_dir}"') == 1 and sum(
        1 for ln in lines if "srcDir" in ln
    ) == 1:
        assert m.src_dir == src_dir
