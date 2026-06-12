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

from milpa.errors import MilpaError
from milpa.manifest import NamedDep, UrlDep
from milpa.nimble import (
    NimbleManifest,
    parse_nimble,
)
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

    def test_srcdir_first_match_wins(self) -> None:
        """When srcDir appears twice, the first value is kept."""
        m = parse_nimble('srcDir = "first"\nsrcDir = "second"\n')
        assert m.src_dir == "first"

    def test_no_srcdir_is_none(self) -> None:
        m = parse_nimble('requires "foo"\n')
        assert m.src_dir is None


# ---------------------------------------------------------------------------
# §5.3 ``when``-block policy
# ---------------------------------------------------------------------------


class TestWhenBlockPolicy:
    def test_when_block_emits_user_warning(self) -> None:
        text = (
            'when defined(linux):\n'
            '  requires "linuxpkg"\n'
            'requires "common"\n'
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            parse_nimble(text)
        assert any(issubclass(w.category, UserWarning) for w in caught)
        warn_msgs = [str(w.message) for w in caught if issubclass(w.category, UserWarning)]
        assert any("when" in msg for msg in warn_msgs)

    def test_when_block_includes_all_requires_unconditionally(self) -> None:
        """All requires inside and outside when are included."""
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

    def test_unparseable_constraint_dropped_silently(self) -> None:
        """A garbled constraint → dep silently dropped (total-scan)."""
        m = parse_nimble('requires "foo NOTANOP version"')
        assert m.deps == ()

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

    def test_deduplication_first_wins(self) -> None:
        text = 'requires "foo >= 1.0.0"\nrequires "foo >= 2.0.0"\n'
        m = parse_nimble(text)
        names = _names(m)
        assert names.count("foo") == 1
        # First occurrence wins
        dep = m.deps[0]
        assert isinstance(dep, NamedDep)
        assert dep.constraint == ">= 1.0.0"

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
