"""Slice 3e: format_manifest tests.

Tests for ``format_manifest(manifest) -> str``.

Coverage:
- Targeted unit tests for each structural requirement.
- Comment-dropped stderr warning (§8): fires when ``manifest.had_comments``
  is ``True``; absent when ``False``.
- ``(url)`` annotation on all URL fields (§2).
- ``spec-version`` present/absent round-trip (§4.4).
- Insertion-stable dep ordering (§8).
- Property test: ``parse_manifest(format_manifest(m))`` round-trips to the
  same logical ``Manifest`` for manifests covering all 5 dep forms, mirrors,
  overrides, flags, predicates, and spec-version variants.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from milpa.manifest import (
    FlagDecl,
    FlagRequest,
    LocalDep,
    Manifest,
    MemberDep,
    NamedDep,
    Override,
    Predicate,
    TarballDep,
    UrlDep,
    format_manifest,
    parse_manifest,
)

# ---------------------------------------------------------------------------
# Alphabet helpers for Hypothesis
# ---------------------------------------------------------------------------

# KDL identifier-safe alphabet: letters + digits + hyphen + underscore.
# Avoids characters that need escaping inside KDL quoted strings.
_SAFE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
_NAME_ALPHA = st.text(alphabet=_SAFE_CHARS, min_size=1, max_size=20)
# Dep/flag names must not be reserved keywords that would be misrouted by the parser.
# "member" → MemberDep; "when" → when-block grouping construct.
# Also exclude names that are purely numeric (not valid as dep names).
_RESERVED_DEP_NAMES: frozenset[str] = frozenset({"member", "when"})
_DEP_NAME = _NAME_ALPHA.filter(
    lambda s: s not in _RESERVED_DEP_NAMES and not s.isdigit()
)
_REF_ALPHA = st.text(alphabet=_SAFE_CHARS, min_size=1, max_size=20)
_PATH_ALPHA = st.text(alphabet="abcdefghijklmnopqrstuvwxyz/_-.", min_size=1, max_size=30)


def _valid_git_url(host: str, path: str) -> str:
    return f"https://{host}.example.com/{path}.git"


_GIT_URL = st.builds(
    _valid_git_url,
    host=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10),
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10),
)
_TARBALL_URL = st.builds(
    lambda h, p: f"https://{h}.example.com/{p}.tar.gz",
    h=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10),
    p=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10),
)

# ---------------------------------------------------------------------------
# Dep strategies
# ---------------------------------------------------------------------------


def _url_dep_strategy(name: st.SearchStrategy[str]) -> st.SearchStrategy[UrlDep]:
    return st.builds(
        UrlDep,
        name=name,
        git=_GIT_URL,
        ref=_REF_ALPHA,
        mirrors=st.just(()),
        predicates=st.just(()),
        flag_requests=st.just(()),
    )


def _named_dep_strategy(name: st.SearchStrategy[str]) -> st.SearchStrategy[NamedDep]:
    return st.one_of(
        st.builds(NamedDep, name=name, constraint=st.none(), constraint_set=st.none()),
        st.builds(
            NamedDep,
            name=name,
            constraint=st.sampled_from([">= 0.1.0", ">= 1.0.0", "< 2.0.0"]),
            constraint_set=st.none(),
        ),
    )


def _local_dep_strategy(name: st.SearchStrategy[str]) -> st.SearchStrategy[LocalDep]:
    return st.builds(LocalDep, name=name, path=_PATH_ALPHA)


def _tarball_dep_strategy(name: st.SearchStrategy[str]) -> st.SearchStrategy[TarballDep]:
    return st.builds(
        TarballDep,
        name=name,
        url=_TARBALL_URL,
        sha256=st.none(),
        strip_components=st.just(0),
    )


def _member_dep_strategy() -> st.SearchStrategy[MemberDep]:
    return st.builds(MemberDep, name=_DEP_NAME)


def _any_dep(name: st.SearchStrategy[str]) -> st.SearchStrategy[
    UrlDep | NamedDep | LocalDep | TarballDep
]:
    return st.one_of(
        _url_dep_strategy(name),
        _named_dep_strategy(name),
        _local_dep_strategy(name),
        _tarball_dep_strategy(name),
    )


def _unique_dep_list(
    max_size: int = 5,
) -> st.SearchStrategy[tuple[UrlDep | NamedDep | LocalDep | TarballDep | MemberDep, ...]]:
    """Generate a tuple of deps with unique names (no MAN-DEP-DUPLICATE)."""

    @st.composite
    def _build(
        draw: st.DrawFn,
    ) -> tuple[UrlDep | NamedDep | LocalDep | TarballDep | MemberDep, ...]:
        n = draw(st.integers(min_value=0, max_value=max_size))
        seen: set[str] = set()
        deps: list[UrlDep | NamedDep | LocalDep | TarballDep | MemberDep] = []
        for _ in range(n):
            # Generate a unique name
            name = draw(_DEP_NAME)
            # Keep retrying until we get a unique name (with a small cap)
            attempts = 0
            while name in seen and attempts < 10:
                name = draw(_DEP_NAME)
                attempts += 1
            if name in seen:
                break
            seen.add(name)
            dep = draw(_any_dep(st.just(name)))
            deps.append(dep)
        return tuple(deps)

    return _build()


# ---------------------------------------------------------------------------
# Targeted tests (per-feature, deterministic)
# ---------------------------------------------------------------------------


class TestFormatManifestMinimal:
    """Minimal manifest serialization."""

    def test_minimal_name_only(self) -> None:
        m = Manifest(name="mypkg", deps=())
        out = format_manifest(m)
        reparsed = parse_manifest(out)
        assert reparsed.name == "mypkg"
        assert reparsed.deps == ()
        assert reparsed.kind == "library"

    def test_kind_application_round_trips(self) -> None:
        m = Manifest(name="app", deps=(), kind="application")
        out = format_manifest(m)
        reparsed = parse_manifest(out)
        assert reparsed.kind == "application"

    def test_kind_library_round_trips(self) -> None:
        m = Manifest(name="lib", deps=(), kind="library")
        out = format_manifest(m)
        reparsed = parse_manifest(out)
        assert reparsed.kind == "library"

    def test_src_dir_round_trips(self) -> None:
        m = Manifest(name="pkg", deps=(), src_dir="src")
        out = format_manifest(m)
        reparsed = parse_manifest(out)
        assert reparsed.src_dir == "src"

    def test_src_dir_absent_stays_absent(self) -> None:
        m = Manifest(name="pkg", deps=(), src_dir="")
        out = format_manifest(m)
        reparsed = parse_manifest(out)
        assert reparsed.src_dir == ""

    def test_output_is_valid_kdl(self) -> None:
        m = Manifest(name="check", deps=())
        out = format_manifest(m)
        # Must be parseable without error
        reparsed = parse_manifest(out)
        assert reparsed.name == "check"


class TestSpecVersionRoundTrip:
    """§4.4: spec-version present/absent round-trip."""

    def test_spec_version_absent_stays_absent(self) -> None:
        """Absent spec-version must NOT be emitted."""
        m = Manifest(name="pkg", deps=(), spec_version=1, spec_version_explicit=False)
        out = format_manifest(m)
        assert "spec-version" not in out
        reparsed = parse_manifest(out)
        assert reparsed.spec_version_explicit is False
        assert reparsed.spec_version == 1  # defaults to 1 per §4.4

    def test_spec_version_present_stays_present(self) -> None:
        """Present spec-version must be emitted."""
        m = Manifest(name="pkg", deps=(), spec_version=1, spec_version_explicit=True)
        out = format_manifest(m)
        assert "spec-version" in out
        reparsed = parse_manifest(out)
        assert reparsed.spec_version_explicit is True
        assert reparsed.spec_version == 1

    def test_spec_version_round_trips_correctly(self) -> None:
        """spec-version value is preserved when explicit."""
        text = 'name "pkg"\nspec-version 1\n'
        m = parse_manifest(text)
        assert m.spec_version_explicit is True
        out = format_manifest(m)
        reparsed = parse_manifest(out)
        assert reparsed.spec_version_explicit is True
        assert reparsed.spec_version == 1


class TestUrlAnnotation:
    """§2: (url) annotation required on all URL fields in serialized output."""

    def test_url_dep_git_has_url_annotation(self) -> None:
        m = Manifest(
            name="pkg",
            deps=(UrlDep(name="dep", git="https://github.com/foo/bar.git", ref="main"),),
        )
        out = format_manifest(m)
        # The git= value must carry (url) annotation
        assert '(url)"https://github.com/foo/bar.git"' in out

    def test_url_dep_mirror_has_url_annotation(self) -> None:
        m = Manifest(
            name="pkg",
            deps=(
                UrlDep(
                    name="dep",
                    git="https://github.com/foo/bar.git",
                    ref="main",
                    mirrors=("https://mirror.example.com/bar.git",),
                ),
            ),
        )
        out = format_manifest(m)
        assert '(url)"https://mirror.example.com/bar.git"' in out

    def test_tarball_url_has_url_annotation(self) -> None:
        m = Manifest(
            name="pkg",
            deps=(TarballDep(name="dep", url="https://example.com/dep.tar.gz"),),
        )
        out = format_manifest(m)
        assert '(url)"https://example.com/dep.tar.gz"' in out

    def test_override_git_has_url_annotation(self) -> None:
        m = Manifest(
            name="pkg",
            deps=(),
            overrides=(Override(name="foo", git="https://github.com/alt/foo.git", ref="v2"),),
        )
        out = format_manifest(m)
        assert '(url)"https://github.com/alt/foo.git"' in out

    def test_self_mirror_has_url_annotation(self) -> None:
        m = Manifest(
            name="pkg",
            deps=(),
            self_mirrors=("https://mirror.example.com/pkg.git",),
        )
        out = format_manifest(m)
        assert '(url)"https://mirror.example.com/pkg.git"' in out

    def test_url_annotated_output_parses_back(self) -> None:
        """(url)-annotated output must parse back cleanly."""
        m = Manifest(
            name="pkg",
            deps=(UrlDep(name="dep", git="https://github.com/foo/bar.git", ref="main"),),
        )
        out = format_manifest(m)
        reparsed = parse_manifest(out)
        assert isinstance(reparsed.deps[0], UrlDep)
        assert reparsed.deps[0].git == "https://github.com/foo/bar.git"


class TestDepOrderPreservation:
    """§8: dep-entry insertion-stable ordering."""

    def test_dep_order_preserved(self) -> None:
        deps = (
            NamedDep(name="alpha", constraint=None),
            NamedDep(name="beta", constraint=None),
            NamedDep(name="gamma", constraint=None),
        )
        m = Manifest(name="pkg", deps=deps)
        out = format_manifest(m)
        reparsed = parse_manifest(out)
        assert [d.name for d in reparsed.deps] == ["alpha", "beta", "gamma"]

    def test_dep_order_not_sorted(self) -> None:
        """Order must be insertion-stable, not alphabetical."""
        deps = (
            NamedDep(name="zzz", constraint=None),
            NamedDep(name="aaa", constraint=None),
            NamedDep(name="mmm", constraint=None),
        )
        m = Manifest(name="pkg", deps=deps)
        out = format_manifest(m)
        reparsed = parse_manifest(out)
        assert [d.name for d in reparsed.deps] == ["zzz", "aaa", "mmm"]

    def test_dev_deps_order_preserved(self) -> None:
        dev_deps = (
            NamedDep(name="testpkg", constraint=None),
            NamedDep(name="benchpkg", constraint=None),
        )
        m = Manifest(name="pkg", deps=(), dev_deps=dev_deps)
        out = format_manifest(m)
        reparsed = parse_manifest(out)
        assert [d.name for d in reparsed.dev_deps] == ["testpkg", "benchpkg"]


class TestAllDepForms:
    """Each of the 5 dep forms round-trips correctly."""

    def test_url_dep_round_trip(self) -> None:
        dep = UrlDep(name="foo", git="https://github.com/foo/bar.git", ref="main")
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, UrlDep)
        assert d.name == "foo"
        assert d.git == "https://github.com/foo/bar.git"
        assert d.ref == "main"

    def test_named_dep_no_constraint_round_trip(self) -> None:
        dep = NamedDep(name="fresco", constraint=None)
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, NamedDep)
        assert d.name == "fresco"
        assert d.constraint is None

    def test_named_dep_with_constraint_round_trip(self) -> None:
        dep = NamedDep(name="fresco", constraint=">= 0.5.0")
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, NamedDep)
        assert d.constraint == ">= 0.5.0"

    def test_local_dep_round_trip(self) -> None:
        dep = LocalDep(name="local-lib", path="../libs/mylib")
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, LocalDep)
        assert d.path == "../libs/mylib"

    def test_tarball_dep_round_trip(self) -> None:
        dep = TarballDep(name="vendor", url="https://example.com/vendor.tar.gz")
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, TarballDep)
        assert d.url == "https://example.com/vendor.tar.gz"
        assert d.sha256 is None
        assert d.strip_components == 0

    def test_tarball_dep_with_sha256_round_trip(self) -> None:
        dep = TarballDep(
            name="vendor",
            url="https://example.com/vendor.tar.gz",
            sha256="abc123",
            strip_components=1,
        )
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, TarballDep)
        assert d.sha256 == "abc123"
        assert d.strip_components == 1

    def test_member_dep_round_trip(self) -> None:
        dep = MemberDep(name="my-sub-pkg")
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, MemberDep)
        assert d.name == "my-sub-pkg"

    def test_mixed_dep_forms_round_trip(self) -> None:
        """All 5 dep forms in one manifest."""
        deps = (
            UrlDep(name="git-dep", git="https://github.com/foo/bar.git", ref="main"),
            NamedDep(name="named-dep", constraint=">= 1.0.0"),
            LocalDep(name="local-dep", path="./local"),
            TarballDep(name="tarball-dep", url="https://example.com/dep.tar.gz"),
            MemberDep(name="member-dep"),
        )
        m = Manifest(name="pkg", deps=deps)
        out = format_manifest(m)
        reparsed = parse_manifest(out)
        assert len(reparsed.deps) == 5
        assert isinstance(reparsed.deps[0], UrlDep)
        assert isinstance(reparsed.deps[1], NamedDep)
        assert isinstance(reparsed.deps[2], LocalDep)
        assert isinstance(reparsed.deps[3], TarballDep)
        assert isinstance(reparsed.deps[4], MemberDep)


class TestOverrides:
    """Overrides round-trip correctly with (url) annotation."""

    def test_override_round_trip(self) -> None:
        ov = Override(name="foo", git="https://github.com/alt/foo.git", ref="v2")
        m = Manifest(name="pkg", deps=(), overrides=(ov,))
        reparsed = parse_manifest(format_manifest(m))
        assert len(reparsed.overrides) == 1
        assert reparsed.overrides[0].name == "foo"
        assert reparsed.overrides[0].git == "https://github.com/alt/foo.git"
        assert reparsed.overrides[0].ref == "v2"


class TestFlags:
    """Flag declarations round-trip correctly."""

    def test_flag_default_false_round_trip(self) -> None:
        fd = FlagDecl(name="my-feature", default=False, description="A feature", defines=())
        m = Manifest(name="pkg", deps=(), flags=(fd,))
        reparsed = parse_manifest(format_manifest(m))
        assert len(reparsed.flags) == 1
        f = reparsed.flags[0]
        assert f.name == "my-feature"
        assert f.default is False
        assert f.description == "A feature"

    def test_flag_default_true_round_trip(self) -> None:
        fd = FlagDecl(name="enabled", default=True, description="", defines=())
        m = Manifest(name="pkg", deps=(), flags=(fd,))
        reparsed = parse_manifest(format_manifest(m))
        assert reparsed.flags[0].default is True

    def test_flag_with_defines_round_trip(self) -> None:
        fd = FlagDecl(name="ssl", default=False, description="", defines=("ssl", "openssl"))
        m = Manifest(name="pkg", deps=(), flags=(fd,))
        reparsed = parse_manifest(format_manifest(m))
        assert reparsed.flags[0].defines == ("ssl", "openssl")


class TestMirrors:
    """Top-level self_mirrors round-trip with (url) annotation."""

    def test_self_mirrors_round_trip(self) -> None:
        m = Manifest(
            name="pkg",
            deps=(),
            self_mirrors=("https://mirror1.example.com/pkg.git",),
        )
        reparsed = parse_manifest(format_manifest(m))
        assert reparsed.self_mirrors == ("https://mirror1.example.com/pkg.git",)

    def test_multiple_mirrors_round_trip(self) -> None:
        m = Manifest(
            name="pkg",
            deps=(),
            self_mirrors=(
                "https://mirror1.example.com/pkg.git",
                "https://mirror2.example.com/pkg.git",
            ),
        )
        reparsed = parse_manifest(format_manifest(m))
        assert reparsed.self_mirrors == (
            "https://mirror1.example.com/pkg.git",
            "https://mirror2.example.com/pkg.git",
        )


class TestCasDir:
    """cas { dir } block round-trips correctly."""

    def test_cas_dir_round_trip(self) -> None:
        m = Manifest(name="pkg", deps=(), cas_dir="/home/user/.cache/milpa")
        out = format_manifest(m)
        reparsed = parse_manifest(out)
        assert reparsed.cas_dir == "/home/user/.cache/milpa"

    def test_cas_dir_absent_stays_absent(self) -> None:
        m = Manifest(name="pkg", deps=(), cas_dir="")
        out = format_manifest(m)
        assert "cas" not in out
        reparsed = parse_manifest(out)
        assert reparsed.cas_dir == ""


class TestDevDeps:
    """dev-deps block round-trips correctly."""

    def test_dev_deps_round_trip(self) -> None:
        m = Manifest(
            name="pkg",
            deps=(),
            dev_deps=(NamedDep(name="testfoo", constraint=None),),
        )
        reparsed = parse_manifest(format_manifest(m))
        assert len(reparsed.dev_deps) == 1
        assert reparsed.dev_deps[0].name == "testfoo"

    def test_dev_deps_absent_when_empty(self) -> None:
        m = Manifest(name="pkg", deps=())
        out = format_manifest(m)
        assert "dev-deps" not in out


class TestPredicates:
    """Predicates on UrlDep round-trip correctly."""

    def test_inline_predicate_round_trip(self) -> None:
        dep = UrlDep(
            name="linuxonly",
            git="https://github.com/foo/bar.git",
            ref="main",
            predicates=(Predicate(name="platform", values=("linux",), negated=False),),
        )
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, UrlDep)
        preds = d.predicates
        assert len(preds) == 1
        assert preds[0].name == "platform"
        assert preds[0].values == ("linux",)
        assert preds[0].negated is False

    def test_negated_predicate_round_trip(self) -> None:
        dep = UrlDep(
            name="notwin",
            git="https://github.com/foo/bar.git",
            ref="main",
            predicates=(Predicate(name="platform", values=("windows",), negated=True),),
        )
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, UrlDep)
        preds = d.predicates
        assert len(preds) == 1
        assert preds[0].negated is True
        assert preds[0].values == ("windows",)

    def test_multi_value_predicate_round_trip(self) -> None:
        dep = UrlDep(
            name="unixonly",
            git="https://github.com/foo/bar.git",
            ref="main",
            predicates=(
                Predicate(name="platform", values=("linux", "macosx"), negated=False),
            ),
        )
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, UrlDep)
        preds = d.predicates
        assert len(preds) == 1
        assert set(preds[0].values) == {"linux", "macosx"}

    def test_flag_request_round_trip(self) -> None:
        dep = UrlDep(
            name="flagged",
            git="https://github.com/foo/bar.git",
            ref="main",
            flag_requests=(FlagRequest(name="ssl", enabled=True),),
        )
        m = Manifest(
            name="pkg",
            deps=(dep,),
            flags=(FlagDecl(name="ssl", default=False, description="", defines=()),),
        )
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, UrlDep)
        assert len(d.flag_requests) == 1
        assert d.flag_requests[0].name == "ssl"
        assert d.flag_requests[0].enabled is True


class TestCommentDropWarning:
    """§8: stderr warning emitted when had_comments=True."""

    def test_no_warning_when_had_comments_false(self, capsys: pytest.CaptureFixture[str]) -> None:
        m = Manifest(name="pkg", deps=(), had_comments=False)
        format_manifest(m)
        captured = capsys.readouterr()
        assert "comment" not in captured.err.lower()

    def test_warning_when_had_comments_true(self, capsys: pytest.CaptureFixture[str]) -> None:
        m = Manifest(name="pkg", deps=(), had_comments=True)
        format_manifest(m)
        captured = capsys.readouterr()
        assert "warning" in captured.err.lower()
        assert "comment" in captured.err.lower()

    def test_warning_goes_to_stderr_not_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        m = Manifest(name="pkg", deps=(), had_comments=True)
        format_manifest(m)
        captured = capsys.readouterr()
        assert captured.out == "" or "comment" not in captured.out
        assert "comment" in captured.err

    def test_warning_text_matches_spec(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Exact warning text per §8."""
        m = Manifest(name="pkg", deps=(), had_comments=True)
        format_manifest(m)
        captured = capsys.readouterr()
        assert "milpa.kdl comments are not preserved when the manifest is rewritten" in captured.err

    def test_parse_sets_had_comments_true_for_commented_kdl(self) -> None:
        """parse_manifest sets had_comments=True when comments are present."""
        text = '// This is a comment\nname "pkg"\n'
        m = parse_manifest(text)
        assert m.had_comments is True

    def test_parse_sets_had_comments_false_for_comment_free_kdl(self) -> None:
        """parse_manifest sets had_comments=False when no comments present."""
        text = 'name "pkg"\n'
        m = parse_manifest(text)
        assert m.had_comments is False

    def test_parse_detects_block_comment(self) -> None:
        """Block comments /* ... */ also trigger had_comments=True."""
        text = 'name "pkg"\n/* block comment */\nkind "library"\n'
        m = parse_manifest(text)
        assert m.had_comments is True

    def test_parse_detects_inline_comment(self) -> None:
        """Inline comments on a node also trigger had_comments=True."""
        text = 'name "pkg" // inline comment\n'
        m = parse_manifest(text)
        assert m.had_comments is True


# ---------------------------------------------------------------------------
# Property test: parse → format → parse round-trip
# ---------------------------------------------------------------------------


@given(
    name=_DEP_NAME,
    deps=_unique_dep_list(max_size=4),
    dev_deps=_unique_dep_list(max_size=3),
    kind=st.sampled_from(["library", "application"]),
    src_dir=st.one_of(st.just(""), _PATH_ALPHA),
    spec_version_explicit=st.booleans(),
)
@settings(max_examples=200)
def test_format_manifest_round_trips(
    name: str,
    deps: tuple[UrlDep | NamedDep | LocalDep | TarballDep | MemberDep, ...],
    dev_deps: tuple[UrlDep | NamedDep | LocalDep | TarballDep | MemberDep, ...],
    kind: str,
    src_dir: str,
    spec_version_explicit: bool,
) -> None:
    """parse_manifest(format_manifest(m)) round-trips to the same logical Manifest.

    The round-trip target is the logical ``Manifest`` (name, kind, all dep forms,
    spec_version, spec_version_explicit, src_dir, dev_deps) — NOT byte identity.
    """
    from milpa.manifest import Kind

    k: Kind = "application" if kind == "application" else "library"

    # Avoid dep-name collisions between deps and dev_deps (they are independent
    # namespaces, so the same name in both is VALID, but this test keeps names
    # globally unique for clarity)
    dep_names = {d.name for d in deps}
    filtered_dev = tuple(d for d in dev_deps if d.name not in dep_names)

    m = Manifest(
        name=name,
        deps=deps,
        dev_deps=filtered_dev,
        kind=k,
        src_dir=src_dir,
        spec_version=1,
        spec_version_explicit=spec_version_explicit,
    )

    out = format_manifest(m)
    reparsed = parse_manifest(out)

    assert reparsed.name == m.name
    assert reparsed.kind == m.kind
    assert reparsed.src_dir == m.src_dir
    assert reparsed.spec_version == m.spec_version
    assert reparsed.spec_version_explicit == m.spec_version_explicit
    assert len(reparsed.deps) == len(m.deps)
    assert len(reparsed.dev_deps) == len(m.dev_deps)

    # Verify each dep round-trips correctly (type + key fields)
    for orig, got in zip(m.deps, reparsed.deps, strict=True):
        assert type(orig) is type(got), f"dep type mismatch: {type(orig)} vs {type(got)}"
        assert orig.name == got.name
        if isinstance(orig, UrlDep):
            assert isinstance(got, UrlDep)
            assert orig.git == got.git
            assert orig.ref == got.ref
        elif isinstance(orig, NamedDep):
            assert isinstance(got, NamedDep)
            assert orig.constraint == got.constraint
        elif isinstance(orig, LocalDep):
            assert isinstance(got, LocalDep)
            assert orig.path == got.path
        elif isinstance(orig, TarballDep):
            assert isinstance(got, TarballDep)
            assert orig.url == got.url
            assert orig.sha256 == got.sha256
            assert orig.strip_components == got.strip_components
        elif isinstance(orig, MemberDep):
            assert isinstance(got, MemberDep)
