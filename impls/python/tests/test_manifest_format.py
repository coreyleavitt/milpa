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
    GitTarget,
    LocalDep,
    LocalTarget,
    Manifest,
    MemberDep,
    MemberTarget,
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


class TestIndexTrustRoundTrip:
    """RD-M2: index-trust / index-trust-signer / index-trust-bundle must survive
    a format_manifest → parse_manifest round trip.

    Pre-fix: format_manifest never emitted these three nodes at all, so `milpa
    add`/`remove` (which rewrite milpa.kdl via format_manifest) silently reverted
    a declared `index-trust "strict"` back to the "warn" default — a fail-open,
    and a spec/manifest-grammar.md §8 semantic-round-trip violation.
    """

    def test_policy_signer_bundle_round_trip(self) -> None:
        m = Manifest(
            name="pkg",
            deps=(),
            index_trust_policy="strict",
            index_trust_policy_explicit=True,
            index_trust_signer="signer@example.com",
            index_trust_bundle="file:///tmp/bundle.json",
        )
        out = format_manifest(m)
        assert 'index-trust "strict"' in out
        assert 'index-trust-signer "signer@example.com"' in out
        assert 'index-trust-bundle "file:///tmp/bundle.json"' in out

        reparsed = parse_manifest(out)
        assert reparsed.index_trust_policy == "strict"
        assert reparsed.index_trust_policy_explicit is True
        assert reparsed.index_trust_signer == "signer@example.com"
        assert reparsed.index_trust_bundle == "file:///tmp/bundle.json"

    def test_policy_not_explicit_stays_absent(self) -> None:
        """A manifest that never declared index-trust must not gain one on format."""
        m = Manifest(name="pkg", deps=())
        out = format_manifest(m)
        assert "index-trust " not in out
        assert "index-trust\n" not in out
        reparsed = parse_manifest(out)
        assert reparsed.index_trust_policy_explicit is False
        assert reparsed.index_trust_policy == "warn"

    def test_explicit_warn_round_trips_as_explicit(self) -> None:
        """index-trust "warn" (matching the default value) must still round-trip
        as explicitly declared — the WHERE, not the value, is what matters for
        WS-INDEX-TRUST-ON-MEMBER (spec: registry-protocol.md §3.4.7)."""
        text = 'name "pkg"\nindex-trust "warn"\n'
        m = parse_manifest(text)
        assert m.index_trust_policy_explicit is True
        out = format_manifest(m)
        assert 'index-trust "warn"' in out
        reparsed = parse_manifest(out)
        assert reparsed.index_trust_policy_explicit is True
        assert reparsed.index_trust_policy == "warn"


class TestIndexHistoryRoundTrip:
    """A2c (RFC registry-append-only.md §2): index-history must survive a
    format_manifest → parse_manifest round trip.  Mirrors TestIndexTrustRoundTrip
    for the sibling axis — a declared "strict" policy must not silently revert
    to the "warn" default when `milpa add`/`remove` rewrite milpa.kdl.
    """

    def test_policy_round_trips(self) -> None:
        m = Manifest(
            name="pkg",
            deps=(),
            index_history_policy="strict",
            index_history_policy_explicit=True,
        )
        out = format_manifest(m)
        assert 'index-history "strict"' in out

        reparsed = parse_manifest(out)
        assert reparsed.index_history_policy == "strict"
        assert reparsed.index_history_policy_explicit is True

    def test_policy_not_explicit_stays_absent(self) -> None:
        """A manifest that never declared index-history must not gain one on format."""
        m = Manifest(name="pkg", deps=())
        out = format_manifest(m)
        assert "index-history " not in out
        assert "index-history\n" not in out
        reparsed = parse_manifest(out)
        assert reparsed.index_history_policy_explicit is False
        assert reparsed.index_history_policy == "warn"

    def test_explicit_warn_round_trips_as_explicit(self) -> None:
        """index-history "warn" (matching the default value) must still round-trip
        as explicitly declared — the WHERE, not the value, is what matters for
        WS-INDEX-HISTORY-ON-MEMBER (spec: registry-protocol.md §3.4.0 / §3.5.2)."""
        text = 'name "pkg"\nindex-history "warn"\n'
        m = parse_manifest(text)
        assert m.index_history_policy_explicit is True
        out = format_manifest(m)
        assert 'index-history "warn"' in out
        reparsed = parse_manifest(out)
        assert reparsed.index_history_policy_explicit is True
        assert reparsed.index_history_policy == "warn"


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
            overrides=(Override(name="foo", target=GitTarget(git="https://github.com/alt/foo.git", ref="v2")),),
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
        ov = Override(name="foo", target=GitTarget(git="https://github.com/alt/foo.git", ref="v2"))
        m = Manifest(name="pkg", deps=(), overrides=(ov,))
        reparsed = parse_manifest(format_manifest(m))
        assert len(reparsed.overrides) == 1
        assert reparsed.overrides[0].name == "foo"
        assert isinstance(reparsed.overrides[0].target, GitTarget)
        assert reparsed.overrides[0].target.git == "https://github.com/alt/foo.git"
        assert reparsed.overrides[0].target.ref == "v2"

    def test_override_local_round_trip(self) -> None:
        ov = Override(name="mylib", target=LocalTarget(path="../mylib-fork"))
        m = Manifest(name="pkg", deps=(), overrides=(ov,))
        reparsed = parse_manifest(format_manifest(m))
        assert len(reparsed.overrides) == 1
        assert reparsed.overrides[0].name == "mylib"
        assert isinstance(reparsed.overrides[0].target, LocalTarget)
        assert reparsed.overrides[0].target.path == "../mylib-fork"

    def test_override_member_round_trip(self) -> None:
        ov = Override(name="shared", target=MemberTarget(member_name="shared"))
        m = Manifest(name="pkg", deps=(), overrides=(ov,))
        reparsed = parse_manifest(format_manifest(m))
        assert len(reparsed.overrides) == 1
        assert reparsed.overrides[0].name == "shared"
        assert isinstance(reparsed.overrides[0].target, MemberTarget)
        assert reparsed.overrides[0].target.member_name == "shared"


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


class TestProvides:
    """S7 (rfc-origin-as-identity.md §4.6): top-level provides {} round-trips."""

    def test_provides_round_trip(self) -> None:
        m = Manifest(name="pkg", deps=(), provides=("foo",))
        reparsed = parse_manifest(format_manifest(m))
        assert reparsed.provides == ("foo",)

    def test_multiple_provides_round_trip(self) -> None:
        m = Manifest(name="pkg", deps=(), provides=("foo", "foo/bar"))
        reparsed = parse_manifest(format_manifest(m))
        assert reparsed.provides == ("foo", "foo/bar")

    def test_absent_provides_round_trip(self) -> None:
        m = Manifest(name="pkg", deps=())
        reparsed = parse_manifest(format_manifest(m))
        assert reparsed.provides == ()


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

    def test_enables_same_pkg_round_trips(self) -> None:
        """FlagDecl.enables_same_pkg serializes and parses back correctly (S1)."""
        from milpa.manifest import CrossPkgEnable
        m = Manifest(
            name="pkg",
            deps=(),
            flags=(
                FlagDecl(name="tls"),
                FlagDecl(name="http"),
                FlagDecl(name="full", enables_same_pkg=("tls", "http")),
            ),
        )
        text = format_manifest(m)
        assert 'enables "tls" "http"' in text
        reparsed = parse_manifest(text)
        full = next(f for f in reparsed.flags if f.name == "full")
        assert full.enables_same_pkg == ("tls", "http")
        assert full.enables_cross_pkg == ()

    def test_enables_cross_pkg_round_trips(self) -> None:
        """FlagDecl.enables_cross_pkg serializes and parses back correctly (S1)."""
        from milpa.manifest import CrossPkgEnable
        m = Manifest(
            name="pkg",
            deps=(),
            flags=(
                FlagDecl(
                    name="full",
                    enables_same_pkg=(),
                    enables_cross_pkg=(
                        CrossPkgEnable(
                            dep="chronos",
                            flag_requests=(FlagRequest(name="tls", enabled=True),),
                        ),
                    ),
                ),
            ),
        )
        text = format_manifest(m)
        assert "enables" in text
        assert "chronos" in text
        reparsed = parse_manifest(text)
        full = reparsed.flags[0]
        assert len(full.enables_cross_pkg) == 1
        cpe = full.enables_cross_pkg[0]
        assert cpe.dep == "chronos"
        assert cpe.flag_requests[0].name == "tls"

    def test_enables_mixed_round_trips(self) -> None:
        """Mixed enables (same-pkg args + cross-pkg children) canonical single-node form."""
        from milpa.manifest import CrossPkgEnable
        m = Manifest(
            name="pkg",
            deps=(),
            flags=(
                FlagDecl(name="tls"),
                FlagDecl(name="http"),
                FlagDecl(
                    name="full",
                    enables_same_pkg=("tls", "http"),
                    enables_cross_pkg=(
                        CrossPkgEnable(
                            dep="chronos",
                            flag_requests=(FlagRequest(name="tls", enabled=True),),
                        ),
                    ),
                ),
            ),
        )
        text = format_manifest(m)
        reparsed = parse_manifest(text)
        full = next(f for f in reparsed.flags if f.name == "full")
        assert full.enables_same_pkg == ("tls", "http")
        assert len(full.enables_cross_pkg) == 1
        assert full.enables_cross_pkg[0].dep == "chronos"

    def test_conflicts_round_trips(self) -> None:
        """FlagDecl.conflicts serializes and parses back correctly (S1)."""
        m = Manifest(
            name="pkg",
            deps=(),
            flags=(
                FlagDecl(name="openssl", conflicts=("bearssl",)),
                FlagDecl(name="bearssl"),
            ),
        )
        text = format_manifest(m)
        assert 'conflicts "bearssl"' in text
        reparsed = parse_manifest(text)
        openssl = next(f for f in reparsed.flags if f.name == "openssl")
        assert openssl.conflicts == ("bearssl",)

    def test_enables_and_defines_together_round_trip(self) -> None:
        """A flag with both defines and enables serializes with a block for both."""
        m = Manifest(
            name="pkg",
            deps=(),
            flags=(
                FlagDecl(name="tls"),
                FlagDecl(
                    name="full",
                    defines=("fullEnabled",),
                    enables_same_pkg=("tls",),
                ),
            ),
        )
        text = format_manifest(m)
        reparsed = parse_manifest(text)
        full = next(f for f in reparsed.flags if f.name == "full")
        assert full.defines == ("fullEnabled",)
        assert full.enables_same_pkg == ("tls",)

    def test_corpus_185_enables_accept_round_trip(self) -> None:
        """Corpus fixture 185: parse → format → parse gives the same enables/conflicts."""
        import pathlib
        conformance = pathlib.Path(__file__).parent.parent.parent.parent / "conformance"
        text = (conformance / "spec-v1/fixture-185-man-flag-enables-accept/milpa.kdl").read_text()
        m = parse_manifest(text)
        full = next(f for f in m.flags if f.name == "full")
        assert full.enables_same_pkg == ("tls", "http")
        assert len(full.enables_cross_pkg) == 1
        assert full.enables_cross_pkg[0].dep == "chronos"
        # Format and re-parse — should be identical
        m2 = parse_manifest(format_manifest(m))
        full2 = next(f for f in m2.flags if f.name == "full")
        assert full2.enables_same_pkg == full.enables_same_pkg
        assert full2.enables_cross_pkg == full.enables_cross_pkg


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


# ---------------------------------------------------------------------------
# Conditional-dep round-trip tests (§8 / #163)
# Predicates must survive format → parse for ALL 5 dep forms.
# ---------------------------------------------------------------------------


class TestConditionalDepRoundTrip:
    """§8 / #163: when-block predicates survive format → parse for all dep forms."""

    def test_named_dep_with_platform_predicate_round_trips(self) -> None:
        dep = NamedDep(
            name="mylib",
            constraint=None,
            predicates=(Predicate(name="platform", values=("linux",), negated=False),),
        )
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, NamedDep)
        assert d.name == "mylib"
        assert len(d.predicates) == 1
        assert d.predicates[0].name == "platform"
        assert d.predicates[0].values == ("linux",)
        assert d.predicates[0].negated is False

    def test_local_dep_with_platform_predicate_round_trips(self) -> None:
        dep = LocalDep(
            name="locallib",
            path="../locallib",
            predicates=(Predicate(name="platform", values=("macosx",), negated=False),),
        )
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, LocalDep)
        assert d.path == "../locallib"
        assert len(d.predicates) == 1
        assert d.predicates[0].name == "platform"
        assert d.predicates[0].values == ("macosx",)

    def test_tarball_dep_with_platform_predicate_round_trips(self) -> None:
        dep = TarballDep(
            name="tarlib",
            url="https://example.com/tarlib.tar.gz",
            predicates=(Predicate(name="platform", values=("linux",), negated=False),),
        )
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, TarballDep)
        assert d.url == "https://example.com/tarlib.tar.gz"
        assert len(d.predicates) == 1
        assert d.predicates[0].name == "platform"
        assert d.predicates[0].values == ("linux",)

    def test_member_dep_with_platform_predicate_parse_error(self) -> None:
        """S1b: MemberDep with predicates formats into a when-gated member node,
        which is a parse-time category error (MAN-MEMBER-WHEN-GATED).

        The data model allows constructing a MemberDep with predicates (for
        internal consistency), but the parser rejects any member inside a when
        block.  format_manifest still emits the when-wrapped form; round-tripping
        through the parser raises MAN-MEMBER-WHEN-GATED rather than succeeding.
        """
        from milpa.errors import MAN_MEMBER_WHEN_GATED, MilpaError

        dep = MemberDep(
            name="submember",
            predicates=(Predicate(name="platform", values=("linux",), negated=False),),
        )
        m = Manifest(name="pkg", deps=(dep,))
        formatted = format_manifest(m)
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(formatted)
        assert exc_info.value.slug == MAN_MEMBER_WHEN_GATED

    def test_negated_predicate_survives_round_trip_local_dep(self) -> None:
        dep = LocalDep(
            name="nonwin",
            path="./nonwin",
            predicates=(Predicate(name="platform", values=("windows",), negated=True),),
        )
        m = Manifest(name="pkg", deps=(dep,))
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, LocalDep)
        assert len(d.predicates) == 1
        assert d.predicates[0].negated is True
        assert d.predicates[0].values == ("windows",)

    def test_multi_predicate_named_dep_round_trips(self) -> None:
        """Multiple predicates (flag + platform) survive round-trip for NamedDep."""
        dep = NamedDep(
            name="condlib",
            constraint=">= 1.0.0",
            predicates=(
                Predicate(name="platform", values=("linux",), negated=False),
                Predicate(name="flag", values=("extras",), negated=False),
            ),
        )
        m = Manifest(
            name="pkg",
            deps=(dep,),
            flags=(FlagDecl(name="extras", default=False),),
        )
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, NamedDep)
        assert d.constraint == ">= 1.0.0"
        assert len(d.predicates) == 2
        pred_map = {p.name: p for p in d.predicates}
        assert pred_map["platform"].values == ("linux",)
        assert pred_map["flag"].values == ("extras",)

    def test_url_dep_predicates_unchanged(self) -> None:
        """UrlDep predicates continue to be emitted inline (not in when block)."""
        dep = UrlDep(
            name="gitdep",
            git="https://github.com/foo/bar.git",
            ref="main",
            predicates=(Predicate(name="platform", values=("linux",), negated=False),),
        )
        m = Manifest(name="pkg", deps=(dep,))
        out = format_manifest(m)
        # Inline form: platform="linux" on the dep node directly, NOT in a when block
        assert 'platform="linux"' in out
        assert "when" not in out
        reparsed = parse_manifest(out)
        d = reparsed.deps[0]
        assert isinstance(d, UrlDep)
        assert len(d.predicates) == 1
        assert d.predicates[0].name == "platform"

    def test_named_dep_flag_requests_with_predicates_round_trips(self) -> None:
        """NamedDep with both flag_requests and when-predicates survives round-trip."""
        dep = NamedDep(
            name="platformlib",
            constraint=None,
            flag_requests=(FlagRequest(name="ssl", enabled=True),),
            predicates=(Predicate(name="platform", values=("linux",), negated=False),),
        )
        m = Manifest(
            name="pkg",
            deps=(dep,),
            flags=(FlagDecl(name="ssl", default=False),),
        )
        reparsed = parse_manifest(format_manifest(m))
        d = reparsed.deps[0]
        assert isinstance(d, NamedDep)
        assert len(d.flag_requests) == 1
        assert d.flag_requests[0].name == "ssl"
        assert len(d.predicates) == 1
        assert d.predicates[0].name == "platform"

    def test_predicate_survives_parse_format_parse_cycle(self) -> None:
        """parse(format(parse(src))) == parse(src) — full cycle for conditional NamedDep."""
        src = (
            'name "mypkg"\n'
            "deps {\n"
            '    when platform="linux" {\n'
            '        "linux-only" ">= 1.0.0"\n'
            "    }\n"
            "}\n"
            'kind "library"\n'
        )
        m1 = parse_manifest(src)
        m2 = parse_manifest(format_manifest(m1))
        assert m2.name == m1.name
        assert len(m2.deps) == len(m1.deps)
        d1 = m1.deps[0]
        d2 = m2.deps[0]
        assert type(d1) is type(d2)
        assert d1.name == d2.name
        assert d1.predicates == d2.predicates  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Hypothesis property test: predicates survive round-trip for all dep forms
# ---------------------------------------------------------------------------

_PRED_NAME = st.sampled_from(["platform", "arch", "nim", "milpa"])
_PRED_VALUE = st.text(alphabet=_SAFE_CHARS, min_size=1, max_size=12)


@st.composite
def _predicate_strategy(draw: st.DrawFn) -> Predicate:
    name = draw(_PRED_NAME)
    value = draw(_PRED_VALUE)
    negated = draw(st.booleans())
    return Predicate(name=name, values=(value,), negated=negated)


@st.composite
def _conditional_dep(draw: st.DrawFn) -> "LocalDep | TarballDep":
    """Generate one of LocalDep/TarballDep with 1..3 unique-name predicates.

    MemberDep is excluded: S1b makes a member inside a when block a parse-time
    category error (MAN-MEMBER-WHEN-GATED) — members are unconditional workspace
    topology and predicates on them are structurally forbidden.

    Predicates must have unique names: KDL §5.5 last-wins means duplicate
    property keys on a `when` node would be deduplicated at parse time, so the
    round-trip cannot preserve inputs with duplicate predicate names.
    """
    # Draw unique predicate names (no repeats — KDL deduplicates same-named props).
    n_preds = draw(st.integers(min_value=1, max_value=3))
    available_names = ["platform", "arch", "nim", "milpa"]
    pred_names = draw(
        st.lists(
            st.sampled_from(available_names),
            min_size=n_preds,
            max_size=n_preds,
            unique=True,
        )
    )
    preds = tuple(
        Predicate(
            name=pname,
            values=(draw(_PRED_VALUE),),
            negated=draw(st.booleans()),
        )
        for pname in pred_names
    )
    name = draw(_DEP_NAME)
    if draw(st.booleans()):
        return LocalDep(name=name, path=draw(_PATH_ALPHA), predicates=preds)
    else:
        return TarballDep(
            name=name,
            url=draw(_TARBALL_URL),
            predicates=preds,
        )


@given(dep=_conditional_dep())
@settings(max_examples=150)
def test_conditional_dep_predicates_survive_round_trip(
    dep: "LocalDep | TarballDep",
) -> None:
    """parse(format(parse(src))) == parse(src): predicates survive for non-URL dep forms.

    This is the core #163 regression property: a conditional LocalDep/TarballDep/
    MemberDep must have its predicates preserved through a format → parse cycle.
    """
    m = Manifest(name="mypkg", deps=(dep,))
    out = format_manifest(m)
    reparsed = parse_manifest(out)
    assert len(reparsed.deps) == 1
    got = reparsed.deps[0]
    assert type(got) is type(dep)
    assert got.name == dep.name
    # The key assertion: predicates must be identical after format → parse.
    assert got.predicates == dep.predicates  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# S9a — format_workspace_manifest tests
# ---------------------------------------------------------------------------


class TestFormatWorkspaceManifest:
    """S9a: canonical WorkspaceManifest → KDL serializer."""

    def test_minimal_two_members(self) -> None:
        from milpa.manifest import WorkspaceManifest, format_workspace_manifest, parse_workspace_or_manifest
        ws = WorkspaceManifest(members=("member-a", "member-b"))
        out = format_workspace_manifest(ws)
        assert 'member "member-a"' in out
        assert 'member "member-b"' in out
        # Re-parse must succeed and produce the same members.
        reparsed = parse_workspace_or_manifest(out)
        from milpa.manifest import WorkspaceManifest as WM
        assert isinstance(reparsed, WM)
        assert reparsed.members == ("member-a", "member-b")

    def test_workspace_block_always_emitted(self) -> None:
        from milpa.manifest import WorkspaceManifest, format_workspace_manifest
        ws = WorkspaceManifest(members=())
        out = format_workspace_manifest(ws)
        assert "workspace {" in out

    def test_name_emitted_when_present(self) -> None:
        from milpa.manifest import WorkspaceManifest, format_workspace_manifest, parse_workspace_or_manifest
        ws = WorkspaceManifest(members=("pkg",), name="my-workspace")
        out = format_workspace_manifest(ws)
        assert 'name "my-workspace"' in out
        reparsed = parse_workspace_or_manifest(out)
        from milpa.manifest import WorkspaceManifest as WM
        assert isinstance(reparsed, WM)
        assert reparsed.name == "my-workspace"

    def test_name_absent_when_none(self) -> None:
        from milpa.manifest import WorkspaceManifest, format_workspace_manifest
        ws = WorkspaceManifest(members=("pkg",), name=None)
        out = format_workspace_manifest(ws)
        # The header has "generated by milpa"; assert no standalone name= line
        lines = out.splitlines()
        assert not any(line.startswith("name ") for line in lines)

    def test_overrides_git_emitted_with_url_annotation(self) -> None:
        from milpa.manifest import (
            GitTarget, Override, WorkspaceManifest, format_workspace_manifest,
            parse_workspace_or_manifest,
        )
        ov = Override(name="foo", target=GitTarget(git="https://github.com/alt/foo.git", ref="v2"))
        ws = WorkspaceManifest(members=("pkg",), overrides=(ov,))
        out = format_workspace_manifest(ws)
        assert 'git=(url)"https://github.com/alt/foo.git"' in out
        assert 'ref="v2"' in out

    def test_overrides_local_round_trips(self) -> None:
        from milpa.manifest import (
            LocalTarget, Override, WorkspaceManifest, format_workspace_manifest,
            parse_workspace_or_manifest,
        )
        ov = Override(name="mylib", target=LocalTarget(path="../mylib-fork"))
        ws = WorkspaceManifest(members=("pkg",), overrides=(ov,))
        out = format_workspace_manifest(ws)
        assert 'local="../mylib-fork"' in out
        reparsed = parse_workspace_or_manifest(out)
        from milpa.manifest import WorkspaceManifest as WM
        assert isinstance(reparsed, WM)
        assert len(reparsed.overrides) == 1
        assert isinstance(reparsed.overrides[0].target, LocalTarget)
        assert reparsed.overrides[0].target.path == "../mylib-fork"

    def test_overrides_member_round_trips(self) -> None:
        from milpa.manifest import (
            MemberTarget, Override, WorkspaceManifest, format_workspace_manifest,
            parse_workspace_or_manifest,
        )
        ov = Override(name="shared", target=MemberTarget(member_name="shared"))
        ws = WorkspaceManifest(members=("shared", "consumer"), overrides=(ov,))
        out = format_workspace_manifest(ws)
        reparsed = parse_workspace_or_manifest(out)
        from milpa.manifest import WorkspaceManifest as WM
        assert isinstance(reparsed, WM)
        assert isinstance(reparsed.overrides[0].target, MemberTarget)
        assert reparsed.overrides[0].target.member_name == "shared"

    def test_flags_round_trip(self) -> None:
        from milpa.manifest import (
            FlagDecl, WorkspaceManifest, format_workspace_manifest,
            parse_workspace_or_manifest,
        )
        fd = FlagDecl(name="ssl", default=True)
        ws = WorkspaceManifest(members=("pkg",), flags=(fd,))
        out = format_workspace_manifest(ws)
        assert '"ssl" default=#true' in out
        reparsed = parse_workspace_or_manifest(out)
        from milpa.manifest import WorkspaceManifest as WM
        assert isinstance(reparsed, WM)
        assert len(reparsed.flags) == 1
        assert reparsed.flags[0].name == "ssl"
        assert reparsed.flags[0].default is True

    def test_ends_with_newline(self) -> None:
        from milpa.manifest import WorkspaceManifest, format_workspace_manifest
        ws = WorkspaceManifest(members=("pkg",))
        out = format_workspace_manifest(ws)
        assert out.endswith("\n")

    def test_header_is_workspace_specific(self) -> None:
        """Workspace header mentions workspace add-member / remove-member."""
        from milpa.manifest import WorkspaceManifest, format_workspace_manifest
        ws = WorkspaceManifest(members=("pkg",))
        out = format_workspace_manifest(ws)
        assert "workspace add-member" in out or "workspace" in out.splitlines()[0]

    def test_member_order_preserved(self) -> None:
        """Members are emitted in declaration order (insertion-stable)."""
        from milpa.manifest import WorkspaceManifest, format_workspace_manifest
        ws = WorkspaceManifest(members=("c", "a", "b"))
        out = format_workspace_manifest(ws)
        pos_c = out.index('"c"')
        pos_a = out.index('"a"')
        pos_b = out.index('"b"')
        assert pos_c < pos_a < pos_b

    def test_idempotent_basic(self) -> None:
        """format(parse(format(ws))) == format(ws) for a minimal workspace."""
        from milpa.manifest import WorkspaceManifest, format_workspace_manifest, parse_workspace_or_manifest
        ws = WorkspaceManifest(members=("member-a", "member-b"), name="root")
        first = format_workspace_manifest(ws)
        reparsed = parse_workspace_or_manifest(first)
        assert isinstance(reparsed, WorkspaceManifest)
        second = format_workspace_manifest(reparsed)
        assert first == second, (
            f"Idempotence violated:\nFirst:\n{first}\nSecond:\n{second}"
        )

    # -- RD-M2: index-trust round-trip (workspace root, root-authority model) --

    def test_index_trust_policy_signer_bundle_round_trip(self) -> None:
        """A workspace-root index-trust "strict" (+ signer/bundle) must survive
        a format_workspace_manifest → parse round trip.

        Pre-fix: format_workspace_manifest never emitted these nodes, so any
        write path through it (e.g. `workspace add-member`/`remove-member`)
        silently reverted a declared strict policy to the "warn" default.
        """
        from milpa.manifest import WorkspaceManifest, format_workspace_manifest, parse_workspace_or_manifest
        ws = WorkspaceManifest(
            members=("pkg",),
            index_trust_policy="strict",
            index_trust_policy_explicit=True,
            index_trust_signer="signer@example.com",
            index_trust_bundle="file:///tmp/bundle.json",
        )
        out = format_workspace_manifest(ws)
        assert 'index-trust "strict"' in out
        assert 'index-trust-signer "signer@example.com"' in out
        assert 'index-trust-bundle "file:///tmp/bundle.json"' in out

        reparsed = parse_workspace_or_manifest(out)
        assert isinstance(reparsed, WorkspaceManifest)
        assert reparsed.index_trust_policy == "strict"
        assert reparsed.index_trust_policy_explicit is True
        assert reparsed.index_trust_signer == "signer@example.com"
        assert reparsed.index_trust_bundle == "file:///tmp/bundle.json"

    def test_index_trust_not_explicit_stays_absent(self) -> None:
        """A workspace root that never declared index-trust must not gain one."""
        from milpa.manifest import WorkspaceManifest, format_workspace_manifest, parse_workspace_or_manifest
        ws = WorkspaceManifest(members=("pkg",))
        out = format_workspace_manifest(ws)
        assert "index-trust " not in out
        assert "index-trust\n" not in out
        reparsed = parse_workspace_or_manifest(out)
        assert isinstance(reparsed, WorkspaceManifest)
        assert reparsed.index_trust_policy_explicit is False
        assert reparsed.index_trust_policy == "warn"

    def test_index_trust_survives_add_member_rewrite(self) -> None:
        """A workspace-root "strict" policy must survive a simulated
        add-member rewrite — the exact real-world path (`milpa workspace
        add-member`) that goes through format_workspace_manifest.
        """
        from dataclasses import replace

        from milpa.manifest import WorkspaceManifest, format_workspace_manifest, parse_workspace_or_manifest

        ws = WorkspaceManifest(
            members=("pkg-a",),
            index_trust_policy="strict",
            index_trust_policy_explicit=True,
        )
        # Simulate `workspace add-member`: append a member, then rewrite to disk.
        ws_with_new_member = replace(ws, members=ws.members + ("pkg-b",))
        out = format_workspace_manifest(ws_with_new_member)
        reparsed = parse_workspace_or_manifest(out)
        assert isinstance(reparsed, WorkspaceManifest)
        assert reparsed.members == ("pkg-a", "pkg-b")
        assert reparsed.index_trust_policy == "strict", (
            "add-member rewrite must not revert a declared strict policy to warn"
        )
        assert reparsed.index_trust_policy_explicit is True

    def test_index_trust_survives_remove_member_rewrite(self) -> None:
        """A workspace-root "strict" policy must survive a simulated
        remove-member rewrite (`milpa workspace remove-member`)."""
        from dataclasses import replace

        from milpa.manifest import WorkspaceManifest, format_workspace_manifest, parse_workspace_or_manifest

        ws = WorkspaceManifest(
            members=("pkg-a", "pkg-b"),
            index_trust_policy="strict",
            index_trust_policy_explicit=True,
        )
        # Simulate `workspace remove-member`: drop a member, then rewrite to disk.
        ws_with_member_removed = replace(
            ws, members=tuple(p for p in ws.members if p != "pkg-b")
        )
        out = format_workspace_manifest(ws_with_member_removed)
        reparsed = parse_workspace_or_manifest(out)
        assert isinstance(reparsed, WorkspaceManifest)
        assert reparsed.members == ("pkg-a",)
        assert reparsed.index_trust_policy == "strict", (
            "remove-member rewrite must not revert a declared strict policy to warn"
        )
        assert reparsed.index_trust_policy_explicit is True

    # -- A2c: index-history round-trip (workspace root, root-authority model) --

    def test_index_history_policy_round_trip(self) -> None:
        """A workspace-root index-history "strict" must survive a
        format_workspace_manifest → parse round trip.  Mirrors the index-trust
        round-trip tests above for the sibling axis."""
        from milpa.manifest import WorkspaceManifest, format_workspace_manifest, parse_workspace_or_manifest
        ws = WorkspaceManifest(
            members=("pkg",),
            index_history_policy="strict",
            index_history_policy_explicit=True,
        )
        out = format_workspace_manifest(ws)
        assert 'index-history "strict"' in out

        reparsed = parse_workspace_or_manifest(out)
        assert isinstance(reparsed, WorkspaceManifest)
        assert reparsed.index_history_policy == "strict"
        assert reparsed.index_history_policy_explicit is True

    def test_index_history_not_explicit_stays_absent(self) -> None:
        """A workspace root that never declared index-history must not gain one."""
        from milpa.manifest import WorkspaceManifest, format_workspace_manifest, parse_workspace_or_manifest
        ws = WorkspaceManifest(members=("pkg",))
        out = format_workspace_manifest(ws)
        assert "index-history " not in out
        assert "index-history\n" not in out
        reparsed = parse_workspace_or_manifest(out)
        assert isinstance(reparsed, WorkspaceManifest)
        assert reparsed.index_history_policy_explicit is False
        assert reparsed.index_history_policy == "warn"

    def test_index_history_survives_add_member_rewrite(self) -> None:
        """A workspace-root "strict" policy must survive a simulated
        add-member rewrite (`milpa workspace add-member`)."""
        from dataclasses import replace

        from milpa.manifest import WorkspaceManifest, format_workspace_manifest, parse_workspace_or_manifest

        ws = WorkspaceManifest(
            members=("pkg-a",),
            index_history_policy="strict",
            index_history_policy_explicit=True,
        )
        ws_with_new_member = replace(ws, members=ws.members + ("pkg-b",))
        out = format_workspace_manifest(ws_with_new_member)
        reparsed = parse_workspace_or_manifest(out)
        assert isinstance(reparsed, WorkspaceManifest)
        assert reparsed.members == ("pkg-a", "pkg-b")
        assert reparsed.index_history_policy == "strict", (
            "add-member rewrite must not revert a declared strict policy to warn"
        )
        assert reparsed.index_history_policy_explicit is True


# ---------------------------------------------------------------------------
# S9a idempotence property test
# ---------------------------------------------------------------------------


@st.composite
def _workspace_manifest_st(draw: st.DrawFn) -> "WorkspaceManifest":
    """Generate a WorkspaceManifest with 1–4 members and optional name/overrides/flags."""
    from milpa.manifest import (
        FlagDecl, GitTarget, LocalTarget, MemberTarget, Override, WorkspaceManifest,
    )

    n_members = draw(st.integers(min_value=1, max_value=4))
    # Use simple alpha names for members to keep valid path strings.
    member_names = draw(
        st.lists(
            st.text(alphabet="abcdefghijklmnopqrstuvwxyz-", min_size=1, max_size=12).filter(
                lambda s: s and s[0].isalpha() and not s.endswith("-")
            ),
            min_size=n_members,
            max_size=n_members,
            unique=True,
        )
    )
    ws_name: str | None = draw(st.one_of(
        st.none(),
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz-", min_size=1, max_size=12).filter(
            lambda s: s and s[0].isalpha() and not s.endswith("-")
        ),
    ))
    # Small override set (0 or 1 entry, no duplicates needed for idempotence)
    has_override = draw(st.booleans())
    overrides: tuple[Override, ...] = ()
    if has_override:
        ov_name = draw(st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8))
        ov = Override(
            name=ov_name,
            target=GitTarget(
                git=f"https://github.com/example/{ov_name}.git",
                ref="main",
            ),
        )
        overrides = (ov,)
    # Flags (0–2, simple leaf flags)
    n_flags = draw(st.integers(min_value=0, max_value=2))
    flag_names = draw(
        st.lists(
            st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8),
            min_size=n_flags,
            max_size=n_flags,
            unique=True,
        )
    )
    flags = tuple(
        FlagDecl(name=fn, default=draw(st.booleans()))
        for fn in flag_names
    )
    return WorkspaceManifest(
        members=tuple(member_names),
        name=ws_name,
        overrides=overrides,
        flags=flags,
    )


@given(ws=_workspace_manifest_st())
@settings(max_examples=200)
def test_format_workspace_manifest_idempotent(ws: "WorkspaceManifest") -> None:
    """S9a idempotence: format(parse(format(ws))) == format(ws).

    Serializing a workspace manifest, parsing the output, and serializing
    again MUST produce the same bytes.  This pins the canonical serializer's
    byte-stability (manifest-grammar.md §8, Depth-F6).
    """
    from milpa.manifest import WorkspaceManifest, format_workspace_manifest, parse_workspace_or_manifest

    first = format_workspace_manifest(ws)
    reparsed = parse_workspace_or_manifest(first)
    assert isinstance(reparsed, WorkspaceManifest), (
        f"Expected WorkspaceManifest after round-trip, got {type(reparsed)}"
    )
    second = format_workspace_manifest(reparsed)
    assert first == second, (
        f"Idempotence violated for ws={ws!r}:\nFirst:\n{first}\nSecond:\n{second}"
    )
