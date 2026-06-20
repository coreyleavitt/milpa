"""Stage-local gate harness for manifest parsing — slices 3a–3d.

Calls ``parse_manifest`` / ``parse_workspace_or_manifest`` directly.
Imports only ``manifest``, ``kdl_io``, ``errors``, ``version``, ``profile``.
No CLI, no filesystem I/O, no solver, no fetcher.

Coverage:
  3a — data model: confirm typed dataclass results from valid inputs.
  3b — NamedDep constraint pre-typing (MAN-DEP-NAMED-CONSTRAINT at boundary).
  3c-1 — UrlDep parse: valid + error cases.
  3c-2 — NamedDep parse: valid + error cases.
  3c-3 — TarballDep parse: valid + error cases.
  3c-4 — LocalDep + MemberDep parse: valid + error cases.
  3c-5 — mirrors block: MAN-DEP-MIRROR-ARITY, MAN-MIRRORS-*, MAN-URL-ARG-TYPE.
  3c-6 — overrides block: MAN-OVERRIDE-*.
  3c-7 — predicates as data: MAN-PREDICATE-* (no eval, data-only).
  3c-8 — flags: MAN-FLAG-* declarations + MAN-DEP-FLAG-* requests.
  3c-9 — spec-version, dev-deps, cas, MAN-UNKNOWN-TOP-LEVEL (exhaustive dispatch).
  3d  — workspace manifest grammar: MAN-WORKSPACE-*.

Corpus fixtures exercised (read directly from conformance/):
  003-single-url-dep, 015-man-dep-ref-missing, 016-man-dep-local-path,
  017-man-dep-tarball-url, 018-man-dep-tarball-sha,
  019-man-dep-tarball-strip, 020-man-dep-member-props,
  021-man-dep-member-arity, 022-man-dep-named-props,
  023-man-dep-named-constraint, 024-man-dep-named-arity,
  025-man-dep-mirror-arity, 026-man-dep-flag-name-missing,
  027-man-dep-flag-too-many-args, 028-man-dep-flag-bool,
  029-man-dep-unknown-child, 030-man-git-url-no-scheme,
  031-man-git-url-bad-scheme, 032-man-override-kind,
  033-man-override-arity, 034-man-override-unknown-props,
  035-man-override-git-missing (now → MAN-OVERRIDE-TARGET-AMBIGUOUS in S8),
  036-man-override-ref-missing, 037-man-override-duplicate,
  202-s8-override-all-forms-accept, 203-man-override-target-ambiguous,
  204-man-override-target-ambiguous-none,
  038-man-flag-duplicate,
  039-man-flag-pos-args, 040-man-flag-unknown-props,
  041-man-flag-default-type, 042-man-flag-description-type,
  043-man-flag-unknown-child, 044-man-flag-defines-arg-type,
  045-man-flag-undeclared-reference, 046-man-predicate-unknown,
  047-man-predicate-value-type, 048-man-predicate-unsupported-annotation,
  049-man-predicate-child-no-args, 050-man-predicate-child-arg-type,
  051-man-predicate-mixed-negation, 052-man-predicate-form-conflict,
  053-man-mirrors-unknown-child, 054-man-mirrors-arity,
  055-man-workspace-has-deps-or-kind, 056-man-workspace-unknown-node,
  057-man-workspace-member-arity, 058-man-workspace-member-duplicate,
  059-man-workspace-unknown-top-level, 060-man-url-arg-type,
  102-man-spec-version-type, 103-man-spec-version-unsupported,
  119-man-dep-named-constraint-bad-string.

Top-level manifest error fixtures (covered here):
  001-man-kdl-syntax, 002-man-name-missing, 004-man-name-duplicate,
  005-man-name-type, 006-man-src-dir-type, 007-man-cas-dir-missing,
  008-man-cas-dir-type, 009-man-unknown-top-level,
  010-man-workspace-has-kind, 011-man-kind-arity, 012-man-kind-invalid,
  013-man-dep-duplicate, 014-man-dep-unknown-props.
"""

from __future__ import annotations

import pathlib
import textwrap

import pytest

from milpa import errors as E
from milpa.errors import MilpaError
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
    WorkspaceManifest,
    parse_manifest,
    parse_workspace_or_manifest,
)
from milpa.profile import Profile
from milpa.version import VersionSet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CONFORMANCE = pathlib.Path(__file__).parent.parent.parent.parent / "conformance"
SPEC_V1 = CONFORMANCE / "spec-v1"


def fixture_kdl(name: str) -> str:
    """Return the text of conformance/spec-v1/fixture-<name>/milpa.kdl."""
    path = SPEC_V1 / name / "milpa.kdl"
    return path.read_text()


def fixture_error(name: str) -> str:
    """Return the expected error slug from conformance/spec-v1/fixture-<name>/expected/error."""
    path = SPEC_V1 / name / "expected" / "error"
    return path.read_text().strip()


def assert_slug(text: str, expected_slug: str) -> MilpaError:
    """Assert that parsing ``text`` raises ``MilpaError`` with ``expected_slug``.

    Returns the exception for further assertions.
    """
    with pytest.raises(MilpaError) as exc_info:
        parse_manifest(text)
    err = exc_info.value
    assert err.slug == expected_slug, (
        f"expected slug {expected_slug!r}, got {err.slug!r}: {err.message}"
    )
    return err


def assert_slug_ws(text: str, expected_slug: str) -> MilpaError:
    """Same as ``assert_slug`` but uses ``parse_workspace_or_manifest``."""
    with pytest.raises(MilpaError) as exc_info:
        parse_workspace_or_manifest(text)
    err = exc_info.value
    assert err.slug == expected_slug, (
        f"expected slug {expected_slug!r}, got {err.slug!r}: {err.message}"
    )
    return err


# ---------------------------------------------------------------------------
# 3a — Data model: valid parse → typed dataclasses
# ---------------------------------------------------------------------------


class TestDataModel:
    """3a: verify that valid inputs produce correctly-typed dataclass values."""

    def test_manifest_basic_fields(self) -> None:
        m = parse_manifest('name "myapp"\nkind "application"\n')
        assert isinstance(m, Manifest)
        assert m.name == "myapp"
        assert m.kind == "application"
        assert m.deps == ()
        assert m.dev_deps == ()
        assert m.src_dir == ""

    def test_manifest_default_kind_library(self) -> None:
        m = parse_manifest('name "pkg"\n')
        assert m.kind == "library"

    def test_manifest_src_dir(self) -> None:
        m = parse_manifest('name "pkg"\nsrc_dir "src"\n')
        assert m.src_dir == "src"

    def test_predicate_dataclass(self) -> None:
        p = Predicate(name="platform", values=("linux",))
        assert p.name == "platform"
        assert p.values == ("linux",)
        assert p.negated is False

    def test_flag_request_dataclass(self) -> None:
        fr = FlagRequest(name="ssl", enabled=True)
        assert fr.name == "ssl"
        assert fr.enabled is True

        fr2 = FlagRequest(name="ssl", enabled=False)
        assert fr2.enabled is False

    def test_url_dep_dataclass(self) -> None:
        dep = UrlDep(name="foo", git="https://github.com/x/foo.git", ref="main")
        assert dep.name == "foo"
        assert dep.git == "https://github.com/x/foo.git"
        assert dep.ref == "main"
        assert dep.mirrors == ()
        assert dep.predicates == ()
        assert dep.flag_requests == ()

    def test_named_dep_no_constraint(self) -> None:
        dep = NamedDep(name="stew", constraint=None)
        assert dep.constraint is None
        assert dep.constraint_set is None

    def test_named_dep_with_constraint(self) -> None:
        dep = NamedDep(name="stew", constraint=">= 0.5.0")
        assert dep.constraint == ">= 0.5.0"
        assert isinstance(dep.constraint_set, VersionSet)

    def test_local_dep_dataclass(self) -> None:
        dep = LocalDep(name="foo", path="../foo")
        assert dep.name == "foo"
        assert dep.path == "../foo"

    def test_tarball_dep_dataclass(self) -> None:
        dep = TarballDep(
            name="foo",
            url="https://example.com/foo.tar.gz",
            sha256="abc123",
            strip_components=1,
        )
        assert dep.sha256 == "abc123"
        assert dep.strip_components == 1

    def test_tarball_dep_defaults(self) -> None:
        dep = TarballDep(name="foo", url="https://example.com/foo.tar.gz")
        assert dep.sha256 is None
        assert dep.strip_components == 0

    def test_member_dep_dataclass(self) -> None:
        dep = MemberDep(name="intonaco")
        assert dep.name == "intonaco"

    def test_profile_from_environment_injected(self) -> None:
        p = Profile.from_environment(nim_version="2.0.8", milpa_version="0.1.0")
        assert p.nim == "2.0.8"
        assert p.milpa == "0.1.0"
        assert isinstance(p.flags, frozenset)

    def test_workspace_manifest_dataclass(self) -> None:
        wm = WorkspaceManifest(members=("a", "b"))
        assert wm.members == ("a", "b")
        assert wm.overrides == ()


# ---------------------------------------------------------------------------
# 3b — NamedDep constraint pre-typed at parse boundary
# ---------------------------------------------------------------------------


class TestConstraintPreTyping:
    """3b: malformed constraint raises MAN-DEP-NAMED-CONSTRAINT at the
    manifest parse boundary, not at resolver time."""

    def test_valid_constraint_produces_version_set(self) -> None:
        m = parse_manifest('name "x"\ndeps {\n    foo ">= 0.5.0"\n}\n')
        dep = m.deps[0]
        assert isinstance(dep, NamedDep)
        assert dep.constraint == ">= 0.5.0"
        assert isinstance(dep.constraint_set, VersionSet)

    def test_non_string_arg_raises_man_dep_named_constraint(self) -> None:
        """Corpus fixture 023: non-string positional arg (int 42)."""
        text = fixture_kdl("fixture-023-man-dep-named-constraint")
        expected = fixture_error("fixture-023-man-dep-named-constraint")
        assert_slug(text, expected)

    def test_bad_constraint_string_raises_man_dep_named_constraint(self) -> None:
        """Corpus fixture 119: malformed constraint string "@@@bad"."""
        text = fixture_kdl("fixture-119-man-dep-named-constraint-bad-string")
        expected = fixture_error("fixture-119-man-dep-named-constraint-bad-string")
        assert_slug(text, expected)

    def test_namedep_direct_construction_raises_at_boundary(self) -> None:
        """Construction outside the parser also raises at the boundary."""
        with pytest.raises(MilpaError) as exc_info:
            NamedDep(name="foo", constraint="@@@bad")
        assert exc_info.value.slug == E.MAN_DEP_NAMED_CONSTRAINT

    def test_namedep_no_constraint_no_error(self) -> None:
        dep = NamedDep(name="foo", constraint=None)
        assert dep.constraint_set is None  # no error raised


# ---------------------------------------------------------------------------
# 3c-1 — UrlDep parse
# ---------------------------------------------------------------------------


class TestUrlDepParse:
    """3c-1: URL dep parse — valid + MAN-DEP-* error cases."""

    def test_valid_url_dep_from_corpus(self) -> None:
        """Corpus fixture 003: single URL dep — must parse cleanly."""
        text = fixture_kdl("fixture-003-single-url-dep")
        m = parse_manifest(text)
        assert len(m.deps) == 1
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.name == "foo"
        assert dep.git == "https://github.com/example/foo.git"
        assert dep.ref == "main"

    def test_url_dep_http_scheme(self) -> None:
        text = 'name "x"\ndeps {\n    foo git="http://example.com/foo.git" ref="main"\n}\n'
        m = parse_manifest(text)
        assert isinstance(m.deps[0], UrlDep)

    def test_url_dep_ssh_scheme(self) -> None:
        text = 'name "x"\ndeps {\n    foo git="ssh://git@github.com/x/y.git" ref="v1"\n}\n'
        m = parse_manifest(text)
        assert isinstance(m.deps[0], UrlDep)

    def test_url_dep_git_scheme(self) -> None:
        text = 'name "x"\ndeps {\n    foo git="git://github.com/x/y.git" ref="v1"\n}\n'
        m = parse_manifest(text)
        assert isinstance(m.deps[0], UrlDep)

    def test_ref_missing_raises_corpus(self) -> None:
        """Corpus fixture 015: MAN-DEP-REF-MISSING."""
        text = fixture_kdl("fixture-015-man-dep-ref-missing")
        expected = fixture_error("fixture-015-man-dep-ref-missing")
        assert_slug(text, expected)

    def test_git_url_no_scheme_corpus(self) -> None:
        """Corpus fixture 030: MAN-GIT-URL-NO-SCHEME."""
        text = fixture_kdl("fixture-030-man-git-url-no-scheme")
        expected = fixture_error("fixture-030-man-git-url-no-scheme")
        assert_slug(text, expected)

    def test_git_url_bad_scheme_corpus(self) -> None:
        """Corpus fixture 031: MAN-GIT-URL-BAD-SCHEME (ftp scheme)."""
        text = fixture_kdl("fixture-031-man-git-url-bad-scheme")
        expected = fixture_error("fixture-031-man-git-url-bad-scheme")
        assert_slug(text, expected)

    def test_unknown_props_corpus(self) -> None:
        """Corpus fixture 014: MAN-DEP-UNKNOWN-PROPS on a UrlDep."""
        text = fixture_kdl("fixture-014-man-dep-unknown-props")
        expected = fixture_error("fixture-014-man-dep-unknown-props")
        assert_slug(text, expected)

    def test_unknown_child_corpus(self) -> None:
        """Corpus fixture 029: MAN-DEP-UNKNOWN-CHILD on a UrlDep."""
        text = fixture_kdl("fixture-029-man-dep-unknown-child")
        expected = fixture_error("fixture-029-man-dep-unknown-child")
        assert_slug(text, expected)

    def test_mirror_valid(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://a/foo.git" ref="main" {
                    mirror (url)"https://b/foo.git"
                }
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.mirrors == ("https://b/foo.git",)

    def test_mirror_arity_corpus(self) -> None:
        """Corpus fixture 025: MAN-DEP-MIRROR-ARITY (mirror with no arg)."""
        text = fixture_kdl("fixture-025-man-dep-mirror-arity")
        expected = fixture_error("fixture-025-man-dep-mirror-arity")
        assert_slug(text, expected)

    def test_flag_request_valid(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://a/foo.git" ref="main" {
                    flag "ssl"
                }
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert len(dep.flag_requests) == 1
        assert dep.flag_requests[0].name == "ssl"
        assert dep.flag_requests[0].enabled is True

    def test_flag_request_explicit_false(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://a/foo.git" ref="main" {
                    flag "ssl" #false
                }
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.flag_requests[0].enabled is False

    def test_flag_name_missing_corpus(self) -> None:
        """Corpus fixture 026: MAN-DEP-FLAG-NAME-MISSING."""
        text = fixture_kdl("fixture-026-man-dep-flag-name-missing")
        expected = fixture_error("fixture-026-man-dep-flag-name-missing")
        assert_slug(text, expected)

    def test_flag_too_many_args_corpus(self) -> None:
        """Corpus fixture 027: MAN-DEP-FLAG-TOO-MANY-ARGS."""
        text = fixture_kdl("fixture-027-man-dep-flag-too-many-args")
        expected = fixture_error("fixture-027-man-dep-flag-too-many-args")
        assert_slug(text, expected)

    def test_flag_bool_corpus(self) -> None:
        """Corpus fixture 028: MAN-DEP-FLAG-BOOL (non-bool second arg)."""
        text = fixture_kdl("fixture-028-man-dep-flag-bool")
        expected = fixture_error("fixture-028-man-dep-flag-bool")
        assert_slug(text, expected)

    def test_plain_string_git_url_accepted(self) -> None:
        """The spec requires both plain string and (url)-annotated forms."""
        text = 'name "x"\ndeps {\n    foo git="https://a/foo.git" ref="main"\n}\n'
        m = parse_manifest(text)
        assert isinstance(m.deps[0], UrlDep)
        assert m.deps[0].git == "https://a/foo.git"


# ---------------------------------------------------------------------------
# 3c-2 — NamedDep parse
# ---------------------------------------------------------------------------


class TestNamedDepParse:
    """3c-2: Named dep parse — valid + MAN-DEP-NAMED-* error cases."""

    def test_named_dep_no_constraint(self) -> None:
        text = 'name "x"\ndeps {\n    results\n}\n'
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, NamedDep)
        assert dep.name == "results"
        assert dep.constraint is None

    def test_named_dep_with_constraint(self) -> None:
        text = 'name "x"\ndeps {\n    stew ">= 0.5.0"\n}\n'
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, NamedDep)
        assert dep.constraint == ">= 0.5.0"
        assert dep.constraint_set is not None

    def test_named_dep_props_corpus(self) -> None:
        """Corpus fixture 022: MAN-DEP-NAMED-PROPS (unknown property)."""
        text = fixture_kdl("fixture-022-man-dep-named-props")
        expected = fixture_error("fixture-022-man-dep-named-props")
        assert_slug(text, expected)

    def test_named_dep_constraint_non_string_corpus(self) -> None:
        """Corpus fixture 023: MAN-DEP-NAMED-CONSTRAINT (int arg)."""
        text = fixture_kdl("fixture-023-man-dep-named-constraint")
        expected = fixture_error("fixture-023-man-dep-named-constraint")
        assert_slug(text, expected)

    def test_named_dep_arity_corpus(self) -> None:
        """Corpus fixture 024: MAN-DEP-NAMED-ARITY (two positional args)."""
        text = fixture_kdl("fixture-024-man-dep-named-arity")
        expected = fixture_error("fixture-024-man-dep-named-arity")
        assert_slug(text, expected)


# ---------------------------------------------------------------------------
# 3c-3 — TarballDep parse
# ---------------------------------------------------------------------------


class TestTarballDepParse:
    """3c-3: Tarball dep parse — valid + MAN-DEP-TARBALL-* error cases."""

    def test_tarball_dep_minimal(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo tarball=(url)"https://example.com/foo.tar.gz"
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, TarballDep)
        assert dep.url == "https://example.com/foo.tar.gz"
        assert dep.sha256 is None
        assert dep.strip_components == 0

    def test_tarball_dep_with_sha256(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo tarball=(url)"https://example.com/foo.tar.gz" sha256="abc123"
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, TarballDep)
        assert dep.sha256 == "abc123"

    def test_tarball_dep_with_strip_components(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo tarball=(url)"https://example.com/foo.tar.gz" strip_components=1
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, TarballDep)
        assert dep.strip_components == 1

    def test_tarball_plain_url_accepted(self) -> None:
        """Plain string (not (url)-annotated) must also be accepted."""
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo tarball="https://example.com/foo.tar.gz"
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, TarballDep)
        assert dep.url == "https://example.com/foo.tar.gz"

    def test_tarball_url_empty_corpus(self) -> None:
        """Corpus fixture 017: MAN-DEP-TARBALL-URL (empty string)."""
        text = fixture_kdl("fixture-017-man-dep-tarball-url")
        expected = fixture_error("fixture-017-man-dep-tarball-url")
        assert_slug(text, expected)

    def test_tarball_sha_corpus(self) -> None:
        """Corpus fixture 018: MAN-DEP-TARBALL-SHA (sha256 is int not string)."""
        text = fixture_kdl("fixture-018-man-dep-tarball-sha")
        expected = fixture_error("fixture-018-man-dep-tarball-sha")
        assert_slug(text, expected)

    def test_tarball_strip_corpus(self) -> None:
        """Corpus fixture 019: MAN-DEP-TARBALL-STRIP (negative strip_components)."""
        text = fixture_kdl("fixture-019-man-dep-tarball-strip")
        expected = fixture_error("fixture-019-man-dep-tarball-strip")
        assert_slug(text, expected)

    def test_tarball_strip_components_zero(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo tarball=(url)"https://example.com/foo.tar.gz" strip_components=0
            }
        """)
        m = parse_manifest(text)
        assert m.deps[0].strip_components == 0  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# 3c-4 — LocalDep + MemberDep parse
# ---------------------------------------------------------------------------


class TestLocalDepParse:
    """3c-4: Local dep parse — valid + MAN-DEP-LOCAL-* error cases."""

    def test_local_dep_valid(self) -> None:
        text = 'name "x"\ndeps {\n    foo local="../foo"\n}\n'
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, LocalDep)
        assert dep.name == "foo"
        assert dep.path == "../foo"

    def test_local_dep_absolute_path(self) -> None:
        text = 'name "x"\ndeps {\n    foo local="/abs/path/to/foo"\n}\n'
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, LocalDep)
        assert dep.path == "/abs/path/to/foo"

    def test_local_dep_empty_path_corpus(self) -> None:
        """Corpus fixture 016: MAN-DEP-LOCAL-PATH (empty local= value)."""
        text = fixture_kdl("fixture-016-man-dep-local-path")
        expected = fixture_error("fixture-016-man-dep-local-path")
        assert_slug(text, expected)


class TestMemberDepParse:
    """3c-4: Member dep parse — valid + MAN-DEP-MEMBER-* error cases."""

    def test_member_dep_valid(self) -> None:
        text = 'name "x"\ndeps {\n    member "intonaco"\n}\n'
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, MemberDep)
        assert dep.name == "intonaco"

    def test_member_dep_props_corpus(self) -> None:
        """Corpus fixture 020: MAN-DEP-MEMBER-PROPS (property on member node)."""
        text = fixture_kdl("fixture-020-man-dep-member-props")
        expected = fixture_error("fixture-020-man-dep-member-props")
        assert_slug(text, expected)

    def test_member_dep_arity_corpus(self) -> None:
        """Corpus fixture 021: MAN-DEP-MEMBER-ARITY (member with no arg)."""
        text = fixture_kdl("fixture-021-man-dep-member-arity")
        expected = fixture_error("fixture-021-man-dep-member-arity")
        assert_slug(text, expected)

    def test_member_dep_two_args_raises_arity(self) -> None:
        text = 'name "x"\ndeps {\n    member "a" "b"\n}\n'
        assert_slug(text, E.MAN_DEP_MEMBER_ARITY)


# ---------------------------------------------------------------------------
# Top-level manifest errors (covered here as they're needed for full fixture
# coverage, even though strictly outside 3c-1..3c-4 scope)
# ---------------------------------------------------------------------------


class TestTopLevelErrors:
    """Top-level manifest structural errors — corpus fixtures 001–014."""

    def test_kdl_syntax_corpus(self) -> None:
        """Corpus fixture 001: MAN-KDL-SYNTAX."""
        text = fixture_kdl("fixture-001-man-kdl-syntax")
        expected = fixture_error("fixture-001-man-kdl-syntax")
        assert_slug(text, expected)

    def test_name_missing_corpus(self) -> None:
        """Corpus fixture 002: MAN-NAME-MISSING."""
        text = fixture_kdl("fixture-002-man-name-missing")
        expected = fixture_error("fixture-002-man-name-missing")
        assert_slug(text, expected)

    def test_name_duplicate_corpus(self) -> None:
        """Corpus fixture 004: MAN-NAME-DUPLICATE."""
        text = fixture_kdl("fixture-004-man-name-duplicate")
        expected = fixture_error("fixture-004-man-name-duplicate")
        assert_slug(text, expected)

    def test_name_type_corpus(self) -> None:
        """Corpus fixture 005: MAN-NAME-TYPE (non-string name arg)."""
        text = fixture_kdl("fixture-005-man-name-type")
        expected = fixture_error("fixture-005-man-name-type")
        assert_slug(text, expected)

    def test_src_dir_type_corpus(self) -> None:
        """Corpus fixture 006: MAN-SRC-DIR-TYPE."""
        text = fixture_kdl("fixture-006-man-src-dir-type")
        expected = fixture_error("fixture-006-man-src-dir-type")
        assert_slug(text, expected)

    def test_cas_dir_missing_corpus(self) -> None:
        """Corpus fixture 007: MAN-CAS-DIR-MISSING."""
        text = fixture_kdl("fixture-007-man-cas-dir-missing")
        expected = fixture_error("fixture-007-man-cas-dir-missing")
        assert_slug(text, expected)

    def test_cas_dir_type_corpus(self) -> None:
        """Corpus fixture 008: MAN-CAS-DIR-TYPE."""
        text = fixture_kdl("fixture-008-man-cas-dir-type")
        expected = fixture_error("fixture-008-man-cas-dir-type")
        assert_slug(text, expected)

    def test_unknown_top_level_corpus(self) -> None:
        """Corpus fixture 009: MAN-UNKNOWN-TOP-LEVEL."""
        text = fixture_kdl("fixture-009-man-unknown-top-level")
        expected = fixture_error("fixture-009-man-unknown-top-level")
        assert_slug(text, expected)

    def test_workspace_has_kind_corpus(self) -> None:
        """Corpus fixture 010: MAN-WORKSPACE-HAS-DEPS-OR-KIND."""
        text = fixture_kdl("fixture-010-man-workspace-has-kind")
        expected = fixture_error("fixture-010-man-workspace-has-kind")
        assert_slug_ws(text, expected)

    def test_kind_arity_corpus(self) -> None:
        """Corpus fixture 011: MAN-KIND-ARITY."""
        text = fixture_kdl("fixture-011-man-kind-arity")
        expected = fixture_error("fixture-011-man-kind-arity")
        assert_slug(text, expected)

    def test_kind_invalid_corpus(self) -> None:
        """Corpus fixture 012: MAN-KIND-INVALID."""
        text = fixture_kdl("fixture-012-man-kind-invalid")
        expected = fixture_error("fixture-012-man-kind-invalid")
        assert_slug(text, expected)

    def test_dep_duplicate_corpus(self) -> None:
        """Corpus fixture 013: MAN-DEP-DUPLICATE."""
        text = fixture_kdl("fixture-013-man-dep-duplicate")
        expected = fixture_error("fixture-013-man-dep-duplicate")
        assert_slug(text, expected)

    def test_dep_unknown_props_corpus(self) -> None:
        """Corpus fixture 014: MAN-DEP-UNKNOWN-PROPS."""
        text = fixture_kdl("fixture-014-man-dep-unknown-props")
        expected = fixture_error("fixture-014-man-dep-unknown-props")
        assert_slug(text, expected)

    def test_empty_manifest_name_missing(self) -> None:
        """An empty document has no 'name' → MAN-NAME-MISSING."""
        assert_slug("", E.MAN_NAME_MISSING)


# ---------------------------------------------------------------------------
# Dispatch seam tests — ensure later slices have clean insertion points
# ---------------------------------------------------------------------------


class TestDispatchSeam:
    """Verify the parser is structured so that 3c-5..3d can slot in cleanly."""

    def test_multiple_dep_forms_in_one_manifest(self) -> None:
        """A manifest with all four non-member dep forms parses correctly."""
        text = textwrap.dedent("""\
            name "project"
            deps {
                foo git=(url)"https://github.com/x/foo.git" ref="main"
                bar ">= 1.0.0"
                baz local="../baz"
                qux tarball=(url)"https://example.com/qux.tar.gz"
            }
        """)
        m = parse_manifest(text)
        assert len(m.deps) == 4
        assert isinstance(m.deps[0], UrlDep)
        assert isinstance(m.deps[1], NamedDep)
        assert isinstance(m.deps[2], LocalDep)
        assert isinstance(m.deps[3], TarballDep)

    def test_dev_deps_independent_namespace(self) -> None:
        """Same name in deps and dev-deps is valid (independent namespaces)."""
        text = textwrap.dedent("""\
            name "project"
            deps {
                foo git=(url)"https://github.com/x/foo.git" ref="main"
            }
            dev-deps {
                foo git=(url)"https://github.com/x/foo.git" ref="main"
            }
        """)
        m = parse_manifest(text)
        assert len(m.deps) == 1
        assert len(m.dev_deps) == 1

    def test_dev_deps_duplicate_within_block_raises(self) -> None:
        """Duplicate in dev-deps raises MAN-DEP-DUPLICATE."""
        text = textwrap.dedent("""\
            name "project"
            dev-deps {
                foo git=(url)"https://github.com/x/foo.git" ref="main"
                foo git=(url)"https://github.com/y/foo.git" ref="main"
            }
        """)
        assert_slug(text, E.MAN_DEP_DUPLICATE)

    def test_member_dep_in_deps_block(self) -> None:
        """member dep in a deps block works and is disambiguated correctly."""
        text = 'name "x"\ndeps {\n    member "intonaco"\n}\n'
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, MemberDep)
        assert dep.name == "intonaco"

    def test_overrides_block_accepted_without_error(self) -> None:
        """Overrides block (3c-6) is accepted without raising (seam is open)."""
        text = textwrap.dedent("""\
            name "x"
            overrides {
            }
        """)
        m = parse_manifest(text)
        assert m.name == "x"

    def test_mirrors_block_accepted_without_error(self) -> None:
        """Mirrors block (3c-5) is accepted without raising (seam is open)."""
        text = textwrap.dedent("""\
            name "x"
            mirrors {
            }
        """)
        m = parse_manifest(text)
        assert m.name == "x"

    def test_flags_block_accepted_without_error(self) -> None:
        """Flags block (3c-8) is accepted without raising (seam is open)."""
        text = textwrap.dedent("""\
            name "x"
            flags {
            }
        """)
        m = parse_manifest(text)
        assert m.name == "x"


# ---------------------------------------------------------------------------
# 3c-5 — Mirrors (UrlDep child + top-level block)
# ---------------------------------------------------------------------------


class TestMirrorsParse:
    """3c-5: mirror child on UrlDep + top-level mirrors block."""

    def test_url_dep_single_mirror(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://primary/foo.git" ref="main" {
                    mirror (url)"https://backup/foo.git"
                }
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.mirrors == ("https://backup/foo.git",)

    def test_url_dep_multiple_mirrors(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://primary/foo.git" ref="main" {
                    mirror (url)"https://backup1/foo.git"
                    mirror (url)"https://backup2/foo.git"
                }
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert len(dep.mirrors) == 2
        assert dep.mirrors[0] == "https://backup1/foo.git"
        assert dep.mirrors[1] == "https://backup2/foo.git"

    def test_url_dep_plain_string_mirror(self) -> None:
        """Plain string mirror (no (url) annotation) is accepted per §2."""
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://a/foo.git" ref="main" {
                    mirror "https://b/foo.git"
                }
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.mirrors == ("https://b/foo.git",)

    def test_dep_mirror_arity_corpus(self) -> None:
        """Corpus fixture 025: MAN-DEP-MIRROR-ARITY (mirror with no arg)."""
        text = fixture_kdl("fixture-025-man-dep-mirror-arity")
        expected = fixture_error("fixture-025-man-dep-mirror-arity")
        assert_slug(text, expected)

    def test_dep_mirror_non_url_arg_raises_url_arg_type(self) -> None:
        """Corpus fixture 060: mirror with non-string arg → MAN-URL-ARG-TYPE."""
        text = fixture_kdl("fixture-060-man-url-arg-type")
        expected = fixture_error("fixture-060-man-url-arg-type")
        assert_slug(text, expected)

    def test_top_level_mirrors_block_valid(self) -> None:
        text = textwrap.dedent("""\
            name "mypkg"
            mirrors {
                mirror (url)"https://mirror1.example.com/mypkg.git"
                mirror (url)"https://mirror2.example.com/mypkg.git"
            }
        """)
        m = parse_manifest(text)
        assert m.self_mirrors == (
            "https://mirror1.example.com/mypkg.git",
            "https://mirror2.example.com/mypkg.git",
        )

    def test_top_level_mirrors_empty_block(self) -> None:
        text = 'name "mypkg"\nmirrors {\n}\n'
        m = parse_manifest(text)
        assert m.self_mirrors == ()

    def test_mirrors_unknown_child_corpus(self) -> None:
        """Corpus fixture 053: MAN-MIRRORS-UNKNOWN-CHILD (non-mirror child)."""
        text = fixture_kdl("fixture-053-man-mirrors-unknown-child")
        expected = fixture_error("fixture-053-man-mirrors-unknown-child")
        assert_slug(text, expected)

    def test_mirrors_arity_corpus(self) -> None:
        """Corpus fixture 054: MAN-MIRRORS-ARITY (mirror child with no URL arg)."""
        text = fixture_kdl("fixture-054-man-mirrors-arity")
        expected = fixture_error("fixture-054-man-mirrors-arity")
        assert_slug(text, expected)


# ---------------------------------------------------------------------------
# 3c-6 — Overrides block
# ---------------------------------------------------------------------------


class TestOverridesParse:
    """3c-6: overrides block — valid parse + MAN-OVERRIDE-* errors."""

    def test_valid_override(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "somelib" git=(url)"https://our-fork.example.com/somelib.git" ref="main"
            }
        """)
        m = parse_manifest(text)
        assert len(m.overrides) == 1
        ov = m.overrides[0]
        assert isinstance(ov, Override)
        assert ov.name == "somelib"
        assert isinstance(ov.target, GitTarget)
        assert ov.target.git == "https://our-fork.example.com/somelib.git"
        assert ov.target.ref == "main"

    def test_multiple_overrides(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "a" git=(url)"https://a/a.git" ref="v1"
                pkg "b" git=(url)"https://b/b.git" ref="main"
            }
        """)
        m = parse_manifest(text)
        assert len(m.overrides) == 2
        assert m.overrides[0].name == "a"
        assert m.overrides[1].name == "b"

    def test_valid_local_override(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "results" local="../results-fork"
            }
        """)
        m = parse_manifest(text)
        assert len(m.overrides) == 1
        ov = m.overrides[0]
        assert ov.name == "results"
        assert isinstance(ov.target, LocalTarget)
        assert ov.target.path == "../results-fork"

    def test_valid_member_override(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "stew" {
                    member "stew"
                }
            }
        """)
        m = parse_manifest(text)
        assert len(m.overrides) == 1
        ov = m.overrides[0]
        assert ov.name == "stew"
        assert isinstance(ov.target, MemberTarget)
        assert ov.target.member_name == "stew"

    def test_override_target_ambiguous_mixed(self) -> None:
        """MAN-OVERRIDE-TARGET-AMBIGUOUS when local= and git= both present."""
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "mylib" local="../mylib" git=(url)"https://example.com/mylib.git" ref="main"
            }
        """)
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(text)
        assert exc_info.value.slug == "MAN-OVERRIDE-TARGET-AMBIGUOUS"

    def test_override_target_ambiguous_none(self) -> None:
        """MAN-OVERRIDE-TARGET-AMBIGUOUS when no target form is present."""
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "mylib"
            }
        """)
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(text)
        assert exc_info.value.slug == "MAN-OVERRIDE-TARGET-AMBIGUOUS"

    def test_empty_overrides_block(self) -> None:
        text = 'name "x"\noverrides {\n}\n'
        m = parse_manifest(text)
        assert m.overrides == ()

    def test_override_kind_corpus(self) -> None:
        """Corpus fixture 032: MAN-OVERRIDE-KIND (unknown override kind)."""
        text = fixture_kdl("fixture-032-man-override-kind")
        expected = fixture_error("fixture-032-man-override-kind")
        assert_slug(text, expected)

    def test_override_arity_corpus(self) -> None:
        """Corpus fixture 033: MAN-OVERRIDE-ARITY (pkg with no positional arg)."""
        text = fixture_kdl("fixture-033-man-override-arity")
        expected = fixture_error("fixture-033-man-override-arity")
        assert_slug(text, expected)

    def test_override_unknown_props_corpus(self) -> None:
        """Corpus fixture 034: MAN-OVERRIDE-UNKNOWN-PROPS."""
        text = fixture_kdl("fixture-034-man-override-unknown-props")
        expected = fixture_error("fixture-034-man-override-unknown-props")
        assert_slug(text, expected)

    def test_override_git_missing_corpus(self) -> None:
        """Corpus fixture 035: MAN-OVERRIDE-GIT-MISSING."""
        text = fixture_kdl("fixture-035-man-override-git-missing")
        expected = fixture_error("fixture-035-man-override-git-missing")
        assert_slug(text, expected)

    def test_override_ref_missing_corpus(self) -> None:
        """Corpus fixture 036: MAN-OVERRIDE-REF-MISSING."""
        text = fixture_kdl("fixture-036-man-override-ref-missing")
        expected = fixture_error("fixture-036-man-override-ref-missing")
        assert_slug(text, expected)

    def test_override_duplicate_corpus(self) -> None:
        """Corpus fixture 037: MAN-OVERRIDE-DUPLICATE."""
        text = fixture_kdl("fixture-037-man-override-duplicate")
        expected = fixture_error("fixture-037-man-override-duplicate")
        assert_slug(text, expected)

    def test_override_target_ambiguous_corpus_mixed(self) -> None:
        """Corpus fixture 203: MAN-OVERRIDE-TARGET-AMBIGUOUS (mixed forms)."""
        text = fixture_kdl("fixture-203-man-override-target-ambiguous")
        expected = fixture_error("fixture-203-man-override-target-ambiguous")
        assert_slug(text, expected)

    def test_override_target_ambiguous_corpus_none(self) -> None:
        """Corpus fixture 204: MAN-OVERRIDE-TARGET-AMBIGUOUS (zero forms)."""
        text = fixture_kdl("fixture-204-man-override-target-ambiguous-none")
        expected = fixture_error("fixture-204-man-override-target-ambiguous-none")
        assert_slug(text, expected)

    def test_workspace_overrides_valid(self) -> None:
        """Workspace manifests may also carry overrides."""
        text = textwrap.dedent("""\
            workspace {
                member "pkgA"
                member "pkgB"
            }
            overrides {
                pkg "shared" git=(url)"https://our-fork.example.com/shared.git" ref="main"
            }
        """)
        wm = parse_workspace_or_manifest(text)
        assert isinstance(wm, WorkspaceManifest)
        assert len(wm.overrides) == 1
        assert wm.overrides[0].name == "shared"


# ---------------------------------------------------------------------------
# 3c-7 — Predicates as data (representation only, no eval)
# ---------------------------------------------------------------------------


class TestPredicatesAsData:
    """3c-7: predicate parsing produces typed Predicate dataclasses — no eval."""

    def test_inline_predicate_platform(self) -> None:
        """Inline platform predicate parses to typed Predicate(name='platform', ...)."""
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://a/foo.git" ref="main" platform="linux"
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert len(dep.predicates) == 1
        p = dep.predicates[0]
        assert p.name == "platform"
        assert p.values == ("linux",)
        assert p.negated is False

    def test_inline_predicate_negated(self) -> None:
        """(not)-annotated inline predicate → negated=True."""
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://a/foo.git" ref="main" platform=(not)"windows"
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert len(dep.predicates) == 1
        p = dep.predicates[0]
        assert p.name == "platform"
        assert p.values == ("windows",)
        assert p.negated is True

    def test_child_predicate_multi_value(self) -> None:
        """Child-node predicate form: multiple values → OR semantics (data only)."""
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://a/foo.git" ref="main" {
                    platform "linux" "macosx"
                }
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert len(dep.predicates) == 1
        p = dep.predicates[0]
        assert p.name == "platform"
        assert p.values == ("linux", "macosx")
        assert p.negated is False

    def test_child_predicate_negated_multi_value(self) -> None:
        """Child-node form with all (not)-annotated values → negated=True."""
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://a/foo.git" ref="main" {
                    platform (not)"windows" (not)"freebsd"
                }
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        p = dep.predicates[0]
        assert p.values == ("windows", "freebsd")
        assert p.negated is True

    def test_multiple_predicates_are_data(self) -> None:
        """Multiple predicates stored as a tuple — no evaluation occurs at parse time."""
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://a/foo.git" ref="main" platform="linux" arch="amd64"
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        # Two predicates, order preserved from property scan.
        pred_names = {p.name for p in dep.predicates}
        assert "platform" in pred_names
        assert "arch" in pred_names
        # No evaluation: dep is present regardless of runtime platform.
        assert len(dep.predicates) == 2

    def test_when_block_predicates_inherited(self) -> None:
        """Deps inside a when { } block inherit the when node's predicates."""
        text = textwrap.dedent("""\
            name "x"
            deps {
                when platform="linux" {
                    foo git=(url)"https://a/foo.git" ref="main"
                }
            }
        """)
        m = parse_manifest(text)
        assert len(m.deps) == 1
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert len(dep.predicates) == 1
        p = dep.predicates[0]
        assert p.name == "platform"
        assert p.values == ("linux",)

    def test_predicate_unknown_corpus(self) -> None:
        """Corpus fixture 046: MAN-PREDICATE-UNKNOWN (unknown predicate key in when)."""
        text = fixture_kdl("fixture-046-man-predicate-unknown")
        expected = fixture_error("fixture-046-man-predicate-unknown")
        assert_slug(text, expected)

    def test_predicate_value_type_corpus(self) -> None:
        """Corpus fixture 047: MAN-PREDICATE-VALUE-TYPE (int instead of string)."""
        text = fixture_kdl("fixture-047-man-predicate-value-type")
        expected = fixture_error("fixture-047-man-predicate-value-type")
        assert_slug(text, expected)

    def test_predicate_unsupported_annotation_corpus(self) -> None:
        """Corpus fixture 048: MAN-PREDICATE-UNSUPPORTED-ANNOTATION (weird tag)."""
        text = fixture_kdl("fixture-048-man-predicate-unsupported-annotation")
        expected = fixture_error("fixture-048-man-predicate-unsupported-annotation")
        assert_slug(text, expected)

    def test_predicate_child_no_args_corpus(self) -> None:
        """Corpus fixture 049: MAN-PREDICATE-CHILD-NO-ARGS (predicate child with no values)."""
        text = fixture_kdl("fixture-049-man-predicate-child-no-args")
        expected = fixture_error("fixture-049-man-predicate-child-no-args")
        assert_slug(text, expected)

    def test_predicate_child_arg_type_corpus(self) -> None:
        """Corpus fixture 050: MAN-PREDICATE-CHILD-ARG-TYPE (non-string arg in child predicate)."""
        text = fixture_kdl("fixture-050-man-predicate-child-arg-type")
        expected = fixture_error("fixture-050-man-predicate-child-arg-type")
        assert_slug(text, expected)

    def test_predicate_mixed_negation_corpus(self) -> None:
        """Corpus fixture 051: MAN-PREDICATE-MIXED-NEGATION (mixed bare/negated values)."""
        text = fixture_kdl("fixture-051-man-predicate-mixed-negation")
        expected = fixture_error("fixture-051-man-predicate-mixed-negation")
        assert_slug(text, expected)

    def test_predicate_form_conflict_corpus(self) -> None:
        """Corpus fixture 052: MAN-PREDICATE-FORM-CONFLICT (same key inline + child)."""
        text = fixture_kdl("fixture-052-man-predicate-form-conflict")
        expected = fixture_error("fixture-052-man-predicate-form-conflict")
        assert_slug(text, expected)

    def test_predicates_are_data_not_evaluated(self) -> None:
        """Verify predicates are stored as-is — evaluation is NOT performed at parse.

        Even an impossible predicate (platform=never_matches) produces a valid
        Predicate dataclass.  No boolean short-circuit, no dep filtering here.
        """
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://a/foo.git" ref="main" platform="never_matches"
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert len(dep.predicates) == 1
        assert dep.predicates[0].values == ("never_matches",)
        # dep is NOT filtered — filtering is the resolver's job.


# ---------------------------------------------------------------------------
# 3c-8 — Flags declarations + consumer flag requests
# ---------------------------------------------------------------------------


class TestFlagsParse:
    """3c-8: flags block (FlagDecl) + UrlDep flag child nodes (FlagRequest)."""

    def test_flag_decl_minimal(self) -> None:
        text = 'name "x"\nflags {\n    ssl\n}\n'
        m = parse_manifest(text)
        assert len(m.flags) == 1
        fd = m.flags[0]
        assert isinstance(fd, FlagDecl)
        assert fd.name == "ssl"
        assert fd.default is False
        assert fd.description == ""
        assert fd.defines == ()

    def test_flag_decl_with_default_true(self) -> None:
        text = 'name "x"\nflags {\n    ssl default=#true\n}\n'
        m = parse_manifest(text)
        assert m.flags[0].default is True

    def test_flag_decl_with_description(self) -> None:
        text = 'name "x"\nflags {\n    ssl description="Enable SSL support"\n}\n'
        m = parse_manifest(text)
        assert m.flags[0].description == "Enable SSL support"

    def test_flag_decl_with_defines(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            flags {
                ssl {
                    defines "-d:sslEnabled" "-d:useOpenssl"
                }
            }
        """)
        m = parse_manifest(text)
        assert m.flags[0].defines == ("-d:sslEnabled", "-d:useOpenssl")

    def test_flag_decl_full(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            flags {
                ssl default=#true description="TLS support" {
                    defines "-d:ssl"
                }
            }
        """)
        m = parse_manifest(text)
        fd = m.flags[0]
        assert fd.name == "ssl"
        assert fd.default is True
        assert fd.description == "TLS support"
        assert fd.defines == ("-d:ssl",)

    def test_multiple_flag_decls(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            flags {
                ssl
                json default=#false
                simd default=#true description="SIMD support"
            }
        """)
        m = parse_manifest(text)
        assert len(m.flags) == 3
        names = [f.name for f in m.flags]
        assert names == ["ssl", "json", "simd"]

    def test_flag_duplicate_corpus(self) -> None:
        """Corpus fixture 038: MAN-FLAG-DUPLICATE."""
        text = fixture_kdl("fixture-038-man-flag-duplicate")
        expected = fixture_error("fixture-038-man-flag-duplicate")
        assert_slug(text, expected)

    def test_flag_pos_args_corpus(self) -> None:
        """Corpus fixture 039: MAN-FLAG-POS-ARGS (positional arg on flag node)."""
        text = fixture_kdl("fixture-039-man-flag-pos-args")
        expected = fixture_error("fixture-039-man-flag-pos-args")
        assert_slug(text, expected)

    def test_flag_unknown_props_corpus(self) -> None:
        """Corpus fixture 040: MAN-FLAG-UNKNOWN-PROPS."""
        text = fixture_kdl("fixture-040-man-flag-unknown-props")
        expected = fixture_error("fixture-040-man-flag-unknown-props")
        assert_slug(text, expected)

    def test_flag_default_type_corpus(self) -> None:
        """Corpus fixture 041: MAN-FLAG-DEFAULT-TYPE (non-bool default)."""
        text = fixture_kdl("fixture-041-man-flag-default-type")
        expected = fixture_error("fixture-041-man-flag-default-type")
        assert_slug(text, expected)

    def test_flag_description_type_corpus(self) -> None:
        """Corpus fixture 042: MAN-FLAG-DESCRIPTION-TYPE (non-string description)."""
        text = fixture_kdl("fixture-042-man-flag-description-type")
        expected = fixture_error("fixture-042-man-flag-description-type")
        assert_slug(text, expected)

    def test_flag_unknown_child_corpus(self) -> None:
        """Corpus fixture 043: MAN-FLAG-UNKNOWN-CHILD (unknown child node)."""
        text = fixture_kdl("fixture-043-man-flag-unknown-child")
        expected = fixture_error("fixture-043-man-flag-unknown-child")
        assert_slug(text, expected)

    def test_flag_defines_arg_type_corpus(self) -> None:
        """Corpus fixture 044: MAN-FLAG-DEFINES-ARG-TYPE (non-string defines arg)."""
        text = fixture_kdl("fixture-044-man-flag-defines-arg-type")
        expected = fixture_error("fixture-044-man-flag-defines-arg-type")
        assert_slug(text, expected)

    def test_flag_undeclared_reference_corpus(self) -> None:
        """Corpus fixture 045: MAN-FLAG-UNDECLARED-REFERENCE.

        when flag="undeclared" references a flag not in the flags block.
        """
        text = fixture_kdl("fixture-045-man-flag-undeclared-reference")
        expected = fixture_error("fixture-045-man-flag-undeclared-reference")
        assert_slug(text, expected)

    def test_flag_request_in_url_dep_enable(self) -> None:
        """Consumer flag request on UrlDep: flag "ssl" → enabled=True."""
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://a/foo.git" ref="main" {
                    flag "ssl"
                }
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert len(dep.flag_requests) == 1
        fr = dep.flag_requests[0]
        assert isinstance(fr, FlagRequest)
        assert fr.name == "ssl"
        assert fr.enabled is True

    def test_flag_request_in_url_dep_disable(self) -> None:
        """Consumer flag request: flag "ssl" #false → enabled=False."""
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://a/foo.git" ref="main" {
                    flag "ssl" #false
                }
            }
        """)
        m = parse_manifest(text)
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        assert dep.flag_requests[0].enabled is False

    def test_dep_flag_name_missing_corpus(self) -> None:
        """Corpus fixture 026: MAN-DEP-FLAG-NAME-MISSING."""
        text = fixture_kdl("fixture-026-man-dep-flag-name-missing")
        expected = fixture_error("fixture-026-man-dep-flag-name-missing")
        assert_slug(text, expected)

    def test_dep_flag_too_many_args_corpus(self) -> None:
        """Corpus fixture 027: MAN-DEP-FLAG-TOO-MANY-ARGS."""
        text = fixture_kdl("fixture-027-man-dep-flag-too-many-args")
        expected = fixture_error("fixture-027-man-dep-flag-too-many-args")
        assert_slug(text, expected)

    def test_dep_flag_bool_corpus(self) -> None:
        """Corpus fixture 028: MAN-DEP-FLAG-BOOL (non-bool second arg)."""
        text = fixture_kdl("fixture-028-man-dep-flag-bool")
        expected = fixture_error("fixture-028-man-dep-flag-bool")
        assert_slug(text, expected)

    def test_declared_flag_is_reachable_by_predicate(self) -> None:
        """A flag predicate referencing a declared flag does NOT raise."""
        text = textwrap.dedent("""\
            name "x"
            flags {
                json default=#false
            }
            deps {
                when flag="json" {
                    foo git=(url)"https://a/foo.git" ref="main"
                }
            }
        """)
        m = parse_manifest(text)
        assert len(m.deps) == 1
        dep = m.deps[0]
        assert isinstance(dep, UrlDep)
        flag_preds = [p for p in dep.predicates if p.name == "flag"]
        assert len(flag_preds) == 1
        assert flag_preds[0].values == ("json",)


# ---------------------------------------------------------------------------
# 3c-9 — spec-version, dev-deps, cas, unknown-top-level (exhaustive dispatch)
# ---------------------------------------------------------------------------


class TestTopLevelNodeDispatch:
    """3c-9: spec-version, dev-deps, cas nodes + exhaustive unknown-top-level."""

    def test_spec_version_explicit(self) -> None:
        text = 'spec-version 1\nname "x"\n'
        m = parse_manifest(text)
        assert m.spec_version == 1
        assert m.spec_version_explicit is True

    def test_spec_version_absent_defaults_to_1(self) -> None:
        text = 'name "x"\n'
        m = parse_manifest(text)
        assert m.spec_version == 1
        assert m.spec_version_explicit is False

    def test_spec_version_type_corpus(self) -> None:
        """Corpus fixture 102: MAN-SPEC-VERSION-TYPE (string instead of int)."""
        text = fixture_kdl("fixture-102-man-spec-version-type")
        expected = fixture_error("fixture-102-man-spec-version-type")
        assert_slug(text, expected)

    def test_spec_version_unsupported_corpus(self) -> None:
        """Corpus fixture 103: MAN-SPEC-VERSION-UNSUPPORTED (epoch > supported)."""
        text = fixture_kdl("fixture-103-man-spec-version-unsupported")
        expected = fixture_error("fixture-103-man-spec-version-unsupported")
        assert_slug(text, expected)

    def test_spec_version_zero_raises_type(self) -> None:
        """spec-version 0 (< 1) → MAN-SPEC-VERSION-TYPE."""
        assert_slug("spec-version 0\nname \"x\"\n", E.MAN_SPEC_VERSION_TYPE)

    def test_dev_deps_parsed(self) -> None:
        """dev-deps block is populated separately from deps."""
        text = textwrap.dedent("""\
            name "x"
            deps {
                foo git=(url)"https://a/foo.git" ref="main"
            }
            dev-deps {
                testhelper git=(url)"https://a/helper.git" ref="main"
            }
        """)
        m = parse_manifest(text)
        assert len(m.deps) == 1
        assert len(m.dev_deps) == 1
        assert isinstance(m.dev_deps[0], UrlDep)
        assert m.dev_deps[0].name == "testhelper"

    def test_dev_deps_empty_when_absent(self) -> None:
        m = parse_manifest('name "x"\n')
        assert m.dev_deps == ()

    def test_dev_deps_accepts_all_dep_forms(self) -> None:
        """dev-deps accepts the same grammar as deps."""
        text = textwrap.dedent("""\
            name "x"
            dev-deps {
                a git=(url)"https://a/a.git" ref="main"
                b ">= 1.0.0"
                c local="../c"
                d tarball=(url)"https://example.com/d.tar.gz"
            }
        """)
        m = parse_manifest(text)
        assert len(m.dev_deps) == 4
        from milpa.manifest import LocalDep, NamedDep, TarballDep, UrlDep

        assert isinstance(m.dev_deps[0], UrlDep)
        assert isinstance(m.dev_deps[1], NamedDep)
        assert isinstance(m.dev_deps[2], LocalDep)
        assert isinstance(m.dev_deps[3], TarballDep)

    def test_cas_dir_parsed(self) -> None:
        text = 'name "x"\ncas {\n    dir "/home/user/.milpa"\n}\n'
        m = parse_manifest(text)
        assert m.cas_dir == "/home/user/.milpa"

    def test_cas_dir_absent_defaults_empty(self) -> None:
        m = parse_manifest('name "x"\n')
        assert m.cas_dir == ""

    def test_unknown_top_level_corpus(self) -> None:
        """Corpus fixture 009: MAN-UNKNOWN-TOP-LEVEL."""
        text = fixture_kdl("fixture-009-man-unknown-top-level")
        expected = fixture_error("fixture-009-man-unknown-top-level")
        assert_slug(text, expected)

    def test_dispatch_is_exhaustive(self) -> None:
        """All recognized top-level nodes parse cleanly — no 'pass' placeholders."""
        text = textwrap.dedent("""\
            spec-version 1
            name "fullyloaded"
            kind "application"
            src_dir "src"
            deps {
                a git=(url)"https://a/a.git" ref="main"
            }
            dev-deps {
                b git=(url)"https://b/b.git" ref="main"
            }
            overrides {
                pkg "a" git=(url)"https://override/a.git" ref="v2"
            }
            flags {
                ssl default=#false
            }
            mirrors {
                mirror (url)"https://backup/fullyloaded.git"
            }
            cas {
                dir "/tmp/cas"
            }
        """)
        m = parse_manifest(text)
        assert m.name == "fullyloaded"
        assert m.kind == "application"
        assert m.src_dir == "src"
        assert len(m.deps) == 1
        assert len(m.dev_deps) == 1
        assert len(m.overrides) == 1
        assert len(m.flags) == 1
        assert len(m.self_mirrors) == 1
        assert m.cas_dir == "/tmp/cas"
        assert m.spec_version_explicit is True


# ---------------------------------------------------------------------------
# 3d — Workspace manifest grammar
# ---------------------------------------------------------------------------


class TestWorkspaceManifestParse:
    """3d: workspace manifest grammar + MAN-WORKSPACE-* error codes."""

    def test_valid_workspace_empty(self) -> None:
        """Minimal workspace with empty member list."""
        text = 'workspace {\n}\n'
        result = parse_workspace_or_manifest(text)
        assert isinstance(result, WorkspaceManifest)
        assert result.members == ()
        assert result.overrides == ()

    def test_valid_workspace_with_members(self) -> None:
        text = textwrap.dedent("""\
            workspace {
                member "pkgA"
                member "pkgB"
                member "libs/pkgC"
            }
        """)
        result = parse_workspace_or_manifest(text)
        assert isinstance(result, WorkspaceManifest)
        assert result.members == ("pkgA", "pkgB", "libs/pkgC")

    def test_workspace_with_name(self) -> None:
        text = textwrap.dedent("""\
            name "myworkspace"
            workspace {
                member "pkgA"
            }
        """)
        result = parse_workspace_or_manifest(text)
        assert isinstance(result, WorkspaceManifest)
        assert result.name == "myworkspace"

    def test_workspace_with_overrides(self) -> None:
        """Workspace may carry a top-level overrides block."""
        text = textwrap.dedent("""\
            workspace {
                member "pkgA"
            }
            overrides {
                pkg "dep" git=(url)"https://a/dep.git" ref="main"
            }
        """)
        result = parse_workspace_or_manifest(text)
        assert isinstance(result, WorkspaceManifest)
        assert len(result.overrides) == 1
        assert result.overrides[0].name == "dep"

    def test_workspace_with_spec_version(self) -> None:
        text = textwrap.dedent("""\
            spec-version 1
            workspace {
                member "pkgA"
            }
        """)
        result = parse_workspace_or_manifest(text)
        assert isinstance(result, WorkspaceManifest)

    def test_workspace_has_deps_or_kind_corpus(self) -> None:
        """Corpus fixture 055: MAN-WORKSPACE-HAS-DEPS-OR-KIND."""
        text = fixture_kdl("fixture-055-man-workspace-has-deps-or-kind")
        expected = fixture_error("fixture-055-man-workspace-has-deps-or-kind")
        assert_slug_ws(text, expected)

    def test_workspace_unknown_node_corpus(self) -> None:
        """Corpus fixture 056: MAN-WORKSPACE-UNKNOWN-NODE."""
        text = fixture_kdl("fixture-056-man-workspace-unknown-node")
        expected = fixture_error("fixture-056-man-workspace-unknown-node")
        assert_slug_ws(text, expected)

    def test_workspace_member_arity_corpus(self) -> None:
        """Corpus fixture 057: MAN-WORKSPACE-MEMBER-ARITY (member with no arg)."""
        text = fixture_kdl("fixture-057-man-workspace-member-arity")
        expected = fixture_error("fixture-057-man-workspace-member-arity")
        assert_slug_ws(text, expected)

    def test_workspace_member_duplicate_corpus(self) -> None:
        """Corpus fixture 058: MAN-WORKSPACE-MEMBER-DUPLICATE."""
        text = fixture_kdl("fixture-058-man-workspace-member-duplicate")
        expected = fixture_error("fixture-058-man-workspace-member-duplicate")
        assert_slug_ws(text, expected)

    def test_workspace_unknown_top_level_corpus(self) -> None:
        """Corpus fixture 059: MAN-WORKSPACE-UNKNOWN-TOP-LEVEL."""
        text = fixture_kdl("fixture-059-man-workspace-unknown-top-level")
        expected = fixture_error("fixture-059-man-workspace-unknown-top-level")
        assert_slug_ws(text, expected)

    def test_workspace_spec_version_unsupported(self) -> None:
        """Workspace manifest with epoch > supported → MAN-SPEC-VERSION-UNSUPPORTED."""
        text = 'spec-version 99\nworkspace {\n}\n'
        assert_slug_ws(text, E.MAN_SPEC_VERSION_UNSUPPORTED)

    def test_document_without_workspace_node_is_package(self) -> None:
        """No workspace node → auto-detected as package manifest."""
        text = 'name "pkg"\n'
        result = parse_workspace_or_manifest(text)
        assert isinstance(result, Manifest)
        assert result.name == "pkg"

    def test_workspace_has_deps_direct_package_manifest(self) -> None:
        """A package manifest with 'workspace' node → MAN-WORKSPACE-HAS-DEPS-OR-KIND."""
        text = textwrap.dedent("""\
            name "x"
            workspace {
                member "y"
            }
        """)
        assert_slug(text, E.MAN_WORKSPACE_HAS_DEPS_OR_KIND)

    # S11 (RFC #23 §3.8): workspace-root flags {} ------------------------------------------

    def test_workspace_flags_field_exists_default_empty(self) -> None:
        """WorkspaceManifest.flags defaults to () — backward compatible."""
        text = 'workspace {\n    member "pkgA"\n}\n'
        result = parse_workspace_or_manifest(text)
        assert isinstance(result, WorkspaceManifest)
        assert result.flags == ()

    def test_workspace_flags_parsed(self) -> None:
        """Workspace root may declare a flags {} block (S11 §3.8)."""
        text = textwrap.dedent("""\
            workspace {
                member "pkgA"
            }
            flags {
                tls default=#true {
                    enables {
                        chronos { flag "tls" }
                    }
                }
            }
        """)
        result = parse_workspace_or_manifest(text)
        assert isinstance(result, WorkspaceManifest)
        assert len(result.flags) == 1
        fd = result.flags[0]
        assert fd.name == "tls"
        assert fd.default is True

    def test_workspace_flags_reuses_flag_decl_type(self) -> None:
        """WorkspaceManifest.flags elements are FlagDecl (SSOT — no parallel type)."""
        from milpa.manifest import FlagDecl
        text = textwrap.dedent("""\
            workspace {
                member "m"
            }
            flags {
                http default=#false
            }
        """)
        result = parse_workspace_or_manifest(text)
        assert isinstance(result, WorkspaceManifest)
        assert len(result.flags) == 1
        assert isinstance(result.flags[0], FlagDecl)

    def test_workspace_flags_enables_cross_pkg(self) -> None:
        """Workspace-root flag enables cross-pkg requests are parsed correctly."""
        text = textwrap.dedent("""\
            workspace {
                member "pkgA"
            }
            flags {
                full default=#true {
                    enables {
                        chronos { flag "tls" }
                    }
                }
            }
        """)
        result = parse_workspace_or_manifest(text)
        assert isinstance(result, WorkspaceManifest)
        fd = result.flags[0]
        assert fd.name == "full"
        assert len(fd.enables_cross_pkg) == 1
        assert fd.enables_cross_pkg[0].dep == "chronos"

    def test_workspace_flags_round_trip_via_package_parser(self) -> None:
        """flags {} in a workspace is parsed by the same _parse_flags_block as package manifests."""
        # This test verifies SSOT: no parallel parser for workspace flags.
        text = textwrap.dedent("""\
            workspace {
                member "m"
            }
            flags {
                opt default=#false { defines "OPT" }
            }
        """)
        result = parse_workspace_or_manifest(text)
        assert isinstance(result, WorkspaceManifest)
        assert result.flags[0].defines == ("OPT",)


# ---------------------------------------------------------------------------
# S1 — enables/conflicts grammar (RFC #23 §3.1.1 and §3.1.4)
# ---------------------------------------------------------------------------


class TestFlagEnablesConflicts:
    """S1: FlagDecl.enables (same-pkg + cross-pkg) and FlagDecl.conflicts parsing."""

    def test_flag_decl_has_enables_field(self) -> None:
        """FlagDecl gains enables_same_pkg + enables_cross_pkg + conflicts fields."""
        text = 'name "x"\nflags {\n    tls\n}\n'
        m = parse_manifest(text)
        fd = m.flags[0]
        assert hasattr(fd, "enables_same_pkg")
        assert hasattr(fd, "enables_cross_pkg")
        assert hasattr(fd, "conflicts")
        assert fd.enables_same_pkg == ()
        assert fd.enables_cross_pkg == ()
        assert fd.conflicts == ()

    def test_enables_same_pkg_bare_string_args(self) -> None:
        """enables "tls" "http" → enables_same_pkg == ("tls", "http")."""
        text = textwrap.dedent("""\
            name "x"
            flags {
                tls
                http
                full {
                    enables "tls" "http"
                }
            }
        """)
        m = parse_manifest(text)
        full = next(f for f in m.flags if f.name == "full")
        assert full.enables_same_pkg == ("tls", "http")
        assert full.enables_cross_pkg == ()

    def test_enables_cross_pkg_child_node(self) -> None:
        """enables { chronos { flag "tls" } } → enables_cross_pkg has one entry."""
        text = textwrap.dedent("""\
            name "x"
            flags {
                full {
                    enables {
                        chronos { flag "tls" }
                    }
                }
            }
        """)
        m = parse_manifest(text)
        full = m.flags[0]
        assert full.enables_same_pkg == ()
        assert len(full.enables_cross_pkg) == 1
        cross = full.enables_cross_pkg[0]
        assert cross.dep == "chronos"
        assert len(cross.flag_requests) == 1
        assert cross.flag_requests[0].name == "tls"
        assert cross.flag_requests[0].enabled is True

    def test_enables_mixed_args_and_children(self) -> None:
        """enables "tls" "http" { chronos { flag "tls" } } — one node, both scopes."""
        text = textwrap.dedent("""\
            name "x"
            flags {
                tls
                http
                full {
                    enables "tls" "http" {
                        chronos { flag "tls" }
                    }
                }
            }
        """)
        m = parse_manifest(text)
        full = next(f for f in m.flags if f.name == "full")
        assert full.enables_same_pkg == ("tls", "http")
        assert len(full.enables_cross_pkg) == 1
        assert full.enables_cross_pkg[0].dep == "chronos"

    def test_enables_repeated_nodes_union(self) -> None:
        """Two enables nodes union together into one same_pkg set (no dedup required for tuple)."""
        text = textwrap.dedent("""\
            name "x"
            flags {
                tls
                http
                full {
                    enables "tls"
                    enables "http"
                }
            }
        """)
        m = parse_manifest(text)
        full = next(f for f in m.flags if f.name == "full")
        # Union — order preserved across both nodes
        assert "tls" in full.enables_same_pkg
        assert "http" in full.enables_same_pkg

    def test_conflicts_bare_string_args(self) -> None:
        """conflicts "bearssl" → conflicts == ("bearssl",)."""
        text = textwrap.dedent("""\
            name "x"
            flags {
                openssl {
                    conflicts "bearssl"
                }
                bearssl
            }
        """)
        m = parse_manifest(text)
        openssl = next(f for f in m.flags if f.name == "openssl")
        assert openssl.conflicts == ("bearssl",)

    def test_enables_undeclared_same_pkg_raises(self) -> None:
        """enables names a flag not declared in this manifest → MAN-FLAG-ENABLES-UNDECLARED."""
        text = textwrap.dedent("""\
            name "x"
            flags {
                full {
                    enables "missing"
                }
            }
        """)
        assert_slug(text, E.MAN_FLAG_ENABLES_UNDECLARED)

    def test_enables_undeclared_dep_name_hint(self) -> None:
        """When the undeclared enables name matches a dep name, diagnostic hints at optional."""
        text = textwrap.dedent("""\
            name "x"
            flags {
                full {
                    enables "chronos"
                }
            }
            deps {
                chronos git=(url)"https://github.com/status-im/nim-chronos.git" ref="master"
            }
        """)
        with pytest.raises(E.MilpaError) as exc_info:
            parse_manifest(text)
        err = exc_info.value
        assert err.slug == E.MAN_FLAG_ENABLES_UNDECLARED
        # The message must mention the dep-name hint
        assert "dependency" in err.message or "optional" in err.message

    def test_enables_forward_reference_is_legal(self) -> None:
        """enables may name a flag declared LATER in the flags block (forward ref OK)."""
        text = textwrap.dedent("""\
            name "x"
            flags {
                full {
                    enables "tls"
                }
                tls
            }
        """)
        m = parse_manifest(text)  # must not raise
        full = m.flags[0]
        assert "tls" in full.enables_same_pkg

    def test_enables_cross_pkg_not_validated_at_parse(self) -> None:
        """Cross-package enables child dep names are NOT checked at parse time."""
        text = textwrap.dedent("""\
            name "x"
            flags {
                full {
                    enables {
                        unknown_dep { flag "tls" }
                    }
                }
            }
        """)
        m = parse_manifest(text)  # must not raise
        full = m.flags[0]
        assert full.enables_cross_pkg[0].dep == "unknown_dep"

    def test_flag_decl_with_enables_and_defines(self) -> None:
        """A flag may carry both defines and enables child nodes."""
        text = textwrap.dedent("""\
            name "x"
            flags {
                tls
                full {
                    defines "fullEnabled"
                    enables "tls"
                }
            }
        """)
        m = parse_manifest(text)
        full = next(f for f in m.flags if f.name == "full")
        assert full.defines == ("fullEnabled",)
        assert full.enables_same_pkg == ("tls",)

    def test_corpus_enables_accept(self) -> None:
        """Corpus fixture for parse-accept with enables + conflicts."""
        text = fixture_kdl("fixture-185-man-flag-enables-accept")
        m = parse_manifest(text)
        full = next(f for f in m.flags if f.name == "full")
        assert "tls" in full.enables_same_pkg
        assert len(full.enables_cross_pkg) == 1

    def test_corpus_enables_undeclared_error(self) -> None:
        """Corpus fixture for MAN-FLAG-ENABLES-UNDECLARED."""
        text = fixture_kdl("fixture-186-man-flag-enables-undeclared")
        expected = fixture_error("fixture-186-man-flag-enables-undeclared")
        assert_slug(text, expected)

    def test_corpus_enables_forward_reference(self) -> None:
        """Corpus fixture: forward reference in enables → accepted."""
        text = fixture_kdl("fixture-187-man-flag-enables-forward-ref")
        m = parse_manifest(text)  # must not raise
        full = next(f for f in m.flags if f.name == "full")
        assert "tls" in full.enables_same_pkg
