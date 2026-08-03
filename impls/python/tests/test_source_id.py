"""Example-based tests for ``milpa.source_id`` (rfc-origin-as-identity.md S1;
revised round-2.5, [[provenance_source_selection]]).

Covers: the closed union's one-way ``canonical()`` grammar per kind (NO
``parse()`` — the frozen dataclass is the authoritative representation), the
normative subpath escape guard, the ``pkg+`` variable-arity name-last grammar
(a host-qualified ``/``-bearing namespace is valid and distinct from having
no namespace), the OCI registry segment-boundary guard, and the
git-normalize three-tier rule (D4). Validation now lives in
``normalize_source`` (the sole boundary since ``parse()`` is gone). Property
tests (the injectivity law, adversarial near-collisions) live in
``test_source_id_properties.py``.
"""

from __future__ import annotations

import pytest

from milpa.errors import SRC_ID_MALFORMED, MilpaError
from milpa.source_id import (
    GitSourceId,
    LocalSourceId,
    MemberSourceId,
    OciSourceId,
    RegistrySourceId,
    SourceId,
    TarballSourceId,
    canonical,
    format_source_id,
    normalize_source,
)

# ---------------------------------------------------------------------------
# canonical() — one example per kind, matching the RFC §4.1 worked examples
# ---------------------------------------------------------------------------


class TestCanonicalPerKind:
    def test_git_no_subpath(self) -> None:
        sid = GitSourceId(url="https://github.com/coreyleavitt/nim-z3")
        assert canonical(sid) == "git+https://github.com/coreyleavitt/nim-z3"

    def test_git_with_subpath(self) -> None:
        sid = GitSourceId(
            url="https://github.com/facebook/react", subpath="packages/react-dom"
        )
        assert (
            canonical(sid)
            == "git+https://github.com/facebook/react#subdirectory=packages/react-dom"
        )

    def test_oci_no_subpath(self) -> None:
        sid = OciSourceId(registry="ghcr.io", repository="coreyleavitt/softlink")
        assert canonical(sid) == "oci+ghcr.io/coreyleavitt/softlink"

    def test_tarball(self) -> None:
        sid = TarballSourceId(url="https://example.com/dist/pkg-1.4.0.tar.gz")
        assert canonical(sid) == "tar+https://example.com/dist/pkg-1.4.0.tar.gz"

    def test_pkg_no_namespace(self) -> None:
        sid = RegistrySourceId(registry="tianguis", namespace=None, name="softlink")
        assert canonical(sid) == "pkg+tianguis/softlink"

    def test_pkg_with_namespace(self) -> None:
        sid = RegistrySourceId(registry="tianguis", namespace="acme", name="utils")
        assert canonical(sid) == "pkg+tianguis/acme/utils"

    def test_file_relative(self) -> None:
        sid = LocalSourceId(path="relative/path/from/workspace/root")
        assert canonical(sid) == "file+relative/path/from/workspace/root"

    def test_file_absolute(self) -> None:
        sid = LocalSourceId(path="/abs/path/outside/workspace")
        assert canonical(sid) == "file+/abs/path/outside/workspace"

    def test_member(self) -> None:
        sid = MemberSourceId(member_name="intonaco")
        assert canonical(sid) == "member+intonaco"


class TestCanonicalRegistryVariableArityNamespace:
    """RFC §4.1 round-2.5: `pkg+<alias>/<namespace>/<name>` is
    variable-arity, name-last — `<namespace>` MAY itself contain `/`
    (884/886 real tianguis namespaces are host-qualified)."""

    def test_host_qualified_namespace(self) -> None:
        sid = RegistrySourceId(registry="tianguis", namespace="codeberg.org/eris", name="mypkg")
        assert canonical(sid) == "pkg+tianguis/codeberg.org/eris/mypkg"

    def test_host_qualified_namespace_distinct_from_no_namespace(self) -> None:
        with_ns = RegistrySourceId(registry="tianguis", namespace="codeberg.org/eris", name="mypkg")
        without_ns = RegistrySourceId(registry="tianguis", namespace=None, name="mypkg")
        assert with_ns != without_ns
        assert canonical(with_ns) != canonical(without_ns)

    def test_host_qualified_namespace_distinct_from_single_segment(self) -> None:
        two_seg = RegistrySourceId(registry="tianguis", namespace="codeberg.org/eris", name="mypkg")
        one_seg = RegistrySourceId(registry="tianguis", namespace="codeberg.org", name="mypkg")
        assert two_seg != one_seg
        assert canonical(two_seg) != canonical(one_seg)


class TestFormatSourceId:
    def test_includes_kind_label_and_canonical_string(self) -> None:
        sid = GitSourceId(url="https://github.com/coreyleavitt/nim-z3")
        msg = format_source_id(sid)
        assert "git" in msg.lower()
        assert canonical(sid) in msg

    def test_distinct_labels_per_kind(self) -> None:
        sids: list[SourceId] = [
            GitSourceId(url="https://x/y"),
            OciSourceId(registry="ghcr.io", repository="x/y"),
            TarballSourceId(url="https://x/y.tar.gz"),
            LocalSourceId(path="x/y"),
            RegistrySourceId(registry="tianguis", namespace=None, name="x"),
            MemberSourceId(member_name="x"),
        ]
        labels = {format_source_id(s).split(" '")[0] for s in sids}
        assert len(labels) == len(sids)  # every kind gets a distinct label


# ---------------------------------------------------------------------------
# normalize_source — git three-tier rule (D4)
# ---------------------------------------------------------------------------


class TestNormalizeGit:
    def test_kept_lowercase_scheme_host_strip_trailing_slash_and_dot_git(self) -> None:
        sid = normalize_source(GitSourceId(url="HTTPS://GitHub.com/Org/Repo.git/"))
        assert sid == GitSourceId(url="https://github.com/Org/Repo")

    def test_kept_path_case_preserved(self) -> None:
        sid = normalize_source(GitSourceId(url="https://github.com/CoreyLeavitt/Nim-Z3"))
        assert sid.url == "https://github.com/CoreyLeavitt/Nim-Z3"

    def test_added_strip_userinfo(self) -> None:
        sid = normalize_source(GitSourceId(url="ssh://git@host/org/repo"))
        assert sid == GitSourceId(url="ssh://host/org/repo")

    def test_added_strip_default_port_ssh(self) -> None:
        a = normalize_source(GitSourceId(url="ssh://user@host:22/org/repo"))
        b = normalize_source(GitSourceId(url="ssh://host/org/repo"))
        assert a == b

    def test_added_strip_default_port_https(self) -> None:
        a = normalize_source(GitSourceId(url="https://host:443/org/repo"))
        b = normalize_source(GitSourceId(url="https://host/org/repo"))
        assert a == b

    def test_added_strip_default_port_http(self) -> None:
        a = normalize_source(GitSourceId(url="http://host:80/org/repo"))
        b = normalize_source(GitSourceId(url="http://host/org/repo"))
        assert a == b

    def test_added_strip_default_port_git_scheme(self) -> None:
        a = normalize_source(GitSourceId(url="git://host:9418/org/repo"))
        b = normalize_source(GitSourceId(url="git://host/org/repo"))
        assert a == b

    def test_non_default_port_preserved(self) -> None:
        sid = normalize_source(GitSourceId(url="ssh://host:2222/org/repo"))
        assert sid == GitSourceId(url="ssh://host:2222/org/repo")

    def test_not_attempted_ssh_https_not_unified(self) -> None:
        a = normalize_source(GitSourceId(url="ssh://host/org/repo"))
        b = normalize_source(GitSourceId(url="https://host/org/repo"))
        assert a != b

    def test_subpath_untouched(self) -> None:
        sid = normalize_source(
            GitSourceId(url="HTTPS://Host/Org/Repo.git", subpath="pkg/foo")
        )
        assert sid == GitSourceId(url="https://host/Org/Repo", subpath="pkg/foo")

    def test_total_never_raises_on_scp_style(self) -> None:
        # SCP-style git@host:org/repo is unreachable from the manifest parser
        # (_validate_git_url rejects any git= without a scheme), but
        # normalize_source itself must still be total (never raise on THIS
        # input) — no netloc is detected, so it falls back to a lowercased
        # whole string.
        sid = normalize_source(GitSourceId(url="git@host:org/repo"))
        assert sid.url == "git@host:org/repo"


class TestNormalizeOtherKinds:
    """The other five kinds are identity (RFC §4.2) — modulo validation."""

    def test_oci_identity(self) -> None:
        raw = OciSourceId(registry="ghcr.io", repository="Org/Repo")
        assert normalize_source(raw) == raw

    def test_tarball_identity(self) -> None:
        raw = TarballSourceId(url="https://example.com/PKG.tar.gz")
        assert normalize_source(raw) == raw

    def test_local_identity(self) -> None:
        raw = LocalSourceId(path="Deps/Foo")
        assert normalize_source(raw) == raw

    def test_registry_identity(self) -> None:
        raw = RegistrySourceId(registry="tianguis", namespace="acme", name="utils")
        assert normalize_source(raw) == raw

    def test_registry_identity_host_qualified_namespace(self) -> None:
        raw = RegistrySourceId(registry="tianguis", namespace="codeberg.org/eris", name="utils")
        assert normalize_source(raw) == raw

    def test_member_identity(self) -> None:
        raw = MemberSourceId(member_name="intonaco")
        assert normalize_source(raw) == raw


# ---------------------------------------------------------------------------
# normalize_source — subpath escape guard (RFC §4.1 normative)
# ---------------------------------------------------------------------------


class TestNormalizeSubpathEscapeGuard:
    def test_absolute_subpath_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(GitSourceId(url="https://example.com/x", subpath="/abs/path"))
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_dotdot_traversal_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(GitSourceId(url="https://example.com/x", subpath="../escape"))
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_dotdot_mid_segment_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(
                GitSourceId(url="https://example.com/x", subpath="pkg/../../escape")
            )
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_empty_subpath_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(GitSourceId(url="https://example.com/x", subpath=""))
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_ordinary_relative_subpath_accepted(self) -> None:
        sid = normalize_source(GitSourceId(url="https://example.com/x", subpath="pkg/foo"))
        assert sid == GitSourceId(url="https://example.com/x", subpath="pkg/foo")

    def test_tarball_subpath_guarded_too(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(
                TarballSourceId(url="https://example.com/x.tar.gz", subpath="/abs")
            )
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_oci_subpath_guarded_too(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(
                OciSourceId(registry="ghcr.io", repository="x/y", subpath="../escape")
            )
        assert exc.value.slug == SRC_ID_MALFORMED


# ---------------------------------------------------------------------------
# normalize_source — the #subdirectory= delimiter-collision injectivity guard
# ---------------------------------------------------------------------------


class TestNormalizeDelimCollisionGuard:
    """RFC §4.1 "Subpath in the one-way key": a base that itself contains a
    literal '#subdirectory=' would let canonical() collide between two
    DIFFERENT structs — normalize_source rejects it instead of escaping it."""

    def test_git_url_with_literal_delim_rejected(self) -> None:
        # A schemeless URL — exercises the (now vestigial for git, since the
        # unconditional '#'-fragment guard in normalize_source fires first)
        # `_validate_no_delim_collision` guard's slug regardless of which
        # check trips.
        with pytest.raises(MilpaError) as exc:
            normalize_source(GitSourceId(url="example.com/x#subdirectory=evil"))
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_tarball_url_with_literal_delim_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(TarballSourceId(url="https://example.com/x#subdirectory=evil"))
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_oci_coordinate_with_literal_delim_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(
                OciSourceId(registry="ghcr.io", repository="x#subdirectory=evil")
            )
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_unvalidated_canonical_would_collide_without_the_guard(self) -> None:
        """Demonstrates WHY the guard is needed: canonical() itself does no
        validation, so bypassing normalize_source, two structurally
        different GitSourceIds collide under canonical(). This is exactly
        the pathological input normalize_source rejects — never reachable
        through the validated construction path."""
        folded = GitSourceId(url="example.com/x#subdirectory=pkg", subpath=None)
        split = GitSourceId(url="example.com/x", subpath="pkg")
        assert folded != split
        assert canonical(folded) == canonical(split)  # the collision, unvalidated
        with pytest.raises(MilpaError) as exc:
            normalize_source(folded)
        assert exc.value.slug == SRC_ID_MALFORMED


# ---------------------------------------------------------------------------
# normalize_source — OCI registry segment-boundary guard
# ---------------------------------------------------------------------------


class TestNormalizeOciRegistrySegmentGuard:
    """RFC §4.1 "oci+ segment boundary": a real OCI registry is host[:port]
    only (no internal '/'). Without this guard, canonical() is NOT
    injective — (registry="a/b", repository="c") and (registry="a",
    repository="b/c") both format to "oci+a/b/c"."""

    def test_registry_with_slash_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(OciSourceId(registry="a/b", repository="c"))
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_unvalidated_canonical_would_collide_without_the_guard(self) -> None:
        a = OciSourceId(registry="a/b", repository="c")
        b = OciSourceId(registry="a", repository="b/c")
        assert a != b
        assert canonical(a) == canonical(b)  # the collision, unvalidated
        with pytest.raises(MilpaError):
            normalize_source(a)


# ---------------------------------------------------------------------------
# normalize_source — RegistrySourceId alias/namespace/name validation
# ---------------------------------------------------------------------------


class TestNormalizeRegistryValidation:
    def test_alias_bad_charset_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(RegistrySourceId(registry="ac me", namespace=None, name="x"))
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_name_bad_charset_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(RegistrySourceId(registry="tianguis", namespace=None, name="soft link"))
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_namespace_empty_segment_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(
                RegistrySourceId(registry="tianguis", namespace="a//b", name="x")
            )
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_namespace_dotdot_segment_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(
                RegistrySourceId(registry="tianguis", namespace="a/../b", name="x")
            )
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_namespace_control_char_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(
                RegistrySourceId(registry="tianguis", namespace="a\tb", name="x")
            )
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_namespace_host_qualified_dot_segment_accepted(self) -> None:
        """The load-bearing positive case: a host-qualified namespace
        segment containing '.' (e.g. a real domain name) is NOT rejected —
        only the stricter valid_dep_name charset would reject it, and that
        charset is deliberately NOT applied per-segment (884/886 real
        tianguis namespaces are host-qualified)."""
        sid = normalize_source(
            RegistrySourceId(registry="tianguis", namespace="codeberg.org/eris", name="mypkg")
        )
        assert sid == RegistrySourceId(registry="tianguis", namespace="codeberg.org/eris", name="mypkg")
        assert canonical(sid) == "pkg+tianguis/codeberg.org/eris/mypkg"

    def test_namespace_unicode_line_separator_rejected(self) -> None:
        """Code-review S2 broadening: the previous namespace guard was
        ASCII-controls-only; U+2028 (Unicode LINE SEPARATOR) must be
        rejected too, mirroring `contains_unsafe_char`'s full charset."""
        with pytest.raises(MilpaError) as exc:
            normalize_source(
                RegistrySourceId(registry="tianguis", namespace="a b", name="x")
            )
        assert exc.value.slug == SRC_ID_MALFORMED


# ---------------------------------------------------------------------------
# normalize_source — control-char / Unicode-line-separator injection guard
# (code-review S2): a crafted, network-fetched `milpa.kdl` must not be able
# to smuggle a terminal-escape sequence through a free-text origin field
# into a diagnostic sink (e.g. `milpa show`'s provenance formatter).
# ---------------------------------------------------------------------------


class TestNormalizeControlCharGuard:
    def test_git_url_with_control_char_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(
                GitSourceId(url="https://evil.example/z3\x1b]0;PWNED\x07")
            )
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_git_url_with_unicode_line_separator_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(GitSourceId(url="https://evil.example/ repo"))
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_tarball_url_with_control_char_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(TarballSourceId(url="https://evil.example/x\x1b.tar.gz"))
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_oci_registry_with_control_char_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(OciSourceId(registry="ghcr.io\x1b", repository="x"))
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_oci_repository_with_control_char_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(OciSourceId(registry="ghcr.io", repository="x\x1by"))
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_local_path_with_control_char_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(LocalSourceId(path="deps/foo\x1bbar"))
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_ordinary_git_url_unaffected(self) -> None:
        sid = normalize_source(GitSourceId(url="https://github.com/coreyleavitt/nim-z3"))
        assert sid == GitSourceId(url="https://github.com/coreyleavitt/nim-z3")


# ---------------------------------------------------------------------------
# normalize_source — git URL query/fragment handling (code-review D1 —
# Python/Rust cross-impl convergence)
# ---------------------------------------------------------------------------


class TestNormalizeGitQueryAndFragment:
    def test_query_stripped(self) -> None:
        sid = normalize_source(
            GitSourceId(url="https://example.com/org/repo?ref=main")
        )
        assert sid == GitSourceId(url="https://example.com/org/repo")

    def test_fragment_rejected(self) -> None:
        with pytest.raises(MilpaError) as exc:
            normalize_source(
                GitSourceId(url="https://example.com/org/repo#subdirectory=x")
            )
        assert exc.value.slug == SRC_ID_MALFORMED

    def test_fragment_without_subdirectory_form_also_rejected(self) -> None:
        """Any fragment is rejected, not just the `#subdirectory=` form —
        the whole '#' namespace is reserved for milpa's own delimiter."""
        with pytest.raises(MilpaError) as exc:
            normalize_source(GitSourceId(url="https://example.com/org/repo#readme"))
        assert exc.value.slug == SRC_ID_MALFORMED
