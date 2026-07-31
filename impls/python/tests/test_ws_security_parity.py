"""Tests for F7, F16, F18, R2-1, R2-2 workspace security/parity fixes.

F7:  load_workspace_with_member_override assert → MilpaError (WS-MEMBER-DIR-MISSING).
F16: Path traversal containment check (WS-MEMBER-PATH-ESCAPE).
F18: Python already rejects "./"; new fixture-284 confirms Rust parity only.
     Python unit tests here just confirm the existing Python behavior is stable.
R2-1: Symlink member whose real target escapes the workspace root → PATH-ESCAPE.
      (Uses actual symlinks in tmp_path; covers the Option-A canonicalize path.)
R2-2: Member "pkg/.." resolves lexically to the workspace root → IS-WORKSPACE,
      not PATH-ESCAPE (inclusive containment check; parity with Python guaranteed
      by the _member_path_is_under_root dedup; fixture-286 corpus counterpart).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.errors import (
    MAN_RESOLUTION_MEMBER_SCOPE,
    MilpaError,
    WS_ENTRY_TRUST_ON_MEMBER,
    WS_INDEX_HISTORY_ON_MEMBER,
    WS_INDEX_TRUST_ON_MEMBER,
    WS_MEMBER_DIR_MISSING,
    WS_MEMBER_DOT,
    WS_MEMBER_IS_WORKSPACE,
    WS_MEMBER_PATH_ESCAPE,
)
from milpa.manifest import WorkspaceManifest, parse_manifest
from milpa.workspace import (
    load_workspace,
    load_workspace_from_manifest,
    load_workspace_with_member_override,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_workspace(root: Path, members: list[str]) -> None:
    lines = "\n".join(f'    member "{m}"' for m in members)
    (root / "milpa.kdl").write_text(f"workspace {{\n{lines}\n}}\n", encoding="utf-8")


def _write_member(member_dir: Path, name: str) -> None:
    member_dir.mkdir(parents=True, exist_ok=True)
    (member_dir / "milpa.kdl").write_text(
        f'name "{name}"\nkind "library"\n', encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# F18: Python rejects "./" with WS-MEMBER-DOT (stable regression guard)
# ---------------------------------------------------------------------------


def test_member_dot_slash_rejected_load_workspace(tmp_path: Path) -> None:
    """load_workspace: member './' raises WS-MEMBER-DOT."""
    _write_workspace(tmp_path, ["./"])
    with pytest.raises(MilpaError) as exc_info:
        load_workspace(tmp_path)
    assert exc_info.value.slug == WS_MEMBER_DOT


def test_member_dot_slash_rejected_load_workspace_from_manifest(tmp_path: Path) -> None:
    """load_workspace_from_manifest: member './' raises WS-MEMBER-DOT."""
    ws_manifest = WorkspaceManifest(members=("./",))
    with pytest.raises(MilpaError) as exc_info:
        load_workspace_from_manifest(tmp_path, ws_manifest)
    assert exc_info.value.slug == WS_MEMBER_DOT


# ---------------------------------------------------------------------------
# F16: Path traversal — WS-MEMBER-PATH-ESCAPE
# ---------------------------------------------------------------------------


def test_path_escape_rejected_load_workspace(tmp_path: Path) -> None:
    """load_workspace: member path that escapes workspace root raises WS-MEMBER-PATH-ESCAPE."""
    _write_workspace(tmp_path, ["../../escape"])
    with pytest.raises(MilpaError) as exc_info:
        load_workspace(tmp_path)
    assert exc_info.value.slug == WS_MEMBER_PATH_ESCAPE


def test_path_escape_rejected_load_workspace_from_manifest(tmp_path: Path) -> None:
    """load_workspace_from_manifest: escaping member path raises WS-MEMBER-PATH-ESCAPE."""
    ws_manifest = WorkspaceManifest(members=("../../escape",))
    with pytest.raises(MilpaError) as exc_info:
        load_workspace_from_manifest(tmp_path, ws_manifest)
    assert exc_info.value.slug == WS_MEMBER_PATH_ESCAPE


def test_dot_before_escape_yields_dot_not_escape(tmp_path: Path) -> None:
    """Dot-check runs before containment check: '.' yields WS-MEMBER-DOT, not WS-MEMBER-PATH-ESCAPE."""
    _write_workspace(tmp_path, ["."])
    with pytest.raises(MilpaError) as exc_info:
        load_workspace(tmp_path)
    assert exc_info.value.slug == WS_MEMBER_DOT


def test_path_escape_existing_dir(tmp_path: Path) -> None:
    """An escaping path that actually exists as a directory still raises WS-MEMBER-PATH-ESCAPE.

    Creates a real sibling directory so the path would be valid if the
    containment check were absent.
    """
    # Create a sibling dir outside tmp_path — we need to go up one level
    parent = tmp_path.parent
    sibling = parent / f"sibling_{tmp_path.name}"
    sibling.mkdir(exist_ok=True)
    # Relative path from tmp_path to sibling: ../sibling_<name>
    rel = f"../sibling_{tmp_path.name}"
    _write_workspace(tmp_path, [rel])
    with pytest.raises(MilpaError) as exc_info:
        load_workspace(tmp_path)
    assert exc_info.value.slug == WS_MEMBER_PATH_ESCAPE


# ---------------------------------------------------------------------------
# R2-2: "pkg/.." resolves lexically to root → WS-MEMBER-IS-WORKSPACE, not PATH-ESCAPE
#
# Fixture-286 is the corpus counterpart.  These unit tests pin the Python behavior
# and confirm it matches the now-fixed Rust.
# ---------------------------------------------------------------------------


def test_member_resolves_to_root_yields_is_workspace_load_workspace(tmp_path: Path) -> None:
    """load_workspace: member 'pkg/..' reduces to workspace root → WS-MEMBER-IS-WORKSPACE.

    'pkg' doesn't exist; Path.resolve() normalizes '..' lexically and returns
    the root.  is_relative_to(root) is True (inclusive), so it is NOT a PATH-ESCAPE;
    it falls through to the manifest-parse check which sees a workspace document.
    """
    _write_workspace(tmp_path, ["pkg/.."])
    with pytest.raises(MilpaError) as exc_info:
        load_workspace(tmp_path)
    assert exc_info.value.slug == WS_MEMBER_IS_WORKSPACE


def test_member_resolves_to_root_yields_is_workspace_from_manifest(tmp_path: Path) -> None:
    """load_workspace_from_manifest: same semantics as load_workspace for 'pkg/..'.

    The workspace manifest is written to disk so that when 'pkg/..' resolves to
    the root and load_workspace_from_manifest reads root/milpa.kdl, it finds a
    workspace document and raises WS-MEMBER-IS-WORKSPACE.
    """
    _write_workspace(tmp_path, ["pkg/.."])
    ws_manifest = WorkspaceManifest(members=("pkg/..",))
    with pytest.raises(MilpaError) as exc_info:
        load_workspace_from_manifest(tmp_path, ws_manifest)
    assert exc_info.value.slug == WS_MEMBER_IS_WORKSPACE


# ---------------------------------------------------------------------------
# R2-1: Existing symlink whose real target escapes workspace root → PATH-ESCAPE
#
# Builds a real symlink in tmp_path so Path.resolve() follows it.
# This pins the Option-A canonicalize behavior.
# ---------------------------------------------------------------------------


def test_symlink_member_escaping_root_yields_path_escape(tmp_path: Path) -> None:
    """A member dir that is a symlink pointing outside the workspace root → WS-MEMBER-PATH-ESCAPE.

    Layout:
      tmp_path/
        workspace-root/
          milpa.kdl         (workspace declaring member "symlink-member")
          symlink-member -> ../outside-root
        outside-root/       (real dir with a package milpa.kdl)

    Path.resolve() follows the symlink → outside-root → not under workspace-root.
    """
    ws_root = tmp_path / "workspace-root"
    outside = tmp_path / "outside-root"
    ws_root.mkdir()
    outside.mkdir()
    (outside / "milpa.kdl").write_text('name "escaped"\nkind "library"\n', encoding="utf-8")
    _write_workspace(ws_root, ["symlink-member"])
    # Create symlink: workspace-root/symlink-member → ../outside-root
    (ws_root / "symlink-member").symlink_to("../outside-root")
    with pytest.raises(MilpaError) as exc_info:
        load_workspace(ws_root)
    assert exc_info.value.slug == WS_MEMBER_PATH_ESCAPE


def test_symlink_member_escaping_root_from_manifest(tmp_path: Path) -> None:
    """Same as above but through load_workspace_from_manifest."""
    ws_root = tmp_path / "workspace-root"
    outside = tmp_path / "outside-root"
    ws_root.mkdir()
    outside.mkdir()
    (outside / "milpa.kdl").write_text('name "escaped"\nkind "library"\n', encoding="utf-8")
    # Write workspace milpa.kdl (needed so ws_root.resolve() works)
    _write_workspace(ws_root, ["symlink-member"])
    (ws_root / "symlink-member").symlink_to("../outside-root")
    ws_manifest = WorkspaceManifest(members=("symlink-member",))
    with pytest.raises(MilpaError) as exc_info:
        load_workspace_from_manifest(ws_root, ws_manifest)
    assert exc_info.value.slug == WS_MEMBER_PATH_ESCAPE


# ---------------------------------------------------------------------------
# S4 (#168) — cyclic and dangling symlink → WS-MEMBER-DIR-MISSING (spec §11.0)
#
# After S4 the best-effort-resolve algorithm uses stat() (not lstat()), so
# dangling and cyclic symlinks are treated as non-existent: the longest
# stat-existing prefix is the parent directory, and the resolved candidate
# stays inside the workspace root.  The dir-existence check then fails →
# WS-MEMBER-DIR-MISSING (not WS-MEMBER-PATH-ESCAPE, not an OSError crash).
#
# Note: an existing symlink whose target is OUTSIDE the root still yields
# WS-MEMBER-PATH-ESCAPE (stat succeeds, fast path canonicalizes to outside).
# ---------------------------------------------------------------------------


def test_dangling_symlink_outside_root_yields_dir_missing(tmp_path: Path) -> None:
    """A dangling symlink with a nonexistent target outside the root → WS-MEMBER-DIR-MISSING.

    Layout::

      tmp_path/
        workspace-root/
          milpa.kdl      (workspace declaring member "dangle-out")
          dangle-out -> ../../outside-nonexistent   (dangling: target absent)

    spec §11.0: stat() fails for a dangling symlink → treated as non-existent →
    best-effort-resolve returns canonical_root/dangle-out → no escape →
    dir-existence check fails → WS-MEMBER-DIR-MISSING.
    Conformance corpus: fixture-310-ws-member-dangling-symlink.
    """
    ws_root = tmp_path / "workspace-root"
    ws_root.mkdir()
    _write_workspace(ws_root, ["dangle-out"])
    (ws_root / "dangle-out").symlink_to("../../outside-nonexistent")
    assert not (ws_root / "dangle-out").exists(), "target must be absent"

    with pytest.raises(MilpaError) as exc_info:
        load_workspace(ws_root)
    assert exc_info.value.slug == WS_MEMBER_DIR_MISSING


def test_cyclic_symlink_yields_dir_missing_no_eloop_crash(tmp_path: Path) -> None:
    """A cyclic (self-referential) symlink member → WS-MEMBER-DIR-MISSING, no OSError crash.

    Layout::

      tmp_path/
        workspace-root/
          milpa.kdl      (workspace declaring member "link-self")
          link-self -> link-self   (self-referential cycle)

    spec §11.0: stat() on a cyclic symlink raises OSError(ELOOP) → treated as
    non-existent → best-effort-resolve returns canonical_root/link-self → no escape →
    dir-existence check fails → WS-MEMBER-DIR-MISSING.  No OSError must escape.
    Conformance corpus: fixture-309-ws-member-cyclic-symlink.
    """
    ws_root = tmp_path / "workspace-root"
    ws_root.mkdir()
    _write_workspace(ws_root, ["link-self"])
    (ws_root / "link-self").symlink_to("link-self")
    assert not (ws_root / "link-self").exists(), "cyclic symlink must not stat-exist"

    with pytest.raises(MilpaError) as exc_info:
        load_workspace(ws_root)
    assert exc_info.value.slug == WS_MEMBER_DIR_MISSING


def test_two_hop_cyclic_symlink_yields_dir_missing(tmp_path: Path) -> None:
    """A two-hop cyclic symlink (a→b, b→a) member → WS-MEMBER-DIR-MISSING, no OSError crash.

    Layout::

      tmp_path/
        workspace-root/
          milpa.kdl          (workspace declaring member "link-a")
          link-a -> link-b   )
          link-b -> link-a   } two-hop cycle → ELOOP

    Exercises the ELOOP crash path that was previously unhandled by Python's
    Path.resolve(strict=False) for multi-hop cycles.
    """
    ws_root = tmp_path / "workspace-root"
    ws_root.mkdir()
    _write_workspace(ws_root, ["link-a"])
    (ws_root / "link-a").symlink_to("link-b")
    (ws_root / "link-b").symlink_to("link-a")
    assert not (ws_root / "link-a").exists(), "cyclic symlink must not stat-exist"

    with pytest.raises(MilpaError) as exc_info:
        load_workspace(ws_root)
    assert exc_info.value.slug == WS_MEMBER_DIR_MISSING


def test_dangling_symlink_inside_root_yields_dir_missing(tmp_path: Path) -> None:
    """A dangling symlink whose target resolves inside the workspace root → WS-MEMBER-DIR-MISSING.

    When the dangling link target is inside the root (e.g. ``link -> nonexistent-inside``),
    the containment check passes (not an escape) and the missing-dir check triggers.
    Parity: Rust ``is_under_root`` lexically resolves the dangling link target to
    ``ws_root/nonexistent-inside`` which starts_with(ws_root) → True → not an escape →
    proceeds to dir-existence → WS-MEMBER-DIR-MISSING.
    """
    ws_root = tmp_path / "workspace-root"
    ws_root.mkdir()
    _write_workspace(ws_root, ["dangle-in"])
    (ws_root / "dangle-in").symlink_to("nonexistent-inside")
    assert not (ws_root / "dangle-in").exists(), "target must be absent"

    with pytest.raises(MilpaError) as exc_info:
        load_workspace(ws_root)
    assert exc_info.value.slug == WS_MEMBER_DIR_MISSING


# ---------------------------------------------------------------------------
# Symlinked-workspace-root divergence (Linux parity — Rust fix verification)
#
# Bug: Rust branch-(c) of old is_under_root used normalize_lexically on the
# non-existent candidate, which does NOT canonicalize symlinks in the prefix.
# So if root is accessed via a symlink:
#   - real_root = canonicalize(link) = realroot
#   - real_cand = normalize_lexically(link/pkg/..) = link  (symlink NOT followed)
#   - link.starts_with(realroot) = False → WS-MEMBER-PATH-ESCAPE (WRONG)
#
# Python already gets this right: (link / "pkg/..").resolve() canonicalizes
# the existing "link" prefix to "realroot" before applying "pkg/.." lexically.
#
# These tests pin the correct Python behavior; the matching Rust test is
# member_resolves_to_root_via_symlinked_ws_root_yields_is_workspace in
# workspace_tests.rs.
# ---------------------------------------------------------------------------


def test_member_resolves_to_root_via_symlinked_ws_root_load_workspace(
    tmp_path: Path,
) -> None:
    """load_workspace via a symlink-accessed root: member 'pkg/..' → WS-MEMBER-IS-WORKSPACE.

    Layout::

      tmp_path/
        realroot/
          milpa.kdl    (workspace declaring member "pkg/..")
        link -> realroot   (symlink)

    Python ``Path.resolve(strict=False)`` canonicalizes the existing "link" prefix
    to "realroot" before normalizing "pkg/.." → "realroot".  ``is_relative_to``
    is True (inclusive) → WS-MEMBER-IS-WORKSPACE, not WS-MEMBER-PATH-ESCAPE.
    """
    realroot = tmp_path / "realroot"
    realroot.mkdir()
    (realroot / "milpa.kdl").write_text(
        'workspace {\n    member "pkg/.."\n}\n', encoding="utf-8"
    )
    link = tmp_path / "link"
    link.symlink_to("realroot")

    with pytest.raises(MilpaError) as exc_info:
        load_workspace(link)
    assert exc_info.value.slug == WS_MEMBER_IS_WORKSPACE, (
        f"Expected WS-MEMBER-IS-WORKSPACE, got {exc_info.value.slug!r} — "
        "symlinked root with member 'pkg/..' should resolve to root"
    )


def test_member_resolves_to_root_via_symlinked_ws_root_from_manifest(
    tmp_path: Path,
) -> None:
    """load_workspace_from_manifest via a symlink-accessed root: same semantics."""
    realroot = tmp_path / "realroot"
    realroot.mkdir()
    (realroot / "milpa.kdl").write_text(
        'workspace {\n    member "pkg/.."\n}\n', encoding="utf-8"
    )
    link = tmp_path / "link"
    link.symlink_to("realroot")

    ws_manifest = WorkspaceManifest(members=("pkg/..",))
    with pytest.raises(MilpaError) as exc_info:
        load_workspace_from_manifest(link, ws_manifest)
    assert exc_info.value.slug == WS_MEMBER_IS_WORKSPACE, (
        f"Expected WS-MEMBER-IS-WORKSPACE, got {exc_info.value.slug!r} — "
        "symlinked root with member 'pkg/..' should resolve to root"
    )


# ---------------------------------------------------------------------------
# Mid-path dangling symlink (S4, spec §11.0 — stat-based, treated as non-existent)
#
# After S4, a dangling mid-path symlink is treated as non-existent (stat fails),
# so the longest stat-existing prefix is the workspace root, and the result
# stays inside the root → WS-MEMBER-DIR-MISSING (not WS-MEMBER-PATH-ESCAPE).
# ---------------------------------------------------------------------------


def test_mid_path_dangling_symlink_outside_root_yields_dir_missing(
    tmp_path: Path,
) -> None:
    """Member 'danglink/pkg' where 'danglink' is a dangling symlink → WS-MEMBER-DIR-MISSING.

    Layout::

      tmp_path/
        workspace-root/
          milpa.kdl      (workspace declaring member "danglink/pkg")
          danglink -> ../../outside-nonexistent   (dangling: target absent)

    spec §11.0: stat() on 'danglink' fails (dangling symlink) → treated as
    non-existent → longest stat-existing prefix = workspace-root → result is
    workspace-root/danglink/pkg → inside root → no escape → WS-MEMBER-DIR-MISSING.
    """
    ws_root = tmp_path / "workspace-root"
    ws_root.mkdir()
    _write_workspace(ws_root, ["danglink/pkg"])
    (ws_root / "danglink").symlink_to("../../outside-nonexistent")
    assert not (ws_root / "danglink").exists(), "danglink target must be absent"
    assert not (ws_root / "danglink" / "pkg").exists(), "mid-path must be unreachable"

    with pytest.raises(MilpaError) as exc_info:
        load_workspace(ws_root)
    assert exc_info.value.slug == WS_MEMBER_DIR_MISSING, (
        f"Expected WS-MEMBER-DIR-MISSING, got {exc_info.value.slug!r} — "
        "mid-path dangling symlink must be treated as non-existent (spec §11.0)"
    )


# ---------------------------------------------------------------------------
# F7: load_workspace_with_member_override must raise MilpaError, not AssertionError
# ---------------------------------------------------------------------------


def test_member_override_missing_member_raises_milpa_error(tmp_path: Path) -> None:
    """load_workspace_with_member_override raises MilpaError when member_dir is not in workspace.

    Previously used `assert found` which is stripped under -O.
    """
    # Build a workspace with one real member
    _write_workspace(tmp_path, ["member-a"])
    _write_member(tmp_path / "member-a", "liba")
    workspace = load_workspace(tmp_path)

    # Pass a directory that is NOT in the workspace
    nonmember = tmp_path / "nonexistent-member"
    from milpa.manifest import Manifest

    dummy_manifest = Manifest(
        name="dummy",
        deps=(),
    )
    with pytest.raises(MilpaError):
        load_workspace_with_member_override(workspace, nonmember, dummy_manifest)


# ---------------------------------------------------------------------------
# S5 redesign: index-trust root authority (RFC registry-trust-federation §6.4a)
#
# index-trust / index-trust-signer / index-trust-bundle are declared ONLY on
# the resolution root.  For a workspace, that's the workspace ROOT manifest.
# A member manifest declaring any of the three is a hard error
# (WS-INDEX-TRUST-ON-MEMBER), raised at workspace-load time, BEFORE any index
# fetch.  This replaces the old max-merge + per-URL conflicting-signers design.
# ---------------------------------------------------------------------------


def _write_workspace_root_with_index_trust(
    root: Path,
    *,
    policy: str | None = None,
    signer: str | None = None,
    bundle: str | None = None,
    member_name: str = "sub",
) -> None:
    """Write a workspace root manifest optionally carrying index-trust fields.

    The root always declares one member ``sub`` with a plain manifest (no
    index-trust fields) so the workspace loads cleanly when the root's fields
    are legal.
    """
    lines = []
    if policy is not None:
        lines.append(f'index-trust "{policy}"')
    if signer is not None:
        lines.append(f'index-trust-signer "{signer}"')
    if bundle is not None:
        lines.append(f'index-trust-bundle "{bundle}"')
    lines.append(f'workspace {{\n    member "{member_name}"\n}}')
    (root / "milpa.kdl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    _write_member(root / member_name, member_name)


def _write_workspace_member_with_index_trust(
    root: Path,
    *,
    member_policy: str | None = None,
    member_signer: str | None = None,
    member_bundle: str | None = None,
    root_policy: str | None = None,
    member_name: str = "sub",
) -> None:
    """Write a workspace where a MEMBER illegally declares an index-trust field."""
    root_lines = []
    if root_policy is not None:
        root_lines.append(f'index-trust "{root_policy}"')
    root_lines.append(f'workspace {{\n    member "{member_name}"\n}}')
    (root / "milpa.kdl").write_text("\n".join(root_lines) + "\n", encoding="utf-8")

    member_dir = root / member_name
    member_dir.mkdir(parents=True, exist_ok=True)
    member_lines = [f'name "{member_name}"', 'kind "library"']
    if member_policy is not None:
        member_lines.append(f'index-trust "{member_policy}"')
    if member_signer is not None:
        member_lines.append(f'index-trust-signer "{member_signer}"')
    if member_bundle is not None:
        member_lines.append(f'index-trust-bundle "{member_bundle}"')
    (member_dir / "milpa.kdl").write_text("\n".join(member_lines) + "\n", encoding="utf-8")


class TestWorkspaceRootIndexTrustAuthority:
    """Root declares index-trust; a plain member coexists with no error."""

    def test_root_declares_strict_no_error(self, tmp_path: Path) -> None:
        _write_workspace_root_with_index_trust(tmp_path, policy="strict")
        loaded = load_workspace(tmp_path)
        assert loaded.workspace_manifest.index_trust_policy == "strict"

    def test_root_declares_off_no_error(self, tmp_path: Path) -> None:
        """Root-declared 'off' is reachable — the whole point of the redesign."""
        _write_workspace_root_with_index_trust(tmp_path, policy="off")
        loaded = load_workspace(tmp_path)
        assert loaded.workspace_manifest.index_trust_policy == "off"

    def test_root_declares_signer_and_bundle_no_error(self, tmp_path: Path) -> None:
        signer = "https://github.com/acme/reg/.github/workflows/sign.yaml@refs/heads/main"
        bundle = "file:///etc/milpa/trust-bundle.json"
        _write_workspace_root_with_index_trust(tmp_path, signer=signer, bundle=bundle)
        loaded = load_workspace(tmp_path)
        assert loaded.workspace_manifest.index_trust_signer == signer
        assert loaded.workspace_manifest.index_trust_bundle == bundle

    def test_root_declares_nothing_defaults_warn(self, tmp_path: Path) -> None:
        _write_workspace_root_with_index_trust(tmp_path)
        loaded = load_workspace(tmp_path)
        assert loaded.workspace_manifest.index_trust_policy == "warn"


class TestWorkspaceMemberIndexTrustRejected:
    """A member declaring index-trust / -signer / -bundle → WS-INDEX-TRUST-ON-MEMBER."""

    def test_member_declares_policy_raises(self, tmp_path: Path) -> None:
        _write_workspace_member_with_index_trust(tmp_path, member_policy="strict")
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        assert exc_info.value.slug == WS_INDEX_TRUST_ON_MEMBER

    def test_member_declares_default_matching_policy_still_raises(self, tmp_path: Path) -> None:
        """Explicit 'warn' on a member still errors — the rule is about WHERE, not the value."""
        _write_workspace_member_with_index_trust(tmp_path, member_policy="warn")
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        assert exc_info.value.slug == WS_INDEX_TRUST_ON_MEMBER

    def test_member_declares_signer_raises(self, tmp_path: Path) -> None:
        signer = "https://github.com/acme/reg/.github/workflows/sign.yaml@refs/heads/main"
        _write_workspace_member_with_index_trust(tmp_path, member_signer=signer)
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        assert exc_info.value.slug == WS_INDEX_TRUST_ON_MEMBER

    def test_member_declares_bundle_raises(self, tmp_path: Path) -> None:
        _write_workspace_member_with_index_trust(
            tmp_path, member_bundle="file:///etc/milpa/trust-bundle.json"
        )
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        assert exc_info.value.slug == WS_INDEX_TRUST_ON_MEMBER

    def test_error_includes_member_path(self, tmp_path: Path) -> None:
        _write_workspace_member_with_index_trust(
            tmp_path, member_policy="strict", member_name="pkg-b"
        )
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        combined = exc_info.value.message + str(exc_info.value.context)
        assert "pkg-b" in combined

    def test_fires_regardless_of_root_policy(self, tmp_path: Path) -> None:
        """The check fires even when the root ALSO legally declares a policy."""
        _write_workspace_member_with_index_trust(
            tmp_path, member_policy="strict", root_policy="warn"
        )
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        assert exc_info.value.slug == WS_INDEX_TRUST_ON_MEMBER

    def test_fires_via_load_workspace_from_manifest(self, tmp_path: Path) -> None:
        """load_workspace_from_manifest (used by add/remove orchestration) also rejects."""
        _write_workspace_member_with_index_trust(tmp_path, member_policy="strict")
        ws_manifest = WorkspaceManifest(members=("sub",))
        with pytest.raises(MilpaError) as exc_info:
            load_workspace_from_manifest(tmp_path, ws_manifest)
        assert exc_info.value.slug == WS_INDEX_TRUST_ON_MEMBER

    def test_no_merge_function_exists(self) -> None:
        """merge_workspace_index_trust_policy is DELETED — no merge machinery remains."""
        import milpa.workspace as workspace_mod

        assert not hasattr(workspace_mod, "merge_workspace_index_trust_policy")
        assert not hasattr(workspace_mod, "_check_conflicting_signers")


# ---------------------------------------------------------------------------
# A2c (RFC registry-append-only.md §2, spec/registry-protocol.md §3.4.0 /
# §3.5.2): index-history root authority — mirrors the index-trust root-
# authority tests above for the sibling axis. index-history has no
# signer/bundle sub-fields (the ratchet is a pure content diff, not a
# Sigstore verification), so this axis is a single-node mirror.
# ---------------------------------------------------------------------------


def _write_workspace_root_with_index_history(
    root: Path,
    *,
    policy: str | None = None,
    member_name: str = "sub",
) -> None:
    """Write a workspace root manifest optionally carrying an index-history field.

    The root always declares one member ``sub`` with a plain manifest (no
    index-history field) so the workspace loads cleanly when the root's field
    is legal.
    """
    lines = []
    if policy is not None:
        lines.append(f'index-history "{policy}"')
    lines.append(f'workspace {{\n    member "{member_name}"\n}}')
    (root / "milpa.kdl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    _write_member(root / member_name, member_name)


def _write_workspace_member_with_index_history(
    root: Path,
    *,
    member_policy: str | None = None,
    root_policy: str | None = None,
    member_name: str = "sub",
) -> None:
    """Write a workspace where a MEMBER illegally declares an index-history field."""
    root_lines = []
    if root_policy is not None:
        root_lines.append(f'index-history "{root_policy}"')
    root_lines.append(f'workspace {{\n    member "{member_name}"\n}}')
    (root / "milpa.kdl").write_text("\n".join(root_lines) + "\n", encoding="utf-8")

    member_dir = root / member_name
    member_dir.mkdir(parents=True, exist_ok=True)
    member_lines = [f'name "{member_name}"', 'kind "library"']
    if member_policy is not None:
        member_lines.append(f'index-history "{member_policy}"')
    (member_dir / "milpa.kdl").write_text("\n".join(member_lines) + "\n", encoding="utf-8")


class TestWorkspaceRootIndexHistoryAuthority:
    """Root declares index-history; a plain member coexists with no error."""

    def test_root_declares_strict_no_error(self, tmp_path: Path) -> None:
        _write_workspace_root_with_index_history(tmp_path, policy="strict")
        loaded = load_workspace(tmp_path)
        assert loaded.workspace_manifest.index_history_policy == "strict"

    def test_root_declares_off_no_error(self, tmp_path: Path) -> None:
        """Root-declared 'off' preserves the baseline (A2d) but is a legal declaration."""
        _write_workspace_root_with_index_history(tmp_path, policy="off")
        loaded = load_workspace(tmp_path)
        assert loaded.workspace_manifest.index_history_policy == "off"

    def test_root_declares_nothing_defaults_warn(self, tmp_path: Path) -> None:
        _write_workspace_root_with_index_history(tmp_path)
        loaded = load_workspace(tmp_path)
        assert loaded.workspace_manifest.index_history_policy == "warn"


class TestWorkspaceMemberIndexHistoryRejected:
    """A member declaring index-history → WS-INDEX-HISTORY-ON-MEMBER."""

    def test_member_declares_policy_raises(self, tmp_path: Path) -> None:
        _write_workspace_member_with_index_history(tmp_path, member_policy="strict")
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        assert exc_info.value.slug == WS_INDEX_HISTORY_ON_MEMBER

    def test_member_declares_default_matching_policy_still_raises(self, tmp_path: Path) -> None:
        """Explicit 'warn' on a member still errors — the rule is about WHERE, not the value."""
        _write_workspace_member_with_index_history(tmp_path, member_policy="warn")
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        assert exc_info.value.slug == WS_INDEX_HISTORY_ON_MEMBER

    def test_error_includes_member_path(self, tmp_path: Path) -> None:
        _write_workspace_member_with_index_history(
            tmp_path, member_policy="strict", member_name="pkg-b"
        )
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        combined = exc_info.value.message + str(exc_info.value.context)
        assert "pkg-b" in combined

    def test_fires_regardless_of_root_policy(self, tmp_path: Path) -> None:
        """The check fires even when the root ALSO legally declares a policy."""
        _write_workspace_member_with_index_history(
            tmp_path, member_policy="strict", root_policy="warn"
        )
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        assert exc_info.value.slug == WS_INDEX_HISTORY_ON_MEMBER

    def test_fires_via_load_workspace_from_manifest(self, tmp_path: Path) -> None:
        """load_workspace_from_manifest (used by add/remove orchestration) also rejects."""
        _write_workspace_member_with_index_history(tmp_path, member_policy="strict")
        ws_manifest = WorkspaceManifest(members=("sub",))
        with pytest.raises(MilpaError) as exc_info:
            load_workspace_from_manifest(tmp_path, ws_manifest)
        assert exc_info.value.slug == WS_INDEX_HISTORY_ON_MEMBER


# ---------------------------------------------------------------------------
# P3a (RFC per-entry-attestation.md §4): entry-trust root authority — mirrors
# the index-history root-authority tests above for the sibling axis. Like
# index-history, entry-trust is a single-node field (no signer/bundle
# sub-fields), so this axis is also a single-node mirror.
# ---------------------------------------------------------------------------


def _write_workspace_member_with_entry_trust(
    root: Path,
    *,
    member_policy: str | None = None,
    root_policy: str | None = None,
    member_name: str = "sub",
) -> None:
    """Write a workspace where a MEMBER illegally declares an entry-trust field."""
    root_lines = []
    if root_policy is not None:
        root_lines.append(f'entry-trust "{root_policy}"')
    root_lines.append(f'workspace {{\n    member "{member_name}"\n}}')
    (root / "milpa.kdl").write_text("\n".join(root_lines) + "\n", encoding="utf-8")

    member_dir = root / member_name
    member_dir.mkdir(parents=True, exist_ok=True)
    member_lines = [f'name "{member_name}"', 'kind "library"']
    if member_policy is not None:
        member_lines.append(f'entry-trust "{member_policy}"')
    (member_dir / "milpa.kdl").write_text("\n".join(member_lines) + "\n", encoding="utf-8")


class TestWorkspaceMemberEntryTrustRejected:
    """A member declaring entry-trust → WS-ENTRY-TRUST-ON-MEMBER."""

    def test_member_declares_policy_raises(self, tmp_path: Path) -> None:
        _write_workspace_member_with_entry_trust(tmp_path, member_policy="strict")
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        assert exc_info.value.slug == WS_ENTRY_TRUST_ON_MEMBER

    def test_member_declares_default_matching_policy_still_raises(self, tmp_path: Path) -> None:
        """Explicit 'warn' on a member still errors — the rule is about WHERE, not the value."""
        _write_workspace_member_with_entry_trust(tmp_path, member_policy="warn")
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        assert exc_info.value.slug == WS_ENTRY_TRUST_ON_MEMBER

    def test_error_includes_member_path(self, tmp_path: Path) -> None:
        _write_workspace_member_with_entry_trust(
            tmp_path, member_policy="strict", member_name="pkg-b"
        )
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        combined = exc_info.value.message + str(exc_info.value.context)
        assert "pkg-b" in combined

    def test_fires_regardless_of_root_policy(self, tmp_path: Path) -> None:
        """The check fires even when the root ALSO legally declares a policy."""
        _write_workspace_member_with_entry_trust(
            tmp_path, member_policy="strict", root_policy="warn"
        )
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        assert exc_info.value.slug == WS_ENTRY_TRUST_ON_MEMBER

    def test_fires_via_load_workspace_from_manifest(self, tmp_path: Path) -> None:
        """load_workspace_from_manifest (used by add/remove orchestration) also rejects."""
        _write_workspace_member_with_entry_trust(tmp_path, member_policy="strict")
        ws_manifest = WorkspaceManifest(members=("sub",))
        with pytest.raises(MilpaError) as exc_info:
            load_workspace_from_manifest(tmp_path, ws_manifest)
        assert exc_info.value.slug == WS_ENTRY_TRUST_ON_MEMBER


# ---------------------------------------------------------------------------
# W1 (rfc-resolution-semantics.md §3 Axis W, §5 MAN-RESOLUTION-MEMBER-SCOPE):
# resolution { } root authority — mirrors the index-history/entry-trust
# root-authority tests above for the resolution-policy axis. Unlike those
# single-node fields, resolution { } is a whole BLOCK (strategy + exclude-
# newer children), so presence is `Manifest.resolution is not None` rather
# than a policy-string comparison.
# ---------------------------------------------------------------------------


def _write_workspace_root_with_resolution(
    root: Path,
    *,
    strategy: str | None = None,
    member_name: str = "sub",
) -> None:
    """Write a workspace root manifest optionally carrying a resolution { } block."""
    lines = []
    if strategy is not None:
        lines.append(f'resolution {{\n    strategy "{strategy}"\n}}')
    lines.append(f'workspace {{\n    member "{member_name}"\n}}')
    (root / "milpa.kdl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    _write_member(root / member_name, member_name)


def _write_workspace_member_with_resolution(
    root: Path,
    *,
    member_has_resolution: bool,
    root_strategy: str | None = None,
    member_name: str = "sub",
) -> None:
    """Write a workspace where a MEMBER illegally declares a resolution { } block."""
    root_lines = []
    if root_strategy is not None:
        root_lines.append(f'resolution {{\n    strategy "{root_strategy}"\n}}')
    root_lines.append(f'workspace {{\n    member "{member_name}"\n}}')
    (root / "milpa.kdl").write_text("\n".join(root_lines) + "\n", encoding="utf-8")

    member_dir = root / member_name
    member_dir.mkdir(parents=True, exist_ok=True)
    member_lines = [f'name "{member_name}"', 'kind "library"']
    if member_has_resolution:
        member_lines.append('resolution {\n}')
    (member_dir / "milpa.kdl").write_text("\n".join(member_lines) + "\n", encoding="utf-8")


class TestWorkspaceRootResolutionAuthority:
    """Root declares resolution { }; a plain member coexists with no error."""

    def test_root_declares_strategy_no_error(self, tmp_path: Path) -> None:
        _write_workspace_root_with_resolution(tmp_path, strategy="minver")
        loaded = load_workspace(tmp_path)
        assert loaded.workspace_manifest.resolution is not None
        assert loaded.workspace_manifest.resolution.strategy is not None

    def test_root_declares_nothing_stays_none(self, tmp_path: Path) -> None:
        _write_workspace_root_with_resolution(tmp_path)
        loaded = load_workspace(tmp_path)
        assert loaded.workspace_manifest.resolution is None


class TestWorkspaceMemberResolutionRejected:
    """A member declaring resolution { } → MAN-RESOLUTION-MEMBER-SCOPE."""

    def test_member_declares_empty_block_raises(self, tmp_path: Path) -> None:
        """Fires even for an EMPTY resolution { } block — the rule is about WHERE
        the block is declared, not what it contains."""
        _write_workspace_member_with_resolution(tmp_path, member_has_resolution=True)
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        assert exc_info.value.slug == MAN_RESOLUTION_MEMBER_SCOPE

    def test_error_includes_member_path(self, tmp_path: Path) -> None:
        _write_workspace_member_with_resolution(
            tmp_path, member_has_resolution=True, member_name="pkg-b"
        )
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        combined = exc_info.value.message + str(exc_info.value.context)
        assert "pkg-b" in combined

    def test_fires_regardless_of_root_policy(self, tmp_path: Path) -> None:
        """The check fires even when the root ALSO legally declares a resolution block."""
        _write_workspace_member_with_resolution(
            tmp_path, member_has_resolution=True, root_strategy="maxver"
        )
        with pytest.raises(MilpaError) as exc_info:
            load_workspace(tmp_path)
        assert exc_info.value.slug == MAN_RESOLUTION_MEMBER_SCOPE

    def test_fires_via_load_workspace_from_manifest(self, tmp_path: Path) -> None:
        """load_workspace_from_manifest (used by add/remove orchestration) also rejects."""
        _write_workspace_member_with_resolution(tmp_path, member_has_resolution=True)
        ws_manifest = WorkspaceManifest(members=("sub",))
        with pytest.raises(MilpaError) as exc_info:
            load_workspace_from_manifest(tmp_path, ws_manifest)
        assert exc_info.value.slug == MAN_RESOLUTION_MEMBER_SCOPE

    def test_plain_member_with_no_resolution_block_is_fine(self, tmp_path: Path) -> None:
        _write_workspace_member_with_resolution(tmp_path, member_has_resolution=False)
        loaded = load_workspace(tmp_path)
        assert loaded.members[0].manifest.resolution is None


def test_standalone_manifest_with_resolution_block_is_unaffected() -> None:
    """A standalone (non-workspace) package manifest declaring resolution { } is FINE —
    the MAN-RESOLUTION-MEMBER-SCOPE rule only applies to a manifest loaded as a
    workspace MEMBER, per rfc-resolution-semantics.md §3 Axis W."""
    text = 'name "solo"\nkind "library"\nresolution {\n    strategy "minver"\n}\n'
    manifest = parse_manifest(text)
    assert manifest.resolution is not None
    assert manifest.resolution.strategy is not None

