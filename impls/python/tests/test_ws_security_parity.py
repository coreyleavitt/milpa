"""Tests for F7, F16, F18 workspace security/parity fixes.

F7:  load_workspace_with_member_override assert → MilpaError (WS-MEMBER-DIR-MISSING).
F16: Path traversal containment check (WS-MEMBER-PATH-ESCAPE).
F18: Python already rejects "./"; new fixture-284 confirms Rust parity only.
     Python unit tests here just confirm the existing Python behavior is stable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.errors import (
    MilpaError,
    WS_MEMBER_DIR_MISSING,
    WS_MEMBER_DOT,
    WS_MEMBER_PATH_ESCAPE,
)
from milpa.manifest import WorkspaceManifest
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
