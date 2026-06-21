"""Unit tests for cmd_workspace_add_member / cmd_workspace_remove_member — S10.

Covers:
  - add-member happy path: appends member, writes manifest + lock.
  - add-member guard 1: dir does not exist → WS-MEMBER-DIR-MISSING (exit 1).
  - add-member guard 2: dir exists but no milpa.kdl → WS-MEMBER-NO-MANIFEST (exit 1).
  - add-member guard 3a: milpa.kdl is itself a workspace → WS-MEMBER-IS-WORKSPACE (exit 1).
  - add-member guard 3b: milpa.kdl has no name → MAN-NAME-MISSING (exit 1).
  - add-member guard 4: name-duplicate among existing members → WS-MEMBER-DUPLICATE-NAME (exit 1).
  - remove-member happy path: drops member, writes manifest + lock.
  - remove-member guard 1: name/path not found → WS-REMOVE-MEMBER-NOT-FOUND (exit 1).
  - remove-member guard 2 (class-1): dangling MemberTarget override →
    WS-REMOVE-MEMBER-TARGET-EXISTS (exit 1).
  - remove-member guard 3 (class-2): dangling member-edge in another member →
    WS-REMOVE-MEMBER-REFERENCED (exit 1).

All tests use real filesystem (tmp_path) + empty mocked transport (no network,
no deps — workspace manifests have no deps in these unit tests).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.cli import cmd_workspace_add_member, cmd_workspace_remove_member
from milpa.context import MilpaEnv
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry
from milpa.manifest import WorkspaceManifest
from milpa.version import Strategy


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _empty_mocked_env(mocked_dir: Path, tmp_store: Path) -> MilpaEnv:
    """Build a MilpaEnv backed by an empty mocked transport (no deps)."""
    mocked_dir.mkdir(parents=True, exist_ok=True)
    store = CAStore(root=tmp_store)
    inner = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(inner, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


def _write_ws(root: Path, members: list[str]) -> None:
    """Write a minimal workspace milpa.kdl at root."""
    lines = "\n".join(f'    member "{m}"' for m in members)
    root.joinpath("milpa.kdl").write_text(
        f"workspace {{\n{lines}\n}}\n",
        encoding="utf-8",
    )


def _write_pkg(pkg_dir: Path, name: str | None) -> None:
    """Write a minimal package milpa.kdl in pkg_dir."""
    pkg_dir.mkdir(parents=True, exist_ok=True)
    if name is None:
        pkg_dir.joinpath("milpa.kdl").write_text('kind "library"\n', encoding="utf-8")
    else:
        pkg_dir.joinpath("milpa.kdl").write_text(
            f'name "{name}"\nkind "library"\n', encoding="utf-8"
        )


def _run_add(root: Path, env: MilpaEnv, member_path: str) -> int:
    return cmd_workspace_add_member(
        root, env, member_path=member_path, strategy=Strategy.MAXVER, max_parallel=1
    )


def _run_remove(root: Path, env: MilpaEnv, name_or_path: str) -> int:
    return cmd_workspace_remove_member(
        root, env, name_or_path=name_or_path, strategy=Strategy.MAXVER, max_parallel=1
    )


# ---------------------------------------------------------------------------
# add-member tests
# ---------------------------------------------------------------------------


def test_add_member_happy_path(tmp_path: Path) -> None:
    """add-member happy path: appends member, writes manifest and lockfile."""
    root = tmp_path / "ws"
    root.mkdir()
    member_a = root / "member-a"
    _write_pkg(member_a, "liba")
    _write_ws(root, ["member-a"])

    new_member = root / "member-b"
    _write_pkg(new_member, "libb")

    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")
    rc = _run_add(root, env, "member-b")

    assert rc == 0, "add-member happy path should exit 0"
    # manifest should now list both members
    text = (root / "milpa.kdl").read_text(encoding="utf-8")
    assert "member-a" in text
    assert "member-b" in text
    # lockfile should be written
    assert (root / "milpa.lock").exists(), "milpa.lock should be written"


def test_add_member_dir_missing(tmp_path: Path) -> None:
    """Guard 1: non-existent directory → WS-MEMBER-DIR-MISSING, exit 1."""
    root = tmp_path / "ws"
    root.mkdir()
    _write_ws(root, [])
    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")

    rc = _run_add(root, env, "nonexistent-dir")
    assert rc == 1


def test_add_member_no_manifest(tmp_path: Path) -> None:
    """Guard 2: dir exists but no milpa.kdl → WS-MEMBER-NO-MANIFEST, exit 1."""
    root = tmp_path / "ws"
    root.mkdir()
    _write_ws(root, [])
    empty_dir = root / "empty-member"
    empty_dir.mkdir()
    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")

    rc = _run_add(root, env, "empty-member")
    assert rc == 1


def test_add_member_is_workspace(tmp_path: Path) -> None:
    """Guard 3a: milpa.kdl is itself a workspace → WS-MEMBER-IS-WORKSPACE, exit 1."""
    root = tmp_path / "ws"
    root.mkdir()
    _write_ws(root, [])
    nested_ws = root / "nested"
    nested_ws.mkdir()
    # Write a workspace manifest (not a package manifest) in nested/.
    nested_ws.joinpath("milpa.kdl").write_text(
        'workspace {\n    member "sub"\n}\n', encoding="utf-8"
    )
    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")

    rc = _run_add(root, env, "nested")
    assert rc == 1


def test_add_member_no_name(tmp_path: Path) -> None:
    """Guard 3b: milpa.kdl has no name → MAN-NAME-MISSING, exit 1."""
    root = tmp_path / "ws"
    root.mkdir()
    _write_ws(root, [])
    noname = root / "noname"
    _write_pkg(noname, name=None)
    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")

    rc = _run_add(root, env, "noname")
    assert rc == 1


def test_add_member_duplicate_name(tmp_path: Path) -> None:
    """Guard 4: name already used by existing member → WS-MEMBER-DUPLICATE-NAME, exit 1."""
    root = tmp_path / "ws"
    root.mkdir()
    member_a = root / "member-a"
    _write_pkg(member_a, "liba")
    _write_ws(root, ["member-a"])

    # Another dir with the same package name.
    member_a2 = root / "member-a2"
    _write_pkg(member_a2, "liba")
    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")

    rc = _run_add(root, env, "member-a2")
    assert rc == 1


# ---------------------------------------------------------------------------
# remove-member tests
# ---------------------------------------------------------------------------


def test_remove_member_happy_path(tmp_path: Path) -> None:
    """remove-member happy path: drops member, writes manifest and lockfile."""
    root = tmp_path / "ws"
    root.mkdir()
    member_a = root / "member-a"
    member_b = root / "member-b"
    _write_pkg(member_a, "liba")
    _write_pkg(member_b, "libb")
    _write_ws(root, ["member-a", "member-b"])

    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")
    rc = _run_remove(root, env, "libb")

    assert rc == 0, "remove-member happy path should exit 0"
    text = (root / "milpa.kdl").read_text(encoding="utf-8")
    assert "member-a" in text, "member-a should remain"
    assert "member-b" not in text, "member-b should be removed"
    assert (root / "milpa.lock").exists(), "milpa.lock should be written"


def test_remove_member_by_path(tmp_path: Path) -> None:
    """remove-member by relative path instead of name."""
    root = tmp_path / "ws"
    root.mkdir()
    member_a = root / "member-a"
    _write_pkg(member_a, "liba")
    _write_ws(root, ["member-a"])

    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")
    rc = _run_remove(root, env, "member-a")

    assert rc == 0
    text = (root / "milpa.kdl").read_text(encoding="utf-8")
    assert "member-a" not in text


def test_remove_member_not_found(tmp_path: Path) -> None:
    """Guard 1: name/path not in workspace → WS-REMOVE-MEMBER-NOT-FOUND, exit 1."""
    root = tmp_path / "ws"
    root.mkdir()
    member_a = root / "member-a"
    _write_pkg(member_a, "liba")
    _write_ws(root, ["member-a"])

    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")
    rc = _run_remove(root, env, "libc")

    assert rc == 1


def test_remove_member_target_exists(tmp_path: Path) -> None:
    """Guard 2 (class-1): dangling MemberTarget override → WS-REMOVE-MEMBER-TARGET-EXISTS, exit 1."""
    root = tmp_path / "ws"
    root.mkdir()
    member_a = root / "member-a"
    member_b = root / "member-b"
    _write_pkg(member_a, "liba")
    _write_pkg(member_b, "libb")
    # Workspace manifest with an override targeting libb.
    root.joinpath("milpa.kdl").write_text(
        'workspace {\n'
        '    member "member-a"\n'
        '    member "member-b"\n'
        '    overrides {\n'
        '        pkg "dep-x" {\n'
        '            member "libb"\n'
        '        }\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )

    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")
    rc = _run_remove(root, env, "libb")

    assert rc == 1


def test_remove_member_referenced(tmp_path: Path) -> None:
    """Guard 3 (class-2): another member has a member-dep edge → WS-REMOVE-MEMBER-REFERENCED, exit 1."""
    root = tmp_path / "ws"
    root.mkdir()
    member_a = root / "member-a"
    member_b = root / "member-b"
    # member-a depends on libb via a member edge.
    member_a.mkdir()
    member_a.joinpath("milpa.kdl").write_text(
        'name "liba"\n'
        'kind "library"\n'
        'deps {\n'
        '    member "libb"\n'
        '}\n',
        encoding="utf-8",
    )
    _write_pkg(member_b, "libb")
    _write_ws(root, ["member-a", "member-b"])

    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")
    rc = _run_remove(root, env, "libb")

    assert rc == 1
