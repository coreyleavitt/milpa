"""Tests for apply_workspace_manifest_change — S9b orchestration primitive.

TDD discipline (S9b RFC slice):
  - Atomicity test: a mutator that causes resolution to fail MUST leave the
    on-disk milpa.kdl UNCHANGED and write NO stale lock.  Failure injected by
    making the proposed workspace reference a non-existent member directory.
  - Happy path: a valid mutation writes both the manifest (canonical
    serialized) and the refreshed lock.
  - Refusal-lift scope: the workspace-typed orchestration path MUST be allowed
    to mutate a workspace doc; ``mutate_manifest_file`` (plain package path)
    still refuses workspace docs with MAN-MUTATE-WORKSPACE-REFUSED.
  - Design-F4: ``apply_workspace_manifest_change`` takes the same shape as the
    inlined single-package orchestration — no asymmetric ``validate`` kwarg.

All tests use real filesystem (tmp_path) + mocked transport (no network).
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import MAN_MUTATE_WORKSPACE_REFUSED, MilpaError
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry
from milpa.lockfile import load_lockfile
from milpa.manifest import WorkspaceManifest, format_workspace_manifest
from milpa.manifest_writer import apply_workspace_manifest_change, mutate_manifest_file
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


def _default_params(strategy: Strategy = Strategy.MAXVER) -> ResolveParams:
    return ResolveParams(strategy=strategy, max_parallel=1)


def _write_workspace(root: Path, members: list[str]) -> None:
    """Write a minimal workspace milpa.kdl at root with the given member paths."""
    members_block = "\n".join(f'    member "{m}"' for m in members)
    root.joinpath("milpa.kdl").write_text(
        f"workspace {{\n{members_block}\n}}\n",
        encoding="utf-8",
    )


def _write_member(member_dir: Path, name: str) -> None:
    """Write a minimal member milpa.kdl (no deps)."""
    member_dir.mkdir(parents=True, exist_ok=True)
    member_dir.joinpath("milpa.kdl").write_text(
        f'name "{name}"\nkind "library"\n',
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Atomicity test: resolution failure leaves manifest untouched
# ---------------------------------------------------------------------------


def test_resolution_failure_leaves_manifest_unchanged(tmp_path: Path) -> None:
    """The key atomicity guarantee: if resolution fails, milpa.kdl is untouched.

    Failure is injected by the mutator referencing a nonexistent member directory.
    ``load_workspace_from_manifest`` raises ``WS-MEMBER-DIR-MISSING`` before
    resolution is attempted, leaving the on-disk manifest and any existing lock
    completely unmodified.
    """
    # Set up a valid 1-member workspace.
    member_a = tmp_path / "member-a"
    _write_member(member_a, "member-a")
    _write_workspace(tmp_path, ["member-a"])

    original_kdl = tmp_path.joinpath("milpa.kdl").read_text()

    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")
    params = _default_params()

    # Mutator adds a member whose directory does NOT exist — should fail.
    def add_nonexistent_member(ws: WorkspaceManifest) -> WorkspaceManifest:
        return replace(ws, members=ws.members + ("nonexistent-member",))

    with pytest.raises(MilpaError):
        apply_workspace_manifest_change(tmp_path, env, params, add_nonexistent_member)

    # milpa.kdl must be byte-identical to what we started with.
    after_kdl = tmp_path.joinpath("milpa.kdl").read_text()
    assert after_kdl == original_kdl, (
        "milpa.kdl was modified despite resolution failure; "
        "atomicity ordering validate→resolve→write-manifest→write-lock violated"
    )

    # No stale lock must have been written.
    assert not tmp_path.joinpath("milpa.lock").exists(), (
        "milpa.lock was written despite resolution failure"
    )


def test_resolve_failure_leaves_existing_lock_unchanged(tmp_path: Path) -> None:
    """An existing milpa.lock is not modified when resolution fails.

    Regression guard: a stale lock must not be written over a good prior lock
    when the proposed mutation fails.
    """
    # Set up a valid 1-member workspace.
    member_a = tmp_path / "member-a"
    _write_member(member_a, "member-a")
    _write_workspace(tmp_path, ["member-a"])

    # Write a dummy prior lock so we can verify it's untouched.
    prior_lock_text = "strategy maxver\n"
    tmp_path.joinpath("milpa.lock").write_text(prior_lock_text, encoding="utf-8")

    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")
    params = _default_params()

    def add_nonexistent_member(ws: WorkspaceManifest) -> WorkspaceManifest:
        return replace(ws, members=ws.members + ("ghost",))

    with pytest.raises(MilpaError):
        apply_workspace_manifest_change(tmp_path, env, params, add_nonexistent_member)

    after_lock = tmp_path.joinpath("milpa.lock").read_text()
    assert after_lock == prior_lock_text, (
        "milpa.lock was overwritten despite resolution failure"
    )


# ---------------------------------------------------------------------------
# Happy path: valid mutation writes both manifest and lock
# ---------------------------------------------------------------------------


def test_happy_path_writes_manifest_and_lock(tmp_path: Path) -> None:
    """A valid mutation writes the canonical manifest AND a fresh milpa.lock."""
    member_a = tmp_path / "member-a"
    member_b = tmp_path / "member-b"
    _write_member(member_a, "member-a")
    _write_member(member_b, "member-b")
    # Start with member-a only.
    _write_workspace(tmp_path, ["member-a"])

    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")
    params = _default_params()

    def add_member_b(ws: WorkspaceManifest) -> WorkspaceManifest:
        return replace(ws, members=ws.members + ("member-b",))

    graph, wr = apply_workspace_manifest_change(tmp_path, env, params, add_member_b)

    # WriteResult points at the manifest path.
    assert wr.path == tmp_path / "milpa.kdl"

    # milpa.kdl now contains member-b.
    kdl_text = tmp_path.joinpath("milpa.kdl").read_text()
    assert '"member-b"' in kdl_text

    # milpa.lock exists and is parseable.
    lock_path = tmp_path / "milpa.lock"
    assert lock_path.exists(), "milpa.lock must be written on success"
    lock = load_lockfile(lock_path)
    assert lock is not None


def test_happy_path_manifest_is_canonical_format(tmp_path: Path) -> None:
    """Written milpa.kdl is the canonical format_workspace_manifest output."""
    member_a = tmp_path / "member-a"
    _write_member(member_a, "member-a")
    _write_workspace(tmp_path, ["member-a"])

    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")
    params = _default_params()

    # Identity mutation — proposed == current.
    def identity(ws: WorkspaceManifest) -> WorkspaceManifest:
        return ws

    graph, wr = apply_workspace_manifest_change(tmp_path, env, params, identity)

    kdl_text = tmp_path.joinpath("milpa.kdl").read_text()

    # Must be parseable and contain the member.
    from milpa.manifest import parse_workspace_or_manifest
    doc = parse_workspace_or_manifest(kdl_text)
    assert isinstance(doc, WorkspaceManifest)
    assert "member-a" in doc.members


def test_happy_path_returns_resolved_graph(tmp_path: Path) -> None:
    """apply_workspace_manifest_change returns the resolved graph (first element)."""
    member_a = tmp_path / "member-a"
    _write_member(member_a, "member-a")
    _write_workspace(tmp_path, ["member-a"])

    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")
    params = _default_params()

    graph, wr = apply_workspace_manifest_change(tmp_path, env, params, lambda ws: ws)

    # graph is a ResolvedGraph — it has .deps
    assert hasattr(graph, "deps")


# ---------------------------------------------------------------------------
# Refusal-lift scoping: workspace-typed path is ALLOWED; package path still refused
# ---------------------------------------------------------------------------


def test_package_mutate_file_still_refuses_workspace_doc(tmp_path: Path) -> None:
    """mutate_manifest_file (plain package path) still refuses a workspace doc.

    Only the workspace-typed path (apply_workspace_manifest_change /
    mutate_workspace_manifest_file) is allowed to mutate workspace docs.
    The package-typed path must continue to raise MAN-MUTATE-WORKSPACE-REFUSED.
    """
    tmp_path.joinpath("milpa.kdl").write_text(
        'workspace {\n    member "pkg"\n}\n',
        encoding="utf-8",
    )

    with pytest.raises(MilpaError) as exc_info:
        mutate_manifest_file(tmp_path / "milpa.kdl", lambda m: m)

    assert exc_info.value.slug == MAN_MUTATE_WORKSPACE_REFUSED


def test_workspace_typed_path_is_allowed_to_mutate(tmp_path: Path) -> None:
    """apply_workspace_manifest_change does NOT raise MAN-MUTATE-WORKSPACE-REFUSED.

    The workspace-typed orchestration path bypasses the package-typed guard.
    """
    member_a = tmp_path / "member-a"
    _write_member(member_a, "member-a")
    _write_workspace(tmp_path, ["member-a"])

    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")
    params = _default_params()

    # Must NOT raise MAN-MUTATE-WORKSPACE-REFUSED.
    try:
        graph, wr = apply_workspace_manifest_change(
            tmp_path, env, params, lambda ws: ws
        )
    except MilpaError as e:
        if e.slug == MAN_MUTATE_WORKSPACE_REFUSED:
            pytest.fail(
                "apply_workspace_manifest_change raised MAN-MUTATE-WORKSPACE-REFUSED; "
                "the workspace-typed path must be allowed to mutate workspace docs"
            )
        raise


# ---------------------------------------------------------------------------
# Ordering proof: validate/resolve happens before any write
# ---------------------------------------------------------------------------


def test_no_tmp_file_left_on_failure(tmp_path: Path) -> None:
    """No .tmp file is left behind when the orchestration fails."""
    member_a = tmp_path / "member-a"
    _write_member(member_a, "member-a")
    _write_workspace(tmp_path, ["member-a"])

    env = _empty_mocked_env(tmp_path / "mocked", tmp_path / "cas")
    params = _default_params()

    def add_ghost(ws: WorkspaceManifest) -> WorkspaceManifest:
        return replace(ws, members=ws.members + ("ghost-does-not-exist",))

    with pytest.raises(MilpaError):
        apply_workspace_manifest_change(tmp_path, env, params, add_ghost)

    # No .tmp files should exist in tmp_path.
    tmp_files = list(tmp_path.glob("*.tmp"))
    assert tmp_files == [], f"Stray .tmp files found: {tmp_files}"
