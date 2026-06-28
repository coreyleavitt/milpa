"""S1 alias-coverage + dev-dep frozen-gate tests — RED → GREEN → REFACTOR.

Bug #142: ``FROZEN-MANIFEST-DEP-NOT-IN-LOCK`` false-positives when a manifest
dep is known only as an alias in the lockfile (not as the canonical name).

Bug #178: Rust ``check_manifest_alignment`` skips ``dev_deps`` — the Python
side already checks them (frozen.py:199 uses ``deps + dev_deps``), but the
Rust-facing conformance fixtures pin the behaviour for both.

Behaviours under test (S1 scope only):

1. Single-package ``resolve_frozen``: manifest has BOTH ``foo`` and ``bar`` as
   separate deps; lockfile has canonical ``foo`` with alias ``bar``.  Condition 2
   (FROZEN-MANIFEST-DEP-NOT-IN-LOCK) must NOT fire for ``bar`` once the alias-
   aware ``_locked_index`` helper is used.

2. Workspace ``resolve_workspace_frozen``: same scenario in a workspace member.

3. Dev-dep gate (Python SSOT confirmation): manifest has a ``dev_dep`` whose
   name is absent from the lockfile → FROZEN-MANIFEST-DEP-NOT-IN-LOCK.
   (Python already passes; the conformance fixture pins Rust too.)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv
from milpa.errors import FROZEN_MANIFEST_DEP_NOT_IN_LOCK, MilpaError
from milpa.frozen import resolve_frozen, resolve_workspace_frozen
from milpa.lockfile import (
    GitProvenanceRecord,
    LockedDep,
    Lockfile,
)
from milpa.manifest import Manifest, UrlDep
from milpa.workspace import LoadedMember, LoadedWorkspace


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _git_prov(url: str) -> GitProvenanceRecord:
    return GitProvenanceRecord(url=url, ref="main", commit_sha="deadbeef", origin="observed")


def _locked(
    name: str,
    identity: str,
    aliases: tuple[str, ...] = (),
) -> LockedDep:
    return LockedDep(
        name=name,
        identity=identity,
        version="0.1.0",
        src_dir="src",
        requires=(),
        provenances=(_git_prov(f"https://example.com/{name}.git"),),
        aliases=aliases,
    )


def _url_dep(name: str) -> UrlDep:
    return UrlDep(
        name=name,
        git=f"https://example.com/{name}.git",
        ref="main",
        mirrors=[],
        predicates=[],
        flag_requests=[],
    )


def _manifest(deps: list, dev_deps: list | None = None) -> Manifest:
    return Manifest(
        name="testpkg",
        kind="application",
        src_dir="src",
        deps=deps,
        dev_deps=dev_deps or [],
        overrides=[],
        flags=[],
        self_mirrors=[],
        cas_dir="",
        spec_version=1,
        spec_version_explicit=False,
        attestation_policy=None,
    )


def _env_with_identity(tmp_path: Path, identity: str) -> MilpaEnv:
    """Build a MilpaEnv whose CAS contains a seeded entry for ``identity``."""
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)

    # Seed a minimal source tree — content doesn't matter for the condition-2
    # (alias lookup) tests; only CAS presence matters for condition-5.
    seed_dir = tmp_path / "seed"
    seed_dir.mkdir()
    (seed_dir / "lib.nim").write_text("# seed\n", encoding="utf-8")

    from milpa.identity import compute_content_hash
    real_id = compute_content_hash(seed_dir)
    store.admit(seed_dir, real_id)

    # We need the store to claim it contains ``identity`` so condition-5 passes.
    # Use the real content hash.
    return MilpaEnv(fetcher=None, index=None, store=store), real_id  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Test 1 — single-package alias coverage (#142)
# ---------------------------------------------------------------------------


class TestSinglePkgAliasCoverage:
    """resolve_frozen must NOT raise FROZEN-MANIFEST-DEP-NOT-IN-LOCK when a
    manifest dep is present only as an alias in the lockfile."""

    def test_alias_dep_passes_condition2(self, tmp_path: Path) -> None:
        """Manifest has foo + bar; lockfile has canonical foo with alias bar.

        RED: before fix, locked_by_name = {foo: ...}, bar missing → raises.
        GREEN: _locked_index maps bar → LockedDep(foo) → passes.
        """
        env, identity = _env_with_identity(tmp_path, "placeholder")

        locked = _locked("foo", identity=identity, aliases=("bar",))
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        # Manifest declares BOTH foo and bar as separate deps.
        manifest = _manifest(deps=[_url_dep("foo"), _url_dep("bar")])

        deps_dir = tmp_path / "_deps"
        # Should NOT raise FROZEN-MANIFEST-DEP-NOT-IN-LOCK for "bar".
        graph = resolve_frozen(manifest, lockfile, env, deps_dir)
        assert len(graph.deps) == 1  # one canonical dep in the graph
        assert graph.deps[0].name == "foo"

    def test_only_alias_dep_passes_condition2(self, tmp_path: Path) -> None:
        """Manifest has only bar (the alias); lockfile has canonical foo with alias bar.

        A manifest that references only the alias name must still find the
        lockfile entry via the alias-aware index.
        """
        env, identity = _env_with_identity(tmp_path, "placeholder")

        locked = _locked("foo", identity=identity, aliases=("bar",))
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        # Manifest declares only bar (the alias).
        manifest = _manifest(deps=[_url_dep("bar")])

        deps_dir = tmp_path / "_deps"
        graph = resolve_frozen(manifest, lockfile, env, deps_dir)
        assert len(graph.deps) == 1
        assert graph.deps[0].name == "foo"

    def test_alias_not_in_lock_still_raises(self, tmp_path: Path) -> None:
        """A dep truly absent from the lockfile (not even an alias) must still raise."""
        env, identity = _env_with_identity(tmp_path, "placeholder")

        locked = _locked("foo", identity=identity)
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = _manifest(deps=[_url_dep("foo"), _url_dep("truly_absent")])

        deps_dir = tmp_path / "_deps"
        with pytest.raises(MilpaError) as exc_info:
            resolve_frozen(manifest, lockfile, env, deps_dir)
        assert exc_info.value.slug == FROZEN_MANIFEST_DEP_NOT_IN_LOCK


# ---------------------------------------------------------------------------
# Test 2 — workspace alias coverage (#142)
# ---------------------------------------------------------------------------


class TestWorkspaceAliasCoverage:
    """resolve_workspace_frozen must also be alias-aware for condition 2."""

    def _make_workspace(self, member_manifest: Manifest, member_abs_dir: Path) -> LoadedWorkspace:
        from milpa.manifest import WorkspaceManifest as _WsManifest
        ws_manifest = _WsManifest(members=("pkg-a",), overrides=())
        member = LoadedMember(
            rel_path="pkg-a",
            abs_dir=member_abs_dir,
            manifest=member_manifest,
        )
        return LoadedWorkspace(
            root_dir=member_abs_dir.parent,
            workspace_manifest=ws_manifest,
            members=(member,),
        )

    def test_ws_alias_dep_passes_condition2(self, tmp_path: Path) -> None:
        """Workspace member with alias dep must pass condition 2."""
        env, identity = _env_with_identity(tmp_path, "placeholder")

        member_dir = tmp_path / "pkg-a"
        member_dir.mkdir()
        # Seed the member dir with a minimal milpa.kdl so compute_content_hash works.
        (member_dir / "milpa.kdl").write_text(
            'name "pkg-a"\nkind "library"\n', encoding="utf-8"
        )

        from milpa.identity import compute_content_hash
        from milpa.lockfile import MemberProvenanceRecord
        member_identity = compute_content_hash(member_dir)

        locked_ext = _locked("foo", identity=identity, aliases=("bar",))
        locked_member = LockedDep(
            name="pkg-a",
            identity=member_identity,
            version="0.0.1",
            src_dir="src",
            requires=("foo",),
            provenances=(
                MemberProvenanceRecord(name="pkg-a", origin="observed"),
            ),
            aliases=(),
        )
        lockfile = Lockfile(deps=(locked_ext, locked_member), strategy="maxver")

        # Member manifest has BOTH foo and bar as deps (it's named "pkg-a" to match).
        member_manifest = Manifest(
            name="pkg-a",
            kind="library",
            src_dir="src",
            deps=[_url_dep("foo"), _url_dep("bar")],
            dev_deps=[],
            overrides=[],
            flags=[],
            self_mirrors=[],
            cas_dir="",
            spec_version=1,
            spec_version_explicit=False,
            attestation_policy=None,
        )
        workspace = self._make_workspace(member_manifest, member_dir)

        deps_dir = tmp_path / "_deps"
        # Must not raise FROZEN-MANIFEST-DEP-NOT-IN-LOCK for "bar".
        graph = resolve_workspace_frozen(workspace, lockfile, env, deps_dir)
        names = {d.name for d in graph.deps}
        assert "foo" in names


# ---------------------------------------------------------------------------
# Test 3 — dev-dep not in lock raises FROZEN-MANIFEST-DEP-NOT-IN-LOCK (#178)
# ---------------------------------------------------------------------------


class TestDevDepNotInLock:
    """A manifest dev-dep absent from the lockfile must raise condition 2.

    Python already passes this (frozen.py:199 checks dev_deps).
    This test pins the behaviour and provides coverage for the conformance
    fixture that also covers the Rust impl.
    """

    def test_dev_dep_absent_from_lock_raises(self, tmp_path: Path) -> None:
        env, identity = _env_with_identity(tmp_path, "placeholder")

        locked = _locked("foo", identity=identity)
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        # dev_dep "devtool" is NOT in the lockfile.
        manifest = _manifest(
            deps=[_url_dep("foo")],
            dev_deps=[_url_dep("devtool")],
        )

        deps_dir = tmp_path / "_deps"
        with pytest.raises(MilpaError) as exc_info:
            resolve_frozen(manifest, lockfile, env, deps_dir)
        assert exc_info.value.slug == FROZEN_MANIFEST_DEP_NOT_IN_LOCK

    def test_dev_dep_in_lock_passes(self, tmp_path: Path) -> None:
        """A dev-dep that IS in the lockfile must not raise."""
        env, identity = _env_with_identity(tmp_path, "placeholder")

        locked_foo = _locked("foo", identity=identity)
        locked_dev = _locked("devtool", identity=identity)
        lockfile = Lockfile(deps=(locked_foo, locked_dev), strategy="maxver")
        manifest = _manifest(
            deps=[_url_dep("foo")],
            dev_deps=[_url_dep("devtool")],
        )

        deps_dir = tmp_path / "_deps"
        graph = resolve_frozen(manifest, lockfile, env, deps_dir)
        assert len(graph.deps) == 2
