"""D-frozen slice tests — frozen reconstruction preserves aliases + provenances.

TDD: RED → GREEN → REFACTOR.

Bug: Python ``_reconstruct_from_locked`` was missing ``aliases=locked.aliases``.
Rust ``resolved_from_locked`` already carries aliases correctly.
Fix: add ``aliases=locked.aliases`` to the Python ResolvedDep construction.

Behaviors under test:
1. (tracer) Frozen reconstruction carries aliases from the lockfile (the bug).
2. Frozen reconstruction carries ALL provenances (not just the first).
3. Alias symlinks materialize in _deps/ after resolve_frozen (via rebuild_deps_view).
4. Regression: plain (non-deduped, single-provenance) dep still works.
5. Workspace frozen path also carries aliases + provenances.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv
from milpa.frozen import resolve_frozen, resolve_workspace_frozen
import pytest

from milpa.errors import (
    FROZEN_CONSTRAINT_UNSATISFIED,
    FROZEN_LOCKED_VERSION_UNPARSEABLE,
    FROZEN_MANIFEST_DEP_NOT_IN_LOCK,
    MilpaError,
)
from milpa.lockfile import (
    GitProvenanceRecord,
    LockedDep,
    Lockfile,
    MemberProvenanceRecord,
    ResolvedDep,
    parse_lockfile,
    format_lockfile,
    from_graph,
)
from milpa.manifest import Manifest, NamedDep, UrlDep
from milpa.workspace import LoadedWorkspace


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _git_prov(url: str, ref: str = "main", sha: str = "abcdef01", *, origin: str = "observed") -> GitProvenanceRecord:
    return GitProvenanceRecord(url=url, ref=ref, commit_sha=sha, origin=origin)


def _locked_dep(
    name: str,
    identity: str,
    version: str = "0.0.1",
    src_dir: str = "src",
    provenances: tuple[GitProvenanceRecord, ...] | None = None,
    aliases: tuple[str, ...] = (),
) -> LockedDep:
    if provenances is None:
        provenances = (_git_prov(f"https://example.com/{name}.git"),)
    return LockedDep(
        name=name,
        identity=identity,
        version=version,
        src_dir=src_dir,
        requires=(),
        provenances=provenances,
        aliases=aliases,
    )


def _manifest_with_dep(name: str) -> Manifest:
    return Manifest(
        name="testapp",
        kind="application",
        src_dir="",
        deps=[UrlDep(name=name, git=f"https://example.com/{name}.git", ref="main", mirrors=[], predicates=[], flag_requests=[])],
        dev_deps=[],
        overrides=[],
        flags=[],
        self_mirrors=[],
        cas_dir="",
        spec_version=1,
        spec_version_explicit=False,
        attestation_policy=None,
    )


def _manifest_empty() -> Manifest:
    return Manifest(
        name="testapp",
        kind="application",
        src_dir="",
        deps=[],
        dev_deps=[],
        overrides=[],
        flags=[],
        self_mirrors=[],
        cas_dir="",
        spec_version=1,
        spec_version_explicit=False,
        attestation_policy=None,
    )


def _make_env_with_tree(tmp_path: Path) -> tuple[MilpaEnv, str]:
    """Create a MilpaEnv with a CAS that holds one small source tree.

    Returns (env, identity) where identity is the content hash of the seeded tree.
    """
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)

    # Seed a minimal source tree into the CAS.
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "foo.nim").write_text("# minimal nim source\n", encoding="utf-8")
    from milpa.identity import compute_content_hash
    identity = compute_content_hash(seed)
    store.admit(seed, identity)

    return MilpaEnv(fetcher=None, index=None, store=store), identity  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Test 1 — tracer: frozen carries aliases (proves the bug)
# ---------------------------------------------------------------------------


class TestFrozenCarriesAliases:
    """Frozen reconstruction must carry aliases from the LockedDep.

    Before the fix: _reconstruct_from_locked omits aliases= → ResolvedDep.aliases=().
    After the fix: aliases=locked.aliases is passed → aliases are preserved.
    """

    def test_aliases_carried_through_frozen_reconstruction(self, tmp_path: Path) -> None:
        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        locked = _locked_dep(
            "foo",
            identity=identity,
            provenances=(_git_prov("https://example.com/foo.git"),),
            aliases=("bar",),
        )
        lockfile = Lockfile(
            deps=(locked,),
            strategy="maxver",
        )
        manifest = _manifest_with_dep("foo")

        graph = resolve_frozen(manifest, lockfile, env, deps_dir)

        assert len(graph.deps) == 1
        dep = graph.deps[0]
        assert dep.name == "foo"
        # The bug: before fix, dep.aliases == () — this assertion fails RED.
        assert dep.aliases == ("bar",), (
            f"frozen reconstruction must carry aliases from LockedDep; "
            f"got dep.aliases={dep.aliases!r}, expected ('bar',)"
        )

    def test_multiple_aliases_all_carried(self, tmp_path: Path) -> None:
        """Three aliases on a single lockfile entry — all must appear on the ResolvedDep."""
        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        locked = _locked_dep(
            "foo",
            identity=identity,
            provenances=(_git_prov("https://example.com/foo.git"),),
            aliases=("aaa", "bar", "zzz"),  # lex-sorted
        )
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = _manifest_empty()  # no constraint check needed

        graph = resolve_frozen(manifest, lockfile, env, deps_dir)

        dep = graph.deps[0]
        assert dep.aliases == ("aaa", "bar", "zzz"), (
            f"all three aliases must be carried; got {dep.aliases!r}"
        )


# ---------------------------------------------------------------------------
# Test 1b — RFC per-entry-attestation.md P2 (§8 Command Coverage): the frozen
# fetch path carries the lockfile's attestation CLAIM through, nothing
# re-checked. Mirrors TestFrozenCarriesAliases's tracer/regression shape.
# ---------------------------------------------------------------------------


class TestFrozenCarriesAttestation:
    def test_attestation_carried_through_frozen_reconstruction(self, tmp_path: Path) -> None:
        import dataclasses

        from milpa.lockfile import LockAttestation
        from milpa.registry import AuthorSigned, EntryAttestation, RekorRef

        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        att = LockAttestation(
            kind=AuthorSigned(signer="https://example.com/wf.yaml"),
            rekor=RekorRef(uuid="u", log_index="1", integrated_time="2"),
        )
        locked = dataclasses.replace(_locked_dep("foo", identity=identity), attestation=att)
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = _manifest_with_dep("foo")

        graph = resolve_frozen(manifest, lockfile, env, deps_dir)

        dep = graph.deps[0]
        assert dep.attestation == EntryAttestation(kind=att.kind, rekor=att.rekor, bundle_pin=None)

    def test_attestation_namespace_carried_through_frozen_reconstruction(
        self, tmp_path: Path
    ) -> None:
        # CR13/4 (updated for S5's field-duplication audit,
        # rfc-origin-as-identity.md §4.4 B2/G10): ``ResolvedDep.
        # registry_namespace`` is DELETED — the offline subject-
        # reconstruction namespace now lives on ``source_id.namespace``
        # (a RegistrySourceId), carried straight through frozen
        # reconstruction via the lockfile's own structured ``source { … }``
        # node, never a separate parallel field.
        import dataclasses

        from milpa.lockfile import LockAttestation
        from milpa.manifest import NamedDep
        from milpa.registry import AuthorSigned
        from milpa.source_id import RegistrySourceId

        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        att = LockAttestation(
            kind=AuthorSigned(signer="https://example.com/wf.yaml"),
            namespace="ns1",
        )
        locked = dataclasses.replace(
            _locked_dep("foo", identity=identity),
            attestation=att,
            source_id=RegistrySourceId(registry="tianguis", namespace="ns1", name="foo"),
        )
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = dataclasses.replace(
            _manifest_empty(),
            deps=[NamedDep(name="foo", constraint=None, predicates=[], flag_requests=[])],
        )

        graph = resolve_frozen(manifest, lockfile, env, deps_dir)

        dep = graph.deps[0]
        assert isinstance(dep.source_id, RegistrySourceId)
        assert dep.source_id.namespace == "ns1"

    def test_no_attestation_stays_none(self, tmp_path: Path) -> None:
        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        locked = _locked_dep("foo", identity=identity)
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = _manifest_with_dep("foo")

        graph = resolve_frozen(manifest, lockfile, env, deps_dir)

        assert graph.deps[0].attestation is None


# ---------------------------------------------------------------------------
# Test 2 — provenances: all provenances carried (not just first)
# ---------------------------------------------------------------------------


class TestFrozenCarriesAllProvenances:
    """Frozen reconstruction must carry the full provenance tuple."""

    def test_single_provenance_carried(self, tmp_path: Path) -> None:
        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        prov = _git_prov("https://example.com/foo.git", sha="abc123")
        locked = _locked_dep("foo", identity=identity, provenances=(prov,))
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = _manifest_empty()

        graph = resolve_frozen(manifest, lockfile, env, deps_dir)

        dep = graph.deps[0]
        assert len(dep.provenances) == 1
        assert dep.provenances[0] == prov

    def test_observed_plus_declared_provenances_both_carried(self, tmp_path: Path) -> None:
        """observed + declared provenance tuple — both must appear on ResolvedDep."""
        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        observed = _git_prov("https://example.com/foo.git", sha="obs123", origin="observed")
        declared = _git_prov("https://mirror.example.com/foo.git", sha=None, origin="declared")
        locked = _locked_dep("foo", identity=identity, provenances=(declared, observed))
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = _manifest_empty()

        graph = resolve_frozen(manifest, lockfile, env, deps_dir)

        dep = graph.deps[0]
        assert len(dep.provenances) == 2, (
            f"both provenances must be carried; got {dep.provenances!r}"
        )
        origins = {p.origin for p in dep.provenances}
        assert "observed" in origins and "declared" in origins, (
            f"both origins must be present; got {origins!r}"
        )


# ---------------------------------------------------------------------------
# Test 3 — alias symlinks materialize in _deps/ after resolve_frozen
# ---------------------------------------------------------------------------


class TestFrozenAliasSymlinksCreate:
    """After resolve_frozen on a deduped dep, _deps/<alias> exists and points
    to the same store entry as _deps/<canonical>."""

    def test_alias_symlink_created(self, tmp_path: Path) -> None:
        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        locked = _locked_dep(
            "foo",
            identity=identity,
            provenances=(_git_prov("https://example.com/foo.git"),),
            aliases=("bar",),
        )
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = _manifest_with_dep("foo")

        resolve_frozen(manifest, lockfile, env, deps_dir)

        # Canonical symlink must exist.
        canonical = deps_dir / "foo"
        assert canonical.is_symlink(), "_deps/foo must be a symlink"
        assert canonical.exists(), "_deps/foo symlink must not be dangling"

        # Alias symlink must exist and resolve to the same CAS entry.
        alias_link = deps_dir / "bar"
        assert alias_link.is_symlink(), "_deps/bar alias symlink must be created"
        assert alias_link.exists(), "_deps/bar alias symlink must not be dangling"

        import os
        assert os.path.realpath(alias_link) == os.path.realpath(canonical), (
            "_deps/bar and _deps/foo must resolve to the same CAS entry"
        )

    def test_nim_cfg_includes_alias_path(self, tmp_path: Path) -> None:
        """nim.cfg must include a --path: line for the alias name."""
        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        locked = _locked_dep(
            "foo",
            identity=identity,
            src_dir="src",
            provenances=(_git_prov("https://example.com/foo.git"),),
            aliases=("bar",),
        )
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = _manifest_with_dep("foo")

        graph = resolve_frozen(manifest, lockfile, env, deps_dir)

        from milpa.nimcfg import format_nimcfg
        nimcfg = format_nimcfg(graph, deps_dir=Path("_deps"), self_src_dir="")

        assert '--path:"_deps/foo/src"' in nimcfg, f"canonical --path missing in nim.cfg:\n{nimcfg}"
        assert '--path:"_deps/bar/src"' in nimcfg, f"alias --path missing in nim.cfg:\n{nimcfg}"


# ---------------------------------------------------------------------------
# Test 4 — regression: plain non-deduped dep works after fix
# ---------------------------------------------------------------------------


class TestFrozenPlainDepRegression:
    """A plain (non-deduped, single-provenance) dep must still reconstruct correctly."""

    def test_plain_dep_no_aliases(self, tmp_path: Path) -> None:
        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        locked = _locked_dep("foo", identity=identity)
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = _manifest_with_dep("foo")

        graph = resolve_frozen(manifest, lockfile, env, deps_dir)

        assert len(graph.deps) == 1
        dep = graph.deps[0]
        assert dep.name == "foo"
        assert dep.identity == identity
        assert dep.aliases == (), f"plain dep must have empty aliases; got {dep.aliases!r}"
        assert len(dep.provenances) == 1
        # Canonical symlink exists.
        assert (deps_dir / "foo").is_symlink()


# ---------------------------------------------------------------------------
# Test 5 — workspace frozen path also carries aliases + provenances
# ---------------------------------------------------------------------------


class TestWorkspaceFrozenCarriesAliasesAndProvenances:
    """resolve_workspace_frozen also passes through _reconstruct_from_locked,
    so it must also carry aliases after the fix."""

    def test_workspace_frozen_carries_aliases(self, tmp_path: Path) -> None:
        """Workspace frozen path: external dep with alias must carry aliases."""
        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        # Build a minimal workspace with one member (empty deps).
        root_dir = tmp_path / "project"
        root_dir.mkdir()
        (root_dir / "milpa.kdl").write_text(
            'workspace {\n    member "mylib"\n}\n', encoding="utf-8"
        )
        lib_dir = root_dir / "mylib"
        lib_dir.mkdir()
        (lib_dir / "milpa.kdl").write_text(
            'name "mylib"\nkind "library"\n', encoding="utf-8"
        )

        from milpa.workspace import load_workspace
        workspace = load_workspace(root_dir)

        # Lockfile: one external dep (with alias) + one member dep.
        from milpa.identity import compute_content_hash
        member_identity = compute_content_hash(lib_dir)

        from milpa.lockfile import MemberProvenanceRecord
        external_locked = _locked_dep(
            "foo",
            identity=identity,
            provenances=(_git_prov("https://example.com/foo.git"),),
            aliases=("bar",),
        )
        member_locked = LockedDep(
            name="mylib",
            identity=member_identity,
            version="0.0.1",
            src_dir="",
            requires=(),
            provenances=(MemberProvenanceRecord(name="mylib"),),
            aliases=(),
        )
        lockfile = Lockfile(
            deps=(external_locked, member_locked),
            strategy="maxver",
        )

        graph = resolve_workspace_frozen(workspace, lockfile, env, deps_dir)

        # External dep carries aliases.
        ext_dep = next((d for d in graph.deps if d.name == "foo"), None)
        assert ext_dep is not None, "external dep 'foo' must be in graph"
        assert ext_dep.aliases == ("bar",), (
            f"workspace frozen: external dep aliases must be carried; got {ext_dep.aliases!r}"
        )

        # Alias symlink was created.
        assert (deps_dir / "bar").is_symlink(), "_deps/bar alias symlink must exist in workspace frozen"

    def test_workspace_frozen_carries_multiple_provenances(self, tmp_path: Path) -> None:
        """Workspace frozen path: external dep with two provenances carries both."""
        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        root_dir = tmp_path / "project"
        root_dir.mkdir()
        (root_dir / "milpa.kdl").write_text(
            'workspace {\n    member "mylib"\n}\n', encoding="utf-8"
        )
        lib_dir = root_dir / "mylib"
        lib_dir.mkdir()
        (lib_dir / "milpa.kdl").write_text(
            'name "mylib"\nkind "library"\n', encoding="utf-8"
        )

        from milpa.workspace import load_workspace
        workspace = load_workspace(root_dir)

        from milpa.identity import compute_content_hash
        member_identity = compute_content_hash(lib_dir)

        observed = _git_prov("https://example.com/foo.git", sha="obs456", origin="observed")
        declared = _git_prov("https://mirror.example.com/foo.git", sha=None, origin="declared")

        from milpa.lockfile import MemberProvenanceRecord
        external_locked = _locked_dep(
            "foo",
            identity=identity,
            provenances=(declared, observed),  # declared < observed per sort key
        )
        member_locked = LockedDep(
            name="mylib",
            identity=member_identity,
            version="0.0.1",
            src_dir="",
            requires=(),
            provenances=(MemberProvenanceRecord(name="mylib"),),
        )
        lockfile = Lockfile(
            deps=(external_locked, member_locked),
            strategy="maxver",
        )

        graph = resolve_workspace_frozen(workspace, lockfile, env, deps_dir)

        ext_dep = next((d for d in graph.deps if d.name == "foo"), None)
        assert ext_dep is not None
        assert len(ext_dep.provenances) == 2, (
            f"workspace frozen: both provenances must be carried; got {ext_dep.provenances!r}"
        )


# ---------------------------------------------------------------------------
# Fix 4 (R1-7) — workspace frozen must check conditions 2-4 per member manifest
# ---------------------------------------------------------------------------
# Regression tests for the gap: resolve_workspace_frozen was skipping conditions
# 2 (FROZEN-MANIFEST-DEP-NOT-IN-LOCK), 3 (FROZEN-LOCKED-VERSION-UNPARSEABLE),
# 4 (FROZEN-CONSTRAINT-UNSATISFIED) for external deps, while the Rust impl runs
# check_manifest_alignment() per member manifest.
# ---------------------------------------------------------------------------


def _build_workspace_with_named_dep(
    tmp_path: Path,
    dep_name: str,
    dep_constraint: str | None,
) -> tuple:
    """Build a minimal workspace on disk where one member declares a named dep.

    Returns (root_dir, workspace, lib_dir, member_identity).
    """
    from milpa.workspace import load_workspace
    from milpa.identity import compute_content_hash

    root_dir = tmp_path / "project"
    root_dir.mkdir()
    (root_dir / "milpa.kdl").write_text(
        'workspace {\n    member "mylib"\n}\n', encoding="utf-8"
    )
    lib_dir = root_dir / "mylib"
    lib_dir.mkdir()

    # Member manifest declares the named dep.
    if dep_constraint is not None:
        member_kdl = (
            f'name "mylib"\nkind "library"\n'
            f'deps {{\n    "{dep_name}" "{dep_constraint}"\n}}\n'
        )
    else:
        member_kdl = (
            f'name "mylib"\nkind "library"\n'
            f'deps {{\n    "{dep_name}"\n}}\n'
        )
    (lib_dir / "milpa.kdl").write_text(member_kdl, encoding="utf-8")

    workspace = load_workspace(root_dir)
    member_identity = compute_content_hash(lib_dir)
    return root_dir, workspace, lib_dir, member_identity


class TestWorkspaceFrozenConditions24:
    """Fix 4 (R1-7): resolve_workspace_frozen must apply conditions 2-4 per member.

    Mirrors Rust: check_manifest_alignment() is called for each member manifest
    inside resolve_workspace_frozen.  Before the fix Python only checked condition
    5 (FROZEN-IDENTITY-NOT-IN-STORE) for external deps.
    """

    def test_condition_2_member_dep_not_in_lock_raises(self, tmp_path: Path) -> None:
        """Condition 2 (FROZEN-MANIFEST-DEP-NOT-IN-LOCK): member declares dep absent from lock.

        The member manifest declares 'extdep' but the lockfile has no entry for it.
        resolve_workspace_frozen must raise FROZEN-MANIFEST-DEP-NOT-IN-LOCK.
        """
        env, _ = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        from milpa.identity import compute_content_hash
        _, workspace, lib_dir, member_identity = _build_workspace_with_named_dep(
            tmp_path, dep_name="extdep", dep_constraint=None
        )

        # Lockfile has only the member dep — no 'extdep' entry.
        member_locked = LockedDep(
            name="mylib",
            identity=member_identity,
            version="0.0.1",
            src_dir="",
            requires=(),
            provenances=(MemberProvenanceRecord(name="mylib"),),
            aliases=(),
        )
        lockfile = Lockfile(deps=(member_locked,), strategy="maxver")

        with pytest.raises(MilpaError) as exc_info:
            resolve_workspace_frozen(workspace, lockfile, env, deps_dir)

        assert exc_info.value.slug == FROZEN_MANIFEST_DEP_NOT_IN_LOCK, (
            f"expected FROZEN-MANIFEST-DEP-NOT-IN-LOCK, got {exc_info.value.slug}"
        )

    def test_condition_3_locked_version_unparseable_raises(self, tmp_path: Path) -> None:
        """Condition 3 (FROZEN-LOCKED-VERSION-UNPARSEABLE): locked version is not valid semver.

        The member declares 'extdep'; the lockfile has an entry with a bad version.
        resolve_workspace_frozen must raise FROZEN-LOCKED-VERSION-UNPARSEABLE.
        """
        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        _, workspace, lib_dir, member_identity = _build_workspace_with_named_dep(
            tmp_path, dep_name="extdep", dep_constraint=None
        )

        # 'extdep' is in the lockfile but has an unparseable version.
        ext_locked = LockedDep(
            name="extdep",
            identity=identity,
            version="NOT-A-SEMVER",  # triggers condition 3
            src_dir="src",
            requires=(),
            provenances=(_git_prov("https://example.com/extdep.git"),),
            aliases=(),
        )
        member_locked = LockedDep(
            name="mylib",
            identity=member_identity,
            version="0.0.1",
            src_dir="",
            requires=(),
            provenances=(MemberProvenanceRecord(name="mylib"),),
            aliases=(),
        )
        lockfile = Lockfile(deps=(ext_locked, member_locked), strategy="maxver")

        with pytest.raises(MilpaError) as exc_info:
            resolve_workspace_frozen(workspace, lockfile, env, deps_dir)

        assert exc_info.value.slug == FROZEN_LOCKED_VERSION_UNPARSEABLE, (
            f"expected FROZEN-LOCKED-VERSION-UNPARSEABLE, got {exc_info.value.slug}"
        )

    def test_condition_4_constraint_unsatisfied_raises(self, tmp_path: Path) -> None:
        """Condition 4 (FROZEN-CONSTRAINT-UNSATISFIED): drifted external-dep constraint.

        The member declares 'extdep >= 2.0.0'; the lockfile has 'extdep' pinned
        at version 1.0.0.  resolve_workspace_frozen must raise
        FROZEN-CONSTRAINT-UNSATISFIED.

        This is the primary regression test for Fix 4 (R1-7): the workspace frozen
        path must check constraints per member manifest, not just CAS presence.
        """
        env, identity = _make_env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        _, workspace, lib_dir, member_identity = _build_workspace_with_named_dep(
            tmp_path, dep_name="extdep", dep_constraint=">= 2.0.0"
        )

        # 'extdep' pinned at 1.0.0 — does NOT satisfy '>= 2.0.0'.
        ext_locked = LockedDep(
            name="extdep",
            identity=identity,
            version="1.0.0",  # does not satisfy '>= 2.0.0'
            src_dir="src",
            requires=(),
            provenances=(_git_prov("https://example.com/extdep.git"),),
            aliases=(),
        )
        member_locked = LockedDep(
            name="mylib",
            identity=member_identity,
            version="0.0.1",
            src_dir="",
            requires=(),
            provenances=(MemberProvenanceRecord(name="mylib"),),
            aliases=(),
        )
        lockfile = Lockfile(deps=(ext_locked, member_locked), strategy="maxver")

        with pytest.raises(MilpaError) as exc_info:
            resolve_workspace_frozen(workspace, lockfile, env, deps_dir)

        assert exc_info.value.slug == FROZEN_CONSTRAINT_UNSATISFIED, (
            f"expected FROZEN-CONSTRAINT-UNSATISFIED, got {exc_info.value.slug}"
        )
