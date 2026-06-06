"""Workspace frozen path (#78).

resolve_workspace_frozen is the workspace analog of resolve_frozen.
External deps come from CAS (symlinked into <root>/_deps/<name>);
members are verified against their on-disk content_hash and stay in
their declared locations.
"""

from pathlib import Path

import pytest

from milpa.tianguis_client import Index
from milpa.cas import CAStore
from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.frozen import NotFrozen, resolve_workspace_frozen
from milpa.identity import compute_content_hash
from milpa.lockfile import (
    GitProvenanceRecord, LockedDep, Lockfile,
    MemberProvenanceRecord,
)
from milpa.manifest import Manifest, UrlDep
from milpa.solver import Strategy
from milpa.workspace import LoadedMember, Workspace


def _populate_cas(store: CAStore, content: str) -> str:
    """Build a tree under store/_scratch, admit, return identity."""
    scratch_root = store.root / "_scratch"
    scratch_root.mkdir(parents=True, exist_ok=True)
    scratch = scratch_root / content
    scratch.mkdir()
    (scratch / "f.txt").write_text(content)
    identity = compute_content_hash(scratch)
    store.admit(scratch, identity)
    return identity


def test_resolve_workspace_frozen_returns_graph_when_aligned(tmp_path):
    """Tracer: a workspace with one member + one external dep, with
    the lockfile pinning both, returns a ResolvedGraph without
    invoking any fetcher."""
    store = CAStore(root=tmp_path / "cas")
    external_identity = _populate_cas(store, content="chronos-bytes")

    # The member's directory and on-disk identity
    member_dir = tmp_path / "fresco"
    member_dir.mkdir()
    (member_dir / "fresco.nim").write_text("# fresco\n")
    member_identity = compute_content_hash(member_dir)

    member_manifest = Manifest(
        kind="library", name="fresco",
        deps=(UrlDep(name="chronos",
                     git="https://example.com/chronos.git", ref="main"),),
    )

    ws = Workspace(
        root=tmp_path,
        members=(LoadedMember(
            name="fresco", path="fresco",
            directory=member_dir, manifest=member_manifest,
        ),),
    )

    lockfile = Lockfile(deps=(
        LockedDep(
            name="fresco", identity=member_identity, version="0.0.1",
            src_dir="", requires=("chronos",),
            provenances=(MemberProvenanceRecord(name="fresco"),),
        ),
        LockedDep(
            name="chronos", identity=external_identity, version="0.0.1",
            src_dir="", requires=(),
            provenances=(GitProvenanceRecord(
                url="https://example.com/chronos.git", ref="main",
                commit_sha="abc",
            ),),
        ),
    ))

    deps_dir = tmp_path / "_deps"
    graph = resolve_workspace_frozen(
        ws, lockfile=lockfile, deps_dir=deps_dir, store=store,
    )

    names = {d.name for d in graph.deps}
    assert names == {"fresco", "chronos"}
    # External symlinked from CAS
    assert (deps_dir / "chronos").is_symlink()
    assert (deps_dir / "chronos").resolve() == store.path_for(external_identity).resolve()
    # Member NOT linked under _deps/ (stays in-tree)
    assert not (deps_dir / "fresco").exists()


def test_resolve_workspace_frozen_external_not_in_cas_raises(tmp_path):
    """An external dep whose identity isn't in the CAS → NotFrozen."""
    store = CAStore(root=tmp_path / "cas")
    # CAS empty

    member_dir = tmp_path / "fresco"
    member_dir.mkdir()
    (member_dir / "fresco.nim").write_text("# fresco\n")
    member_identity = compute_content_hash(member_dir)

    ws = Workspace(
        root=tmp_path,
        members=(LoadedMember(
            name="fresco", path="fresco", directory=member_dir,
            manifest=Manifest(kind="library", name="fresco", deps=(
                UrlDep(name="chronos",
                       git="https://x/chronos.git", ref="main"),
            )),
        ),),
    )
    missing = "sha256:" + "f" * 64
    lockfile = Lockfile(deps=(
        LockedDep(
            name="fresco", identity=member_identity, version="0.0.1",
            src_dir="", requires=("chronos",),
            provenances=(MemberProvenanceRecord(name="fresco"),),
        ),
        LockedDep(
            name="chronos", identity=missing, version="0.0.1",
            src_dir="", requires=(),
            provenances=(GitProvenanceRecord(
                url="https://x/chronos.git", ref="main", commit_sha="abc",
            ),),
        ),
    ))

    with pytest.raises(NotFrozen) as exc:
        resolve_workspace_frozen(
            ws, lockfile=lockfile, deps_dir=tmp_path / "_deps", store=store,
        )
    assert "chronos" in str(exc.value)


def test_resolve_workspace_frozen_member_identity_drift_raises(tmp_path):
    """Member's on-disk content_hash differs from lockfile's pin →
    NotFrozen (slow path will re-snapshot)."""
    store = CAStore(root=tmp_path / "cas")

    member_dir = tmp_path / "fresco"
    member_dir.mkdir()
    (member_dir / "fresco.nim").write_text("# fresco edited\n")
    # Lockfile pins a different identity than what's on disk
    bogus = "sha256:" + "f" * 64

    ws = Workspace(
        root=tmp_path,
        members=(LoadedMember(
            name="fresco", path="fresco", directory=member_dir,
            manifest=Manifest(kind="library", name="fresco", deps=()),
        ),),
    )
    lockfile = Lockfile(deps=(LockedDep(
        name="fresco", identity=bogus, version="0.0.1",
        src_dir="", requires=(),
        provenances=(MemberProvenanceRecord(name="fresco"),),
    ),))

    with pytest.raises(NotFrozen) as exc:
        resolve_workspace_frozen(
            ws, lockfile=lockfile, deps_dir=tmp_path / "_deps", store=store,
        )
    msg = str(exc.value)
    assert "fresco" in msg
    assert "drift" in msg.lower() or "differs" in msg.lower()


def test_resolve_workspace_frozen_member_missing_from_workspace_raises(tmp_path):
    """User removed a member from the workspace declaration, but the
    lockfile still references it → NotFrozen."""
    store = CAStore(root=tmp_path / "cas")
    bogus = "sha256:" + "a" * 64

    # Workspace has NO members
    ws = Workspace(root=tmp_path, members=())
    lockfile = Lockfile(deps=(LockedDep(
        name="ghost", identity=bogus, version="0.0.1",
        src_dir="", requires=(),
        provenances=(MemberProvenanceRecord(name="ghost"),),
    ),))

    with pytest.raises(NotFrozen) as exc:
        resolve_workspace_frozen(
            ws, lockfile=lockfile, deps_dir=tmp_path / "_deps", store=store,
        )
    assert "ghost" in str(exc.value)


def test_resolve_workspace_frozen_member_manifest_dep_not_in_lockfile(tmp_path):
    """A member added a new dep but didn't re-lock → NotFrozen for
    that member naming the unlocked dep."""
    store = CAStore(root=tmp_path / "cas")

    member_dir = tmp_path / "fresco"
    member_dir.mkdir()
    (member_dir / "fresco.nim").write_text("# fresco\n")
    member_identity = compute_content_hash(member_dir)

    ws = Workspace(
        root=tmp_path,
        members=(LoadedMember(
            name="fresco", path="fresco", directory=member_dir,
            manifest=Manifest(kind="library", name="fresco", deps=(
                UrlDep(name="newdep", git="https://x/n.git", ref="main"),
            )),
        ),),
    )
    # Lockfile has only the member, NOT newdep
    lockfile = Lockfile(deps=(LockedDep(
        name="fresco", identity=member_identity, version="0.0.1",
        src_dir="", requires=(),
        provenances=(MemberProvenanceRecord(name="fresco"),),
    ),))

    with pytest.raises(NotFrozen) as exc:
        resolve_workspace_frozen(
            ws, lockfile=lockfile, deps_dir=tmp_path / "_deps", store=store,
        )
    msg = str(exc.value)
    assert "newdep" in msg
    assert "fresco" in msg  # names the member


def test_resolve_workspace_frozen_local_provenance_still_forces_not_frozen(tmp_path):
    """A non-member LocalProvenanceRecord (e.g. `local=../sibling`)
    still triggers NotFrozen even in workspace mode — editable trees
    always re-resolve regardless of context."""
    from milpa.lockfile import LocalProvenanceRecord
    store = CAStore(root=tmp_path / "cas")
    bogus = "sha256:" + "a" * 64

    member_dir = tmp_path / "fresco"
    member_dir.mkdir()
    (member_dir / "fresco.nim").write_text("# fresco\n")
    member_identity = compute_content_hash(member_dir)

    ws = Workspace(
        root=tmp_path,
        members=(LoadedMember(
            name="fresco", path="fresco", directory=member_dir,
            manifest=Manifest(kind="library", name="fresco", deps=()),
        ),),
    )
    lockfile = Lockfile(deps=(
        LockedDep(
            name="fresco", identity=member_identity, version="0.0.1",
            src_dir="", requires=(),
            provenances=(MemberProvenanceRecord(name="fresco"),),
        ),
        LockedDep(
            name="sibling", identity=bogus, version="0.0.1",
            src_dir="", requires=(),
            provenances=(LocalProvenanceRecord(path="../sibling"),),
        ),
    ))

    with pytest.raises(NotFrozen) as exc:
        resolve_workspace_frozen(
            ws, lockfile=lockfile, deps_dir=tmp_path / "_deps", store=store,
        )
    msg = str(exc.value)
    assert "sibling" in msg
    assert "local" in msg.lower()


# ---------------------------------------------------------------------------
# cmd_fetch (workspace path) integration
# ---------------------------------------------------------------------------


def test_cmd_fetch_workspace_uses_frozen_path_when_aligned(tmp_path):
    """End-to-end: workspace project with member + external aligned
    to lockfile + CAS → cmd_fetch on the workspace uses the frozen
    fast path and never invokes the fetcher."""
    from milpa.cli import cmd_fetch
    from milpa.lockfile import format_lockfile

    # Workspace manifest
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "fresco"\n'
        '}\n'
    )

    # Member with one external dep
    member_dir = tmp_path / "fresco"
    member_dir.mkdir()
    (member_dir / "fresco.nim").write_text("# fresco\n")
    (member_dir / "milpa.kdl").write_text(
        'name "fresco"\n'
        'kind "library"\n'
        'deps {\n'
        '    chronos git=(url)"https://example.com/chronos.git" ref="main"\n'
        '}\n'
    )
    member_identity = compute_content_hash(member_dir)

    # Pre-populate CAS with chronos
    store = CAStore(root=tmp_path / "cas")
    external_identity = _populate_cas(store, content="chronos-bytes")

    # Lockfile aligned to both
    (tmp_path / "milpa.lock").write_text(format_lockfile(Lockfile(deps=(
        LockedDep(
            name="fresco", identity=member_identity, version="0.0.1",
            src_dir="", requires=("chronos",),
            provenances=(MemberProvenanceRecord(name="fresco"),),
        ),
        LockedDep(
            name="chronos", identity=external_identity, version="0.0.1",
            src_dir="", requires=(),
            provenances=(GitProvenanceRecord(
                url="https://example.com/chronos.git", ref="main",
                commit_sha="abc",
            ),),
        ),
    ))))

    class ExplodingFetcher:
        def can_handle(self, p): return True
        def fetch(self, name, p, *, dest):
            raise AssertionError("frozen path must not invoke the fetcher")

    registry = FetcherRegistry(store=store)
    registry.register(ExplodingFetcher())

    rc = cmd_fetch(
        tmp_path, fetcher=registry,
        index_loader=lambda *, cache_dir: Index({}),
    )

    assert rc == 0
    # _deps/chronos is symlinked into CAS
    assert (tmp_path / "_deps" / "chronos").is_symlink()
    # Member nim.cfg emitted
    assert (member_dir / "nim.cfg").exists()


def test_cmd_fetch_workspace_falls_through_silently_on_not_frozen(tmp_path):
    """When the frozen path can't be used (e.g., no lockfile),
    cmd_fetch on workspace silently runs the full resolve."""
    from milpa.cli import cmd_fetch

    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n    member "fresco"\n}\n'
    )
    member_dir = tmp_path / "fresco"
    member_dir.mkdir()
    (member_dir / "milpa.kdl").write_text(
        'name "fresco"\nkind "library"\n'
    )
    # NO lockfile

    store = CAStore(root=tmp_path / "cas")
    registry = FetcherRegistry(store=store)
    # No fetchers registered — but workspace has no external deps,
    # so slow path will just snapshot the member.

    rc = cmd_fetch(
        tmp_path, fetcher=registry,
        index_loader=lambda *, cache_dir: Index({}),
    )
    assert rc == 0
    # Lockfile was created by slow path
    assert (tmp_path / "milpa.lock").exists()


def test_cmd_fetch_workspace_with_frozen_flag_exits_1_on_not_frozen(tmp_path, capsys):
    """--frozen in workspace mode: if frozen path can't be used,
    exit 1 + reason on stderr. Never falls through."""
    from milpa.cli import cmd_fetch

    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n    member "fresco"\n}\n'
    )
    member_dir = tmp_path / "fresco"
    member_dir.mkdir()
    (member_dir / "milpa.kdl").write_text(
        'name "fresco"\nkind "library"\n'
    )
    # No lockfile

    class ExplodingFetcher:
        def can_handle(self, p): return True
        def fetch(self, name, p, *, dest):
            raise AssertionError("--frozen must not invoke the fetcher")

    store = CAStore(root=tmp_path / "cas")
    registry = FetcherRegistry(store=store)
    registry.register(ExplodingFetcher())

    rc = cmd_fetch(
        tmp_path, fetcher=registry,
        index_loader=lambda *, cache_dir: Index({}), frozen=True,
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "frozen" in err.lower()
    assert "lockfile" in err.lower()
