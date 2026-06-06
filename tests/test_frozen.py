"""Lockfile-driven frozen resolve (#36).

When `milpa.lock` already pins every dep's identity and the global CAS
already has those bytes, resolve_frozen reconstructs a ResolvedGraph
without any network or fetcher invocation: just symlink each
_deps/<name>/ to its canonical CAS entry.

Falls back via NotFrozen if any precondition fails — manifest drift,
CAS miss, strategy mismatch, or any cas_admissible=False dep.

See docs/rfc-content-addressed-identity.md.
"""

from pathlib import Path

import pytest

from milpa.tianguis_client import Index
from milpa.cas import CAStore
from milpa.frozen import NotFrozen, resolve_frozen
from milpa.identity import compute_content_hash
from milpa.lockfile import (
    GitProvenanceRecord,
    LocalProvenanceRecord,
    LockedDep,
    Lockfile,
    MemberProvenanceRecord,
    OciProvenanceRecord,
)
from milpa.manifest import Manifest, NamedDep, UrlDep


def _populate_cas(store: CAStore, content: str) -> str:
    """Build a tiny tree and admit it to the store. Returns identity."""
    scratch_root = store.root / "_scratch"
    scratch_root.mkdir(parents=True, exist_ok=True)
    scratch = scratch_root / content
    scratch.mkdir()
    (scratch / "file.txt").write_text(content)
    identity = compute_content_hash(scratch)
    store.admit(scratch, identity)
    return identity


def test_resolve_frozen_links_deps_from_cas_without_fetching(tmp_path):
    """Tracer: manifest + lockfile + CAS aligned → ResolvedGraph
    matches lockfile, _deps/<name>/ are symlinks into CAS, no fetcher
    is invoked (we don't pass one — frozen path must not need it)."""
    store = CAStore(root=tmp_path / "cas")
    identity = _populate_cas(store, content="chronos-bytes")

    manifest = Manifest(
        kind="library",
        deps=(UrlDep(name="chronos",
                     git="https://example.com/chronos.git",
                     ref="main"),),
    )
    lockfile = Lockfile(deps=(LockedDep(
        name="chronos",
        identity=identity,
        version="0.5.0",
        src_dir="src",
        requires=(),
        provenances=(GitProvenanceRecord(
            url="https://example.com/chronos.git",
            ref="main",
            commit_sha="abc",
        ),),
    ),))

    deps_dir = tmp_path / "_deps"
    graph = resolve_frozen(
        manifest, lockfile=lockfile, deps_dir=deps_dir, store=store,
    )

    assert len(graph.deps) == 1
    dep = graph.deps[0]
    assert dep.name == "chronos"
    assert dep.identity == identity
    assert dep.src_dir == "src"

    symlink = deps_dir / "chronos"
    assert symlink.is_symlink()
    assert symlink.resolve() == store.path_for(identity).resolve()
    assert (symlink / "file.txt").read_text() == "chronos-bytes"


def test_resolve_frozen_raises_when_cas_does_not_contain_locked_identity(tmp_path):
    """A locked dep whose identity isn't in the store cannot be served
    from the fast path — NotFrozen must surface with the dep name."""
    store = CAStore(root=tmp_path / "cas")
    # CAS is empty
    missing_identity = "sha256:" + "f" * 64

    manifest = Manifest(
        kind="library",
        deps=(UrlDep(name="chronos",
                     git="https://example.com/chronos.git",
                     ref="main"),),
    )
    lockfile = Lockfile(deps=(LockedDep(
        name="chronos", identity=missing_identity, version="0.5.0",
        src_dir="", requires=(),
        provenances=(GitProvenanceRecord(
            url="https://example.com/chronos.git", ref="main",
            commit_sha="abc",
        ),),
    ),))

    with pytest.raises(NotFrozen) as exc:
        resolve_frozen(
            manifest, lockfile=lockfile, deps_dir=tmp_path / "_deps",
            store=store,
        )
    msg = str(exc.value)
    assert "chronos" in msg


def test_resolve_frozen_raises_when_manifest_dep_is_not_in_lockfile(tmp_path):
    """User added a dep but did not re-lock. Frozen path must refuse
    rather than silently skip the new dep."""
    store = CAStore(root=tmp_path / "cas")
    identity_chronos = _populate_cas(store, content="chronos-bytes")

    manifest = Manifest(
        kind="library",
        deps=(
            UrlDep(name="chronos",
                   git="https://example.com/chronos.git", ref="main"),
            UrlDep(name="newdep",
                   git="https://example.com/newdep.git", ref="main"),
        ),
    )
    lockfile = Lockfile(deps=(LockedDep(
        name="chronos", identity=identity_chronos, version="0.5.0",
        src_dir="", requires=(),
        provenances=(GitProvenanceRecord(
            url="https://example.com/chronos.git", ref="main",
            commit_sha="abc",
        ),),
    ),))

    with pytest.raises(NotFrozen) as exc:
        resolve_frozen(
            manifest, lockfile=lockfile, deps_dir=tmp_path / "_deps",
            store=store,
        )
    assert "newdep" in str(exc.value)


def test_resolve_frozen_raises_when_locked_version_violates_manifest_constraint(tmp_path):
    """User tightened a NamedDep constraint but did not re-lock. The
    locked version may no longer satisfy the new constraint — frozen
    must refuse."""
    store = CAStore(root=tmp_path / "cas")
    identity = _populate_cas(store, content="results-bytes")

    manifest = Manifest(
        kind="library",
        deps=(NamedDep(name="results", constraint=">= 2.0.0"),),
    )
    # Lockfile has results 1.5.0 — violates the new ">= 2.0.0"
    lockfile = Lockfile(deps=(LockedDep(
        name="results", identity=identity, version="1.5.0",
        src_dir="", requires=(),
        provenances=(GitProvenanceRecord(
            url="https://example.com/results.git", ref="v1.5.0",
            commit_sha="abc",
        ),),
    ),))

    with pytest.raises(NotFrozen) as exc:
        resolve_frozen(
            manifest, lockfile=lockfile, deps_dir=tmp_path / "_deps",
            store=store,
        )
    msg = str(exc.value)
    assert "results" in msg
    assert "constraint" in msg.lower() or "satisf" in msg.lower()


def test_resolve_frozen_raises_on_local_or_member_provenance(tmp_path):
    """Local + member sources can change between runs (editable trees).
    Frozen path always falls through for them — even if CAS happens to
    hold an entry with the right identity."""
    store = CAStore(root=tmp_path / "cas")
    identity = _populate_cas(store, content="local-bytes")

    # Local provenance — even with CAS hit, must NotFrozen
    manifest = Manifest(kind="library", deps=())
    lockfile = Lockfile(deps=(LockedDep(
        name="sibling", identity=identity, version="0.0.1",
        src_dir="", requires=(),
        provenances=(LocalProvenanceRecord(path="../sibling"),),
    ),))
    with pytest.raises(NotFrozen) as exc:
        resolve_frozen(
            manifest, lockfile=lockfile, deps_dir=tmp_path / "_deps",
            store=store,
        )
    assert "sibling" in str(exc.value)
    assert "local" in str(exc.value).lower()

    # Workspace-member provenance — same
    lockfile_member = Lockfile(deps=(LockedDep(
        name="alpha", identity=identity, version="0.0.1",
        src_dir="", requires=(),
        provenances=(MemberProvenanceRecord(name="alpha"),),
    ),))
    with pytest.raises(NotFrozen) as exc:
        resolve_frozen(
            manifest, lockfile=lockfile_member,
            deps_dir=tmp_path / "_deps2", store=store,
        )
    assert "alpha" in str(exc.value)
    assert "member" in str(exc.value).lower()


def test_resolve_frozen_raises_on_strategy_mismatch(tmp_path):
    """Lockfile records the strategy that built it; a different
    strategy requires re-resolution (the solution space differs)."""
    from milpa.solver import Strategy

    store = CAStore(root=tmp_path / "cas")
    identity = _populate_cas(store, content="bytes")

    manifest = Manifest(kind="library", deps=())
    lockfile = Lockfile(
        deps=(LockedDep(
            name="x", identity=identity, version="0.0.1",
            src_dir="", requires=(),
            provenances=(GitProvenanceRecord(
                url="https://example.com/x.git", ref="main", commit_sha="a",
            ),),
        ),),
        strategy="maxver",
    )

    with pytest.raises(NotFrozen) as exc:
        resolve_frozen(
            manifest, lockfile=lockfile, deps_dir=tmp_path / "_deps",
            store=store, strategy=Strategy.MINVER,
        )
    assert "strategy" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# cmd_fetch integration
# ---------------------------------------------------------------------------


def test_cmd_fetch_uses_frozen_path_and_does_not_call_fetcher(tmp_path):
    """When manifest + lockfile + CAS all align, cmd_fetch resolves
    via the frozen path: _deps/ are symlinks, nim.cfg is emitted, and
    the fetcher is NEVER invoked."""
    from milpa.cli import cmd_fetch
    from milpa.fetchers import FetcherRegistry
    from milpa.lockfile import format_lockfile

    store = CAStore(root=tmp_path / "cas")
    identity = _populate_cas(store, content="foo-bytes-with-nimble")

    # Manifest declares foo
    (tmp_path / "milpa.kdl").write_text(
        'name "test"\n'
        'deps {\n'
        '    foo git="https://example.com/foo.git" ref="main"\n'
        '}\n'
    )
    # Lockfile pins foo to the identity already in CAS
    lockfile = Lockfile(deps=(LockedDep(
        name="foo", identity=identity, version="0.0.1",
        src_dir="", requires=(),
        provenances=(GitProvenanceRecord(
            url="https://example.com/foo.git", ref="main",
            commit_sha="abc",
        ),),
    ),))
    (tmp_path / "milpa.lock").write_text(format_lockfile(lockfile))

    class ExplodingFetcher:
        def can_handle(self, p): return True
        def fetch(self, name, p, *, dest):
            raise AssertionError(
                "frozen path must not invoke the fetcher"
            )

    registry = FetcherRegistry(store=store)
    registry.register(ExplodingFetcher())

    rc = cmd_fetch(
        tmp_path, fetcher=registry,
        index_loader=lambda *, cache_dir: Index({}),
    )

    assert rc == 0
    assert (tmp_path / "_deps" / "foo").is_symlink()
    assert (tmp_path / "nim.cfg").exists()


def test_cmd_fetch_falls_through_to_slow_path_on_not_frozen(tmp_path):
    """When the frozen precondition fails (here: no lockfile), cmd_fetch
    silently runs the full resolve via the fetcher."""
    from milpa.cli import cmd_fetch
    from milpa.fetchers import FetcherRegistry
    from milpa.fetchers.git import GitProvenance, GitReceipt

    (tmp_path / "milpa.kdl").write_text(
        'name "test"\n'
        'deps {\n'
        '    foo git="https://example.com/foo.git" ref="main"\n'
        '}\n'
    )
    # No milpa.lock — frozen will refuse

    called = []
    class CountingFetcher:
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            called.append(name)
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            return GitReceipt(commit_sha="abc")

    store = CAStore(root=tmp_path / "cas")
    registry = FetcherRegistry(store=store)
    registry.register(CountingFetcher())

    rc = cmd_fetch(
        tmp_path, fetcher=registry,
        index_loader=lambda *, cache_dir: Index({}),
    )

    assert rc == 0
    assert called == ["foo"]   # slow path ran


def test_cmd_fetch_with_frozen_flag_errors_on_not_frozen(tmp_path, capsys):
    """--frozen: if frozen path can't be used, exit 1 with the
    NotFrozen reason on stderr. Never falls through to the slow path."""
    from milpa.cli import cmd_fetch
    from milpa.fetchers import FetcherRegistry

    (tmp_path / "milpa.kdl").write_text(
        'name "test"\n'
        'deps {\n'
        '    foo git="https://example.com/foo.git" ref="main"\n'
        '}\n'
    )
    # No milpa.lock — frozen will refuse

    class ExplodingFetcher:
        def can_handle(self, p): return True
        def fetch(self, name, p, *, dest):
            raise AssertionError(
                "frozen=True must not invoke the fetcher"
            )

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


# ---------------------------------------------------------------------------
# S3 (milpa#97) — a legacy `kind "registry"` lock cannot be honored by the
# frozen fast path (no fetchable URL). It must raise an actionable
# NotFrozen so the slow path re-resolves via the index — NOT fabricate a
# git clone URL.
# ---------------------------------------------------------------------------


def test_frozen_legacy_registry_record_raises_actionable_notfrozen():
    from milpa.frozen import _source_from_provenance
    from milpa.lockfile import RegistryProvenanceRecord

    rec = RegistryProvenanceRecord(name="foo", tag="v1", commit_sha="abc")
    with pytest.raises(NotFrozen) as exc:
        _source_from_provenance(rec)
    msg = str(exc.value)
    assert "foo" in msg
    assert "milpa update" in msg


# ---------------------------------------------------------------------------
# L11 — frozen + OCI provenance arm
# ---------------------------------------------------------------------------


def test_frozen_oci_provenance_record_produces_oci_source(tmp_path):
    """L11: a LockedDep whose provenance is OciProvenanceRecord passes the
    frozen fast path; resolve_frozen produces a dep whose source starts with
    'oci:' (exercises _source_from_provenance's OCI arm)."""
    store = CAStore(root=tmp_path / "cas")
    identity = _populate_cas(store, content="nimkdl-bytes")

    manifest = Manifest(kind="library", deps=())
    lockfile = Lockfile(deps=(LockedDep(
        name="nimkdl",
        identity=identity,
        version="0.1.4",
        src_dir="src",
        requires=(),
        provenances=(OciProvenanceRecord(
            registry="ghcr.io",
            repository="coreyleavitt/nimkdl",
            digest="sha256:" + "d" * 64,
        ),),
    ),))

    deps_dir = tmp_path / "_deps"
    graph = resolve_frozen(
        manifest, lockfile=lockfile, deps_dir=deps_dir, store=store,
    )

    assert len(graph.deps) == 1
    dep = graph.deps[0]
    assert dep.name == "nimkdl"
    # _source_from_provenance's OCI arm: "oci:{registry}/{repository}"
    assert dep.source.startswith("oci:")
    assert "ghcr.io" in dep.source
    assert "coreyleavitt/nimkdl" in dep.source
    # The symlink was created in _deps/
    assert (deps_dir / "nimkdl").is_symlink()


def test_show_renders_legacy_registry_and_oci_records():
    from milpa.cli import _format_provenance_for_show
    from milpa.lockfile import OciProvenanceRecord, RegistryProvenanceRecord

    legacy = _format_provenance_for_show(
        RegistryProvenanceRecord(name="foo", tag="v1", commit_sha="abc12345")
    )
    assert "legacy" in legacy and "foo" in legacy

    oci = _format_provenance_for_show(
        OciProvenanceRecord(
            registry="ghcr.io", repository="x/y", digest="sha256:abc",
        )
    )
    assert oci.startswith("oci ") and "ghcr.io/x/y" in oci
