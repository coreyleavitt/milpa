"""Workspace resolution tests (W3 / #75).

resolve_workspace turns a loaded Workspace (W2) into one global
ResolvedGraph: members appear as ResolvedDep entries with
source="member:<name>"; external deps (URL / named / local) appear
once each — one version per package across the whole workspace.
NamedDeps whose name matches a workspace member auto-coerce to
member resolution (handles transitive .nimble requires).

verify_workspace_against_disk closes the verification loop: external
deps are checked against <root>/_deps/, member deps against the
member's directory itself.

See #25 + W3 (#75).
"""

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.manifest import (
    Manifest, MemberDep, NamedDep, UrlDep, WorkspaceManifest,
)
from milpa.resolver import ResolvedDep, ResolvedGraph, resolve_workspace
from milpa.workspace import LoadedMember, Workspace


def _empty_manifest(name: str) -> Manifest:
    return Manifest(deps=(), kind="library", name=name)


@dataclass
class FakeFetcher:
    """Fetcher protocol stub for workspace resolver tests. Maps (url, ref)
    → (sha, nimble_text). Registry computes content_hash from the bytes
    we write to dest."""
    by_url_ref: dict[tuple[str, str], tuple[str, str]]
    calls: list[tuple[str, str, str]] = field(default_factory=list)

    def can_handle(self, p):
        return isinstance(p, GitProvenance)

    def fetch(self, name, p, *, dest):
        self.calls.append((name, p.url, p.ref))
        sha, nimble_text = self.by_url_ref[(p.url, p.ref)]
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text(nimble_text)
        return GitReceipt(commit_sha=sha)


def _fake_registry(by_url_ref):
    fake = FakeFetcher(by_url_ref)
    reg = FetcherRegistry()
    reg.register(fake)
    return reg, fake


def test_resolve_workspace_single_member_no_deps(tmp_path):
    """Tracer: workspace with one member that has no deps → ResolvedGraph
    with one entry (source='member:<name>', content_hash populated)."""
    member_dir = tmp_path / "fresco"
    member_dir.mkdir()
    # member's source content (will be hashed by resolver)
    (member_dir / "fresco.nim").write_text("# fresco\n")

    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco",
                path="fresco",
                directory=member_dir,
                manifest=_empty_manifest("fresco"),
            ),
        ),
    )

    graph = resolve_workspace(
        ws,
        deps_dir=tmp_path / "_deps",
        registry={},
    )

    assert isinstance(graph, ResolvedGraph)
    assert len(graph.deps) == 1
    d = graph.deps[0]
    assert d.name == "fresco"
    assert d.source == "member:fresco"
    assert d.ref is None
    assert d.sha is None
    assert d.tag is None
    assert d.content_hash is not None
    assert len(d.content_hash) == 64
    assert d.requires == ()


def test_resolve_workspace_member_with_url_transitive_dep(tmp_path):
    """A member declares a URL dep in its milpa.kdl. The URL dep is
    fetched normally; both member and URL dep appear in the graph."""
    member_dir = tmp_path / "fresco"
    member_dir.mkdir()
    (member_dir / "fresco.nim").write_text("# fresco\n")

    manifest = Manifest(
        deps=(UrlDep(name="chronos", git="https://example.com/x.git", ref="main"),),
        kind="library",
        name="fresco",
    )
    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco", path="fresco",
                directory=member_dir, manifest=manifest,
            ),
        ),
    )
    reg, _ = _fake_registry({
        ("https://example.com/x.git", "main"): ("csha", 'srcDir = "src"\n'),
    })

    graph = resolve_workspace(
        ws, deps_dir=tmp_path / "_deps", registry={}, fetcher=reg,
    )

    names = {d.name for d in graph.deps}
    assert names == {"fresco", "chronos"}
    chronos = next(d for d in graph.deps if d.name == "chronos")
    assert chronos.source == "https://example.com/x.git"
    assert chronos.sha == "csha"
    fresco = next(d for d in graph.deps if d.name == "fresco")
    assert fresco.source == "member:fresco"
    assert "chronos" in fresco.requires


def test_resolve_workspace_member_to_member_reference(tmp_path):
    """fresco's milpa.kdl declares `member "intonaco"`. Both members
    appear in the graph; no fetcher invocation; fresco.requires
    includes intonaco."""
    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()
    (fresco_dir / "fresco.nim").write_text("# fresco\n")
    intonaco_dir = tmp_path / "intonaco"
    intonaco_dir.mkdir()
    (intonaco_dir / "intonaco.nim").write_text("# intonaco\n")

    fresco_manifest = Manifest(
        deps=(MemberDep(name="intonaco"),),
        kind="library", name="fresco",
    )
    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco", path="fresco",
                directory=fresco_dir, manifest=fresco_manifest,
            ),
            LoadedMember(
                name="intonaco", path="intonaco",
                directory=intonaco_dir, manifest=_empty_manifest("intonaco"),
            ),
        ),
    )
    reg, fake = _fake_registry({})  # no external deps; fetcher must not be invoked

    graph = resolve_workspace(
        ws, deps_dir=tmp_path / "_deps", registry={}, fetcher=reg,
    )

    assert {d.name for d in graph.deps} == {"fresco", "intonaco"}
    fresco = next(d for d in graph.deps if d.name == "fresco")
    intonaco = next(d for d in graph.deps if d.name == "intonaco")
    assert fresco.source == "member:fresco"
    assert intonaco.source == "member:intonaco"
    assert "intonaco" in fresco.requires
    # No fetcher invocation — workspace-internal refs don't fetch.
    assert fake.calls == []


def test_resolve_workspace_shared_external_dep_deduped(tmp_path):
    """Both members depend on the same URL dep. The external dep
    resolves once (single ResolvedDep), and both members' requires
    list it. The fetcher is invoked exactly once for the shared dep."""
    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()
    intonaco_dir = tmp_path / "intonaco"
    intonaco_dir.mkdir()

    shared = UrlDep(name="chronos", git="https://example.com/x.git", ref="main")
    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco", path="fresco", directory=fresco_dir,
                manifest=Manifest(
                    deps=(shared,), kind="library", name="fresco",
                ),
            ),
            LoadedMember(
                name="intonaco", path="intonaco", directory=intonaco_dir,
                manifest=Manifest(
                    deps=(shared,), kind="library", name="intonaco",
                ),
            ),
        ),
    )
    reg, fake = _fake_registry({
        ("https://example.com/x.git", "main"): ("csha", 'srcDir = "src"\n'),
    })

    graph = resolve_workspace(
        ws, deps_dir=tmp_path / "_deps", registry={}, fetcher=reg,
    )

    # chronos appears once in graph
    assert sum(1 for d in graph.deps if d.name == "chronos") == 1
    # Fetched once
    assert sum(1 for c in fake.calls if c[0] == "chronos") == 1
    # Both members reference it
    fresco = next(d for d in graph.deps if d.name == "fresco")
    intonaco = next(d for d in graph.deps if d.name == "intonaco")
    assert "chronos" in fresco.requires
    assert "chronos" in intonaco.requires


def test_resolve_workspace_constraint_conflict_surfaces_clear_error(tmp_path):
    """Two members declare incompatible constraints on the same registry
    dep. Resolution must fail with a clear error — the user should be
    able to identify which members are in conflict."""
    from milpa.registry import RegistryEntry
    from milpa.solver import SolverError

    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()
    intonaco_dir = tmp_path / "intonaco"
    intonaco_dir.mkdir()

    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco", path="fresco", directory=fresco_dir,
                manifest=Manifest(
                    deps=(NamedDep(name="results", constraint="== 0.3.0"),),
                    kind="library", name="fresco",
                ),
            ),
            LoadedMember(
                name="intonaco", path="intonaco", directory=intonaco_dir,
                manifest=Manifest(
                    deps=(NamedDep(name="results", constraint="== 0.5.0"),),
                    kind="library", name="intonaco",
                ),
            ),
        ),
    )
    registry = {
        "results": RegistryEntry(
            name="results", url="https://example.com/results.git", method="git",
        ),
    }
    # Both tags exist; the issue is the cross-member constraint conflict.
    list_tags = lambda url: ["v0.3.0", "v0.5.0"]
    reg, _ = _fake_registry({
        ("https://example.com/results.git", "v0.3.0"): ("s3", ""),
        ("https://example.com/results.git", "v0.5.0"): ("s5", ""),
    })

    with pytest.raises(SolverError):
        resolve_workspace(
            ws, deps_dir=tmp_path / "_deps",
            registry=registry, fetcher=reg, list_tags=list_tags,
        )


def test_resolve_workspace_named_dep_auto_coerces_to_member(tmp_path):
    """The .nimble grammar has no `member` keyword, so transitive
    workspace-internal deps appear as bare NamedDeps. The workspace
    resolver auto-coerces: NamedDep X where X is a workspace member
    routes to the member, not the registry. Fetcher never invoked,
    registry never consulted."""
    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()
    intonaco_dir = tmp_path / "intonaco"
    intonaco_dir.mkdir()

    # fresco declares NamedDep "intonaco" (no constraint). The W3
    # auto-coerce should recognize intonaco as a workspace member.
    fresco_manifest = Manifest(
        deps=(NamedDep(name="intonaco", constraint=None),),
        kind="library", name="fresco",
    )
    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco", path="fresco",
                directory=fresco_dir, manifest=fresco_manifest,
            ),
            LoadedMember(
                name="intonaco", path="intonaco",
                directory=intonaco_dir, manifest=_empty_manifest("intonaco"),
            ),
        ),
    )
    # NO registry entry, NO fetcher fixture for intonaco. If the
    # resolver tried to resolve via registry, list_tags would fail.
    def list_tags_should_not_be_called(url):
        pytest.fail("list_tags should not be called — intonaco should auto-coerce")
    reg, fake = _fake_registry({})

    graph = resolve_workspace(
        ws, deps_dir=tmp_path / "_deps",
        registry={}, fetcher=reg, list_tags=list_tags_should_not_be_called,
    )

    intonaco = next(d for d in graph.deps if d.name == "intonaco")
    assert intonaco.source == "member:intonaco"
    fresco = next(d for d in graph.deps if d.name == "fresco")
    assert "intonaco" in fresco.requires
    assert fake.calls == []


def test_verify_workspace_against_disk_detects_member_drift(tmp_path):
    """After resolve + lockfile, edit a file in a member's directory
    → verify_workspace_against_disk flags drift on that member."""
    from milpa.lockfile import from_graph, verify_workspace_against_disk

    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()
    (fresco_dir / "fresco.nim").write_text("# original\n")

    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco", path="fresco",
                directory=fresco_dir, manifest=_empty_manifest("fresco"),
            ),
        ),
    )

    graph = resolve_workspace(
        ws, deps_dir=tmp_path / "_deps", registry={},
    )
    lockfile = from_graph(graph)

    # No drift initially
    assert verify_workspace_against_disk(ws, lockfile) == []

    # Edit a file in the member's source
    (fresco_dir / "fresco.nim").write_text("# edited\n")

    divergences = verify_workspace_against_disk(ws, lockfile)
    assert len(divergences) == 1
    assert "fresco" in divergences[0]
    assert "mismatch" in divergences[0]


def test_lockfile_round_trip_preserves_member_source(tmp_path):
    """from_graph + format_lockfile + parse_lockfile preserves
    source='member:<name>' faithfully. The lockfile module is source-
    format-agnostic; this test pins the convention."""
    from milpa.lockfile import format_lockfile, from_graph, parse_lockfile

    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()
    intonaco_dir = tmp_path / "intonaco"
    intonaco_dir.mkdir()

    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco", path="fresco", directory=fresco_dir,
                manifest=Manifest(
                    deps=(MemberDep(name="intonaco"),),
                    kind="library", name="fresco",
                ),
            ),
            LoadedMember(
                name="intonaco", path="intonaco",
                directory=intonaco_dir, manifest=_empty_manifest("intonaco"),
            ),
        ),
    )

    graph = resolve_workspace(
        ws, deps_dir=tmp_path / "_deps", registry={},
    )
    lockfile = from_graph(graph)
    text = format_lockfile(lockfile)
    reloaded = parse_lockfile(text)

    assert reloaded == lockfile
    sources = {d.name: d.source for d in reloaded.deps}
    assert sources == {
        "fresco": "member:fresco",
        "intonaco": "member:intonaco",
    }


def test_resolve_workspace_unknown_member_reference_raises(tmp_path):
    """A member declares `member "ghost"` where ghost isn't in the
    workspace. resolve_workspace must surface a clear error naming
    both the referencing member and the missing target — otherwise
    the solver would produce a malformed graph or hang on an
    unsatisfiable term."""
    from milpa.resolver import ResolverError

    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()

    fresco_manifest = Manifest(
        deps=(MemberDep(name="ghost"),),
        kind="library", name="fresco",
    )
    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco", path="fresco",
                directory=fresco_dir, manifest=fresco_manifest,
            ),
        ),
    )

    with pytest.raises(ResolverError) as exc:
        resolve_workspace(ws, deps_dir=tmp_path / "_deps", registry={})
    msg = str(exc.value)
    assert "fresco" in msg
    assert "ghost" in msg


def test_resolve_workspace_handles_cyclic_member_references(tmp_path):
    """fresco depends on intonaco (member); intonaco depends on fresco
    (member). The resolver must terminate (no hang) and the graph
    must contain both members. Member candidates are pre-registered,
    so dedup catches the cycle naturally; PubGrub handles dep-graph
    cycles."""
    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()
    intonaco_dir = tmp_path / "intonaco"
    intonaco_dir.mkdir()

    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco", path="fresco", directory=fresco_dir,
                manifest=Manifest(
                    deps=(MemberDep(name="intonaco"),),
                    kind="library", name="fresco",
                ),
            ),
            LoadedMember(
                name="intonaco", path="intonaco", directory=intonaco_dir,
                manifest=Manifest(
                    deps=(MemberDep(name="fresco"),),
                    kind="library", name="intonaco",
                ),
            ),
        ),
    )

    graph = resolve_workspace(
        ws, deps_dir=tmp_path / "_deps", registry={},
    )

    assert {d.name for d in graph.deps} == {"fresco", "intonaco"}
