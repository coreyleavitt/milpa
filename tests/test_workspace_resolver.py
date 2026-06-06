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
    )

    assert isinstance(graph, ResolvedGraph)
    assert len(graph.deps) == 1
    d = graph.deps[0]
    assert d.name == "fresco"
    assert d.source == "member:fresco"
    assert d.ref is None
    assert d.sha is None
    assert d.tag is None
    assert d.identity is not None
    assert d.identity.startswith("sha256:")
    assert len(d.identity) == len("sha256:") + 64
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
        ws, deps_dir=tmp_path / "_deps", fetcher=reg,
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
        ws, deps_dir=tmp_path / "_deps", fetcher=reg,
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
        ws, deps_dir=tmp_path / "_deps", fetcher=reg,
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
    from milpa.solver import SolverError
    from tests.indexkdl import make_index

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
    # Both versions exist in the index; the issue is the cross-member
    # constraint conflict the solver must reject.
    index = make_index([
        {"name": "results", "version": "0.3.0",
         "url": "https://example.com/results.git", "ref": "v0.3.0"},
        {"name": "results", "version": "0.5.0",
         "url": "https://example.com/results.git", "ref": "v0.5.0"},
    ])
    reg, _ = _fake_registry({
        ("https://example.com/results.git", "v0.3.0"): ("s3", ""),
        ("https://example.com/results.git", "v0.5.0"): ("s5", ""),
    })

    with pytest.raises(SolverError):
        resolve_workspace(
            ws, deps_dir=tmp_path / "_deps",
            index=index, fetcher=reg,
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
    # NO index entry, NO fetcher fixture for intonaco. If the resolver
    # tried to resolve via the index, it would raise TNG-NOT-FOUND.
    reg, fake = _fake_registry({})

    graph = resolve_workspace(
        ws, deps_dir=tmp_path / "_deps",
        fetcher=reg,
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
        ws, deps_dir=tmp_path / "_deps",
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
        ws, deps_dir=tmp_path / "_deps",
    )
    lockfile = from_graph(graph)
    text = format_lockfile(lockfile)
    reloaded = parse_lockfile(text)

    from milpa.lockfile import MemberProvenanceRecord
    assert reloaded == lockfile
    # Each member's provenance is a MemberProvenanceRecord naming the member
    by_name = {d.name: d for d in reloaded.deps}
    for name in ("fresco", "intonaco"):
        provs = by_name[name].provenances
        assert len(provs) == 1
        assert isinstance(provs[0], MemberProvenanceRecord)
        assert provs[0].name == name


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
        resolve_workspace(ws, deps_dir=tmp_path / "_deps")
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
        ws, deps_dir=tmp_path / "_deps",
    )

    assert {d.name for d in graph.deps} == {"fresco", "intonaco"}


def test_resolve_workspace_applies_override_to_member_url_dep(tmp_path):
    """Tracer for W5: workspace-level override on chronos → a member's
    UrlDep for chronos is fetched via the override URL/ref instead of
    the manifest's URL/ref. The override's spec wins."""
    from milpa.manifest import Override
    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()
    (fresco_dir / "fresco.nim").write_text("# fresco\n")

    fresco_manifest = Manifest(
        deps=(UrlDep(name="chronos", git="https://upstream/chronos.git", ref="main"),),
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
        overrides=(
            Override(
                name="chronos",
                git="https://my-fork/chronos.git",
                ref="my-fix",
            ),
        ),
    )
    # Only the OVERRIDE's spec is in the fake — if the resolver tried
    # the upstream URL, FakeFetcher would KeyError loudly.
    reg, _ = _fake_registry({
        ("https://my-fork/chronos.git", "my-fix"): (
            "fork-sha", 'srcDir = "src"\n',
        ),
    })

    graph = resolve_workspace(
        ws, deps_dir=tmp_path / "_deps", fetcher=reg,
    )

    chronos = next(d for d in graph.deps if d.name == "chronos")
    assert chronos.source == "https://my-fork/chronos.git"
    assert chronos.ref == "my-fix"
    assert chronos.sha == "fork-sha"


def test_resolve_workspace_override_applies_uniformly_to_all_members(tmp_path):
    """Two members both depend on chronos via URL. Workspace overrides
    chronos. Both members see the override; chronos appears once in the
    graph (deduped via the override's URL/ref)."""
    from milpa.manifest import Override

    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()
    intonaco_dir = tmp_path / "intonaco"
    intonaco_dir.mkdir()

    upstream_url = "https://upstream/chronos.git"
    fork_url = "https://my-fork/chronos.git"

    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco", path="fresco", directory=fresco_dir,
                manifest=Manifest(
                    deps=(UrlDep(name="chronos", git=upstream_url, ref="main"),),
                    kind="library", name="fresco",
                ),
            ),
            LoadedMember(
                name="intonaco", path="intonaco", directory=intonaco_dir,
                manifest=Manifest(
                    deps=(UrlDep(name="chronos", git=upstream_url, ref="main"),),
                    kind="library", name="intonaco",
                ),
            ),
        ),
        overrides=(
            Override(name="chronos", git=fork_url, ref="my-fix"),
        ),
    )
    # Only the override URL is in the fake — both members must
    # resolve via the override.
    reg, fake = _fake_registry({
        (fork_url, "my-fix"): ("fork-sha", 'srcDir = "src"\n'),
    })

    graph = resolve_workspace(
        ws, deps_dir=tmp_path / "_deps", fetcher=reg,
    )

    # chronos appears exactly once (deduped via the override URL)
    chronos_entries = [d for d in graph.deps if d.name == "chronos"]
    assert len(chronos_entries) == 1
    assert chronos_entries[0].source == fork_url
    # Both members' requires list chronos
    for member_name in ("fresco", "intonaco"):
        m = next(d for d in graph.deps if d.name == member_name)
        assert "chronos" in m.requires
    # Fetched exactly once (overridden URL)
    assert sum(1 for c in fake.calls if c[0] == "chronos") == 1


def test_resolve_workspace_override_on_named_dep_bypasses_registry(tmp_path):
    """A member declares chronos as a NamedDep. The workspace overrides
    chronos. Resolution bypasses the registry path entirely (list_tags
    must not be called) and fetches from the override URL."""
    from milpa.manifest import Override

    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()

    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco", path="fresco", directory=fresco_dir,
                manifest=Manifest(
                    deps=(NamedDep(name="chronos", constraint=">= 0.5.0"),),
                    kind="library", name="fresco",
                ),
            ),
        ),
        overrides=(
            Override(
                name="chronos",
                git="https://my-fork/chronos.git",
                ref="my-fix",
            ),
        ),
    )
    reg, _ = _fake_registry({
        ("https://my-fork/chronos.git", "my-fix"): ("fork-sha", ''),
    })

    graph = resolve_workspace(
        ws, deps_dir=tmp_path / "_deps",
        fetcher=reg,
    )

    chronos = next(d for d in graph.deps if d.name == "chronos")
    assert chronos.source == "https://my-fork/chronos.git"
    assert chronos.ref == "my-fix"


def test_resolve_workspace_override_applies_to_transitive_named_dep(tmp_path):
    """A member depends on intonaco (URL). intonaco's .nimble has
    `requires "chronos"` (NamedDep). Workspace overrides chronos →
    the transitive NamedDep routes through the override URL fetch,
    not the registry."""
    from milpa.manifest import Override

    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()

    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco", path="fresco", directory=fresco_dir,
                manifest=Manifest(
                    deps=(UrlDep(name="intonaco",
                                 git="https://example.com/intonaco.git",
                                 ref="main"),),
                    kind="library", name="fresco",
                ),
            ),
        ),
        overrides=(
            Override(name="chronos",
                     git="https://my-fork/chronos.git", ref="my-fix"),
        ),
    )
    # intonaco's .nimble: NamedDep on chronos (transitive)
    reg, _ = _fake_registry({
        ("https://example.com/intonaco.git", "main"): (
            "isha",
            'srcDir = "src"\nrequires "chronos >= 0.5.0"\n',
        ),
        # Override URL — must be reached for the transitive
        ("https://my-fork/chronos.git", "my-fix"): ("fork-sha", ''),
    })

    graph = resolve_workspace(
        ws, deps_dir=tmp_path / "_deps",
        fetcher=reg,
    )

    chronos = next(d for d in graph.deps if d.name == "chronos")
    assert chronos.source == "https://my-fork/chronos.git"


def test_resolve_workspace_override_name_collision_with_member_raises(tmp_path):
    """A workspace override on name X where X is also a workspace
    member is structurally contradictory. resolve_workspace surfaces
    a clear ResolverError naming the collision before any I/O."""
    from milpa.manifest import Override
    from milpa.resolver import ResolverError

    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()
    intonaco_dir = tmp_path / "intonaco"
    intonaco_dir.mkdir()

    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="fresco", path="fresco", directory=fresco_dir,
                manifest=_empty_manifest("fresco"),
            ),
            LoadedMember(
                name="intonaco", path="intonaco", directory=intonaco_dir,
                manifest=_empty_manifest("intonaco"),
            ),
        ),
        overrides=(
            # intonaco is both a workspace member AND an override target.
            Override(name="intonaco",
                     git="https://my-fork/intonaco.git", ref="my-fix"),
        ),
    )

    with pytest.raises(ResolverError) as exc:
        resolve_workspace(ws, deps_dir=tmp_path / "_deps")
    msg = str(exc.value).lower()
    assert "intonaco" in msg
    assert "override" in msg
    assert "member" in msg
