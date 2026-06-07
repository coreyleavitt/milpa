"""Resolver glue tests.

The resolver assembles fetcher + registry + nimble_parse + solver into
a single `resolve(manifest, ...) -> ResolvedGraph` call. Tests inject a
fake Fetcher (an implementation of the milpa.fetchers Fetcher protocol)
wrapped in a FetcherRegistry, so we exercise the integration without
network or git.

Note on content_hash: identity is computed by the registry from bytes
written to dest, NOT supplied by the fake. The fake writes a synthetic
.nimble; the registry hashes that. So tests don't assert specific
content_hash values — only that they are well-formed sha256 hex.
"""

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.manifest import LocalDep, Manifest, TarballDep, UrlDep
from milpa.resolver import ResolvedDep, ResolvedGraph, resolve


@dataclass
class FakeFetcher:
    """In-test Fetcher. Maps (url, ref) → (sha, nimble_text).

    Implements the Fetcher protocol — handles GitProvenance, writes a
    synthetic .nimble to dest, returns a GitReceipt with the recorded
    sha. content_hash is computed by the registry."""
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


def fake_registry(by_url_ref):
    """Build a FetcherRegistry containing one FakeFetcher. Returns
    (registry, fake) so callers can inspect fake.calls."""
    fake = FakeFetcher(by_url_ref)
    reg = FetcherRegistry()
    reg.register(fake)
    return reg, fake


def test_resolve_single_url_dep_no_transitive(tmp_path):
    reg, _ = fake_registry({
        ("https://example.com/foo.git", "main"): (
            "aaa111", 'srcDir = "src"\n',
        ),
    })
    manifest = Manifest(
        deps=(UrlDep(name="foo", git="https://example.com/foo.git", ref="main"),),
        kind="library",
    )
    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=reg,
    )
    assert isinstance(graph, ResolvedGraph)
    assert len(graph.deps) == 1
    assert graph.deps[0].name == "foo"
    assert graph.deps[0].sha == "aaa111"
    # content_hash is now milpa-computed from the dest tree; only assert shape
    assert graph.deps[0].identity is not None
    assert graph.deps[0].identity.startswith("sha256:")
    assert len(graph.deps[0].identity) == len("sha256:") + 64
    assert graph.deps[0].src_dir == "src"


def test_resolve_url_dep_with_transitive_url(tmp_path):
    reg, _ = fake_registry({
        ("https://example.com/foo.git", "main"): (
            "aaa111",
            'srcDir = "src"\nrequires "https://example.com/bar.git#v1"\n',
        ),
        ("https://example.com/bar.git", "v1"): (
            "bbb222", 'srcDir = "src"\n',
        ),
    })
    manifest = Manifest(
        deps=(UrlDep(name="foo", git="https://example.com/foo.git", ref="main"),),
        kind="library",
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps",
        fetcher=reg,
    )
    names = [d.name for d in graph.deps]
    assert "foo" in names
    assert "bar" in names


def test_resolve_dedup_same_url_ref(tmp_path):
    """Two paths to the same URL+ref → fetched once, single entry."""
    reg, fake = fake_registry({
        ("https://example.com/foo.git", "main"): (
            "aaa111",
            'srcDir = "src"\nrequires "https://example.com/shared.git#v1"\n',
        ),
        ("https://example.com/bar.git", "main"): (
            "bbb222",
            'srcDir = "src"\nrequires "https://example.com/shared.git#v1"\n',
        ),
        ("https://example.com/shared.git", "v1"): (
            "ccc333", 'srcDir = "src"\n',
        ),
    })
    manifest = Manifest(
        deps=(
            UrlDep(name="foo", git="https://example.com/foo.git", ref="main"),
            UrlDep(name="bar", git="https://example.com/bar.git", ref="main"),
        ),
        kind="library",
    )
    graph = resolve(manifest, deps_dir=tmp_path / "_deps",
        fetcher=reg)
    shared_entries = [d for d in graph.deps if d.name == "shared"]
    assert len(shared_entries) == 1
    shared_calls = [c for c in fake.calls if c[0] == "shared"]
    assert len(shared_calls) == 1


def test_resolve_named_dep_strategy_applies_to_index_versions(tmp_path):
    """P3.2: with the multi-version candidate set, the resolver strategy now
    applies to named deps from the index.

    - MAXVER picks the highest satisfying version (1.0.0).
    - MINVER picks the lowest satisfying version (0.4.0).

    Pre-P3.2 behaviour (always maxver regardless of strategy) is GONE —
    this test documents the new correct behaviour.
    """
    from milpa.manifest import NamedDep
    from milpa.solver import Strategy
    from tests.indexkdl import make_index, fake_content_hash

    manifest = Manifest(
        deps=(NamedDep(name="foo", constraint=">= 0.4.0"),),
        kind="library",
    )
    nimble = 'srcDir = "src"\n'
    index = make_index([
        {"name": "foo", "version": "0.4.0",
         "url": "https://example.com/foo.git", "ref": "v0.4.0",
         "content_hash": fake_content_hash("foo", nimble)},
        {"name": "foo", "version": "0.5.0",
         "url": "https://example.com/foo.git", "ref": "v0.5.0",
         "content_hash": fake_content_hash("foo", nimble)},
        {"name": "foo", "version": "1.0.0",
         "url": "https://example.com/foo.git", "ref": "v1.0.0",
         "content_hash": fake_content_hash("foo", nimble)},
    ])

    reg_max, _ = fake_registry({
        ("https://example.com/foo.git", "v1.0.0"): ("sha100", nimble),
    })
    reg_min, _ = fake_registry({
        ("https://example.com/foo.git", "v0.4.0"): ("sha040", nimble),
    })

    # MAXVER: highest satisfying wins.
    graph_max = resolve(
        manifest, deps_dir=tmp_path / "_deps_max",
        index=index, fetcher=reg_max, strategy=Strategy.MAXVER,
    )
    foo_max = next(d for d in graph_max.deps if d.name == "foo")
    assert foo_max.version == (1, 0, 0)
    assert foo_max.ref == "v1.0.0"

    # MINVER: lowest satisfying wins (strategy now applies to named deps).
    graph_min = resolve(
        manifest, deps_dir=tmp_path / "_deps_min",
        index=index, fetcher=reg_min, strategy=Strategy.MINVER,
    )
    foo_min = next(d for d in graph_min.deps if d.name == "foo")
    assert foo_min.version == (0, 4, 0)
    assert foo_min.ref == "v0.4.0"


def test_resolve_parallel_produces_byte_identical_lockfile(tmp_path):
    """`milpa.lock` is byte-identical regardless of max_parallel."""
    from milpa.lockfile import format_lockfile, from_graph
    fixtures = {
        ("https://example.com/foo.git", "main"): ("fsha", 'srcDir = "src"\n'),
        ("https://example.com/bar.git", "main"): ("bsha", 'srcDir = "src"\n'),
        ("https://example.com/baz.git", "main"): ("zsha", 'srcDir = "src"\n'),
    }
    manifest = Manifest(
        deps=(
            UrlDep(name="foo", git="https://example.com/foo.git", ref="main"),
            UrlDep(name="bar", git="https://example.com/bar.git", ref="main"),
            UrlDep(name="baz", git="https://example.com/baz.git", ref="main"),
        ),
        kind="library",
    )
    reg_s, _ = fake_registry(fixtures)
    serial = resolve(
        manifest, deps_dir=tmp_path / "s",
        fetcher=reg_s, max_parallel=1,
    )
    reg_p, _ = fake_registry(fixtures)
    parallel = resolve(
        manifest, deps_dir=tmp_path / "p",
        fetcher=reg_p, max_parallel=8,
    )
    assert format_lockfile(from_graph(serial)) == format_lockfile(from_graph(parallel))


def test_resolve_parallel_dedup_no_double_fetch(tmp_path):
    """Two URL deps both pointing at the same (git, ref) should still
    result in exactly one fetch under parallelism."""
    fixtures = {
        ("https://example.com/foo.git", "main"): (
            "fsha",
            'srcDir = "src"\nrequires "https://example.com/shared.git#v1"\n',
        ),
        ("https://example.com/bar.git", "main"): (
            "bsha",
            'srcDir = "src"\nrequires "https://example.com/shared.git#v1"\n',
        ),
        ("https://example.com/shared.git", "v1"): ("ssha", 'srcDir = "src"\n'),
    }
    reg, fake = fake_registry(fixtures)
    manifest = Manifest(
        deps=(
            UrlDep(name="foo", git="https://example.com/foo.git", ref="main"),
            UrlDep(name="bar", git="https://example.com/bar.git", ref="main"),
        ),
        kind="library",
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps",
        fetcher=reg, max_parallel=4,
    )
    assert sum(1 for d in graph.deps if d.name == "shared") == 1
    assert sum(1 for c in fake.calls if c[0] == "shared") == 1


def test_resolve_parallel_failure_surfaces(tmp_path):
    """One fetcher failure should surface as an exception, not deadlock."""
    from milpa.fetchers import FetchError

    @dataclass
    class FailingFetcher:
        good: dict[tuple[str, str], tuple[str, str]]
        calls: list = field(default_factory=list)
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            self.calls.append(name)
            if (p.url, p.ref) not in self.good:
                raise FetchError(f"simulated failure for {name}")
            sha, nimble_text = self.good[(p.url, p.ref)]
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text(nimble_text)
            return GitReceipt(commit_sha=sha)

    fixtures = {
        ("https://example.com/good1.git", "main"): ("g1", 'srcDir = "src"\n'),
        ("https://example.com/good2.git", "main"): ("g2", 'srcDir = "src"\n'),
    }
    manifest = Manifest(
        deps=(
            UrlDep(name="good1", git="https://example.com/good1.git", ref="main"),
            UrlDep(name="good2", git="https://example.com/good2.git", ref="main"),
            UrlDep(name="bad",   git="https://example.com/bad.git",   ref="main"),
        ),
        kind="library",
    )
    reg = FetcherRegistry()
    reg.register(FailingFetcher(fixtures))
    with pytest.raises(FetchError) as exc:
        resolve(
            manifest, deps_dir=tmp_path / "_deps",
        fetcher=reg, max_parallel=4,
        )
    assert "bad" in str(exc.value)


def test_resolve_parallel_wide_graph(tmp_path):
    """A wide graph (manifest root + 7 sibling URL deps) resolves under
    parallelism without losing or duplicating any dep."""
    names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta"]
    fixtures = {
        (f"https://example.com/{n}.git", "main"): (f"{n}sha", 'srcDir = "src"\n')
        for n in names
    }
    manifest = Manifest(
        deps=tuple(
            UrlDep(name=n, git=f"https://example.com/{n}.git", ref="main")
            for n in names
        ),
        kind="library",
    )
    reg, _ = fake_registry(fixtures)
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps",
        fetcher=reg, max_parallel=4,
    )
    resolved_names = {d.name for d in graph.deps}
    assert resolved_names == set(names)


def test_resolve_parallel_produces_same_graph_as_serial(tmp_path):
    """Parallel and serial resolution must produce identical ResolvedGraphs."""
    fixtures = {
        ("https://example.com/foo.git", "main"): ("fsha", 'srcDir = "src"\n'),
        ("https://example.com/bar.git", "main"): ("bsha", 'srcDir = "src"\n'),
    }
    manifest = Manifest(
        deps=(
            UrlDep(name="foo", git="https://example.com/foo.git", ref="main"),
            UrlDep(name="bar", git="https://example.com/bar.git", ref="main"),
        ),
        kind="library",
    )

    reg_s, _ = fake_registry(fixtures)
    serial = resolve(
        manifest, deps_dir=tmp_path / "serial",
        fetcher=reg_s, max_parallel=1,
    )
    reg_p, _ = fake_registry(fixtures)
    parallel = resolve(
        manifest, deps_dir=tmp_path / "parallel",
        fetcher=reg_p, max_parallel=4,
    )
    def normalize(g):
        return tuple(
            (d.name, d.source, d.ref, d.sha, d.version,
             d.identity, d.src_dir, d.requires)
            for d in g.deps
        )
    assert normalize(serial) == normalize(parallel)


def test_resolve_url_dep_with_override_fetches_override(tmp_path):
    """A manifest URL dep matching an override is fetched from the
    override's URL+ref, not the manifest's."""
    from milpa.manifest import Override
    fixtures = {
        ("https://my-fork/chronos.git", "my-fix"): ("fork-sha", 'srcDir = "src"\n'),
    }
    manifest = Manifest(
        deps=(UrlDep(name="chronos",
                     git="https://upstream/chronos.git",
                     ref="main"),),
        kind="library",
        overrides=(__import__("milpa.manifest", fromlist=["Override"]).Override(
            name="chronos",
            git="https://my-fork/chronos.git",
            ref="my-fix",
        ),),
    )
    reg, _ = fake_registry(fixtures)
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps",
        fetcher=reg,
    )
    chronos = next(d for d in graph.deps if d.name == "chronos")
    assert chronos.source == "https://my-fork/chronos.git"
    assert chronos.ref == "my-fix"


def test_resolve_named_dep_with_override_skips_index(tmp_path):
    """A NamedDep matching an override bypasses the tianguis index
    entirely and fetches the override's URL+ref directly. The index is
    deliberately empty — if the override path consulted it, resolution
    would raise TNG-NOT-FOUND."""
    from milpa.manifest import NamedDep, Override
    from tests.indexkdl import make_index
    fixtures = {
        ("https://my-fork/results.git", "patched"): ("ovr-sha", ""),
    }
    manifest = Manifest(
        deps=(NamedDep(name="results", constraint=">= 0.4.0"),),
        kind="library",
        overrides=(Override(
            name="results",
            git="https://my-fork/results.git",
            ref="patched",
        ),),
    )
    reg, _ = fake_registry(fixtures)
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps",
        fetcher=reg,
        index=make_index([]),   # empty — must not be consulted
    )
    results_dep = next(d for d in graph.deps if d.name == "results")
    assert results_dep.source == "https://my-fork/results.git"
    assert results_dep.ref == "patched"


def test_resolve_transitive_url_dep_override(tmp_path):
    """An override applies to transitive deps brought in by other deps."""
    from milpa.manifest import Override
    fixtures = {
        ("https://example.com/app.git", "main"): (
            "app-sha",
            'srcDir = "src"\nrequires "https://upstream/chronos.git#main"\n',
        ),
        ("https://my-fork/chronos.git", "my-fix"): ("fork-sha", 'srcDir = "src"\n'),
    }
    manifest = Manifest(
        deps=(UrlDep(name="app",
                     git="https://example.com/app.git",
                     ref="main"),),
        kind="library",
        overrides=(Override(
            name="chronos",
            git="https://my-fork/chronos.git",
            ref="my-fix",
        ),),
    )
    reg, _ = fake_registry(fixtures)
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps",
        fetcher=reg,
    )
    chronos = next(d for d in graph.deps if d.name == "chronos")
    assert chronos.source == "https://my-fork/chronos.git"
    assert chronos.ref == "my-fix"


def test_resolve_local_dep_uses_default_local_fetcher(tmp_path):
    """End-to-end: a manifest LocalDep gets copied into _deps/ via
    LocalFetcher (default registry), and the ResolvedGraph carries the
    local dep with source='local:<as-declared>', ref=None, sha=None,
    content_hash populated."""
    # Build a local source tree the resolver will treat as the dep.
    project = tmp_path / "project"
    project.mkdir()
    source = tmp_path / "intonaco"
    source.mkdir()
    (source / "intonaco.nimble").write_text('srcDir = "src"\n')

    manifest = Manifest(
        deps=(LocalDep(name="intonaco", path="../intonaco"),),
        kind="library",
    )
    # Use the default registry — exercises real LocalFetcher
    graph = resolve(
        manifest,
        deps_dir=project / "_deps",
    )

    assert len(graph.deps) == 1
    d = graph.deps[0]
    assert d.name == "intonaco"
    assert d.source == "local:../intonaco"      # as-declared preserved
    assert d.ref is None
    assert d.sha is None
    assert d.identity is not None
    assert d.identity.startswith("sha256:")
    assert len(d.identity) == len("sha256:") + 64
    # Source bytes copied into _deps
    assert (project / "_deps" / "intonaco" / "intonaco.nimble").exists()


def test_resolve_local_dep_with_transitive_url_requires(tmp_path):
    """A local dep whose .nimble has 'requires "https://..."' triggers
    the URL fetch path for the transitive dep. Local + URL transports
    compose end-to-end.

    Uses the default registry for the LOCAL fetch (real LocalFetcher)
    and a fake fetcher for the URL transitive (avoids network)."""
    project = tmp_path / "project"
    project.mkdir()

    # Local source for intonaco with a transitive URL requires.
    source = tmp_path / "intonaco"
    source.mkdir()
    (source / "intonaco.nimble").write_text(
        'srcDir = "src"\n'
        'requires "https://example.com/chronos.git#feat/contextvars"\n'
    )

    # Build a custom registry: LocalFetcher for local + fake fetcher
    # for the URL transitive.
    from milpa.fetchers import FetcherRegistry
    from milpa.fetchers.local import LocalFetcher
    reg = FetcherRegistry()
    reg.register(LocalFetcher())
    fake_url, _ = fake_registry({
        ("https://example.com/chronos.git", "feat/contextvars"): (
            "csha", 'srcDir = "src"\n',
        ),
    })
    # fake_url is itself a registry; pull its single FakeFetcher out
    # and re-register on the combined registry.
    for f in fake_url._fetchers:
        reg.register(f)

    manifest = Manifest(
        deps=(LocalDep(name="intonaco", path="../intonaco"),),
        kind="library",
    )
    graph = resolve(
        manifest,
        deps_dir=project / "_deps",
        fetcher=reg,
    )

    names = {d.name for d in graph.deps}
    assert "intonaco" in names
    assert "chronos" in names
    # intonaco is local
    intonaco = next(d for d in graph.deps if d.name == "intonaco")
    assert intonaco.source == "local:../intonaco"
    # chronos is URL
    chronos = next(d for d in graph.deps if d.name == "chronos")
    assert chronos.source == "https://example.com/chronos.git"
    assert chronos.sha == "csha"


def test_resolve_tarball_dep_via_default_registry(tmp_path):
    """End-to-end: a manifest TarballDep flows through the default
    registry's TarballFetcher; resolved graph carries the dep with
    source='tarball:<url>' and content_hash populated."""
    import hashlib
    import io
    import tarfile

    # Build a local tarball that the resolver will fetch via file://
    archive = tmp_path / "pkg.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        data = 'srcDir = "src"\n'.encode()
        info = tarfile.TarInfo(name="pkg.nimble")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()

    manifest = Manifest(
        deps=(TarballDep(
            name="pkg",
            url=f"file://{archive}",
            sha256=archive_sha,
        ),),
        kind="library",
        name="test",
    )

    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
    )

    assert len(graph.deps) == 1
    d = graph.deps[0]
    assert d.name == "pkg"
    assert d.source == f"tarball:file://{archive}"
    assert d.ref is None
    assert d.sha is None
    assert d.identity is not None
    assert d.identity.startswith("sha256:")
    assert len(d.identity) == len("sha256:") + 64


def test_resolve_topological_order(tmp_path):
    """Dependencies appear before the packages that require them."""
    reg, _ = fake_registry({
        ("https://example.com/app.git", "main"): (
            "a1",
            'srcDir = "src"\nrequires "https://example.com/mid.git#main"\n',
        ),
        ("https://example.com/mid.git", "main"): (
            "m1",
            'srcDir = "src"\nrequires "https://example.com/leaf.git#main"\n',
        ),
        ("https://example.com/leaf.git", "main"): ("l1", 'srcDir = "src"\n'),
    })
    manifest = Manifest(
        deps=(UrlDep(name="app", git="https://example.com/app.git", ref="main"),),
        kind="library",
    )
    graph = resolve(manifest, deps_dir=tmp_path / "_deps",
        fetcher=reg)
    names = [d.name for d in graph.deps]
    assert names.index("leaf") < names.index("mid")
    assert names.index("mid") < names.index("app")
