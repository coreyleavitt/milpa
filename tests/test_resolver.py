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
from milpa.manifest import Manifest, UrlDep
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
        registry={},
        fetcher=reg,
    )
    assert isinstance(graph, ResolvedGraph)
    assert len(graph.deps) == 1
    assert graph.deps[0].name == "foo"
    assert graph.deps[0].sha == "aaa111"
    # content_hash is now milpa-computed from the dest tree; only assert shape
    assert graph.deps[0].content_hash is not None
    assert len(graph.deps[0].content_hash) == 64
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
        registry={}, fetcher=reg,
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
                    registry={}, fetcher=reg)
    shared_entries = [d for d in graph.deps if d.name == "shared"]
    assert len(shared_entries) == 1
    shared_calls = [c for c in fake.calls if c[0] == "shared"]
    assert len(shared_calls) == 1


def test_resolve_minver_strategy_threads_through_to_solver(tmp_path):
    """Strategy passes from resolve() to the solver. Use a named dep
    with multiple registry versions and verify MinVer picks the floor."""
    from milpa.registry import RegistryEntry
    from milpa.solver import Strategy

    manifest = Manifest(
        deps=(
            __import__("milpa.manifest", fromlist=["NamedDep"]).NamedDep(
                name="foo", constraint=">= 0.4.0",
            ),
        ),
        kind="library",
    )
    registry = {
        "foo": RegistryEntry(
            name="foo", url="https://example.com/foo.git", method="git",
        ),
    }
    list_tags = lambda url: ["v0.4.0", "v0.5.0", "v1.0.0"]

    reg, _ = fake_registry({
        ("https://example.com/foo.git", "v0.4.0"): ("sha040", ""),
    })

    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps",
        registry=registry,
        fetcher=reg,
        list_tags=list_tags,
        strategy=Strategy.MINVER,
    )
    foo_dep = next(d for d in graph.deps if d.name == "foo")
    assert foo_dep.tag == "v0.4.0"
    assert foo_dep.version == (0, 4, 0)


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
        registry={}, fetcher=reg_s, max_parallel=1,
    )
    reg_p, _ = fake_registry(fixtures)
    parallel = resolve(
        manifest, deps_dir=tmp_path / "p",
        registry={}, fetcher=reg_p, max_parallel=8,
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
        registry={}, fetcher=reg, max_parallel=4,
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
            registry={}, fetcher=reg, max_parallel=4,
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
        registry={}, fetcher=reg, max_parallel=4,
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
        registry={}, fetcher=reg_s, max_parallel=1,
    )
    reg_p, _ = fake_registry(fixtures)
    parallel = resolve(
        manifest, deps_dir=tmp_path / "parallel",
        registry={}, fetcher=reg_p, max_parallel=4,
    )
    def normalize(g):
        return tuple(
            (d.name, d.source, d.ref, d.tag, d.sha, d.version,
             d.content_hash, d.src_dir, d.requires)
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
        registry={}, fetcher=reg,
    )
    chronos = next(d for d in graph.deps if d.name == "chronos")
    assert chronos.source == "https://my-fork/chronos.git"
    assert chronos.ref == "my-fix"


def test_resolve_named_dep_with_override_skips_registry(tmp_path):
    """A NamedDep matching an override bypasses the registry entirely
    and fetches the override's URL+ref directly."""
    from milpa.manifest import NamedDep, Override
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
    fake_list_tags = lambda url: pytest.fail(
        "list_tags should not be called when override matches"
    )
    reg, _ = fake_registry(fixtures)
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps",
        registry={},
        fetcher=reg,
        list_tags=fake_list_tags,
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
        registry={}, fetcher=reg,
    )
    chronos = next(d for d in graph.deps if d.name == "chronos")
    assert chronos.source == "https://my-fork/chronos.git"
    assert chronos.ref == "my-fix"


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
                    registry={}, fetcher=reg)
    names = [d.name for d in graph.deps]
    assert names.index("leaf") < names.index("mid")
    assert names.index("mid") < names.index("app")
