"""Resolver glue tests.

The resolver assembles fetcher + registry + nimble_parse + solver into a
single `resolve(manifest, ...) -> ResolvedGraph` call. Tests inject a
fake fetcher (and an empty registry, since fresco's tree mostly uses URL
deps for these scenarios) so we exercise the integration without
network or git.
"""

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from milpa.manifest import Manifest, UrlDep
from milpa.resolver import ResolvedDep, ResolvedGraph, resolve


@dataclass
class FakeFetch:
    """In-test fetcher. Maps (git, ref) → (sha, content_hash, nimble_text).

    The fetch function (passed as `fetcher` kwarg to resolve) signature
    matches milpa.fetcher.fetch_url_dep but consults this dict instead
    of running git.
    """
    by_url_ref: dict[tuple[str, str], tuple[str, str, str]]
    calls: list[tuple[str, str, str]] = field(default_factory=list)

    def __call__(self, name, git, ref, *, deps_dir):
        from milpa.fetcher import FetchResult
        self.calls.append((name, git, ref))
        sha, content_hash, nimble_text = self.by_url_ref[(git, ref)]
        # Write a synthetic _deps/<name>/<name>.nimble for the parser
        target = deps_dir / name
        target.mkdir(parents=True, exist_ok=True)
        (target / f"{name}.nimble").write_text(nimble_text)
        return FetchResult(
            name=name, path=target, sha=sha, content_hash=content_hash,
        )


def test_resolve_single_url_dep_no_transitive(tmp_path):
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "aaa111", "deadbeef",
            'srcDir = "src"\n',   # no requires
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
        fetcher=fake,
    )
    assert isinstance(graph, ResolvedGraph)
    assert len(graph.deps) == 1
    assert graph.deps[0].name == "foo"
    assert graph.deps[0].sha == "aaa111"
    assert graph.deps[0].content_hash == "deadbeef"
    assert graph.deps[0].src_dir == "src"


def test_resolve_url_dep_with_transitive_url(tmp_path):
    """Manifest's `foo` URL dep has its own `requires` for `bar` URL.
    Both should be fetched and appear in the resolved graph."""
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "aaa111", "hash_foo",
            'srcDir = "src"\nrequires "https://example.com/bar.git#v1"\n',
        ),
        ("https://example.com/bar.git", "v1"): (
            "bbb222", "hash_bar",
            'srcDir = "src"\n',
        ),
    })
    manifest = Manifest(
        deps=(UrlDep(name="foo", git="https://example.com/foo.git", ref="main"),),
        kind="library",
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps",
        registry={}, fetcher=fake,
    )
    names = [d.name for d in graph.deps]
    assert "foo" in names
    assert "bar" in names


def test_resolve_dedup_same_url_ref(tmp_path):
    """Two paths to the same URL+ref → fetched once, single entry."""
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "aaa111", "hash_foo",
            'srcDir = "src"\nrequires "https://example.com/shared.git#v1"\n',
        ),
        ("https://example.com/bar.git", "main"): (
            "bbb222", "hash_bar",
            'srcDir = "src"\nrequires "https://example.com/shared.git#v1"\n',
        ),
        ("https://example.com/shared.git", "v1"): (
            "ccc333", "hash_shared",
            'srcDir = "src"\n',
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
                    registry={}, fetcher=fake)
    # Shared appears once in the graph
    shared_entries = [d for d in graph.deps if d.name == "shared"]
    assert len(shared_entries) == 1
    # The fetcher was called for shared only once
    shared_calls = [c for c in fake.calls if c[0] == "shared"]
    assert len(shared_calls) == 1


def test_resolve_minver_strategy_threads_through_to_solver(tmp_path):
    """Strategy passes from resolve() to the solver. Use a named dep
    with multiple registry versions and verify MinVer picks the floor."""
    from milpa.registry import RegistryEntry
    from milpa.solver import Strategy

    # Manifest declares a named dep with `>= 0.4.0` constraint.
    manifest = Manifest(
        deps=(
            # NamedDep — registry-resolved, multiple versions
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
    # The registry lists three matching tags; MinVer should pick v0.4.0.
    list_tags = lambda url: ["v0.4.0", "v0.5.0", "v1.0.0"]

    fixtures = {
        ("https://example.com/foo.git", "v0.4.0"): (
            "sha040", "hash040", '',
        ),
        # Only fixture v0.4.0; if the resolver mistakenly picked another,
        # FakeFetch would KeyError loudly.
    }

    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps",
        registry=registry,
        fetcher=FakeFetch(fixtures),
        list_tags=list_tags,
        strategy=Strategy.MINVER,
    )
    foo_dep = next(d for d in graph.deps if d.name == "foo")
    assert foo_dep.tag == "v0.4.0"
    assert foo_dep.version == (0, 4, 0)


def test_resolve_parallel_produces_byte_identical_lockfile(tmp_path):
    """`milpa.lock` is byte-identical regardless of max_parallel.
    Lockfile is sorted by name; fetch order doesn't affect output."""
    from milpa.lockfile import format_lockfile, from_graph
    fixtures = {
        ("https://example.com/foo.git", "main"): (
            "fsha", "fhash", 'srcDir = "src"\n',
        ),
        ("https://example.com/bar.git", "main"): (
            "bsha", "bhash", 'srcDir = "src"\n',
        ),
        ("https://example.com/baz.git", "main"): (
            "zsha", "zhash", 'srcDir = "src"\n',
        ),
    }
    manifest = Manifest(
        deps=(
            UrlDep(name="foo", git="https://example.com/foo.git", ref="main"),
            UrlDep(name="bar", git="https://example.com/bar.git", ref="main"),
            UrlDep(name="baz", git="https://example.com/baz.git", ref="main"),
        ),
        kind="library",
    )
    serial = resolve(
        manifest, deps_dir=tmp_path / "s",
        registry={}, fetcher=FakeFetch(fixtures), max_parallel=1,
    )
    parallel = resolve(
        manifest, deps_dir=tmp_path / "p",
        registry={}, fetcher=FakeFetch(fixtures), max_parallel=8,
    )
    assert format_lockfile(from_graph(serial)) == format_lockfile(from_graph(parallel))


def test_resolve_parallel_dedup_no_double_fetch(tmp_path):
    """Two URL deps both pointing at the same (git, ref) should still
    result in exactly one fetch under parallelism. The seen_url set is
    guarded by the main thread; submit() is the only place that adds to
    it, and the main thread submits sequentially even when workers run
    concurrently."""
    fixtures = {
        ("https://example.com/foo.git", "main"): (
            "fsha", "fhash",
            'srcDir = "src"\nrequires "https://example.com/shared.git#v1"\n',
        ),
        ("https://example.com/bar.git", "main"): (
            "bsha", "bhash",
            'srcDir = "src"\nrequires "https://example.com/shared.git#v1"\n',
        ),
        ("https://example.com/shared.git", "v1"): (
            "ssha", "shash", 'srcDir = "src"\n',
        ),
    }
    fake = FakeFetch(fixtures)
    manifest = Manifest(
        deps=(
            UrlDep(name="foo", git="https://example.com/foo.git", ref="main"),
            UrlDep(name="bar", git="https://example.com/bar.git", ref="main"),
        ),
        kind="library",
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps",
        registry={}, fetcher=fake, max_parallel=4,
    )
    # shared appears once
    assert sum(1 for d in graph.deps if d.name == "shared") == 1
    # shared was fetched exactly once
    assert sum(1 for c in fake.calls if c[0] == "shared") == 1


def test_resolve_parallel_failure_surfaces(tmp_path):
    """One fetcher failure should surface as an exception, not deadlock."""
    from milpa.fetcher import FetchError

    @dataclass
    class FailingFetch:
        good: dict[tuple[str, str], tuple[str, str, str]]
        calls: list = field(default_factory=list)
        def __call__(self, name, git, ref, *, deps_dir):
            from milpa.fetcher import FetchResult
            self.calls.append(name)
            if (git, ref) not in self.good:
                raise FetchError(f"simulated failure for {name}")
            sha, content_hash, nimble_text = self.good[(git, ref)]
            target = deps_dir / name
            target.mkdir(parents=True, exist_ok=True)
            (target / f"{name}.nimble").write_text(nimble_text)
            return FetchResult(name=name, path=target, sha=sha,
                               content_hash=content_hash)

    fixtures = {
        ("https://example.com/good1.git", "main"): (
            "g1", "g1h", 'srcDir = "src"\n',
        ),
        ("https://example.com/good2.git", "main"): (
            "g2", "g2h", 'srcDir = "src"\n',
        ),
        # bad.git deliberately missing → fetcher raises
    }
    manifest = Manifest(
        deps=(
            UrlDep(name="good1", git="https://example.com/good1.git", ref="main"),
            UrlDep(name="good2", git="https://example.com/good2.git", ref="main"),
            UrlDep(name="bad",   git="https://example.com/bad.git",   ref="main"),
        ),
        kind="library",
    )
    with pytest.raises(FetchError) as exc:
        resolve(
            manifest, deps_dir=tmp_path / "_deps",
            registry={}, fetcher=FailingFetch(fixtures), max_parallel=4,
        )
    assert "bad" in str(exc.value)


def test_resolve_parallel_wide_graph(tmp_path):
    """A wide graph (manifest root + 7 sibling URL deps) resolves under
    parallelism without losing or duplicating any dep."""
    names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta"]
    fixtures = {
        (f"https://example.com/{n}.git", "main"): (
            f"{n}sha", f"{n}hash", 'srcDir = "src"\n',
        )
        for n in names
    }
    manifest = Manifest(
        deps=tuple(
            UrlDep(name=n, git=f"https://example.com/{n}.git", ref="main")
            for n in names
        ),
        kind="library",
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps",
        registry={}, fetcher=FakeFetch(fixtures), max_parallel=4,
    )
    resolved_names = {d.name for d in graph.deps}
    assert resolved_names == set(names)


def test_resolve_parallel_produces_same_graph_as_serial(tmp_path):
    """Parallel and serial resolution must produce identical ResolvedGraphs.
    Output determinism is the key invariant — fetch ORDER may vary, but
    the resolved tree, lockfile, and nim.cfg must be byte-identical."""
    fixtures = {
        ("https://example.com/foo.git", "main"): (
            "fsha", "fhash", 'srcDir = "src"\n',
        ),
        ("https://example.com/bar.git", "main"): (
            "bsha", "bhash", 'srcDir = "src"\n',
        ),
    }
    manifest = Manifest(
        deps=(
            UrlDep(name="foo", git="https://example.com/foo.git", ref="main"),
            UrlDep(name="bar", git="https://example.com/bar.git", ref="main"),
        ),
        kind="library",
    )

    serial = resolve(
        manifest,
        deps_dir=tmp_path / "serial",
        registry={},
        fetcher=FakeFetch(fixtures),
        max_parallel=1,
    )
    parallel = resolve(
        manifest,
        deps_dir=tmp_path / "parallel",
        registry={},
        fetcher=FakeFetch(fixtures),
        max_parallel=4,
    )
    # Ignoring the _deps path field (which differs by directory),
    # graph deps should be byte-equal.
    def normalize(g):
        return tuple(
            (d.name, d.source, d.ref, d.tag, d.sha, d.version,
             d.content_hash, d.src_dir, d.requires)
            for d in g.deps
        )
    assert normalize(serial) == normalize(parallel)


def test_resolve_topological_order(tmp_path):
    """Dependencies appear before the packages that require them."""
    fake = FakeFetch({
        ("https://example.com/app.git", "main"): (
            "a1", "hash_app",
            'srcDir = "src"\nrequires "https://example.com/mid.git#main"\n',
        ),
        ("https://example.com/mid.git", "main"): (
            "m1", "hash_mid",
            'srcDir = "src"\nrequires "https://example.com/leaf.git#main"\n',
        ),
        ("https://example.com/leaf.git", "main"): (
            "l1", "hash_leaf",
            'srcDir = "src"\n',
        ),
    })
    manifest = Manifest(
        deps=(UrlDep(name="app", git="https://example.com/app.git", ref="main"),),
        kind="library",
    )
    graph = resolve(manifest, deps_dir=tmp_path / "_deps",
                    registry={}, fetcher=fake)
    names = [d.name for d in graph.deps]
    # leaf before mid before app
    assert names.index("leaf") < names.index("mid")
    assert names.index("mid") < names.index("app")
