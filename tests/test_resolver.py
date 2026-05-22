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
