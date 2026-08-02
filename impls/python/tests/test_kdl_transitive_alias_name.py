"""Regression: a transitive dep's ``milpa.kdl``-declared node name for a
nested ``git=`` sub-dependency must be the AUTHORITATIVE name across the
whole edge-sourcing boundary — the solver term the parent candidate carries,
the BFS-enqueued dep, the provenance-gate key, and root-authority/overrides
suppression must all agree on ONE name.

**The bug:** ``edge_sources.edgeset_to_terms`` derived the parent's solver
term for a ``UrlRequire`` entry from ``_name_from_url(entry.url)`` (the URL
tail), while ``edgeset_to_bfs_deps`` (used to enqueue the actual child dep)
already preferred ``entry.name`` (the declared KDL node name) when set. When
a transitive ``milpa.kdl`` declares a sub-dep under a node name that differs
from its URL's tail — e.g. ``"z3" git=(url)"https://.../nim-z3.git"`` — the
two derivations disagree: the child gets registered/resolved under the
DECLARED name, but the parent's own candidate requires the URL-TAIL name.
That URL-tail name has no candidate anywhere in the graph → PubGrub unwinds
to a conflict, surfacing as "every root dep has no satisfying version" even
though the declared name is fully satisfiable (by a root dep or an
``overrides {}`` rule for that same name/provenance).

Fixture shape (mirrors ``tests/test_provenance_lattice.py``'s mocked-git +
in-memory-index infra): a root package + a ``wrapper`` transitive package
whose OWN ``milpa.kdl`` declares a git sub-dep node-named ``"foo"`` at a URL
whose tail is ``real-bar-repo`` (deliberately different from ``foo``). The
root ALSO declares (or overrides) ``foo`` at that SAME url/ref — root
authority over the name ``foo``. Expected: unifies, resolves cleanly.
"""

from __future__ import annotations

from pathlib import Path

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.lockfile import ResolvedGraph
from milpa.manifest import parse_manifest
from milpa.resolver import resolve

WRAPPER_URL = "https://example.com/wrapper.git"
# Deliberately named so the URL tail ("real-bar-repo") differs from the
# node name the wrapper's milpa.kdl declares for it ("foo").
FOO_URL = "https://example.com/real-bar-repo.git"


def _stage(mocked_dir: Path, url: str, ref: str, *, sha: str, kdl: str | None = None, marker: str = "x") -> None:
    d = mocked_dir / url_key(url, ref)
    content = d / "content"
    content.mkdir(parents=True)
    (content / "marker.nim").write_text(f"# {marker}\n", encoding="utf-8")
    if kdl is not None:
        (content / "milpa.kdl").write_text(kdl, encoding="utf-8")
    (d / "sha").write_text(sha, encoding="utf-8")


def _env(tmp_path: Path, mocked_dir: Path) -> MilpaEnv:
    store = CAStore(tmp_path / "cas")
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


def _resolve(root_kdl: str, env: MilpaEnv, tmp_path: Path) -> ResolvedGraph:
    manifest = parse_manifest(root_kdl)
    deps_dir = tmp_path / "_deps"
    deps_dir.mkdir(exist_ok=True)
    return resolve(manifest, deps_dir, env, ResolveParams())


def _dep(graph: ResolvedGraph, name: str):
    return next(d for d in graph.deps if d.name == name)


def _stage_wrapper_and_foo(mocked_dir: Path) -> None:
    _stage(
        mocked_dir, WRAPPER_URL, "main", sha="a" * 40,
        kdl=(
            'name "wrapper"\nkind "library"\n'
            "deps {\n"
            f'    "foo" git=(url)"{FOO_URL}" ref="main"\n'
            "}\n"
        ),
    )
    _stage(mocked_dir, FOO_URL, "main", sha="b" * 40, marker="foo-leaf")


class TestRootDepUnifiesWithMismatchedAliasName:
    """Root directly declares ``foo`` at the SAME url/ref the transitive
    ``wrapper`` package aliases under node name ``"foo"`` (url tail
    ``real-bar-repo``). Root authority over ``foo`` must unify with the
    transitive's ``foo`` requirement — resolution succeeds, no conflict."""

    def test_resolves_when_root_declares_matching_name(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _stage_wrapper_and_foo(mocked_dir)

        env = _env(tmp_path, mocked_dir)
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    wrapper git=(url)"{WRAPPER_URL}" ref="main"\n'
            f'    foo git=(url)"{FOO_URL}" ref="main"\n'
            "}\n"
        )
        graph = _resolve(root_kdl, env, tmp_path)

        names = {d.name for d in graph.deps}
        assert names == {"wrapper", "foo"}
        # The wrapper's transitive requirement for "foo" and the root's own
        # "foo" dep must be the SAME resolved candidate, not two orphaned names.
        foo_dep = _dep(graph, "foo")
        assert foo_dep.provenances[0].url == FOO_URL


class TestOverrideUnifiesWithMismatchedAliasName:
    """Root has NO direct dep on ``foo`` — instead an ``overrides {}`` rule
    redirects the name ``foo`` to the same url/ref. Root authority via
    override must ALSO unify with the transitive's declared-name ``foo``
    requirement."""

    def test_resolves_when_root_overrides_matching_name(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _stage_wrapper_and_foo(mocked_dir)

        env = _env(tmp_path, mocked_dir)
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    wrapper git=(url)"{WRAPPER_URL}" ref="main"\n'
            "}\n"
            "overrides {\n"
            f'    pkg "foo" git=(url)"{FOO_URL}" ref="main"\n'
            "}\n"
        )
        graph = _resolve(root_kdl, env, tmp_path)

        names = {d.name for d in graph.deps}
        assert names == {"wrapper", "foo"}
        foo_dep = _dep(graph, "foo")
        assert foo_dep.provenances[0].url == FOO_URL


class TestOrdinaryMatchingNameTransitiveStillWorks:
    """Regression pin: an ordinary transitive git dep whose node name ALREADY
    matches its URL tail must keep working exactly as before (no root
    involvement needed — the transitive's own single candidate satisfies it)."""

    def test_matching_name_transitive_resolves_without_root_involvement(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        baz_url = "https://example.com/baz.git"
        _stage(
            mocked_dir, WRAPPER_URL, "main", sha="a" * 40,
            kdl=(
                'name "wrapper"\nkind "library"\n'
                "deps {\n"
                f'    baz git=(url)"{baz_url}" ref="main"\n'
                "}\n"
            ),
        )
        _stage(mocked_dir, baz_url, "main", sha="b" * 40, marker="baz-leaf")

        env = _env(tmp_path, mocked_dir)
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            f'    wrapper git=(url)"{WRAPPER_URL}" ref="main"\n'
            "}\n"
        )
        graph = _resolve(root_kdl, env, tmp_path)

        names = {d.name for d in graph.deps}
        assert names == {"wrapper", "baz"}
