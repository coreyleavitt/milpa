"""Phase B B-resolver dedup tests — content-hash dedup/alias.

After all deps are fetched, if two or more deps reached under DIFFERENT names
have the SAME content-identity, they collapse into ONE canonical node.  The
canonical name is determined by BFS-insertion discovery order, NOT lexicographic
order.  All requires pointing at aliased names are rewritten to the canonical name.
Aliases on the surviving canonical dep are lexicographically sorted.

Spec authority: spec/resolver-semantics.md Phase B, rfc-content-addressed-identity.md.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry
from milpa.lockfile import from_graph
from milpa.manifest import (
    Manifest,
    UrlDep,
    NamedDep,
    Dep,
    parse_manifest,
)
from milpa.resolver import resolve, resolve_workspace
from milpa.version import Strategy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_env(mocked_dir: Path, tmp_path: Path) -> MilpaEnv:
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)
    inner = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(inner, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


def _manifest(deps: list[Dep]) -> Manifest:
    return Manifest(
        name="testapp",
        kind="application",
        src_dir="",
        deps=deps,
        dev_deps=[],
        overrides=[],
        flags=[],
        self_mirrors=[],
        cas_dir="",
        spec_version=1,
        spec_version_explicit=False,
        attestation_policy=None,
    )


def _url_dep(name: str, url: str, ref: str = "main") -> UrlDep:
    return UrlDep(name=name, git=url, ref=ref, mirrors=[], predicates=[], flag_requests=[])


def _write_mock_fetch(
    mocked_dir: Path,
    url: str,
    ref: str,
    nimble_body: str,
    sha: str = "aabbcc",
) -> None:
    """Write a mocked-fetches entry for a git URL."""
    import re
    # url_key: replace non-safe chars with _; separate url and ref with @
    def _safe(s: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", s)

    key = f"{_safe(url)}@{_safe(ref)}"
    fetch_dir = mocked_dir / key
    fetch_dir.mkdir(parents=True, exist_ok=True)
    # Derive name for .nimble file from the URL (last path component without .git)
    dep_name = url.rsplit("/", 1)[-1].removesuffix(".git")
    (fetch_dir / f"{dep_name}.nimble").write_text(nimble_body, encoding="utf-8")
    (fetch_dir / "sha").write_text(sha, encoding="utf-8")


def _write_mock_fetch_milpa_kdl(
    mocked_dir: Path,
    url: str,
    ref: str,
    dep_name: str,
    kdl_body: str,
    sha: str = "aabbcc",
) -> None:
    """Write a mocked-fetches entry using milpa.kdl.

    The mocked fetcher copies files from ``content/`` into the dest dir.
    milpa.kdl must live under ``content/`` to be staged correctly.
    """
    import re

    def _safe(s: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", s)

    key = f"{_safe(url)}@{_safe(ref)}"
    fetch_dir = mocked_dir / key
    content_dir = fetch_dir / "content"
    content_dir.mkdir(parents=True, exist_ok=True)
    (content_dir / "milpa.kdl").write_text(kdl_body, encoding="utf-8")
    (fetch_dir / "sha").write_text(sha, encoding="utf-8")


# Shared milpa.kdl content — used to make two deps byte-identical (same tree,
# same identity hash).  Key: both mocked-fetch dirs write the SAME milpa.kdl
# text, so the sha256 of the tree is identical regardless of the dep name.
_SHARED_KDL = 'name "shared"\nkind "library"\nsrc_dir "src"\n'


# ---------------------------------------------------------------------------
# Test 1: tracer bullet — two URL deps, same content → one node with aliases
# ---------------------------------------------------------------------------


class TestDedupTwoDepsIdenticalContent:
    """Two URL deps with byte-identical trees collapse to one canonical node."""

    def test_graph_has_one_node(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(mocked_dir, "https://example.com/foo.git", "main", "foo", _SHARED_KDL, "sha1")
        _write_mock_fetch_milpa_kdl(mocked_dir, "https://example.com/bar.git", "main", "bar", _SHARED_KDL, "sha2")

        env = _make_env(mocked_dir, tmp_path)
        m = _manifest([
            _url_dep("foo", "https://example.com/foo.git"),
            _url_dep("bar", "https://example.com/bar.git"),
        ])
        deps_dir = tmp_path / "_deps"
        graph = resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        assert len(graph.deps) == 1, f"expected 1 dep after dedup, got {[d.name for d in graph.deps]}"

    def test_canonical_is_bfs_first(self, tmp_path: Path) -> None:
        """BFS-insertion order: 'foo' is declared first → canonical is 'foo', alias is 'bar'."""
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(mocked_dir, "https://example.com/foo.git", "main", "foo", _SHARED_KDL, "sha1")
        _write_mock_fetch_milpa_kdl(mocked_dir, "https://example.com/bar.git", "main", "bar", _SHARED_KDL, "sha2")

        env = _make_env(mocked_dir, tmp_path)
        m = _manifest([
            _url_dep("foo", "https://example.com/foo.git"),
            _url_dep("bar", "https://example.com/bar.git"),
        ])
        deps_dir = tmp_path / "_deps"
        graph = resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        assert graph.deps[0].name == "foo", f"canonical should be 'foo', got {graph.deps[0].name}"

    def test_aliases_field_on_canonical(self, tmp_path: Path) -> None:
        """The surviving dep carries aliases = ('bar',)."""
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(mocked_dir, "https://example.com/foo.git", "main", "foo", _SHARED_KDL, "sha1")
        _write_mock_fetch_milpa_kdl(mocked_dir, "https://example.com/bar.git", "main", "bar", _SHARED_KDL, "sha2")

        env = _make_env(mocked_dir, tmp_path)
        m = _manifest([
            _url_dep("foo", "https://example.com/foo.git"),
            _url_dep("bar", "https://example.com/bar.git"),
        ])
        deps_dir = tmp_path / "_deps"
        graph = resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        dep = graph.deps[0]
        assert dep.aliases == ("bar",), f"expected aliases=('bar',), got {dep.aliases!r}"

    def test_lockfile_emits_aliases(self, tmp_path: Path) -> None:
        """Lockfile output includes the aliases line."""
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(mocked_dir, "https://example.com/foo.git", "main", "foo", _SHARED_KDL, "sha1")
        _write_mock_fetch_milpa_kdl(mocked_dir, "https://example.com/bar.git", "main", "bar", _SHARED_KDL, "sha2")

        env = _make_env(mocked_dir, tmp_path)
        m = _manifest([
            _url_dep("foo", "https://example.com/foo.git"),
            _url_dep("bar", "https://example.com/bar.git"),
        ])
        deps_dir = tmp_path / "_deps"
        graph = resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        from milpa.lockfile import format_lockfile
        lock = from_graph(graph)
        text = format_lockfile(lock)
        assert 'aliases "bar"' in text, f"expected 'aliases \"bar\"' in lockfile:\n{text}"


# ---------------------------------------------------------------------------
# Test 2: BFS-insertion order beats lexicographic order
# ---------------------------------------------------------------------------


class TestBfsInsertionOrderBeatsLex:
    """Root-declared 'zlib' + root-declared 'aaa-zlib' (lex-earlier), same content:
    canonical must be 'zlib' (BFS-first / declaration-first), not 'aaa-zlib' (lex-first).

    Setup: manifest declares [zlib, aaa-zlib] in that order.  Both fetch the same
    milpa.kdl content → same identity.  BFS order = declaration order → zlib first.
    Lex order would give aaa-zlib.  Canonical must be zlib.
    """

    def test_canonical_is_bfs_declared_not_lex_min(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"

        # Both deps have the same milpa.kdl content → identical content hash.
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/zlib.git", "main", "zlib", _SHARED_KDL, "sha-z"
        )
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/aaa-zlib.git", "main", "aaa-zlib", _SHARED_KDL, "sha-a"
        )

        env = _make_env(mocked_dir, tmp_path)
        # Declaration order: zlib FIRST (index 0 in BFS), aaa-zlib SECOND (index 1).
        # Lex order: aaa-zlib < zlib. BFS order must win → canonical = zlib.
        m = _manifest([
            _url_dep("zlib", "https://example.com/zlib.git"),
            _url_dep("aaa-zlib", "https://example.com/aaa-zlib.git"),
        ])
        deps_dir = tmp_path / "_deps"
        graph = resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        assert len(graph.deps) == 1, (
            f"expected 1 dep after dedup, got {[d.name for d in graph.deps]}"
        )
        canonical = graph.deps[0].name
        assert canonical == "zlib", (
            f"BFS-first canonical must be 'zlib' (declared first), got {canonical!r}. "
            f"Lex-min would pick 'aaa-zlib' — BFS order must win."
        )
        assert "aaa-zlib" in graph.deps[0].aliases, (
            f"'aaa-zlib' must be in aliases: {graph.deps[0].aliases!r}"
        )


# ---------------------------------------------------------------------------
# Test 3: requires rewritten to canonical name
# ---------------------------------------------------------------------------


class TestRequiresRewrittenToCanonical:
    """A third dep that requires an aliased name has its requires rewritten to canonical."""

    def test_requires_rewritten(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"

        # app declares: foo, bar (same content as foo), baz (depends on bar)
        # After dedup: foo (canonical), baz's requires should point to foo not bar
        shared_kdl = 'name "shared"\nkind "library"\nsrc_dir "src"\n'
        baz_kdl = (
            'name "baz"\nkind "library"\nsrc_dir "src"\n'
            'deps {\n'
            '    bar git=(url)"https://example.com/bar.git" ref="main"\n'
            '}\n'
        )

        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/foo.git", "main", "foo", shared_kdl, "sha-foo"
        )
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/bar.git", "main", "bar", shared_kdl, "sha-bar"
        )
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/baz.git", "main", "baz", baz_kdl, "sha-baz"
        )

        env = _make_env(mocked_dir, tmp_path)
        m = _manifest([
            _url_dep("foo", "https://example.com/foo.git"),
            _url_dep("bar", "https://example.com/bar.git"),
            _url_dep("baz", "https://example.com/baz.git"),
        ])
        deps_dir = tmp_path / "_deps"
        graph = resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        names = {d.name for d in graph.deps}
        # foo and bar should be deduped (same content)
        assert "bar" not in names, f"'bar' should be deduped away; got names: {names}"
        assert "foo" in names, f"'foo' should be canonical; got names: {names}"
        assert "baz" in names, f"'baz' should still be present; got names: {names}"

        baz_dep = next(d for d in graph.deps if d.name == "baz")
        # baz's requires should reference 'foo' (canonical) not 'bar' (aliased)
        assert "foo" in baz_dep.requires, (
            f"baz.requires should contain 'foo' after rewrite, got {baz_dep.requires!r}"
        )
        assert "bar" not in baz_dep.requires, (
            f"baz.requires should NOT contain 'bar' after rewrite, got {baz_dep.requires!r}"
        )


# ---------------------------------------------------------------------------
# Test 4: different content → NOT merged
# ---------------------------------------------------------------------------


class TestNoDedupForDifferentContent:
    """Two deps with different content must NOT be merged."""

    def test_two_different_deps_remain_two_nodes(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        # Different milpa.kdl content → different identity hashes.
        kdl_a = 'name "alpha"\nkind "library"\nsrc_dir "src"\n'
        kdl_b = 'name "beta"\nkind "library"\nsrc_dir "src"\n'

        _write_mock_fetch_milpa_kdl(mocked_dir, "https://example.com/alpha.git", "main", "alpha", kdl_a, "sha-a")
        _write_mock_fetch_milpa_kdl(mocked_dir, "https://example.com/beta.git", "main", "beta", kdl_b, "sha-b")

        env = _make_env(mocked_dir, tmp_path)
        m = _manifest([
            _url_dep("alpha", "https://example.com/alpha.git"),
            _url_dep("beta", "https://example.com/beta.git"),
        ])
        deps_dir = tmp_path / "_deps"
        graph = resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        names = {d.name for d in graph.deps}
        assert "alpha" in names and "beta" in names, (
            f"different-content deps must not be merged; got: {names}"
        )
        assert len(graph.deps) == 2, f"expected 2 deps, got {len(graph.deps)}: {names}"

        for dep in graph.deps:
            assert dep.aliases == (), f"dep {dep.name!r} should have no aliases, got {dep.aliases!r}"


# ---------------------------------------------------------------------------
# Test 5: three names, same content → one canonical + two aliases (lex-sorted)
# ---------------------------------------------------------------------------


class TestThreeNamesSameContent:
    """Three deps with identical content → one canonical + two aliases, aliases lex-sorted."""

    def test_three_way_dedup(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"

        # All three share the same milpa.kdl content
        shared_kdl = 'name "shared"\nkind "library"\nsrc_dir "src"\n'
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/foo.git", "main", "foo", shared_kdl, "sha-foo"
        )
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/bar.git", "main", "bar", shared_kdl, "sha-bar"
        )
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/baz.git", "main", "baz", shared_kdl, "sha-baz"
        )

        env = _make_env(mocked_dir, tmp_path)
        # Declared order: foo, bar, baz → BFS canonical = foo
        m = _manifest([
            _url_dep("foo", "https://example.com/foo.git"),
            _url_dep("bar", "https://example.com/bar.git"),
            _url_dep("baz", "https://example.com/baz.git"),
        ])
        deps_dir = tmp_path / "_deps"
        graph = resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        assert len(graph.deps) == 1, f"expected 1 dep after 3-way dedup, got {[d.name for d in graph.deps]}"
        dep = graph.deps[0]
        assert dep.name == "foo", f"canonical should be 'foo' (BFS-first), got {dep.name!r}"
        # aliases must be lex-sorted
        assert dep.aliases == ("bar", "baz"), (
            f"expected aliases=('bar','baz') (lex-sorted), got {dep.aliases!r}"
        )


# ---------------------------------------------------------------------------
# Test 6: workspace dedup — R1-1 regression
#
# resolve_workspace() was missing Phase B content-hash dedup: it had no
# discovery_order tracking, no _dedup_candidates call, and passed aliases_map=None
# to _build_graph.  Result: two workspace members declaring different external
# deps that fetch to byte-identical content emitted 2 separate lockfile deps
# instead of 1 canonical dep + alias.
# ---------------------------------------------------------------------------


class TestWorkspaceDedupSameContent:
    """resolve_workspace() collapses byte-identical external deps from different members."""

    def _make_workspace(
        self,
        tmp_path: Path,
        mocked_dir: Path,
    ) -> "object":
        """Build a minimal LoadedWorkspace with two members each requiring a dep
        that fetches to identical byte content.
        """
        from milpa.manifest import Manifest
        from milpa.workspace import LoadedMember, LoadedWorkspace, WorkspaceManifest

        shared_kdl = 'name "shared"\nkind "library"\nsrc_dir "src"\n'
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/foo.git", "main", "foo", shared_kdl, "sha-foo"
        )
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/bar.git", "main", "bar", shared_kdl, "sha-bar"
        )

        def _manifest_for(name: str, dep_name: str, dep_url: str) -> Manifest:
            return Manifest(
                name=name,
                kind="library",
                src_dir="src",
                deps=[_url_dep(dep_name, dep_url)],
                dev_deps=[],
                overrides=[],
                flags=[],
                self_mirrors=[],
                cas_dir="",
                spec_version=1,
                spec_version_explicit=False,
                attestation_policy=None,
            )

        # Create fake member dirs so compute_content_hash has something to hash.
        member_a_dir = tmp_path / "member-a"
        member_a_dir.mkdir()
        (member_a_dir / "milpa.kdl").write_text(
            'name "pkg-a"\nkind "library"\nsrc_dir "src"\n', encoding="utf-8"
        )
        member_b_dir = tmp_path / "member-b"
        member_b_dir.mkdir()
        (member_b_dir / "milpa.kdl").write_text(
            'name "pkg-b"\nkind "library"\nsrc_dir "src"\n', encoding="utf-8"
        )

        ws_manifest = WorkspaceManifest(members=("member-a", "member-b"), overrides=())
        members = (
            LoadedMember(
                rel_path="member-a",
                abs_dir=member_a_dir,
                manifest=_manifest_for("pkg-a", "foo", "https://example.com/foo.git"),
            ),
            LoadedMember(
                rel_path="member-b",
                abs_dir=member_b_dir,
                manifest=_manifest_for("pkg-b", "bar", "https://example.com/bar.git"),
            ),
        )
        return LoadedWorkspace(
            root_dir=tmp_path,
            workspace_manifest=ws_manifest,
            members=members,
        )

    def test_workspace_external_dedup_single_canonical(self, tmp_path: Path) -> None:
        """Two workspace members → same-content external deps → one canonical node."""
        mocked_dir = tmp_path / "mocked-fetches"
        ws = self._make_workspace(tmp_path, mocked_dir)
        env = _make_env(mocked_dir, tmp_path)

        deps_dir = tmp_path / "_deps"
        graph = resolve_workspace(ws, deps_dir, env, ResolveParams())  # type: ignore[arg-type]

        external = [d for d in graph.deps if d.provenances and d.provenances[0].kind == "git"]
        assert len(external) == 1, (
            f"expected 1 canonical external dep after dedup, got {[d.name for d in external]}"
        )

    def test_workspace_canonical_is_member_a_dep(self, tmp_path: Path) -> None:
        """BFS order: member-a's dep (foo) is declared first → canonical is 'foo'."""
        mocked_dir = tmp_path / "mocked-fetches"
        ws = self._make_workspace(tmp_path, mocked_dir)
        env = _make_env(mocked_dir, tmp_path)

        deps_dir = tmp_path / "_deps"
        graph = resolve_workspace(ws, deps_dir, env, ResolveParams())  # type: ignore[arg-type]

        external = [d for d in graph.deps if d.provenances and d.provenances[0].kind == "git"]
        assert len(external) == 1
        assert external[0].name == "foo", (
            f"canonical should be 'foo' (member-a's dep, declared first), got {external[0].name!r}"
        )
        assert external[0].aliases == ("bar",), (
            f"expected aliases=('bar',), got {external[0].aliases!r}"
        )

    def test_workspace_member_requires_rewritten_to_canonical(self, tmp_path: Path) -> None:
        """pkg-b's requires is rewritten from 'bar' to 'foo' after dedup."""
        mocked_dir = tmp_path / "mocked-fetches"
        ws = self._make_workspace(tmp_path, mocked_dir)
        env = _make_env(mocked_dir, tmp_path)

        deps_dir = tmp_path / "_deps"
        graph = resolve_workspace(ws, deps_dir, env, ResolveParams())  # type: ignore[arg-type]

        pkg_b = next((d for d in graph.deps if d.name == "pkg-b"), None)
        assert pkg_b is not None, "pkg-b must be in graph"
        assert "foo" in pkg_b.requires, (
            f"pkg-b.requires should contain 'foo' (canonical), got {pkg_b.requires!r}"
        )
        assert "bar" not in pkg_b.requires, (
            f"pkg-b.requires should NOT contain 'bar' (aliased), got {pkg_b.requires!r}"
        )


# ---------------------------------------------------------------------------
# Test 7: workspace S4a fixpoint — cross-package flag enables (F1 regression)
#
# When a workspace member has a flag with enables_cross_pkg pointing at a
# dep's flag, and that dep's flag gates a sub-dep behind a `when`, the S4a
# fixpoint must fire in resolve_workspace() so the sub-dep is admitted.
#
# Regression: resolve_workspace() was missing the _s4a_run_fixpoint call.
# ---------------------------------------------------------------------------


class TestWorkspaceCrossPkgEnableFixpoint:
    """resolve_workspace() fires the S4a dep×flag fixpoint for member enables."""

    def _make_workspace(self, tmp_path: Path, mocked_dir: Path) -> "object":
        """Build a workspace where member-a.f1 enables lib-b.g1, which gates lib-c."""
        from milpa.workspace import LoadedMember, LoadedWorkspace, WorkspaceManifest

        # lib-c: a plain library with no deps
        lib_c_kdl = 'name "lib-c"\nkind "library"\n'
        _write_mock_fetch_milpa_kdl(
            mocked_dir,
            "https://example.com/lib-c.git",
            "main",
            "lib-c",
            lib_c_kdl,
            "cccc1111cccc1111cccc1111cccc1111cccc1111",
        )

        # lib-b: has flag g1 (default=false); when g1 is active, requires lib-c
        lib_b_kdl = (
            'name "lib-b"\nkind "library"\n'
            'flags {\n'
            '    g1 default=#false\n'
            '}\n'
            'deps {\n'
            '    when flag="g1" {\n'
            '        lib-c git=(url)"https://example.com/lib-c.git" ref="main"\n'
            '    }\n'
            '}\n'
        )
        _write_mock_fetch_milpa_kdl(
            mocked_dir,
            "https://example.com/lib-b.git",
            "main",
            "lib-b",
            lib_b_kdl,
            "bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111",
        )

        # member-a: has flag f1 (default=true) that enables lib-b.g1 cross-pkg;
        # declares dep on lib-b
        member_a_dir = tmp_path / "member-a"
        member_a_dir.mkdir()

        member_a_manifest = parse_manifest(
            'name "member-a"\nkind "library"\n'
            'flags {\n'
            '    f1 default=#true {\n'
            '        enables {\n'
            '            lib-b { flag "g1" }\n'
            '        }\n'
            '    }\n'
            '}\n'
            'deps {\n'
            '    lib-b git=(url)"https://example.com/lib-b.git" ref="main"\n'
            '}\n'
        )
        (member_a_dir / "milpa.kdl").write_text(
            'name "member-a"\nkind "library"\n'
            'flags {\n'
            '    f1 default=#true {\n'
            '        enables {\n'
            '            lib-b { flag "g1" }\n'
            '        }\n'
            '    }\n'
            '}\n'
            'deps {\n'
            '    lib-b git=(url)"https://example.com/lib-b.git" ref="main"\n'
            '}\n',
            encoding="utf-8",
        )

        ws_manifest = WorkspaceManifest(members=("member-a",), overrides=())
        members = (
            LoadedMember(
                rel_path="member-a",
                abs_dir=member_a_dir,
                manifest=member_a_manifest,
            ),
        )
        return LoadedWorkspace(
            root_dir=tmp_path,
            workspace_manifest=ws_manifest,
            members=members,
        )

    def test_cross_pkg_enable_admits_gated_dep(self, tmp_path: Path) -> None:
        """member-a.f1 (default=true) enables lib-b.g1 → lib-c is admitted."""
        mocked_dir = tmp_path / "mocked-fetches"
        ws = self._make_workspace(tmp_path, mocked_dir)
        env = _make_env(mocked_dir, tmp_path)
        deps_dir = tmp_path / "_deps"

        graph = resolve_workspace(ws, deps_dir, env, ResolveParams())  # type: ignore[arg-type]

        names = {d.name for d in graph.deps}
        assert "lib-b" in names, f"lib-b must be in graph; got {names}"
        assert "lib-c" in names, (
            f"lib-c must be admitted by cross-pkg enable fixpoint; got {names}"
        )

    def test_lib_b_active_flags_contains_g1(self, tmp_path: Path) -> None:
        """lib-b's active_flags must include 'g1' (fired by member-a.f1 enables)."""
        mocked_dir = tmp_path / "mocked-fetches"
        ws = self._make_workspace(tmp_path, mocked_dir)
        env = _make_env(mocked_dir, tmp_path)
        deps_dir = tmp_path / "_deps"

        graph = resolve_workspace(ws, deps_dir, env, ResolveParams())  # type: ignore[arg-type]

        lib_b = next((d for d in graph.deps if d.name == "lib-b"), None)
        assert lib_b is not None, "lib-b must be in graph"
        assert "g1" in lib_b.active_flags, (
            f"lib-b.active_flags must contain 'g1'; got {lib_b.active_flags!r}"
        )

    def test_member_active_flags_not_in_lockfile(self, tmp_path: Path) -> None:
        """member-a's active_flags must NOT appear in the resolved graph (internal state)."""
        mocked_dir = tmp_path / "mocked-fetches"
        ws = self._make_workspace(tmp_path, mocked_dir)
        env = _make_env(mocked_dir, tmp_path)
        deps_dir = tmp_path / "_deps"

        graph = resolve_workspace(ws, deps_dir, env, ResolveParams())  # type: ignore[arg-type]

        member_a = next((d for d in graph.deps if d.name == "member-a"), None)
        assert member_a is not None, "member-a must be in graph"
        assert not member_a.active_flags, (
            f"member-a.active_flags must be empty (internal resolver state, not lockfile-pinnable); "
            f"got {member_a.active_flags!r}"
        )
