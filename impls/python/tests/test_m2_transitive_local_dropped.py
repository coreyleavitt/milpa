"""M2: transitive local= deps from non-root manifests must NOT reach the BFS.

Diagnosis (REAL): _collect_transitive_deps returns list(m.deps) including LocalDep;
_enqueue_dep previously appended ("local", dep) for LocalDep, which would let an
attacker-controlled transitive manifest's local= path get symlinked into _deps/.
The fix: _enqueue_dep now drops LocalDep (and TarballDep) with pass — only root-
declared local/tarball deps enter via direct bfs_queue.append() in the seeding loop.

This mirrors:
  - edge_sources.py:333 (Local/Tarball/Member out of scope for transitive EdgeSet)
  - Rust's edgeset_to_extracted (Dep::Local | Dep::Tarball | Dep::Member => {})
"""

from __future__ import annotations

from pathlib import Path
import pytest


def _build_env_with_transitive_local(tmp_path: Path):
    """Build a resolver env where lib-a's manifest declares a local= dep (lib-bad).

    lib-a is a URL dep (transitive).  Its milpa.kdl declares a local= dep
    at '../../../etc' — an arbitrary path that should NEVER be admitted.
    The test asserts that 'lib-bad' does NOT appear in the resolved graph.
    """
    from milpa.context import MilpaEnv, ResolveParams
    from milpa.cas import CAStore

    # lib-a milpa.kdl: declares a local= dep (transitive local — security risk)
    lib_a_kdl = (
        'name "lib-a"\nkind "library"\n'
        'deps {\n'
        '    lib-bad local="../../../evil-path"\n'
        '}\n'
    )
    # lib-a also has a legit URL dep — to confirm the normal BFS still works
    lib_a_with_url_kdl = (
        'name "lib-a"\nkind "library"\n'
        'deps {\n'
        '    lib-bad local="../../../evil-path"\n'
        '    lib-good git=(url)"https://example.com/lib-good.git" ref="main"\n'
        '}\n'
    )
    lib_good_kdl = 'name "lib-good"\nkind "library"\n'

    mocked_dir = tmp_path / "mocked-fetches"

    def _make_mock(url: str, ref: str, kdl: str, sha: str) -> None:
        from milpa.fetchers.mocked import url_key
        key = url_key(url, ref)
        d = mocked_dir / key
        (d / "content").mkdir(parents=True)
        (d / "content" / "milpa.kdl").write_text(kdl, encoding="utf-8")
        (d / "sha").write_text(sha, encoding="utf-8")

    _make_mock("https://example.com/lib-a.git", "main", lib_a_with_url_kdl, "aaaa" * 10)
    _make_mock("https://example.com/lib-good.git", "main", lib_good_kdl, "gggg" * 10)

    from milpa.fetchers.mocked import mocked_registry
    from milpa.fetchers.cas_admitting import CasAdmittingFetcher
    store = CAStore(tmp_path / "cas")
    reg = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(reg, store)
    env = MilpaEnv(fetcher=fetcher, index=None, store=store)
    return env


class TestTransitiveLocalDropped:
    """Transitive local= deps from attacker-controlled manifests are silently dropped."""

    def test_transitive_local_not_admitted(self, tmp_path: Path) -> None:
        """lib-a's local= dep 'lib-bad' must NOT appear in the resolved graph."""
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        env = _build_env_with_transitive_local(tmp_path)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        graph = resolve(manifest, deps_dir, env, params)
        dep_names = {d.name for d in graph.deps}

        # lib-bad must NOT be admitted (it's a transitive local= — security gate)
        assert "lib-bad" not in dep_names, (
            f"transitive local= dep 'lib-bad' must not enter the graph; "
            f"resolved deps: {dep_names}"
        )

    def test_legit_url_dep_still_admitted(self, tmp_path: Path) -> None:
        """Normal URL transitives from lib-a are still admitted (gate is local-only)."""
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        env = _build_env_with_transitive_local(tmp_path)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        graph = resolve(manifest, deps_dir, env, params)
        dep_names = {d.name for d in graph.deps}

        # lib-good IS a URL dep and must still be admitted
        assert "lib-a" in dep_names
        assert "lib-good" in dep_names, (
            f"transitive URL dep 'lib-good' should still be admitted; "
            f"resolved deps: {dep_names}"
        )

    def test_root_local_dep_still_admitted(self, tmp_path: Path) -> None:
        """Root-declared local= deps are still admitted (only transitive ones are dropped)."""
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve
        from milpa.fetchers.local import LocalProvenance
        import shutil

        # Create a real local dep directory
        local_dir = tmp_path / "mylocal"
        local_dir.mkdir()
        (local_dir / "milpa.kdl").write_text(
            'name "mylocal"\nkind "library"\n', encoding="utf-8"
        )

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            f'    mylocal local="{local_dir}"\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)

        from milpa.context import MilpaEnv
        from milpa.fetchers.mocked import mocked_registry
        from milpa.fetchers.cas_admitting import CasAdmittingFetcher
        from milpa.fetchers.local import LocalFetcher
        from milpa.fetchers.types import FetcherRegistry
        from milpa.cas import CAStore

        store = CAStore(tmp_path / "cas")
        # Use a registry that supports local fetching
        from milpa.fetchers.types import FetcherRegistry
        reg = FetcherRegistry()
        reg.register(LocalFetcher())
        fetcher = CasAdmittingFetcher(reg, store)
        env = MilpaEnv(fetcher=fetcher, index=None, store=store)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams(manifest_dir=tmp_path)

        graph = resolve(manifest, deps_dir, env, params)
        dep_names = {d.name for d in graph.deps}

        # Root local dep must still be admitted
        assert "mylocal" in dep_names, (
            f"root local= dep 'mylocal' must be admitted; resolved: {dep_names}"
        )
