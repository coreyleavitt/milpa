"""M1: cross-package enables security gate.

A cross-pkg enable may only affect deps ALREADY in the graph (already fetched).
A transitive dep's enables targeting a dep NOT in the root's dependency closure
must NOT force-admit that dep as a new fetch.

This is a passive security gate: the existing fixpoint code already does
`if target_manifest is None: continue` — the gate is explicit + tested here.

Reference: _s4a_run_fixpoint step 3 comment (M1 security gate).
"""

from __future__ import annotations

from pathlib import Path
import pytest


def _build_env(tmp_path: Path, mocks: list[tuple[str, str, str, str]]):
    """Build a MilpaEnv with multiple mocked URL deps.

    mocks: list of (url, ref, kdl_text, sha_hex)
    """
    from milpa.context import MilpaEnv
    from milpa.fetchers.mocked import mocked_registry, url_key
    from milpa.fetchers.cas_admitting import CasAdmittingFetcher
    from milpa.cas import CAStore

    mocked_dir = tmp_path / "mocked-fetches"
    for url, ref, kdl, sha in mocks:
        key = url_key(url, ref)
        d = mocked_dir / key
        (d / "content").mkdir(parents=True)
        (d / "content" / "milpa.kdl").write_text(kdl, encoding="utf-8")
        (d / "sha").write_text(sha, encoding="utf-8")

    store = CAStore(tmp_path / "cas")
    reg = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(reg, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


class TestM1CrossPkgEnablesGate:
    """Cross-pkg enables from any source cannot force-admit deps not already in the graph."""

    def test_transitive_enable_for_unrelated_dep_does_not_admit_it(
        self, tmp_path: Path
    ) -> None:
        """lib-b (transitive) declares cross-pkg enables on 'evil' (not in root's closure).

        evil is NOT in the root's dep declaration and NOT reachable as a transitive dep
        of lib-a or lib-b via normal BFS.  lib-b's enables_cross_pkg for 'evil' must NOT
        force-admit 'evil' into the resolved graph.
        """
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        # lib-a: root dep. Has lib-b as a transitive dep.
        lib_a_kdl = (
            'name "lib-a"\nkind "library"\n'
            'deps {\n'
            '    lib-b git=(url)"https://example.com/lib-b.git" ref="main"\n'
            '}\n'
        )
        # lib-b: transitive dep. Declares a cross-pkg enable targeting 'evil'.
        # 'evil' is NOT in any dep's declared deps — it would be brand-new if admitted.
        lib_b_kdl = (
            'name "lib-b"\nkind "library"\n'
            'flags {\n'
            '    feat default=#true {\n'
            '        enables {\n'
            '            evil { flag "g" }\n'
            '        }\n'
            '    }\n'
            '}\n'
        )
        # 'evil' is not declared anywhere — it should NEVER be fetched.

        env = _build_env(
            tmp_path,
            [
                ("https://example.com/lib-a.git", "main", lib_a_kdl, "aaaa" * 10),
                ("https://example.com/lib-b.git", "main", lib_b_kdl, "bbbb" * 10),
            ],
        )

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        # Must NOT raise (the unknown 'evil' dep target is silently dropped).
        graph = resolve(manifest, deps_dir, env, params)
        dep_names = {d.name for d in graph.deps}

        assert "evil" not in dep_names, (
            f"'evil' must NOT be admitted via transitive cross-pkg enables; "
            f"resolved: {dep_names}"
        )
        # Normal deps ARE still admitted
        assert "lib-a" in dep_names
        assert "lib-b" in dep_names

    def test_root_cross_pkg_enable_on_existing_dep_still_works(
        self, tmp_path: Path
    ) -> None:
        """Root-requested flag on lib-a can cross-pkg enable lib-b.flag (lib-b already in graph).

        This is the standard S4a use case (fixture-190 equivalent).  Verifying the
        M1 gate does NOT block legitimate root-authority cross-pkg enables.
        """
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        lib_a_kdl = (
            'name "lib-a"\nkind "library"\n'
            'flags {\n'
            '    feat default=#false {\n'
            '        enables {\n'
            '            lib-b { flag "extra" }\n'
            '        }\n'
            '    }\n'
            '}\n'
            'deps {\n'
            '    lib-b git=(url)"https://example.com/lib-b.git" ref="main"\n'
            '}\n'
        )
        lib_b_kdl = (
            'name "lib-b"\nkind "library"\n'
            'flags {\n'
            '    extra default=#false\n'
            '}\n'
            'deps {\n'
            '    when flag="extra" {\n'
            '        lib-c git=(url)"https://example.com/lib-c.git" ref="main"\n'
            '    }\n'
            '}\n'
        )
        lib_c_kdl = 'name "lib-c"\nkind "library"\n'

        env = _build_env(
            tmp_path,
            [
                ("https://example.com/lib-a.git", "main", lib_a_kdl, "aaaa" * 10),
                ("https://example.com/lib-b.git", "main", lib_b_kdl, "bbbb" * 10),
                ("https://example.com/lib-c.git", "main", lib_c_kdl, "cccc" * 10),
            ],
        )

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main" {\n'
            '        flag "feat"\n'
            '    }\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        # Standard S4a multi-hop: lib-c must be admitted.
        graph = resolve(manifest, deps_dir, env, params)
        dep_names = {d.name for d in graph.deps}

        assert "lib-c" in dep_names, (
            f"root cross-pkg enable must still work; expected lib-c in {dep_names}"
        )
