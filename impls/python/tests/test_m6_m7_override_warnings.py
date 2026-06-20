"""M6 + M7: override advisory warnings.

M6: an override naming a dep absent from the resolved graph emits a warning
    (typo guard). Advisory only — not a hard error.

M7: a member= override in a single-package (non-workspace) manifest emits a
    warning (member overrides require a workspace context). Advisory only.
"""

from __future__ import annotations

import warnings
from pathlib import Path
import pytest


# ---------------------------------------------------------------------------
# Helpers: build resolver environments
# ---------------------------------------------------------------------------

def _build_mocked_env(tmp_path: Path, url: str, kdl: str, sha: str):
    """Build a MilpaEnv with a single mocked URL dep."""
    from milpa.context import MilpaEnv
    from milpa.fetchers.mocked import mocked_registry, url_key
    from milpa.fetchers.cas_admitting import CasAdmittingFetcher
    from milpa.cas import CAStore

    mocked_dir = tmp_path / "mocked-fetches"
    key = url_key(url, "main")
    d = mocked_dir / key
    (d / "content").mkdir(parents=True)
    (d / "content" / "milpa.kdl").write_text(kdl, encoding="utf-8")
    (d / "sha").write_text(sha, encoding="utf-8")

    store = CAStore(tmp_path / "cas")
    reg = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(reg, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


# ---------------------------------------------------------------------------
# M6: override naming an absent dep emits a warning
# ---------------------------------------------------------------------------

class TestM6DeadOverrideWarning:
    """M6: overrides whose name is absent from the resolved graph emit a warning."""

    def test_dead_override_emits_warning(self, tmp_path: Path) -> None:
        """An override for 'typo-dep' (not in graph) must emit a UserWarning."""
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        lib_a_kdl = 'name "lib-a"\nkind "library"\n'
        env = _build_mocked_env(
            tmp_path,
            "https://example.com/lib-a.git",
            lib_a_kdl,
            "aaaa" * 10,
        )

        # Override names 'typo-dep' which is NOT in the deps list
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '}\n'
            'overrides {\n'
            '    pkg "typo-dep" git=(url)"https://example.com/fork.git" ref="main"\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            resolve(manifest, deps_dir, env, params)

        user_warnings = [str(x.message) for x in w if issubclass(x.category, UserWarning)]
        dead_warnings = [m for m in user_warnings if "typo-dep" in m]
        assert dead_warnings, (
            f"expected a UserWarning mentioning 'typo-dep'; got warnings: {user_warnings}"
        )

    def test_dead_override_warning_mentions_check_typos(self, tmp_path: Path) -> None:
        """The dead-override warning must mention checking for typos."""
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        lib_a_kdl = 'name "lib-a"\nkind "library"\n'
        env = _build_mocked_env(
            tmp_path,
            "https://example.com/lib-a.git",
            lib_a_kdl,
            "aaaa" * 10,
        )

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '}\n'
            'overrides {\n'
            '    pkg "no-such-dep" git=(url)"https://example.com/fork.git" ref="main"\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            resolve(manifest, deps_dir, env, params)

        user_warnings = [str(x.message) for x in w if issubclass(x.category, UserWarning)]
        relevant = [m for m in user_warnings if "no-such-dep" in m]
        assert relevant, f"no warning mentioning 'no-such-dep'; all warnings: {user_warnings}"
        assert any("typo" in m.lower() for m in relevant), (
            f"warning must mention typos; got: {relevant}"
        )

    def test_present_override_no_dead_warning(self, tmp_path: Path) -> None:
        """An override for a dep that IS in the graph does NOT emit a dead-override warning."""
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        lib_a_kdl = 'name "lib-a"\nkind "library"\n'
        lib_fork_kdl = 'name "lib-a"\nkind "library"\n'
        env = _build_mocked_env(
            tmp_path,
            "https://example.com/lib-a-fork.git",
            lib_fork_kdl,
            "ffff" * 10,
        )

        # Override routes 'lib-a' to a fork → lib-a IS in the graph
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '}\n'
            'overrides {\n'
            '    pkg "lib-a" git=(url)"https://example.com/lib-a-fork.git" ref="main"\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            resolve(manifest, deps_dir, env, params)

        user_warnings = [str(x.message) for x in w if issubclass(x.category, UserWarning)]
        dead_warnings = [m for m in user_warnings if "typo" in m.lower()]
        assert not dead_warnings, (
            f"no dead-override warning expected when override targets a resolved dep; "
            f"got: {dead_warnings}"
        )


# ---------------------------------------------------------------------------
# M7: member= override in non-workspace manifest emits a warning
# ---------------------------------------------------------------------------

class TestM7MemberOverrideNonWorkspace:
    """M7: member= overrides in single-package manifests emit a warning."""

    def test_member_override_emits_warning(self, tmp_path: Path) -> None:
        """A member= override in a single-package manifest emits a UserWarning.

        The warning fires BEFORE the BFS/solver — even if resolution later fails
        because the member override caused an unsatisfiable dep (SOLVE-CONFLICT).
        We catch the warning regardless of whether resolve raises.
        """
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        lib_a_kdl = 'name "lib-a"\nkind "library"\n'
        env = _build_mocked_env(
            tmp_path,
            "https://example.com/lib-a.git",
            lib_a_kdl,
            "aaaa" * 10,
        )

        # member= override in a non-workspace manifest
        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '}\n'
            'overrides {\n'
            '    pkg "lib-a" {\n'
            '        member "lib-a"\n'
            '    }\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try:
                resolve(manifest, deps_dir, env, params)
            except Exception:
                pass  # warning fires before BFS; resolution may fail

        user_warnings = [str(x.message) for x in w if issubclass(x.category, UserWarning)]
        member_warnings = [m for m in user_warnings if "member" in m.lower()]
        assert member_warnings, (
            f"expected a UserWarning mentioning member override; "
            f"got warnings: {user_warnings}"
        )

    def test_member_override_warning_mentions_workspace(self, tmp_path: Path) -> None:
        """The member-override warning must mention workspace context."""
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        lib_a_kdl = 'name "lib-a"\nkind "library"\n'
        env = _build_mocked_env(
            tmp_path,
            "https://example.com/lib-a.git",
            lib_a_kdl,
            "aaaa" * 10,
        )

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '}\n'
            'overrides {\n'
            '    pkg "lib-a" {\n'
            '        member "lib-a"\n'
            '    }\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try:
                resolve(manifest, deps_dir, env, params)
            except Exception:
                pass  # warning fires before BFS; resolution may fail

        user_warnings = [str(x.message) for x in w if issubclass(x.category, UserWarning)]
        relevant = [m for m in user_warnings if "member" in m.lower()]
        assert any("workspace" in m.lower() for m in relevant), (
            f"member-override warning must mention workspace; got: {relevant}"
        )

    def test_no_member_override_no_warning(self, tmp_path: Path) -> None:
        """A git= override in a single-package manifest does NOT emit an M7 warning."""
        from milpa.context import ResolveParams
        from milpa.manifest import parse_manifest
        from milpa.resolver import resolve

        lib_a_kdl = 'name "lib-a"\nkind "library"\n'
        env = _build_mocked_env(
            tmp_path,
            "https://example.com/lib-a-fork.git",
            lib_a_kdl,
            "ffff" * 10,
        )

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '}\n'
            'overrides {\n'
            '    pkg "lib-a" git=(url)"https://example.com/lib-a-fork.git" ref="main"\n'
            '}\n'
        )
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"
        params = ResolveParams()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            resolve(manifest, deps_dir, env, params)

        user_warnings = [str(x.message) for x in w if issubclass(x.category, UserWarning)]
        member_warnings = [m for m in user_warnings if "member override" in m.lower()]
        assert not member_warnings, (
            f"no M7 warning expected for a git= override; got: {member_warnings}"
        )
