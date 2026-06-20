"""S5 (RFC #23 §4 + §7): active_flags lockfile authority.

Coverage:
  1. Resolver populates ResolvedDep.active_flags from dep_active_flags (sorted lex).
     (a) single active flag (default=#true) → appears in ResolvedDep.active_flags
     (b) multiple active flags → lexicographically sorted
     (c) no active flags → empty tuple (field omitted from lockfile)

  2. Lockfile round-trip: active_flags written and read back identically.
     (a) lockfile emission includes active_flags line when non-empty
     (b) lockfile parse returns the same active_flags tuple

  3. Dep with no consumer flag requests but default=#true flags → active_flags populated.

RFC #23 §4 normative: active_flags is the authoritative unified per-dep set,
lexicographically sorted in both impls.
"""

from __future__ import annotations

from pathlib import Path
import pytest


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _make_mock_env_for_s5(tmp_path: Path, dep_name: str, dep_kdl: str, sha: str):
    """Build a MilpaEnv with a single mocked dep."""
    from milpa.fetchers.mocked import mocked_registry, url_key
    from milpa.fetchers.cas_admitting import CasAdmittingFetcher
    from milpa.cas import CAStore
    from milpa.context import MilpaEnv

    url = f"https://example.com/{dep_name}.git"
    ref = "main"
    key = url_key(url, ref)
    mocked_dir = tmp_path / "mocked-fetches"
    d = mocked_dir / key
    (d / "content").mkdir(parents=True)
    (d / "content" / "milpa.kdl").write_text(dep_kdl, encoding="utf-8")
    (d / "sha").write_text(sha, encoding="utf-8")

    store = CAStore(tmp_path / "cas")
    reg = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(reg, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store), url, ref


# ---------------------------------------------------------------------------
# 1a. Single active flag via default=#true
# ---------------------------------------------------------------------------

class TestResolvedDepActiveFlags:
    """Resolver populates ResolvedDep.active_flags from dep_active_flags."""

    def test_single_active_flag_in_resolved_dep(self, tmp_path: Path) -> None:
        """Dep with openssl default=#true → active_flags = ("openssl",) on ResolvedDep."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams

        dep_kdl = """
name "lib-tls"
kind "library"
flags {
    openssl default=#true {
        defines "ssl" "useOpenSSL"
    }
}
"""
        env, url, ref = _make_mock_env_for_s5(tmp_path, "lib-tls", dep_kdl, "aa110000" * 5)
        root_kdl = f'name "myapp"\nkind "application"\ndeps {{\n    lib-tls git=(url)"{url}" ref="{ref}"\n}}\n'
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        graph = resolve(manifest, deps_dir, env, ResolveParams())
        lib_tls = next(d for d in graph.deps if d.name == "lib-tls")
        assert lib_tls.active_flags == ("openssl",)

    def test_multiple_active_flags_sorted_lexicographically(self, tmp_path: Path) -> None:
        """Multiple default=#true flags → active_flags is lex-sorted."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams

        dep_kdl = """
name "lib-tls"
kind "library"
flags {
    zstd default=#true
    aarch64 default=#true
    mbedtls default=#true
}
"""
        env, url, ref = _make_mock_env_for_s5(tmp_path, "lib-tls", dep_kdl, "aa220000" * 5)
        root_kdl = f'name "myapp"\nkind "application"\ndeps {{\n    lib-tls git=(url)"{url}" ref="{ref}"\n}}\n'
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        graph = resolve(manifest, deps_dir, env, ResolveParams())
        lib_tls = next(d for d in graph.deps if d.name == "lib-tls")
        # Must be lexicographically sorted: aarch64 < mbedtls < zstd
        assert lib_tls.active_flags == ("aarch64", "mbedtls", "zstd")

    def test_no_active_flags_empty_tuple(self, tmp_path: Path) -> None:
        """Dep with all flags default=#false → active_flags is empty tuple."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams

        dep_kdl = """
name "lib-tls"
kind "library"
flags {
    openssl default=#false
    bearssl default=#false
}
"""
        env, url, ref = _make_mock_env_for_s5(tmp_path, "lib-tls", dep_kdl, "aa330000" * 5)
        root_kdl = f'name "myapp"\nkind "application"\ndeps {{\n    lib-tls git=(url)"{url}" ref="{ref}"\n}}\n'
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        graph = resolve(manifest, deps_dir, env, ResolveParams())
        lib_tls = next(d for d in graph.deps if d.name == "lib-tls")
        assert lib_tls.active_flags == ()

    def test_active_flag_via_edge_request(self, tmp_path: Path) -> None:
        """Consumer requests a flag that is default=#false → active_flags includes it."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams

        dep_kdl = """
name "lib-tls"
kind "library"
flags {
    openssl default=#false
}
"""
        env, url, ref = _make_mock_env_for_s5(tmp_path, "lib-tls", dep_kdl, "aa440000" * 5)
        root_kdl = (
            f'name "myapp"\nkind "application"\ndeps {{\n'
            f'    lib-tls git=(url)"{url}" ref="{ref}" {{\n'
            f'        flag "openssl"\n'
            f'    }}\n}}\n'
        )
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        graph = resolve(manifest, deps_dir, env, ResolveParams())
        lib_tls = next(d for d in graph.deps if d.name == "lib-tls")
        assert "openssl" in lib_tls.active_flags

    def test_no_flags_declared_active_flags_empty(self, tmp_path: Path) -> None:
        """Dep with no flags block → active_flags is empty tuple."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams

        dep_kdl = """
name "lib-base"
kind "library"
"""
        env, url, ref = _make_mock_env_for_s5(tmp_path, "lib-base", dep_kdl, "aa550000" * 5)
        root_kdl = f'name "myapp"\nkind "application"\ndeps {{\n    lib-base git=(url)"{url}" ref="{ref}"\n}}\n'
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        graph = resolve(manifest, deps_dir, env, ResolveParams())
        lib_base = next(d for d in graph.deps if d.name == "lib-base")
        assert lib_base.active_flags == ()


# ---------------------------------------------------------------------------
# 2. Lockfile round-trip
# ---------------------------------------------------------------------------

class TestActiveFlagsLockfileRoundTrip:
    """Lockfile emission and parse are consistent for active_flags."""

    def test_active_flags_emitted_in_lockfile(self, tmp_path: Path) -> None:
        """Active flags appear in the lockfile text as 'active_flags ...'."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams
        from milpa.lockfile import format_lockfile, from_graph

        dep_kdl = """
name "lib-tls"
kind "library"
flags {
    openssl default=#true {
        defines "ssl" "useOpenSSL"
    }
}
"""
        env, url, ref = _make_mock_env_for_s5(tmp_path, "lib-tls", dep_kdl, "bb110000" * 5)
        root_kdl = f'name "myapp"\nkind "application"\ndeps {{\n    lib-tls git=(url)"{url}" ref="{ref}"\n}}\n'
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        graph = resolve(manifest, deps_dir, env, ResolveParams())
        lockfile = from_graph(graph, strategy="maxver")
        text = format_lockfile(lockfile)
        assert 'active_flags "openssl"' in text

    def test_empty_active_flags_omitted_from_lockfile(self, tmp_path: Path) -> None:
        """Dep with no active flags → 'active_flags' line NOT present in lockfile."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams
        from milpa.lockfile import format_lockfile, from_graph

        dep_kdl = """
name "lib-base"
kind "library"
"""
        env, url, ref = _make_mock_env_for_s5(tmp_path, "lib-base", dep_kdl, "bb220000" * 5)
        root_kdl = f'name "myapp"\nkind "application"\ndeps {{\n    lib-base git=(url)"{url}" ref="{ref}"\n}}\n'
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        graph = resolve(manifest, deps_dir, env, ResolveParams())
        lockfile = from_graph(graph, strategy="maxver")
        text = format_lockfile(lockfile)
        assert "active_flags" not in text

    def test_active_flags_parse_round_trip(self, tmp_path: Path) -> None:
        """Lockfile parse recovers the same active_flags tuple from emission."""
        from milpa.resolver import resolve
        from milpa.manifest import parse_manifest
        from milpa.context import ResolveParams
        from milpa.lockfile import format_lockfile, parse_lockfile, from_graph

        dep_kdl = """
name "lib-tls"
kind "library"
flags {
    openssl default=#true
    bearssl default=#true
}
"""
        env, url, ref = _make_mock_env_for_s5(tmp_path, "lib-tls", dep_kdl, "bb330000" * 5)
        root_kdl = f'name "myapp"\nkind "application"\ndeps {{\n    lib-tls git=(url)"{url}" ref="{ref}"\n}}\n'
        manifest = parse_manifest(root_kdl)
        deps_dir = tmp_path / "_deps"

        graph = resolve(manifest, deps_dir, env, ResolveParams())
        lockfile = from_graph(graph, strategy="maxver")
        text = format_lockfile(lockfile)
        parsed = parse_lockfile(text)
        dep = next(d for d in parsed.deps if d.name == "lib-tls")
        # Both flags active; lex-sorted: bearssl < openssl
        assert dep.active_flags == ("bearssl", "openssl")
