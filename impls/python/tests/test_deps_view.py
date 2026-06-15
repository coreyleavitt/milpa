"""B-nimcfg: atomic _deps/ view rebuild and alias symlink tests.

Behaviors under test:
1. A deduped dep with one alias → _deps/<alias> exists and resolves to same
   target as _deps/<canonical>.
2. Two aliases → both _deps/<alias> symlinks exist, pointing to same target.
3. Stale removal: after a resolve that produced {a,b} in _deps/, a re-resolve
   whose graph no longer contains 'b' leaves _deps/b gone.
4. No dedup → behavior unchanged: one _deps/<name> entry, no extra symlinks.

Spec authority: rfc-content-addressed-identity.md Phase B, B-nimcfg slice.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry
from milpa.lockfile import ResolvedDep, ResolvedGraph
from milpa.manifest import Manifest, UrlDep
from milpa.resolver import resolve


# ---------------------------------------------------------------------------
# Helpers (mirrored from test_resolver_dedup.py)
# ---------------------------------------------------------------------------


def _make_env(mocked_dir: Path, tmp_path: Path) -> MilpaEnv:
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)
    inner = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(inner, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


def _manifest(deps: list[object]) -> Manifest:
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


def _write_mock_fetch_milpa_kdl(
    mocked_dir: Path,
    url: str,
    ref: str,
    dep_name: str,
    kdl_body: str,
    sha: str = "aabbcc",
) -> None:
    import re

    def _safe(s: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", s)

    key = f"{_safe(url)}@{_safe(ref)}"
    fetch_dir = mocked_dir / key
    content_dir = fetch_dir / "content"
    content_dir.mkdir(parents=True, exist_ok=True)
    (content_dir / "milpa.kdl").write_text(kdl_body, encoding="utf-8")
    (fetch_dir / "sha").write_text(sha, encoding="utf-8")


_SHARED_KDL = 'name "shared"\nkind "library"\nsrc_dir "src"\n'
_DIFF_KDL_A = 'name "alpha"\nkind "library"\nsrc_dir "src"\n'
_DIFF_KDL_B = 'name "beta"\nkind "library"\nsrc_dir "src"\n'


def _is_symlink(p: Path) -> bool:
    try:
        return stat.S_ISLNK(os.lstat(p).st_mode)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Test 1: deduped dep with one alias → _deps/<alias> symlink exists, same target
# ---------------------------------------------------------------------------


class TestAliasSymlinkCreated:
    """After a dedup resolve, _deps/<alias> symlink exists pointing to same CAS entry."""

    def test_alias_symlink_exists(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/foo.git", "main", "foo", _SHARED_KDL, "sha1"
        )
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/bar.git", "main", "bar", _SHARED_KDL, "sha2"
        )

        env = _make_env(mocked_dir, tmp_path)
        m = _manifest([
            _url_dep("foo", "https://example.com/foo.git"),
            _url_dep("bar", "https://example.com/bar.git"),
        ])
        deps_dir = tmp_path / "_deps"
        resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        # canonical foo must be a symlink (CAS-admitted)
        assert _is_symlink(deps_dir / "foo"), "_deps/foo must be a symlink to the CAS entry"
        # alias bar must also be a symlink
        assert _is_symlink(deps_dir / "bar"), "_deps/bar alias symlink must exist"

    def test_alias_symlink_resolves_to_same_target(self, tmp_path: Path) -> None:
        """_deps/foo and _deps/bar must resolve to the same CAS content."""
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/foo.git", "main", "foo", _SHARED_KDL, "sha1"
        )
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/bar.git", "main", "bar", _SHARED_KDL, "sha2"
        )

        env = _make_env(mocked_dir, tmp_path)
        m = _manifest([
            _url_dep("foo", "https://example.com/foo.git"),
            _url_dep("bar", "https://example.com/bar.git"),
        ])
        deps_dir = tmp_path / "_deps"
        resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        foo_target = (deps_dir / "foo").resolve()
        bar_target = (deps_dir / "bar").resolve()
        assert foo_target == bar_target, (
            f"_deps/foo and _deps/bar must resolve to the same CAS entry; "
            f"got foo→{foo_target}, bar→{bar_target}"
        )

    def test_alias_symlink_has_no_extra_entries(self, tmp_path: Path) -> None:
        """_deps/ has exactly {foo, bar} — no extra stale entries."""
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/foo.git", "main", "foo", _SHARED_KDL, "sha1"
        )
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/bar.git", "main", "bar", _SHARED_KDL, "sha2"
        )

        env = _make_env(mocked_dir, tmp_path)
        m = _manifest([
            _url_dep("foo", "https://example.com/foo.git"),
            _url_dep("bar", "https://example.com/bar.git"),
        ])
        deps_dir = tmp_path / "_deps"
        resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        entries = sorted(e.name for e in deps_dir.iterdir())
        assert entries == ["bar", "foo"], (
            f"_deps/ should contain exactly {{bar, foo}}; got {entries}"
        )


# ---------------------------------------------------------------------------
# Test 2: two aliases → both symlinks, pointing to same target
# ---------------------------------------------------------------------------


class TestTwoAliasSymlinks:
    """Three-way dedup: canonical + 2 aliases, all _deps/ entries present."""

    def test_three_way_dedup_all_symlinks_present(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        for name in ("foo", "bar", "baz"):
            _write_mock_fetch_milpa_kdl(
                mocked_dir, f"https://example.com/{name}.git", "main", name, _SHARED_KDL, f"sha-{name}"
            )

        env = _make_env(mocked_dir, tmp_path)
        m = _manifest([
            _url_dep("foo", "https://example.com/foo.git"),
            _url_dep("bar", "https://example.com/bar.git"),
            _url_dep("baz", "https://example.com/baz.git"),
        ])
        deps_dir = tmp_path / "_deps"
        resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        assert _is_symlink(deps_dir / "foo"), "_deps/foo (canonical) must be a symlink"
        assert _is_symlink(deps_dir / "bar"), "_deps/bar (alias) must be a symlink"
        assert _is_symlink(deps_dir / "baz"), "_deps/baz (alias) must be a symlink"

        foo_t = (deps_dir / "foo").resolve()
        bar_t = (deps_dir / "bar").resolve()
        baz_t = (deps_dir / "baz").resolve()
        assert foo_t == bar_t == baz_t, (
            f"All three must resolve to the same CAS entry; "
            f"foo→{foo_t}, bar→{bar_t}, baz→{baz_t}"
        )


# ---------------------------------------------------------------------------
# Test 3: stale removal — second resolve removes entries no longer in graph
# ---------------------------------------------------------------------------


class TestStaleRemoval:
    """After a second resolve that drops a dep, its _deps/ entry is gone."""

    def test_stale_entry_removed_on_re_resolve(self, tmp_path: Path) -> None:
        """Pre-populate _deps/stale, then resolve without it → _deps/stale gone."""
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/foo.git", "main", "foo", _DIFF_KDL_A, "sha-foo"
        )

        env = _make_env(mocked_dir, tmp_path)
        deps_dir = tmp_path / "_deps"
        deps_dir.mkdir(parents=True, exist_ok=True)

        # Pre-populate a stale entry (real dir, as if from a previous run).
        stale = deps_dir / "stale"
        stale.mkdir()
        (stale / "stale.nimble").write_text('requires "stale"\n')

        m = _manifest([_url_dep("foo", "https://example.com/foo.git")])
        resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        entries = sorted(e.name for e in deps_dir.iterdir())
        assert "stale" not in entries, (
            f"_deps/stale must be removed after re-resolve; got {entries}"
        )
        assert "foo" in entries, f"_deps/foo must still exist; got {entries}"

    def test_stale_symlink_removed_on_re_resolve(self, tmp_path: Path) -> None:
        """Pre-populate a stale _deps/old-alias symlink → gone after re-resolve."""
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/foo.git", "main", "foo", _DIFF_KDL_A, "sha-foo"
        )

        env = _make_env(mocked_dir, tmp_path)
        deps_dir = tmp_path / "_deps"
        deps_dir.mkdir(parents=True, exist_ok=True)

        # Pre-populate a stale symlink (dangling is fine for this test).
        stale_link = deps_dir / "old-alias"
        os.symlink("/nonexistent-target", stale_link)

        m = _manifest([_url_dep("foo", "https://example.com/foo.git")])
        resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        entries = sorted(e.name for e in deps_dir.iterdir())
        assert "old-alias" not in entries, (
            f"stale symlink _deps/old-alias must be removed; got {entries}"
        )
        assert "foo" in entries, f"_deps/foo must still exist; got {entries}"


# ---------------------------------------------------------------------------
# Test 4: no-dedup → unchanged behavior (one entry per dep)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Test R9: local dep symlink is preserved during stale-entry sweep
# ---------------------------------------------------------------------------


class TestLocalDepPreservation:
    """Regression: rebuild_deps_view must NOT sweep local dep symlinks as stale.

    Local deps (LocalProvenanceRecord) have no CAS identity so they are NOT
    in the ``expected`` set.  Before the fix, ``local_names`` was missing and
    rebuild_deps_view deleted them.  This class pins the corrected behaviour.
    """

    def _make_local_dep(self, source_dir: Path, name: str = "mylib") -> "ResolvedDep":
        """Build a minimal ResolvedDep with a LocalProvenanceRecord."""
        from milpa.lockfile import LocalProvenanceRecord, ResolvedDep
        return ResolvedDep(
            name=name,
            identity=None,
            version="0.0.1",
            src_dir="src",
            requires=(),
            provenances=(LocalProvenanceRecord(path=str(source_dir)),),
        )

    def test_local_symlink_survives_stale_sweep(self, tmp_path: Path) -> None:
        """Local dep symlink is preserved; genuinely stale entry is removed."""
        from milpa.lockfile import ResolvedGraph
        from milpa.cas import CAStore
        from milpa.resolver import rebuild_deps_view

        # Set up _deps/
        deps_dir = tmp_path / "_deps"
        deps_dir.mkdir()

        # 1. The local dep source dir (LocalFetcher would normally create this symlink).
        local_src = tmp_path / "mylib-src"
        local_src.mkdir()
        (local_src / "mylib.nim").write_text("# mylib")

        # 2. _deps/mylib → symlink to local_src (as LocalFetcher creates).
        local_link = deps_dir / "mylib"
        local_link.symlink_to(local_src.resolve())

        # 3. A genuinely stale entry from a prior run — should be removed.
        stale = deps_dir / "stale-dep"
        stale.mkdir()
        (stale / "stale.nim").write_text("old")

        # Graph contains only the local dep (no CAS deps).
        local_dep = self._make_local_dep(local_src)
        graph = ResolvedGraph(deps=(local_dep,))

        store = CAStore(tmp_path / ".cas")
        rebuild_deps_view(graph, deps_dir, store)

        # LOCAL symlink must survive.
        assert _is_symlink(local_link), (
            "_deps/mylib (local dep symlink) must NOT be swept by rebuild_deps_view"
        )
        assert local_link.resolve() == local_src.resolve(), (
            "_deps/mylib must still point to the local source dir"
        )

        # STALE entry must be removed.
        assert not stale.exists(), (
            "_deps/stale-dep must be removed as a stale entry"
        )

    def test_local_symlink_survives_alongside_cas_deps(self, tmp_path: Path) -> None:
        """Local symlink preserved when CAS dep entries also exist in the graph."""
        from milpa.lockfile import ResolvedGraph, GitProvenanceRecord
        from milpa.cas import CAStore
        from milpa.resolver import rebuild_deps_view

        cas_root = tmp_path / ".cas"
        store = CAStore(cas_root)

        # Admit a small CAS entry for the git dep.
        from milpa.identity import compute_content_hash
        seed = tmp_path / "seed"
        seed.mkdir()
        (seed / "foo.nim").write_text("# foo")
        identity = compute_content_hash(seed)
        store.admit(seed, identity)

        deps_dir = tmp_path / "_deps"
        deps_dir.mkdir()

        # Local dep symlink pre-created by LocalFetcher.
        local_src = tmp_path / "local-src"
        local_src.mkdir()
        (local_src / "l.nim").write_text("# local")
        local_link = deps_dir / "locallib"
        local_link.symlink_to(local_src.resolve())

        # Stale entry.
        stale = deps_dir / "old-dep"
        stale.mkdir()

        from milpa.lockfile import LocalProvenanceRecord, ResolvedDep
        local_dep = ResolvedDep(
            name="locallib",
            identity=None,
            version="0.0.1",
            src_dir="src",
            requires=(),
            provenances=(LocalProvenanceRecord(path=str(local_src)),),
        )
        git_dep = ResolvedDep(
            name="foo",
            identity=identity,
            version="0.0.1",
            src_dir="src",
            requires=(),
            provenances=(GitProvenanceRecord(url="https://e/foo.git"),),
        )
        graph = ResolvedGraph(deps=(local_dep, git_dep))

        rebuild_deps_view(graph, deps_dir, store)

        # Local symlink preserved.
        assert _is_symlink(local_link), "_deps/locallib local symlink must survive"
        assert local_link.resolve() == local_src.resolve()

        # CAS symlink created/refreshed.
        assert _is_symlink(deps_dir / "foo"), "_deps/foo CAS symlink must be created"

        # Stale gone.
        assert not stale.exists(), "_deps/old-dep must be removed"


# ---------------------------------------------------------------------------
# Test 4: no-dedup → unchanged behavior (one entry per dep)
# ---------------------------------------------------------------------------


class TestNoDedupUnchanged:
    """Two deps with different content: _deps/ has exactly two symlinks, no extras."""

    def test_two_different_deps_two_symlinks(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/alpha.git", "main", "alpha", _DIFF_KDL_A, "sha-a"
        )
        _write_mock_fetch_milpa_kdl(
            mocked_dir, "https://example.com/beta.git", "main", "beta", _DIFF_KDL_B, "sha-b"
        )

        env = _make_env(mocked_dir, tmp_path)
        m = _manifest([
            _url_dep("alpha", "https://example.com/alpha.git"),
            _url_dep("beta", "https://example.com/beta.git"),
        ])
        deps_dir = tmp_path / "_deps"
        resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        entries = sorted(e.name for e in deps_dir.iterdir())
        assert entries == ["alpha", "beta"], (
            f"_deps/ should contain exactly {{alpha, beta}}; got {entries}"
        )

        alpha_t = (deps_dir / "alpha").resolve()
        beta_t = (deps_dir / "beta").resolve()
        assert alpha_t != beta_t, "different-content deps must not share a CAS target"
