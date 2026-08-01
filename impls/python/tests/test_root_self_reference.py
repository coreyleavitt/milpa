"""§14 "root satisfies its own name" — standalone-root self-satisfaction.

A standalone package is a workspace-of-one (spec/resolver-semantics.md §14,
the non-workspace analog of §11.5's workspace-member self-registration).
When a transitive dep's own manifest requires the resolving root's own
declared name, the ROOT ITSELF satisfies that reference — never a second,
separately-fetched copy.

Concrete motivator: a real project ("softlink") needed an
``overrides { pkg "softlink" local="." }`` workaround because a transitive
test-only dep (``proptest``) requires "softlink" — resolving as a SECOND,
distinct "softlink" fetched into ``_deps/`` alongside the tree under build.

Spec authority: spec/resolver-semantics.md §14.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import RES_ROOT_SELF_VERSION_CONSTRAINT, MilpaError
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry
from milpa.lockfile import RootProvenanceRecord
from milpa.manifest import Manifest, UrlDep
from milpa.resolver import resolve
from milpa.version import Version


# ---------------------------------------------------------------------------
# Helpers (mirror tests/test_resolver_dedup.py)
# ---------------------------------------------------------------------------


def _make_env(mocked_dir: Path, tmp_path: Path) -> MilpaEnv:
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)
    inner = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(inner, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


def _url_dep(name: str, url: str, ref: str = "main") -> UrlDep:
    return UrlDep(name=name, git=url, ref=ref, mirrors=[], predicates=[], flag_requests=[])


def _write_mock_fetch_milpa_kdl(
    mocked_dir: Path,
    url: str,
    ref: str,
    kdl_body: str,
    sha: str = "aabbcc",
) -> None:
    def _safe(s: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", s)

    key = f"{_safe(url)}@{_safe(ref)}"
    fetch_dir = mocked_dir / key
    content_dir = fetch_dir / "content"
    content_dir.mkdir(parents=True, exist_ok=True)
    (content_dir / "milpa.kdl").write_text(kdl_body, encoding="utf-8")
    (fetch_dir / "sha").write_text(sha, encoding="utf-8")


def _root_manifest(name: str, version: "Version | None", deps: list) -> Manifest:
    return Manifest(
        name=name,
        kind="application",
        src_dir="",
        version=version,
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


# ---------------------------------------------------------------------------
# Test 1: a transitive dep requiring the root's own name resolves to the root
# ---------------------------------------------------------------------------


class TestTransitiveRequiresRootName:
    def test_resolves_to_one_root_entry(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(
            mocked_dir,
            "https://example.com/dep-d.git",
            "main",
            'name "dep-d"\nkind "library"\nsrc_dir "src"\ndeps {\n  foo\n}\n',
            "sha-d",
        )
        env = _make_env(mocked_dir, tmp_path)
        m = _root_manifest("foo", Version(1, 0, 0), [_url_dep("dep-d", "https://example.com/dep-d.git")])
        deps_dir = tmp_path / "_deps"
        graph = resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        foo_deps = [d for d in graph.deps if d.name == "foo"]
        assert len(foo_deps) == 1, (
            f"expected exactly one 'foo' in the resolved graph, got "
            f"{[d.name for d in graph.deps]}"
        )
        foo = foo_deps[0]
        assert len(foo.provenances) == 1
        assert isinstance(foo.provenances[0], RootProvenanceRecord), (
            f"'foo' must be the ROOT (RootProvenanceRecord), not a fetched "
            f"dep — got {foo.provenances[0]!r}"
        )
        assert foo.provenances[0].name == "foo"
        # A real fetched dep ("dep-d") is still present, untouched.
        dep_d = next((d for d in graph.deps if d.name == "dep-d"), None)
        assert dep_d is not None
        assert "foo" in dep_d.requires

    def test_no_second_foo_fetched_into_deps_dir(self, tmp_path: Path) -> None:
        """The root's own name never triggers a second fetch (no _deps/foo tree)."""
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(
            mocked_dir,
            "https://example.com/dep-d.git",
            "main",
            'name "dep-d"\nkind "library"\nsrc_dir "src"\ndeps {\n  foo\n}\n',
            "sha-d",
        )
        env = _make_env(mocked_dir, tmp_path)
        m = _root_manifest("foo", Version(1, 0, 0), [_url_dep("dep-d", "https://example.com/dep-d.git")])
        deps_dir = tmp_path / "_deps"
        resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        assert not (deps_dir / "foo").exists(), (
            "the root's own name must never be fetched into _deps/"
        )


# ---------------------------------------------------------------------------
# Test 2: a satisfiable version constraint binds to the root
# ---------------------------------------------------------------------------


class TestSatisfiableConstraintBindsToRoot:
    def test_constraint_matching_root_version_succeeds(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(
            mocked_dir,
            "https://example.com/dep-d.git",
            "main",
            'name "dep-d"\nkind "library"\nsrc_dir "src"\ndeps {\n  foo ">= 1.0.0"\n}\n',
            "sha-d",
        )
        env = _make_env(mocked_dir, tmp_path)
        m = _root_manifest("foo", Version(1, 0, 0), [_url_dep("dep-d", "https://example.com/dep-d.git")])
        deps_dir = tmp_path / "_deps"
        graph = resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        foo_deps = [d for d in graph.deps if d.name == "foo"]
        assert len(foo_deps) == 1
        assert isinstance(foo_deps[0].provenances[0], RootProvenanceRecord)


# ---------------------------------------------------------------------------
# Test 3: an unsatisfiable version constraint raises a clear error
# ---------------------------------------------------------------------------


class TestUnsatisfiableConstraintRaises:
    def test_constraint_stricter_than_root_version_raises(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(
            mocked_dir,
            "https://example.com/dep-d.git",
            "main",
            'name "dep-d"\nkind "library"\nsrc_dir "src"\ndeps {\n  foo ">= 2.0.0"\n}\n',
            "sha-d",
        )
        env = _make_env(mocked_dir, tmp_path)
        # Root declares version 1.0.0 — does NOT satisfy the transitive's ">= 2.0.0".
        m = _root_manifest("foo", Version(1, 0, 0), [_url_dep("dep-d", "https://example.com/dep-d.git")])
        deps_dir = tmp_path / "_deps"

        with pytest.raises(MilpaError) as excinfo:
            resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        assert excinfo.value.slug == RES_ROOT_SELF_VERSION_CONSTRAINT
        # Must NOT have fetched a second "foo" while failing.
        assert not (deps_dir / "foo").exists()


# ---------------------------------------------------------------------------
# Test 4: the ordinary case (nothing transitively requires the root's name)
#         is byte-for-byte unchanged.
# ---------------------------------------------------------------------------


class TestOrdinaryCaseUnchanged:
    def test_no_root_entry_when_nothing_references_root_name(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(
            mocked_dir,
            "https://example.com/dep-e.git",
            "main",
            'name "dep-e"\nkind "library"\nsrc_dir "src"\n',
            "sha-e",
        )
        env = _make_env(mocked_dir, tmp_path)
        m = _root_manifest("foo", Version(1, 0, 0), [_url_dep("dep-e", "https://example.com/dep-e.git")])
        deps_dir = tmp_path / "_deps"
        graph = resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        assert [d.name for d in graph.deps] == ["dep-e"], (
            "no 'foo' entry should appear in the graph when nothing "
            "transitively requires the root's own name"
        )

    def test_no_version_set_on_root_is_also_unaffected(self, tmp_path: Path) -> None:
        """A root with NO declared version (the common case) is unaffected too."""
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(
            mocked_dir,
            "https://example.com/dep-e.git",
            "main",
            'name "dep-e"\nkind "library"\nsrc_dir "src"\n',
            "sha-e",
        )
        env = _make_env(mocked_dir, tmp_path)
        m = _root_manifest("foo", None, [_url_dep("dep-e", "https://example.com/dep-e.git")])
        deps_dir = tmp_path / "_deps"
        graph = resolve(m, deps_dir=deps_dir, env=env, params=ResolveParams())

        assert [d.name for d in graph.deps] == ["dep-e"]
