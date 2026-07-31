"""B3 (resolution-semantics RFC §3 Axis B / §6 D-B2) — ``check_locked_drift``
end to end through a real ``resolve()``.

``tests/test_lockfile.py``'s ``TestCheckLockedDrift`` covers the comparison
function in isolation (synthetic ``Lockfile``/``ResolvedGraph`` literals).
This file proves the same identity-based (never version-label-based) drift
semantics hold when the prior lock and the resolved graph both come from a
REAL resolve — in particular the headline D-B2 scenario: a git dep's
declared-version *label* changing (the one-time Axis-A ``0.0.1``->real
migration) while its content identity + provenance are unchanged must NOT
be reported as drift.

No mocking: real mocked-fetches git content (mirrors
``test_b2_prior_lock_preference.py``'s infra).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import RES_LOCKED_DRIFT, MilpaError
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.lockfile import ResolvedGraph, check_locked_drift, from_graph
from milpa.manifest import parse_manifest
from milpa.resolver import resolve


def _make_git_mock(mocked_dir: Path, url: str, ref: str, *, sha: str, marker: str) -> None:
    d = mocked_dir / url_key(url, ref)
    content = d / "content"
    content.mkdir(parents=True)
    (content / "foo.nim").write_text(f"# foo {marker}\n", encoding="utf-8")
    (d / "sha").write_text(sha, encoding="utf-8")
    return d


def _env(tmp_path: Path, mocked_dir: Path) -> MilpaEnv:
    store = CAStore(tmp_path / "cas")
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


_ROOT_KDL = (
    'name "myapp"\nkind "application"\n'
    "deps {\n"
    '    foo git=(url)"https://example.com/foo.git" ref="v1.0.0"\n'
    "}\n"
)


def _resolve(root_kdl: str, env: MilpaEnv, tmp_path: Path, *, prior=None) -> ResolvedGraph:
    manifest = parse_manifest(root_kdl)
    deps_dir = tmp_path / "_deps"
    deps_dir.mkdir(exist_ok=True)
    return resolve(manifest, deps_dir, env, ResolveParams(prior=prior))


class TestNoDriftOnUnchangedResolve:
    def test_re_resolving_the_same_manifest_against_its_own_lock_is_not_drift(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_git_mock(
            mocked_dir, "https://example.com/foo.git", "v1.0.0", sha="a" * 40, marker="v1"
        )
        env = _env(tmp_path, mocked_dir)

        graph = _resolve(_ROOT_KDL, env, tmp_path, prior=None)
        prior = from_graph(graph)

        # Re-resolve against the just-written lock (steady state, no manifest
        # change) — must be byte-for-byte reproducible, hence no drift.
        graph2 = _resolve(_ROOT_KDL, env, tmp_path, prior=prior)
        check_locked_drift(prior, graph2)  # must not raise


class TestVersionRelabelIsNotDrift:
    """The headline D-B2 scenario: a git dep's declared-version LABEL changes
    (simulating the one-time Axis-A 0.0.1 -> real-declared-version migration)
    while its content identity + provenance are unchanged -- NOT drift."""

    def test_relabeled_version_with_same_identity_and_provenance_passes(
        self, tmp_path: Path
    ) -> None:
        from dataclasses import replace

        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_git_mock(
            mocked_dir, "https://example.com/foo.git", "v1.0.0", sha="a" * 40, marker="v1"
        )
        env = _env(tmp_path, mocked_dir)

        graph = _resolve(_ROOT_KDL, env, tmp_path, prior=None)
        prior = from_graph(graph)
        # Simulate "this lock was written under the pre-Axis-A sentinel":
        # relabel the dep's recorded version, identity/provenance untouched.
        assert prior.deps[0].name == "foo"
        relabeled_deps = tuple(
            replace(d, version="0.0.1", declared_version_source=None) for d in prior.deps
        )
        prior_relabeled = replace(prior, deps=relabeled_deps)

        # A fresh resolve of the SAME manifest against the relabeled prior
        # lock must still pass --locked: identity + provenance match; only
        # the version label differs (and the label is never consulted).
        graph2 = _resolve(_ROOT_KDL, env, tmp_path, prior=prior_relabeled)
        assert graph2.deps[0].version != prior_relabeled.deps[0].version  # sanity: labels DO differ
        check_locked_drift(prior_relabeled, graph2)  # must not raise


class TestDriftOnManifestChange:
    def test_moving_the_dep_to_a_different_ref_is_drift(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_git_mock(
            mocked_dir, "https://example.com/foo.git", "v1.0.0", sha="a" * 40, marker="v1"
        )
        _make_git_mock(
            mocked_dir, "https://example.com/foo.git", "v2.0.0", sha="b" * 40, marker="v2"
        )
        env = _env(tmp_path, mocked_dir)

        graph = _resolve(_ROOT_KDL, env, tmp_path, prior=None)
        prior = from_graph(graph)

        bumped_kdl = (
            'name "myapp"\nkind "application"\n'
            "deps {\n"
            '    foo git=(url)"https://example.com/foo.git" ref="v2.0.0"\n'
            "}\n"
        )
        graph2 = _resolve(bumped_kdl, env, tmp_path, prior=prior)
        with pytest.raises(MilpaError) as exc_info:
            check_locked_drift(prior, graph2)
        assert exc_info.value.slug == RES_LOCKED_DRIFT
        assert "foo" in exc_info.value.message


class TestNoPriorLockAtAll:
    def test_locked_with_no_prior_lock_raises(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_git_mock(
            mocked_dir, "https://example.com/foo.git", "v1.0.0", sha="a" * 40, marker="v1"
        )
        env = _env(tmp_path, mocked_dir)
        graph = _resolve(_ROOT_KDL, env, tmp_path, prior=None)

        with pytest.raises(MilpaError) as exc_info:
            check_locked_drift(None, graph)
        assert exc_info.value.slug == RES_LOCKED_DRIFT
