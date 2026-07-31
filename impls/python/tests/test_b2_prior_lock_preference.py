"""B2 (resolver-semantics RFC §4 stage 4 / §3 Axis B — #192/#70): feeding the
prior lockfile's recorded versions into the solver as preferences, end to end
through ``resolve()``.

``tests/test_solver.py``'s ``TestB2PriorLockPreference`` covers the solver-
internal mechanism (``_pick_version``'s preference short-circuit, and
``solve()`` over a synthetic in-memory provider) in isolation. This file
proves the RESOLVER wires ``params.prior`` into that mechanism for real named/
index deps (multi-candidate — the only case where a preference can ever bite,
per the RFC §7 dependency note) via ``_Provider.preference``.

Scenarios (RFC §3 Axis B "Minimal-change (new default)"):
  1. Fresh resolve (no prior) — unaffected, picks strategy-newest (maxver).
  2. Re-resolve with a prior lock — an unconstrained named dep stays at its
     locked version instead of jumping to a newer one (the default-change
     itself: pre-B2 this would newest-wins bump).
  3. Bumping ONE dep's constraint forces only that dep to move; an unrelated
     dep stays pinned at its locked version even though a newer version is
     available and would win a fresh maxver resolve (the #192 regression
     fixture, at full resolver granularity).

No mocking: real git-backed mocked fetches (``mocked_registry``) + a real
in-memory ``Index`` (``parse_index``), same infra as
``test_a4_version_unknown_constrained.py``.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.identity import compute_content_hash
from milpa.lockfile import ResolvedGraph, from_graph
from milpa.manifest import parse_manifest
from milpa.registry import parse_index
from milpa.resolver import resolve


def _make_git_mock(
    mocked_dir: Path,
    url: str,
    ref: str,
    *,
    sha: str,
    nim_name: str,
    marker: str,
) -> None:
    """Stage one ``mocked-fetches/<url_key>/`` dir with distinct content per
    ``marker`` so each (url, ref) pair gets its own content_hash."""
    d = mocked_dir / url_key(url, ref)
    content = d / "content"
    content.mkdir(parents=True)
    (content / f"{nim_name}.nim").write_text(f"# {nim_name} {marker}\n", encoding="utf-8")
    (d / f"{nim_name}.nimble").write_text(
        f'# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n', encoding="utf-8"
    )
    (d / "sha").write_text(sha, encoding="utf-8")


def _content_hash_for(mocked_dir: Path, url: str, ref: str, name: str) -> str:
    key_dir = mocked_dir / url_key(url, ref)
    with tempfile.TemporaryDirectory() as td:
        dest = Path(td)
        content = key_dir / "content"
        for src in content.rglob("*"):
            if src.is_file():
                rel = src.relative_to(content)
                tgt = dest / rel
                tgt.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, tgt)
        nimble_src = key_dir / f"{name}.nimble"
        if nimble_src.is_file():
            shutil.copy2(nimble_src, dest / f"{name}.nimble")
        return compute_content_hash(dest)


def _stage_two_versions(mocked_dir: Path, name: str, *, sha_prefix: str) -> tuple[str, str]:
    """Stage v1.0.0 + v2.0.0 mocked git content for a named dep, return their
    (content_hash_v1, content_hash_v2)."""
    url = f"https://example.com/{name}.git"
    _make_git_mock(mocked_dir, url, "v1.0.0", sha=f"{sha_prefix}1" * 20, nim_name=name, marker="v1")
    _make_git_mock(mocked_dir, url, "v2.0.0", sha=f"{sha_prefix}2" * 20, nim_name=name, marker="v2")
    h1 = _content_hash_for(mocked_dir, url, "v1.0.0", name)
    h2 = _content_hash_for(mocked_dir, url, "v2.0.0", name)
    return h1, h2


def _index_kdl_two_pkgs(
    *,
    foo_hashes: tuple[str, str],
    bar_hashes: tuple[str, str],
) -> str:
    def pkg_block(name: str, hashes: tuple[str, str]) -> str:
        h1, h2 = hashes
        return f"""\
package "{name}" {{
    version "1.0.0" {{
        content_hash "{h1}"
        provenance {{
            kind "git"
            url "https://example.com/{name}.git"
            ref "v1.0.0"
            commit_sha "{'a' * 40}"
        }}
    }}
    version "2.0.0" {{
        content_hash "{h2}"
        provenance {{
            kind "git"
            url "https://example.com/{name}.git"
            ref "v2.0.0"
            commit_sha "{'b' * 40}"
        }}
    }}
}}
"""

    return "schema_version 1\n" + pkg_block("libfoo", foo_hashes) + pkg_block("libbar", bar_hashes)


def _env(tmp_path: Path, mocked_dir: Path, index_kdl: str) -> MilpaEnv:
    store = CAStore(tmp_path / "cas")
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    index = parse_index(index_kdl)
    return MilpaEnv(fetcher=fetcher, index=index, store=store)


def _versions(graph: ResolvedGraph) -> dict[str, str]:
    return {d.name: d.version for d in graph.deps}


@pytest.fixture()
def _setup(tmp_path: Path) -> tuple[MilpaEnv, Path]:
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    foo_hashes = _stage_two_versions(mocked_dir, "libfoo", sha_prefix="1")
    bar_hashes = _stage_two_versions(mocked_dir, "libbar", sha_prefix="2")
    index_kdl = _index_kdl_two_pkgs(foo_hashes=foo_hashes, bar_hashes=bar_hashes)
    env = _env(tmp_path, mocked_dir, index_kdl)
    return env, tmp_path


def _resolve(root_kdl: str, env: MilpaEnv, tmp_path: Path, *, prior=None) -> ResolvedGraph:
    manifest = parse_manifest(root_kdl)
    deps_dir = tmp_path / "_deps"
    deps_dir.mkdir(exist_ok=True)
    return resolve(manifest, deps_dir, env, ResolveParams(prior=prior))


_UNCONSTRAINED_ROOT = (
    'name "myapp"\nkind "application"\n'
    "deps {\n"
    "    libfoo\n"
    "    libbar\n"
    "}\n"
)

_BUMPED_ROOT = (
    'name "myapp"\nkind "application"\n'
    "deps {\n"
    '    libfoo ">=2.0.0"\n'
    "    libbar\n"
    "}\n"
)


class TestFreshResolveUnaffected:
    """B2 must not change fresh-resolve (no prior) behavior: strategy-newest
    (maxver, the default) still wins — zero-behavior-change is the point."""

    def test_fresh_resolve_picks_newest(self, _setup) -> None:
        env, tmp_path = _setup
        graph = _resolve(_UNCONSTRAINED_ROOT, env, tmp_path, prior=None)
        assert _versions(graph) == {"libfoo": "2.0.0", "libbar": "2.0.0"}


class TestReResolveWithPriorLockKeepsLockedVersion:
    """The default-change itself: an unconstrained named dep, re-resolved
    against a prior lock pinning it below the newest available version,
    STAYS at the locked version — pre-B2 this would newest-wins bump."""

    def test_prior_lock_pins_unconstrained_deps(self, _setup) -> None:
        env, tmp_path = _setup
        fresh = _resolve(_UNCONSTRAINED_ROOT, env, tmp_path, prior=None)
        assert _versions(fresh) == {"libfoo": "2.0.0", "libbar": "2.0.0"}

        # Build a prior lock as though both had been resolved+locked at 1.0.0
        # in an earlier run (e.g. before 2.0.0 was published).
        prior_graph = _resolve(_UNCONSTRAINED_ROOT, env, tmp_path, prior=None)
        prior = from_graph(prior_graph)
        # Force the prior lock's recorded versions down to 1.0.0 (simulating
        # "2.0.0 didn't exist yet when this lock was written").
        prior_v1 = _with_versions(prior, {"libfoo": "1.0.0", "libbar": "1.0.0"})

        graph = _resolve(_UNCONSTRAINED_ROOT, env, tmp_path, prior=prior_v1)
        assert _versions(graph) == {"libfoo": "1.0.0", "libbar": "1.0.0"}


class TestBumpOneDepLeavesUnrelatedPinned:
    """The #192 regression fixture, at resolver granularity: narrowing
    libfoo's constraint to exclude the locked 1.0.0 forces ONLY libfoo to
    move (to 2.0.0, the sole remaining candidate); libbar — unrelated,
    unconstrained — stays pinned at its locked 1.0.0 even though 2.0.0 is
    available and a fresh maxver resolve would pick it."""

    def test_bump_forces_only_the_bumped_dep(self, _setup) -> None:
        env, tmp_path = _setup
        prior_graph = _resolve(_UNCONSTRAINED_ROOT, env, tmp_path, prior=None)
        prior = from_graph(prior_graph)
        prior_v1 = _with_versions(prior, {"libfoo": "1.0.0", "libbar": "1.0.0"})

        graph = _resolve(_BUMPED_ROOT, env, tmp_path, prior=prior_v1)
        versions = _versions(graph)
        assert versions["libfoo"] == "2.0.0"  # forced: 1.0.0 no longer satisfies >=2.0.0
        assert versions["libbar"] == "1.0.0"  # unrelated: stays locked, NOT newest-wins-bumped


class TestB4StrippedPinOptsOutOfPreference:
    """B4 (resolution-semantics RFC §3 Axis B / D-B3): a prior entry with
    ``identity=None`` (the exact shape ``strip_dep_pin`` — the shared
    mechanism ``update <dep>``/``--upgrade <dep>`` delegate to — produces)
    carries NO preference at all, even though its ``version`` field still
    says "1.0.0". Only the stripped dep moves to the newest; an unrelated
    dep with a real (non-None) identity stays locked — proving
    ``_Provider.preference`` reads ``identity``, not just ``version``."""

    def test_stripped_pin_opts_out_but_unrelated_dep_stays_locked(self, _setup) -> None:
        env, tmp_path = _setup
        prior_graph = _resolve(_UNCONSTRAINED_ROOT, env, tmp_path, prior=None)
        prior = from_graph(prior_graph)
        prior_v1 = _with_versions(prior, {"libfoo": "1.0.0", "libbar": "1.0.0"})
        prior_stripped = _with_stripped_identity(prior_v1, {"libfoo"})

        graph = _resolve(_UNCONSTRAINED_ROOT, env, tmp_path, prior=prior_stripped)
        versions = _versions(graph)
        assert versions["libfoo"] == "2.0.0"  # stripped -> no preference -> newest
        assert versions["libbar"] == "1.0.0"  # real pin -> preference still applies


def _with_versions(lock, overrides: dict[str, str]):
    """Rebuild ``lock`` with each named dep's ``version`` field overridden —
    a test-only helper simulating "this lock was written when only 1.0.0
    existed" without needing a second, separately-staged index snapshot."""
    from dataclasses import replace

    new_deps = tuple(
        replace(d, version=overrides.get(d.name, d.version)) for d in lock.deps
    )
    return replace(lock, deps=new_deps)


def _with_stripped_identity(lock, names: set[str]):
    """Rebuild ``lock`` with each named dep in ``names`` given ``identity=None``
    — simulates ``strip_dep_pin`` having run on it, without needing a full
    CLI round-trip through ``update``/``--upgrade``."""
    from dataclasses import replace

    new_deps = tuple(
        replace(d, identity=None) if d.name in names else d for d in lock.deps
    )
    return replace(lock, deps=new_deps)
