"""C3 (resolver-semantics RFC §3 Axis C / D-C2, #98/#111): B2 lock-preference
bypass on VALUE-DIVERGENCE, not CLI flag presence.

Reuses the exact infra ``test_c2_lowest_direct.py`` built (real mocked-git
fetches + a real in-memory ``Index``, ``resolve()`` end to end) — this file
adds a ``prior`` ``Lockfile`` to exercise the bypass gate
(``_Provider._bypasses_lock_preference``, resolver.py).

The three mandated behaviors (§7 slice C4's regression guards, proven here at
resolver granularity — the full conformance-fixture form is C4):

1. ``--strategy maxver`` on an ALREADY-maxver lock is a NO-OP: B2's
   minimal-change preference still wins (the #192 regression guard —
   spelling out the default must never flip the whole graph to
   newest-wins).
2. ``--strategy lowest-direct`` on a maxver lock DOES bypass, but
   ROOT-DIRECT-ONLY: the root-direct dep ignores its lock pin and picks per
   ``lowest-direct``'s MINVER-for-root rule; the purely-transitive dep KEEPS
   its lock pin despite the divergence (the "MinDirect trap" this RFC names
   — a whole-graph bypass here would drag transitives forward, #192 again).
3. A genuinely divergent whole-graph strategy (``minver`` on a maxver lock)
   bypasses lock-preference for EVERY package.
"""

from __future__ import annotations

from pathlib import Path

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry
from milpa.lockfile import Lockfile, LockedDep, ResolvedGraph
from milpa.manifest import parse_manifest
from milpa.registry import parse_index
from milpa.resolver import resolve
from milpa.version import Strategy

from tests.test_c2_lowest_direct import (
    _ROOT_KDL,
    _index_kdl_two_pkgs,
    _stage_two_versions,
    _versions,
)


def _env(tmp_path: Path, mocked_dir: Path, index_kdl: str) -> MilpaEnv:
    store = CAStore(tmp_path / "cas")
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    index = parse_index(index_kdl)
    return MilpaEnv(fetcher=fetcher, index=index, store=store)


def _locked_dep(name: str, version: str) -> LockedDep:
    return LockedDep(
        name=name,
        identity="sha256:" + ("0" * 64),
        version=version,
        src_dir="",
        requires=(),
        provenances=(),
    )


def _resolve(
    root_kdl: str,
    env: MilpaEnv,
    tmp_path: Path,
    *,
    strategy: Strategy,
    prior: Lockfile | None,
) -> ResolvedGraph:
    manifest = parse_manifest(root_kdl)
    deps_dir = tmp_path / "_deps"
    deps_dir.mkdir(exist_ok=True)
    # R9: every test in this file simulates an EXPLICITLY-sourced --strategy
    # (that's the whole point — "value-divergence, not flag-presence"), so
    # strategy_explicit=True here mirrors what the CLI layer would compute
    # for a real `milpa fetch --strategy <value>` invocation. The bypass
    # gate now requires strategy_explicit=True AND value-divergence — a
    # default-filled effective strategy (strategy_explicit=False) never
    # bypasses at all, regardless of value-divergence (see
    # test_c3_strategy_default_fill_never_bypasses.py's R9 regression guard).
    return resolve(
        manifest,
        deps_dir,
        env,
        ResolveParams(strategy=strategy, strategy_explicit=True, prior=prior),
    )


def _stage(tmp_path: Path) -> tuple[MilpaEnv, str]:
    """Stage the SAME two-package (direct root-direct, transitive) shape
    C2's contrast test uses: each dep has two candidate versions 1.0.0/2.0.0.
    """
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    direct_hashes = _stage_two_versions(
        mocked_dir, "direct", sha_prefix="1", requires="transitive"
    )
    transitive_hashes = _stage_two_versions(mocked_dir, "transitive", sha_prefix="2")
    index_kdl = _index_kdl_two_pkgs(
        direct_hashes=direct_hashes, transitive_hashes=transitive_hashes
    )
    return _env(tmp_path, mocked_dir, index_kdl), index_kdl


class TestStrategyMaxverOnMaxverLockIsNoop:
    """The #192 regression guard: explicit ``--strategy maxver`` on an
    already-maxver lock must NOT bypass — a presence-gate would wrongly
    flip the whole graph to newest-wins even though nothing diverges."""

    def test_maxver_explicit_on_maxver_lock_keeps_locked_pin(
        self, tmp_path: Path
    ) -> None:
        env, _ = _stage(tmp_path)
        # Lock pins "direct" at 1.0.0 — NOT what a fresh maxver pick would
        # choose (2.0.0) — so if the lock-preference is honored, the
        # resolve returns the LOCKED 1.0.0, not the naturally-maxver 2.0.0.
        prior = Lockfile(deps=(_locked_dep("direct", "1.0.0"),), strategy="maxver")

        graph = _resolve(
            _ROOT_KDL, env, tmp_path, strategy=Strategy.MAXVER, prior=prior
        )
        versions = _versions(graph)
        assert versions["direct"] == "1.0.0", (
            "explicit --strategy maxver on a maxver-recorded lock must be a "
            "NO-OP against lock-preference (value-divergence gate, not "
            "flag-presence) — got a bypass instead"
        )


class TestStrategyLowestDirectBypassesRootDirectOnly:
    """D-C2: lowest-direct diverging from a maxver lock bypasses ONLY the
    root-direct package; the purely-transitive package keeps its lock pin."""

    def test_root_direct_bypasses_transitive_keeps_lock(
        self, tmp_path: Path
    ) -> None:
        env, _ = _stage(tmp_path)
        # Lock recorded under "maxver": direct pinned at 2.0.0 (NOT what
        # lowest-direct's MINVER-for-root rule would pick — 1.0.0);
        # transitive pinned at 1.0.0 (NOT what lowest-direct's MAXVER-for-
        # transitive rule would pick — 2.0.0). Both pins are deliberately
        # the OPPOSITE of what each package's fresh pick would be, so the
        # test can distinguish "bypassed" (fresh pick wins) from "kept"
        # (locked pin wins) unambiguously.
        prior = Lockfile(
            deps=(
                _locked_dep("direct", "2.0.0"),
                _locked_dep("transitive", "1.0.0"),
            ),
            strategy="maxver",
        )

        graph = _resolve(
            _ROOT_KDL, env, tmp_path, strategy=Strategy.LOWEST_DIRECT, prior=prior
        )
        versions = _versions(graph)
        assert versions["direct"] == "1.0.0", (
            "root-direct dep must BYPASS lock-preference under a diverging "
            "lowest-direct strategy and pick MINVER fresh"
        )
        assert versions["transitive"] == "1.0.0", (
            "purely-transitive dep must KEEP its lock pin under "
            "lowest-direct — a whole-graph bypass here would drag it "
            "forward (#192 again)"
        )


class TestStrategyWholeGraphBypassOnGenuineDivergence:
    """A genuinely divergent non-lowest-direct strategy (minver vs a
    maxver-recorded lock) bypasses lock-preference for EVERY package."""

    def test_minver_vs_maxver_lock_bypasses_whole_graph(
        self, tmp_path: Path
    ) -> None:
        env, _ = _stage(tmp_path)
        # Lock recorded under "maxver": both pinned at 2.0.0 (what maxver
        # naturally picks) — the OPPOSITE of what minver would pick (1.0.0),
        # so a whole-graph bypass is unambiguous for both packages.
        prior = Lockfile(
            deps=(
                _locked_dep("direct", "2.0.0"),
                _locked_dep("transitive", "2.0.0"),
            ),
            strategy="maxver",
        )

        graph = _resolve(
            _ROOT_KDL, env, tmp_path, strategy=Strategy.MINVER, prior=prior
        )
        versions = _versions(graph)
        assert versions["direct"] == "1.0.0"
        assert versions["transitive"] == "1.0.0"
