"""R9 (resolver-semantics RFC §3 Axis C NORMATIVE, code-review finding): the
lockfile-recorded ``strategy`` is diagnostic/frozen-parity only, never a
LIVE resolution input.

Before this fix, ``_resolve_effective_strategy`` had a third precedence tier
that fell back to the prior lockfile's recorded ``strategy`` before the
global default, and ``_Provider._bypasses_lock_preference`` fired B2's
lock-preference bypass on ``effective_strategy != prior.strategy`` alone.
Together these meant:

1. A one-off ``milpa fetch --strategy X`` invisibly and PERMANENTLY governed
   every future BARE resolve (hidden sticky state) — the lockfile became a
   live input, contradicting the RFC's own NORMATIVE text.
2. Naively deleting tier 3 without retargeting the bypass would have been a
   WORSE regression: a bare ``milpa fetch`` on a project whose lock was
   built under a non-default strategy would compute effective=maxver (the
   default), see it "diverge" from the lock's recorded value, and
   newest-wins bump the WHOLE graph — resurrecting #192 through a new door.

The fix: precedence is now CLI > manifest > default (no lockfile tier at
all), and the B2 lock-preference bypass gate additionally requires
``ResolveParams.strategy_explicit`` (CLI or manifest ``resolution {
strategy }`` — never a merely default-filled value) on top of the existing
value-divergence check. Stability of a bare re-resolve against a
non-default-strategy lock now rides ENTIRELY on B2's lock-preference
mechanism, not on treating the lockfile's strategy as a governing tier.

Reuses ``test_b2_prior_lock_preference.py``'s infra (real mocked-git
fetches + a real in-memory ``Index``, ``resolve()`` end to end, two
independent unconstrained named deps).
"""

from __future__ import annotations

from pathlib import Path

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry
from milpa.lockfile import Lockfile, ResolvedGraph, from_graph
from milpa.manifest import parse_manifest
from milpa.registry import parse_index
from milpa.resolver import _resolve_effective_strategy, resolve
from milpa.version import Strategy

from tests.test_b2_prior_lock_preference import _stage_two_versions


def _index_kdl(pkgs: dict[str, tuple[str, str]]) -> str:
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

    return "schema_version 1\n" + "".join(
        pkg_block(name, hashes) for name, hashes in pkgs.items()
    )


def _env(tmp_path: Path, mocked_dir: Path, index_kdl: str) -> MilpaEnv:
    store = CAStore(tmp_path / "cas")
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    index = parse_index(index_kdl)
    return MilpaEnv(fetcher=fetcher, index=index, store=store)


def _versions(graph: ResolvedGraph) -> dict[str, str]:
    return {d.name: d.version for d in graph.deps}


def _resolve(
    root_kdl: str,
    env: MilpaEnv,
    tmp_path: Path,
    *,
    strategy: Strategy,
    strategy_explicit: bool,
    prior: Lockfile | None,
) -> ResolvedGraph:
    manifest = parse_manifest(root_kdl)
    deps_dir = tmp_path / "_deps"
    deps_dir.mkdir(exist_ok=True)
    return resolve(
        manifest,
        deps_dir,
        env,
        ResolveParams(
            strategy=strategy, strategy_explicit=strategy_explicit, prior=prior
        ),
    )


_TWO_DEP_ROOT = (
    'name "myapp"\nkind "application"\n'
    "deps {\n"
    "    libfoo\n"
    "    libbar\n"
    "}\n"
)

_THREE_DEP_ROOT = (
    'name "myapp"\nkind "application"\n'
    "deps {\n"
    "    libfoo\n"
    "    libbar\n"
    "    libbaz\n"
    "}\n"
)


class TestBareResolveOnNonDefaultLockStaysStable:
    """(a) The key regression guard: a BARE re-resolve (no CLI flag, no
    manifest ``resolution`` block — ``strategy_explicit=False``) against a
    lock recorded under a NON-DEFAULT strategy must keep every unconstrained
    multi-candidate named dep at its LOCKED version. Naively dropping tier 3
    without retargeting the bypass would instead newest-wins bump the whole
    graph here (effective maxver "diverges" from the lock's recorded
    minver) — this is exactly the worse regression the fix must avoid."""

    def test_bare_fetch_keeps_locked_versions_despite_nondefault_lock(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        foo_hashes = _stage_two_versions(mocked_dir, "libfoo", sha_prefix="1")
        bar_hashes = _stage_two_versions(mocked_dir, "libbar", sha_prefix="2")
        index_kdl = _index_kdl({"libfoo": foo_hashes, "libbar": bar_hashes})
        env = _env(tmp_path, mocked_dir, index_kdl)

        # Simulates a one-off `milpa fetch --strategy minver` — an explicit,
        # value-diverging strategy — which legitimately picks 1.0.0 for both
        # (lowest available) and records "minver" as the lock's strategy.
        one_off = _resolve(
            _TWO_DEP_ROOT,
            env,
            tmp_path,
            strategy=Strategy.MINVER,
            strategy_explicit=True,
            prior=None,
        )
        assert _versions(one_off) == {"libfoo": "1.0.0", "libbar": "1.0.0"}
        prior = from_graph(one_off, strategy="minver")

        # Now a BARE `milpa fetch` — no CLI flag, no manifest `resolution`
        # block. The CLI layer would compute effective=maxver (tier 3 is
        # gone) and strategy_explicit=False (neither CLI nor manifest named
        # a strategy). Despite effective (maxver) numerically differing
        # from the lock's recorded value (minver), the bypass must NOT
        # fire — both deps must stay at their locked 1.0.0, not jump to the
        # newest-available 2.0.0.
        bare = _resolve(
            _TWO_DEP_ROOT,
            env,
            tmp_path,
            strategy=Strategy.MAXVER,
            strategy_explicit=False,
            prior=prior,
        )
        assert _versions(bare) == {"libfoo": "1.0.0", "libbar": "1.0.0"}, (
            "a bare re-resolve against a non-default-strategy lock must stay "
            "stable via B2 lock-preference — a default-filled effective "
            "strategy must never bypass, even when it numerically diverges "
            "from the lock's recorded strategy"
        )


class TestOneOffExplicitStrategyIsNotSticky:
    """(e) No hidden sticky state: a one-off explicit ``--strategy X`` run
    must NOT make a SUBSEQUENT bare fetch behave as if X were still in
    effect for a brand-NEW dep that didn't exist in the prior lock. The new
    dep must be picked under the DEFAULT strategy (maxver), not the
    previous run's explicit minver — proving the lockfile's recorded
    strategy never became a live input anywhere in the pipeline."""

    def test_new_dep_picked_under_default_not_prior_explicit_strategy(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        foo_hashes = _stage_two_versions(mocked_dir, "libfoo", sha_prefix="1")
        bar_hashes = _stage_two_versions(mocked_dir, "libbar", sha_prefix="2")
        baz_hashes = _stage_two_versions(mocked_dir, "libbaz", sha_prefix="3")
        index_kdl = _index_kdl(
            {"libfoo": foo_hashes, "libbar": bar_hashes, "libbaz": baz_hashes}
        )
        env = _env(tmp_path, mocked_dir, index_kdl)

        # One-off explicit `--strategy minver` run — only libfoo/libbar
        # exist in the manifest at this point; libbaz is not yet declared.
        one_off = _resolve(
            _TWO_DEP_ROOT,
            env,
            tmp_path,
            strategy=Strategy.MINVER,
            strategy_explicit=True,
            prior=None,
        )
        assert _versions(one_off) == {"libfoo": "1.0.0", "libbar": "1.0.0"}
        prior = from_graph(one_off, strategy="minver")

        # Add libbaz to the manifest, then do a BARE fetch (no CLI flag, no
        # manifest resolution block) — the CLI layer computes
        # effective=maxver, strategy_explicit=False, exactly as it would for
        # a real `milpa fetch` with no flags after `milpa add libbaz`.
        bare = _resolve(
            _THREE_DEP_ROOT,
            env,
            tmp_path,
            strategy=Strategy.MAXVER,
            strategy_explicit=False,
            prior=prior,
        )
        versions = _versions(bare)
        # Pre-existing deps stay locked (B2 preference, no bypass).
        assert versions["libfoo"] == "1.0.0"
        assert versions["libbar"] == "1.0.0"
        # The NEW dep has no prior entry to prefer at all — it is picked
        # fresh under THIS resolve's effective strategy (maxver, the
        # default), NOT the previous run's explicit minver. 2.0.0 (not
        # 1.0.0) is the proof: sticky minver would have picked 1.0.0 here.
        assert versions["libbaz"] == "2.0.0", (
            "a new dep with no prior lock entry must be picked under the "
            "CURRENT effective strategy (maxver, default) — a prior run's "
            "explicit --strategy must never leak forward as hidden state"
        )


class TestManifestResolutionBlockDivergenceBypasses:
    """(d) A manifest ``resolution { strategy }`` block — not just a CLI
    flag — counts as an EXPLICIT strategy source. When it diverges from the
    lock's recorded strategy, the bypass must still fire (a declared,
    visible policy change SHOULD re-resolve), exercising the exact
    ``_resolve_effective_strategy`` single-walk call the CLI layer makes
    (deriving both facts from its ``Strategy | None`` result), not a
    hand-set boolean."""

    def test_manifest_resolution_block_diverging_from_lock_bypasses(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        foo_hashes = _stage_two_versions(mocked_dir, "libfoo", sha_prefix="1")
        bar_hashes = _stage_two_versions(mocked_dir, "libbar", sha_prefix="2")
        index_kdl = _index_kdl({"libfoo": foo_hashes, "libbar": bar_hashes})
        env = _env(tmp_path, mocked_dir, index_kdl)

        # A lock recorded under maxver (both pinned at 2.0.0 — the OPPOSITE
        # of what minver would pick), simulating an earlier maxver run.
        root_kdl_no_resolution = _TWO_DEP_ROOT
        maxver_run = _resolve(
            root_kdl_no_resolution,
            env,
            tmp_path,
            strategy=Strategy.MAXVER,
            strategy_explicit=False,
            prior=None,
        )
        assert _versions(maxver_run) == {"libfoo": "2.0.0", "libbar": "2.0.0"}
        prior = from_graph(maxver_run, strategy="maxver")

        # The manifest NOW declares `resolution { strategy "minver" }` — a
        # declared, visible policy change (no CLI flag at all: cli_strategy
        # stays None throughout, exactly as a bare `milpa fetch` would see
        # it after a hand-edit to milpa.kdl).
        root_kdl_with_resolution = (
            'name "myapp"\nkind "application"\n'
            'resolution {\n    strategy "minver"\n}\n'
            "deps {\n"
            "    libfoo\n"
            "    libbar\n"
            "}\n"
        )
        manifest = parse_manifest(root_kdl_with_resolution)
        _strategy_decl = _resolve_effective_strategy(None, manifest)
        strategy_explicit = _strategy_decl is not None
        effective_strategy = _strategy_decl if _strategy_decl is not None else Strategy.MAXVER
        assert effective_strategy == Strategy.MINVER
        assert strategy_explicit is True

        bare = _resolve(
            root_kdl_with_resolution,
            env,
            tmp_path,
            strategy=effective_strategy,
            strategy_explicit=strategy_explicit,
            prior=prior,
        )
        assert _versions(bare) == {"libfoo": "1.0.0", "libbar": "1.0.0"}, (
            "a manifest resolution{strategy} block diverging from the "
            "lock's recorded strategy must still bypass lock-preference — "
            "only a merely DEFAULT-FILLED effective strategy is exempt"
        )
