"""Tier-2 unsatisfiable semantic differential test — gated.

Gate: MILPA_DIFFERENTIAL_TESTS=1 AND the Rust binary must exist.
When skipped, does so cleanly so normal `uv run pytest` is unaffected.

The differential loop (RFC §2c — tier-2 "unsatisfiable semantic"):
  1. Hypothesis generates an unsatisfiable FixtureSpec via unsatisfiable_graph_st().
     The spec is produced by construction-by-known-conflict: two dependency paths
     impose disjoint constraints on a shared package C, making the intersection empty.
  2. Serialize the FixtureSpec to a fresh temp dir.
  3. Run BOTH impls (subprocess, black-box) via run_all_impls().
  4. Assert cross-impl agreement: agreement() is None.
  5. Assert conflict oracle: conflict_oracle() is None (both emit SOLVE-CONFLICT).

The conflict oracle (RFC §2c) is stronger than agreement: it asserts the specific
SOLVE-CONFLICT outcome, not just that the impls agree. "Both wrong the same way"
(e.g., both emit FETCH-MOCK-MISSING masking the real conflict) would pass agreement
but fail the conflict oracle.

Settings: max_examples=30, deadline=None (subprocess-heavy).
"""

from __future__ import annotations

# Trigger the bridge (repo-root -> sys.path) before any harness import.
import differential  # noqa: F401

import os
import shutil
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings

from differential.loop import (
    ConflictOracleFailure,
    _exit_class,
    agreement,
    conflict_oracle,
    run_all_impls,
)
from differential.strategies import ConflictWitness, unsatisfiable_graph_st
from harness.descriptors import build_descriptors
from harness.spec import FixtureSpec, serialize

# ---------------------------------------------------------------------------
# Gate condition
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
_RUST_BIN = _REPO_ROOT / "impls" / "rust" / "target" / "release" / "milpa"

_DIFFERENTIAL_ENABLED = os.environ.get("MILPA_DIFFERENTIAL_TESTS") == "1"
_RUST_BIN_PRESENT = _RUST_BIN.exists()

_SKIP_REASON = (
    "set MILPA_DIFFERENTIAL_TESTS=1 (and ensure impls/rust/target/release/milpa exists) "
    "to run cross-impl differential tests"
    if not _RUST_BIN_PRESENT
    else "set MILPA_DIFFERENTIAL_TESTS=1 to run cross-impl differential tests"
)

pytestmark = pytest.mark.skipif(
    not (_DIFFERENTIAL_ENABLED and _RUST_BIN_PRESENT),
    reason=_SKIP_REASON,
)

# ---------------------------------------------------------------------------
# Descriptors (built once for the module)
# ---------------------------------------------------------------------------

_DESCRIPTORS = build_descriptors(_REPO_ROOT)


# ---------------------------------------------------------------------------
# Tier-2 unsatisfiable differential test
# ---------------------------------------------------------------------------

@given(unsatisfiable_graph_st())
@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_tier2_unsatisfiable_semantic(
    spec_and_witness: tuple[FixtureSpec, ConflictWitness],
) -> None:
    """Both impls must exit 1 with SOLVE-CONFLICT on every unsatisfiable graph.

    Two assertions for each generated unsatisfiable graph:
      A. Cross-impl agreement: both impls exit 1 with the same slug.
      B. Conflict oracle: both impls emit SOLVE-CONFLICT specifically —
         not a parse/fetch/index error masking the conflict.

    On Hypothesis failure the assertion message includes:
      - The conflict witness (which package, which constraint pair)
      - The minimized FixtureSpec (manifest, deps, index, constraints)
      - Per-impl: returncode, exit_class, slug, stderr
      - The specific divergence or oracle violation
    """
    spec, witness = spec_and_witness
    tmp_dir = Path(tempfile.mkdtemp(prefix="milpa-diff-t2-unsat-"))
    try:
        serialize(spec, tmp_dir)
        results = run_all_impls(tmp_dir, _DESCRIPTORS, timeout=60)

        # ---------------------------------------------------------------
        # Build shared diagnostic prefix.
        # ---------------------------------------------------------------
        def _witness_summary() -> str:
            lines = ["", "=== Conflict Witness ==="]
            lines.append(f"conflicting package: {witness.package!r}")
            lines.append(f"constraint A (from {witness.imposer_a!r}): {witness.constraint_a!r}")
            lines.append(f"constraint B (from {witness.imposer_b!r}): {witness.constraint_b!r}")
            lines.append(f"reason: {witness.reason}")
            return "\n".join(lines)

        def _spec_summary() -> str:
            lines = ["", "=== Generated FixtureSpec (unsatisfiable) ==="]
            lines.append(f"packages: {[row.name for row in spec.index_rows]}")
            for row in spec.index_rows:
                vers = [ve.version for ve in row.versions]
                lines.append(f"  {row.name}: versions={vers}")
            lines.append("root deps:")
            for dep in spec.deps:
                if dep.is_named:
                    lines.append(f"  {dep.name!r} constraint={dep.constraint!r}")
            lines.append("DAG edges (from solution version .nimble requires):")
            for (url, ref), (pkg_name, entry) in spec.index_fetch_map.items():
                if entry.nimble_text:
                    import re as _re
                    for m in _re.finditer(
                        r'requires\s+"([^"]+)"', entry.nimble_text
                    ):
                        lines.append(f"  {pkg_name} ({ref}) -> {m.group(1)!r}")
            return "\n".join(lines)

        def _impl_summary() -> str:
            lines = ["", "Per-impl outcomes:"]
            for impl_name, result in results.items():
                lines.append(
                    f"  {impl_name}: rc={result.returncode} "
                    f"class={_exit_class(result)!r} "
                    f"slug={result.slug!r}"
                )
                if result.stderr.strip():
                    last = result.stderr.strip().splitlines()[-8:]
                    lines.append(f"    stderr (last {len(last)} lines):")
                    for ln in last:
                        lines.append(f"      {ln}")
            return "\n".join(lines)

        # ---------------------------------------------------------------
        # Assertion A: cross-impl agreement
        # ---------------------------------------------------------------
        div = agreement(
            results, fixture_id=f"tier2-unsat:{tmp_dir.name}", cmd="resolve"
        )
        if div is not None:
            assert False, "\n".join([
                "",
                "=== DIFFERENTIAL DIVERGENCE (tier-2 unsatisfiable) ===",
                _witness_summary(),
                _spec_summary(),
                _impl_summary(),
                "",
                "Divergence JSON:",
                div.to_json(),
                "=== END DIVERGENCE ===",
            ])

        # ---------------------------------------------------------------
        # Assertion B: conflict oracle — both must emit SOLVE-CONFLICT
        # ---------------------------------------------------------------
        oracle_fail = conflict_oracle(results)
        if oracle_fail is not None:
            assert False, "\n".join([
                "",
                "=== CONFLICT ORACLE FAILURE (tier-2 unsatisfiable) ===",
                _witness_summary(),
                _spec_summary(),
                _impl_summary(),
                "",
                oracle_fail.summary(),
                "=== END ORACLE FAILURE ===",
            ])

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
