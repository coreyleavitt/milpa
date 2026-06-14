"""Tier-2 satisfiable semantic differential test — gated.

Gate: MILPA_DIFFERENTIAL_TESTS=1 AND the Rust binary must exist.
When skipped, does so cleanly so normal `uv run pytest` is unaffected.

The differential loop (RFC §2c — tier-2 "satisfiable semantic"):
  1. Hypothesis generates a satisfiable FixtureSpec via satisfiable_graph_st().
     The spec is produced by construction-by-known-solution: every constraint
     is guaranteed to be satisfied by the chosen solution version.
  2. Serialize the FixtureSpec to a fresh temp dir (manifest + index + fetches).
  3. Run BOTH impls (subprocess, black-box) via run_all_impls().
  4. Assert cross-impl agreement: agreement() is None.
  5. Assert structural oracle for EACH impl independently: structural_oracle()
     is None for both.

The structural oracle (RFC §2c "Tier-2 oracle is structural post-hoc
verification, not cross-impl agreement") catches bugs where both impls are
wrong the same way — something cross-impl agreement alone cannot detect.

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
    OracleFailure,
    _exit_class,
    agreement,
    run_all_impls,
    structural_oracle,
)
from differential.strategies import satisfiable_graph_st
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
# Tier-2 differential test
# ---------------------------------------------------------------------------

@given(satisfiable_graph_st())
@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_tier2_satisfiable_semantic(spec: FixtureSpec) -> None:
    """All impls must succeed and their locks must satisfy the structural oracle.

    Two assertions for each generated satisfiable graph:
      A. Cross-impl agreement: both impls exit 0 and agree on success.
      B. Structural oracle for each impl independently: the produced lock
         contains every required dep at a version satisfying all constraints.

    On Hypothesis failure the assertion message includes:
      - The minimized FixtureSpec (manifest, deps, index, constraints)
      - Per-impl: returncode, exit_class, slug, locked deps
      - The specific divergence or oracle violation
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="milpa-diff-t2-"))
    results: dict = {}
    try:
        serialize(spec, tmp_dir)
        results = run_all_impls(tmp_dir, _DESCRIPTORS, timeout=60)

        # ---------------------------------------------------------------
        # Build a shared diagnostic prefix for both checks.
        # ---------------------------------------------------------------
        def _spec_summary() -> str:
            lines = ["", "=== Generated FixtureSpec ==="]
            lines.append(f"packages: {[row.name for row in spec.index_rows]}")
            for row in spec.index_rows:
                vers = [ve.version for ve in row.versions]
                lines.append(f"  {row.name}: versions={vers}")
            lines.append(f"root deps:")
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
                if result.returncode == 0:
                    lock_path = Path(result.scratch_dir) / "milpa.lock"
                    if lock_path.exists():
                        from differential.loop import _parse_lock_deps
                        locked = _parse_lock_deps(lock_path.read_text())
                        lines.append(f"    locked: {locked}")
                if result.stderr.strip():
                    last = result.stderr.strip().splitlines()[-5:]
                    lines.append(f"    stderr (last {len(last)} lines):")
                    for ln in last:
                        lines.append(f"      {ln}")
            return "\n".join(lines)

        # ---------------------------------------------------------------
        # Assertion A: cross-impl agreement (both succeed, same exit class)
        # ---------------------------------------------------------------
        div = agreement(results, fixture_id=f"tier2:{tmp_dir.name}", cmd="resolve")
        if div is not None:
            assert False, "\n".join([
                "",
                "=== DIFFERENTIAL DIVERGENCE (tier-2 satisfiable) ===",
                _spec_summary(),
                _impl_summary(),
                "",
                "Divergence JSON:",
                div.to_json(),
                "=== END DIVERGENCE ===",
            ])

        # ---------------------------------------------------------------
        # Assertion B: structural oracle for each impl independently
        # ---------------------------------------------------------------
        oracle_failures: list[OracleFailure] = []
        for impl_name, result in results.items():
            failure = structural_oracle(spec, result)
            if failure is not None:
                oracle_failures.append(failure)

        if oracle_failures:
            failure_lines = []
            for f in oracle_failures:
                failure_lines.append(f.summary())
            assert False, "\n".join([
                "",
                "=== ORACLE FAILURE (tier-2 satisfiable) ===",
                _spec_summary(),
                _impl_summary(),
                "",
                "Oracle violations:",
            ] + failure_lines + ["=== END ORACLE FAILURE ==="])

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        for run_result in results.values():
            run_result.cleanup()
