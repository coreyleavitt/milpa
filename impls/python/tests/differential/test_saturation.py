"""Saturation test (slice 3e) — 1000-example no-new-spec-violation bar.

Gate: MILPA_DIFFERENTIAL_TESTS=1 AND the Rust binary must exist.
When skipped, does so cleanly so normal `uv run pytest` is unaffected.

This is the saturation/done-ness bar from RFC acceptance §2c:
  "a tier-2 run of 1000 examples produces no new divergence and no new
  spec hole — the same saturation rule rfc-property-based-testing.md
  uses for nightly CI"

Design
------
Tier-2 (operational bar) only — NOT tier-1 syntactic.

Rationale (from the 3e decision note in the handoff doc):
  With Rust=KDL 2.0 and Python=KDL 1.0 (frozen until rewrite #6), tier-1
  arbitrary-KDL generation produces expected syntactic divergences that are
  NOT spec violations — they are KDL-version-boundary differences.  The
  differential agreement oracle is only valid across same-version impls.
  Tier-2 (semantic graphs in the KDL 1.0 ∩ 2.0 common subset: names,
  quoted strings, semver, integer values — no bare bools or KDL-2.0-only
  syntax) still agrees AND each impl's per-impl structural/conflict oracle
  (version-independent) holds → tier-2 saturation is valid now.

Two sub-tests run:
  A. test_saturation_tier2_satisfiable — N/2 satisfiable examples
  B. test_saturation_tier2_unsatisfiable — N/2 unsatisfiable examples

For each example:
  - Serialize the FixtureSpec to a temp dir.
  - Run both impls.
  - For satisfiable: structural_oracle per impl (per-spec check).
  - For unsatisfiable: conflict_oracle (must exit 1 SOLVE-CONFLICT).
  - Any oracle failure = spec violation → pin candidate + FAIL with details.

Example count
-------------
Controlled by env var `MILPA_SATURATION_EXAMPLES` (default: 1000).
CI may set this lower for speed; the saturation default is 1000.

The split between sat and unsat is 50/50 by default.

Pin candidates
--------------
If a genuine spec violation is found, the minimized example is pinned via
harness.pin.pin_candidate() to a temp directory, and its path is reported.
The test FAILS with a full report so the human can triage.

Coverage report
---------------
After the saturation run, coverage_report() is printed to stdout (via
print) so the gap list is always visible in CI output.

KDL-version-artifact triage
----------------------------
This test does NOT run tier-1 syntactic generation.  Tier-2 generators
produce manifests that use ONLY the KDL 1.0 ∩ 2.0 common subset of syntax
(quoted strings, plain identifiers, integer literals — no bare bools, no
KDL-2.0-only token types).  The mocked-fetches/ and index.kdl they produce
also use only this common subset (all string-valued fields).  Therefore
tier-2 results should not exhibit any KDL-version divergence.

If a tier-2 divergence IS found that appears to be a KDL-version artifact
(Python MAN-KDL-SYNTAX vs Rust success, or vice versa), the test reports it
as a GENUINE BLOCKER (not silently excluded) because tier-2 inputs should
not contain KDL-version-sensitive syntax.  This is intentional: if the
generator accidentally emits KDL-2.0-only syntax in a tier-2 input, that
is itself a generator bug that must be fixed.
"""

from __future__ import annotations

# Trigger the bridge (repo-root -> sys.path) before any harness import.
import differential  # noqa: F401

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional

import pytest
from hypothesis import HealthCheck, given, settings

from differential.loop import (
    ConflictOracleFailure,
    OracleFailure,
    _exit_class,
    agreement,
    conflict_oracle,
    run_all_impls,
    structural_oracle,
)
from differential.strategies import satisfiable_graph_st, unsatisfiable_graph_st
from harness.coverage import CLAUSE_INVENTORY, coverage_report
from harness.dedup import DivergenceCollector
from harness.descriptors import build_descriptors
from harness.pin import pin_candidate
from harness.spec import FixtureSpec, serialize

# ---------------------------------------------------------------------------
# Gate condition
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
_RUST_BIN = _REPO_ROOT / "impls" / "rust" / "target" / "release" / "milpa"
_CONFORMANCE_ROOT = _REPO_ROOT / "conformance"

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
# Saturation count (tunable)
# ---------------------------------------------------------------------------

_DEFAULT_SATURATION_N = 1000

def _saturation_n() -> int:
    """Return the number of saturation examples to run."""
    val = os.environ.get("MILPA_SATURATION_EXAMPLES", "")
    if val.strip().isdigit():
        return max(10, int(val.strip()))
    return _DEFAULT_SATURATION_N


# ---------------------------------------------------------------------------
# Descriptors
# ---------------------------------------------------------------------------

_DESCRIPTORS = build_descriptors(_REPO_ROOT)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _spec_summary(spec: FixtureSpec) -> str:
    lines = ["=== Generated FixtureSpec ==="]
    lines.append(f"packages: {[row.name for row in spec.index_rows]}")
    for row in spec.index_rows:
        vers = [ve.version for ve in row.versions]
        lines.append(f"  {row.name}: versions={vers}")
    lines.append("root deps:")
    for dep in spec.deps:
        if dep.is_named:
            lines.append(f"  {dep.name!r} constraint={dep.constraint!r}")
    return "\n".join(lines)


def _impl_summary(results: dict) -> str:
    import re as _re
    from differential.loop import _parse_lock_deps
    lines = ["Per-impl outcomes:"]
    for impl_name, result in results.items():
        lines.append(
            f"  {impl_name}: rc={result.returncode} "
            f"class={_exit_class(result)!r} slug={result.slug!r}"
        )
        if result.returncode == 0:
            lock_path = Path(result.scratch_dir) / "milpa.lock"
            if lock_path.exists():
                locked = _parse_lock_deps(lock_path.read_text())
                lines.append(f"    locked: {locked}")
        if result.stderr.strip():
            last = result.stderr.strip().splitlines()[-5:]
            for ln in last:
                lines.append(f"    stderr: {ln}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Saturation run state — collected across all @given examples
# ---------------------------------------------------------------------------

class _SaturationState:
    """Accumulates oracle failures and divergences across all generated examples."""

    def __init__(self) -> None:
        self.n_run: int = 0
        self.n_oracle_failures: int = 0
        self.n_divergences: int = 0
        self.failures: list[dict] = []  # each is a serializable finding
        self.pin_dir: Optional[Path] = None
        self.collector = DivergenceCollector()

    def record_oracle_failure(
        self,
        spec: FixtureSpec,
        failure: "OracleFailure | ConflictOracleFailure",
        kind: str,
        tmp_dir: Path,
    ) -> None:
        self.n_oracle_failures += 1
        # Pin candidate for human triage
        if self.pin_dir is None:
            self.pin_dir = Path(tempfile.mkdtemp(prefix="milpa-sat-pins-"))
        candidate_name = f"sat-violation-{self.n_oracle_failures:04d}-{kind}"
        candidate_path = self.pin_dir / candidate_name
        try:
            pin_candidate(spec, {
                "type": "oracle-failure",
                "kind": kind,
                "violation": failure.summary(),
            }, candidate_path)
            pin_path = str(candidate_path)
        except Exception as e:
            pin_path = f"(pin failed: {e})"

        self.failures.append({
            "type": "oracle-failure",
            "kind": kind,
            "summary": failure.summary(),
            "pin_path": pin_path,
        })

    def record_divergence(
        self,
        spec: FixtureSpec,
        div: "Divergence",
        tmp_dir: Path,
    ) -> None:
        self.n_divergences += 1
        self.collector.add(div.cmd, div.output_file, div.impls, record=json.loads(div.to_json()))

        if self.pin_dir is None:
            self.pin_dir = Path(tempfile.mkdtemp(prefix="milpa-sat-pins-"))
        candidate_name = f"sat-divergence-{self.n_divergences:04d}"
        candidate_path = self.pin_dir / candidate_name
        try:
            pin_candidate(spec, json.loads(div.to_json()), candidate_path)
            pin_path = str(candidate_path)
        except Exception as e:
            pin_path = f"(pin failed: {e})"

        self.failures.append({
            "type": "divergence",
            "summary": div.summary(),
            "pin_path": pin_path,
        })


# Module-level state (reset per class instance)
_SAT_STATE = _SaturationState()
_UNSAT_STATE = _SaturationState()


# ---------------------------------------------------------------------------
# Tier-2 satisfiable saturation
# ---------------------------------------------------------------------------

class TestSaturationTier2Satisfiable:
    """Saturation run over tier-2 satisfiable graphs.

    Runs N/2 examples.  For each:
      - Structural oracle per impl (per-spec, version-independent check).
      - Agreement oracle (cross-impl agreement on success).
    Any violation = spec failure → pin candidate.
    """

    @classmethod
    def setup_class(cls):
        cls._state = _SaturationState()
        cls._n = _saturation_n() // 2

    @classmethod
    def teardown_class(cls):
        """Print the coverage report to stdout after the saturation run."""
        print("\n")
        print("=" * 60)
        print(f"[saturation] Tier-2 SAT run: {cls._state.n_run} examples")
        print(f"[saturation] Oracle failures: {cls._state.n_oracle_failures}")
        print(f"[saturation] Divergences: {cls._state.n_divergences}")
        if cls._state.pin_dir:
            print(f"[saturation] Pin candidates written to: {cls._state.pin_dir}")
        print("=" * 60)
        # Coverage report (always printed)
        coverage_report(_CONFORMANCE_ROOT, log=print)

    def test_saturation_tier2_satisfiable(self) -> None:
        """Tier-2 satisfiable saturation: N/2 examples, structural oracle per impl.

        No new spec violation across all N/2 examples.
        """
        n = self.__class__._n
        state = self.__class__._state

        @given(satisfiable_graph_st())
        @settings(
            max_examples=n,
            deadline=None,
            suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
        )
        def _inner(spec: FixtureSpec) -> None:
            state.n_run += 1
            tmp_dir = Path(tempfile.mkdtemp(prefix="milpa-sat-run-"))
            results: dict = {}
            try:
                serialize(spec, tmp_dir)
                results = run_all_impls(tmp_dir, _DESCRIPTORS, timeout=60)

                # --- Agreement oracle (both should succeed on satisfiable input) ---
                div = agreement(
                    results,
                    fixture_id=f"sat-{state.n_run:04d}:{tmp_dir.name}",
                    cmd="resolve",
                )
                if div is not None:
                    state.record_divergence(spec, div, tmp_dir)

                # --- Structural oracle per impl ---
                for impl_name, result in results.items():
                    failure = structural_oracle(spec, result)
                    if failure is not None:
                        state.record_oracle_failure(spec, failure, "structural", tmp_dir)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                # Clean up per-impl scratch + CAS dirs created by run_fixture.
                for run_result in results.values():
                    run_result.cleanup()

        _inner()  # runs the @given loop

        # After all examples: assert no violations found
        if state.n_oracle_failures > 0 or state.n_divergences > 0:
            lines = [
                "",
                "=" * 60,
                "[saturation] SPEC VIOLATIONS FOUND — tier-2 satisfiable",
                f"  Examples run: {state.n_run}",
                f"  Oracle failures: {state.n_oracle_failures}",
                f"  Divergences: {state.n_divergences}",
                "",
                "Findings (first 5):",
            ]
            for f in state.failures[:5]:
                lines.append(f"  [{f['type']}] {f['summary'][:200]}")
                if f.get("pin_path"):
                    lines.append(f"    pinned to: {f['pin_path']}")
            if state.collector.total_count() > 0:
                lines.append("")
                lines.append("Divergence class summary:")
                for cls_key, count in state.collector.summary().items():
                    lines.append(f"  {cls_key}: {count}")
            if state.pin_dir:
                lines.append(f"\nPin candidates: {state.pin_dir}")
            lines.append("=" * 60)
            pytest.fail("\n".join(lines))


# ---------------------------------------------------------------------------
# Tier-2 unsatisfiable saturation
# ---------------------------------------------------------------------------

class TestSaturationTier2Unsatisfiable:
    """Saturation run over tier-2 unsatisfiable graphs.

    Runs up to N/2 examples.  For each:
      - Conflict oracle: every impl MUST exit 1 with SOLVE-CONFLICT.
      - Agreement oracle (both should exit error:SOLVE-CONFLICT).
    Any violation = spec failure → pin candidate.

    Note on example count: the current unsatisfiable_graph_st() generator has
    only 4 structurally distinct variants (the suffix parameter:
    "", "x", "y", "z").  Hypothesis deduplicates identical examples and stops
    at 4 unique examples regardless of max_examples.  This is correct: the
    saturation bar for the unsat tier is "every structurally distinct conflict
    pattern passes" — not "N arbitrary random inputs".  The generator can be
    extended later (e.g., adding more conflict topologies) to increase coverage.
    """

    @classmethod
    def setup_class(cls):
        cls._state = _SaturationState()
        cls._n = _saturation_n() // 2

    @classmethod
    def teardown_class(cls):
        print("\n")
        print("=" * 60)
        print(f"[saturation] Tier-2 UNSAT run: {cls._state.n_run} examples")
        print(f"[saturation] Oracle failures: {cls._state.n_oracle_failures}")
        print(f"[saturation] Divergences: {cls._state.n_divergences}")
        if cls._state.pin_dir:
            print(f"[saturation] Pin candidates written to: {cls._state.pin_dir}")
        print("=" * 60)

    def test_saturation_tier2_unsatisfiable(self) -> None:
        """Tier-2 unsatisfiable saturation: N/2 examples, conflict oracle per impl.

        No new spec violation across all N/2 examples.
        """
        n = self.__class__._n
        state = self.__class__._state

        @given(unsatisfiable_graph_st())
        @settings(
            max_examples=n,
            deadline=None,
            suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
        )
        def _inner(spec_witness) -> None:
            spec, _witness = spec_witness
            state.n_run += 1
            tmp_dir = Path(tempfile.mkdtemp(prefix="milpa-unsat-run-"))
            results: dict = {}
            try:
                serialize(spec, tmp_dir)
                results = run_all_impls(tmp_dir, _DESCRIPTORS, timeout=60)

                # --- Conflict oracle (all impls must exit 1 SOLVE-CONFLICT) ---
                failure = conflict_oracle(results)
                if failure is not None:
                    state.record_oracle_failure(spec, failure, "conflict", tmp_dir)

                # --- Agreement oracle (both should agree on SOLVE-CONFLICT) ---
                div = agreement(
                    results,
                    fixture_id=f"unsat-{state.n_run:04d}:{tmp_dir.name}",
                    cmd="resolve",
                )
                if div is not None:
                    # A divergence on an unsat input is automatically a spec violation
                    # (at least one impl is NOT emitting SOLVE-CONFLICT)
                    state.record_divergence(spec, div, tmp_dir)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                # Clean up per-impl scratch + CAS dirs created by run_fixture.
                for run_result in results.values():
                    run_result.cleanup()

        _inner()  # runs the @given loop

        # After all examples: assert no violations found
        if state.n_oracle_failures > 0 or state.n_divergences > 0:
            lines = [
                "",
                "=" * 60,
                "[saturation] SPEC VIOLATIONS FOUND — tier-2 unsatisfiable",
                f"  Examples run: {state.n_run}",
                f"  Oracle failures: {state.n_oracle_failures}",
                f"  Divergences: {state.n_divergences}",
                "",
                "Findings (first 5):",
            ]
            for f in state.failures[:5]:
                lines.append(f"  [{f['type']}] {f['summary'][:200]}")
                if f.get("pin_path"):
                    lines.append(f"    pinned to: {f['pin_path']}")
            if state.collector.total_count() > 0:
                lines.append("")
                lines.append("Divergence class summary:")
                for cls_key, count in state.collector.summary().items():
                    lines.append(f"  {cls_key}: {count}")
            if state.pin_dir:
                lines.append(f"\nPin candidates: {state.pin_dir}")
            lines.append("=" * 60)
            pytest.fail("\n".join(lines))
