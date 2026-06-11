"""Seeded-divergence test — slice 3d acceptance test.

Gate: MILPA_DIFFERENTIAL_TESTS=1 AND the Rust binary must exist.
When skipped, does so cleanly so normal `uv run pytest` is unaffected.

Acceptance criteria (RFC acceptance):
  "A seeded divergence (deliberately broken impl) is detected and reported
  with the diverging fixture and the per-impl outputs"
  "A generated counterexample flows shrink → pin → corpus"

Design: the broken impl is a hermetic wrapper shim written to a tmp dir by the
test itself. The shim always exits 0 (pretending to succeed) regardless of the
input. On an unsatisfiable fixture the real impls correctly exit 1 with
SOLVE-CONFLICT; the broken shim exits 0 — a guaranteed divergence.

The seam is clean:
  - The shim is a tiny Python script that does `import sys; sys.exit(0)`
  - It is written to a tempfile during test setup and cleaned up after
  - No committed file is modified; no real impl is touched
  - The broken descriptor's argv points at the shim, not the real Python impl

Flow:
  1. Build descriptors: [real python, real rust, broken shim]
  2. Use hypothesis.find(unsatisfiable_graph_st(), ...) to find the MINIMAL
     unsatisfiable FixtureSpec where the broken shim diverges from the real impls.
  3. Assert the divergence is detected by agreement().
  4. Assert pin_candidate() writes a candidate dir with inputs + divergence.json,
     NO expected/.
  5. Assert the candidate dir is well-formed.
"""

from __future__ import annotations

# Trigger the bridge (repo-root -> sys.path) before any harness import.
import differential  # noqa: F401

import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

import pytest
from hypothesis import find, settings, HealthCheck

from differential.loop import Divergence, agreement, run_all_impls
from differential.strategies import satisfiable_graph_st, unsatisfiable_graph_st
from harness.dedup import DivergenceCollector, behavioral_class
from harness.descriptors import ImplDescriptor, build_descriptors
from harness.pin import pin_candidate
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

_REAL_DESCRIPTORS = build_descriptors(_REPO_ROOT)


# ---------------------------------------------------------------------------
# Broken-impl shim construction (hermetic)
# ---------------------------------------------------------------------------

def _write_broken_shim(dest: Path) -> Path:
    """Write a broken impl shim script to dest/.

    The shim is a Python script that always exits 0, ignoring all inputs.
    When run against an unsatisfiable fixture, the real impls exit 1 with
    SOLVE-CONFLICT; the shim exits 0 → guaranteed divergence.

    Returns the path to the shim script (dest/broken_shim.py).
    """
    shim_path = dest / "broken_shim.py"
    shim_path.write_text(
        "#!/usr/bin/env python3\n"
        "# Seeded broken impl — always exits 0 (ignores all inputs).\n"
        "# This shim exists ONLY for the seeded divergence acceptance test.\n"
        "import sys\n"
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    # Make executable
    shim_path.chmod(shim_path.stat().st_mode | stat.S_IEXEC)
    return shim_path


def _broken_descriptor(shim_path: Path) -> ImplDescriptor:
    """Return an ImplDescriptor for the broken shim."""
    return ImplDescriptor(
        name="broken",
        argv=[sys.executable, str(shim_path)],
        cwd=None,
        env={},
        known_failing=set(),
        invoke_via="Direct",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _runs_diverge_with_broken(spec: FixtureSpec, descriptors: list[ImplDescriptor]) -> bool:
    """Return True if the broken impl diverges from the real impls on this spec.

    Serializes spec to a temp dir, runs all impls, returns whether any divergence
    is detected.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="milpa-seeded-check-"))
    try:
        serialize(spec, tmp_dir)
        results = run_all_impls(tmp_dir, descriptors, timeout=60)
        div = agreement(results, fixture_id=f"seeded-check:{tmp_dir.name}", cmd="resolve")
        return div is not None
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Main acceptance test
# ---------------------------------------------------------------------------

class TestSeededDivergence:
    """End-to-end seeded divergence: detect → shrink → pin."""

    def setup_method(self):
        """Create a temp dir for the shim and candidate output."""
        self._shim_dir = Path(tempfile.mkdtemp(prefix="milpa-shim-"))
        self._candidate_dir = Path(tempfile.mkdtemp(prefix="milpa-candidate-"))

    def teardown_method(self):
        """Clean up temp dirs."""
        shutil.rmtree(self._shim_dir, ignore_errors=True)
        shutil.rmtree(self._candidate_dir, ignore_errors=True)

    def test_seeded_divergence_detect_shrink_pin(self):
        """Full flow: broken impl → detect divergence → shrink → pin candidate.

        Step 1: Build descriptors including the broken shim.
        Step 2: Use hypothesis.find() to get the MINIMAL unsatisfiable FixtureSpec
                where the broken shim diverges from the real impls.
        Step 3: Assert agreement() detects the divergence.
        Step 4: Assert pin_candidate() writes a well-formed candidate dir.
        Step 5: Assert candidate has inputs + divergence.json, NO expected/.
        """
        # --- Step 1: Build descriptors ---
        shim_path = _write_broken_shim(self._shim_dir)
        broken_desc = _broken_descriptor(shim_path)
        all_descriptors = _REAL_DESCRIPTORS + [broken_desc]

        # --- Step 2: Find minimal diverging FixtureSpec via hypothesis.find() ---
        # hypothesis.find() returns the smallest example satisfying the predicate.
        # predicate: the broken shim diverges from the real impls on this spec.
        # We use the unsatisfiable generator: real impls → SOLVE-CONFLICT (exit 1),
        # broken shim → exit 0 → guaranteed divergence.

        @settings(max_examples=20, deadline=None,
                  suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
        def _find_minimal():
            # hypothesis.find() applies Hypothesis shrinking internally,
            # returning the minimal example passing the predicate.
            minimal_spec_and_witness = find(
                unsatisfiable_graph_st(),
                lambda spec_witness: _runs_diverge_with_broken(
                    spec_witness[0], all_descriptors
                ),
                settings=settings(
                    max_examples=20,
                    deadline=None,
                    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
                ),
            )
            return minimal_spec_and_witness

        minimal_spec_witness = _find_minimal()
        minimal_spec, witness = minimal_spec_witness

        # --- Step 3: Assert divergence is detected ---
        # Run the minimal spec through all impls and assert divergence.
        fixture_dir = Path(tempfile.mkdtemp(prefix="milpa-seeded-min-"))
        try:
            serialize(minimal_spec, fixture_dir)
            results = run_all_impls(fixture_dir, all_descriptors, timeout=60)
            div = agreement(
                results,
                fixture_id=f"seeded-minimal:{fixture_dir.name}",
                cmd="resolve",
            )
        finally:
            shutil.rmtree(fixture_dir, ignore_errors=True)

        assert div is not None, (
            "Expected divergence on seeded unsatisfiable fixture: broken shim (exit 0) "
            "should disagree with real impls (exit 1 SOLVE-CONFLICT). "
            f"Results: { {k: v.returncode for k, v in results.items()} }"
        )

        # The broken impl should show as "success" (exit 0)
        assert div.impls.get("broken") == "success", (
            f"Expected broken impl = 'success', got: {div.impls.get('broken')!r}"
        )
        # The real impls should show as "error:SOLVE-CONFLICT"
        for real_impl in ["python", "rust"]:
            assert div.impls.get(real_impl) == "error:SOLVE-CONFLICT", (
                f"Expected {real_impl} = 'error:SOLVE-CONFLICT', "
                f"got: {div.impls.get(real_impl)!r}"
            )

        # --- Step 4: Pin the candidate ---
        div_record = json.loads(div.to_json())
        candidate_path = self._candidate_dir / "pin-seeded-001"
        pin_candidate(minimal_spec, div_record, candidate_path)

        # --- Step 5: Assert candidate well-formedness ---
        # (a) Fixture inputs present
        assert (candidate_path / "cmd").exists(), "cmd file not written to candidate"
        assert (candidate_path / "milpa.kdl").exists(), "milpa.kdl not written to candidate"
        assert (candidate_path / "mocked-fetches").exists(), \
            "mocked-fetches/ not written to candidate"

        # (b) divergence.json present and correct shape
        div_json_path = candidate_path / "divergence.json"
        assert div_json_path.exists(), "divergence.json not written to candidate"
        parsed_div = json.loads(div_json_path.read_text(encoding="utf-8"))
        assert "fixture" in parsed_div, "divergence.json missing 'fixture'"
        assert "cmd" in parsed_div, "divergence.json missing 'cmd'"
        assert "output_file" in parsed_div, "divergence.json missing 'output_file'"
        assert "impls" in parsed_div, "divergence.json missing 'impls'"
        assert "broken" in parsed_div["impls"], "divergence.json missing 'broken' impl"

        # (c) expected/ NOT present — human verification required
        assert not (candidate_path / "expected").exists(), \
            "expected/ must NOT be written to pin candidate"

        # (d) The witness package is named in the milpa.kdl deps
        kdl_text = (candidate_path / "milpa.kdl").read_text()
        # The unsatisfiable fixture has pkga + pkgb as root deps
        # Both should appear in the serialized manifest
        assert "deps {" in kdl_text, "milpa.kdl should have a deps block"

        # Print the candidate dir listing for verification (visible in test output)
        print("\n=== Pin candidate dir listing ===")
        for entry in sorted(candidate_path.rglob("*")):
            rel = entry.relative_to(candidate_path)
            print(f"  {rel}")
        print("=== divergence.json contents ===")
        print(div_json_path.read_text())
        print("=== witness ===")
        print(f"  conflict package: {witness.package!r}")
        print(f"  constraint_a: {witness.constraint_a!r} (from {witness.imposer_a!r})")
        print(f"  constraint_b: {witness.constraint_b!r} (from {witness.imposer_b!r})")
        print(f"  reason: {witness.reason}")


class TestDedupWithSeededDivergences:
    """DivergenceCollector deduplication with synthetic divergences (no impl needed).

    This validates that N same-shape divergences collapse to 1 class with count N.
    No real impls are invoked — this is a pure unit test of the dedup logic.
    """

    def test_dedup_collapses_n_same_shape_to_1_class(self):
        """N divergences of the same shape → 1 class with count N."""
        collector = DivergenceCollector()

        # Simulate 7 divergences of the same behavioral class:
        # broken exits 0, real impls exit SOLVE-CONFLICT
        impls = {
            "python": "error:SOLVE-CONFLICT",
            "rust": "error:SOLVE-CONFLICT",
            "broken": "success",
        }
        for i in range(7):
            record = {
                "fixture": f"generated-{i:03d}",
                "cmd": "resolve",
                "output_file": "error-slug",
                "impls": impls,
            }
            collector.add("resolve", "error-slug", impls, record=record)

        assert len(collector) == 1, f"Expected 1 class, got {len(collector)}"
        assert collector.total_count() == 7, f"Expected 7 total, got {collector.total_count()}"

        summary = collector.summary()
        assert len(summary) == 1
        count = list(summary.values())[0]
        assert count == 7, f"Expected class count=7, got {count}"

        records = collector.records()
        assert len(records) == 1
        # The representative is the FIRST one
        assert records[0]["fixture"] == "generated-000"

    def test_dedup_separates_different_shapes(self):
        """Divergences with different behavioral shapes stay in separate classes."""
        collector = DivergenceCollector()

        # Class A: broken exits 0, real impls exit SOLVE-CONFLICT
        impls_a = {"python": "error:SOLVE-CONFLICT", "broken": "success"}
        # Class B: broken crashes, real impl exits SOLVE-CONFLICT
        impls_b = {"python": "error:SOLVE-CONFLICT", "broken": "crash"}
        # Class C: same cmd but different output_file
        impls_c = {"python": "error:SOLVE-CONFLICT", "broken": "success"}

        for _ in range(3):
            collector.add("resolve", "error-slug", impls_a,
                          record={"fixture": "x", "cmd": "resolve",
                                  "output_file": "error-slug", "impls": impls_a})
        for _ in range(2):
            collector.add("resolve", "error-slug", impls_b,
                          record={"fixture": "y", "cmd": "resolve",
                                  "output_file": "error-slug", "impls": impls_b})
        # Same impls as A but different output_file → different class
        for _ in range(5):
            collector.add("resolve", "milpa.lock", impls_c,
                          record={"fixture": "z", "cmd": "resolve",
                                  "output_file": "milpa.lock", "impls": impls_c})

        assert len(collector) == 3, f"Expected 3 classes, got {len(collector)}"
        assert collector.total_count() == 10

        summary = collector.summary()
        counts = sorted(summary.values())
        assert counts == [2, 3, 5], f"Expected counts [2, 3, 5], got {counts}"

    def test_emit_summary_before_findings(self):
        """emit() puts summary first, then findings — the §2e ordering."""
        collector = DivergenceCollector()

        impls = {"python": "error:SOLVE-CONFLICT", "broken": "success"}
        for i in range(4):
            record = {
                "fixture": f"f-{i}",
                "cmd": "resolve",
                "output_file": "error-slug",
                "impls": impls,
            }
            collector.add("resolve", "error-slug", impls, record=record)

        result = collector.emit()
        assert "summary" in result
        assert "findings" in result

        # summary: 1 class with count 4
        assert len(result["summary"]) == 1
        count = list(result["summary"].values())[0]
        assert count == 4

        # findings: 1 representative (the first one added)
        assert len(result["findings"]) == 1
        assert result["findings"][0]["fixture"] == "f-0"
