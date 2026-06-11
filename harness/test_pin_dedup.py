"""Stdlib unittest tests for harness/pin.py and harness/dedup.py (slice 3d).

Tests:
  P1: pin_candidate writes serialized inputs + divergence.json, NOT expected/.
  P2: pin_candidate divergence.json is valid JSON with correct shape.
  P3: pin_candidate creates dest_dir if it doesn't exist.
  D1: behavioral_class collapses same-shape divergences to one class.
  D2: behavioral_class separates different-shape divergences.
  D3: DivergenceCollector accumulates + dedups correctly.
  D4: DivergenceCollector summary and records output (§2e ordering).
  D5: disagreement_shape is order-independent (frozenset).
  D6: DivergenceCollector.emit() returns summary-first dict.

Run with:
    python3 -m unittest discover -s harness -p 'test_*.py'
from the repo root.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from harness.dedup import DivergenceCollector, behavioral_class
from harness.pin import pin_candidate
from harness.spec import DepSpec, FetchEntry, FixtureSpec


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_minimal_spec() -> FixtureSpec:
    """A minimal FixtureSpec with one git dep."""
    dep = DepSpec.git("foo", "https://github.com/example/foo.git", "main")
    entry = FetchEntry(
        sha="abcdef1234567890abcdef1234567890abcdef12",
        content_files={"foo.nim": b"# minimal\n"},
        nimble_text='version = "1.0.0"\nauthor = "x"\ndescription = "x"\nlicense = "MIT"\n',
    )
    return FixtureSpec(
        package_name="testapp",
        kind="application",
        deps=[dep],
        fetch_map={(dep.git_url, dep.ref): entry},
        cmd="resolve",
    )


def _make_divergence_record(
    fixture_id: str = "generated-001",
    cmd: str = "resolve",
    output_file: str = "error-slug",
    impls: dict | None = None,
) -> dict:
    """Build a minimal §2e divergence record dict."""
    if impls is None:
        impls = {
            "python": "success",
            "rust": "error:SOLVE-CONFLICT",
            "broken": "crash",
        }
    return {
        "fixture": fixture_id,
        "cmd": cmd,
        "output_file": output_file,
        "impls": impls,
    }


# ---------------------------------------------------------------------------
# P1–P3: pin_candidate tests
# ---------------------------------------------------------------------------

class TestPinCandidate(unittest.TestCase):
    """P1–P3: pin_candidate writes correct files."""

    def setUp(self) -> None:
        self._tmpdir = Path(tempfile.mkdtemp(prefix="milpa-pin-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_p1_writes_inputs_and_divergence_json_not_expected(self) -> None:
        """P1: pin_candidate writes fixture inputs + divergence.json, NOT expected/."""
        spec = _make_minimal_spec()
        record = _make_divergence_record()
        dest = self._tmpdir / "candidate-001"

        pin_candidate(spec, record, dest)

        # Fixture inputs must be present
        self.assertTrue((dest / "cmd").exists(), "cmd file not written")
        self.assertTrue((dest / "milpa.kdl").exists(), "milpa.kdl not written")
        self.assertTrue((dest / "mocked-fetches").exists(), "mocked-fetches/ not written")

        # divergence.json must be present
        div_path = dest / "divergence.json"
        self.assertTrue(div_path.exists(), "divergence.json not written")

        # expected/ must NOT be present
        self.assertFalse((dest / "expected").exists(), "expected/ must NOT be written")

    def test_p2_divergence_json_valid_shape(self) -> None:
        """P2: divergence.json is valid JSON with the §2e record shape."""
        spec = _make_minimal_spec()
        record = _make_divergence_record(
            fixture_id="test-pin-001",
            cmd="resolve",
            output_file="error-slug",
            impls={"python": "success", "broken": "error:SOLVE-CONFLICT"},
        )
        dest = self._tmpdir / "candidate-002"

        pin_candidate(spec, record, dest)

        div_path = dest / "divergence.json"
        parsed = json.loads(div_path.read_text(encoding="utf-8"))

        # Must have the §2e fields
        self.assertIn("fixture", parsed)
        self.assertIn("cmd", parsed)
        self.assertIn("output_file", parsed)
        self.assertIn("impls", parsed)

        # Field values must match
        self.assertEqual(parsed["fixture"], "test-pin-001")
        self.assertEqual(parsed["cmd"], "resolve")
        self.assertEqual(parsed["output_file"], "error-slug")
        self.assertEqual(parsed["impls"]["python"], "success")
        self.assertEqual(parsed["impls"]["broken"], "error:SOLVE-CONFLICT")

    def test_p3_creates_dest_dir(self) -> None:
        """P3: pin_candidate creates dest_dir if it does not exist."""
        spec = _make_minimal_spec()
        record = _make_divergence_record()
        # deeply nested path that doesn't exist yet
        dest = self._tmpdir / "a" / "b" / "c" / "candidate"

        self.assertFalse(dest.exists())
        pin_candidate(spec, record, dest)
        self.assertTrue(dest.exists())
        self.assertTrue((dest / "cmd").exists())
        self.assertTrue((dest / "divergence.json").exists())

    def test_p_milpa_kdl_contains_spec_content(self) -> None:
        """milpa.kdl in the candidate matches the FixtureSpec."""
        spec = _make_minimal_spec()
        record = _make_divergence_record()
        dest = self._tmpdir / "candidate-003"

        pin_candidate(spec, record, dest)

        kdl = (dest / "milpa.kdl").read_text()
        self.assertIn('name "testapp"', kdl)
        self.assertIn('kind "application"', kdl)
        self.assertIn("https://github.com/example/foo.git", kdl)

    def test_p_cmd_file_contains_resolve(self) -> None:
        """cmd file in the candidate matches spec.cmd."""
        spec = _make_minimal_spec()
        record = _make_divergence_record()
        dest = self._tmpdir / "candidate-004"

        pin_candidate(spec, record, dest)

        self.assertEqual((dest / "cmd").read_text().strip(), "resolve")


# ---------------------------------------------------------------------------
# D1–D6: behavioral_class + DivergenceCollector tests
# ---------------------------------------------------------------------------

class TestBehavioralClass(unittest.TestCase):
    """D1–D2: behavioral_class normalization."""

    def test_d1_same_shape_collapses(self) -> None:
        """D1: two divergences with the same per-impl outcomes → same class."""
        impls_a = {"python": "success", "rust": "error:SOLVE-CONFLICT"}
        impls_b = {"python": "success", "rust": "error:SOLVE-CONFLICT"}

        cls_a = behavioral_class(impls_a, "resolve", "error-slug")
        cls_b = behavioral_class(impls_b, "resolve", "error-slug")

        self.assertEqual(cls_a, cls_b)

    def test_d2_different_shape_separates(self) -> None:
        """D2: two divergences with different per-impl outcomes → different classes."""
        impls_a = {"python": "success", "rust": "error:SOLVE-CONFLICT"}
        impls_b = {"python": "error:SOLVE-CONFLICT", "rust": "crash"}

        cls_a = behavioral_class(impls_a, "resolve", "error-slug")
        cls_b = behavioral_class(impls_b, "resolve", "error-slug")

        self.assertNotEqual(cls_a, cls_b)

    def test_d5_order_independent(self) -> None:
        """D5: impl name order doesn't change the behavioral class."""
        # Different dicts with same values but built differently
        impls_x = {"python": "success", "rust": "error:SOLVE-CONFLICT"}
        impls_y = {"rust": "error:SOLVE-CONFLICT", "python": "success"}

        cls_x = behavioral_class(impls_x, "resolve", "error-slug")
        cls_y = behavioral_class(impls_y, "resolve", "error-slug")

        self.assertEqual(cls_x, cls_y)

    def test_different_cmd_different_class(self) -> None:
        """Different cmd → different behavioral class even with same impls."""
        impls = {"python": "success", "rust": "error:SOLVE-CONFLICT"}
        cls_resolve = behavioral_class(impls, "resolve", "error-slug")
        cls_frozen = behavioral_class(impls, "frozen", "error-slug")
        self.assertNotEqual(cls_resolve, cls_frozen)

    def test_different_output_file_different_class(self) -> None:
        """Different output_file → different behavioral class."""
        impls = {"python": "success", "rust": "success"}
        cls_slug = behavioral_class(impls, "resolve", "error-slug")
        cls_lock = behavioral_class(impls, "resolve", "milpa.lock")
        self.assertNotEqual(cls_slug, cls_lock)


class TestDivergenceCollector(unittest.TestCase):
    """D3–D6: DivergenceCollector accumulation and emission."""

    def _make_record(self, fixture_id: str, impls: dict, cmd: str = "resolve") -> dict:
        return {
            "fixture": fixture_id,
            "cmd": cmd,
            "output_file": "error-slug",
            "impls": impls,
        }

    def test_d3_deduplication(self) -> None:
        """D3: N divergences of the same class → 1 class with count N."""
        collector = DivergenceCollector()

        impls = {"python": "success", "rust": "error:SOLVE-CONFLICT"}
        for i in range(5):
            record = self._make_record(f"fixture-{i:03d}", impls)
            collector.add("resolve", "error-slug", impls, record=record)

        self.assertEqual(len(collector), 1, "Expected 1 behavioral class")
        self.assertEqual(collector.total_count(), 5)

    def test_d3_different_classes_not_deduped(self) -> None:
        """D3: divergences of different classes are kept separate."""
        collector = DivergenceCollector()

        impls_a = {"python": "success", "rust": "error:SOLVE-CONFLICT"}
        impls_b = {"python": "crash", "rust": "success"}

        for i in range(3):
            collector.add("resolve", "error-slug", impls_a,
                          record=self._make_record(f"a-{i}", impls_a))
        for i in range(2):
            collector.add("resolve", "error-slug", impls_b,
                          record=self._make_record(f"b-{i}", impls_b))

        self.assertEqual(len(collector), 2, "Expected 2 behavioral classes")
        self.assertEqual(collector.total_count(), 5)

    def test_d4_summary_counts(self) -> None:
        """D4: summary() returns {class_label: count} for each class."""
        collector = DivergenceCollector()

        impls_a = {"python": "success", "rust": "error:SOLVE-CONFLICT"}
        impls_b = {"python": "crash", "rust": "success"}

        for _ in range(7):
            collector.add("resolve", "error-slug", impls_a,
                          record=self._make_record("x", impls_a))
        for _ in range(3):
            collector.add("resolve", "error-slug", impls_b,
                          record=self._make_record("y", impls_b))

        summary = collector.summary()
        self.assertEqual(len(summary), 2)
        counts = list(summary.values())
        self.assertIn(7, counts)
        self.assertIn(3, counts)

    def test_d4_records_one_per_class(self) -> None:
        """D4: records() returns exactly one representative per class."""
        collector = DivergenceCollector()

        impls = {"python": "success", "rust": "error:SOLVE-CONFLICT"}
        # Add 5 divergences of the same class, each with a different fixture_id
        records_added = []
        for i in range(5):
            rec = self._make_record(f"fixture-{i:03d}", impls)
            records_added.append(rec)
            collector.add("resolve", "error-slug", impls, record=rec)

        records = collector.records()
        self.assertEqual(len(records), 1)
        # The representative must be the FIRST one added
        self.assertEqual(records[0]["fixture"], "fixture-000")

    def test_d6_emit_summary_first(self) -> None:
        """D6: emit() returns {summary: ..., findings: ...} with summary-first ordering."""
        collector = DivergenceCollector()

        impls = {"python": "success", "broken": "crash"}
        rec = self._make_record("test-fixture", impls)
        collector.add("resolve", "error-slug", impls, record=rec)

        result = collector.emit()
        self.assertIn("summary", result)
        self.assertIn("findings", result)

        # summary has 1 entry (1 class)
        self.assertEqual(len(result["summary"]), 1)
        # findings has 1 record
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["fixture"], "test-fixture")

    def test_emit_json_is_valid(self) -> None:
        """emit_json() returns valid JSON."""
        collector = DivergenceCollector()
        impls = {"python": "success", "broken": "crash"}
        collector.add("resolve", "error-slug", impls,
                      record=self._make_record("f1", impls))

        json_str = collector.emit_json()
        parsed = json.loads(json_str)
        self.assertIn("summary", parsed)
        self.assertIn("findings", parsed)

    def test_empty_collector(self) -> None:
        """An empty collector has 0 classes and 0 total count."""
        collector = DivergenceCollector()
        self.assertEqual(len(collector), 0)
        self.assertEqual(collector.total_count(), 0)
        self.assertEqual(collector.summary(), {})
        self.assertEqual(collector.records(), [])

    def test_add_without_record_synthesizes_one(self) -> None:
        """add() with record=None synthesizes a minimal record."""
        collector = DivergenceCollector()
        impls = {"python": "success", "rust": "crash"}
        collector.add("resolve", "error-slug", impls, record=None)

        records = collector.records()
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertIn("cmd", rec)
        self.assertIn("impls", rec)


if __name__ == "__main__":
    unittest.main()
