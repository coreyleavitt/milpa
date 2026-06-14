"""Stdlib unittest tests for the MUST-clause coverage map (slice 3e).

Run with:
    python3 -m unittest discover -s harness -p 'test_*.py'

3e-C1: inventory parses; CLAUSE_INVENTORY is non-empty; all entries are SpecClause.
3e-C2: a known-covered clause (cli.exit-code-failure) maps to a corpus fixture
        that is expected to be present in conformance/spec-v1/.
3e-C3: a deliberately-uncovered clause appears in the gap_ids list when the
        conformance_root has NO matching fixture AND no active tier covers it.
3e-C4: coverage_report returns a CoverageReport with correct counts.
3e-C5: all clause ids are unique (no inventory duplication).
3e-C6: the actual repo corpus exercises coverage_report end-to-end (smoke).
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from harness.coverage import (
    ACTIVE_TIERS,
    CLAUSE_INVENTORY,
    CoverageReport,
    SpecClause,
    coverage_report,
)


_CONFORMANCE_ROOT = _REPO_ROOT / "conformance"


class TestCoverageInventory(unittest.TestCase):
    """3e-C1, C4, C5: inventory structure tests."""

    def test_c1_inventory_is_nonempty(self) -> None:
        """3e-C1: CLAUSE_INVENTORY is non-empty and contains only SpecClause."""
        self.assertGreater(len(CLAUSE_INVENTORY), 0, "CLAUSE_INVENTORY must not be empty")
        for clause in CLAUSE_INVENTORY:
            self.assertIsInstance(clause, SpecClause, f"Expected SpecClause, got {type(clause)}")

    def test_c5_clause_ids_unique(self) -> None:
        """3e-C5: all clause ids are unique (no duplicates in inventory)."""
        ids = [c.id for c in CLAUSE_INVENTORY]
        unique = set(ids)
        self.assertEqual(
            len(ids), len(unique),
            f"Duplicate clause ids found: "
            + str([i for i in ids if ids.count(i) > 1]),
        )

    def test_inventory_has_observable_clauses(self) -> None:
        """Inventory has at least some observable clauses."""
        observable = [c for c in CLAUSE_INVENTORY if c.observable]
        self.assertGreater(len(observable), 5, "Expected ≥5 observable clauses")

    def test_inventory_fully_covered(self) -> None:
        """Every observable MUST-clause has a covering fixture/tier (0 gaps).

        Reached after #125+#120: the last black-box gaps (verify-no-lock,
        dev-deps-root-only, no-index, ws-no-index) are now covered. This asserts
        the milestone holds — a NEW uncovered observable clause (a freshly added
        normative requirement with no fixture yet) breaks this and must be
        closed. The gap-DETECTION machinery itself is guarded by
        test_c3_uncovered_clause_is_a_gap, independent of whether a real gap
        currently exists.
        """
        gaps = [
            c for c in CLAUSE_INVENTORY
            if c.observable
            and not c.covering_fixtures
            and not (set(c.covering_tiers) & ACTIVE_TIERS)
        ]
        self.assertEqual(
            gaps, [],
            "Observable MUST-clauses without coverage: "
            + str([c.id for c in gaps]),
        )


class TestCoverageReport(unittest.TestCase):
    """3e-C2, C3, C4, C6: coverage_report() behavior."""

    def test_c2_known_covered_clause_maps_to_fixture(self) -> None:
        """3e-C2: cli.exit-code-failure maps to fixture-001 which is present in corpus."""
        # Find the clause
        clause = next(
            (c for c in CLAUSE_INVENTORY if c.id == "cli.exit-code-failure"),
            None,
        )
        self.assertIsNotNone(clause, "Expected clause 'cli.exit-code-failure' in inventory")
        self.assertIn(
            "fixture-001-man-kdl-syntax",
            clause.covering_fixtures,
            "Expected fixture-001-man-kdl-syntax in cli.exit-code-failure covering_fixtures",
        )

        # Verify it's actually present in the corpus
        fixture_path = _CONFORMANCE_ROOT / "spec-v1" / "fixture-001-man-kdl-syntax"
        self.assertTrue(
            fixture_path.is_dir(),
            f"fixture-001 not found at {fixture_path}; corpus may need a rebuild",
        )

    def test_c3_gap_clause_appears_in_gap_list(self) -> None:
        """3e-C3: a clause with NO covering fixtures AND no active tier appears in gap_ids.

        We use a synthetic conformance_root (empty spec-v1/) so no real fixture is
        present, and inject a test clause that has no tiers.  Then verify the
        coverage_report includes it in gap_ids.

        Because CLAUSE_INVENTORY is a module-level list and we can't easily inject
        a test clause into it, we instead verify that a clause which IS declared as
        a known gap (covering_fixtures=() AND covering_tiers=() and observable=True)
        appears in the gap_ids when run against a real (or empty) corpus.

        Strategy: run coverage_report against an EMPTY temp dir as conformance_root.
        All clauses with covering_tiers=() will be gaps (no fixtures present).
        The known gap "resolver.dev-deps-root-only" has no fixtures and no tiers.
        """
        with tempfile.TemporaryDirectory(prefix="milpa-coverage-test-") as tmp:
            tmp_path = Path(tmp)
            # Create an empty spec-v1/ dir
            (tmp_path / "spec-v1").mkdir()

            log_lines: list[str] = []
            report = coverage_report(tmp_path, log=log_lines.append)

            # With empty corpus, all fixture-covered-only clauses become gaps
            self.assertGreater(
                report.gaps, 0,
                "Expected at least one gap when corpus is empty",
            )
            # The known gap clause MUST be in gap_ids
            self.assertIn(
                "resolver.dev-deps-root-only",
                report.gap_ids,
                "Expected 'resolver.dev-deps-root-only' in gap_ids (it has no fixtures or tiers)",
            )
            # "cli.add-git" has no tiers, so with an empty corpus it's a gap
            self.assertIn(
                "cli.add-git",
                report.gap_ids,
                "Expected 'cli.add-git' in gap_ids against empty corpus (fixtures absent)",
            )
            # GAP lines must appear in log output
            gap_log_lines = [l for l in log_lines if "[coverage] GAP" in l]
            self.assertGreater(
                len(gap_log_lines), 0,
                "Expected [coverage] GAP log lines",
            )

    def test_c4_coverage_report_returns_coverage_report(self) -> None:
        """3e-C4: coverage_report returns a CoverageReport namedtuple with sane counts."""
        report = coverage_report(_CONFORMANCE_ROOT)
        self.assertIsInstance(report, CoverageReport)
        self.assertGreaterEqual(report.total_observable, 10)
        self.assertGreaterEqual(report.covered, 1)
        self.assertEqual(
            report.total_observable,
            report.covered + report.gaps,
            "covered + gaps must equal total_observable",
        )
        # gap_ids is a tuple of strings
        self.assertIsInstance(report.gap_ids, tuple)
        for gid in report.gap_ids:
            self.assertIsInstance(gid, str)

    def test_c6_smoke_real_corpus(self) -> None:
        """3e-C6: smoke test against the real corpus produces a valid report."""
        self.assertTrue(
            _CONFORMANCE_ROOT.is_dir(),
            f"conformance_root not found: {_CONFORMANCE_ROOT}",
        )

        report = coverage_report(_CONFORMANCE_ROOT)

        # Basic sanity: most observable clauses should be covered by the real corpus
        coverage_fraction = report.covered / report.total_observable
        self.assertGreater(
            coverage_fraction, 0.5,
            f"Less than 50% of observable clauses covered: "
            f"{report.covered}/{report.total_observable}. "
            "Either the corpus is smaller than expected or the inventory is wrong.",
        )

        # All observable clauses are now covered by corpus fixtures, including
        # the formerly-open gaps: cli.verify-no-lock (fixture-164),
        # resolver.dev-deps-root-only (064/130) under #125, and
        # resolver.no-index / resolver.ws-no-index (fixtures 112/113, driven by
        # the empty MILPA_INDEX_URL three-way semantics) under #120.
        now_covered = {
            "cli.add-git", "cli.remove", "cli.update",
            "cli.verify-no-lock", "resolver.dev-deps-root-only",
            "resolver.no-index", "resolver.ws-no-index",
        }
        for clause_id in now_covered:
            self.assertNotIn(
                clause_id, report.gap_ids,
                f"Clause {clause_id!r} should be covered by corpus fixtures",
            )
        self.assertEqual(
            report.gap_ids, (),
            f"Expected zero observable gaps; got {report.gap_ids}",
        )

    def test_c4_log_output_structure(self) -> None:
        """3e-C4 supplemental: log output has COVERED + GAP lines + SUMMARY."""
        log_lines: list[str] = []
        report = coverage_report(_CONFORMANCE_ROOT, log=log_lines.append)

        covered_lines = [l for l in log_lines if "[coverage] COVERED" in l]
        gap_lines = [l for l in log_lines if "[coverage] GAP" in l]
        summary_lines = [l for l in log_lines if "[coverage] SUMMARY" in l]

        self.assertGreater(len(covered_lines), 0, "Expected COVERED log lines")
        # Gaps may be zero in future (if all clauses get fixtures) — just check format
        self.assertEqual(len(summary_lines), 1, "Expected exactly one SUMMARY line")

        # Summary line format: "X/Y clauses covered, Z gaps"
        summary = summary_lines[0]
        self.assertIn("clauses covered", summary)
        self.assertIn("gaps", summary)


if __name__ == "__main__":
    unittest.main()
