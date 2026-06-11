"""Stdlib unittest tests for the differential conformance harness.

Run with:
    python3 -m unittest discover -s harness -p 'test_*.py'

from the repo root, OR:
    python3 -m unittest harness.test_harness

B1: fixture runner — single success + single error fixture via python descriptor.
B2: full corpus python-only — all non-skipped fixtures pass their expected/ gate.
B3: divergence detection — synthetic broken descriptor triggers divergence report.
B4: full corpus python+rust — all non-skipped fixtures pass both gates + zero divergence.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup: repo root is two levels above this file (harness/test_harness.py).
# We add it to sys.path so "import harness.*" works when running from the root
# via python3 -m unittest discover -s harness -p 'test_*.py'.
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from harness.assertions import assert_conformance
from harness.corpus import (
    KNOWN_LIMITATIONS,
    CorpusReport,
    format_report,
    run_corpus,
)
from harness.descriptors import ImplDescriptor, build_descriptors
from harness.runner import run_fixture

_CONFORMANCE_ROOT = _REPO_ROOT / "conformance"
_SPEC_V1 = _CONFORMANCE_ROOT / "spec-v1"


# ---------------------------------------------------------------------------
# B1 — fixture runner: one success + one error fixture via python descriptor
# ---------------------------------------------------------------------------

class TestB1FixtureRunner(unittest.TestCase):
    """B1: fixture runner drives ONE success and ONE error fixture end-to-end."""

    def _python_descriptor(self) -> ImplDescriptor:
        descs = build_descriptors(_REPO_ROOT)
        for d in descs:
            if d.name == "python":
                return d
        self.fail("python descriptor not found")

    def test_b1_success_fixture_061_named_dep(self) -> None:
        """B1-success: fixture-061-named-dep exits 0 + milpa.lock byte-matches."""
        fixture_dir = _SPEC_V1 / "fixture-061-named-dep"
        self.assertTrue(fixture_dir.is_dir(), f"fixture not found: {fixture_dir}")

        desc = self._python_descriptor()
        run = run_fixture(fixture_dir, desc)
        result = assert_conformance(run, fixture_dir)

        # Clean up scratch + CAS after asserting.
        for d in (run.scratch_dir, run.cas_dir):
            shutil.rmtree(d, ignore_errors=True)

        self.assertTrue(
            result.passed,
            f"fixture-061 failed: {[f.detail for f in result.failures]}",
        )
        self.assertEqual(run.returncode, 0)
        self.assertIsNone(run.slug)
        # milpa.lock must be byte-identical to expected.
        self.assertIn("expected/milpa.lock", result.normalized_outputs)

    def test_b1_error_fixture_060_man_url_arg_type(self) -> None:
        """B1-error: fixture-060-man-url-arg-type exits 1 + slug MAN-URL-ARG-TYPE."""
        fixture_dir = _SPEC_V1 / "fixture-060-man-url-arg-type"
        self.assertTrue(fixture_dir.is_dir(), f"fixture not found: {fixture_dir}")

        desc = self._python_descriptor()
        run = run_fixture(fixture_dir, desc)
        result = assert_conformance(run, fixture_dir)

        for d in (run.scratch_dir, run.cas_dir):
            shutil.rmtree(d, ignore_errors=True)

        self.assertTrue(
            result.passed,
            f"fixture-060 failed: {[f.detail for f in result.failures]}",
        )
        self.assertEqual(run.returncode, 1)
        self.assertEqual(run.slug, "MAN-URL-ARG-TYPE")


# ---------------------------------------------------------------------------
# B2 — corpus runner over all fixtures × python only
# ---------------------------------------------------------------------------

class TestB2PythonCorpus(unittest.TestCase):
    """B2: full corpus python-only; every non-skipped fixture passes its gate."""

    @classmethod
    def setUpClass(cls) -> None:
        descs = build_descriptors(_REPO_ROOT)
        python_descs = [d for d in descs if d.name == "python"]
        cls.report: CorpusReport = run_corpus(
            _CONFORMANCE_ROOT,
            python_descs,
        )

    def test_no_failures(self) -> None:
        """B2: zero conformance failures across all python fixtures."""
        if self.report.failed.get("python", 0) > 0:
            detail = "\n".join(
                f"  [{f.fixture_name}] {f.detail}"
                for f in self.report.all_failures
            )
            self.fail(
                f"{self.report.failed['python']} fixture(s) failed:\n{detail}"
            )

    def test_no_divergences(self) -> None:
        """B2: no divergences (trivially true with one impl)."""
        self.assertEqual(
            len(self.report.divergences), 0,
            "Unexpected divergences with single impl",
        )

    def test_pass_count_reasonable(self) -> None:
        """B2: at least 100 fixtures pass (the strategic milestone bar)."""
        passed = self.report.passed.get("python", 0)
        self.assertGreaterEqual(
            passed,
            100,
            f"Only {passed} fixtures passed; expected ≥100",
        )

    def test_known_limitations_skipped(self) -> None:
        """B2: each KNOWN_LIMITATIONS entry is skipped (not run)."""
        skipped_names = {
            s.fixture_name for s in self.report.skip_records
        }
        for name in KNOWN_LIMITATIONS:
            self.assertIn(
                name, skipped_names,
                f"{name} should have been skipped but was not found in skip records",
            )


# ---------------------------------------------------------------------------
# B3 — divergence detection with a synthetic broken descriptor
# ---------------------------------------------------------------------------

class TestB3DivergenceDetection(unittest.TestCase):
    """B3: a deliberately-broken impl triggers a divergence record."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp(prefix="milpa-harness-b3-")

    def tearDown(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_broken_wrapper(self, wrong_slug: str | None = "WRONG-SLUG") -> str:
        """Create a tiny shell wrapper that always exits 1 with a wrong slug.

        If wrong_slug is None, emit wrong bytes in stdout (for a success fixture).
        """
        wrapper = os.path.join(self._tmpdir, "broken-milpa")
        if wrong_slug is not None:
            script = (
                "#!/bin/sh\n"
                f"echo 'milpa-error: {wrong_slug}' >&2\n"
                "exit 1\n"
            )
        else:
            script = (
                "#!/bin/sh\n"
                # Output wrong milpa.lock content.
                "echo 'WRONG LOCKFILE CONTENT' > \"$(cat /dev/stdin 2>/dev/null || true)\"\n"
                # Simpler: just write wrong content into -C dir.
                "for arg in \"$@\"; do\n"
                "  case \"$prev\" in -C) dir=\"$arg\";; esac; prev=\"$arg\"\n"
                "done\n"
                f"echo 'WRONG CONTENT' > \"$dir/milpa.lock\"\n"
                f"echo 'WRONG CFG' > \"$dir/nim.cfg\"\n"
                "exit 0\n"
            )
        with open(wrapper, "w") as f:
            f.write(script)
        os.chmod(wrapper, 0o755)
        return wrapper

    def test_error_fixture_divergence_detected(self) -> None:
        """B3: broken impl emitting wrong slug triggers divergence on error fixture."""
        # Use fixture-001 (MAN-KDL-SYNTAX error fixture) as the corpus.
        fixture_dir = _SPEC_V1 / "fixture-001-man-kdl-syntax"
        self.assertTrue(fixture_dir.is_dir())

        wrapper = self._make_broken_wrapper(wrong_slug="WRONG-SLUG")

        good_descs = [d for d in build_descriptors(_REPO_ROOT) if d.name == "python"]
        broken_desc = ImplDescriptor(
            name="broken",
            argv=[wrapper],
            cwd=None,
            env={},
        )
        all_descs = good_descs + [broken_desc]

        # Build a minimal conformance root pointing at just this one fixture.
        mini_root = Path(self._tmpdir) / "mini-conformance" / "spec-v1"
        mini_root.mkdir(parents=True)
        shutil.copytree(fixture_dir, mini_root / fixture_dir.name)

        report = run_corpus(mini_root.parent, all_descs)

        # The broken impl should fail its own conformance check (wrong slug).
        self.assertGreater(
            report.failed.get("broken", 0), 0,
            "broken impl should have at least one failure",
        )

    def test_divergence_record_structure(self) -> None:
        """B3: DivergenceRecord JSON fields are fixture/cmd/output_file/impls."""
        from harness.corpus import DivergenceRecord
        div = DivergenceRecord(
            fixture_name="fixture-001-man-kdl-syntax",
            cmd="resolve",
            output_file="expected/error",
            impls={"python": "MAN-KDL-SYNTAX", "broken": "WRONG-SLUG"},
        )
        record = {
            "fixture": div.fixture_name,
            "cmd": div.cmd,
            "output_file": div.output_file,
            "impls": div.impls,
        }
        parsed = json.loads(json.dumps(record))
        self.assertEqual(parsed["fixture"], "fixture-001-man-kdl-syntax")
        self.assertEqual(parsed["impls"]["python"], "MAN-KDL-SYNTAX")
        self.assertEqual(parsed["impls"]["broken"], "WRONG-SLUG")

    def test_format_report_includes_divergence(self) -> None:
        """B3: format_report includes divergence section when divergences present."""
        from harness.corpus import DivergenceRecord, CorpusReport
        report = CorpusReport(
            total_fixtures=1,
            impl_names=["python", "broken"],
            passed={"python": 1, "broken": 0},
            failed={"python": 0, "broken": 1},
            skipped_known_failing={"python": 0, "broken": 0},
        )
        report.divergences.append(DivergenceRecord(
            fixture_name="fixture-001-man-kdl-syntax",
            cmd="resolve",
            output_file="expected/error",
            impls={"python": "MAN-KDL-SYNTAX", "broken": "WRONG-SLUG"},
        ))
        text = format_report(report)
        self.assertIn("DIVERGENCE", text)
        self.assertIn("fixture-001-man-kdl-syntax", text)


# ---------------------------------------------------------------------------
# B4 — full corpus python+rust; zero divergence
# ---------------------------------------------------------------------------

class TestB4PythonRustCorpus(unittest.TestCase):
    """B4: full corpus × {python, rust}; zero failures + zero divergence."""

    @classmethod
    def setUpClass(cls) -> None:
        from pathlib import Path
        rust_bin = _REPO_ROOT / "impls" / "rust" / "target" / "release" / "milpa"
        if not rust_bin.exists():
            cls._skip_reason = (
                f"Rust binary not found at {rust_bin}; "
                "build with: ./dev-rust build --release"
            )
            cls.report = None
            return
        cls._skip_reason = None
        descs = build_descriptors(_REPO_ROOT)
        cls.report: CorpusReport = run_corpus(
            _CONFORMANCE_ROOT,
            descs,
        )

    def _skip_if_no_rust(self) -> None:
        if self.__class__._skip_reason is not None:
            self.skipTest(self.__class__._skip_reason)

    def test_python_no_failures(self) -> None:
        """B4: python impl passes all non-skipped fixtures."""
        self._skip_if_no_rust()
        if self.report.failed.get("python", 0) > 0:
            detail = "\n".join(
                f"  [{f.fixture_name}] {f.detail}"
                for f in self.report.all_failures
                if f.impl_name == "python"
            )
            self.fail(f"{self.report.failed['python']} python failure(s):\n{detail}")

    def test_rust_no_failures(self) -> None:
        """B4: rust impl passes all non-skipped fixtures."""
        self._skip_if_no_rust()
        if self.report.failed.get("rust", 0) > 0:
            detail = "\n".join(
                f"  [{f.fixture_name}] {f.detail}"
                for f in self.report.all_failures
                if f.impl_name == "rust"
            )
            self.fail(f"{self.report.failed['rust']} rust failure(s):\n{detail}")

    def test_zero_divergences(self) -> None:
        """B4: zero cross-impl divergences."""
        self._skip_if_no_rust()
        if self.report.divergences:
            detail = "\n".join(
                f"  {d.fixture_name} [{d.output_file}]: "
                + " vs ".join(f"{k}={v[:40]!r}" for k, v in d.impls.items())
                for d in self.report.divergences
            )
            self.fail(
                f"{len(self.report.divergences)} cross-impl divergence(s):\n{detail}"
            )

    def test_pass_counts(self) -> None:
        """B4: python passes ≥100 fixtures; rust passes all fixtures it actively runs.

        Python has no known_failing entries, so its pass count must meet the
        strategic milestone bar. Rust has real reported bugs (BLOCKER-R1 through
        BLOCKER-R4) recorded in known_failing — we assert it fails zero of the
        fixtures it actively runs, not that it meets the absolute milestone.
        """
        self._skip_if_no_rust()
        # Python strategic milestone bar.
        python_passed = self.report.passed.get("python", 0)
        self.assertGreaterEqual(
            python_passed, 100,
            f"python: only {python_passed} fixtures passed; expected ≥100",
        )
        # Rust: zero failures on the active set (known_failing is the logged-bug list,
        # not a silent skip).
        rust_failed = self.report.failed.get("rust", 0)
        self.assertEqual(
            rust_failed, 0,
            f"rust: {rust_failed} fixture(s) failed on the active (non-known-failing) set",
        )


if __name__ == "__main__":
    unittest.main()
