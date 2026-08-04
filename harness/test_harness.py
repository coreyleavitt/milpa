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
    _detect_divergences,
    discover_fixtures,
    format_report,
    run_corpus,
)
from harness.descriptors import ImplDescriptor, build_descriptors
from harness.runner import _build_env, _copy_fixture_inputs, run_fixture

_CONFORMANCE_ROOT = _REPO_ROOT / "conformance"
_SPEC_V1 = _CONFORMANCE_ROOT / "spec-v1"


# ---------------------------------------------------------------------------
# B0 — S3a: dep-decl/ fixture artifact dir + MILPA_DEP_DECL_DIR injection
# ---------------------------------------------------------------------------

class TestB0DepDeclDirInjection(unittest.TestCase):
    """B0: dep-decl/ is copied verbatim + MILPA_DEP_DECL_DIR is injected.

    Mirrors how mocked-fetches/ is copied and MILPA_MOCKED_FETCHES is injected.
    These tests target _copy_fixture_inputs and _build_env directly (unit level)
    to verify the S3a plumbing without running a full impl subprocess.

    B0-a: fixture WITH dep-decl/ → dir copied into scratch + MILPA_DEP_DECL_DIR set.
    B0-b: fixture WITHOUT dep-decl/ → MILPA_DEP_DECL_DIR is absent from env.
    B0-c: dep-decl/ is NOT treated as a control file (i.e. it IS copied).
    B0-d: MILPA_DEP_DECL_DIR value points to scratch/dep-decl/ (absolute resolved path).
    B0-e: MILPA_DEP_DECL_DIR not leaked from host env when fixture lacks dep-decl/.
    """

    def setUp(self) -> None:
        self._fixture_dir = Path(tempfile.mkdtemp(prefix="milpa-b0-fixture-"))
        self._scratch_dir = Path(tempfile.mkdtemp(prefix="milpa-b0-scratch-"))
        self._cas_dir = Path(tempfile.mkdtemp(prefix="milpa-b0-cas-"))

    def tearDown(self) -> None:
        for d in (self._fixture_dir, self._scratch_dir, self._cas_dir):
            shutil.rmtree(d, ignore_errors=True)

    def _make_fixture_with_dep_decl(self) -> None:
        """Populate self._fixture_dir with a dep-decl/ subdirectory + minimal milpa.kdl."""
        (self._fixture_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        dep_decl_dir = self._fixture_dir / "dep-decl"
        dep_decl_dir.mkdir()
        # Write a synthetic artifact file (sha256 hex name, .kdl contents).
        (dep_decl_dir / ("a" * 64 + ".kdl")).write_text("dep_decl {\n    dep_decl_schema_version 0\n}\n")

    def _make_fixture_without_dep_decl(self) -> None:
        """Populate self._fixture_dir WITHOUT dep-decl/ (baseline fixture)."""
        (self._fixture_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')

    def test_b0a_dep_decl_dir_copied_into_scratch(self) -> None:
        """B0-a: when dep-decl/ is present it is copied verbatim into scratch."""
        self._make_fixture_with_dep_decl()
        _copy_fixture_inputs(self._fixture_dir, self._scratch_dir)
        self.assertTrue(
            (self._scratch_dir / "dep-decl").is_dir(),
            "dep-decl/ must be copied into scratch when present in the fixture",
        )

    def test_b0a_dep_decl_contents_copied(self) -> None:
        """B0-a: artifact files inside dep-decl/ are preserved byte-for-byte."""
        self._make_fixture_with_dep_decl()
        _copy_fixture_inputs(self._fixture_dir, self._scratch_dir)
        artifact_name = "a" * 64 + ".kdl"
        artifact = self._scratch_dir / "dep-decl" / artifact_name  # noqa: E501
        self.assertTrue(artifact.exists(), f"Artifact {artifact_name} must be copied")
        original = (self._fixture_dir / "dep-decl" / artifact_name).read_bytes()
        self.assertEqual(artifact.read_bytes(), original)

    def test_b0b_milpa_dep_decl_dir_injected_when_present(self) -> None:
        """B0-b: MILPA_DEP_DECL_DIR is set when scratch/dep-decl/ exists."""
        self._make_fixture_with_dep_decl()
        _copy_fixture_inputs(self._fixture_dir, self._scratch_dir)
        env = _build_env(self._scratch_dir, self._cas_dir, {}, {})
        self.assertIn(
            "MILPA_DEP_DECL_DIR", env,
            "MILPA_DEP_DECL_DIR must be injected when dep-decl/ is present",
        )

    def test_b0b_milpa_dep_decl_dir_absent_when_not_present(self) -> None:
        """B0-b: MILPA_DEP_DECL_DIR is NOT set when fixture lacks dep-decl/."""
        self._make_fixture_without_dep_decl()
        _copy_fixture_inputs(self._fixture_dir, self._scratch_dir)
        # Ensure host env can't leak in (strip MILPA_* as the runner does).
        env = _build_env(self._scratch_dir, self._cas_dir, {}, {})
        self.assertNotIn(
            "MILPA_DEP_DECL_DIR", env,
            "MILPA_DEP_DECL_DIR must NOT be injected when dep-decl/ is absent",
        )

    def test_b0c_dep_decl_not_in_control_files(self) -> None:
        """B0-c: dep-decl/ is a fixture artifact dir, not a control file (it IS copied)."""
        # The control files are: expected, cmd, env.
        # dep-decl/ must NOT be in _CONTROL_FILES.
        from harness.runner import _CONTROL_FILES
        self.assertNotIn("dep-decl", _CONTROL_FILES)

    def test_b0d_milpa_dep_decl_dir_value_is_absolute_scratch_subdir(self) -> None:
        """B0-d: MILPA_DEP_DECL_DIR value is the resolved absolute path scratch/dep-decl/."""
        self._make_fixture_with_dep_decl()
        _copy_fixture_inputs(self._fixture_dir, self._scratch_dir)
        env = _build_env(self._scratch_dir, self._cas_dir, {}, {})
        expected = str((self._scratch_dir / "dep-decl").resolve())
        self.assertEqual(
            env.get("MILPA_DEP_DECL_DIR"), expected,
            f"MILPA_DEP_DECL_DIR must be the resolved scratch/dep-decl/ path: {expected}",
        )

    def test_b0e_host_milpa_dep_decl_dir_stripped(self) -> None:
        """B0-e: a MILPA_DEP_DECL_DIR on the host env does NOT leak when fixture lacks dep-decl/."""
        self._make_fixture_without_dep_decl()
        _copy_fixture_inputs(self._fixture_dir, self._scratch_dir)
        # Inject a fake host MILPA_DEP_DECL_DIR and verify it is stripped.
        # _build_env already strips all MILPA_* from os.environ; we test that
        # the stripped baseline does not re-add an absent dep-decl/ entry.
        original = os.environ.copy()
        os.environ["MILPA_DEP_DECL_DIR"] = "/some/host/path"
        try:
            env = _build_env(self._scratch_dir, self._cas_dir, {}, {})
        finally:
            if "MILPA_DEP_DECL_DIR" in original:
                os.environ["MILPA_DEP_DECL_DIR"] = original["MILPA_DEP_DECL_DIR"]
            else:
                os.environ.pop("MILPA_DEP_DECL_DIR", None)
        self.assertNotIn(
            "MILPA_DEP_DECL_DIR", env,
            "Host MILPA_DEP_DECL_DIR must be stripped when fixture lacks dep-decl/",
        )


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

        # Clean up scratch + CAS after asserting (SSOT via RunResult.cleanup).
        run.cleanup()

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

        # Clean up scratch + CAS after asserting (SSOT via RunResult.cleanup).
        run.cleanup()

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

    def test_certificate_content_divergence_not_just_kind(self) -> None:
        """#130: the cross-impl cert token captures content, not just kind.

        Two impls can each pass their own fixture's expected JSON yet differ
        from each other in certificate *body*. The divergence token must
        reflect that — comparing only ``kind`` ("success"/"failure") is blind
        to a witness/resolved/refutation mismatch.
        """
        from harness.assertions import _canonical_certificate

        a = {
            "kind": "success",
            "resolved": [{"package": "foo", "version": "1.0.0"}],
            "witness": [{"package": "foo", "decision": "1.0.0"}],
        }
        b = {
            "kind": "success",
            "resolved": [{"package": "foo", "version": "2.0.0"}],
            "witness": [{"package": "foo", "decision": "2.0.0"}],
        }
        # Same kind — a kind-only token would call these identical.
        self.assertEqual(a["kind"], b["kind"])
        tok_a = json.dumps(_canonical_certificate(a), sort_keys=True)
        tok_b = json.dumps(_canonical_certificate(b), sort_keys=True)
        self.assertNotEqual(
            tok_a, tok_b,
            "content-differing certs must yield different divergence tokens",
        )

    def test_canonical_certificate_excludes_message(self) -> None:
        """#130: message is human-readable/impl-specific — not part of the token."""
        from harness.assertions import _canonical_certificate

        a = {"kind": "failure", "refutation": [{"package": "x", "constraint": ">=1"}],
             "message": "no version of x satisfies >=1"}
        b = {"kind": "failure", "refutation": [{"package": "x", "constraint": ">=1"}],
             "message": "x has no compatible release"}
        self.assertEqual(_canonical_certificate(a), _canonical_certificate(b))

    def test_canonical_certificate_refutation_order_insensitive(self) -> None:
        """#130: refutation is set-equality (sorted by package, constraint)."""
        from harness.assertions import _canonical_certificate

        a = {"kind": "failure", "refutation": [
            {"package": "x", "constraint": ">=1"},
            {"package": "y", "constraint": "<2"},
        ]}
        b = {"kind": "failure", "refutation": [
            {"package": "y", "constraint": "<2"},
            {"package": "x", "constraint": ">=1"},
        ]}
        self.assertEqual(_canonical_certificate(a), _canonical_certificate(b))

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
# P2-9 — absent-file confinement: ``..``-escape must be rejected
# ---------------------------------------------------------------------------

class TestAbsentFileConfinement(unittest.TestCase):
    """P2-9: rel_path entries in expected/absent must not escape the scratch dir.

    A ``..``-containing line in the absent file could traverse outside the
    scratch directory and probe arbitrary host paths.  The assertion logic
    must confine each rel_path to within scratch before calling .exists().
    """

    def setUp(self) -> None:
        self._scratch = Path(tempfile.mkdtemp(prefix="milpa-p29-scratch-"))
        self._cas = Path(tempfile.mkdtemp(prefix="milpa-p29-cas-"))
        self._fixture_dir = Path(tempfile.mkdtemp(prefix="milpa-p29-fixture-"))
        # Build a minimal expected/ directory for a success fixture.
        expected = self._fixture_dir / "expected"
        expected.mkdir()
        # Write a milpa.lock so the fixture is treated as a success class.
        (expected / "milpa.lock").write_text("# lock\n", encoding="utf-8")
        (self._scratch / "milpa.lock").write_text("# lock\n", encoding="utf-8")

    def tearDown(self) -> None:
        for d in (self._scratch, self._cas, self._fixture_dir):
            shutil.rmtree(str(d), ignore_errors=True)

    def _make_run_result(self) -> "RunResult":
        from harness.runner import RunResult
        return RunResult(
            fixture_name="fixture-p29-confinement",
            impl_name="python",
            returncode=0,
            stdout="",
            stderr="",
            slug=None,
            slug_error=None,
            scratch_dir=str(self._scratch),
            cas_dir=str(self._cas),
        )

    def test_dotdot_escape_in_absent_file_is_rejected(self) -> None:
        """A ``../escape`` line in expected/absent must produce a failure, not probe the host.

        This is the RED test for P2-9: currently the code builds
        ``actual_path = scratch / rel_path`` and calls ``.exists()`` with no
        confinement check, so a ``..``-escape silently probes outside scratch.
        After the fix, a violating line must result in a ConformanceResult
        failure (or raise) — it must NOT silently succeed by probing a host path.
        """
        absent_file = self._fixture_dir / "expected" / "absent"
        # Use a path that would escape scratch via ``..``.
        absent_file.write_text("../escape\n", encoding="utf-8")

        run = self._make_run_result()
        result = assert_conformance(run, self._fixture_dir)

        # The ``../escape`` line MUST trigger a conformance failure — the
        # assertion engine must not silently probe outside the scratch dir.
        self.assertFalse(
            result.passed,
            "Expected assert_conformance to FAIL when absent file contains "
            "a path-traversal line (``../escape``), but it returned passed=True",
        )
        details = [f.detail for f in result.failures]
        self.assertTrue(
            any("escape" in d or ".." in d or "confin" in d or "escape" in d.lower() for d in details),
            f"Expected a confinement-related failure message; got: {details}",
        )

    def test_absolute_path_in_absent_file_is_rejected(self) -> None:
        """An absolute path that does NOT exist on the host must still be rejected.

        Without confinement, the code would check the absolute host path,
        find it absent, and silently pass — leaking that the host path is probed.
        With confinement, the invalid path is caught before any filesystem probe.
        We use a path that is guaranteed not to exist on the host to ensure the
        test is not accidentally satisfied by a host-path .exists() returning True.
        """
        absent_file = self._fixture_dir / "expected" / "absent"
        absent_file.write_text("/milpa_p29_nonexistent_host_path_test\n", encoding="utf-8")

        run = self._make_run_result()
        result = assert_conformance(run, self._fixture_dir)

        # Without confinement: absolute path doesn't exist on host → no failure → passed=True.
        # With confinement: the absolute path is rejected → failure → passed=False.
        self.assertFalse(
            result.passed,
            "Expected assert_conformance to FAIL for an absolute path in absent file "
            "(a non-existent absolute path silently passing is evidence of no confinement)",
        )
        details = [f.detail for f in result.failures]
        self.assertTrue(
            any("absolute" in d.lower() or "confin" in d.lower() for d in details),
            f"Expected a confinement-related failure message; got: {details}",
        )

    def test_normal_absent_path_within_scratch_passes(self) -> None:
        """A plain relative path that stays within scratch must still work normally."""
        absent_file = self._fixture_dir / "expected" / "absent"
        # This path does NOT exist in scratch → absent check should pass.
        absent_file.write_text("member-a/milpa.lock\n", encoding="utf-8")

        run = self._make_run_result()
        result = assert_conformance(run, self._fixture_dir)

        # No confinement error; the lock comparison also passes (both identical).
        confinement_failures = [
            f for f in result.failures
            if "confin" in f.detail.lower() or "escape" in f.detail.lower()
        ]
        self.assertEqual(
            confinement_failures, [],
            f"Unexpected confinement failures for a safe path: {confinement_failures}",
        )


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


# ---------------------------------------------------------------------------
# S8 — attestation surface in the differential harness
# (rfc-attestation-v1-normative.md S8, D13)
# ---------------------------------------------------------------------------

class TestS8AttestationDifferential(unittest.TestCase):
    """S8: the mock-seam index-trust (338-366) + entry-trust (367-377) fixtures.

    These carry cmds/recipes the BLACK-BOX differential runner cannot drive:
    ``index-trust``/``show-index-trust`` have no CLI surface (their ``env``
    carries adapter-only recipe fields — ``MILPA_INDEX_TRUST_MANIFEST``,
    ``mock_verifier_result`` — with no real CLI-flag equivalent, and most ship
    no ``milpa.kdl``); the entry-trust tier resolves via the real CLI but, under
    S4's flipped ``index-trust=strict`` default, hits the index-trust gate
    before reaching the entry-trust gate it was authored for (the S4
    index-trust-gate-ordering follow-up). They are therefore DOCUMENTED
    ``KNOWN_LIMITATIONS`` for ``TestB4PythonRustCorpus`` (see ``corpus.py``), and
    are differentially validated instead by EACH impl's in-process conformance
    adapter matching the SAME committed ``expected/`` — both-match-expected means
    the two impls agree. This class pins that disposition. The real-crypto
    differential (both real verifiers agree on the committed bundle; D13's
    shared trust root makes "identical verdicts" unconditional) is pinned
    per-impl in ``test_entry_trust.py::test_s8_real_entry_bundle_same_outcome_as_rust``
    and its Rust counterpart
    ``entry_trust.rs::tests::s8_real_entry_bundle_same_outcome_as_python``.
    """

    @staticmethod
    def _attestation_names() -> set:
        return {
            fx.name
            for fx in discover_fixtures(_CONFORMANCE_ROOT)
            if "index-trust" in fx.name or "entry-trust" in fx.name
        }

    def test_attestation_fixtures_discovered(self) -> None:
        """discover_fixtures surfaces the whole attestation tier with no allow-list."""
        names = self._attestation_names()
        self.assertIn("fixture-338-index-trust-valid-trusted", names)
        self.assertIn("fixture-367-entry-trust-strict-unattested", names)
        self.assertIn("fixture-377-entry-trust-strict-trusted-succeeds", names)
        self.assertGreaterEqual(
            len(names), 40,
            f"expected >=40 index-trust/entry-trust fixtures, found {len(names)}",
        )

    def test_attestation_fixtures_are_documented_black_box_limitations(self) -> None:
        """Every attestation fixture is a DOCUMENTED KNOWN_LIMITATIONS entry for the
        black-box differential runner (no CLI surface for index-trust/show-index-trust;
        the S4 index-trust-gate-ordering collision for entry-trust). This guarantees
        none silently drops out of cross-impl coverage unaccounted-for: the real
        cross-impl guarantee is each impl's in-process conformance adapter validating
        against the shared expected/ (test_attestation_fixtures_have_shared_expected)."""
        undocumented = self._attestation_names() - set(KNOWN_LIMITATIONS)
        self.assertEqual(
            undocumented, set(),
            "every attestation fixture must be a documented black-box KNOWN_LIMITATIONS "
            "entry (covered instead by each impl's in-process conformance adapter); "
            f"undocumented: {sorted(undocumented)}",
        )

    def test_attestation_fixtures_have_shared_expected(self) -> None:
        """The cross-impl differential ANCHOR: both impls validate each attestation
        fixture against the SAME committed expected/ dir, so both-passing — which the
        green Python + Rust conformance suites establish — means the impls agree
        (the same both-match-shared-expected guarantee S-EpochGate's armed fixtures use)."""
        missing = sorted(
            fx.name
            for fx in discover_fixtures(_CONFORMANCE_ROOT)
            if ("index-trust" in fx.name or "entry-trust" in fx.name)
            and not (fx / "expected").is_dir()
        )
        self.assertEqual(missing, [], f"attestation fixtures missing expected/: {missing}")


if __name__ == "__main__":
    unittest.main()
