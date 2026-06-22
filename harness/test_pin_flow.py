"""Tests for the S-A4 pin flow in harness/pin.py.

Tests drive the NON-interactive core via a fake chooser and synthetic input
dirs in tmp (NOT the real corpus).

Cycle 1 (Diverge): given an input where the two impls DIVERGE, the flow emits
  a candidate fixture dir containing: inputs (milpa.kdl + cmd + mocked-fetches/)
  + expected/ from the chosen winner + divergence.json.
Cycle 2 (Agree): when impls AGREE, the flow raises NoDivergence.
Cycle 3 (Confirm): the post-pin re-run confirmation passes for the winner;
  the emitted expected/ structure matches what the winner produced.
Cycle 4 (Dispatch): ``python3 -m harness pin <dir>`` routes to the flow;
  bare ``python3 -m harness --help`` still describes corpus behavior (dispatch
  is also checked via the argparse tests below).

Design: pin_flow() accepts an injectable ``choose_winner`` callback so these
tests never touch stdin.  We use two fake ImplDescriptor-like wrappers that
write minimal output files directly (no subprocess) by monkey-patching
run_fixture at the harness.pin module level.  Alternatively — following the
pattern from test_divergence_detection.py — we inject pre-built RunResult and
ConformanceResult objects where possible.

For the full-flow tests (Cycles 1–3) we use a REAL fixture input directory
(minimal milpa.kdl + cmd) and two real Python subprocesses where feasible,
OR we patch run_fixture to inject synthetic RunResult objects so the tests run
fast without real impl invocations.  We choose the patch approach: it is
exact, fast, and avoids depending on the real impl binary.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from harness.assertions import AssertionFailure, ConformanceResult
from harness.corpus import DivergenceRecord
from harness.descriptors import ImplDescriptor
from harness.pin import NoDivergence, pin_flow
from harness.runner import RunResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_fixture_dir(tmp: Path, slug: Optional[str] = None) -> Path:
    """Write a minimal fixture dir to tmp (milpa.kdl + cmd).

    If slug is provided, also write expected/error so it looks like an error
    fixture from the harness's perspective.
    """
    fx = tmp / "input-fixture"
    fx.mkdir()
    (fx / "milpa.kdl").write_text(
        'name "testpkg"\nkind "application"\n', encoding="utf-8"
    )
    (fx / "cmd").write_text("resolve\n", encoding="utf-8")
    if slug:
        exp = fx / "expected"
        exp.mkdir()
        (exp / "error").write_text(slug + "\n", encoding="utf-8")
    return fx


def _make_run_result(
    impl_name: str,
    fixture_name: str,
    returncode: int,
    stdout: str = "",
    stderr: str = "",
    slug: Optional[str] = None,
    scratch_dir: Optional[str] = None,
    cas_dir: Optional[str] = None,
) -> RunResult:
    return RunResult(
        fixture_name=fixture_name,
        impl_name=impl_name,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        slug=slug,
        slug_error=None,
        scratch_dir=scratch_dir or tempfile.mkdtemp(prefix=f"milpa-pin-test-scratch-{impl_name}-"),
        cas_dir=cas_dir or tempfile.mkdtemp(prefix=f"milpa-pin-test-cas-{impl_name}-"),
    )


def _make_conformance_result(
    passed: bool,
    run: RunResult,
    outputs: Optional[dict] = None,
    detail: str = "mismatch",
) -> ConformanceResult:
    failures = (
        []
        if passed
        else [AssertionFailure(run.fixture_name, run.impl_name, "error-fixture", detail)]
    )
    return ConformanceResult(
        run=run,
        passed=passed,
        failures=failures,
        normalized_outputs=outputs or {},
    )


def _desc(name: str) -> ImplDescriptor:
    """Minimal fake descriptor (won't be used to actually spawn a process)."""
    return ImplDescriptor(name=name, argv=["echo"], cwd=None)


# ---------------------------------------------------------------------------
# Cycle 1 — divergence → candidate dir emitted with correct shape
# ---------------------------------------------------------------------------

class TestPinFlowDivergence(unittest.TestCase):
    """Cycle 1: impls diverge → candidate fixture dir with correct shape."""

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="milpa-pin-cycle1-"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_candidate_dir_shape_on_divergence(self) -> None:
        """Cycle 1: candidate dir has inputs + expected/ + divergence.json."""
        fx_dir = _minimal_fixture_dir(self._tmp)
        candidate_dir = self._tmp / "candidate"

        # Build fake RunResult objects with their own scratch dirs
        python_scratch = Path(tempfile.mkdtemp(prefix="milpa-pin-py-scratch-"))
        python_cas = Path(tempfile.mkdtemp(prefix="milpa-pin-py-cas-"))
        rust_scratch = Path(tempfile.mkdtemp(prefix="milpa-pin-rust-scratch-"))
        rust_cas = Path(tempfile.mkdtemp(prefix="milpa-pin-rust-cas-"))

        # Python "wins" — exit 0
        py_run = RunResult(
            fixture_name=fx_dir.name,
            impl_name="python",
            returncode=0,
            stdout="",
            stderr="",
            slug=None,
            slug_error=None,
            scratch_dir=str(python_scratch),
            cas_dir=str(python_cas),
        )
        # Write a minimal milpa.lock to python's scratch
        (python_scratch / "milpa.lock").write_text(
            'lock_version 1\n', encoding="utf-8"
        )

        # Rust "fails" — exit 1 with a slug
        rust_run = RunResult(
            fixture_name=fx_dir.name,
            impl_name="rust",
            returncode=1,
            stdout="",
            stderr="milpa-error: SOLVE-CONFLICT\n",
            slug="SOLVE-CONFLICT",
            slug_error=None,
            scratch_dir=str(rust_scratch),
            cas_dir=str(rust_cas),
        )

        py_cr = _make_conformance_result(True, py_run, {"expected/milpa.lock": "lock_version 1\n"})
        rust_cr = _make_conformance_result(False, rust_run, detail="wrong slug")

        descriptors = [_desc("python"), _desc("rust")]

        def fake_run_fixture(fixture_dir, desc, timeout=180):
            return py_run if desc.name == "python" else rust_run

        def fake_assert_conformance(run, fixture_dir):
            return py_cr if run.impl_name == "python" else rust_cr

        fake_chooser = lambda impl_names, runs: "python"

        with (
            patch("harness.pin.run_fixture", side_effect=fake_run_fixture),
            patch("harness.pin.assert_conformance", side_effect=fake_assert_conformance),
            patch("harness.pin._confirm_fixture_passes", return_value=(True, "ok")),
        ):
            result = pin_flow(
                input_dir=fx_dir,
                descriptors=descriptors,
                choose_winner=fake_chooser,
                candidate_dir=candidate_dir,
            )

        # (a) result points at candidate_dir
        self.assertEqual(result.resolve(), candidate_dir.resolve())

        # (b) fixture inputs copied (milpa.kdl + cmd)
        self.assertTrue((candidate_dir / "milpa.kdl").exists(), "milpa.kdl missing")
        self.assertTrue((candidate_dir / "cmd").exists(), "cmd missing")

        # (c) divergence.json present and well-shaped
        div_path = candidate_dir / "divergence.json"
        self.assertTrue(div_path.exists(), "divergence.json missing")
        div = json.loads(div_path.read_text(encoding="utf-8"))
        self.assertIn("fixture", div)
        self.assertIn("impls", div)

        # (d) expected/ present (from winner python)
        self.assertTrue((candidate_dir / "expected").exists(), "expected/ missing")

        # Cleanup scratch dirs
        shutil.rmtree(str(python_scratch), ignore_errors=True)
        shutil.rmtree(str(python_cas), ignore_errors=True)
        shutil.rmtree(str(rust_scratch), ignore_errors=True)
        shutil.rmtree(str(rust_cas), ignore_errors=True)

    def test_divergence_json_has_both_impls(self) -> None:
        """divergence.json records both impl outcomes."""
        fx_dir = _minimal_fixture_dir(self._tmp)
        candidate_dir = self._tmp / "candidate2"

        python_scratch = Path(tempfile.mkdtemp(prefix="milpa-pin-py2-scratch-"))
        python_cas = Path(tempfile.mkdtemp(prefix="milpa-pin-py2-cas-"))
        rust_scratch = Path(tempfile.mkdtemp(prefix="milpa-pin-rust2-scratch-"))
        rust_cas = Path(tempfile.mkdtemp(prefix="milpa-pin-rust2-cas-"))

        py_run = RunResult(
            fixture_name=fx_dir.name,
            impl_name="python",
            returncode=0,
            stdout="", stderr="", slug=None, slug_error=None,
            scratch_dir=str(python_scratch), cas_dir=str(python_cas),
        )
        rust_run = RunResult(
            fixture_name=fx_dir.name,
            impl_name="rust",
            returncode=1,
            stdout="", stderr="milpa-error: SOLVE-CONFLICT\n",
            slug="SOLVE-CONFLICT", slug_error=None,
            scratch_dir=str(rust_scratch), cas_dir=str(rust_cas),
        )

        py_cr = _make_conformance_result(True, py_run)
        rust_cr = _make_conformance_result(False, rust_run, detail="SOLVE-CONFLICT slug mismatch")

        def fake_run_fixture(fixture_dir, desc, timeout=180):
            return py_run if desc.name == "python" else rust_run

        def fake_assert_conformance(run, fixture_dir):
            return py_cr if run.impl_name == "python" else rust_cr

        with (
            patch("harness.pin.run_fixture", side_effect=fake_run_fixture),
            patch("harness.pin.assert_conformance", side_effect=fake_assert_conformance),
            patch("harness.pin._confirm_fixture_passes", return_value=(True, "ok")),
        ):
            pin_flow(
                input_dir=fx_dir,
                descriptors=[_desc("python"), _desc("rust")],
                choose_winner=lambda impl_names, runs: "python",
                candidate_dir=candidate_dir,
            )

        div = json.loads((candidate_dir / "divergence.json").read_text(encoding="utf-8"))
        self.assertIn("python", div["impls"])
        self.assertIn("rust", div["impls"])

        shutil.rmtree(str(python_scratch), ignore_errors=True)
        shutil.rmtree(str(python_cas), ignore_errors=True)
        shutil.rmtree(str(rust_scratch), ignore_errors=True)
        shutil.rmtree(str(rust_cas), ignore_errors=True)

    def test_default_candidate_dir_is_sibling(self) -> None:
        """When candidate_dir is not specified, it defaults to <input>-candidate/."""
        fx_dir = _minimal_fixture_dir(self._tmp)

        python_scratch = Path(tempfile.mkdtemp(prefix="milpa-pin-sib-py-scratch-"))
        python_cas = Path(tempfile.mkdtemp(prefix="milpa-pin-sib-py-cas-"))
        rust_scratch = Path(tempfile.mkdtemp(prefix="milpa-pin-sib-rust-scratch-"))
        rust_cas = Path(tempfile.mkdtemp(prefix="milpa-pin-sib-rust-cas-"))

        py_run = RunResult(
            fixture_name=fx_dir.name, impl_name="python",
            returncode=0, stdout="", stderr="", slug=None, slug_error=None,
            scratch_dir=str(python_scratch), cas_dir=str(python_cas),
        )
        rust_run = RunResult(
            fixture_name=fx_dir.name, impl_name="rust",
            returncode=1, stdout="", stderr="milpa-error: SOLVE-CONFLICT\n",
            slug="SOLVE-CONFLICT", slug_error=None,
            scratch_dir=str(rust_scratch), cas_dir=str(rust_cas),
        )

        py_cr = _make_conformance_result(True, py_run)
        rust_cr = _make_conformance_result(False, rust_run)

        with (
            patch("harness.pin.run_fixture", side_effect=lambda d, desc, timeout=180: py_run if desc.name == "python" else rust_run),
            patch("harness.pin.assert_conformance", side_effect=lambda run, fd: py_cr if run.impl_name == "python" else rust_cr),
            patch("harness.pin._confirm_fixture_passes", return_value=(True, "ok")),
        ):
            result = pin_flow(
                input_dir=fx_dir,
                descriptors=[_desc("python"), _desc("rust")],
                choose_winner=lambda impl_names, runs: "python",
                candidate_dir=None,  # default
            )

        expected_default = fx_dir.parent / (fx_dir.name + "-candidate")
        self.assertEqual(result.resolve(), expected_default.resolve())

        shutil.rmtree(str(python_scratch), ignore_errors=True)
        shutil.rmtree(str(python_cas), ignore_errors=True)
        shutil.rmtree(str(rust_scratch), ignore_errors=True)
        shutil.rmtree(str(rust_cas), ignore_errors=True)


# ---------------------------------------------------------------------------
# Cycle 2 — agreement → NoDivergence raised, no fixture written
# ---------------------------------------------------------------------------

class TestPinFlowNoDivergence(unittest.TestCase):
    """Cycle 2: impls agree → NoDivergence raised, nothing written."""

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="milpa-pin-cycle2-"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_no_divergence_raises_no_divergence(self) -> None:
        """Both impls pass the same output → NoDivergence exception."""
        fx_dir = _minimal_fixture_dir(self._tmp)
        candidate_dir = self._tmp / "should-not-exist"

        python_scratch = Path(tempfile.mkdtemp(prefix="milpa-pin-agree-py-scratch-"))
        python_cas = Path(tempfile.mkdtemp(prefix="milpa-pin-agree-py-cas-"))
        rust_scratch = Path(tempfile.mkdtemp(prefix="milpa-pin-agree-rust-scratch-"))
        rust_cas = Path(tempfile.mkdtemp(prefix="milpa-pin-agree-rust-cas-"))

        same_outputs = {"expected/milpa.lock": "lock_version 1\n"}

        py_run = RunResult(
            fixture_name=fx_dir.name, impl_name="python",
            returncode=0, stdout="", stderr="", slug=None, slug_error=None,
            scratch_dir=str(python_scratch), cas_dir=str(python_cas),
        )
        rust_run = RunResult(
            fixture_name=fx_dir.name, impl_name="rust",
            returncode=0, stdout="", stderr="", slug=None, slug_error=None,
            scratch_dir=str(rust_scratch), cas_dir=str(rust_cas),
        )

        py_cr = _make_conformance_result(True, py_run, same_outputs)
        rust_cr = _make_conformance_result(True, rust_run, same_outputs)

        chooser_called = []

        def fake_chooser(impl_names, runs):
            chooser_called.append(True)
            return "python"

        with (
            patch("harness.pin.run_fixture", side_effect=lambda d, desc, timeout=180: py_run if desc.name == "python" else rust_run),
            patch("harness.pin.assert_conformance", side_effect=lambda run, fd: py_cr if run.impl_name == "python" else rust_cr),
        ):
            with self.assertRaises(NoDivergence):
                pin_flow(
                    input_dir=fx_dir,
                    descriptors=[_desc("python"), _desc("rust")],
                    choose_winner=fake_chooser,
                    candidate_dir=candidate_dir,
                )

        # chooser must NOT have been called (no divergence → no gate)
        self.assertEqual(chooser_called, [], "chooser should not be called when impls agree")
        # candidate dir must NOT have been written
        self.assertFalse(candidate_dir.exists(), "candidate dir must not be written on NoDivergence")

        shutil.rmtree(str(python_scratch), ignore_errors=True)
        shutil.rmtree(str(python_cas), ignore_errors=True)
        shutil.rmtree(str(rust_scratch), ignore_errors=True)
        shutil.rmtree(str(rust_cas), ignore_errors=True)


# ---------------------------------------------------------------------------
# Cycle 3 — confirmation re-run: the emitted fixture passes
# ---------------------------------------------------------------------------

class TestPinFlowConfirmation(unittest.TestCase):
    """Cycle 3: the post-pin re-run confirmation passes for the winner."""

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="milpa-pin-cycle3-"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_confirmation_pass_returns_candidate_dir(self) -> None:
        """When confirmation passes, pin_flow returns the candidate path."""
        fx_dir = _minimal_fixture_dir(self._tmp)
        candidate_dir = self._tmp / "confirmed-candidate"

        python_scratch = Path(tempfile.mkdtemp(prefix="milpa-pin-conf-py-scratch-"))
        python_cas = Path(tempfile.mkdtemp(prefix="milpa-pin-conf-py-cas-"))
        rust_scratch = Path(tempfile.mkdtemp(prefix="milpa-pin-conf-rust-scratch-"))
        rust_cas = Path(tempfile.mkdtemp(prefix="milpa-pin-conf-rust-cas-"))

        py_run = RunResult(
            fixture_name=fx_dir.name, impl_name="python",
            returncode=0, stdout="", stderr="", slug=None, slug_error=None,
            scratch_dir=str(python_scratch), cas_dir=str(python_cas),
        )
        rust_run = RunResult(
            fixture_name=fx_dir.name, impl_name="rust",
            returncode=1, stdout="", stderr="milpa-error: SOLVE-CONFLICT\n",
            slug="SOLVE-CONFLICT", slug_error=None,
            scratch_dir=str(rust_scratch), cas_dir=str(rust_cas),
        )

        py_cr = _make_conformance_result(True, py_run)
        rust_cr = _make_conformance_result(False, rust_run)

        confirm_calls = []

        def fake_confirm(candidate_dir, winner_desc, timeout=180):
            confirm_calls.append(winner_desc.name)
            return True, f"Confirmed pass for {winner_desc.name}"

        with (
            patch("harness.pin.run_fixture", side_effect=lambda d, desc, timeout=180: py_run if desc.name == "python" else rust_run),
            patch("harness.pin.assert_conformance", side_effect=lambda run, fd: py_cr if run.impl_name == "python" else rust_cr),
            patch("harness.pin._confirm_fixture_passes", side_effect=fake_confirm),
        ):
            result = pin_flow(
                input_dir=fx_dir,
                descriptors=[_desc("python"), _desc("rust")],
                choose_winner=lambda impl_names, runs: "python",
                candidate_dir=candidate_dir,
            )

        self.assertEqual(result.resolve(), candidate_dir.resolve())
        # Confirmation was called for the WINNER (python)
        self.assertEqual(confirm_calls, ["python"])

        shutil.rmtree(str(python_scratch), ignore_errors=True)
        shutil.rmtree(str(python_cas), ignore_errors=True)
        shutil.rmtree(str(rust_scratch), ignore_errors=True)
        shutil.rmtree(str(rust_cas), ignore_errors=True)

    def test_confirmation_failure_raises_runtime_error(self) -> None:
        """When the confirmation run fails, pin_flow raises RuntimeError."""
        fx_dir = _minimal_fixture_dir(self._tmp)
        candidate_dir = self._tmp / "fail-confirm-candidate"

        python_scratch = Path(tempfile.mkdtemp(prefix="milpa-pin-fail-py-scratch-"))
        python_cas = Path(tempfile.mkdtemp(prefix="milpa-pin-fail-py-cas-"))
        rust_scratch = Path(tempfile.mkdtemp(prefix="milpa-pin-fail-rust-scratch-"))
        rust_cas = Path(tempfile.mkdtemp(prefix="milpa-pin-fail-rust-cas-"))

        py_run = RunResult(
            fixture_name=fx_dir.name, impl_name="python",
            returncode=0, stdout="", stderr="", slug=None, slug_error=None,
            scratch_dir=str(python_scratch), cas_dir=str(python_cas),
        )
        rust_run = RunResult(
            fixture_name=fx_dir.name, impl_name="rust",
            returncode=1, stdout="", stderr="milpa-error: SOLVE-CONFLICT\n",
            slug="SOLVE-CONFLICT", slug_error=None,
            scratch_dir=str(rust_scratch), cas_dir=str(rust_cas),
        )

        py_cr = _make_conformance_result(True, py_run)
        rust_cr = _make_conformance_result(False, rust_run)

        with (
            patch("harness.pin.run_fixture", side_effect=lambda d, desc, timeout=180: py_run if desc.name == "python" else rust_run),
            patch("harness.pin.assert_conformance", side_effect=lambda run, fd: py_cr if run.impl_name == "python" else rust_cr),
            patch("harness.pin._confirm_fixture_passes", return_value=(False, "fixture FAILED for python")),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                pin_flow(
                    input_dir=fx_dir,
                    descriptors=[_desc("python"), _desc("rust")],
                    choose_winner=lambda impl_names, runs: "python",
                    candidate_dir=candidate_dir,
                )

        self.assertIn("FAILED", str(ctx.exception))

        shutil.rmtree(str(python_scratch), ignore_errors=True)
        shutil.rmtree(str(python_cas), ignore_errors=True)
        shutil.rmtree(str(rust_scratch), ignore_errors=True)
        shutil.rmtree(str(rust_cas), ignore_errors=True)


# ---------------------------------------------------------------------------
# Cycle 4 — argparse dispatch
# ---------------------------------------------------------------------------

class TestPinDispatch(unittest.TestCase):
    """Cycle 4: argparse routing — ``pin <dir>`` routes to cmd_pin;
    bare invocation still runs the corpus path."""

    def test_pin_subcommand_in_help(self) -> None:
        """``python3 -m harness pin --help`` exits 0 and mentions pin."""
        result = subprocess.run(
            [sys.executable, "-m", "harness", "pin", "--help"],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("pin", result.stdout.lower())

    def test_bare_help_still_works(self) -> None:
        """``python3 -m harness --help`` exits 0 and describes corpus behavior."""
        result = subprocess.run(
            [sys.executable, "-m", "harness", "--help"],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        # Should mention corpus or conformance behavior
        combined = result.stdout + result.stderr
        self.assertTrue(
            "corpus" in combined.lower() or "conformance" in combined.lower(),
            f"Expected corpus/conformance in help; got: {combined[:500]}",
        )

    def test_pin_missing_arg_is_error(self) -> None:
        """``python3 -m harness pin`` (no dir) exits non-zero with usage message."""
        result = subprocess.run(
            [sys.executable, "-m", "harness", "pin"],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_pin_nonexistent_dir_is_error(self) -> None:
        """``python3 -m harness pin /nonexistent/path`` exits 1."""
        result = subprocess.run(
            [sys.executable, "-m", "harness", "pin", "/nonexistent/path/that/does/not/exist"],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 1)
        combined = result.stdout + result.stderr
        self.assertIn("not a directory", combined.lower())


# ---------------------------------------------------------------------------
# chooser_called_with_correct_args
# ---------------------------------------------------------------------------

class TestChooserArguments(unittest.TestCase):
    """The chooser is called with the right impl_names and run_results."""

    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="milpa-pin-chooser-"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_chooser_receives_impl_names_and_runs(self) -> None:
        """chooser(impl_names, run_results) is called with both impl names."""
        fx_dir = _minimal_fixture_dir(self._tmp)

        python_scratch = Path(tempfile.mkdtemp(prefix="milpa-chooser-py-"))
        python_cas = Path(tempfile.mkdtemp(prefix="milpa-chooser-py-cas-"))
        rust_scratch = Path(tempfile.mkdtemp(prefix="milpa-chooser-rust-"))
        rust_cas = Path(tempfile.mkdtemp(prefix="milpa-chooser-rust-cas-"))

        py_run = RunResult(
            fixture_name=fx_dir.name, impl_name="python",
            returncode=0, stdout="", stderr="", slug=None, slug_error=None,
            scratch_dir=str(python_scratch), cas_dir=str(python_cas),
        )
        rust_run = RunResult(
            fixture_name=fx_dir.name, impl_name="rust",
            returncode=1, stdout="", stderr="milpa-error: SLUG\n",
            slug="SLUG", slug_error=None,
            scratch_dir=str(rust_scratch), cas_dir=str(rust_cas),
        )

        py_cr = _make_conformance_result(True, py_run)
        rust_cr = _make_conformance_result(False, rust_run)

        captured = {}

        def recording_chooser(impl_names, run_results):
            captured["impl_names"] = list(impl_names)
            captured["run_result_keys"] = list(run_results.keys())
            return "python"

        with (
            patch("harness.pin.run_fixture", side_effect=lambda d, desc, timeout=180: py_run if desc.name == "python" else rust_run),
            patch("harness.pin.assert_conformance", side_effect=lambda run, fd: py_cr if run.impl_name == "python" else rust_cr),
            patch("harness.pin._confirm_fixture_passes", return_value=(True, "ok")),
        ):
            pin_flow(
                input_dir=fx_dir,
                descriptors=[_desc("python"), _desc("rust")],
                choose_winner=recording_chooser,
                candidate_dir=self._tmp / "chooser-candidate",
            )

        self.assertIn("python", captured["impl_names"])
        self.assertIn("rust", captured["impl_names"])
        self.assertIn("python", captured["run_result_keys"])
        self.assertIn("rust", captured["run_result_keys"])

        shutil.rmtree(str(python_scratch), ignore_errors=True)
        shutil.rmtree(str(python_cas), ignore_errors=True)
        shutil.rmtree(str(rust_scratch), ignore_errors=True)
        shutil.rmtree(str(rust_cas), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
