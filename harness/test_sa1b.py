"""S-A1b — new normative enforcement tests: EMPTY_STDOUT_VERBS + exact exit codes.

RED→GREEN structure:
- Cycle 1 (empty-stdout): prove EMPTY_STDOUT_VERBS constant exists and is wired
  in assertions.py for success/clean fixtures.
- Cycle 2 (exit code): prove the mismatch message names actual vs expected code,
  and that NORMATIVE_EXIT_CODES covers {0, 1, 2}.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import surfaces


def _minimal_run(**overrides):
    from harness.runner import RunResult

    tmpdir = tempfile.mkdtemp(prefix="milpa-sa1b-")
    defaults = dict(
        fixture_name="test",
        impl_name="python",
        returncode=0,
        stdout="",
        stderr="",
        slug=None,
        slug_error=None,
        scratch_dir=tmpdir,
        cas_dir=tmpdir,
        cert_path=None,
    )
    defaults.update(overrides)
    return RunResult(**defaults), tmpdir


# ---------------------------------------------------------------------------
# Cycle 1: EMPTY_STDOUT_VERBS value tests
# ---------------------------------------------------------------------------


class TestEmptyStdoutVerbsValues(unittest.TestCase):
    """Assert the EMPTY_STDOUT_VERBS constant exists with the correct members."""

    def test_empty_stdout_verbs_is_frozenset(self) -> None:
        self.assertIsInstance(surfaces.EMPTY_STDOUT_VERBS, frozenset)

    def test_empty_stdout_verbs_contains_all_seven(self) -> None:
        expected = frozenset({"fetch", "lock", "verify", "clean", "add", "remove", "update"})
        self.assertEqual(surfaces.EMPTY_STDOUT_VERBS, expected)

    def test_show_not_in_empty_stdout_verbs(self) -> None:
        self.assertNotIn("show", surfaces.EMPTY_STDOUT_VERBS)

    def test_version_not_in_empty_stdout_verbs(self) -> None:
        self.assertNotIn("--version", surfaces.EMPTY_STDOUT_VERBS)


# ---------------------------------------------------------------------------
# Cycle 1: enforcement wired in assertions.py
# ---------------------------------------------------------------------------


class TestEmptyStdoutEnforcement(unittest.TestCase):
    """Prove assertions.py enforces EMPTY_STDOUT_VERBS on success/clean paths."""

    def setUp(self) -> None:
        self._tmpdirs: list[str] = []

    def tearDown(self) -> None:
        for d in self._tmpdirs:
            shutil.rmtree(d, ignore_errors=True)

    def _make_fixture(self, cmd: str = "fetch") -> Path:
        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1b-fx-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        (fx_dir / "cmd").write_text(f"{cmd}\n")
        expected = fx_dir / "expected"
        expected.mkdir()
        # Write a milpa.lock so the success-path lock diff is satisfied.
        lock_content = "lock-content\n"
        (expected / "milpa.lock").write_text(lock_content)
        return fx_dir, lock_content

    # ----- RED cases: non-empty stdout on EMPTY_STDOUT_VERBS must fail -----

    def test_fetch_with_nonempty_stdout_fails(self) -> None:
        """fetch is in EMPTY_STDOUT_VERBS — non-empty stdout on success must fail."""
        from harness.assertions import assert_conformance

        fx_dir, lock_content = self._make_fixture(cmd="fetch")
        run, tmpdir = _minimal_run(
            returncode=0,
            stdout="some unexpected output\n",  # must trigger failure
        )
        self._tmpdirs.append(tmpdir)
        # Write matching milpa.lock in scratch.
        Path(run.scratch_dir).joinpath("milpa.lock").write_text(lock_content)

        result = assert_conformance(run, fx_dir)
        self.assertFalse(
            result.passed,
            "fetch with non-empty stdout must fail the empty-stdout enforcement; "
            f"failures: {[f.detail for f in result.failures]}",
        )
        self.assertTrue(
            any("stdout" in f.detail.lower() for f in result.failures),
            f"Failure detail must mention stdout; got: {[f.detail for f in result.failures]}",
        )

    def test_lock_with_nonempty_stdout_fails(self) -> None:
        """lock is in EMPTY_STDOUT_VERBS — non-empty stdout on success must fail."""
        from harness.assertions import assert_conformance

        fx_dir, lock_content = self._make_fixture(cmd="lock")
        run, tmpdir = _minimal_run(
            returncode=0,
            stdout="lock output\n",
        )
        self._tmpdirs.append(tmpdir)
        Path(run.scratch_dir).joinpath("milpa.lock").write_text(lock_content)

        result = assert_conformance(run, fx_dir)
        self.assertFalse(result.passed)

    def test_verify_with_nonempty_stdout_fails(self) -> None:
        """verify is in EMPTY_STDOUT_VERBS."""
        from harness.assertions import assert_conformance

        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1b-verify-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        (fx_dir / "cmd").write_text("verify\n")
        (fx_dir / "expected").mkdir()
        # verify success fixtures need no output files, just exit 0
        run, tmpdir = _minimal_run(returncode=0, stdout="unexpected\n")
        self._tmpdirs.append(tmpdir)

        result = assert_conformance(run, fx_dir)
        self.assertFalse(result.passed)

    def test_add_with_nonempty_stdout_fails(self) -> None:
        """add is in EMPTY_STDOUT_VERBS."""
        from harness.assertions import assert_conformance

        fx_dir, lock_content = self._make_fixture(cmd="add somelib")
        run, tmpdir = _minimal_run(returncode=0, stdout="adding...\n")
        self._tmpdirs.append(tmpdir)
        Path(run.scratch_dir).joinpath("milpa.lock").write_text(lock_content)

        result = assert_conformance(run, fx_dir)
        self.assertFalse(result.passed)

    # ----- GREEN cases: empty stdout on EMPTY_STDOUT_VERBS must pass -----

    def test_fetch_with_empty_stdout_passes(self) -> None:
        """fetch with empty stdout (correct) must pass the empty-stdout enforcement."""
        from harness.assertions import assert_conformance

        fx_dir, lock_content = self._make_fixture(cmd="fetch")
        run, tmpdir = _minimal_run(returncode=0, stdout="")
        self._tmpdirs.append(tmpdir)
        Path(run.scratch_dir).joinpath("milpa.lock").write_text(lock_content)

        result = assert_conformance(run, fx_dir)
        self.assertTrue(
            result.passed,
            f"fetch with empty stdout must pass; failures: {[f.detail for f in result.failures]}",
        )

    def test_lock_with_empty_stdout_passes(self) -> None:
        """lock with empty stdout must pass."""
        from harness.assertions import assert_conformance

        fx_dir, lock_content = self._make_fixture(cmd="lock")
        run, tmpdir = _minimal_run(returncode=0, stdout="")
        self._tmpdirs.append(tmpdir)
        Path(run.scratch_dir).joinpath("milpa.lock").write_text(lock_content)

        result = assert_conformance(run, fx_dir)
        self.assertTrue(
            result.passed,
            f"lock with empty stdout must pass; failures: {[f.detail for f in result.failures]}",
        )

    # ----- Liveness cmds with non-empty stdout must still PASS -----

    def test_show_with_nonempty_stdout_passes(self) -> None:
        """show is a liveness cmd — non-empty stdout is expected, not forbidden."""
        from harness.assertions import assert_conformance

        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1b-show-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        (fx_dir / "cmd").write_text("show\n")
        (fx_dir / "expected").mkdir()

        run, tmpdir = _minimal_run(returncode=0, stdout="dep tree output\n")
        self._tmpdirs.append(tmpdir)

        result = assert_conformance(run, fx_dir)
        self.assertTrue(
            result.passed,
            f"show with non-empty stdout must pass (liveness); "
            f"failures: {[f.detail for f in result.failures]}",
        )

    def test_version_with_nonempty_stdout_passes(self) -> None:
        """--version is a liveness cmd — non-empty stdout is expected."""
        from harness.assertions import assert_conformance

        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1b-ver-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        (fx_dir / "cmd").write_text("--version\n")
        (fx_dir / "expected").mkdir()

        run, tmpdir = _minimal_run(returncode=0, stdout="milpa 0.1.0\n")
        self._tmpdirs.append(tmpdir)

        result = assert_conformance(run, fx_dir)
        self.assertTrue(
            result.passed,
            f"--version with non-empty stdout must pass (liveness); "
            f"failures: {[f.detail for f in result.failures]}",
        )

    # ----- Derivation proof: EMPTY_STDOUT_VERBS patch propagates -----

    def test_empty_stdout_verbs_patch_propagates(self) -> None:
        """Patch EMPTY_STDOUT_VERBS to include a sentinel verb.

        Fixture cmd = SENTINEL-VERB + non-empty stdout + exit 0 + milpa.lock.
        With patch: must fail (non-empty stdout on EMPTY_STDOUT_VERBS verb).
        Without patch: SENTINEL-VERB goes through success path; milpa.lock matches → passes.
        """
        import harness.surfaces as surf_mod
        from harness.assertions import assert_conformance

        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1b-patch-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        (fx_dir / "cmd").write_text("SENTINEL-VERB\n")
        expected = fx_dir / "expected"
        expected.mkdir()
        lock_content = "sentinel-lock\n"
        (expected / "milpa.lock").write_text(lock_content)

        run, tmpdir = _minimal_run(returncode=0, stdout="non-empty\n")
        self._tmpdirs.append(tmpdir)
        Path(run.scratch_dir).joinpath("milpa.lock").write_text(lock_content)

        patched_verbs = frozenset(surf_mod.EMPTY_STDOUT_VERBS | {"SENTINEL-VERB"})
        with patch.object(surf_mod, "EMPTY_STDOUT_VERBS", patched_verbs):
            result_patched = assert_conformance(run, fx_dir)

        result_unpatched = assert_conformance(run, fx_dir)

        self.assertFalse(
            result_patched.passed,
            "With EMPTY_STDOUT_VERBS patched to include SENTINEL-VERB, "
            "non-empty stdout must be flagged as a failure; "
            f"failures: {[f.detail for f in result_patched.failures]}",
        )
        self.assertTrue(
            result_unpatched.passed,
            "Without patch, SENTINEL-VERB is not in EMPTY_STDOUT_VERBS; "
            "milpa.lock matches → must pass; "
            f"failures: {[f.detail for f in result_unpatched.failures]}",
        )


# ---------------------------------------------------------------------------
# Cycle 2: NORMATIVE_EXIT_CODES value tests
# ---------------------------------------------------------------------------


class TestNormativeExitCodesValues(unittest.TestCase):
    """Assert NORMATIVE_EXIT_CODES exists with the correct members."""

    def test_normative_exit_codes_is_frozenset(self) -> None:
        self.assertIsInstance(surfaces.NORMATIVE_EXIT_CODES, frozenset)

    def test_normative_exit_codes_contains_zero(self) -> None:
        self.assertIn(0, surfaces.NORMATIVE_EXIT_CODES)

    def test_normative_exit_codes_contains_one(self) -> None:
        self.assertIn(1, surfaces.NORMATIVE_EXIT_CODES)

    def test_normative_exit_codes_contains_two(self) -> None:
        self.assertIn(2, surfaces.NORMATIVE_EXIT_CODES)

    def test_normative_exit_codes_exactly_three_values(self) -> None:
        self.assertEqual(surfaces.NORMATIVE_EXIT_CODES, frozenset({0, 1, 2}))


# ---------------------------------------------------------------------------
# Cycle 2: exit-code mismatch message quality
# ---------------------------------------------------------------------------


class TestExitCodeMismatchMessage(unittest.TestCase):
    """Prove that exact-code mismatches produce messages naming actual vs expected."""

    def setUp(self) -> None:
        self._tmpdirs: list[str] = []

    def tearDown(self) -> None:
        for d in self._tmpdirs:
            shutil.rmtree(d, ignore_errors=True)

    def _error_fixture_dir(self) -> Path:
        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1b-ec-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        expected = fx_dir / "expected"
        expected.mkdir()
        (expected / "error").write_text("SOME-ERROR\n")
        return fx_dir

    def _success_fixture_dir(self) -> Path:
        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1b-ecs-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        expected = fx_dir / "expected"
        expected.mkdir()
        lock_content = "lock\n"
        (expected / "milpa.lock").write_text(lock_content)
        return fx_dir, lock_content

    def test_error_fixture_wrong_exact_code_is_flagged(self) -> None:
        """An error fixture where the impl exits 2 (not 1) must be flagged.

        This is the 'impl exits 2 where another exits 1' divergence.
        """
        from harness.assertions import assert_conformance

        fx_dir = self._error_fixture_dir()
        run, tmpdir = _minimal_run(returncode=2, slug=None)
        self._tmpdirs.append(tmpdir)

        result = assert_conformance(run, fx_dir)
        self.assertFalse(
            result.passed,
            "Error fixture with returncode=2 (expected 1) must fail",
        )

    def test_error_fixture_wrong_code_message_names_actual_and_expected(self) -> None:
        """The failure detail for a wrong exit code must name both actual and expected."""
        from harness.assertions import assert_conformance

        fx_dir = self._error_fixture_dir()
        run, tmpdir = _minimal_run(returncode=2, slug=None)
        self._tmpdirs.append(tmpdir)

        result = assert_conformance(run, fx_dir)
        self.assertFalse(result.passed)
        details = " ".join(f.detail for f in result.failures)
        self.assertIn(
            "1", details,
            f"Failure detail must name expected exit code 1; got: {details}",
        )
        self.assertIn(
            "2", details,
            f"Failure detail must name actual exit code 2; got: {details}",
        )

    def test_success_fixture_wrong_exact_code_is_flagged(self) -> None:
        """A success fixture where the impl exits 2 (not 0) must be flagged.

        Exit 2 is a usage-error (§3) — not a clean failure — so the harness
        must distinguish it from exit 0.
        """
        from harness.assertions import assert_conformance

        fx_dir, lock_content = self._success_fixture_dir()
        run, tmpdir = _minimal_run(returncode=2, stdout="", slug=None)
        self._tmpdirs.append(tmpdir)

        result = assert_conformance(run, fx_dir)
        self.assertFalse(
            result.passed,
            "Success fixture with returncode=2 (expected 0) must fail",
        )
        details = " ".join(f.detail for f in result.failures)
        self.assertIn(
            "2", details,
            f"Failure detail must name actual exit code 2; got: {details}",
        )
        self.assertIn(
            "0", details,
            f"Failure detail must name expected exit code 0; got: {details}",
        )

    def test_error_fixture_correct_code_still_passes(self) -> None:
        """Sanity: exit 1 on an error fixture with correct slug still passes."""
        from harness.assertions import assert_conformance

        fx_dir = self._error_fixture_dir()
        run, tmpdir = _minimal_run(returncode=1, slug="SOME-ERROR")
        self._tmpdirs.append(tmpdir)

        result = assert_conformance(run, fx_dir)
        self.assertTrue(
            result.passed,
            f"exit 1 + correct slug must pass; failures: {[f.detail for f in result.failures]}",
        )

    def test_success_fixture_correct_code_still_passes(self) -> None:
        """Sanity: exit 0 on a success fixture with correct lock still passes."""
        from harness.assertions import assert_conformance

        fx_dir, lock_content = self._success_fixture_dir()
        run, tmpdir = _minimal_run(returncode=0, stdout="")
        self._tmpdirs.append(tmpdir)
        Path(run.scratch_dir).joinpath("milpa.lock").write_text(lock_content)

        result = assert_conformance(run, fx_dir)
        self.assertTrue(
            result.passed,
            f"exit 0 + correct lock must pass; failures: {[f.detail for f in result.failures]}",
        )


# ---------------------------------------------------------------------------
# Cycle 3: NORMATIVE_EXIT_CODES baseline enforcement (RED→GREEN)
# ---------------------------------------------------------------------------


class TestNormativeExitCodesEnforcement(unittest.TestCase):
    """Prove assert_conformance flags any returncode outside NORMATIVE_EXIT_CODES.

    RED: before wiring, a returncode of 127 (crash/segv class) is not caught
    by the per-class checks (which only compare against their expected code) and
    is never checked against NORMATIVE_EXIT_CODES — so the baseline passes when
    it should not.  After wiring the baseline catches it regardless of fixture
    class.

    The chokepoint must be in assert_conformance itself, so the check runs for
    every fixture class (success, error, liveness, clean, check-certificate)
    without per-class copy-paste.
    """

    def setUp(self) -> None:
        self._tmpdirs: list[str] = []

    def tearDown(self) -> None:
        for d in self._tmpdirs:
            shutil.rmtree(d, ignore_errors=True)

    def _success_fixture_dir(self) -> tuple[Path, str]:
        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1b-nc-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        (fx_dir / "expected").mkdir()
        lock_content = "lock\n"
        (fx_dir / "expected" / "milpa.lock").write_text(lock_content)
        return fx_dir, lock_content

    def _error_fixture_dir(self) -> Path:
        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1b-nce-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        (fx_dir / "expected").mkdir()
        (fx_dir / "expected" / "error").write_text("SOME-ERROR\n")
        return fx_dir

    # ----- RED: out-of-range returncode must be flagged -----

    def test_out_of_range_returncode_flagged_on_success_fixture(self) -> None:
        """returncode 127 (crash class) on a success fixture must be flagged as
        a normative failure citing cli-contract §3.

        This is the core RED test: before NORMATIVE_EXIT_CODES is wired as a
        baseline check in assert_conformance, a returncode of 127 on a success
        fixture only triggers the per-class 'expected 0, got 127' check — the
        test below verifies the ADDITIONAL normative-range failure that names
        the out-of-range code and cites cli-contract §3.
        """
        from harness.assertions import assert_conformance

        fx_dir, lock_content = self._success_fixture_dir()
        run, tmpdir = _minimal_run(returncode=127, stdout="", slug=None)
        self._tmpdirs.append(tmpdir)

        result = assert_conformance(run, fx_dir)
        self.assertFalse(result.passed, "returncode 127 must fail")

        # The failure set must include a normative-range failure that names
        # the actual code (127) and cites cli-contract §3.
        details = " ".join(f.detail for f in result.failures)
        self.assertIn(
            "127", details,
            f"Failure must name the out-of-range code 127; got: {details}",
        )
        self.assertIn(
            "cli-contract", details,
            f"Failure must cite cli-contract §3; got: {details}",
        )

    def test_out_of_range_returncode_flagged_on_error_fixture(self) -> None:
        """returncode 127 on an error fixture must also be flagged at the baseline.

        Ensures the normative-range check is not per-class but fires universally
        in the assert_conformance chokepoint, regardless of fixture class.
        """
        from harness.assertions import assert_conformance

        fx_dir = self._error_fixture_dir()
        run, tmpdir = _minimal_run(returncode=127, slug=None)
        self._tmpdirs.append(tmpdir)

        result = assert_conformance(run, fx_dir)
        self.assertFalse(result.passed, "returncode 127 on error fixture must fail")

        details = " ".join(f.detail for f in result.failures)
        self.assertIn("127", details, f"Must name 127; got: {details}")
        self.assertIn(
            "cli-contract", details,
            f"Must cite cli-contract §3; got: {details}",
        )

    # ----- GREEN: in-range returncodes must NOT trigger the baseline -----

    def test_returncode_2_not_flagged_by_normative_range_check(self) -> None:
        """returncode 2 is IN NORMATIVE_EXIT_CODES — the baseline must not flag it.

        The per-class check will still flag it (success fixture expects 0, got 2),
        but no failure should mention cli-contract §3 as the normative range
        violation — that detail is reserved for truly out-of-range codes.
        """
        from harness.assertions import assert_conformance

        fx_dir, lock_content = self._success_fixture_dir()
        run, tmpdir = _minimal_run(returncode=2, stdout="", slug=None)
        self._tmpdirs.append(tmpdir)

        result = assert_conformance(run, fx_dir)
        self.assertFalse(result.passed, "returncode 2 on success fixture fails the class check")

        # The failure(s) here come from the per-class 'expected 0, got 2' check
        # — NOT from the normative-range baseline (2 is in {0,1,2}).
        # None of the failure details should cite the normative-range violation.
        normative_range_failures = [
            f for f in result.failures
            if "cli-contract" in f.detail and "§3" in f.detail and "127" not in f.detail
            # narrow to the "out of range" message, not the per-class mismatch
        ]
        # Specifically: no failure should say the code is outside NORMATIVE_EXIT_CODES.
        out_of_range_failures = [
            f for f in result.failures
            if "outside" in f.detail or "out of range" in f.detail or "not in" in f.detail.lower()
        ]
        self.assertEqual(
            out_of_range_failures, [],
            f"returncode 2 is valid per cli-contract §3 — must not be flagged "
            f"as out-of-range; got: {[f.detail for f in out_of_range_failures]}",
        )

    def test_returncode_0_not_flagged_by_normative_range_check(self) -> None:
        """returncode 0 is the canonical success code — must not be flagged."""
        from harness.assertions import assert_conformance

        fx_dir, lock_content = self._success_fixture_dir()
        run, tmpdir = _minimal_run(returncode=0, stdout="")
        self._tmpdirs.append(tmpdir)
        Path(run.scratch_dir).joinpath("milpa.lock").write_text(lock_content)

        result = assert_conformance(run, fx_dir)
        self.assertTrue(
            result.passed,
            f"returncode 0 + correct lock must pass; failures: {[f.detail for f in result.failures]}",
        )


# ---------------------------------------------------------------------------
# Cycle 3: surfaces.py module-load invariant
# ---------------------------------------------------------------------------


class TestExpectedExitCodeInvariant(unittest.TestCase):
    """Prove surfaces.EXPECTED_EXIT_CODE values are all in NORMATIVE_EXIT_CODES.

    This is the module-load invariant declared in surfaces.py: no per-class
    expected code can drift outside the declared valid range.
    """

    def test_all_expected_exit_codes_are_normative(self) -> None:
        """Every value in EXPECTED_EXIT_CODE must be a member of NORMATIVE_EXIT_CODES."""
        for cls, code in surfaces.EXPECTED_EXIT_CODE.items():
            self.assertIn(
                code,
                surfaces.NORMATIVE_EXIT_CODES,
                f"EXPECTED_EXIT_CODE[{cls!r}] = {code} is outside NORMATIVE_EXIT_CODES "
                f"{surfaces.NORMATIVE_EXIT_CODES} — drift detected",
            )


if __name__ == "__main__":
    unittest.main()
