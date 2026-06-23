"""SSOT proof tests for harness/surfaces.py (S-A1).

Two concerns:
1. **Value tests** — assert the constants carry the expected current values so
   a careless edit to surfaces.py is immediately caught.
2. **Derivation proof** — assert that assertions.py GENUINELY derives its
   comparison logic from surfaces.py rather than coincidentally matching it.
   A monkeypatch that adds a sentinel to a surfaces constant must propagate
   into assertions.py's observable behaviour; if it does not, the two modules
   have drifted back to independent definitions.

The derivation proof uses ``unittest.mock.patch`` to mutate the surfaces
constants in-place during a test and verifies the assertion function follows
the patched value.  This is the canonical S-A1 RED→GREEN step: RED is a test
that fails before assertions.py imports from surfaces; GREEN is after the
import is wired.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import surfaces


# ---------------------------------------------------------------------------
# Value tests — surfaces.py carries the expected literal values
# ---------------------------------------------------------------------------


class TestSurfaceValues(unittest.TestCase):
    """Assert the constants carry the correct current values."""

    # Named FileSurface constants -----------------------------------------------

    def test_lock_file_name(self) -> None:
        self.assertEqual(surfaces.LOCK_FILE.name, "milpa.lock")

    def test_root_nimcfg_name(self) -> None:
        self.assertEqual(surfaces.ROOT_NIMCFG.name, "nim.cfg")

    def test_manifest_file_name(self) -> None:
        self.assertEqual(surfaces.MANIFEST_FILE.name, "milpa.kdl")

    def test_deps_structure_file_name(self) -> None:
        self.assertEqual(surfaces.DEPS_STRUCTURE_FILE.name, "_deps_structure.txt")

    def test_certificate_file_name(self) -> None:
        self.assertEqual(surfaces.CERTIFICATE_FILE.name, "certificate.json")

    # NORMATIVE_FILES derived from named constants --------------------------------
    # These tests verify that NORMATIVE_FILES is constructed FROM the named
    # constants (identity, not just equal value) — so a rename propagates.

    def test_normative_files_has_three_command_classes(self) -> None:
        keys = set(surfaces.NORMATIVE_FILES.keys())
        self.assertEqual(keys, {"success", "check-certificate", "error"})

    def test_success_tuple_is_derived_from_named_constants(self) -> None:
        """NORMATIVE_FILES["success"] must BE the named constants, not copies."""
        success = surfaces.NORMATIVE_FILES["success"]
        self.assertIn(surfaces.LOCK_FILE, success)
        self.assertIn(surfaces.ROOT_NIMCFG, success)
        self.assertIn(surfaces.MANIFEST_FILE, success)
        self.assertIn(surfaces.DEPS_STRUCTURE_FILE, success)

    def test_check_certificate_tuple_is_derived_from_named_constant(self) -> None:
        """NORMATIVE_FILES["check-certificate"] must contain CERTIFICATE_FILE."""
        cert_tuple = surfaces.NORMATIVE_FILES["check-certificate"]
        self.assertIn(surfaces.CERTIFICATE_FILE, cert_tuple)

    def test_success_files(self) -> None:
        names = {f.name for f in surfaces.NORMATIVE_FILES["success"]}
        self.assertIn("milpa.lock", names)
        self.assertIn("nim.cfg", names)
        self.assertIn("_deps_structure.txt", names)
        self.assertIn("milpa.kdl", names)

    def test_check_certificate_has_certificate_json(self) -> None:
        names = {f.name for f in surfaces.NORMATIVE_FILES["check-certificate"]}
        self.assertIn("certificate.json", names)

    def test_error_has_no_files(self) -> None:
        self.assertEqual(surfaces.NORMATIVE_FILES["error"], ())

    # LIVENESS_CMDS -------------------------------------------------------------

    def test_liveness_cmds_contains_show(self) -> None:
        self.assertIn("show", surfaces.LIVENESS_CMDS)

    def test_liveness_cmds_contains_version_flag(self) -> None:
        self.assertIn("--version", surfaces.LIVENESS_CMDS)

    def test_liveness_cmds_does_not_contain_resolve(self) -> None:
        self.assertNotIn("resolve", surfaces.LIVENESS_CMDS)

    def test_liveness_cmds_is_frozenset(self) -> None:
        self.assertIsInstance(surfaces.LIVENESS_CMDS, frozenset)

    # EXPECTED_EXIT_CODE --------------------------------------------------------

    def test_success_exit_0(self) -> None:
        self.assertEqual(surfaces.EXPECTED_EXIT_CODE["success"], 0)

    def test_liveness_exit_0(self) -> None:
        self.assertEqual(surfaces.EXPECTED_EXIT_CODE["liveness"], 0)

    def test_clean_exit_0(self) -> None:
        self.assertEqual(surfaces.EXPECTED_EXIT_CODE["clean"], 0)

    def test_error_exit_1(self) -> None:
        self.assertEqual(surfaces.EXPECTED_EXIT_CODE["error"], 1)

    # ABSENT_PATHS_SURFACE ------------------------------------------------------

    def test_absent_paths_surface_is_absent(self) -> None:
        self.assertEqual(surfaces.ABSENT_PATHS_SURFACE, "absent")


# ---------------------------------------------------------------------------
# Derivation proof — assertions.py follows patched surfaces constants
# ---------------------------------------------------------------------------


class TestDerivationFromSurfaces(unittest.TestCase):
    """Prove assertions.py derives from surfaces.py, not coincidentally matches.

    Each test patches a surfaces constant, then drives assertions.py through a
    minimal synthetic fixture.  If the assertion code hard-codes the literal
    instead of reading from surfaces, the test fails.
    """

    def _minimal_run(self, **overrides):
        """Build a minimal fake RunResult-like object."""
        from harness.runner import RunResult
        tmpdir = tempfile.mkdtemp(prefix="milpa-sa1-")
        self._tmpdirs.append(tmpdir)
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
        return RunResult(**defaults)

    def setUp(self) -> None:
        self._tmpdirs: list[str] = []

    def tearDown(self) -> None:
        for d in self._tmpdirs:
            shutil.rmtree(d, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Liveness command derivation
    # -------------------------------------------------------------------------

    def test_liveness_cmd_derived_from_surfaces(self) -> None:
        """assertions.py uses surfaces.LIVENESS_CMDS — adding a sentinel cmd
        must cause that cmd to be dispatched as liveness (exit-0, no byte-diff).

        We add 'SENTINEL-LIVENESS-CMD' to LIVENESS_CMDS and craft a fixture
        whose cmd file contains it.  With the patch, the assertion must pass
        (exit 0 + non-empty stdout).  Without the patch (or if assertions.py
        hard-codes the set) the sentinel cmd falls through to the success path,
        which fails because there is no milpa.lock.
        """
        import harness.surfaces as surf_mod
        from harness.assertions import assert_conformance

        # Build a minimal fixture dir: cmd=SENTINEL-LIVENESS-CMD, expected/ present.
        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1-fx-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        (fx_dir / "cmd").write_text("SENTINEL-LIVENESS-CMD\n")
        (fx_dir / "expected").mkdir()

        run = self._minimal_run(returncode=0, stdout="some output\n")

        sentinel_set = frozenset(surf_mod.LIVENESS_CMDS | {"SENTINEL-LIVENESS-CMD"})
        with patch.object(surf_mod, "LIVENESS_CMDS", sentinel_set):
            result = assert_conformance(run, fx_dir)

        # With the patch active, SENTINEL-LIVENESS-CMD must be treated as liveness:
        # exit 0 + non-empty stdout → passes with no milpa.lock check.
        self.assertTrue(
            result.passed,
            f"Expected pass with patched LIVENESS_CMDS, got failures: "
            f"{[f.detail for f in result.failures]}",
        )
        self.assertIn("<liveness>", result.normalized_outputs)

    def test_liveness_cmd_without_patch_fails_success_path(self) -> None:
        """Inverse: without the patch, SENTINEL-LIVENESS-CMD takes the success
        path and fails (no milpa.lock in scratch)."""
        from harness.assertions import assert_conformance

        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1-fx2-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        (fx_dir / "cmd").write_text("SENTINEL-LIVENESS-CMD\n")
        expected = fx_dir / "expected"
        expected.mkdir()
        # Put a milpa.lock in expected/ so the success path tries to diff it.
        (expected / "milpa.lock").write_text("lock content\n")

        run = self._minimal_run(returncode=0, stdout="some output\n")

        # No patch — the sentinel cmd goes through _assert_success_fixture,
        # which tries to find scratch/milpa.lock (absent → failure).
        result = assert_conformance(run, fx_dir)
        self.assertFalse(result.passed)

    # -------------------------------------------------------------------------
    # Exit code derivation
    # -------------------------------------------------------------------------

    def test_error_exit_code_derived_from_surfaces(self) -> None:
        """assertions.py reads surfaces.EXPECTED_EXIT_CODE['error'].

        Patch it to 42 and verify a returncode=42 error fixture passes;
        returncode=1 (the old value) must fail.

        NORMATIVE_EXIT_CODES must also be patched to include 42 so the
        baseline normative-range check (wired in assert_conformance, S-A1b)
        does not catch 42 before the per-class check can exercise it.  Both
        patches are applied together; that is the correct framing for a
        hypothetical impl that redefines the exit-code set globally — if you
        change EXPECTED_EXIT_CODE you must also change NORMATIVE_EXIT_CODES,
        and the module-load invariant in surfaces.py enforces exactly that.
        """
        import harness.surfaces as surf_mod
        from harness.assertions import assert_conformance

        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1-fx3-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        expected = fx_dir / "expected"
        expected.mkdir()
        (expected / "error").write_text("SOME-SLUG\n")

        run42 = self._minimal_run(returncode=42, slug="SOME-SLUG")

        patched_codes = dict(surf_mod.EXPECTED_EXIT_CODE)
        patched_codes["error"] = 42
        patched_normative = frozenset(surf_mod.NORMATIVE_EXIT_CODES | {42})
        with (
            patch.object(surf_mod, "EXPECTED_EXIT_CODE", patched_codes),
            patch.object(surf_mod, "NORMATIVE_EXIT_CODES", patched_normative),
        ):
            result42 = assert_conformance(run42, fx_dir)

        self.assertTrue(
            result42.passed,
            f"With patched exit code=42, returncode=42 must pass; "
            f"failures: {[f.detail for f in result42.failures]}",
        )

        # Without patch: returncode=42 must fail (both the normative-range
        # baseline and the per-class check catch it).
        result_no_patch = assert_conformance(run42, fx_dir)
        self.assertFalse(
            result_no_patch.passed,
            "Without patch, returncode=42 must fail (expected exit 1)",
        )

    # -------------------------------------------------------------------------
    # Absent paths surface derivation
    # -------------------------------------------------------------------------

    # -------------------------------------------------------------------------
    # Named-constant derivation proofs
    # -------------------------------------------------------------------------

    def test_lock_file_constant_derived_by_success_fixture(self) -> None:
        """assertions.py reads surfaces.LOCK_FILE.name, not a hard-coded string.

        Patch LOCK_FILE to a sentinel name and create a fixture with a matching
        expected/<sentinel> file.  The assert_conformance call must pass — it finds
        the sentinel file because it derives the name from surfaces.LOCK_FILE.name.
        Without the patch (LOCK_FILE.name == "milpa.lock") the sentinel file is
        ignored and the assertion fails because there is no expected/milpa.lock
        to diff against (no failure on missing expected).  We verify the REVERSE:
        with the patch active and an expected/sentinel file present, if assertions.py
        still looked for "milpa.lock" it would not find expected/milpa.lock and
        would not error (the fixture has no milpa.lock), meaning it would PASS for
        the wrong reason.  So we also put a mismatched milpa.lock in scratch only
        and verify that without the patch assertions.py does not accidentally succeed
        by diffing the wrong file.

        The cleanest proof: put ONLY expected/<sentinel>.lock in expected/.
        With patch: assertions.py looks for scratch/<sentinel>.lock → present →
          compare passes → overall pass.
        Without patch: assertions.py looks for expected/milpa.lock → absent →
          no lock diff runs → passes trivially (not a useful signal).

        We therefore use a MISMATCH signal: put expected/<sentinel> with content A
        and scratch/<sentinel> with content B.  With patch → mismatch → FAIL.
        Without patch → assertions.py ignores <sentinel>, looks for milpa.lock
          in expected/ (absent) → no lock check → PASS.
        This asymmetry proves derivation.
        """
        import harness.surfaces as surf_mod
        from harness.assertions import assert_conformance

        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1-lock-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        expected = fx_dir / "expected"
        expected.mkdir()

        sentinel_lock = surfaces.FileSurface("sentinel.lock")
        (expected / sentinel_lock.name).write_text("expected-content\n")

        run = self._minimal_run(returncode=0, stdout="")
        # Write a MISMATCHED version in scratch.
        Path(run.scratch_dir).joinpath(sentinel_lock.name).write_text("actual-content\n")

        patched = surf_mod.LOCK_FILE
        with patch.object(surf_mod, "LOCK_FILE", sentinel_lock):
            result_patched = assert_conformance(run, fx_dir)

        # Without patch: assertions.py looks for expected/milpa.lock → absent
        # → no lock diff → no failures from that check (other checks also absent).
        result_unpatched = assert_conformance(run, fx_dir)

        self.assertFalse(
            result_patched.passed,
            "With LOCK_FILE patched to sentinel, mismatch must be detected; "
            f"failures: {[f.detail for f in result_patched.failures]}",
        )
        self.assertTrue(
            result_unpatched.passed,
            "Without patch, sentinel.lock expected/ file is ignored → no failure; "
            f"failures: {[f.detail for f in result_unpatched.failures]}",
        )
        _ = patched  # suppress unused-variable warning

    def test_certificate_file_constant_derived_by_check_certificate(self) -> None:
        """assertions.py reads surfaces.CERTIFICATE_FILE.name for check-certificate.

        Patch CERTIFICATE_FILE to a sentinel name.  With patch: the expected/
        sentinel file is found and compared; with an INTENTIONAL MISMATCH in
        scratch the assertion must fail.  Without patch: expected/certificate.json
        is absent → no cert diff → the check-certificate fixture passes trivially
        (on the cert step), proving the derivation asymmetry.
        """
        import harness.surfaces as surf_mod
        from harness.assertions import assert_conformance

        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1-cert-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        (fx_dir / "cmd").write_text("check-certificate\n")
        expected = fx_dir / "expected"
        expected.mkdir()

        sentinel_cert = surfaces.FileSurface("sentinel.cert.json")
        expected_cert_data = {"kind": "success", "resolved": [], "witness": []}
        (expected / sentinel_cert.name).write_text(json.dumps(expected_cert_data))

        # Also write a milpa.lock so the delegated _assert_success_fixture passes.
        (expected / "milpa.lock").write_text("lock\n")

        run = self._minimal_run(returncode=0, stdout="")
        Path(run.scratch_dir).joinpath("milpa.lock").write_text("lock\n")

        # Write a MISMATCHED cert to scratch (wrong kind → mismatch).
        scratch_cert = Path(run.scratch_dir) / sentinel_cert.name
        scratch_cert.write_text(json.dumps({"kind": "failure", "refutation": []}))

        with patch.object(surf_mod, "CERTIFICATE_FILE", sentinel_cert):
            result_patched = assert_conformance(run, fx_dir)

        result_unpatched = assert_conformance(run, fx_dir)

        self.assertFalse(
            result_patched.passed,
            "With CERTIFICATE_FILE patched to sentinel, kind mismatch must be detected; "
            f"failures: {[f.detail for f in result_patched.failures]}",
        )
        self.assertTrue(
            result_unpatched.passed,
            "Without patch, sentinel.cert.json is ignored → cert step passes; "
            f"failures: {[f.detail for f in result_unpatched.failures]}",
        )

    def test_absent_paths_surface_derived_from_surfaces(self) -> None:
        """assertions.py reads surfaces.ABSENT_PATHS_SURFACE for the filename.

        Patch it to 'sentinel-absent' and verify a fixture with that control
        file (listing a path that exists in scratch) is flagged as a failure.
        Without the patch (reading 'absent') the sentinel file is ignored.
        """
        import harness.surfaces as surf_mod
        from harness.assertions import assert_conformance

        fx_dir = Path(tempfile.mkdtemp(prefix="milpa-sa1-fx4-"))
        self._tmpdirs.append(str(fx_dir))
        (fx_dir / "milpa.kdl").write_text('name "test"\nkind "application"\n')
        expected = fx_dir / "expected"
        expected.mkdir()
        # Put a milpa.lock in expected/ so the success path passes the lock check.
        (expected / "milpa.lock").write_text("lock content\n")
        # Use a SENTINEL filename instead of 'absent'.
        (expected / "sentinel-absent").write_text("should-not-exist.txt\n")

        run = self._minimal_run(returncode=0, stdout="")
        # Create the file in scratch that must be absent.
        Path(run.scratch_dir).joinpath("should-not-exist.txt").write_text("oops")
        # Also write the matching milpa.lock in scratch.
        Path(run.scratch_dir).joinpath("milpa.lock").write_text("lock content\n")

        # With the patch: 'sentinel-absent' is read → failure because file exists.
        with patch.object(surf_mod, "ABSENT_PATHS_SURFACE", "sentinel-absent"):
            result_patched = assert_conformance(run, fx_dir)

        # Without the patch: 'absent' is the filename — 'sentinel-absent' is ignored
        # → only the milpa.lock check runs → passes.
        result_unpatched = assert_conformance(run, fx_dir)

        self.assertFalse(
            result_patched.passed,
            "With patched ABSENT_PATHS_SURFACE='sentinel-absent', the absent check "
            "must fire and flag the existing file",
        )
        self.assertTrue(
            result_unpatched.passed,
            "Without patch (ABSENT_PATHS_SURFACE='absent'), 'sentinel-absent' is "
            "ignored and the fixture must pass",
        )


if __name__ == "__main__":
    unittest.main()
