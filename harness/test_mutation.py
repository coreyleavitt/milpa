"""Tests for the §2f fixture-format extension (issue #5).

Covers:
  - runner._cmd_to_cli mapping of the mutation/liveness cmd surface forms.
  - assertions for expected/milpa.kdl byte-compare (add/remove).
  - assertions for liveness fixtures (show / --version): exit 0 + non-empty
    stdout, NO byte-compare.

stdlib only; no import milpa.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from harness.assertions import assert_conformance
from harness.runner import RunResult, _cmd_to_cli


def _mk_run(scratch: Path, *, returncode: int = 0, stdout: str = "", stderr: str = "",
            slug: str | None = None) -> RunResult:
    return RunResult(
        fixture_name="fixture-test",
        impl_name="test-impl",
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        slug=slug,
        slug_error=None,
        scratch_dir=str(scratch),
        cas_dir=str(scratch / "_cas"),
    )


class TestCmdMapping(unittest.TestCase):
    def test_add_with_ref(self) -> None:
        gf, argv = _cmd_to_cli("add foo git=https://e/foo.git ref=main")
        self.assertEqual(gf, [])
        self.assertEqual(argv, ["add", "foo", "--git", "https://e/foo.git", "--ref", "main"])

    def test_add_without_ref(self) -> None:
        gf, argv = _cmd_to_cli("add foo git=https://e/foo.git")
        self.assertEqual(argv, ["add", "foo", "--git", "https://e/foo.git"])

    def test_remove(self) -> None:
        gf, argv = _cmd_to_cli("remove foo")
        self.assertEqual(argv, ["remove", "foo"])

    def test_update_all(self) -> None:
        gf, argv = _cmd_to_cli("update")
        self.assertEqual(argv, ["update"])

    def test_update_named(self) -> None:
        gf, argv = _cmd_to_cli("update foo")
        self.assertEqual(argv, ["update", "foo"])

    def test_show(self) -> None:
        gf, argv = _cmd_to_cli("show")
        self.assertEqual((gf, argv), ([], ["show"]))

    def test_version(self) -> None:
        gf, argv = _cmd_to_cli("--version")
        self.assertEqual((gf, argv), (["--version"], []))

    def test_resolve_and_frozen_unchanged(self) -> None:
        self.assertEqual(_cmd_to_cli("resolve"), ([], ["fetch"]))
        self.assertEqual(_cmd_to_cli("frozen"), (["--frozen"], ["fetch"]))

    def test_add_requires_git(self) -> None:
        with self.assertRaises(ValueError):
            _cmd_to_cli("add foo ref=main")

    def test_unknown_cmd(self) -> None:
        with self.assertRaises(ValueError):
            _cmd_to_cli("frobnicate")


class TestExpectedManifestAssertion(unittest.TestCase):
    def _fixture(self, tmp: Path, expected_manifest: str) -> Path:
        fixture = tmp / "fixture-200-add"
        (fixture / "expected").mkdir(parents=True)
        (fixture / "cmd").write_text("add foo git=https://e/foo.git ref=main")
        (fixture / "expected" / "milpa.kdl").write_text(expected_manifest)
        return fixture

    def test_matching_manifest_passes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            content = 'name "app"\nkind "application"\n'
            fixture = self._fixture(tmp, content)
            scratch = tmp / "scratch"
            scratch.mkdir()
            (scratch / "milpa.kdl").write_text(content)
            result = assert_conformance(_mk_run(scratch), fixture)
            self.assertTrue(result.passed, result.failures)
            self.assertIn("expected/milpa.kdl", result.normalized_outputs)

    def test_diverging_manifest_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            fixture = self._fixture(tmp, 'name "app"\nkind "application"\n')
            scratch = tmp / "scratch"
            scratch.mkdir()
            (scratch / "milpa.kdl").write_text('name "DIFFERENT"\n')
            result = assert_conformance(_mk_run(scratch), fixture)
            self.assertFalse(result.passed)
            self.assertTrue(any("milpa.kdl" in f.detail for f in result.failures))

    def test_missing_manifest_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            fixture = self._fixture(tmp, 'name "app"\n')
            scratch = tmp / "scratch"
            scratch.mkdir()
            result = assert_conformance(_mk_run(scratch), fixture)
            self.assertFalse(result.passed)


class TestLivenessAssertion(unittest.TestCase):
    def _fixture(self, tmp: Path, cmd: str) -> Path:
        fixture = tmp / "fixture-201-show"
        (fixture / "expected").mkdir(parents=True)
        (fixture / "cmd").write_text(cmd)
        return fixture

    def test_show_liveness_passes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            fixture = self._fixture(tmp, "show")
            scratch = tmp / "scratch"
            scratch.mkdir()
            run = _mk_run(scratch, returncode=0, stdout="foo  1.0.0\n  identity sha256:abcd\n")
            result = assert_conformance(run, fixture)
            self.assertTrue(result.passed, result.failures)
            self.assertIn("<liveness>", result.normalized_outputs)

    def test_show_empty_stdout_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            fixture = self._fixture(tmp, "show")
            scratch = tmp / "scratch"
            scratch.mkdir()
            run = _mk_run(scratch, returncode=0, stdout="   \n")
            result = assert_conformance(run, fixture)
            self.assertFalse(result.passed)

    def test_show_nonzero_exit_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            fixture = self._fixture(tmp, "show")
            scratch = tmp / "scratch"
            scratch.mkdir()
            run = _mk_run(scratch, returncode=1, stdout="anything\n")
            result = assert_conformance(run, fixture)
            self.assertFalse(result.passed)

    def test_show_does_not_byte_compare_stdout(self) -> None:
        # Two different stdout texts both pass liveness AND record the same
        # stable marker → no cross-impl divergence from non-frozen format.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            fixture = self._fixture(tmp, "show")
            scratch = tmp / "scratch"
            scratch.mkdir()
            r1 = assert_conformance(_mk_run(scratch, stdout="layout A\n"), fixture)
            r2 = assert_conformance(_mk_run(scratch, stdout="totally different layout B\n"), fixture)
            self.assertTrue(r1.passed and r2.passed)
            self.assertEqual(
                r1.normalized_outputs["<liveness>"],
                r2.normalized_outputs["<liveness>"],
            )

    def test_version_liveness(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            fixture = self._fixture(tmp, "--version")
            scratch = tmp / "scratch"
            scratch.mkdir()
            run = _mk_run(scratch, returncode=0, stdout="milpa 0.1.0\n")
            result = assert_conformance(run, fixture)
            self.assertTrue(result.passed, result.failures)


if __name__ == "__main__":
    unittest.main()
