"""Tests for the static corpus lint (S-A3 — fixture-rot guard).

Structure (TDD):
  - Synthetic-corpus tests drive RED→GREEN over the lint logic on constructed
    temp dirs (no real corpus, no impl execution).
  - Real-corpus test asserts the actual conformance/ corpus passes the lint
    clean; any failure here is a FINDING (a rotted fixture).

Run with:
    python3 -m pytest harness/test_corpus_lint.py
    python3 -m unittest harness.test_corpus_lint        # alternative
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup — repo root on sys.path for ``from harness.X import ...``
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from harness.corpus_lint import LintViolation, _dir_name_slug_part, lint_corpus, parse_spec_slugs

_CONFORMANCE_ROOT = _REPO_ROOT / "conformance"
_ERRORS_MD = _REPO_ROOT / "spec" / "errors.md"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_error_fixture(
    spec_dir: Path,
    name: str,
    slug: str,
) -> Path:
    """Create a minimal error fixture directory under *spec_dir*."""
    fixture_dir = spec_dir / name
    expected = fixture_dir / "expected"
    expected.mkdir(parents=True, exist_ok=True)
    (expected / "error").write_text(slug, encoding="utf-8")
    # milpa.kdl is not required for the lint (it's static)
    return fixture_dir


def _make_success_fixture(spec_dir: Path, name: str) -> Path:
    """Create a minimal success fixture directory (no expected/error)."""
    fixture_dir = spec_dir / name
    expected = fixture_dir / "expected"
    expected.mkdir(parents=True, exist_ok=True)
    # Write something other than error so the fixture is recognizable
    (expected / "nim.cfg").write_text("# success\n", encoding="utf-8")
    return fixture_dir


def _make_errors_md(tmp: Path, *slugs: str) -> Path:
    """Write a minimal errors.md containing the given slugs."""
    lines: list[str] = ["# milpa error catalog\n", "\n"]
    for slug in slugs:
        lines.append(f"### `{slug}`\n\nSome description.\n\n")
    path = tmp / "errors.md"
    path.write_text("".join(lines), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Unit tests: parse_spec_slugs
# ---------------------------------------------------------------------------

class TestParseSpecSlugs(unittest.TestCase):
    """parse_spec_slugs reads slugs from errors.md correctly."""

    def test_reads_real_errors_md(self) -> None:
        """parse_spec_slugs returns a non-empty frozenset from the real errors.md."""
        slugs = parse_spec_slugs(_ERRORS_MD)
        self.assertIsInstance(slugs, frozenset)
        self.assertGreater(len(slugs), 50, "Expected >50 slugs in spec/errors.md")

    def test_known_slugs_present(self) -> None:
        """A spot-check: well-known slugs appear in the parsed set."""
        slugs = parse_spec_slugs(_ERRORS_MD)
        for known in ("MAN-KDL-SYNTAX", "SOLVE-CONFLICT", "TNG-DEPDECL-FETCH-FAILED"):
            self.assertIn(known, slugs, f"Expected {known!r} in parsed slug set")

    def test_synthetic_errors_md(self) -> None:
        """Synthetic errors.md with two slugs parses correctly."""
        with tempfile.TemporaryDirectory(prefix="milpa-lint-test-") as tmp:
            errors_md = _make_errors_md(Path(tmp), "FOO-BAR", "BAZ-QUUX")
            slugs = parse_spec_slugs(errors_md)
            self.assertEqual(slugs, frozenset({"FOO-BAR", "BAZ-QUUX"}))


# ---------------------------------------------------------------------------
# Unit tests: _dir_name_slug_part
# ---------------------------------------------------------------------------

class TestDirNameSlugPart(unittest.TestCase):
    """_dir_name_slug_part extracts and uppercases the slug portion."""

    def test_simple(self) -> None:
        self.assertEqual(_dir_name_slug_part("fixture-001-man-kdl-syntax"), "MAN-KDL-SYNTAX")

    def test_number_padding(self) -> None:
        self.assertEqual(_dir_name_slug_part("fixture-100-solve-conflict"), "SOLVE-CONFLICT")

    def test_descriptive_name(self) -> None:
        self.assertEqual(_dir_name_slug_part("fixture-062-diamond-conflict"), "DIAMOND-CONFLICT")

    def test_non_fixture_returns_none(self) -> None:
        self.assertIsNone(_dir_name_slug_part("dep-decl-golden"))
        self.assertIsNone(_dir_name_slug_part("not-a-fixture"))


# ---------------------------------------------------------------------------
# Synthetic corpus tests: RED cases
# ---------------------------------------------------------------------------

class TestLintSyntheticViolations(unittest.TestCase):
    """lint_corpus flags deliberately-corrupted fixtures."""

    def _lint(self, conformance_root: Path, errors_md: Path) -> list[LintViolation]:
        return lint_corpus(conformance_root, errors_md)

    def test_check_a_unknown_slug(self) -> None:
        """Check (a): expected/error with an unknown slug is flagged.

        Uses a fixture whose dir name does NOT embed a known slug, so only
        check (a) fires (no check (b) cross-contamination).
        ``fixture-062-diamond-conflict`` → dir slug ``DIAMOND-CONFLICT`` is
        NOT a known slug → only check (a) fires.
        """
        with tempfile.TemporaryDirectory(prefix="milpa-lint-test-") as tmp:
            tmp_path = Path(tmp)
            spec_dir = tmp_path / "spec-v1"
            spec_dir.mkdir()
            # SOLVE-CONFLICT is in catalog; DIAMOND-CONFLICT is NOT
            errors_md = _make_errors_md(tmp_path, "SOLVE-CONFLICT")

            # Dir name has descriptive (non-slug) portion "DIAMOND-CONFLICT";
            # expected/error is also bogus → only check (a) fires
            _make_error_fixture(spec_dir, "fixture-062-diamond-conflict", "BOGUS-SLUG-UNKNOWN")

            violations = self._lint(tmp_path, errors_md)
            self.assertEqual(len(violations), 1, f"Expected exactly 1 violation; got {violations}")
            v = violations[0]
            self.assertEqual(v.fixture_name, "fixture-062-diamond-conflict")
            self.assertEqual(v.check, "a")
            self.assertIn("BOGUS-SLUG-UNKNOWN", v.detail)

    def test_check_b_dir_slug_mismatch(self) -> None:
        """Check (b): dir-name encodes known slug X but expected/error is slug Y."""
        with tempfile.TemporaryDirectory(prefix="milpa-lint-test-") as tmp:
            tmp_path = Path(tmp)
            spec_dir = tmp_path / "spec-v1"
            spec_dir.mkdir()
            # Both slugs must be in errors.md for check (b) to apply
            errors_md = _make_errors_md(tmp_path, "MAN-KDL-SYNTAX", "SOLVE-CONFLICT")

            # Dir encodes MAN-KDL-SYNTAX but expected/error says SOLVE-CONFLICT
            _make_error_fixture(spec_dir, "fixture-001-man-kdl-syntax", "SOLVE-CONFLICT")

            violations = self._lint(tmp_path, errors_md)
            self.assertEqual(len(violations), 1, f"Expected 1 violation; got {violations}")
            v = violations[0]
            self.assertEqual(v.fixture_name, "fixture-001-man-kdl-syntax")
            self.assertEqual(v.check, "b")
            self.assertIn("MAN-KDL-SYNTAX", v.detail)
            self.assertIn("SOLVE-CONFLICT", v.detail)

    def test_both_checks_fire_on_corrupt_fixture(self) -> None:
        """A fixture with unknown slug AND dir-name mismatch fires both (a) and (b)."""
        with tempfile.TemporaryDirectory(prefix="milpa-lint-test-") as tmp:
            tmp_path = Path(tmp)
            spec_dir = tmp_path / "spec-v1"
            spec_dir.mkdir()
            # Only MAN-KDL-SYNTAX in catalog — BOGUS-UNKNOWN is not
            errors_md = _make_errors_md(tmp_path, "MAN-KDL-SYNTAX")

            # Dir encodes MAN-KDL-SYNTAX (a known slug) but expected/error is
            # BOGUS-UNKNOWN (not in catalog) → both (a) and (b) fire
            _make_error_fixture(spec_dir, "fixture-001-man-kdl-syntax", "BOGUS-UNKNOWN")

            violations = self._lint(tmp_path, errors_md)
            checks = {v.check for v in violations}
            self.assertIn("a", checks, "Check (a) should fire for unknown slug")
            self.assertIn("b", checks, "Check (b) should fire for dir/expected mismatch")

    def test_success_fixture_skipped(self) -> None:
        """Success fixtures (no expected/error) are not linted."""
        with tempfile.TemporaryDirectory(prefix="milpa-lint-test-") as tmp:
            tmp_path = Path(tmp)
            spec_dir = tmp_path / "spec-v1"
            spec_dir.mkdir()
            errors_md = _make_errors_md(tmp_path, "MAN-KDL-SYNTAX")

            _make_success_fixture(spec_dir, "fixture-003-single-url-dep")

            violations = self._lint(tmp_path, errors_md)
            self.assertEqual(violations, [], "Success fixture should produce no violations")

    def test_descriptive_dir_name_exempt_from_check_b(self) -> None:
        """Dir name with descriptive (non-slug) portion is exempt from check (b).

        ``fixture-062-diamond-conflict`` uses dir portion ``DIAMOND-CONFLICT``
        which is NOT a known slug — check (b) must not fire.
        """
        with tempfile.TemporaryDirectory(prefix="milpa-lint-test-") as tmp:
            tmp_path = Path(tmp)
            spec_dir = tmp_path / "spec-v1"
            spec_dir.mkdir()
            # Only real slug is SOLVE-CONFLICT; DIAMOND-CONFLICT is not a slug
            errors_md = _make_errors_md(tmp_path, "SOLVE-CONFLICT")

            # Descriptive dir, correct expected slug
            _make_error_fixture(spec_dir, "fixture-062-diamond-conflict", "SOLVE-CONFLICT")

            violations = self._lint(tmp_path, errors_md)
            self.assertEqual(violations, [], "Descriptive dir name exempt from check (b)")

    def test_empty_corpus_clean(self) -> None:
        """An empty spec-v1/ directory produces no violations."""
        with tempfile.TemporaryDirectory(prefix="milpa-lint-test-") as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "spec-v1").mkdir()
            errors_md = _make_errors_md(tmp_path, "MAN-KDL-SYNTAX")

            violations = self._lint(tmp_path, errors_md)
            self.assertEqual(violations, [])

    def test_check_a_valid_slug_passes(self) -> None:
        """A fixture with a valid slug in expected/error passes check (a)."""
        with tempfile.TemporaryDirectory(prefix="milpa-lint-test-") as tmp:
            tmp_path = Path(tmp)
            spec_dir = tmp_path / "spec-v1"
            spec_dir.mkdir()
            errors_md = _make_errors_md(tmp_path, "MAN-KDL-SYNTAX")

            _make_error_fixture(spec_dir, "fixture-001-man-kdl-syntax", "MAN-KDL-SYNTAX")

            violations = self._lint(tmp_path, errors_md)
            self.assertEqual(violations, [], f"Clean fixture should produce no violations; got {violations}")

    def test_multiple_fixtures_independent(self) -> None:
        """Multiple fixtures are linted independently; each violation is reported."""
        with tempfile.TemporaryDirectory(prefix="milpa-lint-test-") as tmp:
            tmp_path = Path(tmp)
            spec_dir = tmp_path / "spec-v1"
            spec_dir.mkdir()
            errors_md = _make_errors_md(tmp_path, "MAN-KDL-SYNTAX", "SOLVE-CONFLICT")

            _make_error_fixture(spec_dir, "fixture-001-man-kdl-syntax", "BOGUS-ONE")
            _make_error_fixture(spec_dir, "fixture-002-man-name-missing", "BOGUS-TWO")

            violations = self._lint(tmp_path, errors_md)
            fixture_names = {v.fixture_name for v in violations}
            self.assertIn("fixture-001-man-kdl-syntax", fixture_names)
            self.assertIn("fixture-002-man-name-missing", fixture_names)


# ---------------------------------------------------------------------------
# Real corpus test: the key assertion
# ---------------------------------------------------------------------------

class TestRealCorpusClean(unittest.TestCase):
    """The real conformance/ corpus must pass the lint clean.

    If this test fails, a rotted fixture has been found (FINDING).
    Report the offending fixtures and do NOT loosen the rule without
    understanding whether the rule or the corpus is wrong.
    """

    def test_real_corpus_passes_lint(self) -> None:
        """No fixture in conformance/ has an unknown slug or dir-name inconsistency.

        Failure = FINDING: print the violations and fail clearly.
        """
        self.assertTrue(
            _CONFORMANCE_ROOT.is_dir(),
            f"conformance_root not found at {_CONFORMANCE_ROOT}",
        )
        self.assertTrue(
            _ERRORS_MD.is_file(),
            f"spec/errors.md not found at {_ERRORS_MD}",
        )

        violations = lint_corpus(_CONFORMANCE_ROOT, _ERRORS_MD)

        if violations:
            lines = [
                f"\nFINDING: {len(violations)} lint violation(s) in the real corpus:\n"
            ]
            for v in violations:
                lines.append(f"  [{v.check}] {v.fixture_name}: {v.detail}")
            self.fail("\n".join(lines))


if __name__ == "__main__":
    unittest.main()
