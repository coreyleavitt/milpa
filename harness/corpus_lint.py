"""Static corpus lint — fixture-rot guard (S-A3).

Runnable WITHOUT executing any impl.  For every fixture in
``conformance/spec-v<N>/``, asserts:

  (a) If the fixture has an ``expected/error`` file, the slug it contains
      EXISTS in ``spec/errors.md`` (the canonical error catalog).

  (b) If the fixture's DIRECTORY NAME slug portion (characters after
      ``fixture-NNN-``, uppercased) exactly matches a known slug in
      ``spec/errors.md``, that dir-name slug MUST equal the
      ``expected/error`` slug.  A dir name that is descriptive and does
      NOT match any known slug is exempted — the corpus uses descriptive
      names for many fixtures (e.g. ``fixture-062-diamond-conflict``
      describes the scenario, not the slug ``SOLVE-CONFLICT``).  Only
      when the dir name unambiguously encodes a specific slug (because
      that slug exists verbatim in ``errors.md``) is consistency
      enforced.

Design:
  - ``lint_corpus()`` is a pure function: takes the conformance root Path
    and the errors.md Path; returns a list of ``LintViolation`` records.
    Filesystem I/O is confined to this one function.
  - Fixture discovery reuses ``harness.corpus._discover_fixtures`` (SSOT).
  - Slug parsing reuses the same line-scan logic as
    ``impls/python/tests/test_errors.py`` — no second errors.md parser.

Wire into the §3.6 harness CI job alongside ``harness/test_coverage.py``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Slug parser — mirrors test_errors.py::_parse_spec_slugs exactly.
# The regex ``### `<SLUG>``` is the normative line form in spec/errors.md.
# ---------------------------------------------------------------------------

_SLUG_HEADER_RE = re.compile(r"^### `([^`]+)`")


def parse_spec_slugs(errors_md: Path) -> frozenset[str]:
    """Parse every slug defined in *errors_md* (``spec/errors.md``).

    Mirrors the logic in ``impls/python/tests/test_errors.py::_parse_spec_slugs``
    exactly: strip ``### \\```, take up to the next backtick.  Returns a
    frozenset of slug strings.
    """
    text = errors_md.read_text(encoding="utf-8")
    slugs: set[str] = set()
    for line in text.splitlines():
        m = _SLUG_HEADER_RE.match(line)
        if m:
            slugs.add(m.group(1))
    return frozenset(slugs)


# ---------------------------------------------------------------------------
# Dir-name slug extraction
# ---------------------------------------------------------------------------

_FIXTURE_PREFIX_RE = re.compile(r"^fixture-\d+-(.+)$")


def _dir_name_slug_part(fixture_dir_name: str) -> Optional[str]:
    """Return the slug-like portion of a fixture directory name.

    ``fixture-001-man-kdl-syntax`` → ``MAN-KDL-SYNTAX``
    ``fixture-062-diamond-conflict`` → ``DIAMOND-CONFLICT``

    Returns ``None`` if the directory name doesn't match the
    ``fixture-NNN-<rest>`` pattern.
    """
    m = _FIXTURE_PREFIX_RE.match(fixture_dir_name)
    if not m:
        return None
    return m.group(1).upper()


# ---------------------------------------------------------------------------
# Violation record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LintViolation:
    """One lint finding on one fixture."""

    fixture_name: str
    """Directory name of the offending fixture (e.g. ``fixture-001-man-kdl-syntax``)."""

    check: str
    """Which check fired: ``'a'`` or ``'b'``."""

    detail: str
    """Human-readable description of the violation."""


# ---------------------------------------------------------------------------
# Core lint function
# ---------------------------------------------------------------------------

def lint_corpus(
    conformance_root: Path,
    errors_md: Path,
) -> list[LintViolation]:
    """Lint every fixture under *conformance_root* against *errors_md*.

    Returns a list of :class:`LintViolation` records (empty = clean corpus).

    Checks performed:

    (a) ``expected/error`` slug exists in ``spec/errors.md``.
    (b) If the dir-name slug portion (uppercased) is itself a known slug,
        it must equal the ``expected/error`` slug.

    Only fixtures that HAVE an ``expected/error`` file are subject to check (a)
    and (b).  Success fixtures (no ``expected/error``) are skipped silently.
    """
    # Reuse SSOT fixture discovery from harness.corpus (avoids duplicating
    # the spec-v<N>/fixture-* glob logic).
    from harness.corpus import _discover_fixtures  # noqa: PLC0415

    known_slugs = parse_spec_slugs(errors_md)
    fixtures = _discover_fixtures(conformance_root)
    violations: list[LintViolation] = []

    for fixture_dir in fixtures:
        error_file = fixture_dir / "expected" / "error"
        if not error_file.exists():
            continue  # success fixture — skip

        slug = error_file.read_text(encoding="utf-8").strip()
        fixture_name = fixture_dir.name

        # ── Check (a): slug must exist in spec/errors.md ──────────────────
        if slug not in known_slugs:
            violations.append(LintViolation(
                fixture_name=fixture_name,
                check="a",
                detail=(
                    f"expected/error slug {slug!r} is NOT in spec/errors.md "
                    f"(known slugs: {len(known_slugs)})"
                ),
            ))

        # ── Check (b): dir-name slug inconsistency ─────────────────────────
        dir_slug = _dir_name_slug_part(fixture_name)
        if dir_slug is not None and dir_slug in known_slugs:
            # The dir name unambiguously encodes a known slug — it must match.
            if dir_slug != slug:
                violations.append(LintViolation(
                    fixture_name=fixture_name,
                    check="b",
                    detail=(
                        f"dir-name slug {dir_slug!r} is a known errors.md slug "
                        f"but expected/error contains {slug!r}"
                    ),
                ))

    return violations
