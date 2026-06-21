"""Normative surface set — single source of truth (S-A1 / S-A1b).

This module declares the closed set of outputs that conformant milpa
implementations MUST match, per ``spec/conformance-fixtures.md`` §Normative
surface and ``spec/cli-contract.md §3.1``.

Design intent
-------------
``assertions.py`` derives ALL comparison logic from the constants here.  No
normative-surface literal is restated inline in the runner.  A third impl
(e.g. the planned Nim dogfood) inherits an unambiguous, machine-checkable
statement of what it must match and what it is free to vary.

Scope of this module
---------------------
S-A1 extracted the comparison-surface declarations and named FileSurface
constants from ``assertions.py`` into this module.  S-A1b adds
``EMPTY_STDOUT_VERBS`` and ``NORMATIVE_EXIT_CODES`` — both are live
enforcement constants:

- ``EMPTY_STDOUT_VERBS`` is checked by ``assertions.assert_conformance`` for
  every success/clean fixture (``cli-contract §4`` NORMATIVE).
- ``NORMATIVE_EXIT_CODES`` is checked by ``assertions.assert_conformance`` as a
  baseline across ALL fixture classes: any returncode outside this set is a
  conformance violation naming the code and citing ``cli-contract §3``
  (``rfc-conformance-parity.md §2`` warns against declaring constants that
  nothing wires).  A module-load invariant below also guarantees that every
  value in ``EXPECTED_EXIT_CODE`` is a member of ``NORMATIVE_EXIT_CODES``,
  preventing per-class expected codes from drifting outside the declared range.

Non-normative surfaces (explicitly excluded)
--------------------------------------------
The following are NOT in this set and MAY differ per impl by design
(``cli-contract.md §3.1``):
- The human-readable diagnostic line(s) on stderr, including any prefix
  (Python ``milpa:`` vs Rust ``<CODE>:``).
- Stdout prose for liveness commands (``show``, ``--version``) — only
  exit-0 + non-empty is asserted.
- Ordering/timing of progress output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Mapping


# ---------------------------------------------------------------------------
# File-level surface descriptors
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FileSurface:
    """Describes a single output file on the normative surface.

    Attributes
    ----------
    name:
        Relative path of the file within ``expected/`` (e.g. ``"milpa.lock"``).
    required:
        When ``True`` the file MUST be present in the impl's output whenever
        the fixture includes it in ``expected/``; a missing file is a failure.
        When ``False`` the file is compared only if the fixture provides it —
        the impl is not penalised for omitting it *unless* the fixture expects it.

    Note: all fixtures presently use "compare if the fixture provides it" logic,
    but ``milpa.lock`` on a resolve-success fixture is effectively required
    because every resolve-success fixture ships an ``expected/milpa.lock``.
    The distinction is preserved here because it is *structurally* different
    from "file is optional in the fixture corpus".
    """
    name: str
    required: bool


# ---------------------------------------------------------------------------
# Named FileSurface constants — semantic SSOT for well-known output files
# ---------------------------------------------------------------------------

# success-class outputs — each carries its semantic role as its identifier.
# NORMATIVE_FILES["success"] is built FROM these so a name change here
# propagates everywhere; nothing in assertions.py restates the literal string.

LOCK_FILE: FileSurface = FileSurface("milpa.lock", required=True)
"""The lockfile written on every successful resolve."""

ROOT_NIMCFG: FileSurface = FileSurface("nim.cfg", required=False)
"""The root-level nim.cfg emitted after resolution (single-package case;
per-member nim.cfg files are discovered dynamically from the fixture tree)."""

MANIFEST_FILE: FileSurface = FileSurface("milpa.kdl", required=False)
"""The manifest — compared on mutation fixtures (add/remove) that pin the
post-mutation manifest in expected/."""

DEPS_STRUCTURE_FILE: FileSurface = FileSurface("_deps_structure.txt", required=False)
"""The CAS-normalized _deps/ symlink listing (spec §2.6)."""

# check-certificate output
CERTIFICATE_FILE: FileSurface = FileSurface("certificate.json", required=True)
"""The proof certificate emitted by check-certificate."""


# ---------------------------------------------------------------------------
# NORMATIVE_FILES
# ---------------------------------------------------------------------------

# Per-command-class normative output files.
#
# Keys are command class names matching the dispatch logic in assertions.py:
#   "success"            — resolve/lock/add/remove/update that succeeded
#   "check-certificate"  — milpa check-certificate
#   "error"              — any fixture with expected/error (no file diff, slug only)
#
# Per-member nim.cfg files (``expected/<member>/nim.cfg``) and per-member
# ``milpa.kdl`` mutation outputs (``expected/<member>/milpa.kdl``) are handled
# by the workspace iteration loop in assertions.py and are NOT enumerated here
# as separate FileSurface entries — their existence is discovered dynamically
# from the fixture tree, not declared statically.  The root ``nim.cfg`` and
# ``milpa.kdl`` ARE listed here.
#
# "error" class: the slug on the ``milpa-error: <SLUG>`` line is the sole
# normative surface; no output files are compared.
#
# The tuple order here is the comparison order used by assertions.py; do not
# reorder without auditing the iteration in _assert_success_fixture.

NORMATIVE_FILES: Mapping[str, tuple[FileSurface, ...]] = {
    "success": (
        LOCK_FILE,
        ROOT_NIMCFG,
        MANIFEST_FILE,
        DEPS_STRUCTURE_FILE,
    ),
    "check-certificate": (
        CERTIFICATE_FILE,
    ),
    "error": (),  # slug only; no file diff
}


# ---------------------------------------------------------------------------
# LIVENESS_CMDS
# ---------------------------------------------------------------------------

# Commands whose stdout format is non-frozen for spec v1.0
# (``conformance-fixtures.md §2.7.2``).  The harness checks exit-0 +
# non-empty stdout only; it does NOT byte-compare stdout for these verbs.
LIVENESS_CMDS: FrozenSet[str] = frozenset({"show", "--version"})


# ---------------------------------------------------------------------------
# EMPTY_STDOUT_VERBS (S-A1b)
# ---------------------------------------------------------------------------

# Verbs that MUST produce NO output on stdout on a successful run
# (``cli-contract.md §4`` NORMATIVE).  The harness asserts ``stdout == ""``
# for any run whose command verb (the first whitespace-delimited token) is in
# this set AND whose outcome class is "success" or "clean".
#
# Liveness verbs (``LIVENESS_CMDS``) are explicitly excluded: ``show`` is the
# only verb with machine-readable stdout output; ``--version`` prints a
# human-readable version string.  ``check-certificate`` is also excluded
# because it writes the certificate to a *file* path (not stdout).
EMPTY_STDOUT_VERBS: FrozenSet[str] = frozenset({
    "fetch", "lock", "verify", "clean", "add", "remove", "update",
})


# ---------------------------------------------------------------------------
# NORMATIVE_EXIT_CODES (S-A1b)
# ---------------------------------------------------------------------------

# The complete set of defined exit codes for spec v1.0
# (``cli-contract.md §3`` NORMATIVE).  No other exit codes are defined;
# anything outside this set is a crash-class verdict (R4).
#
# - 0: success (all verbs on a successful run)
# - 1: diagnosed failure (any condition with an ``errors.md`` slug)
# - 2: argument-parse / usage error (invalid flag value, unrecognized flag)
#
# An impl exiting 2 where another exits 1 is a divergence (previously
# invisible because the harness only compared zero-vs-nonzero).  After
# S-A1b the mismatch message names the actual vs expected code explicitly.
NORMATIVE_EXIT_CODES: FrozenSet[int] = frozenset({0, 1, 2})


# ---------------------------------------------------------------------------
# EXPECTED_EXIT_CODE
# ---------------------------------------------------------------------------

# The exact process exit code each command class MUST produce on its primary
# path.  ``assertions.py`` compares run.returncode against this mapping and
# names both the actual and expected codes in any mismatch message (S-A1b).
EXPECTED_EXIT_CODE: Mapping[str, int] = {
    "success": 0,
    "liveness": 0,
    "clean": 0,
    "error": 1,
}


# Module-load invariant: every per-class expected code must be within the
# normative range.  A plain assert is correct here — this is a programming
# error (a developer added an out-of-range value to EXPECTED_EXIT_CODE), not
# a runtime condition, so a hard failure at import time is the right signal.
assert all(code in NORMATIVE_EXIT_CODES for code in EXPECTED_EXIT_CODE.values()), (
    f"EXPECTED_EXIT_CODE contains a value outside NORMATIVE_EXIT_CODES "
    f"{NORMATIVE_EXIT_CODES}: "
    + ", ".join(
        f"{cls!r}={code}"
        for cls, code in EXPECTED_EXIT_CODE.items()
        if code not in NORMATIVE_EXIT_CODES
    )
)


# ---------------------------------------------------------------------------
# ABSENT_PATHS_SURFACE
# ---------------------------------------------------------------------------

# Relative filename (within ``expected/``) of the control file that lists
# scratch-relative paths that MUST NOT exist after the run.
# Each non-empty, non-comment line is a path relative to the scratch root.
# Used by S11e to assert that member-local ``milpa.lock`` was not written.
ABSENT_PATHS_SURFACE: str = "absent"
