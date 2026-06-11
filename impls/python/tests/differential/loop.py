"""Differential driver — reusable across tiers.

`run_all_impls(input_dir, descriptors)` — invoke every registered impl against
one fixture input directory, return a dict of name → RunResult.

`agreement(results)` — the tier-1 oracle: all impls must agree on:
  1. The same exit-code class (success / error / crash).
  2. The same slug (when exit-code class is "error").
Returns None on agreement; a Divergence on disagreement.

`structural_oracle(spec, result)` — the tier-2 oracle (RFC §2c):
  Independently verifies one impl's lockfile output against the known-solution
  FixtureSpec. Does NOT require cross-impl agreement (catches bugs where both
  impls are wrong the same way). Only meaningful on rc==0.
  - Parses the produced milpa.lock from the impl's scratch dir (stdlib-only,
    no import milpa).
  - For each locked dep, asserts the locked version satisfies every constraint
    declared for that dep in the manifest + transitive requires.
  - Asserts the locked solution is complete (every transitively required
    package is present in the lock).
Returns None on pass; an OracleFailure on violation.

Exit-code classes (RFC §2c / §2d):
  - "success" (rc == 0, no slug line)
  - "error"   (rc == 1, exactly one slug line)
  - "crash"   (any other rc, OR rc==1 with no slug, OR protocol violation)
    Note: exit 2 (arg-parse failure) is treated as "crash" per RFC Gap-1 R4.

Reuses `harness.runner.run_fixture` and `harness.descriptors.ImplDescriptor`;
does NOT import any milpa impl internals.
"""

from __future__ import annotations

# Trigger the bridge so `import harness.*` resolves.
import differential  # noqa: F401 — side-effect: repo-root on sys.path

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from harness.descriptors import ImplDescriptor
from harness.runner import RunResult, run_fixture

if TYPE_CHECKING:
    from harness.spec import FixtureSpec


# ---------------------------------------------------------------------------
# Exit-code class
# ---------------------------------------------------------------------------

def _exit_class(result: RunResult) -> str:
    """Classify a RunResult into one of three exit classes.

    "success" — rc == 0, no slug, no protocol violation.
    "error"   — rc == 1, exactly one slug, no protocol violation.
    "crash"   — anything else: non-0/1 rc, rc==1 with no slug, or
                a protocol violation (2+ slug lines).
    """
    if result.slug_error is not None:
        # Protocol violation (multiple milpa-error lines).
        return "crash"
    if result.returncode == 0 and result.slug is None:
        return "success"
    if result.returncode == 1 and result.slug is not None:
        return "error"
    # rc==1 but no slug, or rc != 0 or 1
    return "crash"


# ---------------------------------------------------------------------------
# Divergence record
# ---------------------------------------------------------------------------

@dataclass
class Divergence:
    """Structured disagreement between impls on one input.

    Mirrors §2e's JSON record shape:
      { fixture, cmd, output_file, impls: { name: slug-or-bytes } }

    For tier-1 (slug agreement), `output_file` is always "error-slug"
    (not a real file; the signal is the slug value or its absence).
    """
    fixture_id: str                  # e.g. temp dir name or a description
    cmd: str                         # fixture cmd (e.g. "resolve")
    output_file: str                 # "error-slug" for tier-1
    impls: dict[str, str]           # impl_name -> "exit_class:slug" or "exit_class"

    def to_json(self) -> str:
        record = {
            "fixture": self.fixture_id,
            "cmd": self.cmd,
            "output_file": self.output_file,
            "impls": self.impls,
        }
        return json.dumps(record, indent=2)

    def summary(self) -> str:
        lines = [
            f"DIVERGENCE fixture={self.fixture_id!r} cmd={self.cmd!r}",
        ]
        for impl_name, value in self.impls.items():
            lines.append(f"  {impl_name}: {value}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core driver functions
# ---------------------------------------------------------------------------

def run_all_impls(
    input_dir: Path,
    descriptors: list[ImplDescriptor],
    timeout: int = 60,
) -> dict[str, RunResult]:
    """Run all registered impls against one fixture input directory.

    Returns a mapping of impl name -> RunResult. Each impl gets its own
    isolated scratch + CAS dir (harness.runner.run_fixture handles this).

    `input_dir` is the fixture dir with cmd + milpa.kdl (+ optional
    index.kdl / mocked-fetches/ for tier-2). It is treated as read-only;
    the runner deep-copies inputs to a fresh scratch dir per impl.
    """
    return {
        desc.name: run_fixture(input_dir, desc, timeout=timeout)
        for desc in descriptors
    }


def _impl_key(result: RunResult) -> str:
    """Produce a short string representing one impl's outcome for comparison."""
    cls = _exit_class(result)
    if cls == "error" and result.slug:
        return f"error:{result.slug}"
    return cls


def agreement(
    results: dict[str, RunResult],
    fixture_id: str = "generated",
    cmd: str = "resolve",
) -> Optional[Divergence]:
    """Tier-1 oracle: all impls must agree on exit-class AND slug.

    Returns None if all impls produced the same outcome.
    Returns a Divergence if any two impls disagree.

    Two impls agree when `_impl_key(r)` is identical for all r in results.
    """
    if len(results) < 2:
        # Nothing to compare with one impl.
        return None

    keys = {name: _impl_key(result) for name, result in results.items()}
    distinct = set(keys.values())

    if len(distinct) == 1:
        return None  # All agree.

    return Divergence(
        fixture_id=fixture_id,
        cmd=cmd,
        output_file="error-slug",
        impls=keys,
    )


# ---------------------------------------------------------------------------
# Tier-2 structural oracle (RFC §2c)
# ---------------------------------------------------------------------------

@dataclass
class OracleFailure:
    """Structural oracle violation for one impl's output.

    impl_name   — which impl produced the violation.
    violation   — human-readable description of the invariant violated.
    locked_deps — the parsed lock: {pkg_name → version_str}.
    """
    impl_name: str
    violation: str
    locked_deps: dict[str, str]

    def summary(self) -> str:
        lines = [
            f"ORACLE FAILURE impl={self.impl_name!r}",
            f"  violation: {self.violation}",
            f"  locked deps: {self.locked_deps}",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Minimal stdlib lockfile parser (no import milpa)
# ---------------------------------------------------------------------------

# Matches:  dep "pkgname" {
_DEP_LINE_RE = re.compile(r'^dep\s+"([^"]+)"')
# Matches:  version "1.2.3"  (inside a dep block)
_VER_LINE_RE = re.compile(r'^\s+version\s+"([^"]+)"')


def _parse_lock_deps(lock_text: str) -> dict[str, str]:
    """Parse a milpa.lock file and return {pkg_name → version_str}.

    Minimal line-oriented parse — no KDL parser. Walks the text looking
    for `dep "name" {` blocks and the `version "x.y.z"` line inside each.

    Only extracts name + version; ignores identity, provenance, etc.
    Returns an empty dict if the lock file is empty or has no dep blocks.
    """
    result: dict[str, str] = {}
    current_dep: Optional[str] = None
    for line in lock_text.splitlines():
        dep_match = _DEP_LINE_RE.match(line)
        if dep_match:
            current_dep = dep_match.group(1)
            continue
        if current_dep is not None:
            ver_match = _VER_LINE_RE.match(line)
            if ver_match:
                result[current_dep] = ver_match.group(1)
                current_dep = None  # done with this dep block's version
            elif line.strip() == "}":
                current_dep = None  # end of dep block without finding version
    return result


# ---------------------------------------------------------------------------
# Minimal stdlib semver satisfies() (no import milpa)
# ---------------------------------------------------------------------------

def _parse_semver(version: str) -> tuple[int, int, int]:
    """Parse a semver string to (major, minor, patch). Returns (0,0,0) on failure."""
    parts = version.split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except (ValueError, IndexError):
        return (0, 0, 0)


def _satisfies_constraint(version: str, constraint: str) -> bool:
    """Return True if version satisfies constraint.

    Handles the constraint forms produced by _version_constraint_containing():
      ">= X.Y.Z"   — version >= X.Y.Z
      "X.Y.Z"      — exact match
      ">= 0.0.1"   — always true for any real semver

    Only handles the subset that satisfiable_graph_st() actually generates.
    For unknown forms, returns True (permissive — avoids false positives).
    """
    c = constraint.strip()
    if not c or c == "*":
        return True

    v = _parse_semver(version)

    m = re.match(r'^>=\s*(.+)$', c)
    if m:
        floor = _parse_semver(m.group(1).strip())
        return v >= floor

    m = re.match(r'^<=\s*(.+)$', c)
    if m:
        ceil = _parse_semver(m.group(1).strip())
        return v <= ceil

    m = re.match(r'^>\s*(.+)$', c)
    if m:
        floor = _parse_semver(m.group(1).strip())
        return v > floor

    m = re.match(r'^<\s*(.+)$', c)
    if m:
        ceil = _parse_semver(m.group(1).strip())
        return v < ceil

    # Exact match (e.g. "1.0.0")
    if re.match(r'^\d+\.\d+\.\d+$', c):
        return _parse_semver(c) == v

    # Unknown form — permissive
    return True


# ---------------------------------------------------------------------------
# Tier-2 conflict oracle (RFC §2c — unsatisfiable instances)
# ---------------------------------------------------------------------------

_SOLVE_CONFLICT_SLUG = "SOLVE-CONFLICT"


@dataclass
class ConflictOracleFailure:
    """Conflict oracle violation for one or more impls on an unsatisfiable input.

    Each entry in `impls` maps impl_name → a short description of what went
    wrong: "exit-0 (wrongly resolved)", "wrong-slug:<slug>", or "crash".
    """
    impls: dict[str, str]  # impl_name -> failure description

    def summary(self) -> str:
        lines = ["CONFLICT ORACLE FAILURE:"]
        for impl_name, desc in self.impls.items():
            lines.append(f"  {impl_name}: {desc}")
        return "\n".join(lines)


def conflict_oracle(
    results: dict[str, RunResult],
) -> Optional[ConflictOracleFailure]:
    """Tier-2 conflict oracle: every impl MUST exit 1 with SOLVE-CONFLICT.

    For an unsatisfiable instance this is stronger than agreement():
    - agreement() only requires impls to agree with each other (both-wrong-same-way
      passes agreement but may mask the real conflict with e.g. FETCH-MOCK-MISSING).
    - conflict_oracle() asserts the specific SOLVE-CONFLICT outcome from the catalog
      (spec/errors.md: "No version solution exists — dep constraints are unsatisfiable").

    Failure modes flagged:
      - exit 0  → impl wrongly resolved a genuinely unsatisfiable instance (unsound solver
                  OR the generator emitted a satisfiable graph it thought was unsat)
      - exit 1 with wrong slug → a parse/fetch/index error is masking the conflict
      - crash (non-0/1, no slug, or protocol violation) → infra failure

    Returns None if every impl emitted SOLVE-CONFLICT. Returns ConflictOracleFailure
    if any impl did not.
    """
    failures: dict[str, str] = {}
    for impl_name, result in results.items():
        cls = _exit_class(result)
        if cls == "success":
            failures[impl_name] = "exit-0 (wrongly resolved — unsound solver or generator bug)"
        elif cls == "error":
            if result.slug != _SOLVE_CONFLICT_SLUG:
                failures[impl_name] = f"wrong-slug:{result.slug!r} (expected {_SOLVE_CONFLICT_SLUG!r})"
        else:
            # crash — non-0/1, no slug, or protocol violation
            failures[impl_name] = (
                f"crash (rc={result.returncode}, slug={result.slug!r})"
            )

    if failures:
        return ConflictOracleFailure(impls=failures)
    return None


def structural_oracle(
    spec: "FixtureSpec",
    result: RunResult,
) -> Optional[OracleFailure]:
    """Tier-2 structural oracle: verify one impl's lock output against the spec.

    Only runs on success (rc==0). Reads the milpa.lock from result.scratch_dir,
    then checks:
      1. Every dep in the lock satisfies every constraint declared for it
         (from manifest deps + transitive nimble requires in the solution graph).
      2. Every transitively-required package is present in the lock
         (completeness: if A is locked and A's solution version requires B,
         then B must also be locked).

    Returns None on pass; OracleFailure on any violation.
    """
    if result.returncode != 0:
        # Not a success — nothing to check
        return None

    lock_path = Path(result.scratch_dir) / "milpa.lock"
    if not lock_path.exists():
        return OracleFailure(
            impl_name=result.impl_name,
            violation=f"milpa.lock not found in scratch dir {result.scratch_dir!r}",
            locked_deps={},
        )

    lock_text = lock_path.read_text()
    locked = _parse_lock_deps(lock_text)

    # Build: for each package, the constraint the solver must satisfy.
    # Sources:
    #   a) Root manifest deps (DepSpec.named)
    #   b) Transitive requires from each locked dep's solution version .nimble
    constraints_for: dict[str, list[str]] = {}

    # a) Root manifest constraints
    for dep in spec.deps:
        if dep.is_named:
            constraints_for.setdefault(dep.name, [])
            if dep.constraint:
                constraints_for[dep.name].append(dep.constraint)

    # b) Transitive requires from locked deps' solution .nimbles
    # For each locked dep, find its index version entry's fetch entry and
    # parse the nimble requires to find transitive constraints.
    for pkg_name, locked_version in locked.items():
        # Find the index row for this package
        index_row = next(
            (row for row in spec.index_rows if row.name == pkg_name), None
        )
        if index_row is None:
            continue
        # Find the version entry matching the locked version
        ve = next(
            (v for v in index_row.versions if v.version == locked_version), None
        )
        if ve is None:
            continue
        # Get the fetch entry for this version
        key = (ve.git_url, ve.ref)
        if key not in spec.index_fetch_map:
            continue
        _, entry = spec.index_fetch_map[key]
        if entry.nimble_text is None:
            continue
        # Parse requires lines (import-free: re-implement inline)
        for m in re.finditer(
            r'^requires\s+"([A-Za-z][A-Za-z0-9_-]*)\s+([^"]*)"',
            entry.nimble_text,
            re.MULTILINE,
        ):
            req_name, req_constraint = m.group(1), m.group(2).strip()
            constraints_for.setdefault(req_name, [])
            if req_constraint:
                constraints_for[req_name].append(req_constraint)

    # Check 1: every locked dep satisfies its constraints
    for pkg_name, constraints in constraints_for.items():
        if pkg_name not in locked:
            # Check 2 (completeness) — missing transitive dep
            if constraints:
                return OracleFailure(
                    impl_name=result.impl_name,
                    violation=(
                        f"completeness: dep {pkg_name!r} is required "
                        f"(constraints: {constraints}) but not in the lock"
                    ),
                    locked_deps=locked,
                )
            continue
        locked_version = locked[pkg_name]
        for constraint in constraints:
            if not _satisfies_constraint(locked_version, constraint):
                return OracleFailure(
                    impl_name=result.impl_name,
                    violation=(
                        f"dep {pkg_name!r} locked at {locked_version!r} "
                        f"does NOT satisfy constraint {constraint!r}"
                    ),
                    locked_deps=locked,
                )

    return None
