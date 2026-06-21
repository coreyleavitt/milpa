"""Corpus runner — iterates all fixtures × all registered impls.

For each fixture:
  1. Checks per-impl known_failing and KNOWN_LIMITATIONS — skipped with reason.
  2. Runs each non-skipped impl through the fixture runner.
  3. Asserts each result against expected/ individually.
  4. Cross-impl compares normalized outputs; emits JSON divergence records on mismatch.

Entry point: run_corpus() — returns a CorpusReport.

Design constraints:
- stdlib only; no import milpa.
- All skips are LOGGED LOUDLY (RFC "no silent caps").
"""

from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from harness.assertions import AssertionFailure, ConformanceResult, assert_conformance
from harness.descriptors import ImplDescriptor
from harness.runner import RunResult, run_fixture


# ---------------------------------------------------------------------------
# Module-level known limitations (apply to ALL impls)
# ---------------------------------------------------------------------------

# These fixture directory names are skipped for all impls for structural
# reasons that a stdlib harness can't work around without reimplementing
# milpa internals.  Document the reason clearly.  If either actually passes
# black-box, remove it from this set.
KNOWN_LIMITATIONS: dict[str, str] = {
    "fixture-114-frozen-legacy-registry-provenance": (
        "requires CAS pre-seeding from cas-seed/ — a stdlib harness cannot "
        "compute the identity hash without reimplementing spec/identity.md; deferred"
    ),
    # Slice C c4 (rfc-conformance-parity §4): partial-profile absent-axis fixtures.
    # The CLI builds its Profile via Profile.from_environment(), which host-defaults
    # every absent MILPA_TARGET_* axis (cli-contract §8) — so a partial profile
    # (e.g. PLATFORM set, ARCH absent → None) is not expressible through the CLI on
    # EITHER impl, and both produce a host-defaulted resolution. The partial-profile
    # resolver behavior (absent axis ⇒ indeterminate predicate ⇒ excluded,
    # resolver-semantics §3.C) is covered by each impl's in-process suite. Making
    # this black-box-testable requires the CLI to express an explicitly-absent axis
    # — an open spec decision tied to #159/#160 (Profile optional axes) and #110
    # (universal cross-platform resolution). Deferred pending that governance call.
    "fixture-255-s4-partial-profile-positive-absent-axis": (
        "partial-profile absent-axis not expressible via the CLI (from_environment "
        "host-defaults absent axes, cli-contract §8); covered in-process. Deferred "
        "pending #159/#160/#110 — see RFC §4 Slice C c4"
    ),
    "fixture-256-s4-partial-profile-negated-absent-axis": (
        "partial-profile absent-axis not expressible via the CLI (from_environment "
        "host-defaults absent axes, cli-contract §8); covered in-process. Deferred "
        "pending #159/#160/#110 — see RFC §4 Slice C c4"
    ),
    "fixture-117-ws-two-member-success": (
        "workspace multi-member expected/member-*/nim.cfg layout — "
        "black-box check is structurally possible but workspace nim.cfg "
        "paths are relative to each member's dir; deferred pending §2.5 "
        "workspace fixture verification in the harness"
    ),
    # In-process-only verbs: lock-roundtrip and workspace-manifest-roundtrip
    # exercise parse+format pipelines inside the impl with no CLI surface.
    # The black-box harness cannot drive them (there is no CLI verb that maps
    # to these cmds); they are covered exclusively by each impl's internal test
    # suite (pytest / cargo test).
    "fixture-172-lock-aliases-field": (
        "cmd=lock-roundtrip has no CLI surface — covered by impl-internal "
        "tests only (pytest / cargo test); black-box harness cannot drive it"
    ),
    "fixture-264-s9a-workspace-manifest-roundtrip": (
        "cmd=workspace-manifest-roundtrip has no CLI surface — covered by "
        "impl-internal tests only (pytest / cargo test); black-box harness "
        "cannot drive it"
    ),
    "fixture-283-ws-manifest-roundtrip-special-chars": (
        "cmd=workspace-manifest-roundtrip has no CLI surface — covered by "
        "impl-internal tests only (pytest / cargo test); black-box harness "
        "cannot drive it"
    ),
    # NOTE (#120): fixtures 112/113 were previously quarantined here on the
    # belief that "no index configured" had no CLI surface. That is stale: the
    # three-way MILPA_INDEX_URL semantics (cli-contract §8.1 NORMATIVE) make
    # empty == explicitly no index, honored by BOTH impls' CLI path
    # (`_load_index_for_verb` / `maybe_index`), and run_fixture already sets
    # MILPA_INDEX_URL="" for fixtures with no index.kdl. Both fixtures pass
    # black-box on python+rust with zero divergence, so they are no longer
    # limitations.
    #
    # NOTE: fixture-288-ws-member-symlink-escape was previously listed here.
    # It is now REMOVED — the black-box CLI harness drives it correctly (both
    # python + rust CLI pass WS-MEMBER-PATH-ESCAPE with zero divergence).
    # The in-process guards in test_conformance.py and milpa-conformance/runner.rs
    # remain (those adapters read milpa.kdl from fx.dir directly and do not
    # honour the project-dir control file — they are covered by impl-internal
    # unit tests instead).
}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class SkipRecord:
    fixture_name: str
    reason: str
    scope: str  # "all-impls" or impl name


@dataclass
class DivergenceRecord:
    fixture_name: str
    cmd: str
    output_file: str                      # e.g. "expected/milpa.lock"
    impls: dict[str, str]                 # impl_name -> normalized content/slug


@dataclass
class CorpusReport:
    """Full result of a corpus run."""
    total_fixtures: int
    impl_names: list[str]

    # Per-impl counters.
    passed: dict[str, int] = field(default_factory=dict)
    failed: dict[str, int] = field(default_factory=dict)
    skipped_known_failing: dict[str, int] = field(default_factory=dict)

    skipped_known_limitations: int = 0
    skip_records: list[SkipRecord] = field(default_factory=list)

    all_failures: list[AssertionFailure] = field(default_factory=list)
    divergences: list[DivergenceRecord] = field(default_factory=list)

    def overall_passed(self) -> bool:
        return (
            sum(self.failed.values()) == 0
            and len(self.divergences) == 0
        )


# ---------------------------------------------------------------------------
# Fixture discovery
# ---------------------------------------------------------------------------

def _discover_fixtures(conformance_root: Path) -> list[Path]:
    """Discover all spec-v<N>/fixture-NNN-* directories, sorted."""
    fixtures: list[Path] = []
    if not conformance_root.is_dir():
        return fixtures
    for spec_dir in sorted(conformance_root.iterdir()):
        if not spec_dir.is_dir() or not spec_dir.name.startswith("spec-v"):
            continue
        for fixture_dir in sorted(spec_dir.iterdir()):
            if not fixture_dir.is_dir() or not fixture_dir.name.startswith("fixture-"):
                continue
            fixtures.append(fixture_dir)
    return fixtures


# ---------------------------------------------------------------------------
# Cross-impl divergence detection
# ---------------------------------------------------------------------------

def _detect_divergences(
    fixture_name: str,
    cmd: str,
    results_by_impl: dict[str, ConformanceResult],
) -> list[DivergenceRecord]:
    """Detect cross-impl parity violations for one fixture.

    A divergence is EITHER:
      (1) a pass/fail asymmetry — the impls disagree on whether the run conforms
          to ``expected/`` (one matches, another does not). This is the textbook
          cross-impl divergence and was previously invisible: the old detector
          compared only impls that BOTH passed, and two co-passers both equal
          ``expected/`` by construction, so it could never fire on a fixture that
          carries an ``expected/`` (Finding 1, docs/rfc-conformance-parity.baseline.md).
      (2) a normative-surface disagreement among impls that both passed — kept for
          fixtures without an ``expected/`` (pinned-divergence inputs) and as a
          belt-and-suspenders check.

    Impls parked in ``known_failing`` are excluded upstream (never enter
    ``results_by_impl``), so an intentional per-impl gap is not flagged here.
    A both-fail case is symmetric (not an asymmetry) and is reported only as the
    two per-impl failures it already is — typically a shared runner/fixture-input
    gap rather than a parity violation.
    """
    if len(results_by_impl) < 2:
        return []

    divergences: list[DivergenceRecord] = []

    # (1) Pass/fail asymmetry vs expected/.
    verdicts = {name: r.passed for name, r in results_by_impl.items()}
    if len(set(verdicts.values())) > 1:
        impls_view: dict[str, str] = {}
        for name, r in results_by_impl.items():
            if r.passed:
                impls_view[name] = "PASS"
            else:
                detail = r.failures[0].detail if r.failures else "FAIL"
                impls_view[name] = f"FAIL: {detail}"
        divergences.append(DivergenceRecord(
            fixture_name=fixture_name,
            cmd=cmd,
            output_file="<conformance-verdict>",
            impls=impls_view,
        ))

    # (2) Normative-surface disagreement among co-passers.
    passed_results = {
        name: r for name, r in results_by_impl.items() if r.passed
    }
    if len(passed_results) >= 2:
        all_keys: set[str] = set()
        for r in passed_results.values():
            all_keys.update(r.normalized_outputs.keys())
        for key in sorted(all_keys):
            values_by_impl = {
                name: r.normalized_outputs.get(key, "<MISSING>")
                for name, r in passed_results.items()
            }
            if len(set(values_by_impl.values())) > 1:
                divergences.append(DivergenceRecord(
                    fixture_name=fixture_name,
                    cmd=cmd,
                    output_file=key,
                    impls=values_by_impl,
                ))
    return divergences


# ---------------------------------------------------------------------------
# Main corpus runner
# ---------------------------------------------------------------------------

def run_corpus(
    conformance_root: Path,
    descriptors: list[ImplDescriptor],
    timeout: int = 180,
) -> CorpusReport:
    """Run the full corpus against all registered impls.

    Prints progress to stdout as it runs (one line per fixture per impl).
    """
    fixtures = _discover_fixtures(conformance_root)
    impl_names = [d.name for d in descriptors]

    report = CorpusReport(
        total_fixtures=len(fixtures),
        impl_names=impl_names,
        passed={n: 0 for n in impl_names},
        failed={n: 0 for n in impl_names},
        skipped_known_failing={n: 0 for n in impl_names},
    )

    for fixture_dir in fixtures:
        fixture_name = fixture_dir.name

        # Check global known limitations first.
        if fixture_name in KNOWN_LIMITATIONS:
            reason = KNOWN_LIMITATIONS[fixture_name]
            print(f"  SKIP (known-limitation) {fixture_name}: {reason}")
            report.skipped_known_limitations += 1
            report.skip_records.append(SkipRecord(
                fixture_name=fixture_name,
                reason=reason,
                scope="all-impls",
            ))
            continue

        cmd_file = fixture_dir / "cmd"
        cmd = cmd_file.read_text().strip() if cmd_file.exists() else "resolve"

        results_by_impl: dict[str, ConformanceResult] = {}

        for desc in descriptors:
            # Per-impl known_failing check.
            if fixture_name in desc.known_failing:
                reason = f"listed in {desc.name}.known_failing"
                print(f"  SKIP ({desc.name}/known-failing) {fixture_name}")
                report.skipped_known_failing[desc.name] += 1
                report.skip_records.append(SkipRecord(
                    fixture_name=fixture_name,
                    reason=reason,
                    scope=desc.name,
                ))
                continue

            run = run_fixture(fixture_dir, desc, timeout=timeout)
            result = assert_conformance(run, fixture_dir)

            # Clean up scratch and CAS dirs after asserting (SSOT via RunResult.cleanup).
            run.cleanup()

            if result.passed:
                report.passed[desc.name] += 1
                status = "PASS"
            else:
                report.failed[desc.name] += 1
                report.all_failures.extend(result.failures)
                status = "FAIL"

            results_by_impl[desc.name] = result
            print(f"  {status} ({desc.name}) {fixture_name}")

        # Cross-impl divergence detection.
        divs = _detect_divergences(fixture_name, cmd, results_by_impl)
        report.divergences.extend(divs)
        for div in divs:
            print(f"  DIVERGENCE {fixture_name} [{div.output_file}]: "
                  f"{list(div.impls.keys())}")

    return report


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def format_report(report: CorpusReport) -> str:
    """Format the corpus report as a human-readable string."""
    lines: list[str] = []
    lines.append("")
    lines.append("=" * 70)
    lines.append("MILPA DIFFERENTIAL CONFORMANCE HARNESS — CORPUS REPORT")
    lines.append("=" * 70)
    lines.append(f"Total fixtures: {report.total_fixtures}")
    lines.append(f"Skipped (known limitations, all impls): {report.skipped_known_limitations}")

    for name in report.impl_names:
        lines.append(
            f"  {name}: "
            f"PASS={report.passed.get(name, 0)} "
            f"FAIL={report.failed.get(name, 0)} "
            f"SKIP(known-failing)={report.skipped_known_failing.get(name, 0)}"
        )

    # Skip log (known limitations).
    lim_skips = [s for s in report.skip_records if s.scope == "all-impls"]
    if lim_skips:
        lines.append("")
        lines.append("SKIPPED (known limitations):")
        for s in lim_skips:
            lines.append(f"  [{s.fixture_name}] {s.reason}")

    # Per-impl known_failing skips.
    impl_skips = [s for s in report.skip_records if s.scope != "all-impls"]
    if impl_skips:
        lines.append("")
        lines.append("SKIPPED (per-impl known-failing):")
        for s in impl_skips:
            lines.append(f"  [{s.scope}] {s.fixture_name}: {s.reason}")

    # Failures.
    if report.all_failures:
        lines.append("")
        lines.append(f"FAILURES ({len(report.all_failures)}):")
        for f in report.all_failures:
            lines.append(f"  [{f.impl_name}] {f.fixture_name} ({f.kind}): {f.detail}")

    # Divergences.
    if report.divergences:
        lines.append("")
        lines.append(f"CROSS-IMPL DIVERGENCES ({len(report.divergences)}):")

        # Group by (cmd, output_file, disagreement_shape).
        from collections import Counter
        shapes: Counter[tuple[str, str, str]] = Counter()
        for d in report.divergences:
            shape = " vs ".join(sorted(set(d.impls.values())))
            shapes[(d.cmd, d.output_file, shape)] += 1

        lines.append("  Summary (cmd, output_file, shape, count):")
        for (cmd, outfile, shape), count in shapes.most_common():
            lines.append(f"    cmd={cmd!r} file={outfile!r} count={count}: {shape[:80]}")

        lines.append("")
        lines.append("  Per-fixture divergence records (JSON):")
        for d in report.divergences:
            record = {
                "fixture": d.fixture_name,
                "cmd": d.cmd,
                "output_file": d.output_file,
                "impls": d.impls,
            }
            lines.append("  " + json.dumps(record))
    else:
        lines.append("")
        lines.append("Cross-impl divergences: NONE")

    lines.append("")
    if report.overall_passed():
        lines.append("OVERALL: PASS")
    else:
        lines.append("OVERALL: FAIL")
    lines.append("=" * 70)

    return "\n".join(lines)
