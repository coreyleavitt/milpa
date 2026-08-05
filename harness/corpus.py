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
    "fixture-316-s5b-namespace-lock-roundtrip": (
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
    #
    # S8 (rfc-attestation-v1-normative.md, differential: attestation surface in
    # the harness): the index-trust / show-index-trust fixture tier (338-366)
    # is NOW WIRED (see runner.py's _write_index_trust_manifest /
    # _translate_index_trust_env / _dispatch_cmd). The fixture's env carries
    # schema-only recipe fields (MILPA_INDEX_TRUST_MANIFEST, mock_verifier_result,
    # MILPA_INDEX_TRUST_WS_ROOT, MILPA_INDEX_TRUST_WS_MEMBER_ILLEGAL,
    # MILPA_REQUIRE_ATTESTED_INDEX); the black-box runner translates these into a
    # real synthesized milpa.kdl (+ workspace member dirs) and real CLI-recognized
    # env vars / flags, then dispatches to `fetch` (index-trust) or
    # `show --index-trust` (show-index-trust) — driving the REAL CLI's
    # `_build_index_trust` → `load_default_index` → `enforce_index_trust` gate,
    # confirmed empirically to match `expected/outcome` exactly on both impls
    # for all 29 fixtures (0 divergence). No entries remain here for this tier.
    #
    # 9 of the 29 (the `error:<SLUG>` outcomes — 340-345, 355, 363, 364) show up
    # as ASSERTION FAILURES (not skips, not divergences) in TestB2/TestB4: the
    # generic black-box assertion dispatch (harness/assertions.py, off-limits to
    # this task) treats a fixture with no `expected/error` file as success-class
    # (exit 0 required) — it has no schema awareness of `expected/outcome`'s
    # `error:<SLUG>` string. The real CLI's exit code (1) + slug are verified by
    # hand to be byte-correct in every case; this is a known, symmetric (both
    # impls agree) assertion-schema gap, not a behavior bug — see
    # TestS8AttestationDifferential's updated docstring in test_harness.py.
    #
    # S8: the entry-trust fixture tier (367-377). Unlike the index-trust tier
    # above, these DO carry a real milpa.kdl + mocked-fetches/ and dispatch via
    # the ordinary default cmd ("resolve" — no cmd file), so runner.py maps them
    # to a real CLI invocation. But none of them declares `index-trust` and none
    # ships an `index.kdl.bundle`, so under S4's flipped default (index-trust now
    # strict) the REAL CLI's index-trust gate fires FIRST (TNG-INDEX-BUNDLE-MISSING)
    # — before the fixture ever reaches the entry-trust gate it was authored to
    # exercise. This is not a fresh S8 finding: it is the exact gap the S4 handoff
    # already flagged as a non-blocking follow-up for Corey ("the general
    # conformance corpus does NOT exercise index-trust=strict end-to-end (adapter
    # bypasses it)... deferred; the flip is proven via dedicated fixtures + unit
    # tests instead") — the in-process adapter's `_build_env` never invokes the
    # CLI's index-trust gate (it constructs the index directly via `parse_index`),
    # so it never sees this ordering collision; only the real black-box CLI does.
    # Fixing this means deciding how the shared fixtures declare index-trust (the
    # deferred ~228-fixture-style migration option (b)) — a judgment call for
    # Corey, not a harness change. Covered today by each impl's own in-process
    # conformance adapter (test_corpus_fixture / milpa-conformance), which DOES
    # reach the entry-trust gate.
    **{
        name: (
            "cmd=resolve, but the real CLI's index-trust gate (strict default, "
            "S4) now fires before entry-trust because this fixture declares "
            "neither `index-trust` nor an index.kdl.bundle — a known, already-"
            "flagged S4 follow-up (see docs/rfc-attestation-v1-normative.handoff.md), "
            "not a fresh S8 finding; deferred pending a fixture-authoring decision "
            "for Corey. Covered by each impl's in-process conformance adapter, "
            "which bypasses the CLI's index-trust gate and reaches entry-trust — "
            "see RFC rfc-attestation-v1-normative.md S8"
        )
        for name in (
            "fixture-367-entry-trust-strict-unattested",
            "fixture-368-entry-trust-strict-bundle-missing-nopin",
            "fixture-369-entry-trust-strict-bundle-missing-unfetchable",
            "fixture-370-entry-trust-warn-bundle-pin-mismatch-unconditional",
            "fixture-371-entry-trust-strict-bundle-malformed",
            "fixture-372-entry-trust-strict-digest-mismatch",
            "fixture-373-entry-trust-strict-subject-mismatch",
            "fixture-374-entry-trust-strict-signature-invalid",
            "fixture-375-entry-trust-strict-signer-mismatch",
            "fixture-376-entry-trust-workspace-member-illegal",
            "fixture-377-entry-trust-strict-trusted-succeeds",
        )
    },
    # H-infra git-protocol tier (cmd=git-protocol, 13 fixtures): NOW WIRED (see
    # runner.py's _prepare_git_protocol) for 9 of 13 — the black-box runner
    # materializes the declared repos, synthesizes a single-dep manifest against
    # a reserved `.invalid` host, and rewrites the real transport target
    # per-subprocess via git's GIT_CONFIG_COUNT/KEY_n/VALUE_n `insteadOf`
    # mechanism (no file:// URL ever reaches the manifest — spec/manifest-
    # grammar.md §git NORMATIVE rejects it, MAN-GIT-URL-BAD-SCHEME, confirmed
    # against both real binaries). Confirmed passing on both impls with 0
    # divergence: 294, 296, 297, 299, 301, 334, 337 (content_hash-class) — the
    # black-box gate is exit-0-only (no byte-level content_hash re-derivation;
    # assertions.py has no comparison surface for `expected/content_hash`, and
    # extending it is out of this task's touch-list — the real cross-impl
    # content_hash guarantee remains each impl's own in-process H-infra adapter
    # matching the SAME committed expected/content_hash, exactly the
    # both-match-shared-expected pattern the entry-trust tier above relies on).
    #
    # The remaining 4 stay here:
    "fixture-295-git-protocol-non-tip-commit": (
        "the fixture pins an exact, non-ref commit_sha (fetch.commit_sha, "
        "H4/#177) distinct from ref — the manifest grammar has NO commit_sha "
        "field (spec/manifest-grammar.md §git NORMATIVE: 'In the manifest, git "
        "provenance is expressed as a UrlDep's git=+ref= properties'; commit_sha "
        "is lockfile/Provenance-only), so this cannot be driven through the "
        "CLI's fetch verb without silently substituting the mutable-ref-tip "
        "resolver for the exact-commit-pin `_ensure_commit_present` path the "
        "fixture exists to exercise. Covered by the in-process H-infra adapter, "
        "which constructs GitProvenance(ref=, commit_sha=) directly."
    ),
    **{
        name: (
            "the real CLI's per-candidate fetch loop "
            "(impls/python/milpa/resolver.py _fetch_url_dep_worker, and the Rust "
            "equivalent) catches EVERY exception from `fetcher.fetch()` — including "
            "definitive, non-retryable containment-guard errors raised during "
            "materialization (EXTRACT-SYMLINK-ESCAPE / EXTRACT-ZIP-SLIP / "
            "FETCH-GIT-LFS-POINTER) — as a 'this mirror candidate failed, try the "
            "next one'. With a single candidate (no mirrors declared, as in this "
            "fixture) the loop exhausts and wraps the swallowed error into a "
            "generic FETCH-ALL-FAILED, discarding the real slug entirely. "
            "Confirmed empirically on BOTH impls (same wrapped slug, same lost "
            "detail) driving this fixture through the real CLI's fetch verb via "
            "the black-box runner. This is a genuine, pre-existing, cross-impl "
            "resolver bug independent of the harness — a real user hitting this "
            "path (mirror-exhausted symlink-escape/zip-slip/LFS dep) gets the same "
            "useless FETCH-ALL-FAILED instead of an actionable slug. Filed as "
            "#198 (not fixed here — impls/ is off-limits, control-loop "
            "break-glass boundary); covered by the in-process H-infra adapter, "
            "which calls GitFetcher.fetch() directly and observes the real slug."
        )
        for name in (
            "fixture-298-git-protocol-symlink-escape",
            "fixture-300-git-protocol-lfs-pointer",
            "fixture-335-git-protocol-hostile-tree-parent-escape",
            "fixture-336-git-protocol-hostile-tree-absolute-path",
        )
    },
    # cmd=hash (1 fixture) and cmd=dag-oracle (5 fixtures): discovered while
    # wiring git-protocol/index-trust above — runner.py has never mapped either
    # cmd to a CLI invocation either (same "Unknown fixture cmd" crash), but
    # NEITHER was in this task's scope (git-protocol / index-trust /
    # show-index-trust only). Left here rather than silently crashing the
    # corpus loop; wiring them is a natural follow-up (both reuse the same
    # git-protocol.json repo-generation infra via harness/git_protocol_repo.py)
    # but is out of scope for this change. Covered by each impl's in-process
    # adapter (test_conformance.py::_execute_hash_fixture /
    # _execute_dag_oracle_fixture and their Rust equivalents).
    "fixture-326-hash-git-probe": (
        "cmd=hash has no black-box CLI dispatch yet — out of scope for this "
        "change (git-protocol/index-trust/show-index-trust only); covered by "
        "the in-process adapter (test_conformance.py::_execute_hash_fixture)"
    ),
    **{
        name: (
            "cmd=dag-oracle has no black-box CLI dispatch yet — out of scope for "
            "this change (git-protocol/index-trust/show-index-trust only); "
            "covered by the in-process adapter "
            "(test_conformance.py::_execute_dag_oracle_fixture)"
        )
        for name in (
            "fixture-329-dag-oracle-empty-root",
            "fixture-330-dag-oracle-nested-leafsort",
            "fixture-331-dag-oracle-git-nested",
            "fixture-332-dag-oracle-tarball-nested",
            "fixture-333-dag-oracle-local-nested",
        )
    },
    # index-history fixture tier (378-410, 453; cmd=index-trust): a NEWER
    # extension of the index-trust tier (A4a, RFC registry-append-only.md §2 —
    # the append-only ratchet baseline) discovered while wiring 338-366 above.
    # These share cmd="index-trust" but carry a DIFFERENT, richer recipe
    # (MILPA_INDEX_HISTORY_MANIFEST, `baseline-seed/`, `expected/baseline-state`,
    # `expected/baseline`, `expected/digest`, `expected/recurring`) that the
    # 338-366 translation in runner.py does not attempt to honor — out of scope
    # for this change. Left here (rather than silently crashing the corpus loop
    # once 338-366 stopped being a blanket skip) pending a dedicated wiring pass.
    # Covered by each impl's in-process adapter (already green — both
    # test_conformance.py::_execute_index_trust_fixture's A4a extension and the
    # Rust equivalent pass all 30 today).
    **{
        name: (
            "index-history tier (A4a ratchet-baseline extension) — recipe fields "
            "(MILPA_INDEX_HISTORY_MANIFEST, baseline-seed/, expected/baseline-state) "
            "not honored by this task's index-trust translation; out of scope. "
            "Covered by the in-process adapter "
            "(test_conformance.py::_execute_index_trust_fixture A4a extension)"
        )
        for name in (
            "fixture-378-index-history-baseline-seed-clean-advance",
            "fixture-379-index-history-baseline-seed-violation-warn",
            "fixture-380-index-history-rollback-version-removed-warn",
            "fixture-381-index-history-rollback-package-removed-warn",
            "fixture-382-index-history-frozen-content-hash-swap-strict",
            "fixture-383-index-history-set-once-backfill-legal-clean",
            "fixture-384-index-history-schema-version-regression-warn",
            "fixture-385-index-history-schema-version-absent-equiv-one-clean",
            "fixture-386-index-history-provenance-in-place-mutation-strict",
            "fixture-387-index-history-provenance-append-clean",
            "fixture-388-index-history-yank-flip-clean",
            "fixture-389-index-history-attestation-epoch-violation-warn",
            "fixture-390-index-history-dep-decl-lockstep-violation-warn",
            "fixture-391-index-history-off-preserves-baseline-clean",
            "fixture-392-index-history-corrupt-baseline-warn",
            "fixture-393-index-history-corrupt-baseline-strict",
            "fixture-394-index-history-corrupt-baseline-off-never-reads-clean",
            "fixture-395-index-history-parse-at-gate-no-clobber",
            "fixture-396-index-history-tofu-no-seed-establishes-baseline",
            "fixture-397-index-history-recurring-suppressed-warn",
            "fixture-398-index-history-recurring-new-remutation-warn",
            "fixture-399-index-history-composite-ordering-worked-example-warn",
            "fixture-404-index-history-attestation-strip-warn",
            "fixture-405-index-history-attestation-reattribution-strict",
            "fixture-406-index-history-attestation-repin-warn",
            "fixture-407-index-history-attestation-upgrade-clean",
            "fixture-408-index-history-rekor-frozen-changed-strict",
            "fixture-409-index-history-attestation-epoch-violation-strict",
            "fixture-410-index-history-root-vs-root-composite-tie-worked-example-warn",
            "fixture-453-index-history-provenance-oci-source-mutation-strict",
        )
    },
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
    output_file: str                      # e.g. "expected/milpa.lock"; "<conformance-verdict>" for verdict asymmetries
    impls: dict[str, str]                 # impl_name -> normalized content/slug
    is_verdict_asymmetry: bool = False    # True when impls disagree on pass/fail, not on output bytes


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

def discover_fixtures(conformance_root: Path) -> list[Path]:
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
            is_verdict_asymmetry=True,
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
    fixtures = discover_fixtures(conformance_root)
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
