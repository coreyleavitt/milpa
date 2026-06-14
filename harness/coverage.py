"""MUST-clause coverage map for the differential conformance harness (slice 3e).

Enumerates the normative MUST/SHALL clauses from spec/*.md that are
*black-box observable* — things a fixture or generated example can exercise:
manifest parse outcomes, resolution outcomes, lockfile schema, CLI error codes.

For each clause we record:
  - A stable slug identifier (e.g. "cli.exit-codes", "resolver.maxver")
  - The source spec file + section description
  - The set of corpus fixture names (basenames) that exercise it (may be empty)
  - The generator tiers that exercise it ("tier1-syntactic", "tier2-sat",
    "tier2-unsat") — may be empty if only corpus covers it, or vice versa

`coverage_report(conformance_root, log)` is the main entry point.  It:
  1. Enumerates the actual fixture names present in the corpus.
  2. For each clause, checks whether any covering_fixtures are present AND/OR
     a covering_tier is in the active generator tiers.
  3. Prints covered clauses (log-level DEBUG) and gap clauses (log-level WARN).
  4. Returns a CoverageReport namedtuple with covered/gap counts.

This is a discovery artifact.  The build does NOT fail on gaps; the gap list
must be visible so missing coverage can be added over time.

Maintenance: when a new normative MUST clause is added to the spec and a fixture
is written for it, add an entry here (or extend an existing entry's
`covering_fixtures` list).  The clause inventory is the single source of truth
for saturation tracking.

Stdlib only; no 3rd-party dependencies, no import milpa.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, NamedTuple, Optional


# ---------------------------------------------------------------------------
# Clause descriptor
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SpecClause:
    """One normative MUST/SHALL clause from the milpa spec.

    id               — stable slug (dotted: "<spec-file-short>.<topic>")
    spec_ref         — human-readable "file §section" location
    description      — one-line summary of what the clause requires
    covering_fixtures — corpus fixture basenames (list of strings; order
                        does not matter) that exercise this clause.  Empty
                        list means only the generator tiers cover it, or it
                        is a known gap.
    covering_tiers   — which generator tiers exercise this clause:
                       "tier1-syntactic", "tier2-sat", "tier2-unsat"
    observable       — True if the clause is black-box observable (parse
                       outcome, exit code, error slug, output file contents).
                       Non-observable clauses (e.g. internal architecture
                       requirements) are included for completeness but are
                       excluded from the gap report.
    """

    id: str
    spec_ref: str
    description: str
    covering_fixtures: tuple[str, ...] = field(default_factory=tuple)
    covering_tiers: tuple[str, ...] = field(default_factory=tuple)
    observable: bool = True


# ---------------------------------------------------------------------------
# The clause inventory
# ---------------------------------------------------------------------------
# Each clause is black-box observable unless observable=False.
# Clauses that are covered ONLY by the corpus (no generator tier exercises them)
# are listed with covering_tiers=() — they are covered (not gaps) as long as
# the fixture is present.
# Clauses with covering_fixtures=() AND covering_tiers=() are GAPS.

CLAUSE_INVENTORY: list[SpecClause] = [
    # -----------------------------------------------------------------------
    # cli-contract.md §3 — Error channel / exit codes
    # -----------------------------------------------------------------------
    SpecClause(
        id="cli.exit-code-success",
        spec_ref="cli-contract.md §3.1",
        description="Successful invocation MUST exit 0 with no milpa-error: line",
        covering_fixtures=("fixture-003-single-url-dep",
                           "fixture-061-named-dep"),
        covering_tiers=("tier2-sat",),
    ),
    SpecClause(
        id="cli.exit-code-failure",
        spec_ref="cli-contract.md §3.1",
        description="Failure MUST exit 1 with exactly one milpa-error: <SLUG> line",
        covering_fixtures=("fixture-001-man-kdl-syntax",
                           "fixture-002-man-name-missing",
                           "fixture-062-solve-conflict"),
        covering_tiers=("tier1-syntactic", "tier2-unsat"),
    ),
    SpecClause(
        id="cli.error-slug-r1",
        spec_ref="cli-contract.md §3.1 R1",
        description="Error slug MUST match ^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$ and be in errors.md catalog",
        covering_fixtures=("fixture-001-man-kdl-syntax",
                           "fixture-002-man-name-missing"),
        covering_tiers=("tier1-syntactic", "tier2-unsat"),
    ),
    SpecClause(
        id="cli.error-slug-r2",
        spec_ref="cli-contract.md §3.1 R2",
        description="Exactly one milpa-error: line on failure; none on success",
        covering_fixtures=("fixture-001-man-kdl-syntax",
                           "fixture-003-single-url-dep"),
        covering_tiers=("tier1-syntactic", "tier2-sat", "tier2-unsat"),
    ),
    SpecClause(
        id="cli.error-slug-r3",
        spec_ref="cli-contract.md §3.1 R3",
        description="milpa-error: line appears iff exit 1 (not on exit 0)",
        covering_fixtures=("fixture-003-single-url-dep",
                           "fixture-061-named-dep"),
        covering_tiers=("tier2-sat",),
    ),
    SpecClause(
        id="cli.exit-code-crash",
        spec_ref="cli-contract.md §3.1 R4",
        description="Any non-0/1 exit or exit-1 with no slug = crash verdict",
        covering_fixtures=(),
        covering_tiers=("tier1-syntactic",),
    ),

    # -----------------------------------------------------------------------
    # cli-contract.md §5.1 — fetch verb
    # -----------------------------------------------------------------------
    SpecClause(
        id="cli.fetch-success-milpa-lock",
        spec_ref="cli-contract.md §5.1",
        description="On success, fetch MUST write milpa.lock and nim.cfg",
        covering_fixtures=("fixture-003-single-url-dep",
                           "fixture-061-named-dep"),
        covering_tiers=("tier2-sat",),
    ),
    SpecClause(
        id="cli.fetch-atomic-write",
        spec_ref="cli-contract.md §5.1",
        description="On failure, MUST NOT leave a partial milpa.lock or nim.cfg (atomic write)",
        covering_fixtures=("fixture-001-man-kdl-syntax",
                           "fixture-002-man-name-missing"),
        covering_tiers=("tier1-syntactic", "tier2-unsat"),
    ),

    # -----------------------------------------------------------------------
    # cli-contract.md §5.3 — show verb
    # -----------------------------------------------------------------------
    SpecClause(
        id="cli.show-no-lock",
        spec_ref="cli-contract.md §5.3",
        description="show MUST exit 1 with LOCK-FILE-NOT-FOUND when milpa.lock absent",
        covering_fixtures=("fixture-157-lock-file-not-found",),
        covering_tiers=(),
    ),

    # -----------------------------------------------------------------------
    # cli-contract.md §5.4 — verify verb
    # -----------------------------------------------------------------------
    SpecClause(
        id="cli.verify-no-lock",
        spec_ref="cli-contract.md §5.4",
        description="verify MUST exit 1 with LOCK-FILE-NOT-FOUND when milpa.lock absent",
        covering_fixtures=(),
        covering_tiers=(),
        # GAP: no corpus fixture exercises verify with a missing milpa.lock
        # (fixture-157 covers the show verb; a separate verify+no-lock fixture
        # would need cmd=verify without milpa.lock — not yet authored)
    ),
    SpecClause(
        id="cli.verify-graph-drift",
        spec_ref="cli-contract.md §5.4",
        description="verify MUST exit 1 with LOCK-GRAPH-MISMATCH when _deps/ diverges from milpa.lock",
        covering_fixtures=("fixture-159-lock-graph-mismatch",),
        covering_tiers=(),
    ),

    # -----------------------------------------------------------------------
    # manifest-grammar.md §3 — KDL structure
    # -----------------------------------------------------------------------
    SpecClause(
        id="manifest.kdl-parse",
        spec_ref="manifest-grammar.md §3",
        description="Manifest MUST be a valid KDL 2.0 document; parser MUST reject invalid KDL",
        covering_fixtures=("fixture-001-man-kdl-syntax",),
        covering_tiers=("tier1-syntactic",),
    ),
    SpecClause(
        id="manifest.name-required",
        spec_ref="manifest-grammar.md §3.2",
        description="Manifest MUST contain exactly one name node",
        covering_fixtures=("fixture-002-man-name-missing",
                           "fixture-004-man-name-duplicate",
                           "fixture-005-man-name-type"),
        covering_tiers=("tier1-syntactic",),
    ),
    SpecClause(
        id="manifest.kind-required",
        spec_ref="manifest-grammar.md §3.3",
        description="Manifest MUST contain exactly one kind node with application or library",
        covering_fixtures=("fixture-011-man-kind-arity",
                           "fixture-012-man-kind-invalid"),
        covering_tiers=("tier1-syntactic",),
    ),
    SpecClause(
        id="manifest.unknown-top-level",
        spec_ref="manifest-grammar.md §3.2",
        description="Unknown top-level node names MUST raise MAN-UNKNOWN-TOP-LEVEL",
        covering_fixtures=("fixture-009-man-unknown-top-level",),
        covering_tiers=("tier1-syntactic",),
    ),
    SpecClause(
        id="manifest.dep-duplicate",
        spec_ref="manifest-grammar.md §4",
        description="Duplicate dep names MUST raise MAN-DEP-DUPLICATE",
        covering_fixtures=("fixture-013-man-dep-duplicate",),
        covering_tiers=(),
    ),
    SpecClause(
        id="manifest.url-dep-git-required",
        spec_ref="manifest-grammar.md §4.1",
        description="URL dep MUST carry both git= and ref=; missing ref= raises MAN-DEP-REF-MISSING",
        covering_fixtures=("fixture-015-man-dep-ref-missing",),
        covering_tiers=(),
    ),
    SpecClause(
        id="manifest.url-annotation",
        spec_ref="manifest-grammar.md §3.1",
        description="URL-typed fields MUST accept (url) annotation; wrong type raises MAN-URL-ARG-TYPE",
        covering_fixtures=("fixture-060-man-url-arg-type",),
        covering_tiers=(),
    ),
    SpecClause(
        id="manifest.named-dep-constraint",
        spec_ref="manifest-grammar.md §4.3",
        description="Named dep MUST parse constraint at parse boundary; malformed raises MAN-DEP-NAMED-CONSTRAINT",
        covering_fixtures=("fixture-119-man-dep-named-constraint-bad-string",),
        covering_tiers=("tier2-sat",),
    ),
    SpecClause(
        id="manifest.workspace-no-deps",
        spec_ref="manifest-grammar.md §3.2",
        description="workspace node MUST NOT also declare deps or kind",
        covering_fixtures=("fixture-010-man-workspace-has-kind",),
        covering_tiers=(),
    ),

    # -----------------------------------------------------------------------
    # resolver-semantics.md §3 — resolution correctness
    # -----------------------------------------------------------------------
    SpecClause(
        id="resolver.completeness",
        spec_ref="resolver-semantics.md §3",
        description="Resolver MUST find a solution whenever one exists",
        covering_fixtures=("fixture-003-single-url-dep",
                           "fixture-061-named-dep"),
        covering_tiers=("tier2-sat",),
    ),
    SpecClause(
        id="resolver.conflict-detection",
        spec_ref="resolver-semantics.md §3",
        description="If no solution exists, resolver MUST produce SOLVE-CONFLICT",
        covering_fixtures=("fixture-062-diamond-conflict",),
        covering_tiers=("tier2-unsat",),
    ),
    SpecClause(
        id="resolver.constraint-intersection",
        spec_ref="resolver-semantics.md §4",
        description="Resolver MUST intersect all consumers' constraints on a shared dep",
        covering_fixtures=("fixture-062-diamond-conflict",),
        covering_tiers=("tier2-unsat",),
    ),
    SpecClause(
        id="resolver.no-backtrack-on-identity",
        spec_ref="resolver-semantics.md §5",
        description="URL/local/tarball deps resolved by identity; MUST NOT backtrack",
        covering_fixtures=("fixture-003-single-url-dep",),
        covering_tiers=(),
    ),
    SpecClause(
        id="resolver.maxver-default",
        spec_ref="resolver-semantics.md §6",
        description="Default strategy MUST be maxver; select highest version satisfying constraints",
        covering_fixtures=("fixture-061-named-dep",),
        covering_tiers=("tier2-sat",),
    ),
    SpecClause(
        id="resolver.determinism",
        spec_ref="resolver-semantics.md §6",
        description="Same input MUST produce byte-identical lockfile output",
        covering_fixtures=("fixture-003-single-url-dep",
                           "fixture-061-named-dep"),
        covering_tiers=("tier2-sat",),
    ),
    SpecClause(
        id="resolver.sort-order",
        spec_ref="resolver-semantics.md §8",
        description="Lockfile dep entries MUST be sorted lexicographically by dep name",
        covering_fixtures=("fixture-003-single-url-dep",
                           "fixture-061-named-dep"),
        covering_tiers=("tier2-sat",),
    ),
    SpecClause(
        id="resolver.predicate-filtering",
        spec_ref="resolver-semantics.md §9",
        description="Deps whose predicates do not match the active profile MUST NOT enter graph",
        covering_fixtures=("fixture-115-conditional-dep-excluded",),
        covering_tiers=(),
    ),
    SpecClause(
        id="resolver.frozen-no-network",
        spec_ref="resolver-semantics.md §7",
        description="Under --frozen, implementation MUST NOT contact any network resource",
        covering_fixtures=("fixture-083-frozen-identity-not-in-store",),
        covering_tiers=(),
    ),
    SpecClause(
        id="resolver.frozen-identity-check",
        spec_ref="resolver-semantics.md §7.1",
        description="Frozen path MUST raise FROZEN-* error if lockfile/identity conditions fail",
        covering_fixtures=("fixture-083-frozen-identity-not-in-store",
                           "fixture-086-frozen-member-identity-drift"),
        covering_tiers=(),
    ),
    SpecClause(
        id="resolver.dev-deps-root-only",
        spec_ref="resolver-semantics.md §10",
        description="dev-deps MUST be enrolled only at the root; transitive dev-deps MUST be ignored",
        covering_fixtures=(),
        covering_tiers=(),
        # GAP: no corpus fixture currently covers this directly
    ),

    # -----------------------------------------------------------------------
    # lockfile-schema.md
    # -----------------------------------------------------------------------
    SpecClause(
        id="lockfile.kdl-valid",
        spec_ref="lockfile-schema.md §3",
        description="milpa.lock MUST be a valid KDL 2.0 document",
        covering_fixtures=("fixture-003-single-url-dep",
                           "fixture-061-named-dep"),
        covering_tiers=("tier2-sat",),
    ),
    SpecClause(
        id="lockfile.version-node",
        spec_ref="lockfile-schema.md §3.1",
        description="Lockfile MUST contain exactly one top-level version node",
        covering_fixtures=("fixture-067-lock-version-missing",
                           "fixture-068-lock-version-unsupported"),
        covering_tiers=(),
    ),
    SpecClause(
        id="lockfile.dep-sort",
        spec_ref="lockfile-schema.md §3.3",
        description="Dep nodes MUST be sorted lexicographically by name",
        covering_fixtures=("fixture-003-single-url-dep",
                           "fixture-061-named-dep"),
        covering_tiers=("tier2-sat",),
    ),
    SpecClause(
        id="lockfile.identity-format",
        spec_ref="lockfile-schema.md §4.1",
        description="identity field MUST be sha256:<64-hex>; malformed raises LOCK-DEP-IDENTITY-INVALID",
        covering_fixtures=("fixture-073-lock-dep-identity-invalid",),
        covering_tiers=(),
    ),
    SpecClause(
        id="lockfile.string-escaping",
        spec_ref="lockfile-schema.md §3",
        description="Lockfile MUST correctly escape KDL string characters",
        covering_fixtures=("fixture-118-lock-string-escaping",),
        covering_tiers=(),
    ),

    # -----------------------------------------------------------------------
    # cli-contract.md §8 — environment variables
    # -----------------------------------------------------------------------
    SpecClause(
        id="cli.env-milpa-index-url",
        spec_ref="cli-contract.md §8.3",
        description="MILPA_INDEX_URL MUST be used as the tianguis index URL",
        covering_fixtures=("fixture-061-named-dep",),
        covering_tiers=("tier2-sat",),
    ),
    SpecClause(
        id="cli.env-milpa-mocked-fetches",
        spec_ref="cli-contract.md §8.4",
        description="MILPA_MOCKED_FETCHES MUST activate the mocked transport for all fetches",
        covering_fixtures=("fixture-003-single-url-dep",
                           "fixture-061-named-dep"),
        covering_tiers=("tier2-sat", "tier2-unsat"),
    ),
    SpecClause(
        id="cli.env-milpa-cache-dir",
        spec_ref="cli-contract.md §8.5",
        description="MILPA_CACHE_DIR MUST be used as the root of the CAS store",
        covering_fixtures=("fixture-003-single-url-dep",),
        covering_tiers=("tier2-sat",),
    ),
    SpecClause(
        id="cli.env-target-platform",
        spec_ref="cli-contract.md §8.1",
        description="MILPA_TARGET_PLATFORM MUST be used as the platform key in predicate evaluation",
        covering_fixtures=("fixture-115-conditional-dep-excluded",),
        covering_tiers=(),
    ),

    # -----------------------------------------------------------------------
    # manifest-grammar.md — overrides block
    # -----------------------------------------------------------------------
    SpecClause(
        id="manifest.overrides",
        spec_ref="manifest-grammar.md §5",
        description="overrides block MUST be accepted; unknown/malformed props raise MAN-OVERRIDE-*",
        covering_fixtures=("fixture-032-man-override-kind",
                           "fixture-033-man-override-arity",
                           "fixture-034-man-override-unknown-props",
                           "fixture-037-man-override-duplicate"),
        covering_tiers=(),
    ),

    # -----------------------------------------------------------------------
    # Known gaps (currently unexercised by corpus or generator)
    # -----------------------------------------------------------------------
    SpecClause(
        id="resolver.result-certificate",
        spec_ref="resolver-semantics.md §5.1",
        description="Conformant impl MUST emit a result certificate (future — deferred per RFC)",
        covering_fixtures=(),
        covering_tiers=(),
        observable=False,  # Not yet observable / not yet specified in full
    ),
    SpecClause(
        id="cli.add-git",
        spec_ref="cli-contract.md §5.6",
        description="add --git MUST fetch, resolve commit SHA, write to milpa.kdl + milpa.lock",
        covering_fixtures=("fixture-120-add-git-dep",
                           "fixture-161-man-add-dep-exists"),
        covering_tiers=(),
    ),
    SpecClause(
        id="cli.remove",
        spec_ref="cli-contract.md §5.7",
        description="remove MUST remove dep from milpa.kdl; absent dep raises MAN-REMOVE-DEP-ABSENT",
        covering_fixtures=("fixture-121-remove-dep",
                           "fixture-162-man-remove-dep-absent"),
        covering_tiers=(),
    ),
    SpecClause(
        id="cli.update",
        spec_ref="cli-contract.md §5.8",
        description="update MUST drop pins and refetch; MUST NOT mutate milpa.kdl",
        covering_fixtures=("fixture-123-update-all",
                           "fixture-124-update-scoped",
                           "fixture-160-lock-dep-not-found"),
        covering_tiers=(),
    ),
    SpecClause(
        id="cli.show-format",
        spec_ref="cli-contract.md §5.3",
        description="show output format (non-frozen in v1 — liveness-only coverage until format is frozen)",
        covering_fixtures=(),
        covering_tiers=(),
        observable=False,  # §2f: show format not frozen; liveness-only
    ),
]


# ---------------------------------------------------------------------------
# Active generator tiers (what the saturation test runs)
# ---------------------------------------------------------------------------

ACTIVE_TIERS: frozenset[str] = frozenset({
    "tier1-syntactic",
    "tier2-sat",
    "tier2-unsat",
})


# ---------------------------------------------------------------------------
# CoverageReport
# ---------------------------------------------------------------------------

class CoverageReport(NamedTuple):
    """Summary of clause coverage."""

    total_observable: int          # observable clauses in inventory
    covered: int                   # clauses with ≥1 fixture OR ≥1 active tier
    gaps: int                      # observable clauses with NO coverage
    gap_ids: tuple[str, ...]       # stable IDs of gap clauses
    missing_fixtures: dict[str, tuple[str, ...]]  # clause_id -> fixtures not in corpus


# ---------------------------------------------------------------------------
# coverage_report — main entry point
# ---------------------------------------------------------------------------

def coverage_report(
    conformance_root: "str | Path",
    log: Optional[Callable[[str], None]] = None,
) -> CoverageReport:
    """Compute and log the clause coverage map.

    Enumerates actual fixtures present in conformance/spec-v1/, then for each
    clause in CLAUSE_INVENTORY:
      - If any covering_fixture is present OR any covering_tier is in ACTIVE_TIERS
        → "covered"
      - Otherwise → "gap" (visible in the log output)

    Does NOT fail on gaps; emits them to `log` for visibility.

    Parameters
    ----------
    conformance_root : path to the repo's conformance/ directory
                       (the parent of spec-v1/).
    log              : callable(str) for output; defaults to print.
    """
    if log is None:
        log = print

    corpus_root = Path(conformance_root) / "spec-v1"
    present_fixtures: frozenset[str] = frozenset()
    if corpus_root.is_dir():
        present_fixtures = frozenset(
            d.name for d in corpus_root.iterdir() if d.is_dir()
        )

    observable_clauses = [c for c in CLAUSE_INVENTORY if c.observable]

    covered_ids: list[str] = []
    gap_ids: list[str] = []
    missing_fixtures_map: dict[str, tuple[str, ...]] = {}

    for clause in observable_clauses:
        # Check if any covering fixture is present in the corpus
        fixture_covered = any(
            fx in present_fixtures for fx in clause.covering_fixtures
        )
        # Check if any covering tier is in the active set
        tier_covered = bool(set(clause.covering_tiers) & ACTIVE_TIERS)

        covered = fixture_covered or tier_covered

        # Track which listed fixtures are absent (for informational output)
        missing = tuple(
            fx for fx in clause.covering_fixtures if fx not in present_fixtures
        )
        if missing:
            missing_fixtures_map[clause.id] = missing

        if covered:
            covered_ids.append(clause.id)
            log(
                f"[coverage] COVERED  {clause.id:<45s} "
                f"(fixtures={len([f for f in clause.covering_fixtures if f in present_fixtures])}"
                f"+missing={len(missing)}"
                f", tiers={list(set(clause.covering_tiers) & ACTIVE_TIERS)})"
            )
        else:
            gap_ids.append(clause.id)
            log(
                f"[coverage] GAP      {clause.id:<45s} "
                f"| {clause.spec_ref} — {clause.description}"
            )

    log(
        f"\n[coverage] SUMMARY: "
        f"{len(covered_ids)}/{len(observable_clauses)} clauses covered, "
        f"{len(gap_ids)} gaps"
    )
    if gap_ids:
        log(f"[coverage] GAP list: {', '.join(gap_ids)}")
    else:
        log("[coverage] No gaps detected — all observable MUST-clauses are covered.")

    return CoverageReport(
        total_observable=len(observable_clauses),
        covered=len(covered_ids),
        gaps=len(gap_ids),
        gap_ids=tuple(gap_ids),
        missing_fixtures=missing_fixtures_map,
    )
