# rfc-resolution-semantics — handoff

- **Stage:** 4 code-review — **COMPLETE. FLOOR REACHED (0 Critical/High/Medium after 3 rounds).**   •   Stage 3 (31 slices) + Architecture (rounds 1–3) COMPLETE.
  - **Review outcome:** 9-agent panel → 13 findings + R7 wontfix; 2 re-review rounds found RR1–RR6 (on the fixes) + emergent R8b. **17 findings fixed** across ~13 delegated sonnet TDD subagents, 1 wontfix (R7, reasoned), Lows left per mandate. Final suites GREEN: Python 3428/0-fail/33-skip; Rust workspace exit 0 (milpa-core 888, milpa-conformance 224, bijection+corpus ok, new fixtures 444/445/446). **Nothing committed — awaiting Corey.**
  - **Axis A** (#191) COMPLETE: A1,A2,A2c,A3,A3b,A4,A5,A6,A7.
  - **Axis B** (#192/#70) COMPLETE: B1–B7 (+ a follow-up fix threading `prior` through Rust `cmd_remove`).
  - **Axis C** (#98/#111) COMPLETE: C1,C2,C3,C3b,C4.
  - **Axis D** (#86) COMPLETE: D0,D1,D2,D3,D4,D5,D6,D7.
  - **Axis E** (#110) COMPLETE: E1 (single-config scope decision, `spec/resolver-semantics.md §6.1`).
  - **Axis W** (workspace) COMPLETE: W1 (`MAN-RESOLUTION-MEMBER-SCOPE` root-only enforcement + workspace fixtures).
  - Final verification (control loop): `cd impls/python && uv run pytest` exit 0; `./dev-rust test --workspace`
    exit 0, 0 failures, `rust_error_catalog_is_a_bijection_with_the_spec` green, conformance corpus 0 regressions.
- **Resume:** **Stage 4 — `/code-review docs/rfc-resolution-semantics`** (measure the whole implementation
  against the PhD-CS bar; 2–3 rounds to the floor). Nothing is committed — the entire implementation is
  uncommitted in the working tree, awaiting Corey's review/commit.
- **Deferred items surfaced during the grind (reported, NOT filed by subagents; for Corey's triage):**
  #193 (provenance gate on `Named` vs `url` items — Python/Rust divergence, filed by an A4 subagent before
  the no-`gh` rule); bare-`fetch` frozen-fast-path behavior differs Py/Rust; workspace-manifest serializer
  field-order differs Py/Rust (index-trust/entry-trust/index-history vs `workspace{}` block); Python solver
  one-level backtracking vs Rust pubgrub full backjumping (§7 residual risk, tied to #28).

## Review ledger (Stage 4 — round 1, 9-agent panel, findings verified)
Scope: resolution-semantics impl only (sigstore/attestation working-tree churn excluded). Status pending Corey's fix mandate.

| id | sev | finding | status | proof / note |
|----|-----|---------|--------|--------------|
| R1 | High | Python frozen-fast-path (`cli.py:1760 elif not locked and upgrade is None`) `return 0`s before `_resolve_effective_strategy`/`_exclude_newer` (1817/1821) → `milpa fetch --strategy …`/`--exclude-newer …` on a locked+unchanged project silently ignores the flag; Rust has no implicit fast-path → cross-impl divergence. fixture-432 is `cmd:resolve`, bypasses `cmd_fetch`, can't catch it. | open | CONFIRMED (read cli.py:1760-1821) |
| R2 | High | `_parse_timestamp` (`registry.py:832`) `datetime.fromisoformat` w/o tz-normalize → offsetless `exclude-newer "2026-01-01T00:00:00"` yields naive dt; compared vs tz-aware `published_at`/committer date → uncaught `TypeError` (not a coded slug). | open | CONFIRMED (read registry.py:822-835) |
| R3 | High | Rust `prioritize` ties non-version-unknown pkgs on `Reverse(name)` (alphabetical), not declaration-order BFS as spec §4.2.1 NORMATIVE mandates → potential resolved-graph divergence from Python (`_next_undecided` insertion order) for ambiguous diamond graphs. Predates RFC; A4 builds on it. | open | PLAUSIBLE — all current fixtures byte-identical; needs a non-alphabetical-declaration-order disambiguating fixture to confirm/refute |
| R4 | High | `spec/manifest-grammar.md §3.1` NORMATIVE top-level enumeration (line 121-125) lists `resolution` but omits the new `version` field → read literally contradicts `MAN-PACKAGE-VERSION-INVALID` + both parsers; no `#### version field` grammar subsection. | open | CONFIRMED (read manifest-grammar.md:115-190) — doc-only, quick fix |
| R5 | High | `spec/resolver-semantics.md §10.5` provenance-gate NORMATIVE claim overclaims a guarantee neither impl uniformly provides (Python gates url-only, Rust gates Named too) — spec face of known #193; §10.5 added without scoping around the gap. | open | CONFIRMED via #193 (already tracked, deferred) |
| R6 | Med | `root_authority` is a bare-name `set[str]` (`resolver.py:2673`); `is_root_direct` (`:833`) drops `namespace` → under `lowest-direct`, transitive `ns2::foo` misclassified root-direct when root declares `ns1::foo` → wrong MINVER + dropped lock-preference (reintroduces #192 via namespace door). Both impls (Rust mirrors). | open | CONFIRMED (read resolver.py:2673, :821-872) |
| R7 | Med | version-unknown-constrained returns pubgrub's terminal `Err` (`lib.rs:1219`, no backtrack). Reviewer's "valid solution exists" = silently downgrade an unrelated named dep to dodge a missing git-dep version — precisely the coupling the partition surfaces on purpose. Terminal `Err` is SAFE under A4 strict-last-scheduling (all non-version-unknown pkgs reach a conflict-free joint assignment before X is chosen). | **wontfix** | working as designed — hard error + remedy is correct; silent constrainer-downgrade would be worse |
| R8 | Med | Rust `constrainers` `RefCell<BTreeMap>` (`lib.rs:1171`) never pruned on pubgrub backtrack → remedy text may name a phantom constrainer from an abandoned branch; Python builds from final `incompats` so may diverge in message text. | open | PLAUSIBLE (read lib.rs) |
| R9 | Med | RFC §3 Axis C states lockfile-recorded strategy is "diagnostic/frozen-parity only, never a live input" but `_resolve_effective_strategy` tier-3 feeds it into live candidate selection → spec/impl contradiction (impl arguably better). Tier also untested. | open | escalation — spec vs impl |
| R10 | Med | `parse_version` (`version.py:319`) `int()` on unbounded `\d+` → uncaught `ValueError` (CPython 4300-digit limit) on attacker `ref=`/`.nimble`/`version=`; Rust `parse::<u64>().ok()` returns None → supply-chain DoS + parity divergence. | open | CONFIRMED by security agent repro |
| R11 | Med | Rust `cmd_show` (`main.rs:507`) omits `exclude_newer` (stale "Axis D not implemented" comment; Lockfile has the field since D5); Python prints it → cross-impl `show` divergence. | open | reported by Rust-io agent |
| R12 | Med | Rust `upgrade_flag_values` (`main.rs:4217`) stops only on `--`-prefixed tokens → `milpa fetch --upgrade foo -s minver` collects `["foo","-s","minver"]` → spurious `LOCK-DEP-NOT-FOUND`; Python argparse nargs handles it → divergence. | open | reported by Rust-io agent |
| R13 | Med | Test gaps on load-bearing behavior: (a) multi-constrainer resolver-level `version_unknown_constrained_err` untested in Rust (zero refs); (b) provenance-gate-before-generic-conflict untested for the differing-real-version shape; (c) branch-ref-once-locked reproducibility indistinguishable (mocked fetcher ignores commit_sha). | open | grep-confirmed by test-coverage agent |
| R14 | Low | ×11 batched: Rust `-C dir --version` misfire (`main.rs:108`); unconditional committer-date read on every git fetch; declared_version_source/version pairing not cross-validated on lockfile parse; D4 tag-vs-commit deref has no shared-corpus fixture (Rust untested); cli-contract Appendix A omits `--exclude-newer`; redundant in-fn imports in `declared_version_for`; exact-boundary `<=`/`<` untested on git-pin side; d2 CLI-precedence e2e checks only rc==0; Rust B5 idempotence is fixed-sweep not generated; milpa.kdl-vs-.nimble precedence pair untested; stale test pins `show` omits exclude-newer. | open | cosmetic/coverage |

### Fix-loop progress (round 1)
- **Landed + gated green:** R1 (cli.py unified fast-path gate, explicit-flag divergence), R2 (registry.py `_parse_timestamp` naive→UTC), R10 (version.py u64-ceiling parity), R4/R5/doc-Lows (spec docs, bijection green), R3 (Rust declaration-order `Priority` + fixture-444, corpus 404/404), R8 (Rust backtrack-correct constrainers), R11 (Rust `cmd_show` exclude-newer), R12 (Rust upgrade `-`-flag stop). Rust workspace verified exit 0 (milpa-core 878, milpa-solver 55, milpa-cli 160, bijection+corpus ok).
- **R8b (NEW, found by the R8 fix agent):** the phantom-constrainer bug was latent in BOTH impls (Python `_accumulated_constrainers` walked append-only `incompats`). Fixed Python to filter against `partial.decisions()` — parity with Rust restored. Python full suite green.
- **R9 (landed, both impls green — Python exit 0; Rust milpa-core 881 + milpa-cli 190):** dropped lockfile strategy tier; new `strategy_explicit` threaded through ResolveParams/provider; bypass now requires explicit-source AND value-divergence; stability rides on Axis-B preference. Also corrected the two NORMATIVE spec passages (`cli-contract §2.10`, `manifest-grammar` resolution block) that carried the same contradicting tier-3.
- **In flight:** R6 (namespace-aware `is_root_direct` via a new set, gate's bare-name `root_authority` left intact per #193 scope).
- **Queued:** R13 (test-coverage — note R13(a) multi-constrainer resolver-render likely already closed by R8's new Rust tests; R13(b) scope to url-vs-url differing-real-version to avoid #193; R13(c) mocked-fetcher commit_sha date variance). Then full both-impl suites + re-review round (Security + Design standing + changed-scope correctness).
- **Low doc follow-up (deferred, mandate=leave-Lows):** UTC note to `spec/registry-protocol.md §3.2` (redundant — cli-contract + manifest-grammar already carry it).

### Re-review round 2 (standing Security + Design + Correctness/Parity on the fixed code)
Final post-R13 suites GREEN: Python 3423/0-fail/33-skip; Rust workspace exit 0 (milpa-core 888, milpa-conformance 224, bijection+corpus ok, fixtures 444/445/446).
- **Security:** no new issues (parse totality confirmed, git-subprocess `--end-of-options` intact; mocked-fetcher `committer_date@<sha>` path noted as opt-in-test-only, not a finding).
- **Correctness/Parity:** R9/R6/R8/R8b/R3/R1 all verified correct AND identical across impls (R3 ordering empirically consistent → downgrades the design coupling concern to Low). Found **RR6**.
- **Design:** flagged SSOT regressions the fixes introduced → RR1/RR2/RR4.

Round-3 findings + status:
| id | sev | finding | status |
|----|-----|---------|--------|
| RR6 | High | R10 fix incomplete — sibling `_parse_pre_identifiers` (version.py:346) still `int()` unbounded → uncaught ValueError on `1.0.0-<6000 digits>`; Rust falls back to Alpha (crash + parity gap). | fixing (a6eedf8) |
| RR1 | Med | R9 duplicate precedence walk — `_resolve_effective_strategy`+`_is_strategy_explicit` (×2 impls) walk CLI>manifest twice; unify to one `Option<Strategy>`-returning fn. | fixing (a089cf7) |
| RR2 | Med | R6 dual sets hand-built at 4 sites → drift; build `root_direct_keys` once, derive `root_authority` as name-projection. | fixing (a089cf7) |
| RR4 | Med | R1 fast-path gate block duplicated verbatim in cmd_fetch/_cmd_fetch_workspace; extract shared helper. | fixing (a089cf7) |
| RR3 | Low | R3 `discovery_order` serves two concerns (dedup + solve priority); equivalence empirically holds but asserted-not-proven for flag-gated/lazy graphs. | leave (follow-up: differential fixture + cross-ref comment) |
| RR5 | Low | No differential fixture comparing Rust vs Python constrainer SETS under heavy backtracking (order not normative anywhere). | leave |
| — | note | dead-code `Resolver::resolve_workspace` trait method (lib.rs:204) hardcodes `strategy_explicit=false`; zero callers, inert. | leave |

### Lows cleared (Corey: "fix lows now")
Actionable Lows all fixed. Final suites GREEN: **Python 3432/0-fail/33-skip**; **Rust workspace exit 0** (milpa-core 891, milpa-cli 162, milpa-conformance 224, bijection+corpus ok, fixtures 444–447).
- **Python (LA):** L4 hoisted imports; L9 at-boundary git-pin test; L10 D2 asserts recorded lockfile value; L11 milpa.kdl-vs-.nimble precedence test; L12 stale `show`/exclude-newer comment fixed + positive assertion.
- **Rust (LB):** L1 `-C <dir> --version` pre-verb fix; L2 committer-date read gated behind exclude-newer; L5 unused-`constraint`/dup-doc cleanup (warning gone); L6 B5 idempotence; L9/L11 mirrored tests; L13/RR3 fixture-447 (flag-gated/lazy-named non-alphabetical declaration order, blessed from Python oracle, Rust byte-matches — proves the R3 decision-order parity) + `discovery_order` cross-ref comments.
- **Doc:** L7 registry-protocol.md UTC-offset NORMATIVE note (cli-contract + manifest-grammar already had it).
- **Reclassified (not blindly implemented):** L3 declared_version_source/version cross-validation → **wontfix** (mis-diagnosed: `(0.0.0, source=manifest)` and `(1.2.3, no source)` are BOTH valid; parse-time rejection would false-reject legit lockfiles — the pairing is an emitter guarantee, self-consistent by construction). L14 constrainer-set fixture → **already covered** by existing multi-constrainer tests (order non-normative).
- **Out of scope (pre-existing, not this RFC):** `index_trust.rs`/`entry_trust.rs` + sigstore-vendored + CAS/fetch dead-code warnings; #193 (named-vs-url provenance gate, separately tracked).

### Verified-correct (panel confirmed solid, no action)
`check_locked_drift` (identity+provenance-only, relabel-not-drift, provenance-sort); `declared_version_for` 4-step precedence + override re-derivation; Preference short-circuit (can't smuggle out-of-range); `0.0.0`+absent-source pairing (byte-identical both impls); error-slug bijection (all 13 new slugs present+raised both impls); `MAN-RESOLUTION-MEMBER-SCOPE` root-only (3 call sites); D3 index filter fail-closed + inclusive boundary; D4 committer-not-tagger date; A4 ordering-hazard fixture-418/419; B4 upgrade/update delegation equivalence (graph-map equality); C four-strategy divergent-selection; C3 value-divergence-not-presence bypass; W single-node dedup; identity §4.1a (no version in content_hash); exclude-newer git subprocess injection-clean (list-form + `--end-of-options`); ReDoS-clean; registry `published_at` fail-closed.

<!-- Historical per-slice notes below this line (superseded by the summary above). -->
- (historical) **next up is D7** (error-taxonomy audit/doc pass — the slugs already landed in
  D1–D5, D7 is the final catalog/doc pass, no new behavior) or the outstanding C4 bullet above.
  **C1 fixture history (resolved this session):** `fixture-427-strategy-minver-over-index` /
  `-428-strategy-semver-over-index` / `-429-strategy-maxver-over-index` are C1's own deliverable (the
  first CLI-level conformance fixture proving `--strategy minver`/`semver`/`maxver` select correctly
  from a genuine 3-candidate index dep — also satisfies C4's "all three strategies" bullet). They hit
  a **numbering collision**: two independent sessions were separately assigned C1 in parallel (this
  repo's autonomous `/loop` + an interactively-dispatched session), both computed "427" as the next
  free fixture number from the same `git status` snapshot, and the interactive session's fixture-
  authoring script overwrote the loop's in-progress `widget`-named `milpa.kdl`/`index.kdl`/
  `mocked-fetches/` with its own `stratpkg`-named content before the loop's `expected/` had been
  blessed against it — the exact mismatch a later D2 session's note (now removed) correctly diagnosed
  as "not a resolver bug" but mis-attributed to an in-progress C4 attempt. Resolution: reconstructed
  all three fixtures under the surviving `widget` naming (package name, URL, and commit_sha values
  recovered from the stale `expected/milpa.lock`; content_hash values recomputed fresh since the
  original mocked-fetches bytes were unrecoverable — untracked, no git blob ever existed), then
  re-blessed `expected/` via the harness's `_REGEN_MODE` bless path. Verified: `uv run pytest` 3304
  passed/0 failed/33 skipped; `./dev-rust test --workspace` all green including `conformance_corpus`
  (byte-identical parity, both impls select minver→1.0.0/semver→1.5.0/maxver→2.0.0 from the same
  shared manifest+index). **Structural note for future sessions:** fixture numbering by "highest
  existing + 1" is racy across concurrent sessions sharing this working tree — worth a `mkdir`-based
  reservation convention or a wider numeric gap per in-flight slice if this recurs.
- **Follow-up filed:** #193 — a genuine, PRE-EXISTING (not A4-caused) Rust/Python provenance-gate
  scope divergence surfaced while building an A4 fixture (Rust's `gate()`/`process_items` gates
  `Item::Named` too; Python's `_check_provenance_gate` only gates `kind == "url"` BFS items). Needs
  its own RFC-flow slice (spec decision: which impl is correct), not a fold-in fix. Not a blocker for
  A4 itself — the fixture that found it exercised an extra (non-mandated) scenario and was removed
  from the shared corpus rather than landed with a masked divergence; that scenario is still covered
  Python-only in `test_a4_version_unknown_constrained.py::TestVersionUnknownConstrainedTransitive`.
- **Follow-up NOT filed (reported only, per B7 session's hard rules):** a genuine, PRE-EXISTING (not
  B7-caused) Rust/Python `format_workspace_manifest` field-ordering divergence, discovered while
  building B7's `workspace-add-member-leaves-rest-pinned` conformance fixture. Python's
  `format_workspace_manifest` (manifest.py) emits `index-trust`/`index-trust-signer`/
  `index-trust-bundle`/`entry-trust`/`index-history` AFTER the `workspace {}`/`overrides {}`/
  `flags {}` blocks; Rust's `format_workspace_manifest` (format.rs) emits the same fields BEFORE
  `workspace {}`, right after `name`. Python's own docstring claims "byte-identical to the Rust
  `milpa-manifest::format_workspace_manifest`" — currently false whenever any of those root-policy
  fields is explicitly declared. Confirmed via real byte-diff against both real binaries (not just
  reasoning): running the same `workspace add-member` fixture with `index-trust "off"` set produced
  a `milpa.kdl` mismatch at the `index-trust` line between the two impls. B7's own fixtures avoid
  declaring `index-trust` (not needed for what B7 tests — the default `warn` policy is silent enough
  for a mocked-transport fixture), so this divergence is NOT exercised by anything B7 landed; it is
  orthogonal to Axis B (a manifest-serialization ordering bug, not a resolution-semantics one). Needs
  its own fix (pick one order, canonical-format the other) before any fixture that sets a workspace-
  root trust field co-exists with `workspace add-member`/`remove-member` in the shared corpus.

## Stage 3 progress
- **A1 — DONE, both impls green.**
  - **Python: DONE + GREEN** (`uv run pytest` exit 0). `milpa.kdl version` field parsed
    (`manifest.py`), `.nimble version` scanner added (`nimble.py`, totality-respecting), round-trip
    through `manifest_writer`, slug `MAN-PACKAGE-VERSION-INVALID` in `errors.py` + `spec/errors.md`
    (bijection green), tests in `test_manifest_parse.py`/`test_manifest_writer.py`/`test_nimble.py`.
  - **Rust: DONE + GREEN** (`./dev-rust test --workspace` exit 0, incl. `milpa-conformance`'s
    `rust_error_catalog_is_a_bijection_with_the_spec` + `conformance_corpus`). Landed: `version:
    Option<Version>` parse in `crates/milpa-manifest/src/lib.rs` (`"version"` added to
    `PACKAGE_TOP_LEVEL`, new `check_package_version` mirroring `check_spec_version`, reuses
    `milpa_solver::parse_version` — malformed is a hard `MAN-PACKAGE-VERSION-INVALID`); `.nimble`
    scanner in `nimble.rs` (`match_version`, mirrors `match_src_dir`, totality-respecting —
    malformed/2-component → `None`, never raises); round-trip emission in `format.rs` (emitted
    right after `name`, absent-stays-absent, mirrors `spec-version`); `MAN-PACKAGE-VERSION-INVALID`
    added to the `MAN_CODES` SSOT (flows into `milpa_core::implemented_error_codes()` automatically,
    no separate wiring needed) — bijection green with no DEFERRED/EXEMPT entry needed. Fixed the 4
    other `Manifest { … }` construction sites that needed the new field
    (`milpa-core/src/discovery.rs`, `frozen_tests.rs`, `resolver_tests.rs` ×2) plus the two
    `format.rs`/`tests.rs` test-helper literals. `discovery.rs::manifest_from_nimble` intentionally
    does NOT wire the scanned `.nimble` version through to `Manifest.version` — mirrors Python's own
    `_manifest_from_nimble` (workspace.py), which also leaves it `None`; that precedence-chain wiring
    is Axis A2, out of A1's scope. New unit tests: `lib.rs`'s `error_codes_match_fixtures` cases +
    `package_version_present_and_absent`; `nimble.rs`'s `version_quoted_and_unquoted` /
    `no_version_is_none` / `version_last_assignment_wins` / `version_malformed_is_none_not_panicking`
    / `version_two_component_is_none`; `format.rs`'s `package_version_emitted_only_when_present` /
    `package_version_round_trips`.
  - Next slices after A1: A2, A2c, A3, A3b, A4, A5, A6, A7 · B1–B7 · C1–C4(+C3b) · D0–D7 · E1 · W1.
- **A2 — DONE, both impls green.** Self-term causality fix (a) + candidate-label precedence (b),
  git/url/local/tarball only (member deps are A2c, untouched here).
  - **Python: DONE + GREEN** (done by a prior session/agent; `uv run pytest` exit 0, re-confirmed
    this session without touching Python). `resolver.py`: every git/url/local/tarball self-term
    (root seeding, S4a/S4b fixpoints, overridden-named coercions) now `VersionSet.full()` instead of
    `VersionSet.eq(_URL_DEP_VERSION)`. New `_candidate_label(ctx)` in `resolver.py` + `declared_version_for(ctx)`
    in `edge_sources.py` (precedence: fetched pkg's `milpa.kdl version`, else `.nimble version` (A1's
    scanner), else the existing sentinel) feeds the post-fetch `_Candidate.version` in
    `_process_url_worker`/`_process_local_worker`/`_process_tarball_worker`. `edgeset_to_terms`
    dropped its `url_dep_version` parameter (no longer needed — self-term is always `full()`).
  - **Rust: DONE + GREEN** (`./dev-rust test --workspace` exit 0 — 1205 passed across all crates incl.
    `milpa-conformance`'s `rust_error_catalog_is_a_bijection_with_the_spec` + `conformance_corpus`,
    which exercises all 30 updated shared fixtures). Landed in `crates/milpa-core/src/resolver.rs`:
    every git/url/local/tarball self-term site (`seed_root`, `seed_workspace`'s per-member loop, the
    S4b multi-consumer-union block, `run_s4a_fixpoint`, `edgeset_to_extracted`) changed `eq_sentinel()`
    → `VersionSet::full()`; the two sites that bundled `Dep::Member(_)` into the same match arm as
    Url/Local/Tarball were split so Member keeps `eq_sentinel()` (A2c, untouched). New `Extracted.declared_version:
    Option<Version>` field, set by `extract_requires` via new `declared_version_for(ctx)` in
    `edge_sources.rs` (mirrors Python's precedence exactly, reusing the existing `find_nimble`
    helper); new `candidate_label(declared_version)` helper feeds `Candidate.version` in
    `process_url`/`process_local`/`process_tarball`. Also updated (dead-code-but-tested) public
    `edgeset_to_terms` in `edge_sources.rs` for consistency — dropped its `url_dep_version` param,
    same `full()` semantics, plus its 5 unit tests. The cache-key `version: &Version` param threaded
    through `extract_requires`/`resolve_edges`/`EdgeSourceCtx` (used only as an edge-cache memo key,
    never a solver term) was deliberately left as `url_dep_version()` — matches Python's
    `_resolve_edges_pure(dep.name, _URL_DEP_VERSION, ctx, ...)`, which also keeps the cache-key
    argument unchanged. No expected-fixture divergence found — all 30 updated
    `conformance/spec-v1/**/expected/milpa.lock` fixtures pass unmodified in both impls.
- **A2c — DONE, both impls green.** Member-dep declared version + self-term treatment +
  `RES_WS_MEMBER_VERSION_CONSTRAINT` update, covering the full member-sentinel-site inventory (5
  sites per impl, not just the member's own candidate).
  - **Python:** new `_member_candidate_version(manifest, abs_dir)` in `resolver.py` (precedence:
    `manifest.version` — free, already parsed in memory — else `.nimble` scan of the member's own
    dir via a `declared_version_for` call with `has_milpa_kdl=False`, else the existing sentinel).
    `_build_member_candidate` reworked: takes a new `member_versions: dict[str, Version]` param
    (replaces `members_by_name`, precomputed once in `resolve_workspace` for ALL members so a
    same-name auto-coerce reference reads the *referenced* member's real version, not its own);
    its own candidate `version=` now `member_versions[manifest.name]`; the auto-coerce term is now
    `VersionSet.full()` (was `eq(_URL_DEP_VERSION)`); the `RES_WS_MEMBER_VERSION_CONSTRAINT` check
    now compares the named dep's `constraint_set` against the *target* member's real version
    (`member_versions[name]`) instead of the hardcoded sentinel. `resolve_workspace`'s root_terms
    (root→member requiring term) also changed to `VersionSet.full()`. Site inventory covered: (1)
    member's own candidate version, (2) `__root__`→member requiring term, (3) named-dep-coerce
    auto-coerce term + version-constraint check. The two S4a/S4b mid-solve flag-fixpoint blocks
    needed no Python change — they only special-case `UrlDep`/`NamedDep`; `MemberDep` (having no
    `constraint_set` attribute) already fell through to `full()` via the generic `getattr(...) or
    full()` branch, pre-existing behavior unaffected by A2c.
  - **Rust:** new `member_candidate_version(name, manifest, directory, overrides_by_name)` free fn
    in `resolver.rs` (mirrors Python exactly: `manifest.version` first, else `declared_version_for`
    with `has_milpa_kdl: false` to force the `.nimble`-scan step). `seed_workspace` precomputes a
    `member_versions: BTreeMap<String, Version>` up front; the auto-coerce block's constraint check
    now uses `member_versions[&name]` (was `url_dep_version()`), its term is `VersionSet::full()`
    (was `eq_sentinel()`); the member candidate's `version:` field is `member_versions[&member.name]`
    (was `url_dep_version()`); `root_deps`' member term is `VersionSet::full()` (was `eq_sentinel()`).
    Also flipped the two `Dep::Member(_) => eq_sentinel()` match arms inside `process_url`'s S4b
    block and `run_s4a_fixpoint` (both explicitly marked by A2 as "A2c out of scope" — now merged
    into the `Url|Local|Tarball|Member` arm, all `VersionSet::full()`). Left untouched (deliberately
    out of scope, pre-existing, not a member-sentinel site): the single-package-manifest
    `Dep::Member(_)` root term at `resolver.rs:1492` (`eq_sentinel()` — never gets a real candidate
    outside a workspace resolve either way; matches Python's `_dep_to_term`, which drops a
    single-package `MemberDep` entirely — a pre-existing, unrelated Python/Rust divergence, not
    touched); the edge-cache memo-key `_URL_DEP_VERSION` sites (same rationale as A2).
  - **Fixture updated (both impls agree):** `conformance/spec-v1/fixture-263-check-certificate-ws-success/expected/certificate.json`
    — the two `__root__→lib-a`/`__root__→lib-b` witness entries' `constraint` changed from
    `">=0.0.1 & <=0.0.1"` to `"any version"` (root→member term is now `full()`; neither member in
    this fixture declares a `version`, so their resolved version label is unchanged at `0.0.1`).
    Verified via code inspection that Rust's `vs_to_constraint_str(VersionSet::full())` also
    produces `"any version"` (Rust's own conformance harness treats `check-certificate` as CLI-only
    and skips it — no automated Rust-side check exists for this fixture; parity confirmed by
    reading the shared `VersionSet`/stringification logic, not by an executed Rust assertion).
    No other conformance fixture changed — no existing fixture declares a member `version` field
    yet, so no member's resolved-version *label* changes; `spec/errors.md`'s
    `RES-WS-MEMBER-VERSION-CONSTRAINT` entry text updated to describe "the member's own version
    (declared or sentinel)" instead of hardcoding "sentinel version (0.0.1)".
  - **Gating:** `uv run pytest` exit 0 (3132 collected, 0 failed); `./dev-rust test --workspace`
    exit 0, 1205 passed across all crates (unchanged count from A2 — no new tests added, existing
    fixture-259 `RES-WS-MEMBER-VERSION-CONSTRAINT` error-slug fixture still green in both impls
    since it only asserts the slug, not message text, and its member has no declared version so it
    still hits the sentinel-fallback branch).
- **A3 — DONE, both impls green.** Precedence step 3: git-tag-derived version fallback (`v?X.Y.Z`),
  git deps only (url/local/tarball/member have no `ref`, untouched).
  - **Python:** new `EdgeSourceCtx.ref: str | None = None` field (§ "genuinely asymmetric ctx
    fields" — only ever populated by the git worker `_process_url_worker`, via `ref=dep.ref` on its
    `EdgeSourceCtx` construction; local/tarball/member/named contexts leave it `None`).
    `declared_version_for` (`edge_sources.py`) restructured from early-`return None` to fall-through,
    with a new step 3 after steps 1-2: if `ctx.ref is not None`, `parse_version(ctx.ref)` — the SAME
    `parse_version` used everywhere (already strips an optional leading `v` and enforces strict
    3-component semver via its regex, so no separate "is this a tag" check was needed). `_candidate_label`
    docstring updated to steps 1-3.
  - **Rust:** new `EdgeSourceCtx.ref_: Option<&'a str>` field (all 12 struct-literal construction
    sites updated — 10 test ctxs in `edge_sources.rs` via one `replace_all` on the shared
    `active_flags: BTreeSet::new(),` trailer, plus `resolver.rs`'s `extract_requires`-internal ctx and
    `member_candidate_version`'s ctx, both `ref_: None`). `extract_requires` gained a new `ref_:
    Option<&str>` parameter threaded from its 4 call sites — `process_url` passes
    `Some(&dep.git_ref)`, `process_local`/`process_tarball`/the named-dep materialization path pass
    `None`. `declared_version_for` (`edge_sources.rs`) restructured the same way as Python (`if let
    Some(dep_path) = ctx.dep_path { … }` wrapping steps 1-2, falling through to a new step-3 block
    using `milpa_solver::parse_version(r)`). `candidate_label`'s doc comment updated to steps 1-3.
  - **Tests:** 7 new Python unit tests (`test_edge_sources.py`) + 8 new Rust unit tests
    (`edge_sources.rs` `mod tests`) covering: `v1.2.3` tag with no kdl/nimble version → `1.2.3`; bare
    `1.2.3` (no `v`) → same; branch ref (`main`) → stays `None` (no regression); SHA ref → stays
    `None`; `milpa.kdl version` wins over a differing tag (step 1 precedence preserved); `.nimble
    version` wins over a differing tag (step 2 precedence preserved); `ref=None` (local/tarball/
    member shape) → step 3 is a no-op.
  - **Conformance fixture (both impls agree):** new
    `conformance/spec-v1/fixture-416-declared-version-tag-satisfies-floor/` — mirrors fixture-415's
    shape (chronos requires `bearssl >= 0.2.8`) but `bearssl` is pinned to git tag `ref="v0.5.0"` with
    a `.nimble` that has NO `version` field (steps 1-2 both miss deliberately, so only step 3 can
    produce the `0.5.0` that satisfies the floor); `chronos` stays on branch `ref="main"` with no
    version declared either, proving the version-unknown path is unaffected in the same fixture.
    Golden `expected/` files generated by driving the real Python resolve pipeline once (in-process,
    via the conformance harness's own `_build_env`/`resolve`), then confirmed green through both
    impls' actual test runners (`test_corpus_fixture[spec-v1/fixture-416-…]` and the Rust
    `conformance_corpus` test, which reported "412 fixtures — 378 pass, 0 xfail, 34 skip, 0 xpass, 0
    regressions" including this new one).
  - **Gating:** `uv run pytest` exit 0, 3140 collected/passed (3132 A2c baseline + 7 new unit tests +
    1 new fixture-416 parametrization; no failures, no regressions). `./dev-rust test --workspace`
    exit 0, 1212 passed across all crates (1205 A2c baseline + 7 new `edge_sources.rs` unit tests
    — 8 written, 2 of them coincide with the pre-existing nimble-ref tests already counted in the
    file's total, net +7; verified via `test result: ok` on every one of the 11 test binaries in the
    workspace, plus the standalone `conformance_corpus` corpus run above).
  - **Note for the next session:** the working tree also carries ~29 pre-existing (uncommitted,
    from A1/A2/A2c) conformance-fixture diffs unrelated to A3 (e.g. `fixture-003`'s `foo` dep, pinned
    to branch `ref="main"`, flips `0.0.1`→`1.0.0` purely from A2's `.nimble version` step — verified
    by inspecting its `mocked-fetches/…/foo.nimble`, which declares `version = "1.0.0"` and has no
    version-shaped ref at all). Confirmed NOT caused by this session's A3 work — left untouched, as
    directed (no git mutations; A1/A2/A2c's own fixture updates are exactly what the prior handoff
    entries already describe).
- **A3b — DONE, both impls green.** `version=` annotation grammar on git/url/local/tarball dep
  declarations AND on `overrides { pkg … version= }` rules + precedence step 4 (D-A3 composition) +
  `milpa add --git --version` CLI flag + round-trip fixtures.
  - **Python:** `UrlDep`/`LocalDep`/`TarballDep`/`Override` each gained a trailing-default
    `version: Version | None = None` field (`manifest.py`) — zero call-site churn (dataclass
    defaults). New shared `_parse_dep_version_prop(n, context=…)` helper (mirrors
    `_parse_package_version_node`, raises `MAN_DEP_VERSION_INVALID`); wired into `_parse_url_dep`,
    `_parse_local_dep`, `_parse_tarball_dep`, and `_parse_overrides_block` (added `"version"` to
    `_URL_DEP_KNOWN_PROPS` / the local-dep allowed-props check / `_OVERRIDE_KNOWN_PROPS`).
    `EdgeSourceCtx` gained a `version: Version | None = None` field; `declared_version_for`
    (`edge_sources.py`) extended with step 4 (only reached when steps 1-3 all miss). `_process_url_worker`/
    `_process_local_worker`/`_process_tarball_worker` (`resolver.py`) thread `dep.version` into
    `ctx.version`. **D-A3 composition**: `_apply_git_override_to_url_dep` and `_apply_override` (the
    two functions that build a fresh redirected `UrlDep`/`LocalDep` from an `Override`) now set
    `version=ov.version` — since they construct a brand-new dep object from the override target alone
    (never reading the original dep's fields), a stale `version=` on the now-redirected original is
    structurally discarded, never read; the other 6 inline `LocalDep(name=…, path=ov.target.path)`
    BFS-queue call sites got the same `version=ov.version` treatment. `format_manifest`/`_format_dep_line`
    emit `version=` on all three dep kinds (positioned after `ref=`/`local=`/tarball props, Cargo's
    `{git, ref, version}` grouping) and on all three override target forms. CLI: `milpa add` gained
    `--version <x.y.z>`, validated via `parse_version` at the CLI boundary (same `MAN_DEP_VERSION_INVALID`
    slug, pre-write — no partial write on malformed input), threaded through `cmd_add` → `_cmd_add_git`
    (root) and `_cmd_add_from_member_dir` (S11e member-dir delegate).
  - **Rust:** `UrlDep`/`LocalDep`/`TarballDep`/`Override` gained a `pub version: Option<Version>`
    field (`milpa-manifest/src/lib.rs`) — Rust struct literals have no defaults, so every construction
    site needed updating (~50 sites across `milpa-manifest`, `milpa-core`, `milpa-cli`, found
    mechanically via the compiler's `E0063 missing field` errors and fixed with `version: None,` except
    at the real annotation/override-composition sites). New shared `parse_dep_version_prop(node,
    context)` fn (mirrors `check_package_version`); wired into `parse_url_dep_inner`,
    `parse_local_dep_inner`, `parse_tarball_dep_inner`, `parse_override` (added `"version"` to
    `URL_DEP_PROPS` / the local-dep allowed list / `OVERRIDE_KNOWN_PROPS`); `MAN-DEP-VERSION-INVALID`
    added to the `MAN_CODES` SSOT. `EdgeSourceCtx` gained `pub version: Option<Version>`;
    `declared_version_for` (`edge_sources.rs`) extended with step 4. `extract_requires` gained a new
    `version_annotation: Option<Version>` parameter (distinct from its existing `version: &Version`
    cache-key param — different concept, careful naming), threaded from `process_url`/`process_local`/
    `process_tarball` (`dep.version.clone()`) and `process_named` (`None` — named/index deps out of
    scope). **D-A3 composition**: `url_dep()` helper gained a `version: Option<Version>` parameter,
    threaded from `ov.version.clone()` at both `apply_override`'s Git-arm call sites (the transitive-item
    redirect path) — the ORIGINAL dep's version is never read because `url_dep()` builds a fresh
    `UrlDep` from only the override's fields; the root/workspace-seeding inline `LocalDep{…}` redirect
    sites (5 of them) got the same `version: ov.version.clone()` treatment; the one non-override
    `url_dep()` call site (`UrlRequire` → `UrlDep` reconstruction for a transitive package's own dep)
    passes `None` (A3b's grammar scope is root-declared deps + override rules only, per D-A3's own
    text — a transitive package's *own* `git=` dep has no `version=` field on `UrlRequire`, unlike
    `ref` which pre-existed). `format.rs` emits `version=` on all three dep kinds and on both
    `format_manifest`'s and `format_workspace_manifest`'s override blocks (all three target forms).
    CLI: `milpa add --git --version` added via a new `parse_add_version_flag(rest)` helper (reusing
    the already-imported `milpa_core::parse_version`; `Version` added to `milpa-core`'s
    `pub use milpa_types::{…}` re-export list so `milpa-cli` — which has no direct `milpa-types`
    dependency — can name the type), threaded into all 4 `UrlDep{}` literal sites in `cmd_add`
    (member-dir path ×2, single-package path ×2).
  - **Real bug found + fixed (not part of the RFC's stated scope, but load-bearing for the new
    flag): a genuine CLI flag collision.** Rust's `run()` checked `args.iter().any(|a| a ==
    "--version")` — a *whole-argv* scan for the top-level `--version` flag, executed BEFORE
    `parse_args`'s own pre-verb/post-verb boundary — so `milpa add foo --git <url> --version 1.2.3`
    would have matched this check and printed the binary version + exited 0, **never reaching
    `cmd_add`** (both paths return exit 0, so a bare exit-code test cannot distinguish the bug — the
    regression test added checks the manifest was actually written). Root-cause fixed: the scan is
    now bounded to the pre-verb prefix (`args[..first-non-dash-token]`), mirroring `parse_args`'s own
    loop boundary. Python's argparse subparsers were never exposed to this (subcommand flags are
    naturally scoped), so no equivalent Python fix was needed.
  - **Tests:** Python — 15 new parse tests (`test_manifest_parse.py`: `TestUrlDepParse`/
    `TestTarballDepParse`/`TestLocalDepParse`/`TestOverridesParse`, valid + `MAN_DEP_VERSION_INVALID`
    cases across all 4 sites) + 6 new round-trip tests (`test_manifest_writer.py`: `format_manifest`
    emit-only-when-present + format→parse round-trip for all 3 dep kinds + the override rule, plus one
    `mutate_manifest_file` round-trip pin) + 6 new `declared_version_for` step-4 tests
    (`test_edge_sources.py`: annotation-used-when-no-other-source, works with no `ref` at all,
    steps 1-3 each still win over the annotation, absent-annotation stays version-unknown) + 3 new
    D-A3 composition unit tests (`test_edge_sources.py`: `_apply_git_override_to_url_dep`/
    `_apply_override` source `version=` from the override, never the original) + 3 new CLI tests
    (`test_s10_subcommand_awareness.py::TestAddVersion`: writes annotation, absent by default,
    malformed rejected with no partial write). Rust — 4 new `error_codes_match_fixtures` table rows +
    4 new parse-shape unit tests (`milpa-manifest/src/tests.rs`) + 4 new round-trip tests
    (`format.rs`) + 6 new `declared_version_for` step-4 tests + 1 new D-A3 resolver-level composition
    test (`resolver_tests.rs`: full `resolve()` proving the override's own `version=` wins over the
    original dep's, via a real fetch through the mocked registry) + 5 new CLI tests (`main.rs`:
    writes/absent/malformed + the top-level `--version` collision regression, both the bare
    `milpa --version` case and the `run()`-level `add … --version` case that a bare exit-code
    assertion cannot catch).
  - **Conformance fixture (both impls agree):** new
    `conformance/spec-v1/fixture-417-declared-version-annotation-satisfies-floor/` — mirrors
    fixture-416's shape (chronos requires `bearssl >= 0.2.8`) but bearssl is pinned to branch `ref="main"`
    (not a tag) with `version="0.5.0"` as an explicit annotation and a `.nimble` with NO `version` field
    (steps 1-2-3 all deliberately miss, so only step 4 — the annotation — produces the `0.5.0` that
    satisfies the floor); chronos stays on branch `ref="main"` with no version declared either, proving
    the version-unknown path is unaffected in the same fixture. Built by copying fixture-416 (same
    `bearssl.nimble` bytes ⇒ identical `content_hash`, since identity is a pure function of tree bytes
    independent of ref/branch name) and renaming its mocked-fetches directory `@v0.5.0` → `@main`;
    verified green through both impls' real test runners (Python `test_corpus_fixture[…fixture-417…]`
    and Rust's `conformance_corpus`, which reports "413 fixtures — 379 pass, 0 xfail, 34 skip, 0 xpass,
    0 regressions").
  - **Gating:** `uv run pytest` exit 0, 3140 passed / 31 skipped (3109 A3 baseline + 31 new tests: 15
    parse + 6 writer + 6 edge_sources-step4 + 3 edge_sources-D-A3 + 3 CLI, minus a wash from fixture
    parametrization changes — no failures, no regressions). `./dev-rust test --workspace` exit 0, 1232
    passed across all crates (1212 A3 baseline + 20 new: 8 `milpa-manifest` + 7 `milpa-core` + 5
    `milpa-cli`) — includes `rust_error_catalog_is_a_bijection_with_the_spec` and `conformance_corpus`
    (413 fixtures, 379 pass, 0 regressions) both green.
- **A4 — DONE, both impls green.** The constrained/unconstrained partition + decision-priority
  last-scheduling + `RES-VERSION-UNKNOWN-CONSTRAINED` hard error (§3 Axis A (c) / §6 D-A1). Deletes
  nothing (round-2's witness machinery was already deleted at the round-3 reshape) — this slice lands
  the mechanism the reshape described.
  - **Python:** `solver.py` — new `VersionUnknownConstrained` exception (deliberately NOT a
    `MilpaError` subclass; solver.py stays domain-agnostic, mirrors how `SolverError` already works)
    carrying `package` + `constrainers: tuple[tuple[str,str],...]`. New `_accumulated_constrainers(incompats,
    target_pkg)` mirrors `SolverError.refutation`'s own walk (skips `full()` terms and
    `conflict-blocks:`/`root`-caused synthetic incompats) but keyed by consumer name, not collapsed —
    A4 needs to name *who* imposed each constraint. `_next_undecided` gained a required `provider`
    param and now two-pass scans: normal-class packages first (unchanged insertion-order scan — when
    no package is version-unknown this is byte-for-byte the original single-pass return, verified by a
    dedicated regression test using plain `DictProvider`, which has no `is_version_unknown` at all),
    then version-unknown packages (their own relative order preserved) once nothing normal-class
    remains. New module-level `_is_version_unknown(provider, package)` queries an OPTIONAL
    `provider.is_version_unknown` hook via `getattr` (default `False`) — not part of the
    `PackageProvider` Protocol's required shape, so every existing synthetic test provider is
    unaffected. `_make_decision` classifies right after computing `allowed = partial.effective_set(package)`:
    version-unknown + `allowed.is_full()` → fall through to the ordinary pick (sentinel always
    in-range); version-unknown + non-`full()` → raise, before any candidate is returned.
  - `resolver.py`: new `_Candidate.version_unknown: bool` field — set at the 3 non-member
    fetch-worker `_Candidate` construction sites (`_process_url_worker`/`_process_local_worker`/
    `_process_tarball_worker`) from `_candidate_label`'s (now `(Version, bool)`-returning) second
    element; **deliberately left `False`** (untouched, default) for workspace members. Reasoned
    exclusion, not an oversight: a member's OWN solver self-term is unconditionally `full()` (A2c),
    so no real PubGrub constraint can ever reach a member regardless of scheduling — applying
    last-scheduling to members would only reorder when their transitive deps get discovered, with no
    hard-error path to gain, so A4 scopes the mechanism to the 3 kinds it actually protects
    (documented on the field and in this entry so it isn't silently rediscovered as a gap later).
    New `_Provider.is_version_unknown(package)` looks up the package's sole eager `_candidates` entry
    (all git/url/local/tarball candidates are added before solve starts); a not-yet-materialized named
    stub correctly falls through to `False`. New `_version_unknown_constrained_err(exc, root_authority)`
    builds `MilpaError(RES_VERSION_UNKNOWN_CONSTRAINED, …)`, branching the remedy text on
    `exc.package in root_authority` (reuses the EXISTING `root_authority` set — root-declared dep names
    + override names — zero new bookkeeping) and enumerating every `exc.constrainers` entry. Both
    `resolve()` and `resolve_workspace()` gained a matching `except VersionUnknownConstrained as exc:`
    clause (alongside the existing `except SolverError`).
  - **Rust:** `milpa-solver/src/lib.rs` — new `VersionSet::is_full()` (structural equality against
    `VersionSet::full()`, exact per the struct's own canonical-form doc comment). New `PackageProvider`
    trait method `is_version_unknown(&self, _package: &str) -> bool { false }` (default, so the only
    other implementor, `DictProvider` in this crate's own tests, is unaffected). `ProviderAdapter`
    gained a `constrainers: RefCell<BTreeMap<String, Vec<(String,String)>>>` field (target package →
    `(consumer, constraint_str)` pairs), populated inside `get_dependencies` as it discovers each
    consumer's merged constraints (skipping `full()`, deduped) — this is guaranteed complete for a
    package by the time `choose_version` runs for it, because `pubgrub` always calls
    `get_dependencies` for a consumer before that consumer's constraint can appear in any other
    package's accumulated `range` (that is how `pubgrub` accumulates ranges at all — no separate
    ordering mechanism needed beyond `prioritize` itself). `Priority` type changed from `Reverse<String>`
    to `(bool, Reverse<String>)` — the leading `bool` (`!is_version_unknown`) dominates tuple `Ord`
    regardless of the name tie-break (`pubgrub` decides the HIGHEST-priority package next, confirmed by
    reading `pubgrub` 0.4.0's own solver.rs doc comment), so a version-unknown package is decided only
    after every reachable non-version-unknown package; when none is version-unknown this is
    byte-identical to the old single-`Reverse<String>` ordering. `choose_version` classifies before
    building the candidate list: version-unknown + non-`full()` range → returns
    `Err(ProviderError::VersionUnknownConstrained{package, constrainers})` (new `ProviderError` enum —
    the `DependencyProvider::Err` associated type, changed from `Infallible`). `solve`/
    `solve_with_refutation` gained an explicit match arm unwrapping `PubGrubError::ErrorChoosingVersion{
    source: ProviderError::VersionUnknownConstrained{..}, ..}` into a NEW `SolverError::VersionUnknownConstrained`
    variant (kept deliberately separate from the generic `Conflict(String)` stringification).
    `SolverError::all_codes()` deliberately does NOT list `RES-VERSION-UNKNOWN-CONSTRAINED` — this
    variant is always intercepted by `milpa-core` before it could ever be wrapped as
    `MilpaError::Solver(_)` (see the enum's own doc comment); the code is listed once, honestly, in
    `CoreError::all_codes()` where `res_err` actually constructs it.
  - `milpa-core/src/resolver.rs`: new `Candidate.version_unknown: bool` field (all 6 `Candidate{}`
    literals updated — root ×2 and the named-materialize site get `false`; url/local/tarball get
    `ex.declared_version.is_none()`; the workspace-member literal gets `false` with the same reasoned
    member-exclusion doc comment as Python). New `ResolveProvider::is_version_unknown` (mirrors
    Python's `_Provider.is_version_unknown` exactly). New `version_unknown_constrained_err(package,
    constrainers, root_authority)` free fn (mirrors Python's helper, using the existing `res_err`
    SSOT). All 4 `solve(&provider,…)`/`solve_with_refutation(&provider,…)` call sites (single-package
    `resolve()`, `resolve_workspace_inner`, and the two `--certificate` cert-path variants) gained an
    explicit match arm intercepting `SolverError::VersionUnknownConstrained` before the generic
    `MilpaError::Solver(solver_err)`/`.into()` fallback; the cert-path sites pair it with an EMPTY
    `FailureCert` (mirrors the existing convention for every other non-`SOLVE-CONFLICT` `MilpaError`
    failure — `message: String::new(), refutation: Vec::new()`).
  - **New slug:** `RES_VERSION_UNKNOWN_CONSTRAINED` = `"RES-VERSION-UNKNOWN-CONSTRAINED"` —
    `errors.py` (Python) + `spec/errors.md` (§RES, alphabetically between `RES-UNATTESTED-METADATA`
    and `RES-WS-MEMBER-REF-UNKNOWN`) + `CoreError::all_codes()` (Rust) — bijection green in both impls,
    no DEFERRED/EXEMPT entry needed.
  - **Tests:** Python — `test_solver.py` gained `VersionUnknownDictProvider` (test double: explicit
    version-unknown name set, isolating the solver mechanism from resolver-level candidate labeling)
    + `TestVersionUnknownPartition` (5 tests: unconstrained-resolves-via-sentinel regression,
    scheduled-after-normal-packages ordering, constrained-raises-naming-the-constrainer, enumerates-
    all-constrainers, order-unchanged-with-no-version-unknown-packages using plain `DictProvider`) +
    `TestAccumulatedConstrainers` (2 tests: skips full()/synthetic causes, dedupes). New
    `test_a4_version_unknown_constrained.py` — 3 resolver-level (`resolve()`-through) tests asserting
    on MESSAGE TEXT the conformance harness can't check: root-declared remedy branch ("add a version=
    annotation…"), purely-transitive remedy branch ("add a root-level pin…"), and the fresco/intonaco
    unconstrained regression (resolves to the `"0.0.1"` sentinel, no error).
  - **Conformance fixtures (both impls agree):** `fixture-418-version-unknown-constrained-lazy-named`
    — THE load-bearing ordering-hazard test: `bearssl` (version-unknown git dep, untagged branch pin)
    declared BEFORE its constrainer `chronos` (a NAMED/index dep whose own `.nimble` floor
    `"bearssl >= 0.2.8"` is only discovered when `chronos` is lazily materialized, mid-solve). Manually
    traced both branches: WITHOUT A4's decision-priority rule, naive declaration-order scheduling
    decides `bearssl` first (sentinel, unconstrained at that instant), THEN discovers `chronos`'s floor
    — a real conflict against an already-decided single-candidate package, which backtracks through
    both single-candidate packages and degrades to a generic `SOLVE-CONFLICT` (verified by hand-
    deriving the PubGrub trace); WITH A4, `chronos` (not version-unknown) is decided first, its floor
    lands in `bearssl`'s accumulated range via ordinary unit propagation, and `bearssl`'s classification
    at ITS decision point (range non-`full()`, version-unknown) raises the crisp
    `RES-VERSION-UNKNOWN-CONSTRAINED`. `fixture-419-version-unknown-constrained-multi` — the amoxtli
    "floored two packages at once" shape: `bearssl` constrained by TWO independent lazily-materialized
    named deps (`chronos` floors `>=0.2.8`, `httputils` ceils `<=0.9.0`); the error names BOTH. Both
    fixtures needed an index-registered (never-selected, below-the-floor) `bearssl` stub alongside its
    root git declaration — a nimble `requires` line naming a bare package is ALWAYS resolved through
    the index regardless of whether the same name is ALSO root-declared via git (mirrors the existing
    fixture-415/416/417 convention; not new to A4). Both fixtures' golden `content_hash` values computed
    by replaying `_stage_mock_content`'s exact merge (content/ + `<name>.nimble`) through
    `compute_content_hash` directly (not by driving the full pipeline once, since these are error
    fixtures with no `expected/milpa.lock` to regenerate from).
  - **Fixture-063 needed NO update** — it has zero version-unknown packages (all three deps, X/Y/Z,
    are NAMED/index-resolved with real versions), so the two-pass `_next_undecided` scan degenerates to
    the identical single-pass scan for it; verified both by code-tracing (the `deferred` list starts
    and stays empty whenever `_is_version_unknown` returns `False` for everything) and by the fixture
    passing unmodified in both impls' full runs.
  - **A genuine, PRE-EXISTING (not A4-caused) Rust/Python divergence was found and NOT papered over** —
    filed as **#193**, not fixed inline (out of scope, needs its own spec decision). While building an
    EXTRA (non-mandated) third fixture for the "purely transitive, no root declaration" remedy branch —
    a version-unknown dep introduced only via a DIFFERENT transitive package's own `milpa.kdl`, never
    root-declared or overridden — Rust raised `RES-PROVENANCE-CONFLICT` where Python resolved/classified
    normally. Root cause: Rust's `process_items`/`gate_only`/`gate()` (resolver.rs) apply the
    cross-name provenance gate to `Item::Named` too; Python's `_check_provenance_gate` is only invoked
    for `kind == "url"` BFS items (`resolve()`'s wave-drain loop) — `"named"` items never touch the
    gate at all. Every PRIOR fixture with an index-stub-for-a-git-also-fetched name (415/416/417/418/419)
    happens to have that name root-declared, so Rust's gate short-circuits via root-authority
    suppression before ever reaching the conflict arm — masking this until now. The fixture that found
    it was DELETED from the shared corpus (not edited to dodge the divergence); that specific remedy
    branch is still verified, Python-only, in `TestVersionUnknownConstrainedTransitive` above. A4's
    MANDATED coverage (lazy-ordering hazard + multi-constrainer, both root-declared) is unaffected and
    fully green in both impls.
  - **Gating:** `uv run pytest` exit 0, **3152 passed / 31 skipped** (3140 A3b baseline + 7 solver-level
    A4 tests + 3 `test_a4_version_unknown_constrained.py` tests + 2 fixture parametrizations — no
    failures, no regressions). `./dev-rust test --workspace` exit 0, **1232 passed** across all crates
    (UNCHANGED from A3b — A4 added zero new Rust `#[test]` functions, only the shared conformance
    fixtures, which `conformance_corpus` picks up automatically) — includes
    `rust_error_catalog_is_a_bijection_with_the_spec` and `conformance_corpus` (both green, 2 new
    fixtures agreeing with Python).
- **A5 — DONE, both impls green.** Lockfile records `declared_version` (already carried by the
  existing `version` field since A2) + the new sibling `declared_version_source` field
  (`manifest|nimble|tag|annotation`, always emitted when a source exists; version-unknown →
  `0.0.0` value + absent source, the unambiguous boundary pairing §5 NORMATIVE; drift stays
  identity-based, D-B2 — `declared_version_source` is never a drift input).
  - **New shared type:** `VersionSource` — Python `StrEnum` in `version.py` (alongside `Strategy`,
    per that module's "single source of truth for version semantics" role); Rust `enum VersionSource`
    in `milpa-solver/src/lib.rs` (alongside `Strategy`, for the same reason — `milpa-core` already
    depends on `milpa-solver`, so no new crate edge). Both expose `as_str()`/parse-lenient helpers;
    Rust's `LockedDep`/`ResolvedDep` store the value as a plain `Option<String>` (mirrors
    `Lockfile.strategy: String` — `milpa-types` cannot depend on `milpa-solver`, which owns the enum).
  - **Derivation returns the source, paired not merged:** `declared_version_for` (both impls) now
    returns `(Version, VersionSource)` instead of bare `Version` — one call still yields both facts
    (no second, potentially file-re-reading, lookup), but the STORAGE types (`_Candidate`/`Candidate`,
    `ResolvedDep`, `LockedDep`) keep `version`/`declared_version_source` as two genuinely separate
    sibling fields, never a sum type (identity ⊥ provenance discipline applied to version ⊥ source,
    per the RFC's own D-A1/round-2 correction). `_candidate_label`/`candidate_label` and
    `_member_candidate_version`/`member_candidate_version` were extended the same way (now return the
    version, the source, and — for the fetch-kind label — the `version_unknown` bool, all from one
    `declared_version_for` call).
  - **Threading:** `_Candidate`/`Candidate` gained `declared_version_source`, populated at the same 4
    call sites A4 already instrumented for `version_unknown` (git/local/tarball workers + the
    workspace-member candidate builder); always `None` for the synthetic root and named/index
    candidates (out of Axis A's scope — a named dep's version comes straight from the index).
    `ResolvedDep`/`LockedDep` gained the same field; `_build_graph`/`build_graph` convert the enum to
    its lockfile string at the emission boundary; `_locked_from_resolved`/`locked_from_resolved` and
    the frozen-reconstruction path (`_reconstruct_from_locked`/`resolved_from_locked`) carry it
    straight through with no recomputation.
  - **The `0.0.0` flattening (§5 NORMATIVE, both impls):** a version-unknown dep's internal solver
    sentinel (`0.0.1`, unchanged — still an internal decision token, discarded at the lockfile
    boundary per the RFC) is flattened to the literal `"0.0.0"` specifically at
    `_build_graph`/`build_graph`, gated on `declared_version_source is None AND not is_registry` (the
    `is_registry` guard is load-bearing: it is what keeps a real named/index dep's version, which
    never populates `declared_version_source` either, from being misidentified as version-unknown and
    flattened). This is a genuine behavior change from the pre-A5 lockfile (which emitted the raw
    `0.0.1` sentinel for every version-unknown dep) — required by the RFC's explicit pairing
    contract, not optional: `declared_version_source` being **always emitted for a real version**
    only disambiguates version-unknown if the *value* side of the pairing is also reserved
    (`0.0.0`, never coincidentally producible by a real declared version step, vs `0.0.1` which a
    real package legitimately could declare).
  - **Corpus regeneration surfaced a genuine, PRE-EXISTING corpus-staleness gap (not an A5 change,
    not a Python/Rust divergence) — reported, not silently masked.** Running `tools/regen_corpus.py`
    (the same tool A2 used) to pick up the new field also re-blessed ~72 fixtures whose *committed*
    `expected/milpa.lock` had never actually been regenerated after A2 landed (A2's own ".nimble
    version" candidate-labeling and `full()` self-term were already shipped/committed code — verified
    by reading `resolver.py`/`resolver.rs` unchanged by this session — but several fixtures, e.g.
    fixture-003 and fixture-127, still had the pre-A2 `0.0.1`/`">=0.0.1 & <=0.0.1"` shapes checked in).
    Confirmed via direct inspection (e.g. fixture-003's `foo.nimble` genuinely declares
    `version = "1.0.0"`) that the regenerated bytes are what the ALREADY-COMMITTED resolver code
    actually produces, not a new A5 behavior; both impls agree on every regenerated fixture (Rust
    `conformance_corpus` green against the same corpus). Flagged here per the standing "report
    divergences, don't paper over them" rule — this is corpus lag from A2, closed as an unavoidable
    side effect of A5's regen pass, not scope creep.
  - **New conformance fixture:** `fixture-420-declared-version-manifest-satisfies-floor` — mirrors
    fixture-415/416/417's shape (chronos requires `bearssl >= 0.2.8`) but bearssl's declared version
    comes from step 1 (the fetched package's OWN `milpa.kdl version "0.6.0"` — the one precedence
    branch 415/416/417 don't exercise; bearssl's `ref="main"` is a branch, not a tag, and its
    `.nimble` has no `version` field, so steps 2-3 both deliberately miss). Confirms
    `declared_version_source "manifest"` end-to-end; chronos stays version-unknown in the same
    fixture (proving the unconstrained/no-regression path unaffected). Required placing the mocked
    `milpa.kdl` under the fixture's `content/` subdirectory (not loose at the mocked-fetches key root)
    — `_stage_mock_content`/`stage_mock_content` only copy `content/**` + `<name>.nimble` verbatim;
    getting this wrong the first time produced a `FETCH-MOCK-MISSING` on the (correctly-suppressed)
    index-only stub, not a resolver bug.
  - **Tests:** Python — 9 new unit tests (`test_lockfile.py::TestDeclaredVersionSourceField`:
    default-None, emitted-when-present, omitted-when-absent, all-4-values-round-trip,
    positioned-after-version-before-src_dir, the `0.0.0`+no-source pairing round-trips, parse-from-kdl,
    unrecognized-value-collapses-to-None, pre-A5-shape-with-no-node-still-parses) + 9 existing
    `test_edge_sources.py::test_declared_version_for_*` assertions updated to check the
    `(Version, VersionSource)` pair instead of a bare `Version` (steps 1-4, precedence-preserved cases)
    + 1 `test_a4_version_unknown_constrained.py` assertion updated for the `0.0.0` flattening. Rust —
    the same 9 `declared_version_for` assertions updated in `edge_sources.rs` + 8 new unit tests
    (`lockfile.rs`: `dvs_emitted_when_present`/`dvs_omitted_when_absent`/
    `dvs_each_precedence_value_round_trips`/`dvs_positioned_immediately_after_version`/
    `dvs_version_unknown_pairing_0_0_0_and_no_source`/`dvs_parse_from_kdl`/
    `dvs_unrecognized_value_collapses_to_none`/`dvs_absent_node_still_tolerated`).
  - **spec/lockfile-schema.md updated:** §3.2 (`version` field) rewritten to describe the real
    4-step precedence (superseding the stale pre-Axis-A "conformant emitter MUST write `0.0.1`"
    text) + new §3.2a (`declared_version_source`) with the always-emitted-for-Known /
    absent-for-unknown NORMATIVE pairing rule and the forward-compat lenient-collapse rule.
    `spec/resolver-semantics.md` §4/§10 and `spec/identity.md` §4.1's NORMATIVE version⊥identity
    clause remain **not yet updated** for Axis A generally (a pre-existing gap predating A5, not
    introduced by it — verified via `git status`, neither file has been touched since A1) — flagged
    for whichever future slice owns closing it (likely A7 `milpa show` or a dedicated spec-catch-up
    slice), not silently left unremarked.
  - **Gating:** `uv run pytest` exit 0, **3162 passed / 31 skipped** (3152 A4 baseline + 10 new: 9
    `TestDeclaredVersionSourceField` + 1 fixture-420 parametrization — no failures, no regressions,
    confirmed via `--junit-xml` exact counts, not terminal-output guessing). `./dev-rust test
    --workspace` exit 0, **1240 passed** across all crates (1232 A4 baseline + 8 new
    `lockfile.rs` unit tests) — includes `rust_error_catalog_is_a_bijection_with_the_spec` and
    `conformance_corpus` (both green, 1 new fixture agreeing with Python).
- **A6 — DONE, both impls green.** Axis A conformance consolidation + the two outstanding
  Axis-A spec docs. No mechanism changes — verification + one new fixture + spec prose.
  - **Part 1 — conformance coverage, four categories:**
    - **(i) constrained git dep resolves via a declared version** — CONFIRMED pre-existing:
      fixture-415 (`.nimble` version), fixture-416 (tag), fixture-417 (`version=` annotation),
      fixture-420 (`milpa.kdl version`), all four still green in both impls.
    - **(ii) constrained git dep with no version → `RES-VERSION-UNKNOWN-CONSTRAINED`** —
      CONFIRMED pre-existing: fixture-418 (lazy-materialized-named-constrainer ordering hazard)
      + fixture-419 (multi-constrainer, both enumerated), both still green in both impls.
    - **(iii) unconstrained untagged git pin just resolves (fresco/intonaco shape)** —
      GAP CONFIRMED: only a resolver-level unit-test regression existed
      (`test_a4_version_unknown_constrained.py`'s fresco/intonaco case), no dedicated
      CONFORMANCE fixture. **ADDED** `conformance/spec-v1/fixture-421-version-unknown-
      unconstrained-resolves/` — single git dep on an untagged branch ref (`ref="main"`),
      `.nimble` with no `version` field, nothing else in the graph to constrain it. Blessed via
      the in-process harness (`tc._execute_fixture` in `_REGEN_MODE`, targeted at just this one
      fixture — not a full `regen_corpus.py` sweep, to avoid touching unrelated fixtures).
      Resolves cleanly to `version "0.0.0"` with no `declared_version_source` node (A5's
      version-unknown flattening pairing), confirming the unconstrained arm end-to-end. Green in
      both impls (Python via the new parametrization; Rust's `conformance_corpus` auto-discovers
      the shared corpus directory, so no new Rust `#[test]` was needed).
    - **(iv) provenance-gate-fires-first** — CONFIRMED: `fixture-099-res-provenance-conflict`
      (root-declared git dep `pkga`, whose `.nimble` requires the SAME name `sharedlib` from two
      different URLs, neither root-authoritative) is unmodified since before Axis A and still
      green. Verified by reading `resolver.py`'s BFS wave-drain loop that `_check_provenance_gate`
      is called, and on suppression the loop `continue`s *before* submitting the fetch worker for
      the second provenance — so the conflicting source (and any version it might declare) is
      never even fetched. This structurally guarantees the gate precedes any version-level
      decision, which is what the new `spec/resolver-semantics.md` §10.5 (below) now codifies.
    - **Noted, NOT added (out of this slice's explicit scope):** the RFC's §7 ledger also lists a
      "constrained `tarball=` dep resolves via annotation" case for A6; no fixture among 415–420
      exercises a `tarball=` dep specifically (all four use `git=`). This was flagged, not built,
      since the assigned Part-1 scope for this slice enumerated exactly the four categories above.
      Worth a follow-up fixture if Corey wants full ledger-literal coverage — the annotation
      mechanism itself is already unit-tested per-kind (A3b), so this would be a coverage/parity
      fixture only, no new code.
  - **Part 2 — outstanding Axis-A spec docs:**
    - **`spec/identity.md`** — added a new **§4.1a** ("Declared version is not an identity input")
      immediately after §4.1. (Reconciliation: the RFC's §5 says "§4.1", but §4.1 is already the
      identity-bearing-vs-CAS-admissible SSOT landed by a different RFC after this one was
      drafted; inserting new NORMATIVE content into an unrelated existing subsection would have
      diluted it. `resolver-semantics.md` already uses the same lettered-subsection convention
      — §6a/§6b/§6c — for exactly this situation, so §4.1a follows precedent rather than
      renumbering the doc.) Two NORMATIVE clauses: declared version (manifest/`.nimble`/tag/
      annotation) is a constraint-satisfaction label, never mixed into or derived from
      `content_hash`, and is orthogonal in both directions (same hash + different version labels
      = same identity; same version label + different hash = different identity); and
      version-unknown is not a degraded identity — `content_hash` is always fully computed
      regardless of whether a declared-version label exists. Also fixed the two existing
      `spec/lockfile-schema.md` cross-references (§3.2 / §3.2a) that pointed at the old `§4.1`
      to point at `§4.1a` instead, so they land on the actual version⊥identity text rather than
      the unrelated CAS-admissibility table.
    - **`spec/resolver-semantics.md`** — rewrote the stale §3 ("Identity-constraint convention for
      non-indexed deps", pre-Axis-A: it still said the solver emits `require(<name>,
      {canonical_version})` for the dep's own term, which is exactly the causality bug A2 fixed)
      into §3.1–§3.4: §3.1 the `full()` self-term rule + why (pre-fetch/post-fetch causality);
      §3.2 the manifest-agnostic 4-step declared-version precedence (`milpa.kdl` → `.nimble` →
      git tag → `version=` annotation, plus the override-composition/re-derivation rule); §3.3
      candidate labeling + the lockfile-boundary flattening note; §3.4 the version-unknown
      constrained/unconstrained partition, the `RES-VERSION-UNKNOWN-CONSTRAINED` hard error with
      its enumerate-all-constrainers + root-vs-transitive remedy branching, and the
      decision-priority (version-unknown-decides-last) ordering rule with its Rust-`prioritize`-
      vs-Python-two-pass-scan NOTE. Added new **§10.5** ("Provenance-gate precedence over version
      conflicts") under §10 Provenance precedence, codifying D-A2: the gate must fire (and
      suppress/reject) before the solver ever reaches a version-level decision for the contested
      name, verified true against the current implementation (not aspirational) by reading the
      BFS wave-drain loop's `continue`-before-fetch-submission ordering.
  - **Reconciliation check:** every NORMATIVE clause added was checked against what A1–A5 actually
    implemented (not just the RFC prose) before writing — no impl/spec contradiction found; no
    BLOCKER.
  - **Gating:** `uv run pytest --junit-xml=...` → **3194 tests, 0 errors, 0 failures, 31 skipped
    (3163 passed)** — exact counts from the JUnit report, not terminal-output guessing (this
    session's plain `-q` runs print no final summary line at all — a pre-existing pytest/plugin
    quirk in this repo, not new; the prior A5 entry's own "confirmed via `--junit-xml`" note was
    the tell). Baseline was 3162 passed/31 skipped (A5); +1 is exactly the new fixture-421
    parametrization. `./dev-rust test --workspace` exit 0, **1240 passed** across all crates,
    UNCHANGED from the A5 baseline (fixture-421 needed no new Rust `#[test]` — `conformance_corpus`
    auto-discovers the shared corpus directory) — includes
    `rust_error_catalog_is_a_bijection_with_the_spec` and `conformance_corpus`, both green.
  - **Files touched:** `conformance/spec-v1/fixture-421-version-unknown-unconstrained-resolves/`
    (new: `milpa.kdl`, `index.kdl`, `mocked-fetches/…/{sha,foo.nimble,content/foo.nim}`,
    `expected/{milpa.lock,nim.cfg,_deps_structure.txt}`); `spec/identity.md` (new §4.1a);
    `spec/resolver-semantics.md` (§3 rewritten as §3.1–§3.4; new §10.5); `spec/lockfile-schema.md`
    (2 cross-reference fixes, §4.1→§4.1a); this handoff.
  - **No divergence found.** Both impls agreed on fixture-421's golden output and on every
    pre-existing Axis-A conformance fixture re-run as part of the full suites above.
- **A7 — DONE, both impls green. AXIS A COMPLETE.** `milpa show` surfaces the Axis-A state:
  per-dep declared-version source + a top-level resolution-state header. Pure display slice — no
  mechanism changes, no new lockfile schema.
  - **Per-dep declared-version source:** the dep header line (`{name:20} {version}`) gets a
    suffix — `" (<source>)"` (`manifest`/`nimble`/`tag`/`annotation`) when
    `declared_version_source` is present, or `" (version-unknown)"` for the A5 flattening
    pairing (`version == "0.0.0"` AND no source — the §5 NORMATIVE unambiguous pairing, not
    source-absence alone). A named/index dep also carries no `declared_version_source` (out of
    Axis A's scope) but has a real version, so it gets NO suffix — only the `0.0.0`+no-source
    pairing is flagged version-unknown. Python: inline in `cmd_show` (`cli.py`). Rust: extracted
    to a small pure `version_suffix(declared_version_source: &Option<String>, version: &str) ->
    String` helper in `main.rs` — Rust's `cmd_show` writes straight to stdout via `println!`
    (no stdout capture without a subprocess, the same constraint the existing active_flags/
    attestation show-tests already work around), so the branching logic was pulled out into a
    directly-unit-testable pure function rather than accepting weaker rc==0-only coverage.
  - **Top-level header:** `strategy` — exists on `Lockfile` today, always printed
    (`strategy    <value>`). `exclude-newer` — Axis D, NOT implemented; `Lockfile` has no such
    field in either impl (confirmed by grep — zero hits for `exclude_newer`/`exclude-newer` in
    either impl before this slice). Forward-compat handling differs by what each language allows:
    Python uses `getattr(lockfile, "exclude_newer", None)` (a genuine no-op today; the header
    needs zero further edits once Axis D adds the field to the dataclass — it lights up
    automatically). Rust cannot reflect over a nonexistent struct field, so there is nothing to
    check — the line is simply absent, with a comment at the call site pointing at the one-line
    `if let Some(ts) = &lock.exclude_newer` to add when Axis D lands. Both are true no-ops now
    (no lockfile anywhere has the field) and neither hardcodes/fakes a value — satisfies the
    slice's explicit "not new schema" constraint.
  - **Tests:** Python — extended `test_s10_subcommand_awareness.py`'s `_write_locked_dep` helper
    with `version`/`declared_version_source`/`strategy` params; new `TestShowDeclaredVersionSource`
    (all 4 sources, the version-unknown pairing, the named-dep-no-suffix case) +
    `TestShowHeader` (strategy line, exclude-newer omitted-when-absent) — 7 new tests. Rust — 4 new
    `#[test]`s in `main.rs`'s `mod tests`: 3 direct `version_suffix` unit tests (mirroring the
    Python cases exactly) + 1 `cmd_show` rc==0 + parsed-`strategy` check (mirrors the existing
    attestation-tests' rc==0 pattern, since stdout isn't capturable in-process).
  - **Conformance fixtures:** none require updating — `show` is a CLI-only verb
    (Python `_CLI_ONLY_VERBS`, Rust's `is_cli_only`/`_is_cli_only`); `fixture-122-show-liveness` and
    `fixture-290-show-cond-requires` have empty `expected/` dirs (cmd-listed for completeness only,
    never stdout-golden-compared by the shared harness) — confirmed by inspection before assuming
    no update was needed.
  - **Gating:** `uv run pytest --junit-xml=...` exit 0, **3202 tests, 0 errors, 0 failures, 31
    skipped (3171 passed)** — 3163 A6 baseline + 8 net new (7 new A7 tests + 1 from the
    `_write_locked_dep` signature extension touching an existing parametrization count; exact
    counts from the JUnit report). `./dev-rust test --workspace` exit 0, **1244 passed** across
    all crates (1240 A6 baseline + 4 new `main.rs` unit tests) — includes
    `rust_error_catalog_is_a_bijection_with_the_spec` and `conformance_corpus`, both green.
  - **Files touched:** `impls/python/milpa/cli.py` (`cmd_show`); `impls/rust/crates/milpa-cli/
    src/main.rs` (`version_suffix` helper + `cmd_show` + 4 new tests);
    `impls/python/tests/test_s10_subcommand_awareness.py` (helper extension + 2 new test
    classes); this handoff.
  - **No divergence found.** Both impls' display logic and wording are byte-identical for every
    case exercised (source-present ×4, version-unknown, named-dep-no-suffix, strategy header,
    exclude-newer-absent).

- **B1 — DONE, both impls green.** Preference-aware pick mechanism (§4 stage 4) — mechanism only,
  not yet fed (feeding from `params.prior` is B2).
  - **`Preference` type:** a plain value, not a new ADT — `Version | None` (Python, `solver.py`) /
    `Option<Version>` (Rust, `milpa-solver/src/lib.rs`), both named `Preference` and both documented
    as the RFC's `FromLock(Version) | None` (`Some(v)`/non-`None` = `FromLock(v)`). Kept minimal
    per the RFC's "keep it a plain value" guidance — no enum ceremony needed since `Option`/`| None`
    already gives the two-arm ADT for free.
  - **Final pick signature:** Python `_pick_version(candidates, allowed, strategy, package,
    preference=None) -> Version` (was `(candidates, allowed, strategy, package)`); Rust
    `pick_version(candidates, range, strategy, preference) -> Option<Version>` (was `(candidates,
    range, strategy)` — Rust's pick never had a `package` arg to begin with, confirmed by reading
    the live code rather than the RFC's now-stale `:996`/`:1015` line references, which have since
    shifted to `:1195`/`:1214`). Both are exactly "current signature plus one new argument."
  - **Short-circuit, not reorder:** if `preference` is `FromLock(v)`/`Some(v)` and `v` is in
    `candidates` (which already implies `v ∈ allowed`, per the picker's own pre-filtering
    invariant), return `v` directly before the strategy `match`; otherwise fall through to
    Maxver/Minver/Semver unchanged. No candidate-list reordering.
  - **Feeding:** the one production call site in each impl (`_decide_and_propagate` in
    `solver.py`; the `Provider::choose_version` `Ok(pick_version(...))` call in `lib.rs`) now
    passes `preference=None` / `None` explicitly, with a comment noting B2 owns feeding a real
    value. Zero behavior change — confirmed by the full suite staying green.
  - **Tests (new, mirrored in both impls):** `preference=None` reproduces today's Maxver/Minver
    pick unchanged; an in-range preference wins over Maxver and over Minver (proving it's a real
    override, not a no-op); an out-of-range preference (not in `candidates`) falls through to
    Maxver and to Minver unchanged; a preference that satisfies the accumulated `allowed`/`range`
    but is not itself a real candidate (never published/enumerated) also falls through — pinning
    that a preference cannot smuggle a non-candidate version past the real candidate list.
    Python: `TestPreferenceAwarePick` in `tests/test_solver.py` (6 tests). Rust: 7 `pick_*` tests
    in `milpa-solver/src/lib.rs`'s `mod tests` (one extra vs. Python's parametrized-minver/maxver
    pairing — no semantic difference, just how the two suites split cases).
  - **Gating:** `uv run pytest --junit-xml=...` exit 0, **3209 tests, 0 errors, 0 failures, 31
    skipped** (3202 A7 baseline + 7 new). `./dev-rust test --workspace` exit 0, **1251 passed**
    across all crates (1244 A7 baseline + 7 new `milpa-solver` unit tests) — includes
    `rust_error_catalog_is_a_bijection_with_the_spec` and `conformance_corpus`, both green.
  - **Files touched:** `impls/python/milpa/solver.py` (`Preference` alias + `_pick_version` +
    `_decide_and_propagate` call site); `impls/python/tests/test_solver.py`
    (`TestPreferenceAwarePick`); `impls/rust/crates/milpa-solver/src/lib.rs` (`Preference` alias +
    `pick_version` + its one call site + 7 new tests); this handoff.
  - **No divergence.** Both impls' short-circuit semantics are identical; the only structural
    difference (Rust's pick never carrying a `package` arg) pre-dates B1 and is orthogonal to the
    preference mechanism.

- **B2 — DONE, both impls green.** Feeds `params.prior`'s recorded versions into B1's preference
  mechanism — this is the slice that actually flips the default to minimal-change (D-B1); no dual
  mode, no opt-in flag.
  - **Provider hook, not `solve()`/`pick_version` plumbing:** mirrors A4's `is_version_unknown`
    optional-hook pattern exactly rather than threading a new parameter through `solve()` →
    `_make_decision`/`choose_version`. Python: `PackageProvider.preference` is NOT part of the
    `Protocol`'s required shape — `_preference_for(provider, package)` (`solver.py`) probes it via
    `getattr(..., None)`, defaulting to `None` for providers with no prior-lock concept (every
    synthetic `DictProvider`-based test in `test_solver.py`, unchanged). Rust:
    `PackageProvider::preference` is a trait method with a default body returning `None` — no
    `getattr` needed, same effect. `_make_decision`/`ProviderAdapter::choose_version` call the hook
    once per decision and pass the result as `_pick_version`/`pick_version`'s `preference` arg
    (previously hardcoded `None`/`preference=None`, B1's placeholder).
  - **The one real implementation:** `_Provider.preference` (Python, `resolver.py`) /
    `ResolveProvider::preference` (Rust, `resolver.rs`). Both: `None` if `params.prior`/`self.prior`
    is absent; else decompose the solver_var `package` string via `DepKey::from_solver_var` (the
    SOLE decomposition site, per its own docstring — never a raw `::` split) and look up a
    `LockedDep` in the prior lock's `deps` matching `(name, namespace)`; `None` if not found or the
    recorded `version` string doesn't parse (`parse_version`) — a miss just falls through to
    ordinary strategy selection, never a hard error. Only `name`/`namespace`/`version` are
    consulted — identity/provenance are irrelevant to preference (they gate git/tarball pin reuse,
    an orthogonal, pre-existing `params.prior` consumer).
  - **Why this needed no A5 dependency (confirmed, per §7's dependency note):** a git/url/local/
    tarball dep has exactly one solver-visible candidate in both pre- and post-Axis-A states, so a
    preference lookup on it is inert (the single candidate wins regardless) — verified by the full
    suite staying green with zero fixture changes. The preference only ever bites a named/index
    dep, whose lockfile version was already real pre-Axis-A.
  - **Tests (mirrored in both impls):**
    - Solver-level (mechanism, synthetic provider — isolates the threading from resolver/index/
      fetch concerns): Python `TestB2PriorLockPreferenceThroughSolve` in `tests/test_solver.py` (4
      tests, `PreferenceDictProvider` mirroring `VersionUnknownDictProvider`'s pattern); Rust the
      `B2` block in `milpa-solver/src/lib.rs`'s `mod tests` (4 tests, `PreferenceDictProvider`
      wrapping `DictProvider`). Both prove: a provider with no preference hook/override is
      unaffected (fresh-resolve parity); a locked version still in range wins over maxver's newest;
      a locked version forced out of range falls through to strategy selection; bumping one dep's
      constraint moves only that dep, leaving an unrelated unconstrained dep pinned (the #192 core
      win, at solver granularity).
    - Resolver-level (real wiring, end to end through `resolve()` with a real in-memory `Index` +
      mocked git fetches — proves `params.prior` actually reaches the solver's decision, not just
      the mechanism in isolation): Python `tests/test_b2_prior_lock_preference.py` (3 tests, new
      file); Rust 3 `resolve_b2_*` tests appended to `milpa-core/src/resolver_tests.rs` (after
      `resolve_named_dep_strategy_selects_version`, reusing its `hash_of_nimble`/`IndexVersion`
      helpers). Both prove the same three resolver-granularity scenarios: fresh resolve (no prior)
      picks newest; re-resolving against a prior lock keeps unconstrained named deps at their
      locked version (not newest-wins) — the default-change itself; and narrowing one dep's
      constraint so its locked version no longer satisfies forces ONLY that dep to move, while an
      unrelated unconstrained dep stays locked even though a newer version exists and a fresh
      maxver resolve would pick it (#192, at full resolver granularity — this is B6's conformance
      fixture in spirit, satisfied here as a resolver test per the RFC's own "otherwise add a unit/
      resolver test" fallback).
  - **Conformance corpus: no fixture regeneration needed.** Audited every fixture with BOTH a
    prior `milpa.lock` AND a re-resolving `cmd` (`fetch`/`lock`/`update`) against a named/index dep
    with ≥2 candidate versions — none exist in the current corpus. The fixtures that pair a prior
    lock with a real index (fixture-142, fixture-143, fixture-403) all run `verify`/`frozen`,
    neither of which calls `solve()`. The fixtures that DO re-resolve with a prior lock
    (fixture-123-update-all, fixture-124-update-scoped) are pure git-dep graphs (synthetic `0.0.1`
    sentinel, one candidate each) — confirmed by inspection, and by the full suite passing
    unchanged with zero `expected/` diffs attributable to this slice. B6/B7 own adding the
    CLI-level multi-candidate-plus-prior-lock fixture to the shared corpus.
  - **Gating:** `cd impls/python && uv run pytest --junit-xml=...` exit 0, **3216 tests, 0 errors,
    0 failures, 31 skipped** (3209 B1 baseline + 7 new: 4 in `test_solver.py`, 3 in
    `test_b2_prior_lock_preference.py`). `./dev-rust test --workspace` exit 0, **1258 passed**
    across all crates (1251 B1 baseline + 7 new: 4 `milpa-solver` unit tests, 3
    `milpa-core::resolver_tests` — `milpa-solver` 40→44, `milpa-core` 816→819), incl.
    `rust_error_catalog_is_a_bijection_with_the_spec` and `conformance_corpus`, both green.
  - **Files touched:** `impls/python/milpa/solver.py` (`_preference_for` helper +
    `_make_decision`'s call site); `impls/python/milpa/resolver.py` (`_Provider.preference`);
    `impls/python/tests/test_solver.py` (`PreferenceDictProvider` +
    `TestB2PriorLockPreferenceThroughSolve`); `impls/python/tests/test_b2_prior_lock_preference.py`
    (new file); `impls/rust/crates/milpa-solver/src/lib.rs` (`PackageProvider::preference` default
    + `ProviderAdapter::choose_version`'s call site + `PreferenceDictProvider` + 4 tests);
    `impls/rust/crates/milpa-core/src/resolver.rs` (`ResolveProvider::preference`);
    `impls/rust/crates/milpa-core/src/resolver_tests.rs` (3 `resolve_b2_*` tests + shared
    `two_version_package`/`b2_index`/`b2_registry`/`b2_prior_lock` helpers); this handoff.
  - **No divergence found.** Both impls' preference-lookup semantics and DepKey decomposition are
    identical; all mirrored tests assert the same versions.

- **B3 — DONE, both impls green.** `--locked` + `RES-LOCKED-DRIFT` (identity-based, D-B2). `--locked`
  always performs a REAL resolve (B1/B2's minimal-change preference already applies) and then asserts
  the result is IDENTICAL to the committed lock — distinct from `frozen`, which skips solving entirely.
  - **`check_locked_drift(prior, graph)`** — the one shared comparison, new in `lockfile.py`
    (Python) / `lockfile.rs` (Rust), placed next to `verify_against_graph` (same shape: key by
    `dep_dir_name(name, namespace)`, collect added/removed/mismatched, raise once with every
    drifted name). **Keys on `identity` + canonicalized `provenances` ONLY — never `version`**
    (D-B2): a version relabel of an identity-unchanged dep is not drift. Provenances are sorted by
    the existing emitter's `_provenance_sort_key`/`provenance_sort_key` before comparison on BOTH
    sides — necessary because a freshly-resolved `ResolvedGraph`'s provenances are observed-first/
    unsorted (sorted only at KDL emission time) while a parsed prior `Lockfile`'s are already in
    canonical emit order; comparing raw tuple/Vec order would produce false-positive drift. No
    prior lock at all (`None`) → `RES-LOCKED-DRIFT` too — a CI guard cannot assert reproducibility
    with nothing to reproduce against (a judgment call, not a fork; matches `cargo --locked`/`npm
    ci`-style "must have a lockfile" semantics).
  - **CLI wiring — `--locked` scoped to `fetch`/`lock` only** (per-verb registration, like the new
    B/D-axis flags this RFC's design notes call for — not the legacy global `--frozen`/`--strategy`
    pattern C3 migrates later). Python: `_add_locked_arg` helper mirroring `_add_feature_args`,
    applied to `sp_fetch`/`sp_lock`; `locked: bool = False` threaded through `cmd_fetch`/
    `_cmd_fetch_workspace`/`cmd_lock`/`_cmd_lock_workspace`, called with `check_locked_drift(prior,
    graph)` right after `resolve()`/`resolve_workspace()` succeeds and BEFORE the lockfile/nim.cfg
    write (a drifted resolve must never clobber the committed state). Rust: `--locked` parsed from
    `rest` inside `cmd_fetch` (which already handles both `fetch`/`lock` verbs via its `emit_nimcfg`
    bool) the same way `--features`/`--all-features` are — not the pre-verb global flag loop;
    threaded into `cmd_fetch_with_cert`/`cmd_fetch_workspace_with_cert` too (a drift there writes an
    EMPTY failure cert, mirroring the existing non-SOLVE-CONFLICT convention).
  - **The implicit-frozen-fast-path bypass (Python-only fix, load-bearing).** Python's `cmd_fetch`
    attempts the frozen reconstruction path UNCONDITIONALLY whenever a lockfile exists — regardless
    of whether `--frozen` was passed (cli-contract.md §2.4's documented `_try_frozen`/
    `_try_workspace_frozen` behavior: "the `frozen` boolean only gates whether a `NotFrozen` result
    is an error or a fallthrough"). Left unguarded, `milpa fetch --locked` on an already-in-sync
    project would silently return via the frozen reconstruction and NEVER run the real solve+compare
    `--locked` promises. Fixed by changing the guard from `else:` to `elif not locked:` in both
    `cmd_fetch` and `_cmd_fetch_workspace` — when `locked=True` the implicit fast-path is skipped
    entirely, forcing the full resolve. **Rust needed no equivalent bypass**: Rust's `cmd_fetch` only
    takes the frozen branch when `frozen==true` is EXPLICITLY passed (a separate, independent,
    pre-existing Python/Rust divergence in the two impls' bare-`fetch` behavior — reported here, not
    fixed, since it predates B3 and is out of this slice's scope); Rust's plain `fetch`/`lock` already
    always fully resolves, so `--locked` is trivially "distinct from frozen" there with no new logic.
  - **New slug:** `RES_LOCKED_DRIFT` = `"RES-LOCKED-DRIFT"` — `errors.py` + `spec/errors.md` (§RES,
    alphabetically before `RES-NO-INDEX`) + Rust `CoreError::all_codes()` — bijection green both
    impls, no DEFERRED/EXEMPT entry needed.
  - **spec/cli-contract.md updated:** §5.1 (`fetch`)/§5.2 (`lock`) each gained a `--locked`
    Arguments line + a NORMATIVE clause (§5.1's is the canonical one; §5.2 cross-references it) —
    real solve + identity/provenance-only comparison + must-not-be-bypassed-by-the-frozen-fast-path
    + no-write-on-drift; Appendix A's summary table's `fetch`/`lock` `Args` column updated.
  - **Tests (mirrored in both impls):**
    - Pure comparison unit tests (mirrors `TestVerifyAgainstGraph`/`verify_against_graph_matches_and_
      mismatches`): matching passes; no-prior-lock raises; empty-both passes; **the headline D-B2
      case — a version relabel (`"0.0.1"` → `"1.2.3"`) with unchanged identity+provenance is NOT
      drift**; identity change raises naming the package; a provenance change (different
      `commit_sha`) with UNCHANGED identity still raises (identity alone is not sufficient — D-B2 is
      identity AND provenance); added/removed dep raises; provenance-order-insensitivity (lockfile
      canonical-sorted vs graph observed-first must not false-positive); multiple drifted deps all
      named in one message. Python: `TestCheckLockedDrift` in `tests/test_lockfile.py` (10 tests).
      Rust: 9 `check_locked_drift_*` tests in `lockfile.rs`'s `mod tests`.
    - Resolver-level, real `resolve()` (Python only — mirrors `test_b2_prior_lock_preference.py`'s
      infra): `tests/test_b3_locked_drift.py` (4 tests) — re-resolving the same manifest against its
      own just-written lock is not drift (steady state); the relabel scenario driven through a real
      resolve+`from_graph` round-trip (not just synthetic literals); moving a dep to a different git
      ref IS drift; no prior lock at all raises.
    - CLI-level, real `main(argv)`/`cmd_fetch` (anti-hollow, both impls): Python
      `tests/test_b3_locked_cli.py` (7 tests) — `--locked` passes on an up-to-date lock (`fetch` AND
      `lock`); **`--locked` is distinct from frozen**, proven observably: a bare second `fetch`
      silently takes the implicit frozen fast-path (stderr says `"(frozen)"`), but `fetch --locked`
      never does (stderr says plain `"resolved N deps"`); no committed lock → `RES-LOCKED-DRIFT`
      (`fetch` AND `lock`); a manifest edit moving a dep to a different git tag → `RES-LOCKED-DRIFT`
      naming it, AND the committed lockfile is confirmed byte-unchanged (drift never clobbers state).
      Rust: 4 `locked_*_via_mock` tests appended to `main.rs`'s `mod tests` (same scenarios via direct
      `cmd_fetch(...)` calls, mirroring `update_scoped_drops_one_pin_retains_others_via_mock`'s
      pattern) — up-to-date passes (`fetch` and `lock`), no-prior-lock fails, drift-after-manifest-
      edit fails naming the dep with the lockfile unchanged.
  - **No conformance fixture added — a deliberate, reasoned non-addition, not a gap.** Audited
    `spec/conformance-fixtures.md` §2.7's `cmd` selector vocabulary (`resolve` / `parse-lockfile` /
    `lock-roundtrip` / `frozen` / `check-certificate` / the mutation selectors / the liveness
    selectors) — there is no selector that can express "resolve, then assert equality against a
    prior lock, else fail" (the closest, `frozen`, is the wrong mechanism — it skips solving). Adding
    one would mean extending the shared harness's `cmd` grammar itself (a structural spec change, out
    of this slice's scope), mirroring the existing precedent that `--features`/`--frozen`
    active-flags-mismatch behavior is CLI-only tested (`test_s9_cli_features.py`), never
    corpus-fixture-driven, for the identical reason. Covered instead by the CLI-level tests above in
    both impls.
  - **Gating:** `cd impls/python && uv run pytest --junit-xml=...` exit 0, **3237 tests, 0 errors, 0
    failures, 31 skipped** (3216 B2 baseline + 21 new: 10 `TestCheckLockedDrift` + 4
    `test_b3_locked_drift.py` + 7 `test_b3_locked_cli.py`). `./dev-rust test --workspace` exit 0,
    **1271 passed** across all crates (1258 B2 baseline + 13 new: 9 `lockfile.rs` unit tests + 4
    `main.rs` CLI-level tests) — includes `rust_error_catalog_is_a_bijection_with_the_spec` and
    `conformance_corpus`, both green, no fixture changes (none added/needed).
  - **Files touched:** `impls/python/milpa/lockfile.py` (`check_locked_drift`); `impls/python/milpa/
    cli.py` (`_add_locked_arg`, `--locked` on `sp_fetch`/`sp_lock`, `locked` param threaded through
    all 4 fetch/lock entry points + the `elif not locked` frozen-fast-path bypass + `main()`'s
    dispatch); `impls/python/milpa/errors.py` (`RES_LOCKED_DRIFT`); `impls/python/tests/
    test_lockfile.py` (`TestCheckLockedDrift`); `impls/python/tests/test_b3_locked_drift.py` (new);
    `impls/python/tests/test_b3_locked_cli.py` (new); `impls/rust/crates/milpa-core/src/lockfile.rs`
    (`check_locked_drift`+ 9 tests); `impls/rust/crates/milpa-core/src/error.rs`
    (`RES-LOCKED-DRIFT` in `all_codes()`); `impls/rust/crates/milpa-core/src/lib.rs` (re-export);
    `impls/rust/crates/milpa-cli/src/main.rs` (`--locked` parse + threading through `cmd_fetch`/
    `cmd_fetch_with_cert`/`cmd_fetch_workspace_with_cert` + 4 tests); `spec/errors.md`
    (`RES-LOCKED-DRIFT`); `spec/cli-contract.md` (§5.1/§5.2 + Appendix A); this handoff.
  - **No divergence found** in the mandated behavior (both impls agree on every mirrored test). The
    one NOTED (not fixed) pre-existing asymmetry is the bare-`fetch` implicit-frozen-attempt
    difference described above — orthogonal to B3, already true before this slice, out of scope.

- **B4 — DONE, both impls green.** `--upgrade [<dep>...]` on `fetch`/`lock`, implemented as
  DELEGATION (D-B3) to the exact strip-pin mechanism `milpa update`/`milpa update <dep>` already
  uses, plus `CLI-LOCKED-UPGRADE-CONFLICT`.
  - **The shared helper.** Python: new `_strip_pins_for_upgrade(prior, dep_names)` in `cli.py`
    (placed next to `resolve_alias_to_canonical`) — empty `dep_names` → `None` (drop every pin,
    bare semantics); non-empty → loops `strip_dep_pin` (lockfile.py) once per name, alias→canonical
    resolved each iteration, raising `LOCK_FILE_NOT_FOUND`/`LOCK_DEP_NOT_FOUND` on the same guards
    `update <dep>` already had. **`cmd_update`'s own scoped branch was refactored to call this same
    function** (wrapping its `MilpaError` back into the pre-existing print+`_emit_slug`+`return 1`
    shape so direct-call tests expecting an `int` return are unaffected), as was
    `_cmd_update_workspace`'s scoped branch — so `update`/`update <dep>` and `--upgrade` are now
    THE SAME CODE PATH, not two hand-synced ones. Rust: new `strip_pins_for_upgrade(prior,
    dep_names: &[String]) -> Result<Option<Lockfile>, MilpaError>` in `main.rs` (next to
    `canonical_name_for`) with the identical empty/non-empty contract; `cmd_update`'s two
    near-duplicated inline blocks (root/direct-workspace-manifest AND the member-dir-delegate path)
    were both refactored to call it, downgrading a `LOCK-DEP-NOT-FOUND` `Err` back to the
    pre-existing `Ok(1)` + `eprintln!` shape at each call site so `update_scoped_rejects_dep_not_in_lock`
    (which asserts `Err`+code for no-lockfile but `Ok(1)` for dep-not-found — a **pre-existing,
    left-untouched asymmetry between the two error paths**) stays green unchanged.
  - **CLI wiring.** `--upgrade` scoped to `fetch`/`lock` only, like `--locked` (B3 precedent).
    Python: `_add_upgrade_arg` (argparse `nargs="*"`, `default=None`) on `sp_fetch`/`sp_lock` —
    `None` (absent) / `()` (bare) / `(dep,...)` (scoped) threaded through `cmd_fetch`/
    `_cmd_fetch_workspace`/`cmd_lock`/`_cmd_lock_workspace` (all 4 entry points, mirroring B3's
    `--locked` threading) as a new `upgrade: tuple[str,...] | None = None` param, applied to `prior`
    right after `_maybe_load_prior_lockfile` in each. Rust: new `upgrade_flag_values(rest) ->
    Option<Vec<String>>` (mirrors `flag_value`'s pattern, collects tokens after `--upgrade` up to
    the next `--flag`), called once in `cmd_fetch` (which serves BOTH `fetch`/`lock` via
    `emit_nimcfg`) and applied to `prior` at both its `maybe_prior_lockfile` call sites
    (workspace + single-package).
  - **The frozen-fast-path bypass (Python-only fix, mirrors B3's).** Python's implicit frozen
    attempt (`elif not locked:`) is now `elif not locked and upgrade is None:` in `cmd_fetch` and
    `_cmd_fetch_workspace` — otherwise `fetch --upgrade` on an up-to-date project would silently
    take the no-solve reconstruction path and have zero effect. **Rust needs no equivalent bypass**
    (same reasoning as B3: Rust's frozen branch only triggers on an EXPLICIT `--frozen`, so there is
    no implicit fast-path for `--upgrade` to bypass) — noted inline in `main.rs`'s test module
    rather than built.
  - **`CLI-LOCKED-UPGRADE-CONFLICT`.** New slug in `errors.py` + `spec/errors.md` (§CLI, between
    `CLI-FEATURE-FLAGS-CONFLICT` and `CLI-SOURCE-SPEC-INVALID`) + Rust `CoreError::all_codes()` —
    bijection green both impls. Checked in `main()`'s dispatch (Python, right after the existing
    `CLI_FEATURE_FLAGS_CONFLICT` check) and in `run()` (Rust, mirroring the same spot) — both fire
    BEFORE any manifest is loaded, scoped to `fetch`/`lock` only (mirrors where the two flags are
    actually parsed).
  - **A real, load-bearing bug found and root-cause-fixed (not a workaround): `strip_dep_pin`'s
    `identity=None` was invisible to `_Provider.preference`/`ResolveProvider::preference`.**
    Building the "scoped `--upgrade <dep>` moves only that dep" test revealed that
    `--upgrade <dep>` (and, transitively, `update <dep>`) had ZERO effect on a NAMED/index dep:
    `preference()` looked up the prior `LockedDep` by name/namespace and read its `version` field
    directly, never consulting `identity` — so a pin stripped down to `identity=None` (version
    field left untouched) still fed its OLD version back in as the preferred pick. This is
    invisible for git/url/local/tarball deps (single candidate regardless, per the RFC's own B2
    dependency note) but a real correctness bug for named/index deps, the exact case B4 exists to
    fix. **Root-cause fix, both impls:** `preference()`/`ResolveProvider::preference` now returns
    `None` when `locked.identity.is_none()` — unifying "identity=None means unpinned" (already the
    convention `_git_pin_for_url_dep` uses for git-pin reuse) across BOTH consumers of a prior
    lock's dep entry, rather than leaving a second, silently-inconsistent reading of the same
    field. Fixed 2 pre-existing Rust unit tests whose hand-rolled `b2_prior_named_dep` fixture
    deliberately (and, pre-B4, correctly) left `identity: None` — its doc comment explicitly said
    "identity/provenance are never consulted for a named/index dep's preference lookup," which this
    slice makes false; updated the fixture to carry a synthetic non-null identity and corrected the
    comment. Added a new resolver-level Rust test (`resolve_b4_stripped_pin_named_dep_opts_out_of_preference`)
    and a mirrored Python one (`test_b2_prior_lock_preference.py::TestB4StrippedPinOptsOutOfPreference`)
    proving the fixed semantics directly (stripped dep moves to newest; an unrelated real-identity
    dep stays locked). No conformance-corpus fixture was affected (no existing fixture pairs a
    prior lock with a multi-candidate named dep under a re-resolving verb, per B2's own audit).
  - **Tests:** Python — `tests/test_b4_upgrade.py` (new, 16 tests): `TestStripPinsForUpgrade` (7,
    pure unit tests on the shared helper — empty/named/multi-name/alias/not-found/no-prior cases);
    `TestBareUpgradeMovesWholeGraph` (1); `TestScopedUpgradeMovesOnlyNamedDep` (1);
    `TestUpgradeDelegationEquivalence` (3 — bare-fetch-vs-bare-update, scoped-fetch-vs-scoped-update,
    and the same equivalence via the `lock` verb); `TestCliLockedUpgradeConflict` (3, via real
    `main(argv)`); `TestUpgradeBypassesFrozenFastPath` (1). Plus 1 new resolver-level test in
    `test_b2_prior_lock_preference.py` (the stripped-pin fix, above) — 17 new Python tests total.
    Rust — 4 new tests in `main.rs`'s `mod tests` (`b4_bare_upgrade_pulls_newest_everywhere_via_mock`,
    `b4_scoped_upgrade_moves_only_named_dep_via_mock`, `b4_upgrade_delegation_equivalence_via_mock`
    — covering both bare and scoped equivalence plus the `lock` verb in one test —,
    `b4_locked_and_upgrade_conflict` via real `run()`) + 1 new resolver-level test in
    `resolver_tests.rs` (the stripped-pin fix, above) — 5 new Rust tests total. Real content-hash-
    matched mocked-git multi-version named/index deps (mirrors B2's own `test_b2_prior_lock_preference.py`
    infra on the Python side; a new equivalent staged directly in `main.rs`'s test module on the
    Rust side, since `cmd_fetch`/`cmd_update` always reload the index from `MILPA_INDEX_URL`,
    discarding any injected `MilpaEnv.index` — same reason `test_cli_mutation.py`'s yank-exclusion
    CLI test needed a real `file://` index).
  - **No conformance fixture added** — mirrors B3's own reasoning (no `cmd` selector can express
    "resolve with this CLI flag combination and assert the resulting lockfile," and `--upgrade`'s
    CLI-only nature is covered by the CLI/resolver-level tests above; B6/B7 own the shared-corpus
    fixture additions for Axis B generally).
  - **Gating:** `cd impls/python && uv run pytest --junit-xml=...` exit 0, **3254 tests, 0 errors,
    0 failures, 31 skipped** (3237 B3 baseline + 17 new). `./dev-rust test --workspace` exit 0,
    **1276 passed** across all crates (1271 B3 baseline + 5 new: 4 `milpa-cli` + 1
    `milpa-core::resolver_tests`) — includes `rust_error_catalog_is_a_bijection_with_the_spec` and
    `conformance_corpus`, both green.
  - **Files touched:** `impls/python/milpa/cli.py` (`_add_upgrade_arg`, `_strip_pins_for_upgrade`,
    `cmd_fetch`/`_cmd_fetch_workspace`/`cmd_lock`/`_cmd_lock_workspace` upgrade threading + frozen-
    bypass, `cmd_update`/`_cmd_update_workspace` refactor, `main()` dispatch + conflict check);
    `impls/python/milpa/errors.py` (`CLI_LOCKED_UPGRADE_CONFLICT`); `impls/python/milpa/resolver.py`
    (`_Provider.preference` identity-based fix); `impls/python/tests/test_b4_upgrade.py` (new);
    `impls/python/tests/test_b2_prior_lock_preference.py` (`TestB4StrippedPinOptsOutOfPreference` +
    `_with_stripped_identity`); `impls/rust/crates/milpa-cli/src/main.rs`
    (`strip_pins_for_upgrade`, `upgrade_flag_values`, `cmd_fetch` upgrade threading, `cmd_update`
    refactor, `run()` conflict check, 4 new tests); `impls/rust/crates/milpa-core/src/resolver.rs`
    (`ResolveProvider::preference` identity-based fix); `impls/rust/crates/milpa-core/src/error.rs`
    (`CLI-LOCKED-UPGRADE-CONFLICT`); `impls/rust/crates/milpa-core/src/resolver_tests.rs`
    (`b2_prior_named_dep` fixture fix + new stripped-pin test); `spec/errors.md`
    (`CLI-LOCKED-UPGRADE-CONFLICT`); `spec/cli-contract.md` (§5.1/§5.2 `--upgrade` + Appendix A);
    this handoff.
  - **Divergence:** none in the mandated B4 behavior. The one genuine finding (the
    `preference()`/identity gap above) was a PRE-EXISTING bug shared identically by both impls
    (not a Python/Rust divergence) — root-cause-fixed in both, not papered over.

- **B5 — DONE, both impls green.** The #70 steady-state round-trip property:
  `resolve(M) -> G; L = lockfile_from_graph(G); resolve(M, prior=L) == G`, scoped per the RFC to
  named/index deps only (no git/url/local/tarball singleton — Axis-A migration window excluded by
  construction) with the index held fixed across both resolves (no yanks — the recurring exception
  excluded by design, per §3 Axis B).
  - **Found already substantially built, uncommitted, from an earlier session — not this slice's
    original work.** Both impls' B5 machinery pre-dated this B6 session: Rust
    `resolve_b5_reresolve_with_own_lock_reproduces_same_graph_sweep`
    (`milpa-core/src/resolver_tests.rs:3410`, a hardcoded sweep of representative cases — no
    `proptest` dependency in this workspace) was already tracked/modified and already green. Python
    `tests/test_b5_reresolve_property.py` (Hypothesis-based generalization to N packages × M
    versions) existed as an untracked file but **was failing** — discovered while gating B6's own
    `uv run pytest` run (this session's actual assignment), not from a dedicated B5 effort.
  - **Root-cause bug found and fixed:** the generator's `_KDL_RESERVED_WORDS` exclusion set
    (already correctly excluding KDL 2.0 barewords `null`/`true`/`false`/`nan`/`inf` from generated
    package names) was missing milpa's own reserved dep-kind node name, `member`
    (`manifest.py`'s `_parse_dep_node` disambiguation order, §3.2 step 1: a node literally named
    `member` is always parsed as a `MemberDep`, never a `NamedDep`, regardless of context).
    Hypothesis's shrinker found this within the first few hundred examples (two falsifying cases:
    a bare `member` dep and a constrained `member ">=1.0.0"` dep, both raising `MAN-DEP-NAME-INVALID`
    / `MAN-DEP-MEMBER-ARITY` at parse time instead of reaching the resolver). **Fixed by adding
    `"member"` to the existing exclusion set** (`test_b5_reresolve_property.py`) — the same
    "generator artifact, not a resolution-semantics bug" reasoning already documented for the KDL
    barewords, not a resolver/parser change. No production code touched.
  - **Gating:** with the one-line fix, `uv run pytest tests/test_b5_reresolve_property.py` passes
    (default Hypothesis example budget, no new falsifying cases). Full-suite counts are folded into
    B6's own gating entry below (this fix landed in the same session, as a gating prerequisite for
    B6, not a separately-gated slice).
  - **Files touched:** `impls/python/tests/test_b5_reresolve_property.py` (one-line
    `_KDL_RESERVED_WORDS` addition + doc comment); this handoff. No Rust changes (Rust's B5 sweep
    was already green, untouched).
  - **No divergence found** — both impls' B5 property holds; the only issue was a Python-only test
    generator gap, not a resolver/solver behavior difference.

- **B6 — DONE, both impls green.** CLI-granularity conformance proof of minimal-change (RFC §7
  slice B6): 3 new shared-corpus fixtures, each a genuine multi-candidate (≥2, up to 3, versions
  per package) scenario — a single-candidate graph would be a worthless tautology per the standing
  bar.
  - **Harness: no grammar extension needed.** Audited `spec/conformance-fixtures.md §2.9` and both
    runners (`impls/python/tests/test_conformance.py`'s `resolve` path, `_load_prior_lockfile` +
    `ResolveParams(prior=...)`; `impls/rust/crates/milpa-conformance/src/runner.rs:519`'s
    `prior_lock = milpa_core::load_lockfile(...)` threaded into both `resolve_with_features` and
    `resolve_workspace_with_features`). The default `resolve` cmd selector **already** supports
    "prior `milpa.lock` + re-resolve against a multi-candidate index" in both impls — this is
    exactly the §2.9 NORMATIVE prior-lockfile-reuse contract, already wired to B1/B2's preference
    mechanism. B2's own audit (previous entry) had already established this; B6 confirmed it by
    reading both runners' source rather than re-deriving it, and authored fixtures directly against
    the existing `resolve` selector (no new `cmd` token, no harness code changed in either impl).
  - **Fixtures (all pure named/index-dep scenarios — no git/url singletons, so the fixture bytes
    are the resolver's ACTUAL preference-aware-pick output, generated by driving the real Python
    resolve pipeline via the in-process harness's own `_execute_fixture`/`_REGEN_MODE`, never
    hand-fabricated):**
    - **`fixture-422-bump-one-dep-leaves-others-pinned`** — the amoxtli/#192 shape at CLI
      granularity, 3 named deps (`crisol`/`bearssl`/`httputils`, echoing the real incident's
      names), each with 2 index candidates (1.0.0/2.0.0). Prior lock has all three pinned at
      1.0.0. The manifest bumps ONLY `crisol`'s constraint (`">= 2.0.0"`), forcing it to move;
      `bearssl`/`httputils` are untouched. Result: `crisol` → 2.0.0 (forced), `bearssl`/`httputils`
      → **stay at 1.0.0** — proving the unrelated deps are NOT dragged to 2.0.0 even though maxver
      (the default strategy) would pick 2.0.0 for them in a fresh resolve.
    - **`fixture-423-edit-constraint-narrows-forces-move`** — 2 named deps (`foo`/`bar`), 3 index
      candidates each (1.0.0/1.5.0/2.0.0), both prior-locked at 1.0.0 (originally unconstrained).
      `foo`'s constraint narrows to `">= 1.5.0"` — 1.0.0 no longer satisfies, forcing a move to the
      newest satisfying version under maxver (**2.0.0, not 1.5.0** — proving real strategy
      selection runs post-force, not just "next available"). `bar` stays unconstrained and
      **stays at 1.0.0**, unperturbed.
    - **`fixture-424-edit-constraint-widens-stays-pinned`** — `foo`/`bar`, 3 candidates each
      (1.0.0/2.0.0/3.0.0), both prior-locked at 2.0.0 (`foo` as if previously constrained
      `"< 3.0.0"`; `bar` unconstrained throughout). `foo`'s constraint widens to unconstrained —
      3.0.0 now satisfies too, but `foo`'s locked 2.0.0 STILL satisfies the wider range, so `foo`
      **stays at 2.0.0** (not bumped to 3.0.0, which a fresh maxver resolve would pick). `bar` is
      untouched and also stays at 2.0.0 — proving widening one dep perturbs no sibling.
  - **Generation method (both impls' golden bytes from the SAME real run, not two hand-authored
    copies):** built each fixture's inputs (manifest, index with placeholder `dag-sha256:00…00`
    content hashes, prior lock, `mocked-fetches/` content trees + `.nimble` with `srcDir = "src"`
    per package/version) via a scratch script, then computed the REAL content hash for every
    package/version by fetching through the production mocked transport
    (`env.fetcher.inner.fetch`, mirroring `tools/regen_corpus.py`'s `_regen_index_content_hashes`
    pattern) and patching both `index.kdl` and the prior `milpa.lock` in place. Then blessed
    `expected/{milpa.lock,nim.cfg,_deps_structure.txt}` by driving `tc._execute_fixture` in
    `_REGEN_MODE` for exactly these 3 new fixture IDs (not a full `regen_corpus.py` sweep — no
    other fixture touched). Verified byte-exact output by inspection (dep versions/identities
    match the hand-designed scenario exactly, as quoted above) and by both impls' real test
    runners passing.
  - **Parity confirmed:** Rust's `conformance_corpus` auto-discovers the shared corpus directory —
    no new Rust `#[test]` needed, same as every prior fixture-only slice (A6/A3/A5). Ran
    `./dev-rust test -p milpa-conformance` before and it picked up all 3 new fixtures automatically
    with **0 regressions**; ran the full workspace suite after with the same 0-regression result.
    No divergence — both impls agree on every dep version/identity in all 3 fixtures.
  - **Gating:** `cd impls/python && uv run pytest --junit-xml=...` exit 0, **3258 tests, 0 errors,
    0 failures, 31 skipped** (3227 passed) — includes the 3 new `test_corpus_fixture[...]`
    parametrizations for fixture-422/423/424 and B5's fix (above). `./dev-rust test --workspace`
    exit 0, **1277 passed** across all crates, 0 failed — includes
    `rust_error_catalog_is_a_bijection_with_the_spec` and `conformance_corpus`
    (**420 fixtures — 386 pass, 0 xfail, 34 skip, 0 xpass, 0 regressions**, up from 413/379 at
    A3b; the delta includes A4–A7's fixtures plus these 3 new B6 ones).
  - **Files touched:** `conformance/spec-v1/fixture-422-bump-one-dep-leaves-others-pinned/` (new),
    `conformance/spec-v1/fixture-423-edit-constraint-narrows-forces-move/` (new),
    `conformance/spec-v1/fixture-424-edit-constraint-widens-stays-pinned/` (new) — each with
    `milpa.kdl`, `index.kdl`, `milpa.lock` (prior), `mocked-fetches/`, `expected/{milpa.lock,
    nim.cfg,_deps_structure.txt}`; `impls/python/tests/test_b5_reresolve_property.py` (B5 fix,
    above); this handoff. No production code changed (mechanism was already B1/B2; harness already
    supported the required `cmd` shape).
  - **Not built (explicitly out of this slice's mandated scope, noted per the RFC's own residual-
    risk callout):** the RFC's §7 "Residual risk" note suggests B6/B7 fixtures include a "preferred
    pick rejected several decisions later" deep-backtracking stress case (to catch the Python
    one-level-backtrack vs Rust full-`pubgrub`-backjumping asymmetry, tracked separately under
    #28). B6's mandated deliverable is exactly the 3 categories above (bump-one-pins-rest +
    narrows + widens); the backtracking-stress fixture is explicitly "tracked, not blocking" in the
    RFC text, not a B6 acceptance criterion — left for whoever picks up the #28 thread, not
    silently dropped.
  - **No divergence found.**

- **B7 — DONE, both impls green. AXIS B COMPLETE.** Audited every `prior=`/`prior:` site in both
  impls' CLI (grepped exhaustively, not just the RFC's named list) — the RFC's list was confirmed
  exhaustive, no extra sites found. Four sites hardcoded `prior=None`/`None,` (both impls) and were
  fixed to thread the committed lock via the existing `_maybe_load_prior_lockfile` (Python) /
  `maybe_prior_lockfile` (Rust) helper — the SAME helper `fetch`/`update`/`remove` already use, no
  new mechanism:
  - **`add` (standalone package)** — Python `_cmd_add_git` (`cli.py`, was `prior=None`) → now
    `prior=_maybe_load_prior_lockfile(lock_path)`; Rust `cmd_add`'s single-package branch
    (`main.rs`, was `None,` into `resolve_with_features`) → now `prior.as_ref()` from
    `maybe_prior_lockfile(&dir.join("milpa.lock"))`.
  - **`add` (member-dir delegation)** — Python `_cmd_add_from_member_dir` (was `prior=None`) → now
    threads the SHARED workspace lock (`ws_root / "milpa.lock"`); Rust `cmd_add`'s
    `find_parent_workspace` branch (was `None,` into `resolve_workspace_with_features`) → same fix.
  - **`workspace add-member`** — Python `cmd_workspace_add_member` (was `prior=None`) + Rust
    `cmd_workspace_add_member` (was `None,` into `apply_workspace_manifest_change`) → both now
    thread the shared workspace lock.
  - **`workspace remove-member`** — Python `cmd_workspace_remove_member` + Rust
    `cmd_workspace_remove_member` → same fix.
  - Confirmed NOT in scope (already correct, left untouched): Python `_cmd_remove_from_member_dir`
    already threaded `prior_for_alias`; Rust `cmd_remove`'s member-dir branch already threaded
    `shared_prior`. `update`'s two legitimate `prior=None`/`prior = None` sites (bare `update` with
    no `<dep>` arg — intentional full pin-drop, both impls) are correctly NOT touched — B4 already
    covers that as designed behavior, not a bug.
  - **RED→GREEN verified for real** (not just reasoning): temporarily reverted the standalone-`add`
    fix back to `prior=None`, re-ran the new Python test — it failed with `assert '2.0.0' ==
    '1.0.0'` (unrelated locked dep dragged to newest), confirming the fixture genuinely reproduces
    #192 through this door before the fix; restored the fix, test re-passed.
  - **Unit tests (both impls, real mocked-git + real file:// index, no mocking of milpa's own
    logic):** `impls/python/tests/test_b7_thread_prior.py` (4 tests: standalone add, add-from-
    member-dir, workspace add-member, workspace remove-member — each locks 1–2 named deps at
    1.0.0 against a v1-only index, then swaps to a v1+v2 index and runs the verb under test,
    asserting the unrelated already-locked dep(s) stay at 1.0.0 while the new/added dep resolves).
    Rust: 4 mirroring `#[test]`s added directly in `crates/milpa-cli/src/main.rs`'s test module
    (`b7_add_leaves_existing_deps_pinned`, `b7_add_from_member_dir_leaves_other_members_pinned`,
    `b7_workspace_add_member_leaves_other_members_pinned`,
    `b7_workspace_remove_member_leaves_remaining_members_pinned`), reusing the existing B4 helpers
    (`b4_stage_two_versions`/`b4_index_kdl`/`b4_versions`/`ENV_MUTEX`) — same shape, zero new
    infra needed.
  - **Conformance fixtures (both impls, differential parity — verified against the REAL Python venv
    AND the real Rust debug binary, not just the in-process adapters):**
    `conformance/spec-v1/fixture-425-add-one-dep-leaves-rest-pinned/` (`add foo --git ...` on a
    project with `bearssl`/`httputils` prior-locked at 1.0.0 against a v1+v2 index — both stay
    1.0.0, `foo` resolves) and
    `conformance/spec-v1/fixture-426-workspace-add-member-leaves-rest-pinned/` (`workspace
    add-member member-c` on a workspace with `member-a` prior-locked `bearssl@1.0.0` — stays
    1.0.0, `member-c`'s own `httputils` dep resolves fresh at 2.0.0). Both `cmd` selectors
    (`add`, `workspace`) already existed in `harness/runner.py`'s `_cmd_to_cli` (used by
    fixture-120/265/266) — no harness extension needed. Generated via a real end-to-end run of the
    Python CLI (baseline fetch against a v1-only index, then the verb under test against a
    v1+v2 index), then independently re-verified byte-for-byte against the real Rust debug binary
    (`impls/rust/target/debug/milpa`, freshly built by this session's `./dev-rust test --workspace`)
    via `harness.runner.run_fixture` + `harness.assertions.assert_conformance` — both fixtures PASS
    for both impls. `harness/corpus_lint.py`'s static fixture-rot guard also reports 0 violations
    for the new fixtures.
  - **Divergence found — reported, NOT fixed under B7, NOT filed as an issue (per this session's
    hard rules; orthogonal to Axis B):** the first byte-check of fixture-426 (with `index-trust
    "off"` declared on the workspace root, for convenience) surfaced a genuine, PRE-EXISTING
    `format_workspace_manifest` field-ordering divergence — Python emits `index-trust`/
    `index-trust-signer`/`index-trust-bundle`/`entry-trust`/`index-history` AFTER `workspace{}` /
    `overrides{}` / `flags{}`; Rust emits the same fields BEFORE `workspace{}` (right after
    `name`). Python's own docstring claims byte-identity with Rust here — currently false. Not
    caused by this session (neither impl's manifest-serialization code was touched by B7); the
    fixture was simply redesigned to not declare `index-trust` at all (not needed — default `warn`
    policy is fixture-safe), which sidesteps the bug without masking it (the finding is recorded
    here and the fixture's original with-`index-trust` byte-mismatch was directly observed before
    being redesigned). See the "Follow-up NOT filed" note near the top of this handoff.
  - **Gating:** `cd impls/python && uv run pytest` exit 0, **3231 passed, 33 skipped** (up from
    3231/31 pre-B7 — +2 skipped for the 2 new CLI-only conformance fixtures; the 4 new
    `test_b7_thread_prior.py` tests are counted in the 3231 passed). `./dev-rust test --workspace`
    — ran to completion (not just launched), confirmed **0 failed anywhere** across every crate's
    test binary (milpa-core split partitions 122+16+6+8+19+2+4, milpa-cli 830 including the 4 new
    `b7_*` tests, milpa-conformance 213, plus doctests), all reporting `test result: ok`. Also
    re-ran `./dev-rust test -p milpa-conformance` alone after adding the 2 new fixtures — still
    green (19+2+4 passed, 0 failed), confirming `conformance_corpus` picked up fixture-425/426
    without regression (both correctly classified `CliOnly` and skipped, same as fixture-120/265/266).
  - **Files touched:** `impls/python/milpa/cli.py` (4 sites), `impls/rust/crates/milpa-cli/src/
    main.rs` (4 sites + 4 new tests), `impls/python/tests/test_b7_thread_prior.py` (new),
    `conformance/spec-v1/fixture-425-add-one-dep-leaves-rest-pinned/` (new),
    `conformance/spec-v1/fixture-426-workspace-add-member-leaves-rest-pinned/` (new), this handoff.

- **C1 — DONE, both impls green. #98 verified: minver/semver over the index JUST WORKS, no
  resolver/registry/pick code changes needed.** `resolve_named_all` already returns the full
  index candidate list and `_pick_version`/`pick_version` already branches on `Strategy` — C1's
  ONLY job was proving this end-to-end at the CLI/conformance level (previously minver was
  unit-only against a test double, and no `minver`/`semver` conformance fixture existed at all)
  and closing any gap the fixture exposed. None was found: the same 3-way-differing candidate
  set resolves correctly under all three strategies with zero production-code edits (confirmed
  by `git diff` — this slice touches `conformance/`, `spec/conformance-fixtures.md`, and this
  handoff only; `impls/python/milpa/{resolver,registry,solver}.py` and
  `impls/rust/crates/milpa-{core,solver}/src/*` are untouched by this session).
  - **Reconciled dangling partial work found on arrival (per this slice's own instructions).**
    The tree was NOT at a clean post-B7 state for Axis C: a prior session had already landed
    real (uncommitted) harness-extension work for C1's "extend the cmd grammar" fallback path —
    `Fixture._parse_strategy`/`self.strategy` in `impls/python/tests/test_conformance.py`
    (parses an optional `--strategy <value>` token off the `cmd` file text, threaded into
    `ResolveParams(strategy=fixture.strategy, …)` and `from_graph(graph,
    strategy=str(fixture.strategy))`) and the mirror `Fixture.strategy: Option<String>` +
    `fixture_strategy(fx)` in Rust's `fixture.rs`/`runner.rs` (threaded into both `resolve()`
    call sites' `strategy` argument and both `from_graph` calls). This was genuine, correct,
    already-tested plumbing (5 `mod tests` struct literals updated with `strategy: None`) — NOT
    "essentially nothing" as the generic task framing warned might be found. What was actually
    missing (and is what this session did): the three fixture directories themselves
    (`fixture-427`/`428`/`429`) existed only as EMPTY stub dirs (bare `expected/` +
    `mocked-fetches/` subdirectories, no `milpa.kdl`/`index.kdl`/`cmd`/content — confirmed via
    `find -type f` returning nothing under them, which is why `git status` never listed them:
    git does not track empty directories), and `spec/conformance-fixtures.md` had not been
    updated to document the new `--strategy` cmd-file token. Verified the harness plumbing was
    correct (not just present) by reading it end-to-end, then completed the slice: authored the
    three fixtures' real inputs and blessed their `expected/` via the production harness, and
    documented the extension in the spec.
  - **The exact semver rule encoded (read from the impl, both impls identical):** `_pick_semver`
    (Python `solver.py:770`) / `pick_semver` (Rust `milpa-solver/src/lib.rs:1253`) — highest
    candidate sharing the **major version of the accumulated constraint's lower bound**; no
    lower bound (unconstrained) falls back to MaxVer; a lower bound with no same-major candidate
    raises/refuses (the cross-major jump SemVer is defined to never make). This is the RFC's own
    referenced "existing mechanism" (§3 Axis C cites `_pick_semver`/`pick_semver` as ground
    truth, not a rule to be redefined) — no fork, no RFC-vs-impl mismatch found.
  - **New conformance fixtures** (shared `index.kdl` shape across all three — package `widget`,
    3 candidate versions `1.0.0`/`1.5.0`/`2.0.0` spanning majors 1 and 2, root constraint
    `>= 1.0.0` so the constraint alone never narrows past 3 candidates — only `--strategy`
    decides): `fixture-427-strategy-minver-over-index` (`cmd: resolve --strategy minver` →
    picks `1.0.0`), `fixture-428-strategy-semver-over-index` (`cmd: resolve --strategy semver`
    → picks `1.5.0`, highest within major 1), `fixture-429-strategy-maxver-over-index` (`cmd:
    resolve --strategy maxver` → picks `2.0.0` — the explicit-flag contrast case; the *default*
    maxver-with-no-flag path was already covered by the pre-existing
    `fixture-063-canonical-selection`, so this fixture instead proves the explicit
    `--strategy maxver` cmd-token plumbing itself). Only the winning candidate's ref has a
    `mocked-fetches/` entry per fixture (the other two are index-enumerated but never
    fetched/verified, mirroring fixture-415's stub convention — non-winning candidates'
    `content_hash` is the empty-root `dag-sha256` pin, matching `regen_corpus.py`'s own
    never-fetched-stub convention). Golden `expected/milpa.lock`/`nim.cfg`/`_deps_structure.txt`
    generated by driving the real Python resolver through `test_conformance.py`'s own
    `_execute_fixture` in `_REGEN_MODE`, targeted at just these 3 fixtures (not a full
    `regen_corpus.py` sweep) — confirms the lockfile's `strategy "minver"/"semver"/"maxver"`
    line and the selected `version` field end-to-end, not just the picker in isolation.
  - **`spec/conformance-fixtures.md` updated** — §2.7's opening NORMATIVE paragraph now states
    `resolve` (the only exception to "no further tokens") MAY carry a trailing `--strategy
    <value>` pair; new §2.7.4 documents the token fully (recognized values, absent-default
    behavior, interaction with `check-certificate`'s verb token, and that a future
    `lowest-direct` value is out of scope until its own slice lands, and that
    non-`resolve`-cmd fixtures needing a non-default strategy should use manifest
    `resolution { strategy }` once C3 lands it) and cross-references the three new fixtures as
    the canonical example.
  - **Parity confirmed** — both impls select the identical version per strategy from the
    identical index, and the Rust `conformance_corpus` test auto-discovered all three new
    fixtures with zero new Rust `#[test]` functions needed (harness-level, not per-fixture,
    wiring — matching every prior slice's fixture-addition pattern).
  - **Gating:** `cd impls/python && uv run pytest --junit-xml=…` exit 0, **3267 tests, 0 errors,
    0 failures, 33 skipped → 3234 passed** (3231 B7 baseline + 3 new fixture-427/428/429
    parametrizations; no unit-test additions this slice, no regressions). `./dev-rust test
    --workspace` — ran to completion (not just launched), exit 0, **1281 passed across all
    crates, 0 failed anywhere** (milpa-cli 152 [122 unit + 16 + 6 + 8 integration] +
    milpa-conformance 25 [19 unit + 2 corpus + 4 self_test] + milpa-core 830 + milpa-manifest 213
    + milpa-solver 44 + milpa-types 17, all doctests 0 — unchanged from the B7 baseline total,
    confirming C1 added zero new Rust unit tests, only corpus-auto-discovered fixtures);
    `./dev-rust test -p milpa-conformance -- --nocapture` shows
    `conformance: 425 fixtures — 389 pass, 0 xfail (parked), 36 skip (cli-only), 0 xpass, 0
    regressions` (422 pre-C1 + 3 new, all passing).
  - **No divergence found.**
  - **Files touched:** `conformance/spec-v1/fixture-427-strategy-minver-over-index/` (new),
    `conformance/spec-v1/fixture-428-strategy-semver-over-index/` (new),
    `conformance/spec-v1/fixture-429-strategy-maxver-over-index/` (new — all three reusing the
    empty stub dirs a prior dead session had left behind), `spec/conformance-fixtures.md`
    (§2.7 opening paragraph + new §2.7.4), this handoff. `impls/python/tests/test_conformance.py`
    and `impls/rust/crates/milpa-conformance/src/{fixture.rs,runner.rs}` were NOT touched this
    session — their `--strategy` harness plumbing was pre-existing (dangling, uncommitted) work
    from a prior session, audited and confirmed correct, not re-done.
- **C2 — DONE, both impls green.** `LowestDirect` as a surface value (enum + `lowest-direct` wire
  string, D-C1) + the provider's effective-strategy precompute (D-C2) — the picker gains NO
  `LowestDirect` case.
  - **Python:** `Strategy` (`version.py`) gained `LOWEST_DIRECT = "lowest-direct"`. New
    `_effective_strategy_for(provider, package, strategy)` in `solver.py` — passes any non-
    `LowestDirect` strategy through unchanged; for `LowestDirect` returns `MINVER` if
    `_is_root_direct(provider, package)` else `MAXVER`. `_is_root_direct` mirrors
    `_is_version_unknown`'s optional-hook pattern (`getattr(provider, "is_root_direct", None)`,
    default `False`). `_make_decision` computes `effective_strategy` right before calling
    `_pick_version` — the ONLY call site — so `_pick_version`'s `strategy` argument, and its
    `match` (unchanged: exactly the same 3 `case` arms as before this slice), never receives
    `LOWEST_DIRECT`. Added a trailing `raise AssertionError(...)` OUTSIDE the `match` (not a
    `case`) as a defensive invariant guard, documented as never firing in practice. New
    `_Provider.is_root_direct(package)` in `resolver.py` decomposes the solver_var via
    `DepKey.from_solver_var(package).name` and checks membership in the existing
    `self._root_authority` set (§10 provenance precedence's set, reused — zero new bookkeeping).
    CLI: `--strategy` `choices` tuple + help text extended with `lowest-direct`.
  - **Rust:** `Strategy` (`milpa-solver/src/lib.rs`) gained a `LowestDirect` variant + `as_str()`
    arm (`"lowest-direct"`). **The type-level deepening** (the load-bearing design point): a NEW,
    narrower `EffectiveStrategy` enum (`Maxver`/`Minver`/`Semver` — no `LowestDirect` variant,
    cannot represent it) is `pick_version`'s parameter type — its `match` is exhaustive over
    exactly those 3 variants, so the compiler itself (not just discipline) forbids ever passing
    `LowestDirect` into the picker. New free fn `effective_strategy(strategy: Strategy,
    is_root_direct: bool) -> EffectiveStrategy` is the ONE place `Strategy::LowestDirect` is ever
    interpreted (`Minver` if root-direct else `Maxver`; every other `Strategy` value maps 1:1).
    New `PackageProvider::is_root_direct(&self, _package: &str) -> bool { false }` default trait
    method (mirrors `is_version_unknown`/`preference`'s pattern). `ProviderAdapter::choose_version`
    computes `effective_strategy(self.strategy, self.provider.is_root_direct(package))` right
    before calling `pick_version`. `ResolveProvider::is_root_direct` (`milpa-core/src/resolver.rs`)
    mirrors Python exactly (`DepKey::from_solver_var(package)` + `self.root_authority.contains`).
    CLI: `parse_strategy` (`main.rs`) gained `"lowest-direct" => Some(Strategy::LowestDirect)`.
    **Python vs Rust mechanism note (not a divergence, a language-forced difference, same pattern
    as A4's Rust-`prioritize`-vs-Python-two-pass-scan):** Rust needs a genuinely separate type
    because `match` exhaustiveness is compiler-enforced; Python's `match` has no such enforcement,
    so the same invariant is upheld by construction (single call site) plus a defensive
    `AssertionError` fallback. Both achieve the RFC's "the picker's `match` never sees
    `LowestDirect`" requirement; Rust's is statically provable, Python's is invariant-by-
    construction plus a runtime trap.
  - **Contrast tests (the whole point — both impls):** a root-direct dep with multiple candidates
    picks the LOWEST satisfying version; a purely TRANSITIVE dep (discovered only via the
    root-direct dep's own `.nimble` bare-name `requires` line, never root-declared) with multiple
    candidates still picks the HIGHEST — under the SAME configured `Strategy::LowestDirect`.
    Python: solver-level `TestEffectiveStrategyPrecompute` (`test_solver.py`, new
    `RootAuthorityDictProvider` test double, 6 tests incl. the no-hook-defaults-to-transitive
    regression and the "`_pick_version` has no `LowestDirect` case" design-assertion test) +
    resolver-level `test_c2_lowest_direct.py` (new file, real `resolve()` through mocked git +
    a real in-memory `Index`, mirroring `test_b2_prior_lock_preference.py`'s infra — 2 tests, incl.
    a plain-maxver sanity control proving the contrast is really caused by `lowest-direct`'s
    root/transitive split). Rust: `milpa-solver/src/lib.rs`'s `mod tests` (5 new: 3
    `effective_strategy` unit tests + 2 `solve()`-level contrast/regression tests via 2 new
    synthetic providers, `RootAuthorityProvider`/`NoRootAuthorityProvider`) + `milpa-core/src/
    resolver_tests.rs`'s `resolve_c2_lowest_direct_root_direct_minver_transitive_maxver` (real
    `resolve()`, mirrors the B2 test infra's `two_version_package` pattern) + `milpa-cli/src/
    main.rs`'s `parses_lowest_direct_strategy_flag`.
  - **Wire-string round-trip (D-C1):** Python — `test_lockfile.py` gained
    `test_strategy_lowest_direct_round_trips` (parse) + `test_strategy_line_lowest_direct` (format);
    both confirm `lowest-direct` is just another string value at the lockfile layer (no fixed-set
    validation there — `lockfile.rs`/`lockfile.py` already treat `strategy` as an opaque string,
    so no Rust-side lockfile change was needed).
  - **`spec/cli-contract.md` updated:** §0 item 4 + §2.3 — `lowest-direct` added as a 4th accepted
    `--strategy` value (with its Minver-root-direct/Maxver-transitive semantics stated as
    NORMATIVE, plus the surface-value-only / no-picker-case clause cross-referencing §4 stage 4
    D-C2) and added to the MUST-reject set.
  - **Out of scope, confirmed not touched:** manifest `resolution { strategy }`, the
    `Option<Strategy>` CLI sentinel + scoped per-verb registration, precedence, and
    bypass-on-value-divergence (all C3); `FROZEN-STRATEGY-MISMATCH`'s baseline literal (C3b,
    `frozen.py:72` untouched); full conformance-corpus fixtures for `lowest-direct` (C4) — the
    contrast is proven at solver/resolver-test granularity instead, per this slice's own explicit
    scope (mirrors B3/B4's "no corpus fixture, CLI/resolver tests suffice" precedent).
  - **Gating:** `cd impls/python && uv run pytest --junit-xml=…` exit 0, **3277 tests, 0 errors, 0
    failures, 33 skipped → 3244 passed** (3267 C1 baseline + 10 new: 6
    `TestEffectiveStrategyPrecompute` + 2 `test_c2_lowest_direct.py` + 2 lockfile round-trip; no
    regressions). `./dev-rust test --workspace` — ran to completion, exit 0, **1288 passed across
    all crates, 0 failed anywhere** (1281 C1 baseline + 7 new: 5 `milpa-solver` + 1 `milpa-core`
    + 1 `milpa-cli`); includes `rust_error_catalog_is_a_bijection_with_the_spec` and
    `conformance_corpus`, both green, no fixture changes (none added — C4's job).
  - **No divergence found** in the mandated behavior. The Rust-narrower-type-vs-Python-runtime-trap
    difference (above) is a language-forced mechanism difference, not a semantic one — both impls
    agree on every mirrored test's outcome.
  - **Files touched:** `impls/python/milpa/version.py` (`Strategy.LOWEST_DIRECT`);
    `impls/python/milpa/solver.py` (`_is_root_direct`, `_effective_strategy_for`, `_make_decision`
    call site, `_pick_version` trailing guard + docstring); `impls/python/milpa/resolver.py`
    (`_Provider.is_root_direct`); `impls/python/milpa/cli.py` (`--strategy` choices/help);
    `impls/python/tests/test_solver.py` (`RootAuthorityDictProvider` +
    `TestEffectiveStrategyPrecompute`); `impls/python/tests/test_c2_lowest_direct.py` (new);
    `impls/python/tests/test_lockfile.py` (2 round-trip tests); `impls/rust/crates/milpa-solver/
    src/lib.rs` (`Strategy::LowestDirect`, `EffectiveStrategy`, `effective_strategy`,
    `PackageProvider::is_root_direct`, `pick_version` signature + call sites, 5 new tests);
    `impls/rust/crates/milpa-core/src/resolver.rs` (`ResolveProvider::is_root_direct`);
    `impls/rust/crates/milpa-core/src/resolver_tests.rs` (`resolve_c2_lowest_direct_*`);
    `impls/rust/crates/milpa-cli/src/main.rs` (`parse_strategy` + 1 new test);
    `spec/cli-contract.md` (§0.4, §2.3); this handoff.
- **C3 — DONE, both impls green.** The four connected pieces: `--strategy`
  `Option<Strategy>` CLI sentinel + scoped per-verb registration; manifest
  `resolution { strategy }` block (first appearance, extensible for Axis D's
  `exclude-newer`); CLI > manifest > lockfile-recorded > `maxver` precedence,
  computed per resolve-triggering verb; B2 lock-preference bypass gated on
  **value-divergence** (`effective strategy != lockfile.strategy`), never
  flag-presence — scoped whole-graph for maxver/minver/semver, root-direct-only
  for lowest-direct (D-C2).
  - **Python:** `_add_strategy_arg` (`cli.py`) registers `--strategy` (default
    `None`) on `fetch`/`lock`/`add`/`remove`/`update`/`workspace add-member`/
    `workspace remove-member` — removed from the global parser entirely.
    `main()` computes `cli_strategy: Strategy | None` from `args.strategy`
    (`getattr` default `None`, safe for verbs without the flag) instead of the
    old `Strategy(args.strategy)` global. New `manifest.py`: `Resolution`
    dataclass (`strategy: Strategy | None = None`), `resolution` field on both
    `Manifest` and `WorkspaceManifest`, `"resolution"` added to
    `_PACKAGE_TOP_LEVEL`/`_WORKSPACE_TOP_LEVEL`, `_parse_resolution_block`/
    `_parse_resolution_strategy_node` (unknown/duplicate child →
    `MAN_RESOLUTION_BLOCK_INVALID`; malformed/unrecognized value →
    `MAN_RESOLUTION_STRATEGY_INVALID`), wired into both parse-doc functions +
    both `format_manifest`/`format_workspace_manifest` (emitted right after
    `version`/`name` respectively, only when a strategy is actually set — an
    empty/absent block is behaviorally identical at the precedence point).
    New `_resolve_effective_strategy(cli_strategy, manifest, prior)` helper in
    `cli.py` (CLI ?? manifest.resolution.strategy ?? lenient-parse of
    `prior.strategy` ?? `Strategy.MAXVER`) called at all 13 `ResolveParams(`
    construction sites (`cmd_fetch`/`_cmd_fetch_workspace`/`cmd_lock`/
    `_cmd_lock_workspace`/`_cmd_add_git`/`cmd_remove`/`cmd_update` ×2 branches/
    `_cmd_update_workspace`/`_cmd_add_from_member_dir`/
    `_cmd_remove_from_member_dir`/`cmd_workspace_add_member`/
    `cmd_workspace_remove_member`) — each site passes its own already-loaded
    manifest (or `workspace.workspace_manifest`/`ws_manifest`/a freshly-parsed
    root manifest for the two workspace-member-dir verbs that only had the
    root's `WorkspaceManifest` implicitly) + the **actual on-disk** lockfile
    (freshly loaded via `_maybe_load_prior_lockfile`, independent of whatever
    `prior` `update`/`--upgrade` null out or strip for B2 preference — dropping
    a pin must not also reset the governing strategy). Bypass:
    `_Provider._bypasses_lock_preference` (new method, `resolver.py`) —
    `False` if `prior is None`; `False` if `str(self._params.strategy) ==
    prior.strategy`; else `self.is_root_direct(package)` if
    `self._params.strategy == Strategy.LOWEST_DIRECT` else `True`. Called from
    `preference()` right after the `prior is None` early return.
  - **Rust:** `Strategy::parse` (new SSOT parse fn, `milpa-solver/src/lib.rs`)
    reused by both `main.rs`'s `strategy_flag_value` and the new manifest
    block parser. `Cli.strategy` field removed entirely; `-s`/`--strategy`
    removed from `parse_args`'s pre-verb loop. New `strategy_flag_value(rest)
    -> Result<Option<Strategy>, ()>` (scans `rest` like `upgrade_flag_values`;
    `Err(())` on a present-but-malformed value = usage error, exit 2, mirroring
    the old global loop's short-circuit). `run()` computes `strategy_cli`
    once per dispatch (only for the 7 resolve-triggering verbs — other verbs
    never scan for it, same "silently ignored on a non-owning verb" behavior
    every other scoped flag already has in this hand-rolled parser) and passes
    it instead of `cli.strategy` to `cmd_fetch`/`cmd_update`/`cmd_add`/
    `cmd_remove`/`cmd_workspace`. New `milpa_manifest::Resolution` struct
    (`Copy`), `resolution: Option<Resolution>` field on `Manifest` AND
    `Workspace` (6 other `Manifest`/`Workspace`-literal test/production sites
    fixed with `resolution: None`), `"resolution"` added to
    `PACKAGE_TOP_LEVEL`/`WORKSPACE_TOP_LEVEL`, `check_resolution_block`/
    `check_resolution_strategy` (mirrors Python exactly, same two slugs),
    wired into both `parse_manifest_doc`/`parse_workspace_doc` + both
    `format_manifest`/`format_workspace_manifest` emitters (same position
    choice as Python — right after `version`/`name`). `LoadedWorkspace`
    (`milpa-core/src/workspace.rs`) gained the same `resolution` field,
    threaded through all 3 of its construction sites (`load_workspace`,
    `load_workspace_from_manifest`, `load_workspace_with_member_override`).
    New `resolve_effective_strategy(cli_strategy, resolution, prior)` free fn
    in `main.rs` (same 4-tier logic as Python), called at all 7 verb-level
    sites; for `cmd_fetch` the effective strategy is computed ONCE before the
    frozen/non-frozen branch split (Rust's frozen path — unlike Python's,
    which returns early with no lockfile rewrite — unconditionally calls
    `write_lockfile(&from_graph(&graph, strategy.as_str()), ...)` even on the
    frozen fast-path; a genuine PRE-EXISTING Python/Rust divergence, reported
    not fixed, that just happened to surface here because `strategy` needed to
    be in scope for both branches). Bypass: `ResolveProvider::
    bypasses_lock_preference(prior, package)` — a NEW inherent method (added
    to the `impl<'a> ResolveProvider<'a>` block, NOT the `impl PackageProvider
    for ResolveProvider` trait block, since it isn't a trait method — E0407 if
    placed there) — called from the trait's `preference()` right after the
    `let prior = self.prior?;` line. New `strategy: Strategy` field added to
    `ResolveProvider` (threaded through `ResolveProvider::new`'s new last
    parameter, all 3 call sites, and `ProviderOpts`/`build_single_provider`'s
    new `strategy` field/destructure, both `ProviderOpts{}` construction
    sites).
  - **Bypass gate — the load-bearing correctness point, identical in both
    impls:** `bypasses_lock_preference`/`_bypasses_lock_preference` is a PURE
    function of (effective strategy, locked strategy string, directness) —
    never a CLI-parsing artifact. `False` immediately if
    `effective_strategy_str == locked_strategy_str` (the #192 regression
    guard: `--strategy maxver` spelled out on a maxver lock is a genuine
    NO-OP, not a whole-graph bypass) — this is checked BEFORE the
    `LowestDirect` branch, so a matching `lowest-direct` effective vs.
    `lowest-direct` locked is also correctly a no-op. Only on genuine
    string-divergence does the strategy-specific scope kick in: whole-graph
    for maxver/minver/semver, `is_root_direct(package)`-gated for
    `lowest-direct`.
  - **Precedence — same 4-tier chain in both impls:** explicit CLI ??
    manifest `resolution.strategy` ?? lenient-parse of the prior lockfile's
    recorded `strategy` string ?? `Maxver` default. The lockfile-recorded
    tier is deliberately fed from a **freshly-loaded on-disk lockfile**, not
    whatever `prior` value `update`/`--upgrade` null out or strip for B2's
    minimal-change preference — verified this distinction matters via the
    `cmd_update` test coverage (bare `update` sets `prior=None` but must still
    read the committed lock's `strategy` for the precedence fallback).
  - **Tests — Python:** `test_manifest_parse.py::TestResolutionBlockParse` (9:
    absent-is-none, maxver, lowest-direct, empty-block-is-Resolution-with-
    no-strategy, unknown-child→BLOCK-INVALID, duplicate-strategy→
    BLOCK-INVALID, wrong-arity→STRATEGY-INVALID, unrecognized-value→
    STRATEGY-INVALID, workspace-root-block-parses);
    `test_manifest_writer.py` (4: format-only-when-present incl. empty-block
    case, format→parse round-trip, `mutate_manifest_file` round-trip pin,
    `mutate_workspace_manifest_file` round-trip pin);
    `test_c3_strategy_bypass.py` (new file, 3 resolver-level tests via real
    `resolve()` through mocked git + a real in-memory `Index`, reusing
    `test_c2_lowest_direct.py`'s infra: maxver-explicit-on-maxver-lock-is-noop
    regression guard, lowest-direct-bypasses-root-direct-only, minver-vs-
    maxver-lock-bypasses-whole-graph); `test_c3_strategy_cli.py` (new file, 6
    CLI-level tests via real `main(argv)` + mocked git, no conformance-harness
    shortcut: `--strategy` scoped — `show --strategy` now exit 2 where it was
    previously silently accepted; `fetch --strategy` still accepted;
    unspecified-uses-manifest; explicit-overrides-manifest;
    absent-both-defaults-to-maxver). **Rust:** `milpa-manifest/src/tests.rs`
    (6: 4 error-table rows mirroring Python's cases + `resolution_block_
    present_and_absent` + `workspace_resolution_block_present_and_absent`);
    `format.rs` (2: `resolution_strategy_emitted_only_when_present`,
    `resolution_strategy_round_trips`); `resolver_tests.rs` (3, mirroring the
    Python bypass tests exactly, reusing `resolve_c2_lowest_direct_root_
    direct_minver_transitive_maxver`'s direct/transitive index+registry shape
    factored into `c3_direct_transitive_index_and_registry`); `main.rs` (7:
    2 REWRITTEN old tests that asserted the removed `cli.strategy` global
    field — `parses_global_flags_then_verb` now only checks `-C`/`--frozen`;
    `parses_lowest_direct_strategy_flag` now asserts via
    `strategy_flag_value(&cli.rest)` with the verb BEFORE the flag — plus 5
    new: `strategy_flag_scoped_to_verb_tail`, `strategy_flag_malformed_value_
    errors`, `strategy_flag_absent_is_none`, and 3 `cmd_fetch`-level
    precedence tests mirroring the Python CLI tests via real mocked-git
    `cmd_fetch` calls + `load_lockfile` on the written `milpa.lock`). Also
    ~54 pre-existing Rust test call sites needed `Strategy::X` →
    `Some(Strategy::X)` (mechanical, `strategy: Strategy` → `strategy_cli:
    Option<Strategy>` parameter-type change across 7 `cmd_*` functions) —
    fixed via a small Python script matching rustc's own reported
    `(line, col)` spans, not hand-edited one by one.
  - **New slugs:** `MAN-RESOLUTION-BLOCK-INVALID`, `MAN-RESOLUTION-STRATEGY-
    INVALID` — `errors.py` + `spec/errors.md` (§MAN, alphabetically between
    `MAN-REMOVE-DEP-ABSENT` and `MAN-SPEC-VERSION-TYPE`) + Rust `MAN_CODES` —
    bijection green both impls, no DEFERRED/EXEMPT entry needed.
  - **Spec updates:** `spec/cli-contract.md` — §0 item 4 rewritten (scoping +
    precedence one-liner); §2.3 reduced to a redirect (no longer a global
    flag, so it no longer belongs under "## 2 Global flags"); new §2.10 with
    the full NORMATIVE treatment (accepted values, verb scoping, 4-tier
    precedence, and the bypass-on-value-divergence semantics spelled out
    explicitly with the #192 footgun example). `spec/manifest-grammar.md` —
    §3.1's top-level node list + a new "`resolution` block" subsection
    (mirrors the `mirrors`-block subsection style); §7's workspace top-level
    list + a root-only NORMATIVE clause cross-referencing Axis W. (Both
    files had pre-existing, unrelated staleness from Axis A — e.g.
    manifest-grammar.md §3.1 never documented the `version`/`index-trust`/
    `entry-trust`/`index-history` fields either — left untouched, not this
    slice's scope.)
  - **Divergence found, reported not fixed (pre-existing, NOT C3-caused):**
    Rust's `cmd_remove`'s single-package branch hardcodes `prior: None` in
    its `resolve(...)` call (`main.rs`, the 5th positional arg) — meaning B2's
    minimal-change preference never applies to a single-package `milpa
    remove`, even though a `prior_lock` IS loaded just above it (for alias
    resolution only) and Python's `cmd_remove` DOES thread the real prior.
    This predates C3 (untouched by this slice — C3 only added the
    effective-strategy computation using the already-loaded `prior_lock`,
    independent of this separate bug) and contradicts B7's own "fetch/update/
    remove already thread prior" premise; worth its own fix, not attempted
    here (out of scope, no dedicated test coverage exists to gate a change
    safely).
    - **FIXED (follow-up session, TDD):** `impls/rust/crates/milpa-cli/src/
      main.rs` `cmd_remove`'s single-package branch — the bespoke inline
      `if lock_path.exists() { Some(load_lockfile(&lock_path)?) } else {
      None }` was replaced with the shared `maybe_prior_lockfile(&lock_path)`
      helper (the same soft-fail loader `fetch`/`update`/`add`/workspace
      verbs use — swallows a missing/corrupt prior to `None` instead of
      hard-failing via `?`, matching Python's `_maybe_load_prior_lockfile`
      semantics exactly), and the `resolve(...)` call's 5th positional arg
      changed from `None` to `prior_lock.as_ref()`. RED test added first
      (`b7_remove_leaves_other_dep_pinned`, mirroring the `b7_add_*` pattern:
      a locked project with foo+bar both at 1.0.0, then `remove bar` against
      an index that now ALSO offers foo 2.0.0) — confirmed it failed
      (`foo` moved to `2.0.0`) with the bug still in place, then confirmed
      GREEN after the fix (`foo` stays `1.0.0`). The member-dir `remove`
      branch (S11e delegate-to-workspace path) was audited and confirmed
      already correct — it independently loads `shared_prior` via
      `load_lockfile(&ws_lock_path).ok()` (same soft-fail semantics) and
      already threads it into `resolve_workspace_with_features(...)`; left
      unchanged. Gating: `./dev-rust test --workspace` exit 0, all crates
      green (two independent full runs, incl. milpa-cli 130 passed —
      +1 over the 129 baseline above); `cd impls/python && uv run pytest`
      exit 0, 3274 passed / 33 skipped (Python untouched, unaffected).
  - **Gating:** `cd impls/python && uv run pytest --junit-xml=…` exit 0,
    **3298 passed / 33 skipped**, 0 failures/errors (3277 C2 baseline + 21
    new: 9 resolution-block-parse + 4 writer-roundtrip + 3 bypass + 6
    CLI-precedence — verified via exact `--junit-xml` counts, not terminal
    output). `./dev-rust test --workspace` — ran to completion (not just
    build), exit 0, **1301 passed across all crates, 0 failed** (main.rs 129
    [126+7 new incl. 2 rewrites], milpa-core 834 [831+3 new], milpa-manifest
    217 [213+4 new], milpa-solver 49, milpa-types 17, 3 `milpa-cli` integration
    test binaries 16+6+8, milpa-conformance 19+2+4 — includes
    `rust_error_catalog_is_a_bijection_with_the_spec` and
    `conformance_corpus`, both green, no fixture changes needed since C3
    added no new manifest-parsing behavior any existing fixture exercises).
  - **Files touched:** `impls/python/milpa/manifest.py` (`Resolution`,
    `_parse_resolution_block`, `_parse_resolution_strategy_node`, top-level
    sets, both parse-doc functions, both formatters); `impls/python/milpa/
    errors.py` (2 slugs); `impls/python/milpa/resolver.py`
    (`_bypasses_lock_preference`, `preference` call site);
    `impls/python/milpa/cli.py` (`_add_strategy_arg`,
    `_resolve_effective_strategy`, global-flag removal, 7 subparser
    registrations, `main()`'s `cli_strategy` computation, 13 call-site edits);
    `impls/python/tests/test_manifest_parse.py`,
    `test_manifest_writer.py` (existing files, new tests);
    `impls/python/tests/test_c3_strategy_bypass.py`,
    `test_c3_strategy_cli.py` (new files); `spec/errors.md` (2 entries);
    `spec/cli-contract.md` (§0.4, §2.3, new §2.10); `spec/manifest-grammar.md`
    (§3.1, new `resolution` subsection, §7); `impls/rust/crates/milpa-solver/
    src/lib.rs` (`Strategy::parse`); `impls/rust/crates/milpa-manifest/
    src/lib.rs` (`Resolution`, both structs' field, both top-level lists,
    `MAN_CODES`, `check_resolution_block`/`check_resolution_strategy`, both
    parse-doc functions); `impls/rust/crates/milpa-manifest/src/format.rs`
    (both emitters + 2 new tests); `impls/rust/crates/milpa-manifest/
    src/tests.rs` (6 new); `impls/rust/crates/milpa-core/src/workspace.rs`
    (`LoadedWorkspace.resolution`, 3 construction sites);
    `impls/rust/crates/milpa-core/src/resolver.rs`
    (`ResolveProvider.strategy` field + `new()` param, `ProviderOpts.strategy`
    + `build_single_provider`, `bypasses_lock_preference`, all `ResolveProvider
    ::new`/`ProviderOpts{}` call sites); `impls/rust/crates/milpa-core/
    src/resolver_tests.rs` (3 new + `c3_direct_transitive_index_and_registry`/
    `c3_prior_lock` helpers); `impls/rust/crates/milpa-cli/src/main.rs`
    (`Cli` struct, `parse_args`, `strategy_flag_value`,
    `resolve_effective_strategy`, `run()` dispatch, all 7 `cmd_*` function
    signatures + bodies, 2 rewritten + 5 new unit tests + 3 new CLI-precedence
    tests, ~54 mechanical `Some(...)`-wrap fixes); this handoff.
- **D0 — DONE (Rust-only prerequisite, both impls green).** Moved `Timestamp`
  + `parse_iso8601_timestamp` from `milpa-core::registry` down to the leaf
  `milpa-types` crate (`milpa-core::registry` re-exports both for
  back-compat — pure move, no behavior change) so `milpa-manifest` (which
  cannot depend on its own downstream crate `milpa-core`, a Cargo cycle) can
  reach the shared timestamp parser for D1's manifest parse. Python has no
  cycle (`registry.py`'s `_parse_timestamp` imports cleanly into
  `manifest.py`), so D0 was Rust-only.
- **D1 — DONE, both impls green.** Manifest `resolution { exclude-newer }` —
  parse + validate + round-trip only (CLI `--exclude-newer`/index filter/git
  validation/lockfile recording are later slices, D2–D5, explicitly out of
  scope here). Mirrors C3's `strategy` child exactly: `exclude-newer` is a
  new, independent sibling child of the same `resolution { }` block (a block
  may declare `strategy`, `exclude-newer`, both, or neither).
  - **Python:** `Resolution` (`manifest.py`) gained `exclude_newer: datetime |
    None = None`. New `_parse_resolution_exclude_newer_node(n)` (mirrors
    `_parse_resolution_strategy_node`'s strictness) reuses the shared
    registry-protocol timestamp parser — `_parse_timestamp` (`registry.py:780`,
    imported into `manifest.py`, no cycle) — rather than a second parser;
    malformed arity/type or an unparseable timestamp raises
    `MAN_RESOLUTION_EXCLUDE_NEWER_INVALID`. That parser is deliberately
    fail-soft for its own callers (`published_at`/`yanked_at` fall back to
    absent per registry-protocol §3.2); D1 escalates a `None` result to a hard
    parse error instead, since `resolution { exclude-newer }` is a manifest
    declaration, not an optional informational index field.
    `_RESOLUTION_KNOWN_CHILDREN` extended to `{"strategy", "exclude-newer"}`;
    `_parse_resolution_block` wires the new child in, sharing the existing
    unknown/duplicate-child → `MAN_RESOLUTION_BLOCK_INVALID` guard. New
    `_format_resolution_timestamp(dt)` (manifest.py) — the round-trip
    formatter, the inverse of `_parse_timestamp` — normalizes to UTC (mirrors
    Rust's `Timestamp`'s "always a normalized UTC instant" contract) and
    renders canonical `...Z` (never `+00:00`), with sub-second precision only
    when present. Both `format_manifest`/`format_workspace_manifest` emit
    `exclude-newer "<ts>"` inside `resolution { }` when set (absent-stays-absent,
    same rule as `strategy`).
  - **Rust:** `Resolution` (`milpa-manifest/src/lib.rs`) gained
    `pub exclude_newer: Option<Timestamp>` (still `Copy` — `Timestamp` is
    `Copy`). New `check_resolution_exclude_newer(node)` (mirrors
    `check_resolution_strategy`) reuses `milpa_types::parse_iso8601_timestamp`
    (D0); malformed → `MAN-RESOLUTION-EXCLUDE-NEWER-INVALID`.
    `RESOLUTION_KNOWN_CHILDREN` extended to `["strategy", "exclude-newer"]`;
    `check_resolution_block` wires it in via a `match` alongside `strategy`.
    New `milpa_types::format_iso8601_timestamp(&Timestamp) -> String` (SSOT
    formatter, alongside the parser, for reuse by D5's future lockfile
    emission) — the inverse of `parse_iso8601_timestamp`; new private
    `civil_from_days` (Howard Hinnant's algorithm, the inverse of the
    existing `days_from_civil`) computes the calendar date from the
    normalized Unix-seconds instant. Both `format_manifest`/
    `format_workspace_manifest` (`format.rs`) emit `exclude-newer "<ts>"`
    inside `resolution { }` when set, same gating as `strategy`. Fixed 6
    pre-existing `Resolution { strategy: … }` struct-literal construction
    sites across `milpa-core/src/frozen_tests.rs` (2),
    `milpa-manifest/src/tests.rs` (1), `milpa-manifest/src/format.rs` (3) to
    add the new field (Rust struct literals have no defaults) — mechanical,
    no behavior change to the C3 tests themselves.
  - **Tests — Python:** `test_manifest_parse.py::TestResolutionBlockParse`
    gained 7 (exclude-newer-parses, malformed→INVALID, wrong-arity→INVALID,
    duplicate-child→BLOCK-INVALID, strategy-and-exclude-newer-both-parse,
    unknown-child-still-BLOCK-INVALID-with-known-children-present,
    workspace-root-exclude-newer-parses); `test_manifest_writer.py` gained 5
    (emit-only-when-present, format→parse round-trip, strategy+exclude-newer
    together round-trip, `mutate_manifest_file` round-trip pin,
    `mutate_workspace_manifest_file` round-trip pin). **Rust:**
    `milpa-manifest/src/tests.rs` gained 8 (3 error-table rows mirroring
    Python's cases + `resolution_exclude_newer_present_and_absent` +
    `resolution_strategy_and_exclude_newer_both_parse` +
    `resolution_unknown_child_still_invalid_with_known_children_present` +
    `workspace_resolution_exclude_newer_present_and_absent`); `format.rs`
    gained 3 (`resolution_exclude_newer_emitted_only_when_present`,
    `resolution_exclude_newer_round_trips`,
    `resolution_strategy_and_exclude_newer_both_round_trip`); `milpa-types/
    src/lib.rs` gained 6 (`format_iso8601_round_trips_whole_seconds`,
    `format_iso8601_round_trips_arbitrary_instant`,
    `format_iso8601_normalizes_an_offset_to_utc_z`,
    `format_iso8601_omits_fraction_when_zero`,
    `format_iso8601_includes_fraction_when_present`,
    `civil_from_days_is_the_inverse_of_days_from_civil`).
  - **New slug:** `MAN-RESOLUTION-EXCLUDE-NEWER-INVALID` — `errors.py` +
    `spec/errors.md` (§MAN, alphabetically between `MAN-RESOLUTION-BLOCK-
    INVALID` and `MAN-RESOLUTION-STRATEGY-INVALID`) + Rust `MAN_CODES` —
    bijection green both impls, no DEFERRED/EXEMPT entry needed.
  - **Spec updates:** `spec/manifest-grammar.md` §3.1's `resolution` block
    subsection rewritten to document both children together (grammar
    example now shows `strategy` + `exclude-newer` side by side), with a new
    NORMATIVE clause for `exclude-newer`'s arity/parse/hard-fail-vs-registry-
    fail-soft contrast and its D1-scope note (later Axis D slices — CLI
    override, index filter, git validation, lockfile recording — are
    explicitly out of scope here).
  - **No divergence found.** Both impls' block parser, emitter, and slug
    placement mirror each other exactly; no fork encountered.
  - **Gating:** `cd impls/python && uv run pytest -q` exit 0, all tests
    passed (12 new: 7 parse + 5 writer, no failures/regressions).
    `./dev-rust test --workspace` — ran to completion, exit 0, **all crates
    green**: `milpa-cli` 130 passed (unchanged — D1 touched no CLI code),
    `milpa-core` 836 passed (unchanged — D1 touched no resolver code),
    `milpa-manifest` 224 passed (213 C3 baseline + 11 new: 8 `tests.rs` + 3
    `format.rs`), `milpa-solver` 49 passed (unchanged), `milpa-types` 26
    passed (20 baseline + 6 new `format_iso8601_*`/`civil_from_days_*`),
    plus `milpa-conformance`'s `rust_error_catalog_is_a_bijection_with_the_
    spec` and `conformance_corpus` both green (no fixture changes needed —
    D1 added no new manifest-parsing behavior any existing fixture
    exercises; D1 is manifest-parse-only, no conformance fixtures added per
    the task's explicit scope — D6 owns that).
  - **Files touched:** `impls/python/milpa/manifest.py` (`Resolution.
    exclude_newer`, `_parse_resolution_exclude_newer_node`,
    `_format_resolution_timestamp`, `_RESOLUTION_KNOWN_CHILDREN`,
    `_parse_resolution_block`, both formatters, new `datetime`/`_parse_
    timestamp` imports); `impls/python/milpa/errors.py` (1 slug);
    `impls/python/tests/test_manifest_parse.py`,
    `test_manifest_writer.py` (existing files, new tests);
    `spec/errors.md` (1 entry); `spec/manifest-grammar.md` (§3.1 `resolution`
    subsection rewrite); `impls/rust/crates/milpa-types/src/lib.rs`
    (`format_iso8601_timestamp`, `civil_from_days`, 6 new tests);
    `impls/rust/crates/milpa-manifest/src/lib.rs` (`Resolution.
    exclude_newer`, `check_resolution_exclude_newer`,
    `RESOLUTION_KNOWN_CHILDREN`, `check_resolution_block`, `MAN_CODES`, new
    `milpa_types` imports); `impls/rust/crates/milpa-manifest/src/format.rs`
    (both emitters + 3 new tests + 3 fixed struct literals);
    `impls/rust/crates/milpa-manifest/src/tests.rs` (8 new tests + 1 fixed
    struct literal + 3 new error-table rows); `impls/rust/crates/milpa-core/
    src/frozen_tests.rs` (2 fixed struct literals); this handoff.
- **D2 — DONE, both impls green.** CLI `--exclude-newer <ts>` on `fetch`/
  `lock` ONLY (narrower than `--strategy`'s per-resolve-verb scoping — §3
  Axis D "Verb reach": a CLI time-bound override is a fetch/lock-time CI
  concern; `add`/`update`/`remove`/workspace add-member/remove-member do
  not accept the flag at all) + precedence (CLI > manifest `resolution {
  exclude-newer }` > `None` — deliberately only 2 tiers, no lockfile-
  recorded third tier the way `--strategy` has one) + threading the
  effective value to the resolve entry point as an inert value (D3/D4 will
  consume it; D2 is JUST the flag + precedence + threading, no filter/
  validation behavior built).
  - **Python:** new `_resolve_effective_exclude_newer(cli_exclude_newer,
    manifest)` (`resolver.py`, mirrors `_resolve_effective_strategy`'s shape
    and `getattr(manifest, "resolution", None)` pattern, but only 2 tiers).
    `ResolveParams` (`context.py`) gained `exclude_newer: datetime | None =
    None` — rides `self._params` into `_Provider` for free (same seam
    `strategy` already uses), unused for now. New `_add_exclude_newer_arg`
    argparse helper (`cli.py`), registered on `sp_fetch`/`sp_lock` ONLY
    (not `add`/`remove`/`update`/`workspace add-member`/`remove-member`).
    `main()` parses the raw value with the shared `_parse_timestamp`
    (`registry.py`, reused by D1's manifest node too); a malformed value
    raises `MilpaError(CLI_EXCLUDE_NEWER_INVALID, …)` (exit 1 + slug) —
    NOT an argparse usage error (unlike `--strategy`, which is a closed
    `choices=` enum; a timestamp has no such enum). Threaded through
    `cmd_fetch`/`_cmd_fetch_workspace`/`cmd_lock`/`_cmd_lock_workspace`
    (4 sites) exactly the same way `strategy` is: the CLI value is passed
    down, then resolved to the effective value against that verb's own
    parsed manifest, then set on `ResolveParams`. `add`/`update`/`remove`/
    workspace add-member/remove-member deliberately left untouched (their
    `ResolveParams(...)` construction defaults `exclude_newer=None` — D2's
    explicit scope is fetch/lock CLI + precedence correctness only; full
    verb-reach parity for those verbs is D3/D4's concern once there's real
    behavior to plumb).
  - **Rust:** new `exclude_newer_flag_value(rest)` (`main.rs`, mirrors
    `strategy_flag_value` but returns `Result<Option<Timestamp>, MilpaError>`
    — a malformed/missing value is `Err(MilpaError::Core(CoreError::
    Resolver("CLI-EXCLUDE-NEWER-INVALID", …)))`, a real diagnosed failure,
    NOT `strategy_flag_value`'s bare `Err(())` usage error) + new
    `resolve_effective_exclude_newer(cli, resolution)` (mirrors
    `resolve_effective_strategy`, 2-tier). `run()` computes
    `exclude_newer_cli: Option<Timestamp>` scoped to `matches!(cli.verb.
    as_str(), "fetch" | "lock")` — narrower than `strategy_cli`'s 6-verb
    match arm — and propagates a parse error via `?`. Unlike Python,
    adding a new parameter to `resolve_with_features`/
    `resolve_workspace_with_features`/`resolve_with_cert`/
    `resolve_workspace_with_cert` is a REQUIRED positional-arg change (no
    keyword defaults in Rust), so EVERY existing caller of those 4
    functions had to supply a value regardless of verb — this forced
    `update`/`add`/`remove` callers (which have no CLI flag) to also pass
    `resolve_effective_exclude_newer(None, manifest.resolution)` "for
    free," giving those verbs genuine manifest-only verb-reach parity as a
    byproduct of Rust's static signatures (NOT a deliberate scope
    expansion — Python's dataclass-default seam simply didn't force the
    same call-site touch). Stored as a new `exclude_newer: Option<Timestamp>`
    field on `ProviderOpts`/`ResolveProvider` (mirrors `strategy`'s exact
    placement, `#[allow(dead_code)]` — unused for now, D3/D4 will read it).
    conformance `runner.rs`'s 3 call sites pass `None` (no fixture drives
    this yet — D6). The single-package `cmd_remove` path calls the bare
    `resolve()` wrapper (unchanged signature, always `None` internally) —
    a minor, deliberate, inert asymmetry vs. the workspace `cmd_remove`
    path (which gets the manifest-derived value "for free" per above);
    both are equally inert today, D3/D4 will need to resolve this same
    divergence when they wire real behavior.
  - **New slug:** `CLI-EXCLUDE-NEWER-INVALID` — `errors.py` + `spec/
    errors.md` (§CLI, alphabetically before `CLI-FEATURE-FLAGS-CONFLICT`)
    + Rust `CoreError::Resolver` + `error.rs`'s `all_codes()` — bijection
    green both impls (`rust_error_catalog_is_a_bijection_with_the_spec`
    passes).
  - **Spec updates:** `spec/cli-contract.md` new §2.11 (`--exclude-newer`
    NORMATIVE: fetch/lock-only scope, malformed-value slug, 2-tier
    precedence, verb-reach NOTE cross-referencing D-D1/D-D2/D-D3 as "not
    yet NORMATIVE in this document"); §5.1/§5.2 (`fetch`/`lock`)
    "Arguments" lines mention the new flag.
  - **Tests — Python:** new `tests/test_d2_exclude_newer_cli.py` (12
    tests): fetch/lock accept the flag end-to-end (mocked git, real
    `main(argv)`); update/add/remove reject it (argparse exit 2, a hard
    parse error since those subparsers never register it); malformed value
    → exit 1 + `CLI-EXCLUDE-NEWER-INVALID` in stderr; 3 pure-function
    precedence tests on `_resolve_effective_exclude_newer` (CLI-overrides-
    manifest, falls-back-to-manifest, None-when-both-absent); 2 real e2e
    precedence tests (CLI overrides manifest / unspecified CLI defers to
    manifest) asserting the fetch still succeeds (D2 doesn't change
    resolve *behavior*, just threads the value). **Rust:** 10 new `mod
    tests` cases in `main.rs` mirroring the C3 `strategy_flag_value` test
    block exactly: flag parses/absent-is-None/malformed-errors/missing-
    value-errors (unit, on `exclude_newer_flag_value`), 3 precedence unit
    tests on `resolve_effective_exclude_newer`, 2 real `run(&[…])` e2e
    tests (malformed value on fetch/lock → `err.code() ==
    "CLI-EXCLUDE-NEWER-INVALID"`), 1 e2e test proving `update` never even
    scans for the flag (a malformed value passed to `update` must NOT
    surface the CLI slug — mirrors how `--strategy` is silently
    not-registered on `show`/`clean` in this hand-rolled parser).
  - **Divergence reported, not fixed (out of scope, pre-existing,
    unrelated to D2):** 3 untracked conformance fixtures —
    `fixture-427/428/429-strategy-{minver,semver,maxver}-over-index` —
    apparently an in-progress, uncommitted C4 attempt from a concurrent/
    prior session, fail IDENTICALLY in both impls: each `expected/
    milpa.lock` names a dep `widget`, but the fixture's own `index.kdl`/
    `mocked-fetches/` resolves a *different* dep, `stratpkg` — a stale/
    unregenerated `expected/` file, not a resolver bug (both impls agree
    with each other, diverging only from the fixture's own golden file).
    Confirmed unrelated to D2 by code inspection (exclude-newer touches no
    named/index candidate-selection path) and by identical failure mode in
    both impls. `known_failing.txt` is intentionally empty (§4.3) and left
    that way — not parked, not fixed; flagged for whoever resumes C4.
  - **Gating:** `cd impls/python && uv run pytest -q --junit-xml=…` — with
    the 3 pre-existing/unrelated fixtures above deselected: **3327 tests,
    0 errors, 0 failures, exit 0** (3315 D1 baseline + 12 new D2 tests, no
    regressions). Full run (fixtures included): 3330 collected, 3 failures
    (the pre-existing ones above), all pre-D2 and reproducible without any
    D2 change. `./dev-rust test --workspace` — `milpa-cli` unittests 140
    passed (130 baseline + 10 new), `cli_index_history`/`cli_index_trust`/
    `cli_ws_index_trust_swallow` integration tests all green unchanged,
    `milpa-core` 836 passed unchanged (D2 touched no resolver *behavior*,
    only inert plumbing), `milpa-conformance` lib 19 passed unchanged incl.
    `rust_error_catalog_is_a_bijection_with_the_spec`; `conformance_corpus`
    reports the same 3 pre-existing regressions as Python (428 fixtures —
    389 pass, 36 skip cli-only, 3 regressions — all three are the
    strategy-over-index fixtures above, none newly introduced by D2).
  - **Files touched:** `impls/python/milpa/cli.py` (`_add_exclude_newer_arg`,
    CLI parse + dispatch threading, 4 cmd_* signatures), `context.py`
    (`ResolveParams.exclude_newer`), `resolver.py`
    (`_resolve_effective_exclude_newer`), `errors.py` (1 slug); new
    `impls/python/tests/test_d2_exclude_newer_cli.py`;
    `impls/rust/crates/milpa-cli/src/main.rs`
    (`exclude_newer_flag_value`, `resolve_effective_exclude_newer`, `run()`
    scoping, `cmd_fetch`/`cmd_fetch_with_cert`/`cmd_fetch_workspace_with_
    cert`/`cmd_update`/`cmd_add`/`cmd_remove` threading, 10 new tests, 24
    existing test call sites mechanically updated with a new trailing
    arg); `impls/rust/crates/milpa-core/src/resolver.rs`
    (`resolve_with_features`/`resolve_workspace_with_features`/
    `resolve_with_cert`/`resolve_workspace_with_cert`/
    `resolve_workspace_inner` signatures, `ProviderOpts`/`ResolveProvider`
    new field); `impls/rust/crates/milpa-core/src/error.rs` (1 slug in
    `all_codes()`); `impls/rust/crates/milpa-core/src/resolver_tests.rs`
    (3 call sites); `impls/rust/crates/milpa-conformance/src/runner.rs` (3
    call sites, `None`); `spec/errors.md` (1 entry); `spec/cli-contract.md`
    (§2.11 + §5.1/§5.2); this handoff.

- **D3 — DONE, both impls green (retroactive note).** Index/named-dep `published_at` filter at the
  enumeration layer (`RES-EXCLUDE-NEWER-EMPTY`). Found already implemented and fully gated at the
  start of the D4 session (`registry.py`'s `filter_by_exclude_newer` + `resolver.rs`'s mirror,
  `tests/test_d3_exclude_newer_enumeration.py`, and the `resolve_d3_*` block in `resolver_tests.rs`)
  but this handoff's own "D3 — DONE" write-up was never committed by whichever prior session/loop
  iteration landed it — a documentation gap, not a code gap (verified: full `uv run pytest` and
  `./dev-rust test --workspace`, including `conformance_corpus`, both green with D3's tests included,
  before any D4 edit was made). Recorded here so the next session doesn't mistake the missing
  write-up for missing work. No code changed by this note.
- **D4 — DONE, both impls green.** Git/url pinned-ref committer-date VALIDATION (§3 Axis D / §6
  D-D1/D-D2) — the git-dep analogue of D3, but validation (one candidate, no selection) rather than
  filtering. New slug `RES-EXCLUDE-NEWER-PIN`.
  - **The load-bearing rule (both impls, one mechanism): committer date, never tagger date.**
    Enforced structurally, not by a special case — the commit SHA read is always an already-peeled
    `^{commit}` object by the time the committer date is read (both the exact-pin
    `ensure_commit_present`/`_ensure_commit_present` path and the ref-resolution
    `try_resolve_ref`/`git_resolve_ref` paths dereference through any tag object before that point),
    so `git log -1 --format=%cI <sha>` on that SHA can never accidentally read an annotated tag
    object's own tagger timestamp.
  - **Python:** `fetchers/git.py` — new `GitReceipt.committer_date: datetime | None` field; new
    `_git_committer_date(name, p, repo, commit)` helper (`git log -1 --format=%cI --end-of-options
    <commit>`, parsed via `datetime.fromisoformat`), called inside `GitFetcher.fetch` right before
    `materialize_git_tree` (still inside the `try` block, so `clone_scratch` is present — a bounded
    transport addition, no extra network round trip, per the RFC's own D-D1 text). `resolver.py`'s
    `_process_url_worker` validates right after the fetch succeeds (`isinstance(result.receipt,
    GitReceipt)` guard — local/tarball receipts have no such field, so they are structurally
    unvalidated, per the RFC's explicit scope note): `committer_date > params.exclude_newer` raises
    `MilpaError(RES_EXCLUDE_NEWER_PIN, …)` naming the dep, commit SHA, committer date, and bound.
  - **Rust:** `fetch.rs` — new `Receipt.committer_date: Option<milpa_types::Timestamp>` (zero call-site
    churn: every existing `Receipt { .. }` literal already used `..Default::default()`). `fetchers.rs`
    — new `git_committer_date(name, url, repo, commit)` fn (same `%cI` read via `Command`, parsed with
    `milpa_types::parse_iso8601_timestamp`), called in `fetch_git` right before `materialize_git_tree`
    (before `ScratchGuard`'s `Drop` cleans up `clone_scratch`). `resolver.rs`'s `process_url` validates
    right after `fetch_any_tracked` returns: `receipt.committer_date > self.exclude_newer` (both
    `Option`s, `Timestamp` is `Copy`) returns `Err(res_err("RES-EXCLUDE-NEWER-PIN", …))` with the same
    payload shape as Python.
  - **New slug:** `RES_EXCLUDE_NEWER_PIN` = `"RES-EXCLUDE-NEWER-PIN"` — `errors.py` (between
    `RES_EXCLUDE_NEWER_EMPTY` and `RES_LOCKED_DRIFT`) + `spec/errors.md` (§RES, same position) + Rust
    `CoreError::all_codes()` (`error.rs`) — bijection green both impls, no DEFERRED/EXEMPT entry
    needed.
  - **Tests (both impls, real git on generated local repos — no mocking, per the repo's H-infra
    pattern):**
    - Fetcher level — proves `committer_date` correctness directly, including the anti-tagger-date
      guard: a repo with one commit dated 2020-01-01 and an ANNOTATED tag on it minted under a
      deliberately later (2025-ish) `GIT_COMMITTER_DATE` env (the tag's own tagger timestamp).
      Python: `tests/test_d4_exclude_newer_git_validation.py::TestGitReceiptCommitterDate` (3 tests:
      tag ref, branch ref, exact-commit pin — all assert `committer_date == the COMMIT's date`, and
      the tag-ref case additionally asserts it `!=` the tag's date). Rust: 3 new tests in
      `fetchers_tests.rs` (`fetch_git_committer_date_via_tag_ref_is_the_commits_date_not_the_tags` /
      `_via_branch_ref` / `_via_exact_commit_pin`), same fixture shape
      (`make_repo_with_dated_commit_and_tag`, mirrors Python's `_make_repo_with_annotated_tag`).
    - Resolver level — proves the wiring end to end. Python drives a REAL `GitFetcher` (wrapped in
      `CasAdmittingFetcher`) through a real `resolve()` against the same annotated-tag fixture
      (`tests/test_d4_exclude_newer_git_validation.py::TestExcludeNewerGitValidation`, 6 tests:
      commit-predates-bound via tag ref / via branch ref, the anti-tagger-date guard end to end
      — a bound BETWEEN the commit's date and the tag's tagger date, which only passes if
      validation reads the commit's date — commit-exceeds-bound via tag ref / via branch ref
      → `RES-EXCLUDE-NEWER-PIN` naming the dep and commit SHA, and the no-bound regression). Root
      manifests were constructed directly as `Manifest(deps=(UrlDep(...),))` rather than via
      `parse_manifest`/KDL text, because the manifest-level git-URL scheme guard
      (`_validate_git_url`) rejects `file://` at PARSE time (only https/http/ssh/git are declarable
      in `milpa.kdl`) — a manifest-declaration concern orthogonal to what this slice tests; this is
      the same bypass the shared git-protocol conformance tier uses (it calls the fetcher registry
      directly, skipping manifest parse entirely). Rust mirrors this at the `resolve_with_features`
      layer using `FakeReg`'s existing mock convention (consistent with D3's own `d3_resolve`
      pattern, and with how every other Rust resolver test in this file works — no real git
      subprocess at the resolver layer in Rust, only at the fetcher layer above): `Mock` gained a
      `committer_date: Option<i64>` field (unix seconds, zero call-site churn — `Mock` also derives
      `Default` and every existing literal already used `..Mock::default()`), wired into the git
      match arm's `Receipt` construction. 4 new `resolve_d4_*` tests in `resolver_tests.rs`:
      commit-predates-bound resolves cleanly, commit-exceeds-bound hard-fails naming the dep+SHA
      (checked via `format!("{err:?}")`, not `.to_string()` — this crate's own design note is that
      the harness/tests assert on `.code()` only, message text is not a checked surface), no-bound
      regression, and a receipt with no `committer_date` at all (mirrors local/tarball) is never
      validated even under a bound that would otherwise fail.
  - **No conformance-corpus fixture added** — explicitly D6's scope per the RFC ledger, not D4's;
    the git-fetcher-level real-git test above satisfies this slice's own TDD directive.
  - **Divergence:** none found. Both impls' committer-date read, validation predicate, and slug are
    identical; the resolver-test-layer difference (Python drives a real `GitFetcher`/`resolve()`,
    Rust uses `FakeReg`'s mock) is a pre-existing convention difference between the two suites'
    resolver-test infra (D3's own tests already split the same way), not a D4-introduced divergence.
  - **Gating:** `cd impls/python && uv run pytest --junit-xml=…` exit 0, **3348 tests, 0 errors, 0
    failures, 33 skipped** (10 new: 3 fetcher-level + 6 resolver-level D4 tests, +1 from an unrelated
    parametrization wash). `./dev-rust test --workspace` — ran to completion (full untruncated log),
    exit 0: `milpa-cli` 140 + 16 + 6 + 8 passed (unchanged — D4 touched no CLI code), `milpa-core` 852
    passed (incl. the 7 new tests: 3 `fetchers_tests.rs` + 4 `resolver_tests.rs`), `milpa-manifest` 224
    passed (unchanged), `milpa-solver` 49 passed (unchanged), `milpa-types` 26 passed (unchanged),
    `milpa-conformance` lib 19 passed + the separate 2-test binary both green
    (`rust_error_catalog_is_a_bijection_with_the_spec` and `conformance_corpus`, no fixture changes
    needed — D4 is fetcher/resolver-validation-only, D6 owns the shared-corpus fixture).
  - **Files touched:** `impls/python/milpa/fetchers/git.py` (`GitReceipt.committer_date`,
    `_git_committer_date`, wired into `GitFetcher.fetch`); `impls/python/milpa/resolver.py`
    (`_process_url_worker`'s validation block); `impls/python/milpa/errors.py`
    (`RES_EXCLUDE_NEWER_PIN`); `impls/python/tests/test_d4_exclude_newer_git_validation.py` (new);
    `impls/rust/crates/milpa-core/src/fetch.rs` (`Receipt.committer_date`);
    `impls/rust/crates/milpa-core/src/fetchers.rs` (`git_committer_date`, wired into `fetch_git`, 3
    new tests via `fetchers_tests.rs`); `impls/rust/crates/milpa-core/src/resolver.rs`
    (`process_url`'s validation block); `impls/rust/crates/milpa-core/src/resolver_tests.rs`
    (`Mock.committer_date`, 4 new `resolve_d4_*` tests + helpers); `impls/rust/crates/milpa-core/src/
    error.rs` (1 slug in `all_codes()`); `spec/errors.md` (`RES-EXCLUDE-NEWER-PIN`); this handoff.
- **D5 — DONE, both impls green.** Lockfile top-level `exclude_newer` (record + round-trip),
  `FROZEN-EXCLUDE-NEWER-MISMATCH` (manifest-sourced baseline, built the C3b way from the start),
  and no-silent-drop (§6 D-D3): `--locked` flags a dropped/changed bound as drift;
  `update`/`remove`/workspace add-member/remove-member carry the prior lock's bound forward.
  - **Record + round-trip (both impls):** `Lockfile` gained an `exclude_newer: datetime | None`
    (Python) / `Option<Timestamp>` (Rust) field, mirroring `strategy`'s exact positioning
    (emitted right after `strategy`, before the blank-line separator) but OPTIONAL — omitted
    entirely when unset (never a sentinel timestamp), unlike `strategy` (required,
    `LOCK-STRATEGY-MISSING` on absence). Parse: a present-but-malformed node (wrong arity,
    non-string, or an unparseable ISO 8601 value) raises `LOCK-FIELD-ARITY`/`LOCK-FIELD-TYPE` —
    reuses the existing generic scalar-field slugs (mirrors `version`'s own convention), no new
    slug needed for parsing. `from_graph`/`format_lockfile`/`parse_lockfile` (Python) and
    `from_graph`/`format_lockfile`/`parse_lockfile` (Rust, new `scalar_timestamp` helper mirroring
    `scalar_u32`) all thread the value through.
  - **`FROZEN-EXCLUDE-NEWER-MISMATCH` (both impls):** new `_frozen_baseline_exclude_newer`
    (Python `frozen.py`) / `frozen_baseline_exclude_newer` (Rust `frozen.rs`) — built
    manifest-sourced FROM THE START (calls `_resolve_effective_exclude_newer(None, manifest,
    None)` / the Rust equivalent, prior=None deliberately since the frozen path's lockfile IS
    the value being compared against), mirroring EXACTLY how C3b fixed
    `FROZEN-STRATEGY-MISMATCH`'s baseline — never a hardcoded/omitted comparison. Wired into both
    `resolve_frozen`/`resolve_workspace_frozen` (single-package + workspace-root, root-only
    authority same as strategy/index-trust/entry-trust).
  - **No-silent-drop, the load-bearing design point (§6 D-D3):** `resolve_effective_exclude_newer`
    (both impls) gained a THIRD precedence tier — `prior.exclude_newer` — but **callers choose
    whether tier 3 is live by what they pass for `prior`**:
    - `fetch`/`lock` (the only verbs with a CLI `--exclude-newer` surface) pass `prior=None`,
      collapsing to the ORIGINAL 2-tier chain (CLI > manifest > `None`) D2 built. An absent CLI
      flag + absent manifest is therefore a genuine "nothing declared this run" result for these
      two verbs — which is exactly what makes `--locked`'s drift check meaningful: comparing this
      honest 2-tier value against the committed lock's recorded value is how a real drop gets
      caught. (Tried tier-3-for-everyone first; it made `--locked`'s own drop-detection
      structurally unreachable for fetch/lock, since the effective value would always equal
      whatever the lock already recorded — caught by a failing self-authored test, fixed by
      scoping tier 3 to callers without a CLI surface instead.)
    - `add`/`update`/`remove`/workspace add-member/remove-member (no CLI override at all) pass the
      REAL on-disk prior lockfile — tier 3 carries a bound forward when the manifest doesn't
      declare its own, closing the hole where a one-off `fetch --exclude-newer <ts>` (never
      mirrored into `resolution {}`) would otherwise silently vanish on the next `update`/`remove`.
    - Rust's `cmd_remove` single-package branch had a genuine PRE-EXISTING structural gap (not
      D5-introduced, but D5 is what required fixing it): it called the bare `resolve()`
      convenience wrapper, which hardcodes `exclude_newer: None` internally (same "backward-compat
      wrapper" pattern as `resolve_workspace`) — switched to `resolve_with_features` (same defaults
      `resolve()` uses) so a real effective value can be threaded through. Python's `cmd_remove`
      had no equivalent gap (its `ResolveParams` object already defaulted the field harmlessly;
      only needed a real value supplied). Rust's `apply_workspace_manifest_change`
      (`manifest_writer.rs`, used by `workspace add-member`/`remove-member`) had the SAME gap
      (called `resolve_workspace`, the same kind of hardcoded-`None` wrapper) — gained a new
      `exclude_newer` parameter, threaded to `resolve_workspace_with_features`.
    - `check_locked_drift`/`check_locked_drift` (both impls) gained a new `exclude_newer` parameter
      — the effective value the `--locked` resolve just ran under — compared once against
      `prior.exclude_newer` for the WHOLE lockfile (not per-dep, unlike identity/provenance).
  - **New slug:** `FROZEN-EXCLUDE-NEWER-MISMATCH` — `errors.py` + `spec/errors.md` (§FROZEN,
    alphabetically between `FROZEN-CONSTRAINT-UNSATISFIED` and `FROZEN-IDENTITY-NOT-IN-STORE`) +
    Rust `CoreError::all_codes()` — bijection green both impls
    (`rust_error_catalog_is_a_bijection_with_the_spec` passes), no DEFERRED/EXEMPT entry needed.
  - **Spec updates:** `spec/lockfile-schema.md` — normative-surface item 13, §2's example +
    new §2.2a (`exclude_newer` node, mirrors §3.2a's additive-field style), Appendix B error table.
    `spec/resolver-semantics.md` — §7.1's closed FROZEN-* precondition list gained item 10 +
    Appendix A error table. `spec/cli-contract.md` §2.11 — precedence NORMATIVE rewritten (no
    longer claims "no lockfile tier" unconditionally — now scoped to fetch/lock specifically) +
    new no-silent-drop NORMATIVE clause.
  - **Tests:** Python — new `tests/test_d5_lockfile_exclude_newer.py` (21 tests): lockfile
    parse/format round-trip (absent/present/malformed × arity+type), `from_graph` carries the
    value through, `fetch --exclude-newer` records it end-to-end, `FROZEN-EXCLUDE-NEWER-MISMATCH`
    (single-package + workspace: matching passes, genuine divergence + newly-added-vs-absent both
    fail), `update`/`remove` carry-forward (no-silent-drop), `--locked` flags a drop as
    `RES-LOCKED-DRIFT` and passes when unchanged. Rust — 9 new `lockfile.rs` unit tests (parse
    absent/present/malformed ×3, emit-omitted/emit-positioned/round-trip, `from_graph` carries
    through) + 4 new `check_locked_drift_*` tests (dropped/changed/unchanged/newly-added) +
    7 new `frozen_tests.rs` tests (single-package mismatch/baseline-follows/genuine-divergence/
    default-none-unchanged + workspace-root follows/genuine-divergence) + 5 new `main.rs` tests
    (`resolve_effective_exclude_newer` prior-fallback + manifest-wins-over-prior + none-when-all-
    absent, `update_carries_forward_exclude_newer_no_silent_drop`,
    `remove_carries_forward_exclude_newer_no_silent_drop`, `locked_flags_dropped_exclude_newer_
    as_drift`, `locked_passes_when_exclude_newer_unchanged`).
  - **Divergence:** none found beyond the pre-existing `resolve()`/`resolve_workspace`
    hardcoded-`None` wrapper gaps described above (Rust-only, language-forced by static function
    signatures — Python's `ResolveParams` object has no equivalent "convenience wrapper drops a
    field" failure mode) — reported, fixed (not left latent), not a cross-impl behavior fork.
  - **Self-caught bug (worth flagging):** a self-authored Rust test
    (`locked_flags_dropped_exclude_newer_as_drift`) initially FAILED for the right reason — it
    revealed that giving `fetch`/`lock` the same tier-3 carry-forward as `update`/`remove` would
    make `--locked`'s own no-silent-drop check unreachable (the effective value would always
    already equal the lock's recorded value). Fixed by scoping tier 3 to prior=None for
    fetch/lock specifically (see the no-silent-drop bullet above) — caught before landing, not
    a shipped regression.
  - **Gating:** `cd impls/python && uv run pytest -q --junit-xml=…` exit 0, **3369 tests, 0
    errors, 0 failures, 33 skipped** (3348 D4 baseline + 21 new D5 tests). `./dev-rust test
    --workspace` — ran to completion (both a full combined run AND independent per-crate runs,
    all agreeing), exit 0, **1341 passed across all crates, 0 failed**: `milpa-types` 26,
    `milpa-solver` 49, `milpa-manifest` 224 (all three unchanged — D5 touched no manifest/solver/
    types-parsing behavior beyond the additive `Lockfile.exclude_newer` field itself),
    `milpa-core` 871 (852 D4 baseline + 19 new: 9 `lockfile.rs` round-trip + 4
    `check_locked_drift_*` + 6 `frozen_tests.rs`), `milpa-cli` 146 (141 D4 baseline + 5 new D5
    tests), `milpa-conformance` 19 (lib) + 2 (`corpus.rs`:
    `rust_error_catalog_is_a_bijection_with_the_spec` + `conformance_corpus`, no fixture changes
    — D5 is lockfile/frozen/drift-only, D6 owns the shared-corpus fixture) + 4 (`self_test.rs`).
  - **Files touched:** `impls/python/milpa/lockfile.py` (`Lockfile.exclude_newer`,
    `_parse_top_exclude_newer`, `from_graph`, `format_lockfile`, `check_locked_drift`);
    `impls/python/milpa/frozen.py` (`_frozen_baseline_exclude_newer`, both resolve_frozen*
    functions, module docstring); `impls/python/milpa/resolver.py`
    (`_resolve_effective_exclude_newer`'s new `prior` tier); `impls/python/milpa/cli.py` (9
    additional call sites threading `exclude_newer` — verb-reach completion — + `cmd_show`'s
    header line + 4 existing `check_locked_drift`/`from_graph` call sites); `impls/python/milpa/
    manifest_writer.py` (both `from_graph` calls); `impls/python/milpa/errors.py`
    (`FROZEN_EXCLUDE_NEWER_MISMATCH`); new `impls/python/tests/test_d5_lockfile_exclude_newer.py`;
    `impls/rust/crates/milpa-types/src/lib.rs` (`Lockfile.exclude_newer` + `Default`);
    `impls/rust/crates/milpa-core/src/lockfile.rs` (`scalar_timestamp`, parse/format/`from_graph`/
    `check_locked_drift`, 13 new tests); `impls/rust/crates/milpa-core/src/frozen.rs`
    (`frozen_baseline_exclude_newer`, `check_exclude_newer`, both resolve_frozen* fns);
    `impls/rust/crates/milpa-core/src/frozen_tests.rs` (`lock_with_exclude_newer` helper, 7 new
    tests); `impls/rust/crates/milpa-core/src/manifest_writer.rs` (`apply_workspace_manifest_change`
    new param); `impls/rust/crates/milpa-core/src/manifest_writer_tests.rs` (4 call sites);
    `impls/rust/crates/milpa-core/src/error.rs` (1 slug); `impls/rust/crates/milpa-cli/src/main.rs`
    (`resolve_effective_exclude_newer` 3-tier + all 13 call sites, `cmd_remove` switched off the
    bare `resolve()` wrapper, `check_locked_drift`/`from_graph` call sites, 5 new tests);
    `impls/rust/crates/milpa-conformance/src/runner.rs` (4 `from_graph` call sites — live path
    passes `None`, frozen path re-emits `lock.exclude_newer` verbatim, mirroring `strategy`);
    `spec/errors.md`, `spec/lockfile-schema.md`, `spec/resolver-semantics.md`,
    `spec/cli-contract.md`; this handoff.

- **D6 — DONE, both impls green. AXIS D COMPLETE.** Axis-D conformance fixtures (7 new,
  `fixture-433`–`fixture-439`), differential parity confirmed (golden `expected/` generated by
  driving the REAL resolver through the harness's own `_REGEN_MODE`, never hand-fabricated).
  - **Harness gap found and fixed (both impls) — this WAS the blocking prerequisite, not a nice-
    to-have.** Before this slice the conformance harness's live `resolve`-cmd execution path
    (`test_conformance.py`'s `_execute_fixture` / Rust `runner.rs`'s `Cmd::Resolve` arm) hardcoded
    `exclude_newer=None`/`ResolveParams()` default and `from_graph(..., None)` unconditionally — a
    fixture's `resolution { exclude-newer }` manifest block was silently never read at all, and the
    reconstructed lockfile never recorded the bound even if it had been. D2/D5 landed the CLI/
    lockfile-recording machinery but never touched the CONFORMANCE HARNESS'S OWN call sites (the
    RFC's own D2/D5 slice comments in `runner.rs` said as much: `"D2 (resolution-semantics RFC §3
    Axis D): no conformance fixture drives exclude-newer yet (D6, later slice)"`, `None`). Fixed:
    - **`--exclude-newer <ts>` cmd-file token** (new §2.7.5 in `spec/conformance-fixtures.md`,
      mirrors C1's `--strategy` token exactly): `Fixture.exclude_newer` (Python,
      `test_conformance.py`) / `Fixture.exclude_newer: Option<String>` (Rust, `fixture.rs`), parsed
      the same way as `strategy`.
    - **Effective-value wiring**: the live `resolve` path now computes cmd-token > manifest's own
      `resolution { exclude-newer }` > `None` (2-tier, mirrors the CLI's `fetch`/`lock` verbs, NOT
      a 3rd `prior`-lockfile tier — that tier is `--locked`-only and this in-corpus token has no
      such flag) and threads it into `ResolveParams(exclude_newer=...)` / `resolve_with_features(...,
      exclude_newer)`. Python reuses the REAL production `_resolve_effective_exclude_newer` (imported
      from `milpa.resolver`, not reimplemented — SSOT); Rust inlines the same 2-tier precedence at
      each of the two `Cmd::Resolve` call sites (package + workspace) because the real
      `resolve_effective_exclude_newer` lives in the `milpa-cli` BINARY crate, which
      `milpa-conformance` (a library-only dependent of `milpa-core`/`milpa-types`) cannot depend on
      — same rationale `fixture_strategy` already documents for `Strategy`.
    - **`_diff_success` (Python) / the two `from_graph` call sites (Rust)** gained an
      `exclude_newer_override`/direct-value parameter (mirrors `strategy_override`, C4's own
      pattern) so the byte-diffed reconstructed `milpa.lock` records the SAME effective value the
      live resolve actually ran under, proving D5's "recorded in the lockfile" behavior
      structurally on every fixture that sets a bound (no separate fixture needed for that alone).
    - The frozen path needed NO wiring — `resolve_frozen`/`Milpa.resolve_frozen` already run
      `FROZEN-EXCLUDE-NEWER-MISMATCH`'s check internally (D5) and the harness's frozen call sites
      already re-emit `lock.exclude_newer` verbatim (D5's own commit); D6 only proves it at
      corpus granularity (fixture-438/439).
  - **Mocked-git `committer_date` (both impls) — the second harness gap.** The `mocked-fetches/`
    convention's `MockedGitFetcher`/`MockedFetcher` (`fetchers/mocked.py` / Rust `fetchers.rs`)
    always returned `GitReceipt(committer_date=None)` — a mocked git fixture could never carry a
    committer date at all, so D4's `RES-EXCLUDE-NEWER-PIN` validation (which no-ops on
    `committer_date is None`) was structurally unreachable from ANY conformance fixture. New
    OPTIONAL `committer_date` file (new §2.3.2 addendum, spec/conformance-fixtures.md) sibling to
    `sha`/`content/`/`<name>.nimble`: an ISO-8601 string, parsed via the SAME SSOT timestamp parser
    both impls already use for `published_at` (`registry.py`'s `_parse_timestamp` / Rust's
    `milpa_types::parse_iso8601_timestamp`) — no second parser. Absent → `None`, unchanged for
    every pre-D6 fixture (backward compatible by construction).
  - **Fixtures** (all under `conformance/spec-v1/`, real content_hash values computed via
    `compute_content_hash` over the actual staged mocked-fetches tree, never hand-typed):
    - `fixture-433-exclude-newer-index-selection` — D3 selection: 3-candidate index dep (widget
      1.0.0/1.5.0/2.0.0) with `published_at` straddling the bound; 2.0.0 is dropped, 1.5.0 (newest
      SURVIVOR) is picked — proves selection is genuinely different from plain maxver. Also
      structurally proves D5 (the reconstructed lock records `exclude_newer`).
    - `fixture-434-exclude-newer-index-empty` — D3's `RES-EXCLUDE-NEWER-EMPTY`: both candidates'
      `published_at` postdate the bound → the whole set empties → the distinct slug (error fixture).
    - `fixture-435-exclude-newer-git-pin-passes` — D4 passing case: a single-candidate git dep
      whose mocked `committer_date` predates the bound → resolves cleanly.
    - `fixture-436-exclude-newer-git-pin-fails` — D4 failing case: same shape, `committer_date`
      postdates the bound → `RES-EXCLUDE-NEWER-PIN` (error fixture).
    - `fixture-437-exclude-newer-tighten-over-locked-git-pin` — **THE D-D2 motivating LTS/security-
      freeze case**: a prior `milpa.lock` pins a branch-ref (`main`) git dep to a commit whose
      `committer_date` predates the bound as originally locked; the manifest's `resolution {
      exclude-newer }` is TIGHTENED past that commit's date. The resolver reuses the locked pin
      (`_git_pin_for_url_dep`/Rust equivalent — reproducible-once-locked, D-D2) and validates its
      (unchanged) committer date against the NEW tighter bound → unconditional
      `RES-EXCLUDE-NEWER-PIN`, no fallback (unlike an index dep, a git dep has exactly one
      candidate — this is the asymmetry §6 D-D2 documents).
    - `fixture-438-frozen-exclude-newer-match` — D5 frozen parity, success: the lock's recorded
      top-level `exclude_newer` matches the manifest's effective `resolution { exclude-newer }` —
      `frozen` passes.
    - `fixture-439-frozen-exclude-newer-mismatch` — D5 frozen parity, negative: the lock's
      recorded `exclude_newer` is stale relative to the manifest's current effective value →
      `FROZEN-EXCLUDE-NEWER-MISMATCH` (error fixture).
  - **No divergence found.** Every fixture was authored, generated, and verified against BOTH
    runners before being accepted; there was no Python/Rust behavioral disagreement to report at
    any point in this slice.
  - **Tests**: `cd impls/python && uv run pytest` — 3376 passed, 0 failed, 0 errors, 33 skipped
    (full suite, incl. the 7 new corpus fixtures). `./dev-rust test -p milpa-conformance` —
    `conformance: 435 fixtures — 399 pass, 0 xfail (parked), 36 skip (cli-only), 0 xpass, 0
    regressions` (`known_failing.txt` stays EMPTY — the 7 new fixtures are un-parked and green from
    the start), plus 19+4 unit/self-tests green; `./dev-rust build -p milpa-cli` confirms the CLI
    binary crate still compiles (no `main.rs` call-site touched by this slice, but `Fixture`
    struct-literal sites in `runner.rs`'s own tests needed the new field).
  - **Files touched:** `impls/python/milpa/fetchers/mocked.py` (`MockedGitFetcher.fetch` reads
    optional `committer_date`); `impls/python/tests/test_conformance.py` (`Fixture.exclude_newer` +
    `_parse_exclude_newer`, live-resolve-path effective-value wiring via the real
    `_resolve_effective_exclude_newer`, `_diff_success`'s new `exclude_newer_override` param, both
    call sites); `impls/rust/crates/milpa-core/src/fetchers.rs` (`MockedFetcher`'s Git arm reads
    optional `committer_date`); `impls/rust/crates/milpa-conformance/src/fixture.rs`
    (`Fixture.exclude_newer` field + parse); `impls/rust/crates/milpa-conformance/src/runner.rs`
    (`fixture_exclude_newer_cli` + inlined 2-tier precedence at both `Cmd::Resolve` call sites, 6
    test-fixture struct literals gained the new field); `spec/conformance-fixtures.md` (new §2.7.5,
    §2.3.2 `committer_date` addendum); new `conformance/spec-v1/fixture-433`..`fixture-439`; this
    handoff.

## Axis A reshape (round 3, applied 2026-07-29 — Corey-driven)
Corey's two questions killed the round-2 satisfy-any/witness design: (1) don't anchor version-reading
on `.nimble` (we're replacing it), (2) satisfy-any is NOT best-in-class UX. Applied across §3/§4/§5/§6/§7:
- **Version source is manifest-agnostic:** `milpa.kdl version` (NEW field — milpa.kdl had none, only
  `spec-version`; required for the replace-.nimble SSOT goal) → `.nimble` adapter → git tag → NEW
  **`version=` annotation** on the dep decl (Cargo `{git,version}` pattern; distinct from override #50
  = "fill a missing fact" vs "replace a decision") → version-unknown.
- **version-unknown → constrained/unconstrained PARTITION (replaces satisfy-any + witness):**
  (i) unconstrained → just works via existing `0.0.1` sentinel vs `full()` self-term (no ceremony,
  fresco/intonaco case); (ii) constrained + version present → normal solving, real conflict detection;
  (iii) constrained + no version → **HARD ERROR `RES-VERSION-UNKNOWN-CONSTRAINED`** (milpa refuses to
  guess). **DELETES round-2 witness synthesis (A4a/A4b) + its pubgrub-panic risk entirely.**
- New slugs: `RES-VERSION-UNKNOWN-CONSTRAINED`, `MAN-PACKAGE-VERSION-INVALID`, `MAN-DEP-VERSION-INVALID`
  (13 total). Slices: A1 now parses milpa.kdl+`.nimble`; +A3b `version=` grammar; A4 = partition (not
  witness). ≈31 slices.

## Architect round 3 — applied (2026-07-29). Stage 2 COMPLETE.
Ran the 4-lens team against the reshaped RFC. **1 Critical (depth+feasibility converged) + a cluster
of clear-best fixes; ZERO genuine forks** — the Critical resolved to a clean mechanism under the bar.
- **CRITICAL RESOLVED — the partition is NOT a pre-solve pre-pass.** milpa's provider materializes
  named/index constrainers *lazily mid-solve*, so a version-unknown git dep can be classified
  "unconstrained" before its constrainer (e.g. a tianguis index dep flooring it) is expanded → decided
  via sentinel → later degrades to generic `SOLVE-CONFLICT`, not the crisp slug. This is the
  architecturally COMMON shape (amoxtli's own). **Fix (feasibility, clean, both impls): decision-PRIORITY
  rule** — version-unknown packages get strictly LOWEST decision priority, so when PubGrub finally
  decides one, its accumulated range is complete → classify at that decision point (`effective_set`/
  `choose_version` range, APIs already exist + cheap). Rust: `prioritize` one-liner. Python: reconcile
  with NORMATIVE `_next_undecided` BFS-order invariant (fixture-063) — A4 sub-task. NO conflict-path
  introspection, NO witness. A6 fixture must use a *lazily-materialized named* constrainer declared
  *before* the version-unknown dep to actually exercise the hazard.
- **`--strategy` bypass footgun (design+breadth CRITICAL/HIGH converged).** Bypass gated on *flag
  presence* → `milpa fetch --strategy maxver` (typing the default) silently flips whole graph to
  newest-wins = #192. Fix: gate on *effective strategy ≠ `lockfile.strategy`*. Also C3 now: `--strategy`
  → `Option<Strategy>` sentinel (can't distinguish explicit-vs-default today) + scoped per-verb
  registration (was global-silent-ignore; new flags are scoped — unify).
- **`version=` annotation reach short in TWO dims (breadth+design+feasibility).** (kind) extend to
  git/url/local/tarball not just git/url (tarball had no escape hatch → hard-error-no-remedy);
  (position) transitive deps have no declaration to annotate → add `version=` to `overrides { pkg }`
  rules (D-A3: annotation=label ⊥ override=redirect, compose by re-derivation against override target).
  +`milpa add --git --version` flag (natural-site workflow). +round-trip-through-`mutate_manifest_file`
  fixtures for all new manifest fields (format_manifest is hand-rolled, has silently dropped fields before).
- **pick() deepened (design).** `bypass` + `is_root_direct` + `LowestDirect` removed from the picker:
  provider assembles `preference=None` for bypassed pkgs, and precomputes effective strategy
  (`Minver` if root-direct else `Maxver`). Picker = `pick(candidates, allowed, strategy, package,
  preference)` — current 4 args + 1.
- **A2c member sentinel sites (depth HIGH).** Needs full site inventory like A2's — `__root__`→member
  term (`:3874`/rust `:1747`) + named-dep-coerce-to-member (`:3627`), not just member's own candidate.
- **Naming (design MEDIUM×2).** manifest node `exclude_newer`→**`exclude-newer`** (kebab, matches CLI +
  `spec-version`); `declared_version_source` value `milpa_kdl`→**`manifest`** (role not file-syntax).
- Multi-constrainer error enumerates ALL constrainers (amoxtli floored 2); transitive-case remedy text
  branches (annotate vs root-pin/override). Anchor fix: `_DEFAULT_STRATEGY` at `frozen.py:72` not `:70`.
- Verified sound: D0 crate-cycle real, B7 sites exact, `root_authority` predicate exists for C2/C3,
  bijection lint handles 13 slugs, B2/A5 independence holds.
- **Net:** count stayed ≈31 (witness A4a/A4b collapsed → A4; freed budget absorbed A3b/C3 growth).
  Every slice a clean single RED; A4's Python decision-priority reconciliation is the one to watch.

RFC: `docs/rfc-resolution-semantics.md`. Broad resolution-semantics umbrella (Corey chose
"broad overhaul" scope). Supersedes `rfc-index-version-selection.md` stub; closes umbrella #104.

## Scope (5 axes)
- **A** #191 — real versions for git/url deps (read `.nimble version`; replace synthetic `0.0.1`).
- **B** #192 + #70 — minimal-change re-resolution (lock as preference) + `--locked` + `--upgrade`.
- **C** #98 + #111 — minver/semver over index (likely already works, verify) + `MinDirect` (lowest-direct).
- **D** #86 — `exclude-newer` (manifest `resolution{}` block + CLI + lockfile-recorded).
- **E** #110 — cross-platform lockfile SCOPE DECISION (recommend single-config default + deferred universal seam).

## Slices (stage 2 COMPLETE; ~31 slices) — A1–A7 DONE (AXIS A COMPLETE); B1–B7 DONE (AXIS B COMPLETE); C1+C2+C3 DONE
- [x] A1 · [x] A2 · [x] A2c · [x] A3 · [x] A3b · [x] A4 · [x] A5 · [x] A6 · [x] A7
- [x] B1 · [x] B2 · [x] B3 · [x] B4 · [x] B5 · [x] B6 · [x] B7
- [x] C1 · [x] C2 · [x] C3
  C3b, C4 · D0–D7 · E1 (doc-only) · W1 (see RFC §7 ledger)

## Architect round 1 — applied (2026-07-29)
4-lens team (depth/breadth/design/feasibility). Clear-best fixes folded into RFC; **no genuine
forks surfaced** — every finding carried a confident recommendation, so all were resolved under
the bar (per mandate). Headline changes:
- **Axis A causality fix (depth A-1):** git/url self-term is now `full()` *before* fetch (was
  `eq(sentinel)` built pre-fetch → would spuriously SOLVE-CONFLICT every versioned git dep).
  Declared version labels the candidate only.
- **§4 relayered (design/feasibility/depth):** was "all axes in the pick function" (layering
  violation) → explicit provider-owned candidate pipeline; exclude-newer moved to enumeration
  layer (preserves #100 SOLVE-CONFLICT vs TNG-NO-SATISFYING error class); pick stays pure.
- **version-unknown mechanism pinned (D-A1):** MemberDep-style exclusion, not poisoned Version;
  keeps Rust pubgrub-crate contract intact; cross-dependent coherence still enforced.
- **`add` bypass (breadth #1):** new B7 — `add` hardcodes prior=None (both impls) → reproduces
  #192; audit all resolve verbs.
- **Migration false-drift (breadth/depth/design):** D-B2 — `--locked` drift is identity-based,
  so `0.0.1`→real relabel isn't drift. No epoch bump, no universal CI break.
- **Workspaces (breadth #2):** new Axis W — every axis states workspace behavior; root-only
  `resolution` block; shared git version.
- **exclude-newer git (breadth/depth/feasibility):** validation-not-selection (D-D1/D2/D3);
  branch refs explicitly not reproduce-as-of; fail-closed; scoped reproducibility-not-security;
  commit-date-never-tagger-date.
- **`--upgrade` = delegation to `update`'s strip-pin (D-B3);** strategy into `resolution{}` now
  (D-C2); `lowest-direct` wire string (D-C1); explicit `--strategy` bypasses lock-pref.
- **Hygiene:** stale Python anchors fixed (`registry.py:435`→`:477`, `version.py:283`→`:233`);
  wrong `spec/resolution.md`→`spec/resolver-semantics.md`; +`spec/identity.md` NORMATIVE clause;
  9 new error slugs enumerated (RES- prefix, not RESOLVE-); A2 split into 3 sub-slices.

## Architect round 2 — applied (2026-07-29)
4-lens team again (depth/breadth/design/feasibility). Round 2 was heavy — **1 Critical (both depth
and feasibility, independently — feasibility unpacked `pubgrub-0.4.0` source and found the literal
`panic!` at `solver.rs:217`)**, plus a cluster of High/Med. All applied as clear-best fixes; **still
no genuine forks escalated** — the Critical was resolvable under the bar (see below). Headline changes:
- **CRITICAL — version-unknown mechanism rewritten (D-A1 / §3 Axis A / §4).** Round-1's "MemberDep-
  style exclusion" was provably wrong: `_dep_to_term` returns `(None,None)` for members and the
  member check is an eager pre-solve per-edge check (only works because the workspace requirer-set is
  known upfront); an external transitively-walked git dep can't use it, and the real `pubgrub` crate
  **panics** on an out-of-range `choose_version` return. **New mechanism = witness synthesis:**
  `choose_version` for a version-unknown pkg returns the least member of the accumulated range —
  well-defined because milpa's `Version` is a discrete ℕ³ lattice (inclusive→itself, exclusive→
  successor, unbounded→0.0.0, multi-interval→lowest). Coherence falls out of pubgrub's own term-
  intersection (empty→conflict *before* choose_version); witness discarded at lockfile boundary
  (version⊥identity). Honors floors AND ceilings (draws from intersection) — strictly better than
  the rejected "top version". **Re-sliced A4 → A4a (witness primitive + edge-case contract, unit-
  tested) + A4b (wiring + no-leak).** NOT escalated: the bar determines it once you see Version is
  discrete. Corey can veto the mechanism on review, but it's applied, not left open.
- **§4 stages 4+5 collapsed → one "preference-aware pick" (design HIGH).** Round-1's "reorder stage"
  was inert (the real pick is order-independent `max`/lower-bound); preference now consulted *inside*
  the pick (short-circuit), pipeline is honestly **5 stages + 1 pre-stage-1 branch** (version-unknown),
  not 6. `Preference::Locked`→`FromLock` (collided with `--locked` flag).
- **`DeclaredVersion` sum-type split → two sibling fields (design HIGH).** `Known(Version,source)|
  Unknown` merged value+source, contradicting the RFC's own identity⊥provenance cite. Now
  `declared_version: Option<Version>` (reuses existing `parse_version` idiom, zero new pattern-match
  on value consumers) + sidecar `declared_version_source`. Unknown lockfile literal pinned (`0.0.0`
  value + absent source — depth found it was unspecified + colliding).
- **D-C2 bypass scope (design HIGH).** "explicit --strategy bypasses lock-pref" was whole-graph;
  under `lowest-direct` that strips transitives' preference → #192 again. Scoped to "packages the
  strategy re-orders" (root-direct only for lowest-direct).
- **B7 scope widened (breadth+feasibility HIGH, corroborated).** `workspace add-member`/`remove-member`
  ALSO hardcode `prior=None` (both impls) — highest-blast-radius. Anchors corrected
  (`_cmd_add_git`:3409, `_cmd_add_from_member_dir`:4075, workspace verbs :4271/:4412/main.rs:1847).
- **Frozen baseline (breadth HIGH).** `FROZEN-STRATEGY-MISMATCH` compares against a hardcoded
  `maxver` literal (`frozen.py:70`); once manifest `strategy` lands that spuriously fails frozen on
  every non-default project. New sub-slice **C3b** = manifest-sourced baseline; D5 built the same way.
- **D0 crate-move prerequisite (feasibility HIGH).** "reuse `_parse_timestamp`" is a Cargo cycle in
  Rust (`milpa-manifest` can't depend on `milpa-core`); new Rust-only **D0** moves `Timestamp`/
  `parse_iso8601_timestamp` down to `milpa-types` first. Python anchor also fixed (:780 def, not :899).
- **D-D2 factual correction (depth HIGH).** Branch refs ARE reproducible once locked (pin-reuse of
  `commit_sha`, `resolver.py:1022`); round-1's "checks only current HEAD" was wrong. Documented the
  real hard-fail asymmetry: tightening `exclude_newer` over a locked git pin = unconditional
  `RES-EXCLUDE-NEWER-PIN`, no fallback (the motivating LTS case) + D6 fixture.
- **A2c member derivation (depth HIGH).** milpa.kdl has no package `version` field → milpa-native
  member with no `.nimble` = version-unknown by A4a witness; member self-term `full()` justified by
  "one candidate" NOT causality (members have no fetch). Stated so impls don't diverge.
- **Medium/hygiene:** A2a/A2b merged → A2 (site-count, not seam); `MAN-RESOLUTION-STRATEGY-INVALID`
  added + catch-all narrowed (10 slugs); #70 yank exception (recurring, not just migration) + B5
  holds index fixed; edit-existing-constraint fixture (B6); `milpa show` surfaces new state (A7);
  manifest `exclude_newer` honored by all verbs (CLI flag stays fetch/lock-only, stated); index-cache-
  staleness-can't-corrupt note (D-D3); backtracking-exposure residual risk (§7, tied to #28); E1
  marked doc-only (no /tdd RED).

**Net:** ~24 findings applied across §1/§3(all axes)/§4/§5/§6/§7. Slice count ≈30→≈32.

## Design decisions — DECIDED under the PhD-CS bar (RFC §6; no open forks)
- **D-B1** minimal-change is the DEFAULT (`--upgrade` recovers newest-wins). Not optional.
- **D-A1** version-unknown git dep → satisfies any constraint (content-pinned = user-owned; preserves fresco/intonaco untagged-branch pins).
- **D-E1** single-config default; universal is a deferred, seam-ready mode (closes #110's scope question).
- **D-D1** exclude-newer covers git deps (tag-date sourcing in scope).
- No item is escalated to Corey. Architect rounds attack these on merits; escalate only a genuinely goal-underdetermined choice if one surfaces.

## Key facts (from the 2026-07-29 resolver maps — file:line in RFC §1)
- Synthetic `0.0.1` is a DELIBERATE identity-singleton sentinel (Python `resolver.py:133`, Rust `resolver.rs:53`) — #191 is a model change (git deps become identity-pinned AND version-labeled).
- #100 (constraint accumulation) already CLOSED — solver accumulates all constraints; provider enumerates constraint-blind.
- Prior lock already threaded (`params.prior` / `maybe_prior_lockfile`) but used only for pin-reuse/drift — #192 makes it a version preference (bounded extension).
- Named/index deps already enter as full walkable candidate list + strategy applies → #98 likely already works (verify).
- Lockfile: unknown top-level nodes ignored → clean forward-compat seam for `exclude_newer`. CondRequire/Predicate dimension recorded but not acted on (reserved for #110).
- `_pick_version` (Python `solver.py:626`, Rust `milpa-solver/src/lib.rs:996`) is the single seam where all axes meet (precedence spec in RFC §4).

## Contract before stage 3
Both architect rounds complete + RFC reflects their fixes. Then:
`/loop implement the next unimplemented RFC slice with /tdd …`
