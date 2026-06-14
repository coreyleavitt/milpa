# rfc-conditional-requires (#26) — handoff

- **Stage:** 3 COMPLETE — **all slices S1–S6 done + committed.** Next: Stage 4 `/code-review`.   •   **Round:** —
- **Resume:** `/clear` first (between-stage), then `/code-review #26` (RFC `docs/rfc-conditional-requires.md`; scope = the 8 commits S1→S6).
- **Deferred + filed:** `milpa show` CLI-only cond_requires conformance fixture → **#135** (cmd_show is unit-tested; corpus completeness only).
- **Resume:** `/loop implement the next unimplemented RFC slice (docs/rfc-conditional-requires.md §9) with /tdd following the standing rules; after each slice report one progress line; stop when every slice is implemented`

## Stage-3 progress
- [x] **S1** (commit after `d53d600`) — `parse_when_condition` pure fn, both impls; 62 unit tests each; both gates green. Canonical nim value space-free (`">=1.4.0"`). **Confirm at S5:** single-`NimMajor` form accepts all 5 operators (`>=,>,<,<=,==`), generalizing the table's `>=`-only example — fold into the §3.1 normative table / dep-decl §7.5 when writing the spec slice.
- [x] **S2** — `Predicate` moved to leaf `milpa/predicate.py` (Python) + `milpa-types` (Rust), re-exported from prior home (SSOT, import cycle broken); `predicates` field on `NamedRequire`/`UrlRequire`, EdgeSet round-trips it; 15 Rust ctor sites updated; 14 Py + 3 Rust tests; green.
- [x] **S3a** — standalone `parse_when_branches(lines) -> [WhenBranch{predicates|None, require_lines}]` state machine, both impls; full §3.2 algebra (block+colon forms, elif/else negation w/ deterministic order, chain poisoning, nested→None). 35 Py + 21 Rust tests; green.
- [x] **S3b** — wired `parse_when_branches` into both scanners; predicates carried across `edge_sources` bridge onto `NamedRequire`/`UrlRequire`. **Python**: aligned `NimbleManifest.dep_predicates` tuple (shared `NamedDep`/`UrlDep` untouched); warning flips to fire ONLY on UNRECOGNIZED/poisoned. **Rust**: predicates inline on scanner-local `NimbleRequirement` variants; no warning channel. Colon-form `when X: requires "y"` now extracted (was missed). Dep set + lockfile byte-identical. Updated `test_when_block_emits_user_warning` (now uses `defined(release)` to keep asserting the warn path). 12 Py + 5 Rust tests; green.
- [x] **S4** — additive `cond-require` lockfile recorder, both impls. `CondRequire`+`LockedDep.cond_requires`/`ResolvedDep.cond_requires`; `edgeset_to_terms` 3-tuple w/ `requires_predicates` dict (advisory only); threaded `_Candidate`→`ResolvedDep`→`LockedDep`. Canonical byte-identical emission (inline single `cond-require "x" platform="linux"` / `platform=(not)"linux"`; `{ when … }` block for AND; sorted after `requires`). Parser reads `(not)` tag. `cmd_show` shows it; frozen/verify/nimcfg read `requires` only. fixture-138 expected.lock gained the additive line (requires byte-identical — note: CLI harness `python3 -m harness` not re-run yet; validated in S6 w/ rust release rebuild). 29 Py + 14 Rust tests; round-trip identity; both gates verified green by control loop.
- [x] **S5** — spec prose. `dep-decl.md` §1 (predicates field) + §7.5 (grammar table w/ NimMajor-all-5-operators + space-free nim value + posix exclusion, branch/poison algebra, warn-only-on-UNRECOGNIZED); `manifest-grammar.md` §5.3 mirror (§6 untouched); `lockfile-schema.md` §3.5 cond-require (inline + `{ when }` block, `(not)`, ordering) + CondRequire/cond_requires + #110 addendum. No version bump, no new error codes, in-code warning text already matched. Both gates green.
- [x] **S6** — conformance corpus + four-runner validation. 5 fixtures (166 translate, 167 negation elif/else block, 168 nim two-sided block, 169 unrecognized over-include, 170 multi-requires-per-branch) + 5 coverage clauses registered atomically. **ALL FOUR runners green**: python 1455 passed, rust workspace ok, `python3 -m harness` 168 fixtures ZERO divergence (post rust-release rebuild — validated fixture-138's S4 change for the first time), coverage 52/52 0 gaps. `milpa show` fixture deferred→#135.

## ✅ #26 IMPLEMENTATION COMPLETE (Stage 3 done)
8 commits S1→S6. Zero cross-impl divergence, spec updated, no version bump. Stage 4 = `/code-review #26`.

## Round 2 outcome — additive `cond-require` (NO genuine forks)
The round-2 depth agent edited the RFC toward an *overloaded* `requires { when }` form;
design + feasibility lenses found the additive **`cond-require`** node is strictly
better. Reconciled to `cond-require`:
- Lockfile: `requires "bar" "extra"` UNCHANGED (byte-identical, no re-lock churn); NEW
  `cond-require "extra" platform="linux"` (inline single / `{ when … }` block multi-clause).
- Data model: `LockedDep.cond_requires` ADDITIVE field; `requires: tuple[str,...]` unchanged →
  frozen/verify/nimcfg untouched; `cmd_show` displays cond_requires.
- Propagation: `edgeset_to_terms` drops predicates → add a `requires_predicates` dict (§3.4.3 opt a).
- `Predicate` extracted to `predicate.py` in S2 (breaks manifest↔dep_decl import cycle).
- Asymmetry acknowledged: milpa.kdl root `when` FILTERS now; `.nimble` transitive `when` RECORDS (→#110).
- S3a/S3b test-timing fixed: TestWhenBlockPolicy warning update lands in S3b (scanner wiring), not S3a.
- Pre-S4 gate: confirm manifest §6 negation spelling `(not)"value"`, mirror in cond-require.

## R1 RESOLVED — (c): reduce #26, defer activation to #110
#26 = recognize `when` + attach predicates + **record them on a universal (platform-
neutral) lockfile** (`requires "x" { when platform="linux" }`). It EXCLUDES NOTHING —
dep set unchanged, lockfile stays reproducible. Build-time *activation* (filter nim.cfg /
active set by profile) → **#110**. Round-1 host-exclusion findings (matcher SSOT,
Profile=None guard, double-parse, frozen contract, CI under-include diagnostic)
**transferred to #110** — TODO: add a summary comment to #110.
RFC §1/§3.4/§5/§6/§8/§9 restructured (commit pending). New slice S4 = lockfile recorder
(lockfile-schema.md + writer/parser round-trip), NOT a filter.

## Round 1 — applied fixes (fork-independent)
- §3.1 table: +`win`, +three-tuple/operator/two-sided `nim` forms; **dropped `posix`**
  (under-include risk); renamed fn `parse_when_condition`, `None`=UNRECOGNIZED + never-empty postcondition.
- §3.2: real state machine (not regex), single-line-colon form, multiple-requires/branch,
  chain-poisoning, `parse_when_branches` standalone.
- §3.3: predicates on `RequireEntry` via `_nimble_edges` bridge (NOT shared NamedDep/UrlDep); eliminate double-parse.
- §3.4: `predicates.py` SSOT, filter in `edgeset_to_terms(profile=)`, `Profile=None` guard, `active_flags=frozenset()`.
- §6: do NOT mutate fixture-138 (retained-unchanged rule) — new fixtures 139+; added URL/dev-deps/workspace/overrides/multi-require scenarios; coverage clauses atomic.
- §9: split S3→S3a (state machine, updates TestWhenBlockPolicy IN-slice) + S3b (wiring); S4+ gated on R1; no spec-version bump.
- Resolved forks: F1/F6 (table closed), F4 (unrecognized), F5 (one matcher). Open: F2, F3(#134), F7(diagnostic).

## Core design (one-line)
Route `.nimble` `when` blocks into milpa's EXISTING `Predicate`/`Profile` matcher —
translate a closed recognizable subset to predicates, attach to fallback edges, filter
transitive edges with the same matcher. Unrecognized → today's over-include + warn.

## Slices
- [ ] S1 — `nimscript_when_to_predicates(cond)` pure fn (both impls) — the §3.1 table
- [ ] S2 — `RequireEntry.predicates` data-model field (both impls)
- [ ] S3 — scanner `when/elif/else` branch tracking + attach predicates
- [ ] S4 — resolver transitive-edge predicate filter (single matcher, F5)
- [ ] S5 — spec: dep-decl §7.5 + §1, manifest-grammar §5.3, resolver-semantics
- [ ] S6 — conformance fixtures + coverage clauses
- S7 DEFERRED → filed as **#134** (DepDecl artifact schema v1 predicates, cross-repo)

## Open forks (awaiting architect review / Corey) — §8 of the RFC
- F1 recognizable subset boundary (rec: ship the table as-is)
- F2 flat chains only; nested when → UNRECOGNIZED (rec: yes)
- F3 attested-artifact predicates → deferred (#134 filed)
- F4 defined(release/js/custom) → UNRECOGNIZED for now (flag-map is future, needs #23)
- F5 one matcher helper, two call sites (rec: factor in S4)
- F6 posix → which OSes (confirm vs manifest-grammar §6 vocab)

## Key decisions (this session)
- Reuse the predicate model, NOT a new features system (#23 is a different axis). → SSOT.
- Fallback path only; attested stays publisher-curated. → minimal-over-completeness.
- Strictly additive: unrecognized conditions = today's behavior exactly. → no breakage.

## Four-runner discipline (from pre-Nim handoff — carry forward)
Every slice gates on: `cd impls/python && uv run pytest` AND `./dev-rust test --workspace`
AND `python3 -m harness` (rebuild rust RELEASE first: `./dev-rust build --release -p milpa-cli`).
Four runners: python CLI, rust CLI, python in-process, rust in-process.
