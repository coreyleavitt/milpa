# rfc-conditional-requires (#26) — handoff

- **Stage:** 4 `/code-review` COMPLETE + SHIPPED. Fix loop hit the FLOOR (0 Critical/High/Medium) after R1+R2+R3. **Committed & PUSHED to main:** `a597509` (when-depth DoS guard, both impls) + `f366e26` (rest of review findings). Four-runner green, harness ZERO cross-impl divergence, coverage 53/53.   •   **Round:** DONE
- **#26 issue:** still OPEN (commits say `(#26)`, not `closes`) — close when satisfied feature is complete (S1–S6 + review all done).
- **NEXT (agreed with Corey):** Tier 2 is COMPLETE (#23 features closed-completed 2026-05-24; #25 workspace milestone 1 open child = #93; #26 shipped). Pivot to **Tier 3 structural** AFTER a `/clear` (between-RFC boundary; context was ~251k of #26-review). Resume command: **`/clear` then `/tdd #43`** (F4 HgFetcher — clean fetcher-protocol TDD vertical; alternatives #99 registry named-dep, #48 SafeExtractor). New session will Explore the `fetchers/` protocol + present a plan first.
- **CLAUDE.md roadmap is STALE** (lists Tier 2 as open; it's done) — worth a refresh pass.
- **R1 status:** C1✓ H1✓ H2✓(HEAD) H3✓ H4✓ M1✓ M2✓ M3✓ M4✓ M5✓ M6✓ M7✓ ; M8 deferred→#110 ; L1✓(via M1) L2 wontfix(by-design) L3✓(via M5).
- **R2 (fixes introduced new findings, all fixed):** M2-rust (HIGH, Rust scan_region stack-overflow DoS — depth guard added, mirrors Python) ✓ ; C1-ssot (MED, sort-key SSOT unify → cond_require_sort_key delegating to formatter, both impls) ✓ ; M2-dup (MED, _skip_continuation helper) ✓ ; M4(→ValueError/panic!+spec) ✓ ; M3-alias✓ M2-asym(comment+Rust note+spec)✓.
- **R3 (re-review of R2; all fixed inline):** DES-1 (MED, spec self-contradiction lockfile-schema §3.5 'lexicographic by name' vs new total-order — reworded) ✓ ; DES-2 (LOW, _cond_require_sort_key→public cond_require_sort_key) ✓ ; DES-3 (LOW, 3 stale 'sorted by name' comments) ✓ ; all R3 security CLEAN, cross-impl parity CLEAN (depth-guard path verified by inspection — no fixture nests ≥8 deep).
- **New fixture-171** (same-name multi-branch) added; corpus 169 fixtures.
- **Deferred→filed:** C1-shape (Vec<Vec>/list[tuple] named-wrapper polish) → NEW issue ; cmd_show predicate-VALUE ANSI injection (pre-existing, Low) → NEW issue ; M8 (resolver predicate-matching reimplements VersionSet, pre-existing) → #110 comment. #135 already open (show fixture).
- **Pre-existing failures (stash-verified, NOT #26):** Rust fixture-099 (RES-PROVENANCE-CONFLICT vs FETCH-ALL-FAILED) + fixture-144 (TNG-DEPDECL-FETCH-FAILED vs RES-UNATTESTED-METADATA). Untracked as GH issues — surfaced to Corey.
- **NOT committed** (commit after Corey approval).

## Stage-4 review ledger (R1) — 5 agents (correctness, cross-impl, security, design, coverage), findings adversarially verified
Status legend: open / fixed / deferred / wontfix / refuted. Severity in caps.

| id | sev | status | file:line | issue / verifying note |
|----|-----|--------|-----------|------------------------|
| C1 | CRITICAL | open | nimble.py:213-241 + edge_sources.py requires_predicates dict + lockfile both impls | Same-name dep across ≥2 `when` branches collapses: Python dedups (keeps FIRST predicate), Rust `requires_predicates.insert` keeps LAST → divergent lockfile bytes + data loss. Violates spec §7.1 (MUST NOT dedup, verified line 518). Surfaced by Design-F1, Ximpl-D3, Correct-F1, Cover-gap2. Fix is non-trivial: remove Python dedup AND fix the `dict[name→preds]` seam (same name in 2 branches needs ≥2 cond-require records) in BOTH impls. |
| H1 | HIGH | open | nimble.py:168 vs nimble.rs:91 | `srcDir` first-wins (Python) vs last-wins (Rust). Spec §7.3 (verified line 573) mandates LAST. Fix Python: drop `if src_dir is None` guard. |
| H2 | HIGH | open(fork) | nimble.py:299 (HEAD) vs edge_sources.rs:99 (main) | Bare URL require (no `#ref`) defaults to different ref → different commit/identity/lockfile. Spec silent. Pre-existing. NEEDS DECISION: HEAD (nimble-compat) vs main; then pin in spec. |
| H3 | HIGH | open | lockfile.rs:584-599 vs lockfile.py:767-794 | Rust `kdl_str` emits named escapes (`\n \r \t \b \f`); Python emits `\u{N}` for all ctrl chars. Breaks byte-identity on ctrl chars in string fields. Spec §2.4 names PYTHON as reference (line 187) → fix Rust (drop named escapes). Comment falsely claims "Mirrors lockfile.py exactly". |
| H4 | HIGH | open | tests/test_lockfile.py | No property/round-trip PBT generating `CondRequire`-bearing deps (existing roundtrip strategy always sets cond_requires=()). Violates PBT discipline. Add `@given` cond-require strategy, assert format→parse→format byte-identical. |
| M1 | MEDIUM | open | lockfile.py:_format_predicate_prop + lockfile.rs parse_cond_require | `pred.name` from untrusted lockfile accepted unvalidated, re-emitted as unescaped KDL identifier (both impls). Fix: whitelist `{platform,arch,nim,milpa,flag}` on parse, drop unknown. (Verifier ceiling: cond_requires advisory-only; can't alter resolution.) |
| M2 | MEDIUM | open | nimble.py:_scan_region/_collect_direct_requires | O(n³) CPU DoS on deeply-nested `when` (measured depth300=2.2s, depth500=18.6s). Python only (Rust unaffected). Fix: depth guard (depth≥1 already→None) or iterate. |
| M3 | MEDIUM | open | nimble.py:370 vs edge_sources.py:599 | `_url_to_name` / `_name_from_url` duplicated, divergent on no-path URLs (full-string vs None-drop). SSOT violation. Unify. |
| M4 | MEDIUM | open | lockfile.py:804 `_format_predicate_prop` | Silently emits only `values[0]`; multi-value (OR) `Predicate` drops `values[1:]`. Invariant (cond-require preds always single-value) undocumented/unenforced. Assert + document, or handle. |
| M5 | MEDIUM | open | resolver.py:582-643 | `_parse_transitive_deps`/`_parse_from_nimble` DEAD (zero external callers, verified) — superseded by edge_sources. Would strip predicates if reactivated. Delete both; KEEP `_dep_to_term` (live @1695). |
| M6 | MEDIUM | open | resolver.py:168 | `_Candidate.requires_predicates` typed `dict[str,tuple[object,...]]` + `type:ignore` @1627; no real cycle blocks importing `Predicate` from leaf `predicate.py`. Use concrete type, drop ignore. |
| M7 | MEDIUM | open | rust lockfile tests + both parsers | Missing: Rust multi-cond-require sort-order test; malformed `cond-require` parse test (no-name / non-`when` child / propless `when`) both impls. |
| M8 | MEDIUM | deferred→#110 | resolver.py:460-500 | `_value_matches`/`_version_satisfies`/`_normalize_constraint` reimplement `VersionSet` SSOT. PRE-EXISTING (commit 9de7a90), part of deferred #110 activation path. Fold into #110, not #26. |
| L1 | LOW | open | cli.py:807 cmd_show | `pred.name`/`values[0]` printed raw → ANSI/terminal injection from untrusted lockfile. Fold into M1 vocab check. |
| L2 | LOW | wontfix? | nimble.py:536-546 | `_split_on_and` returns None (no fallthrough to single-pred) when one side non-nim, e.g. `NimMajor>=1 and defined(linux)`. By-design per spec (nim-and-nim only); both impls agree. Note only. |
| L3 | LOW | open | resolver.py:563 vs edge_sources.py:203 | `_find_nimble_file` duplicated (raise vs None). Resolved by M5 deletion. |
| L4 | LOW | open | tests + conformance | Gaps: tabs-indent in when-body, two consecutive when-blocks (first no requires), NimMajor single-form conformance fixture, Rust require_lines tracking, huge-version robustness. |

## Cross-cutting note
The dedup cluster (C1) + M3 + M5 + M6 are all SSOT/duplication smells in the .nimble→edge pipeline; several pre-date #26 but #26's S5 spec newly pins the correct behavior (no-dedup, last-wins srcDir), making C1/H1 in-scope to fix now. H2/M8/L2 are pre-existing/by-design.


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
