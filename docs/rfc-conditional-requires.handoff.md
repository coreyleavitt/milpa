# rfc-conditional-requires (#26) — handoff

- **Stage:** 3 (/tdd grind) — **S1+S2+S3a done; S3b next**   •   **Round:** —
- **Resume:** `/loop implement the next unimplemented RFC slice (docs/rfc-conditional-requires.md §9) with /tdd following the standing rules; after each slice report one progress line; stop when every slice is implemented`

## Stage-3 progress
- [x] **S1** (commit after `d53d600`) — `parse_when_condition` pure fn, both impls; 62 unit tests each; both gates green. Canonical nim value space-free (`">=1.4.0"`). **Confirm at S5:** single-`NimMajor` form accepts all 5 operators (`>=,>,<,<=,==`), generalizing the table's `>=`-only example — fold into the §3.1 normative table / dep-decl §7.5 when writing the spec slice.
- [x] **S2** — `Predicate` moved to leaf `milpa/predicate.py` (Python) + `milpa-types` (Rust), re-exported from prior home (SSOT, import cycle broken); `predicates` field on `NamedRequire`/`UrlRequire`, EdgeSet round-trips it; 15 Rust ctor sites updated; 14 Py + 3 Rust tests; green.
- [x] **S3a** — standalone `parse_when_branches(lines) -> [WhenBranch{predicates|None, require_lines}]` state machine, both impls; full §3.2 algebra (block+colon forms, elif/else negation w/ deterministic order, chain poisoning, nested→None). 35 Py + 21 Rust tests; green; `TestWhenBlockPolicy` unchanged (no scanner wiring yet). **For S3b:** wire `parse_when_branches` into `parse_nimble`, carry predicates across `edge_sources._nimble_edges` onto `NamedRequire`/`UrlRequire` (NOT shared `NamedDep`/`UrlDep`); update `TestWhenBlockPolicy` / `when_block_includes_requires_unconditionally` so warning fires ONLY on UNRECOGNIZED (None-branch). Lockfile byte-identical (recording is S4). Note colon-form requires are currently NOT extracted by `parse_nimble` (`_REQUIRES_RE` misses the `when …: requires` tail) — S3b must extract them too.

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
