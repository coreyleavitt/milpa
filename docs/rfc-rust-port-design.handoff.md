# Rust-port design RFC — handoff

- **Stage:** 3 (slice grind) — **P1–P4 ALL DONE (landed). §10 pre-grind COMPLETE. Next = S0 spikes, then cut `rust` branch + S1 scaffold.**   •   **Round:** 2/2
- **Resume (stage 3):** `/loop implement the next unimplemented RFC slice with /tdd …` — next = **S0 spikes** (kdl-rs annotation/value + line-col error; pubgrub-rs vs fixture-063) → then **cut `rust` branch** → S1 scaffold (commits rust/Containerfile + cargo workspace) → S2 … **NOTE: S1 onward lands on the `rust` branch, not `main`.**
- **Uncommitted (Corey-gated):** P1–P4 changes are GREEN but NOT committed (all on `main`). P1: fixture-117, harness per-member-nim.cfg routing, nimcfg `format_workspace_nimcfgs` extraction, conformance-fixtures §2/§2.1.1/§2.5, RFC P1/S11/§9. P2: `_load_manifest_from_nimble`→`load_nimble` SSOT unify + code-translation, catalog when-text + errors.md, 2 tests, KNOWN_UNTESTED trim, RFC P2/S3/§9. P3: `_kdl_str` SSOT escaper in lockfile.py (R11), round-trip test, fixture-118, lockfile-schema R11 NOTE, RFC P3. P4: `FETCH_UNCODED_INVARIANTS` lint SSOT, plugin-contract §5.1 normative exemption, RFC P4. Suite 906 passing.
- **Resume (stage 3):** `/loop implement the next unimplemented RFC slice with /tdd, following the standing rules; after each slice report one progress line; stop when every slice is implemented` — order: §10 pre-grind P1–P4 (on `main`) → S0 spikes → cut `rust` branch → S1 scaffold → S2…
- **RFC:** `docs/rfc-rust-port-design.md` (rounds 1+2 fixes applied; **committed** main `8375f84`).
- **§8 GATE: RESOLVED + COMMITTED** — R1–R11 spec reconciliations committed main `b49e21b`. Suite 901 green.
- **Branch:** still on `main`. `rust` branch NOT yet cut — it's created at S1 scaffold (after P1–P4 + S0).
- **Dev image (untracked):** `rust/Containerfile` built = `ghcr.io/coreyleavitt/milpa-rust:1.96` (Tumbleweed + rustup-pinned Rust 1.96.0 + rustfmt/clippy; `cargo build` smoke-tested). Untracked on purpose — gets committed at S1 with the workspace, on the `rust` branch.

## P1 RESOLVED — workspace nim.cfg is per-member, not single (approved, landed)
P1 (workspace success fixture) hit a latent gap: the conformance harness's
`_outputs` emits ONE root nim.cfg via the single-package `format_nimcfg`, treating
members as `_deps/<name>` external deps. But milpa actually emits **per-member**
nim.cfg via `write_workspace_nimcfgs` — each member dir gets its own nim.cfg with
relative sibling paths, and there is NO root nim.cfg. Verified output for the
fixture-117 two-member case:
- `member-a/nim.cfg` = header only (no deps)
- `member-b/nim.cfg` = header + `--path:"../member-a/src"`
The spec (conformance-fixtures.md §2 layout / §2.1.1 / §2.5) assumes a single
`expected/nim.cfg`. No workspace success fixture ever existed, so the gap was never
exercised. milpa.lock + _deps_structure.txt ARE correct as shared root outputs
(members are exempt from CAS materialization, so _deps_structure is empty here).

**Recommended resolution (clear-best, but amends frozen spec v1.0 → needs go/no-go):**
1. Workspace success fixtures express nim.cfg per-member: `expected/<member-path>/nim.cfg`,
   one per member (mirrors the member-subdir input layout). No root `expected/nim.cfg`.
2. Harness `_outputs`/runner: when parsed type is WorkspaceManifest, write per-member
   nim.cfg via `write_workspace_nimcfgs` into a scratch copy and byte-diff each against
   `expected/<member>/nim.cfg`. milpa.lock + _deps_structure.txt stay single shared root files.
3. Amend conformance-fixtures.md §2/§2.1.1/§2.5 to define per-member nim.cfg for workspace fixtures.
4. Update RFC P1 text ("expected/{milpa.lock,nim.cfg,_deps_structure.txt}") + S11 + §9 coverage to match.
Fixture-117 inputs already authored (root + member-a/liba + member-b/libb→member liba).
Once approved: finish harness change, generate expected/, green Python suite, then resume P2.

## P2 RESOLVED — NIMBLE-* not fixture-expressible + SSOT dup fixed inline (Corey: fix inline; DONE)
P2 said "author 2 NIMBLE-* error fixtures (coverage-floor bijection gap)". Investigation:
- **No bijection gap.** `NIMBLE-FILE-NOT-FOUND` has a direct unit test (test_error_catalog.py:923);
  `NIMBLE-FILE-UNREADABLE` is already in that file's KNOWN_UNTESTED (line 941). Lint is clean now.
- **Not fixture-reachable.** `load_nimble` (sole raiser of NIMBLE-*) has NO production caller —
  only tests call it. The conformance harness never runs `.nimble` discovery (reads milpa.kdl text
  directly; cmds = resolve/parse-lockfile/frozen). And you can't commit a missing/unreadable file to
  git, so -NOT-FOUND/-UNREADABLE are intrinsically not fixture-expressible.
- **SSOT duplication found.** `_load_manifest_from_nimble` (the real discovery path) re-reads the file
  and raises `MAN-FILE-UNREADABLE`; `load_nimble`(→NIMBLE-*) is dead outside tests. Two codes, one condition.

**Recommended resolution:**
1. **P2 = exemption, not fixtures** (mirror P4): document NIMBLE-FILE-* as CLI-discovery file-IO errors
   exempt from the conformance corpus — covered by unit tests + KNOWN_UNTESTED. Add to both impls'
   bijection-lint exemption lists (Python already effectively exempts via KNOWN_UNTESTED; document for Rust).
   Update RFC P2 text + §9 (NIMBLE-* row already says "none exist (corpus gap)" → change to "exempt").
2. **File a separate cleanup issue** for the load_nimble vs MAN-FILE-UNREADABLE duplication (catalog-design
   call: delegate `_load_manifest_from_nimble`→`load_nimble` and pick one code, OR retire load_nimble+NIMBLE-*).
   Touches errors.md (frozen v1.0) + both catalogs → not inline corpus-prep work. Per [[feedback_defer_file_now]] file now.

## Round-2 changes applied (clear-best)
- **CRITICAL** fixed: VersionSet/Strategy+algebra moved to milpa-solver (orphan-rule); milpa-types = raw Version + data only. Added type-placement table.
- **CRITICAL** fixed: pubgrub seam = `DependencyProvider::prioritize` (order P), NOT VersionSet trait; S0(b) criterion = solution-match on fixture-063, not emission order.
- Resolver trait gains `prior_lockfile` param (pin reuse). Provenance → closed enum (not dyn Any). Traits+MilpaError+From-impls live in milpa-core. build.rs→`#[test]` for bijection lint. BTreeMap/IndexMap determinism non-negotiable. FixtureContext builder seam + canonicalize-not-readlink trap. known_failing xpass detection. Containerfile base-image-with-toolchain + MSRV≥1.74.
- Slices: S5→S5a(parse,no-S4)/S5b(emit); S7b depends on S6; "unblocks vs greens" labels fixed; S13 now all 8 verbs incl add/remove/update + format_manifest; S14 strip-before-hash test; per-slice unreachable-code unit tests. §9 coverage map corrected (first success = S4+S5b+S6+S7b+S7c+S9).
- New §10 **pre-grind P-slices** (Corey's call: make them the FIRST slices, not side-channel issues): P1 workspace-success fixture, P2 NIMBLE-* fixtures, P3 escaping fixture+Python fix, P4 exclusive-dispatch exemption decision. (strip_components folded into S14, not a corpus slice.) Fixed factual error: MAN-*=62 not ~65; NIMBLE-* fixtures=0.
- Spec doc: lockfile §7.4 cross-ref to always-on header (R5 follow-up).

## Stage-3 order (when grind begins)
P1–P4 (on `main`) → S0 spikes (kdl-rs, pubgrub-rs) → S1 scaffold → S2 harness+self-test+CI → S3… per §6. First success fixture greens at S9.

## Open items for Corey
1. ~~Commit gate~~ — DONE: RFC+handoff (`8375f84`) + 3 spec docs (`b49e21b`) committed to main.
2. Containerfile push to ghcr-public deferred (needs `podman login ghcr.io` + push + flip package visibility). Not blocking.

## Constraints from Corey (verbatim intent)
- Rust impl developed on a **separate branch** (`rust`); merge to main when green.
- **Same-repo coexistence for now** — design how Python + Rust live side by side in this repo.
- Do **NOT** design a multi-repo conformance harness yet (may split repos later; not worth it now). One shared fixture corpus, read from disk by both impls.

## Key decisions in the draft (to be stressed in architect rounds)
- Pure Rust (no PyO3) — the reference must be an independent oracle.
- Layout: `/rust/` cargo workspace, crates `milpa-core` (lib) / `milpa-cli` (bin) / `milpa-conformance` (harness). Hatchling only packages `milpa/`, so Python build is unaffected. Fixtures referenced by relative path (one copy).
- The **fixtures** are the single source of truth; two runners (Python pytest + Rust `milpa-conformance`) consume one corpus.
- Library forks-with-fallback: `kdl` (kdl-rs) for parse only / hand-roll fallback; `pubgrub` (pubgrub-rs) or port the teaching solver; `sha2`; real fetchers behind a trait (fake-injected in fixtures, not fixture-gated).
- Spec-conformance is the bar, not Python-parity (Rust may be *more* conformant, e.g. #117).

## Slices (15; see RFC §6)
S1 scaffold+coexistence · S2 conformance harness (RED backbone) · S3 KDL+manifest · S4 identity+CAS · S5 lockfile · S6 version/VersionSet/Strategy · S7 solver+resolver · S8 fetcher trait+fake+index/TNG · S9 nim.cfg · S10 frozen · S11 workspace · S12 error-catalog parity · S13 CLI · S14 real fetchers · S15 (stretch) differential harness.
Done = S1–S13 + full spec-v1 suite green under milpa-conformance.

## Open questions — ALL RESOLVED in round 1 (RFC §7)
- kdl-rs → S0(a) spike (annotation+value accessible; error carries line/col); hand-roll fallback.
- pubgrub-rs → S0(b) spike vs fixture-063; milpa VersionSet impls pubgrub trait; port fallback.
- harness → #[test]/rstest parametrization (not standalone bin).
- error parity → independent Rust catalog + build.rs lint vs errors.md.

## Round-1 changes applied to RFC (clear-best)
- Crate split 3→6 (milpa-types vocabulary crate enforces SSOT at compile time).
- 3 narrow traits (LockfileParser/Resolver/FrozenResolver) replace god `trait Milpa`.
- Fetcher returns receipt-not-identity; cas_admissible on Provenance. Per-domain error enums + MilpaError.code().
- Slices: added S0 spikes; split S7→S7a/b/c; S2 done = synthetic pass+fail self-test (not "all RED"); S14 gets local no-network tests; known_failing.txt drives progress; CI minimal by S2; toolchain pinned + containerized.
- Added missing-coverage acceptance criteria: verify verb (S13), index cache 4-state (S8), mirror fallback + pin reuse + provenance precedence + dev-deps (S7b), .nimble parse + TOFU (S3/S14), per-member nim.cfg closure (S11), env→Profile/_deps literal/member subdirs (S2).
- New §8 (11 spec reconciliations R1–R11 + workspace-success-fixture corpus gap) and §9 (fixture coverage map).

## GATE awaiting Corey (the one escalation)
§8: the review found 11 internal spec contradictions (R1/R2 text-verified: nim.cfg order conflict; _deps_structure relative-vs-absolute). All fixtures-win, v1-permitted reconciliations. Need go/no-go to land them on main (per §4.3 reflow) before the dependent slices.

## Context note
This RFC opened in the same session that froze spec v1.0 (prior RFC: rfc-reaching-rust-rewrite, committed: a2957b6/ad55aa0/20e2de6). Context is large — safe to `/compact` after architect round 1, or `/clear` before a fresh session (re-read this handoff first).

## Review ledger (stage 4)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| —  | —   | (stage 4 not started) | — | — |
