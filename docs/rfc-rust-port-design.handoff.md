# Rust-port design RFC — handoff

- **Stage:** 2 architecture review — **rounds 1+2 DONE** → **stage 3 (slice grind) next**   •   **Round:** 2/2
- **Resume (stage 3):** `/loop implement the next unimplemented RFC slice with /tdd, following the standing rules; after each slice report one progress line; stop when every slice is implemented` — BUT first do the §10 pre-grind prerequisites (P1–P5) + S0 spikes.
- **RFC:** `docs/rfc-rust-port-design.md` (rounds 1+2 fixes applied, uncommitted — Corey-gated).
- **§8 GATE: RESOLVED** — R1–R11 applied to spec docs (uncommitted). Suite 901 green.
- **Uncommitted files (Corey-gated commit):** `docs/rfc-rust-port-design.md`, `.handoff.md`, `docs/spec/{lockfile-schema,conformance-fixtures,resolver-semantics}.md`.

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
1. **Commit gate** — all uncommitted (RFC + handoff + 3 spec docs); Corey-gated. (Q2 "next step" not yet answered — Corey said sort Q1 first; Q1 now resolved as P-slices.)

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
