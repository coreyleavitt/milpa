# Pre-Nim program — handoff

The work that must land **before** the Nim dogfood impl starts, so Nim is built
once against a tight, frozen contract instead of chasing a churning spec.

Decided 2026-06-14 (this session): do **both** halves below, then Nim.

- **Stage:** Half A COMPLETE (4/4) — coverage 46/46, zero divergence   •   **Round:** —
- **Resume:** decide `--no-index` flag (optional UX, NOT a coverage blocker — see below); then Half B (start with #26 when-blocks RFC)

## Why this ordering
Spec + 161-fixture corpus + harness (python+rust, zero divergence) is the contract
a third impl builds against. The harness has blind spots that would let a Nim impl
pass the corpus **while silently diverging** — close those first. Then land the
Tier 2/3 spec features so the surface is frozen before Nim transcribes it. See
[[testing_differential_blind_spot]].

## Half A — harness hardening (NO RFC; straight to /tdd)
Hygiene backed by `rfc-differential-conformance-harness.md` + `spec/conformance-fixtures.md`.
- [ ] **#130** — harness compares only certificate `kind`, not content
- [ ] **#125** — 3 uncovered black-box MUST clauses (missing fixtures)
- [x] **#128** — closed: `spec/errors.md` already spec-owned; no generator path remains.
- [x] **#130** — fixed (a354c41): `_canonical_certificate()` is the single source for both fixture comparison + divergence token.
- [x] **#125** — fixed (19e39ca): fixture-164 (verify-no-lock); registered 064/130 for dev-deps-root-only; RES-NO-INDEX clauses now documented gaps (44/46 honest).
- [x] **#120** — RESOLVED (20f7b1c) with ZERO new production code. The "no CLI
      surface for no-index" premise was STALE: empty `MILPA_INDEX_URL` already
      means "explicitly no index" (cli-contract §8.1 NORMATIVE), honored by both
      impls' CLI path, and the runner already sets it for no-index.kdl fixtures.
      Un-quarantined 112/113 → pass both impls, zero divergence → coverage 46/46.
      Corey's earlier "build `--no-index`" choice was made on my wrong framing;
      corrected. The flag is now an OPTIONAL UX enhancement (empty-env works but
      isn't discoverable), NOT a coverage blocker. Decision pending.

### `--no-index` flag — optional follow-up (re-posed honestly)
The discoverable flag would alias the existing empty-`MILPA_INDEX_URL` behavior.
Pro: pip/uv `--no-index` parity, discoverable offline mode. Con: cross-impl
spec+code surface for a capability that already exists. Options: build now as a
small feature / file as its own issue for Half B / skip (env-var is enough).

## Half B — Tier 2/3 spec features (enter flow at Stage 1, RFC each)
Each is genuine design → RFC + slicing + two architect rounds before /tdd.
Recommended order (most self-contained first):
- [ ] **#26** — conditional / `when`-gated requires in `.nimble`  → `docs/rfc-conditional-requires.md`
- [ ] **#23** — per-dep features / optional / patch (Cargo-style)  → own RFC (biggest)
- [ ] **#108** — qualified `NamedDep(namespace, name)` end-to-end  (may fold into #23 or registry RFC)
- [ ] **#132** — Tier-3 registry-encoded requires graph (named-dep subset)

## Then — Nim dogfood impl
Only after A+B fully land. Do **not** let Half B additions land piecemeal while
Nim is mid-build — that recreates the spec-churn this ordering exists to avoid.

## Open forks (awaiting Corey)
- None currently. (#23 vs #108 fold-in decision deferred to when #23's RFC is drafted.)

## Key decisions (this session)
- Harden harness AND finish Tier 2/3 spec before Nim (not Nim-now-against-stable-core). → avoids Nim chasing spec churn.
- Half A skips the RFC pipeline — filed issues + existing harness RFC are sufficient contract. → no ceremony on hygiene.
