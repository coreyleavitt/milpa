# Pre-Nim program — handoff

The work that must land **before** the Nim dogfood impl starts, so Nim is built
once against a tight, frozen contract instead of chasing a churning spec.

Decided 2026-06-14 (this session): do **both** halves below, then Nim.

- **Stage:** Half A → 3/4 done; #120 awaiting Corey's contract decision   •   **Round:** —
- **Resume:** after #120 decision, implement the chosen option; then Half B (start with #26 when-blocks RFC)

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
- [ ] **#120** — AWAITING CONTRACT DECISION. The two RES-NO-INDEX clauses are the last black-box gaps. Options:
      1. `MILPA_INDEX_URL=none` sentinel — magic string, overloads empty semantics. Rejected (hack).
      2. **`--no-index` flag (recommended)** — explicit CLI surface; matches pip/uv `--no-index`, cargo `--offline`; makes 112/113 real corpus fixtures; delivers a real offline/air-gapped resolution feature. BUT: cross-impl change (cli-contract.md + python + rust + fixtures) — bigger than hygiene, touches spec surface.
      3. Accept in-process-only; mark 112/113 `observable=False`. Cheapest; accepts a permanent harness blind spot for two normative codes.

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
