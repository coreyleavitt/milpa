# Pre-Nim program — handoff

The work that must land **before** the Nim dogfood impl starts, so Nim is built
once against a tight, frozen contract instead of chasing a churning spec.

Decided 2026-06-14 (this session): do **both** halves below, then Nim.

- **Stage:** Half A → Stage 3 (/tdd, no RFC needed)   •   **Round:** —
- **Resume:** `/loop close the harness blind spots — work issues #130, #125, #120 each with /tdd following the standing rules, then close #128 (errors.md already spec-owned); after each report one progress line; stop when all four are done`

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
- [ ] **#120** — RES-NO-INDEX / RES-WS-NO-INDEX not black-box expressible (fixtures 112/113)
- [ ] **#128** — close: `spec/errors.md` already spec-owned ("do not generate from any implementation"); no impl generates it. Verify + close.

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
