# Pre-Nim program — handoff

The work that must land **before** the Nim dogfood impl starts, so Nim is built
once against a tight, frozen contract instead of chasing a churning spec.

Decided 2026-06-14 (this session): do **both** halves below, then Nim.

- **Stage:** Half A COMPLETE (4/4 + `--no-index` shipped) — coverage 47/47, zero divergence   •   **Round:** —
- **Resume:** Half B — start with #26 when-blocks RFC (Stage 1: draft `docs/rfc-conditional-requires.md`, slice, then `/architect ... round 1/2`)

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

- [x] **`--no-index` flag** — SHIPPED (9d68b61). Corey chose to build it. Spec §2.6 +
      both impls + fixture-165 + all four conformance runners. coverage 47/47.

## Half A retro (lessons for Half B)
- **Four runners, not two.** Every fixture must pass: python CLI, rust CLI
  (both via `python3 -m harness`), python in-process (`test_conformance.py`),
  AND rust in-process (`milpa-conformance/tests/corpus.rs`). The last lags most;
  gate with `cd impls/python && uv run pytest` AND `./dev-rust test --workspace`.
- **Rebuild the rust RELEASE binary** (`./dev-rust build --release -p milpa-cli`)
  before `python3 -m harness` — it runs `target/release/milpa`, not the debug
  test binary. A stale binary silently fails fixtures.
- Validate stale-issue premises empirically before building (#120 was already
  solved; saved a redundant flag justification — see [[feedback_validate_diagnosis_first]]).

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
