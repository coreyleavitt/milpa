# RFC: Features completion — Cargo-parity v2 (STUB)

Status: **stub** — triage grouping from the 2026-06-21 issue audit. Not yet designed.
Umbrella: #171. Milestone: *Tier 2+ — features parity*.
Supersedes the deferral tail of `rfc-features-optional-patch.md` (#23, shipped).

## Problem

#23 shipped the v1 features/optional/patch system, deliberately scoped to the
motivating cases. The Stage-4 review and the RFC's own §9 deferred a coherent set of
Cargo-parity and hardening follow-ups. They cluster: weak/conditional activation,
cross-package interaction, and the spec/lockfile/profile invariants that keep flag
resolution exact and cross-impl-identical.

## Issues unified

### Cargo-parity feature surface
- **#150 — weak dependency activation (`dep?/feature`).** Enable a feature on an
  optional dep *only if* already present, without pulling it in. Not modeled in v1.
- **#151 — cross-package conflicts (`conflicts { dep { flag } }`).** v1 `conflicts`
  is same-package only; extend to cross-package mutual exclusion.
- **#152 — `milpa features` / `show --why-flag` activation trace.** The primary
  feature-debugging question is *why* a flag is active; v1 records the source but
  exposes no trace command. (Coordinate with `rfc-resolution-diagnostics.md`.)

### Hardening / invariants
- **#155 — cross-package `enables`: optional opt-in activation-audit gate.** milpa
  implements Cargo-style cross-package `enables`; this adds an audit gate so a dep
  silently flipping flags on another package is reviewable.
- **#157 — `EdgeSet` should carry parsed flag decls** to avoid double-parsing
  `milpa.kdl` in `_materialize`. SSOT/efficiency; changes the edge-source seam.
- **#158 — lockfile `root_active_flags` field** for exact frozen-active-flags
  verification (replaces the S9 MVP heuristic). Spec/lockfile-schema change.
- **#159 — align Python `Profile` to optional axes** (Rust uses `Option`) for
  partial-profile cross-impl parity. Latent (no partial-profile fixture yet).
- **#160 — workspace seed path missing the (absent-profile + features) flag-filter
  arm.** Latent; close before workspace+features fixtures are authored.
- **#162 — spec hole: dep non-optional in `deps` + optional in `dev-deps`** —
  auto-flag namespace fusion undefined. Both impls agree (no error); spec must
  define the behavior so a future change can't silently diverge.

## Why one RFC

All flag-resolution semantics. The Cargo-parity additions (#150/#151) and the
invariants (#157–#162) share one model — `active(D)`, the dep×flag fixpoint, and the
edge-source seam — so they must be designed together to avoid re-litigating the same
data model three times. #158/#162 are spec changes that must land normatively (not
silent impl edits), per the honor-the-spec discipline.

## Open questions

- Does `dep?/feature` (#150) require the lockfile to record weak-activation
  provenance, or is it purely a resolve-time predicate?
- #157 changes the shared `EdgeSet` contract — sequence it before or after the
  Cargo-parity slices?

## Slices

TBD. The latent invariants (#159/#160/#162) are cheap "close before the fixture
exists" wins; the Cargo-parity surface (#150/#151) is the larger design.
