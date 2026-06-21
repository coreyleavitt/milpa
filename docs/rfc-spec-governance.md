# RFC: Spec governance & provenance extensibility (STUB)

Status: **stub** — triage grouping from the 2026-06-21 issue audit. Not yet designed.
Umbrella: #173. Milestone: *v1.5 — spec extraction*.

## Problem

Three pure spec-design decisions with no immediate consumer — they define *how the
spec evolves* and *how far resolution scope extends*, not a build task. They were
deferred from the Rust-readiness gate and a four-way (milpa/nimble/atlas/uv)
completeness comparison. Grouping them keeps the governance story in one place rather
than scattered across the cross-impl contract.

## Issues unified

- **#113 — amendment process for adding a new provenance kind.** The Rust-readiness
  gate froze the closed provenance meta-grammar (`<kind> { …typed fields }`) and the
  spec-versioning rule; this issue specs the *process* for adding a new kind without
  breaking the cross-impl contract.
- **#114 — backend-override config: bind an alternate backend to an existing
  provenance kind.** The gate established this is "safe by construction" (identity is
  content-addressed, transport-independent); this issue designs the config surface.
  See `docs/spec/plugin-contract.md §6`.
- **#110 — scope of universal (cross-platform) resolution / lockfile — the uv-parity
  question.** The one lockfile-design axis uv has answered and milpa has not RFC'd: a
  **scope decision**, not a build task. Does milpa resolve/lock a single platform or
  a universal cross-platform graph?

## Why one RFC

All three are spec-governance: how the provenance meta-grammar grows (#113/#114) and
how wide the resolution contract reaches (#110). They feed `spec/` directly and
should be settled before the v1.5 spec extraction freezes the surface. Deciding them
together avoids a partial governance story (e.g. an amendment process that doesn't
account for cross-platform provenance variants).

## Open questions

- #110 is genuinely a *decision* fork (single-platform vs universal); it may resolve
  to "out of scope, documented" rather than a build. Resolve the scope first.
- Does #114's backend-override interact with #110's cross-platform axis (a backend
  available on one platform only)?

## Slices

TBD. #110 (scope decision) gates the others and should be resolved first.
