# RFC: Cross-impl conformance parity & corpus widening (STUB)

Status: **stub** — triage grouping from the 2026-06-21 issue audit. Not yet designed.
Umbrella: #169. Milestone: *v1.5 — spec extraction + cross-impl hardening*.

## Problem

The shared `conformance/spec-v1/` corpus is the *only* guard against Python-vs-Rust
divergence, yet several known reds and gaps sit unowned. Today: two fixtures emit
the wrong error slug on one impl, the human-readable stderr prefix differs between
impls, the corpus has coverage holes (no fixture reaches certain transport/identity
behaviors), and two in-process runner / generator limitations mean the harness
under-exercises what it claims to cover. These are all one concern — **make the two
reference impls byte-identical and the corpus actually exhaustive** — and defining
them piecemeal yields inconsistent fixes and silent gaps.

Baseline note (2026-06-21): Python conformance is fully green; fixture-099 passes in
Python and fixture-144 is tracked XFAIL ("resolver not yet implemented"). The reds
below are therefore Rust-side or cross-impl, **not** "both impls wrong." First slice
of this RFC MUST re-establish a fresh Rust baseline before any fix.

## Issues unified

- **#154 — fixture-099 `res-provenance-conflict` wired in Python, not Rust.** Rust
  emits `FETCH-ALL-FAILED` where the corpus expects `RES-PROVENANCE-CONFLICT`.
  (Supersedes #138, the same observation from the #26 review.)
- **#153 — fixture-144 `depdecl-fetch-failed` error mapping.** Expects
  `TNG-DEPDECL-FETCH-FAILED`; Rust emits `RES-UNATTESTED-METADATA`, Python is XFAIL
  pending the resolver slice. Reframe from the original "both impls" wording.
  (Supersedes #139.)
- **#156 — CLI error stderr prefix differs** (Python `milpa:` vs Rust `<CODE>:`).
  Pick one normative prefix in `spec/cli.md` / `spec/errors.md`; align both impls.
- **#146 — corpus coverage gap: tarball bz2-identity + mixed-case sha256.** Blocked
  on encoder determinism; the only guard against byte-divergence has a hole here.
- **#148 — cross-impl divergence on adversarial corrupt tar archives** (mid-archive
  bad checksum; GNU base-256 checksum). Latent — no corpus fixture reaches it.
- **#124 — widen tier-2 unsatisfiable generator diversity.** The differential
  harness builds conflicts from a single fixed shape; broaden the generator.
- **#167 — teach in-process runners to honor the `project-dir` control file.** Needed
  so workspace-root-in-subdirectory fixtures (e.g. fixture-288) run under the
  in-process adapter, not just the CLI.
- **#166 — workspace + dev-deps resolve fixture.** Both impls seed member dev-deps in
  workspace mode but no fixture exercises it.
- **#135 — CLI-only `milpa show` fixture surfacing cond_requires** (#26 S6 follow-up).

## Why one RFC

One conformance vocabulary: a single normative stderr/error-slug contract, a fresh
cross-impl baseline, and a corpus-widening discipline (every divergence becomes a
fixture). The fixes share a baseline and a "promote latent divergence to a pinned
fixture" workflow — see `rfc-property-based-testing.md` §Counterexample lifecycle and
the #72 promotion infrastructure.

## Open questions

- Normative stderr prefix: bare `milpa:`, `<CODE>:`, or both (code + message)?
- Does encoder-determinism (#146 blocker) need its own slice first?

## Slices

TBD. Slice 0 = fresh Rust baseline + dup-issue reconciliation. #156 (stderr prefix)
is a small spec-then-align win; likely early.
