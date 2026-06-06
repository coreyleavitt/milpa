# RFC: Index version-selection semantics (STUB)

Status: **stub** — triage grouping from the 2026-06-06 issue audit. Not yet designed.
Umbrella: (umbrella issue links here). Milestone: *resolution semantics*.

## Problem

After milpa#97 the tianguis index is the sole source of named-dep versions, and
`tianguis_client.resolve_named` eagerly returns the single highest version
satisfying *whichever constraint arrived first*. Three open issues all turn on
the same missing machinery — **walking the index version list and materializing
more than one candidate** — so they should be designed together, not piecemeal.

## Issues unified

- **#100 — collect all constraints for a named dep before resolving (LATENT BUG).**
  `resolver.py` `seen_named` dedups by *name only*. Two transitive deps requiring
  the same package under different constraints (`chronos>=1.0` + `chronos>=2.0`)
  → the first-seen constraint wins, the second is silently dropped at the submit
  gate, and the conflict resurfaces later as an opaque solver "no version
  satisfies" error naming neither the conflict nor the deps. The old registry
  path masked this (it listed all tags; the solver filtered post-hoc). This is the
  real mechanism behind the "single-version provider" observation from the #97
  review (refuted there as a *regression* — it is pre-existing — but it is a
  genuine correctness gap).
- **#98 — minver/semver strategy.** The old `registry.resolve_named` threaded a
  `Strategy` enum (maxver/minver/semver); #97 scoped to maxver. Strategy over the
  index means the resolver must walk the version list in strategy order.
- **#86 — `exclude-newer` time-bounded resolution.** A manifest-level
  `resolution { exclude_newer "<ts>" }` setting that filters out index
  versions / refs / tarballs published after a timestamp (uv's `--exclude-newer`).

## Why one RFC

All three require the resolver to stop treating a named dep as "one eagerly-chosen
version" and instead **accumulate the full constraint set for a name, then select
from the index's candidate list** under a policy (strategy + time bound). #100's
fix *is* the substrate #98 and #86 build on. Designing them separately would mean
rebuilding the same constraint-accumulation + multi-candidate-materialization path
three times.

## Design direction (sketch — to be settled)

- Replace name-only `seen_named` with a name→constraint-set accumulator; defer
  `resolve_named` until the constraint set for a name is closed (or feed multiple
  candidate versions to the solver so it can backtrack, restoring the old
  list-all-tags semantics without the old network cost).
- Make `resolve_named` strategy-aware (walk ascending/descending/semver-major).
- Thread an optional `exclude_newer` timestamp into candidate filtering; needs an
  index-recorded publish timestamp per version (tianguis schema question).

## Open questions

- Eager-accumulate vs. feed-many-candidates-to-solver (the cleaner restoration of
  pre-#97 backtracking) — which model?
- Does `exclude_newer` need a publish timestamp in the tianguis index schema?
  (cross-repo: tianguis).
- Error message for the #100 conflict case (name the two constraints + sources).

## Slices

TBD once the design is settled. #100 (the bug) likely lands first as a
correctness fix with its own regression test.
