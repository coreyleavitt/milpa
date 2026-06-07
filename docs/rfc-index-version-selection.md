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

## Design direction — settled at the architecture level (2026-06-06)

The root cause is **not** in the resolver — it's that the tianguis index carries
no dependency edges, so milpa must *fetch* a package to learn its requires, which
forces the eager single-version pre-resolution layer that drops the second
constraint. Every best-in-class resolver avoids this by keeping dep metadata cheap
and lazy and letting the solver own selection:

- **uv** (pubgrub-rs): PubGrub accumulates constraints natively; `get_dependencies`
  is a cheap per-version metadata fetch (PEP 658), never the artifact.
- **Cargo**: the crates.io index *is* per-version `{name, version, deps[]}` — the
  whole graph resolves with zero crate downloads.

milpa **already has the constraint-accumulating PubGrub** (`solver.py`); it's being
starved by the eager layer. So the real fix is the **Cargo/uv model: put per-version
dep edges in the tianguis index** → milpa's provider answers `get_dependencies`
from the index → the eager layer is retired → PubGrub resolves natively → **#100
dissolves**, with backtracking + good conflict diagnostics for free. #98 (strategy)
and #86 (exclude-newer; `published_at` already exists per index version) ride the
same provider.

This depends on tianguis schema work and is sequenced **after** tianguis #32
(identity = `(namespace, name)`), because dep edges reference packages by identity:

1. tianguis **#32** — settle `(namespace, name)`, designed to be referenceable.
2. tianguis **`docs/rfc-index-deps.md`** (DRAFT, committed) — per-version dep
   metadata citing #32 identity.
3. milpa — provider gains cheap `get_dependencies`; retire the eager named-dep
   layer; #98/#86 land on the native PubGrub path.

**Rejected:** the in-architecture "re-resolve against the accumulated intersection
+ re-fetch on conflict" patch — it's throwaway machinery the index-deps model
deletes ([[feedback_no_workarounds]]). No stopgap is being built; #100 stays open,
blocked on the index-deps work.

## Open questions

- Constraint grammar in the index `requires` edges (align with #27); see the
  tianguis RFC's open questions (vendor-bot edge extraction from `.nimble`,
  non-index deps, edge attestation, schema versioning).
- Strategy (#98) semantics once the solver owns selection (minver/semver as a
  PubGrub version-ordering policy).

## Slices

TBD — gated on tianguis #32 + `rfc-index-deps`. #100 is **blocked on index-deps**
(not a standalone milpa fix). #98 and #86 are the milpa-side resolver work once the
index carries edges + timestamps (the latter already present).
