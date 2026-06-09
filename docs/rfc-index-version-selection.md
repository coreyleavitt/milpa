# RFC: Index version-selection semantics (STUB)

Status: **stub** — triage grouping from the 2026-06-06 issue audit. Not yet designed.
Umbrella: (umbrella issue links here). Milestone: *resolution semantics*.

> **Correction (2026-06-08).** An earlier draft of this RFC (commit `01f905d`,
> 2026-06-06) framed #100 as a live correctness bug rooted in a missing index
> feature. That framing was **overtaken within ~18 hours** by the P3.x work
> (`079dbf0`/`8f1aa35`/`130ecd1`, 2026-06-07): the multi-version named-dep
> provider retired the eager single-version layer on the **main `resolve()`
> path**, so PubGrub now accumulates constraints natively there. A three-lens
> agent review (2026-06-08) verified this against current code — the #100 diamond
> is covered by a passing test (`test_diamond_conflict_named_dep_backtracks`) and
> produces a correct conflict-chain error. **#100's described mechanism is gone
> from the main path.** The only surviving instance of first-constraint-wins is
> `resolve_workspace()` (`resolver.py:931`, still on `_process_named`), tracked
> by **#109** as a small, durable migration — *not* blocked on index-deps. The
> sections below have been corrected accordingly; index-deps remains the right
> model for #98/#86 and for retiring fetch-to-learn-edges, but it does **not**
> own #100's correctness.

## Problem

After milpa#97 the tianguis index is the sole source of named-dep versions. The
remaining work here is selection *policy* over the index's candidate list —
**walking the version list and materializing more than one candidate under a
strategy + time bound** — plus closing the last non-PubGrub-native resolution
path (workspace). These turn on the same machinery, so they are designed together.

## Issues unified

- **#100 — collect all constraints for a named dep before resolving.**
  **Largely resolved (see Correction above).** The main `resolve()` path no longer
  pre-resolves a named dep to one version: `_enumerate_named` registers *all*
  satisfying versions as stubs (constraint passed as `None`, so the solver sees the
  full candidate space), and PubGrub's `effective_set` intersects every consumer's
  constraint at solve time. `seen_named` dedups *enumeration of a name's candidate
  set*, never a chosen constraint. The residual — `resolve_workspace()` still on the
  single-version `_process_named` — is tracked by **#109** (workspace Phase A/B
  migration), a small durable fix, not index-deps work.
- **#98 — minver/semver strategy.** The old `registry.resolve_named` threaded a
  `Strategy` enum (maxver/minver/semver); #97 scoped to maxver. Strategy over the
  index means the resolver must walk the version list in strategy order.
- **#86 — `exclude-newer` time-bounded resolution.** A manifest-level
  `resolution { exclude_newer "<ts>" }` setting that filters out index
  versions / refs / tarballs published after a timestamp (uv's `--exclude-newer`).

## Why one RFC

#98 and #86 both require the resolver to **select from the index's candidate list
under a policy** (strategy + time bound) rather than the current implicit highest-
satisfying default. They ride the same provider surface, so they are designed
together. #109 (workspace migration) is adjacent — it brings the second resolution
entry point onto the same multi-candidate model the main path already uses.

## Design direction — index-deps is for cheap `get_dependencies`, not for #100

The forward architecture play is the **Cargo/uv model**: keep per-version dep
metadata cheap and lazy so the solver owns selection.

- **uv** (pubgrub-rs): PubGrub accumulates constraints natively; `get_dependencies`
  is a cheap per-version metadata fetch (PEP 658), never the artifact.
- **Cargo**: the crates.io index *is* per-version `{name, version, deps[]}` — the
  whole graph resolves with zero crate downloads.

milpa **already has constraint-accumulating PubGrub** (`solver.py`) *and* a
multi-version provider on the main path (P3.x). What it still lacks is cheap
transitive-edge discovery: today milpa must *fetch and parse* each package's
manifest to learn its `requires`. Moving per-version dep edges into the tianguis
index (the **Cargo/uv model**) lets the provider answer `get_dependencies` from the
index — eliminating fetch-to-learn-edges, a real perf/architecture win. #98
(strategy) and #86 (exclude-newer; `published_at` already exists per index version)
ride the same provider.

This is a genuine improvement, but note what it does **not** do: it does not "fix
#100." Constraint accumulation is durable PubGrub substrate that already works and
that index-deps keeps — only the *transport* of dep edges changes. The earlier
draft conflated the two; see the Correction at the top.

The index-deps path depends on tianguis schema work, sequenced **after** tianguis
#32 (identity = `(namespace, name)`), because dep edges reference packages by
identity:

1. tianguis **#32** — settle `(namespace, name)`, referenceable. *(CLOSED)*
2. tianguis **`docs/rfc-index-deps.md`** (DRAFT) — per-version dep metadata citing
   #32 identity. Still a draft stub; not yet sliceable.
3. milpa — provider gains cheap `get_dependencies`; retire fetch-to-learn-edges;
   #98/#86 land on it.

**Still rejected:** any "re-fetch on conflict" re-resolution loop — that *is*
throwaway machinery the index-deps model deletes ([[feedback_no_workarounds]]).
What the earlier draft wrongly bundled into that rejection — constraint
accumulation — is not a stopgap; it is the kept substrate and already lives in the
solver.

## Open questions

- Constraint grammar in the index `requires` edges (align with #27); see the
  tianguis RFC's open questions (vendor-bot edge extraction from `.nimble`,
  non-index deps, edge attestation, schema versioning).
- Strategy (#98) semantics once the solver owns selection (minver/semver as a
  PubGrub version-ordering policy).

## Slices

- **#109 (workspace migration)** — milpa-only, *not* gated on index-deps. Migrate
  `resolve_workspace()`'s named-dep path off single-version `_process_named` onto
  the Phase A/B `_enumerate_named` model the main path already uses. Closes the last
  first-constraint-wins site. Small + durable.
- **#98 / #86 (strategy + exclude-newer)** — selection policy over the candidate
  list. Can begin on the current fetch-to-learn-edges provider; cleaner once
  index-deps lands. `published_at` for #86 is already in the index schema.
- **Index-deps consumer work** — gated on tianguis `rfc-index-deps` (a draft stub,
  itself unblocked now that tianguis #32 is closed). Retires fetch-to-learn-edges.

**Spec note (critical-path).** When `spec/resolver-semantics.md` is extracted,
it must specify the **PubGrub-native** constraint-accumulation target (all
consumers' constraints intersect; empty intersection → structured conflict chain
naming every contributing dep), explicitly **not** any eager/first-constraint-wins
behavior. Add a diamond-conflict conformance fixture (rides #72). Without this the
Rust port could inherit a spec ambiguity or codify the stale behavior.
