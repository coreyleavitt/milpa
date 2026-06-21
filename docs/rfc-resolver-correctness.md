# RFC: Resolver & frozen-path correctness (STUB)

Status: **stub** — triage grouping from the 2026-06-21 issue audit. Not yet designed.
Umbrella: #172. Milestone: *v0.x / v1 — correctness*.

## Problem

A set of resolver-core and frozen-fast-path correctness issues that don't belong to
any feature RFC — they're invariants on dedup identity, named-dep qualification, and
the frozen-resolve fast path. Each is a place where the resolver can produce a
subtly-wrong graph, mis-cache, or silently no-op.

## Issues unified

- **#108 — qualified `NamedDep(namespace, name)` end-to-end.** `resolver.py`'s
  `seen_named: set[str]` dedups transitive named deps by **bare name**, so two deps
  with the same bare name in different namespaces collide. (Verified live 2026-06-21:
  `seen_named` is still bare-name keyed.) Needs resolver/manifest/BFS/callback
  threading of the qualified identity.
- **#115 — legacy `registry` provenance disqualifies the frozen fast-path.** A
  lockfile entry with the pre-#97 `kind "registry"` provenance trips
  `FROZEN-LEGACY-REGISTRY-PROVENANCE` and forces a full re-fetch on every `fetch`.
  (Verified live 2026-06-21 in `frozen.py`.) Needs a migration/upgrade path.
- **#131 — Python URL/tarball/local resolve workers bypass the `resolve_edges`
  coordinator.** The per-transport workers instantiate edge sources directly,
  duplicating the seam the named path goes through. SSOT violation.
- **#142 — frozen manifest-coverage check is not alias-aware.**
  `FROZEN-MANIFEST-DEP-NOT-IN-LOCK` matches manifest deps against lockfile **names**,
  not dedup **aliases**; after Phase B dedup, two same-content deps collapse and the
  check false-positives.
- **#129 — `milpa fetch --certificate` is a silent no-op in workspace mode (Rust).**
  The `ManifestDoc::Workspace` branch returns `Ok(0)` without consulting `cert_path`.
- **#168 — workspace cyclic-symlink member yields divergent slug** (PATH-ESCAPE vs
  DIR-MISSING). Pathological containment edge; impls disagree on the error.

Note: **#109** (migrate `resolve_workspace` named deps to Phase A/B backtracking) was
**verified DONE on 2026-06-21** — workspace named deps now flow through the shared
`_run_bfs_wave_loop` → `_enumerate_named_stubs` (full solver backtracking). It is NOT
part of this RFC; close it.

## Why one RFC

These are the resolver/frozen invariants that survived the feature RFCs. They share
the dedup-identity model (#108/#142), the frozen fast-path (#115/#142), and the
resolve-edges seam (#131) — fixing them piecemeal risks re-introducing the same
alias/identity confusion. #129/#168 are the cross-impl correctness tail and
coordinate with `rfc-conformance-parity.md`.

## Open questions

- #108: does qualified naming need a manifest grammar change (`namespace/name`) or is
  it purely an internal identity key?
- #115: silent in-place lockfile migration, or require explicit `milpa update`?

## Slices

TBD. #108 (qualified named dedup) is the deepest; #115/#142 (frozen path) cluster
and are likely first.
