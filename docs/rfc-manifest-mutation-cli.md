# RFC: `milpa add` / manifest-mutation CLI (STUB)

Status: **stub** — triage grouping from the 2026-06-06 issue audit. Not yet designed.
Umbrella: (umbrella issue links here). Milestone: *v0.x — ergonomic CLI + manifest editing*.

## Problem

`milpa add NAME --git URL` (#16) shipped on top of the
`apply_manifest_change_with_resolve` primitive, which already supports any
transport and any manifest edit. What's missing is the **CLI surface** for every
other source kind and for workspace manifests. These are separate UX cycles but
one design space (the same writer + re-resolve orchestration), so group them.

## Issues unified

- **#99 — `milpa add <name>` (named dep via the tianguis index).** Post-#97 the
  index is authoritative for named deps but there's no CLI path to add a
  `NamedDep` by name. Validate against the index, write via `manifest_writer`,
  re-resolve.
- **#83 — `--tarball` / `--local` / `--version` transport flags.** Each appends
  the matching dep kind (TarballDep / LocalDep / …) via the same primitive.
- **#84 — `milpa add NAME URL` transport auto-detection.** Infer the dep kind
  from URL shape (path → local, `.tar.gz` → tarball, git host / `.git` → git,
  bare name → named/index) so users don't pick a flag.
- **#81 — workspace-manifest mutation.** `mutate_manifest_file` currently refuses
  workspace manifests; lift that once `milpa workspace add-member` / overrides
  editing need it.
- **#96 — `publish` auto-discover `--name`/`--version`** from `milpa.kdl` + git
  tag (adjacent: a manifest-derived CLI ergonomics win on the publish path).

## Why one RFC

Every item is "a CLI verb that edits `milpa.kdl` then re-resolves," all sharing
`apply_manifest_change_with_resolve` + `manifest_writer`. Designing the flag
grammar, the auto-detection precedence, and the workspace-mutation guard-lift
together keeps the surface coherent (one `add` mental model, consistent probing
behavior, consistent re-resolve semantics).

## Design direction (sketch — to be settled)

- Settle the `add` precedence: explicit flag > URL-shape detection > bare-name →
  index lookup, with a cheap `git ls-remote` / HEAD probe as the last resort.
- TOFU semantics for tarball sha256 (pin on first fetch); `--version` for named.
- Lift the workspace-manifest refusal behind the specific verbs that need it.

## Open questions

- How aggressive should URL probing be (network on `add`)?
- Workspace verbs (`workspace add-member`) — same RFC or a thin follow-up?

## Slices

TBD. #99 (named add) is the natural first slice now that #97 makes the index
authoritative.
