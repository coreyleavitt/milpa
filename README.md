# milpa

A dependency resolver for Nim projects.

## What it is

milpa reads a `milpa.kdl` manifest, clones URL-based and named-package dependencies into a local `_deps/` directory, resolves transitive deps, and emits a `nim.cfg` with `--path:` lines so `nim` compiles your project directly. No `nimble` involvement during builds.

Built because `nimble v0.22.2`'s vnext SAT solver cannot resolve two URL-based `requires` that share a transitive URL — a real-world case fresco hits (fresco requires intonaco URL, intonaco requires chronos URL, fresco also requires chronos URL → "Unsatisfiable dependencies"). milpa sidesteps the whole resolver layer; nimble stays useful for nim-lang-registered packages where its tooling works, but you don't have to be at its mercy for URL-based deps.

## Name

The Mesoamerican multi-crop polyculture: corn, beans, and squash grown together — each crop supporting the others (corn provides stalks, beans fix nitrogen, squash shades the ground). Apt for a dependency resolver: packages grow together; the tool's job is figuring out which combinations are stable.

## Status

v0 shipped — fresco's hard split unblocked. v0.x and v1 in progress on Tier 1+2 features (`.nimble` compat, parallel fetch, resolution strategies, content-addressed identity Phase A). See `docs/comparison-vs-nimble-atlas.md` for the roadmap.

## What's structurally distinct

milpa separates **identity** (sha256 of source tree) from **provenance** (URL, ref, commit SHA). Existing Nim resolvers conflate them by pinning commit SHA. milpa records both — identity for trust-independent verification, provenance for delivery — which enables cross-fork dedup, mirror substitution, offline lockfile verification, and (when Phase B-C land) a global content-addressed package store.

See [`docs/identity-and-provenance.md`](docs/identity-and-provenance.md) for the model and [`docs/rfc-content-addressed-identity.md`](docs/rfc-content-addressed-identity.md) for the structural argument.

## Why not fix nimble

Considered. nimble has ~3 active maintainers and the design issues are structural (Turing-complete nimscript manifests, URL not first-class, conflated PM+build+task-runner). Fixes reach users via Nim minor releases — months out. milpa solves the resolution problem in days, locally, with zero ecosystem-coordination cost. nimble continues to work fine for nim-lang-registered packages where you don't need URL-based deps.

## Why not full uv-for-nim

Considered. 8-12 weeks for a competent replacement covering resolver + build invoker + task runner. milpa intentionally scopes to *just* the resolver and emits paths that any `nim` invocation can consume — ~600 lines of Python instead of a multi-month project.

## License

Apache 2.0.
