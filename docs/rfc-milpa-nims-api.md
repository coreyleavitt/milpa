# RFC stub: `milpa.nims` — typed-data API for user-owned `config.nims`

**Status**: Stub / research direction (deferrable, post-v2)
**Author**: Corey Leavitt
**Date**: 2026-05-22

## Why this stub exists

`decision-config-nims.md` settles the immediate question: milpa owns
`nim.cfg`, user owns `config.nims`. But there's an attractive
intermediate design worth capturing before it's lost: milpa could emit
a separate file — `milpa.nims` — exposing its resolved state as typed
constants and read-only procs, which the user's `config.nims` can
`import`.

This stub records the idea so it survives. Implementation is post-v2
work, gated on demand.

## The shape

```nim
# milpa-generated milpa.nims (auto-regenerated on every milpa fetch)
# DO NOT EDIT — milpa overwrites this file.

const MILPA_LOCK_VERSION* = 2
const MILPA_KIND* = "library"

# Per-dep constants
const CHRONOS_PATH* = "_deps/chronos"
const CHRONOS_SHA* = "90660858a9da783c6edf14c269d5b6165e7f6bb2"
const CHRONOS_VERSION* = "0.0.1"
const CHRONOS_CONTENT_HASH* = "sha256:e69bd0696a3ac88ce931dae1f1e5b2af7710c361d141e0724551a8afb382af32"

const INTONACO_PATH* = "_deps/intonaco/src"
# ... etc

# Queryable
proc depPath*(name: string): string = ...
proc depVersion*(name: string): string = ...
proc depContentHash*(name: string): string = ...
proc deps*(): seq[string] = ...

# Toolchain (post-v2 toolchain RFC)
const NIM_VERSION* = "2.2.10"
const NIM_PATH* = "_toolchain/bin/nim"
```

User's hand-written `config.nims` can then:

```nim
# config.nims (user-owned, hand-written)
import milpa

when defined(release):
  switch("opt", "speed")
  # Add link flags for a specific dep's directory
  switch("passL", "-L" & milpa.depPath("openssl") & "/lib")

when defined(linux) and defined(release):
  # Use the chronos SHA in a custom define for diagnostic builds
  switch("define", "buildHash:" & milpa.CHRONOS_SHA)
```

## Why this is interesting

1. **No NimScript generation by milpa.** `milpa.nims` is pure data —
   constants and read-only procs. No `if`/`else`, no `case`, no logic.
   It compiles as a declaration; it doesn't run anything at config
   time. The declarative-manifest commitment is preserved.

2. **Composes with user logic.** Users who need conditional compile
   flags or platform-specific tweaks write their own `config.nims`,
   but they can query milpa's state as typed constants instead of
   hardcoding `_deps/chronos` everywhere.

3. **Refactor-safe.** When milpa renames or moves a dep, every
   `milpa.depPath("foo")` lookup updates automatically. Hardcoded
   `--path:_deps/foo` strings would silently break.

4. **Typed.** NimScript benefits from Nim's type system. A typo in
   `milpa.depPaht("chronos")` is a compile error, not a runtime
   surprise.

5. **Discoverable.** A user can `nim doc milpa.nims` (or read it
   directly) to see what's available without consulting docs.

## Why this is deferred

1. **Not needed for v0/v1.** Users with simple needs don't write
   `config.nims` at all. milpa.kdl + nim.cfg covers the common case.

2. **Adds an output surface to maintain.** Every spec version change
   that touches dep representation has to propagate to `milpa.nims`
   schema. More cells in the conformance test suite.

3. **Doesn't solve a problem v0/v1 users actually have.** It's
   anticipatory — solving for advanced users who will eventually
   exist, not for adoption-blocking pain today.

4. **Couples to the toolchain RFC.** The most interesting fields
   (NIM_PATH, toolchain identities) only exist post-v2.

## When to revisit

Revisit when one of these triggers fires:

- A real user reports friction integrating milpa with their
  hand-written `config.nims` — specifically asking for typed access
  to milpa's resolved state.
- The toolchain RFC (`rfc-toolchain-content-addressing.md`) lands and
  there's demand for cross-toolchain-version conditional builds.
- A research direction needs build-time access to milpa's identity
  claims (e.g. embedding content hashes into binaries for
  provenance attestation at runtime).

Until then: filed, sitting.

## Open questions to resolve before implementing

- What's the granularity? Per-dep constants (`CHRONOS_PATH`)? Or only
  the queryable proc interface (`milpa.depPath("chronos")`)? Or both?
- How do we handle dep names that aren't valid Nim identifiers
  (hyphens, etc.)? Sanitize? Reject? Provide both raw + sanitized?
- Does `milpa.nims` need to be regenerated as a precondition for
  every nim invocation, or only on `milpa fetch`?
- Spec impact: milpa.nims would be part of the spec's CLI contract
  ("which files does milpa write"). Versioning needed.

These are answerable when the work starts; no need to settle them
now.
