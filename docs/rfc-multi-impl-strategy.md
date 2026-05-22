# RFC: multi-implementation strategy — spec + Python + Rust (+ optional Nim)

**Status**: Proposed (commitment for v1.5 onward; v0/v1 stays single-impl Python)
**Author**: Corey Leavitt
**Date**: 2026-05-22

## Why this RFC exists

milpa's structural ambitions — content-addressed identity, declarative
manifest, multi-provenance, pluggable transports, content-addressed
toolchain — are research-grade claims. A research claim with **one
implementation** is just code: there's no way to distinguish "this is
the model" from "this is whatever the code happens to do." A research
claim with **two conformant implementations** is a *specification*:
ambiguities surface as inter-impl disagreements, the spec becomes
precise *because* the implementations disagree until it's tightened.

This RFC commits milpa to that discipline. After v1 ships, milpa
becomes:

1. A **spec** (versioned, separately maintained) that defines manifest
   grammar, lockfile grammar, identity algorithm, resolution algorithm,
   fetcher protocol, and CLI contract.
2. A **conformance test suite** (black-box input/output fixtures) that
   any implementation must pass to claim conformance.
3. Two reference implementations — **Python** (research, extensibility,
   established) and **Rust** (distribution, performance, bootstrap-
   independent).
4. Optionally, a third **Nim** implementation for dogfooding (v3+).

This RFC also supersedes the earlier issue #53 (Python binary
distribution via PyInstaller/zipapp), which becomes unnecessary
once the Rust reference implementation ships pre-built binaries.

## The principle

> A single-implementation tool is whatever its code does. A
> multi-implementation system is whatever its spec says, with the code
> serving as a check on the spec's clarity. milpa's structural claims
> (content-addressed identity especially) are testable only with
> differential validation across implementations.

Concretely: the spec stops being a doc that drifts from the code and
starts being the contract that bounds both impls.

## Why Rust over Nim for the second implementation

The bootstrap argument is decisive:

**With Python milpa**, a user runs `pip install milpa` or
`uv tool install milpa`. Python is universally available. milpa can
then fetch nim (per `rfc-toolchain-content-addressing.md`). Works on
machines with no Nim installed.

**With a Rust milpa**, a user runs `cargo install milpa` (if they have
Rust), OR downloads a pre-built static binary via `curl install.sh`
(if they have neither Rust nor Nim). The binary is self-contained:
linux-musl static link, macOS universal binary, Windows .exe. milpa
then fetches nim. Works on machines with no Rust *and* no Nim — the
binary is the bootstrap.

**With a Nim milpa**, the user needs nim already installed to build
or run milpa-the-Nim-binary. Chicken-and-egg: how do you install a
Nim tool that's supposed to install Nim for you?

The blasphemy framing is wrong: Rust isn't competition for Nim, it's
the *vehicle* that lets milpa bootstrap Nim without requiring Nim.
The polyculture metaphor includes the seeds you bring with you to
plant the field.

Boring engineering wins also favor Rust:

- Best-in-class CLI ecosystem (clap, indicatif, ratatui)
- Cargo's UX is the closest reference for what milpa is trying to be
- Static linking on linux-musl, macOS universal, Windows .exe — all
  solved problems
- Performance crushes Python on large dep trees (matters when
  Phase B content-hash dedup runs over cross-project stores)
- Wider contributor pool than Nim
- `serde` + `kdl-rs` give us KDL parsing in Rust trivially
- `git2` (libgit2 bindings) is solid; `gix` is the pure-Rust alternative

Nim as a third implementation is *symbolic* (dogfooding, "Nim tool
written in Nim") and worth doing eventually, but it's v3+ work and
doesn't solve the bootstrap problem.

## Architecture

```
            ┌─────────────────────┐
            │  milpa-spec         │  ←─ canonical contract
            │  (versioned doc)    │     manifest, lockfile,
            └──────────┬──────────┘     identity, resolution,
                       │                 fetchers, CLI
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │ Python   │  │ Rust     │  │ Nim      │
  │ impl     │  │ impl     │  │ impl     │
  │ (v0/v1)  │  │ (v2)     │  │ (v3+)    │
  │ research │  │ binaries │  │ dogfood  │
  └────┬─────┘  └────┬─────┘  └────┬─────┘
       │              │              │
       └──────────────┼──────────────┘
                      ▼
            ┌─────────────────────┐
            │  Conformance suite  │  ←─ black-box validation
            │  (input fixtures →  │     spec-version-tagged
            │   expected output)  │
            └─────────────────────┘
```

The spec is the source of truth. Each impl declares which spec
version it conforms to. The conformance suite is shared across impls
and tagged by spec version. A user picks the impl that fits their
deployment (pip-installable Python, single-binary Rust, future
dogfood Nim); the *behavior* is identical because conformance demands
it.

## The spec — what it contains

A separate repo: `coreyleavitt/milpa-spec` (TBD on naming). Or
initially `docs/spec/` in this repo, lifted to its own repo when
stable.

Sections:

1. **Manifest grammar**
   - KDL schema (EBNF or pseudo-grammar)
   - Every node and attribute documented
   - Reserved future-extension nodes
   - Versioning policy (manifest schema versions)

2. **Lockfile grammar**
   - KDL schema, versioned (v1 → v2 → ...)
   - Migration semantics between versions
   - Required vs optional fields per version

3. **Identity algorithm**
   - Exact bytes hashed for `content_hash` (per
     `rfc-content-addressed-identity.md` §What exactly is "content")
   - File order canonicalization (POSIX relpath sort)
   - Mode encoding (executable bit only)
   - Symlink handling
   - `.git/` exclusion rules
   - Hash algorithm encoding (multihash)

4. **Resolution algorithm**
   - PubGrub semantics (terms, incompatibilities, partial solution)
   - Conflict-narration format (derivation chain shape)
   - Backtracking discipline
   - Cycle detection
   - Strategy modes (MaxVer / SemVer / MinVer)

5. **Fetcher protocol**
   - Provenance kinds (git, tarball, hg, fossil, local, OCI, IPFS)
   - Per-kind manifest grammar
   - FetchResult contract
   - Pre-fetch vs post-fetch verification rules
   - Partial-state recovery

6. **CLI contract**
   - Every command + every flag
   - Exit code semantics
   - Output format (stderr vs stdout)
   - Environment variable contract

7. **Conformance requirements**
   - What a conformant impl MUST do
   - What a conformant impl MAY do (extensions, optional features)
   - What a conformant impl MUST NOT do (banned behaviors)

## The conformance test suite

Lives in `coreyleavitt/milpa-spec` repo under `tests/`. Black-box
fixtures, language-neutral:

```
tests/
  fixture-001-single-url-dep/
    milpa.kdl              # input manifest
    registry.json          # input registry state (frozen)
    mocked-fetches/        # what fake fetcher returns for each URL
      example.com_foo.git_main/
        sha
        content
        nimble
    expected/
      milpa.lock           # exact expected lockfile bytes
      nim.cfg              # exact expected nim.cfg bytes
      _deps_structure.txt  # expected _deps/ layout
  fixture-002-url-dedup/
    ...
  fixture-NNN-...
```

A conformance runner invokes each implementation against each
fixture and diffs the output against the `expected/` files. Any
diff is a conformance failure. Each fixture is tagged with the
spec-version it tests.

Implementations declare their conformance level:

```toml
# Python impl
[milpa]
spec-version = "2.0"
conformance-suite = "milpa-spec @ tag v2.0"
status = "fully-conformant"  # | "partial" | "experimental"
```

## Why the spec version matters

Implementations evolve at different paces. New spec features land in
spec-version N+1; both impls implement at their own cadence; both
are conformant-to-spec-vN while v(N+1) is in flux. This is the
HTTP/1.1 vs HTTP/2 vs HTTP/3 pattern — implementations declare which
version they speak, users know what they're getting.

Spec versions are not the same as implementation versions. The
Python impl's version (e.g. 1.4.2) refers to the impl's release;
the spec-version (e.g. 2.0) refers to the contract.

## Phasing

### v0 → v1: Python only, no spec yet

Iterate freely. Don't pre-freeze a spec while design is still moving.
v0 closed (fresco-unblock done); v0.x and v1 land Tier 1-3 priorities
in Python.

**Don't do during this phase:**
- Spec extraction (premature; spec would describe code that's still
  changing)
- Rust impl (no spec to implement against)
- Conformance suite (no second impl to validate)

### v1.5: spec extraction

When v1 is feature-complete, extract the spec from the working
Python implementation. This is a *documentation pass*, not a
redesign:

1. Write the spec by reading what Python milpa actually does
2. Identify every "the implementation just decides X" point and turn
   it into an explicit spec rule
3. Build the conformance test suite from the existing test fixtures
   + new edge cases that surface during extraction
4. Tag spec v1.0; Python impl declares conformance

**Estimated effort:** 4-6 weeks of doc work. Not parallelizable with
v1 feature work; sequential.

### v2: Rust reference implementation

Once the spec is stable, start the Rust impl as a separate repo
(`coreyleavitt/milpa-rs`):

1. Implement against spec v1.0
2. Run the conformance suite continuously
3. Surface every disagreement with Python as either:
   - A Python bug (Python diverged from spec)
   - A Rust bug (Rust diverged from spec)
   - A spec ambiguity (spec wasn't precise enough → spec patch)
4. When fully conformant, ship pre-built binaries via GH releases

In parallel with v2 work, the v2 toolchain RFC
(`rfc-toolchain-content-addressing.md`) lands in both impls. Each
new spec feature increments the spec version; conformance is
re-validated at each version.

**Estimated effort:** 3-4 months for Rust impl to reach Python parity
on spec v1.0. Toolchain RFC adds another 2-3 months in both impls.

### v3+: optional Nim third implementation

After v2 ships, a Nim impl (`coreyleavitt/milpa-nim`) becomes feasible
because the spec is stable. Implementation uses intonaco for its
reactive substrate (architectural symmetry: the Nim tool for Nim
uses the Nim substrate). Validates spec language-independence.

Doesn't solve the bootstrap problem (still requires Nim to install),
but adds dogfooding value and bus-factor protection.

**Optional. Defer until the spec has proven stable across Python + Rust.**

## Risks + mitigations

### Risk: spec drift if Python ships features faster than Rust

Python is the active development impl during v0/v1. Once Rust starts
in v2, Python continues evolving. If the spec patches every Python
feature change, Rust always lags.

**Mitigation:** spec freezes at versions. Python ships
"experimental" features outside spec-version conformance, then
spec-versions when stable. Rust catches up at version boundaries,
not feature-by-feature.

### Risk: maintenance overhead of two impls

Two codebases means double the bug surface, double the
documentation, double the release process.

**Mitigation:** the conformance suite catches divergences
automatically. Most maintenance is shared (spec + suite). Each impl
maintains its own language-specific surface; bugs in one impl don't
require the other to change.

### Risk: "why have two impls when one would do?"

Adoption story is more complex.

**Mitigation:** clear positioning. Python = research, easily
extensible, install via pip. Rust = production, single binary,
install via curl. Users pick based on deployment context, not
"which is better." Same model as cpython vs pypy in Python land.

### Risk: spec extraction is hard and never happens

Spec extraction at v1.5 is a non-glamorous 4-6 week doc effort.
Easy to skip in favor of more features.

**Mitigation:** spec extraction is the gate between v1 and v2. No
Rust work starts until spec exists. This is a calendar commitment,
not a "we'll get to it" aspiration.

### Risk: third-party impls don't materialize

The "multi-impl strategy" claim is weaker if there's no actual
third party trying to write a milpa-conformant implementation.

**Mitigation:** the value is in the *spec itself* + the validation
discipline, not in waiting for third parties. Two impls already
validate the model. Third parties can come or not; the spec stands.

## What this RFC supersedes

- **Issue #53** (Python binary distribution via PyInstaller / zipapp /
  shiv). Becomes unnecessary once Rust impl ships pre-built binaries.
  Closed as superseded.

## What this RFC commits milpa to

- After v1 ships, **the spec exists** as a separate canonical doc.
- After v1 ships, **two reference implementations** (Python + Rust)
  run continuously against a shared conformance suite.
- Pre-built binary distribution comes from the Rust impl, not from
  packaging Python.
- The Python impl remains canonical for research / extensibility;
  the Rust impl is canonical for production deployment.
- Spec ambiguities are first-class bugs, equally as severe as impl
  bugs.

## What this RFC does NOT commit milpa to

- A timeline for the Nim third implementation (deferred to v3+,
  optional)
- A specific spec format (markdown? formal grammar? hybrid?
  decide during extraction)
- A specific differential-testing framework (decide when building
  the conformance suite)
- A separate repo for the spec vs `docs/spec/` in milpa itself
  (start in-tree, lift when stable)
- Third-party fetcher implementations (those compose with either
  impl independently per `rfc-pluggable-fetchers.md`)

## Acceptance: testable invariants

The strategy succeeds when:

1. The spec exists at a separately versioned location (repo or
   directory).
2. Both Python and Rust impls declare conformance to the same spec
   version.
3. The conformance suite has ≥100 fixtures covering each spec
   section.
4. Differential testing runs continuously in CI for both impls.
5. A new milpa user can install via `pip install milpa` (Python),
   `cargo install milpa` (Rust source), or `curl install.sh` (Rust
   binary), and get the same behavior.
6. A spec ambiguity discovered through a Python/Rust disagreement
   gets fixed in the spec, then trickles down to both impls.

## Issues this RFC will spawn (later, not now)

These will be filed when the relevant work begins (v1.5 onward).
Filing now as a forward-looking placeholder list:

- spec extraction methodology + initial spec v1.0 draft (v1.5)
- conformance test suite — fixture format + runner (v1.5)
- `coreyleavitt/milpa-rs` repo bootstrap (v2)
- Rust impl: manifest parser + KDL handling (v2)
- Rust impl: fetcher protocol + Git/Tarball/Local fetchers (v2)
- Rust impl: PubGrub solver (v2)
- Rust impl: lockfile + nim.cfg emission (v2)
- Rust impl: CLI parity with Python (v2)
- Binary distribution + GH releases for milpa-rs (v2)
- Differential CI — run conformance suite against both impls (v2)
- Nim impl bootstrap — `coreyleavitt/milpa-nim` (v3, optional)
