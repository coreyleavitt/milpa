# RFC: Rust reference implementation — design & in-repo coexistence

- **Status:** Draft — rfc-flow stage 2 (architecture review, rounds 1+2 applied)
- **Depends on:** spec v1.0 (`docs/spec/`), the spec-v1 conformance suite
  (`tests/conformance/spec-v1/`), `rfc-multi-impl-strategy.md`
- **Supersedes:** nothing (this is the "separate later RFC" the
  reaching-rust-rewrite gate deferred Rust-port design to)

## 1. Why

The spec is frozen at v1.0 and the Python implementation is its reference
oracle. Per `rfc-multi-impl-strategy.md`, the next implementation is a
**Rust reference implementation** — an independent, from-spec reimplementation
whose purpose is twofold:

1. **Validate the spec.** A second implementation written from the spec (not
   from the Python source) is the only real test of whether the spec is
   complete and unambiguous. Every divergence is either a Rust bug or a spec
   hole; the latter feed the amendment process.
2. **Become the performance/distribution reference.** Pure-Rust, statically
   linkable, no interpreter — the long-term distributable milpa.

This RFC designs **how the Rust impl is built and how it coexists with the
Python impl in this repo** — not the line-by-line port (that's the slice
grind in stage 3).

## 2. Scope

**In scope (v1 Rust reference = "done"):**
- A pure-Rust implementation that **passes every fixture in
  `tests/conformance/spec-v1/`** via its own harness.
- In-repo coexistence layout (Python + Rust side by side, one shared spec +
  one shared fixture corpus).
- A Rust conformance harness consuming the **same** fixture format the Python
  runner does.

**Out of scope:**
- Multi-repo split and a cross-repo conformance harness. We may break the
  Rust impl into its own repo later; we explicitly do **not** design for that
  now. The shared corpus lives in this repo and both impls read it from disk.
- PyO3 / Python bindings. The reference is pure Rust (§4.2). Bindings are a
  later, separate concern.
- Any behavior outside the spec's conformance surface (publish, keepalive,
  index authoring — all out of spec-v1 conformance already).
- Rewriting the Python impl. It stays as the second oracle and the fixture
  generator.

## 3. Non-negotiables (inherited)

These carry over from the project's standing commitments and constrain the
Rust design:

- **Single source of truth.** The **fixtures** are the shared truth, not any
  runner. Two runners (Python, Rust) consume one corpus. The spec docs are
  the prose truth; where prose and a fixture disagree, that's a spec defect
  (spec README §4 arbiter rule).
- **Identity ⊥ provenance**, **declarative manifest (no code execution)**,
  **byte-exact outputs** — all spec-mandated; the Rust impl inherits them.
- **Deterministic iteration (round-2).** Byte-exactness plus parallelism-
  invariance (resolver-semantics §4.4) forbid `HashMap`/`HashSet` for any
  collection whose iteration order can affect resolver output or *which* error
  is raised first (the dedup/alias map, the root-authority set, the provenance
  registry). These MUST use `BTreeMap`/`BTreeSet` or insertion-ordered `IndexMap`.
- **Spec-conformance is the bar**, not Python-parity. The Rust impl matches
  the *spec*; the Python impl is a convenience oracle, and where it lags the
  spec (e.g. #117 comment-drop warning) the Rust impl may be *more*
  conformant. Fixtures, not Python output, are authoritative.

> NOTE (round-1 review): the architecture review surfaced that the spec
> itself carries internal contradictions (prose-vs-prose and prose-vs-fixture)
> that a from-spec implementer would trip on — this is exactly purpose (1)
> (validate the spec) firing before a line of Rust is written. These are
> enumerated in **§8** and must be reconciled on `main` (fixtures win, per the
> README arbiter rule) before the affected slices begin. The reconciliations
> tighten ambiguity / align prose to the executable arbiter; they do not
> invalidate the Python impl (which already matches the fixtures), so they are
> permitted within the v1 freeze (README §4 freeze policy).

## 4. Key design decisions

### 4.1 In-repo coexistence layout

The repo stays a Python project at root (hatchling packages only `milpa/`); a
self-contained Rust workspace lives in a sibling directory.

```
/milpa/                     Python package (unchanged)
/rust/                      Rust cargo workspace
  Cargo.toml                [workspace] manifest
  Cargo.lock                COMMITTED (milpa-cli is a deployable binary)
  rust-toolchain.toml       COMMITTED — pins channel + edition (MSRV)
  Containerfile             pinned Rust toolchain (project policy: no host toolchains)
  crates/
    milpa-types/            zero-logic shared vocabulary (data only): Version
                            (raw newtype), Provenance enum, ResolvedDep,
                            ResolvedGraph, Lockfile (data struct)
    milpa-solver/           VersionSet + Strategy + their algebra + parse_version
                            + PubGrub DependencyProvider; depends on milpa-types
    milpa-manifest/         milpa.kdl + .nimble parsers, Manifest, Workspace,
                            Profile; depends on milpa-types
    milpa-core/             resolver glue + lockfile emit + identity/CAS + nim.cfg
                            + registry/Index + CaStore + FetcherRegistry +
                            MilpaError + the three resolver traits; depends on
                            the three above
    milpa-cli/              bin: the CLI contract (S13); depends on milpa-core
    milpa-conformance/      the Rust fixture harness; depends on milpa-core
/docs/spec/                 shared normative spec (unchanged)
/tests/conformance/         shared, language-agnostic fixture corpus (unchanged)
```

**Type placement** (resolves the round-2 orphan-rule problem — see §4.6):

| Type(s) | Crate | Why |
|---|---|---|
| `Version` (raw newtype), `Provenance` enum, `ResolvedDep`, `ResolvedGraph`, `Lockfile` (data) | `milpa-types` | shared vocabulary every crate needs; zero logic |
| `VersionSet`, `Strategy`, `parse_version`, `impl pubgrub::DependencyProvider` | `milpa-solver` | the algebra is *inherent* to `VersionSet`; it cannot be split from the type without an orphan-rule/newtype mess |
| `Manifest`, `Workspace`, `Profile`, `ManifestError` | `milpa-manifest` | manifest-layer concepts; `milpa-core` imports them (correct DAG direction) |
| `Index`, `CaStore`, `FetcherRegistry`, `Fetcher` impls, `MilpaError`, the 3 resolver traits | `milpa-core` | the traits reference `Index`/`CaStore`/`MilpaError`, and `MilpaError` wraps every domain error → only `milpa-core` (DAG top of the lib graph) sees them all |

Rationale: keeping Rust under `/rust/` (not scattered) means the Python build,
`uv`, and pytest are wholly unaffected. The fixture corpus is referenced by
**relative path** from the Rust harness (`../../tests/conformance/`), so there
is exactly one copy.

> CORRECTION (round-2): an earlier draft put `VersionSet`/`Strategy` in
> `milpa-types` ("types only, no logic"). That is incoherent — `VersionSet`'s
> `contains`/`intersection`/`complement` and its `pubgrub` trait impl ARE the
> type's inherent methods; Rust's orphan rule forces the trait impl to live in
> the crate that owns the type. So `VersionSet`+algebra live in `milpa-solver`;
> only the raw `Version` newtype is shared via `milpa-types`. `milpa-manifest`
> gets `Version` for constraint *parsing* without importing the solver.

> DECISION: `/rust/` top-level dir, cargo workspace. Alternative considered: a
> flat `Cargo.toml` at repo root — rejected because it muddies the
> Python-project root and risks tooling (hatchling/uv) confusion.

> DECISION (crate split, round-1): **six crates, not three.** A monolithic
> `milpa-core` recreates the Python package's one-big-namespace risk, where
> nothing structurally stops constraint matching from being re-implemented
> outside `VersionSet`. Rust gives compile-time SSOT enforcement for free: a
> zero-dependency **`milpa-types`** vocabulary crate lets `milpa-solver` and
> `milpa-manifest` share the data model without importing each other, and the
> compiler then guarantees the identity algorithm lives only in `milpa-core`,
> the algebra only in `milpa-solver`. This mirrors the SSOT boundaries
> CLAUDE.md already names (`identity.py` / `solver.py` / `manifest.py` …) and
> keeps the conformance harness + any future PyO3 binding depending only on
> `milpa-core`'s public API.

> DECISION (toolchain, round-1): `rust-toolchain.toml` (channel + edition
> pinned) and `Cargo.lock` are **committed** for reproducible builds. Per the
> standing dev-tools-in-containers policy, Rust is **not** installed on the
> host: a `/rust/Containerfile` provides the pinned toolchain and a thin
> `./dev-rust` wrapper runs `cargo` inside it (podman preferred, docker
> fallback). `.gitignore` gets `/rust/target/` and `/rust/.cargo/` (everything
> else under `/rust/` is tracked).

> DECISION (round-2): the `Containerfile` pins a base image **that already
> contains the toolchain** (`FROM docker.io/library/rust:<MSRV>-slim` by digest),
> so `./dev-rust cargo build` needs no in-container `rustup` download and the
> S1 done-criterion is not silently network-dependent. The base-image pull is a
> one-time prerequisite of S1 (network needed once to fetch the image), called
> out so it is not a surprise. **MSRV floor: ≥ 1.74**, driven by `gix`
> (`pubgrub` needs ≥1.65, `kdl` tracks recent stable); the exact pin is recorded
> as part of the S0 decision output.

### 4.2 Pure Rust, not PyO3

The reference impl is pure Rust with no Python dependency. A PyO3 binding
would couple the "independent oracle" to the thing it validates, defeating
purpose (1). `multi_impl_strategy` already leans this way. Bindings, if ever
wanted, are downstream of a green reference.

### 4.3 Branch strategy

The Rust **code** is developed on a `rust` branch and merged to `main` only
once it passes the full spec-v1 suite. The **RFC + any spec amendments it
forces** land on `main` (design and spec are shared, visible, and may affect
the Python impl too). This keeps `main` green (Python suite) while the Rust
impl is incomplete, without a separate repo.

> DECISION: design/spec on main; Rust impl on `rust` branch until green.
> Pre-1.0 "direct to main" still holds for the Python side and for the spec.

**Corpus-drift protocol (round-1).** The fixture corpus lives on `main` and may
advance (Python bugfix, new spec clause, coverage-floor addition) while the
`rust` branch is in flight. To prevent silent rot and merge chaos:

- Merge `main` into `rust` on a regular cadence (at minimum at every slice
  boundary). New fixtures arriving from `main` land as RED.
- The Rust harness reads a tracked **`rust/crates/milpa-conformance/known_failing.txt`**
  (fixture IDs + the issue/slice that will green them). Listed fixtures are
  reported but do not fail the build, so the branch keeps moving. Entries are
  removed as slices green them.
- **Unexpected-pass is a signal, not silence (xfail/xpass).** A fixture listed
  in `known_failing.txt` that *passes* MUST emit `UNEXPECTED PASS: fixture-NNN`
  — non-blocking warning in local dev, **blocking failure in CI** (the entry
  must be removed before merge). A stale known-failing entry otherwise hides a
  fixture that was fixed for the wrong reason.
- **Done (§6) requires `known_failing.txt` to be empty.** A non-empty list at
  merge time is a blocking condition, not a silent caveat.

**Spec-gap reflow protocol (round-1).** When the Rust impl uncovers a spec hole
(purpose 1), the fix flows in a fixed order so the spec never trails the code:
(a) open a GitHub issue tagged `spec-hole`; (b) land the normative diff + a new
fixture on `main`; (c) merge `main` into `rust`; (d) implement the Rust fix.
The spec/fixture change is never carried as an informal note on `rust`.

### 4.4 The Rust conformance harness (the coexistence linchpin)

`milpa-conformance` walks `tests/conformance/spec-v<N>/`, and for each fixture
reproduces exactly the contract `conformance-fixtures.md` defines and the
Python runner implements:

- dispatch on the `cmd` file (`resolve` | `parse-lockfile` | `frozen`),
- build the index from `index.kdl` (or **index absent** when there is no file),
- a fake fetcher backed by `mocked-fetches/<urlkey>/` (same urlkey encoding —
  including the `@`-in-ref edge case, §8),
- CAS seeding from `cas-seed/` by **copy, then admit** (never move — see below),
- a `Profile` built from the `env` file with a **mocked** nim-version query (no
  subprocess); **`env` absent ⇒ profile absent ⇒ all conditional deps included**,
- `format_nimcfg` invoked with `deps_dir` = the literal relative path `_deps`
  (the committed `expected/nim.cfg` encode this),
- for workspace fixtures, the fixture root is passed to `load_workspace`, which
  reads member subdirectories (`<member>/milpa.kdl`) from disk,
- byte-diff `expected/{milpa.lock,nim.cfg,_deps_structure.txt}` with
  `<CAS_ROOT>` normalization (resolve the CAS-root path first so it has no
  symlink components; substitute its canonical no-trailing-separator string),
  or assert `expected/error`.

> TRAP (round-2): to build the `_deps_structure.txt` lines, the harness MUST
> use `std::fs::canonicalize("_deps/<name>")` (follows the relative symlink AND
> resolves symlink components in the CAS-root path) — **not** `read_link`, which
> returns the raw relative target and cannot be `<CAS_ROOT>`-substituted. The
> on-disk symlink stays relative (identity.md §3.5); `_deps_structure.txt`
> records the *resolved* target. These are consistent, not contradictory.

**Fixture-context builder (round-2).** Constructing the typed inputs (`Manifest`
or `Workspace`, optional `Index`, the fake fetcher, optional `Profile`, a temp
`CaStore`, and the `Expected` outputs) from a fixture directory is a single deep
seam, not logic smeared across the parametrized test:

```rust
struct FixtureContext { cmd: Cmd, manifest: Option<Manifest>, workspace: Option<Workspace>,
    index: Option<Index>, fetcher: FakeFetcher, profile: Option<Profile>,
    store: TempCaStore, expected: Expected }
impl FixtureContext { fn load(fixture_dir: &Path) -> Result<Self, HarnessError>; }
```

`FakeFetcher` (one impl of the `Fetcher` trait, backed by `mocked-fetches/`) and
`TempCaStore` (copy-then-admit from `cas-seed/`) are first-class harness types.
Each `#[test]` is then just `load → dispatch on cmd → diff against expected`.
**S2's done-criterion is precisely "`FixtureContext::load` works on the two
synthetic fixtures,"** which makes the construction logic itself unit-tested.

This harness is the proof of coexistence: **one corpus, two readers**. Its
acceptance criterion is identical to the Python runner's. Codes that are
unreachable via black-box (documented in `conformance-fixtures.md` §4) get
Rust unit tests, mirroring the Python side.

> DECISION (round-1): the Rust harness mirrors the Python runner's *seams* 1:1,
> but **not its bugs**. `conformance-fixtures.md` §2.10 documents that the
> Python adapter destroys `cas-seed/` trees on first run (admit moves, not
> copies). The Rust harness MUST copy seed trees into scratch before admission
> so it is idempotent across runs. (This is also the corrected behavior the
> Python side is tracking.)

> DECISION (round-1): the harness drives the **library API** (the three traits
> in §4.6), not the `milpa-cli` binary. No spec-v1 fixture requires invoking
> the binary as a subprocess; CLI-surface behavior (exit codes, stdout/stderr
> discipline) is covered by `milpa-cli` integration tests in S13, not the
> fixture corpus.

> DECISION (round-1): the harness is built with **`#[test]` parametrization**
> (`rstest`-style), one test per fixture, IDs matching `fixture-NNN-<slug>` for
> grep/filter. Rationale over a standalone bin: per-fixture failure reporting,
> `cargo test <slug>` filtering, per-test tempdir isolation, and native
> `cargo`/CI exit-code integration all come for free. Fixtures not yet greenable
> are gated by `known_failing.txt` (§4.3), not by deletion or blanket `#[ignore]`,
> so the RED→green transition of each fixture is observable.

### 4.5 Library choices

These are the load-bearing dependency decisions. The two high-risk ones are
**de-risked by a pre-grind spike** (S0), not gambled on mid-slice — discovering
mid-grind that a crate can't meet spec exactness would force an unplanned
1000+-line port under time pressure (`solver.py` is ~1.4k lines, `manifest.py`
~1.4k). Each retains a hand-rolled/port fallback.

- **KDL parsing — `kdl` (kdl-rs):** must expose the `(url)` type annotation
  *and* the annotated value as accessible fields, and carry line/column on
  parse errors (for MAN-* diagnostics; note the *message text* is not
  conformance-checked — only the code — so "precise enough" means **the parse
  error struct exposes line + column**, the concrete S0 pass criterion). It
  must NOT be relied on for *emission*: lockfile/nim.cfg bytes are
  hand-serialized per spec, exactly as Python does (a pretty-printer cannot
  guarantee byte-exactness). The crate boundary enforces this — `kdl-rs` is an
  implementation detail inside `milpa-manifest`'s `parse_*` functions; the
  parsed `Manifest` is a milpa-owned struct, never a re-exported `kdl-rs` AST,
  and no emission code anywhere depends on `kdl-rs`. **Fallback:** hand-rolled
  recursive-descent reader scoped to milpa's subset.
- **PubGrub — `pubgrub` (pubgrub-rs):** the spec is engine-agnostic (PubGrub is
  the reference *producer*, not normative; what is moored is the
  canonical-solution selection + emission order, resolver-semantics §4.2/§4.4).
  **Seam (corrected round-2):** milpa implements pubgrub-rs's
  `DependencyProvider` trait, with `VersionSet` as its version-set associated
  type (`VersionSet` implements pubgrub's `version_set::VersionSet` for set
  algebra) **and `prioritize()` implementing the spec's package-BFS order P** —
  package selection order is governed by `prioritize()`, NOT by the version-set
  trait. pubgrub-rs's built-in `Ranges`/`SemanticVersion` types are **never**
  used (they hardcode a different algebra). **Spike criterion (corrected):** the
  S0(b) spike asserts the *canonical solution* on `fixture-063-canonical-selection`
  matches (`X@2.0.0, Y@1.0.0, Z@1.0.0`) — **not** "emission order," which is
  always lexicographic-by-name (§4.4) and therefore cannot discriminate a right
  `prioritize()` from a wrong one. The spike drives the solver in isolation
  against a hand-built package database; fixture-063 only *greens in the harness*
  after S8 (index reader) is also complete. **Fallback:** port the teaching-clean
  solver from `solver.py` — note this is a ~1.4k-line port, an asymmetric cost
  (see S0). Either way `Version`/`VersionSet`/`Strategy` are milpa types.
- **sha256 — `sha2`:** trivial; identity algorithm is fully spec'd.
- **git/tarball/oci fetch:** out of the conformance hot path (fake fetcher in
  fixtures). Real fetchers (`git2`/`gix`, `tar`+`flate2`, an OCI client) live
  behind the fetcher trait (§4.6). Not fixture-gated, but **not untested**: S14
  gates them against local, no-network integration tests (clone the existing
  `tests/fixtures/milpa_fetcher_stub/` repo; assert the materialized content
  hash; `safe_extract` path-traversal cases). Network-real tests are env-gated.

### 4.6 Crate decomposition, traits, and error model

**SSOT per concern (crate-enforced).** `Version`/parse and the algebra live only
in `milpa-solver`/`milpa-types`; content hash only in `milpa-core`'s identity
module; constraint matching only via `VersionSet`. The six-crate split (§4.1)
turns each of these from a convention into a compile-time guarantee.

**Harness seam — three narrow traits, not one god `Milpa` trait.** The `cmd`
dispatch already factors into three paths with disjoint input shapes; the traits
follow. **All three are defined in `milpa-core`** (the only lib crate that sees
`Index`/`CaStore`/`MilpaError` — see the §4.1 placement table):

```rust
trait LockfileParser { fn parse_lockfile(&self, text: &str) -> Result<Lockfile, MilpaError>; }

trait Resolver {
    fn resolve(&self, m: &Manifest, idx: Option<&Index>, f: &dyn FetcherRegistry,
               p: Option<&Profile>, prior: Option<&Lockfile>, deps_dir: &Path)
               -> Result<ResolvedGraph, MilpaError>;
    fn resolve_workspace(&self, w: &Workspace, idx: Option<&Index>, f: &dyn FetcherRegistry,
               p: Option<&Profile>, prior: Option<&Lockfile>, deps_dir: &Path)
               -> Result<ResolvedGraph, MilpaError>;
}

trait FrozenResolver {   // frozen bypasses the solver → no index, no fetcher
    fn resolve_frozen(&self, m: &Manifest, lock: &Lockfile, store: &CaStore,
               deps_dir: &Path) -> Result<ResolvedGraph, MilpaError>;
    fn resolve_workspace_frozen(&self, w: &Workspace, lock: &Lockfile, store: &CaStore,
               deps_dir: &Path) -> Result<ResolvedGraph, MilpaError>;
}
```

The `prior` parameter (round-2) carries the prior lockfile for **pin reuse**
(resolver-semantics §8, an S7b deliverable); the harness passes `None` for
fixtures that don't test pin-reuse. A partially-implemented impl (e.g. a
milestone that skips frozen) is a *compile error*, not a silent gap.

**Fetcher dispatch — `Provenance` is a closed enum, identity cannot be forged.**
The spec fixes exactly four transport kinds, so `Provenance` is an **enum**, not
a `dyn Any` trait object (round-2): exhaustive `match` dispatch, compile-time
completeness when a kind is added, trivial serde, and — for a supply-chain tool
— new transports are *auditable variants*, not silently-injectable trait impls.
`fetch` returns a receipt, never an identity; the registry computes identity by
walking the materialized tree, so no fake (or buggy real fetcher) can lie.
`cas_admissible` is a method on the enum (`Local` ⇒ `false`, so `milpa fetch` on
a workspace member doesn't freeze the user's edits).

```rust
enum Provenance { Git { url, ref_spec }, Tarball { url, expected_sha256, strip_components },
                  Local { path }, Oci { registry, repository, digest } }
impl Provenance { fn cas_admissible(&self) -> bool { !matches!(self, Provenance::Local { .. }) } }

trait Fetcher {   // one impl per kind; registry dispatches by matching the variant
    fn fetch(&self, name: &str, p: &Provenance, dest: &Path)
        -> Result<Receipt, FetchError>;   // NOT (identity, receipt)
}
```

**Error model — per-domain enums + one boundary wrapper.** Each crate has its
own error enum (`ManifestError` in `milpa-manifest`, `SolverError` in
`milpa-solver`, lockfile/identity/resolver/fetch/tianguis errors in `milpa-core`)
carrying `fn code(&self) -> &'static str`, giving clean `?`-propagation within a
crate. `milpa-core` exposes `enum MilpaError { Manifest(..), Solver(..), … }`
with a delegating `code()`. **The `From<DomainError> for MilpaError` impls live
in `milpa-core`** (the only crate that can write them without a dependency
cycle); lower crates' internal fns return `Result<_, DomainError>` and the
conversion happens at the `milpa-core` boundary via `?`. The harness asserts on
`.code()` only — the spec does **not** check message text
(conformance-fixtures §3.1), so the variant shape is per-*domain*, not
per-*code*, keeping the wrapper bounded as the catalog grows.

**Error-code parity (resolves open-Q4).** The Rust catalog is maintained
**independently** (not generated from the Python source — generating from Python
would couple the "independent oracle" to the thing it validates). A **`#[test]`**
in `milpa-conformance` (not a `build.rs` — round-2: build scripts have no
well-defined CWD and break for packaged/relocated builds; a test anchored at
`env!("CARGO_MANIFEST_DIR")` is robust) reads `docs/spec/errors.md` and asserts
the Rust `code()` slug set is in bijection with the spec's. **`errors.md` is the
shared truth, edited only spec-first:** when the Rust impl is *more* conformant
and needs a code Python lacks (e.g. #117), the flow is amend `errors.md` →
file a Python-defect issue → both impls' lints pass against the spec. The Rust
lint never silently diverges from `errors.md`.

### 4.7 Differential testing (stretch, post-green)

Once the Rust impl passes the corpus, a differential harness generates inputs
(manifests/indexes) and runs **both** Python and Rust, comparing outputs. Two
independent implementations make this valuable (it is not the shared-upstream
blind spot — they share only the spec, which is exactly what we want to
stress). Counterexamples become new conformance fixtures (spec README §4) or
spec amendments. This is a stretch slice, not part of v1-done.

## 5. CI

Minimal, but **not deferred to the end**. The project has no CI today and
Python rewrite/branch churn is expected, so do not build elaborate CI. But a
`rust` branch in flight for weeks with no green signal accumulates silent build
breakage. Therefore: a single small workflow — `cargo check` + `cargo test`
(incl. the conformance harness, honoring `known_failing.txt`) inside the pinned
`/rust/Containerfile`, plus `uv run pytest` for the Python side — MUST land **no
later than S2** (when the harness first exists). It runs on the `rust` branch.
Elaboration (matrix, caching, lints) stays deferred.

## 6. Slices (stage-1 decomposition)

Ordered for a test-first grind. **The pre-grind P-slices (§10) run first** — they
land corpus/catalog prep on `main` so S3/S5b/S8/S11 are unblocked — then S0
spikes, then the S1+ Rust grind. The "RED backbone" framing is **honest about
front-loading**: of the spec-v1 fixtures, the large MAN-* error family greens at
S3, the LOCK-*/TNG-*/FROZEN-*/WS-* error families green at their respective
slices, but the *success* fixtures (full resolve→lock→nim.cfg pipeline) cannot
green until S4+S5b+S6+S7+S9 are all complete. The per-slice green counts below set
honest expectations; the §9 coverage map ties each fixture family to its slice.

- **S0 — De-risking spikes (pre-grind, not a slice).** Two throwaway probes
  that close the load-bearing library decisions *before* any S3/S7 code:
  (a) **kdl-rs**: parse `git=(url)"https://…"`, assert annotation + value are
  both accessible and that a syntax error carries line/column → else commit to
  the hand-rolled reader. (b) **pubgrub-rs**: drive `choose_package_version` in
  BFS order P on the `fixture-063-canonical-selection` scenario, assert the
  canonical (lex-maximal) solution → else commit to porting the teaching solver.
  Output: a one-line decision recorded in this RFC + handoff. ~1 day total.
  **Asymmetric fallback (round-2):** if S0(b) picks the port, S7a's scope changes
  from "wire pubgrub-rs" (~3 days) to "port ~1.4k-line `solver.py`" (~10+ days)
  and the first-success-fixture milestone shifts accordingly. Likewise an S0(a)
  fall to the hand-rolled KDL reader enlarges S3. These contingencies are why S0
  runs *before* the grind commits to estimates, not mid-S7.
- **S1 — Workspace scaffold + coexistence.** Six-crate `/rust/` workspace
  (§4.1), `rust-toolchain.toml`, committed `Cargo.lock`, `Containerfile` +
  `./dev-rust`, `.gitignore`. `milpa-types` holds the type skeletons; the three
  trait families (§4.6) + `Fetcher`/`Provenance` traits compile as stubs.
  Done: `./dev-rust cargo build` + a trivial unit test green; `uv run pytest`
  still green.
- **S2 — Conformance harness + self-test.** `milpa-conformance` discovers
  fixtures, parametrizes one `#[test]` each, implements `cmd` dispatch, the
  byte-diff + `expected/error` contract, urlkey encoding, `<CAS_ROOT>`
  normalization, `cas-seed` copy-then-admit, `env`→Profile, `_deps` literal,
  workspace member-subdir loading, and `known_failing.txt`. **Done-criterion is
  not "all fixtures RED"** (that is unfalsifiable): S2 is green when the harness
  itself is proven against **two hand-authored synthetic fixtures** — one
  known-pass, one known-fail — driven through a stub trait impl, so discovery /
  dispatch / diffing / normalization are all exercised with zero domain logic.
  Land the minimal CI workflow here (§5). Every real fixture starts in
  `known_failing.txt`.
- **S3 — KDL reader + manifest grammar (incl. `.nimble` compat).** Per the S0
  decision. Parse `milpa.kdl` (package + workspace), `(url)` annotation,
  `when`/predicate blocks, feature flags, `dev-deps`, `spec-version`; **and the
  `.nimble` line-form compat parser** (four `requires` forms, `srcDir`,
  `when`-block warning, `nim`-requirement drop). Greens the **62 MAN-* error
  fixtures** (the bulk of the corpus). *Note: `NIMBLE-*` codes are **exempt**
  from the conformance corpus (§10/P2 — not fixture-expressible; unit-tested and
  translated to `MAN-FILE-UNREADABLE` at the discovery layer); the `.nimble`
  parser is exercised indirectly via transitive `.nimble` files in S7b+ success
  fixtures, plus the unit tests this slice ports.*
- **S4 — Identity + CAS.** Byte-exact content hash, CAS layout/admit/link, the
  4-tier precedence, scratch lifecycle, symlink UTF-8 guard, **two-table
  algorithm-agility dispatch** (`SUPPORTED_ALGORITHMS` + digest-length table, not
  a hardcoded `== "sha256"` — identity.md §2.3) so future multihash is a one-file
  change. Enables every fixture that materializes deps.
- **S5a — Lockfile parse.** Parse + validation only. Greens the **12 LOCK-*
  error fixtures** (all `cmd=parse-lockfile`, no CAS) — **independent of S4**, so
  it may sit between S3 and S4. Plus unit tests for the unreachable LOCK-* codes
  in `conformance-fixtures.md` §4 (`LOCK-FILE-NOT-FOUND`, `LOCK-GRAPH-MISMATCH`).
- **S5b — Lockfile canonical serialization (emit).** Byte-exact `milpa.lock`
  (canonical serialization + per-kind provenance records + placeholder version +
  TOFU `archive_sha256` field for tarballs). Prerequisite for any success fixture;
  depends on S4 (resolved identities exist before emission).
- **S6 — Version / VersionSet / Strategy / Profile.** The constraint algebra to
  spec, plus the `Profile` type (predicate matching, absent-profile semantics).
  **Unit-tested only** — done-criterion is the ported `solver`/`profile` unit
  tests pass; no fixture greens solely on S6 (the algebra is exercised through
  S7). **S7a/S7b depend on S6.**
- **S7a — Solver core.** PubGrub (crate or port, per S0): `solve` loop,
  partial solution, incompatibilities, conflict detection. Greens
  `SOLVE-CONFLICT`. Depends on S6.
- **S7b — Resolver orchestration.** Two-phase materializing provider, fake-
  fetcher injection, content-hash dedup/alias, **prior-lockfile pin reuse**
  (resolver-semantics §8), **mirror fallback / `fetch_any` ordered-candidate
  list** (§8a), **provenance precedence + transitive-override suppression**
  (§10, supply-chain-critical), **dev-deps context** (root-enrolls /
  transitive-excludes / member-as-root, §9). Depends on S4+S5b+S6. *Unblocks*
  URL-dep success fixtures (they go green only once S7c+S9 also land — see §9).
- **S7c — Canonical emission order.** `_build_graph` toposort + the lex-by-name
  emission order (§4.4). With S9, greens multi-dep success fixtures.
- **S8 — Fetcher dispatch + fake + registry read + index cache.** Fake-fetcher
  seam; tianguis `index.kdl` read contract + TNG-* validators; the **four-state
  index cache** (fresh / stale-refetch / offline-fallback / no-cache-error),
  atomic write, `sha256(url)`-first-16 cache key, `MILPA_INDEX_URL` override,
  and the `milpa clean` MUST-NOT-evict rule. Greens TNG-* error fixtures;
  *unblocks* named-dep success fixtures (green once S9 lands).
- **S9 — nim.cfg emission.** Byte-exact, incl. self `src_dir` path + active
  flags + the normative header + trailing newline (§8). **First success fixtures
  go green here** (with S4+S5b+S7b+S7c complete).
- **S10 — Frozen path.** `resolve_frozen` / `resolve_workspace_frozen`, the
  authoritative 10-code disqualification list (incl. `FROZEN-LEGACY-REGISTRY-
  PROVENANCE` raisable from **both** paths, §8). Greens FROZEN-*.
- **S11 — Workspace resolution.** Multi-member union + detection (resolver §11,
  cli §7.1) **and per-member `nim.cfg` emission filtered to each member's own
  closure** (lockfile §7.6). Greens the 6 WS-* error fixtures + unit tests for
  unreachable `WS-NO-MANIFEST`. Greens the workspace *success* fixture
  (fixture-117, created in §10/P1), whose expected nim.cfg is **per-member**
  (`expected/<member>/nim.cfg`, no root `nim.cfg`) — the Rust harness must route
  workspace fixtures through the per-member emitter, exactly as the Python
  adapter now does.
- **S12 — Error catalog parity.** Independent Rust catalog + the **`#[test]`**
  bijection lint against `errors.md` (§4.6, not `build.rs`). Add the
  **conformance declaration** (`[package.metadata.milpa]` spec version +
  known-failing set).
- **S13 — CLI contract (all 8 verbs).** `fetch lock show verify clean` +
  **`add`/`remove`/`update`** (the manifest-mutating verbs — cli-contract §1
  lists all eight as conformance verbs; honoring the spec means implementing
  them, incl. `format_manifest` serialization in `milpa-manifest` with the
  comment-drop warning + insertion-stable dep order + `(url)` annotation on URL
  fields, manifest-grammar §8). Flags, exit codes, env vars, stdout/stderr
  discipline. Tested by `milpa-cli` integration tests (not fixtures — these
  verbs mutate manifests and are outside the black-box fixture format).
- **S14 — Real fetchers (git/tarball/oci).** Per-kind `Fetcher` impls; gated by
  local no-network integration tests + `safe_extract` traversal cases + a
  **`strip_components=1` test asserting strip-before-hash** (manifest-grammar
  §4.2 / lockfile §5 — no fixture exercises this) + **tarball TOFU first-use
  pinning** (lockfile §6, which S5b emits). Env-gated network-real tests.
- **S15 (stretch) — Differential harness.** Python↔Rust generated-input diff;
  counterexamples become fixtures (README §4) or spec amendments.

**Done (v1 Rust reference):** P1–P4 landed on `main`; S0 decisions recorded;
S1–S13 complete; the full `tests/conformance/spec-v1/` suite green under
`milpa-conformance` with `known_failing.txt` **empty**; S14 for real-world use;
S15 optional.

## 7. Open questions

The four original open questions are **resolved in-RFC** by the round-1 review:

- **KDL crate exactness** → resolved by the S0(a) spike with a concrete pass
  criterion (annotation + value accessible; error carries line/column);
  hand-roll fallback. (§4.5)
- **pubgrub-rs drivability** → resolved by the S0(b) spike against
  `fixture-063`; milpa's `VersionSet` implements pubgrub's trait, `Ranges` never
  used; teaching-solver port fallback. (§4.5)
- **Harness form** → `#[test]` parametrization (`rstest`), not a standalone bin.
  (§4.4)
- **Error-code parity** → independent Rust catalog + `build.rs` lint against
  `errors.md`; not generated from Python. (§4.6)

No open forks remain for the *Rust design*. The one outstanding gate is §8
(spec reconciliation), which is a decision about the **spec**, not the Rust port.

## 8. Spec reconciliations this RFC forces (LANDED)

Purpose (1) fired during the review: a from-spec reader hits genuine
contradictions in the frozen v1.0 spec. Each is **fixtures-win** under the README
arbiter rule and does not invalidate the Python impl (which already matches the
fixtures), so each is a permitted v1 reconciliation.

> STATUS (round-1): Corey approved; **R1–R11 are applied to the spec docs**
> (uncommitted — Corey-gated commit). The Python suite stays green (901 passed),
> confirming these are prose-only alignments to existing fixtures/impl. R4 was
> found already-normative in `conformance-fixtures.md` §2.8; only its
> `resolver-semantics.md` §6 mirror was added. R1/R2/R5 were byte-verified
> against committed fixtures during application.

| # | Doc / loc | Defect | Fix (fixtures win) | Blocks |
|---|---|---|---|---|
| R1 | resolver-semantics §4.4 vs lockfile-schema §7.4 | nim.cfg `--path:` order: "lexicographic by name" vs "graph.deps resolution-stable order" — **direct NORMATIVE conflict** (verified). | Amend §7.4 to "lexicographic by name (see resolver §4.4)"; drop "resolution-stable". | S9 |
| R2 | conformance-fixtures §2.6 | `_deps_structure.txt` target: "relative … absolute non-conformant" vs the `<CAS_ROOT>/sha256/…` absolute form used by every fixture (verified). | Remove the relative-only clause; keep resolve→`<CAS_ROOT>`-substitute as the normative algorithm. | S2, S4 |
| R3 | conformance-fixtures §2 layout | workspace member subdirs (`<member>/milpa.kdl`) are read by the runner but absent from the layout table. | Add a normative "workspace member subdirectories" clause. | S2, S11 |
| R4 | conformance-fixtures §2.8 | absent-`env` ⇒ all-deps-included is only a NOTE, not normative. | Promote to NORMATIVE in §2.8 + mirror in resolver §6. | S2, S6 |
| R5 | lockfile-schema §7.1 | the 3-line nim.cfg header + blank line is a NOTE but every fixture mandates it (arbiter rule). | Promote header + blank line to NORMATIVE. | S9 |
| R6 | conformance-fixtures §5 | harness `deps_dir=_deps` literal not specified. | Add NORMATIVE clause. | S2, S9 |
| R7 | conformance-fixtures §2.6 | `<CAS_ROOT>` substitution algorithm under-specified (trailing sep, symlinked tmp). | Specify: resolve CAS root first; canonical no-trailing-sep prefix. | S2 |
| R8 | resolver-semantics §7.1 | `FROZEN-LEGACY-REGISTRY-PROVENANCE` scoping ambiguous (single vs both frozen paths). | Clarify: applies in **both** paths. | S10 |
| R9 | conformance-fixtures §2.3.1 | urlkey `@`-in-ref prose ("encode whole key as a unit") ≠ Python (replaces `@`→`_`). | Correct prose to match impl. | S2, S8 |
| R10 | lockfile-schema §7.4 NOTE | "trailing blank line" wording implies `\n\n`; impl emits single trailing `\n`. | Correct NOTE wording. | S9 |
| R11 | lockfile-schema §2.4 | spec mandates `"`/`\`/control escaping; Python does none (latent — no fixture hits it). | Add NOTE: Rust escaping is *more* conformant; track Python defect. | S5 |

**Corpus prerequisite (not a spec defect).** There are currently **zero
workspace *success* fixtures** — every WS fixture is an error case. S11 cannot
byte-validate workspace lockfile/nim.cfg output without one. Add ≥1 two-member
workspace success fixture (with `expected/{milpa.lock,nim.cfg,_deps_structure.txt}`)
on `main` before S11. Filed as a corpus gap, generated by the Python oracle.

## 9. Fixture coverage map (which slice greens what)

Sets honest expectations for the grind and exposes the front-loading:

| Fixture family | Earliest all-green at | Kind |
|---|---|---|
| MAN-* (62) / MANIFEST-SPEC-VERSION | S3 | error |
| LOCK-* (12) | S5a | error |
| SOLVE-CONFLICT | S6 + S7a | error |
| URL-dep / multi-dep **success** | S4 + S5b + S6 + S7b + S7c + S9 | success |
| named-dep success, TNG-* (errors) | TNG: S8 · named-dep success: S4+S5b+S6+S7b+S7c+S8+S9 | mixed |
| nim.cfg-shape **success** | + S9 | success |
| FROZEN-* | S10 | error |
| WS-* (6, errors) | S11 | error |
| workspace **success** (added, §10/P1) | S11 (fixture-117; **per-member** nim.cfg, see §10/P1) | success |
| NIMBLE-* | exempt — unit-tested, not fixture-expressible (§10/P2) | exempt |

The first *success* fixture greens only after **S4+S5b+S6+S7b+S7c+S9** — the RED
backbone's value is real but concentrated in the error families until then. Note
the §6 "unblocks vs greens" distinction: S7b/S8 *unblock* success fixtures but
none go green before S9.

## 10. Pre-grind slices (corpus + catalog prep, on `main`)

The review surfaced gaps in the **shared corpus/catalog** (not the Rust code).
Rather than track them as side-channel issues, they are the **first slices of
the plan** — ground RED→GREEN like any other, but landing on `main` (Python
oracle generates them) so the corpus-drift protocol (§4.3) then carries them to
`rust`. They run *before* the Rust scaffold grind; none of them block S0–S2, but
they gate S3/S5b/S8/S11, so doing them first keeps those slices unblocked.

- **P1 — Workspace success fixture(s). DONE.** There were zero (all 6 WS fixtures
  are errors), so S11's success path had no byte-validation target. Authored
  fixture-117 (two-member workspace) via the Python oracle. **Workspace nim.cfg is
  per-member, not a single root file** — milpa emits one `nim.cfg` per member
  (`write_workspace_nimcfgs`, W4/#76) with `--path:` lines relative to each
  member's dir (sibling members → `../<member>/<src>`, externals → shared
  `../_deps/<dep>/<src>`); there is no root `nim.cfg`. The first workspace success
  fixture surfaced this latent gap (the harness previously emitted a single
  single-package `nim.cfg`). Resolution (approved): expected layout is
  `expected/{milpa.lock,_deps_structure.txt}` + `expected/<member>/nim.cfg` per
  member; the harness routes `WorkspaceManifest` fixtures through the per-member
  emitter (`format_workspace_nimcfgs`, extracted as the SSOT emitter shared by the
  CLI writer and the harness); spec `conformance-fixtures.md` §2/§2.1.1/§2.5
  amended; `resolver-semantics.md` §11.4 already covered per-member emission. Done:
  Python suite greens it (902 passing). **Gates S11.**
- **P2 — `NIMBLE-*` codes. DONE (premise corrected + SSOT fix).** The original
  framing ("coverage-floor bijection gap, author 2 fixtures") was wrong on
  investigation: (1) the bijection lint was already clean (`NIMBLE-FILE-NOT-FOUND`
  unit-tested, `-UNREADABLE` in `KNOWN_UNTESTED`); (2) `NIMBLE-*` are **not
  conformance-fixture-expressible** — `load_nimble` (their sole raiser) had no
  production caller, the conformance harness never runs `.nimble` discovery, and a
  missing/unreadable file can't be committed to git. Investigation also surfaced an
  **SSOT duplication**: `_load_manifest_from_nimble` re-implemented the file read and
  raised `MAN-FILE-UNREADABLE`, while `load_nimble`(→`NIMBLE-*`) was dead outside
  tests. Resolution (Corey: fix inline): `_load_manifest_from_nimble` now **delegates
  to `load_nimble`** (single `.nimble` reader / SSOT) and **translates** its
  nimble-layer error to the discovery layer's `ManifestError` contract
  (IO→`MAN-FILE-UNREADABLE`, non-IO→`MAN-NIMBLE-PARSE`); the `ManifestError`
  contract is load-bearing (CLI catches it at 6 sites). The MAN-/NIMBLE- overlap is
  resolved by **explicit layering** (loader codes vs discovery-adapter codes, one
  read impl), not duplicate reads. Catalog `when=` text + `errors.md` updated to
  document the layering; both file-IO codes are now directly tested
  (`KNOWN_UNTESTED` for them removed). **Conformance/Rust note (S12):** `NIMBLE-*`
  are exempt from the conformance corpus — covered by unit tests, translated to
  `MAN-FILE-UNREADABLE` before any resolver/CLI surface; the Rust catalog lint
  carries the same exemption. Done: suite 904 passing. **Gates S3 completeness.**
- **P3 — Lockfile string-escaping fixture (R11). DONE.** Authored
  `fixture-118-lock-string-escaping` — a URL dep whose `ref` contains both `"`
  and `\` (raw value `v1"x\y`), with the escaped `expected/milpa.lock`
  (`ref "v1\"x\\y"`). Fixed the Python `format_lockfile` R11 defect at the root:
  added the SSOT `_kdl_str` escaper (escapes `"`, `\`, control chars) and routed
  **every** emitted string value through it (dep/strategy/identity/version/src_dir/
  requires/active_flags/self_mirrors + all provenance fields). Added a
  format→parse round-trip unit test over the full special-char domain. No
  `known_failing` parking needed — the fix landed directly. lockfile-schema R11
  NOTE updated (defect reconciled). Done: suite 906 passing. **Gates S5b escaping
  correctness.**
- **P4 — Exclusive-dispatch error decision (plugin-contract §5). DONE.** The
  ambiguous / no-handler conditions (+ `fetch_any` no-candidates) raise bare
  `FetchError` with no slug. **Decision: exempt** — programmer-invariants, not
  user-facing; no `FETCH-AMBIGUOUS-DISPATCH`/`FETCH-NO-HANDLER` minted. Made the
  exemption a true SSOT: replaced the Python lint's dead `KNOWN_UNCODED` set +
  fragile inline snippet-chain with one used list, `FETCH_UNCODED_INVARIANTS`
  (three condition tokens), in `tests/test_error_catalog.py`. Added a NORMATIVE
  §5.1 to `plugin-contract.md` recording the catalog exemption for **both** impls
  (the Rust catalog lint mirrors the same set). Done: suite 906 passing.
  **Gates S8/S12.**

> NOTE: P-slices land on `main` and feed `rust` via §4.3. The
> `strip_components`-before-hash ordering (earlier listed separately) needs no
> corpus fixture — it is an S14 no-network integration test, already folded into
> S14's done-criterion.
