# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

It is the canonical re-init document for the milpa repo — open this
first in any new session.

## What milpa is

**milpa** is a Nim dependency resolver. It reads `milpa.kdl`, fetches
deps into `_deps/`, runs PubGrub-based resolution, emits `nim.cfg` and
`milpa.lock`. It bypasses nimble's broken-as-of-v0.22.2 vnext SAT solver
for chained URL requires.

The name is the Mesoamerican intercropping system (corn + beans +
squash grown together as an integrated agricultural unit). The metaphor
maps onto milpa's design intent: **source deps + toolchain + tasks as
an integrated polyculture**, not just a narrow dep resolver. See
`docs/rfc-toolchain-content-addressing.md` for the polyculture argument.

Position in the broader stack:

```
milpa            — Python dep resolver (this repo)
fresco           — Nim terminal-UI library (sibling repo)
intonaco         — reactive substrate (sibling repo, depended on by fresco)
chronos (fork)   — async runtime with contextvars (sibling repo)
sinopia          — planned trace frontend on intonaco (sibling repo, not yet implemented)
```

milpa unblocked fresco's hard split from intonaco — that was its
initial fresco-unblock charter (v0). It then expanded scope to become
**the best possible Nim dep manager**, not just a narrow workaround.
See `docs/comparison-vs-nimble-atlas.md` for the full design ambition.

## Repository layout (mono-repo, multi-impl)

milpa is a **multi-implementation** project in one repo. The three first-class
peers are the spec, the shared conformance corpus, and the implementations:

```
spec/          — normative contract (manifest, lockfile, identity, resolution, CLI, errors)
conformance/   — shared spec-v<N>/ fixture corpus, consumed by EVERY impl's runner (impl-neutral)
impls/
  python/      — Python reference impl (uv-managed): milpa/ package + pyproject.toml + tests/
  rust/        — Rust reference impl: cargo workspace (crates/…); run via ./dev-rust
  (nim/        — future dogfood impl)
harness/       — (future) the differential conformance harness (rfc-differential-conformance-harness.md)
docs/          — RFCs + design docs
```

Each impl declares which spec version it conforms to and passes the shared
`conformance/` corpus. See `docs/rfc-multi-impl-strategy.md`.

## Architecture (Python impl)

The Python implementation (uv-managed) lives in `impls/python/`; its package is
`impls/python/milpa/`:

| Module | Role |
|---|---|
| `manifest.py` | `milpa.kdl` data model and parser; auto-discovery (`.nimble` fallback) |
| `nimble.py` | heuristic line-scanner for `.nimble` files (no nimscript eval) |
| `identity.py` | `compute_content_hash(path)` — sha256 of source tree per `spec/identity.md` |
| `kdl_io.py` | KDL 2.0 façade over kdl-py |
| `version.py` | `Version` type + version algebra — single source of truth for version semantics |
| `solver.py` | **PubGrub** (teaching-clean port) + `VersionSet` algebra + `Strategy` enum |
| `dep_decl.py` | `DepDecl` artifact parser and `EdgeSet` type (S1 consumer side) |
| `dep_decl_store.py` | `DepDeclStore` protocol + `FileDepDeclStore` + `HttpDepDeclStore` (S3b) |
| `edge_sources.py` | edge-sourcing seam — S4-i + S3b (RFC: Content-Addressed Attested Dependency Metadata) |
| `registry.py` | tianguis `index.kdl` reader — named-dep resolution (S8a) |
| `index_cache.py` | tianguis index acquisition — four-state freshness cache (S8b) |
| `attestation.py` | attestation-policy helpers (S5 — RFC: Content-Addressed Attested Dependency Metadata) |
| `context.py` | execution-context seam — `MilpaEnv` + `ResolveParams` |
| `profile.py` | `Profile` data types — runtime resolution context |
| `resolver.py` | top-level glue: manifest → fetch + solve → `ResolvedGraph` |
| `frozen.py` | lockfile-backed graph reconstruction (no fetcher invocation) |
| `workspace.py` | workspace loading and manifest discovery — all filesystem I/O |
| `lockfile.py` | `milpa.lock` parse + format + verification |
| `nimcfg.py` | `nim.cfg` emission from `ResolvedGraph` |
| `cas.py` | content-addressed store per `spec/identity.md §3` |
| `manifest_writer.py` | atomic mutation of `milpa.kdl` |
| `errors.py` | error slug constants + `MilpaError` exception |
| `cli.py` | CLI entry point — all subcommands (`fetch`/`lock`/`show`/`verify`/`clean`/`add`/`remove`/`update`) |
| `fetchers/` | pluggable fetcher subpackage: `types.py` (protocol + registry), `git.py`, `tarball.py`, `local.py`, `oci.py`, `mocked.py` (conformance fakes), `cas_admitting.py` (CAS wrapper), `safe_extract.py` |

The package boundary lines up with conceptual responsibility. There's
**one source of truth** for each cross-cutting concern:
- `Version` type + version algebra → `version.py` only
- Content hash algorithm → `identity.py` only
- Constraint matching → `VersionSet.from_constraint(c).contains(v)` in `solver.py` only
- Error slugs → `errors.py` only (`spec/errors.md` is spec-owned, NOT generated from impl)

If you find yourself implementing something that already exists in
another module, stop. There's an audit-for-duplication discipline
([[feedback_audit_for_duplication]]) — duplications get unified, not
left in parallel.

## Non-negotiables

These are commitments embedded in milpa's data model. Violating them
defeats the design intent.

### Identity vs provenance

Every dep records two distinct kinds of information:
- **Identity** (`content_hash`): sha256 of the source tree. Immutable,
  trust-independent, recomputable from bytes alone.
- **Provenance** (typed `Provenance` on the resolved dep → lockfile
  `*Record`): git URL + ref + commit SHA, or OCI registry/repository/
  digest. Mutable, trust-dependent.

These are NOT the same field. Treat them as orthogonal. See
`docs/identity-and-provenance.md` for the conceptual model and
`docs/rfc-content-addressed-identity.md` for the structural argument.

### Declarative manifest

`milpa.kdl` is **pure data**. No embedded scripting language. The
parser must not execute any code. This is what distinguishes milpa
from nimble (which evaluates nimscript) and atlas (which still uses
nimscript .nimble files). Supply-chain attack surface that nimscript
has is structurally absent from milpa.

The same rule applies to milpa's **outputs**: `nim.cfg` is declarative;
milpa does NOT generate `config.nims` (that's NimScript). See
`docs/decision-config-nims.md`.

### Single source of truth

Duplicate code paths are bugs. When two functions compute the same
predicate, unify them. The audit-for-duplication memory
([[feedback_audit_for_duplication]]) documents the discipline. This
session deleted four parallel implementations of identity / version
parsing / constraint matching.

### Root-cause fixes over symptom patches

[[feedback_no_workarounds]] is the strongest standing rule. When a
duplicate appears, unify (don't property-test the equivalence). When
a spec has a hole, sharpen the spec (don't add a special case). When
a feature is missing, build it cleanly (don't bolt it on).

### Spec outlives implementation

[[feedback_spec_vs_impl]] — when designing manifest format, lockfile
format, identity algorithm, etc., decide based on what serves the
spec long-term, not what's convenient for today's Python impl. milpa
is committed to multi-implementation (`docs/rfc-multi-impl-strategy.md`)
so the spec must outlive any one language.

### Honor the spec once it's set

[[feedback_honor_the_spec]] — once a spec is set, execute it. "First
consumer doesn't need feature X" is NOT a reason to silently downgrade.
This rule has been triggered twice in milpa already (PubGrub scoping,
workspace scoping). Default to the BEST dep manager design, not what
the immediate consumer needs.

## RFCs (canonical design docs)

Read these to understand the structural design commitments:

| RFC | Topic | Status |
|---|---|---|
| `rfc-content-addressed-identity.md` | Identity = content hash; provenance is multi-valued metadata | Phases A done (#29-31); Phases B-E open |
| `rfc-pluggable-fetchers.md` | Transport abstraction; tarball/hg/fossil/OCI/IPFS as separate fetchers | F1-F7 open |
| `rfc-toolchain-content-addressing.md` | v2 polyculture — nim compiler + companion bins + declarative tasks in the build closure | v2 milestone |
| `rfc-multi-impl-strategy.md` | Python + Rust reference impls + spec + conformance suite | v1.5+ |
| `rfc-property-based-testing.md` | Hypothesis → counterexamples → spec conformance fixtures | Tiers A-C done (#63-68); research open |
| `rfc-beyond-pubgrub.md` | Proof certificates, capability-aware resolution, refinement-typed versions | research catalog |
| `rfc-compile-time-dep-graphs.md` | compile-time-first dep extraction | research stub |
| `rfc-effect-typed-deps.md` | capability/effect typing on deps | research stub |
| `rfc-milpa-nims-api.md` | Future: typed-data `milpa.nims` for user's `config.nims` | deferred post-v2 |

Other reference docs:
- `docs/identity-and-provenance.md` — user-facing explanation of the model
- `docs/decision-config-nims.md` — settled decision on the lane separation
- `docs/comparison-vs-nimble-atlas.md` — feature matrix vs incumbents + priority tiers

## Roadmap

`docs/comparison-vs-nimble-atlas.md` has the canonical tier breakdown.
Short version:

- **Tier 1 — adoption blockers**: ✓ DONE (.nimble compat, parallel
  fetch, content-addressing Phase A)
- **Tier 2 — atlas parity**: ✓ DONE (#49 strategies, #50 overrides,
  #25 cargo-style workspace W1–W5, #23 per-dep features/optional/patch,
  #26 conditional `when` blocks). Residual workspace polish is tracked by
  the workspace-completion RFC (see below).
- **Tier 3 — structural differentiation**: content-addressing Phase B-C
  (dedup, global store, multihash), pluggable fetchers F1-F3, multi-
  provenance
- **Tier 4 — research**: paper-grade contributions (proof certificates,
  effect-typed deps, refinement types, OCI/IPFS, sigstore)

After Tier 1+2+3 (~3 calendar months focused): milpa is the obvious
choice for any Nim consumer who cares about identity model, transport
extensibility, or supply-chain integrity.

After Tier 4: milpa contributes to dep-resolution-as-a-field, not just
Nim tooling.

## Workspace status (#25 — SHIPPED) + completion RFC (COMPLETE)

#25 shipped as cargo-style true workspace: W1–W5 (#73–#77) landed in both
impls (`1a395b3`→`2a43755`, Rust `S11a/S11b`). A workspace root carries a
`workspace { member … }` block, members self-identify with `name`,
member-to-member edges use the `member "<name>"` reserved-keyword dep kind,
resolution produces one shared graph + `<root>/milpa.lock`, and per-member
`nim.cfg` points at a shared `<root>/_deps/`. Cross-repo dev linking is the
separate `local=` / LocalFetcher path (#42, also shipped).

The **workspace-completion RFC** (`docs/rfc-workspace-completion.md`) is
**COMPLETE** — all 19 slices (S1–S12, including S5b, S9a/S9b, S11a–e)
implemented and gated across both impls. Issues closed: #160, #159, #109,
#93, #129, #81, plus the eighth asymmetry (member-dir `add`/`remove`/`update`
detect-and-delegate, S11e). `milpa show` member-scoped output is deferred to
#165. The workspace symmetry thesis is now total: every milpa capability
behaves identically on a standalone package or a workspace member.

## Dev workflow

The Python impl is uv-managed from `impls/python/` (run these from there):

```bash
cd impls/python
uv sync                    # install milpa + dev deps (pytest, hypothesis)
uv run pytest              # unit tests (~11 sec)
MILPA_INTEGRATION_TESTS=1 uv run pytest tests/test_integration.py   # gated network tests
uv run python -m milpa --help                          # invoke CLI
uv run python -m milpa -C <project_dir> fetch          # fetch in some other project
```

The Rust impl runs inside the pinned container via `./dev-rust` (from repo root):

```bash
./dev-rust test --workspace          # full Rust suite (incl. conformance corpus)
./dev-rust test -p milpa-conformance # just the shared-corpus run
```

Both impls read the shared corpus at the repo-root `conformance/`. No Docker for
Python (pure Python); Rust uses podman/docker. Hypothesis runs ~100 examples per
property by default; the database lives at `impls/python/.hypothesis/` (gitignored).

Toolchain expectations:
- Python 3.11+
- uv (already installed on the user's machine)
- git (for the fetcher subprocess + test fixtures)

`./dev` exists in fresco/, NOT in milpa/. Don't try to run it here.

## Commit conventions

- **Conventional commits**: `feat:`, `fix:`, `refactor:`, `docs:`,
  `infra:`, `chore:`, `arch:`, `rfc:`
- **Direct to main**, pre-1.0, no PRs
- **`closes #N` syntax** auto-closes GitHub issues on push
- **No `Co-Authored-By` trailers, no "Generated with..." footers**
- **Use the global git config** — never `-c user.email=...` overrides.
  The global is `corey@leavitt.dev`. Past breach got rewritten with
  `git filter-branch`; don't recreate the problem.

## Testing patterns

- Example tests for specific behaviors (in `tests/test_*.py`)
- Property tests for algebraic / round-trip properties (in
  `tests/test_*_properties.py`) — Hypothesis with KDL-safe alphabets
- Integration tests gated by `MILPA_INTEGRATION_TESTS=1` (real network
  against real github URLs; uses fresco's actual dep tree as fixture)
- No mocking. Tests use real subprocess for git, real Hypothesis,
  fakes injected as kwargs (`fetcher`, `index`/`index_loader`)
  for unit tests where network would be undesirable.

Counterexamples Hypothesis discovers get **pinned as regression tests**
in the corresponding `test_*.py` file (per
`rfc-property-based-testing.md` Phase A: shrink → fix → pin). When the
v1.5 spec extraction lands, those pinned counterexamples get promoted
to JSON fixtures in the conformance test suite.

## Status snapshot (2026-06-14)

#6 (clean-room Python rewrite, RFC `rfc-python-clean-room-rewrite`) fully complete and
swapped in: `impls/python/` IS the rewrite; the frozen design-vehicle impl is deleted;
`spec/errors.md` is spec-owned (not generated from any impl); harness runs `python` +
`rust` with zero cross-impl divergence.

## Real fresco verification

milpa is verified end-to-end against fresco's real dep tree:
- fresco's `milpa.kdl` declares `intonaco git=... ref=main`
- intonaco's `intonaco.nimble` requires chronos (URL) + transitives (named)
- `milpa fetch` resolves 7 deps (intonaco, chronos, results, stew,
  bearssl, httputils, unittest2) in ~5 seconds via parallel fetch
- Lockfile records every dep with sha + content_hash
- `milpa verify` confirms _deps/ matches the lockfile

This is the integration test suite's primary fixture. Don't break it.

## Anti-priorities

Things that are NOT milpa's job and resist scope creep into:

- Nim compiler installation / version management (#54 — deferred to v2
  toolchain RFC; not v0.x/v1 territory). Until then, nimble/choosenim
  handles this.
- Task scripts / build hooks (#55 — also v2 toolchain RFC; v0.x/v1
  is pure dep resolver).
- Companion binary symlinking (#56 — same).
- Building features without first checking if the data model already
  supports them. Audit before building.

## Where to start a new session

Sequenced from most actionable to most exploratory:

1. **Tier 3 structural work**: Phase B content-addressing (#32, #33, #34).
   Global CAS dedup, multihash encoding, and the store-gc mini-RFC.
2. **Pluggable fetchers**: F4 HgFetcher (#43), F5 FossilFetcher (#44),
   then research-tier F6/F7 (#45/#46). (F1–F3 + tarball + local shipped.)
3. **`milpa show` member-scoping** (#165): follow-up from the
   workspace-completion RFC — attribute each dep to its originating member.
4. **v1.5 prep**: when Tier 3 is done, the spec extraction (#14
   error catalog is filed there as the first deliverable)

Read `docs/comparison-vs-nimble-atlas.md` for the full picture before
deciding what to prioritize.

## Compact Instructions

When compacting, preserve in the summary: the active RFC and its handoff-doc
path, the current stage/round, slices done vs remaining, open forks awaiting
Corey, and the exact resume command. After compacting, re-read the handoff doc
and MEMORY.md before continuing.
