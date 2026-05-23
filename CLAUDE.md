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

## Architecture

milpa is a Python package (uv-managed). All code in `milpa/`:

| Module | Role |
|---|---|
| `manifest.py` | `milpa.kdl` parse + format + auto-discovery (`.nimble` fallback) |
| `nimble_parse.py` | `.nimble` line-form parser (no nimscript eval) |
| `identity.py` | `compute_content_hash(path)` — sha256 of source tree per spec |
| `fetcher.py` | git clone + content hash via `fetch_url_dep(name, git, ref, deps_dir)` |
| `registry.py` | nim-lang/packages registry resolution + version constraint matching |
| `solver.py` | **PubGrub** (teaching-clean form) + `VersionSet` algebra + `Strategy` enum |
| `resolver.py` | top-level glue: manifest → fetch + parse + solve → `ResolvedGraph` |
| `lockfile.py` | `milpa.lock` parse + format + verification (`verify_against_graph`, `verify_lockfile_against_deps`) |
| `nimcfg.py` | `nim.cfg` emission from `ResolvedGraph` |
| `cli.py` | argparse + the 5 subcommands (`fetch`/`lock`/`show`/`verify`/`clean`) |

The package boundary lines up with conceptual responsibility. There's
**one source of truth** for each cross-cutting concern:
- `Version` type + `parse_version` → `solver.py` only
- Content hash algorithm → `identity.py` only
- Constraint matching → `VersionSet.from_constraint(c).contains(v)` only

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
- **Provenance** (`source` + `ref` + `tag` + `sha`): URL or registry
  name + git ref + commit SHA. Mutable, trust-dependent.

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
- **Tier 2 — atlas parity**: 2/5 done (#49 strategies, #50 overrides);
  open: #25 workspace (re-scope pending — see open question below),
  #23 features, #26 conditional `when` blocks
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

## Open question: #25 workspace re-scoping

At session end (2026-05-22), unresolved: should #25 (workspace) be:

- **Best-dep-manager framing**: keep #25 as cargo-style true workspace
  (monorepo, shared lockfile, member-by-name resolution). Build the
  cross-repo dev linking via #42 (local-path provenance / LocalFetcher)
  separately. Both ship.

This is the framing the user landed on at session end (correcting an
earlier session-internal mistake of letting fresco's needs frame the
issue). #25's body still needs sharpening to reflect this. **Sharpen
#25's body before implementing.**

## Dev workflow

```bash
uv sync                    # install milpa + dev deps (pytest, hypothesis)
uv run pytest              # unit tests (~6 sec)
MILPA_INTEGRATION_TESTS=1 uv run pytest tests/test_integration.py   # gated network tests
uv run python -m milpa --help                          # invoke CLI
uv run python -m milpa -C <project_dir> fetch          # fetch in some other project
```

No Docker. Pure Python. Hypothesis runs ~100 examples per property
by default; the database lives at `.hypothesis/` (gitignored).

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
  fakes injected as kwargs (`fetcher`, `list_tags`, `registry_loader`)
  for unit tests where network would be undesirable.

Counterexamples Hypothesis discovers get **pinned as regression tests**
in the corresponding `test_*.py` file (per
`rfc-property-based-testing.md` Phase A: shrink → fix → pin). When the
v1.5 spec extraction lands, those pinned counterexamples get promoted
to JSON fixtures in the conformance test suite.

## Status snapshot (2026-05-22)

- **Suite**: 220 unit tests + 4 gated integration tests (all passing)
- **Commits since v0**: significant (Tier 1 + Tier 2 partial + property
  tests A-C + audit cleanups + RFC commits)
- **Open milestones**:
  - v0.x — ergonomic CLI + manifest editing (9 open)
  - backlog — unscheduled (5 open)
  - content-addressed identity (8 open — Phase B-E)
  - pluggable fetchers (9 open — F1-F8 + SafeExtractor)
  - property-based testing (4 open — research + infrastructure)
  - research roadmap (3 open)
  - v2 toolchain (8 open)
  - v1.5 spec extraction (1 open — error catalog #14)
- **Bugs found by Hypothesis this session** (good kind of finding):
  2 (VersionSet `_normalize_intervals` lo=None merge gap; lockfile
  format silently dropping `tag` field). Both fixed + pinned as
  regression tests.
- **Code quality cleanups this session**: 4 unifications (`match_constraint`
  → VersionSet, duplicate `Version` type, duplicate `parse_version`,
  `_content_hash` thin alias)

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

1. **Sharpen #25's body** with the cargo-style workspace framing from
   the open-question section above. Then start implementing it.
2. **Tier 2 remaining items**: #23 features, #26 conditional requires
3. **Tier 3 structural work**: Phase B content-addressing (#32, #33, #34)
4. **Pluggable fetchers**: F1 protocol refactor (#40), then F2 tarball
   (#41), F3 local-path (#42 — also unblocks workspace use cases)
5. **v1.5 prep**: when Tier 2+3 are done, the spec extraction (#14
   error catalog is filed there as the first deliverable)

Read `docs/comparison-vs-nimble-atlas.md` for the full picture before
deciding what to prioritize.
