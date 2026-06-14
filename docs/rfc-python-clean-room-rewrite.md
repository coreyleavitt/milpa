# RFC: Clean-room Python implementation

**Status:** Draft (Stage 1 — slicing). Architecture rounds 1–2 applied; all
escalations resolved (§8). Ready for `/tdd`.
**Supersedes:** the frozen `impls/python/` design-vehicle impl (KDL 1.0).
**Depends on:** the settled spec (`spec/`), the Rust reference (`impls/rust/`),
and the shared conformance corpus (`conformance/spec-v1/`).

## 1. Motivation

milpa is committed to multiple first-class implementations from a single spec
([[multi_impl_strategy]], `docs/rfc-multi-impl-strategy.md`). The lifecycle is:
Python (design vehicle) → Rust (reference) → **Python rewrite** → Nim (dogfood).

Rust now ships as the reference (full conformance corpus green, fuzzed, live-e2e
verified, installed as the production `milpa 0.1.0`). The current Python impl has
served its purpose as the design vehicle and is **frozen at KDL 1.0**: ~10
conformance fixtures are `python_known_failing`, the tier-1 syntactic differential
is gated, and it carries prototype design accidents (the `kdl-py`/`ParseResult`
shim layer, a git-only `MockedFetcher`, mutation verbs that don't thread
`MILPA_MOCKED_FETCHES`, a 1300-line monolithic `resolver.py`).

This RFC defines a **clean-room, from-scratch** Python implementation built to the
spec + Rust reference. It is explicitly **not** a port or refactor of the frozen
impl — extending that code would drag its accumulated accidents forward. The
frozen impl is a *reference to read* for design intent, never a base to build on.

### Why a pure-Python impl at all (not PyO3 bindings to Rust)

Restating the [[multi_impl_strategy]] rationale, because it constrains design:
1. **Plugin-ecosystem authenticity** — plugin authors write plain Python, no PyO3
   FFI tax. (Binding to Rust would make "extensible in Python" a lie.) **Scope:**
   plugin extensibility is the *fetch* layer (a new `Fetcher` for an
   already-specified provenance kind, `spec/plugin-contract.md` Layer 3). The
   *manifest grammar* is closed at v1 — a new provenance **kind** with new manifest
   syntax requires a spec amendment, not a plugin (`plugin-contract.md` §4). The
   "plain Python" claim is true for transport, not for grammar; the RFC states this
   explicitly so the goal is not oversold.
2. **Real spec validation needs an independent impl** — a binding shares the
   reference's decisions and bugs and validates nothing. An independent rebuild
   actively probes spec ambiguity. This is the whole point of the differential
   harness.
3. **Distribution simplicity** — `pip install milpa`, any platform, no wheel
   matrix.

These three force a hard constraint: **pure Python, no compiled extension in the
default install path.**

## 2. Goals / non-goals

**Goals**
- A from-scratch Python package that passes the entire shared conformance corpus
  (the spec is the authority; cross-impl agreement is a finder, not the verdict —
  [[feedback_best_in_class_check]]).
- KDL **2.0** throughout (manifest, lockfile, registry), matching the corpus.
- Restore the differential harness to a genuine two-impl (Rust + new-Python) check
  with zero divergence on the common subset.
- Hard single-source-of-truth boundaries (no duplicate `Version` / content-hash /
  constraint-parsing paths — [[feedback_audit_for_duplication]]).
- A **single execution-context seam** (`MilpaEnv`, §4.4) carrying the injectable
  `fetcher` / `index` / `store` so the in-process conformance adapter can drive core
  without a subprocess, and so `MILPA_MOCKED_FETCHES` is read in exactly one place.
  Per-call resolution parameters (`strategy` / `max_parallel` / `profile` / `prior`)
  ride a separate `ResolveParams` so the env seam stays constant per process and the
  `frozen.py` path — which receives `MilpaEnv` but no fetcher-driving params — cannot
  structurally reach a fetcher.

**Non-goals**
- `publish` (out of CLI-contract scope, S15 §10).
- Performance tuning beyond the network-bound baseline (CPU work is negligible;
  see [[multi_impl_strategy]]).
- Maintaining the frozen impl. It is deleted at swap (§8).
- A new spec. This impl conforms to the existing spec; any gap found is a spec
  escalation, not a local patch ([[feedback_no_workarounds]]).

## 3. Key decision: KDL 2.0 via git-pinned `kdl-py`

No pure-Python KDL 2.0 library is on PyPI yet. `kdl-py` (tabatkins/kdlpy — by
KDL's own author) has complete 2.0 support on `main` but is **unreleased**;
`ckdl` is 2.0 but a C extension (violates the pure-Python constraint);
`python-cuddle` / `kdl-rs-py` are dead/stubs.

**Decision (Corey, 2026-06-11):** depend on `kdl-py` git-`main` via a **pinned
commit SHA** for reproducibility:
```
kdl-py @ git+https://github.com/tabatkins/kdlpy.git@<SHA>
```
Swap to `kdl-py>=2.0` when it publishes to PyPI (tracked as a follow-up issue).

**Risks + mitigations**
- *Unreleased dependency.* Pin an exact SHA; never float `main`. The swap is a
  one-line `pyproject` change.
- *Recursion / stack-overflow on deep nesting.* `kdl-py` is a pure-Python
  recursive-descent parser; deep input would raise `RecursionError`
  **before** any milpa code runs, violating the cli-contract R3 invariant (every
  exit-1 carries a `milpa-error:` line). Two independent recursion vectors exist and
  **both** are pre-scanned: (1) node-children `{ }` nesting (the
  `parseNode`↔`parseNodeChildren` path) and (2) **nested `/* */` block comments**
  (`parseBlockComment` recurses per level — the brace scan alone does NOT cover this).
  The `KDL_MAX_NESTING_DEPTH=32` guard is therefore a **pre-parse character-level scan**
  in `kdl_io.py`, run *before* `kdl.parse()`, tracking **both** `{ }` depth and `/* */`
  depth; on overflow it raises the context-appropriate `*-KDL-SYNTAX` `MilpaError`.
  (Mirrors the Rust `kdl_brace_depth` pre-scan, extended for the comment vector.)
  As a belt-and-suspenders backstop, the `kdl.parse()` call is wrapped in
  `try/except RecursionError -> MilpaError(*-KDL-SYNTAX)` (Python `RecursionError` is
  always catchable, unlike Rust's SIGABRT). **`sys.setrecursionlimit` is NOT used** —
  it is process-global across all threads, so lowering it inside a `ThreadPoolExecutor`
  worker (parallel fetch, S9b-7) would spuriously trip unrelated threads. The pre-scan
  + `except RecursionError` pair is the complete guard.
- *Byte-format vs canonicalization.* Both the **lockfile** and **manifest**
  emitters are **hand-rolled** (string templating, like Rust) so their output is
  byte-exact: `milpa.lock` per S5 §2.4, `milpa.kdl` per S3 3e.  The manifest
  emitter (`format_manifest`) re-emits every URL field as a typed `(url)"…"` value
  (`manifest-grammar.md` §2, normative), preserves `spec-version`
  present-stays-present / absent-stays-absent (§4.4), and emits a stderr warning
  when comments are dropped (§8).  `kdl-py`'s printer is not used for serialization.
  Parsing always goes through `kdl-py`.
- *Edge-case differences from the corpus.* The S2 slice validates `kdl_io` against
  the relevant corpus fixtures (KDL syntax error fixtures) before anything builds
  on it.

`kdl_io.py` is the **only** module that imports `kdl-py`. Everything else sees a
typed DOM façade (interface specified in §4.3), so a future swap (to PyPI `kdl-py`,
or a hand-rolled parser if the release stalls) is contained to one module.

## 4. Architecture

Mirror the proven Rust crate decomposition, adapted to Python idioms. Package
name stays **`milpa`** (so `pip install milpa` / `python -m milpa` are unchanged);
it is developed at a new path and swapped in at parity (§6). The module split
**follows the Rust reference**: where Rust keeps two `milpa-core` modules separate
(`resolver.rs`/`frozen.rs`, `registry.rs`/`index_cache.rs`), so does this impl —
the blueprint is authoritative and the boundaries are load-bearing (no-I/O vs I/O,
fetch vs no-fetch). The merge suggestions raised in review were considered and
rejected on that basis.

### 4.1 Single-source-of-truth boundaries

Each lives in exactly one module; duplication is a bug:
- `Version`, `PreId`, `parse_version`, `format_version_str`, `VersionSet`,
  `from_constraint`, `from_nimble_constraint`, `Strategy` → `version.py` **[S1]**
  (pure computation, no KDL/fetcher deps; must be importable by `manifest.py` and
  `lockfile.py` without importing the solver — hence Stage 1, before manifest).
- `compute_content_hash`, `parse_identity` → `identity.py`
- error slugs (as **named constants** — `MAN_DEP_REF_MISSING = "MAN-DEP-REF-MISSING"`,
  one per slug) + `MilpaError(slug, message, **context)` base → `errors.py`
- CAS admit/link → `cas.py`
- KDL 2.0 parse/emit (the only `kdl-py` importer) → `kdl_io.py`
- `url_key` (mocked-fetch key encoder) → `fetchers/mocked.py`
- constraint→`VersionSet` parsed at the manifest parse boundary (the #121 design:
  resolver holds only typed sets) → `manifest.py` calling `version.py`
- transport→`ProvenanceRecord` mapping: `ResolvedDep` carries a lockfile
  `ProvenanceRecord` (defined in `lockfile.py`), **not** a transport `Provenance`.
  The resolver maps transport→record at graph-build time, so `lockfile.from_graph`
  needs no import from `fetchers/` (mirrors the Rust layering; avoids the frozen
  impl's cross-layer import).

### 4.2 Module layout

```
milpa/
  __init__.py  __main__.py
  errors.py            # all slugs; MilpaError base (bijection-tested vs spec/errors.md)
  version.py           # Version, PreId, VersionSet, from_constraint, Strategy  [S1]
  identity.py          # compute_content_hash, parse_identity  [S2]
  cas.py               # CAStore: admit, link, contains, default_store, scratch lifecycle  [S5]
  profile.py           # Profile.from_environment  (DATA TYPES ONLY — no predicate eval)  [S3]
  kdl_io.py            # KDL 2.0 façade over kdl-py; pre-parse nesting-depth guard  [S2]
  manifest.py          # manifest + workspace types, parse, format  (NO filesystem I/O)  [S3]
  nimble.py            # .nimble line-scanner  [S3]
  lockfile.py          # parse / hand-rolled byte-exact format / from_graph / verify  [S4]
  nimcfg.py            # format_nimcfg, format_workspace_nimcfgs  [S4]
  solver.py            # PubGrub solve(), SolverError, result certificate  [S6]
  registry.py          # parse_index, Index, security validators  [S8]
  index_cache.py       # four-state freshness, MILPA_INDEX_URL (incl. file://)  [S8]
  context.py           # MilpaEnv + ResolveParams (execution-context seam, §4.4)  [S9]
  fetchers/
    types.py           # Provenance, ProvenanceReceipt, Fetcher ABC, FetcherRegistry,
    #                    FetcherConfig, entry-point discovery (milpa.fetchers group)  [S7]
    cas_admitting.py   # CasAdmittingFetcher (wraps a registry; cas_admissible gating)  [S7]
    mocked.py          # mocked_registry() factory + per-kind Mocked*Fetcher fakes; url_key (§4.5)
    git.py tarball.py oci.py local.py
    safe_extract.py    # extract_tar, Limits  [EXTRACT-*]
  workspace.py         # load_workspace, find_workspace_root  (filesystem I/O lives here)  [S9]
  resolver.py          # resolve, resolve_workspace, ResolvedGraph, §8 prior-pin reuse  [S9]
  frozen.py            # resolve_frozen, resolve_workspace_frozen (NO fetcher invocation)  [S9]
  manifest_writer.py   # mutate_manifest_file, add_mirror (explicit KDL-2.0 AST build)  [S10]
  cli.py               # argparse, 8 verbs + --version, exit-code + slug discipline  [S10]
```

**Boundary criteria (explicit, to prevent drift):**
- `manifest.py` does **no filesystem I/O** — it is pure text↔value. All
  file-loading (`load_or_discover_manifest`, `.nimble` fallback discovery) lives in
  `workspace.py` / a loader helper. (The frozen impl leaked `load_manifest` into
  `manifest.py`; that accident is not reproduced.)
- `profile.py` carries **data + `Profile.from_environment` only**, and contains **no
  I/O**. `Profile.from_environment(*, nim_version: str | None = None, target_os=…, …)`
  takes the Nim version as an **injected string** (default `"0.0.0"`); it never spawns
  `nim --version`. The subprocess that queries the live Nim version lives in `cli.py`
  (the I/O layer) and is passed in — so `profile.py` is importable in tests without a
  Nim toolchain present, and the conformance adapter supplies a fixed version. Predicate
  *evaluation* (`_filter_manifest_by_profile`) is a resolver step (S9), run **before**
  the solver input is built (`resolver-semantics.md` §6). The manifest parser represents
  predicates as data and never evaluates them — the `profile=None` conformance path
  (`conformance-fixtures.md` §2.8) must include **all** deps.
- `frozen.py` **never invokes a fetcher**. It reconstructs a `ResolvedGraph` from a
  lockfile + CAS. §8 prior-lockfile pin reuse (incl. tarball TOFU re-assertion) is a
  *live-resolve* behavior and lives in `resolver.py`, not here.

### 4.3 The `kdl_io.py` façade interface (specified, not discovered)

The façade is only swap-safe if nothing else reaches a `kdl.*` type. The `(url)`
annotation must not escape as `urllib.parse.ParseResult` (the exact leak in the
frozen impl's `manifest.py`). The module exports **only** milpa-owned types:

```python
# milpa-owned DOM types (opaque wrappers; never a kdl.* type crosses the boundary)
class KdlDocument: ...
class KdlNode: ...
class UrlValue:                                   # proves a value was a URL scalar
    def __str__(self) -> str: ...                 # (bare string OR (url)-annotated)
KdlValue = str | int | float | bool | None

def parse_kdl(text: str, *, context: Literal["manifest", "lockfile", "registry"]
              ) -> KdlDocument                    # applies depth guard; raises the
                                                  # context-correct *-KDL-SYNTAX MilpaError
def node_name(n: KdlNode) -> str
def node_args(n: KdlNode) -> list[KdlValue]
def node_props(n: KdlNode) -> dict[str, KdlValue]
def node_children(n: KdlNode) -> list[KdlNode]

# Node-level extractors — the operations manifest.py actually performs at every node.
# These fold the `node_args()[i]` lookup + isinstance check into one call, so the
# 40+ `isinstance(node.args[0], str)` sites in the frozen impl do not recur.
def node_arg_str(n: KdlNode, index: int = 0) -> str | None        # None = absent OR wrong type
def node_arg_url(n: KdlNode, index: int = 0) -> UrlValue | None
def node_prop_str(n: KdlNode, key: str) -> str | None
def node_prop_url(n: KdlNode, key: str) -> UrlValue | None
def node_prop_int(n: KdlNode, key: str) -> int | None
def node_prop_bool(n: KdlNode, key: str) -> bool | None

# Scalar extractors — for the rarer case where a KdlValue arrives independently
# (e.g. from a node_props() dict). value_as_url returns a UrlValue, NOT a bare str:
# this distinguishes "wrong type" (None) from "URL-shaped value" so manifest.py can
# raise MAN-*-ARG-TYPE precisely. (url) is unwrapped ONLY here / in node_*_url.
def value_as_str(v: KdlValue) -> str | None
def value_as_int(v: KdlValue) -> int | None
def value_as_bool(v: KdlValue) -> bool | None
def value_as_url(v: KdlValue) -> UrlValue | None

```

`manifest.py` calls `node_arg_url(node, 0)` / `value_as_url(v)` and gets a `UrlValue`
or `None` — the `ParseResult` leak is structurally impossible, and a bare string
(accepted per `manifest-grammar.md` §4 rule 4) is indistinguishable at the call site
from a `(url)`-annotated one (both yield `UrlValue`), while a non-string value yields
`None` so the caller raises the right `MAN-*-ARG-TYPE`. The lockfile emitter never
touches `kdl_io` (hand-rolled).

**Discovered constraint (S0a de-risk probe, verified on the pinned SHA).** `parse_kdl`
**must** call kdl-py as `kdl.parse(text, kdl.ParseConfig(nativeTaggedValues=False))` at
*every* parse site. With the default `nativeTaggedValues=True`, kdl-py's built-in
converter intercepts the `(url)` annotation and silently coerces the value to a
`urllib.parse.ParseResult` — the tag is consumed and unrecoverable (this is the exact
`ParseResult` leak §4.3 exists to prevent, and the default config *reintroduces* it). With
`nativeTaggedValues=False`, every tagged scalar surfaces as a `kdl.String`/`kdl.Bool`/… with
`.tag` and `.value`, so `node_*_url` / `value_as_url` can recognize `tag == "url"` and wrap
it in `UrlValue`. This flag is the lynchpin of the whole façade; S2a wires it once in
`parse_kdl`.

### 4.4 The `MilpaEnv` / `ResolveParams` execution-context seam

The frozen impl threaded `fetcher=` / `index_loader=` kwargs through every
orchestration function; `MILPA_MOCKED_FETCHES` was consequently read independently
per verb and got dropped on the mutation verbs (the bug behind fixtures 120/125–126).
With 8 verbs the kwarg approach is parameter-threading. The fix is **two** frozen
dataclasses with an explicit cut between *injectable environment seams* and
*per-call resolution parameters* — the cut the Rust reference already makes (its
`resolve(...)` takes `fetcher`/`index` plus positional `profile`/`prior`/`strategy`):

```python
@dataclass(frozen=True)
class MilpaEnv:
    """Injectable seams — constant per process, DI'd by the conformance adapter.
       Read once, at construction, from the environment."""
    fetcher: FetcherRegistry          # default registry, or a Mocked/Fake for conformance
    index: Index | None               # see eager-load note below
    store: CAStore

@dataclass(frozen=True)
class ResolveParams:
    """Per-call resolution parameters — may differ verb-to-verb / fixture-to-fixture."""
    strategy: Strategy
    max_parallel: int
    profile: Profile | None           # None = predicate filtering disabled
    prior: Lockfile | None            # §8 prior-pin reuse input; None = no prior / `update` with no <dep>
```

`resolve(manifest, deps_dir, env, params)` / `resolve_workspace(..., env, params)`
take both; `resolve_frozen(lockfile, env)` takes **only** `env` — it has no
`ResolveParams` and therefore no `strategy`/`max_parallel`/`prior`, making "frozen
never resolves live" enforceable by signature, not by discipline. `format_lockfile`
/ `format_nimcfg` take neither.

`MILPA_MOCKED_FETCHES`, `MILPA_CACHE_DIR`, `MILPA_INDEX_URL`, `MILPA_TARGET_*` are
read in exactly one place each (env construction for the first three; `Profile`
construction for the last). The in-process conformance adapter builds one
`MilpaEnv(fetcher=fake, index=fake, store=…)` and a per-fixture `ResolveParams`.
Adding a future env seam (e.g. a credential) is a one-field change to `MilpaEnv`.

**`index` is loaded eagerly, not lazily.** A `frozen=True` dataclass cannot have its
`None` field replaced after construction, so "lazy-load" is not expressible here and
would also smear `MILPA_INDEX_URL` reads across the call graph. Instead the CLI loads
the index **once** (via `index_cache.load()`) before building `MilpaEnv`, for the
verbs that need named-dep resolution; verbs that never touch the index
(`show`/`verify`/`clean` and the frozen fast-path) pass `index=None`. `None` means
"this invocation does not require index resolution," never "load it later."

**`prior` threading (settled here, not ad-hoc in Stage 9).** Each mutating verb's
command function loads the prior lockfile from disk (`maybe_load_lockfile(dir /
"milpa.lock")`) and passes it in `ResolveParams.prior`. `lock` and non-`<dep>`
`fetch` pass the loaded prior; `update` with no `<dep>` passes `prior=None` (drops
all pins). The frozen path receives no `ResolveParams` and constructs its graph
directly from the lockfile it was handed.

### 4.5 Conformance integration (designed in from slice 1)

- **Black-box CLI**: a `harness/descriptors.py` descriptor invokes the impl via the
  **absolute interpreter path** of its own venv —
  `<repo>/impls/python-ng/.venv/bin/python -m milpa` — never a bare `python -m milpa`
  (which would resolve to whichever venv is first on `$PATH` and silently invalidate
  the differential when both impls coexist). The binary must honor
  `MILPA_MOCKED_FETCHES`, `MILPA_CACHE_DIR`, `MILPA_INDEX_URL`, `MILPA_TARGET_*`,
  emit exactly one `milpa-error: <SLUG>` on exit 1, no slug on exit 0/2.
- **In-process adapter**: `resolve` / `resolve_workspace` take a `MilpaEnv` +
  `ResolveParams` (§4.4); `resolve_frozen` takes `MilpaEnv` only; `format_lockfile` /
  `format_nimcfg` take neither — so `tests/test_conformance.py`-style adapters drive
  core directly. The adapter builds `Profile` via
  `Profile.from_environment(nim_version=fixture_nim_version)` (a fixed string from the
  fixture's `env` file, default `"0.0.0"`) so no live `nim --version` subprocess runs
  in tests (the subprocess lives in `cli.py`, not `profile.py` — see §4.2).
- **Mocked transport is a `FetcherRegistry` factory, not a re-implemented dispatcher.**
  Rather than one `MockedFetcher` that `match`es on provenance kind (duplicating the
  registry's own `can_handle` dispatch — two mechanisms for the same four kinds), the
  module exposes `mocked_registry(mocked_dir) -> FetcherRegistry` that registers one
  fake fetcher per kind (`MockedGitFetcher`, `MockedTarballFetcher`, `MockedLocalFetcher`,
  and an `MockedOciFetcher` stub until OCI fixtures are defined). Each fake implements
  `can_handle` + `fetch` **once**; the registry's existing unique-match dispatch routes
  to it, exactly as for the real fetchers. Adding a kind = registering one fake, nothing
  else changes. The conformance adapter wraps `mocked_registry(...)` in
  `CasAdmittingFetcher` for the in-process path, identically to the CLI path — fixing the
  frozen impl's git-only gap (fixtures 125–126). The on-disk fixture layout per kind is
  governed by `conformance-fixtures.md` §2.3 (referenced, not re-invented in code);
  `url_key` is the SSOT key encoder, shared by all four fakes.

## 5. Stage + slice plan

Each slice is one RED-GREEN-REFACTOR cycle with a single clear failing-test target.
Conformance fixtures come online incrementally (see the gates). **Prerequisite
stages are stated per slice** — "independently testable" means *given its
prerequisites*, not in isolation.

**Stage 0 — scaffold**
- 0a `pyproject.toml` (git-pinned `kdl-py`; `ruff` lint config; **`mypy --strict`**
  in the dev toolchain and CI — ruff is a linter, not a type checker, and the
  `kdl_io` façade boundary is too load-bearing to leave types unenforced; this is the
  Python analogue of `cargo check` that the "Rust-level strictness" claim needs),
  full type annotations the policy, `milpa/__init__.py`+`__main__.py`, `uv sync`,
  empty pytest green. **De-risk `kdl-py` before committing the SHA:** confirm
  `kdl.parse('foo git=(url)"https://example.com" ref="main"')` and
  `kdl.parse('bar "x" #true "extra"')` (the `(url)` type-annotation, `#true` boolean,
  and prop+arg constructs milpa relies on) produce the expected AST on the pinned
  `main` SHA; record the verified SHA + these probe expressions in a `kdl_io.py`
  comment. If `kdl-py` fails the probe, the §8 fallback (hand-rolled parser) triggers
  here, before any stage builds on it.
- 0b harness `python-ng` descriptor (absolute venv interpreter path, §4.5) invokes
  the stub; exits 2, no slug. Wire into `harness/descriptors.py` **gated behind
  `MILPA_PYTHON_NG=1`** so it is dormant by default: a stub registered unconditionally
  would FAIL every corpus fixture not in its `known_failing` set and break
  `python -m harness` / CI's `overall_passed()` immediately. The gate keeps the green
  harness undisturbed; local dev runs `MILPA_PYTHON_NG=1 python -m harness` to exercise
  the new impl. The gate is removed at swap (S11c), when `python-ng` *is* `python`.

**Stage 1 — errors + version** (pure computation; no deps)
- 1a `errors.py`: all slugs as **importable named constants** (the name *is* the
  slug, so a typo at a raise site is a load-time `NameError`, not a test-time bijection
  miss) + `MilpaError(slug, message, **context)`; bijection test (single module — resolves
  open-Q3; the frozen 14-file split is not reproduced). This module **becomes the
  generator/SSOT for `errors.md`** at swap (replacing the frozen `error_catalog.py`;
  `errors.md` is generated, "do not edit by hand"). It includes the two v1 codes added
  this round (§8): **`FETCH-REF-DISCOVERY-FAILED`** (raised at S10e) and
  **`MILPA-INDEX-UNREACHABLE`** (raised at S8b). **Do NOT regenerate the shared
  `spec/errors.md` in this slice** — per §8 that breaks the frozen impl's generator +
  bijection tests and the Rust catalog bijection (both require a raise site + trigger test
  per code; the dev plan keeps both suites green). So the S1a bijection test asserts
  `errors.py`'s constant set equals the **current `spec/errors.md` slugs ∪ {the two pending
  codes}** — the two are explicitly marked pending-spec-inclusion. At swap (S11c)
  `errors.md` is regenerated *from* `errors.py` (gaining the two), the Rust companion
  (catalog entry + `DEFERRED`→`implemented` move) lands alongside the raise sites, and the
  test's `∪ {pending}` term is deleted so it reduces to `errors.py == errors.md` exactly.
- 1b `version.py` core: `Version`/`PreId`/`parse_version`/`format_version_str`/
  `Strategy`; property tests (round-trip, total order per semver §10–11).
- 1c `version.py` sets: `VersionSet` interval algebra
  (complement/intersect/union/contains) + `from_constraint` + `from_nimble_constraint`;
  property tests, **pinning the frozen impl's known Hypothesis counterexamples as
  regressions immediately** (the `_normalize_intervals` lo=None merge gap). Pinning
  counterexamples on discovery is a continuous discipline from here on, not a
  Stage-11 activity.

**Stage 2 — KDL façade + identity**
- 2a `kdl_io.py`: parse via `kdl-py`; the typed-DOM façade of §4.3; **pre-parse**
  `KDL_MAX_NESTING_DEPTH=32` scan over **both** `{ }` depth and `/* */` block-comment
  depth (§3) + `except RecursionError` backstop; parse/depth error →
  `MAN-KDL-SYNTAX`/`LOCK-KDL-SYNTAX`/`TNG-KDL-SYNTAX` by context. *Validation mechanism
  (stage-local, no CLI yet):* a `tests/test_kdl_io.py` that reads the KDL-syntax corpus
  fixture files directly (`conformance/spec-v1/fixture-001-*/milpa.kdl`, …), calls
  `parse_kdl(text, context=…)`, and asserts the exact slug — mirroring the S3
  `tests/test_manifest_parse.py` pattern. The black-box harness version of these
  fixtures lights up at S10a-0; do not claim harness coverage at Stage 2.
- 2b `identity.py`: `compute_content_hash` (byte stream S12 §1), `parse_identity`
  (5 ordered checks); property tests (same tree→same hash, `.git/` excluded, mode
  bits).

**Stage 3 — manifest** (deps: S1 version, S2 kdl_io)
- 3a manifest/workspace dataclasses (`Predicate`, `FlagRequest`, 5 dep forms,
  `Override`, `FlagDecl`) + `profile.py` data types (no eval).
- 3b `NamedDep` constraint pre-typed at parse via `VersionSet.from_constraint`
  (`MAN-DEP-NAMED-CONSTRAINT` raised at the boundary — #121 design; `VersionSet`
  already exists from S1c).
- 3c-1 URL dep parse (git + ref + `(url)`, `MAN-DEP-*`).
- 3c-2 named dep parse (constraint/arity, `MAN-DEP-NAMED-*`).
- 3c-3 tarball dep parse (sha256, strip_components, `MAN-DEP-TARBALL-*`).
- 3c-4 local + member dep parse (`MAN-DEP-LOCAL-*`, `MAN-DEP-MEMBER-*`).
- 3c-5 mirrors (`MAN-DEP-MIRROR-*`, `MAN-MIRRORS-*`).
- 3c-6 overrides (`MAN-OVERRIDE-*`).
- 3c-7 predicates as data (`MAN-PREDICATE-*`) — representation only, no eval.
- 3c-8 flags (`MAN-FLAG-*`, `MAN-DEP-FLAG-*`).
- 3c-9 `spec-version`, `dev-deps`, `cas`, top-level (`MAN-SPEC-VERSION-*`,
  `MAN-UNKNOWN-TOP-LEVEL`).
- 3d workspace manifest grammar (`MAN-WORKSPACE-*`).
- 3e `format_manifest`: hand-rolled byte-exact serializer (mirrors Rust
  `milpa-manifest::format_manifest`) — `(url)` annotations, insertion-stable order,
  `spec-version` present/absent round-trip (§4.4), comment-dropped stderr warning
  (§8). Property test: parse→format→parse round-trips to the same logical
  `Manifest`; byte-exact property: format(parse(x)) == format(parse(format(parse(x)))).
- 3f `nimble.py` (4 `requires` forms, `srcDir`, `when` warning, `nim` drop);
  property test mirroring the frozen `test_manifest_properties.py`.
- *Gate:* manifest-parse error fixtures exercised via a **stage-local
  `tests/test_manifest_parse.py`** that calls `parse_*` directly (imports only
  `manifest`/`kdl_io`/`errors`/`version`/`profile`) — integration signal at Stage 3
  without the CLI. The black-box harness manifest fixtures light up after the S10a-0
  bootstrap.

**Stage 4 — lockfile + nimcfg** (deps: S1, S2; uses `ProvenanceRecord` types it owns)
- 4a lockfile types (6-variant `ProvenanceRecord`, `LockedDep`, `Lockfile`) — owned
  here so the resolver maps transport→record (§4.1); `from_graph` needs no
  `fetchers/` import.
- 4b `parse_lockfile` (KDL 2.0, all provenance kinds, `strategy` node with `maxver`
  fallback for pre-v1.0 lockfiles, `self_mirrors`, `LOCK-*`); property tests.
- 4c `from_graph` + hand-rolled byte-exact `format_lockfile` (lexicographic dep +
  `requires` order; emits the `strategy` node). The `_kdl_str` escaper is SSOT for
  all string values: `\`→`\\`, `"`→`\"`, control chars U+0000–U+001F as `\u{NNNN}`,
  everything else verbatim (`lockfile-schema.md` §2.4). *Gate (unit, not harness):*
  fixture-118 (`lock-string-escaping`) is a full-resolve **success** fixture and is
  unreachable at Stage 4 — instead hand-craft a `ResolvedGraph` whose `ref` carries
  `"`, `\`, and control chars, call `format_lockfile()`, and assert byte-equality
  against `fixture-118/expected/milpa.lock`. The harness version of fixture-118 lights
  up at S9b-1.
- 4d `nimcfg.py` (POSIX paths, emission order). **Scope:** covers `lockfile-schema.md`
  §7.1–7.4; the §7.5 feature-flag `-d:<dep>_<flag>` emit is **deferred** (no corpus
  fixture exercises it; the Rust reference defers it too — tracked at #23), and
  `format_workspace_nimcfgs` (the §7.6 per-member relative-path emitter) is **stubbed
  here** and made real at S9d (it needs a workspace `ResolvedGraph`).
- 4e `verify_against_graph`, `verify_lockfile_against_deps`; property test over
  generated graphs.

**Stage 5 — CAS** (one slice; scratch lifecycle is not separable from admit)
- 5a `cas.py`: `admit` (atomic rename, dup=no-op), `link` (relative symlink),
  `contains`, `default_store` (4-tier precedence), and the `_scratch/<uuid>/`
  lifecycle with `BaseException` cleanup. Property tests (admit idempotence,
  link target resolves, hash stability).

**Stage 6 — solver** (deps: S1 version)
- 6a `solver.py` data structures (`Term`, `Incompatibility`, `PartialSolution`,
  `Assignment`, `PackageProvider` protocol). **Port the frozen impl's teaching-clean
  PubGrub algorithm verbatim** (resolves open-Q4 — it is the one frozen module worth
  reading: pure algorithm, no KDL/prototype coupling, already spec-clean).
- 6b-1 `solve()` + `SolverError`/conflict chain. RED: synthetic `PackageProvider`
  unit test (a known diamond conflict). Unit-only signal until S9 lights the solver
  via conformance fixtures.
- 6b-2 `Strategy` dispatch (MAXVER / MINVER / SEMVER). RED: same provider, different
  strategy → different selected version.
- 6b-3 the **result certificate** shape (`resolver-semantics.md` §5: success
  `{resolved, witness}` with the per-entry validity predicate
  `VersionSet.from_constraint(c).contains(v)`; failure refutation / weak UNSAT core
  naming every contributing consumer per §2/§5.2). The certificate is a **normative
  external output** (§5: MUST be emitted "in all contexts where correctness
  verification is requested" — Corey, 2026-06-11, kept external for v1). The observable
  channel is a CLI flag that serializes the certificate as JSON (S10b emits it; the
  `--certificate <path>` surface is a `cli-contract.md` addition — see §8); a
  **`check-certificate` conformance fixture type** compares the emitted JSON to
  `expected/certificate.json`. RED here (unit): build a known solution + a known
  diamond conflict, assert the §5.1 validity predicate / §5.2 refutation. The harness
  `check-certificate` fixtures light up at S10b. **Add the certificate-JSON serializer
  in `solver.py` (or a thin `certificate.py`) — SSOT, used by both the in-process
  adapter and the CLI flag.**

  **Canonical-solution selection is NOT a solver slice.** `resolver-semantics.md`
  §4.2.1 (BFS package order P, lexicographically-maximal solution under P,
  declaration-order tie-break) is built from the *manifest's* dep-declaration order +
  transitive expansion, which `solver.py` cannot see. It lives in the resolver
  (S9b-3c), wired by constraining the order in which packages enter the solver. See
  the ordering invariant stated there.

**Stage 7 — fetchers** (deps: S5 CAS, S4 records)
- 7a base types (`Provenance`, `ProvenanceReceipt`, `Fetcher` ABC,
  `FetcherRegistry`, unique-match dispatch) + `FetcherConfig` (v1 shape per
  `plugin-contract.md` §7.1) + entry-point discovery for the `milpa.fetchers` group
  (`_build_default_registry`). Port the `milpa-fetcher-stub` test fixture into the
  new `pyproject.toml`. `FETCH_UNCODED_INVARIANTS` catalog exemption (§5.1).
- 7b `CasAdmittingFetcher` — wraps a `FetcherRegistry`, gates admission on
  `provenance.cas_admissible` (immutable→CAS symlink; local/editable→real dir).
  **Mirrors the Rust `CasAdmittingFetcher<R>`** (the blessed best-in-class design);
  CAS gating is *not* folded into the plain registry.
- 7c `MockedFetcher` — all transport kinds; `url_key` SSOT; per-kind fixture readers
  (§4.5).
- 7d-1 `GitFetcher` (subprocess `git clone`, commit SHA, `GIT-*`).
- 7d-2 `safe_extract.py` (`extract_tar`, `Limits`, `EXTRACT-ZIP-SLIP`/
  `EXTRACT-SYMLINK-ESCAPE`/`EXTRACT-SIZE-LIMIT`) — standalone, no fetcher protocol.
- 7d-3 `TarballFetcher` (download + `safe_extract`; receipt carries
  `archive_sha256`; TOFU first-use recording — the #116 mechanism, see S9c).
- 7d-4 `LocalFetcher` (`cas_admissible=False`, identity-only, no network).
- 7d-5 `OciFetcher` (registry auth, digest verify — most complex; lowest priority,
  only `TNG-*` parse-path fixtures are mandatory at v1).
- 7e `FETCH-RECEIPT-EMPTY` guard; `FETCH-ALL-FAILED` mirror fallback over the
  **three-part ordered candidate list** (`resolver-semantics.md` §8a: primary URL,
  dep-block mirrors, prior-lockfile `self_mirrors`).

**Stage 8 — registry + index cache** (kept as two modules, mirroring Rust)
- 8a `registry.py`: `parse_index`, `Index`, security validators (commit SHA, OCI
  digest, no-leading-dash, unsafe name); `TNG-*`. Property tests on validators.
- 8b `index_cache.py`: four-state freshness; `MILPA_INDEX_URL` **including the
  `file://` scheme** (`cli-contract.md` §8.1, required for air-gapped harness runs);
  default URL. State 4 (network failure, no usable cache) raises the new v1 catalog code
  **`MILPA-INDEX-UNREACHABLE`** (§8); state 3 (stale-cache offline fallback) warns and
  proceeds — its warning MUST NOT emit a `milpa-error:` line (R3).

**Stage 9 — resolver** (deps: S3, S4, S5, S6, S7, S8) — *not* independently testable
in isolation
- 9a `context.py` (`MilpaEnv` + `ResolveParams`, §4.4) + `workspace.py`:
  `load_workspace`, `find_workspace_root`; `WS-*`; the orphan-member stderr warning for
  undeclared member-shaped subdirectories (`cli-contract.md` §7.1).
- 9a-pre `tests/test_conformance.py` (the **in-process adapter** itself — a real slice,
  not a side-effect of 9a): fixture discovery, `parents[N]` corpus-path verification,
  workspace-vs-single-package dispatch, frozen-vs-live routing, `MilpaEnv` construction
  with `mocked_registry(...)`+`CasAdmittingFetcher`, per-fixture `ResolveParams` +
  `Profile`. **This file must exist before any S9b-* "fixture green" gate can be
  checked.** RED: the adapter imports all needed modules and the `parents[N]` path
  resolves to a non-empty fixture set (a wrong depth → 0 fixtures → vacuous green; the
  path assertion is the RED test).
- 9b-1 `resolve` — URL-only deps, serial (`max_parallel=1`), no prior, no
  predicates. Gate: fixture-003 green.
- 9b-2 predicate filtering (`ctx.profile`; `_filter_manifest_by_profile` run before
  the solver). Gate: fixture-115 (`conditional-dep-excluded`).
- 9b-3a named-dep Phase-A enumeration (from the index) + Phase-B lazy materialization
  for a single named dep. Gate: fixture-061.
- 9b-3b BFS transitive expansion (a materialized named dep whose `.nimble` introduces
  another named dep). RED: a two-hop transitive named-dep fixture.
- 9b-3c **canonical-solution selection** (`resolver-semantics.md` §4.2.1), relocated
  here from S6 (see 6b-3). **Ordering invariant (normative, state it in code):** the
  order packages enter the solver MUST equal package order P — the BFS traversal from
  root in declaration order. Concretely, deps at BFS depth *d* emit their dependency
  terms before any dep at depth *d+1*, and a named dep takes the BFS position of the
  package that first introduced it. A different iteration order yields a different
  lex-maximal solution that passes every unit test but fails fixture-063. RED:
  fixture-063 variant A (X declared first); pin variant B (Y declared first)
  immediately.
- 9b-4 provenance precedence (`resolver-semantics.md` §10: root authority set,
  transitive provenance suppression, same-provenance dedup, `RES-PROVENANCE-CONFLICT`
  on non-root conflict). Gate: fixture-065.
- 9b-5 `dev-deps` (`§9`): root + workspace-member dev-deps resolved; a transitive
  dep's dev-deps MUST NOT enter the graph. Gate: fixture-064.
- 9b-6 local-dep arm (no fetch, symlink-in-place).
- 9b-7 parallel fetch (`ThreadPoolExecutor`); the **determinism property**: same
  manifest + strategy → byte-identical lockfile regardless of `-j`.
- 9c §8 prior-lockfile pin reuse in `resolver.py` (NOT `frozen.py`): for a dep whose
  manifest key (URL+ref, or tarball URL) is unchanged, reuse the recorded identity
  and never re-fetch. **Tarball TOFU re-assertion mechanism (the #116 fix), spelled
  out:** (i) `TarballFetcher` receipt carries `archive_sha256`; (ii) `_process_tarball`
  reads `result.receipt.archive_sha256` (not the manifest-declared `dep.sha256`,
  which is `None` on first TOFU fetch) onto the candidate; (iii) `from_graph` records
  the archive sha256 into `TarballProvenanceRecord` using the precedence
  `dep.sha256 or receipt.archive_sha256 or locked_sha256` — i.e. a manifest-declared
  `dep.sha256` (the **non-TOFU** case) is authoritative and `receipt.archive_sha256` is
  used only when `dep.sha256 is None` (mirrors the Rust rule); (iv) on refetch with a prior
  lock, the locked `archive_sha256` is threaded back as the fetcher's
  `expected_sha256`, raising `FETCH-SHA256-MISMATCH` on substitution. Gate:
  fixtures 125 (record) + 126 (refetch-mismatch).
- 9d `resolve_workspace` (union members, cross-member constraint accumulation, §11) +
  the real `format_workspace_nimcfgs` (§7.6: per-member `nim.cfg` paths **relative to
  the member's directory**, member-deps routed to the member dir not `_deps/`). Like
  `resolve`, it accepts `ResolveParams.prior` — the §8 pin-reuse and §8a mirror-fallback
  apply identically to workspace resolutions (each external dep is pinned from the prior
  lock regardless of which member introduced it). Gate: fixture-116, fixture-117.
- 9e `frozen.py` (`resolve_frozen`/`resolve_workspace_frozen`; **no fetcher
  invocation**). Enumerate the **10 resolver-level `FROZEN-*` preconditions**
  (`resolver-semantics.md` §7.1's closed list). The 2 additional catalog codes —
  `FROZEN-NO-LOCKFILE`, `FROZEN-NO-CAS` — are **CLI-level guards** raised in `cli.py`
  before the frozen path is entered (S10b), a different layer; 12 `FROZEN-*` codes
  total in `errors.md`. (See §8 — the spec §7.1 "closed list" wording needs a scope
  clarification; escalated.)
- *Gate:* core `resolve` fixtures green via the in-process adapter; the black-box
  resolve fixtures after the S10 CLI.

**Stage 10 — CLI** (deps: S9)
- 10a-0 **bootstrap CLI**: minimal argparse that can run `milpa fetch -C <dir>`,
  load/discover the manifest, and emit `milpa-error: <SLUG>` on a manifest parse
  error — *before* any fetch. This is what first lights the black-box manifest-parse
  fixtures in the harness. (Closes the "no fixture runs until very late" gap.)
- 10a `cli.py` skeleton: argparse for 8 verbs + `--version` (`cli-contract.md` §9:
  print `milpa <version>` to stdout, exit 0) + global flags (`-C`/`--directory`,
  `-j`, `-s`, `--frozen`); exit-code + R1–R4 slug discipline; `MilpaEnv` built once
  per process (`MILPA_MOCKED_FETCHES` wired in here) and a per-verb `ResolveParams`
  (§4.4).
- 10b `fetch`/`lock`. `fetch` honors `--frozen` (fast-path with the 2 CLI-level
  `FROZEN-NO-*` guards) and passes `ResolveParams.prior` for §8 reuse. `lock`
  **always** runs the full resolver (`cli-contract.md` §5.2): it passes `--frozen=false`
  so the frozen fast-path is never taken, *but* it still passes a loaded
  `ResolveParams.prior` for §8 pin reuse (matching Rust — `lock` reuses prior pins; it
  just always re-resolves) and emits no `nim.cfg`.
- 10c `show`/`verify`/`clean`.
- 10d `manifest_writer.py` (explicit KDL-2.0 AST: `mutate_manifest_file` calls
  `manifest.format_manifest` for serialization and does **only** the file I/O — zero KDL
  AST construction duplicated here; `add_mirror`; comment-dropped warning per §3). The
  write MUST be **atomic** (sibling tmp + `os.replace()`) for both `milpa.kdl` and
  `milpa.lock`, so a mid-write kill leaves the files unmodified (`cli-contract.md` §5.6).
- 10e `add`/`remove`/`update` with mocked transport. **Mocked ref-resolution:** when
  `MILPA_MOCKED_FETCHES` is set and `--ref` is omitted, discover the default branch from
  the mocked transport (`conformance-fixtures.md` §2.3.3 / `cli-contract.md` §5.6),
  fixing the frozen impl's fixture-120 gap. **Error paths (each needs a test, harness
  fixture where black-box-observable, else unit + tracking issue):** `add --git` dup →
  `MAN-ADD-DEP-EXISTS`; `add --mirror` → `MAN-ADD-MIRROR-IDENTITY-MISMATCH` /
  `MAN-MIRROR-EDITABLE-PROVENANCE`; `remove` absent → `MAN-REMOVE-DEP-ABSENT`; `update
  <dep>` not in lock → `LOCK-DEP-NOT-FOUND`; `update <dep>` no lockfile →
  `LOCK-FILE-NOT-FOUND`. `update` with **no** `<dep>` passes `prior=None` (drops all
  pins, §4.4). The non-mocked `add --git` ref-discovery failure raises the new v1 catalog
  code **`FETCH-REF-DISCOVERY-FAILED`** (§8), honoring R3.

**Stage 11 — conformance saturation + swap**
- 11a full harness over the new impl; triage to zero divergence on the common
  subset; remove `python_known_failing` entries that no longer apply.
- 11b `harness/coverage.py` MUST-clause coverage. **Done-condition for the
  no-fixture slugs:** the ~50 catalog slugs with no corpus fixture are partitioned into
  three buckets, and the partition itself is the deliverable (no silent gaps): (a)
  **black-box-testable via mocked transport / filesystem state** (e.g.
  `FETCH-SHA256-MISMATCH`, `FETCH-MOCK-MISSING`, `VERIFY-DEPS-DIR-MISSING`,
  `MAN-NO-MANIFEST`, the mutation-verb error slugs from 10e) — file new corpus fixtures
  here; (b) **network-only, genuinely un-fixtureable at v1** (e.g.
  `FETCH-DOWNLOAD-FAILED`, `FETCH-GIT-FAILED`) — accept with a tracking issue each; (c)
  **implementation-internal** (`MILPA-INTERNAL`, `INTERNAL-PANIC`) — unit-test only. Run
  the Hypothesis property suites (counterexamples are pinned continuously from S1 — this
  pass *promotes* selected pins to JSON corpus fixtures, it is not first-discovery).
  **Live e2e fresco verification** (`MILPA_INTEGRATION_TESTS=1`): the new impl resolves
  fresco's real 7-dep tree and emits lock+cfg **byte-identical to the Rust output**.
- 11c **swap** (§6) per the pre-flight checklist; rename descriptor `python-ng` →
  `python`; **update CLAUDE.md's architecture table and the `multi_impl_strategy`
  memory** to the new module layout.

## 6. Migration / coexistence (§8 of the rollout)

During development the frozen impl stays at `impls/python/` (KDL 1.0, its
`python_known_failing` set intact) so the harness stays green. The clean-room impl
is developed at `impls/python-ng/`, package `milpa`, in its **own venv**, wired to
the harness as a separate `python-ng` descriptor that invokes the venv's interpreter
by **absolute path** (§4.5). Both packages declare `name = "milpa"` — the collision
is managed purely by the venv boundary (safe; never activate both venvs in one
shell). The package is **not** renamed `milpa-ng` (that would couple the
in-progress state into `import` statements and the swap). Open-Q1 resolves to:
separate path, swap at parity. (A branch+worktree variant was considered; the
separate-path approach keeps the green harness undisturbed with lower cognitive
overhead.)

**CI during development.** Add a `python-ng` CI job starting at **S3** (when the first
tests exist) that runs `uv run pytest` from `impls/python-ng/`. It may legitimately
have failures until S11a triage, but a *newly* red job must not be ignored — it is the
regression signal across the long build. The harness job stays gated (`MILPA_PYTHON_NG`
unset) until swap. The `python-ng` pytest job is removed/renamed at swap.

**Stage 11c swap pre-flight checklist** (the swap is mechanically risky; the rename +
descriptor + CI updates + old-impl delete are **one atomic commit** — doing them as
separate commits breaks CI mid-swap):
1. Verify `python-ng/tests/test_conformance.py` finds `conformance/` via the correct
   `parents[N]` depth (a wrong path silently skips every fixture → vacuous green).
2. `uv run pytest` from `impls/python-ng/` fully green; harness over `python-ng`
   (`MILPA_PYTHON_NG=1`) zero-divergence; live fresco e2e byte-matches Rust.
3. `git mv impls/python impls/python-old` (park the frozen impl — avoids the path
   collision while both briefly exist).
4. `git mv impls/python-ng impls/python` (the physical rename).
5. Update `harness/descriptors.py`: interpreter path now `impls/python/.venv/bin/python`;
   rename descriptor `python-ng` → `python`; drop the `MILPA_PYTHON_NG` gate.
6. Update `.github/workflows/ci.yaml` `working-directory: impls/python`; drop the
   transient `python-ng` job.
7. **Commit steps 3–6 as the single swap commit**, then run the full harness to confirm
   zero regression at the new path.
8. `git rm -r impls/python-old` + commit (only after step 7 is green).
9. Update CLAUDE.md architecture table + `multi_impl_strategy` memory.

## 7. Resolved design questions (were open; settled in round 1)

1. **Dev path/package name during coexistence.** → separate `impls/python-ng/` path,
   descriptor by absolute interpreter path, swap at parity (§6).
2. **Emitter mechanisms.** → both lockfile and manifest use hand-rolled byte templating
   (`_kdl_str` escaper for lockfile §5 4c; equivalent escaping for manifest §3 3e);
   `kdl-py`'s printer is not used for serialization.
3. **`errors.py` shape.** → single module of slug constants + bijection test (§5 1a).
4. **PubGrub.** → port the frozen impl's teaching-clean algorithm verbatim (§5 6a).
5. **`kdl-py` SHA pin + PyPI-swap tracking issue.** → file now
   ([[feedback_defer_file_now]]).

## 8. Risks + escalations

- **`kdl-py` never publishes 2.0 to PyPI.** Mitigation: the `kdl_io.py` façade
  (interface in §4.3) contains the dependency to one module; the fallback
  (hand-rolled parser) is a contained swap, and milpa has deep KDL-parser expertise
  (nkdl).
- **Scope.** This is a full reimplementation (~45 slices after the round-1 reslice).
  Mitigated by small vertical slices, the spec + corpus as the fixed target, and the
  Rust reference as the blueprint. The long pole is S6 (PubGrub port) — unit-test
  signal only until S9 lights the solver via conformance fixtures.
- **Two Python packages named `milpa` transiently.** Mitigated by separate venvs and
  the absolute-interpreter-path descriptor; resolved at swap.
- **Result certificate stays an external MUST (RESOLVED — Corey, 2026-06-11).**
  `resolver-semantics.md` §5 requires emitting a certificate but no current CLI surface
  or fixture observes it. Decision: keep it external for v1 (settle the spec right, even
  without an immediate consumer). **Required follow-on spec work:** (a) `cli-contract.md`
  gains a `--certificate <path>` global flag (or equivalent) — writing the certificate
  JSON is an exit-0 success path, **no slug**; (b) `conformance-fixtures.md` gains a
  `check-certificate` fixture type (compares emitted JSON to `expected/certificate.json`).
  The RFC (S6b-3, S10b) builds to this; the two spec sections must be written before
  S10b implements the flag.
- **`add --git` ref-discovery failure slug (RESOLVED — Corey, 2026-06-11).** v1 gains
  catalog code **`FETCH-REF-DISCOVERY-FAILED`**, raised in both impls (Rust currently
  exits 1 with no `milpa-error:` line — an R3 violation the Rust reference must be fixed
  to honor; the new Python impl raises it at S10e's non-mocked path). `cli-contract.md`
  §5.6 references the slug. **Wiring note:** `errors.md` is *generated* (header: "do not
  edit by hand") — today from the frozen impl's `error_catalog.py`. So this code is NOT
  hand-added now (that would break the frozen impl's generator+bijection tests, which the
  dev plan keeps green); it is added by the **new impl's `errors.py` named-constant SSOT**
  (S1a), which becomes the generator at swap, with the Rust `DEFERRED`→`implemented`
  companion landing alongside the raise sites.
- **`index_cache` state-4 (offline, no cache) slug (RESOLVED — Corey, 2026-06-11).** v1
  gains **`MILPA-INDEX-UNREACHABLE`** as-is (Rust already emits this exact sentinel but
  keeps it *out* of its catalog list — cataloguing it + promoting it into
  `implemented_error_codes()` restores the bijection). S8b raises it for the
  network-failure-with-no-cache state per `registry-protocol.md` §6. Same generator
  wiring note as above: it enters `errors.md` via the new impl's `errors.py`, not a hand
  edit to the frozen-generated file.
- **`FROZEN-*` closed-list scope (uncovered in review — RESOLVED).**
  `resolver-semantics.md` §7.1 read "No other `FROZEN-*` codes exist. The list is
  closed," but `errors.md` catalogs **12** `FROZEN-*` codes — the extra two,
  `FROZEN-NO-CAS` and `FROZEN-NO-LOCKFILE`, are CLI-level guards (`_try_frozen` /
  `_try_workspace_frozen`) raised *before* the resolve path is entered. §7.1 was
  re-scoped (2026-06-11) to ten *resolve-path preconditions* + a note pointing at the
  two CLI-level guards (twelve total). Wording clarification, no behavior change. The
  new impl follows this layering: 10 codes in `resolve_frozen`/`resolve_workspace_frozen`
  (S9e), 2 guards in `cli.py` (S10b).
