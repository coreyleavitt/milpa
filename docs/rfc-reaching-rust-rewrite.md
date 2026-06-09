# RFC: Reaching the Rust rewrite — the Python readiness gate

Status: **draft** (2026-06-08). Milestone: *v1.5 — spec extraction
(rfc-multi-impl-strategy)*.

## What this RFC is — and is not

milpa's implementation lifecycle ([[multi_impl_strategy]],
`docs/rfc-multi-impl-strategy.md`): Python is the **design vehicle**; the
**Rust reference impl** is ported from the *settled spec*; a clean Python
rewrite follows from the Rust reference; Nim dogfoods last. All three are
first-class, maintained from one spec.

This RFC defines the **gate** between phase 1 (Python design vehicle) and
phase 2 (Rust reference): the exact set of Python-side deliverables that must
ship *before* starting the Rust port, plus the **exit criteria** that declare
"Python is ready to port." It stops at that line.

**Non-goals (explicitly out of scope — a separate later RFC):**
- The Rust port's own design: crate layout, async strategy, HTTP/git stack,
  port sequence, PyO3-vs-pure boundaries.
- Any feature deferred to the Rust impl per [[multi_impl_strategy]]
  (informational verbs #19/#20/#21, richer constraint vocab #27, transport
  flags #83/#84, Hg/Fossil #43/#44, v2 toolchain).
- Resolution-semantics *policy* (#98 strategy, #86 exclude-newer) and the
  tianguis index-deps play — worthwhile but post-gate / parallel, not
  port-blocking (`docs/rfc-index-version-selection.md`).

## Why gate at all

The criterion for inclusion is singular: **does shipping this in Python reduce
port-time design risk or enable independent conformance verification?** If yes,
it belongs in the gate; if it's polish or a feature the Rust impl would build
once anyway, it does not (it would be wasted double-work). The gate exists so
the Rust port starts against a *frozen, conformance-backed spec* rather than a
moving target — which is the entire point of using Python as the design vehicle
first.

## The gate deliverables

Five items. State verified against the repo 2026-06-08.

### G1 — Error catalog complete (#92)
**State:** `ManifestError` done (#14 — 61 codes, bijection-tested,
`spec/errors.md`). `TianguisError` already follows the pattern.
Remaining: extend it ([[error_catalog_discipline]]) to the other user-facing
categories — LockfileError, ResolverError, FetchError, CASError, NotFrozen,
IdentityError, NimbleParseError, SolverError, **WorkspaceError**,
**ExtractionError** (`safe_extract.py`), manifest_writer, tarball.
**Scope of "raise":** the catalog covers **user-facing** errors only. The repo
has ~113 `raise` sites outside `manifest.py`, but a large fraction are
**programmer-invariant panics** (`AttributeError`/`IndexError`/`ValueError` for
"immutable Version mutated", "unparseable clause reached impossible branch",
subprocess-infra `RuntimeError` in `publish.py`/`profile.py`). Those stay
**uncatalogued by design** — they are bugs, not contract. G1 must draw this line
normatively: a catalog code is a *contract with the caller*; an invariant panic
is an internal assertion. **Decidable criterion (so the audit is reproducible and
the taxonomy is consistent across categories):** a raise is *user-facing* iff it
is reachable by some call that originates from **user-supplied input** — manifest
bytes, lockfile bytes, index bytes, or CLI arguments — without the user writing
code. "Can a user trigger this raise without writing Python?" Yes → catalog code;
no (only a milpa bug or a programmer misusing the API can reach it) → invariant
panic. This rule resolves the cross-boundary cases below mechanically rather than
by per-site judgment. The done-criterion below is about the former.
**Pre-work (call out as step 1 of S2):** unlike `ManifestError`/`TianguisError`,
the other exception classes (`LockfileError`, `ResolverError`, `FetchError`,
`NotFrozen`, …) currently lack a `.code` field. Adding it + the per-category
bijection lint (ideally via a shared base, not copy-paste — single source of
truth) is prerequisite work, and will churn the many tests that assert on
exception *message strings* rather than `.code`.
**Cross-boundary code (resolved by the decidable criterion):** `solver.py`'s
`ValueError` for an unparseable constraint (`solver.py:439/451`, raised from
`VersionSet.from_constraint`) is reached from `_build_terms` (`resolver.py:1731`)
while processing a transitive dep's `.nimble` requires — i.e. **user-supplied
data** → user-facing. Per the criterion it is a `ManifestError` (malformed
constraint in package data), reclassified **at the `_build_terms` callsite**, not
left as a bare `ValueError` in `solver.py`. `SolverError` itself carries a
`.chain` (`ConflictChain`) and exactly one user-facing condition (unsatisfiable);
it takes a constant `.code` (e.g. `SOLVE-CONFLICT`). S2 executes both.
**Why port-blocking:** the Rust impl must emit the same error identities; an
incomplete catalog means undefined error behavior the Rust impl would have to
invent and then reconcile.
**Done when:** every user-facing raise carries a catalog code; the bijection
lint passes for all categories; `spec/errors.md` covers them; **slugs are
frozen at gate-close** via a **bidirectional** validator — it errors if a spec'd
slug disappears from code without a tombstone/alias entry (catches *renames/
deletions*), **and** errors if a slug appears in code that is absent from
`errors.md` (catches *post-freeze additions* — the more dangerous direction: a new
Python-only code with no Rust counterpart silently desyncs the spec). After
gate-close, a new slug requires a spec amendment (add to `errors.md`) *before* it
may appear in code; the validator runs in CI. (A one-directional deletion check
would leave the spec non-authoritative for additions — the exact failure spec
extraction is meant to prevent.)
**Kind:** mostly mechanical code + spec, with the two design decisions above.

### G2 — Workspace named-dep Phase A/B migration (#109)
**State:** the main `resolve()` path uses the multi-version `_enumerate_named`
+ native-PubGrub model; `resolve_workspace()` (`resolver.py:931`) still uses
single-version `_process_named`. So workspace resolution is *strictly weaker*
than single-project for named deps. (This is the real residual of the now-closed
#100.) **Two distinct gaps**, which must not be conflated:
1. **No cross-consumer constraint intersection** — `_process_named` picks per
   requirer; multiple members' constraints on one named dep are not intersected
   before selection.
2. **No candidate enumeration / backtracking** — `_process_named` calls
   `tianguis_client.resolve_named` (single best-match) rather than
   `resolve_named_all`, so the solver never sees the full candidate set.

Fixing only (1) would leave (2); the done-criterion below must close both.

**Known implementation risk (verified against code — the real gap is callback
wiring, not the executor).** Round-1's "pre-solve drain" framing was wrong and is
retracted: `_on_new_url` (`resolver.py:728`) calls `_process_url` *directly* — it
never touches the `ThreadPoolExecutor` — so the closed-executor concern does not
arise, and no pre-solve URL-transitive drain is needed or correct. The actual gap
`resolve_workspace()` has today is that it goes straight to `solve()` with **no
`provider.start_solve(...)` call** (`resolver.py:961-963`): no `_on_new_named` /
`_on_new_url` callbacks are wired. After migration, the solver will call
`dependencies()` → `_materialize_stub`, but with the callbacks unset, any named or
URL transitive discovered *at solve time* silently does nothing → a wrong (under-
resolved) graph. **S1 must wire `provider.start_solve(_on_new_named, _on_new_url)`
in the workspace path**, with closures over workspace-local `seen_named` /
`seen_url`, mirroring `resolve()`. It must also call `_enumerate_named` with a
`None` constraint (not the first member's constraint — following `_on_new_named`'s
pattern at `resolver.py:710-718`) so candidate enumeration is not pre-filtered by
member *arrival order*.
**Why port-blocking:** a divergence between two resolution entry points is a
behavior the spec would otherwise have to document as a wart, and that the Rust
impl would either faithfully reproduce or silently diverge on. Remove it before
spec extraction so `resolver-semantics.md` describes *one* model.
**Done when:** `resolve_workspace()` resolves named deps through the same
enumerate-then-solve path; **for any named dep + constraints, workspace
resolution selects the same version `resolve()` would** (not merely "the same
conflict is detected") — pinned by a property test asserting the two paths agree;
a workspace diamond that succeeds single-project also succeeds in a workspace;
`_process_named` (sole caller `resolver.py:931`) and `resolve_named` retired.
**Kind:** code (`/tdd`).

### G3 — Spec extraction (`spec/`)
**State:** only `errors.md` exists.
**Anchor:** `rfc-multi-impl-strategy.md` §"The spec — what it contains" already
enumerates the **canonical 7 sections** the spec must cover. The gate must
produce all of them that are port-blocking — the earlier draft of this RFC
covered only 3 (manifest grammar, lockfile grammar, resolution algorithm) and
**silently dropped the identity algorithm (§3), CLI contract (§6), the
fetcher-protocol details (§5), and conformance requirements (§7)**. A "frozen
spec" missing the content-hash algorithm is not frozen. Mapping:

| Canonical §| Gate doc | Slice |
|---|---|---|
| 1 Manifest grammar | `manifest-grammar.md` | S4 |
| 2 Lockfile grammar | `lockfile-schema.md` | S5 |
| 3 **Identity algorithm + CAS layout** | `identity.md` | **S12 (new)** |
| 4 Resolution algorithm | `resolver-semantics.md` | S6 |
| 5 Fetcher protocol | `plugin-contract.md` (G5) + provenance shapes in `manifest-grammar.md` | S10/S4 |
| 6 **CLI contract** | `cli-contract.md` | **S15 (new)** |
| 7 Conformance requirements | the normative/incidental + MUST/MAY/MUST-NOT framing across all docs + G4 | all |
| — **`nim.cfg` emission** (expected conformance output) | `nim-cfg.md` (or §of `lockfile-schema.md`) | S5 |
| — **tianguis index read-format** (named-dep input) | `registry-protocol.md` | **S14 (new)** |
| — **`.nimble` compat parsing** (transitive-dep input) | §of `manifest-grammar.md` | S4 |
| — **conditional-dep / `when`-block evaluation** (dep-set input) | §of `manifest-grammar.md` (syntax) + `resolver-semantics.md` (eval) | S4/S6 |

**Why these additions are port-blocking (not scope creep):**
- **Identity algorithm** — `content_hash` is milpa's non-negotiable identity
  primitive. The byte-level details (canonical stream, POSIX relpath sort,
  exec-bit mode encoding, symlink target handling, `.git/` exclusion at *any*
  depth, multihash prefix, **raw bytes — line endings NOT normalized**) cannot
  be reverse-engineered safely; any divergence silently changes every hash. CAS
  layout (`<root>/<algo>/<hex>/`, default `~/.cache/milpa`, atomic `rename(2)`
  admission, duplicate = no-op) + the `_deps/<name>→CAS` symlink convention must
  match cross-impl or the frozen fast-path and `nim.cfg` `--path:` lines break.
- **`nim.cfg` emission** — the conformance fixtures list `nim.cfg` and
  `_deps_structure.txt` as **expected outputs**. Format is a cross-impl
  commitment: `--path:` line form, **POSIX separators regardless of host**,
  ordering (self src → dep paths → `-d:` flags), the `<dep>_<flag>` define rule,
  workspace per-member relative paths.
- **tianguis index read-format** — without it the Rust impl can't resolve named
  deps at all. Covers `index.kdl` schema, `TIANGUIS_INDEX_SCHEMA_VERSION`
  negotiation (`TNG-SCHEMA-UNKNOWN` on higher version), per-version provenance
  record shape, and the security-critical TNG validators (commit-SHA / OCI-digest
  / unsafe-name-URL-ref). This is the index *read* contract — distinct from and
  not blocked by the deferred index-deps *policy* (#98/#86).
- **`.nimble` compat** — the Rust impl parses transitive deps' `.nimble` to learn
  their requires; a different heuristic silently diverges the resolved graph.
  Spec the 4 `requires` forms, `srcDir`, the `when`-block policy (skip + warn),
  URL-vs-named classification, and `NimbleParseError` semantics.
- **conditional-dep / `when`-block evaluation** (`profile.py` + `manifest.py`
  `Predicate` + `resolver.py:_filter_manifest_by_profile`) — **live, user-visible,
  cross-impl behavior with no spec home in the round-1 draft.** Predicates
  (`platform`, `arch`, `nim`, `milpa`) decide which deps enter the solver input, so
  a divergent evaluator silently resolves a *different graph*. Spec: predicate
  syntax + the four keys + OR semantics for multi-value + negation annotation +
  the mixed-negation parse error (S4); that predicates are evaluated **before**
  solver input — `_filter_manifest_by_profile` is **normative** (S6); the canonical
  platform/arch vocabulary tables (Nim `hostOS`/`hostCPU` names — e.g. `darwin` and
  `macosx`, `x86_64` and `amd64`) (S4/appendix); and the `MILPA_TARGET_PLATFORM` /
  `MILPA_TARGET_ARCH` / `MILPA_TARGET_NIM` override env vars (S15). This is as
  port-blocking as `.nimble` compat — same failure mode (wrong dep set).
- **CLI contract** — exit-code semantics, stderr/stdout routing, `--frozen` /
  `-C` behavior, env vars. Lower risk for most verbs (self-documenting) but
  `--frozen` carries a **normative no-network guarantee** (see below) CI users
  depend on. **Scope cut ([[feedback_minimal_over_completeness]], gate criterion):**
  `publish` (tianguis dispatch / OIDC / OCI push / Sigstore) is **not part of spec
  v1.0 conformance** — it depends on external services, is not dir-tree-fixture
  testable, and a second impl need not replicate it. S15 enumerates the
  conformance-tested verbs (fetch/lock/show/verify/clean/add/remove/update) and
  marks `publish` out-of-scope, reserved for a later amendment.

**Critical normative decisions:**
- `resolver-semantics.md` MUST encode the **constraint-accumulation** target
  (engine-agnostic) — all consumers' constraints intersect; an empty intersection
  produces a structured failure refutation naming every contributing dep — **not**
  any eager/first-constraint-wins behavior. (PubGrub realizes this; the requirement
  is the accumulation semantics, not the algorithm.)
- It must also spec the **identity-constraint convention** for URL / local /
  member deps (the *shape*, not the Python sentinel value `_URL_DEP_VERSION`):
  a non-indexed dep is treated as version-unique by identity — the solver sees it
  as a package with a single canonical version. This is what makes `fetch_any`
  + content-hash verification compose with backtracking; omit it and the Rust
  impl invents its own mechanism.
- **Resolution semantics — moor to observable behavior, NOT to the engine
  (decided; revisit depth at spec-writing).** The spec must outlive not just the
  Python impl but the *algorithm* ([[feedback_spec_vs_impl]]). PubGrub is the
  **reference producer**, not a normative requirement. Three observables, only one
  of which is PubGrub-flavored:
  1. **Completeness** — a solution is found iff one exists. Engine-agnostic; any
     complete solver satisfies it. (*Not* "MAY use any strategy" — that's
     incoherent with G4's byte-exact lockfiles, and an incomplete solver narrates
     conflicts that aren't truly unsatisfiable.)
  2. **A canonical solution — byte-identical lockfiles via a specified
     *solution-selection function*, not a tie-break alone.** Round-1 framed this as
     "deterministic decision/traversal order as a total function of partial state,
     without collapsing to run-PubGrub." Round-2 depth review proved that framing
     **incorrect**: a tie-break (MaxVer) plus "some deterministic order" does *not*
     force one lockfile across genuinely different complete engines. Counter-
     example — `A → {B≥1, C≥1}`, `B@2 → D≥2`, `C@1 → D≥1`, `D∈{1,2}`: PubGrub-style
     propagation decides `D@2`; a DPLL/CDCL engine may return the equally-complete
     `{A,B@1,C@1,D@1}` on its own variable-ordering heuristic. Both satisfy every
     constraint; neither is "wrong." Byte-identical output therefore requires the
     spec to define **the canonical solution declaratively** — *which* satisfying
     assignment is THE answer — not merely a tie-break. The right mooring: the
     lockfile is the **lexicographically-maximal complete solution** under a
     spec-defined package order (canonical BFS from roots; declaration order within
     a manifest) with per-package version chosen by `Strategy` (default MaxVer),
     resolved with backtracking. This is a *declarative selection function over the
     solution space* — it moors impls to the **canonical solution (the *what*)**,
     **not** to PubGrub's algorithm (the *how*). PubGrub's propagation naturally
     produces it; a raw SAT engine conforms by implementing the selection procedure
     (or enumerate-then-select). That distinction — moor to the solution, not the
     engine — is what keeps `rfc-beyond-pubgrub.md`'s alternative engines open while
     still guaranteeing one lockfile. This is the real substance of
     `resolver-semantics.md`. *(Exact canonical-order procedure pinned at
     spec-writing, per Corey; the **mechanical** done-check is in S6: two
     independent in-Python implementations of the selection rule must produce
     byte-identical lockfiles on the diamond fixture.)*
  3. **Checkable result certificate (engine-agnostic correctness proof — distinct
     from #2's determinism).** #2 moors *which solution*; #3 moors *a proof the
     solution is correct*, checkable without re-running the solver. Commit to the
     **weak (UNSAT-core) failure-certificate**, not PubGrub's derivation graph:
     - **Success witness** — `{resolved: [(pkg,ver)], witness: [(pkg,ver,
       constraint, satisfied_by)]}`: an `O(n·constraints)` check that every declared
       constraint is met by the chosen versions. No engine internals.
     - **Failure refutation** — a **set of incompatibilities** (`{(pkg,
       constraint)}`) that is *itself* unsatisfiable, verifiable in polynomial time
       — i.e. an UNSAT core, **not** the derivation DAG. "Names all contributing
       incompatibilities" is defined as "the named set is genuinely unsatisfiable,"
       a checkable predicate, **not** "reproduces what PubGrub would name" (which
       would re-moor to the engine and foreclose `rfc-beyond-pubgrub.md` D1/D3).
       PubGrub's derivation graph *is* one valid refutation; a SAT UNSAT-core is
       another. **Human-readable conflict text stays incidental** (never
       byte-normative).

  **Gate scope line ([[feedback_minimal_over_completeness]], spec ≠ impl):** v1
  freezes the **certificate schema + the validity predicate** (the two shapes
  above), and conformance tests byte-identical lockfile (success — #2) + structural
  validity & genuine-unsatisfiability of the named core (failure — #3). The full
  **independent poly-time verifier** ("don't trust the producer") is the
  `rfc-beyond-pubgrub.md` Direction-1 follow-up — non-breaking *because* the schema
  is frozen to support it. Python's missing backjumping (`solver.py:28`) is a
  tracked-incidental fix-issue, not gate-blocking.
- `manifest-grammar.md` carries a **spec/manifest version field** — implemented as an
  **integer epoch** (`spec-version <int>`, **optional, absent ⇒ 1**;
  `MANIFEST_SPEC_VERSION = 1`). It guards the one failure P3 cannot: a **breaking semantic
  redefinition of existing syntax** (an old impl would otherwise parse a new manifest and
  silently misinterpret it). Modeled on Cargo `edition` / k8s `apiVersion`, **not** a
  lockfile-style hard gate: bumped **only** for breaking changes; *additive* evolution stays
  within an epoch and is handled by the P3 forward-unknown properties (no bump). An impl
  **MUST reject** (`MAN-SPEC-VERSION-UNSUPPORTED`) a manifest declaring an epoch greater than it
  implements. This reuses the **same major-vs-minor bump discipline as G4's fixtures**; it is a
  **distinct namespace** from `LOCKFILE_SCHEMA_VERSION` and `TIANGUIS_INDEX_SCHEMA_VERSION`.
  Behavior for a **forward-unknown provenance kind** (an *additive* change, no epoch bump) is
  fixed by P3's descriptor model — **parse-always, verify-always, fetch-fails-precisely** (a
  hard, diagnostic error only on a cache-miss fetch of an unknown kind; never a silent drop).
- Each doc must distinguish **normative** (any conformant impl must match) from
  **incidental** (this Python impl happens to do it this way) — using a **single
  prescribed convention so all ~11 docs are consistent**: a `> NORMATIVE:`
  block-quote per normative claim, `> NOTE:` for incidentals, **plus** a
  "Normative surface" summary at the top of each doc enumerating exactly what a
  conformant impl must implement. Without a prescribed convention each doc invents
  its own and the porter can't tell commitment from description.
  [[feedback_spec_vs_impl]].
- `manifest-grammar.md` includes the `(url)` convention ([[kdl_url_convention]])
  and the P3 **provenance-descriptor model**: closed meta-grammar
  (`<kind> { …fields }`), spec-version-owned kind registry, and the
  parse-always / verify-always / fetch-fails-precisely properties.
- **`--frozen` is a resolver behavior, not just a CLI flag (S6 + S15).** Spec the
  normative guarantees: (a) **no network access occurs** under `--frozen` (the CI
  security guarantee); (b) the frozen path **rebuilds `ResolvedGraph` from the
  lockfile record alone — it does NOT re-run the solver** (`_try_frozen` /
  `_try_workspace_frozen`); (c) the precondition chain (lockfile present, CAS
  attached, manifest loadable, strategy matches) and which failures are silent
  fall-through vs hard error *with* `--frozen` (`NotFrozen` reasons). The
  no-network + solver-bypass guarantees go in `resolver-semantics.md`; flag/exit
  semantics in `cli-contract.md`.
- **Prior-lockfile pin reuse (S6).** `resolve()` / `resolve_workspace()` accept a
  `prior_lockfile` that makes `_pin_for_url_dep` / `_pin_for_tarball_dep` reuse a
  previously-fetched identity instead of re-fetching a moved ref — observable
  (changes the lockfile) and **distinct from `--frozen`** (a soft selection
  preference, not a hard freeze). Spec it as a named normative behavior (stability
  guarantee), not an incidental optimization.
- **CAS is append-only (S12).** The store has no eviction today; admission is the
  only write. Normative: a conformant impl **MUST NOT silently evict a CAS entry a
  lockfile still references**. Eviction/GC is out of scope for spec v1.0 (a later
  amendment). State it either way — silence makes the Rust impl invent a policy.
- **`cas_admissible` is a contract, not an impl detail (S10/S12).** Each provenance
  kind declares whether its bytes are CAS-admissible; **editable sources (local,
  member) are NOT admissible** — admitting them would silently freeze user edits.
  The registry reads this before `admit()`. As load-bearing as the
  identity-forbidden-in-receipt obligation; spec it in the fetcher contract.
- **Lockfile version negotiation (S5).** Today `parse_lockfile` hard-rejects any
  version ≠ 1. Spec the policy normatively: a conformant impl **MUST raise
  `LockfileError` on an unrecognized (higher) version** (no best-effort parse);
  spec v1.0 defines only lockfile version 1; a v2 schema requires an amendment.
- **Tarball TOFU + `strip_components` (S4/S5).** `strip_components` changes which
  paths enter the tree and therefore the content hash — spec that stripping happens
  **before** `content_hash` (S4). The TOFU model (absent `sha256` → first fetch
  pins the archive sha into the lockfile receipt) is **normative first-use
  pinning**, not incidental (S5).
- **Index provenance records are a strict subset of manifest descriptors (S14).**
  `registry-protocol.md` does **not** define a second provenance grammar: a
  `git { url … ref … }` in an `index.kdl` entry follows the *same* meta-grammar,
  kind-set, and fields as in a manifest (S4 / P3), plus index-only metadata (Rekor
  attestation, version set). State this normatively so the porter doesn't write two
  divergent parsers.
**Done when:** all mapped spec docs exist, reviewed, normative/incidental marked
per the prescribed convention, spec-version declared (see exit criteria).
**Kind:** doc (design-review, not `/tdd`).

### G4 — Conformance fixture suite (#72)
**State:** counterexamples are pinned as Python regression tests; no language-
agnostic fixtures yet.
**Why port-blocking:** the conformance corpus is the *arbiter* when impls
disagree ([[multi_impl_strategy]] — "spec is the reference; corpus is the
arbiter"). The Rust impl must run the identical fixtures.
**Fixture format — decided, not deferred.** Adopt the **directory-tree format
already designed** in `rfc-multi-impl-strategy.md` §"The conformance test suite":
each `fixture-NNN-<slug>/` holds `milpa.kdl`, a frozen index snapshot,
`mocked-fetches/` (per-URL fake-fetcher returns: sha/content/nimble), and
`expected/` (`milpa.lock`, `nim.cfg`, `_deps_structure.txt`). This is a byte-diff
black-box format a non-Python harness diffs directly — **not** a bespoke JSON
`{input, expected}` schema (which would force a different Rust harness
architecture and re-litigate the encoding). The earlier "JSON fixtures" framing
is dropped. **Index-input format correction (post-#97):** the frozen index is
`index.kdl` (raw KDL text that `parse_index` consumes), **not** `registry.json` —
`registry.py` was retired (#97), so the multi-impl RFC's `registry.json` layout
must be updated to `index.kdl` when S8a lands (otherwise the fixture format embeds
an already-removed abstraction). Promoting `test_man_code_triggers.py`-style
trigger tables means extracting the *input KDL document* + *expected error code*
into this layout (a translation, since the current tables hold Python lambdas, not
data).
**Spec-version & fixture lifecycle (cross-cutting G3↔G4).** Each fixture is tagged
with the spec-version it targets and lives under `conformance/spec-v<N>/`. A
**normative behavior change requires a new spec-version**; old-version fixtures are
**retained** under their version dir (not mutated in place), so each impl declares
which spec-version it conforms to and the corpus stays a stable arbiter (the
HTTP/1.1 pattern this RFC cites). Format-break vs behavioral-extension is the
major-vs-minor bump rule. (Note: the impl-internal `LOCKFILE_SCHEMA_VERSION` and
spec-version are *related but distinct* namespaces — state the mapping in S5.)
**Done when:** `conformance/spec-v1/` holds dir-tree fixtures in the above
format; the existing trigger tables are promoted; **a diamond-conflict fixture**
(two consumers, conflicting constraints on one named dep → structured failure
refutation) is included (pairs with `resolver-semantics.md`); **coverage floor —
≥1 normative fixture per MUST-clause across the spec docs** (cross-references
`rfc-multi-impl-strategy.md` §"Acceptance"; gate-close is *not* achievable with a
trivially small suite); the Python suite runs them via a thin adapter.
**Kind:** mixed — the format/layout is a design decision (S8a [doc]); the adapter
+ promotion is code (S8b [code]). The two were conflated in one slice and are
split so the adapter doesn't stall on an undecided schema.

### G5 — Plugin architecture (designed inline — §below)
**State:** `Fetcher` Protocol + `FetcherRegistry` exist; built-ins wired in
`fetchers/__init__.py`; **no public third-party entry-point/discovery
convention**, and no spec-level (language-agnostic) Fetcher contract. This is
the one undesigned hole.
**Why port-blocking:** plugin authenticity is a stated reason for the eventual
pure-Python rewrite ([[multi_impl_strategy]] — plugins stay ordinary Python, no
PyO3 tax). Both impls must agree on what a plugin *is*; that contract is a spec
artifact, so it must be settled before the port, not after.
**Done when:** the discovery mechanism + the language-agnostic Fetcher contract
are specified (see design below) and a reference third-party fetcher loads
through it (test strategy in P1). **No new transports are built**
([[feedback_minimal_over_completeness]]).
**Kind:** design + small code (`/tdd` for discovery + adapter).

## Plugin architecture (designed inline)

The existing substrate (verified `milpa/fetchers/types.py`,
`fetchers/__init__.py`):

- `Fetcher` is a `@runtime_checkable Protocol`: `can_handle(p: Provenance) ->
  bool` and `fetch(name, p, *, dest) -> ProvenanceReceipt`. **Identity is not
  the fetcher's job** — the registry computes the content hash post-fetch from
  `dest`. This is the clean seam.
- Dispatch is **exclusive, not first-match-wins.** `FetcherRegistry._select`
  (`types.py:236`) collects *all* fetchers whose `can_handle` returns `True` and
  **raises `FetchError` if more than one matches** (and if none match). Exactly
  one fetcher must claim a given `Provenance`. `default_registry` pre-registers
  Git/Local/Tarball/OCI. (The earlier "first-match-wins" framing was wrong; the
  real invariant — and the one the spec/Rust port must encode — is *unique
  match*. Registration order is for readability, not priority.)
  **Pre-work (S10/S11, before spec extraction transcribes them):** the
  `FetcherRegistry` class docstring (`types.py:104-109`) and the `fetchers/__init__.py`
  comment **still say "first match wins" / "disjoint isinstance types" and name only
  one built-in** — both are now false and will be copied into the spec verbatim if
  not fixed first. Correct them to the exclusive-dispatch model as the first step of
  the plugin slices. The spec states exclusivity **without** the Python-specific
  `isinstance` mechanism: "a plugin's `can_handle` MUST return `True` for exactly the
  provenance kinds it declares; the registry enforces unique-match at dispatch and
  raises an ambiguity error if two registered fetchers both claim one descriptor."

Three things must be designed to make this a *plugin* system that holds across
impls.

### P1 — Discovery (Python mechanism)
Use `importlib.metadata` entry points under the group **`milpa.fetchers`**.
Each entry point resolves to a factory returning a `Fetcher`. `default_registry`
construction registers built-ins, then discovered plugins.

The safety property is **not** registration order — it is exclusive dispatch over
a **closed set of `Provenance` subclasses** (P3). A plugin's `can_handle` only
fires for a `Provenance` instance; since built-ins each own exactly one spec'd
shape, a plugin that also claimed `GitProvenance` would trigger the
*ambiguity error*, not silently shadow git. So a plugin cannot hijack a built-in
transport even in principle — the closed grammar + unique-match rule enforce it
structurally. (This is stronger than "built-ins win"; it fails loud.)

**Factory signature:** a **one-arg factory `(config: FetcherConfig) -> Fetcher`**,
where `FetcherConfig` is a spec-defined struct that is **empty for v1**. Rationale:
zero-arg forecloses ever passing a plugin a mirror URL / timeout / token without a
breaking signature change; reserving the slot now (empty) costs nothing and keeps
[[feedback_minimal_over_completeness]] satisfied — we build the slot, not the
config system. Threading actual config is a filed follow-up, not gate work.
**`FetcherConfig` must actually exist (S11 step 0):** it is referenced only in prose
today — the Rust porter cannot derive its schema, so a one-paragraph normative
definition (in `plugin-contract.md`) plus the dataclass (in `types.py`) is the
*first* sub-step of S11, before the reference plugin can be written. v1 shape: an
opaque struct with **no required fields**, reserving exactly one optional forward
hook (`mirror_urls: list[str]`, not required to be honored in v1) and nothing else.
A defined-but-empty struct is what makes the slot non-breaking; leaving it undefined
guarantees the Rust impl invents a different shape — the exact failure the gate
exists to prevent.

**Test strategy (S11):** entry points only populate after install, so the
reference plugin is a minimal package `tests/fixtures/milpa_fetcher_<x>/` with a
`[project.entry-points."milpa.fetchers"]` declaration, installed as a **dev
dependency** (`[dependency-groups].dev`) so the test exercises the *real*
`importlib.metadata` path (not a monkeypatched `entry_points()`). It is a
"third-party" plugin only in the structural sense. This test lives in the
**Python unit suite, never in `conformance/`** — discovery is a
Python-specific *mechanism*; only the *contract* (P2) is language-agnostic.

### P2 — The language-agnostic Fetcher contract (the spec artifact)
A plugin is defined, independent of language, by three obligations:
1. **Claim** — declares which provenance kind(s) it handles (`can_handle`).
2. **Materialize** — given a provenance descriptor, produce a source tree at a
   destination path. Pure w.r.t. milpa: it must not compute or assert identity.
3. **Receipt** — return a transport receipt (descriptive, not identity-bearing).

The contract must also pin these obligations the three-word skeleton leaves
implicit (each a cross-impl divergence risk if unstated):
- **Failure** — materialization failure is signalled by raising `FetchError`
  (Python) / `Err(FetchError)` (Rust). Tree contents at `dest` after failure are
  **undefined**; the **registry** owns cleanup (`clear_dest`, `types.py:164`).
- **Identity is forbidden in the receipt — drawn as a precise field-level line, not
  a vague MUST-NOT.** A `ProvenanceReceipt` subclass MUST NOT define a field whose
  value is a function of the *materialized tree bytes* (`content_hash`, `identity`,
  a tree sha256, …) — that is milpa's identity, computed by the registry in every
  impl; smuggling an `expected_hash` would be a trust bypass. Fields recording the
  *transport artifact's* own identifier are **permitted and expected** — a git
  commit SHA identifies a git object, an OCI layer digest the compressed blob, a
  resolved local path the source — none is the source-tree hash milpa keys on. State
  this exact permitted/forbidden boundary so a porter writing `GitReceipt {
  commit_sha }` knows it is allowed and *why*.
- **Receipt must be non-empty/identifying — enforced structurally, not by prose.**
  `ProvenanceReceipt` is the *abstract base* (no fields by design — calling a bare
  instance "malformed" is the wrong framing; it is simply not instantiable). Make it
  an ABC with `@abstractmethod transport_fields() -> dict[str, str]`, forcing every
  concrete receipt to declare ≥1 transport-pinning field and giving the registry a
  hook to validate non-emptiness **at admission time** (not later at lockfile-write,
  when a useless provenance record is already baked in).
- **`cas_admissible` is part of the contract** — a `Provenance` kind MUST declare
  whether its materialized bytes are CAS-admissible. **Editable sources (local,
  workspace member) are NOT admissible** (admission would silently freeze user
  edits); immutable sources (git ref, tarball) are. The registry reads this before
  `admit()`. As load-bearing as the identity-forbidden obligation, and equally a
  cross-impl divergence risk if unstated.
- **Cancellation/timeout** — explicitly **not guaranteed** into the plugin for
  v1; plugins are not required to handle cancellation. Stated so the Rust impl
  doesn't invent propagation semantics.
- **Credentials/auth** — explicitly **deferred** (per `rfc-pluggable-fetchers.md`)
  and flagged as a known spec hole, so no impl invents a credential convention.

This contract is the **fetcher protocol** spec section (§5). It goes in
`spec/plugin-contract.md` and covers the *protocol obligations only*. The
**enumeration of valid provenance shapes** (the closed grammar, P3) lives in
`manifest-grammar.md` (§1), not here — one question ("what shapes may `milpa.kdl`
declare?") must have one home.

### P3 — Provenance descriptors: closed meta-grammar, open kind-set
The earlier framing posed a trade — "plugin power vs. cross-impl portability" —
and asked which to sacrifice. **That trade is false.** It dissolves once milpa's
own identity⊥provenance non-negotiable is taken seriously at the extensibility
layer: **content-addressed identity decouples transport from meaning**, so
portability and pluggability can live in *different layers* that cannot
compromise each other. The spec defines all three layers; the gate implements a
subset (below).

**Layer 1 — Declaration surface. Self-describing, content-anchored descriptors;
closed *meta-grammar*, open *kind-set*.** A provenance descriptor in `milpa.kdl`
is structurally uniform: `<kind> { …kind-specific fields }`, paired (via index /
lockfile) with a content-address commitment. The *meta-grammar* (a provenance
node is a kind-discriminant + typed children) is closed and spec-frozen; the *set
of kinds* is an enumeration **owned by the spec-version** (git, local, tarball,
oci today). This yields three properties that replace the old "closed-vs-open"
dichotomy:
- **Parse-always** — any impl parses *any* descriptor regardless of whether it
  knows the `kind`. Portability is **structural**, not version-negotiated: an old
  Rust milpa can read a manifest naming a newer transport without choking.
- **Verify-always (of a *materialized* tree)** — `content_hash(tree)` is
  computable without knowing the transport, so an impl can verify a **previously-
  materialized** dep (a CAS hit, or an existing `_deps/<name>/` tree, or a lockfile
  entry against such a tree) for a dep it **cannot itself fetch** — because identity
  ⊥ transport. (Lockfile/CAS forward-compat falls out for free.) The precise claim
  is *not* "verify before fetch": an unknown-`kind` dep that is not yet materialized
  cannot be verified (there is no tree to hash) — and cannot be fetched either
  (fetch-fails-precisely). The three properties compose to: **an old impl reading a
  new-format lockfile verifies every already-fetched dep and reports precisely which
  ones it cannot re-fetch** — never a silent drop.
- **Fetch-fails-precisely** — only a *cache-miss* on an unknown `kind` fails,
  with an exact diagnostic ("dep X requires transport `kind`, unsupported by this
  impl/spec-version N; install a plugin or upgrade"). Unknown-transport is a
  **capability gap, not a comprehension gap** — never a silent drop (silently
  ignoring a fetch source would resolve a different graph — a security hole).

Prior art this is modeled on (so it provably works): OCI descriptors
(`mediaType`+`digest` — understand & verify without handling the transport),
multiformats/multicodec, Nix content-addressed derivations, Cargo
source-replacement + checksums. Nothing executable enters the manifest — Layer 1
stays pure data ([[reference_milpa]] declarative non-negotiable holds).

**Layer 2 — Backend binding. Fully pluggable, explicitly overridable, safe by
construction.** *Which code* materializes a given `kind` is free to vary, because
the output is verified by content-hash, which is transport-independent: a libgit2
backend and a subprocess-git backend for `git` produce byte-identical trees →
identical hash → **indistinguishable to the resolver**. So backend override is
not a footgun to forbid — it is *safe by the content-addressing model*, provided
it is **explicit and total**: exactly-one-backend-per-`kind`, enforced by the
exclusive-dispatch ambiguity-error (P1). A hostile backend cannot forge identity
(recomputed from delivered bytes, checked against index/lockfile); the trust
boundary is the content-hash, not the transport. The implicit footgun was only
ever *silent* override (a registration race) — which exclusive dispatch already
rejects.
**Scope of the byte-identical claim (precise).** Two backends produce identical
trees only for an **immutable ref** (commit SHA, tag, content hash). For a
**mutable ref** (`ref=main`) two backends (or one backend at two times) may clone
different commits → different trees → different hashes. This is **not** a hole in
the safety argument: for a **locked** dep the identity is pinned, so a backend that
delivers the wrong commit *fails the identity check* (`fetch_any` +
content-hash verification) rather than silently substituting. State Layer 2's
override-safety as scoped: **byte-equivalence across backends holds for pinned
identities; for unfrozen resolution of a mutable ref, backends may diverge and the
identity check detects it.** (This is why mutable-ref resolution is not part of the
frozen fast-path — it is inherently non-reproducible until pinned.)

**Layer 3 — Capability declaration + discovery.** A plugin announces, via the
P1 entry point, either "I bind backend B to existing `kind`" (Layer 2, lands
now) or "I provide `kind`′, requiring spec-version N" (Layer 1, lands when the
spec amendment does). The descriptor is designed **extensible to carry capability
/ effect metadata** later ([[reference_three_package_architecture]];
`rfc-effect-typed-deps.md`) — a v1 *hook in the structure*, not a v1 mandate.

**Gate split (per "full spec, staged implementation").** The gate **specs all
three layers** (descriptor meta-grammar + kind registry + the three properties;
the backend-binding contract + its content-addressing safety argument; the
capability/discovery protocol). The gate **implements** discovery (P1) + the
existing built-in kinds. Deferred as filed, non-breaking follow-ups: a concrete
*new* transport kind (needs a spec amendment by definition) and the
backend-*override* configuration surface. The Rust port then ports a *complete,
proven* extensibility contract — not a hook with a TODO.

## Exit criteria — the gate condition

The Rust-port RFC may open when **all** hold:
1. G1–G5 complete per their done-criteria.
2. Full Python suite green (unit + property + gated integration).
3. `spec/` covers the canonical sections — errors, manifest-grammar
   (+`.nimble` compat, **conditional-dep/`when` syntax + platform/arch tables**,
   spec-version field, forward-unknown policy), lockfile-schema (+**version
   negotiation**, **tarball TOFU**), **identity** (+CAS layout, **append-only
   policy**), resolver-semantics (engine-agnostic: completeness + **canonical-
   solution selection** + checkable certificate; **`--frozen`** + **prior-lockfile
   pin** behaviors), **nim.cfg emission**, **registry-protocol** (tianguis read,
   **subset of manifest grammar**), **cli-contract** (`publish` out-of-scope),
   plugin-contract (**`FetcherConfig`**, `cas_admissible`) — each reviewed,
   normative/incidental marked **per the prescribed convention**, and **declaring a
   single spec-version** (this gate produces spec **v1.0**; the Python impl declares
   conformance to it).
4. `conformance/spec-v1/` dir-tree fixtures pass via the Python adapter,
   meet the **≥1-fixture-per-MUST-clause coverage floor**, and are documented as the
   cross-impl arbiter with the fixture-lifecycle/versioning rule.

When these hold, the spec is frozen enough that the Rust port is a
*transcription against a conformance suite*, not a redesign.

## Sequencing

1. **G1 (#92)** — mechanical, unblocks freezing error identities; do first so
   spec extraction can reference complete categories.
2. **G2 (#109)** — removes the resolution divergence before it has to be spec'd.
3. **G3 + G4** — spec extraction and conformance fixtures together (G4's
   fixtures are the executable form of G3's normative claims; the diamond
   fixture pairs with `resolver-semantics.md`). Depends on G1 (codes) + G2
   (one resolution model). **Intra-phase ordering (round-2):** S8b (fixture
   promotion) depends on **S5** (nim.cfg), **S12** (identity/CAS →
   `_deps_structure.txt`), **and S14** (index input format); **S9** (diamond
   fixture) depends on **S1** (migrated workspace path). Settle those doc slices
   before the dependent code slices.
4. **G5** — plugin contract + discovery. The P3 descriptor model (Layer 1: meta-
   grammar + kind registry) lives in `manifest-grammar.md` (S4), so S10
   (`plugin-contract.md`, the Layer 2 backend contract) finalizes after S4 is set;
   S11 (Layer 3 discovery) depends only on S4 being settled. P3 is resolved (the
   three-layer descriptor model), so S10/S11 implement it directly — no fork
   remains; the deferred pieces (a new kind, override-config) are filed issues.

## Slices

Marked **[code]** (drives a `/tdd` RED→GREEN slice) or **[doc]** (design
deliverable, reviewed not test-driven). Doc slices still pass through the
architect rounds; they just don't have a failing test as their contract.

- **S1 [code]** G2/#109 — migrate `resolve_workspace()` named-dep path onto
  `_enumerate_named`. **Real fix (round-2, verified): wire
  `provider.start_solve(_on_new_named, _on_new_url)`** in the workspace path with
  closures over workspace-local `seen_named`/`seen_url` (no pre-solve drain — that
  framing was wrong; `_on_new_url` runs synchronously, no executor); call
  `_enumerate_named` with a **`None` constraint** to avoid arrival-order
  pre-filtering. **RED test:** workspace diamond — member A `foo>=0.3.0`, member B
  `foo>=0.5.0`, index has both → assert resolved version `== 0.5.0 ==` the
  `resolve()` result for the equivalent merged manifest (version-selection *parity*,
  not just conflict detection). Retire `_process_named` (sole caller
  `resolver.py:931`, verified) + `resolve_named` (called only from `_process_named`).
- **S2 [code]** G1/#92 — error-catalog pre-work: add `.code` to `LockfileError`/
  `ResolverError`/`SolverError`/… and a **shared scan helper** (`_code_slugs_in_
  source(prefix)` in `test_error_catalog.py` — *not* a runtime base-class hierarchy;
  the existing `__init__` signatures differ) **then** the Lockfile + Resolver +
  Solver categories. `SolverError` gets a constant `.code` (`SOLVE-CONFLICT`);
  reclassify the `solver.py:439/451` `ValueError` to `ManifestError` **at the
  `_build_terms` callsite** (`resolver.py:1731`), per the decidable user-facing
  criterion in G1. ~70 raise-site touches; tests gain `.code` assertions but do not
  break (message strings unchanged).
- **S3 [code]** G1/#92 — error catalog: Fetch + CAS + Identity + NimbleParse +
  NotFrozen + Workspace + Extraction (`safe_extract`) + manifest_writer +
  tarball categories. **Bidirectional slug-freeze validator** — add
  `check_no_orphan_slugs(prefix, tombstoned=…)`: RED test registers a probe slug,
  deletes its raise from source, validator fails (deletion direction) **and** a
  slug present in code but absent from `errors.md` fails (addition direction).
- **S4 [doc]** G3 §1+§5-shapes — `spec/manifest-grammar.md` (KDL grammar,
  `(url)` convention, P3 **provenance-descriptor model**: closed meta-grammar +
  spec-version-owned kind registry + parse/verify/fetch properties, spec-version
  field, `.nimble`-compat parsing section, **conditional-dep / `when`-block syntax**
  (4 keys, OR semantics, negation annotation, mixed-negation parse error) +
  **canonical platform/arch vocabulary tables**, **tarball `strip_components`**
  (stripping precedes content-hash)).
- **S5 [doc]** G3 §2 — `spec/lockfile-schema.md` (+ `nim.cfg` emission spec:
  `--path:` form, POSIX separators, ordering, `<dep>_<flag>` rule, workspace
  relative paths — or split to `nim-cfg.md`; **lockfile version-negotiation policy**
  (hard-reject unknown version) + the `LOCKFILE_SCHEMA_VERSION`↔spec-version mapping;
  **tarball TOFU first-use pinning**).
- **S6 [doc]** G3 §4 — `spec/resolver-semantics.md` — **engine-agnostic
  observable semantics** (PubGrub = reference producer, not normative):
  completeness; constraint accumulation; URL/local/member identity-constraint
  convention; **the canonical-solution selection function** (lexicographically-
  maximal complete solution under spec-defined package order + `Strategy`
  version-pick — moors to the *solution*, not the engine; NOT "deterministic order
  as a total function of partial state", which round-2 disproved); **checkable
  result certificate** (success witness `{resolved, witness}`; **weak UNSAT-core**
  failure refutation — "named set is genuinely unsatisfiable", not the derivation
  DAG; human text incidental); certificate *schema + validity predicate* normative,
  full poly-time verifier deferred to `rfc-beyond-pubgrub.md` D1; **`--frozen`
  resolution** (no-network + solver-bypass) and **prior-lockfile pin reuse** as
  named normative behaviors; conditional-dep evaluation is **pre-solver** input
  filtering (`_filter_manifest_by_profile`, normative); note Python backjumping as
  tracked-incidental. **Mechanical done-check:** two independent in-Python
  implementations of the selection rule produce byte-identical lockfiles on the
  diamond fixture. *(Exact canonical-order procedure revisited at spec-writing, per
  Corey.)*
- **S7 [doc]** G3 §7 — extend `spec/errors.md` to the categories added in
  S2/S3 (normative/incidental marked; bijection lint extended).
- **S8a [doc]** G4 — adopt + document the dir-tree fixture format from
  `rfc-multi-impl-strategy.md`, **correcting `registry.json`→`index.kdl`** (raw KDL
  the `parse_index` path consumes; post-#97) and adding the **spec-version/fixture-
  lifecycle** layout (`conformance/spec-v<N>/`, old versions retained). The
  `expected/` outputs depend on **S5** (nim.cfg) + **S12** (identity/CAS symlink
  format for `_deps_structure.txt`) being settled.
- **S8b [code]** G4/#72 — Python adapter + promote existing trigger tables into
  `conformance/spec-v1/` dir-tree fixtures. **Depends on S8a (format), S5
  (nim.cfg), S12 (CAS/`_deps_structure.txt`), and S14 (index input format).**
- **S9 [code]** G4 — diamond-conflict fixture (pairs with S6). **Depends on S1** —
  the fixture's correctness needs the migrated workspace named-dep path (else the
  second member's constraint is dropped and the conflict won't surface).
- **S10 [doc]** G3 §5 — `spec/plugin-contract.md` (P2 Layer-2 backend
  obligations: claim/materialize/receipt + failure / identity-forbidden-as-field-
  level-line / non-empty-receipt-via-ABC / `cas_admissible` / cancellation / auth;
  the explicit-total-binding + content-addressing override-safety argument **scoped
  to pinned identities**; exclusivity stated without `isinstance`; the `FetcherConfig`
  normative definition). Descriptor model (Layer 1) lives in S4. **Pre-step:** fix
  the stale `FetcherRegistry`/`__init__.py` "first-match-wins" docstrings before
  transcription.
- **S11 [code]** G5/P1 — **step 0: create the `FetcherConfig` dataclass** (empty +
  `mirror_urls` hook) and make `ProvenanceReceipt` an ABC with
  `transport_fields()`; **then** `milpa.fetchers` entry-point discovery (Layer 3) in
  `default_registry` (one-arg `FetcherConfig` factory); exclusive-dispatch
  preserved; reference plugin as a dev-dep fixture package (`tests/fixtures/
  milpa_fetcher_<x>/` with its own `pyproject.toml`) loads through the real
  `importlib.metadata` path (Python unit suite, not conformance).
- **S12 [doc]** G3 §3 — `spec/identity.md` (content-hash canonical byte
  stream, sort, mode/symlink/`.git` rules, raw-bytes/no-EOL-normalization,
  multihash; CAS layout + atomic admission + `_deps/` symlink convention;
  **CAS-append-only / no-silent-eviction** normative statement).
- **S13** — *(reserved; folded — nim.cfg into S5, nimble-compat into S4)*.
- **S14 [doc]** G3 — `spec/registry-protocol.md` (tianguis `index.kdl` read
  format: schema + version negotiation + per-version provenance record + TNG
  validators). **Normative cross-ref: index provenance records are a strict subset
  of the manifest descriptor grammar (S4/P3)** — not a second grammar. Read
  contract only; **not** index-deps policy. **Settle before S8b** (fixtures embed
  index input).
- **S15 [doc]** G3 §6 — `spec/cli-contract.md` (conformance-tested verbs:
  fetch/lock/show/verify/clean/add/remove/update; flags, exit-code semantics,
  stderr/stdout, env vars incl. `MILPA_TARGET_PLATFORM`/`_ARCH`/`_NIM`; `--frozen`
  flag/exit semantics — the no-network + solver-bypass *guarantees* live in S6).
  **`publish` explicitly out-of-scope for spec v1.0 conformance** (external-service
  dependent, not dir-tree testable; reserved for an amendment).

## Open questions

No goal-determined fork remains. Both items round 1 surfaced as "forks" had
answers forced by the PhD bar + milpa's non-negotiables once spec was separated
from implementation:

### Resolved (folded into the RFC)
- ~~**F1 — plugin power / closed-grammar trade**~~ → **dissolved.** The
  power-vs-portability trade was false; P3's three-layer **provenance-descriptor
  model** (closed meta-grammar + open kind-set; parse-always / verify-always /
  fetch-fails-precisely; content-addressing makes backend override safe) puts
  portability and pluggability in non-interfering layers. Gate specs all three,
  implements discovery + built-in kinds; a new kind and override-config are filed
  follow-ups. *Issues to file during planning ([[feedback_defer_file_now]]):* (i)
  spec-amendment mechanism for a new provenance kind; (ii) backend-override
  configuration surface; (iii) capability/effect metadata on descriptors
  (`rfc-effect-typed-deps.md`).
- ~~**F2 — resolution completeness**~~ → **engine-agnostic observable semantics**,
  **corrected in round 2**: (1) completeness; (2) a **canonical-solution selection
  function** (lexicographically-maximal complete solution under a spec-defined
  package order + `Strategy`) — round 1's "deterministic order as a total function
  of partial state" was *disproved* (two complete engines diverge on a diamond); the
  fix moors impls to the **canonical solution**, not the engine; (3) a **checkable
  certificate** (success witness + **weak UNSAT-core** failure refutation, *not*
  PubGrub's derivation DAG). PubGrub is the *reference producer*. v1 freezes the
  certificate *schema + validity predicate*; the independent poly-time verifier is
  the D1 follow-up. Python backjumping gap = tracked incidental + fix-issue. (Per
  Corey: exact canonical-order procedure revisited at spec-writing; S6 carries a
  two-impl byte-identity done-check.)
- ~~Conformance fixture encoding~~ → dir-tree format from
  `rfc-multi-impl-strategy.md` (G4 / S8a), not bespoke JSON.
- ~~Lockfile version field~~ → **yes**, plus a spec-version across all docs
  (exit criterion 3).

### Research hooks deliberately left open (designed-for, not v1-mandated)
- **Independent poly-time certificate verifier** (`rfc-beyond-pubgrub.md` D1) —
  v1 freezes the certificate *format*; the trust-nothing checker lands later.
- **Capability-aware resolution** (`rfc-beyond-pubgrub.md` D2 /
  `rfc-effect-typed-deps.md`) — descriptors carry an effect signature the resolver
  reasons about; milpa's flagged *novel* contribution.
- **Refinement-typed versions** (`rfc-beyond-pubgrub.md` D3) — SMT over typed
  constraints; far from production.
All must be *non-breaking* extensions of frozen v1; the descriptor model, the
certificate format, and the engine-agnostic mooring are structured so each can
land without a format break. (NB: the *certificate itself* is now v1-normative —
only the trust-nothing verifier is deferred.)

### Non-goal-determining (author's discretion)
- **Spec doc granularity** — one `resolver-semantics.md` vs split
  (selection / backtracking / conflict-narration). Default: one doc unless it
  exceeds readability. Left to S6's author.
