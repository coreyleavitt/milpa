# milpa resolver semantics (S6)

Normative spec of milpa's dependency-resolution algorithm. Every
rule marked `> NORMATIVE:` defines a requirement any conformant
implementation MUST satisfy. Items marked `> NOTE:` describe the
reference Python implementation; conformant alternatives MAY differ
in those details.

This document covers **algorithm semantics** only. Related specs:

- `docs/spec/manifest-grammar.md` (S4) — dep syntax, conditional-dep
  predicate syntax (§6), provenance-descriptor grammar
- `docs/spec/lockfile-schema.md` (S5) — lockfile representation of a
  resolved graph; nim.cfg emission
- `docs/spec/errors.md` — every error code this document references
- `docs/spec/identity.md` (S12) — content-hash algorithm and CAS layout
- `docs/spec/cli-contract.md` (S15) — `--frozen` flag / exit-code
  semantics; `MILPA_TARGET_*` env-var overrides

---

## Normative surface

A conformant implementation of this spec MUST:

1. Find a solution whenever one exists (completeness).
2. Accumulate all consumers' constraints on every named dep before
   selecting a version; never use eager / first-constraint-wins selection.
3. Treat URL, local, and workspace-member deps as version-unique by
   identity: present each to the solver as a package with exactly one
   canonical version.
4. Select the **canonical solution** — the lexicographically-maximal
   complete solution under the spec-defined package order P (BFS from
   root; declaration order within each manifest; first-occurrence dedup —
   see §4.2.1) with per-package version chosen by `Strategy` (default
   `maxver`) — producing byte-identical lockfiles for the same manifest
   and strategy.
5. On success, emit a **result certificate** whose `resolved` and
   `witness` fields satisfy the validity predicate in §5.
6. On failure, emit a **failure refutation** — a set of named
   incompatibilities that is itself genuinely unsatisfiable — and include
   a human-readable conflict description.
7. Evaluate conditional-dep predicates **before** passing any dep to the
   solver; deps whose predicates do not match the active profile MUST NOT
   enter the candidate set or resolution.
8. Under `--frozen`: perform no network access, rebuild `ResolvedGraph`
   from the lockfile record alone without re-running the solver, and raise
   `FROZEN-*` on any precondition failure (see §7.1 for the complete list
   of 10 precondition codes).
9. When a `prior_lockfile` is supplied, reuse its recorded identity for
   a dep whose manifest key (URL + ref, or tarball URL) is unchanged;
   never re-fetch when the pin matches.
10. Resolve `dev-deps` for the root package and workspace members (§9);
    silently ignore a transitive dep's `dev-deps`. A transitive dep's
    dev-deps MUST NOT enter the graph.
11. Emit all ordering-sensitive outputs (lockfile dep entries, `requires`
    argument lists, nim.cfg `--path:` lines) in **lexicographic order by
    dep name** (§4.4). The resolved graph, lockfile, and nim.cfg MUST be
    identical regardless of the `-j` parallelism level.
12. For workspace resolutions, union all members' dep sets into one solve,
    accumulate cross-member named constraints, and produce a lockfile
    equivalent to what a single-package manifest declaring the same total
    dep set would produce (§11).

---

## 1  Completeness

> NORMATIVE: A conformant resolver MUST find a solution whenever one
> exists in the candidate space. If no solution exists, it MUST produce
> a failure refutation (§5.2). An incomplete solver that returns "no
> solution" when a solution in fact exists is non-conformant.

This requirement is engine-agnostic. It does not specify PubGrub,
SAT, DPLL, or any other algorithm — any complete solver satisfies it.

> NOTE: The reference implementation (`solver.py`) uses PubGrub with
> unit propagation and single-level backtracking. Full backjumping
> (conflict-driven incompatibility learning, `solver.py:28`) is omitted
> from the reference Python implementation as a tracked-incidental gap
> (§12). This does not affect completeness on typical Nim dep graphs;
> it affects performance on pathological cases. PubGrub is the
> **reference producer** of solutions, not a normative requirement.

---

## 2  Constraint accumulation

> NORMATIVE: Every consumer of a named dep contributes a constraint. A
> conformant resolver MUST intersect all consumers' constraints on a
> given named package before selecting a version. The intersection is
> the effective version set; a version is eligible only if it falls
> within the intersection. If the intersection is empty, the resolver
> MUST produce a failure refutation (§5.2) naming every contributing
> consumer.

> NORMATIVE: The resolver MUST NOT use eager / first-constraint-wins
> selection, where the version is chosen from a single consumer's
> constraint and later consumers' constraints are ignored or checked
> post-facto. The intersection must be computed before any version
> is selected.

**Why this matters.** Consider two manifest deps `A >=1.0.0` and
`B >=2.0.0`, where `A@1.0.0` requires `shared >=1.0.0` and `B@2.0.0`
requires `shared <1.0.0`. The conflict is between both consumers of
`shared`. An eager resolver that satisfied `A`'s constraint first and
then checked `B`'s would silently select a wrong version or produce a
misleading error naming only one consumer. A conformant resolver names
both.

> NOTE: The reference implementation satisfies this via PubGrub's
> unit-propagation loop: every declared requires clause becomes an
> `Incompatibility` term, and the propagation accumulates all positive
> constraints on a package in `PartialSolution.effective_set` before
> any decision is made. `VersionSet.intersect` is the single source of
> truth for constraint intersection (`solver.py`).

---

## 3  Identity-constraint convention for non-indexed deps

URL deps, local deps, and workspace-member deps are resolved by
**identity** (content hash) rather than version-range negotiation.
They do not appear in a named registry; only one concrete tree exists
for each such dep in a given resolution.

> NORMATIVE: A conformant resolver MUST present each URL dep, local dep,
> and workspace-member dep to the solver as a package with exactly one
> canonical version — a fixed, non-range singleton. The solver treats
> these deps as decided by identity; it MUST NOT attempt to backtrack
> across different versions of a URL/local/member dep.

> NORMATIVE: The solver MUST emit a constraint of the form
> `require(<name>, {canonical_version})` for every URL, local, and
> member dep. The exact value of `canonical_version` is an
> implementation detail; what is normative is that (a) there is
> exactly one such version per dep, (b) it is the same value whether
> the dep appears as a direct manifest dep or as a transitive require,
> and (c) the identity check (content-hash verification) is performed
> **outside** the solver, by the fetcher layer, before the candidate is
> handed to the solver.

This convention is what makes `fetch_any` + content-hash verification
compose correctly with backtracking: the solver never needs to
distinguish "which URL version" — identity is settled before the solver
runs.

> NOTE: The reference implementation uses the sentinel
> `_URL_DEP_VERSION = Version(0, 0, 1)` as the canonical version for
> all URL/local/member deps (`resolver.py`). The exact sentinel value
> is an incidental implementation choice; a Rust port may use any
> fixed singleton value, including an opaque discriminant. What is
> normative is the one-version-per-dep shape, not `(0,0,1)`.

---

## 4  Canonical-solution selection function

This section is the core normative commitment of the resolver spec. It
answers: **which** of the (possibly many) complete solutions is THE
solution that produces the lockfile?

### 4.1  The problem: tie-break alone is insufficient

A version-selection rule ("prefer the highest version satisfying each
constraint") is not sufficient to force byte-identical lockfiles across
independent implementations. Different complete solvers may explore
the solution space in different orders and return genuinely different
complete assignments.

**Counter-example (diamond dependency).**

```
A → { B >=1.0.0, C >=1.0.0 }
B@2.0.0 → D >=2.0.0
C@1.0.0 → D >=1.0.0
D ∈ {1.0.0, 2.0.0}
```

Two complete solutions exist:

- S₁ = `{A, B@2.0.0, C@1.0.0, D@2.0.0}` (B forces D to 2.0.0)
- S₂ = `{A, B@1.0.0, C@1.0.0, D@1.0.0}` (B@1.0.0 removes the D>=2 constraint)

Both are complete; neither violates any declared constraint. A
PubGrub-style propagation naturally reaches S₁ (it propagates B's
constraint on D before deciding B's version). A DPLL/CDCL engine with a
different variable-ordering heuristic may reach S₂. Applying "MaxVer"
locally to each decision does not help: within its chosen assignment
each engine is already maximizing.

The lockfile must be identical across implementations. The spec
therefore defines **which** satisfying assignment is canonical — not
merely how to tie-break individual package picks.

### 4.2  The canonical solution (NORMATIVE)

> NORMATIVE: The canonical solution is the **lexicographically-maximal
> complete solution** under the following total order and selection rule:
>
> 1. **Package order** — packages are ordered by a canonical BFS
>    traversal from the root manifest, with declaration order within each
>    manifest used to break ties among deps discovered at the same BFS
>    depth. This defines a total order over the package set.
>
> 2. **Per-package version selection** — for each package in that order,
>    the chosen version is the maximum version satisfying the accumulated
>    constraint under the active `Strategy` (see §4.3), subject to
>    backtracking: if a chosen version for an earlier package forces a
>    later package's accumulated constraint to be unsatisfiable, the
>    resolver MUST backtrack to the latest decision point that can be
>    revised and re-select.
>
> 3. **Lexicographic maximality** — the resulting assignment is
>    lexicographically maximal in the package order defined above: no
>    other complete assignment has a higher version for any package
>    (given the earlier packages' choices in the ordering).
>
> A conformant implementation MUST produce byte-identical lockfile output
> for the same manifest, strategy, and candidate set as any other
> conformant implementation.

#### 4.2.1  Package order P — exact canonical BFS procedure (NORMATIVE)

> NORMATIVE: The package order P is produced by the following procedure:
>
> 1. **Roots:** collect the direct deps of the root manifest in the
>    order they are declared in the `deps` block of `milpa.kdl`.  These
>    are the BFS seed at depth 1.
>
> 2. **BFS expansion:** for each package at depth d (processed left-to-
>    right in their declaration order within the manifest that introduced
>    them), collect that package's own declared deps (transitive deps from
>    its `.nimble` `requires` clauses, in the order they appear in the
>    `.nimble` file).  Those deps form the BFS frontier at depth d+1.
>
> 3. **First-occurrence dedup:** a package keeps the position it was
>    FIRST assigned in P.  If a package appears as a dep of multiple
>    parents, all occurrences after the first are ignored for ordering
>    purposes.  Every package in the reachable closure thus has exactly
>    one position in P.
>
> 4. **Result:** the total order P is the BFS visit sequence — root
>    deps first (left-to-right), then their transitives (parent-
>    declaration order, first-occurrence dedup), and so on.
>
> A conformant implementation MUST produce the same P for the same
> manifest, index, and strategy.  The solved package order determines
> which of the (possibly many) complete solutions is canonical.

**Worked example — declaration order decides the canonical solution.**

Consider the scenario from the conformance fixture
`fixture-063-canonical-selection`:

```
milpa.kdl  deps { X; Y }          ← X declared first, Y second
index:
  X@2.0.0  requires Z <= 1.0.0
  X@1.0.0  requires Z (any)
  Y@2.0.0  requires Z >= 2.0.0
  Y@1.0.0  requires Z (any)
  Z@1.0.0, Z@2.0.0  (no requires)
```

Two complete solutions exist:

- S₁ = `{X@2.0.0, Y@1.0.0, Z@1.0.0}` — X forced to 2.0.0 by P;
  Z forced ≤ 1.0.0 by X@2; Y forced to 1.0.0 (only Y version that
  allows Z@1.0.0).
- S₂ = `{X@1.0.0, Y@2.0.0, Z@2.0.0}` — would be canonical if Y were
  declared first.

Package order P (X declared first): `X, Y, Z`.  The canonical solution
is lexicographically maximal under P: maximise X first (→ X@2.0.0),
then maximise Y subject to X@2 being fixed and a complete extension
existing (→ Y@1.0.0, since Y@2 would force Z≥2 which conflicts with
X@2's Z≤1), then Z is forced to 1.0.0.  **Canonical = S₁.**

If Y were declared first, P becomes `Y, X, Z` and the canonical
solution becomes S₂ = `{Y@2.0.0, X@1.0.0, Z@2.0.0}` — confirmed by
the reference implementation.

**Mechanical done-check:** two independent in-Python implementations of
the selection rule MUST produce byte-identical lockfiles on the
`fixture-063-canonical-selection` fixture.

> NOTE: PubGrub's propagation naturally produces the canonical solution
> for most dep graphs because its propagation order biases toward higher
> versions and its variable-selection heuristic follows constraint
> arrival order. PubGrub is the reference producer; it is not the
> normative procedure. The spec moors to **the solution**, not to
> PubGrub's algorithm.

### 4.3  Strategy (version-pick rule)

> NORMATIVE: The `Strategy` parameter governs per-package version
> selection within the accumulated constraint. A conformant
> implementation MUST support at minimum the three strategies below.
> The default MUST be `maxver`.
>
> - `maxver` — choose the highest version in the accumulated constraint's
>   feasible set.
> - `minver` — choose the lowest version in the feasible set.
> - `semver` — choose the highest version within the same major version
>   as the constraint's lower bound; raise `SOLVE-CONFLICT` if no
>   candidate shares that major.
>
> URL, local, and member deps have exactly one version (§3); `Strategy`
> does not affect them.

The `Strategy` is recorded in the lockfile (`strategy` field, S5). The
frozen fast path (§7) checks that the requested strategy matches the
lockfile strategy; a mismatch raises `FROZEN-STRATEGY-MISMATCH`.

The `semver` strategy's **lower bound** is the minimum inclusive lower
bound across all intervals of the accumulated `VersionSet`. If any
interval is unbounded below (lower bound = `None`), the semver strategy
falls back to `maxver` (selects the globally-highest candidate).
Formally: given `VersionSet` intervals `[(lo₁, hi₁), (lo₂, hi₂), …]`,
the target major is `min(lo₁, lo₂, …)[0]` if every `loᵢ` is non-`None`;
otherwise `None` and the fallback applies. If all `loᵢ` are non-`None`
but no candidate shares the target major, `SOLVE-CONFLICT` is raised.

> NOTE: The reference implementation is `_lower_bound_of` / `_pick_semver`
> in `solver.py`. `_lower_bound_of` returns `None` if any interval has
> `lo = None`; otherwise returns `min(iv[0] for iv in vs.intervals)`.
> `_pick_semver` calls `max(candidates)` when `lower_bound is None`, and
> raises `_Conflict` when no candidate shares `lower_bound[0]`.

### 4.4  Canonical emission order (NORMATIVE)

Every ordering-sensitive output MUST be emitted in **lexicographic order
by dep name** (Unicode code-point order on the UTF-8 dep name string):

> NORMATIVE: Lockfile dep entries MUST be sorted lexicographically by dep
> name. The `requires` argument list within each dep entry MUST also be
> sorted lexicographically by name. `nim.cfg` `--path:` lines MUST be
> emitted in lexicographic order by dep name.

Rationale: a single, trivially-reproducible total order that is
independent of any traversal artifact. Topological sort also produces
deterministic output but its sibling tie-break is defined by BFS arrival
order, which varies across parallel-fetch runs and between independent
implementations. Lexicographic order on name strings is a total order
every conformant implementation computes identically. Nim's search-path
order within `nim.cfg` is not semantically load-bearing (deps reside in
disjoint directories), so no correctness property is sacrificed.

> NOTE: The reference implementation enforces this rule in two places:
> `lockfile.py` `from_graph` sorts `LockedDep` records by `d.name` and
> `_locked_from_resolved` sorts `requires` via `tuple(sorted(d.requires))`;
> `nimcfg.py` `format_nimcfg` sorts `graph.deps` by `d.name` before
> emitting `--path:` lines.

> NOTE: **Distinction from package order P (§4.2.1).** P is the BFS-
> derived ordering used by the *solver* to select the canonical complete
> solution (lexicographically-maximal under P). §4.4 governs *emission*
> — how the already-solved result is written to disk. P affects which of
> the (possibly many) satisfying assignments is THE solution; §4.4 affects
> only the serialization of that solution. Both are deterministic; they
> are independent rules. A dep that appears early in P may appear anywhere
> in the lexicographically-sorted lockfile output.

> NORMATIVE: The resolved graph, lockfile, and nim.cfg MUST be identical
> regardless of the `-j` / parallelism level passed to the resolver.
> Parallelism governs fetch throughput only; it MUST NOT affect the
> contents of any output artifact.

---

## 5  Checkable result certificate

The result certificate provides a proof that the chosen solution is
correct (success) or that no solution exists (failure). It is
**engine-agnostic**: a consumer can verify it in `O(n · constraints)`
time without re-running the solver.

> NORMATIVE: A conformant implementation MUST emit a result certificate
> of the shape defined below. The certificate schema and validity
> predicate are frozen at spec v1.0. The certificate accompanies the
> resolved graph in all contexts where correctness verification is
> requested.

### 5.1  Success witness

**Schema:**

```
{
  resolved: [(package: str, version: str), ...],
  witness:  [(package: str, version: str,
              constraint: str, satisfied_by: str), ...]
}
```

**Validity predicate.** A success certificate is valid iff:

1. Every `(package, version)` in `resolved` names a package in the
   candidate set.
2. For every `(package, version, constraint, satisfied_by)` in
   `witness`: the `version` is in the feasible set of `constraint`
   (`VersionSet.from_constraint(constraint).contains(parse_version(version))`
   holds), and `satisfied_by` identifies the consuming package whose
   dep declared this constraint.
3. Every declared constraint across all resolved packages is represented
   by exactly one entry in `witness`.

Verification is `O(n · constraints)` — linear in the total number of
dep declarations across all resolved packages.

### 5.2  Failure refutation (weak UNSAT core)

> NORMATIVE: On failure, a conformant implementation MUST emit a failure
> refutation: a **set of incompatibilities** `{(package, constraint)}`
> that is itself genuinely unsatisfiable. The refutation MUST name every
> contributing incompatibility.
>
> "Names every contributing incompatibility" is defined as: the named
> set is genuinely unsatisfiable — i.e., no version assignment satisfies
> all constraints in the set simultaneously. This is a **checkable
> predicate** on the named set itself. It is NOT defined as "reproduces
> the sequence PubGrub would name."

> NORMATIVE: Human-readable conflict text (e.g., "Because A >=1.0.0
> requires shared >=1.0.0 and B >=2.0.0 requires shared <1.0.0, shared
> has no satisfying version") is INCIDENTAL — it MUST NOT be
> byte-normative. Two conformant implementations may render conflict
> prose differently; neither is wrong. Conformance tests check that
> the named incompatibility set is genuinely unsatisfiable, not that
> prose is identical.

This formulation — a weak UNSAT core, not PubGrub's derivation DAG —
is what keeps `rfc-beyond-pubgrub.md` Direction-1 (independent
poly-time verifier) and Direction-3 (alternative algorithms) open. A
PubGrub derivation graph is **one valid refutation**; a SAT UNSAT core
is another; both satisfy the validity predicate.

**Deferred.** The full independent poly-time verifier ("don't trust the
producer") is `rfc-beyond-pubgrub.md` D1, deferred post-v1.0. It is
non-breaking because the certificate schema is frozen here.

> NOTE: The reference implementation's `SolverError` carries a
> `ConflictChain` (`solver.py`) — an ordered list of `ConflictStep`
> records, each naming the conflicted package and the antecedent Terms
> that forced it. `build_conflict_chain` assembles this from the
> collected `root_cause_conflicts` and the final incompatibility.
> The `ConflictChain` is one valid failure refutation; its structure is
> incidental. `render_conflict_chain` produces the human-readable prose;
> it is not normative.

---

## 6  Conditional-dep evaluation (pre-solver filtering)

Conditional deps — deps annotated with `when` blocks or inline
predicates — are filtered **before** the solver sees any dep. The
syntax of predicates (four keys: `platform`, `arch`, `nim`, `milpa`;
OR semantics for multi-value; negation annotation; mixed-negation parse
error `MAN-PREDICATE-MIXED-NEGATION`) is defined in
`docs/spec/manifest-grammar.md` §6.

> NORMATIVE: Predicate evaluation MUST occur before the solver input is
> constructed. A dep whose predicates do not all match the active
> profile MUST NOT enter the candidate set, MUST NOT be fetched, and
> MUST NOT appear in any solver constraint. The resolver treats the
> profile-filtered manifest as if the non-matching deps were never
> declared.

> NORMATIVE: Evaluation order within a single dep's predicate list is
> conjunction: ALL predicates on a dep must match. Evaluation across
> values within one predicate is disjunction (OR semantics): the
> predicate matches if ANY declared value matches.

> NORMATIVE: For `nim` and `milpa` predicates, a value that looks like
> a constraint expression (starts with a comparison operator: `>=`,
> `<=`, `>`, `<`, `==`, `!=`, `~`, `^`) MUST be evaluated as a version
> constraint against the actual version string, using the same
> `VersionSet` algebra as solver constraints. A plain string value MUST
> be matched by equality.

> NORMATIVE: A `flag` predicate is satisfied iff at least one (or none,
> if negated) of its declared values is in the set of active feature
> flags for the current resolution. Active flags default to the
> manifest's `default=true` flag declarations.

> NOTE: The reference implementation is `_filter_manifest_by_profile`
> in `resolver.py`, called at the start of `resolve()` and per-member
> in `resolve_workspace()`, before BFS or any candidate enumeration.
> Profile predicates are evaluated by `_predicate_satisfied`; version
> predicates go through `_version_satisfies` → `VersionSet.from_constraint`.

---

## 7  `--frozen` resolution

`--frozen` is a resolver behavior, not merely a CLI flag. The normative
guarantees of the frozen path are defined here; flag and exit-code
semantics are in `docs/spec/cli-contract.md` (S15).

> NORMATIVE: Under `--frozen`, a conformant implementation MUST:
>
> (a) **No network access.** No fetcher invocation, no git clone, no
>     HTTP request MAY occur. The frozen path MUST reconstruct the
>     `ResolvedGraph` from the lockfile and the CAS alone.
>
> (b) **Solver bypass.** The frozen path MUST NOT re-run the solver.
>     It rebuilds the `ResolvedGraph` directly from the lockfile's
>     recorded dep entries.
>
> (c) **Hard error on precondition failure.** If any frozen precondition
>     fails (see §7.1), the implementation MUST raise a `FROZEN-*` error
>     and MUST NOT fall through to the slow (full-resolve) path when
>     `--frozen` was explicitly set.

> NOTE: The reference implementation's `_try_frozen` / `_try_workspace_frozen`
> (in `frozen.py`) return a `NotFrozen` reason string on precondition
> failure; the CLI's `_try_frozen` wrapper catches it and returns the
> reason to the caller. When `--frozen` is set, the CLI treats a
> non-`ResolvedGraph` return as a hard error. When `--frozen` is not
> set, the same failure silently falls through to the slow path. The
> frozen path does not call `resolve()` or `solve()`.

### 7.1  Frozen preconditions

This section is the **authoritative source** for the complete list of
conditions that disqualify the `--frozen` fast path. `docs/spec/cli-contract.md`
cross-references this section rather than restating the list.

> NORMATIVE: The frozen path raises exactly the following ten
> `FROZEN-*` codes on precondition failure (non-`FROZEN-*` failures
> silently fall through to the slow path when `--frozen` was not
> explicitly set, or hard-error when it was):
>
> 1. **`FROZEN-STRATEGY-MISMATCH`** — the lockfile's recorded `strategy`
>    field does not equal the requested `Strategy`.
> 2. **`FROZEN-MANIFEST-DEP-NOT-IN-LOCK`** — a dep declared in the
>    manifest has no corresponding lockfile entry.
> 3. **`FROZEN-LOCKED-VERSION-UNPARSEABLE`** — a locked version string
>    cannot be parsed as a valid semver `X.Y.Z`.
> 4. **`FROZEN-CONSTRAINT-UNSATISFIED`** — for a `NamedDep` with a
>    declared constraint, the locked version does not satisfy that
>    constraint.
> 5. **`FROZEN-IDENTITY-NOT-IN-STORE`** — a dep's recorded identity is
>    absent from the CAS.
> 6. **`FROZEN-LEGACY-REGISTRY-PROVENANCE`** — a locked dep carries the
>    legacy `kind "registry"` provenance record (pre-#97 lockfile); run
>    `milpa update <dep>` to re-resolve it through the tianguis index.
> 7. **`FROZEN-LOCAL-DEP`** — a dep carries a local-path provenance;
>    editable trees always re-resolve.
> 8. **`FROZEN-MEMBER-DEP`** — a locked dep carries a workspace-member
>    provenance in a single-package (non-workspace) resolve context.
> 9. **`FROZEN-MEMBER-NOT-IN-WORKSPACE`** — the lockfile references a
>    workspace member that is not present in the current workspace.
> 10. **`FROZEN-MEMBER-IDENTITY-DRIFT`** — a workspace member's on-disk
>     `content_hash` differs from the lockfile's pinned identity.
>
> No other `FROZEN-*` codes exist. The list is closed.

> NORMATIVE: Conditions 1–5 and 6–7 are checked inside
> `resolve_frozen()` (single-package path); conditions 8–10 are checked
> inside `resolve_workspace_frozen()`. Condition 6 (`FROZEN-LEGACY-REGISTRY-PROVENANCE`)
> may be raised from either path via `_source_from_provenance`.

> NORMATIVE: Workspace-member deps are verified by computing their
> on-disk `content_hash` and comparing against the lockfile's pinned
> identity. A mismatch raises `FROZEN-MEMBER-IDENTITY-DRIFT`. The
> frozen path MUST NOT silently accept a member whose bytes have changed.

---

## 8  Prior-lockfile pin reuse

`resolve()` and `resolve_workspace()` accept a `prior_lockfile`
parameter. This is a **named normative behavior** (a stability
guarantee), distinct from `--frozen`.

> NORMATIVE: When a `prior_lockfile` is supplied, a conformant
> implementation MUST reuse the previously-fetched identity for a dep
> whose manifest key is unchanged:
>
> - For a URL dep: the manifest's `(git, ref)` pair matches the
>   lockfile's recorded `GitProvenanceRecord.(url, ref)` → reuse the
>   locked identity as the expected identity for the fetch, rejecting
>   any tree with a different hash (`FETCH-ALL-FAILED` if every
>   candidate mismatches).
> - For a tarball dep: the manifest's `url` matches the lockfile's
>   recorded `TarballProvenanceRecord.url` → reuse the locked identity.
>
> A dep whose manifest key has changed (different git URL, different
> ref, different tarball URL) MUST NOT have its prior identity reused —
> the pin is dropped and the dep is re-fetched freely.

> NORMATIVE: When a prior lockfile pins a git dep whose `(url, ref)`
> still matches the manifest, a conformant implementation MUST fetch
> the **pinned commit** (the `GitProvenanceRecord.commit_sha` from the
> lockfile), not the ref tip. The `ref` field is retained for
> provenance/debuggability, but the working tree MUST be checked out at
> the immutable commit SHA. The pinned identity is then verified against
> that commit's content.
>
> If the lockfile's `commit_sha` is absent (e.g., old lockfile
> pre-dating the field), the implementation MAY fall back to ref-tip
> checkout (legacy behaviour) but MUST still enforce the identity pin.
>
> Rationale: a `ref` is a mutable pointer; fetching the ref tip after
> it has moved yields different bytes, which triggers a spurious
> identity mismatch and a `FETCH-ALL-FAILED` error even though the
> pinned commit is still reachable on the remote. Fetching by the
> immutable commit SHA preserves reproducibility.

> NORMATIVE: Prior-lockfile pin reuse is a **soft preference**, not a
> hard freeze. Unlike `--frozen`, the slow resolve path still runs;
> network access still occurs; the solver still executes. The pin only
> constrains the identity check during fetch — it prevents a silently-
> moved ref from resolving to different bytes across two fetches of the
> same manifest.

This behavior is observable (it changes the lockfile if the ref has
moved upstream) and is the named stability guarantee that makes
repeated `milpa fetch` runs idempotent for unchanged manifests.

> NOTE: The reference implementation's `_git_pin_for_url_dep` extracts
> both the locked identity AND the locked `commit_sha` from the same
> matched `GitProvenanceRecord` in a single lookup (single source of
> truth). `_process_url` uses this tuple to (a) set
> `expected_identity` on `fetch_any` and (b) populate
> `GitProvenance.commit_sha` so `GitFetcher` checks out the immutable
> commit. `_pin_for_tarball_dep` extracts the identity for the tarball
> path. Local deps are excluded from pin reuse because they are not
> CAS-admissible (editable sources; see `docs/spec/plugin-contract.md`
> S10).

---

## 8a  Mirror fallback

For each URL dep, the resolver constructs an **ordered candidate list**
and tries each candidate in turn until one succeeds and passes the
identity gate.

> NORMATIVE: For each URL dep, the candidate list is:
>
> 1. **Primary URL** — the `git=` URL declared in the manifest dep block,
>    with the `ref=` from the same block.
> 2. **Dep-block mirrors** — the `mirror` entries declared inside the
>    dep's block in `milpa.kdl`, in their declaration order.
> 3. **Prior-lockfile self-mirrors** — the `self_mirrors` URLs recorded
>    in the prior lockfile for this dep (in the order they were stored),
>    if a `prior_lockfile` was supplied.
>
> A conformant implementation MUST try candidates in this order. The
> first candidate that succeeds AND whose fetched content passes the
> identity gate (content hash matches `expected_identity` when a pin
> exists, or is freely admitted when no pin exists) MUST be used; no
> further candidates are tried.
>
> A candidate that delivers different bytes from the pinned identity is
> **skipped** (not an error): the implementation tries the next
> candidate. If all candidates fail (network error or identity mismatch),
> `FETCH-ALL-FAILED` is raised.

> NOTE: When a prior-lockfile pin exists, every candidate in the list —
> primary, dep-block mirrors, and prior-lockfile self-mirrors — is passed
> the same `commit_sha` and `expected_identity` from the pin. A mirror
> serving the same immutable content (same commit) will have the same
> identity and passes the gate; a mirror that has diverged fails the gate
> and is skipped.

> NOTE: The reference implementation is `_process_url` in `resolver.py`.
> It builds the `candidates` list in order (primary
> `GitProvenance(url=dep.git, ref=dep.ref, commit_sha=pinned_commit_sha)`,
> then dep-block mirrors via `dep.mirrors`, then prior-lockfile
> self-mirrors via `_prior_self_mirrors_for`), then calls
> `fetcher.fetch_any(dep.name, candidates, …, expected_identity=…)`.
> The identity gate is enforced inside `fetch_any`; `_process_url` does
> not inspect individual candidate outcomes.

---

## 9  dev-deps resolution context

`dev-deps` are dependencies declared in a package's `dev-deps` block
(see `docs/spec/manifest-grammar.md` §3.3). This section defines
their normative resolution semantics.

> NORMATIVE: **Root package** — when a package is the direct target of
> resolution (the root), its `dev-deps` MUST be enrolled as root
> requirements alongside its regular `deps`. They are resolved, locked,
> and appear on the `nim.cfg` path exactly like regular deps. Conditional
> predicates (`when` blocks, inline platform/arch/nim/milpa/flag predicates)
> MUST be applied to `dev-deps` with the same filtering semantics as `deps`
> (cross-reference §6).

> NORMATIVE: **Transitive deps** — when a package appears as a transitive
> dependency (reachable from the root via one or more dep edges), its
> `dev-deps` MUST be silently ignored. They MUST NOT be fetched, MUST NOT
> contribute terms to the solver, and MUST NOT appear in the resolved graph,
> lockfile, or `nim.cfg`. This rule applies at every transitive depth.

> NORMATIVE: **Workspace members** — a workspace member is treated as a
> root for its own resolution closure. A member's `dev-deps` MUST be
> enrolled alongside its `deps` in the workspace resolution graph. The
> transitive-dep rule still applies: any external dep transitively reached
> by a member's `deps` or `dev-deps` has its own `dev-deps` excluded.

> NORMATIVE: The transitive-exclusion rule is enforced at the point where a
> fetched dep's milpa.kdl is read to extract its own requirements. A
> conformant implementation MUST read only `manifest.deps` from a transitive
> dep's milpa.kdl; it MUST NOT read `manifest.dev_deps` from that path.

> NOTE: The reference implementation enforces this rule in
> `_extract_from_milpa_kdl` (`resolver.py`): the function reads only
> `manifest.deps`, never `manifest.dev_deps`. The root path enrolls
> `manifest.dev_deps` by iterating `list(manifest.deps) + list(manifest.dev_deps)`
> at the top of `resolve()`. The workspace member path uses the same pattern
> inside `_terms_from_member_manifest`. The structural guard comment in
> `_extract_from_milpa_kdl` marks the single point where the exclusion is
> enforced.

The conformance fixture `tests/conformance/spec-v1/fixture-064-dev-deps`
verifies this rule: a root dep `a` whose milpa.kdl declares `dev-deps { e ... }`
is correctly excluded from the resolved graph (only `a` and the root's own
dev-dep `d` appear).

---

## 10  Provenance precedence

This section defines which provenance (source) wins when multiple parts of
the dependency graph declare conflicting sources for the same package name.

### 10.1  Root authority

> NORMATIVE: The **root authority set** is the set of all package names
> declared in the root manifest's `deps`, `dev-deps`, and `overrides {}`
> blocks.  For a workspace, every workspace member contributes its `deps`,
> `dev-deps`, and the workspace-level `overrides {}` block to the root
> authority set.  Workspace members themselves are also root-authoritative
> (they are not subject to transitive override).

> NORMATIVE: When a transitive dependency (a dep reachable via fetching
> another dep's milpa.kdl or .nimble) declares a provenance for a package
> name that is already in the root authority set, the transitive provenance
> MUST be silently suppressed — it MUST NOT be fetched and MUST NOT
> affect resolution.  The root manifest's declared provenance (the first
> provenance registered for that name from the root) is the binding
> specification.  This is deterministic and order-independent: root
> authority is declared at parse time, not at BFS arrival time.

This is the Cargo `[patch]`/`[replace]` / npm `overrides` / Go `replace`
model: **only the top-level project being built can redirect a dep's
source**.  An intermediate library cannot hijack another dep's provenance.

### 10.2  Transitive overrides are ignored

> NORMATIVE: A transitive dep's `overrides {}` block MUST be silently
> ignored.  A conformant implementation MUST NOT apply overrides from a
> fetched dep's milpa.kdl to any other dep in the graph.  Only the root
> manifest's `overrides {}` block (and, for workspaces, the workspace-
> level `overrides {}` block) apply.

**Security rationale.** A dependency that can override another
dependency's source is a supply-chain attack vector.  Restricting
override authority to the root eliminates this class of attack: the
project owner controls which sources are authoritative.

> NOTE: The reference implementation enforces this by never reading
> `manifest.overrides` from a fetched transitive dep's milpa.kdl.
> `_extract_from_milpa_kdl` reads only `manifest.deps` (and applies
> `overrides_by_name` from the root's table, not from the fetched file).

### 10.3  Non-root provenance disagreement

When a package name is not in the root authority set but two transitive
deps declare different provenances for it, the resolver must handle the
ambiguity explicitly.

> NORMATIVE: If two transitive deps declare different provenances for
> the same package name and the root manifest has no authority over that
> name, the resolver MUST raise `RES-PROVENANCE-CONFLICT`.  It MUST NOT
> silently pick one provenance over the other.

> NORMATIVE: If two transitive deps declare the **same** provenance
> (same transport kind, same URL/path, same ref) for the same package
> name, they are treated as duplicates — the second occurrence is
> suppressed and resolution proceeds normally.

> NOTE: For URL deps, "same provenance" means the same `(git_url, ref)`
> pair.  Content-hash dedup (§3, Phase B) provides an additional
> unification layer for packages from different URLs that happen to
> produce the same content hash.  The provenance gate fires first (on
> the URL+ref key); content-hash dedup fires after fetch.

### 10.4  Orthogonality with dev-deps

> NORMATIVE: Provenance precedence is orthogonal to dev-dep propagation
> (§9).  Suppressing a transitive provenance claim does NOT affect
> whether dev-deps are included — those are always governed by §9's
> root-only dev-dep rule.

The conformance fixture
`tests/conformance/spec-v1/fixture-065-root-override-precedence`
verifies this rule: the root declares `shared` from `our-fork.example.com`;
a transitive dep (`translib`) declares `shared` from `upstream.example.com`.
The expected output shows `shared` resolved to the root's provenance
(`our-fork.example.com`) and the upstream URL was not fetched.

Cross-reference: `docs/spec/manifest-grammar.md` §3.4 for the `overrides {}`
block syntax.  `docs/spec/errors.md` for `RES-PROVENANCE-CONFLICT`.

---

## 11  Workspace resolution

A workspace is a collection of related packages resolved together into
one shared graph. This section is normative for any implementation that
supports milpa workspace manifests.

### 11.1  Member dep-set union

> NORMATIVE: The workspace resolver MUST union the `deps` and `dev-deps`
> of all workspace members into a single solver problem. Every member is
> a **root** for purposes of dev-dep enrollment (§9): each member's
> `dev-deps` MUST be included in the workspace resolution graph exactly
> as if that member were the root of a single-package resolution.

> NORMATIVE: Cross-member named constraints are accumulated and
> intersected exactly as any other constraint accumulation (§2). When
> two members declare different version constraints on the same named
> dep, the effective constraint is their intersection. If the
> intersection is empty, the resolver MUST produce a failure refutation
> (§5.2) naming both members as contributing consumers.

### 11.2  Multi-root BFS package order

> NORMATIVE: The package order P for a workspace resolution (§4.2.1) is
> seeded from ALL members, not just one. The BFS seed (depth 1) is
> assembled by iterating workspace members in their declaration order in
> the workspace manifest and collecting each member's deps in
> declaration order within that member's manifest. Dedup is
> first-occurrence across all members: if the same dep name appears in
> multiple members, it keeps the position assigned by the first member
> that introduced it.

### 11.3  Workspace lockfile equivalence

> NORMATIVE: The workspace lockfile MUST equal the lockfile that a
> single-package manifest declaring the same total dep set (the union of
> all members' deps and dev-deps) under the same strategy would produce.
> A conformant implementation MUST produce byte-identical workspace
> lockfiles for the same workspace manifest, member manifests, strategy,
> and candidate set, regardless of the number of members or their
> declaration order (within first-occurrence dedup).

This invariant is the primary testable property for workspace
conformance: produce the workspace lockfile, then construct the
equivalent single-package manifest and resolve it; the two lockfiles
MUST be byte-identical.

### 11.4  Shared lockfile

> NORMATIVE: The workspace shares a single lockfile. Every resolved
> package (external dep, member, or member's transitive dep) appears
> exactly once in the lockfile. The lockfile's dep-entry sort order is
> lexicographic by name (§4.4), irrespective of which member introduced
> the dep first.

> NORMATIVE: Per-member `nim.cfg` files are emitted using only the
> closure of deps reachable from that member's own `deps` and `dev-deps`
> (cross-reference `docs/spec/lockfile-schema.md` §7.6). The shared
> lockfile does not imply all deps appear in every member's `nim.cfg`.

### 11.5  Member self-registration

> NORMATIVE: Each workspace member MUST be pre-registered as a candidate
> in the solver with version `_URL_DEP_VERSION` (the same sentinel used
> for URL deps — §3). The member's on-disk `content_hash` is computed
> at the time of registration (no fetch). Named deps whose name matches
> a workspace member name auto-coerce to member resolution: they are
> treated as requiring the already-registered member candidate rather
> than being looked up in the tianguis index.

> NOTE: The reference implementation is `resolve_workspace` in
> `resolver.py`. Members are iterated in `workspace.members` order;
> each member's `_terms_from_member_manifest` produces solver `Term`s
> and a queue of external deps. The root candidate `__root__` collects
> a `Term.require` for every member. `start_solve` wires up callbacks
> for transitives discovered during solve. The solver is called once
> over the combined provider; `_build_graph` assembles the
> `ResolvedGraph`.

---

## 12  Python backjumping gap (tracked-incidental)

> NOTE: The reference Python implementation omits conflict-driven
> incompatibility learning and multi-level backjumping (tracked at
> `solver.py:28`, GitHub issue #28). The solver always backtracks one
> decision level. This does not affect correctness (all solutions are
> still found; all genuine unsatisfiability is detected) and does not
> affect the canonical-solution invariant (§4.2). It affects
> performance on pathological dep graphs with deep conflict chains.
> A conformant alternative implementation MAY implement full
> backjumping. This gap is NOT gate-blocking for spec v1.0. It is
> tracked as a fix-issue for the Python reference implementation.

---

## Appendix A  Error codes referenced by this document

All codes are defined in `docs/spec/errors.md`.

| Code | Condition |
|---|---|
| `SOLVE-CONFLICT` | No solution exists; failure refutation emitted |
| `FROZEN-STRATEGY-MISMATCH` | `--frozen` lockfile strategy ≠ requested strategy (§7.1 #1) |
| `FROZEN-MANIFEST-DEP-NOT-IN-LOCK` | Manifest dep has no lockfile entry (§7.1 #2) |
| `FROZEN-LOCKED-VERSION-UNPARSEABLE` | Locked version string is not a valid semver (§7.1 #3) |
| `FROZEN-CONSTRAINT-UNSATISFIED` | Locked version no longer satisfies named dep constraint (§7.1 #4) |
| `FROZEN-IDENTITY-NOT-IN-STORE` | Dep identity absent from CAS (§7.1 #5) |
| `FROZEN-LEGACY-REGISTRY-PROVENANCE` | Locked dep uses pre-#97 registry provenance; re-resolve via tianguis (§7.1 #6) |
| `FROZEN-LOCAL-DEP` | Editable local dep cannot use frozen path (§7.1 #7) |
| `FROZEN-MEMBER-DEP` | Workspace member dep cannot use frozen path in single-package context (§7.1 #8) |
| `FROZEN-MEMBER-NOT-IN-WORKSPACE` | Lockfile references member not present in workspace (§7.1 #9) |
| `FROZEN-MEMBER-IDENTITY-DRIFT` | Member on-disk hash differs from lockfile pin (§7.1 #10) |
| `FETCH-ALL-FAILED` | Every mirror candidate failed (network error or identity mismatch) (§8a) |
| `RES-PROVENANCE-CONFLICT` | Two transitive deps declare different provenances for the same name (§10.3) |
| `MAN-PREDICATE-MIXED-NEGATION` | Predicate mixes negated and non-negated values (manifest-grammar §6) |
