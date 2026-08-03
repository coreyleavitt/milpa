# milpa resolver semantics (S6)

Normative spec of milpa's dependency-resolution algorithm. Every
rule marked `> NORMATIVE:` defines a requirement any conformant
implementation MUST satisfy. Items marked `> NOTE:` describe the
reference Python implementation; conformant alternatives MAY differ
in those details.

This document covers **algorithm semantics** only. Related specs:

- `spec/manifest-grammar.md` (S4) — dep syntax, conditional-dep
  predicate syntax (§6), provenance-descriptor grammar
- `spec/lockfile-schema.md` (S5) — lockfile representation of a
  resolved graph; nim.cfg emission
- `spec/errors.md` — every error code this document references
- `spec/identity.md` (S12) — content-hash algorithm and CAS layout
- `spec/cli-contract.md` (S15) — `--frozen` flag / exit-code
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

### 2.1  Error-slug ownership — `SOLVE-CONFLICT` is canonical for unsatisfiable constraints

> NORMATIVE: **Enumerate-all is normative for named-dep Phase-A enumeration.**
> When enumerating available versions of a named dep at Phase A, a conformant
> implementation MUST enumerate ALL known versions from the index for that
> package (i.e. pass no constraint filter to the index lookup). The solver,
> via incompatibility accumulation, owns the satisfiability verdict.
>
> Consequence: when the index has at least one version of a package but none
> satisfies the declared constraint, the canonical error is `SOLVE-CONFLICT`
> (the solver's failure refutation), NOT `TNG-NO-SATISFYING-VERSION` (an
> eager enumerator pre-filter). `TNG-NO-SATISFYING-VERSION` is reserved for
> the case where the package is absent from the index entirely after
> enumeration yields zero candidates with provenance.
>
> A conformant implementation MUST NOT short-circuit Phase-A enumeration by
> pre-filtering against the declared constraint. Pre-filtering produces the
> correct selected version on the happy path (PubGrub accumulates the
> constraint independently via `Term.require` before solving), but emits the
> wrong error slug on the failure path — a cross-impl divergence that makes
> error messages implementation-dependent.

---

## 3  Identity-constraint convention for non-indexed deps

URL deps, local deps, and workspace-member deps are resolved by
**identity** (content hash) rather than version-range negotiation.
They do not appear in a named registry; only one concrete tree exists
for each such dep in a given resolution. This section also specifies the
**declared version** these deps carry alongside their identity — a
solver-facing label, never an identity input (`spec/identity.md
§4.1a`) — per the resolution-semantics RFC's Axis A (#191).

### 3.1  Exactly one candidate; self-term is `full()`

> NORMATIVE: A conformant resolver MUST present each URL dep, local dep,
> and workspace-member dep to the solver as a package with **exactly one
> candidate** — a fixed, non-range singleton (§3.3 states what value that
> candidate carries). The solver treats these deps as decided by
> identity; it MUST NOT attempt to backtrack across different candidates
> of a URL/local/member dep, because there is only ever one.

> NORMATIVE: The **requiring term** contributed by the dep's own
> declaration site — whether it is declared directly in a manifest's
> `deps`/`dev-deps` or reached as a transitive `requires` — MUST be
> `full()` (the unconstrained version set), never `eq(<version>)` fixed
> to the dep's own candidate version. This holds independent of whether
> the candidate's declared version is knowable at declaration time: for a
> fetched dep (git/url/tarball) the declaration's term is built *before*
> the fetch runs, while the candidate's real declared version (§3.2) is
> only known *after* the fetch resolves the source tree. A `full()` term
> removes any pre-commitment, so there is no window in which the
> pre-fetch term and the post-fetch candidate could disagree and produce
> a spurious `SOLVE-CONFLICT` on every dep that has a real declared
> version. (A workspace member has no fetch step, so this particular
> causality hazard does not apply to it, but the `full()` self-term is
> still required — it is what lets a member satisfy another member's
> floor on it when the member declares a version, §11.)

> NORMATIVE: The only constraints a URL/local/member dep's single
> candidate must satisfy are those contributed by **other** deps that
> require it (e.g. an index dep's `.nimble` floor on it). The dep's own
> self-term never constrains its own candidate.

> NOTE: The reference implementation builds this term as
> `VersionSet.full()` (`resolver.py`, `milpa-solver/src/lib.rs`) at every
> site that previously built `eq(_URL_DEP_VERSION)` — root seeding,
> mid-solve fixpoint blocks, and the workspace member-seeding path alike.

### 3.2  Declared version — manifest-agnostic precedence

> NORMATIVE: The **declared version** — the value that labels a URL,
> local, tarball, or workspace-member dep's sole candidate for constraint
> satisfaction (§3.1) — is derived by trying these sources in order,
> stopping at the first that yields a value:
>
> 1. the fetched (or, for a member, in-tree) package's own `milpa.kdl`
>    `version` field — native and authoritative;
> 2. else its `.nimble` `version` field (the compat adapter for the
>    existing Nim ecosystem; `spec/manifest-grammar.md`);
> 3. else, **git deps only** (a dep with a `ref`), a version-shaped tag
>    (`v?X.Y.Z`, parsed the same way as any other version literal);
> 4. else, an explicit `version=` annotation on the dep's own
>    declaration — or, for a purely-transitive dep with no root-owned
>    declaration site, on an `overrides { pkg … version= }` rule
>    targeting it (`spec/manifest-grammar.md`; distinct from an
>    override's source *redirect* — the annotation only supplies a
>    missing version label, it does not change which source is used);
> 5. else, the dep is **version-unknown** (§3.4).
>
> A named/index dep's version comes directly from the tianguis index and
> is never subject to this precedence — its version is never ambiguous.

> NORMATIVE: When an `overrides {}` rule redirects a dep to a different
> source, this precedence re-runs against the **override target's**
> manifest/tag/annotation; a `version=` left on the now-redirected
> original declaration is not read (the redirect changed which manifest
> is in play, which is not itself a conflict to detect).

> NOTE: The reference implementation is `declared_version_for`
> (`edge_sources.py`/`edge_sources.rs`); it reuses the same version
> parser as every other version literal in the system (`parse_version`),
> so a malformed value (e.g. `"0.1"`, non-numeric) is never a hard parse
> error — it simply fails to yield a value, and precedence falls through
> to the next step, ending at version-unknown if steps 1–4 all miss.

### 3.3  Candidate labeling and the lockfile boundary

> NORMATIVE: The dep's single candidate (§3.1) is labeled with the
> declared version from §3.2 when one exists. This label is a
> **constraint-satisfaction fact only**: it is compared against other
> deps' constraints on this package name exactly like any indexed
> version, but it is never an input to, and is never derived from, the
> dep's `content_hash` (`spec/identity.md §4.1a`). Two dependency trees
> carrying the same declared version but different content remain
> distinct by identity.

> NOTE: When no declared version exists (version-unknown, §3.4) the
> reference implementation still labels the internal candidate with a
> fixed internal sentinel token (e.g. `0.0.1`) purely so the solver has a
> concrete value to reason about; that token is an implementation detail,
> flattened to the reserved literal `"0.0.0"` at the lockfile boundary
> (`spec/lockfile-schema.md §3.2`), paired with an absent
> `declared_version_source` (§3.2a) — the unambiguous version-unknown
> encoding.

### 3.4  Version-unknown: the constrained/unconstrained partition

A dep can legitimately reach §3.2 step 5 (version-unknown) — for
example, an untagged branch pin with no `milpa.kdl`/`.nimble` version and
no `version=` annotation. Because such a dep is still fully and uniquely
resolved by content-hash identity (§3.1, `spec/identity.md`), this is not
itself a defect. What matters is whether **another** dep imposes a range
constraint on it.

> NORMATIVE: A conformant resolver MUST classify a version-unknown dep at
> the moment its solver decision is made — not earlier, and not by
> conflict-path introspection after the fact; see the ordering rule below
> — into exactly one of:
>
> - **unconstrained** — the accumulated constraint range for this
>   package is still the full/unbounded set (nothing floors or ceilings
>   it). The resolver proceeds normally, deciding the dep via its single
>   candidate (§3.1/§3.3); no error, no ceremony. This is the common
>   untagged-branch-pin case (e.g. an unreleased fork tracked at the tip
>   of a branch).
> - **constrained, with no declared version available** — some other
>   dep's requirement narrows the accumulated range below full. The
>   resolver MUST raise `RES-VERSION-UNKNOWN-CONSTRAINED` rather than
>   silently satisfying, or refusing to satisfy, the foreign constraint by
>   guessing a version. The error MUST enumerate **every** consumer that
>   contributes a constraint on the package (not just the first) and MUST
>   name the constrained package. Its remedy text MUST branch on whether
>   the constrained dep has a user-editable declaration site: root-declared
>   → "add a `version=` annotation (or pin a versioned tag)"; purely
>   transitive (no declaration the user owns) → "add a root-level pin or
>   an `overrides { … version= }` rule naming this package."
>
> (A constrained dep that DOES have a declared version, §3.2, is not
> version-unknown at all — it is an ordinary versioned dep subject to
> ordinary constraint satisfaction, and `SOLVE-CONFLICT` on a genuine
> incompatibility.)

> NORMATIVE: **Decision-priority ordering.** Because milpa's provider
> materializes named/index deps' own requirements **lazily** — the first
> time the solver selects a candidate for them — a depender's floor on a
> version-unknown package is not visible until the depender itself has
> been decided. A conformant resolver MUST therefore give a version-unknown
> package **strictly lowest decision priority** among all packages the
> solver has yet to decide. This guarantees that, by the time a
> version-unknown package's own decision is made, every other reachable
> package has already been decided and its constraints (if any) are
> already folded into the accumulated range — so the unconstrained/
> constrained classification above is exact, never a premature guess a
> later-discovered floor could invalidate. A resolver that classifies a
> version-unknown package before all its potential constrainers are
> decided (e.g. a naive declaration-order or BFS-order scan) risks
> committing the package's sentinel candidate while the range still looks
> unconstrained, then discovering a real conflict against an
> already-decided single-candidate package later — degrading to a generic
> `SOLVE-CONFLICT` instead of the precise `RES-VERSION-UNKNOWN-CONSTRAINED`.
> Relative order among version-unknown packages themselves, and among all
> other (normal-class) packages, is otherwise unaffected by this rule — it
> only requires that version-unknown packages be decided last.

> NOTE: The reference implementation's Rust provider extends its priority
> function so a version-unknown package's priority is dominated by a
> `not is_version_unknown` boolean ahead of any existing tie-break
> (`milpa-solver/src/lib.rs`); Python's BFS-order `_next_undecided`
> (§4.2.1) performs a two-pass scan — normal-class packages first, in
> their existing deterministic order, version-unknown packages after, in
> their own relative order — so this rule is additive to, not a
> replacement for, the existing canonical package order P.

Cross-reference: `spec/errors.md` for `RES-VERSION-UNKNOWN-CONSTRAINED`;
`spec/manifest-grammar.md` for the package `version` field, the dep-level
`version=` annotation, and the `overrides { … version= }` grammar;
`spec/lockfile-schema.md` §3.2/§3.2a for the wire encoding.

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

> NORMATIVE (`rfc-origin-as-identity.md` §4.2.1/§4.7): **first-occurrence
> dedup (step 3) is keyed by `canonical(source_id)`, not by the reference's
> declared label.** Since the solver variable is a source-id (§6b), two BFS
> parents reaching the same origin under two different author-chosen labels
> (e.g. one dep block names it `nimz3`, another names the same URL `z3lib`)
> are ONE position in P, not two — the position is assigned at the origin's
> first BFS occurrence. This is what makes the pre-fetch collapse of
> same-URL-different-label direct deps possible (§10.1's binding-phase
> `DUPLICATE` outcome is the arbitration; this rule is its ordering
> consequence). The chosen **display** label for that position (which of the
> two author-chosen names appears in `_deps/`/`nim.cfg`) is a separate,
> fully-specified tie-break — root-declared label beats any transitive's;
> among transitive labels with no root claim, first-BFS-occurrence wins;
> derived URL-tail label is last resort (`rfc-origin-as-identity.md` §4.7) —
> and a dropped label MUST be surfaced as a visible, low-severity note (never
> a silent disappearance from `_deps/`).

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
`spec/manifest-grammar.md` §6.

> NORMATIVE: Predicate evaluation MUST occur before the solver input is
> constructed. A dep whose predicates do not all match the active
> profile MUST NOT enter the candidate set, MUST NOT be fetched, and
> MUST NOT appear in any solver constraint. The resolver treats the
> profile-filtered manifest as if the non-matching deps were never
> declared.

> NORMATIVE: When **no profile is supplied** (an absent/None profile, as opposed
> to a profile with unset fields), predicate filtering is **disabled**: every
> dep is included regardless of its predicates, exactly as if no predicates were
> declared. An absent profile is not the same as a profile that matches nothing.
> (The conformance runner passes an absent profile when **no `MILPA_TARGET_*`
> axis is set** — independent of whether an `env` file exists for other keys
> such as `MILPA_CLI_FEATURES`. The runner builds a Profile only from explicit
> `MILPA_TARGET_{PLATFORM,ARCH,NIM,MILPA}` values; host-defaulting is a
> CLI-only behavior (cli-contract §8) not exercised by the host-independent
> corpus. See `conformance-fixtures.md` §2.8.)

> NORMATIVE (§3.C — S4, #159): **Absent-axis predicate semantics.** A
> profile MAY be **partial** — one or more of its axes (`platform`, `arch`,
> `nim`, `milpa`) may be absent (None/null) while the profile as a whole is
> present (i.e., at least one axis is set, so §470 "absent profile ⇒ passthrough"
> does NOT apply). An absent axis is **indeterminate**: every predicate over
> that axis MUST evaluate to `false` regardless of the predicate's negation.
> Concretely:
>
> - `when arch="amd64"` with `arch=None` → `false` (dep excluded).
> - `when arch=(not)"arm64"` with `arch=None` → `false` (dep excluded).
>
> Rationale: if we cannot evaluate whether the dep applies to this target
> axis, we cannot deterministically include it (conservative three-valued
> collapse). This is distinct from an absent *whole* profile — the CLI
> host-defaults every axis (cli-contract §8), so a partial profile only
> arises in the conformance runner and library API, never the default CLI
> path. Implementations MUST NOT flip the negation after an absent-axis
> short-circuit (i.e., absent-axis ⇒ `!false = true` is non-conformant).
> Conformance fixtures: `fixture-255` (positive) and `fixture-256`
> (negated, the cross-impl divergence guard).

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

### 6.1  Resolution scope: single-config is the deliberate default (#110)

> NORMATIVE (scope decision, closes #110): milpa resolves for a **single
> configuration** — the active profile. `when`-gated conditional deps are
> *stripped* against that profile per §6 before the solver runs, and the
> emitted lockfile reflects the **resolving machine's configuration only**.
> milpa does NOT resolve the union of a manifest's platform branches, and a
> lockfile is NOT a universal (all-target) artifact.

Rationale. uv's universal-lock motivation (per-platform *binary wheels*) does
not transfer to Nim: milpa deps are source, and platform variation is expressed
by compile-time `when` in the consumer, not by divergent resolved artifacts. A
single-config lock is therefore the correct default, not a limitation — building
union-resolution now would be speculative machinery for a consumer that does not
yet exist ([[feedback_minimal_over_completeness]], [[positioning_no_generic]]).

> NOTE (deferred, seam-ready): a **universal resolution** mode remains *defined
> but unimplemented*. Should a concrete cross-platform-divergent Nim consumer
> appear, it would: solve the union of `when` branches; record per-target
> provenance/identity under the `CondRequire`/marker dimension **already carried
> in the lockfile** (reserved for exactly this); and teach `verify` to check the
> active slice. The schema seam exists today; the resolution behavior is
> deferred. This is a landed scope *decision*, not a build.

> NORMATIVE (Axis B per-config boundary): the minimal-change guarantee (§8 prior-
> lockfile preference — bumping one dep does not move unrelated deps) is
> **per-lockfile / per-configuration, not per-manifest**. A `when`-gated dep that
> is stripped on the resolving machine has no entry in that machine's lockfile,
> so on a *different* configuration it has no prior preference to reuse and
> resolves fresh (newest-wins) — the same residual gap the single-config default
> defers above. Tooling MUST NOT describe minimal-change as spanning
> configurations it did not resolve.

---

## 6a  DepKey — the binding/grouping key

> NORMATIVE: Every implementation MUST represent a dep **reference's**
> grouping identity as a **`DepKey`** value, not a bare string. The canonical
> shape is:
>
> ```
> DepKey { name: String, namespace: Option<String> }
> ```
>
> `namespace` is `None` for a bare (unqualified) reference and populated from
> the manifest grammar for a namespace-qualified `NamedDep` reference (§3.2 of
> `spec/manifest-grammar.md`).
>
> **Ordering:** `DepKey` values are ordered lexicographically by `(namespace,
> name)`, with `None` namespace sorting before any non-`None` value.
>
> **Usage:** `DepKey` is used as the key in the frozen-path manifest-coverage
> index (§7.1 condition 2), MUST be used in `seen_named` (the resolver's
> transitive-named-dep dedup set), and — since `rfc-origin-as-identity.md`
> §4.3 — is the grouping/query key of the **binding phase** (§6b): a bare-name
> store is the literal root cause of #193 (a same-name, different-namespace
> collision falsely treated as one package), so every binding-phase lookup
> and arbitration decision is scoped by `DepKey`, never by bare `name` alone.
> This forces the alias-awareness fix: the frozen-path index maps EVERY
> canonical name AND every alias to its `LockedDep`.

## 6b  The solver variable — a source-id, in two phases (`rfc-origin-as-identity.md` §3/§4)

> NORMATIVE (repeal-and-replace): The rule this subsection previously stated —
> that the solver variable is a name/`DepKey`-derived string (`name`, or
> `"ns::name"` for a qualified reference) and that a "cross-name precedence
> gate" (`RES-PROVENANCE-CONFLICT`) keyed on that string to stop two
> transports from claiming one dep — is **superseded**. The defect that rule
> encoded (`#193`) was keying the solver by the consumer's **label**. The
> solver variable is now a **source-id**: the dep's version-independent
> **origin** (`SourceId` — a git URL, an OCI coordinate, a tarball URL, a
> local path, a registry coordinate, or a workspace-member name; ref/tag/
> digest excluded — they are versions, not origin). Coordinate-is-origin: a
> `named` (registry) dep's origin **is** its registry coordinate; a
> `git=`/`local=`/`tarball=` dep's origin is its own declared URL/path. The
> same name resolving through two different origins is **not** one package —
> it is two packages sharing an import label; `overrides {}` is the only
> bridge between them (§10).

> NORMATIVE: Deriving the solver variable for a given dep **reference**
> (a root/workspace-member declaration, a transitive `requires` occurrence, a
> provider stub, or a solved candidate alike) is **two distinct, separately
> specified phases** — conflating them was the root cause of the earlier
> "fictional registry canonical" defect this subsection also repeals:
>
> 1. **Name-resolution** (`reference → source_id`, binding-aware) — *what
>    source does this reference actually point to?* Evaluated against the
>    current state of the **binding phase** (a `BindingResolver`, or
>    equivalent, holding one accepted `SourceId` per `DepKey`):
>    1. If this reference's `DepKey` is **already bound** (by a root claim, an
>       `overrides {}` rule, a workspace member/standalone-root self-claim, or
>       an earlier-accepted transitive claim) — that bound `SourceId` wins,
>       **regardless of what kind of declaration this reference itself is**.
>       This is what unifies a root `bearssl git=(url)"…"` with a transitive
>       bare `requires "bearssl >= 0.2.8"`: both share one `DepKey`
>       (`name="bearssl"`, `namespace=None`); the transitive's own guess is
>       never even computed, because the root's bound `GitSourceId` is found
>       first. A direct `git=`/`local=`/`tarball=`/`oci=` declaration is
>       therefore, semantically, an **implicit override** of that name (the
>       same mechanism as an explicit `overrides {}` rule, Cargo `[patch]` /
>       nimble URL-federation unified into one).
>    2. Otherwise (genuinely first encounter — no root claim, no
>       `overrides {}` rule, no prior transitive binding) — fall back to a
>       **kind default**: the standalone root's own declared name → the
>       workspace-member-style self source-id (§14); an `overrides {}` match →
>       the override target's source-id; a `git=`/`tarball=`/`local=`
>       declaration → that declaration's own URL/path; otherwise (a bare
>       `named` reference) → the registry coordinate resolved via the
>       pre-loaded index.
> 2. **Canonicalization** (`source_id → canonical`, uniform) — *what is the
>    stable key for this source?* `canonical(source_id)` (one-way, injective;
>    `spec/identity.md`). This step is **kind-free**: every kind is
>    canonicalized the same way. There is no "eager kinds stay name-keyed"
>    carve-out — the PubGrub solver variable (`Term.package`) is
>    `canonical(source_id)` for **every** resolved node, git/tarball/local/
>    member/registry alike.

> NORMATIVE: **Root-vs-root** disagreement for one `DepKey` (e.g. a root dep
> declaration and a root `overrides {}` rule naming the same package) MUST be
> reconciled — the override pre-empting the plain declaration — **before**
> any claim is bound; two disagreeing root claims for one `DepKey` reaching
> the binding phase is an implementation-internal invariant violation, never
> a resolvable-at-runtime case. **Transitive** claims are arbitrated as they
> arrive (§10 has the full arbitration table and error conditions —
> `RES-BINDING-CONFLICT`, the successor to the repealed
> `RES-PROVENANCE-CONFLICT`).

> NORMATIVE (repeal-and-replace of the prior "`::` MUST NOT appear on any
> serialized surface" rule): a namespace-qualified reference's lookup form
> (`"ns::name"`, used only as an internal grouping-key convenience when
> constructing a `DepKey`/looking up a binding) remains solver/binding-phase
> internal — but the rule requiring this is now vacuously satisfied by
> construction, not by a separate leak-prevention check: the **on-disk**
> origin is always the structured `source { … }` block (`spec/lockfile-
> schema.md` §3.10), never the solver's in-memory canonical string or the
> `::` lookup form, so neither can leak onto any serialized surface. `_deps/`
> layout and `nim.cfg`/`requires` emission for a qualified named dep keep the
> unchanged `@<namespace>/<name>` convention (§6c) — that convention is about
> the *display* slot for a qualified reference, orthogonal to solver keying.

> NOTE: The reference implementation is `binding.canonical_key_for_requirement`
> (phase 1 + phase 2 composed) and `BindingResolver` (`binding.py`,
> `rfc-origin-as-identity.md` §4.3) for the binding-phase state; `Term.package`
> and the provider's candidate/stub dicts are fed `canonical(source_id)`
> uniformly. `DepKey.from_solver_var`/`Claim.name` still carry the `"ns::name"`
> qualified-lookup string internally — this is the phase-1 lookup key, not the
> phase-2 solver variable, and it is what §6a's `DepKey`-scoping discipline
> (not a bare `name`) protects against the #193 regression.

## 6c  On-disk layout for qualified deps — S5b

> NORMATIVE (S5b): A qualified dep MUST be materialized under
> `_deps/@<namespace>/<name>/` (npm-scope form). A bare dep is materialized
> as `_deps/<name>/` (unchanged). The `@` prefix is RESERVED — bare dep
> names MUST NOT start with `@` (see `spec/manifest-grammar.md §2.1`).
>
> This form is Windows-safe (no `:` in path components), human-readable, and
> collision-free with bare names.
>
> **nim.cfg:** Qualified dep paths are emitted as
> `--path:"_deps/@<namespace>/<name>/src"`. Bare dep paths are unchanged.
>
> **requires field in lockfile:** When dep A requires qualified dep B
> (`namespace = "ns"`, `name = "bar"`), A's `requires` node lists it as
> `"ns/bar"` (slash-separated). This is the canonical serialized form for
> qualified dep names in `requires`. Bare dep names are unchanged.
>
> **Lockfile dep node:** A qualified dep is serialized with the bare name as
> the node argument and `namespace` as the FIRST child node:
>
> ```kdl
> dep "bar" {
>     namespace "ns1"
>     identity "sha256:..."
>     ...
> }
> ```
>
> The lockfile records two qualified deps with the same bare name as two
> separate `dep "bar"` nodes distinguished by their `namespace` child:
>
> ```kdl
> dep "bar" {
>     namespace "ns1"
>     identity "sha256:aaa..."
>     ...
> }
>
> dep "bar" {
>     namespace "ns2"
>     identity "sha256:bbb..."
>     ...
> }
> ```
>
> And `_deps/` contains: `_deps/@ns1/bar/` and `_deps/@ns2/bar/`.

## 7  `--frozen` resolution

`--frozen` is a resolver behavior, not merely a CLI flag. The normative
guarantees of the frozen path are defined here; flag and exit-code
semantics are in `spec/cli-contract.md` (S15).

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
conditions that disqualify the `--frozen` fast path. `spec/cli-contract.md`
cross-references this section rather than restating the list.

> NORMATIVE: The frozen *resolve path* (`resolve_frozen()` /
> `resolve_workspace_frozen()`) raises exactly the following twelve
> `FROZEN-*` codes on precondition failure (non-`FROZEN-*` failures
> silently fall through to the slow path when `--frozen` was not
> explicitly set, or hard-error when it was):
>
> 1. **`FROZEN-STRATEGY-MISMATCH`** — the lockfile's recorded `strategy`
>    field does not equal the requested `Strategy`.
> 2. **`FROZEN-MANIFEST-DEP-NOT-IN-LOCK`** — a dep declared in the
>    manifest's `deps` **or** `dev-deps` (§9 cross-ref) has no corresponding
>    lockfile entry. The check is alias-aware: a manifest dep whose name
>    matches a lockfile alias (not just a canonical name) is considered
>    present (S1, rfc-resolver-correctness.md #142). Both `deps` and
>    `dev-deps` are checked on both the single-package and workspace paths.
> 3. **`FROZEN-LOCKED-VERSION-UNPARSEABLE`** — a locked version string
>    cannot be parsed as a valid semver `X.Y.Z`.
> 4. **`FROZEN-CONSTRAINT-UNSATISFIED`** — for a `NamedDep` with a
>    declared constraint, the locked version does not satisfy that
>    constraint.
> 5. **`FROZEN-IDENTITY-NOT-IN-STORE`** — a dep's recorded identity is
>    absent from the CAS.
> 6. **`FROZEN-LOCAL-DEP`** — a dep carries a local-path provenance;
>    editable trees always re-resolve.
> 7. **`FROZEN-MEMBER-DEP`** — a locked dep carries a workspace-member
>    provenance in a single-package (non-workspace) resolve context.
> 8. **`FROZEN-MEMBER-NOT-IN-WORKSPACE`** — the lockfile references a
>    workspace member that is not present in the current workspace.
> 9. **`FROZEN-MEMBER-IDENTITY-DRIFT`** — a workspace member's on-disk
>     `content_hash` differs from the lockfile's pinned identity.
> 10. **`FROZEN-EXCLUDE-NEWER-MISMATCH`** (D5, resolution-semantics RFC
>     §3 Axis D) — the lockfile's recorded top-level `exclude_newer`
>     (`lockfile-schema.md` §2.2a) does not equal the manifest's EFFECTIVE
>     `resolution { exclude-newer }` (default: unset). Built manifest-
>     sourced from the start, mirroring exactly how #1
>     (`FROZEN-STRATEGY-MISMATCH`) is built — never a hardcoded literal.
> 11. **`FROZEN-REGISTRY-ALIAS-UNRESOLVED`** (rfc-origin-as-identity.md
>     §7.1 D3, S5) — a locked dep's structured `source { kind "registry"
>     … }` node (`lockfile-schema.md` §3.10) names a registry alias this
>     machine's configuration does not recognize. **Checked FIRST** among
>     the two source-id preconditions (before #12) and short-circuits: an
>     unresolved alias means the coordinate comparison cannot even be
>     attempted, so it is never misreported as a mismatch instead.
> 12. **`FROZEN-SOURCE-ID-MISMATCH`** (rfc-origin-as-identity.md §7.1 D2,
>     S5) — a manifest dep's declared origin (`git=`/`local=`/`tarball=`/a
>     bare registry name), evaluated **AFTER** any `overrides {}` rule
>     redirects it (reusing the same override-reconciliation helper
>     `BindingResolver.__init__`/`BindingResolver::new` uses — never a
>     second copy, and never the raw pre-override declaration), does not
>     equal the corresponding locked dep's `source_id`. Scoped to
>     root-authoritative claims only (an ordinary manifest dep declaration
>     or an `overrides {}` target) — a purely transitive dep's own
>     declaration lives inside another dep's fetched manifest, which the
>     frozen path never re-reads, so there is nothing to compare it
>     against. For a bare (unqualified) named dep, only the registry alias
>     and name are compared (the namespace component needs a live index
>     the frozen path does not have). Both preconditions are skipped
>     entirely for a locked dep with no recorded `source_id` (a pre-S5
>     lockfile, forward-compat).
>
> No other `FROZEN-*` *resolve-path preconditions* exist; this list is
> closed. Two further `FROZEN-*` codes — `FROZEN-NO-LOCKFILE` and
> `FROZEN-NO-CAS` — are **CLI-level guards** raised *before* the resolve
> path is entered (the caller, `_try_frozen` / `_try_workspace_frozen`,
> checks for a present `milpa.lock` and an attached CAS; see
> `spec/cli-contract.md` and `spec/errors.md`). They are a distinct layer
> from the twelve preconditions above and bring the catalog total to
> fourteen `FROZEN-*` codes.

> NORMATIVE: Conditions 1–5, 6, 11, and 12 are checked inside
> `resolve_frozen()` (single-package path); conditions 7–9, 11, and 12 are
> checked inside `resolve_workspace_frozen()` (workspace path). Conditions
> 11/12 are ALSO checked by `milpa verify` (not just `--frozen`) via the
> same SSOT wrapper (`check_source_id_preconditions_standalone` /
> `check_source_id_preconditions_workspace`), positioned before the
> disk-state check (manifest-vs-lockfile consistency before disk-vs-lockfile
> consistency) — see `spec/cli-contract.md` §5.4 (verify).

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
> CAS-admissible (editable sources; see `spec/plugin-contract.md`
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
(see `spec/manifest-grammar.md` §3.3). This section defines
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

The conformance fixture `conformance/spec-v1/fixture-064-dev-deps`
verifies this rule: a root dep `a` whose milpa.kdl declares `dev-deps { e ... }`
is correctly excluded from the resolved graph (only `a` and the root's own
dev-dep `d` appear).

---

## 10  Source selection — the binding phase (`rfc-origin-as-identity.md`)

> This section is a full rewrite superseding the prior "provenance
> precedence" model (name-keyed unification + a name-scoped root-authority
> suppression + a non-root same-source-agreement check). That model conflated
> *unification* (which claims are one package) with *name*; under
> coordinate-is-origin, unification is keyed by **origin** (`SourceId`), not
> name, so the two concerns separate cleanly into §6b (keying) and this
> section (which origin a reference resolves to, and what happens when two
> claims disagree).

### 10.0  The model: coordinate-is-origin, the binding phase, and the bridge

Source selection rests on separating three decisions milpa makes, which MUST
NOT be conflated (`rfc-origin-as-identity.md` §3):

- **Origin** (`SourceId`, §6b) — a dep's identity *as a solver variable*: a
  registry coordinate, a normalized git/tarball URL, an OCI coordinate, a
  local path, or a workspace-member name. Version-independent, pre-fetch,
  known from the manifest/index alone.
- **Binding** — which origin a given **reference** (a root/override/member
  declaration, or a transitive `requires` occurrence) resolves to, and what
  happens when two references for the same `DepKey` disagree — the subject of
  this section.
- **Identity** (`content_hash`, `spec/identity.md`) — whether a *fetched* tree
  is what was expected. Strictly post-fetch and orthogonal to binding: it
  governs verification and CAS dedup, never which origin a reference binds
  to. It DOES, however, enable one further, **post-fetch** unification of two
  *different* origins that turn out to be byte-identical (§10.6) — a
  merge-on-proof, never a merge-on-heuristic.

> NORMATIVE: **Coordinate-is-origin.** A `named` (registry) reference's
> origin **is** its registry coordinate (`RegistrySourceId`). A
> `git=`/`local=`/`tarball=` reference's origin is its own declared URL/path.
> The same bare name resolving through two different declared origins is
> **not** automatically one package — a transitive
> `"z3" git=(url)"…/org-a/nim-z3.git"` and a registry entry named `z3` at
> `org-b/nimz3` are, by default, two unrelated packages that happen to share
> an import label. milpa never auto-unifies them by inspecting/normalizing
> URLs (undecidable, and a correctness/security hazard — `rfc-origin-as-
> identity.md` §3.2). The bridge is `overrides {}` (§10.3): declaring the name
> at the root explicitly rebinds it, Cargo-`[patch]`-style.

> NORMATIVE: Orthogonality with the attestation policy (`attestation-policy`,
> `RES-UNATTESTED-METADATA`, §13): this section decides which ORIGIN a
> reference binds to; the attestation policy independently governs how much a
> *named* (registry) resolution is trusted. A conformant implementation MUST
> NOT fold attestation strength into binding. (The registry-shadow tripwire,
> §10.5, is a distinct, narrower mechanism layered on the same
> `attestation-policy` strict/permissive switch — it decides whether a
> transitive claim that *shadows* a registry-owned name is accepted, not how
> much a resolved registry entry is trusted.)

### 10.1  The binding phase — root arbitrates, deterministic, pre-fetch where possible

> NORMATIVE: A conformant implementation MUST maintain, for the duration of
> one resolve, a **binding phase** that records at most one accepted
> `SourceId` per `DepKey`, and arbitrates every claim (a `(DepKey, SourceId)`
> pair asserted by some reference) against that record. Every reference in
> the graph — root dep, `overrides {}` target, workspace member, standalone
> root's own name (§14), and every transitive `requires` occurrence — asserts
> exactly one claim.

> NORMATIVE: **Root claims bind first, structurally.** The set of **root**
> claims — every root manifest `deps`/`dev-deps` entry (after `overrides {}`
> pre-emption, §10.3), every workspace member's own name, and (for a
> standalone resolve) the root's own declared name (§14) — is constructed and
> bound as a unit before any transitive claim is considered. Two root claims
> disagreeing on one `DepKey` is unreachable by construction (an
> implementation-internal invariant violation if it ever occurs, never a
> user-facing error) because `overrides {}` pre-emption (§10.3) reconciles a
> root dep declaration against a root override on the same name before
> binding either.

> NORMATIVE: **Arbitrating a transitive claim** against the binding phase's
> current record for its `DepKey` yields exactly one of three outcomes:
>
> - **New** — the `DepKey` has no existing binding. The claim's `SourceId` is
>   recorded; the caller enqueues it for fetch (if not already in flight).
> - **Duplicate** — the claim's `SourceId` equals the existing binding
>   (structural equality on the frozen `SourceId`, §identity). A harmless
>   no-op; resolution proceeds. Two `git=` claims naming the same URL at
>   *different* `ref`s are a duplicate at the binding layer (`ref` is
>   excluded from `SourceId` — it is a version, not an origin, §6b) — but a
>   conformant implementation MUST still register the later claim's pinned
>   `ref` as an additional candidate version for the bound origin; silently
>   dropping it loses a real pin.
> - **Lost-to-root** — the `DepKey` is already bound by a **root** claim, and
>   the transitive claim's `SourceId` disagrees. The transitive claim is
>   silently discarded (this IS the Cargo-`[patch]` semantics — the root
>   always wins over an unrequested transitive opinion). Discarding a claim
>   this way is not silent forever: an `overrides {}` rule that turns out to
>   name nothing reachable is separately flagged by `RES-DEAD-OVERRIDE`
>   (non-fatal), and a diagnostic surface (e.g. `milpa show`) MAY report which
>   transitive claims lost to which root binding.
>
> A transitive claim disagreeing with an **existing transitive** binding (no
> root claim governs that `DepKey`) is **not** one of the three outcomes
> above — it is a binding **conflict**:

> NORMATIVE: **`RES-BINDING-CONFLICT`.** When two *transitive* claims for one
> `DepKey` disagree on `SourceId`, and no root claim binds that `DepKey`, a
> conformant implementation MUST raise `RES-BINDING-CONFLICT` and MUST NOT
> silently pick one. This covers URL-vs-URL (two `git=` claims at different
> URLs) and named-vs-URL (a `named` claim's registry coordinate vs. a `git=`
> claim's URL) alike — both are simply "two different `SourceId`s claiming one
> `DepKey`." The remedy is to declare the name at the root via `overrides {}`
> (§10.3), which promotes one of the two to root authority and the other is
> then silently discarded (lost-to-root) rather than conflicting.

This is the Cargo `[patch]`/`[replace]` / npm `overrides` / Go `replace`
model: **only the top-level project being built can redirect a dep's
origin.** An intermediate library cannot hijack another dep's binding.

> NOTE: The reference implementation is `BindingResolver`
> (`rfc-origin-as-identity.md` §4.3): `__init__(root_claims)` binds every root
> claim as a unit (raises if handed a non-root claim); `submit(claim)` accepts
> only non-root claims and returns a `BindingDecision{accepted, outcome}` with
> `outcome ∈ {NEW, DUPLICATE, LOST_TO_ROOT}`; a transitive-vs-transitive
> disagreement raises `MilpaError(RES_BINDING_CONFLICT, …)` naming both
> sources via `format_source_id`. Authority is a two-valued fact
> (`Claim.is_root: bool`), never a priority lattice/tier integer. Keyed by
> `DepKey`, never bare `name` (§6a) — `ns1::foo` and `ns2::foo` never
> cross-bind.

### 10.2  Pure and pre-fetch, with one necessary exception

> NORMATIVE: Binding-phase arbitration itself performs no I/O — it is a pure,
> in-memory decision over already-known `SourceId` values. Every origin is
> knowable **before** the corresponding tree is fetched: a `git=`/`local=`/
> `tarball=` reference's origin comes directly from its own manifest
> declaration; a `named` reference's origin comes from the pre-loaded
> registry index. Fetching only ever selects a *version* within an already-
> bound origin, never the origin itself.

> NORMATIVE: The one necessary exception: constructing the claim for a
> transitively-discovered **named** reference requires that its parent's tree
> already be fetched and its manifest/`.nimble` parsed (to discover the
> `requires` occurrence at all) — so *claim construction* for named
> transitives is interleaved with BFS exactly as fetching is. The win of the
> binding phase is a typed, pure arbitration seam replacing an ad hoc
> side-table, not a synchronous up-front pass over the whole graph before any
> fetch begins.

### 10.3  Overrides are the sole rebind bridge, and are root-only

> NORMATIVE: `overrides {}` (§3.4 of `spec/manifest-grammar.md`) is the
> **sole** mechanism for rebinding a name to a different origin than its
> ordinary declaration/registry lookup would produce. An `overrides {}` rule
> is applied — reconciled against any root dep declaration of the same name,
> the override winning — **before** the binding phase's root claims are
> constructed (§10.1), so a root dep declaration and a root override for the
> same name never reach the binding phase as two disagreeing root claims.

> NORMATIVE: A transitive dep's own `overrides {}` block (from a fetched
> dep's `milpa.kdl`) MUST be silently ignored. A conformant implementation
> MUST NOT apply overrides from any manifest but the root's (and, for a
> workspace, the workspace-level `overrides {}` block). **Security
> rationale:** a dependency that can override another dependency's origin is
> a supply-chain attack vector; restricting override authority to the root
> means only the project owner controls which origins are authoritative.

> NORMATIVE: An override's target may itself be a *different registry
> coordinate* than the overridden name (e.g. `chronos` → `acme::chronos-fork`)
> — the binding phase's grouping key stays the **overridden** `DepKey`, while
> the accepted `SourceId` describes the **new** coordinate. The lockfile
> record, attestation subject, and diagnostics all read the accepted
> `SourceId`'s own coordinate fields, never the overridden grouping key.

> NOTE: The reference implementation never reads `manifest.overrides` from a
> fetched transitive dep's `milpa.kdl` — `_extract_from_milpa_kdl` reads only
> `manifest.deps`. Root reconciliation is `binding.reconcile_root_claims`,
> shared by `BindingResolver.__init__`'s caller and the frozen-path
> `FROZEN-SOURCE-ID-MISMATCH` precondition (§7.1 D2) so the two never
> diverge.

### 10.4  Workspace members and the standalone root's own name

> NORMATIVE: A workspace member's own name is a root claim bound to a
> `MemberSourceId` at workspace load — conflict-free by construction (member
> names are unique, §11). A standalone (non-workspace) resolve's root
> manifest's own declared `name` is likewise a root claim, bound to the same
> `MemberSourceId`-shaped self-reference (§14: a standalone package is a
> workspace-of-one). Both generalize into the same binding-phase arbitration
> path as any other root claim — including `RES-WS-OVERRIDE-MEMBER-COLLISION`
> (a workspace override naming a member) and the version-constraint checks of
> §11.5/§14.3, which are orthogonal to *binding* (they gate the member/root
> candidate's version, not which origin it binds to).

### 10.5  The registry-shadow tripwire (dependency-confusion defense)

Coordinate-is-origin means a `git=`/`tarball=`/`oci=` claim and a
registry-owned coordinate sharing a bare name are, by default, simply two
different packages — nothing about §10.1–§10.4 alone stops a transitive dep
from quietly pinning a *different* repository under a name the registry
already owns and trusts. Because milpa's positioning is supply-chain
integrity and dependency-confusion is the canonical supply-chain attack, this
defense is retained as an explicit, separate, pre-fetch check
(`rfc-origin-as-identity.md` §6.1 / §11 D-Fork1) — layered on the
`attestation-policy` seam, not folded into binding arbitration.

> NORMATIVE: Before a **new** (previously-unbound) transitive `git=`/
> `tarball=`/`oci=` claim is admitted, a conformant implementation MUST check
> whether the claim's bare name is a coordinate the registry owns, in any
> namespace:
>
> - If the name is **not** registry-owned at all, nothing fires — this is an
>   ordinary self-declared origin (`RES-BINDING-CONFLICT`, §10.1, still
>   governs true multi-claim disagreements independently).
> - If the name **is** registry-owned, compare the claim's normalized origin
>   against every comparable upstream source the registry entry records
>   (across every version of the owning package). A match is a legitimate
>   same-repository pin — **silent accept**.
> - Otherwise (the URL disagrees, or the entry is OCI-only with no comparable
>   upstream source recorded at all) — raise `RES-REGISTRY-SHADOW`: **warn by
>   default** (a git fork of a registry package is common and legitimate; the
>   claim still proceeds to fetch), **hard-fail under `attestation-policy`
>   strict** (the claim is never fetched).

> NORMATIVE: This check is deliberately **pre-fetch, URL-only, and static** —
> unlike the model it supersedes, it performs **no post-fetch content-hash
> reconciliation**. An OCI-only registry entry pinned via a shadowing `git=`
> claim can no longer be auto-accepted by comparing fetched bytes before
> deciding whether to fetch at all; `content_hash` still verifies the fetched
> bytes independently at materialization (§10.6), but does not participate in
> this admission decision. This is an accepted, signed-off honest narrowing —
> the alternative (fetch first, decide after) exposes the tree before the
> decision is made.

> NOTE: The reference implementation is `binding.check_registry_shadow`,
> called for every NEW transitive `git=`/`tarball=`/`oci=` claim (never for
> `registry`/`local`/`member` claims, and never re-run for a claim that is a
> `DUPLICATE`/`LOST_TO_ROOT` outcome). It is gated off for a name already in
> `root_authority` — a root's own explicit source choice is never
> second-guessed by this tripwire.

### 10.6  Post-fetch cross-origin unification (content-hash, milpa's edge over Cargo)

> NORMATIVE: After a claim is fetched, a conformant implementation MAY
> collapse two or more *distinct* solved solver variables (distinct
> `canonical(source_id)` values) into one, if and only if their fetched trees
> share an identical `content_hash` AND an invariant guard holds (identical
> `content_hash` ⇒ identical `requires` set; a violation is an internal
> error, never a silent merge). This is **merge-on-proof**, strictly
> post-fetch, and is the sole exception to "different origin = different
> package": it does not weaken §10.0's prohibition on merging origins by
> *heuristic* (URL-guessing), because it fires only on byte-identical
> content — a dependency-confusion attack requires *different* bytes, which
> never merge. A collapse MUST record **every** collapsed origin's own
> observed provenance in the lockfile (§lockfile-schema §3.8/§4.0a) — the
> audit trail survives even though the solver now treats them as one package.
> Under coordinate-is-origin this unification is **cross-origin**: a registry
> coordinate and a git URL that happen to fetch byte-identical trees collapse
> to one solver variable, not merely to one on-disk directory — the
> differentiator milpa has over Cargo's pure name+origin identity, realized
> at the solver layer rather than only at the storage layer.

> NOTE: The reference implementation is `resolver.py`'s "Phase B"
> content-hash dedup pass (`_dedup_candidates`), re-keyed by `source_id`
> (`rfc-origin-as-identity.md` §4.5/§S4b) rather than by name — this fixes a
> latent bug where two BFS parents reaching one repository under two
> different labels sealed two separate `edge_cache` entries instead of
> coalescing to one.

### 10.7  Orthogonality with dev-deps

> NORMATIVE: Source selection is orthogonal to dev-dep propagation (§9).
> Discarding a losing transitive claim (lost-to-root, §10.1) does NOT affect
> whether dev-deps are included — those are always governed by §9's
> root-only dev-dep rule.

The conformance fixture
`conformance/spec-v1/fixture-065-root-override-precedence`
verifies the root-authority half of this model: the root declares `shared`
from `our-fork.example.com`; a transitive dep (`translib`) declares `shared`
from `upstream.example.com`. The expected output shows `shared` resolved to
the root's origin (`our-fork.example.com`) and the upstream URL was not
fetched (the transitive claim is `LOST_TO_ROOT`, §10.1).

Cross-reference: `spec/manifest-grammar.md` §3.4 for the `overrides {}`
block syntax (six target kinds: git/local/member/oci/tarball/registry, plus
version-scoping). `spec/errors.md` for `RES-BINDING-CONFLICT`,
`RES-REGISTRY-SHADOW`, and `RES-DEAD-OVERRIDE`.

### 10.8  When binding is decided (ordering)

> NORMATIVE: A `DepKey`'s binding is decided as claims are discovered, not by
> a global post-hoc collision scan. Root claims (§10.1) are all bound before
> any transitive claim is considered. For a `DepKey` with no root claim, the
> **first** transitive claim registers the binding (`NEW`); a later claim
> with the same `SourceId` is a `DUPLICATE`; a later claim with a *different*
> `SourceId` raises `RES-BINDING-CONFLICT` (§10.1). Because a claim's
> `SourceId` is a static fact of the claim itself (a `git=` URL directly; a
> `named` claim's coordinate from the pre-loaded registry record), this holds
> regardless of discovery order — a `named` claim discovered mid-solve (e.g.
> as a transitive of another named dep) is arbitrated against the `DepKey`'s
> already-registered binding at that point. That is a terminal outcome: no
> already-committed solver candidate is ever retracted.

> NORMATIVE: This ordering is load-bearing now that declared versions are
> real (§3, Axis A): two disagreeing origins could each declare a differing
> version for the same name, and an implementation that admitted both before
> arbitrating origins would degrade the precise `RES-BINDING-CONFLICT` into a
> generic `SOLVE-CONFLICT`. Arbitrating on origin (independent of any version
> either carries) keeps this correct.

Cross-reference: `spec/errors.md` for `RES-BINDING-CONFLICT`; §3 for the
declared-version mechanism this section's ordering protects.

---

## 11  Workspace resolution

A workspace is a collection of related packages resolved together into
one shared graph. This section is normative for any implementation that
supports milpa workspace manifests.

### 11.0  Member-path canonicalization (S4 — #168)

> NORMATIVE: Before checking whether a declared member path escapes the
> workspace root, a conformant implementation MUST canonicalize the
> candidate path using the **best-effort-resolve** algorithm:
>
> 1. If the full candidate path **stat-exists** (i.e. `stat()` succeeds,
>    following all symlinks), fully canonicalize it (resolve all symlinks
>    to real paths).
> 2. Otherwise, walk up the path hierarchy from longest to shortest
>    prefix, finding the longest prefix for which `stat()` succeeds.
>    Canonicalize that prefix (all symlinks resolved), then append the
>    remaining suffix and normalize lexically (`..` / `.` eliminated
>    without touching the filesystem).
>
> **Critical invariant:** a dangling or cyclic symlink MUST be treated
> as non-existent — `stat()` MUST be used (follows symlinks), NOT
> `lstat()` (which would lstat-succeed on a dangling or cyclic symlink
> and therefore include the symlink itself in the "existing prefix").
> Concretely: if the declared member path is a dangling symlink (target
> absent) or a cyclic symlink (ELOOP), `stat()` fails, so the longest
> stat-existing prefix is the **parent directory** of the symlink.  The
> result is `canonical_parent / symlink_name` — which is inside the
> workspace root — and the path therefore does NOT escape.  The
> subsequent directory-existence check then fails → `WS-MEMBER-DIR-MISSING`.
>
> This rule has two concrete consequences for unresolvable symlinks:
>
> - **Cyclic symlink member** (`link-a → link-a`, or `a → b, b → a`):
>   stat fails (ELOOP) → treated as non-existent → best-effort-resolve
>   returns `canonical_root/link-a` → no escape → `WS-MEMBER-DIR-MISSING`.
>   (Without this rule, Python's `Path.resolve(strict=False)` would raise
>   an unhandled `OSError(ELOOP)` — a crash.)
> - **Dangling symlink member pointing outside the root** (`link-d → ../outside`,
>   where `../outside` does not exist): stat fails → treated as non-existent →
>   best-effort-resolve returns `canonical_root/link-d` → no escape →
>   `WS-MEMBER-DIR-MISSING`.  (Without this rule, following the link target
>   one hop would detect an escape and yield `WS-MEMBER-PATH-ESCAPE`, leaking
>   information about the link target's path.)
>
> Note: an existing symlink whose target resolves to a real path **outside**
> the workspace root is NOT in either case above — `stat()` succeeds and
> the path is fully canonicalized to the outside location →
> `WS-MEMBER-PATH-ESCAPE` (unchanged behavior, correct security boundary).

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
> (cross-reference `spec/lockfile-schema.md` §7.6). The shared
> lockfile does not imply all deps appear in every member's `nim.cfg`.

### 11.5  Member self-registration

> NORMATIVE: Each workspace member MUST be pre-registered as a candidate
> in the solver with version `_URL_DEP_VERSION` (the same sentinel used
> for URL deps — §3). The member's on-disk `content_hash` is computed
> at the time of registration (no fetch). Named deps whose name matches
> a workspace member name auto-coerce to member resolution: they are
> treated as requiring the already-registered member candidate rather
> than being looked up in the tianguis index.

> NORMATIVE: When a `NamedDep` auto-coerces to a member, the declared
> version constraint MUST be checked against the member's sentinel
> version.  If the sentinel version does not satisfy the constraint,
> the resolver MUST raise `RES-WS-MEMBER-VERSION-CONSTRAINT`.
> Silently discarding the consumer's declared constraint is a
> correctness violation — the resolver is not free to ignore a `>= 2.0.0`
> constraint simply because the target is a workspace member.

> NOTE: The reference implementation is `resolve_workspace` in
> `resolver.py`. Members are iterated in `workspace.members` order;
> each member's `_terms_from_member_manifest` produces solver `Term`s
> and a queue of external deps. The root candidate `__root__` collects
> a `Term.require` for every member. `start_solve` wires up callbacks
> for transitives discovered during solve. The solver is called once
> over the combined provider; `_build_graph` assembles the
> `ResolvedGraph`.

### 11.6  Cross-member flag-conflict validation (§3.8-conflict)

A workspace resolution accumulates flag requests from **all members** into
each dep's unified `active_flags` set (the workspace-wide union). This union
is then subject to the same post-fixpoint flag-conflict validation that
applies to single-package resolutions (§6 / RFC #23 §3.1.4).

> NORMATIVE: After the dep×flag fixpoint has converged across all workspace
> members — and therefore after the cross-member union is fully accumulated
> in each dep's `active_flags` — a conformant implementation MUST run the
> flag-conflict validation pass (§6) over the converged `active_flags` for
> every dep. This pass MUST NOT be scoped to individual members; it MUST
> operate on the fully-unioned set.

> NORMATIVE: If any dep D has two flags `f` and `g` both present in D's
> converged `active_flags`, and D's manifest declares `f conflicts g` (or
> equivalently `g conflicts f`), the resolver MUST raise
> `RESOLVE-FLAG-CONFLICT`. The source of the conflicting activations
> (which member requested which flag) is included in the error payload for
> diagnostics but does not affect the validation rule: the union itself is
> invalid regardless of which member contributed each flag.

> NORMATIVE: This validation runs **before** the solver is entered and
> **after** the dep×flag fixpoint converges. It reads the converged
> `active_flags` monotonically (never retracts). The check is therefore
> order-independent: the same union produces the same validation outcome
> regardless of member declaration order or BFS traversal order.

The conformance fixture `conformance/spec-v1/fixture-253-ws-cross-member-flag-conflict`
pins this behavior: member-a requests flag `async` and member-b requests
flag `sync` on the same shared dep `lib-net`, where `lib-net` declares
`async conflicts sync`. The workspace resolve raises `RESOLVE-FLAG-CONFLICT`
because the cross-member union produces `active_flags = {async, sync}` for
`lib-net`, triggering the conflict check.

> NOTE: The reference Python implementation adds `_s4c_check_flag_conflicts`
> after the workspace BFS completes, before the solve step in `resolve_workspace`
> (mirroring the identical call in single-package `resolve()`). The Rust
> reference implementation calls `provider.check_s4c_flag_conflicts(deps_dir)`
> at the same position in `seed_workspace` / `resolve_workspace`. Both impls
> read `dep_active_flags` which already stores the cross-member union at this
> point, so no additional union step is required.

---

## 13  Attestation policy

The resolver classifies each named dep's edge source as one of:

- **`MilpaKdl`** — dep declared in `milpa.kdl` with an explicit URL (no index lookup).
- **`DepDecl`** — dep resolved via a `dep_decl` pointer in the tianguis index entry.
- **`NimbleFallback`** — dep resolved from the `.nimble` metadata embedded in the
  tianguis index entry, with no `dep_decl` attestation.

Attestation policy governs how the resolver handles `NimbleFallback` deps.

### 13.1  Effective policy

> NORMATIVE: The **effective attestation policy** for a resolve invocation is the
> logical OR of the following three sources:
>
> 1. The manifest `attestation-policy` field equals `"strict"` (see
>    `spec/manifest-grammar.md` §attestation-policy). For a **workspace resolve**,
>    source 1 is active when **any** workspace member's package manifest declares
>    `attestation-policy "strict"` — the OR is taken across all members (a workspace
>    is strict if any member is strict).
> 2. The `--require-attested-metadata` CLI flag is present.
> 3. The `MILPA_REQUIRE_ATTESTED_METADATA` environment variable is set to a
>    non-empty value that is not `"0"` or `"false"`.
>
> A `"strict"` policy derived from the manifest CANNOT be weakened by the other
> two sources; they can only add strictness. The effective policy is therefore
> `strict` if any of the three sources is active, and `permissive` otherwise.
>
> **Workspace note:** Sources 2 and 3 (flag and env-var) apply equally to
> workspace and single-package resolves. An implementation MUST NOT silently
> drop the flag or env-var when routing to the workspace resolve path.
> `enforce_attestation_policy` MUST be called after the workspace solve completes,
> exactly as for single-package mode.

### 13.2  Permissive policy (default)

> NORMATIVE: Under permissive policy, if one or more resolved named deps have
> `source == NimbleFallback`, the implementation MUST emit exactly one
> human-readable summary warning to stderr listing those deps by name. The
> warning MUST NOT cause the implementation to exit non-zero, and MUST NOT
> prevent any output file from being written. The exact format of the warning
> is non-normative.
>
> If no resolved named deps have `source == NimbleFallback`, no warning is
> emitted.

### 13.3  Strict policy

> NORMATIVE: Under strict policy, if one or more resolved named deps have
> `source == NimbleFallback`, the implementation MUST raise
> `RES-UNATTESTED-METADATA` and exit non-zero without writing any output files.
>
> If no resolved named deps have `source == NimbleFallback`, the invocation
> succeeds normally.

> NOTE: `MilpaKdl` and `DepDecl` deps are never subject to attestation policy
> enforcement — `MilpaKdl` deps are declared by the user directly in `milpa.kdl`
> (no index lookup), and `DepDecl` deps carry an explicit attestation pointer.
> Only `NimbleFallback` deps (index entries without a `dep_decl` pointer) trigger
> the policy.

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

## 14  Root satisfies its own name (standalone-root self-satisfaction)

A **standalone package is a workspace-of-one.** §11.5 establishes that a
workspace member is pre-registered as a candidate for its own name, and a
`NamedDep` whose name matches a member auto-coerces to that member's
candidate rather than being looked up in the tianguis index or fetched a
second time. This section establishes the identical rule for the
**non-workspace** (single-package) resolve path: the root itself is
pre-registered as a candidate for its own declared `name`, so that a
transitive dep's `requires "<root's own name>"` is satisfied by the root's
own working tree — never by fetching a second, distinct copy of that name.

Concrete motivation: a package `P` (e.g. a real-world case: the `name
"softlink"` root of the `softlink` project) has a transitive dep `D` (e.g. a
test-only dependency such as `proptest`) whose OWN manifest declares
`requires "P"` (or, concretely, `requires "softlink"`) — perhaps because
`D` is designed to be usable both standalone and as a component of `P`.
Without this rule, that transitive claim resolves as an ordinary named
dep: it is looked up in the tianguis index (or, if the root happens to
also have declared itself as a named/URL dep somewhere reachable, is
fetched again) — producing a SECOND, distinct copy of `P` in `_deps/`,
alongside the tree already under build. This is never correct: `P` is
already being built; a second copy is redundant at best and a
provenance/version inconsistency at worst.

### 14.1  Root self-candidate registration

> NORMATIVE: When resolving a standalone (non-workspace) manifest, a
> conformant implementation MUST pre-register the root itself as a
> candidate for its own declared `name`, using the same declared-version
> precedence as §3 Axis A / §11.5's member block (`milpa.kdl version`,
> else `.nimble version` found in the root's own project directory, else
> the version-unknown sentinel `0.0.1`). This candidate:
>
> - carries the root's own `src_dir` and declared version;
> - carries NO outgoing dep terms of its own — the root's own `deps`/
>   `dev-deps` are already fully represented by the ordinary root-BFS seed
>   (§4.2.1); registering them a second time on this candidate would be
>   redundant, not incremental;
> - is never fetched, never staged into the CAS, and never subject to
>   Phase B content-hash dedup (identical treatment to a workspace member,
>   §11.5, which is likewise pre-registered rather than fetched).

### 14.2  Suppression of transitive claims on the root's own name

> NORMATIVE: The root's own declared `name` MUST be bound as a **root claim**
> (§10.1/§10.4) for a standalone resolve, exactly as a workspace member's
> name is a root claim for a workspace resolve. Any transitive claim on that
> name — whether a `named` (registry-style) claim, or a self-declared
> `git=`/`tarball=`/`local=` claim — MUST be suppressed by the same
> binding-phase arbitration that suppresses any other transitive claim
> disagreeing with a root binding (§10.1's `LOST_TO_ROOT` outcome): it MUST
> NOT be fetched, MUST NOT be looked up in the tianguis index, and MUST NOT
> affect resolution. The root's own pre-registered candidate (§14.1) is the
> sole candidate for that name.

### 14.3  Version-constraint validation

> NORMATIVE: When a transitive `NamedDep` claim on the root's own name
> carries an explicit version constraint (e.g. `requires "P >= 2.0.0"`),
> the implementation MUST validate that constraint against the root's own
> candidate-label version (§14.1) BEFORE suppressing the claim. If the
> root's own version does not satisfy the constraint, the implementation
> MUST raise `RES-ROOT-SELF-VERSION-CONSTRAINT` — it MUST NOT silently
> discard the constraint (the consumer's `>= 2.0.0` is a real requirement
> that the resolver is not free to ignore just because the target
> happens to be the root) and MUST NOT fetch an unrelated second copy of
> the name to satisfy it. This mirrors `RES-WS-MEMBER-VERSION-CONSTRAINT`
> (§11.5) exactly, with the root's own candidate in place of the member's.
>
> This check is performed once, at the first transitive claim on the
> root's own name (mirroring the workspace member check, which is
> likewise performed once per auto-coerced `NamedDep` occurrence, not
> re-validated against every subsequent consumer). A second, later
> transitive consumer with an even stricter, unsatisfiable constraint is
> still caught — but as an ordinary `SOLVE-CONFLICT` from PubGrub's own
> constraint accumulation over the root's single candidate, not as this
> dedicated diagnostic. Both outcomes are correct (the build never
> silently succeeds against a version the root does not carry); only the
> diagnostic's specificity differs.

### 14.4  Ordinary case is unaffected

> NORMATIVE: When no transitive dep ever requires the root's own name,
> the root's self-candidate (§14.1) MUST NOT appear in the resolved
> graph — it is never selected by the solver (no term ever names it), so
> `ResolvedGraph.deps` is byte-identical to a resolve of the same manifest
> under a spec version that lacks this rule. This rule is purely additive:
> it only changes behavior for the (previously either erroneous or
> workaround-requiring) self-referential case.

### 14.5  Lockfile representation

> NORMATIVE: When the root's self-candidate IS selected (§14.1–§14.3), its
> `ResolvedDep` entry uses a distinct `root` provenance kind (`name` field
> only) — NOT the `member` kind (§4.4 of `lockfile-schema.md`), because
> `member` is workspace-scoped (its `_deps/<name>` symlink convention and
> its `FROZEN-MEMBER-DEP` single-package rejection both presuppose a
> workspace context that does not exist here). `root` is identity-bearing
> in name only: its lockfile `identity` field is `None` (mirroring the
> synthetic root-of-solve node, which also carries no separate identity)
> — the standalone project root is not an isolated, independently-hashed
> tree the way a fetched dep or a workspace member's own directory is (it
> typically also contains `_deps/`, `milpa.lock`, and other resolver-
> owned artifacts that must not be folded into a content hash).
>
> `nim.cfg` emission MUST NOT emit a `--path:` line for the root's own
> `root`-kind entry — the root's own source directory is already emitted
> as the (always-first) self-`src_dir` path line (`lockfile-schema.md`
> §7.1/§7.4); a second `--path:"_deps/<name>"` line would point at a
> directory that does not exist (the root's tree is never staged into
> `_deps/`).

> NOTE: The reference implementation is in `resolve()` in `resolver.py`.
> The root's self-candidate is built once, alongside the synthetic
> `__root__` node, via the same `_member_candidate_version`-style
> precedence helper §11.5 already uses for workspace members
> (`_root_self_candidate_version`, a thin standalone-manifest-dir variant
> of `_member_candidate_version`). Suppression (§14.2) is achieved by
> pre-registering the root's own name as a **root claim** bound to a
> `MemberSourceId(member_name=<root's own name>)` self-reference (§10.4) —
> the standalone analog of a workspace member's self-claim, and the same
> `kind "member"` on-disk representation (`spec/lockfile-schema.md` §3.10).
> The `BindingResolver` arbitration path (§10.1) then suppresses any
> subsequent transitive claim on that name via the ordinary `LOST_TO_ROOT`
> outcome, with no root-name-specific gate logic (this repeals and replaces
> the prior `provenance_gate`/`_check_provenance_gate` side-table this NOTE
> used to describe — §10). The version check (§14.3) is a small, explicit,
> early check inline in the shared `_run_bfs_wave_loop`'s `"named"` BFS-item
> branch, gated on an optional `root_self_name`/`root_self_version` pair
> threaded through that function (and `_s4a_run_fixpoint`) — `None` by
> default, so `resolve_workspace` (which does not pass them) is entirely
> unaffected.

> NOTE (known gap, out of scope for this rule): the same *mechanism* —
> suppressing a THIRD-PARTY transitive dep's claim on a workspace member's
> own name and validating its version constraint — is not currently wired
> for the workspace path the way §14.2/§14.3 wire it for the standalone
> path. §11.5's existing auto-coerce only covers a `NamedDep` declared
> directly on ANOTHER workspace member's own `deps`/`dev-deps` list; a
> transitive dep fetched from outside the workspace (analogous to
> `proptest` in this section's motivating example) that itself requires a
> member's name currently resolves via the ordinary registry path and
> fails with `TNG-NOT-FOUND` if that name is not a real index entry. This
> is a pre-existing gap, not introduced or widened by this section, and
> is left for separate follow-up.

---

## Appendix A  Error codes referenced by this document

All codes are defined in `spec/errors.md`.

| Code | Condition |
|---|---|
| `SOLVE-CONFLICT` | No solution exists; failure refutation emitted |
| `FROZEN-STRATEGY-MISMATCH` | `--frozen` lockfile strategy ≠ requested strategy (§7.1 #1) |
| `FROZEN-MANIFEST-DEP-NOT-IN-LOCK` | Manifest dep has no lockfile entry (§7.1 #2) |
| `FROZEN-LOCKED-VERSION-UNPARSEABLE` | Locked version string is not a valid semver (§7.1 #3) |
| `FROZEN-CONSTRAINT-UNSATISFIED` | Locked version no longer satisfies named dep constraint (§7.1 #4) |
| `FROZEN-IDENTITY-NOT-IN-STORE` | Dep identity absent from CAS (§7.1 #5) |
| `FROZEN-LOCAL-DEP` | Editable local dep cannot use frozen path (§7.1 #6) |
| `FROZEN-MEMBER-DEP` | Workspace member dep cannot use frozen path in single-package context (§7.1 #7) |
| `FROZEN-MEMBER-NOT-IN-WORKSPACE` | Lockfile references member not present in workspace (§7.1 #8) |
| `FROZEN-MEMBER-IDENTITY-DRIFT` | Member on-disk hash differs from lockfile pin (§7.1 #9) |
| `FROZEN-EXCLUDE-NEWER-MISMATCH` | `--frozen` lockfile `exclude_newer` ≠ manifest's effective `resolution { exclude-newer }` (§7.1 #10) |
| `FROZEN-REGISTRY-ALIAS-UNRESOLVED` | Locked `source { kind "registry" }` names a registry alias this machine doesn't recognize (§7.1 #11) |
| `FROZEN-SOURCE-ID-MISMATCH` | Declared origin (post-override) ≠ locked `source_id` (§7.1 #12) |
| `FETCH-ALL-FAILED` | Every mirror candidate failed (network error or identity mismatch) (§8a) |
| `RES-BINDING-CONFLICT` | Two transitive claims disagree on a `DepKey`'s origin and no root claim arbitrates (§10.1, supersedes `RES-PROVENANCE-CONFLICT`) |
| `RES-REGISTRY-SHADOW` | A transitive `git=`/`tarball=`/`oci=` claim shadows a registry-owned coordinate with no comparable upstream match (§10.5) |
| `RES-DEAD-OVERRIDE` | An `overrides {}` entry names a dep absent from the resolved graph (§10.1) |
| `RES-IMPORT-COLLISION` | Two distinct source-ids export the same Nim import symbol (§4.6 of `rfc-origin-as-identity.md`) |
| `SRC-ID-MALFORMED` | A raw origin fails `SourceId` well-formedness (registry/namespace/subpath validation) |
| `MAN-PREDICATE-MIXED-NEGATION` | Predicate mixes negated and non-negated values (manifest-grammar §6) |
| `RES-UNATTESTED-METADATA` | Strict policy: ≥1 named dep resolved from un-attested `.nimble` metadata (§13.3) |
| `RES-ROOT-SELF-VERSION-CONSTRAINT` | Standalone root's own version does not satisfy a transitive's constraint on the root's own name (§14.3) |
