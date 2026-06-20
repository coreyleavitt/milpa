# RFC: Features, optional deps, and patch (Cargo-style per-dep knobs)

- **Issue:** #23 (Per-dep features / optional / patch)
- **Status:** Draft — Stage 2 **complete** (architect rounds 1 + 2 applied).
  Ready for Stage 3 (`/tdd` slice grind). No open forks.
- **Scope (decided 2026-06-15):** all three knobs — features **+** optional **+** patch.
- **Companion / prior art in-repo:** #26 (flags + `flag` predicate, shipped),
  #50 (`overrides`, shipped), #42 (local provenance, shipped), #25 (workspace
  members, shipped), #110 (universal-lockfile scope — *separate question, see §6*).

## 1. Summary

Add three Cargo-/npm-style per-dependency knobs to milpa:

1. **Features** — select-into optional capabilities a dependency exposes; the
   selection propagates (with union semantics) through the dep graph.
2. **Optional deps** — a dependency present only when a feature enables it,
   enabling minimal builds.
3. **Patch** — replace a (possibly transitive) dependency's *source* with a
   local checkout, fork, or workspace member without editing the dep that
   requires it.

**The thesis of this RFC: these are not three new subsystems. They are three
extensions to mechanisms milpa already ships.** Honoring single-source-of-truth
(milpa non-negotiable), each knob is built by deepening an existing module, not
by adding a parallel one:

| Knob | Built on | Extension |
|---|---|---|
| Features | `flags` block + `flag` predicate (#26) | flag→flag/flag→dep implication (`enables`) + cross-package activation + **unification** |
| Optional | the `flag` predicate (#26) | `optional` property as sugar that auto-declares a same-named flag gating the dep |
| Patch | `overrides` block (#50) | accept `local=` / `member` provenance targets, not just git→git |

## 2. Background — what already exists

milpa already has most of a feature system. Establishing the exact starting
point is load-bearing for the "extend, don't duplicate" argument.

### 2.1 Flags (`spec/manifest-grammar.md` §3.5)

The spec already calls these **feature flags**:

```kdl
flags {
    tls default=#false description="enable BearSSL TLS" {
        defines "ssl" "useOpenSSL"   // -d:ssl -d:useOpenSSL when active
    }
}
```

A flag is: a name + `default` (bool) + `description` + a `defines` child (Nim
`-d:` symbols emitted when active). Evaluated via the `flag` **predicate**
(`Predicate(name="flag", values=(...), negated=bool)`,
`impls/python/milpa/predicate.py:16`), which is satisfied when any named flag is
in the active-flag set (`resolver.py:_predicate_satisfied`, ~`:448`).

### 2.2 The active-flag set + root-level activation

`Profile.flags: frozenset[str]` (`profile.py:85`) carries the **root consumer's**
active flags. `_filter_manifest_by_profile` (`resolver.py:411`) seeds the active
set from default-true flags and **filters root deps pre-solver** by their
predicates. **Root-level flag gating already works today.** What does *not* exist
is (a) any per-*transitive*-dep active-flag set, (b) any flag→flag implication,
and (c) consistent transitive flag-gated edge filtering — see §2.6 for the
current cross-impl divergence the feature work must first close.

### 2.3 Cross-package flag requests (§3.6)

A dep block may already *request* a flag state on that dep:

```kdl
chronos git=(url)"..." ref="main" {
    flag "tls"          // enable chronos's tls flag
    flag "docs" #false  // a negative request on a default-true flag — see §3.1.3
}
```

Today this is parsed and recorded on `UrlDep` only (`manifest.py`,
`flag_requests` field). This RFC defines its **resolution semantics**
(activation + unification), which §3.6 deliberately left open, and extends the
field to `NamedDep` (§3.1.5).

### 2.4 Overrides (§3.4) — milpa's `[patch]`, git-only

```kdl
overrides {
    pkg "results" git=(url)"https://.../my-fork" ref="patched"
}
```

Root-authority only; applies project-wide (direct, transitive URL, named);
does **not** propagate to downstream consumers; changes provenance, not the
identity algorithm (`resolver.py` application points ~`:797`, ~`:1037`,
~`:1476`). This is structurally already Cargo `[patch]` — it just can't target
non-git provenance yet. `Override` is currently a **product type** (`name` +
mandatory `git` + `ref`) in both impls; §3.3 makes it a discriminated union.

### 2.5 Replacement targets: local (#42) and member (#25)

`LocalProvenance` (`fetchers/local.py:46`, `cas_admissible=False`,
identity-bearing **NO** per `spec/identity.md` §3.2) and
`MemberProvenanceRecord` (`lockfile.py:134`, identity-bearing **YES**,
`cas_admissible` **NO**) are the provenance kinds patch will let `overrides`
point at.

### 2.6 Existing transitive-edge divergence (must close before features)

The transitive edge projection is **not** flag-aware *and the two impls already
disagree*:

- **Python** `_manifest_to_edgeset` (`edge_sources.py:273`) projects **every**
  `manifest.deps` entry unconditionally — it ignores predicates entirely, so a
  flag-gated transitive edge is always admitted.
- **Rust** `build_edgeset_from_manifest` (`resolver.rs:~1408`) filters
  transitive deps by the transitive manifest's **own default-true flags** via
  `dep_passes_flag_predicates`.

So today a transitive `milpa.kdl` dep with a default-off flag-gated subdep
produces a *different `requires` array* across impls. The corpus does not yet
exercise this path, so the divergence is masked. **S2.5 (new) closes it before
any cross-package activation is wired** — otherwise every feature fixture risks a
byte-identity failure that is really this pre-existing bug.

## 3. Design

### 3.1 Part A — Features

A feature is a `flags` entry that can **enable** other flags, including flags on
a dependency. We add one child node, `enables`, to the existing flag grammar.

A flag node may carry **any combination** of three child kinds, with distinct
semantics (none required — a childless flag is a valid feature that has no
immediate effect and is meaningful only when enabled transitively):

- `defines "<sym>"…` — Nim `-d:` symbols emitted when the flag is active
  (existing).
- `enables …` — activates other flags when this flag is active (new, §3.1.1).
- `conflicts …` — declares flags that must not be co-active with this one (new,
  §3.1.4).

#### 3.1.1 The `enables` grammar — KDL-native, no embedded delimiters

Same-package flags are bare strings (already KDL identifiers); cross-package
activation uses a **child node whose name is the target dep** — milpa does not
invent a `"dep:flag"` sub-grammar inside an opaque string (that would force
milpa to own a delimiter the KDL parser never validates):

```kdl
flags {
    tls  default=#false { defines "ssl" }
    http default=#false
    full default=#false {
        enables "tls" "http" {          // same-package flags = bare string args
            chronos { flag "tls" }      // cross-package = child node (dep name),
                                        //   flag child = flag on that dep
        }
    }
}
```

- **One `enables` node carries both scopes.** A single `enables` node may have
  bare string *arguments* (same-package flags) **and** child nodes (cross-package
  `dep { flag }`) — KDL permits args + children on one node. Mixed-scope features
  therefore need exactly one `enables` node, not two. (Repeated `enables` nodes
  are still legal and union together, but the single-node form is canonical.)
- The cross-package child form is **structurally identical** to the existing
  §3.6 `dep { flag "x" }` request — the dep name is a parsed/validated KDL
  identifier, and error messages name the identifier ("unknown dep `chronos` in
  `enables`"), not a string half. It is the unified spelling of Cargo's
  `dep/feature`.
- **Diagnostic (normative).** When `MAN-FLAG-ENABLES-UNDECLARED` fires on a bare
  name that is *also a non-optional dep name* in the same manifest, the message
  must add: "`<name>` is a dependency, not a flag — add `optional=#true` to make
  it a feature." (The dual namespace, §3.2, makes this confusion likely.)
- **Name charset (normative).** Flag names and dep names that participate in
  `enables`/optional desugaring/predicates must match `[A-Za-z0-9_-]+`
  (the existing KDL bare-identifier charset already used for dep names). This is
  stated normatively in `spec/manifest-grammar.md §3.5` so `MAN-…` clash/charset
  errors are well-defined.
- **Validation order (normative).** `enables` bare-name validation is a
  **post-parse pass** over the fully-built `flags` table (mirroring the existing
  `MAN-FLAG-UNDECLARED-REFERENCE` check), not single-pass — so a forward
  reference to a flag declared later in the block is legal. A bare name with no
  matching declared flag raises `MAN-FLAG-ENABLES-UNDECLARED`.
- **Cross-package undeclared/absent targets (resolve-time, not manifest errors):**
  - dep absent from the resolved graph → resolve-time warning (the dep may be
    conditionally absent), recorded like an unsatisfied predicate.
  - dep present but the named flag is **not declared** by that dep (incl. the
    `.nimble`-sourced case, §3.5) → resolve-time **warn-and-ignore**
    (`RESOLVE-FLAG-UNKNOWN-ON-TARGET`, non-fatal). Rationale: the dep author
    owns its feature surface; a consumer naming a not-yet-declared feature must
    not hard-fail (the dep may add it later).

#### 3.1.2 Activation = a monotone closure interleaved with resolution

This is the algorithmic core. The active-flag set is **per-dependency** and held
in a resolver-scoped map `dep_active_flags`. This is a *new* structure — distinct
from `Profile.flags`, which remains the **root consumer's** requested set;
`dep_active_flags[D]` is the **computed** `active(D)` for transitive dep D.

**Keying (normative — closes the alias/dedup hole).** During BFS the map is keyed
by **resolved dep identity after override application**, not by the consumer-side
name, because milpa already collapses two names that hash-identically into one
canonical candidate (`_dedup_candidates` / `aliases_map`, `resolver.py:~1680`;
canonical = earliest in `discovery_order`). The activation rules therefore obey:
(a) a cross-package request/`enables` addressed to a name that is later aliased to
a canonical candidate routes its flags to the **canonical** key — `active(alias)`
is folded into `active(canonical)` during the same dedup pass via `aliases_map`,
never dropped; (b) because flag closure must be settled before a non-canonical
alias is discarded, the dep×flag fixpoint converges **before** the Phase-B dedup
pass collapses aliases; (c) the lockfile (§4) records the converged set under the
canonical name only. At convergence the flat `_deps/` invariant (one resolved
entry per name) makes the externally-visible map name-keyed, which is why
`LockedDep.active_flags` keys by name without ambiguity.

**Activation provenance (normative).** Each membership in `active(D)` has a
**source**: a flag default, a CLI `--features` request, an edge `D { flag "f" }`,
or an `enables` rule on some active flag. Both impls must track the source set per
activated flag (not merely the flag names) so that (a) `RESOLVE-FLAG-CONFLICT`
(§3.1.4) can name the two forcing consumers, and (b) a future `milpa features`
trace (§3.7) needs no re-resolution. The fixpoint is a monotone closure over this
*set of activation sources*; the flag-name set is its projection. Naming the
source enumeration explicitly removes the cross-impl divergence risk of each impl
inventing its own representation (the §2.6 pattern).
`active(D)` is the least fixpoint of:

```
active(D) ⊇ { f ∈ D.flags : f.default }                       (D's own defaults)
active(D) ⊇ { f : some active consumer C of D requests "f" on D }  (cross-package)
active(D) ⊇ enables-closure within D                          (flag→flag, same package)
```

where a consumer "requests f on D" via either a `D { flag "f" }` child or an
`enables { D { flag "f" } }` on any *active* flag of the consumer. Every rule
only *adds* to `active`, so the set is **monotone** over a finite universe (the
union of all declared flags); the fixpoint exists and is reached in finitely
many iterations, **independent of visitation order** (union is commutative —
this is what guarantees both impls emit the same `active_flags`).

**Termination (the full argument, not just "finite universe").** The combined
*(deps × flags)* fixpoint terminates because: (1) the dep-name set is bounded by
the transitive closure of unconditional **plus** optional deps reachable from the
root, which is finite — milpa has no dep cycles; (2) within each dep the flag set
is finite and declared statically in its manifest, so the flag universe is the
finite union of those declarations over the (finite) reachable dep set; (3)
`enables`-cycles *within* a package (flag `a` enables `b`, `b` enables `a`) are
absorbed by the same-package closure (S2) and terminate at the first pass that
adds no new flag. Both the dep set and each `active(D)` are monotone-growing over
finite domains, so the outer loop reaches a fixed point in
O(|deps| × max_flags_per_dep) iterations.

Activation is **interleaved with the BFS dep-discovery wave**: enabling a feature
can pull in a new optional dep (§3.2), whose own manifest may declare flags and
requests, which can enable further features. The resolver runs a combined
fixpoint over *(discovered deps × active flags)*: each wave (a) computes
flag-closure given the deps known so far, (b) admits any newly flag-gated edges,
(c) discovers their manifests, repeating until **neither set grows**.

**Where the fixpoint lives, and the sealed-edge invariant.** Flag-gated dep
filtering happens **before** `EdgeSet` construction — the EdgeSet is built from
the surviving (flag-clean) dep list, so the existing *sealed-once* `edge_cache`
invariant (`edge_sources.py`) is **preserved**, not broken. The outer fixpoint
iterates at the *dep-list / active-flag* level around `_run_bfs_wave_loop`
(Python) / `process_items` (Rust), not inside EdgeSet memoization. An EdgeSet is
still sealed immutably once built; what changes is which deps reach construction.

**PubGrub runs exactly once, after the dep×flag fixpoint fully converges.** The
BFS waves discover packages and flags; the solver is not entered until
convergence. This is the model the current single-shot solver
(`solver.py`, no conflict-driven backjumping) supports without a
restart/continuation API. Feature activation only ever *adds* solver terms; it
is a pre-solver / edge-admission concern, never interleaved with
unit-propagation.

> **Known limitation — feature-conditional version constraints.** A flag that
> gates a *named* dep carrying a version constraint (e.g. an optional `D >= 2.0`)
> can, in principle, introduce an incompatibility with an already-discovered
> constraint on `D`. Because the current solver errors on first conflict rather
> than backjumping, such a case surfaces as a `SolverError`, not a backtrack.
> This is low-frequency in Nim's URL-dep-dominated ecosystem (URL deps do not
> version-select) and is **not** regressed by this RFC — the batch-solve model
> means the solver simply sees the fully-activated term set. Conflict-driven
> backjumping is out of scope (tracked separately under `rfc-beyond-pubgrub`).

#### 3.1.3 Unification, opt-out, and exclusion — two intents, not one symbol

If two parts of the graph request different feature sets of the same dep D, D is
resolved **once** with the **union** of the requested features (Cargo's rule).
Union is forced by monotonicity: there is no sound way to resolve D twice with
different feature sets in a single flat `_deps/` tree, and additivity is the only
choice that keeps activation a fixpoint rather than an oscillation.

A naïve design overloads `flag "x" #false` to carry two genuinely different
intents — "I don't *need* x" (minimization) and "x is *incorrect* here"
(incompatibility). Cargo collapses both into absence-of-request and so cannot
express the second (its well-known mutual-exclusion gap); the inverse
(assertion-always) makes slim builds impossible. milpa keeps them **separate**,
which satisfies both of milpa's standing values (composability **and**
surface-don't-hide) without a trade:

- **Opt-out (`flag "x" #false`, and root/CLI `--no-default-features`, §3.4)** is
  **absence-of-request**: *this edge* does not request x. Union still applies —
  x is active iff some *other* active edge or a non-suppressed default requests
  it. This preserves the monotone fixpoint and makes per-edge opt-out /
  `--no-default-features` actually work. It is never, by itself, an error.

- **Exclusion (`conflicts`, §3.1.4)** is a first-class declaration that two flags
  **cannot be co-active**. It is checked as a **post-fixpoint validation pass**
  over the converged active set: if union forced both on,
  raise `RESOLVE-FLAG-CONFLICT`. Because the pass only *reads* the final state
  and never retracts, monotonicity is untouched and the check is
  order-independent (both impls see the same converged set).

So `RESOLVE-FLAG-CONFLICT` is **scoped to declared incompatibility**, not to
every opt-out — the error now denotes a real, author-declared contradiction the
user must resolve. This also gives milpa **mutually-exclusive features**, which
Cargo lacks (un-defers the §9 item).

> Forward note (does not block this RFC): a future universal lockfile (#110)
> could instead record flag-gated edges as annotations so any feature selection
> reconstructs from one lock. That is a lockfile-shape decision, orthogonal to
> the activation semantics defined here. See §6.

#### 3.1.4 Exclusion (`conflicts`) — mutually-exclusive features

A flag may declare **same-package** flags it cannot be co-active with, using bare
strings (KDL-native, validated post-parse like `enables`):

```kdl
flags {
    openssl default=#false { defines "ssl" "useOpenSSL" }
    bearssl default=#false { defines "ssl" }
    openssl { conflicts "bearssl" }     // the two TLS backends are mutually exclusive
}
```

- **Scope: same-package only in v1.** A flag's `conflicts` names other flags *in
  the same manifest*. This covers the motivating case (a library's mutually
  exclusive backends) cleanly, with a sound authority model (a package author
  declares incompatibilities among features they own). Cross-package `conflicts`
  (one package asserting an incompatibility about a flag it does not own) has a
  murky authority model and a different absent-dep semantic; it is **deferred to a
  follow-on issue** (file at Stage 3 start), and the same `conflicts { dep { … } }`
  child grammar can be added later without a breaking change.
- **Symmetric.** `openssl conflicts bearssl` ≡ `bearssl conflicts openssl`;
  declare once. Undeclared bare name → `MAN-FLAG-CONFLICTS-UNDECLARED` (post-parse).
- **Check algorithm (normative).** A **post-fixpoint validation** over each
  converged `active(D)`: *for each dep D, for each flag `f ∈ active(D)`, for each
  `g` in `f.conflicts`: if `g ∈ active(D)`, raise `RESOLVE-FLAG-CONFLICT`.* The
  pass only *reads* the converged set and never retracts, so monotonicity is
  untouched and the check is order-independent (both impls see the same set). This
  is the **only** source of `RESOLVE-FLAG-CONFLICT`; opt-out (§3.1.3) never raises it.
- **Checked, never pruned.** milpa surfaces the conflict rather than silently
  turning one flag off (which would be non-monotone *and* would hide the
  author-declared incompatibility).
- **Error payload (normative — actionable without `--why-flag`).**
  `RESOLVE-FLAG-CONFLICT` carries `{dep, flag_a, flag_b, sources_a, sources_b}`
  where `sources_*` are the activation sources (§3.1.2) that forced each flag on
  (the requesting consumers / enabling flags / CLI / default). Without the two
  source lists the user cannot locate the cause in a non-trivial graph, so this
  payload is required, not optional polish.

#### 3.1.5 `flag` requests on named deps

Cross-package requests today live only on `UrlDep.flag_requests`. `NamedDep`
gains the same field so `chronos { flag "tls" }` works whether `chronos` is a
URL or a registry-named dep. (S3 deliverable.)

### 3.2 Part B — Optional deps

```kdl
deps {
    chronos git=(url)"..." ref="main" optional=#true
}
```

`optional=#true` is **pure sugar** with a precise **parse-time** desugaring (the
output of `parse_manifest` is already desugared — both impls desugar identically
at parse time so the `MAN-DEP-OPTIONAL-FLAG-CLASH` error fires at the same
pipeline stage cross-impl):

1. Auto-declare a flag whose name is the dep's name (`chronos`), `default=#false`.
2. Gate the dep with the predicate `flag="<depname>"`.

**Collision rules (all parse-time, all normative):**

- The dep name must be a valid flag name (§3.1.1 charset) — else
  `MAN-DEP-OPTIONAL-INVALID-NAME` (distinct slug: a charset failure has a
  different message and fix than a collision).
- If a flag of that name is already declared → `MAN-DEP-OPTIONAL-FLAG-CLASH`.
- If the dep *also* carries an explicit `flag="<depname>"` predicate (manual gate
  duplicating the auto-gate) → the duplicate is collapsed (idempotent), not an
  error; any *other* explicit `flag` predicate composes normally.
- **Namespace hygiene (normative):** because optional fuses the dep and flag
  namespaces, the parser validates that **no non-optional dep shares a name with
  any declared flag** either — surfacing latent confusion, not just the optional
  case.

Consequences fall out of Part A for free: the dep is absent unless its flag is
enabled — directly (`flags { chronos default=#true }`), by an `enables`, by a
cross-package request, or (Cargo parity) by *another feature of the same name*.
Cargo's "an optional dep implicitly defines a feature of the same name" is
exactly this desugaring. `optional=#false` is the default and a no-op.

Activation of optional deps is **resolve-time** per §3.1.2, so optional deps
**prune** (a disabled optional dep is never added as a solver term and never
fetched) — this is the whole point (minimal builds) and it works without #110.

**Presence vs. feature-request (normative — two distinct "absences").** An
optional dep D is **present iff D's auto-flag is in the converged `active` set**
at fixpoint convergence — *not* at any intermediate iteration. The "never fetched"
guarantee is a property of the converged state: an early iteration may not yet
have activated D's flag, but a later `enables` can, and that is not a violation.
Two absences must not be conflated: (a) **dep absent** — D is in no resolved edge
(pruned, never fetched); (b) **feature not requested** — D *is* present (some
*other* unconditional edge requires it) but this consumer did not request D's
optional feature. In case (b) D is fetched regardless, and `active(D)` still
accumulates the union of *all* requesters' flags (§3.1.3) — a consumer's opt-out
of the optional feature does not subtract flags another active edge requested.
The `enables`-target absent-warning (§3.1.1) keys on case (a) only.

**dev-deps (normative).** `optional` and feature requests are permitted on
`dev-deps` and behave identically to regular deps; dev-deps are already root-only
(not part of any downstream transitive closure), so no separate
feature-unification rule is needed.

> **Weak activation deferred (#TBD — file at Stage 3 start).** Cargo's
> `dep?/feature` (enable a feature on an optional dep *only if* the dep is
> already present, without pulling it in) is **not** modeled in v1. Plain
> `enables { chronos { flag "tls" } }` is the **strong** form: it activates
> chronos (matching Cargo's strong `dep/feature`). The chosen child-node grammar
> (§3.1.1) accommodates a future weak marker (e.g. `chronos?`) **without a
> breaking change**, so deferral is safe. Authors who want minimal builds simply
> do not write a strong `enables` for a dep they don't want pulled in.

### 3.3 Part C — Patch

Extend `overrides` `pkg` rules to accept the same provenance forms milpa already
parses for deps, not just `git=`/`ref=`. **`Override` becomes a discriminated
union** (`name` + exactly one of `GitTarget | LocalTarget | MemberTarget`) in
both impls — a real type-system change from today's product type (§2.4), not a
field addition; it is the load-bearing S7 seam.

```kdl
overrides {
    pkg "results" local="../results-fork"      // → LocalProvenance
    pkg "stew"    { member "stew" }            // → workspace member
    pkg "chronos" git=(url)"..." ref="patched" // existing git form, unchanged
}
```

- **Exactly one** provenance form per `pkg` rule. Mixed/≠1 forms raise
  `MAN-OVERRIDE-TARGET-AMBIGUOUS` (new); the existing git-arity errors are
  unchanged for the git form.
- **Identity follows the target's kind** (the two-axis model, `identity.md`
  §3.2): a `local=` patch is liveness-only / not identity-bearing / not
  CAS-admissible; a `member` patch is identity-bearing + drift-detected + not
  CAS-admissible; a `git=` patch is identity-bearing + CAS-admissible. No new
  identity rules — patch just routes to an existing provenance's rules.
- **Feature surface follows the patch target (normative).** When a dep is
  overridden, its `flags {}` / `enables` / `conflicts` surface comes from the
  **override target's** manifest, not the original dep's — the BFS wave fetches the
  manifest from wherever the dep is sourced. A consumer's `dep { flag "x" }`
  request against a flag the *patched* version does not declare is
  `RESOLVE-FLAG-UNKNOWN-ON-TARGET` (warn-and-ignore, §3.1.1), exactly as for any
  other not-yet-declared flag.
- **Active flags do not change identity (normative).** `active_flags` are a build
  configuration (compiler `-d:` symbols), not source bytes; the same dep resolved
  with different `active_flags` has the **same `content_hash`** and the **same CAS
  key** (`identity.md` §3.2 — the hash covers the source tree, not the build
  config). There is no per-feature-set CAS fan-out.
- **Reproducibility carve-out (normative).** A `local=` patch makes the
  resolution **non-reproducible for anyone without the same sibling checkout at
  the same relative path** (the inherent #42 limitation). Therefore: (a) the lock
  records no `identity` for a `local=` patch; (b) `milpa` emits a
  non-reproducible-override warning at lock time; (c) under `--frozen`, a
  `local=` override is an **error via the existing `FROZEN-LOCAL-DEP` slug** — a
  `local=` patch resolves to a `LocalProvenanceRecord`, which the frozen path
  already rejects with `FROZEN-LOCAL-DEP`. No new slug (SSOT). `git=`/`member`
  patches remain reproducible (member within a workspace checkout).
- **Security boundary unchanged:** root-authority only; transitive `overrides`
  ignored (`resolver-semantics.md` §10.2). A patch can repoint a *transitive*
  dep, but only the *root* manifest may declare the patch.
- **Application points:** the **four** existing override interception sites
  (`resolver.py` ~`:797` BFS loop, ~`:1037` root-seed URL, ~`:1050` root-seed
  named, ~`:1483` `_enqueue_dep`) construct `LocalDep`/`MemberDep` (routing to
  `_process_local_worker` / the member path) instead of always rewriting to
  `UrlDep`. **`member` override requires the workspace resolver
  path** (the single-package member-resolution path is currently a no-op) — so
  `member` patch is sliced separately (S8b) and exercised only against workspace
  fixtures; `local=` patch (S8a) needs no workspace.

This makes `overrides` milpa's full `[patch]`: replace any dep's source with any
provenance kind, from root authority, without editing the requirer. *(Considered
and rejected: a separate `replace`/`develop` block à la Cargo's `[patch]` vs.
`[replace]`. SSOT wins — one block, with the reproducibility distinction carried
by the carve-out above rather than by parallel grammar.)*

## 3.4 CLI surface (feature selection)

Features are a **resolve-time input** (§6), so they must be injectable without
editing `milpa.kdl`. `ResolveParams` (`context.py`) gains
`features: frozenset[str]` and `no_default_features: bool` / `all_features: bool`;
`cli.py` (`cmd_fetch`, `cmd_lock`, `cmd_update`) gain Cargo-parity flags, spelled
in `spec/cli-contract.md`:

- `--features <comma-list>` — additional flags to activate on the **root**.
  **Root-level only (normative):** `--features` names flags the root manifest
  declares; it cannot directly name a transitive dep's flag. To activate a flag on
  a transitive dep without editing per-resolve, declare an
  `enables { dep { flag "x" } }` on a root flag and select that root flag. (This
  is Cargo's actual position too; stating it prevents a false sense of
  completeness.)
- `--no-default-features` (normative semantics, stated inline — the former Fork 1
  is dissolved, §8): suppress the implicit activation of the **root** manifest's
  `default=#true` flags only (not transitives'). The request then starts from a
  zero-default root baseline and is purely additive via `--features`. Per §3.1.3
  this is **absence-of-request**, never an error by itself; a default-true flag
  still activates if another active edge requests it.
- `--all-features` — activate every flag the root manifest declares.

`--frozen` interaction (normative, `resolver-semantics.md §8`): under `--frozen`,
milpa recomputes the active closure from the **current manifest + the CLI feature
inputs supplied now** and compares it to the lockfile's stored `active_flags` (the
same check as §4). A mismatch is an **error** (the lock cannot satisfy a different
request), exactly like a version mismatch. No CLI-selection field is added to the
lockfile: the user supplies the inputs at frozen-check time, so the comparison is
computed-closure vs. stored-result and needs no record of the *prior* inputs.

## 3.5 `.nimble` interaction

- **Declaring side:** a `.nimble`-only dep cannot declare features (strict
  superset; documented, not an error — features originate only from `milpa.kdl`).
- **Consuming side:** a `milpa.kdl` consumer may *request* a flag on a
  `.nimble`-sourced dep (`chronos { flag "tls" }`). Since that dep declares no
  `flags {}`, the request is **warn-and-ignore** at resolve time
  (`RESOLVE-FLAG-UNKNOWN-ON-TARGET`, §3.1.1) — never a hard failure. chronos is
  milpa's primary real-world dep and is `.nimble`-sourced, so this path is on the
  integration critical path.

## 3.6 nim.cfg emission (un-defers spec §7.5)

`nimcfg.py:91` currently carries `# §7.5 … DEFERRED (#23)` — **this RFC is #23
and owns it.** §9's prior claim of "no change" was wrong: today nim.cfg emits
**zero** `-d:` defines. Feature work must emit them:

- For each resolved dep, for each flag in `dep.active_flags`, emit that flag's
  `defines` symbols as `-d:` lines (a block separated from the `--path:` block
  by a blank line, per spec §7.4/§7.5 layout), lexicographically ordered for
  reproducibility.
- **Empty-`defines` convention (normative).** A flag with no explicit `defines`
  emits `-d:<pkg>_<flag>` (the convention already documented on `FlagDecl`,
  `manifest.py:331`). v1 adopts this convention so a childless feature is still
  observable in `nim.cfg`.
- **`defines` source = manifest, not lockfile (normative — SSOT).** The
  flag→defines mapping lives in the manifest's `flags {}` block; the lockfile
  records only `active_flags` (the flag *names*). nim.cfg is regenerated from
  *(manifest flags table + lock `active_flags`)*. Persisting `defines` in the lock
  would duplicate the manifest — rejected. **Consequence (documented, not a bug):**
  editing a flag's `defines` in the manifest correctly changes `nim.cfg` on the
  next emit *without* a re-`fetch`, because `defines` are compiler flags that do
  **not** affect dep identity (§3.3, content hash excludes build config). `milpa
  verify` checks `active_flags` membership, not `defines` content; this is in
  scope of verify's guarantee by design.
- **Emit-time seam (implementation note).** `emit_nim_cfg`'s current signature is
  `(graph, deps_dir)`; emitting defines needs the manifest's flag table, so S6
  threads the manifest (or a precomputed `flag_defines` map) into the emitter.
- A conformance fixture with non-empty `expected/nim.cfg` `-d:` lines is required
  (none exists today), including a childless-flag fixture exercising the
  `-d:<pkg>_<flag>` convention.

## 3.7 Mutating + inspecting subcommands

- `milpa add <dep> --optional` writes `optional=#true`; `milpa add <dep>
  --features a,b` writes `flag "a"`/`flag "b"` children (via `manifest_writer`).
  **Pre-write check:** `milpa add` must reject (before writing) a dep whose name
  would clash with an existing flag under the §3.2 namespace-hygiene rule — i.e.
  apply the parse-time `MAN-DEP-OPTIONAL-FLAG-CLASH` / `MAN-DEP-OPTIONAL-INVALID-NAME`
  checks at add-time so the writer never produces an unparseable manifest.
- `milpa remove <dep>` removes only the dep node. The optional auto-flag is a
  **parse-time** construct (§3.2) that never appears in the KDL file, so there is
  no phantom `flags {}` entry to clean up — confirmed explicitly to remove
  implementer ambiguity. `enables`/`conflicts` references to a removed optional dep
  become undeclared-target warnings on the next resolve (§3.1.1), not write errors.
- `milpa update <dep>` re-resolves with the **lockfile's** recorded
  `active_flags` (reproducibility), not all-features-off.
- `milpa show` prints per-dep `active_flags` (the field already exists on
  `LockedDep`) so a user can see *that* a transitive optional dep is present (the
  `cargo tree -e features` need).
- **`milpa features` (designed inspection surface, forward note).** The primary
  feature-debugging question is *why* a flag is active. The activation-source
  tracking (§3.1.2) makes a `milpa features` trace — per dep, each active flag and
  the source(s) that activated it — reconstructable. v1 ships `milpa show`'s flat
  listing; `milpa features` (and `show --why-flag`) is the named follow-on, with no
  lockfile-schema change required because sources are re-derivable from manifest +
  lock on demand. File alongside the cross-package-`conflicts` follow-on at Stage 3.
- `milpa verify` checks that the lockfile's `active_flags` per dep match the set
  the current manifest defaults + selection would compute; a mismatch exits
  non-zero (same class as a version-mismatch), so a defaults edit without a
  re-`fetch` is caught. (Scope: flag *membership*, not `defines` content — §3.6.)

## 3.8 Workspace feature unification (#25)

In a workspace, feature activation is **workspace-wide union**: `active(D)` is
the union of every member's requests on D (matching Cargo). `resolve_workspace`
solves the combined graph, so the per-dep map is shared. Consequences:

- `format_workspace_nimcfgs` emits, for each member, the `defines` of **all**
  flags active on shared deps in the workspace graph (not only that member's
  requests) — a shared dep is built once with the unified feature set.
- A workspace **root** manifest may carry a `flags {}` block whose activations
  apply workspace-wide (grammar addition: workspace manifest gains `flags`).

## 4. Lockfile & reproducibility

- **Selected features** are recorded in `LockedDep.active_flags`
  (`lockfile.py:238`, spec §3.6) as the authoritative **unified** per-dep set, so
  a re-resolve from the lock is byte-reproducible. Emitted only when non-empty;
  **lexicographically sorted** in both impls (Rust currently writes
  `Vec::new()` — S5 must sort).
- **Reproducibility scope (normative):** "byte-reproducible" holds **except** for
  `local=` patches (§3.3 carve-out), which are development-only and inherently
  path-dependent.
- **Lockfile migration / stale flags (normative).** The frozen check recomputes
  the active closure from **the current manifest + the CLI feature inputs supplied
  now** (the same fixpoint used at resolve time) and compares it to the stored
  `active_flags`. It must **not** re-derive from the *stored* flags — that is
  circular (a deterministic fixpoint of the stored set reproduces the stored set,
  so a pre-RFC lock with empty `active_flags` would pass vacuously even when the
  manifest now activates flags). A pre-RFC lock (empty/partial `active_flags`)
  therefore correctly fails the comparison against the freshly computed closure
  and exits non-zero with "lockfile stale, re-run `milpa fetch`" rather than
  silently emitting a different nim.cfg.
- **Optional pruning** needs no new field: a pruned optional dep is simply absent
  from the locked graph.
- **Patch** records the resolved provenance in the existing `provenance` block
  per target kind (git/local/member records already exist); a `local=` patch
  records no `identity`.

## 5. Cross-impl + conformance

Both reference impls implement this with **zero cross-impl byte-identity
divergence**, enforced by the shared `conformance/spec-v1/` corpus. Every slice
gate: `cd impls/python && uv run pytest` green **and** `./dev-rust test
--workspace` green, corpus divergences NONE.

**Highest divergence risks (from feasibility review), each pinned to a slice:**

1. **S2.5** — the pre-existing `_manifest_to_edgeset` (Python, no filter) vs.
   `build_edgeset_from_manifest` (Rust, default-flag filter) split (§2.6). Close
   *first*, with a transitive-flag-gated fixture, or every later feature fixture
   inherits the divergence.
2. **S4a** — fixpoint iteration order: convergence is order-independent by
   monotonicity (§3.1.2), but both impls must emit identical `active_flags`;
   union commutativity guarantees it — assert via a two-requester fixture.
3. **S4c** — `RESOLVE-FLAG-CONFLICT` must be detected at the same point
   (post-fixpoint, not eager) in both impls, and its `{dep, flag_a, flag_b,
   sources_a, sources_b}` payload (§3.1.4) must be byte-identical.
4. **S5** — `active_flags` lexicographic sort in both impls.

New error slugs — `MAN-FLAG-ENABLES-UNDECLARED`, `MAN-FLAG-CONFLICTS-UNDECLARED`,
`MAN-DEP-OPTIONAL-FLAG-CLASH`, `MAN-DEP-OPTIONAL-INVALID-NAME`,
`MAN-OVERRIDE-TARGET-AMBIGUOUS`, `RESOLVE-FLAG-UNKNOWN-ON-TARGET`,
`RESOLVE-FLAG-CONFLICT` (scoped to declared same-package exclusions, §3.1.4) —
require the 1:1 bijection sync across `spec/errors.md` ↔ Python `errors.py` ↔
Rust `all_codes()`, each introduced in the slice that first needs it. The
`local=`-under-`--frozen` case reuses the **existing** `FROZEN-LOCAL-DEP` slug
(no new slug — §3.3).

## 6. The #110 boundary (why this RFC does not block on it)

#110 asks whether milpa wants a **universal cross-platform lockfile** — one
resolution solved for all `platform`/`arch`/`nim` targets at once, with
target-varying conditionals recorded as annotations. That is about
**target-varying** predicates: the dep graph differs by *where you build*.

**Features are different in kind.** A feature selection is a **resolve-time
input**, fixed for a given resolution like the manifest itself — not a property
of the build target. There is no "resolve for all feature combinations" the way
there is "resolve for all platforms." Therefore feature/optional activation
belongs **inside this resolution** (§3.1.2), extending the existing root-level
pre-solver filter to transitive flag-gated edges, and is **independent of the
#110 decision**. The split — flag predicates activated now, platform/arch
predicates governed by #110 — falls on a real semantic seam (resolve-time-fixed
vs. target-varying), not an arbitrary one.

**Registry/tianguis note (#132):** a cross-package `flag` request on a
*registry-named* dep cannot be validated index-only — the dep's feature surface
lives in its `milpa.kdl`, fetched on resolution. This is a known semantic
incompleteness (fast index-only resolution can't pre-validate feature requests);
carrying feature metadata in the index/`DepDecl` artifact is deferred to #134.
Documented, not solved here.

(If #110 later makes the lockfile universal, features would simply join platform
as an annotated dimension; §3.1.3's forward note covers the shape. Nothing here
forecloses that.)

## 7. Stages → slices

Sequenced so each slice is independently testable and green in both impls before
the next. Patch (Part C) is independent of Features/Optional. CLI/nim.cfg/
subcommand/workspace surfaces are sliced explicitly (they were implicit in the
draft).

### Stage A — Features core
- **S1 — `enables` grammar.** Parse the `enables` node — bare same-package string
  args **and** cross-package `dep { flag }` children **on one node** (§3.1.1) — in
  both impls; add `enables` (and `conflicts`, §3.1.4) fields to `FlagDecl`; spec
  §3.5 addition; charset rule; **post-parse** `MAN-FLAG-ENABLES-UNDECLARED`
  validation incl. the dep-name diagnostic (§3.1.1). **Round-trip:** update
  `format_manifest` (Python `manifest.py:~1639` + Rust) so `enables`/`conflicts`
  serialize back losslessly — `milpa add/remove` round-trips through it. Manifest
  only, no resolution. Conformance: parse-accept + the new error + forward
  reference accepted + format round-trip identity.
- **S2 — same-package flag closure.** Monotone `enables` fixpoint over a
  manifest's own flags (no cross-package, no deps). Pure function; unit +
  conformance incl. cycles (idempotent).
- **S2.5 — align transitive edge filtering (divergence fix, §2.6).** Make Python
  `_manifest_to_edgeset` filter flag-predicated transitive deps by the dep's own
  default-true flags, matching Rust. Conformance: transitive `milpa.kdl` dep with
  a default-off flag-gated subdep — identical `requires` cross-impl.
- **S3 — cross-package request activation (direct deps).** Add `flag_requests`
  to `NamedDep` (§3.1.5); extend `EdgeSourceCtx` with a per-dep
  `active_flags: frozenset[str]`; introduce the `dep_active_flags` map (keyed by
  resolved identity, §3.1.2) carrying activation **sources**; wire §3.6
  `dep { flag }` and `enables { dep { flag } }` to activate flags within the
  target dep's resolution. **Single-hop only (the outer fixpoint arrives in
  S4a):** S3 fixtures are restricted to one requester → one target with no
  transitive chain; multi-hop fixtures land in S4a. State this in the fixture
  headers so the gap is intentional, not a latent bug.
- **S4a — interleaved dep×flag fixpoint loop. ⚠ LARGEST SLICE (~2–3× a normal
  grammar slice).** Wrap `_run_bfs_wave_loop` / `process_items` in the outer
  fixpoint (§3.1.2): iterate until `(deps ∪ active_flags)` stabilizes; newly
  flag-activated edges re-enter BFS; flag-filtering stays *before* EdgeSet
  construction (sealed-once preserved). The cost is not the loop but its state:
  `dep_active_flags` is mutable state shared between the outer loop and the
  per-wave parallel workers (thread-safety), and each iteration must diff
  *admitted-deps-before* vs *after* flag-closure to know which edges re-enter BFS.
  `discovery_order` accumulates across iterations (monotone — safe); `edge_cache`
  entries are never invalidated (new deps get new entries). Conformance: a feature
  transitively pulling an optional dep that declares further flags (multi-hop);
  single-consumer cases only. **Consider landing the thread-safe `dep_active_flags`
  container as a tiny precursor sub-slice before the loop refactor.**
- **S4b — unification + opt-out.** Union across multiple requesters (§3.1.3);
  `flag "x" #false` / `--no-default-features` as absence-of-request (monotone, no
  error). Conformance: union across two requesters; opt-out overridden by another
  edge (x stays on, no error).
- **S4c — exclusion (`conflicts`, same-package) + `RESOLVE-FLAG-CONFLICT`.** Parse
  `conflicts` bare names (grammar landed in S1; `MAN-FLAG-CONFLICTS-UNDECLARED`) +
  the post-fixpoint validation pass over the converged active set, with the
  `{dep, flag_a, flag_b, sources_a, sources_b}` payload (§3.1.4). **Same-package
  only** — cross-package `conflicts` is deferred (file the follow-on at Stage 3).
  Conformance: mutually-exclusive flags forced co-active → `RESOLVE-FLAG-CONFLICT`
  with both source lists populated; a satisfiable selection passes.
- **S5 — `active_flags` lockfile authority.** Record the unified per-dep set
  (sorted, both impls); re-resolve-from-lock reproducibility; stale-lock
  `--frozen` rule (§4). Parallelizable with S4 against a stub map.
- **S6 — nim.cfg `-d:` emission (un-defer §7.5).** Thread the manifest flag table
  into `emit_nim_cfg` (signature change, §3.6); emit `defines` for active flags,
  including the `-d:<pkg>_<flag>` childless-flag convention; first fixtures with
  `-d:` lines (explicit-defines + childless-convention).

### Stage B — Optional (sugar; depends on Stage A)
- **S7 — `optional` desugaring.** **Parse-time** desugar → auto-flag + `flag=`
  gate; full collision/charset/namespace rules (§3.2);
  `MAN-DEP-OPTIONAL-FLAG-CLASH`. Conformance: optional dep absent by default,
  present when enabled, **pruned (not fetched)** when off.

### Stage C — Patch (independent of A/B)
- **S8 — `Override` discriminated union + ambiguity error.** Restructure
  `Override` (product → sum) in both impls; parse `local=` / `member` / `git=`
  forms; `MAN-OVERRIDE-TARGET-AMBIGUOUS`; spec §3.4. Manifest-layer (the bulk of
  the type change lives here — ~1.5× a normal grammar slice). **Note: there are
  *four* override interception sites, not three** (verified): BFS-loop URL dep
  (`resolver.py:~797`), root-seed `UrlDep` branch (`~1037`), root-seed `NamedDep`
  branch (`~1050`), and `_enqueue_dep` (`~1483`, two sub-branches). All four must
  learn the `LocalTarget`/`MemberTarget` dispatch in S8a/S8b.
- **S8a — `local=` patch resolution + identity routing.** Apply local targets at
  the override interception sites; liveness-only identity; lock-time
  non-reproducible warning; `--frozen` error. Conformance: a transitive git dep
  repointed to a local fork.
- **S8b — `member` patch (workspace).** Apply member targets via the workspace
  resolver path; identity-bearing + drift-detected. Conformance: a transitive
  dep repointed to a workspace member (workspace fixture).

### Stage D — Surfaces
- **S9 — CLI feature selection.** `ResolveParams.features` + `--features` /
  `--no-default-features` / `--all-features`; `--frozen`+selection-mismatch
  error; `spec/cli-contract.md`. Conformance via `env` fixtures.
- **S10 — subcommand awareness.** `milpa add --optional/--features`,
  `milpa update` honoring locked `active_flags`, `milpa show` printing
  `active_flags`, `milpa verify` feature-mismatch check (§3.7).
- **S11 — workspace feature unification.** Workspace-wide union; workspace-root
  `flags {}`; per-member nim.cfg includes unified active defines (§3.8).

### Stage E — Hardening
- **S12 — property tests** (`rfc-property-based-testing.md` discipline). Hypothesis
  generators over random dep DAGs + flag requests asserting: (a) **union
  commutativity / order-independence** — `active(D)` is invariant to BFS
  visitation order; (b) **fixpoint idempotence** — running the closure twice is a
  no-op; (c) **prune completeness** — a dep whose auto-flag is inactive at
  convergence appears in neither `_deps/` nor the solver term set. Pin any
  counterexample as a regression test, then promote to a conformance fixture.
- **S13 — doc sync.** Update `docs/comparison-vs-nimble-atlas.md` (the
  features/optional/patch row — milpa now exceeds atlas: mutual exclusion,
  KDL-native grammar, fixpoint activation) and `docs/identity-and-provenance.md`
  (note that `active_flags` do not alter `content_hash`, §3.3).

## 8. Open forks (awaiting Corey)

**None.** The draft's apparent fork (negative-request semantics) was a false
dichotomy caused by overloading `flag "x" #false` with two distinct intents. It
is dissolved in §3.1.3–§3.1.4 by separating them — opt-out (absence-of-request,
monotone) vs. exclusion (`conflicts`, post-fixpoint validation). Both of milpa's
values are satisfied with no trade, and milpa gains mutually-exclusive features
(a Cargo gap). No design choice remains that the PhD-CS bar can't resolve.

### Resolved (recorded, not forks)
- Negative-request semantics: opt-out = absence-of-request (§3.1.3); exclusion =
  first-class `conflicts` (§3.1.4); `RESOLVE-FLAG-CONFLICT` scoped to declared
  exclusions only.
- Scope = all three knobs; naming stays `flags`/`flag`; #110 boundary (§6); the
  `enables`/`conflicts` KDL-native child grammar (§3.1.1/§3.1.4, replacing the
  draft's `"dep:flag"` string); patch stays in one `overrides` block (§3.3);
  optional desugars at parse time (§3.2); weak-dep activation deferred with a
  non-breaking grammar path (§3.2) — **file the weak-dep issue at Stage 3 start.**

### Round-2 design decisions (resolved, not forks — flag if you disagree)
- **`conflicts` is same-package-only in v1** (§3.1.4); cross-package `conflicts`
  deferred to a follow-on (murky authority model, different absent-dep semantics).
  Same-package covers the motivating openssl/bearssl case fully. **Heads-up:** you
  put the `conflicts` mechanism in scope last round — this trims its *cross-package*
  reach only; mutual exclusion within a package ships.
- **`enables` args+children on one node** (§3.1.1) — mixed-scope features need one
  node, not two.
- **`dep_active_flags` keyed by resolved identity**, alias-folded to canonical
  before lockfile write (§3.1.2); activation **sources** tracked for error payloads
  + future `milpa features`.
- **Frozen check = recompute-from-manifest+CLI vs stored** (§3.4/§4); no
  CLI-selection field added to the lockfile; `local=`-under-`--frozen` reuses
  `FROZEN-LOCAL-DEP` (no new slug).
- **`active_flags` never alter `content_hash`** (§3.3); **`defines` stay in the
  manifest, not the lock** (§3.6, SSOT); childless flag → `-d:<pkg>_<flag>`.
- Split `MAN-DEP-OPTIONAL-INVALID-NAME` from `MAN-DEP-OPTIONAL-FLAG-CLASH` (§3.2);
  dev-deps participate in features identically (§3.2).
- New hardening slices S12 (property tests) + S13 (doc sync); S4a flagged as the
  largest slice; S8 has four override interception sites.

## 9. Deferred / out of scope

- **Weak dependency activation** (`dep?/feature`) — §3.2; non-breaking to add
  later; file issue at Stage 3 start.
- **Cross-package `conflicts`** (`conflicts { dep { flag } }`) — §3.1.4; same
  `conflicts` grammar extends to it without a breaking change; deferred for the
  authority/absent-dep reasons above. File issue at Stage 3 start (alongside
  `milpa features` / `--why-flag` and the weak-dep issue).
- **#134** (DepDecl artifact schema carrying feature metadata): features
  originate from `milpa.kdl`, never from `.nimble`/DepDecl. A `.nimble`-only dep
  cannot declare features (strict superset; documented). Registry index feature
  metadata (§6) rides with #134.
- **#110** universal-lockfile decision (§6).
- **Conflict-driven backjumping** for feature-conditional version constraints
  (§3.1.2 known limitation) — `rfc-beyond-pubgrub`.
- ~~Mutually-exclusive feature sets~~ — **now modeled** via `conflicts` (§3.1.4),
  the mechanism that resolves the former Fork 1. A milpa differentiator vs Cargo.
