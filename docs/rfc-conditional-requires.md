# RFC: Conditional (`when`-gated) requires in `.nimble` files

- **Status:** Draft (**architecture rounds 1 + 2 applied; ready for `/tdd`**). R1 resolved **(c)**: #26 recognizes `when`, attaches predicates, and records them on a universal (platform-neutral) lockfile via an **additive `cond-require` node** — no host exclusion (the existing `requires` line is byte-identical); build-time *activation* deferred to **#110**. Round 2 replaced the overloaded-`requires` draft with the additive `cond-require` design (no re-lock churn), pinned the EdgeSet→lockfile predicate propagation, extracted `Predicate` to break an import cycle, and acknowledged the root-vs-transitive `when` semantic asymmetry.
- **Scope:** milpa spec (`dep-decl.md` §1 + §7.5, `manifest-grammar.md` §5.3 + §6, `resolver-semantics.md` transitive predicate filtering) + both reference impls (nimble scanner, edge types, resolver) + conformance corpus.
- **Milestone:** v1 Tier 2 (atlas parity — #26). Additive; no day-one breakage (unrecognized conditions keep today's over-include + warn behavior).
- **Closes:** #26. **Files (deferred):** DepDecl artifact schema v1 carrying predicates (cross-repo tianguis) — see §8 F3.
- **Reuses, does not duplicate:** the `Predicate(name, values, negated)` model and the `Profile`-based matcher already shipped for milpa.kdl `when` predicates (`manifest-grammar.md §6`; `_predicate_satisfied` / `predicate_satisfied`). There is ONE conditional-dep system in milpa; this RFC routes `.nimble` `when` blocks into it.

## 1  Summary

A `.nimble` file is NimScript and may gate `requires` on compile-time conditions:

```nim
requires "bar >= 2.0.0"
when defined(linux):
  requires "extra >= 1.0.0"
```

Today milpa's heuristic `.nimble` scanner **detects** `when` but **includes every
branch unconditionally** and emits a `UserWarning` (normative: `dep-decl.md §7.5`,
`manifest-grammar.md §5.3`). The resolver then pulls `extra` into the graph on
*every* platform, not just linux. Evidence in the corpus today:

- `fixture-137-depdecl-when-attested` — the **attested** DepDecl artifact for `qux`
  was curated by the publisher to omit `extra`; the resolved graph excludes it.
- `fixture-138-depdecl-when-fallback` — the **unattested** `.nimble` fallback
  over-includes `extra` on every platform.

This RFC makes the **fallback** path translate the *recognizable subset* of NimScript
`when` conditions into milpa's existing `Predicate` model, attach those predicates to
the extracted require entries, and **record them as annotations on the lockfile's
`requires` edges**. NimScript remains un-evaluated; we recognize a bounded, well-defined
surface and translate it. Anything outside that surface falls back to **today's behavior**
(include + warn).

**Scope boundary (R1 resolved — §8).** #26 does NOT exclude deps by host profile. The
resolver still includes every branch (the lockfile stays **platform-neutral /
universal** — milpa's reproducible-build commitment is preserved); the predicate is
*recorded* on the locked edge, not *acted on*. The build-time **activation** (filtering
`nim.cfg` / the active dep set by the resolving profile) is the deliberate domain of
**#110 (universal resolution / lockfile)**. #26 is the substrate — translation, the
in-memory predicate edge, and the lockfile annotation that #110 consumes. This keeps
#26 bounded and correct, and avoids a silently host-specific lockfile (the Critical
finding of round 1). Because nothing is excluded, #26 *never* under-includes — the
graph is byte-identical in dep *set* to today; only the lockfile gains metadata.

The attested DepDecl path is unchanged: a publisher still curates the artifact (the
fixture-137 model). Carrying predicates *inside* an attested artifact (so attestation
can itself be conditional rather than baked) is a natural schema-v1 follow-up, filed
not built (§8 F3).

## 2  Motivation

### 2.1  The precise defect

Over-inclusion is *safe* (a build gets a dep it doesn't need) but not *free*:
- it fetches, hashes, and locks deps that the target platform never compiles;
- it can force resolution conflicts that wouldn't exist on the real target
  (`extra` might constrain a shared transitive that `bar` also needs);
- it makes the lockfile non-representative of any single real build.

uv/pip resolve this with environment markers (`; sys_platform == "linux"`); cargo
with `[target.'cfg(...)'.dependencies]`. milpa already has the equivalent for its
own manifests (`when platform="linux" { ... }`, `manifest-grammar.md §6`). The gap
is only that `.nimble`-sourced edges can't carry that information — so a Nim package
expressing a perfectly ordinary platform-gated dep loses the gating the moment milpa
reads it.

### 2.2  Why not evaluate NimScript

NimScript is Turing-complete; faithful evaluation means shipping a Nim interpreter in
every milpa impl — unbounded, non-portable, and a supply-chain surface milpa exists to
avoid (`CLAUDE.md` "Declarative manifest"). We instead recognize a **closed grammar**
of `when` conditions whose meaning is unambiguous and maps onto an existing profile
axis. Everything else is explicitly out of scope and degrades to over-include + warn.

### 2.3  Why reuse the predicate model (not a new "features" system)

#23 (cargo-style features) is a *different* axis (opt-in capability flags). The
`when defined(linux)` case is platform/arch/version gating — precisely what
`Predicate` already encodes. Building a second conditional mechanism for `.nimble`
would violate single-source-of-truth ([[feedback_audit_for_duplication]]). The
`flag` predicate key already exists as the seam where a future feature system (or an
unrecognized `defined(<custom>)`) could plug in (§8 F4) — but that is not this RFC.

## 3  Design

### 3.1  The recognizable `when` subset → `Predicate` translation

A single pure function — the *only* new parsing logic — maps a NimScript `when`/`elif`
condition string to a tuple of `Predicate`s, or signals **unrecognized**:

```
parse_when_condition(cond: str) -> tuple[Predicate, ...] | None     # Python
fn parse_when_condition(cond: &str) -> Option<Vec<Predicate>>       # Rust
```

`None` (Python) / `None` (Rust `Option`) is the UNRECOGNIZED signal — pinned across
both impls so the harness can cross-check. **Postcondition:** a recognized condition
ALWAYS yields a non-empty tuple; the function never returns `()` / `Some(vec![])`.
(Naming: `parse_when_condition` matches `parse_nimble`/`parse_manifest`; lives in the
nimble module, so no `nimscript_` prefix. — round 1, design lens.)

Recognized grammar (normative table, to live in `dep-decl.md §7.5`):

| NimScript condition | Predicate(s) | Notes |
|---|---|---|
| `defined(windows\|win)` | `platform="windows"` | `win` is a standard Nim alias (round 1, depth lens) |
| `defined(macosx\|macos)` | `platform="macosx"` | `macos` is a Nim ≥1.4 alias |
| `defined(linux\|freebsd\|openbsd\|netbsd)` | `platform="<os>"` | Nim `hostOS` vocabulary (`manifest-grammar.md §6` table) |
| `defined(amd64\|arm64\|i386)` | `arch="<cpu>"` | Nim `hostCPU` vocabulary |
| `not <recognized>` | the predicate, `negated=True` | single negation |
| `NimMajor >= X` | `nim>=X.0.0` | |
| `(NimMajor, NimMinor) >= (X, Y)` | `nim>=X.Y.0` | also `>`, `<`, `<=`, `==` → the matching `nim` operator |
| `(NimMajor, NimMinor, NimPatch) >= (X, Y, Z)` | `nim>=X.Y.Z` | three-tuple form (idiomatic; round 1) |
| `(NimMajor,NimMinor) >= (X,Y) and (NimMajor,NimMinor) < (X2,Y2)` | `(nim>=X.Y.0, nim<X2.Y2.0)` | two-sided range = **tuple-of-predicates AND** — the model expresses it (round 1, design lens Finding 1) |
| anything else | **UNRECOGNIZED** | `defined(release)`, `defined(js)`, `defined(<custom>)`, general `and`/`or`, nested calls, etc. |

**`defined(posix)` is deliberately NOT recognized** (→ UNRECOGNIZED → over-include).
Reason (round 1, depth lens Finding 4/5): Nim's `posix` is true on platforms outside
milpa's vocabulary (haiku, solaris, android-on-linux). Expanding it to a fixed
in-vocab OR set would *under-include* on those platforms — violating the §1
"never under-includes" invariant. Over-including on the (few) posix-using packages is
the safe choice; a precise `posix` mapping waits on a formally-closed platform vocab.

`UNRECOGNIZED` is the safety valve: the branch's `requires` are included
unconditionally (today's behavior) and the `UserWarning` fires. A chain with ANY
unrecognized branch degrades **wholly** to over-include (§3.2) — because correct
`else`/`elif` negation cannot be computed across an opaque branch.

> **Bounded by design.** The table is the entire surface. Adding a row is a spec
> amendment, not an impl tweak. F1 (boundary) and F6 (vocab) are resolved here per the
> round-1 depth/design lenses; remaining additions are corpus-driven.

### 3.2  Branch structure: `when` / `elif` / `else`

**This is a real state machine, not a regex bolt-on (round 1, depth + feasibility
lenses).** Today's `parse_nimble` is a stateless linear line-scan. Branch tracking
needs indentation/level awareness and must handle BOTH NimScript block forms:

```nim
when defined(linux):        # indented-block form
  requires "a"
  requires "extra >= 1.0"   # EVERY require in the branch inherits platform="linux"
elif defined(macosx):       # closes A at the when-indent level
  requires "b"
else:
  requires "c"

when defined(arm64): requires "neon"   # single-line colon form — body on the SAME line
```

Branch semantics (canonical predicate tuples — pinned so both impls agree, round 1
breadth lens Gap 6):
- A branch's predicate(s) attach to **every** require inside it (multiple requires per
  branch — round 1 breadth Gap 5).
- `elif B` after `when A` ⇒ `(B-predicates) AND (not-A-predicates)`. Example:
  `when defined(linux) … elif defined(macosx)` → branch B requires carry
  `(platform="macosx", platform=(not)"linux")`.
- `else` ⇒ AND of the negations of every preceding branch condition.
- **Chain poisoning (acknowledged user-visible cost):** if ANY branch in the chain is
  UNRECOGNIZED (e.g. a compound `when defined(linux) or defined(macosx)`), the WHOLE
  chain degrades to over-include + warn — we cannot compute sound negations across an
  opaque branch. A single compound condition anywhere in a chain forfeits filtering for
  all its branches. Documented, not hidden.
- **Nested `when`** ⇒ the inner chain is UNRECOGNIZED (over-include the inner requires +
  warn); the OUTER recognized chain is unaffected. Flat chains are the supported
  surface; §8 F2.

Multiple predicates on one require compose with **AND** — already the semantics of
`Predicate` tuples on a dep (`manifest-grammar.md §6.3`). No new composition rule.

The branch tracker is factored as a standalone, unit-testable function
(`parse_when_branches(lines) -> [(predicates|None, [require-line-indices])]`) so the
state machine is tested in isolation from the predicate translation and the scanner
wiring — see the S3a/S3b split in §9.

### 3.3  Data model — predicates on the require entry

`RequireEntry` (`NamedRequire` / `UrlRequire`, `dep_decl.py` / `milpa-manifest`)
gains an optional, ordered predicate tuple, defaulting empty (back-compatible):

```python
@dataclass(frozen=True)
class NamedRequire:
    name: str
    constraint_str: str
    predicates: tuple[Predicate, ...] = ()   # NEW

@dataclass(frozen=True)
class UrlRequire:
    url: str
    ref: str
    predicates: tuple[Predicate, ...] = ()   # NEW
```

`Predicate` is imported from the manifest model — **not** redefined (SSOT). `EdgeSet`
is unchanged structurally (its `requires` list now carries predicate-bearing entries);
its `__eq__`/`__repr__` already delegate to the entries. The in-memory `source` tag is
untouched. The DepDecl *artifact* serialization is unchanged in this RFC (§8 F3) —
predicates exist only on the in-memory fallback edges.

**The type-crossing is load-bearing (round 1, feasibility lens RISK 3 / design
Finding 3).** `RequireEntry` (`NamedRequire`/`UrlRequire`) is the correct home for
`predicates` — it is the *edge* type. But today's scanner returns `NimbleManifest.deps`
as `NamedDep`/`UrlDep` (from `manifest.py`, **shared with the milpa.kdl path**, which
must NOT gain predicates). So the scanner must NOT thread predicates through
`NamedDep`/`UrlDep`. Resolution:
- `parse_nimble` returns predicate-annotated entries via a scanner-local representation
  (each extracted require paired with its branch predicates), NOT by mutating the shared
  `NamedDep`/`UrlDep`.
- The single crossing point is the bridge `edge_sources._nimble_edges`, which already
  maps scanner output → `NamedRequire`/`UrlRequire`; it now also carries the predicates
  onto those entries.
- **Eliminate the double-parse.** Today the URL-dep BFS path parses the `.nimble`
  twice: once via `NimbleEdgeSource → edgeset_to_terms` (the terms the solver sees) and
  once via `_collect_transitive_deps → parse_nimble → nm.deps` (what gets *enqueued and
  fetched*). Filtering only the first leaves the second fetching excluded deps (depth
  lens Finding 1 — the "never fetched" invariant breaks for URL transitives). The fix is
  to derive BFS enqueuing from the **same** (predicate-bearing, filtered) `EdgeSet`, so
  there is ONE parse and ONE filter point. Under (c) nothing is excluded, so both paths
  agree trivially; unifying them is a worthwhile cleanup but **not load-bearing for #26**
  (no never-fetched invariant to protect). Treat it as optional refactor, not a gate.

### 3.4  Recording predicates on the lockfile — additive `cond-require` node

**R1 resolved (c):** #26 does **not** filter transitive edges by host profile. The
resolver enrolls every branch exactly as today (the dep *set* AND the existing
`requires` line are byte-identical). The predicate is recorded as a **new additive
`cond-require` annotation node**, which #110 later reads to drive build-time activation.

#### 3.4.1  Lockfile schema — `requires` UNCHANGED, additive `cond-require`

The existing `requires "bar" "extra"` node is **left exactly as today** — a flat
multi-arg list naming the full (universal) require set, conditional entries included. A
**new sibling node `cond-require`** annotates which of those requires are conditional and
records their predicate(s):

```kdl
dep "qux" {
    version "1.0.0"
    requires "bar" "extra"                  // UNCHANGED — full universal require set
    cond-require "extra" platform="linux"   // NEW — additive annotation only
    provenance { ... }
}
```

- **Single predicate → inline property form:** `cond-require "name" key="value"`, with
  negation as `key=(not)"value"` (manifest §6 syntax, verbatim).
- **AND-conjunction** (an `elif` branch → `platform="macosx" AND not platform="linux"`,
  or a two-sided `nim` range) → **child block, one `when` node per clause:**

  ```kdl
  cond-require "macstuff" {
      when platform="macosx"
      when platform=(not)"linux"
  }
  ```
  Stacked `when` children on a `cond-require` are **AND** by definition (OR within a key
  is the multi-value inline form `key="a" "b"`; OR across keys does not arise from the
  §3.1 grammar). The single-predicate inline form and the multi-clause block form are the
  only two shapes — a proper, byte-canonical subset of the manifest §6 surface.
- **Canonical ordering:** `cond-require` nodes follow the `requires` node, sorted
  lexicographically by name (byte-stable across impls).
- **Negation encoding** = manifest §6 `(not)"value"` **verbatim** — confirm the exact §6
  spelling in S5 before writing S4 tests; do NOT invent a lockfile-specific form.

**Why additive `cond-require` and NOT overloading `requires` (round 2, design +
feasibility lenses — supersedes the round-1 depth-agent draft):**
- `requires` stays a flat multi-arg node → **no re-lock byte-churn** for existing
  lockfiles (a one-node-per-entry rewrite would have changed *every* lockfile on
  re-lock — eliminated here), **no last-wins→accumulate parser change** for `requires`,
  and **no change to `frozen.py` / `cmd_show` / `nimcfg.py` / `verify`**, which all read
  `requires` by name and are untouched.
- **Forward-compat by construction:** an older milpa skips the unknown `cond-require`
  node and still sees the complete universal set in `requires` (correct degradation —
  the dep is included, only the annotation is dropped).
- **Generalizes to #134:** the DepDecl artifact gains the symmetric
  `cond-require "name" "constraint" key="value"`, distinct from unconditional
  `require "name" "constraint"` by node name — no `require` overloading in either spec.

#### 3.4.2  Data model — additive `cond_requires` field

- `LockedDep` gains `cond_requires: tuple[CondRequire, ...] = ()`, where
  `CondRequire(name: str, predicates: tuple[Predicate, ...])`. **`requires: tuple[str, ...]`
  is UNCHANGED.** Both impls (Rust: `LockedDep.cond_requires: Vec<CondRequire>`).
- **`Predicate` placement / circular import (round 2, design Finding 4):** `Predicate`
  lives in `manifest.py`, but `manifest.py` imports `dep_decl.py` (via `edge_sources`),
  so importing `Predicate` into `dep_decl.py`/`lockfile.py` would cycle. Extract
  `Predicate` into its own tiny module (`predicate.py`) imported by `manifest.py`,
  `dep_decl.py`, and `lockfile.py`. This is an **S1/S2 prerequisite, not deferred to
  #110** (S2's "no existing test breaks" still holds — it's a pure move).
- **`cmd_show`** is extended to surface `cond_requires` (one line per conditional require
  with its predicate) — cheap, and keeps the annotation visible to users. `verify`,
  `frozen`, `nimcfg` read `requires` only → unaffected; state this in S5/§5.

#### 3.4.3  Predicate propagation path (the load-bearing data flow — round 2, depth lens)

`edgeset_to_terms()` returns `(list[Term], list[str])`; the `list[str]` is
`requires_names`, which **discards predicates**. `_Candidate.requires_names`,
`ResolvedDep.requires`, and `LockedDep.requires` are all names-only — no type in the
selection path carries predicates. So S4 is *not* merely a writer change; the predicate
must be routed to the writer out-of-band:

**Adopt option (a):** extend `edgeset_to_terms` to also return
`dict[str, tuple[Predicate, ...]]` (dep-name → predicates; empty for unconditional).
`_Candidate` grows a parallel `requires_predicates` dict; `_locked_from_resolved` reads
it to populate `LockedDep.cond_requires`. This is additive — the `list[str]` selection
contract and all `requires_names` callers (incl. Rust's multi-site type) are unchanged;
the dict is **advisory metadata only, never consulted for selection/solving** (dep-name
keys are unique per candidate — a PubGrub invariant).

#### 3.4.4  Semantic asymmetry: root `when` filters, transitive `when` records (round 2, breadth Gap 6)

The same `when platform="linux"` surface means **different things by origin**, and the
RFC names this deliberately:
- A **milpa.kdl ROOT** dep `when platform="linux" { foo … }` is **FILTERED at resolve
  time** (existing, intentional behavior — `foo` is absent from the lockfile on a
  non-linux host). This is *authored intent*: you declared `foo` linux-only.
- A **`.nimble` TRANSITIVE** `when defined(linux): requires "extra"` is **RECORDED**
  under (c) — `extra` stays in the universal lockfile, annotated; #110 activates it.
  This is *inferred-from-opaque-NimScript*: milpa extracted a predicate it cannot safely
  act on at resolve time until #110's universal-activation model exists.

The justification is the trust gradient: declarative authored intent is honored
immediately; a predicate reverse-engineered from un-evaluated NimScript is recorded for
a deliberate, universal-lockfile-preserving activation later. The S3 warning text and
spec MUST distinguish the two so a user reading `when` in both places is not misled.

**No matcher call site, no `predicates.py`-matcher split for #26** — #26 only *writes*
the annotation; it never *reads* it to filter. The round-1 host-exclusion findings
(matcher SSOT / `Profile=None` / double-parse / frozen contract / CI diagnostic) were
consequences of *exclusion*; under (c) they do not arise and are transferred to **#110**
(§8). *(Note: the `predicate.py` extraction in §3.4.2 is a type-placement move, distinct
from the #110 matcher SSOT.)*

**Other `parse_nimble` callers (round 2, breadth Gap 7):** the narrowed warning (fires
only on UNRECOGNIZED after S3) is also observed by `workspace` root ingest and **tianguis
ingest** (which runs the same scanner at publish). This is the correct behavior change —
a recognized `when` no longer warns; no cross-repo coordination is required for #26.

### 3.5  Attested DepDecl path — unchanged (and why)

A DepDecl artifact is publisher-curated: fixture-137 shows the publisher already
resolved the `when` at publish time and emitted a flat require list. That remains
valid and is the *higher-fidelity* path (a human/tool decided). This RFC does not
touch artifact bytes, the index, or tianguis. The natural next step — let an artifact
carry `require "extra" ">= 1.0.0" platform="linux"` so attestation itself is
conditional — is a schema-v1 bump with cross-repo blast radius; filed, not built
(§8 F3). Doing it now would violate minimal-over-completeness
([[feedback_minimal_over_completeness]]): one proven consumer (the fallback) needs
predicates; the attested path has a working alternative (curation).

## 4  Spec reconciliation (collision map)

| Spec location | Current text | This RFC |
|---|---|---|
| `dep-decl.md §7.5` | "`when` ⇒ include all unconditionally + warn" | Replace with the §3.1 translation table + the UNRECOGNIZED→include+warn fallback + the §3.2 branch algebra. The warning text changes to fire only on UNRECOGNIZED conditions. |
| `dep-decl.md §1` | `RequireEntry` = name+constraint / url+ref | Add optional `predicates` tuple (in-memory; not serialized in v0 artifacts). |
| `manifest-grammar.md §5.3` | mirror of §7.5 | Mirror the same update (the two are kept in lockstep — they already cross-reference). |
| `manifest-grammar.md §6` | predicate vocab + matcher | **Unchanged** — reused verbatim. The §3.1 table maps INTO this vocabulary; the lockfile annotation (§3.4) reuses the `when platform=…` surface syntax. |
| `lockfile-schema.md` | `requires` = one node, N positional-arg names | **`requires` UNCHANGED.** ADD a sibling `cond-require` node (§3.4.1): inline `cond-require "name" key="value"` (single predicate, `(not)"value"` for negation per §6) or a `{ when … }` block (multi-clause AND). Add the `cond_requires`/`CondRequire` type (§3.4.2). |
| `resolver-semantics.md` | — | **No change in #26.** Transitive predicate *activation* (filtering by profile) is **#110**, not here. |

No error-catalog change: UNRECOGNIZED is a warning, not an error; malformed
constraints still raise the existing `MAN-NIMBLE-CONSTRAINT`.

## 5  Transition & compatibility

- **Strictly additive, never under-includes.** Under (c) the resolved dep *set* is
  identical to today on every platform — #26 excludes nothing. The only observable change
  is a NEW `cond-require` annotation node; the existing `requires` line is untouched.
- **`.nimble` with no `when` blocks:** **byte-identical lockfile** — no `cond-require`
  nodes, `requires` exactly as today. (The additive `cond-require` design means there is
  **no re-lock churn** for existing lockfiles — the round-2 depth-agent's overloaded-
  `requires` rewrite, which would have changed every lockfile, is avoided.)
- **`.nimble` with a recognized `when`:** the conditional require stays in `requires`
  (universal lockfile, unchanged), and the lock gains a `cond-require` annotation for it.
  Lockfile bytes change only by *adding* the `cond-require` line; the dep set does not.
- **Unrecognized `when`:** identical to today (include + warn), no `cond-require`.
- **Unaffected consumers** (read `requires` by name; never `cond-require`): `frozen.py`,
  `milpa verify`, `nimcfg.py`. `cmd_show` is extended to *display* `cond-require`. Older
  milpa silently skips the unknown `cond-require` node → still sees the full universal
  set in `requires` (correct degradation; no lockfile-schema-version bump needed).
- **Lockfile stays platform-neutral** → `--frozen`, prior-reuse, and cross-host sharing
  are unaffected (the round-1 frozen/reproducibility hazard does not arise under (c)).
- **#110 later** reads the recorded `cond-require` to filter the active build set /
  `nim.cfg` by the resolving profile — where host-specific *activation* (and the default-
  profile / CI-diagnostic concerns from round 1) will be designed.

## 6  Conformance plan

Under (c) every fixture asserts the lockfile **records** the right predicate annotation
— never that a dep is excluded. Fixtures run across all FOUR runners (§9). No
`MILPA_TARGET_*` env is needed (resolution is profile-independent in #26 — the
annotation is recorded regardless of host), which also makes the fixtures
**host-deterministic on any CI machine** (round-1 determinism concern dissolves).

- **fixture-138 expected.lock gains a `cond-require` line** — its `requires "bar" "extra"`
  line stays **byte-identical** (the dep set is unchanged); the lock simply gains
  `cond-require "extra" platform="linux"`. Purely additive; not a contract weakening.
- **recognized translation** (one fixture per §3.1 family): `defined(linux)`,
  `defined(win)`, `defined(amd64)`, `not defined(windows)`, nim-version (two-tuple,
  three-tuple, **two-sided range** → the multi-clause `cond-require { when … }` block) →
  assert the exact recorded `cond-require` node.
- **else/elif chain** → assert each branch's `cond-require` carries its canonical
  predicate clauses (incl. the negation conjunction in block form).
- **UNRECOGNIZED** (`defined(release)`, compound `or`) → no `cond-require` node, require
  still in `requires`, warning fires.
- **`milpa show`** (breadth Gap 1/8) → a liveness/format fixture asserting `show`
  surfaces the conditional require with its predicate (the `cmd_show` extension, §3.4.2).
- **mixed attested + fallback graph** (breadth Gap 10) → one dep via DepDecl (flat
  `requires`, no `cond-require`), one via nimble fallback (annotated) — assert the lock
  records `cond-require` only for the fallback dep.
- **Scenarios the reviews flagged (add fixtures):** a `when`-gated **URL** require
  (breadth Gap 4); **multiple requires in one branch** each getting a `cond-require`
  (breadth Gap 5); a **workspace member** `.nimble` `when` fallback (breadth Gap 9); a
  **root** `.nimble`-only project with a `when` block (breadth Gap 3). *(`overrides`
  interaction — Gap 8 — is moot under (c): nothing is filtered.)*
- **attested unchanged**: fixture-137 stays green untouched (regression guard).
- **coverage clauses (add atomically with fixtures — feasibility RISK 5):**
  `nimble.when-translate`, `nimble.when-negation`, `nimble.when-nim-version`,
  `nimble.when-unrecognized-over-include`, `lockfile.cond-require`.

## 7  Threat model

Under (c), #26 changes no dep selection — it only *records* metadata — so it cannot
cause under- or over-inclusion at all relative to today (over-inclusion of unrecognized
`when` blocks is preserved exactly). A malicious `.nimble` cannot use the annotation to
hide a dep, because #26 never acts on it (that is #110's surface, where the threat model
for *activation* belongs). No new trust is placed in `.nimble` bytes that wasn't already
(the fallback path is already TOFU; the attested path remains the higher-trust route).

## 8  Open forks (for architecture review / Corey)

### R1 — lockfile platform-specificity — RESOLVED (c)

*Surfaced by round 1 (depth Finding 2 + breadth Gap 1), Critical. **Corey chose (c).***
Host-filtering would have made `milpa.lock` host-specific, breaking the reproducible
lockfile + `--frozen` cross-host and colliding with **#110**. Resolution: **#26
recognizes + attaches predicates + records them on a universal (platform-neutral)
lockfile; it excludes nothing. Build-time activation moves to #110.** §3.4/§5/§6/§9
restructured accordingly. The round-1 host-exclusion findings (matcher/`Profile=None`/
double-parse/frozen/CI-diagnostic — depth 1/2/3/11, breadth 1/7) are **transferred to
#110** as its design constraints; they do not arise in #26.

### Resolved this round (folded into §3)
- **F1 / F6 `posix`** — table closed as written; added `win`, three-tuple + operator +
  two-sided `nim` forms; **dropped `posix`** to UNRECOGNIZED (depth Finding 4).
- **F4 `defined(release/js/custom)`** — UNRECOGNIZED; `flag`-mapping waits on #23.
- **F5 one matcher** — moot in #26 (no filter call site under (c)); becomes #110's when
  activation introduces the evaluator.

### Still open (non-blocking, recommendations stand)
- **F2 — nesting depth.** Flat chains only; nested `when` ⇒ UNRECOGNIZED subtree.
  *Recommend:* yes.
- **F3 — attested DepDecl predicates (schema v1).** *Recommend:* defer — filed as **#134**.

### Transferred to #110 (activation — round-1 findings that only arise when filtering)
- Matcher SSOT (`predicates.py`) + single call site; `Profile=None` guard;
  double-parse unification; `--frozen` profile contract; default-profile / CI
  under-inclusion diagnostic. **A comment summarizing these should be added to #110.**

## 9  Slices (Stage-1 breakdown → `/tdd`-sized)

Each slice lands **both impls + spec + fixtures together** (the four-runner discipline
from the pre-Nim handoff: python CLI, rust CLI, python in-process, rust in-process —
and rebuild the rust *release* binary before `python3 -m harness`). Slices are ordered
so each is independently testable and leaves the tree green.

*R1 resolved (c): #26 records predicates on the universal lockfile; it never excludes.
S4 is the lockfile recorder, not a filter. No `resolver-semantics.md` change, no graph
behavior change — only metadata. Each slice lands both impls + spec + fixtures together;
rebuild the rust **release** binary before `python3 -m harness`.*

- **S1 — translation function.** `parse_when_condition(cond)` pure function in both
  impls (the §3.1 table; returns `None`/`Option::None` for UNRECOGNIZED; never empty).
  RED: unit tests per table row + UNRECOGNIZED. No scanner/resolver wiring. Smallest,
  highest-leverage; pins the grammar. *(F6/posix resolved in §3.1 — no pre-S1 lookup.)*
- **S2 — `RequireEntry.predicates` data model + `Predicate` extraction.** First **move
  `Predicate` into its own `predicate.py`** (imported by `manifest.py`/`dep_decl.py`/
  `lockfile.py`) to break the import cycle (§3.4.2 / round-2 design Finding 4) — a pure
  move, no behavior change. Then add the optional `predicates` field to
  `NamedRequire`/`UrlRequire` (both impls); `EdgeSet` equality/repr round-trips it.
  Nothing populates it yet — no existing test breaks. RED: predicate-bearing edge
  equality/repr; import-cycle-free.
- **S3a — branch-tracker state machine.** Standalone, unit-testable
  `parse_when_branches(lines)` handling indented-block AND single-line-colon forms,
  `elif`/`else` negation algebra, chain-poisoning, nested→UNRECOGNIZED. RED: a battery
  of indentation/chain inputs. **No `parse_nimble` wiring yet → the warning still fires
  as today; existing `TestWhenBlockPolicy` tests stay green this slice.**
- **S3b — scanner wiring.** Thread `parse_when_branches` + `parse_when_condition` into
  `parse_nimble`; carry predicates across the `edge_sources._nimble_edges` bridge onto
  `NamedRequire`/`UrlRequire` **without** touching the shared `NamedDep`/`UrlDep` (§3.3).
  **Update `TestWhenBlockPolicy` / `when_block_includes_requires_unconditionally` HERE**
  (the warning now fires only on UNRECOGNIZED — this is the slice that wires the scanner,
  so the behavior change lands here, NOT S3a; round-2 feasibility RISK 5).
  RED: §1 example → the `extra` EdgeSet entry carries `platform="linux"`; UNRECOGNIZED
  still over-includes + warns. (Lockfile byte-identical this slice — recording is S4.)
- **S4 — lockfile recorder (additive `cond-require`).** Well-bounded, additive (§3.4):
  (a) New `CondRequire(name, predicates)` type (both impls); `LockedDep` gains
  `cond_requires` — **`requires` type UNCHANGED**.
  (b) `edgeset_to_terms` extended to also return a `requires_predicates` dict (§3.4.3
  option a); `_Candidate` gains the field; `_locked_from_resolved` reads it → `cond_requires`.
  (c) `format_lockfile` emits `cond-require` nodes (inline single / `{ when … }` block
  multi-clause) after `requires`, lexicographically — `requires` emission untouched.
  (d) Parser learns the new `cond-require` node into `cond_requires` — **`requires`
  parsing untouched** (no last-wins→accumulate change). `cmd_show` displays `cond_requires`.
  `frozen.py`/`verify`/`nimcfg` read `requires` only — unchanged.
  NO graph selection change. RED: resolve §1 example → lock gains `cond-require "extra"
  platform="linux"`, `requires "bar" "extra"` byte-identical; round-trip parse=format=parse
  identity. Both impls. Rebuild rust release before harness.
  **Pre-coding gate:** confirm `manifest-grammar.md §6` negation spelling (`(not)"value"`)
  and mirror it in the lockfile `cond-require` exactly (§3.4.1).
- **S5 — spec.** `dep-decl.md §7.5` (table + algebra + warning-on-UNRECOGNIZED),
  `dep-decl.md §1` (predicates field), `manifest-grammar.md §5.3` (mirror),
  `lockfile-schema.md` (the additive `cond-require` node + the `§7.5`-activation-→#110
  addendum). Update in-code warning text. **No spec/lockfile-version bump** (additive,
  forward-compatible, pre-stabilization — `spec_versioning_deferred`).
- **S6 — conformance corpus.** Author §6 fixtures; **update fixture-138 expected.lock**
  (additive annotation, dep set unchanged); add coverage clauses **atomically** with
  fixture dirs (feasibility RISK 5 — else `test_inventory_fully_covered` reddens).
  Verify all four runners + zero divergence + coverage stays 100%. Rebuild rust RELEASE
  binary before `python3 -m harness` (feasibility RISK 7).

S7 (deferred, filed as #134): DepDecl artifact schema v1 carrying predicates —
cross-repo tianguis; **not** a milpa `/tdd` slice (§8 F3).
