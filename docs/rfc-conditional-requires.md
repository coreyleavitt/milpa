# RFC: Conditional (`when`-gated) requires in `.nimble` files

- **Status:** Draft (Stage 1 — sliced; pending architecture review rounds 1 + 2)
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
the extracted require entries, and let the resolver's **existing** profile matcher
filter them — exactly as it already filters milpa.kdl `when`-gated deps. NimScript
remains un-evaluated; we recognize a bounded, well-defined surface and translate it.
Anything outside that surface falls back to **today's behavior** (include + warn) —
so the change is strictly an improvement: never under-includes, never breaks a build.

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
nimscript_when_to_predicates(cond: str) -> tuple[Predicate, ...] | UNRECOGNIZED
```

Recognized grammar (normative table, to live in `dep-decl.md §7.5`):

| NimScript condition | Predicate(s) | Notes |
|---|---|---|
| `defined(windows\|macosx\|linux\|freebsd\|openbsd\|netbsd)` | `platform="<os>"` | Nim `hostOS` vocabulary (`manifest-grammar.md §6` table) |
| `defined(posix)` | `platform` ∈ {linux, macosx, freebsd, openbsd, netbsd} | multi-value OR; excludes windows |
| `defined(amd64\|arm64\|i386)` | `arch="<cpu>"` | Nim `hostCPU` vocabulary |
| `defined(macos)` | `platform="macosx"` | documented alias only |
| `not <recognized>` | the predicate, `negated=True` | single negation |
| `(NimMajor, NimMinor) >= (X, Y)` / `NimMajor >= X` | `nim>=X.Y.0` / `nim>=X.0.0` | the common Nim-version guard forms |
| anything else | **UNRECOGNIZED** | `defined(release)`, `defined(js)`, `defined(<custom>)`, `and`/`or` compounds, nested calls, etc. |

`UNRECOGNIZED` is the safety valve: the branch's `requires` are included
unconditionally (today's behavior) and the existing `UserWarning` fires. A mixed
branch (one recognized `when`, one unrecognized `elif`) treats only the recognized
branches as predicated and over-includes the rest — never under-includes.

> **Bounded by design.** The table is the entire surface. Adding a row is a spec
> amendment, not an impl tweak. The architect rounds should pressure the boundary
> (§8 F1) — but the boundary existing at all is the point.

### 3.2  Branch structure: `when` / `elif` / `else`

The scanner tracks indentation-delimited branch blocks (NimScript is
indentation-structured). For a flat chain:

```nim
when defined(linux):   # branch A → predicate platform="linux"
  requires "a"
elif defined(macosx):  # branch B → platform="macosx" AND not-A
  requires "b"
else:                  # branch C → not-A AND not-B
  requires "c"
```

- `else` ⇒ conjunction of the negations of every preceding branch condition in the
  chain (here: `platform=(not)"linux"` AND `platform=(not)"macosx"`).
- `elif` ⇒ its own condition AND the negations of earlier branches.
- **If ANY branch in the chain is UNRECOGNIZED**, the whole chain degrades to
  over-include + warn (we cannot compute correct negations across an opaque branch).
  This keeps the negation algebra sound.
- **Nested `when`** (a `when` inside a branch) ⇒ the inner chain is UNRECOGNIZED
  (degrade that subtree). Flat chains are the supported surface; §8 F2.

Multiple predicates on one require compose with **AND** — already the semantics of
`Predicate` tuples on a dep (`manifest-grammar.md §6.3`). No new composition rule.

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

### 3.4  Resolver — extend the existing filter to transitive edges

Today `_filter_manifest_by_profile` (resolver.py) filters **root manifest** deps by
`Profile` before the solver, using `_predicate_satisfied`. Transitive `.nimble` edges
are not filtered because they had no predicates. This RFC:

1. keeps `_predicate_satisfied` as the **single** matcher (no second evaluator);
2. when an `EdgeSet`'s requires are turned into solver terms (`edges_to_terms` /
   BFS edge consumption), drops any require whose `predicates` don't satisfy the
   active `Profile` — the same predicate, same matcher, applied one layer deeper.

Evaluation timing matches §6: a predicate-excluded transitive require is removed
**before** it becomes solver input — it is never fetched, never locked (mirroring the
"never fetched" guarantee already tested for root deps in resolver tests). When
`Profile` is `None` (filtering disabled), predicate-bearing edges are all included
(absent profile ≠ matches-nothing, per §6 NORMATIVE) — i.e. identical to today.

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
| `manifest-grammar.md §6` | predicate vocab + matcher | **Unchanged** — reused verbatim. The §3.1 table maps INTO this vocabulary. |
| `resolver-semantics.md` | root-manifest predicate filtering only | Add: the same filter applies to transitive `EdgeSet` requires (§3.4), before solver input. |

No error-catalog change: UNRECOGNIZED is a warning, not an error; malformed
constraints still raise the existing `MAN-NIMBLE-CONSTRAINT`.

## 5  Transition & compatibility

- **Strictly additive.** A `.nimble` with no `when` blocks: byte-identical behavior.
- **Recognized `when`:** the gated require gains predicates; on a matching profile the
  resolved graph is **identical to today**, on a non-matching profile the dep is now
  (correctly) excluded. The only observable change is *fewer* deps on some platforms.
- **Unrecognized `when`:** identical to today (include + warn).
- **Default profile:** when no `MILPA_TARGET_*` is set, `Profile.from_environment()`
  supplies the host platform/arch — so a host resolve filters to the host, which is
  what a developer expects. (`Profile=None` only inside tests that opt out.)

## 6  Conformance plan

New/changed fixtures (each runs across all FOUR runners — see §9 discipline):

- **fixture-138** (fallback): pin an `env` (`MILPA_TARGET_PLATFORM=linux`) so `extra`
  is included deterministically; add a sibling fixture resolving under
  `MILPA_TARGET_PLATFORM=windows` where `extra` is excluded.
- **else/elif chain**: a `.nimble` with `when defined(linux) … elif defined(macosx) …
  else …`; assert the right branch's dep under three target platforms.
- **negation**: `when not defined(windows): requires "x"` — included on linux,
  excluded on windows.
- **nim-version guard**: `when (NimMajor, NimMinor) >= (2, 0): requires "y"` under
  `MILPA_TARGET_NIM=1.6.0` (excluded) vs `2.2.0` (included).
- **UNRECOGNIZED**: `when defined(release): requires "z"` — included on every profile
  + the warning fires (assert over-include preserved).
- **attested unchanged**: fixture-137 stays green untouched (regression guard).

## 7  Threat model

The translation only ever *removes* edges that a recognized, negation-sound condition
proves inapplicable to the target profile. A maliciously crafted `.nimble` cannot use
this to hide a dep on the *target* platform: on that platform the predicate matches and
the dep is included. Cross-platform under-inclusion is impossible because UNRECOGNIZED
and any negation-unsound chain degrade to over-include. No new trust is placed in
`.nimble` bytes that wasn't already (the fallback path is already TOFU; this is why the
attested path remains the recommended, higher-trust route).

## 8  Open forks (for architecture review / Corey)

- **F1 — subset boundary.** Is the §3.1 table the right closed set? Candidates to
  add/drop: `defined(bsd)` family grouping; `defined(unix)`; Nim's `defined(gcc)` /
  backend defines (recommend: leave UNRECOGNIZED); `windows` vs `win` spellings.
  *Recommendation:* ship the table as written; additions are spec amendments driven by
  real corpus packages, not speculation.
- **F2 — branch nesting depth.** Support only flat `when/elif/else` chains; nested
  `when` ⇒ UNRECOGNIZED subtree. *Recommendation:* yes — flat is 95% of real `.nimble`
  usage; nesting can be added later without breaking the flat contract.
- **F3 — attested DepDecl predicates (schema v1).** Defer to a filed tianguis-side
  issue (cross-repo). *Recommendation:* defer; file now per [[feedback_defer_file_now]].
- **F4 — `defined(<custom>)` / build-mode (`release`/`danger`) / backend (`js`).**
  No `Profile` axis exists. *Recommendation:* UNRECOGNIZED for now. A future mapping of
  `defined(<x>)` → milpa `flag` predicate is the seam, but needs the #23 feature model
  first; do not invent profile fields here.
- **F5 — one filter or two call sites.** §3.4 reuses `_predicate_satisfied` but adds a
  second *call site* (transitive edges). *Recommendation:* factor a single
  `dep/require-matches-profile(predicates, profile)` helper used by both the root-dep
  filter and the edge filter, so the matcher has exactly one definition. Confirm in S4.
- **F6 — `posix` membership.** Does milpa's platform vocab include all five posix OSes
  for the OR expansion? Confirm against `manifest-grammar.md §6` table; if the vocab is
  narrower, `posix` expands only to the supported subset.

## 9  Slices (Stage-1 breakdown → `/tdd`-sized)

Each slice lands **both impls + spec + fixtures together** (the four-runner discipline
from the pre-Nim handoff: python CLI, rust CLI, python in-process, rust in-process —
and rebuild the rust *release* binary before `python3 -m harness`). Slices are ordered
so each is independently testable and leaves the tree green.

- **S1 — translation function.** `nimscript_when_to_predicates(cond)` pure function in
  both impls (the §3.1 table + negation). RED: unit tests per table row + UNRECOGNIZED.
  No scanner/resolver wiring yet. Smallest, highest-leverage; pins the grammar.
- **S2 — `RequireEntry.predicates` data model.** Add the optional field to
  `NamedRequire`/`UrlRequire` in both impls; `EdgeSet` equality/repr round-trips
  predicates. RED: construct a predicate-bearing edge, assert equality/repr.
- **S3 — scanner branch tracking.** Extend the `.nimble` scanner to track
  `when/elif/else` indentation blocks and attach S1's predicates (or degrade to
  UNRECOGNIZED→over-include+warn) to the requires inside. RED: scan the §1 example →
  `extra` carries `platform="linux"`; an `else` chain; an UNRECOGNIZED block still
  over-includes + warns. Both impls.
- **S4 — resolver transitive filter.** Factor the single matcher helper (F5); apply it
  to `EdgeSet` requires before solver input. RED: resolve the fixture-138 graph under
  linux (includes `extra`) vs windows (excludes, and `extra` is never fetched). Both
  impls.
- **S5 — spec.** Rewrite `dep-decl.md §7.5` (table + algebra + warning-on-UNRECOGNIZED),
  `dep-decl.md §1` (predicates field), `manifest-grammar.md §5.3` (mirror),
  `resolver-semantics.md` (transitive filtering). Update the in-code warning text.
- **S6 — conformance corpus.** Author the §6 fixtures (recognized include/exclude,
  else/elif, negation, nim-version, UNRECOGNIZED over-include, attested-unchanged
  regression). Add coverage clauses (`nimble.when-translate`, `resolver.transitive-predicate-filter`). Verify
  all four runners + zero divergence + coverage stays 100%.

S7 (deferred, file issue): DepDecl artifact schema v1 carrying predicates — cross-repo
tianguis; **not** a milpa `/tdd` slice (§8 F3).
