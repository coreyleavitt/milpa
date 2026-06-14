# RFC: Conditional (`when`-gated) requires in `.nimble` files

- **Status:** Draft (Stage 1 — sliced; **architecture round 1 applied**; BLOCKED on the §8 R1 escalation before round 2). Round 1 fixes folded into §3.1/§3.2/§3.3/§3.4/§6/§9; one genuine fork (R1: host-specific vs universal lockfile, ↔ #110) awaits Corey.
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
  there is ONE parse and ONE filter point. This removes a pre-existing duplication.
  *(Whether filtering excludes-from-graph at all depends on the §8 R1 escalation.)*

### 3.4  Resolver — extend the existing filter to transitive edges

> **⚠ ROUND-1 ESCALATION (R1) — this section is GATED on a Corey decision (§8).**
> The reviews surfaced that filtering transitive edges by the *host* profile makes the
> `milpa.lock` **platform-specific**, which collides head-on with the lockfile's stated
> purpose ("reproducible build snapshot") and with the deferred universal-resolution
> question **#110**. The text below describes the *host-filtering* design as drafted;
> whether milpa does host-exclusion at all (vs. universal-lock + build-time activation)
> is the open fork in §8 R1. Do not implement §3.4 until R1 is resolved.

Today `_filter_manifest_by_profile` (resolver.py) filters **root manifest** deps by
`Profile` before the solver, using `_predicate_satisfied`. Transitive `.nimble` edges
are not filtered because they had no predicates. The drafted design:

1. **One matcher, in one module.** Extract `_predicate_satisfied` / `dep_matches_profile`
   into a new `predicates.py` (SSOT) importable by both `resolver.py` (root filter) and
   `edge_sources.py` (edge filter) without a circular import (round 1, design Finding 4).
   Target helper: `require_matches_profile(predicates, profile, active_flags) -> bool`.
2. **Filter inside `edgeset_to_terms`,** via a new `profile: Profile | None = None`
   parameter — the single conversion site `EdgeSet → (terms, names)` — not a separate
   pre-pass (round 1, design Finding 4). `active_flags = frozenset()` for transitive
   nimble edges (a `.nimble` has no flags block; round 1, design Finding 4).
3. **`Profile=None` guard at the call site.** `_predicate_satisfied(pred, None, …)`
   would compute `getattr(None, name)` → `None` → exclude-everything. The new call site
   MUST guard `if profile is None: include all` exactly as the root filter does
   (round 1, depth Finding 3). Absent profile ≠ matches-nothing (§6 NORMATIVE).

Evaluation timing matches §6: a predicate-excluded transitive require is removed
**before** it becomes solver input. The "never fetched" guarantee holds only once the
double-parse (§3.3) is unified — otherwise the BFS path still fetches it (depth
Finding 1). **Frozen / prior-reuse interaction** (depth Finding 2, breadth Gap 1) is
part of the R1 escalation: a host-specific lockfile replayed under `--frozen` on a
different host mismatches. R1's resolution dictates the frozen contract.

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

*Provisional pending R1 — exact expected-lockfiles depend on the host-filter vs
universal-lock decision. Fixtures run across all FOUR runners (§9). The env-file
mechanism for `MILPA_TARGET_*` already exists in both in-process runners
(`harness/runner.py` `_read_env_file`; rust `fixture_profile` in `runner.rs`) — no new
harness infra (round 1, feasibility RISK 6).*

- **Do NOT mutate fixture-138** (round 1, depth Finding 9): `spec/conformance-fixtures.md`
  requires existing fixtures be retained unchanged. fixture-138 (no `env`, profile=None)
  stays as the **over-include regression guard**. Add NEW fixtures (139+) for the
  profile-pinned variants.
- **recognized include/exclude**: new fixtures with `env` pinning
  `MILPA_TARGET_PLATFORM=linux` (include `extra`) vs `=windows` (exclude `extra`).
- **else/elif chain**, **negation** (`when not defined(windows)`), **nim-version guard**
  (`(NimMajor,NimMinor) >= (2,0)` under `MILPA_TARGET_NIM` 1.6.0 vs 2.2.0),
  **two-sided nim range** (depth/design), **UNRECOGNIZED over-include + warn**.
- **Missing scenarios the reviews flagged (add fixtures):** a `when`-gated **URL**
  require (not just named — breadth Gap 4); **multiple requires in one branch** all
  inheriting the predicate (breadth Gap 5); a **workspace member** with a `.nimble`
  `when` fallback (breadth Gap 9); the **root package** being a `.nimble`-only project
  with a `when` block (breadth Gap 3); **`overrides`** naming a predicate-excluded dep
  (filter-before-override, breadth Gap 8).
- **attested unchanged**: fixture-137 stays green untouched (regression guard).
- **coverage clauses (add atomically with the fixtures — feasibility RISK 5):**
  `nimble.when-translate`, `nimble.when-negation`, `nimble.when-nim-version`,
  `nimble.when-unrecognized-over-include`, and (if R1 ≠ pure-(c)) `resolver.transitive-predicate-filter`.

## 7  Threat model

The translation only ever *removes* edges that a recognized, negation-sound condition
proves inapplicable to the target profile. A maliciously crafted `.nimble` cannot use
this to hide a dep on the *target* platform: on that platform the predicate matches and
the dep is included. Cross-platform under-inclusion is impossible because UNRECOGNIZED
and any negation-unsound chain degrade to over-include. No new trust is placed in
`.nimble` bytes that wasn't already (the fallback path is already TOFU; this is why the
attested path remains the recommended, higher-trust route).

## 8  Open forks (for architecture review / Corey)

### R1 — THE escalation: does #26 make the lockfile platform-specific? (BLOCKING)

*Surfaced by round 1 (depth Finding 2 + breadth Gap 1), severity Critical. This is a
genuine fork — it depends on milpa's reproducibility philosophy and the relationship to
#110, not on a goal-determined answer.*

Host-filtering transitive edges (§3.4 as drafted) means `milpa fetch` on linux and on
windows produce **different `milpa.lock` files** — breaking the lockfile's stated
purpose ("reproducible build snapshot") and `--frozen` replay across hosts. milpa
already has a filed home for exactly this tension: **#110 (universal / cross-platform
resolution & lockfile — uv-parity)**. The options:

- **(a) Host-specific lockfiles now.** Ship §3.4 as drafted; the lockfile reflects the
  resolving host; `--frozen` needs a profile-stamp or re-filter. *Cost:* abandons the
  portable-lockfile commitment until #110; sharp edge for CI/cross-compile.
- **(b) Universal lockfile, build-time activation (uv model).** Resolve & lock ALL
  conditional branches (lockfile stays platform-neutral); record each conditional edge
  WITH its predicate; filter only at `nim.cfg`/active-build emission. *Cost:* needs a
  lockfile-schema change (predicate on the locked edge) — squarely #110 territory;
  bigger; arguably #26 ⊂ #110.
- **(c) Reduce #26.** Land recognize + attach + (universal) lockfile annotation now;
  defer the actual *activation/exclusion* semantics to #110. #26 becomes the
  translation + data-model substrate; #110 decides what filtering means.

*My recommendation:* **not (a).** The reproducible-build lockfile is a milpa
non-negotiable; a silently host-specific lockfile violates it. Prefer **(c)** — it
keeps #26 bounded and correct (universal lockfile, predicates recorded), unblocks the
genuinely-useful translation/scanner work, and hands the philosophical filtering
decision to #110 where it belongs. (b) is the eventual end-state; (c) is the right
increment toward it. **This decision reshapes §3.4 / §5 / §6 / §9 — those sections are
provisional until R1 is resolved, and round 2 should review the restructured RFC.**

### Resolved this round (folded into §3)
- **F1 subset boundary / F6 `posix`** — *resolved:* table is closed as written; added
  `win`, three-tuple + operator + two-sided `nim` forms; **dropped `posix`** to
  UNRECOGNIZED (under-include risk on out-of-vocab POSIX platforms — depth Finding 4).
- **F4 `defined(release/js/custom)`** — *resolved:* UNRECOGNIZED; `flag`-mapping waits
  on #23. Unchanged.
- **F5 one matcher** — *resolved:* extract `predicates.py` SSOT; filter inside
  `edgeset_to_terms(profile=…)`; `active_flags=frozenset()` for nimble edges (§3.4).

### Still open (non-blocking, recommendations stand)
- **F2 — nesting depth.** Flat chains only; nested `when` ⇒ UNRECOGNIZED subtree.
  *Recommend:* yes.
- **F3 — attested DepDecl predicates (schema v1).** *Recommend:* defer — filed as **#134**.
- **F7 — silent under-inclusion diagnostic (round 1, depth Finding 11 / breadth Gap 7).**
  When a recognized `when` drops a transitive dep, emit a stderr diagnostic naming the
  dep + the predicate that excluded it (over-inclusion was visible in the lockfile;
  exclusion must not be silent). *Recommend:* yes — mandate it in §3.4/spec. (Final
  shape depends on R1: under (c) nothing is excluded yet, so this lands with #110.)

## 9  Slices (Stage-1 breakdown → `/tdd`-sized)

Each slice lands **both impls + spec + fixtures together** (the four-runner discipline
from the pre-Nim handoff: python CLI, rust CLI, python in-process, rust in-process —
and rebuild the rust *release* binary before `python3 -m harness`). Slices are ordered
so each is independently testable and leaves the tree green.

*S1–S3 are R1-independent (translation + data model + scanner produce predicates
regardless of what filtering means). S4+ are gated on R1 — under recommendation (c) S4
becomes "record predicates in the (universal) lockfile" rather than "exclude from
graph," and the exclusion/activation work moves to #110.*

- **S1 — translation function.** `parse_when_condition(cond)` pure function in both
  impls (the §3.1 table; returns `None`/`Option::None` for UNRECOGNIZED; never empty).
  RED: unit tests per table row + UNRECOGNIZED. No scanner/resolver wiring. Smallest,
  highest-leverage; pins the grammar. *(F6/posix resolved in §3.1 — no pre-S1 lookup.)*
- **S2 — `RequireEntry.predicates` data model.** Add the optional field to
  `NamedRequire`/`UrlRequire` (both impls); `EdgeSet` equality/repr round-trips it.
  Nothing populates it yet — no existing test breaks. RED: predicate-bearing edge
  equality/repr.
- **S3a — branch-tracker state machine.** Standalone, unit-testable
  `parse_when_branches(lines)` handling indented-block AND single-line-colon forms,
  `elif`/`else` negation algebra, chain-poisoning, nested→UNRECOGNIZED. RED: a battery
  of indentation/chain inputs. **Updates the existing `TestWhenBlockPolicy` /
  `when_block_includes_requires_unconditionally` tests in the SAME slice** (the
  warning now fires only on UNRECOGNIZED — feasibility RISK 1; do NOT defer to S5).
- **S3b — scanner wiring.** Thread `parse_when_branches` + `parse_when_condition` into
  `parse_nimble`; carry predicates across the `edge_sources._nimble_edges` bridge onto
  `NamedRequire`/`UrlRequire` **without** touching the shared `NamedDep`/`UrlDep`
  (§3.3); unify the double-parse. RED: §1 example → `extra` carries `platform="linux"`;
  UNRECOGNIZED still over-includes + warns; fixture-138 stays green (profile=None).
- **S4 — (GATED on R1) filtering / lockfile recording.** Under (c): extract
  `predicates.py` SSOT; record predicates on universal lockfile edges. Under (a)/(b):
  the §3.4 transitive filter. RED depends on R1.
- **S5 — spec.** `dep-decl.md §7.5` (table + algebra + warning-on-UNRECOGNIZED),
  `dep-decl.md §1` (predicates field), `manifest-grammar.md §5.3` (mirror), and (R1-
  dependent) `resolver-semantics.md`. Note: **no spec-version bump** — no serialized
  artifact format changes (breadth Gap 12); the predicates field is in-memory (and, under
  (c), a lockfile-schema question owned by #110).
- **S6 — conformance corpus.** Author §6 fixtures; add coverage clauses **atomically**
  with fixture dirs (feasibility RISK 5 — else `test_inventory_fully_covered` reddens).
  Verify all four runners + zero divergence + coverage stays 100%. Rebuild rust RELEASE
  binary before `python3 -m harness` (feasibility RISK 7).

S7 (deferred, filed as #134): DepDecl artifact schema v1 carrying predicates —
cross-repo tianguis; **not** a milpa `/tdd` slice (§8 F3).
