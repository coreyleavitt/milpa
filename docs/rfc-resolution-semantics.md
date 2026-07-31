# RFC: Resolution semantics

**Status:** draft (rfc-flow stage 2 — architect rounds 1–3 applied; ready for stage 3 `/tdd`)
**Supersedes:** `docs/rfc-index-version-selection.md` (stub) — closes umbrella #104.
**Unifies:** #191, #192, #70, #98, #111, #86, #110 (substrate #100 already CLOSED).

## 0. Why one RFC

milpa's resolver works, but three months of point features (identity-pinned git deps,
the tianguis-index swap #97, per-dep strategy) left the *resolution-semantics* surface
under-specified along several independent axes. A single real incident (2026-07-29,
amoxtli) exercised two of them at once and produced a silent build regression:

- bumping **one** dep (`crisol`) re-resolved the whole graph newest-wins and dragged two
  *unrelated* unpinned transitives (`bearssl` 0.2.11→0.2.12, `httputils` 0.4.3→0.5.0)
  forward, breaking a pinned chronos fork at compile time (**#192**); and
- the obvious fix — pin those transitives with `git= ref=` — failed, because a git dep is
  assigned a synthetic `0.0.1` version that cannot satisfy another dep's `>= 0.2.8` floor
  (**#191**).

Those two are the *correctness* core. Around them sit three more resolution axes that a
best-in-class dep manager owns and milpa has only partially specified: selection strategy
over the index (**#98**, **#111**), time-bounded resolution (**#86**), and whether the
lockfile is single-config or universal (**#110**). They share one substrate — the PubGrub
provider and the lockfile schema — and they interact (derivation feeds floors; floors feed
strategy; strategy interacts with minimal-change; time-bound filters the candidate set).
Speccing them together, once, avoids five overlapping mini-RFCs that each re-open the same
provider seam.

This RFC is **semantics + schema**, not a rewrite. Every axis is a bounded change to the
existing provider / lockfile / manifest, mapped to concrete `file:line` seams below.

## 1. Current architecture (ground truth)

Verified by reading both impls (2026-07-29). Anchors are load-bearing for the slices.

| Concern | Python | Rust |
|---|---|---|
| `Strategy` enum (Maxver/Minver/Semver) | `version.py:233` (`class Strategy`) | `milpa-solver/src/lib.rs:18` |
| Winner pick (`_pick_version`) | `solver.py:626` (`_pick_semver` 646) | `milpa-solver/src/lib.rs:996` (`pick_semver` 1015) |
| Candidate list = full sorted satisfying set | `_Provider.versions` `resolver.py:646` | `resolver.rs:3616` |
| Constraint accumulation (**#100 — CLOSED**) | solver accumulates; provider enumerates constraint-blind (`_enumerate_named_stubs` `resolver.py:1223`) | `resolver.rs:2388` (`VersionSet::full()`) |
| Git/url dep version = synthetic sentinel (**shared across url/git/local/tarball/member — 28 sites**) | `_URL_DEP_VERSION = Version(0,0,1)` `resolver.py:133` | `url_dep_version()` `resolver.rs:53` |
| Named/index resolution returns **full walkable list** | `resolve_named_all` `registry.py:477` | `registry.rs:435` |
| Candidate selection = filter `allowed` then pick | `_make_decision` `solver.py:592` | `choose_version` `milpa-solver/src/lib.rs:957` (feeds real `pubgrub` crate) |
| Provenance disambiguation (same name, diff source) | `_check_provenance_gate` `resolver.py:2656`; keyed on `("url", git, ref)` `resolver.py:1269` | resolver provenance gate |
| Member-dep sentinel is **load-bearing user-facing** | `RES_WS_MEMBER_VERSION_CONSTRAINT` `resolver.py:3630` | member coerce path |
| Prior lock loaded — **pin-reuse/drift only, not preference** | `params.prior` `context.py:136`; `_git_pin_for_url_dep` `resolver.py:1022` | `maybe_prior_lockfile` `main.rs:1062` |
| Frozen = reconstruct-from-lock, **no solve** | `frozen.py:192` | `frozen.rs:30` |
| Platform `when` — **single-config, deps stripped at Step 1** | `filter_manifest` `resolver.py:888` | predicate gates in resolver |
| Lockfile top-level fields = `version`,`strategy`,`deps` (unknown nodes ignored) | `lockfile.py` | `lockfile.rs:33`/`:751`, `milpa-types/src/lib.rs:517` |
| CondRequire/Predicate dimension recorded, **not acted on** (reserved for #110) | — | `milpa-types/src/lib.rs:468`; caveat `:465` |
| CLI `--strategy` only; **no manifest strategy field** | — | `main.rs:196` (`parse_strategy` `:251`) |

Two facts reframe the work:

1. **The synthetic `0.0.1` is a deliberate SSOT sentinel** ("version-unique by identity, so
   they enter the solver as a fixed singleton"), not an oversight. #191 is therefore a
   *model* change: git deps must become **identity-pinned AND version-labeled**, not
   identity-only. This is consistent with milpa's identity⊥provenance separation — we add a
   third orthogonal fact (declared version) that already lives in the package's `.nimble`.
2. **Minimal-change is a bounded extension of an existing seam** — the prior lock is already
   threaded in (`prior`), just used only for pin-reuse. #192 turns it into a version
   *preference*; no net-new plumbing.

## 2. Non-goals

- Not a PubGrub rewrite (backjumping etc. stays in #28).
- Not resolution *diagnostics/observability* (that is #106 / `rfc-resolution-diagnostics.md`).
- Not new transports/fetchers (#43–#47).
- Not registry trust/attestation (separate RFC line).

## 3. Design — five axes

### Axis A — real versions for git/url deps (#191)

**Problem.** Every url/git/local/tarball dep enters the solver as the fixed singleton
`0.0.1`. A dep that is *also* a floored transitive (`chronos requires bearssl >= 0.2.8`)
then can't be pinned by URL — `0.0.1 < 0.2.8` ⇒ `SOLVE-CONFLICT`.

**Design.** Read the package's **real declared version from its manifest** and use it as the
*candidate label*, keeping identity (content hash) and provenance (url/ref/commit) exactly as today.
The design has three parts: (a) a `full()` self-term (the causality fix); (b) a **manifest-agnostic**
version source with a **user annotation** for the gap; and (c) a **constrained/unconstrained
partition** for the residual version-unknown case that replaces round 2's satisfy-any + witness
synthesis. Parts (b)/(c) are the round-3 reshape (Corey: "satisfy-any is NOT the best UX", and "we
will replace `.nimble` — don't anchor on it").

**(a) The self-term is always `full()`, never `eq(declared)`.** A git/url/local/tarball dep's own
requirement term — seeded from the manifest declaration — becomes `VersionSet::full()`,
*unconditionally and independent of the fetch*. This fixes a causality hole: the self-term is built
synchronously off the manifest (Python `resolver.py:2360–2420`, Rust early seeding) **before** any
fetch, while the candidate is constructed post-fetch (`_process_url_worker` `resolver.py:2698`). If
the self-term tried to equal `eq(declared)`, the pre-fetch term would carry the old sentinel while
the post-fetch candidate carried the real version — a spurious `SOLVE-CONFLICT` for **every**
versioned git dep. `full()` removes the pre-commitment: there is exactly one real candidate for such
a dep, so `full()` is harmless — PubGrub picks it, and the *only* constraints that matter are those
imposed by **other** deps (e.g. chronos's `bearssl >= 0.2.8`). This part is unchanged from round 2.

**(b) The declared version is read from the manifest, source-agnostic — with a user annotation for
the gap.** The version is a property of the *package*, living in whichever manifest the package ships;
`.nimble` is one *adapter*, not the design (milpa's north star replaces `.nimble` with `milpa.kdl` —
anchoring new load-bearing derivation on `.nimble` would fight that). Source precedence for the
candidate label (never the self-term):

1. the fetched package's **`milpa.kdl` `version "x.y.z"`** — native, authoritative. *This field does
   not exist today* (`milpa.kdl` carries only `spec-version`, the schema epoch — verified against
   `manifest.py`); Axis A **adds it** (§5 manifest grammar). A package manifest that cannot state its
   own version cannot be the SSOT that replaces `.nimble`, so this is required by the north star, not
   optional. It is a constraint-satisfaction label, orthogonal to content-hash identity;
2. else, the fetched package's **`.nimble` `version`** — the *compat adapter* for the existing Nim
   ecosystem that hasn't adopted `milpa.kdl` (chronos, bearssl, …). Net-new line-scanner regex in
   `nimble.py`/`nimble.rs` (today only `srcDir`/`requires` are captured; no nimscript eval — the
   declarative-manifest non-negotiable holds);
3. else, **git only**, a version-shaped `ref` tag (`v?X.Y.Z`), parsed;
4. else, an explicit **`version=` annotation on the dep declaration** (§5 grammar) — the user supplies
   the one fact the fetched artifact lacked, *at the natural site*. This is Cargo's `{ git = "…",
   version = "…" }` pattern, prior-art-grounded (§0-adjacent: "how the field handles this"). It is
   **distinct from an override** (#50 = "resolver, pick X instead of what you'd choose" — a
   *relabel/replace* of a resolver decision); an annotation merely *fills a missing declared version*,
   the narrower and safer concept. It also gives the solver a *real* version, so upper bounds (`< Y`)
   are honored and genuine conflicts surface — strictly more correct than satisfy-any, which swallowed
   them;
5. else — no manifest version, no tag, no annotation — the dep is **version-unknown**, resolved by the
   partition in (c). (Consistent with the scanner's totality contract, `nimble.py:6–19`: a malformed
   `version` is never a hard *parse* error; it falls through to here.)

**(c) Version-unknown = a constrained/unconstrained partition, evaluated at the decision point of a
last-scheduled package.** The key realisation: **a version-unknown dep only *matters* when another dep
constrains it.** That cleaves the case cleanly and deletes all the round-2 witness machinery — but the
classification must be made at the **right time**, which round-3 review pinned down precisely:

**Why it cannot be a pre-solve pre-pass (the subtlety).** milpa's provider is *two-phase*: git/url/
local/tarball deps are materialized eagerly to a BFS closure before the solve, but **named/index deps
are materialized lazily, the first time PubGrub selects a candidate for them** (`resolver.py:365-374`,
`resolver.rs:11-14`). A depender's floor (`chronos requires bearssl >= 0.2.8`) enters the constraint
set *only after that depender is itself decided* — intrinsic to PubGrub. So a static "is `bearssl`
constrained?" check run before the solve, or at an arbitrary decision point, can see `full()` (chronos
not yet expanded), commit the sentinel, and only *later* hit chronos's floor against an
already-decided single-candidate package — degrading to a generic `SOLVE-CONFLICT` (or, if the
constrainer has alternatives, silently resolving to a *different* graph), never the crisp
`RES-VERSION-UNKNOWN-CONSTRAINED`. This is the architecturally *common* shape (git pin floored by an
index dep — the amoxtli shape), not an edge case.

(The partition is about how *others'* constraints on a version-unknown package are satisfied — never
about how it constrains others: a dep's *outgoing* requires are read from its own manifest independent
of its version label, `_dep_to_term resolver.py:1176`, so a version-unknown package constrains its own
dependencies exactly as any package does. "Only matters when constrained" is not bidirectional.)

**The mechanism: schedule version-unknown packages last, then classify at their decision point.**
A version-unknown package is assigned **strictly lowest decision priority** — PubGrub decides it only
after every other reachable package has been expanded and decided. By then *all* its potential
constrainers are decided and their floors are in the accumulated range, so the range PubGrub hands to
`choose_version` / that `PartialSolution.effective_set(package)` returns (`solver.py:209`,
`lib.rs:957`) is **complete and exact**. The classification is then a local decision-point check, no
conflict-path introspection needed:

- **Range still `full()` → unconstrained:** nothing floors it. The existing `0.0.1` sentinel is a
  fine internal decision token (trivially inside `full()`, so `choose_version` never returns
  out-of-range — no `pubgrub` panic, `solver.rs:217`), discarded at the lockfile boundary in favor of
  content-hash identity + `declared_version = None`. **The common fresco/intonaco untagged-branch-pin
  case just works, zero ceremony.**
- **Range non-`full()`, a declared version exists** (manifest / tag / `version=` annotation): a real
  version — normal solving, real conflict detection, ceilings honored.
- **Range non-`full()`, no version, no annotation:** **hard error `RES-VERSION-UNKNOWN-CONSTRAINED`**,
  raised at that decision point *before* returning anything to the solver (so no out-of-range return).
  It **enumerates every accumulated constrainer** (not just the first — the amoxtli incident floored
  *two* packages; a serial fail-fix-rerun loop is the papercut best-in-class resolvers avoid), names
  the constrained package, and gives the remedy. For a *root-declared* dep the remedy is "add
  `version=` here or pin a versioned tag"; for a **purely transitive** dep (no declaration the user
  owns) it is "add a root-level pin or an `overrides { pkg … version= }` for `<name>`" — the error
  text branches on whether a user-editable declaration site exists.

This ordering rule is the load-bearing part of A4. In Rust it is a one-line extension of the existing
`prioritize` hook (rank version-unknown packages last). In **Python** there is no priority hook today —
`_next_undecided` decides in insertion/BFS order, which is itself NORMATIVE (fixture-063 depends on
it); the rule must be layered as "version-unknown packages sort strictly after all others, existing
deterministic order preserved among each class," reconciled with that invariant (a companion fixture
if the BFS assertion shifts). Called out as its own concern in A4 so it is designed, not discovered
mid-`/tdd`. (Assumes an acyclic dep graph — a true P⇄Q version-unknown cycle has no "last"; noted as a
non-goal, cycles are #28 territory.)

This **deletes round 2's witness-synthesis apparatus** (the `VersionSet::witness` primitive, its
open/exclusive/unbounded/multi-interval edge-case contract, and its `pubgrub`-panic exposure). The
residual internal token is only ever committed for a genuinely-`full()` package, so the existing
sentinel suffices. **The root cause of #191 was never "the sentinel exists" — it was "the sentinel is
used even when a real version is available or supplyable, *and* it silently satisfies floors."** (b)/(c)
fix exactly that and throw away the cleverest, riskiest thing we designed.

The declared version is carried as **two sibling fields, not a merged sum type** —
`declared_version: Option<Version>` (reusing `parse_version`'s existing `Version | None`,
`version.py:276`, so value consumers — `_pick_version`, `VersionSet.contains`, sort/`max` — read it
with zero new pattern-matching) and a separate sidecar `declared_version_source: Option<VersionSource>`
(`manifest | nimble | tag | annotation` — `manifest` names the *role* (this package's own manifest),
not the file syntax of the day, so the wire value survives a future manifest-format evolution;
produced at derivation time, consumed at the lockfile write + diagnostics). `declared_version = None`
*is* version-unknown. Keeping value and source unmerged is the same identity ⊥ provenance discipline
milpa applies to content-hash vs `Provenance`.

**Identity is unchanged.** Two git refs with the same declared version but different trees remain
distinct by content hash; the lockfile already records both. Version is a *label* for constraint
satisfaction, not an identity — codified as a NORMATIVE clause in `spec/identity.md §4.1` (§5).

**Provenance-gate precedence preserved.** Same-name/different-source deps are disambiguated by the
provenance gate (`_check_provenance_gate` `resolver.py:2656`), *not* by version. After (b), two
sources declaring *different* real versions could make PubGrub raise a generic `SOLVE-CONFLICT` first,
a diagnostic regression — so A2 keeps provenance-gate suppression logically prior to the solver
reaching a version decision, and the precise `RES-PROVENANCE-CONFLICT` still fires (§6 D-A2).

**Slices:** A1 parse the declared version from **`milpa.kdl` (new `version` field) and the `.nimble`
adapter** (net-new scanner regex; fixture with `"0.1"` / non-numeric → falls through to version-unknown)
· A2 self-term → `full()` + declared label, applied **uniformly** to git/url/local/tarball (one
type-switch, one rule per D-A2) · A2c member-dep declared version (now readable from `milpa.kdl`
`version`) + self-term treatment + `RES_WS_MEMBER_VERSION_CONSTRAINT` update (§6 D-A2) · A3 git
tag-derived fallback · **A3b** `version=` annotation grammar on git/url deps + precedence step 4
(§5 grammar; distinct from overrides #50) · **A4** the constrained/unconstrained partition +
`RES-VERSION-UNKNOWN-CONSTRAINED` hard error (both impls; *replaces* round 2's A4a/A4b witness — no
primitive, no edge-case contract) · A5 lockfile records `declared_version` + `declared_version_source`
(source always emitted; version-unknown → `0.0.0` value + absent source is unambiguous; identity-based
drift, §6 D-B2) · A6 conformance: (i) constrained git dep resolves via `version=` annotation (amoxtli,
minimized); (ii) constrained git dep with no version → `RES-VERSION-UNKNOWN-CONSTRAINED`; (iii)
*unconstrained* untagged pin just resolves (fresco/intonaco); (iv) provenance-gate-fires-first · A7
`milpa show` surfaces the new state — top-level `strategy`/`exclude_newer` header + per-dep
declared-version source (`milpa_kdl`/`nimble`/`tag`/`annotation`/version-unknown), so a version-unknown
dep is inspectable (`cmd_show` `cli.py:1966` prints no top-level field today).

**Member-dep declared version (A2c).** With `milpa.kdl` now carrying a `version` field, a milpa-native
member *can* declare its version natively (precedence step 1). A member that doesn't, and is
unconstrained, is version-unknown and just works (partition, unconstrained arm); a member that is
*constrained* by another member's floor follows the same annotation-or-`RES-VERSION-UNKNOWN-CONSTRAINED`
rule. The member self-term is `full()` too, but justified by "one candidate, must satisfy members'
floors", **not** by the pre-fetch/post-fetch causality argument (members have no fetch, so that hole
doesn't exist for them). Stated so the two impls don't silently diverge on the member mechanism.

### Axis B — lockfile-aware minimal-change re-resolution (#192, #70)

**Problem.** Re-resolution is always a fresh newest-wins solve; the committed lock is a
drift-check, not a preference. Bumping one dep silently moves unrelated transitives.

**Design.** Two behaviors:

- **Minimal-change (new default).** Seed the provider with the prior lock's versions as
  *preferred*: when the solver must choose a version for a package and the locked version is
  still within the accumulated constraint set, prefer it over the strategy pick. Only
  packages *forced* to move (constraint no longer satisfiable, or the manifest changed the
  dep) move. This is cargo/npm/uv semantics. Implemented as a preference layer in
  `_pick_version` / `pick_version` (a `preferred: Option<Version>` consulted before the
  strategy ordering), fed from `params.prior`.
- **`--upgrade [<dep>…]`.** Opt out of the preference — globally or for named deps — to pull
  the latest allowed. This is **not new plumbing**: `--upgrade` is *literal delegation* to the
  strip-pin-then-resolve mechanism `milpa update` already implements (bare `update` drops all
  pins → `prior=None`; `update <dep>` strips one dep's pin via `strip_dep_pin`). A2 requires
  extracting that mechanism into a shared internal helper called by **both** `update`'s handler
  and `fetch`/`lock`'s `--upgrade` path, so the two are structurally identical, not two
  accidentally-kept-in-sync implementations (§6 D-B3). `--upgrade` on `fetch`/`lock` is CI/
  scripting sugar (one invocation instead of `fetch` + `update`); it inherits `update`'s
  workspace-delegation and alias→canonical resolution for free by construction.
- **`--locked`.** Resolve, but **fail** (`RES-LOCKED-DRIFT`) if any package would deviate
  from the committed lock. The reproducible-build / CI guard. (Distinct from frozen, which
  skips solving entirely; `--locked` solves and asserts equality.) **Drift is defined by
  identity (content hash) + provenance, not by the version label** — so the one-time Axis-A
  `0.0.1`→real-declared-version relabel of an identity-unchanged git dep is *not* drift (§6
  D-B2). `--locked` with `--upgrade` is contradictory (one forbids deviation, the other forces
  it) → rejected at CLI validation with `CLI-LOCKED-UPGRADE-CONFLICT`, following the existing
  `CLI-FEATURE-FLAGS-CONFLICT` precedent.

**Default-change note.** Today `fetch` is newest-wins; the new default is minimal-change.
Pre-v1, clean cutover ([[feedback_no_legacy_support_prev1]]) — no dual mode. `--upgrade`
recovers the old "take newest" intent explicitly. This is **decided**, not optional — §6 D-B1.

**All resolve-triggering verbs must thread `prior`.** Minimal-change is only real if every
verb that re-resolves seeds the preference. Today `fetch`/`update`/`remove` thread `params.prior`,
but several verbs hardcode `prior=None` in both impls, and each reproduces #192 through a door the
incident never hit:
- **`add`** — Python `_cmd_add_git` (`prior=None` at `cli.py:3409`); Rust `cmd_add`
  `main.rs:1553`/`:1671`;
- the workspace **`add-from-member-dir`** path mixes `None` and `prior_for_alias` across branches
  (`_cmd_add_from_member_dir`, `prior=None` at `cli.py:4075`);
- **`workspace add-member` / `workspace remove-member`** — Python `cmd_workspace_add_member`
  (`prior=None` at `cli.py:4271`) + `cmd_workspace_remove_member` (`cli.py:4412`); Rust
  `cmd_workspace_add_member` (`main.rs:1847`) + its remove sibling. Adding/removing a member relocks
  the *entire shared workspace graph* — the highest-blast-radius newest-wins bump of all.

B7 audits and fixes **all** of these (the list is exhaustive as of 2026-07-29, verified by grepping
every `prior=` site in both impls), not just `add`. Left unfixed, `milpa add somedep` — or worse,
`milpa workspace add-member` — would still newest-wins-bump every unrelated transitive.

**#70 acceptance.** The property `resolve(M); L = from_graph(G); resolve(M, prior=L) == G`
becomes a *provable* Hypothesis/proptest property once minimal-change lands — Axis B's
acceptance test. It holds only when the *candidate universe is held fixed between the two resolves*.
Two exceptions must be excluded from B5's model — one transient, one recurring:
- the one-time **Axis-A migration window** (a prior lock's `0.0.1` labels won't match a fresh
  resolve's real declared versions even though the dependency graph is unchanged);
- **index yanks** (recurring, *not* one-time): a version present in the prior lock can be yanked
  between resolves with the manifest unchanged (`registry.py:392`: "a yanked version never becomes a
  candidate"). It vanishes from stage-1 enumeration, so lock-preference never finds it and the
  package legitimately moves. This is correct behavior, not a property violation — so B5 must hold
  the index fixed (no yank events) between the paired resolves, or generate-and-exclude them.
B5 pins the property over locks already in the new format, with a stable index.

**Slices:** B1 `Preference` value (`FromLock(Version) | None`, assembled from `params.prior`)
threaded into the pure **preference-aware pick** (§4 stage 4) — the pick short-circuits to the
preferred version when it survived the constraint filter, else falls through to strategy; **no**
candidate "reorder" (inert against an order-independent `max`/lower-bound pick), both impls · B2 feed
`params.prior` versions as preferences · B3 `--locked` + `RES-LOCKED-DRIFT` (identity-based) +
`CLI-LOCKED-UPGRADE-CONFLICT` · B4 `--upgrade [dep]` as shared-helper delegation to `update`'s
strip-pin path · B5 #70 round-trip property (steady-state, index held fixed) · B6 conformance:
bump-one-dep-leaves-others-pinned (amoxtli) **+ edit-existing-constraint cases** (narrowing an
existing dep's range forces only it to move; widening leaves it pinned and perturbs no sibling — the
"manifest changed the dep" forcing condition the prose names but no version-bump/add fixture
exercises) · B7 audit+fix **all** resolve-triggering verbs to thread `prior` (fixes `add`,
`add-from-member-dir`, `workspace add-member`/`remove-member`) + conformance
`add-one-dep-leaves-rest-pinned` + `workspace-add-member-leaves-rest-pinned`.

### Axis C — selection strategy completion (#98, #111)

**#98 (minver/semver over the index).** The map shows named deps already enter the solver as
the *full* candidate list (`resolve_named_all`) and `_pick_version` already applies the active
strategy — so minver/semver over the index likely already works post-#97. Axis C's #98 work
is therefore **verify-and-lock-in**: a conformance fixture proving `--strategy minver`/`semver`
select the expected index version, plus closing any gap the fixture exposes. (If a gap
exists, it is small — the candidate list and pick function are already strategy-general.)

**#111 (lowest-direct).** Add a strategy variant that applies the *minimum* preference only to
**root-direct** deps while transitives keep the default (highest) — uv's `--resolution
lowest-direct`, the practical way to test that your advertised lower bounds build. The provider
already distinguishes constraint source (root vs transitive edge), so this is a strategy branch
keyed on "is this package named directly in the root manifest", not a structural change.
**Wire-format string:** `lowest-direct` (matching uv, discoverable), enum variant `LowestDirect`.
The existing three values happen to be mashed single words (`maxver`/`minver`/`semver`), but that
is not a load-bearing convention — a compound strategy takes the legible kebab spelling for the
CLI flag *and* the lockfile `strategy` node identically (§6 D-C1). This literal is a cross-impl,
lockfile-serialized, conformance-bijected surface — pinned here, not discovered per-impl.

**Manifest `strategy` lands now, not deferred.** `strategy` moves into the new `resolution { }`
block (Axis D) *in the same slice that introduces the block* — a manifest `strategy` field with
CLI `--strategy` overriding it. Deferring it (CLI-only now, manifest "later") would be exactly the
pre-announced second migration D-B1 refuses for minimal-change; pre-v1 clean-cutover applies here too.
Precedence: **CLI `--strategy` > manifest `resolution { strategy }` > lockfile-recorded `strategy`**
(the last diagnostic/frozen-parity only, never a live input).

**This precedence needs a plumbing fix — `--strategy` cannot express "unspecified" today.** Both
impls resolve `--strategy` to a *concrete* `Strategy` once, globally, before any manifest is parsed,
via a **literal default** (Python `cli.py:205` `default="maxver"` → `Strategy(args.strategy)` in
`main()`; Rust `main.rs:165` `Strategy::default()` overwritten in the flag loop). There is no way to
tell "user typed `--strategy maxver`" from "user typed nothing." Building the precedence above requires
changing the flag to an **`Option<Strategy>`/`None`-default sentinel**, threaded to each resolve verb
and resolved against *that verb's* parsed manifest — the exact shape Axis D already adopted for
`exclude_newer`. Same fix, same reason. (C3.)

**CLI scoping — resolve the flag-registration inconsistency while we're here.** `--strategy` is a
*global, pre-dispatch* flag today (valid, and silently ignored, on `show`/`clean`/etc.), whereas the
new resolution flags (`--exclude-newer`, `--locked`, `--upgrade`) are scoped to the resolve-triggering
verbs — a hard parse error on `milpa show --exclude-newer` but a silent no-op on `milpa show
--strategy`. Since C3 is already reworking `--strategy`'s plumbing, migrate it to the same scoped
per-verb registration so the surface has *one* philosophy, not two. (If Corey judges the migration
out of this RFC's scope, §7 files the follow-up issue per [[feedback_defer_file_now]] rather than
leaving the divergence unremarked.)

**Interaction with Axis B (the MinDirect trap) — bypass on value-divergence, not flag-presence.**
Lock-preference and strategy are ordered in §4, but a strategy that genuinely *diverges* from the one
the lock was produced under must **bypass** lock-preference for the packages it re-orders — otherwise
`milpa fetch --strategy lowest-direct` on an already-locked project is a silent no-op (the locked
maxver pick still satisfies, lock-preference wins, `lowest-direct` never acts). **The bypass trigger
is `effective strategy ≠ the lock's recorded strategy`, NOT "was `--strategy` typed."** Gating on
flag-*presence* is a footgun that resurrects #192 through the most innocuous invocation in the surface:
`milpa fetch --strategy maxver` (spelling out the default, e.g. in a CI script) would, under a
presence-gate, flip the whole graph to newest-wins bypass even though the effective strategy equals
the locked one. Comparing against `lockfile.strategy` (already threaded for C3b's frozen-parity) makes
`--strategy maxver` on a maxver lock correctly a no-op, while a real divergence still bypasses. **Scope
of the bypass is strategy-specific:** whole-graph for `maxver`/`minver`/`semver`; **root-direct only**
for `lowest-direct` (transitives keep lock-preference — a whole-graph bypass here would drag unrelated
transitives forward, #192 again), gated on the `root_authority` predicate C2 already needs (§6 D-C2).
Bypass is thus a pure function of (effective strategy, locked strategy, directness) — a testable,
impl-parity-safe value, not a CLI-parsing artifact.

**Frozen-parity baseline must follow the manifest strategy.** `FROZEN-STRATEGY-MISMATCH` today
compares `lockfile.strategy` against a hardcoded `_DEFAULT_STRATEGY = "maxver"` literal (`frozen.py:70`
— its *only* consumer of `lockfile.strategy`). Once manifest `resolution { strategy }` lands, that
baseline is wrong: a project that sets a non-default strategy would spuriously fail `frozen` on every
run even when its lock is perfectly consistent. The baseline must become the manifest's *effective*
`resolution { strategy }` (default `maxver` when absent). D5's `FROZEN-EXCLUDE-NEWER-MISMATCH` is
built the same way from the start (baseline = manifest's effective `exclude_newer`, default unset),
so it doesn't inherit the flaw.

**Slices:** C1 verify #98 minver/semver over index — **real work, not a rubber stamp**: existing
minver coverage is unit-only against a test double; no `minver`/`semver` end-to-end conformance
fixture exists (only maxver). C1 authors the first CLI-level index fixture (wire if a gap surfaces)
· C2 `LowestDirect` as a manifest/CLI/lockfile-surface value (`lowest-direct` wire string) + the
provider's **effective-strategy precompute** (`Minver` for a `root_authority` package else `Maxver`)
so the picker never gains a `LowestDirect` case or an `is_root_direct` arg (§4 stage 4), both impls ·
C3 `--strategy` **`Option<Strategy>` sentinel** plumbing (resolve "unspecified" vs explicit, per-verb,
scoped registration — not the global literal default) + manifest `resolution { strategy }` +
precedence + bypass-on-value-divergence-from-`lockfile.strategy` (root-direct-scoped, D-C2) · **C3b**
frozen-parity baseline: `FROZEN-STRATEGY-MISMATCH` reads the manifest's effective `resolution
{ strategy }` (default `maxver`) instead of the `_DEFAULT_STRATEGY` literal (`frozen.py:72`), both
impls · C4 conformance fixtures: all three strategies + frozen-with-non-default-strategy +
**`--strategy maxver`-on-a-maxver-lock-is-a-no-op** (the value-divergence-not-flag-presence regression
guard) + `--strategy lowest-direct`-still-bypasses.

### Axis D — time-bounded resolution / exclude-newer (#86)

**Problem.** No way to pin the whole graph to a point in time (reproduce-as-of, security
freeze, LTS snapshot) without per-dep pins.

**Design.** A new manifest **`resolution { … }`** block (the first manifest-level resolution
config; also the natural future home for a manifest `strategy`):

```kdl
resolution {
    exclude-newer "2026-01-01T00:00:00Z"
}
```

(Manifest node spelled kebab — `exclude-newer` — matching the CLI flag `--exclude-newer` and the
`spec-version` bare-node precedent; the recorded lockfile key stays the timestamp value. §5, D-C2.)

plus CLI `--exclude-newer <ts>` (overrides the manifest) on `fetch`/`lock`. **Verb reach.** The
manifest-recorded `exclude_newer` is honored automatically by *every* resolve-triggering verb —
`add`, `update`, `remove`, and the workspace paths all resolve through the same seam, so adding a dep
under an active time-bound validates it against that bound with no new plumbing (the Axis-D analogue
of B7's prior-threading). The *CLI override* flag stays deliberately narrower than global `--strategy`:
it is registered on `fetch`/`lock` only, because a time-bound override is a fetch/lock-time CI
concern (`milpa fetch --exclude-newer <ts>` to test an LTS snapshot), whereas `add`/`update`/`remove`
always read the manifest's committed bound. Two mechanisms, by dep kind — a **selection** filter for
multi-candidate deps and a **validation** for pinned deps (they are genuinely different operations;
conflating them is a spec bug):

- **index/named deps (selection):** the tianguis index carries `published_at` per version
  (confirmed present today, `IndexVersion.published_at` `registry.py:343`) — the enumeration
  layer drops candidates with `published_at > ts` *before* the solver sees them (§4 stage 2).
- **git/url/local/tarball deps (validation):** these are pinned to one author-chosen `ref`,
  not a candidate set milpa selects among — there is nothing to "filter". exclude-newer
  **validates** the pinned ref's resolved commit committer-date `<= ts`, hard-failing with
  `RES-EXCLUDE-NEWER-PIN` otherwise. milpa does **not** enumerate tags or walk history to
  "resolve as of ts" — that would give git deps a candidate-selection model Axis A explicitly
  says they don't have, and is speculative machinery ([[feedback_minimal_over_completeness]]).
  **What "the resolved commit" means (steady state).** milpa already reuses the prior lock's
  `commit_sha` for a matching `(git, ref)` — *including a branch ref* (`_git_pin_for_url_dep`
  `resolver.py:1022`; `fetchers/git.py:96`: "checks out this SHA instead of the mutable ref tip").
  So a *locked* branch-pinned dep validates the pinned commit's date, not live HEAD's — it is
  reproducible in steady state. The genuine non-reproducibility is narrower than round 1 stated: only
  on **first resolve or after `--upgrade`/`update`** (when no pin is reused) does a branch ref float
  to HEAD, and there validation sees only current HEAD's date. A branch is inherently non-reproducible
  *before it is first locked* (the user's own choice, consistent with D-A1); once locked it is pinned
  like any other ref. (Corrects the round-1 "checks only current HEAD" claim — §6 D-D2.)
  **Hard-fail asymmetry, stated plainly.** Because a git dep has exactly one candidate (no selection),
  newly setting or tightening `exclude_newer` over an already-locked, identity-unchanged git pin whose
  commit date now exceeds `ts` is an **unconditional `RES-EXCLUDE-NEWER-PIN` with no fallback** —
  unlike an index dep, which gracefully re-selects an older allowed version. This is exactly the
  LTS-snapshot / security-freeze scenario Axis D is motivated by, so it *will* be hit; it is documented
  (§6 D-D2) with a conformance fixture (D6), not left to surprise the user.

**Timestamp source is fail-closed and non-security.** (§6 D-D3.)
- A candidate whose timestamp *cannot be established* is **excluded** (index `published_at` is
  `None` when absent-or-malformed, `registry.py:318`; that permissive-informational default is
  overridden here — an unprovable date fails the "predates ts" test by construction). When this
  empties a package's set, `RES-EXCLUDE-NEWER-EMPTY` fires with the count dropped, not a bare
  no-satisfying-version.
- **Committer date is forgeable** (`GIT_COMMITTER_DATE`, `--amend --date`, history rewrites).
  exclude-newer is a **reproducibility / LTS-snapshot aid, not a security control** — it does
  not defend against a backdated malicious release. The RFC scopes the feature to that claim
  explicitly; a real security freeze needs an attested timestamp source (out of scope).

The effective timestamp is **recorded in the lockfile** (top-level `exclude_newer`) for
reproducibility. Because dropping it *relaxes* semantics (silently un-freezes a project), the
round-trip path must **not** silently drop a previously-set `exclude_newer`: `--locked` treats
"present in old lock, absent in new" as drift, and `update`/`remove` carry it forward (§6 D-D3).

**Slices:** **D0** (Rust-only prerequisite) move `Timestamp` + `parse_iso8601_timestamp` down from
`milpa-core::registry` into the leaf `milpa-types` crate. `milpa-manifest` (where D1 parses the block)
**cannot** depend on `milpa-core` — that crate is *downstream* of `milpa-manifest`, so the import is a
Cargo cycle the compiler refuses. Python has no cycle (`registry.py`'s `_parse_timestamp`, def at
`registry.py:780`, imports cleanly into `manifest.py`), so D0 is Rust-only; Python D1 just reuses the
existing private helper (accepted deliberately, or promote it to non-private) · D1 parse manifest
`resolution { exclude_newer; strategy }` block (both impls; reuse the shared timestamp parser — from
D0 in Rust, `_parse_timestamp` `registry.py:780` in Python — not a new parser) · D2 CLI
`--exclude-newer` + precedence over manifest · D3 index candidate filter by `published_at` at the
**enumeration layer** (own error slug when it empties, preserving #100's error-class distinction) · D4
git pinned-ref committer-date **validation** (net-new — no date-reading exists in `git.py` today; use
the resolved commit's committer date, *never* the annotated-tag tagger date — one rule, both impls,
fixture with an annotated tag whose dates differ) · D5 lockfile top-level `exclude_newer` (record +
frozen parity via `FROZEN-EXCLUDE-NEWER-MISMATCH`, baseline sourced from the manifest's effective
`exclude_newer` — **not** a hardcoded literal, see Axis C's frozen-baseline fix — + no-silent-drop on
round-trip) · D6 conformance fixtures (incl. tighten-`exclude_newer`-over-locked-git-pin → hard-fail)
· D7 error taxonomy: `RES-EXCLUDE-NEWER-PIN`, `RES-EXCLUDE-NEWER-EMPTY`, `CLI-EXCLUDE-NEWER-INVALID`,
`MAN-RESOLUTION-EXCLUDE-NEWER-INVALID`, `MAN-RESOLUTION-STRATEGY-INVALID`, `MAN-RESOLUTION-BLOCK-INVALID`.

### Axis E — universal (cross-platform) resolution: scope decision (#110)

**This axis is a decision, not (yet) a build.** milpa resolves for a single configuration:
`when`-gated conditional requires are *stripped* at Step 1 against the running machine's
profile; nothing resolves the union of platform branches, and the lock reflects the resolving
machine only. uv's universal `uv.lock` motivation (per-platform binary wheels) is weak for
Nim's source-dep + compile-time-`when` model — but an OS-gated `when require` on a
Linux+Windows team *is* a real, narrow reproducibility hole.

**The substrate already exists**: `CondRequire` + `Predicate` are recorded per dep in the
lockfile today (explicitly "reserved for #110", `milpa-types/src/lib.rs:465`) but not acted
on in resolution.

**Decision (§6 D-E1).** Adopt outcome (1)-with-a-seam: **document single-config as milpa's
deliberate default**, and specify universal resolution as a *defined but deferred* v-next
mode (solve the union of `when` branches, record per-target provenance/identity under the
existing marker dimension, teach `verify` to check the active slice) — deferred until a
concrete cross-platform-divergent Nim consumer exists. This closes #110 as a landed scope
decision without building speculative machinery, while leaving the schema seam ready.

**Residual gap Axis B must document (not fix).** Because `when`-gated deps are stripped at
Step 1 against the resolving machine's profile, a Windows-only `when require` is invisible in a
Linux-produced lock. Axis B's minimal-change guarantee is therefore **per-lockfile / per-config,
not per-manifest**: a Windows dev re-resolving a Linux-produced lock has no prior entry for the
Windows-only deps, so they resolve newest-wins regardless of the new default. This is exactly
the hole Axis E defers. Axis B's "universal lock contract" framing (D-B1) must state this
boundary explicitly rather than imply cross-platform coverage it doesn't have.

**Slices (if E is in-scope now):** none — E lands as a documented decision + a `spec/`
note. If Corey elects to *build* universal resolution, it becomes its own RFC (the schema,
union-solve, and verify changes are large and independent).

### Axis W (cross-cutting) — workspace behavior for every axis

milpa has cargo-style workspaces (NORMATIVE `spec/resolver-semantics.md §11`: member dep-set
union, multi-root BFS, **§11.4 one shared lock**, member self-registration), with existing
conformance fixtures (`fixture-213-s11-workspace-wide-union`, `fixture-264-s9a-workspace-manifest-
roundtrip`). None of A–D is complete without stating its workspace behavior:

- **Axis A:** a git dep required by two members resolves to **one** declared version in the one
  shared lock (single node, derived once) — not re-derived per member.
- **Axis B:** the `prior`-threading audit (B7) covers the workspace resolve paths too —
  `_cmd_fetch_workspace`, `_cmd_add_from_member_dir` (`prior=None` at `cli.py:4075`), and
  `workspace add-member`/`remove-member` (`cli.py:4271`/`:4412`) get the same fix as their standalone
  counterparts.
- **Axis D:** `resolution { exclude-newer }` / `resolution { strategy }` are **root-only** —
  one shared lock ⇒ one resolution policy for the whole workspace; a member-level `resolution`
  block is rejected (`MAN-RESOLUTION-MEMBER-SCOPE`). The workspace symmetry thesis holds: the
  policy lives where the shared lock lives.

**Slices:** W1 workspace conformance fixtures for A (shared git-version), B (member add/fetch
threads prior), D (root-only `resolution` block + member-scope rejection). Folded into each
axis's fixture slice, not a separate axis — but called out so no axis ships workspace-blind.

## 4. Cross-axis interactions (the candidate pipeline)

The axes do **not** all live in the pick function — that would dissolve the solver/provider
boundary the codebase deliberately maintains (`solver.py:6`, `version.py:14`: the pick function
"knows nothing about fetching, `.nimble` files, or registries"). Threading lock state, the root
dep-set, and release timestamps into a pure algebra module is a layering violation. Instead the
axes compose as an explicit **candidate-transform pipeline owned by the provider/resolver**, with
the pick function as the pure final stage.

**Outside the numbered pipeline (a decision-point branch on a last-scheduled package).** A
**version-unknown package (Axis A)** does not flow through the candidate pipeline — it has no candidate
*set*, only its single content pin. It is assigned **strictly lowest decision priority** so PubGrub
decides it only after every other reachable package, at which point its accumulated range is complete
(§3 Axis A (c)). At that decision point: *range `full()`* → decided trivially via the existing `0.0.1`
sentinel (always in-range — no `choose_version` panic); *range non-`full()` + declared version* →
normal path; *range non-`full()` + no version* → **hard error `RES-VERSION-UNKNOWN-CONSTRAINED`**,
raised there before returning to the solver. There is no witness synthesis and no in-pipeline stage —
round 2's "stage 6" is deleted, not renumbered. (The classification is *not* a static pre-pass:
because named/index constrainers materialize lazily mid-solve, only the last-scheduled decision point
sees the complete range — see §3 Axis A (c).)

Per package that *does* have a real candidate set, per solver decision, the pipeline is **five
stages** (not six — the sixth was the branch above):

1. **Enumerate** the full candidate space, constraint-blind (existing #100 behavior — the
   accumulated constraint is *not* applied at enumeration, so the correct `SOLVE-CONFLICT` vs
   `TNG-NO-SATISFYING-VERSION` error class still fires; `_enumerate_named_stubs` `resolver.py:1223`).
2. **exclude-newer filter (Axis D)** — a *hard, unconditional* cut applied here in the
   **enumeration/registry layer** (not the pick function). Emptying the set raises its own slug
   (`RES-EXCLUDE-NEWER-EMPTY`), distinct from ordinary constraint-exhaustion. Git/url singletons are
   *validated* here against the pinned ref's date (per Axis D), not ordered later.
3. **Accumulated-constraint filter (existing)** — solver-owned, unchanged. This stays the
   solver's job precisely so #100's error taxonomy is preserved.
4. **Preference-aware pick (Axes B + C — one stage).** The pure final stage
   `pick(candidates, allowed, strategy, package, preference) -> Version` — the *current*
   `_pick_version(candidates, allowed, strategy, package)` plus **one** argument, `preference`. It does
   **not** reorder the candidate list — a reorder is inert against the real pick, an order-independent
   `max` / lower-bound (`_pick_semver` `solver.py:646`, `pick_semver` `lib.rs:1015`). Instead: if
   `preference = FromLock(v)` and `v ∈ candidates ∩ allowed`, return `v`; otherwise fall through to the
   strategy ordering (Maxver / Minver / Semver). Two things are resolved **one layer up** so they never
   enter the deep picker (design deepening, round 3):
   - **bypass is not a picker parameter.** An explicit-`--strategy` bypass (D-C2) is expressed by the
     provider simply assembling `preference = None` for the bypassed packages — the picker never learns
     the concept "bypass" exists, and there is no `bypass` branch inside it.
   - **`LowestDirect` is not a picker case.** Per D-C2 it is *exactly* `Minver` for a root-direct
     package and `Maxver` otherwise; the provider precomputes an **effective strategy** per package
     (using the `root_authority` predicate it already has) and passes a concrete `Maxver | Minver |
     Semver`. `LowestDirect` stays a manifest/CLI/lockfile-surface value — it is never a variant the
     picker's `match` sees, and `is_root_direct` never crosses the boundary.
   `preference` is a plain `FromLock(Version) | None` assembled upstream from `params.prior` (an O(1)
   lookup — *not* a candidate-transform stage of its own, which is why round 1's separate "reorder
   stage" is deleted, not merely fixed). The pick never learns about lockfiles, manifests, or
   directness — its one new argument is a plain value.

The pipeline is specified once and tested once per impl; the pick function stays deep and pure (four
args + one), stages 1–3 are each an independently unit-testable transform of
`(candidates, …) -> candidates`, and the preference-vs-strategy decision lives in exactly one place
(stage 4) rather than smeared across a dead "reorder" step plus the pick.

## 5. Lockfile & manifest schema deltas

- **Manifest:** three additions, all backward-compatible optional nodes. All three round-trip through
  the hand-rolled per-field emitter `format_manifest` (Python `manifest.py:2785`, Rust `format.rs:39`)
  — which has *silently dropped a new field before* when an emitter line was forgotten (documented at
  `format.rs:60-67`), so each field's slice requires a **round-trip-through-`mutate_manifest_file`
  fixture**, not just a parse fixture (feasibility round 3).
  - new `resolution { }` block — **`exclude-newer`** (kebab, matching the CLI flag `--exclude-newer`
    and the `spec-version` bare-node precedent — *not* snake `exclude_newer`, which would force users to
    remember "dash on the CLI, underscore in the file" for one concept) **and** `strategy` (both land
    now, §3 Axis C); `MAN-RESOLUTION-BLOCK-INVALID` for an unknown child, `MAN-RESOLUTION-*-INVALID` per
    field.
  - new top-level **package `version "x.y.z"`** field (§3 Axis A (b) step 1). Today `milpa.kdl` carries
    only `spec-version` (the schema epoch) and *cannot state the package's own release version* — a gap
    that blocks `milpa.kdl` from being the SSOT that replaces `.nimble`. Axis A adds it: authoritative
    native source for the declared version, orthogonal to content-hash identity. Malformed value →
    `MAN-PACKAGE-VERSION-INVALID`.
  - new **`version=` annotation**, valid on **every dep kind Axis A relabels — git/url/local/tarball**
    (§3 Axis A (b) step 4; scoping it to git/url only, as round-2 did, would leave a constrained
    `tarball=` dep with *no* remedy but the hard error — reproducing the no-escape-hatch failure this
    RFC's own D-A1 rejects) **and on `overrides { pkg … version= }` rules** (so a *purely transitive*
    version-unknown dep, which has no declaration the root user owns, still has an attachment site — the
    override block is milpa's existing project-wide reach mechanism, §3 Axis A (c) transitive-remedy).
    It is Cargo's `{ git, version }` pattern; the user supplies a declared version the fetched artifact
    lacks. **Distinct from an override's *redirect*** (#50 changes *which source* is used; the annotation
    only *labels a version*) — but they compose: when an override redirects a dep to a different source,
    the Axis-A precedence (steps 1–4) re-runs against the *override target's* manifest, and a `version=`
    on the override rule is step 4 for that target; a stale `version=` on the now-redirected original
    declaration is ignored (§6 D-A3). Malformed value → `MAN-DEP-VERSION-INVALID`. `milpa add --git`
    gains a first-class **`--version`** flag so the natural-site workflow isn't "run add, hit the hard
    error, hand-edit `milpa.kdl`, retry" (mirrors the existing `--optional`/`--features` writable
    annotations; A3b).
- **Lockfile:** top-level `exclude_newer "<ts>"` (Axis D — the lockfile key stays the recorded
  timestamp; only the *manifest node* is kebab), recorded when set and **not silently droppable** on
  round-trip (D-D3); per-dep `version` now carries the *real* declared version for git/url/local/tarball
  deps (Axis A) instead of `0.0.1`, plus a **sibling** `declared_version_source` field (`manifest |
  nimble | tag | annotation` — `manifest` names the *role* not the file syntax, durable across a future
  format change; kept distinct from the version value — the source is not merged into the version type).
  The source is **always emitted** (including for `Known` versions),
  which makes
  version-unknown unambiguous at the boundary: a version-unknown dep serializes to the existing
  absent-version literal `0.0.0` (`lockfile.py:267`) *with* `declared_version_source` absent, a
  combination no `Known` case ever produces (a `Known` always names its source). This is the one
  concrete flattening rule for the boundary — round 1 left the `Unknown` literal unspecified, where it
  would have silently collided with the `0.0.0` absent-sentinel. Additive; unknown-node tolerance
  already present. No schema-epoch bump (pre-v1, in-place mutation per [[spec_versioning_deferred]]) —
  **and none is needed for the `0.0.1`→real transition because `--locked` drift is identity-based, not
  version-label-based** (D-B2).
- **spec/** updates (filenames verified — the normative resolver doc is `resolver-semantics.md`,
  there is no `spec/resolution.md`):
  - `spec/resolver-semantics.md` — the candidate pipeline (§4), minimal-change, exclude-newer
    semantics (selection vs validation), strategy precedence, and **§10 provenance-precedence
    interaction** (Axis A must not let a version `SOLVE-CONFLICT` pre-empt `RES-PROVENANCE-CONFLICT`);
  - `spec/manifest-grammar.md` — the `resolution { }` block (`exclude-newer`, `strategy`), the
    top-level package `version` field, the dep-level `version=` annotation (git/url/local/tarball) and
    the `overrides { pkg … version= }` property; all four grammar additions land in `format_manifest`
    /`mutate_manifest_file` (`manifest_writer.py`) with round-trip fixtures, not just the parser;
  - `spec/lockfile-schema.md` — `exclude_newer`, real git versions, the sibling
    `declared_version_source` field (always-emitted; version-unknown = `0.0.0` value + absent source),
    frozen-parity (baseline = manifest's effective policy, not a literal) + no-silent-drop; a
    `> NOTE:` that `verify` needs no new work because the version label is a pure function of
    already-content-hashed `.nimble` bytes;
  - `spec/identity.md §4.1` — a `> NORMATIVE:` clause that the version label ⊥ identity
    (constraint satisfaction only, never an identity input);
  - `spec/errors.md` — all new slugs (below);
  - single-config decision note + Axis B per-config boundary (Axis E).

**New error slugs** (enumerated up front for the bijection discipline; new `RES-*` slugs adopt
the category's dominant `RES-` prefix, *not* the minority `RESOLVE-` spelling — noted so the
split isn't deepened): `RES-LOCKED-DRIFT`, `RES-EXCLUDE-NEWER-PIN`, `RES-EXCLUDE-NEWER-EMPTY`,
`RES-VERSION-UNKNOWN-CONSTRAINED` (Axis A (c): a version-unknown dep is floored/ceilinged by another
dep and carries no declared version or `version=` annotation — the hard error that replaces round 2's
silent satisfy-any), `CLI-LOCKED-UPGRADE-CONFLICT`, `CLI-EXCLUDE-NEWER-INVALID`,
`MAN-RESOLUTION-EXCLUDE-NEWER-INVALID`, `MAN-RESOLUTION-STRATEGY-INVALID` (malformed `strategy` value —
per-field, mirroring the `exclude_newer` slug; the catalog's `MAN-*` norm is one slug per field, no
catch-all), `MAN-RESOLUTION-BLOCK-INVALID` (narrowed to its real job: an unknown/extra *child node*
under `resolution { }`), `MAN-RESOLUTION-MEMBER-SCOPE`, `MAN-PACKAGE-VERSION-INVALID` (malformed
top-level package `version`), `MAN-DEP-VERSION-INVALID` (malformed dep-level `version=` annotation),
`FROZEN-EXCLUDE-NEWER-MISMATCH`. **Thirteen slugs.**

## 6. Design decisions (resolved under the PhD-CS bar)

There are **no open forks**. Each candidate decision below is determined by the best-in-class
bar (correctness + milpa's Nim positioning + the standing "build what the real consumer
needs"), so each is **decided and baked into §3**, with its defense recorded here. The
architect rounds should attack these on the merits — not re-open them as preferences.

- **D-B1 — minimal-change is the default.** Bumping one dep must not move unrelated
  transitives. This is the universal lock contract (cargo/npm/uv/bundler), it is the direct
  fix for the incident that motivated this RFC, and there is no priority-dependent trade-off
  that would favor newest-wins-by-default — that behavior is a footgun, not a feature.
  `--upgrade [dep]` recovers "take newest" explicitly and legibly. Pre-v1: clean cutover, no
  dual mode ([[feedback_no_legacy_support_prev1]]). **Boundary:** the guarantee is per-lockfile
  /per-config, not per-manifest — `when`-gated cross-platform deps absent from the resolving
  machine's lock are not covered (Axis E residual gap, stated in §3 Axis E).
- **D-A1 — a version-unknown dep is a constrained/unconstrained partition, not satisfy-any (round-3
  reshape).** Rounds 1–2 both answered "how does a version-unknown dep satisfy a foreign floor?" —
  round 1 with MemberDep-exclusion (didn't transfer), round 2 with witness synthesis (worked but
  invented a `pubgrub`-panic-adjacent algorithm primitive). Round 3 asks the better question:
  *satisfy-any is bad UX regardless of mechanism — can we avoid needing it?* Yes. **A version-unknown
  dep only matters when another dep constrains it**, which partitions the case:
  (i) *unconstrained* → nothing to satisfy; decided against its own `full()` self-term via the existing
  `0.0.1` sentinel (always in-range, no panic), discarded at the lockfile boundary — the common
  fresco/intonaco untagged-pin case, zero ceremony;
  (ii) *constrained + a declared version exists* (milpa.kdl / .nimble / tag / `version=` annotation) →
  a real version, normal solving, real conflict detection;
  (iii) *constrained + no version + no annotation* → **hard error `RES-VERSION-UNKNOWN-CONSTRAINED`**,
  precise and actionable. milpa refuses to guess.
  This is better on all three bar axes: **ergonomics** (pay only in the genuinely ambiguous case, at
  the natural dep site, via the Cargo-precedented `version=` annotation — not a silent global relaxation
  and not a separate override block), **correctness** (a supplied version makes ceilings and real
  conflicts fire, which satisfy-any swallowed), and **simplicity** (deletes the whole witness apparatus
  + its panic exposure; the sentinel survives only for the unconstrained arm it was always fine for).
  The root cause of #191 was "the sentinel is used even when a real version is available/supplyable and
  it silently satisfies floors" — (b)/(c) fix exactly that. Still identity-pinned; trust unweakened.
  **The load-bearing round-3 refinement (why this isn't a naive pre-pass):** the partition is decided
  at the version-unknown package's *own decision point*, and that package is given **strictly lowest
  decision priority** so its accumulated range is complete when PubGrub decides it (milpa's provider
  materializes named/index constrainers lazily *mid-solve*, so an earlier or pre-solve check would
  misclassify a git pin as unconstrained and degrade to a generic `SOLVE-CONFLICT` — §3 Axis A (c)).
  Rust extends `prioritize`; Python must reconcile with the NORMATIVE `_next_undecided` BFS-order
  invariant (a sub-task of A4). `RES-VERSION-UNKNOWN-CONSTRAINED` **enumerates all** accumulated
  constrainers (the amoxtli incident floored two packages) and branches its remedy text on whether a
  user-editable declaration site exists (root-declared → annotate here; transitive → root pin or
  `overrides … version=`).
- **D-A2 — Axis A applies to every on-disk-`.nimble` dep kind, and preserves the provenance
  gate.** `_URL_DEP_VERSION` is shared across git/url/local/tarball/member (28 sites), so the
  self-term→`full()` + declared-label change is uniform for git/url/local/tarball — one type-switch,
  one rule, so A2a/A2b collapse into a single slice A2 (the round-1 split was site-count, not a seam).
  **Member deps are the one genuinely distinct seam (A2c):** with `milpa.kdl` now gaining a package
  `version` field (§3 Axis A (b) step 1), a milpa-native member *can* declare its version natively; a
  member that doesn't and is unconstrained is version-unknown and just works (partition arm i), and a
  *constrained* member follows the same annotation-or-`RES-VERSION-UNKNOWN-CONSTRAINED` rule. Its
  self-term is `full()` too, justified by "one candidate, must satisfy members' floors", **not** by the
  pre-fetch/post-fetch causality argument (members have no fetch). `RES_WS_MEMBER_VERSION_CONSTRAINT` is
  updated accordingly. For the fetched kinds the self-term is `full()` **before** the fetch (fixing the
  term-built-before-value causality hole), and provenance-gate suppression stays logically prior to any
  version `SOLVE-CONFLICT` so the precise `RES-PROVENANCE-CONFLICT` diagnostic still fires for
  same-name/different-source deps. The A2c member fix must cover **all** sentinel sites, not just the
  member's own candidate: the `__root__`→member requiring term (`resolver.py:3874`, `resolver.rs:1747`)
  and the named-dep-coerces-to-member path (`resolver.py:3627`) both hardcode `eq(0.0.1)` today and
  would spuriously conflict with a versioned member — an explicit member-site inventory, mirroring A2's
  "28 sites" discipline, is part of A2c.
- **D-A3 — `version=` annotation and override (#50) are orthogonal (label vs redirect) and compose by
  re-derivation.** An annotation *supplies a missing declared version*; an override *redirects which
  source is used*. They are not rivals, and both are needed because they attach at different reaches:
  the annotation at a dep declaration (root-declared deps), the override at any project-wide `pkg` rule
  (transitive deps with no user-owned declaration). **Composition rule:** when an override redirects a
  dep, the Axis-A version precedence (steps 1–4) re-runs against the *override target's* manifest, and a
  `version=` on the override rule is that target's step 4; a `version=` left on the now-redirected
  original declaration is dead and ignored (not a conflict — the redirect simply changed which manifest
  is in play). `version=` is therefore a property valid at both sites, reusing `MAN-DEP-VERSION-INVALID`
  for a malformed value at either. This keeps two clean concepts rather than collapsing them into one
  overloaded mechanism, while guaranteeing every site `RES-VERSION-UNKNOWN-CONSTRAINED` can fire against
  has a reachable remedy.
- **D-B2 — drift is identity-based, so the `0.0.1`→real migration is not drift.** `--locked`
  and lock-comparison key on content hash + provenance, never the version label. The one-time
  Axis-A relabel of an identity-unchanged git dep is therefore compatible, not drift — no
  schema-epoch bump, no universal first-run CI breakage. This is also simply the *correct*
  definition of drift given version ⊥ identity (D-A1/§3 Axis A), not a migration special-case.
- **D-B3 — `--upgrade` is delegation, not parallel plumbing.** `--upgrade [dep]` on `fetch`/
  `lock` is the exact strip-pin-then-resolve `milpa update` already does; A2/B4 extract that into
  one shared internal helper both call, so they cannot drift. `--locked` + `--upgrade` is
  contradictory → `CLI-LOCKED-UPGRADE-CONFLICT`.
- **D-C1 — `lowest-direct` is the wire string.** Kebab, matching uv, identical in CLI flag and
  lockfile `strategy` node. The mashed-word spelling of the existing three is not a load-bearing
  convention; a cross-impl conformance-bijected string is pinned in the RFC, not per-impl.
- **D-C2 — manifest `strategy` lands now; bypass triggers on value-divergence, not flag-presence,
  scoped to what the strategy re-orders.** `strategy` moves into `resolution { }` in the same slice as
  `exclude-newer` (no deferred second migration, consistent with D-B1). Precedence CLI > manifest >
  lockfile-recorded — which requires changing `--strategy` from a global literal-default to an
  `Option<Strategy>` sentinel threaded per resolve-verb (today neither impl can distinguish explicit
  `--strategy maxver` from an unspecified default; C3), and migrating it to the scoped per-verb
  registration the new flags use. **The lock-preference bypass triggers on `effective strategy ≠ the
  lock's recorded strategy`, NOT on whether `--strategy` was typed** — a presence-gate would make
  `milpa fetch --strategy maxver` (spelling out the default) silently flip the whole graph to
  newest-wins, resurrecting #192 through the most innocuous invocation in the surface. Comparing against
  `lockfile.strategy` (already threaded for C3b) makes that a correct no-op while a real divergence still
  bypasses. Scope of the bypass is **whole-graph** for `maxver`/`minver`/`semver`, **root-direct only**
  for `lowest-direct` (a whole-graph bypass there drags transitives forward — #192 again). Bypass is a
  pure function of (effective strategy, locked strategy, directness), not a CLI-parsing artifact. And
  once manifest `strategy` exists, the `FROZEN-STRATEGY-MISMATCH` baseline must read the manifest's
  *effective* strategy, not the hardcoded `maxver` literal (`frozen.py:72`), or every non-default
  project spuriously fails `frozen` (sub-slice C3b).
- **D-E1 — single-config by default; universal is a deferred, seam-ready mode.** uv's
  universal lock is motivated by per-platform binary wheels; Nim's source-dep + compile-time
  `when` model has no such artifact divergence, so building union-resolution now is
  speculative machinery for a consumer that does not exist ([[feedback_minimal_over_completeness]],
  [[positioning_no_generic]]). #110 explicitly asks for a *scope decision* — this RFC makes
  it: single-config is milpa's deliberate default; the `CondRequire`/marker dimension already
  recorded in the lock is the seam a future universal mode would use, kept ready but unbuilt.
- **D-D1 — exclude-newer covers git deps, as validation not selection.** A time-bound that
  only touched index/named deps would silently miss git deps, milpa's *most common* dep form.
  But git deps are pinned to one `ref`, not a candidate set — so exclude-newer **validates** the
  pinned ref's committer-date `<= ts` (`RES-EXCLUDE-NEWER-PIN` on failure), it does not enumerate
  tags or walk history to select. Reading the commit date off the already-full clone is a bounded
  transport addition (no extra network round-trip; `fetchers/git.py:838`).
- **D-D2 — branch refs are reproducible once locked; tightening a bound over a locked git pin is a
  hard fail.** Round 1 claimed validation "sees only current HEAD's date" for a branch ref — wrong in
  steady state: milpa reuses the prior lock's `commit_sha` even for a branch ref (`_git_pin_for_url_dep`
  `resolver.py:1022`), so a *locked* branch-pinned dep validates its pinned commit's date. The genuine
  non-reproducibility is only pre-first-lock or post-`--upgrade` (no pin to reuse), which is the user's
  own choice (consistent with D-A1). Building git "resolve as of ts" (history walk-back / tag
  enumeration) remains speculative and out of scope ([[feedback_minimal_over_completeness]]). **Stated
  consequence:** because a git dep has one candidate and no selection fallback, newly setting/tightening
  `exclude_newer` over an already-locked pin whose date exceeds `ts` is an unconditional
  `RES-EXCLUDE-NEWER-PIN` — unlike an index dep, which re-selects an older allowed version. This is the
  motivating LTS/freeze case, so it is documented with a D6 fixture, not left to surprise.
- **D-D3 — fail-closed, and scoped as reproducibility-not-security.** A candidate whose timestamp
  can't be established is excluded (index `published_at=None`'s permissive-informational default
  is overridden here). Committer dates are forgeable, so exclude-newer is a reproducibility/LTS
  aid, **not** a security control — the RFC makes that claim explicit rather than letting the
  "security freeze" phrasing overpromise. Index-cache staleness cannot corrupt this: `published_at`
  is an immutable per-version fact, so a stale cache can only *omit newer versions* (which a past
  `ts` excludes anyway), never report a wrong date for a version it does hold — a stale-but-consistent
  view, not an incorrect one. And because dropping the bound *relaxes* semantics, the recorded
  `exclude_newer` is not silently droppable on round-trip (`--locked` treats its disappearance as
  drift; `update`/`remove` carry it forward).

If the architect rounds surface a genuinely goal-underdetermined choice (the bar yields no
answer), that — and only that — gets escalated. None is known at draft time.

## 7. Slice ledger (for stage 3)

**Dependency note.** A and B are thematically linked (same incident, adjacent seams) but **not
sequentially dependent**: B's preference only bites on multi-candidate (named/index) deps, whose
lockfile version is already real today, so B2 does not need A5 (verified by code-tracing in round 2 —
a git/url dep has exactly one solver-visible candidate in *both* the pre- and post-Axis-A states, so
a preference is a no-op on it either way). C and D are independent of A/B. The §4 pipeline layers in
incrementally, so no big-bang slice. Hard prerequisites, all settled here: §4 stage placement
(exclude-newer at enumeration; preference folded *into* the pick, not a reorder stage), the A2
dep-kind scope (D-A2), the A4 constrained/unconstrained partition (D-A1, round-3 — no witness
primitive), and — Rust only — D0 (timestamp-parser crate move) landing before D1.

**Residual risk (tracked, not blocking).** Making minimal-change the default asks the solver to
commit to non-strategy-optimal versions far more often — the decision profile most likely to need
deep backtracking. Python's solver backtracks one level at a time (teaching-clean; full CDCL
backjumping is #28); Rust's `pubgrub` crate does full backjumping. The default-change therefore
*widens* exposure to a pre-existing cross-impl asymmetry. B6/B7 fixtures should include a
"preferred pick rejected several decisions later" case to confirm both impls agree; if they diverge
that is #28 surfacing, flagged here so it is not mistaken for an Axis-B regression.

- **A** (#191): A1 parse declared version from **`milpa.kdl` (new `version` field) + `.nimble`
  adapter** (net-new scanner regex; malformed→version-unknown fixture; **round-trip-through-
  `mutate_manifest_file` fixture** for the new `milpa.kdl version` field, not just parse) · A2
  self-term→`full()` + declared label, **uniform** across git/url/local/tarball — includes threading
  `declared_version` through *every* `_URL_DEP_VERSION`-equivalent site (~25 py / ~22 rust; "one rule"
  ≠ "one site") · A2c member-dep version (now readable from `milpa.kdl`) + self-term + **the full
  member-sentinel-site inventory** (`__root__`→member term `resolver.py:3874`/`resolver.rs:1747`;
  named-dep-coerce-to-member `resolver.py:3627`) + `RES_WS_MEMBER_VERSION_CONSTRAINT` update · A3 git
  tag fallback · **A3b** `version=` annotation grammar on **git/url/local/tarball** deps **and on
  `overrides { pkg … version= }`** + precedence step 4 (D-A3) + `milpa add --git --version` flag +
  round-trip fixtures (distinct from overrides' *redirect*) · **A4** the partition + **strictly-lowest
  decision-priority ordering** for version-unknown packages (Rust `prioritize`; Python reconcile with
  the NORMATIVE `_next_undecided` BFS-order invariant — its own design concern, companion fixture if the
  assertion shifts) + `RES-VERSION-UNKNOWN-CONSTRAINED` raised at the decision point, enumerating all
  constrainers (both impls; *replaces* round-2 A4a/A4b witness — no primitive, no edge-case contract, no
  `pubgrub`-panic exposure) · A5 lockfile `declared_version` + sibling `declared_version_source`
  (`manifest|nimble|tag|annotation`, always emitted; identity-based drift) · A6 conformance:
  constrained git dep resolves via `version=`; **constrained by a *lazily-materialized named/index* dep,
  version-unknown declared *before* its constrainer → `RES-VERSION-UNKNOWN-CONSTRAINED`** (the ordering
  hazard, not the easy eager case); multi-constrainer error enumerates both; constrained `tarball=` dep
  resolves via annotation; unconstrained untagged pin just resolves; provenance-gate-fires-first · A7
  `milpa show` surfaces declared-version source (`manifest`/`nimble`/`tag`/`annotation`/unknown) +
  top-level `strategy`/`exclude-newer`.
- **B** (#192/#70): B1 `Preference` (`FromLock|None`) folded into the pure preference-aware pick (no
  reorder) · B2 feed prior-lock preferences · B3 `--locked` + `RES-LOCKED-DRIFT` (identity-based) +
  `CLI-LOCKED-UPGRADE-CONFLICT` · B4 `--upgrade [dep]` via shared strip-pin helper (delegation to
  `update`) · B5 #70 property (steady-state, index fixed) · B6 conformance (bump-one-pins-rest +
  edit-existing-constraint narrows/widens) · B7 audit+fix all resolve verbs to thread `prior` (fixes
  `add`, `add-from-member-dir`, `workspace add-member`/`remove-member`) + `add-one-pins-rest` +
  `workspace-add-member-pins-rest`.
- **C** (#98/#111): C1 first minver/semver-over-index conformance fixture (real work; +wire if
  gap) · C2 `LowestDirect` surface value + provider **effective-strategy precompute** (`Minver` if
  root-direct else `Maxver`; no picker `LowestDirect` case / `is_root_direct` arg) · C3 `--strategy`
  **`Option<Strategy>` sentinel** + scoped per-verb registration + manifest `resolution { strategy }` +
  precedence + **bypass-on-value-divergence-from-`lockfile.strategy`** (root-direct-scoped) · **C3b**
  frozen-baseline reads manifest *effective* strategy (not the `maxver` literal, `frozen.py:72`) · C4
  conformance (all three + frozen-non-default-strategy + `--strategy maxver`-on-maxver-lock-is-a-no-op).
- **D** (#86): **D0** (Rust-only) move `Timestamp`/`parse_iso8601_timestamp` to `milpa-types`
  (unblocks D1's manifest parse without a crate cycle) · D1 manifest `resolution { exclude-newer;
  strategy }` (reuse the shared timestamp parser) · D2 CLI `--exclude-newer` + precedence · D3 index
  `published_at` filter at enumeration layer · D4 git pinned-ref committer-date validation (commit
  date, never tagger date) · D5 lockfile field + frozen parity (manifest-sourced baseline) +
  no-silent-drop · D6 conformance (incl. tighten-over-locked-pin hard-fail) · D7 error taxonomy
  (6 slugs, §5).
- **E** (#110): E1 single-config decision doc + spec note + Axis B per-config boundary. **Doc-only —
  no `/tdd` RED step; lands as a plain doc commit** (so a `/loop` grind doesn't stall waiting for a
  test that will never exist).
- **W** (cross-cutting): W1 workspace conformance for A (shared git-version), B (member
  add/fetch threads prior), D (root-only `resolution` + `MAN-RESOLUTION-MEMBER-SCOPE`). Folded
  into each axis's fixture work; listed so no axis ships workspace-blind.

Each slice: both impls where applicable, gated on `cd impls/python && uv run pytest` **and**
`./dev-rust test --workspace`, with conformance fixtures for cross-impl parity
([[feedback_gate_active_impl_pytest]]). Revised count ≈ 31 slices (round 3 kept the count flat while
deepening: witness A4a/A4b collapsed into the single partition slice A4, freeing budget for A3b's
annotation-on-four-kinds-plus-overrides and the C3 sentinel/scoping rework — net wash). **Every slice
is a clean one-behavior-per-cycle RED.** The hardest remaining slice is A4 — not for the classification
(ordinary control-flow) but for the **decision-priority ordering** it requires: trivial in Rust
(`prioritize`), a real design sub-task in Python (reconcile "version-unknown decides last" with the
NORMATIVE `_next_undecided` BFS-order invariant fixture-063 depends on). That reconciliation is the one
place in the ledger worth extra care at implementation time.

## 8. Issues closed / advanced

Closes: #104 (umbrella), #191, #192, #70, #98, #111, #86, #110. References #100 (substrate,
already closed), #106 (diagnostics — sibling), #28 (PubGrub parity — out of scope).
