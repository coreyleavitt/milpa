# RFC: Workspace completion — features unification, resolver parity, and CLI symmetry

**Status:** Draft (Stage 2 — architect rounds 1 + 2 applied; ready for `/tdd`)
**Issue:** #25 umbrella (core W1–W5 shipped); this RFC organizes the work deferred *against* #25.
**Supersedes the stale "Open question: #25 workspace re-scoping" section in CLAUDE.md.**

---

## 0. Framing — what this RFC is, and is not

The cargo-style workspace core (#25 → W1–W5, #73–#77) **already shipped** in both
reference impls (`1a395b3`→`2a43755`; Rust `S11a/S11b`). A workspace root carries a
`workspace { member … }` block, members self-identify with `name`, member-to-member
edges use the `member "<name>"` reserved-keyword dep kind, resolution produces one
shared graph + one `<root>/milpa.lock`, and per-member `nim.cfg` points at a shared
`<root>/_deps/`.

So this RFC does **not** design the workspace core. It closes the **workspace-shaped
hole** the subsequent features RFC (#23) repeatedly deferred with notes of the form
*"blocked on #25 / author when #25 lands"* — now unblocked because #25 landed — plus
the adjacent workspace gaps that accumulated as later features (certificates, manifest
mutation, `self_src_dir`) were built for the single-package path only and never
back-filled to the workspace path.

The unifying thesis: **every milpa capability should behave identically whether it
operates on a standalone package or a workspace member.** Today that symmetry is
broken in **eight** concrete places (round 2 found the eighth: `add`/`remove`/`update`
invoked from *inside* a member dir silently write a member-local lock instead of updating
the shared graph — §3.G/S11e). A best-in-class workspace is one where "is this a
workspace?" is a dispatch detail, never a feature cliff. This RFC makes the symmetry
total and pins it with cross-impl conformance fixtures.

### Honesty about current state (audited, not assumed)

The issue list overstates the remaining work. Audit findings (file:line in §2):

| Claimed gap | Audited reality |
|---|---|
| §3.8 workspace feature *union* | **Mostly implemented.** `WorkspaceManifest.flags` is applied workspace-wide; per-dep `active_flags` is unioned across members in the fixpoint; `format_workspace_nimcfgs` emits the unified defines. The *only* hole is the seed-path filter arm (#160). |
| #109 workspace Phase A/B parity | **Python already done** (`_process_named` deleted; `resolve_workspace` shares `_run_bfs_wave_loop`). The GitHub issue is stale-open. Live residual is a *Rust Phase-A constraint-passing* divergence (§3.B) that is **real on the error path** (different error slug), not merely a selection question. |
| #160 seed-path arm | **Real, both impls.** The load-bearing correctness gap. In Rust it is *larger than a wiring fix*: `resolve_workspace`/`seed_workspace` take no feature-selection params at all (§3.A), so the arm requires a signature extension + workspace `cli_seed` computation. |
| #159 Profile axes | **Real, latent.** Python axes non-optional vs Rust `Option`; partial-profile divergence masked only because the CLI host-defaults every axis. A second, sharper divergence hides here: **negated predicates over an absent axis** disagree across impls (Python excludes, Rust includes) — surfaces the moment S4 lands (§3.C). |
| `clean` (claimed ws-aware, both) | **Rust violates the spec.** Python `cmd_clean` removes `<root>/_deps` + each member's `nim.cfg`; Rust `cmd_clean` removes only `dir/nim.cfg` (absent in ws mode) → **per-member `nim.cfg` files leak**. `cli-contract.md:602-603` is normative. Rust-only fix. |
| `update` (claimed single-only, both) | **Rust already workspace-aware** (`cmd_update` detects `Workspace`, calls `resolve_workspace`, writes shared lock). Python `cmd_update` raises the confusing internal `MAN-WORKSPACE-HAS-DEPS-OR-KIND`. The fix is **Python-only**. |
| `add`/`remove` at ws root | **Both impls emit the wrong error slug** (Python `MAN-WORKSPACE-HAS-DEPS-OR-KIND`; Rust reuses `MAN-ADD-DEP-EXISTS`/`MAN-REMOVE-DEP-ABSENT`). Canonical slug `MAN-MUTATE-WORKSPACE-REFUSED` already exists — both must surface it. Cross-impl error divergence today. |
| #93 / #129 / #81 | **Real CLI asymmetries**, single-package path only. |

Net: the semantics core is small and sharp (#160 + #159 + verify/close #109); the
bulk of the line-count is CLI symmetry (Bucket C).

---

## 1. Goals / non-goals

**Goals**
- G1. A workspace resolve with CLI feature selection but no profile filters member deps
  by flag predicates exactly as the single-package path does. (#160)
- G2. Partial profiles (`platform` set, `arch` unset) behave byte-identically across
  impls; the absent-axis semantics are spec-pinned and corpus-covered. (#159)
- G3. Workspace resolver parity with single-package is verified and the stale #109
  closed; any residual Rust Phase-A constraint divergence is resolved at the spec
  level (one behavior, both impls).
- G4. Every member's `nim.cfg` emits its own `src_dir` `--path:` line — self-module
  shadowing parity with single-package. (#93)
- G5. `milpa fetch --certificate` and `lock --certificate` honor the flag in workspace
  mode in **both** impls. (#129)
- G6. Workspace manifests are mutable through a typed, comment-preserving primitive,
  surfaced as `milpa workspace add-member` / `remove-member`. (#81)
- G7. Every residual single-package-only verb reaches workspace parity: `milpa update`
  does a full workspace re-resolve (no "fail cleanly" escape); `add`/`remove` at a ws root
  emit the canonical `MAN-MUTATE-WORKSPACE-REFUSED` directive; Rust `clean` removes each
  member's `nim.cfg`. No verb emits a confusing internal error at a workspace root.
- G8. **Conformance is the proof.** Each goal lands with shared `conformance/spec-v1/`
  fixtures that are byte-identical across Python and Rust. No goal is "done" on one
  impl alone.

**Non-goals (deferred, file-as-issue if surfaced)**
- N1. `[workspace.dependencies]` cargo-style dep inheritance (members reuse a
  workspace-declared dep). Out of scope; the original #25 deferred this as W6.
- N2. Glob member discovery (`member "packages/*"`). Explicit list only.
- N3. Per-member `overrides` blocks (W5 settled: workspace-root only).
- N4. Universal cross-platform lockfile (#110) — orthogonal axis, separate RFC.
- N5. Nested workspaces (W1 settled: forbidden).

---

## 2. Audited current state (the ground truth the slices build on)

### Bucket A — Workspace × Features

**A-1. Single-package three-row dispatch (the reference).**
`impls/python/milpa/resolver.py:660-744` documents and implements:
```
profile present              → _filter_manifest_by_profile  (all predicates)
profile absent + CLI features → _filter_manifest_by_flags_only (flag preds only)
profile absent + no features  → passthrough
```
Rust mirror: `impls/rust/crates/milpa-core/src/resolver.rs:199-252`
(`Some(p)` / `None if has_cli_features` / `None`).

**A-2. Workspace seed path — the gap (#160).**
Python `resolve_workspace` member-dep seeding (`resolver.py:3593-3600`) and Rust
`seed_workspace` (`resolver.rs:1064-1070`) each have **two arms only**:
`Some(profile)` → profile filter, `None` → passthrough. The middle arm
(`None + has_cli_features` → flag-only filter) is **missing in both**. Consequence:
a workspace resolve with `--features` but no profile does not prune member deps gated
on unsatisfied flag predicates before BFS seeding → over-inclusion, and a latent
cross-impl divergence the corpus does not yet observe.

**A-3. §3.8 union — already implemented (no work, just pin).**
`WorkspaceManifest.flags` (`manifest.py:533`) seeded workspace-wide
(`resolver.py:3571-3591`, Rust `resolver.rs:1213-1244`); per-dep `active_flags`
unioned across members in the fixpoint (`resolver.py:1388-1402`);
`format_workspace_nimcfgs` emits unified defines (`nimcfg.py:238-256`). The slice
here is a **fixture that pins the union**, not new code.

**A-4. Profile axes (#159).**
Python `Profile` (`profile.py:64-85`) — `platform/arch/nim/milpa` are non-optional
`str`; `from_environment` host-defaults every absent axis. Rust `Profile`
(`milpa-manifest/src/lib.rs:290-296`) — every axis `Option<String>`; absent axis
"matches nothing" in `predicate_satisfied` (`resolver.rs:3284-3313`). The divergence
is latent because the CLI host-defaults all axes (FIX-A1, #23 round 5) — but the
*library* APIs disagree, so a partial profile is representable in Rust and not in
Python, and no fixture can currently express it.

### Bucket B — Resolver parity (#109)

**B-1. Python parity already achieved.** `_process_named` deleted; `resolve_workspace`
(`resolver.py:3658,3685`) shares `_run_bfs_wave_loop` + `_enumerate_named_stubs` with
the single-package path (`rfc-reaching-rust-rewrite.handoff.md:28`). #109 is
**stale-open** — close it after a parity-asserting fixture.

**B-2. Residual Rust Phase-A constraint divergence (to verify).** Python Phase-A
enumerates with `constraint=None` and lets PubGrub accumulate constraints as terms
(`resolver.py:1189,2321,3685`). Rust passes the accumulated constraint into
`resolve_named_all` at Phase A (`resolver.rs:1768`). This affects single-package **and**
workspace in Rust (not workspace-specific). Slice B must **first verify** whether this
produces any observable selection difference; if yes, resolve to one spec-mandated
behavior; if provably benign (pre-filter is a subset optimization that cannot change
the canonical selection), document it as such with a fixture and close. Do not "fix"
a non-divergence.

### Bucket C — CLI symmetry

**C-1. `self_src_dir` (#93).** `format_nimcfg` emits `--path:"<self_src_dir>"` first
(`nimcfg.py:85-86`); `format_workspace_nimcfgs` emits only dep paths, not each
member's own `src_dir` (`nimcfg.py:230-236`). Members lose self-module shadowing.

**C-2. `--certificate` in workspace (#129).** Rust workspace fetch branch
(`milpa-cli/src/main.rs:546-599`) never reads `cert_path`; single-package routes to
`cmd_fetch_with_cert` (`main.rs:635-645`). Python `_cmd_fetch_workspace` *does* honor
it (`cli.py:865-873`). So this is a **Rust-only** correctness gap, but the fixture
must assert both impls emit the certificate in workspace mode.

**C-3. Workspace manifest mutation (#81).** `mutate_manifest_file` refuses workspace
manifests (`manifest_writer.py:162-169`, `MAN-MUTATE-WORKSPACE-REFUSED`). No
`milpa workspace` subcommand group exists. Need `mutate_workspace_manifest_file`,
`apply_workspace_manifest_change` (validate → mutate → workspace-relock), and the
`add-member` / `remove-member` verbs.

**C-4. Verb workspace-awareness audit (re-audited per impl — the original table was too coarse).**

| verb | Python | Rust |
|---|---|---|
| `fetch` / `lock` / `verify` | ws-aware | ws-aware |
| `clean` | ws-aware (removes `<root>/_deps` + each member `nim.cfg`, `cli.py:1383-1395`) | **bug**: removes only `dir/nim.cfg` (absent in ws mode); per-member `nim.cfg` leak (`main.rs:371-375`) |
| `update` | **errors** (`MAN-WORKSPACE-HAS-DEPS-OR-KIND` via `parse_manifest`) | **already ws-aware** (`main.rs:809-831`: detects `Workspace`, `resolve_workspace`, shared lock) |
| `add` / `remove` at ws root | errors with wrong slug `MAN-WORKSPACE-HAS-DEPS-OR-KIND` | errors with wrong slug `MAN-ADD-DEP-EXISTS` / `MAN-REMOVE-DEP-ABSENT` (`main.rs:880-884,1106-1110`) |
| `show` at ws root | flat shared-graph dump (no member attribution); from a member dir with no own lock → `LOCK-FILE-NOT-FOUND` | same |

The load-bearing fixes: (1) Rust `clean` per-member `nim.cfg`; (2) Python `update`
workspace-awareness; (3) both impls' `add`/`remove`-at-ws-root must surface the
**existing** canonical slug `MAN-MUTATE-WORKSPACE-REFUSED` (today they emit three
*different wrong* slugs → cross-impl error divergence). `show` member-scoping is polish (F-d).

---

## 3. Design

### 3.A  #160 — the missing seed-path arm

Introduce a **single shared filter helper** so the workspace seed path cannot drift from
the single-package path again (root-cause over symptom: the divergence exists *because*
there are two copies of the dispatch). But the deepest factoring is **not** a three-row
dispatch keyed off `(profile, cli_active_seed)`; the three rows collapse to **two
independent predicates** once the "compute the closed flag set" step is lifted out of the
filter. Encode both decisions in a value type:

```python
@dataclass(frozen=True)
class FilterContext:
    profile: Profile | None       # None ⟺ platform-filtering disabled (§470)
    active_flags: frozenset[str]  # already-closed flag set; empty ⟺ no flag filtering

    @classmethod
    def build(
        cls, manifest: Manifest, profile: Profile | None,
        *, cli_seed: frozenset[str] | None,   # None ⟺ use manifest's default flags
    ) -> FilterContext:
        seed = cli_seed if cli_seed is not None else _default_flag_seed(manifest)
        active = flag_enables_closure(manifest.flags, seed) if seed else frozenset()
        return cls(profile=profile, active_flags=active)

def filter_manifest(manifest: Manifest, ctx: FilterContext) -> Manifest:
    # filter by profile predicates iff ctx.profile is not None
    # filter by flag predicates    iff ctx.active_flags is nonempty
    # (the two predicates are independent; no 30-line "why two arms" comment needed)
```

**The closure is a smart constructor, not a caller responsibility (Design-F1).** Making
`FilterContext.build(manifest, profile, *, cli_seed)` the *only* construction path closes a
real footgun: the flag-closure (`flag_enables_closure(manifest.flags, seed)`) must run
against **the manifest being filtered** — at a workspace member site that is the *member's*
`flags` block, which differs from the workspace root's `flags` seed. A bare-dataclass
`FilterContext(profile, active_flags)` lets a caller pass the *root's* closed flags into a
*member* filter (pruning member deps gated on member-specific flags), and the two S2 sites
(`_build_member_candidate` and the BFS seed loop) each construct independently — exactly
where the bug would slip in. `build()` takes the manifest and computes the closure from
*its* flags, so the right flags are always used and the closure is never skipped. The
raw fields remain public for Rust symmetry; Python callers always go through `build()`.

**Predicate ownership — no double evaluation (Depth-F7).** `filter_manifest`'s profile gate
evaluates **only platform/arch/nim/milpa axes**; **flag** predicates are owned exclusively by
the flag gate. Today `_filter_manifest_by_profile` evaluates flag predicates internally via
`_predicate_satisfied`; under the two-predicate model that path MUST skip `pred.name ==
"flag"` and leave it to the flag gate. (Otherwise a flag predicate is evaluated twice — same
result by idempotent AND, but a latent discrepancy if the two flag-evaluation paths ever
drift. Single owner, no drift.) Spec this in `resolver-semantics §3.A`.

Rust mirror: `struct FilterCtx { profile: Option<&Profile>, active_flags: BTreeSet<String> }`
with a `FilterCtx::build(manifest, profile, cli_seed)` associated fn (this also retires the
awkward `enriched_profile_storage` lifetime dance at `resolver.rs:199-253`).
Named `filter_manifest`, **not** `filter_member_manifest` — it serves the root manifest too;
the "member" in a name would mislead.

**Two application sites inside `resolve_workspace` (Python).** The filtered manifest must
reach **both** the candidate pre-registration loop (`resolver.py:3518-3531` →
`_build_member_candidate`, which reads `manifest.deps + manifest.dev_deps` at `:3319` to
build solver `dep_terms`) **and** the BFS seed loop (`:3593-3600`). Filtering only the
second site leaves flag-gated deps as solver terms → spurious fetch/resolve, or a
spurious `SOLVE-CONFLICT` if a gated dep version-clashes. In Rust the two are fused into
one `seed_workspace` loop (`:1061-1174`), so one call site suffices there.

**Rust scope (not a mechanical extraction).** `resolve_workspace` (`resolver.rs:511-521`)
and `seed_workspace` (`:1036`) take **no** feature-selection params today — the entire
`has_cli_features` / `cli_seed` infrastructure lives only inside single-package `resolve()`
(`:122-244`). The #160 arm therefore requires (a) extending the `resolve_workspace` public
signature with the feature inputs, (b) computing a workspace-scoped `cli_seed` from the
workspace manifest's `flags` block, (c) threading it into `seed_workspace`, plus updating
**every `resolve_workspace` caller** — the conformance runner has **three** workspace call
sites, not two: `Cmd::Resolve` (`runner.rs:463`), `resolve_workspace_frozen` (`:592`, no
feature params — frozen reconstructs from lock), and **`Cmd::Verify` (`:714`)** which the
earlier draft missed (Feasibility-F3) — plus `cmd_fetch` (`main.rs:546-599`). **Also route
`resolve_with_cert` through the shared helper (Feasibility-F9):** its own filter block
(`resolver.rs:3744-3751`) is two-arm-only (`Some(profile)`/`None`) and would inherit the
exact `None + has_cli_features` bug after S1 unless it goes through `filter_manifest` in the
same slice. This is a signature extension, not a copy-delete.

**Normative (resolver-semantics):** the flag-only filter arm applies to **member deps'
own deps** identically to top-level deps. A `member`-kind dep itself is workspace
topology, not a conditional dep — see the decision below.

**Frozen workspace + `--features` mismatch (Breadth-P1b).** The single-package
`FROZEN-ACTIVE-FLAGS-MISMATCH` check (`cli.py:540-630`) is guarded by `if ws is None:`
(`:1194`) — **entirely skipped for workspaces**. Consequence: a workspace locked under
`--features X`, re-run as `fetch --frozen` *without* `--features X`, raises the wrong slug
(`FROZEN-MANIFEST-DEP-NOT-IN-LOCK` from `resolve_workspace_frozen` iterating unfiltered
member deps at `frozen.py:330`) instead of the correct `FROZEN-ACTIVE-FLAGS-MISMATCH`. Two
distinct fixes, both in S2's scope: (1) `resolve_workspace_frozen` filters member deps by
`FilterContext` *before* its "dep not in lock" check, so a flag-excluded dep doesn't
mis-fire; (2) the workspace frozen CLI path recomputes the root active-flag closure and runs
the mismatch check (per `cli-contract.md:318-325`, which does *not* exempt workspaces).
Fixture: workspace with a feature-gated member dep, `--frozen` without `--features` ⇒
`FROZEN-ACTIVE-FLAGS-MISMATCH`.

**`when`-gated member deps — forbid at parse (closes a latent spec hole).** The grammar
currently *allows* `member "x"` inside a `when { … }` block, and `MemberDep.predicates`
(`manifest.py:375-376`) is populated from the enclosing predicates — but both seed sites
**silently drop** those predicates (`:3324`, `:3606`). That is undocumented behavior that
can silently violate user intent. Resolution: a `member` node inside a `when` block is a
**category error** (members are workspace topology, present unconditionally in every
resolution), so the parser MUST reject it with a new `MAN-MEMBER-WHEN-GATED` error rather
than silently honor or silently drop it. This makes the "members are never filtered" rule
*structurally true* instead of tacit. (Spec: `manifest-grammar.md` + `errors.md`.)

**Named-dep → member auto-coercion drops the version constraint (spec hole, Breadth-P1c).**
When a named dep matches a member name it auto-coerces to `Term.require(name,
VersionSet.eq(_URL_DEP_VERSION))` (`resolver.py:3320-3329`), **silently discarding the
dep's declared version constraint**: a `foo >= 2.0` named dep where member `foo` is at
`0.1.0` resolves successfully with no violation. `resolver-semantics §11.1` says named deps
matching a member auto-coerce but is silent on the constraint. Resolution: the constraint
MUST be checked against the member's declared `version` and a mismatch raised (members carry
a real version; silently dropping the consumer's constraint is a correctness hole, not a
convenience). Pin with a fixture (`foo >= 2.0` vs member `foo version "0.1.0"` → error).
Folded into S5 (workspace-resolver touch); spec `resolver-semantics §11.1`.

### 3.B  #109 / Rust Phase-A constraint — verify, then resolve once

1. Add a workspace-vs-single-package **parity fixture**: a 2-member workspace whose
   union of deps equals a standalone manifest's deps must produce a byte-identical
   lockfile (already the normative claim in `resolver-semantics.md`; pin it). Close #109.
2. Investigate the Rust Phase-A constraint-passing (`resolver.rs:1768`). The framing in
   earlier drafts ("a constraint that *widens* after backtracking") is analytically
   wrong: PubGrub accumulates incompatibilities monotonically and never removes a
   constraint once derived, so the *selected version* for a satisfiable problem is
   identical either way (solver terms carry the constraint independently of the
   enumerator). **The real divergence is on the error path.** Construct: dep A requires
   `foo >= 2.0.0`, index has only `foo` 1.x.
   - **Rust** (pre-filter at `resolve_named_all(foo, >=2.0.0)`) → eager
     `TNG-NO-SATISFYING-VERSION` at BFS time.
   - **Python** (`constraint=None`, enumerate all 1.x stubs) → solver sees `foo >= 2.0.0`
     as an incompatibility no 1.x satisfies → `SOLVE-CONFLICT`.

   Same root cause, **two different error slugs**. So this is *not* benign — "provably
   benign" was too narrow; it only covered selection. The spec must pick one canonical
   error. Recommendation (folded into fork F-a): **enumerate-all is normative** — PubGrub
   correctness wants the solver, not the enumerator, to own constraint intersection — so
   `SOLVE-CONFLICT` is the canonical slug — and **both impls change**, not just Rust
   (Depth-F8): Rust defers the satisfiability verdict to the solver (enumerate-all at Phase
   A), **and Python drops/relaxes its own pre-check** at `:1187-1188` (which calls
   `index.resolve_named_all(name, constraint_str)` and would itself raise
   `TNG-NO-SATISFYING-VERSION` when `constraint_str` is non-`None` and nothing satisfies —
   so Python *also* emits the wrong slug on this path unless reconciled with
   `_enumerate_named_stubs`' `constraint=None`). S6 must list both impls' edits explicitly.
   This investigation is pulled out as a **pre-slice spike** (see S5b) so the fork is
   resolved *before* the implementing slice writes its test. **No speculative fix.**

### 3.C  #159 — Profile optional axes

Make Python `Profile` axes `str | None` to mirror Rust's `Option<String>`. Split the
constructor so the partial-profile case is explicit at the call site rather than hidden
behind a changed default:

```python
@classmethod
def partial(cls, *, platform=None, arch=None, nim=None, milpa=None) -> Profile:
    # explicit partial constructor; any axis not provided is None. No env-var coupling.
@classmethod
def from_environment(cls, …) -> Profile:   # MILPA_TARGET_* + host defaults (CLI path)
```

**Naming (Design-F2): `partial`, not `from_env_overrides`.** The conformance/CLI distinction
must not leak into the type. `from_env_overrides` conflates "env-var overrides" with "partial
profile" — a resolver unit test wanting `Profile(platform="linux", arch=None, …)` has no env
var in play. `Profile.partial(...)` is an explicit partial constructor mirroring Rust's
`Profile { platform: Option<String>, … }` field-setting, with **no env coupling**; the
conformance runner builds it from `MILPA_TARGET_*` reads and returns `None` when no axis is
set (the runner already has this guard at `test_conformance.py:254-259`). The CLI calls
`from_environment()` (host-defaulting stays per `cli-contract §8`); a partial profile
(`platform="linux", arch=None, …`) is then representable and byte-identical across impls.
**Audit every `Profile(...)` construction site** when the fields become optional (Rust is
already `Option`) — and mandate that resolver *behavior* unit tests use `Profile.partial(...)`,
reserving `from_environment()` for tests explicitly about host-default behavior.

**Absent-axis predicate semantics (the load-bearing decision — both impls must match).**
A predicate over an absent axis is **indeterminate**, and indeterminate ⇒ the dep is
**excluded**, *for both positive and negated forms*. This is three-valued logic collapsed
conservatively: if we cannot evaluate whether the dep applies to this target, we do not
deterministically include it. Concretely, with `platform` unset:
- `when platform == "linux"` → excluded (Python `:776-778` already does this).
- `when platform != "windows"` → **also excluded** (we cannot confirm the platform is
  *not* windows when we don't know it).

Today Python excludes both (early `return False` before checking `negated`), but **Rust
returns `True` for the negated case** (`!any_match` at `:3289-3312`) — a real divergence
that S4 will surface. Rust's negation handling changes to match. The earlier RFC phrase
"absent axis *disables filtering*" was backwards (it reads as *include*); the normative
statement is: **an absent axis makes every predicate over that axis evaluate to `false`,
regardless of negation.** This is distinct from an absent *whole* profile, which disables
non-flag filtering entirely (passthrough). Spec: `resolver-semantics §470/§6`, with a
fixture carrying a *negated* predicate over an unset axis.

### 3.D  #93 — member `self_src_dir`

`format_workspace_nimcfgs` emits, for each member with `src_dir` set, a
`--path:"<member-relative src_dir>"` line **before** the dep paths — the same
shadowing-first ordering as `format_nimcfg`. Member-to-member references already point
at the other member's directory; this is purely the member's *own* src.

**Ordering is normative (Breadth-P3d).** With multiple members carrying `src_dir`, each
member's `nim.cfg` emits: **self-`src_dir` first, then all other deps (member + external)
lex-sorted by name** — exactly the single-package `format_nimcfg` rule (`nimcfg.py:85-86`
self-first; `:195` lex-sort). Pin this with a **3-member** fixture (A→B, B→C, A has
`src_dir "src"`) so the self-first + lex-sort order is specified, not incidental. Spec:
`cli-contract §5.9`.

### 3.E  #129 — `--certificate` in workspace (Rust)

Rust workspace fetch/lock branch reads `cert_path` and writes the §5 result certificate
(success cert on resolve, failure cert on `SOLVE-CONFLICT`) — mirroring Python
`_cmd_fetch_workspace`. The certificate content for a workspace is defined by
`cli-contract §2.5` over the workspace graph (already defined for the single graph;
workspace graph is one graph).

### 3.F  #81 — workspace manifest mutation

**Mutation is canonical re-serialization, NOT comment-preserving.** Earlier drafts said
"comment-preserving (kdl-py AST mutate path)" — that is wrong. Neither impl has a
trivia-preserving path: `format_manifest` warns *"comments are not preserved when the
manifest is rewritten"* (`manifest.py:2388`), and Rust `manifest_writer.rs:7-8` states the
formatter is declarative and drops hand-written comments. Workspace mutation drops
comments with the same warning, exactly like package mutation. **`format_workspace_manifest`
does not exist in either impl and must be built** (a canonical `WorkspaceManifest → KDL`
serializer, byte-identical across impls) before S9's fixture can pass.

**Typed writers, not a runtime path-dispatcher.** A loaded document is *already* either a
`Manifest` or a `WorkspaceManifest` — re-detecting "file kind" from a path (`apply_change(path)`)
is runtime type-detection where the type system already knows the answer, and it forces a
redundant parse. Keep the two paths typed and let the **caller** (which knows its kind)
pick:
- `mutate_workspace_manifest_file(path, mutator)` — typed analog of `mutate_manifest_file`.
- `apply_workspace_manifest_change(root, *, validate, mutate)` — orchestration analog.

  **Atomicity ordering (mirror the single-package add/remove, `cli.py:1683-1688`):**
  *validate → workspace-resolve with the proposed manifest in memory → write manifest →
  write lock.* Resolve **before** any on-disk mutation, so a **network or resolution
  failure** leaves the manifest untouched — this closes the window the naive
  *mutate→resolve→write-lock* ordering opens (where a relock network failure leaves the
  manifest mutated and the lock stale). **Honest scope (Depth-F2):** the only residual
  window is a *filesystem write failure between the manifest write and the lock write* —
  a crash-safe filesystem recovers on re-run, and this is identical to what single-package
  add/remove already accept; it is *not* eliminated, only minimized. Both writes go through
  the existing `_atomic_write_text` primitive (`manifest_writer.py:83`).

  `add`/`remove` call `apply_manifest_change`; `workspace add-member`/`remove-member` call
  `apply_workspace_manifest_change`. No `apply_change(path)` dispatcher. **Signature
  symmetry (Design-F4):** both orchestration fns take the same shape — either both accept an
  explicit `validate` callable or neither does (the workspace path's validation is the same
  "the mutated doc parses + resolves" check the package path performs implicitly); do not
  introduce an asymmetric keyword-only `validate` arg on only the workspace variant. Both
  compose `_atomic_write_text`; the only essential difference is the typed doc they load.
- Verbs: `milpa workspace add-member <path>` appends a `member` node (validates the dir
  exists, has a `milpa.kdl` with a `name`, no nesting, name-unique) then relocks;
  `milpa workspace remove-member <name|path>` drops it then relocks.
- **`remove-member` with a dangling reference → refuse (two symmetric classes, Depth-F3).**
  Removing a member can orphan two distinct kinds of reference; both must be refused up front
  rather than surfaced as an opaque downstream relock error:
  1. **Dangling override** — the workspace root's `overrides {}` has a `MemberTarget` pointing
     at the removed member. Refuse with `WS-REMOVE-MEMBER-TARGET-EXISTS` (renamed from the
     draft's `WS-REMOVE-MEMBER-HAS-OVERRIDES`, which collides confusingly with the *existing*
     `WS-MEMBER-HAS-OVERRIDES` at `errors.md:1191` — that one fires when a member declares its
     *own* overrides block; this one fires when the *root* targets the member being removed,
     Depth-F5).
  2. **Dangling member-edge** — *another* member's `deps`/`dev_deps` carries `member "<removed>"`.
     Removal would make the next relock fail with `RES-WS-MEMBER-REF-UNKNOWN`. Refuse with
     `WS-REMOVE-MEMBER-REFERENCED` and name the referencing member(s) in the message.
  **Pre-existing bug to fix in passing (Depth-F3):** the `RES-WS-MEMBER-REF-UNKNOWN` validator
  iterates only `member.manifest.deps`, **not `dev_deps`** (`resolver.py:3428`,
  `resolver.rs:555`), so a `member "X"` in `dev_deps` is an *undetected* dangling reference
  today. Fix both impls (and the class-2 refusal above must check `dev_deps` too). Folded into
  S5's workspace-resolver touch.
- **`add-member` structural validation reuses existing slugs (Depth-F4 — resolved, not deferred).**
  "dir exists but `milpa.kdl` has no `name`" already fires `MAN-NAME-MISSING`
  (`manifest.py:1018-1022`, `errors.md:760`); `WS-MEMBER-NO-MANIFEST` means "the file does not
  exist at all." No new slug and no widening — the two existing slugs already partition the
  cases correctly.
- **New error slugs** (full 1:1 bijection sync, spec ↔ `errors.py` ↔ Rust `all_codes()`):
  `WS-REMOVE-MEMBER-NOT-FOUND` (name/path not in members), `WS-REMOVE-MEMBER-TARGET-EXISTS`
  (class-1 above), `WS-REMOVE-MEMBER-REFERENCED` (class-2 above). Each slice introducing a slug
  carries its full `errors.md` entry text (trigger condition + narrative), not just "add to
  errors.md" (Depth-F5).
- Lift `MAN-MUTATE-WORKSPACE-REFUSED` **only** for the workspace-typed path; a plain
  package mutate of a workspace doc still errors with it.

### 3.G  G7 — `milpa update` workspace-awareness + verb-at-root cleanups

**No "fail cleanly" escape hatch.** The RFC's own thesis forbids a feature cliff, and
`feedback_no_workarounds` forbids the symptom-patch. `update` does the **full workspace
re-resolve** (drop pins → re-resolve the shared graph → refresh the shared lock),
mirroring `fetch`. This is **Rust-already-done** (`cmd_update`, `main.rs:809-831`); the
fix is **Python-only** (`cmd_update` currently calls `parse_manifest` → raises
`MAN-WORKSPACE-HAS-DEPS-OR-KIND`). Bring Python to parity with Rust + pin both with a
fixture. (`update` writes no `nim.cfg` in either impl — consistent, keep it.)

**`add`/`remove` at a workspace root** surface the **existing canonical**
`MAN-MUTATE-WORKSPACE-REFUSED` with a directive message ("to add a dep, `cd` to a member;
to add a member, use `milpa workspace add-member`"). Today Python emits
`MAN-WORKSPACE-HAS-DEPS-OR-KIND` and Rust reuses `MAN-ADD-DEP-EXISTS`/`MAN-REMOVE-DEP-ABSENT`
— three different wrong slugs; unify both impls on `MAN-MUTATE-WORKSPACE-REFUSED`.

**Rust `clean` per-member `nim.cfg`** (`main.rs:371-375`): in workspace mode remove
`<root>/_deps` + each member's `nim.cfg`, matching Python and `cli-contract.md:602-603`.
Rust-only fix + a fixture asserting each member's `nim.cfg` is absent post-`clean`.

**`add`/`remove`/`update` from a member dir → detect-and-delegate (D5, the eighth asymmetry).**
The thesis forbids a feature cliff at the member boundary: a member dir must behave like a
standalone package *and* keep the shared graph coherent. Today these verbs never call
`find_workspace_root` (`cli.py:1683,1897,1950`; `main.rs:960-990`) so they silently write a
member-local lock — a real corruption bug. Normative behavior: from a member dir, detect the
parent workspace, mutate **the member's** manifest, then re-resolve the **whole workspace**
(shared lock + shared `_deps/`), exactly as `cargo add` does from a member. (Detect-and-refuse
was the bounded alternative; the thesis + cargo precedent select full delegation.) Implemented
in S11e on S9b's machinery.

---

## 4. Spec changes (normative)

**Discipline: each slice carries its own spec edit.** A fixture cannot be authored from a
spec section that doesn't exist yet (G8 makes the spec the oracle). Every slice below that
changes behavior names the spec section it edits *in the slice bullet*, and the edit lands
*in the same slice* as its fixture — no batched spec-sync at the end.

- `resolver-semantics.md`: §3.A shared `filter_manifest`/`FilterContext` + member-deps'-own-deps
  flag-filter rule; §3.B canonical workspace==union lockfile (pin) + **Phase-A error-slug
  ownership** (`SOLVE-CONFLICT` canonical, enumerate-all normative); §3.C absent-axis vs
  absent-profile distinction **incl. negated-predicate-over-absent-axis ⇒ false** (§470/§6).
- `cli-contract.md`: `--certificate` honored by workspace `fetch`/`lock` (both impls) —
  the workspace certificate is compared as **parsed JSON, not bytes** (`cli-contract.md:238-241`
  already normative; the two impls' JSON *formatting* differs — Python `json.dumps(indent=2)`
  vs Rust's hand-rolled writer — so byte-equality is the wrong assertion, Feasibility-F2);
  **new §5.9** `milpa workspace add-member`/`remove-member` verbs (validation + relock
  ordering) + multi-member `self_src_dir` emit ordering (§3.D); `update`/`add`/`remove`/
  `clean`/`show` behavior at a workspace root **and from within a member dir** (see §3.G).
- `manifest-grammar.md`: `member` node is **non-`when`-gateable** (parser rejects a
  `member` inside a `when` block — §3.A); workspace-manifest mutation is well-defined
  (member-node add/remove is a canonical re-serialize — **comments are dropped with a
  warning**, same as package manifests; not trivia-preserving). **De-facto byte-normativity
  (Depth-F6):** `manifest-grammar.md:997-998` says the serializer is "not byte-normative,"
  but the existing `add`/`remove` corpus fixtures byte-compare `expected/milpa.kdl` — so the
  *canonical* serializer is byte-normative **in practice**. `format_workspace_manifest`
  inherits this: its output is byte-pinned by fixtures. Update the spec sentence to say the
  canonical serializer's output IS byte-stable (distinct from "round-trips the original
  source," which it does not).
- `errors.md` (each added with 1:1 bijection sync `spec/errors.md` ↔ `errors.py` ↔ Rust
  `all_codes()`, each with full entry text in its slice): `MAN-MEMBER-WHEN-GATED`,
  `WS-REMOVE-MEMBER-NOT-FOUND`, `WS-REMOVE-MEMBER-TARGET-EXISTS`, `WS-REMOVE-MEMBER-REFERENCED`;
  **plus** correct the misuse of existing slugs — `add`/`remove`-at-ws-root must emit
  `MAN-MUTATE-WORKSPACE-REFUSED` in both impls (no new slug, but a normative correction).
- `lockfile-schema.md`: no change expected (workspace lock already shares the schema;
  confirm `source = "member:<name>"` round-trips under mutation).

---

## 5. Slices (TDD-sized, each independently testable; each gated by
`cd impls/python && uv run pytest` green **and** `./dev-rust test --workspace` green,
corpus divergences NONE)

> Ordering rationale: semantics first (they can change lockfiles), then nim.cfg, then
> CLI. Within semantics, the shared-dispatch refactor (S1) precedes the fixtures that
> would otherwise inherit the divergence.

**Bucket A — features × workspace**
- **S1 [code, both impls]** Extract `filter_manifest(manifest, ctx: FilterContext)` (§3.A)
  — **all three behaviors present in the helper from the start** (profile, flag-only,
  passthrough), unit-tested in isolation for every arm (the third arm is dead at the
  workspace call sites until S2 — that's fine; S1's unit tests do the RED work for S2's
  arm). Route single-package `resolve()` through it; **no single-package behavior change**
  (regression-gated, full corpus green). **Rust scope (per §3.A): not a mechanical
  extraction** — extend `resolve_workspace`/`seed_workspace` signatures with the
  feature-selection inputs + workspace `cli_seed` computation + conformance-runner wiring,
  so S2 can reach the arm. (S1 and S2 are kept separate deliberately — S1 is the
  refactor-with-green-corpus checkpoint; if the reviewer prefers, they may land together,
  but the gate is identical.)
- **S1b [code+fixture, both impls]** `MAN-MEMBER-WHEN-GATED`: parser rejects a `member`
  node inside a `when` block (§3.A); errors-bijection sync; fixture asserts the parse
  error in both impls. (Small, isolatable; closes the latent silent-drop hole before any
  filter fixture relies on member semantics.)
- **S2 [code+fixture, both impls]** #160: wire the flag-only arm into **both** workspace
  application sites (candidate pre-registration `_build_member_candidate` **and** BFS seed
  loop — §3.A) via S1's helper. Fixtures: (a) member dep flag-gated, resolved under
  `--features` no-profile — red before S2, green after; (b) the **frozen** path
  (`resolve_workspace_frozen` seeds member deps too) under the same conditions. **Plus the
  frozen-flags mismatch (Breadth-P1b, §3.A):** filter member deps in `resolve_workspace_frozen`
  *before* its "dep not in lock" check, and run the workspace `FROZEN-ACTIVE-FLAGS-MISMATCH`
  check in the CLI frozen path; fixture: ws locked under `--features`, re-run `--frozen`
  without it ⇒ `FROZEN-ACTIVE-FLAGS-MISMATCH` (not `FROZEN-MANIFEST-DEP-NOT-IN-LOCK`). All
  byte-identical across impls. Close #160.
- **S3 [code-spec+fixture]** Pin §3.8 union: a 2-member workspace where members request
  disjoint flags on a shared dep ⇒ unified `active_flags` + unified `-d:` defines in *both*
  members' nim.cfg. **Plus** a flag-*conflict* variant: memberA wants `async`, memberB wants
  `sync`, and the dep declares them conflicting ⇒ the union raises **`RESOLVE-FLAG-CONFLICT`**
  (the real slug — `errors.py:233`, `errors.md:983`; the draft's `FLAG-CONFLICT` does not
  exist, Depth-F1/Feasibility-F5). **Hidden spec-authoring:** workspace *cross-member*
  flag-conflict is not in `resolver-semantics` today (only single-resolve per-dep
  post-fixpoint validation is) — S3 must author the `resolver-semantics §3.8-conflict`
  section in the same slice as its fixture (§4 discipline). **Plus** a workspace
  *non-member* git-URL override success fixture (a member's transitive dep redirected via
  the root `overrides {}` to a non-member URL — the resolver path exists but is corpus-untested,
  Breadth-P2b).
- **S4 [code+fixture, both impls]** #159: Python `Profile` axes → `str | None`; split
  `from_env_overrides()` (conformance) / `from_environment()` (CLI host-default); **audit
  all `Profile(...)` call sites**; `_predicate_satisfied` — absent axis ⇒ `false` for
  **positive *and* negated** predicates (Rust negation handling changes to match — §3.C).
  Fixtures: partial profile (one axis set) with (a) a positive predicate over the unset
  axis and (b) a **negated** predicate over the unset axis, **inside a workspace member's
  deps**. Sharpen `resolver-semantics §470/§6`. Close #159.

**Bucket B — resolver parity**
- **S5 [code+fixture, both impls]** Workspace==union parity fixture; close #109. **Plus,
  while touching the workspace resolver:** (a) fix the `RES-WS-MEMBER-REF-UNKNOWN` validator
  to iterate `dev_deps` as well as `deps` (`resolver.py:3428`, `resolver.rs:555` — Depth-F3);
  (b) check the **named-dep→member auto-coercion** version constraint against the member's
  declared `version`, raising on mismatch (Breadth-P1c, §3.A) + fixture; (c) add a workspace
  **named-dep-via-index success** fixture (mocked index, member with a named dep — the
  `resolver.py:3440-3460` path is corpus-untested; complements the existing
  `fixture-113-res-ws-no-index` error case, Breadth-P2a).
- **S5b [SPIKE, Rust, pre-slice]** Resolve fork F-a *before* S6. A standalone
  `milpa-core` unit test constructing the error-path case (§3.B: dep requires `foo>=2.0`,
  index has only 1.x). Output is deterministic: either it demonstrates the
  `TNG-NO-SATISFYING-VERSION` vs `SOLVE-CONFLICT` divergence (→ S6 is "switch Rust to
  enumerate-all, `SOLVE-CONFLICT` canonical") or proves invariance (→ S6 is a doc note).
  Deliverable: the unit test + the resolved fork. (A spike, not a TDD slice — you cannot
  write a failing fixture for "find out whether X diverges.") **Loop-gate exception
  (Feasibility-F7):** a spike that deliberately surfaces a *failing* diagnostic breaks the
  loop's "each slice tests-green" contract — so write the diagnostic as a
  `Result<(), _>`/assertion that **records** the observed slug on both paths and passes
  (proving *which* outcome occurs), or mark it `#[ignore]` for manual run. The loop's green
  gate is preserved; the fork is resolved by reading the recorded outcome.
- **S6 [code-or-doc, both impls]** Implement S5b's resolved target. If divergent (D1):
  **both** impls change (Depth-F8) — Rust defers the satisfiability verdict to the solver
  (enumerate-all at Phase A), **and** Python drops/relaxes its `:1187-1188` pre-check (which
  otherwise emits `TNG-NO-SATISFYING-VERSION` itself on the non-`None` constraint path) so
  both reach `SOLVE-CONFLICT` — plus normative slug note + corpus fixture asserting
  `SOLVE-CONFLICT`. If benign: the invariance doc + fixture. Known target — no embedded fork.
  (Not Rust-only: list each impl's exact edit in the slice.)

**Bucket C — CLI symmetry**
- **S7 [code+fixture, both impls]** #93: per-member `self_src_dir` emission in
  `format_workspace_nimcfgs`/Rust mirror (`nimcfg.rs:185-248`); nim.cfg conformance
  fixture asserts the ordering (self path first). The cleanest slice (~5 lines/impl).
  Close #93.
- **S8 [code+fixture, Rust]** #129: Rust workspace `fetch`/`lock` honor `--certificate`
  (the workspace branch returns at `main.rs:598` before any cert code; route `cert_path`
  into the workspace branch's post-resolve emission). **Fixture-ownership decision first:**
  certificate fixtures are `CliOnly` (`fixture.rs:50-52`) and are *not* run by the
  in-process corpus that `./dev-rust test --workspace` exercises — **so `./dev-rust test
  --workspace` will SKIP this fixture (Feasibility-F1); the binding gate is the black-box
  harness** (`python -m harness --fixture …`). Author it as a `check-certificate` harness
  fixture and state the gate explicitly. **Assert parsed-JSON equality, NOT bytes
  (Feasibility-F2):** `cli-contract.md:238-241` is normative that the certificate check
  compares *parsed JSON objects* — Python emits `json.dumps(indent=2)`, Rust hand-rolls a
  different layout, so the bytes legitimately differ while the objects are equal. Assert the
  workspace certificate's JSON *object* matches Python's. Close #129.
- **S9a [code, both impls]** #81 part 1a — the serializer: build `format_workspace_manifest`
  (new canonical `WorkspaceManifest→KDL` serializer, byte-stable across impls — **comments
  dropped with a warning**, §3.F) + idempotence property test + `mutate_workspace_manifest_file`.
  No orchestration, no relock. **Cross-impl byte-identity has no existing harness mechanism
  (Feasibility-F4):** the package serializer is only ever checked via `add`/`remove` CLI
  fixtures — there is no `manifest-roundtrip` Cmd. S9a must either (i) add a
  `workspace-manifest-roundtrip` Cmd to `fixture.rs` + `harness/runner.py`, or (ii) defer
  byte-identity verification to S10's `add-member`/`remove-member` output diff. Pick (i) if a
  standalone serializer fixture is wanted; (ii) otherwise. State the choice in the slice.
- **S9b [code, both impls]** #81 part 1b — orchestration: `apply_workspace_manifest_change`
  with the **validate→resolve-in-memory→write-manifest→write-lock** ordering (§3.F atomicity),
  composing `_atomic_write_text`. **Depends on S1+S2 green** (the in-memory re-resolve calls
  the feature-extended `resolve_workspace`). **Two typed orchestration functions, symmetric
  signatures, no `apply_change(path)` dispatcher** (§3.F). Lift the refusal for the
  workspace-typed path only.
- **S10 [code+test]** #81 part 2: the `add-member`/`remove-member` verbs (exact CLI surface
  per D4 below) + **new §5.9 cli-contract** + slugs (`WS-REMOVE-MEMBER-NOT-FOUND`,
  `WS-REMOVE-MEMBER-TARGET-EXISTS`, `WS-REMOVE-MEMBER-REFERENCED`). Happy-path CLI fixture
  (add → member discoverable on next fetch; remove → absent from next resolve) **and
  failure-path fixtures**: add-member of missing dir, `milpa.kdl`-without-`name`
  (→ `MAN-NAME-MISSING`), duplicate name, nested-workspace; remove-member of unknown member;
  remove-member with a dangling root override (→ `WS-REMOVE-MEMBER-TARGET-EXISTS`);
  remove-member referenced by another member's `deps`/`dev_deps` (→ `WS-REMOVE-MEMBER-REFERENCED`).
  Gate is the black-box harness (CLI verbs are `CliOnly`, Feasibility-F1). Close #81.
  > **Harness-gate note for S11a–c (Feasibility-F1):** `add`/`remove`/`update`/`clean` are
  > `CliOnly` — `./dev-rust test --workspace` SKIPS their fixtures. Each slice's binding gate
  > is `uv run pytest` **and** the black-box harness (`python -m harness --fixture …`), not the
  > in-process corpus.
- **S11a [code, both impls]** `add`/`remove` at a workspace root emit the canonical
  `MAN-MUTATE-WORKSPACE-REFUSED` directive (fixing two *different* wrong slugs today —
  §3.G); fixture pins the slug in both impls.
- **S11b [code, Python; fixture both]** G7: Python `milpa update` full workspace
  re-resolve (Rust already done — §3.G); fixture pins workspace `update` parity. **Also
  picks up the orphaned `verify` workspace `FROZEN-ACTIVE-FLAGS-MISMATCH` check
  (Breadth-P2c):** `cli.py:1191-1194` defers it to "S11" but no slice claimed it — it shares
  the workspace-flag-check concern with `update`, so land it here (complements S2's `fetch`
  frozen path).
- **S11c [code, Rust; fixture both]** Rust `clean` removes each member's `nim.cfg` in
  workspace mode (§3.G, `cli-contract.md:602-603`); fixture asserts member `nim.cfg`
  absence post-`clean`.
- **S11e [code+test, both impls]** **The eighth asymmetry (D5): `add`/`remove`/`update` from
  within a member dir → detect-and-delegate.** Today both impls silently write a member-local
  `milpa.lock` + `_deps/`, diverging from the shared graph (`cli.py:1683,1897,1950`;
  `main.rs:960-990` never call `find_workspace_root`). Fix: from a member dir, detect the
  parent workspace (`find_workspace_root`, as `fetch`/`lock`/`verify`/`clean` already do),
  mutate **the member's** manifest, then re-resolve the **whole workspace** (shared lock +
  shared `_deps/`) — same as `cargo add` from a member. Reuses S9b's
  `apply_workspace_manifest_change` machinery (the member-manifest mutate + workspace relock)
  and S11b's `update` workspace re-resolve. Spec: `cli-contract §5.6-5.8` member-dir behavior.
  Fixtures (harness, both impls byte-identical): `add` a dep from member A ⇒ shared
  `<root>/milpa.lock` gains it, member-local lock NOT written; `remove` from member A ⇒
  dropped from shared graph; `update` from member A ⇒ full workspace re-resolve. **Depends on
  S9b + S11b green.**
- **S11d [deferred → follow-up issue #165]** `milpa show` member-scoped output (F-d). Filed
  as #165; fold into S11* only if it falls out cheaply.
  Until then, spec a sentence in `cli-contract.md` for `show`-at-ws-root current behavior
  (flat shared-graph dump; `LOCK-FILE-NOT-FOUND` from a lockless member dir).

**Close-out**
- **S12 [doc]** Rewrite CLAUDE.md's stale "Open question: #25 re-scoping" section to
  point at this RFC's outcome; refresh the roadmap (#25 done, Bucket A/B/C done).

---

## 6. Cross-impl divergence risks (each pinned to a slice)

1. **S1** — the shared-dispatch extraction must be byte-equivalent to today's
   single-package behavior in *both* impls before any workspace fixture relies on it,
   or every later fixture inherits a refactor bug. Gate: full corpus green post-S1.
2. **S2** — the flag-only arm must filter at the *same point* (pre-BFS-seed) in both
   impls; assert via a transitive-flag-gated member fixture.
3. **S4** — None-axis semantics must match exactly **including negation**: Python excludes
   a negated predicate over an absent axis, Rust currently *includes* it. The
   partial-profile fixture MUST carry a negated predicate over the unset axis or the
   divergence ships silently.
4. **S5b/S6** — the Phase-A question is the highest-risk: the divergence is on the
   **error path** (`TNG-NO-SATISFYING-VERSION` vs `SOLVE-CONFLICT`), not selection, so a
   "benign" verdict that only checked selection would be wrong. The S5b spike must test
   the *error* case explicitly, never a bare selection assertion.
5. **S8** — the certificate's *parsed JSON object* for a workspace must match across impls
   (NOT bytes — the impls format JSON differently; `cli-contract.md:238-241` mandates
   parsed-object comparison, Feasibility-F2). The gate is the black-box harness, since
   certificate fixtures are `CliOnly` and the in-process corpus skips them (Feasibility-F1).
6. **S9** — `format_workspace_manifest` is *new in both impls*; its output must be
   byte-identical before any mutation fixture can pass. Comments are dropped (with a
   warning) by design — the fixture must not assert comment round-trip.

---

## 7. Open forks / normative decisions (for architecture review / Corey)

**Resolved during round 1 (no longer forks — recorded for the trail):**
- ~~**F-b** `apply_change` dispatcher vs typed functions~~ → **resolved: typed functions.**
  Runtime path-detection is a smell where the type system already knows the kind; callers
  know their kind. (§3.F.)
- ~~**F-c** `update` full re-resolve vs clean-fail~~ → **resolved: full re-resolve.** The
  thesis forbids the feature cliff, and Rust *already* does it; only Python lags. (§3.G.)
- ~~**F-d** `milpa show` member-scoping~~ → **resolved: follow-up issue (S11d), file now.**

**Resolved by Corey (round 1) — all three confirmed as recommended; now normative:**

- **D1 (S5b/S6) — Phase-A error-slug ownership → `SOLVE-CONFLICT` canonical.** When an
  index has no version satisfying a declared constraint, enumerate-all is normative (the
  solver, not the enumerator, owns satisfiability); **Rust changes** to defer the verdict.
- **D2 (§3.C, S4) — absent-axis predicate ⇒ `false` for positive AND negated.**
  Indeterminate ⇒ excluded, conservatively. **Rust's negation handling changes** to match.
- **D3 (§3.A, S1b) — `when`-gated `member` ⇒ parse error `MAN-MEMBER-WHEN-GATED`.** Members
  are unconditional workspace topology.

**Resolved by Corey (round 2) — both confirmed; now normative:**

- **D4 (§3.F, S10) — member-management verb shape → grouped `milpa workspace add-member` /
  `milpa workspace remove-member`.** Namespaced under a `workspace` subcommand group (Rust
  gains a two-level dispatch; argparse gets a nested subparser). The
  `MAN-MUTATE-WORKSPACE-REFUSED` directive references `milpa workspace add-member`.
- **D5 (§3.G, S11e) — `add`/`remove`/`update` from a member dir → detect-and-delegate
  (full parity).** Detect the parent workspace, mutate the member manifest, re-resolve the
  whole workspace. The thesis + cargo precedent select full delegation over the bounded
  detect-and-refuse alternative. New slice S11e.

*(No open forks remain. The RFC is ready for `/tdd`.)*

---

## 8. Acceptance (definition of done)

- #160, #159, #109, #93, #129, #81 closed; G7 landed (`update` parity, ws-root slug
  unification, Rust `clean` per-member `nim.cfg`); the **eighth asymmetry** (member-dir
  `add`/`remove`/`update` → detect-and-delegate, S11e) closed.
- Every Bucket A/B/C behavior covered by a `conformance/spec-v1/` fixture,
  byte-identical Python↔Rust (certificates compared as **parsed JSON**, not bytes),
  zero corpus divergence — **including** the failure-path fixtures (S1b parse error, S10
  add/remove-member failures, S4 negated-absent-axis, S2 frozen-flags mismatch).
- `filter_manifest(manifest, ctx)` via the `FilterContext.build` smart constructor is the
  single source of the filter logic per impl (no second copy in the workspace path, and
  `resolve_with_cert` routed through it too); no `apply_change(path)` runtime dispatcher.
- New slugs (`MAN-MEMBER-WHEN-GATED`, `WS-REMOVE-MEMBER-NOT-FOUND`,
  `WS-REMOVE-MEMBER-TARGET-EXISTS`, `WS-REMOVE-MEMBER-REFERENCED`) pass the 1:1 bijection
  lint; `add`/`remove`-at-ws-root emit `MAN-MUTATE-WORKSPACE-REFUSED` in *both* impls; the
  pre-existing `RES-WS-MEMBER-REF-UNKNOWN` `dev_deps` blind spot is fixed.
- CLAUDE.md stale section replaced; roadmap refreshed.
- The fresco real-tree integration test still passes (don't break the primary fixture).
