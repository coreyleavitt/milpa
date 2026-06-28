# RFC: Resolver & frozen-path correctness

Status: **design draft** — architect round 1 applied (2026-06-27): stub fleshed into a
sliced design grounded in a both-impl code map of all five live bug sites, then
hardened by a 4-lens review team (depth / breadth / design / feasibility). One new
Critical surfaced during review (#178). Umbrella: #172. Milestone: *v0.x / v1 —
correctness*.

## Problem

A set of resolver-core and frozen-fast-path correctness issues that don't belong to
any feature RFC — they're invariants on dedup identity, named-dep qualification, and
the frozen-resolve fast path. Each is a place where the resolver can produce a
subtly-wrong graph, mis-cache, silently no-op, or diverge across impls.

## Issues unified

- **#108 — qualified `NamedDep(namespace, name)` end-to-end.** `resolver.py`'s
  `seen_named: set[str]` (Rust: `RefCell<BTreeSet<String>>`) dedups transitive named
  deps by **bare name**. The registry layer already models `Package(namespace, name)`,
  but every consumer key downstream (`seen_named`, provenance key `("named", name)`,
  `EdgeSourceCtx.dep_name`, `_NamedStub.name`, **and the PubGrub solver variable**) is
  bare. **Masked today, not unreachable:** a bare-name collision across namespaces
  currently trips `TNG-AMBIGUOUS-NAME` in `lookup_bare` *before* `seen_named` is
  consulted, so the silent collapse never fires — but the key is structurally wrong,
  and the collapse becomes reachable once two namespaces can co-resolve. **Resolved:
  ship qualified naming end-to-end** (internal key *and* manifest grammar) — the
  `TNG-AMBIGUOUS-NAME` message already promises "use a namespace-qualified reference,"
  so the grammar is the root-cause fix for a spec hole, not optional scope. Split
  S5a (internal key) / S5b (grammar) for TDD granularity, not deferral. See S5.
- **#115 — legacy `registry` provenance disqualifies the frozen fast-path.** A
  lockfile entry with the pre-#97 `kind "registry"` provenance trips
  `FROZEN-LEGACY-REGISTRY-PROVENANCE` on both frozen paths, forcing a full re-resolve on
  every `fetch`. **Resolution (revised 2026-06-27, Corey):** milpa is pre-v1 with NO
  external consumers — a *migration path for an obsolete format is itself the workaround.*
  **Delete the legacy `registry` provenance kind outright** (no migration, no auto-heal,
  no actionable error): an old lockfile simply fails to parse → regenerate. A sweep
  (S3) found three more read-compat shims of the same class — purge them all and make the
  parser strict. See S3.
- **#131 — URL/tarball/local resolve workers bypass the `resolve_edges` coordinator.**
  **Not only an SSOT violation — a correctness gap.** `resolve_edges`
  (`edge_sources.py:453`, `edge_sources.rs:260`) is the normative §4.2.1 coordinator:
  clause (a) cache → (b) override-suppression → (c) DepDecl indexing → (d)
  milpa.kdl/Nimble fallback. Python's per-transport workers call `_pick_edges`
  (`resolver.py:2572`) — **only clause (d)** — so URL/tarball/local deps **silently
  ignore user overrides (b) and attested DepDecl metadata (c)**. *Worse:* the workers
  also call `_collect_transitive_deps`, a **second independent parse** of the same tree
  that skips flag-filtering and overrides, so the BFS-enqueue view and the solver-edge
  view can disagree (latent over-fetch + override-blind transitive enqueue). Rust's
  `extract_requires` (`resolver.rs:2485`) duplicates the coordinator inline for *all*
  deps and never calls `resolve_edges` (dead coordinator). Three edge-resolution paths
  where there should be one.
- **#142 — frozen manifest-coverage check is not alias-aware.**
  `FROZEN-MANIFEST-DEP-NOT-IN-LOCK` (`frozen.py:196`/`339`, `frozen.rs:288`) matches
  manifest deps against lockfile **canonical names** only. Phase B content-dedup **is
  fully implemented** — `_dedup_candidates` collapses same-identity deps to one
  canonical `LockedDep` carrying an `aliases` tuple, written to and read back from the
  lockfile. So two same-content manifest deps (`foo`, `bar` → identical bytes →
  canonical `foo`, alias `bar`) make the next frozen run **false-positive on `bar`**.
  Currently triggerable, **both frozen paths, both impls**. Clean fix.
- **#178 — Rust `check_manifest_alignment` skips `dev_deps`** (NEW, found in review).
  Python checks `deps + dev_deps`; Rust iterates only `manifest.deps`
  (`frozen.rs:289`). A manifest/member with a dev-dep absent from the lockfile makes
  Python raise `FROZEN-MANIFEST-DEP-NOT-IN-LOCK` while Rust silently passes. Live
  divergence. Folded into S1 (same gate as #142).
- **#168 — workspace cyclic-symlink member yields divergent slug** (`WS-MEMBER-PATH-ESCAPE`
  vs `WS-MEMBER-DIR-MISSING`). Both impls correctly **reject**, but Python's
  `Path.resolve(strict=False)` (`workspace.py:170`) *follows* the symlink → escape (and
  on a true cycle, raises an **unhandled `OSError(ELOOP)`**), while Rust's
  `best_effort_resolve` (`workspace.rs:62`) stops at the longest existing prefix →
  lexical → missing-dir. See Fork C (recommended, resolved).

Note: **#129** (Rust `--certificate` workspace no-op) and **#109** (workspace named →
Phase A/B) were **closed 2026-06-27 / 2026-06-21**. Not part of this RFC.

## Why one RFC

Three shared substrates: the **dedup-identity model** (#108 bare-name key vs
#142/#178 alias/scope), the **frozen fast-path** (#115 provenance gate, #142/#178
coverage gate), and the **resolve-edges seam** (#131 coordinator). Fixing them
piecemeal risks re-introducing the same alias/identity confusion. #168 is the
cross-impl correctness tail and coordinates with `rfc-conformance-parity.md`.

## Design model

**One identity rule, two violations — but only two.** The unifying defect behind #108
and #142 is: *a bare string name is not a sufficient identity key.* The resolver
already has the richer keys — the registry models `Package(namespace, name)` (#108),
the lockfile models `LockedDep.identity` + `aliases` (#142) — but the gates read bare
`name` and discard them. The fix threads the **already-existing** richer key through
the gate that drops it; it does not invent a new identity model (stays aligned with
`spec/identity.md`: identity = content hash; everything else is a label).

To keep S1 and S5 from drifting (they touch the same theme on different code paths),
introduce **one named key type per impl in S1**, not a tuple in S5:

```python
# Python
@dataclass(frozen=True)
class DepKey:
    name: str                       # canonical bare name (always present)
    namespace: str | None = None    # None = default; populated only by S5
```
```rust
// Rust
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DepKey { pub name: String, pub namespace: Option<String> }
```

In S1, `namespace` is always `None` — strictly equivalent to a bare string, but
type-correct everywhere a name is used as a key. S5 *populates* the slot from the
manifest grammar; no gate re-plumbs. A named type (not a tuple) gives call-site
guardrails and forces Python and Rust to converge. Its fields and ordering are specced
in `spec/resolver-semantics.md` so the impls can't name/shape it differently.

**Caveat (#131 is NOT this defect).** #131 is a *coordination-seam* problem — two/three
edge-resolution code paths that should be one deep module — not an identity-key
problem. Do not fold it into the `DepKey` narrative; it shares no code with #108/#142.

**Frozen path invariant (made precise).** The frozen fast-path **MUST NOT write the
lockfile and MUST NOT invoke a fetcher.** It **MAY** rebuild `_deps/` symlinks
(`rebuild_deps_view` already does, legitimately). The earlier "read-only" phrasing was
wrong — `_deps/` view materialization is expected. This precise form is what makes
#115 *path-dependent* (S3): the frozen path may only error; lockfile-writing migration
belongs to the non-frozen `fetch`/`update` path.

## Slices

Each slice gates on `cd impls/python && uv run pytest` **and** `./dev-rust test
--workspace`, lands its conformance fixture(s) in the shared corpus, and keeps the
`spec/errors.md` bijection green. Final ordering (revised by the feasibility lens):
**S1 → S2a → S2b → S3 → S4 → S5a → S5b.**

- **S1 — alias/scope-aware frozen coverage (#142 + #178; both impls; no fork).**
  - Introduce `DepKey` (above) in both impls.
  - Extract one SSOT helper `_locked_index(deps) -> dict[DepKey, LockedDep]` mapping
    **every** name *and alias* to its canonical `LockedDep`; reuse it across **both**
    `resolve_frozen` (`frozen.py:196`) **and** `resolve_workspace_frozen`
    (`frozen.py:339`), and all conditions that currently rebuild `locked_by_name`. Rust
    has a single shared `check_manifest_alignment` — fix once there.
  - #178: Rust `check_manifest_alignment` must iterate `deps + dev_deps`
    (`deps.iter().chain(dev_deps.iter())`).
  - **Two** fixtures (existing `fixture-177`/`178` don't trigger — 177 has only one
    manifest dep; 178 is the live-resolve path, not frozen): (a) single-package frozen
    with **two** same-content manifest deps → 2nd frozen run GREEN; (b) workspace frozen
    member declaring both aliased deps → GREEN. Plus a dev-dep-absent-from-lock fixture
    pinning #178 cross-impl.
  - Spec: sharpen `spec/resolver-semantics.md §7.1 #2` to name `deps` *or* `dev-deps`
    (cross-ref §9).
  - Surface `aliases` in `milpa show` (both impls) so a user can see `bar` was deduped
    into `foo` — this is the slice that completes the alias-identity model. `show` is
    liveness-only/non-normative, so it's a display add, not a conformance-compared field.
- **S2a — Rust coordinator unification (#131, Rust only; SSOT).** Refactor
  `extract_requires` to *call* `edge_sources::resolve_edges` for clauses (b)–(d),
  keeping `Provider`'s `RefCell` cache for clause (a). The dead coordinator becomes the
  single live path. Pure refactor, fast to TDD; establishes the clean coordinator
  shape S2b targets.
- **S2b — Python worker routing (#131, Python only; correctness).** Split
  `resolve_edges` into a pure `_resolve_edges_pure(name, version, ctx, sources) ->
  EdgeSet` (clauses b/c/d) and a thin cached wrapper (clause a, owned by the main
  thread). Workers call the pure variant, passing the shared `edge_cache` **read-only**
  (GIL-safe — workers never write it; the main thread seals). **Delete `_pick_edges`
  unconditionally.** Also replace `_collect_transitive_deps` with the transitive dep
  list **derived from the returned `EdgeSet`**, eliminating the third parse so BFS
  enqueue and solver edges agree. Because workers run inside the shared
  `_run_bfs_wave_loop`, this fix covers `resolve()` **and** `resolve_workspace()`
  identically. Regression fixtures: a URL dep **with an override** and a URL dep **with
  a DepDecl** — both now honored (today: ignored) — including one inside a workspace
  member; assert the solver constraint change, not just "override applied."
- **S3 — purge pre-v1 lockfile read-compat → strict parser (#115 + sweep; both impls).**
  Pre-v1, no external consumers: delete every read-compat shim for a format the writer
  never emits, and every "tolerate absent field on old lockfiles" default. The parser
  becomes strict — unknown kind → `LOCK-PROV-KIND-UNKNOWN`, absent required field → field
  error, old format → regenerate. Four purges (all dead-on-write, confirmed by the sweep):
  1. **`registry` provenance kind** — `RegistryProvenanceRecord` /
     `ProvenanceRecord::Registry`, the `FROZEN-LEGACY-REGISTRY-PROVENANCE` slug + frozen
     condition-6 (both paths), and every parse/format/sort/show arm. Drop `registry` from
     the `LOCK-PROV-KIND-UNKNOWN` known-set. Delete `fixture-114` + its tests. This
     dissolves the `milpa verify` legacy-detection question (nothing to detect).
  2. **`self_mirrors` lockfile node** — parser converts old `self_mirrors` nodes →
     `GitProvenanceRecord`; writer "NEVER emits" (D-provenance removed). Delete the parse
     branch + conversion (Python `lockfile.py:512-563,687-694`; Rust
     `lockfile.rs:134,197-227`) + spec §3.7 + its tests. (The `mirrors {}` manifest field
     is live and separate — KEEP.)
  3. **`strategy` absent → "maxver" default** — make a missing `strategy` node a field
     error (like missing `version`), not a silent default. Spec §2.2.
  4. **`origin` absent → "observed" default** — make a missing provenance `origin` a
     `LOCK-PROV-FIELD-MISSING`, not a silent default. Spec §4.
  Plus a manifest-grammar tightening (Corey, 2026-06-27):
  5. **Require `(url)` annotation on URL fields** — drop plain-string acceptance for
     `git=`/`tarball=`/`mirror` URLs; a bare string raises a manifest parse error. KDL's
     typed annotations are the point. Update `kdl_io.py` `_kdl_entry_as_url` + Rust
     manifest parser + `spec/manifest-grammar.md §3/§4`; reuse an existing manifest-parse
     slug if one fits, else add one (bijection in the same change). Update memory
     [[kdl_url_convention]] post-landing.
  - **Bijection:** `FROZEN-LEGACY-REGISTRY-PROVENANCE` removed from `errors.md` **and**
    `errors.py`/Rust `all_codes()` together.
  - **Fixtures:** delete `fixture-114`; add (a) lockfile with `kind "registry"` →
    `LOCK-PROV-KIND-UNKNOWN`; (b) lockfile missing `strategy` → field error; (c) manifest
    with a plain-string `git=` URL → manifest parse error. (self_mirrors/origin defaults
    have no fixtures to convert — unit tests suffice.)
  - **Out of scope, file separately:** `filter_manifest_by_profile` half-done migration
    (`seed_root` never moved to `FilterCtx`/`filter_manifest` like `seed_workspace`).
- **S4 — cyclic/dangling-symlink slug convergence (#168; both impls).** Converge to
  `WS-MEMBER-DIR-MISSING`. Adopt Rust's algorithm in Python: replace `Path.resolve(strict=False)`
  in `_member_path_is_under_root` with a best-effort resolve that stops at the longest
  existing prefix — this *inherently* avoids the `OSError(ELOOP)` (Python no longer
  follows the cycle) and converges the slug to `WS-MEMBER-DIR-MISSING`. Write the
  normative member-path-canonicalization clause in `spec/` first (oracle), then the
  cyclic-symlink and dangling-symlink fixtures (git-committable; no new harness
  machinery), then the Python fix.
- **S5a — internal qualified key (#108, both impls; correctness).** Thread `DepKey`
  through `seen_named`, the named provenance key, `EdgeSourceCtx`, `_NamedStub`, **and
  the PubGrub solver variable** (today bare-name; `(ns1, foo)` and `(ns2, foo)` must be
  distinct solver variables). Because the manifest grammar to *write* a second namespace
  lands in S5b, S5a's RED test is an **in-process property/unit test** that injects
  synthetic registry namespaces; the cross-impl conformance fixture arrives with S5b.
  S5a is code-independent of S1 (shared theme, not shared code); it can land any time
  after `DepKey` exists.
- **S5b — qualified-name manifest grammar (#108, both impls).** Add namespace-qualified
  named-dep syntax. **Canonical form: a KDL-native `namespace=` attribute** on the
  named-dep node (`pkg namespace="core" "^1.0"`), matching milpa's existing typed-attr
  convention (`git=`, `ref=`) and the pure-data manifest rule. Accept `"core/pkg"`
  slash-shorthand that desugars to the attribute (familiar from cargo/npm/go). Touches
  `spec/manifest.md` grammar + both parsers + CLI `add`/`remove` arg parsing + the
  `TNG-AMBIGUOUS-NAME` message (now reachable-and-resolvable). Makes the #108 collapse
  conformance-testable (two packages, same bare name, two namespaces → distinct solver
  variables → both resolve). Coordinate the qualified solver-variable keying with
  `rfc-index-version-selection.md` (constraint accumulation keys on the qualified var).

## Resolved decisions (no open forks)

Per the PhD-CS / best-dep-manager bar, every fork the review surfaced resolves to a
goal-determined answer. None deferred.

- **#108 surface (was Fork A) → ship qualified naming end-to-end.** The
  `TNG-AMBIGUOUS-NAME` message already promises "use a namespace-qualified reference";
  shipping only the internal key (or deferring the grammar) leaves that a permanent
  dead-end — a workaround, not a fix. The grammar closes a spec hole and is what a
  best-in-class resolver provides (cargo/npm/go all do). S5a/S5b is a TDD split, not a
  scope deferral; both land in this RFC.
- **#115 (revised — Corey, 2026-06-27) → delete the legacy format, strict parser (S3).**
  Pre-v1 with no external consumers, a migration path for an obsolete format IS the
  workaround. Delete the `registry` provenance kind outright; an old lockfile fails to
  parse → regenerate. A sweep found 3 sibling read-compat shims (`self_mirrors`,
  `strategy`-absent, `origin`-absent) + a manifest leniency (plain-string URLs) — purge
  all, make both parsers strict. (Earlier "path-dependent migration" design was itself
  the legacy-thinking smell.)
- **#168 slug (was Fork C) → `WS-MEMBER-DIR-MISSING`.** Don't follow a member symlink
  into an escape; an unresolvable member path is a missing dir. Avoids leaking
  out-of-root path info, and adopting Rust's prefix-stopping resolve in Python kills the
  ELOOP crash for free.
- **`milpa verify` legacy-registry detection → in S3** (not deferred).
- **`milpa show` alias display → in S1** — surface `aliases` in `show` so a user can see
  `bar` was deduped into `foo`; it's the slice that completes the alias-identity model.

## Sequencing

S1 → S2a → S2b → S3 → S4 → S5a → S5b. Only hard code-dependency: S2b after S2a (clean
coordinator shape first). S3/S4/S5a are mutually independent; ordered by frozen-path
test-scaffold warmth. S5b after S5a (grammar populates the threaded key).
