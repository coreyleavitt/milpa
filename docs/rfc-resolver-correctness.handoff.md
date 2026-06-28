# rfc-resolver-correctness — handoff

- **Stage:** 3 (tdd grind, via `/loop` dynamic). **7/7 slices done — GRIND COMPLETE.** Round-1
  architect design COMPLETE — zero open forks (all resolved under the bar). RFC:
  `docs/rfc-resolver-correctness.md`. Each slice delegated to a sonnet subagent
  (RED→GREEN→REFACTOR); control loop stays thin; no commits during the grind (left in
  tree). Gates per slice: `cd impls/python && uv run pytest` + `./dev-rust test --workspace`.

## Grind progress
- [x] **S1** (#142 + #178 + show-alias) — `DepKey` named type (Python `version.py`, Rust
  `milpa-types`); `_locked_index` SSOT alias-aware helper reused by both frozen paths
  (`frozen.py` resolve_frozen + resolve_workspace_frozen); Rust `check_manifest_alignment`
  now iterates `deps + dev_deps` (#178) + alias-aware `find_locked`; `aliases` surfaced
  in `milpa show` (both impls); spec `§6a DepKey` + sharpened `§7.1 #2`. Fixtures
  179 (single-pkg alias), 180 (ws alias), 181 (dev-dep-not-in-lock). Gates: Python 2260
  passed/30 skip; Rust 755 + conformance 268 pass / 0 regressions.
- [x] **S2a** (#131 Rust coordinator SSOT) — `dep_passes_flag_predicates` moved to
  `edge_sources.rs` as `pub(crate)` SSOT; `build_edgeset_with_flags` added to
  `edge_sources.rs` (flag-aware manifest→EdgeSet with ctx.active_flags); `MilpaKdlEdgeSource.edges_for`
  now calls `build_edgeset_with_flags` (flag-aware); `DepDeclSource::edges_for` return type changed
  to `Result<EdgeSet, MilpaError>`; `resolve_edges` return type changed to
  `Result<&'cache EdgeSet, MilpaError>`; `PolicyDepDeclSource` added to `resolver.rs` (wraps
  `DepDeclEdgeSource` with non-strict FETCH-FAILED fallback); `extract_requires` refactored to
  call `resolve_edges` via `PolicyDepDeclSource` — inline clauses (b)–(d) deleted;
  `build_edgeset_from_manifest` deleted entirely. 3 S2a characterization tests pinned (all green).
  Gates: Python 2260 passed/30 skip; Rust 758 passed / 0 regressions.
- [x] **S2b** (#131 Python coordinator routing — correctness) — `resolve_edges` split into
  `_resolve_edges_pure` (clauses b/c/d) + thin cached wrapper (clause a); URL/tarball/local
  workers now call `_resolve_edges_pure` (gain override-suppression + DepDecl), passing the
  shared `edge_cache` read-only; `_pick_edges` **deleted**; `_collect_transitive_deps`
  **deleted** → BFS enqueue derives from the EdgeSet via new `edgeset_to_bfs_deps`
  (`UrlRequire` gained `name` + `flag_requests_raw` to reconstruct without a 2nd parse);
  `_dedup_candidates` updated to use it too. Fixtures 303 (flag-gate transitive absent),
  304 (ws variant), 305 (override + flag-gate). Both impls green. Gates: Python 2263
  passed/30 skip; Rust 758 / 0 regressions.
- [x] **S3** (#115) — purge pre-v1 lockfile read-compat: deleted `RegistryProvenanceRecord` +
  parse/format/sort arms (both impls); `self_mirrors` lockfile shim silently ignored (manifest
  `mirrors {}` kept); `strategy` absent → `LOCK-STRATEGY-MISSING` (new slug); `origin` absent →
  `LOCK-PROV-FIELD-MISSING`; `(url)` annotation required on all URL fields (`git=`, `tarball=`,
  `mirror`) — plain strings raise `MAN-URL-ARG-TYPE`. Fixture 307 (strategy-missing), 308
  (git-url-not-annotated); fixture-114 repurposed to `LOCK-PROV-KIND-UNKNOWN`. Gates: Python
  2264 passed/30 skip; Rust 758 passed / 0 regressions.
- [x] **S4** (#168 symlink slug convergence) — Python `_best_effort_resolve` (stat-not-lstat,
  longest-existing-prefix) replaces `resolve(strict=False)` in member containment → kills ELOOP
  crash + converges to `WS-MEMBER-DIR-MISSING`. Found+fixed a real Rust gap (dangling-outside
  was PATH-ESCAPE there too) via metadata()-not-symlink_metadata(). Policy: unresolvable
  (cyclic/dangling) member symlink → DIR-MISSING; genuine escape to an EXISTING out-of-root
  target still → PATH-ESCAPE (security preserved). Spec §11.0 (member-path canonicalization).
  Fixtures 309 (cyclic), 310 (dangling-outside); both impls. Gates: Python 2268/30; Rust 760/0.
- [x] **S5a** (#108 internal key) — `DepKey.solver_var()` added (Python `version.py`,
  Rust `milpa-types`); `seen_named: set[str]` → `set[DepKey]` (Python `resolver.py`
  `resolve()`/`resolve_workspace()`/`_run_bfs_wave_loop()`/`_s4a_run_fixpoint()`/
  `_Provider`; Rust `resolver.rs` struct field + `process_named` + two transitive
  enqueue sites); `PKey::Named(String)` → `PKey::Named(DepKey)` (Rust); BFS queue
  format `("named", str, …)` → `("named", DepKey, …)` (Python); `_NamedStub.name: str`
  → `dep_key: DepKey` + `name` property (Python); `_enumerate_named_stubs` + `register_named_stubs`
  take `DepKey`; `_dep_to_solver_term` uses `dep_key.solver_var()` for NamedDep; `_provenance_key_for_named`
  signature updated to `(dep_key: DepKey)`. RED: 8 Python tests + 4 Rust tests in
  `milpa-types` tests. GREEN: all pass. `namespace=None` behavior bit-identical to pre-S5a.
  Gates: Python 2278/30 skip; Rust 764/0.
- [x] **S5b** (#108 grammar) — `namespace=` attribute + `"ns/pkg"` slash-shorthand desugar at parse
  boundary (both impls); `lookup_qualified(ns, name)` on `Index` bypasses `TNG-AMBIGUOUS-NAME`;
  gate uses `gate_key()` (solver_var) not bare name so `ns1::bar` and `ns2::bar` don't
  conflict; `cmd_remove` desugars `"ns/name"` → `"ns::name"` (both impls); manifest writer
  emits canonical `namespace=` attribute form; spec updated (`manifest-grammar.md` §3.2 NamedDep
  + `registry-protocol.md` §5.1a + `resolver-semantics.md` §6b solver_var); errors.md
  descriptions updated for `MAN-DEP-NAME-INVALID` + `MAN-DEP-NAMED-PROPS`; conformance
  fixtures 311–314 (canonical attr, slash sugar, malformed, two-namespaces payoff).
  Gates: Python 2304 passed/30 skip; Rust 779 passed / 0 regressions.
- **S2b clause-(c) correction (RESOLVED via follow-up B):** the real S2b correctness win is
  clause (b) OVERRIDES (were genuinely dropped on URL/tarball/local; fixtures 303–305), NOT
  clause (c) DepDecl. URL/tarball/local deps hardcode `dep_decl=None` in BOTH impls
  (`resolver.py:2760`, `resolver.rs:2197`) — correct by design (a DepDecl is index-attested
  metadata; an out-of-index URL dep has none to ignore). Clause (c) is reachable only on the
  NAMED path; `fixture-315-depdecl-clause-c-overrides-in-tree` now pins it (DepDecl disagrees
  with in-tree nimble → DepDecl wins; remove dep-decl/ → resolution changes). Earlier "URL
  deps silently ignore attested DepDecl" framing was overstated.

## Follow-ups — ALL DONE (2026-06-27, in tree)
- [x] **#179** `filter_manifest_by_profile` migration: `seed_root` → `FilterCtx`+`filter_manifest`;
  deleted `filter_manifest_by_profile`/`dep_matches_profile`/`predicate_satisfied` (~60 lines).
  Behavior-preserving (`profile.flags` always empty at both call sites → merge was a no-op);
  2 characterization tests pin it. Python already single-path. Closes #179 on commit.
- [x] **S2b DepDecl fixture** — `fixture-315` (above), byte-identical both impls.
- [x] **S3 self_mirrors nit** — deleted the `elif cname == "self_mirrors": pass` vestige; generic
  unknown-node skip handles it (test `test_self_mirrors_silently_ignored` confirms identical).
- **Final gates after follow-ups: Python 2305 passed / 30 skip; Rust 781 passed / 0 failed.**
- **Umbrella:** #172. Live children: #108, #115, #131, #142, #168. New child filed in
  review: **#178** (Rust `check_manifest_alignment` skips dev_deps — folded into S1).
  #129/#109 already closed (not in RFC).
- **Resume / next stage:** GRIND + all 3 follow-ups COMPLETE, all in the tree, NOTHING
  committed. Final gates 2026-06-27: **Python 2305 passed / 30 skipped; Rust 781 passed / 0
  failed.** Next = **stage 4 `/code-review docs/rfc-resolver-correctness.md`** (scope = the
  uncommitted tree), then commit (`closes #142 #178 #131 #115 #168 #108 #179`).

## Stage-4 code-review ledger (2026-06-28 — scope = uncommitted tree)

4 reviewers (correctness/port-fidelity, security, design, spec-conformance) + 3 adversarial
verifiers (frozen-qualified, transitive-qualified, fixture-collision). Status legend:
open / fixed / deferred / wontfix / refuted.

| id | sev | status | finding | verified by |
|----|-----|--------|---------|-------------|
| C1 | CRIT | open | **Qualified deps can't round-trip through the lockfile.** `solver_var` folds namespace into `ResolvedDep.name` as `"ns::bar"`; serialized as `dep "ns::bar"`; on re-parse `_require_dep_name`/`dep_name()` reject `:` (`[A-Za-z0-9_-]+`) → `LOCK-DEP-NAME-INVALID`. So `fetch` writes a lockfile milpa itself can't read back — `verify`/`show`/frozen/re-lock all crash. Both impls broken identically (not divergent). fixture-314 masks it (resolver→text only; never re-parses). Same root cause as the `_deps/ns::bar` on-disk dir (`:` illegal on Windows) + `--path:"_deps/ns::bar/src"` in nim.cfg. Root fix: carry `name`(bare)+`namespace` as separate fields in Resolved/LockedDep; serialize namespace as a child node; solver_var (`::`) stays solver-internal, never on disk. **Spec hole → escalation** (lockfile-schema + `_deps/` layout unspecified for qualified deps). | frozen verifier (ran it: `LOCK-DEP-NAME-INVALID`); design #3/#6; security nim.cfg note |
| H1 | HIGH | open | **strategy fail-open divergence.** `_parse_top_strategy` (lockfile.py:471-476) returns `"maxver"` on a malformed arg (`strategy 42`); Rust raises `LOCK-STRATEGY-MISSING`. Violates zero-divergence mandate. Docstring still says "fail-open for diagnostics" — stale post-S3. No fixture covers malformed (only absent, fx-307). | correctness F1; confirmed from source |
| H2 | HIGH | open | **Transitive qualified deps silently collapse to bare.** A transitive milpa.kdl `"core/pkg"` loses its namespace crossing the EdgeSet (`NamedRequire` has no namespace field; both impls hardcode `namespace:None` for transitive, commented as intended). Both impls agree (no divergence) but silent semantic loss — `"core/pkg"` resolves as `pkg`. Should be supported or rejected (MAN error), not silently downgraded. #4 (`_on_transitive_named` mis-parse) becomes live once this is fixed. | transitive verifier (REAL #5 / LATENT #4) |
| M1 | MED | open | **SSOT: 5 bare `::` constructions bypass `solver_var()`** (Rust: manifest lib.rs:983, cli main.rs:1732/1745, resolver.rs:2369 + split at 2390). Needs `DepKey::solver_var()` / `from_solver_var()` as sole join/split. Reshaped by the C1 redesign. | design #2; confirmed from source |
| M2 | MED | open | **slash + `namespace=` disagreement silently overridden** (manifest.py `_parse_named_dep`): `"core/pkg" namespace="other"` → namespace="other", no error. Should raise `MAN-DEP-NAME-INVALID`. Both impls. | design #9; correctness corroborates override |
| M3 | MED | open | **conformance-fixtures.md references nonexistent fixture-306** (line ~1109) — the LOCK-PROV-KIND-UNKNOWN case is fixture-114 (repurposed). Index points to a hole. | spec reviewer; confirmed (`ls` no 306) |
| M4 | MED | open | **Fixture number collisions** 179/180/181 each used by two dirs. Runner keys on full dir name → not corpus-breaking, but breaks number cross-ref + `test_fixture_ids_sorted` hygiene. Renumber the new ones. | spec reviewer; confirmed via `ls` |
| M5 | MED | open | **`UrlRequire.flag_requests_raw` leaky boundary** — consumer-side flag requests encoded as raw tuples in a provider-side type to dodge a circular import; `FlagRequest→tuple→FlagRequest` round-trip in `edgeset_to_bfs_deps`. Belongs in the BFS item, not the edge-source contract. | design #8 |
| L1 | LOW | open | Double `_best_effort_resolve` in `load_workspace` (predicate recomputes the resolution). Shallow; theoretical TOCTOU, non-exploitable, pre-existing pattern. | design #7 + security (non-exploitable) |
| L2 | LOW | open | `frozen.py` stale docstrings + inconsistent condition numbers (103/118 vs 219/222; 304-306 names deleted FROZEN-LEGACY-REGISTRY-PROVENANCE). | correctness F2; spec reviewer |
| L3 | LOW | open | `lockfile.rs:~578` doc comment still lists `"registry"→5` in kind_rank (match arm correct; comment drifts from spec + Python). | spec reviewer |
| L4 | LOW | open | `fixture-114` dir name still encodes deleted slug `frozen-legacy-registry-provenance` (expected/error now LOCK-PROV-KIND-UNKNOWN). | spec reviewer |
| L5 | LOW | open | `_provenance_key_for_named` is dead production code (only tests call it); format silently changed 2-tuple→3-tuple. | correctness F3 |
| L6 | LOW | open | No conformance fixture for absent `origin` → `LOCK-PROV-FIELD-MISSING` (Rust unit-tested only; not cross-impl). | spec reviewer |
| — | — | refuted | **No path-escape / containment bypass** from the S4 symlink change — boundary holds in both impls (dangling/cyclic→DIR-MISSING, live-outside→PATH-ESCAPE). fixtures 309/310 prove it. | security reviewer |
| — | — | refuted | **Design #3 as a *divergence*** — `_deps/ns::bar` + nim.cfg are byte-identical across impls (fixture-314 green). Folded into C1 as the design-layout dimension, not a divergence. | own check of fixture-314 expected files |

**Headline:** S5b (qualified naming, the #108 payoff) works *only* for the direct-dep resolve→fetch
path; it breaks on the first lockfile re-read (C1), on transitive use (H2), and uses a
Windows-illegal `::` on-disk layout. The qualified-identity *representation* is the wrong data
model (namespace folded into a `::` name string). This is a spec hole → escalation, not a silent patch.

## Stage-4 FIX LOOP — COMPLETE (floor reached 2026-06-28)

Ratified design (Corey "go"): namespace is a first-class field (never folded into the name);
`solver_var()`/`from_solver_var()` are the sole `::` join/split (solver-internal only); lockfile
serializes a `namespace` child node; on-disk layout `_deps/@<ns>/<name>` (npm-scoped, Windows-safe);
spec hole closed (lockfile-schema + resolver-semantics `_deps/` layout).

Fix rounds (all delegated sonnet agents, both impls gated each round):
- **R1** — C1 (Python data-model + spec + shared fixtures 314/316/317/318) → C1 (Rust to byte-match,
  + M1 SSOT, + store.rs `create_dir_all` for `@ns/` links) → cleanup batch (H1/M3/M4/M5 + L1–L6;
  fixtures renumbered 179/180/181→320/321/322, fixture-114 renamed, +319/323).
- **R2 re-review** (3 lenses) found: HIGH lockfile-namespace path-traversal (unvalidated charset, BOTH
  impls); HIGH Python `resolve_workspace._on_transitive_named` port divergence; MED `load_workspace_from_manifest`
  not S4-updated; MED 2 inline `::` joins in cli.py; MED spec namespace charset stricter than impls;
  + Lows. **R2 fix**: all resolved (+fixture-324 traversal-reject; spec charset aligned; dep_dir_name→version.py).
- **R3 re-review** (security+port / design+spec) → both HIGHs confirmed closed, SSOT+bijection clean.
  Residual: MED S4b/S4c built `milpa.kdl` path from raw solver-var (wrong `_deps/ns::bar`, silent
  `except: pass`) — BOTH impls; + the deeper gap that named deps aren't in `_candidates` at S4c time
  so named-dep flag conflicts were skipped entirely. **R3 fix**: path via `from_solver_var`+`dep_dir_name`;
  materialization-time conflict check (reuses `_raise_if_flag_conflicts` — SSOT); +fixture-325. Plus a
  Low spec-slug wording fix in manifest-grammar.md (charset → `MAN-DEP-NAME-INVALID`).
- **R3 verify** — final tight pass: bare-dep path byte-identical, no false-positive conflicts, Python/Rust
  raise same slug at same point, fixture-325 sound. **Nothing above Low → FLOOR.**

Every C1/H1/H2/M1/M2/M3/M4/M5 + all Lows: status **fixed**. Path-escape refuted findings stay refuted.
New fixtures this stage: 316,317,318,319,320,321,322,323,324,325 (314/311/312 updated; 114 renamed).
**Resume:** commit the tree — `closes #142 #178 #131 #115 #168 #108 #179`.

## Round-1 ledger (4 lenses → consolidated)

Code grounded by 3 Explore mappers (both impls). Review team found 1 new Critical
(#178) + reshaped the slice plan. All clear-best fixes applied to the RFC:

- **DepKey type in S1** (design lens): named key type per impl (`name` + `namespace=None`),
  not a tuple threaded in S5. Specced in `spec/resolver-semantics.md`. S5 only populates
  the slot — no gate re-plumbs.
- **`_locked_index` SSOT helper** (design): one `dict[DepKey, LockedDep]` over name∪aliases,
  reused by both frozen paths + all conditions.
- **#178 dev-deps** (breadth, NEW Crit): Rust gate skips dev_deps; folded into S1 + spec §7.1#2 sharpen.
- **#131 is 3 paths, not 2** (depth): `_collect_transitive_deps` is a third independent
  parse bypassing flag-filter + overrides — S2b must unify it via the returned EdgeSet.
- **S2 split → S2a (Rust delegate to resolve_edges) + S2b (Python pure/cached split,
  delete `_pick_edges`, shared read-only cache, GIL-safe)** (design+depth+feasibility).
- **S5 split → S5a (internal DepKey threading, property-tested only — unreachable via
  manifest under Fork A(ii)) + S5b (grammar, own mini-RFC)** (feasibility). S5 is NOT
  code-coupled to S1.
- **Frozen invariant corrected** (depth): "read-only" was false (`rebuild_deps_view`
  writes `_deps/`). Tightened to "no lockfile writes, no fetcher invocations; MAY
  rebuild `_deps/` symlinks." This is what gates Fork B(ii).
- **S4 ELOOP** (depth): Python `resolve(strict=False)` raises unhandled `OSError(ELOOP)`
  on a true cycle. Adopting Rust's prefix-stopping resolve fixes it for free and
  converges the slug to DIR-MISSING (Fork C resolved).
- **#108 reachability reframed** (depth): silent collapse is *masked today* by
  `TNG-AMBIGUOUS-NAME` firing first; key is structurally wrong regardless; reachable
  only once disambiguation exists (Fork A). Solver variable must also key on DepKey.
- **Out of scope, tracked:** `milpa verify` legacy-registry detection (file w/ S3);
  `milpa show` alias display (UX issue).

## Resolved decisions (no forks — bar yields a goal-determined answer for each)
- **#108 surface:** ship qualified naming end-to-end (internal key S5a + grammar S5b).
  The `TNG-AMBIGUOUS-NAME` message already promises qualified refs → the grammar closes
  a spec hole; internal-key-only/deferral = a permanent user-facing dead-end (workaround).
  Grammar form: KDL-native `namespace=` attr (canonical) + `"ns/pkg"` slash sugar.
- **#115 (REVISED — Corey, 2026-06-27):** the path-dependent-migration design was itself
  legacy-thinking. Pre-v1 / no consumers → **delete the legacy `registry` kind outright**
  + a sweep-driven strict-parser purge (self_mirrors, strategy-absent, origin-absent) +
  `(url)`-mandatory manifest tightening. The `milpa verify` legacy-detection sub-item
  DISSOLVED (nothing to detect). Closes #115 on commit/push. Sweep also filed #179
  (`filter_manifest_by_profile` half-migration, separate).
- **#168 slug:** converge to `WS-MEMBER-DIR-MISSING` (Rust behavior; kills Python ELOOP).
- **`milpa show` alias display → S1** (not deferred).

## Final slice order
S1 (#142+#178+show-alias) → S2a (#131 Rust) → S2b (#131 Python) → S3 (#115 strict-parser
purge) → S4 (#168) → S5a (#108 internal key) → S5b (#108 grammar).

## S3 code-review nit
- Python `self_mirrors` lockfile branch was made a `pass` (silently ignored) rather than
  deleted — functionally equivalent to the generic unknown-node skip, but leaves a named
  vestige; consider deleting the branch outright at stage-4 review.
