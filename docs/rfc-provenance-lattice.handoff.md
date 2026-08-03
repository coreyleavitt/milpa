# Provenance / source-selection — handoff

## ⭐ CURRENT STATE — READ THIS FIRST (2026-08-02, supersedes everything below)

**STAGE: rfc-flow Stage 3 — ✅ COMPLETE (2026-08-03). All automatable slices S0–S10 + seen_url fix DONE-GREEN both impls, UNCOMMITTED.**
NEXT: (1) Stage 4 `/code-review docs/rfc-origin-as-identity` (Corey-triggered); (2) 3 open decisions below (subpath partial-checkout depth,
S7 tree-scan default, Rust unused-digest warn); (3) S11 amoxtli manual proof (Corey-gated runbook). Loop STOPPED (automatable scope exhausted).
Build order was RFC §10 (17 numbered items S0–S11).

## ⭐ STAGE 4 — CODE REVIEW (in progress, 2026-08-03)

6 review lenses complete (Python-correctness, Rust-correctness, differential, security, design, spec/coverage).
Adversarial verification pass running. Dominant theme: **namespace/bare-name conflation** — coordinate-is-origin
makes same-bare-name/different-namespace legal, and many sites still key/match by bare name.

### Review ledger — ALL Critical/High adversarially verified (2026-08-03). status: confirmed/refuted; all open (no fixes yet)
Legend: [RFC]=introduced by origin-as-identity work · [PRE]=pre-existing S5b/#172 CLI-audit gap, surfaced here · [both]/[py]/[rust]=impls affected
| id | sev | verdict | finding | file(s) |
|----|-----|---------|---------|---------|
| P1 | **Critical** | CONFIRMED (live) — worse: silent STATE CORRUPTION | [RFC][both] root deps{}+dev-deps{} same bare-name+ns, different source → reconcile_root_claims silently keeps first, no RES-BINDING-CONFLICT; lockfile `source` disagrees w/ materialized provenance+symlink; `verify` passes | binding.py:484-509 / binding.rs; manifest.py per-block seen_names:1719 |
| S1 | **High** | CONFIRMED (live, both impls) — most serious | [RFC][both] root_authority is bare-name → RES-REGISTRY-SHADOW skipped for an unrelated-ns coordinate; malicious transitive `foo git=evil` admitted, and every innocent `requires "foo"` then resolves to attacker URL. Dependency-confusion. | resolver.py:3489,5770,2427; resolver.rs:2002,2468,2647 |
| R1 | **High** | CONFIRMED (test) — Rust-only DIVERGENCE | [RFC][rust] reconcile_root_claims binds overridden named dep bare; seed_root queries qualified key override-check-AFTER → canonical_for miss → MILPA-INTERNAL crash. Python checks override-first → resolves clean. | binding.rs:473-493; resolver.rs:1862-1873 (py ok: resolver.py:3637-3688) |
| R2 | **High** | CONFIRMED (test) — SHARED (not divergence) | [RFC-incomplete-B3][both] member_dep_closure keyed by bare .name but requires are qualified `ns::name` → silently drops ns-qualified transitive + whole subtree from member nim.cfg search path. RFC's own B3 claimed this fixed; incomplete in BOTH impls. | nimcfg.rs:306-337; nimcfg.py:333-361 (caller:236) |
| P2 | **High** | CONFIRMED (live) — control=fixture461 | [RFC][both] FROZEN-SOURCE-ID-MISMATCH structurally unreachable for RegistryTarget override (declared_by_key uses subject name, locked dep uses target coord → get() always None). Edit override target w/o refetch passes verify. | frozen.py:243,270-273; resolver.py:1791-1804 (shared frozen helper → rust likely same) |
| D1 | **High** | CONFIRMED (exec both) | [RFC] git-URL normalize divergence: Python urlsplit DROPS query/fragment, Rust hand-parse KEEPS → different source-id; `#subdirectory=` ACCEPTED by Python, REJECTED (SRC-ID-MALFORMED) by Rust. | source_id.py:383-417 vs source_id.rs:271-319 |
| D3 | **High** | **FIXED (both, green)** | [both-divergence] root `member` dep in non-workspace manifest: Python silently dropped (locked 0), Rust hard-failed SOLVE-CONFLICT. → NEW slug `RES-MEMBER-OUTSIDE-WORKSPACE` raised at both seed arms (errors.py + error.rs catalog + spec/errors.md, bijection kept); dead `eq_sentinel()` removed. Tests: py `test_d3_member_outside_workspace.py` (deps + dev-deps), rust `resolve_member_dep_in_single_package_manifest_fails_with_coded_error`. Py EXIT:0; Rust milpa-core 1077 + conformance 19. | resolver.py:3729 / resolver.rs:1926 |
| D4 | **High** | CONFIRMED (exec both) | [divergence] TarballDep unknown-prop validation: Rust raises MAN-DEP-UNKNOWN-PROPS, Python silently ignores (`subpathh=` typo → no-subpath). | manifest.py:2439-2557 vs lib.rs:2288-2300 |
| P3 | High | CONFIRMED (repro) | [PRE][py] _cmd_remove_from_member_dir bare-name → `remove foo` from member dir deletes BOTH ns deps (standalone cmd_remove is DepKey-aware — intra-impl inconsistency) | cli.py:4762,4772 |
| P4 | High | CONFIRMED (repro) — worse: DATA LOSS | [PRE][py] update/remove alias resolve_alias_to_canonical/_strip_pins/strip_dep_pin bare-name → `update foo` silently DELETES the sibling ns `foo` lockfile entry; no CLI disambiguation | cli.py:4036-4097; lockfile.py strip_dep_pin |
| DE1 | High (design/judgment) | valid — Corey's call | [RFC] bare-str solver key forces canonical→DepKey reverse map + ~58-site scattered projection; reviewer argues reopen RFC §4.4/§13 "solver untouched" fork (generic Term[K]/SolverKey). Genuine design fork. | binding.py/rs + resolver.py/rs |
| S2 | Medium | CONFIRMED (live e2e) | [RFC][both] normalize_source omits control-char/U+2028-9 reject on url/path/registry/repo → terminal-escape injection at `milpa show` sink (cli.py:2465 prints raw) | source_id.py:420-468; cli.py:2465 |
| R3 | Medium | CONFIRMED — +Rust-only divergence | [RFC][rust] OCI-override digest= not format-validated on override path, no milpa-side re-verify (relies on oras). Python validates via OciProvenance.__post_init__ type-invariant; Rust Provenance::Oci has none. | lib.rs:3033-3045; fetchers.rs:1886; (py ok: fetchers/oci.py:128) |
| P5 | Medium | CONFIRMED (repro) | [PRE][py] _verify_dep_decl_pins bare lookup_bare; AmbiguousName→false LOCK-DEPDECL-PIN-MISSING (lookup_qualified exists, should be used) | cli.py:2858-2860 |
| P6 | Medium | CONFIRMED (read all sites) | [RFC][py] record_discovery records bare name for tarball/local/oci override BFS arms (url/named arms use canonical) → BFS-first tiebreak degrades to _LARGE on cross-origin collapse | resolver.py:2508,2528,2549 |
| D5 | Medium | CONFIRMED (exec both) | [divergence] override dup-check vs version-error ordering: Python MAN-OVERRIDE-DUPLICATE, Rust MAN-DEP-VERSION-INVALID, same input | manifest.py:2833 vs lib.rs:3126 |
| DE2 | Medium (design) | valid | [RFC] canonical_key_for_requirement is a shallow 90-line proc w/ many optional kwargs — two-phase complexity leaks to every call site (unlike deep BindingResolver) | binding.py:340-430 |
| DE3 | Medium (design) | valid — DE1 mitigation | [RFC] no single boundary type forces projection at emission sites; a SolverKeyProjector newtype would kill the canonical-leak bug class without touching the solver | resolver.py/rs |
| D2 | Low | REFUTED as divergence | [rust] Rust finalize() lacks Python's identical-requires dedup guard, but precondition (identical hash + diff requires) is unreachable by construction → parity-only defensive note | resolver.rs:4236-4328 |
| R4 | Low | valid | [rust] check_registry_shadow no OCI comparator → over-fire on legit direct OCI pin of registry's own artifact | binding.rs:578-601 |
| P7 | Low | valid | [py] namespace= override prop lacks cross-form guard subpath= has | manifest.py:2645-2706 |
| R5 | Low | valid | [rust] stale doc: ResolvedDep.source_id "None for frozen" but frozen.rs:711 populates it | milpa-types/src/lib.rs:459 |
| R6 | Low | valid | [rust] check_directory_slot_collisions always cites group[0]/[1] | lockfile.rs:1586 |

**Clean:** spec/coverage lens (bijective catalog, no drift, coverage complete).
**Known-soft edges resolved:** OCI "unused-digest" → NOT unused (drives oras pull-by-digest); real gap is R3. subpath →
CONFIRMED hollow both impls (fetch ignores subpath, monorepo root manifest resolved instead) = open design decision #1.
**Theme:** namespace/bare-name conflation dominates. [RFC]-introduced: P1,S1,R1,R2,P2,S2,P6,R3,D1 + design DE1-3. [PRE]
S5b-audit gaps surfaced (fix regardless): P3,P4,P5. Divergences: R1,R3,D1,D3,D4,D5.
**Mandate (Corey 2026-08-03):** fix through Medium INCLUDING pre-existing P3/P4/P5; DE1 = **reopen the fork, GENERICIZE the solver key** (rich SolverKey/Term[K], delete reverse map + projection scatter, both impls). Lows skipped.

### FIX-LOOP PROGRESS (⚠️ session hit 200/200 subagent spawn cap — remaining work being done inline or needs cap raised)
- **P1 (Critical) — FIXED, both impls, Python green.** `reconcile_root_claims` now raises RES-BINDING-CONFLICT when a second root decl of the same (name,namespace) disagrees on source (was silent first-wins). Test: `test_binding.py::TestRootClaimDuplicateSourceConflict`. Confirmed green in a full run (D4/D5 agent saw 3687 passed).
- **S1 (High) — FIXED, both impls, Python binding green; Rust build running.** Added `BindingResolver.is_root_authority(DepKey)`; the registry-shadow gate now keys on the EXACT DepKey (was bare-name `root_authority`, the dependency-confusion bypass). `root_authority` kept for `version_unknown_constrained_err`. Test: `TestIsRootAuthority`.
- **D4 + D5 — FIXED (agent aaf7a7c), green.** Python tarball unknown-prop allowlist (MAN-DEP-UNKNOWN-PROPS); Rust override duplicate-first ordering. Python 3687 passed / Rust milpa-manifest 247 / conformance green, 0 fixtures flipped.
- **S2 + D1 — in flight (agent a992f16, source_id.py/rs).**
- **P3 + P4 + P5 — in flight (agent a5f922b, cli.py).**
- **R1 (High, Rust crash) — FIXED, both seed paths (standalone + workspace), regression test `resolve_namespaced_named_dep_with_override_does_not_crash`. Rust 1076 passed.** seed now queries the BARE key when an override applies (was qualified → MILPA-INTERNAL).
- **R3 (Medium, Rust OCI digest) — FIXED.** `validate_oci_digest` (pub(crate)) now called at the `process_oci` fetch boundary → clean TNG-BAD-OCI-DIGEST; test `oci_override_malformed_digest_fails_with_coded_error_before_fetch`. Python already validated via OciProvenance.__post_init__.
- **S2 + D1 — FIXED (agent a992f16), both impls green.** control-char reject in normalize_source (reuses contains_unsafe_char) + `milpa show` repr; git-URL: strip query, reject `#fragment` (SRC-ID-MALFORMED) uniformly.
- **P3 + P4 + P5 — FIXED (agent a5f922b), Python green.** DepKey-aware member-dir remove; update/strip no longer deletes sibling ns entry (new LOCK-DEP-AMBIGUOUS-NAME on bare-ambiguous); verify uses lookup_qualified.
- **LOCK-DEP-AMBIGUOUS-NAME bijection** — P4's new slug was Python+spec only; ADDED to Rust `error.rs` catalog to restore the bijection lint.
- **P2 (High, frozen RegistryTarget) — FIXED, both impls path (shared helper), tests `TestFrozenRegistryTargetOverride`.** Declared-side check: a RegistryTarget override's target coordinate must appear among locked source-ids, else FROZEN-SOURCE-ID-MISMATCH (the subject-keyed loop couldn't match the renamed dep). Full Python suite green with it.
- **R2 (High, nim.cfg closure, both impls) — FIXED, tests py `test_member_includes_namespace_qualified_transitive_dep` + rust mirror.** `member_dep_closure` index now keyed by qualified solver-var (was bare) → namespaced transitive + subtree no longer dropped from member nim.cfg.
- **P6 (Medium) — FOLDED INTO DE1.** Its root cause (discovery_order records bare name for tarball/local/oci override arms vs canonical lookup) is exactly what the DE1 rich-key rewrite unifies; an isolated patch risks a canonical_for-before-binding crash and would be rewritten by DE1. Sequenced into DE1, not punted.
- **REMAINING: DE1 genericize (High design, both impls)** — the big solver-key refactor (subsumes P6, DE2, DE3). Best delegated (subagent cap hit). Everything else C/H/M is fixed + tested.
- **Final verification GREEN (2026-08-03):** full Python suite exit 0; Rust milpa-core 1076 passed + milpa-conformance corpus 19 + `rust_error_catalog_is_a_bijection_with_the_spec` OK, 0 failed. All landed fixes co-verified.
- **STATUS: every Critical/High/Medium finding FIXED + tested in both impls EXCEPT DE1 and D3** (see NEXT-SESSION queue). Lows (D2 parity note, R4, P7, R5, R6) intentionally skipped per mandate. Nothing committed (Corey: don't commit yet).

### NEXT SESSION (Corey chose: fresh session, delegated — 2026-08-03)
Two items remain; both to be DELEGATED to sonnet subagents in a fresh session (this session hit the 200/200 cap). Baseline is GREEN: Python exit 0, Rust milpa-core 1076 + conformance 19 + bijection.
1. **DE1 — genericize the solver key (High design, approved "reopen the fork").** Rich `SolverKey` (frozen: `identity=canonical(source_id)` for eq/hash + `display: DepKey` = BFS-first label) as `Term.package`/`Term<K>`; delete `BindingResolver._canonical_index`/`depkey_for_canonical` reverse map + the ~58 `_depkey_for_solved_name`/projection call sites (read `.display` directly at emission; single boundary serialization). Update RFC §4.4/§13 to record the REVERSED decision + rationale (58-site scatter cost > solver-touch cost). **Subsumes P6** (make `discovery_order` keyed uniformly by the rich key — fixes the tarball/local/oci-override bare-name recording at resolver.py:2514/2534/2555 + Rust), **DE2** (canonical_key_for_requirement deepens), **DE3** (projection boundary unified). Keep ALL conformance fixtures byte-identical (pure representation refactor). Sequence Python-first then Rust-mirror.
2. **D3 — root `member` dep in a NON-workspace manifest (High divergence).** Python silent-drops (resolver.py ~3723 `elif isinstance(dep, MemberDep): pass`), Rust hard-fails cryptically (seed_root unsatisfiable term ~1915). Converge BOTH to a clear coded error. Recommended: NEW slug `RES-MEMBER-OUTSIDE-WORKSPACE` (errors.py + error.rs catalog + spec/errors.md + keep bijection), raised at both seed arms; regression test/fixture. `MAN-RESOLUTION-MEMBER-SCOPE` is NOT it (that's member-declares-`resolution{}`).
**Recommendation surfaced to Corey:** raise CLAUDE_CODE_MAX_SUBAGENTS_PER_SESSION or resume in a fresh session so R1/R2/P2/P6/R3 + the DE1 genericization can be delegated to sonnet subagents rather than ground out inline in this long control loop (uncommitted-tree + context-exhaustion risk). Nothing committed.
Each code slice = one background `sonnet` subagent (RED→GREEN→REFACTOR + Rust in-window mirror per §9), gated on
`cd impls/python && uv run pytest` (baseline 3538 passed / 33 skipped) + `./dev-rust test -p milpa-core` (baseline 998).
NOTHING committed — all uncommitted, awaiting Corey. Subagents briefed NO-GIT (I do all git myself).

**⚠️ ROUND-2.5 REPRESENTATION DECISION (Corey "go" 2026-08-02) — applied to RFC.** coordinate-is-origin KEPT
(URL-as-origin considered+REJECTED — demotes tianguis to a phonebook; see RFC §13 + §11 "Decided (round 2.5)").
The `pkg+<alias>/<ns>/<name>` FLAT parse-back string was the anti-pattern (884/886 real tianguis namespaces contain
`/`, e.g. `codeberg.org/eris`). FIX: `SourceId`=native frozen struct (identity); **structured on disk** (uv-style
`source { registry; namespace; name }` KDL node); `canonical()`=ONE-WAY injective solver-key/display only
(registry form variable-arity, name-last, `/`-ns OK); **`parse()` + escaping DELETED**; namespace validated
per-`/`-segment. Details in [[provenance_source_selection]] memory + RFC §4.1/§4.4/§7/§10-S1/S5.

**⚠️ NO-DEFER RULE (Corey 2026-08-02, [[feedback_no_deferring_in_loop]]):** don't punt sub-parts to "file an issue" /
"phased, rest later" — finish each slice's FULL scope before the loop is complete; breaking changes fine pre-v1.
Sequencing to a later slice of THIS grind (e.g. solver-rekey S3a→S5) is NOT deferral. Un-deferred so far: S8b now
implements the COMPLETE overrides bridge (Oci/Tarball/**Registry** targets + version-scoped, was "file gaps"); B/D exit
condition = **FIX the wave-orchestration defect in-loop** (was xfail+file). Genuinely-separate RFCs (NOT this loop's
slices), surfaced to Corey: #192/R6 (lowest-direct drift), #32-34 (global CAS store + multihash), F4-F7 (Hg/Fossil/IPFS
fetchers) — leave for their own RFCs unless Corey pulls them in.

**Grind progress:**
- [x] **S0** — no-code base decision. No-op for me.
- [x] **S1** — `milpa/source_id.py` + `registry.py` (per-segment ns validation, whole-string fix reverted) +
  `SRC-ID-MALFORMED` + Rust `source_id.rs`. Python 3538 / Rust 998 at landing. **NEEDS REVISION** (round-2.5): delete
  `parse()`+escaping, make `canonical()` one-way variable-arity name-last so `/`-namespaces get a valid injective key,
  rewrite round-trip tests → injectivity. Net simplification. ← DO THIS NEXT.
- [x] **S2** — `milpa/binding.py` `BindingResolver` (DepKey-keyed via `from_solver_var(claim.name)`; 3-way BindOutcome;
  RES-BINDING-CONFLICT transitive-vs-transitive; root-vs-root=assert) + Rust `binding.rs`. Python 3561 / Rust 1019,
  zero regressions. Unaffected by round-2.5 (already coordinate-is-origin). DONE.
- [x] **S1-rev** — round-2.5 revision DONE: `parse()`+escaping helpers deleted (both impls); `canonical()` one-way
  variable-arity name-last (`pkg+tianguis/codeberg.org/eris/mypkg` ✓); `normalize_source`=sole validation boundary
  (per-segment ns validation); `spec/errors.md` SRC-ID-MALFORMED re-described. Python 3550 / Rust 1021. No non-test
  caller of `parse()` existed.
**⚠️ S3a SECURITY-DESIGN DECISION (Corey "go" 2026-08-02, best-in-class):** the registry-shadow tripwire is
**NAME-TRIGGERED + URL-REFINED** (not the old URL-agree/disagree source gate). Trigger = transitive
`git=`/`tarball=`/`oci=` claim whose BARE NAME matches a registry-OWNED name (any ns); refine = silent-accept iff the
entry has a comparable upstream URL matching the claim; else (URL disagrees, OR OCI-only/no comparable URL) →
`RES-REGISTRY-SHADOW` warn-default / strict-hardfail. NO post-fetch content-hash comparator (deleted). Honest
consequence signed off: OCI-only git-pins can't be pre-fetch-confirmed → warn/strict (old silent-accept gone);
content_hash still verifies at materialize. **Corrected fixture re-home:** multi-claim (2 competing claims/name) →
RES-BINDING-CONFLICT; lone-name-shadow → RES-REGISTRY-SHADOW. **Same-URL/diff-ref = one source-id, 2 versions** — a
DUPLICATE binding must still register the pinned ref as a candidate version (don't drop it); file issue if it ripples
into #191. Defense layering: source-id (no merge) → tripwire (attestation-policy) → import-slot (post-solve) →
content_hash (materialize). RFC §6.1/Fork1/§10-S3a/S3c updated.

- [x] **S3a (Python oracle) — DONE, verified green independently (3557 passed / 33 skipped / 0 failed).** BindingResolver +
  `reconcile_root_claims` wired into BOTH entry points; multi-claim → RES-BINDING-CONFLICT; **S3c tripwire implemented**
  (`binding.check_registry_shadow` — name-triggered + URL-refined, warn-default / strict-hardfail, wired in the url BFS
  arm — the sole reachable site); test re-homes done; conformance fixtures retrofitted (099/448/449) + new (454/455).
  Real bugs the agent found+fixed: (a) **root-satisfies-own-name** — standalone root now gets a
  `Claim(MemberSourceId(manifest.name), is_root=True)` ("workspace-of-one", RFC §6) and `submit()` is ALWAYS called
  (never skipped for is_root; the skip was the regression); (b) a **third unwired admission site** `_on_transitive_named`
  (mid-solve lazy-materialize callback) wired in both entry points; (c) a **workspace-member auto-coerce collision** with
  reconcile_root_claims. Verified NOT an over-fire: `test_a4`'s new RES-BINDING-CONFLICT is a genuine two-different-source
  transitive conflict (git= pin vs named require), not same-coordinate named-vs-named (which stays DUPLICATE). Old TIER_*
  present-but-unreferenced ✓; on-disk lockfile format unchanged (source_id only on in-memory ResolvedDep, not LockedDep) ✓.
  NOTE (modeling decision to reflect in RFC later): standalone-root self-name uses MemberSourceId ("workspace-of-one").
- [x] **S3a-Rust — DONE, verified.** milpa-core 1025 passed / 0 failed; milpa-conformance corpus byte-identical
  (099/447/448/449/454/455); bijection green; clippy clean (only the expected present-but-unreferenced dead-code warns);
  on-disk lockfile schema unchanged. Rust's unified `gate_only`/`process_items` covers the mid-solve site automatically
  (no separate `_on_transitive_named` wiring needed). Kept `gate()` called for `discovery_order` bookkeeping only (verdict
  discarded) in Named/Url arms — needed for fixture-447 tiebreak.

**⚠️ SOLVER RE-KEY DEFERRED S3a→S5 (round-2.5 refinement, verified in BOTH impls: `canonical(` absent from resolver.py,
solver still name-keyed).** S3a wires BindingResolver for ADMISSION (dedup/conflict/tripwire) + records `source_id` on
`ResolvedDep` as metadata, but does NOT feed `canonical(source_id)` to the solver (`Term.package` stays name-keyed).
Reason: feeding canonical changes resolved-graph node keys the lockfile serializes → can't land before S5 without breaking
the on-disk format S3a must preserve. Lands WITH the lockfile re-key in S5. Correctness meanwhile intact: admission-dedup
(same DepKey) + Phase B `_dedup_candidates` (same content_hash, post-fetch) already handle §2.1 missed-unification; the
solver re-key just makes it pre-fetch (efficiency, not new correctness). RFC §4.4 + §10-S5 updated.

**S3b PREREQ (Rust, flagged by mirror agent):** before deleting `gate()`/`Gate`/`TIER_*`, extract `discovery_order`
bookkeeping into an independent method (Local/Tarball arbitration + solver tiebreak depend on it). The 4
validate-against-registry fns (`normalize_git_source_url`/`registry_git_urls`/`registry_oci_source_urls`/
`validate_transitive_url_against_registry`) are fully dead now → safe to delete outright in S3b.

- [x] **S3a-req — DONE, verified.** Re-derivation + tie-break were ALREADY correct (root-beats-transitive via
  `discovery_order` min; `_dedup_candidates` Step 4 already rewrites `requires` pre-solve — proven by live nim.cfg repro),
  so no re-derivation machinery added (sound YAGNI, not a defer). The genuine gap = the **visible-collapse note** (§4.7):
  built `lockfile.format_dep_origin`/`collapse_notes` (SSOT, typed over ResolvedDep|LockedDep, no source_id dep) → wired
  into resolve()/resolve_workspace() (stderr `[milpa] note:`) + `milpa show` + spec/cli-contract.md, both impls. Python
  full suite exit 0; Rust milpa-core 1035 passed (+10), conformance green. Regression `TestWorkspaceNimcfgClosureSurvives
  Collapse` proves nim.cfg `--path` closure keeps the canonical dep.
- [x] **S3b — DONE, verified (full Python suite EXIT=0; Rust milpa-core 1016 passed; conformance byte-match incl 456/457).**
  ~410 lines deleted from resolver.py (all TIER_*/provenance_gate/validate-against-registry machinery + dead S3a imports).
  **Cases B/D resolve BY CONSTRUCTION** (BindingResolver's typed per-claim arbitration can't reproduce the old
  shared-side-table starvation bug — no wave-orchestration fix needed) → fixtures 456(case-b)/457(case-d) blessed as
  SUCCESS. `root_authority` retained both impls (2 consumers: `_version_unknown_constrained_err` + tripwire's
  `not in root_authority` gate). Docstrings re-homed (OciIndexProvenance.source_url + publishing.py → audit-only). Rust:
  4 dead validate fns deleted; `discovery_seen`/`record_discovery` extracted (the PREREQ); `gate()`/`Gate`/`TIER_*` KEPT
  live for Local/Tarball only. **Entire S3 block complete** — core origin-as-identity resolver replacement is in.
  (cwd is already impls/python — `uv run pytest` needs no cd.)
- [x] **S4 — DONE, verified.** `edge_cache` re-keyed `(name,Version)`→`(source_id,Version)` both impls (`cache_key =
  (source_id, version)`; Rust `HashMap<(SourceId,Version),EdgeSet>`). Python 3546 passed/exit 0; Rust milpa-core 1017 +
  453-fixture corpus 0 regressions. Design: "caller computes source_id, callee uses" (bare name for url/tarball/local,
  qualified solver_var for named — internal derivation broke fixture-317 MILPA-INTERNAL, fixed). Diamond regression in
  both impls. No fixture (cache-identity only, no byte change — S4b owns observable dedup).
**⚠️ OPERATIONAL (control loop): do NOT run your own full `uv run pytest` while a subagent is verifying** — concurrent
suite runs contend and look like a hang/5-min-timeout (happened at S4b; wasn't a hang). Read the agent's own log
(`/tmp/milpa_*` or its reported path) or wait for its completion notification. If you must verify, first `pgrep -af "uv run pytest"`
and kill only orphaned runs by PID. cwd is already impls/python.

- [x] **S4b — DONE, verified.** Cross-origin unification landed: `_dedup_candidates`/`finalize` moved POST-solve (over the
  solution — a named candidate's real fetched identity only exists after materialization) → a registry coordinate + a git
  URL with identical bytes collapse to ONE dep, BOTH `origin "observed"` provenances appended (audit trail), sharing one
  `_deps/` CAS entry. Identical-`requires` invariant guard KEPT; merge is proof-only (real fetched content_hash, never the
  index's claim). fixture-458 (cross-origin) added; 173/178/184 reblessed (+alias provenance block); lockfile-schema.md
  §3.8/§4.0a normative (multiple observed-provenance blocks legit on a collapse). Fixed latent asymmetry: resolve()'s
  `_on_transitive_named` now calls `_record_discovery`. Python exit 0; Rust milpa-core 1019 + conformance 25. NOTE: true
  "one PubGrub variable" collapse still lands at S5 (solver re-key); S4b collapses at graph-construction = sufficient for
  the on-disk/audit guarantee.
- [x] **S6 — DONE, verified (agent exit 0 ×2 + artifacts confirmed; over-fire guarded by exit 0).** Directory-slot floor
  `check_directory_slot_collisions` + `RES-IMPORT-COLLISION`, wired into resolve()/resolve_workspace() AND frozen paths,
  both impls. content_hash short-circuit: groups by `dep_dir_name` (SSOT w/ rebuild_deps_view), raises only when
  identities differ; empty/None identity raises (secure default, never "proven equal"). fixture-458 stays non-raising.
  Frozen-path: cleaner 3rd option — `_dep_origin_label` prefers `format_source_id` (fresh) / falls back to
  `format_dep_origin` (frozen, pre-S5) → full frozen coverage now, no new plumbing, wired at all 6 rebuild_deps_view sites
  (Rust has 4 live entry points incl undocumented resolve_with_cert). Caveat (directory-slot-only) in slug+spec. Python
  exit 0; Rust milpa-core 1025 (+6); conformance incl fixture-459.
  **FLAGGED (separate, pre-existing, NOT origin-as-identity scope — like #192):** Python/Rust divergence on frozen
  `FROZEN-IDENTITY-NOT-IN-STORE` for `identity=None` external deps (Python skips CAS check, Rust always fails). Agent did
  NOT patch it (out of scope); redesigned fixture-459 to real content hashes to sidestep. → surface to Corey / file.
- [~] **S5 (#2–#8) — DONE, verified (PYTEST_EXIT=0; Rust milpa-core 1025; 114 fixtures reblessed + 2 new, byte-match).**
  Structured on-disk `source { kind; … }` (uv model, `/`-namespaces lossless), field-dup audit (`registry_namespace`
  DELETED from Resolved/LockedDep — LockAttestation.namespace derives from source_id.namespace; internal _Candidate field
  kept for pre-graph entry-trust), FROZEN-SOURCE-ID-MISMATCH (declared-after-override via reconcile_root_claims) +
  FROZEN-REGISTRY-ALIAS-UNRESOLVED (checked-first) wired into --frozen AND `milpa verify` (verify never called frozen
  before!), fixtures 460/461, add/remove/update needed no change (key still name until rekey). parse() still absent
  (source{} deserializes via normalize_source). §3.10 lockfile-schema + §7.1 preconditions 11/12 spec.
  **DEFERRED #1 (against no-defer) → now the S5-rekey slice below.**
- [x] **S5-rekey — ✅ DONE across BOTH impls (2026-08-03). RFC core thesis realized: solver var = `canonical(source_id)` uniformly, two-phase §4.4.1.**
  Python full suite exit 0; Rust milpa-core 1028 + conformance corpus byte-identical (INDEPENDENTLY re-verified exit 0, 0 fixtures
  modified — shared oracle intact). Kind-conditional keying deleted both impls; binding-aware name-resolution (phase 1) + uniform
  canonicalization (phase 2); a direct git=/local=/tarball=/oci= decl = implicit name→source override. Collapse tests green both
  impls (registry label-collapse + git-pin↔bare-`requires` → ONE git node pre-fetch). Rust found the #4 ns-drop bug too + 2 more
  latent "stale bare-name lookup into canonical-keyed map" bugs (fixtures 282 ws-cross-pkg-enable-fixpoint + 447
  declaration-order-tiebreak). Projection at every emission boundary (lockfile requires/aliases/cond-requires,
  RESOLVE-FLAG-CONFLICT/RES-VERSION-UNKNOWN-CONSTRAINED payloads, attestation warnings, §5.1/§5.2 solve certificate). NOTHING
  COMMITTED (awaiting Corey). ↓ history of the fork resolution retained below.
- [x] **S5b — ✅ DONE both impls (2026-08-03).** Rust: RES-DEAD-OVERRIDE added to error.rs all_codes() + resolve_workspace_inner
  dead-override check (found the SAME resolve_workspace-had-no-check gap Python found); `cmd_remove` solver_var bug fixed
  (routed identity through joined `ns::name`, broke ns-qualified deps — mirrored Python's structured-DepKey rewrite: parse_dep_ref
  / dep_key_of / display_dep_ref `ns/name` slash form); 3 dead-override tests ported. milpa-core 1031, milpa-conformance 25
  (corpus byte-identical + bijection green). **ALSO fixed (S5 loose end I closed):** `cargo test -p milpa-cli` was non-compiling —
  2 `#[cfg(test)]` LockedDep literals (main.rs:5902/6012) missing the `source_id: Option<SourceId>` field S5 added; added
  `source_id: None` to both → milpa-cli test crate green (162+16+6+8 passed, CLI_EXIT:0).
- [x] **S7 — ✅ Python DONE-GREEN (2026-08-03); Rust catch-up in S10.** Symbol-level import-slot check (RFC §4.6 / §10 item 13).
  New `milpa/import_slot.py`: `ImportSlot(module, fidelity)` + `SymbolProviderPort` + `ManifestDeclaredSymbolProvider`
  (reads new `provides { module … }` manifest block) + `FetchedTreeSymbolProvider` (scans srcDir *.nim), composed
  declared-beats-inferred. Post-solve checker catches symbol collisions across DIFFERENTLY-named slots (the case S6's directory
  floor misses); S6 RETAINED as fast-path pre-filter; content_hash short-circuit preserved (§3.3 same-bytes/diff-origin). New
  `provides {}` grammar in manifest.py. RES-IMPORT-COLLISION caveat updated for symbol-level (spec/errors.md, bijection green).
  Full suite exit 0 (3646 green, 0 fail); +1 fixture (462-s7-import-slot-symbol-collision-cross-slot), 0 existing changed.
- [x] **S8 + S8b — ✅ Python DONE-GREEN (2026-08-03); Rust in S10.** S8 subpath: `subpath=` on UrlDep/TarballDep (manifest.py parse +
  round-trip), threaded into GitSourceId/TarballSourceId at claim construction (binding.py + resolver.py url arm), escape-guard
  REUSED from `normalize_source._validate_subpath` (no dup; traversal/abs/empty → SRC-ID-MALFORMED at resolve). test_subpath_grammar.py
  (16). S8b overrides: `OverrideTarget` now 6-way (added OciTarget/TarballTarget/RegistryTarget + GitTarget.subpath); grammar in
  `_parse_overrides_block`; new slugs MAN-OVERRIDE-{DIGEST-MISSING,OCI-MALFORMED,NAMED-MISSING} (bijection 1:1 verified). Rebind wired
  through phase-1 `_override_target_to_raw_origin` (index-aware; Registry resolves bare→ns) — NOT a parallel mechanism; resolver gained
  `_seed_extended_override_target`/`_extended_override_bfs_item` + new `"oci"` BFS kind (seen_oci threaded through all 5 loop sites) +
  `_process_oci_worker`. Version-scoped: RegistryTarget → exact `==` solver constraint; Git/Tarball/Oci → A3b version label. Fixed a
  RegistryTarget-name bug (used overridden dep's name not target's). test_override_targets_extended.py (20). Full suite exit 0 [100%]
  0 fail; 0 conformance fixtures changed (parity deferred to S10 per RFC §10 items 14/16 — sequencing, not deferral). Unified a
  duplicated format_manifest/format_workspace override-render block (fixed latent version= drop on workspace-root round-trip).
- [x] **S9 — ✅ DONE (2026-08-03, spec-prose only).** resolver-semantics.md §6a/§6b (leak-rule repeal→two-phase), §10 full rewrite
  (coordinate-is-origin binding phase: §10.0 model, §10.1 BindOutcome+RES-BINDING-CONFLICT, §10.2 pure/pre-fetch, §10.3 6-way
  overrides sole bridge, §10.4 ws-member/root-self, §10.5 RES-REGISTRY-SHADOW, §10.6 cross-origin merge-on-proof, §10.7 dev-deps,
  §10.8 ordering), §4.2.1 (BFS dedup keyed by canonical), §14.2 stale provenance_gate refs fixed, Appendix A slugs. manifest-grammar.md
  §3.4 (6-way overrides + version-scoped + subpath), UrlDep/TarballDep subpath, NamedDep solver-var note fixed. identity.md §4.1b
  (source-id vs content_hash vocabulary + canonical stable-wire-format). lockfile-schema.md + errors.md already current (earlier slices).
  Bijection lint green (8 passed). Agent verified each spec claim against impl.
- [ ] **⚠️ OPEN (surfaced to Corey, for decision / stage-4 review) — S7 default symbol-provider narrowing.** The 4 live call sites wire
  `ManifestDeclaredSymbolProvider` ALONE (`live_symbol_provider()`); `FetchedTreeSymbolProvider` (tree-scan *.nim) is implemented+tested
  but NOT in the zero-config default, on false-positive grounds. RFC §4.6 says compose BOTH (declared-beats-inferred). NOTE: tree-scan
  collisions may be GENUINE in Nim's path model (two deps both exporting `utils` on the search path = real ambiguity), so the
  "false-positive" framing is itself debatable. errors.md discloses the narrowing honestly. DECISION NEEDED: default declared-only (opt-in
  tree-scan) vs compose-both-in-default. Not blocking S10/S11 (Rust mirrors current Python behavior; changing the default later changes both).
- [x] **S10 — ✅ DONE-GREEN (2026-08-03). Rust catch-up complete; full workspace green.** S8 subpath (manifest format/lib/tests),
  S8b 6-way `OverrideTarget` enum (Git/Local/Member/Oci/Tarball/Registry, lib.rs:208 + parse 3002-3123) + MAN-OVERRIDE-* slugs in
  milpa-manifest catalog (bijection green) + OCI-override worker + version-scoped, S7 import_slot.rs + provides grammar + symbol-level
  check (declared-only default, mirrors Python). +2 shared fixtures (463-s8-subpath-distinct-source-ids, 464-s8b-tarball-target-override-rebind,
  locks from Python oracle); fixture-462 (S7) passes in Rust. Full `cargo test` workspace: milpa-core 1061, milpa-manifest 247, milpa-cli
  162+16+6+8, milpa-conformance 19+2+4 (corpus byte-match + bijection), **0 failed anywhere**. MINOR: a few unused-var warnings
  (digest/sha in the OCI/tarball override worker) — flag for stage-4 (is the override digest/sha256 pin actually verified? worth a look).
- [x] **seen_url subpath dedup fix — ✅ DONE-GREEN BOTH IMPLS (2026-08-03).** Rust `seen_url: BTreeSet<(String,String,Option<String>)>`
  (resolver.rs:1470); tests s8_same_url_ref_different_subpath + same_subpath (resolver_tests.rs:7069/7130). milpa-core 1063, conformance
  corpus byte-identical (independently re-verified CONF_EXIT:0). Python side: was DONE-GREEN prior. `seen_url` was keyed `(url,ref)` in
  BOTH impls → two deps same url+ref/different subpath collapsed (Python: crashed SOLVE-CONFLICT; now graceful). Fixed to `(url,ref,subpath)`.
  Python: resolver.py sites 2456/3011 + type annots; test_subpath_grammar.py::TestSubpathSeenUrlDedup; full suite exit 0, 0 fixtures changed.
- [ ] **⚠️ OPEN FOR COREY — subpath is grammar+identity-ONLY, not a real partial-checkout (surfaced 2026-08-03, decision needed).**
  In S8 as shipped, `fetch()` ignores subpath (whole repo fetched) and `compute_content_hash` hashes the WHOLE tree → two same-repo/
  different-subpath deps have IDENTICAL content_hash → §3.3 content-dedup legitimately folds them to ONE node (alias+collapse note). So
  subpath's solver-level identity discrimination is MOOT for same-repo deps (they re-merge on content). This may be the RFC's literal S8
  scope ("subpath grammar threaded into SourceId" — item 14; §7:759 "grammar slice can land separately"), but the feature is HOLLOW as a
  monorepo mechanism. Making it real = subtree content-hash (repo/subpath) + srcDir/nim.cfg projection + fetch-subpath — which TOUCHES the
  content-hash IDENTITY non-negotiable, so NOT expanded unilaterally. Also found (agent, out-of-scope): (a) `dep_decl.py UrlRequire` has NO
  subpath field → transitive git-dep subpath silently dropped; (b) `binding.py canonical_key_for_requirement` GitSourceId omits subpath →
  would mismatch once (a) is fixed. DECISION: accept S8 grammar+identity-only + file follow-up RFC for real partial-checkout, OR expand now.
  Root-declared subpath (grammar/identity) works; only same-repo-collapse + transitive-threading are the gaps.
- [ ] **S11 — amoxtli manual proof (NOT automatable; RFC item 17, Corey-gated runbook).** Re-resolve amoxtli; softlink resolves via its
  own URL with NO tianguis republish; commit only amoxtli's milpa.lock. Talks to live git remotes → on-demand smoke test, not CI-gated.
  The hermetic B/D fixture (S3b) is the automated regression guard; S11 is confirmation. **PRESENTED TO COREY as the manual next step.**
- [x] (history) **S10 — was NEXT (Rust catch-up + conformance parity).** Mirror S7 (import_slot + provides grammar), S8 (subpath grammar), S8b (6-way
  OverrideTarget + version-scoped + OCI-override worker) into Rust function-for-function; ensure Rust passes ALL conformance fixtures incl.
  the Python-added fixture-462 (S7); add S8/S8b conformance fixtures for cross-impl parity. Per-crate dev-rust, background builds. Then
  S11 (amoxtli manual proof).
- [x] (history) **S9 — was NEXT (spec-prose only, no code).** Rewrite normative spec to match the implemented origin-as-identity design (RFC §10 item 15):
  `resolver-semantics.md` §6a/§6b (leak-rule repeal-and-replace) + §10 source-selection (from the S0 base, coordinate-is-origin +
  two-phase §4.4.1, NOT the old validate-against-registry stopgap) + §4.2.1; §7.1; `identity.md` (source-id, structured source{},
  subpath, canonical = stable wire format); `manifest-grammar.md` (provides{}, subpath=, complete 6-way overrides); `errors.md`
  consolidation; bijection lint green. Then S10 (Rust catch-up S7/S8/S8b + conformance parity), S11 (amoxtli manual).
- [x] (history) **S8 + S8b — was NEXT (Python-first grammar; Rust in S10).** S8: manifest grammar `subpath="pkg/foo"` on git/url/tarball(/oci)
  deps → thread into `SourceId.subpath` (value-type already reserves it), escape-guarded (§4.1, malformed→SRC-ID-MALFORMED).
  S8b (NO DEFERRAL, all four): extend `OverrideTarget` (=Git|Local|Member today) with **OciTarget + TarballTarget + RegistryTarget**
  (RegistryTarget = redirect a direct-source dep TO a registry coordinate) + **version-scoped overrides**. The overrides bridge
  must be COMPLETE for the "sole rebind bridge" claim (§7 B5).
- [x] (history) **S5b — Python DONE-GREEN (2026-08-03); Rust NEXT.** CLI-wide `solver_var` audit + dead-override diagnostic (RFC §10 item 12).
  `RES-DEAD-OVERRIDE` slug added (errors.py:297 + spec/errors.md:1221, WARN-only like RES-REGISTRY-SHADOW, non-fatal — fires when
  an `overrides {}` entry's name matches no resolved dep; checked post-resolve both resolve()/resolve_workspace). Audited the 66
  `solver_var`/`from_solver_var` sites (9 in cli.py mutation verbs) — each explicitly display/lockfile-bare vs solver-canonical.
  New tests: test_res_dead_override.py, test_s5b_mutation_verb_audit.py, test_m6_m7_override_warnings.py. Full suite exit 0 (3654
  green, 0 failed, verified clean run), 0 conformance fixtures changed. **→ Rust S5b (F7): mirror the ~35 Rust solver_var sites
  audit + RES-DEAD-OVERRIDE warn; per-crate dev-rust, run conformance in background (watchdog).**
- [x] (history) **S5-rekey — Stage A DONE; Stage B PYTHON DONE-GREEN but PAUSED ON A FORK (awaiting Corey). Rust NOT started.**
  **Stage B Python DONE-GREEN (2026-08-02, agent a1f0b56b):** full `uv run pytest` exit 0 (twice); **0 existing
  conformance fixtures changed** (byte-identical); headline collapse test PASS
  (`test_s5_rekey_solver_var.py::...test_bare_root_and_qualified_transitive_collapse_to_one_node` — root bare `foo` +
  transitive `acme::foo` → ONE node @1.2.0 via shared registry source-id). Forward ~20 sites use
  `binding_resolver.canonical_for()` / `canonical_key_for_requirement()`; reverse ~15 sites use new
  `_depkey_for_solved_name()` (depkey_for_canonical + fallback). Also fixed 8 deeper bugs incl. latent
  `reconcile_root_claims` ns-drop, solve-certificate canonical leak (`_project_solve_success/_error`),
  cross-pkg-enables target keys. Files: binding.py, resolver.py, edge_sources.py, +test_s5_rekey_solver_var.py (new),
  test_edge_sources/lockfile/s5a_qualified updated.
  **✅ DECIDED (Corey 2026-08-02, "build it best-in-class, stop compromising, honor the mandate") — TWO-PHASE design,
  RFC §4.4.1 now normative.** Kind-aware keying REJECTED as a shortcut. The correct design separates the two conflated
  questions: **(phase 1) name-resolution** `reference→source_id` (binding-aware: root/override pin wins → prior accepted
  binding → else kind default [git=/local=/tarball=/oci=→that source; bare name→registry coordinate]; disagreeing later
  claim = RES-BINDING-CONFLICT); **(phase 2) canonicalization** `source_id→canonical`, UNIFORM, kind-free. Solver var =
  `canonical(resolve_name_to_source_id(ref, binding_state))` for EVERY dep kind. Unifying reframe: **a direct
  git=/local=/tarball=/oci= decl IS an implicit name→source override** (Cargo [patch] / nimble URL-federation unified) — so a
  transitive bare `requires "bearssl"` resolves THROUGH the root git pin to the same GitSourceId → same canonical → ONE
  solver var, collapsed PRE-fetch. Delivers: registry label-collapse + git-pin↔require pre-fetch unification + same-URL-label
  collapse + correct RES-BINDING-CONFLICT + cross-origin content-dedup via Phase B. No regime split, thesis fully delivered.
  **✅ Python Stage B DONE-GREEN with two-phase design (2026-08-03, agent a1f0b56b).** Kind-conditional keying DELETED;
  solver var uniformly `canonical(source_id)`; phase-1 name-resolution is binding-aware (root/override pin → prior binding →
  kind default [git=/local=/tarball=/oci= decl → canonical(that source); bare named → registry coord]). Full `uv run pytest`
  exit 0; **0 conformance fixtures changed** (byte-identical); NO `return dep.name`/kind-conditional branch left in binding.py.
  Two tests green: `test_bare_root_and_qualified_transitive_collapse_to_one_node` (registry label-collapse) +
  `test_root_git_dep_and_transitive_bare_named_require_collapse_to_one_git_node` (git-pin↔bare-`requires` → ONE git node,
  PRE-fetch — the case the shortcut was working around). Found+fixed a projection leak the rework surfaced: S4c conflict-payload
  showed canonical `git+https://…` instead of display name — added the canonical→display projection at that boundary (same
  class as the certificate/lockfile projections #6/#7). Files: binding.py, resolver.py, edge_sources.py, tests. Fixes #2–#8
  carried over; #1 redone correctly.
  **→ Rust Stage B — IN PROGRESS (agent aec404122a).** Uniform canonical keying wired in resolver.rs (root terms use
  `canonical_for(&DepKey::bare(...))`, "no eager-kind bare-name carve-out"); both resolver-level collapse tests ported
  (resolver_tests.rs:6668 + 6770); **milpa-core GREEN (1028)**. BUT **`-p milpa-conformance` FAILS on 2 fixtures** (agent
  stalled on the cold conformance build before ever seeing them): **fixture-282** (ws cross-pkg-enable fixpoint never fires —
  member's own `flags{}.enables{}` looked up by bare name into canonical-keyed candidate map = Python fix #3 / supplement #3;
  actual lockfile missing lib-b `requires "lib-c"`+`active_flags "g1"`, lib-c absent) + **fixture-447**
  (transitive-named declaration-order tiebreak — discovery/preference order/keying diverged). Agent resumed with both targets +
  instruction to run the slow conformance build via `run_in_background` (the watchdog killed it on a foreground multi-min build).
  **Corpus is READ-ONLY** — fix Rust code, never re-bless (Python matches byte-identical, 0 changed). Definition of done:
  `-p milpa-core` + `-p milpa-conformance` both green. Per-crate dev-rust, never `--workspace` cold.
  **Stage A DONE + verified (grep-confirmed 2026-08-02):** (a) Rust Item::Local/Item::Tarball migrated to BindingResolver;
  `gate()`/`Gate`/`TIER_*`/`PKey`/`seen_by_name`/`override_target_to_pkey`/dead `Item::name()` + dead `process_url`
  RES-PROVENANCE-CONFLICT emit all DELETED; 9 gate() unit tests removed; Rust milpa-core 1016 (Stage A) → 1026 (+10 Stage-B
  foundation tests). (b) `RES-PROVENANCE-CONFLICT` deleted from errors.py + error.rs + spec/errors.md catalog
  (bijection lint green). Two residual mentions are BENIGN prose (spec/errors.md:1263 = RES-REGISTRY-SHADOW explaining what
  it superseded; resolver.rs:2472/2538 = historical comments) — bijection keys on `### CODE` headings, unaffected.
  **Stage B FOUNDATION landed + tested green** (additive, not yet wired): `binding.py` gained `_canonical_index: dict[str,DepKey]`
  (atomic in __init__/submit), `canonical_for(key)`, `depkey_for_canonical(str)` (THE reverse map, replaces
  `DepKey.from_solver_var`), `canonical_key_for_requirement(...)` (pure pre-submission). Rust mirrored. +12 py / +10 rs tests.
  **Stage B WIRING = the RFC headline, NOT yet done.** Python half in flight now (agent a5fd27348ebcc0c72): wire
  `canonical_key_for_requirement`→`edgeset_to_terms` (add `index` param) + root-term construction in resolve()/resolve_workspace();
  rekey `_Provider._candidates`/`_stubs` (resolver.py:629/631) to canonical keys; replace EVERY `DepKey.from_solver_var(package)`
  in is_root_direct/preference/_on_transitive_named/S4b/S4c/_build_graph with `binding_resolver.depkey_for_canonical(package)`;
  rekey `aliases_map` in _dedup_candidates/finalize (name→name today, confirmed NOT source-id-keyed). ~49 construction + ~13
  reverse-map sites Python. Headline regression: **two distinct labels → same source-id collapse to ONE solver var / ONE node.**
  **On-disk lockfile UNCHANGED** — emit `dep "<name>" {source{}}`, project canonical→name; existing label==name fixtures
  byte-identical (0 change), +1 collapse fixture. All-or-nothing within resolver.py (half-wired breaks
  is_root_direct/preference/graph-build immediately). **Rust Stage B = NEXT slice after Python verifies** (~41 construction +
  ~13 reverse-map; byte-match the Python-reblessed corpus; per-crate dev-rust). If Python can't land coherently green → STOP
  PARTIAL, never leave red.
- [ ] (dead) **S5** — NEXT (BIG, breaking): (1) **feed solver `canonical(source_id)`** — `Term.package`=canonical, provider
  candidate/stub dicts re-keyed name→canonical (§4.4, moved from S3a); (2) **structured on-disk lockfile source** — each
  LockedDep gains a `source { kind; … }` KDL node (uv model), deserialize field-by-field into SourceId (NO parse());
  one-shot regen; (3) field-dup audit (§4.4/B2): delete `registry_namespace` (read source_id.namespace), re-home
  `provenances` to per-version transport provenance; (4) slot projection → nim.cfg/_deps + milpa show/verify; (5)
  **FROZEN-SOURCE-ID-MISMATCH** precondition — declared-AFTER-override (reuse `reconcile_root_claims` helper, §7.1/D2) +
  fixture; (6) **FROZEN-REGISTRY-ALIAS-UNRESOLVED** checked FIRST (D3) + fixture; (7) pull add/remove/update lockfile-key
  sites in (F5, cli.py). **Re-bless the WHOLE conformance corpus** (every milpa.lock changes) from Python oracle; Rust
  byte-matches (structured source format is normative — highest cross-impl-divergence risk). Rust mirror (per-crate
  dev-rust). May report PARTIAL+split if too large — default is finish.
- [ ] (dead) **S6** — import-slot DIRECTORY floor (§4.6). `check_directory_slot_collisions(resolved)` → `RES-IMPORT-COLLISION`
  when two DISTINCT source-ids project to the same `_deps/<slot>/`, WITH the **content_hash short-circuit** (same slot +
  same content_hash = the cross-origin-identical case S4b celebrates → MUST NOT raise; fixture-458 is the regression guard).
  Plain function, NO port (port is S7). Kept as fast-path pre-filter under S7. Slug carries "directory-slot only, not full
  import" caveat. **Frozen reachability (F4, no-defer):** the floor needs source_id; on fresh resolve it's present, but
  frozen/verify has no source_id until S5 re-keys the lockfile — so EITHER populate source_id at frozen.py's ResolvedDep
  construction now, OR scope the floor fresh-resolve-only AND ensure S5 extends it to frozen (in-loop, not deferred out).
  Rust mirror in-window (per-crate dev-rust).
- [ ] (dead) **S4b** — reconcile Phase B `_dedup_candidates` (Python) / `finalize` (Rust) with source-id keying. Today they
  group by content_hash only + produce a LABEL-keyed `aliases_map`. Make it source-id-aware → genuine CROSS-ORIGIN
  unification (a registry coordinate + a git URL fetching identical bytes collapse to one solver var + one _deps/ view =
  the §3.3 win). KEEP the identical-`requires` invariant guard. **Record BOTH collapsed origins' provenance** (today only
  one survives; `provenances` is an existing list field on LockedDep so this is richer data, not a format change → S5-safe).
  Regression: (a) 2 distinct source-ids / identical content_hash → 1 solver var + both provenances survive; (b) 2 distinct
  source-ids / different content_hash → never merged. Observable output change (2 provenances) → conformance fixture
  warranted. Rust mirror in-window (per-crate dev-rust).
- [ ] (dead) **S3b** — Remove `provenance_gate`, `TIER_ROOT/REGISTRY/SELF_URL`, `_check_provenance_gate`,
  `_validate_transitive_url_against_registry`, `_registry_git_provenances`/`_registry_oci_source_urls`, `_ROOT_SELF_PKEY`/
  `_NAMED_PKEY`; rewrite `OciIndexProvenance.source_url` docstring→audit-only (+note publishing.py audit-only source_url);
  delete the now-dead unit tests of those fns. **RETAIN `root_authority`** single-purpose for `_version_unknown_constrained_err`
  (comment it). Add hermetic conformance fixture reproducing `BUG-root-authority-kdl-transitive.md` cases B/D — **if B/D
  still fail → FIX the BFS wave-orchestration defect IN-LOOP** (no xfail/file; fixture asserts B/D resolve correctly).
  **Rust PREREQ (from S3a-Rust agent):** before deleting `gate()`/`Gate`/`TIER_*`, extract `discovery_order` bookkeeping
  into an independent method (Local/Tarball arbitration + solver tiebreak depend on it); the 4 validate-against-registry
  fns are fully dead → delete outright. Rust per-crate dev-rust (not --workspace).
- [ ] S3a-req / S3b / S4 / S4b / S6 / S5 / S5b / S7 / S8+S8b / S9 / S10 / S11 — queued.
  (S3a NOTE from S2 agent: wire into BOTH resolve()/resolve_workspace(); write the override-preempts-dep reconciliation
  helper; land S3c registry-shadow tripwire in the SAME commit; Claim.name = manifest `ns::name` joined form at ~10 BFS sites.)

**RESUME after a compaction:** re-read this block + RFC §10 + [[provenance_source_selection]]; check filesystem for the
last slice's deliverables; if a subagent notification is pending, wait for it; else launch the next unimplemented slice
(S1-rev, then S3a) via a `sonnet` subagent. STRICTLY SERIALIZE — wait for each slice's full report before launching the next.

---
### (pre-grind) STAGE: rfc-flow Stage 2 — architect review. BOTH ROUNDS DONE.
RFC = `docs/rfc-origin-as-identity.md`. Round-1 + round-2 both ran the 4-lens team (depth /
breadth / design-ergonomics / feasibility); all clear-best fixes applied to the RFC (ledgers
below). **Round 2 found NO genuine forks** — every finding had a goal-determined answer and was
resolved under the bar (decisions recorded in §11 "Decided (round 2)"), pending only Corey's veto.
**RESUME:** `/loop implement the next unimplemented RFC slice with /tdd …` — the S1→S11 grind in
§10 build order. Do NOT re-open coordinate-is-origin (settled) or re-derive the model.
Safe to `/compact` here.

**Round-2 headline fixes (grounded against real code):**
1. **Security-critical slice ordering (F1/F2, CRIT).** The deleted checks are `continue`-gated BFS
   admission — so the dependency-confusion gap opens at **S3a, not S3b**. Fix: S3c (registry-shadow
   tripwire) now lands *inside* S3a's commit, feeding `submit()`'s pre-check → `main` never exposed.
2. **Phase B `_dedup_candidates` (D1/B4, HIGH — CORRECTED after Corey pushed to honor the roadmap).**
   The reviewer flagged that this pass merges solver variables by content_hash pre-solve; I first
   proposed deleting it (S4b). WRONG: it is shipped Phase B, merge-on-*proof* (identical content_hash +
   identical-requires invariant guard), post-fetch + identical-bytes-only → does NOT violate §3.3
   (forbids merge-on-*heuristic*), CANNOT blind the pre-fetch tripwire, and IS milpa's differentiator
   at the solver layer. Deleting it would regress the roadmap's own goal. Fix: KEEP & extend; §3.3
   invariant reworded (merge-on-proof legit, cross-origin under source-id keying); S4b flips to
   RECONCILE (re-key aliases_map to source-ids + record both collapsed origins' provenance). #32–34
   (global CAS store, multihash) = the still-open part, not this within-resolve unification.
3. **`source_id_for(name)` grouping-key bug (B1/G1, HIGH — two lenses).** Bare-name key = literal #193
   root cause. → `DepKey`, with an S2 RED test for `ns1::foo`/`ns2::foo` non-crossing.
4. **`FROZEN-SOURCE-ID-MISMATCH` ignores overrides (D2, HIGH).** frozen.py never reads `overrides` →
   naive check false-positives on every override project. → compares declared-*after-override*.
5. **git-normalizer over-claim (D4, HIGH).** Credited with userinfo/port/SCP behavior it lacks. →
   three explicit tiers: kept / added (userinfo+default-port) / not-attempted (ssh↔https, SCP).

### Round-1 "forks" — RESOLVED under the bar (were polling errors; awaiting Corey veto only)
- **D-Fork1 — dependency-confusion defense = KEEP a pre-fetch registry-shadow tripwire (§6.1/§11).**
  Resolved (a): warn-default, hard-fail under `attestation-policy` strict; `RES-REGISTRY-SHADOW`;
  orthogonal to coordinate-is-origin (Cargo's identity model ≠ Cargo's absence of a confusion
  defense — separable); re-homes threat-model fixtures; lands S3c in the S3b window. Rejected (b)
  full-Cargo-no-tripwire = security step-down for milpa's differentiator. Bar-decisive (milpa's
  positioning is supply-chain integrity; Birsan-2021 attack class).
- **D-Fork2 — discard the stopgap §10 text (S0).** Resolved (a): S9 writes §10 from last-committed
  base (stopgap encodes a factually-wrong "name-keyed as in Go" model). End-state identical either
  way. Residue = Corey's git action on his own tree (revert the §10 hunk or leave it dormant; RFC
  bases off last-committed regardless). I won't touch git unilaterally.
- **D-Fork3 — subpath grammar stays in-RFC as S8.** No design content; splitting = pure overhead,
  no consumers waiting.

### Round-1 review ledger (all applied to the RFC unless noted)
| id | lens | sev | finding | resolution |
|----|------|-----|---------|-----------|
| D1 | depth | CRIT | `pkg+` flat-slash-join non-injective; round-trip law undecidable if registry=base-URL; `namespace` not `_validate_safe_name`'d (real pre-existing bug) | §4.1 rewritten: registry=alias slug, exact 2/3-segment parse algo, namespace-validation gap folded into S1 |
| D4 | depth | MED-HI | `#subdirectory=` unescaped; tarball/oci subpath collisions constructible | §4.1 uniform percent-escaping rule for all subpath-bearing kinds |
| D3 | depth | HIGH | new lockfile key contradicts live NORMATIVE §6b "`::` MUST NOT appear on disk" | §7 explicit repeal-and-replace clause |
| D2 | depth | HIGH | §12 over-claims BUG B/D fixed; B=already-dedup, D=BFS-orchestration collateral, not keying | §12 claim tightened; A–D fixtures (S3b/S11); trace required |
| D5 | depth | MED | "pure/pre-fetch" overstated for named claim construction | §4.3 scoped: arbitration pure; named claim-construction index-I/O + BFS-interleaved |
| D6 | depth | MED | no arbitration branch for two ROOT claims (dep + override same name) | §4.3: override pre-empts root dep before binding (unreachable by construction) |
| D7 | depth | MED | directory-slot floor content-hash-blind → false-positive on §3.3's own edge case | §4.6 content_hash short-circuit |
| D8 | depth | LOW-MED | override to different registry coordinate → SourceId fields diverge from DepKey | §5 new row: read accepted SourceId's own coordinate |
| D9 | depth | LOW | #191 attribution misleading (already shipped Axis A) | header + §14 fixed |
| G1 | design | HIGH | `ClaimAuthority(IntEnum)` = deleted tier lattice smuggled back | §4.3 → `is_root: bool` |
| G2 | design | HIGH | reverse-map side-table redundant (parse() is inverse; ResolvedDep exists) | §4.4 → `ResolvedDep.source_id` + parse() |
| G3 | design | MED-HI | `SymbolProviderPort` shipped unused day-one vs RFC's own YAGNI | §4.6: S6 plain function, port in S7 |
| G4 | design | MED | `SourceIdNormalizer` Protocol/registry speculative (1 of 6 kinds real) | §4.2 → single `normalize_source` fn |
| G5 | design | MED | "root submitted first" precondition unenforced | §4.3 structural `__init__(root_claims)` |
| G6 | design | LOW | §3.1 blurs "identity" back onto source-id | §3.1 vocabulary-discipline note |
| F1 | feas | CRIT | S3 is really 4 slices (32 gate sites); wire+delete = unreviewable long RED | §10 split S3a/S3b(+fixture); reorder |
| F2 | feas | CRIT | model deletes live dependency-confusion defense under "test migration" | §6.1 callout + **Fork 1** |
| F3 | feas | HIGH | uncommitted §10 stopgap = different superseded model; inconsistent base | **Fork 2** + S0 |
| F4 | feas | MED | Rust deferred to S10 → 9-slice divergence; corpus can't gain fixtures; mirror into `edgeset_to_extracted` (live), not `edgeset_to_terms` (dead) | §9 per-slice mirror rule |
| F5 | feas | MED | amoxtli proof manual/non-reproducible | S3b hermetic B/D fixture; S11 = confirmation |
| F6 | feas | LOW | S1 property tests need URL-aware composite strategies not bare alphabet | S1 note |
| F7 | feas | LOW | naming collision source_spec.py vs source_id.py; reuse split_oci_target | S1 cross-ref note |
| B1 | breadth | HIGH | frozen.py/verify never checks source-id → edit git= URL passes silently | §7.1 `FROZEN-SOURCE-ID-MISMATCH` (S5) |
| B2 | breadth | HIGH | CLI add/remove/update conflate label & key via solver_var (34 sites); from_solver_var unsound | S5b CLI-verb audit slice |
| B3 | breadth | HIGH | `requires` edges carry raw labels → stale-label drops dep from nim.cfg closure | §4.7 re-derive edges through source-id |
| B4 | breadth | MED | S5 (rekey) before S6 (collision) → silent slot-collision window | §10 S6 pulled forward before S5 |
| B5 | breadth | MED | overrides can't express Oci/Tarball/Registry/version-scoped rebinds | §7 add Oci/Tarball targets; defer+file Registry/version-scoped |
| B6 | breadth | MED | deleted validate has ACCEPT path; new model → hard RES-BINDING-CONFLICT | folded into Fork 1 threat-model audit |
| B7 | breadth | MED | attestation subject must bind to coordinate not display name | §4.7/§7 normative clause |
| B8 | breadth | MED | subpath no path-escape guard (../, absolute) | §4.1 escape-guard (SRC-ID-MALFORMED) |
| B9 | breadth | LOW | OciIndexProvenance.source_url docstring describes deleted purpose | §6 rewrite in S3b |
| B10 | breadth | LOW | no dead-override diagnostic | S5b |
| B11 | breadth | LOW | no "Alternatives Considered" (content-hash-key, resolve-through) | §13 added |
| B12 | breadth | LOW | adjacent RFCs not cross-referenced | §14 added |
| B13 | breadth | LOW | no slug for unresolvable registry alias | §7 `FROZEN-REGISTRY-ALIAS-UNRESOLVED` |

### Round-2 review ledger (all applied to the RFC; no genuine forks — decisions in §11 "Decided (round 2)")
| id | lens | sev | finding | resolution |
|----|------|-----|---------|-----------|
| R2-F1 | feas | CRIT | §10 numbers S3c last but text says "S3b window"; ordering contradiction | §10 rewritten as strict build order; S3c folded into S3a |
| R2-F2 | feas | CRIT | deleted checks are `continue`-gated BFS admission → confusion gap opens at S3a not S3b | S3c lands *inside* S3a's commit, feeds `submit()` pre-check; §9 states same for Rust |
| R2-D1 | depth | HIGH | existing pre-solve `_dedup_candidates` merges solver vars by content_hash — vs §3.3 slogan | **CORRECTED (Corey):** it's merge-on-proof (shipped Phase B), post-fetch, identical-bytes-only → keep & extend; §3.3 invariant reworded; S4b = reconcile+record-both-provenance (not delete); #32–34 = global CAS/multihash only |
| R2-B1/G1 | breadth+design | HIGH | `source_id_for(name)` contradicts `(namespace,name)` grouping = #193 root cause | §4.3 → `source_id_for(key: DepKey)`; S2 RED test for namespace non-crossing |
| R2-D2 | depth | HIGH | `FROZEN-SOURCE-ID-MISMATCH` ignores overrides → false-positives every override project | §7.1: compare declared-*after-override* via shared helper; S5-scoped + fixture |
| R2-D4 | depth | HIGH | promoted `_normalize_git_source_url` credited with userinfo/port/SCP it lacks | §4.2 three tiers: kept / added(userinfo+port) / not-attempted(ssh↔https,SCP) |
| R2-F3 | feas | HIGH | S3a bundles 2 BFS entry points + requires-edge re-derivation + pretty-printer | §10 split: S3a (wiring) / S3a-req (requires-edge, own nim.cfg coverage) |
| R2-F4 | feas | HIGH | S6 floor unreachable on verify/frozen until S5 (source_id not in lockfile) | §10 S6: scope "fresh-resolve only" or fold frozen.py:193 source_id population |
| R2-F5 | feas | HIGH | S5→S5b gap breaks add/remove/update lockfile-key reads, no sign-off | §10: pull mutation-verb key sites into S5; S5b = broader audit only |
| R2-B2/G10 | breadth+design | HIGH | 3 things called "namespace"; source_id vs registry_namespace/provenances duplicate | §4.4 audit: source_id authoritative, delete registry_namespace, re-home provenances |
| R2-G2 | design | MED-HI | `suppressed: bool` hides dedup-vs-lost-to-root (the opacity this RFC removes) | §4.3 → 3-way `BindOutcome` enum; feeds dead-override diagnostic |
| R2-G3 | design | MED-HI | "declared name wins" no tie-break for declared-vs-declared → silent label drop | §4.7 tie-break root>first-BFS>URL-tail + visible drop note |
| R2-G4 | design | MED | `MemberSourceId` exemption from edge_cache/import-slot/attestation is untyped | §4.1 split `FetchableOrigin` vs `SourceId`; type consumers over FetchableOrigin |
| R2-B3 | breadth | MED | S3b deletion list omits `root_authority`'s other consumer (`_version_unknown…`) | §6 Kept: root_authority survives single-purpose, bare-name-scoped, commented |
| R2-B4 | breadth | MED | §3.3 "avoid double compilation" not delivered (only same-slot dedup) | §3.3 rescoped to disk-level; compile-level = #32–34 forward-ref |
| R2-B5 | breadth | MED | #192 "adjacent" asserted never examined; R6 namespace door directly relevant | §14 traces R6 verdict: unaffected/still-open, tracked #192, next RFC |
| R2-B6 | breadth | MED | pretty-printer scope < surfaces needing it (RES-BINDING-CONFLICT in S2 pre-S3a) | S1 defines `format_source_id`; all slugs reuse it |
| R2-F6/F7/F12 | feas | MED | Rust: same security-window; ~35 mutation sites not in S10; S3b ~55 hits not ~34 | §9 states all three for Rust; S5b Rust half explicit; re-count before sizing |
| R2-F8 | feas | MED | "reuse split_oci_target" correct only for OCI; pkg+ is fixed-arity | §10 S1: reuse for OciSourceId only; pkg+ needs its own splitter |
| R2-F9 | feas | MED | S1 Hypothesis is really 3 composite generators, not "one" | §10 S1: three named generators (base+subpath / pkg+ arity / round-trip) |
| R2-G7 | design | MED | source_id.py staples heuristic + formal-wire-format boundaries | §10 S1: section formal-half vs heuristic-half; split file only if diff harms review |
| R2-D3 | depth | MED | no precedence between FROZEN-SOURCE-ID-MISMATCH and FROZEN-REGISTRY-ALIAS-UNRESOLVED | §7.1: alias-unresolved checked first, short-circuits |
| R2-D5 | depth | MED | §12 B/D "lock whatever behavior" has no exit condition | S3b/§12: if still-broken → file issue + xfail, never green-pin a bug |
| R2-F10 | feas | MED | S11 amoxtli has no /tdd-compatible execution mode (network) | §10 S11 = manual/gated runbook, not automated; S3b fixture is the guard |
| R2-F11 | feas | LOW | overrides Oci/Tarball targets filed under S9 spec but it's parser work | §10 S8b: parser/grammar slice, not spec-prose S9 |
| R2-G5 | design | MED | `subpath` copy-pasted 3/6 kinds → Subpathed[T]? | §4.1 considered+declined (flat union beats heterogeneous generic union) |
| R2-G6 | design | MED | "origin" used as both component-of and synonym-for SourceId; §2.1 pre-empts §3.1 | §2.1 heading→"Package origin"; §3 formula reworded |
| R2-G8 | design | LOW-MED | free-function canonical/parse diverges from DepKey method precedent | §4.1 one-line rationale note |
| R2-G9 | design | LOW | S6 fate at S7 unstated; RES-IMPORT-COLLISION over-promises | §4.6 S6 kept as fast-path; errors.md caveat "directory-slot only" |
| R2-B7 | breadth | LOW | publishing.py audit-only source_url not in §6 re-homed list | §6 one-line note |
| R2-D6 | depth | LOW-MED | LocalSourceId no case-normalization rule | §4.1 normative: case-sensitive; documented case-insensitive-FS limitation |
| R2-D7 | depth | LOW | OCI segment-boundary assumption unstated (parity vs pkg+) | §4.1 normative OCI segment rule |

---

### (Historical — round-1 kickoff context, superseded by the ledger above)

**DECISION MADE (Corey, 2026-08-01): decision (b) → the deeper keying model, at full ambition.**
Chose **"Origin-keyed (full)"** scope. We are NOT shipping the corrected-§10 stopgap as an
endpoint — it becomes one component of a larger RFC. RFC written → 2 architect review rounds →
`/tdd` grind.

**THE NEW MODEL (origin-as-identity / source-id keying):**
The root error was that the **PubGrub solver variable is the consumer's NAME/label** (a bare
`str` in both impls). Fix: the solver variable becomes a **source-id** = the package's origin.
Three distinct namespaces, previously fused into one string, are now separated:
- **Import symbol** (`import z3`) — Nim compile-time, build-local slot. At most one occupant per
  build. Checked POST-solve (two distinct source-ids providing the same symbol → RES-IMPORT-COLLISION).
- **Package identity / solver variable** = **source-id** = `(normalized_url | oci_coordinate, subpath?)`,
  **ref EXCLUDED** (ref/tag is a *version*, not identity). Version-independent.
- **Per-version verification** = `content_hash` (spec/identity.md) — UNCHANGED, untouched.
  NB: identity=content_hash non-negotiable is NOT violated; we rename the *solver variable* from
  name to source-id (Cargo's term). content_hash keeps its per-tree job.

**TARGET PIPELINE:**
`claims + registry index` → **BINDING PHASE** (pure, pre-fetch: each name → one source-id; root
arbitrates; one name bound to ≥2 source-ids in a build → RES-BINDING-CONFLICT — this is all §10
becomes) → **PubGrub over source-ids** (aliases collapse; nim-z3 ≠ nimz3 by construction) →
**post-solve import-slot check** (RES-IMPORT-COLLISION) → materialize (content_hash unchanged) →
lockfile keyed by source-id.

**GROUNDING CONFIRMED (4 Explore agents, both impls):**
- Solver var is a bare `String`/`str` today (Python `Term.package:str`; Rust `Dep.package:String`).
- **Every origin is knowable pre-solve** — git/local/tarball from manifest; `named` from the
  pre-loaded registry index (`IndexVersion.provenances[0]`). Fetch only picks a version, never
  discovers a source. Binding phase can be pure + pre-fetch. **Load-bearing assumption HOLDS.**
- Source-selection today is a fragile **side-table** (`provenance_gate[name]=(pkey,tier)`);
  `BUG-root-authority-kdl-transitive.md` is a direct symptom (suppress a claim → dangling edge →
  collapse). The real structural win = make binding a first-class phase producing the solver's
  variables, killing that whole bug class by construction.

**FOUR PIECES, all needed regardless of keying (bundle into the RFC):**
1. Don't consult the registry for a lone self-sourced dep (the corrected-§10 content).
2. Post-solve import-slot check (RES-IMPORT-COLLISION) — the correct home for Nim's flat-namespace constraint.
3. Read real versions (#191) — orthogonal; synthetic `Version(0,0,1)` (`resolver.py:159` / Rust `url_dep_version` ~50-60) is a separate concern.
4. First-class binding phase (name→source-id) replacing the side-table. **The structural fix.**

**THE ONE HARD SUB-PROBLEM:** source-id canonicalization — URL-equivalence policy (scheme/host-case/
`.git`/trailing-slash; is `git@h:x/y` ≡ `https://h/x/y`? — lean yes, Go-style) + monorepo **subpath**
(one git URL can host multiple packages → source-id MUST carry subpath, else over-unify). The RFC must nail this.

**SPEC BLAST RADIUS (HIGH, accepted):** rewrite normative §6a/§6b (DepKey-is-solver-var), all of §10,
§4.2.1 (BFS dedup "package ≡ name"). Plus fix a factual error: §10.0 currently claims Go is
name-keyed — it's URL-keyed (exactly our new model). Lockfile re-keyed by source-id = clean pre-v1
break (no compat shim, per [[feedback_no_legacy_support_prev1]]).

**PROOF target (unchanged):** amoxtli resolves softlink via its own URL, NO tianguis republish. The
whole publish-softlink/backfill thread chased a false conflict.

**KEEP (correct, reused by the new model):** alias-name fix (`8238e2d`), OCI `source` field +
tianguis write-path (tianguis `2770d3d`) + §3.5.3 digest (`79be709`) — OCI `source` becomes the
name→source-id resolution for the OCI transport. root-satisfies-own-name (`31454de`, spec §14) stays.
The `validate_transitive_url_against_registry` model (`1ff17bd`, `f889621`, resolver part of
`31454de`) gets REPLACED by the binding phase (not just rescoped).

**UNCOMMITTED (do NOT commit yet — being superseded by the RFC):** `spec/resolver-semantics.md` §10
rewrite (the stopgap draft — its *content* folds into piece #1, but §10 will be rewritten again for
source-ids); `BUG-root-authority-kdl-transitive.md` (untracked; keep as a design fixture — it's the
canonical repro the binding phase must fix).

**RFC WRITTEN → `docs/rfc-origin-as-identity.md`** (architect Step 6 done). Design settled = hybrid:
Ergonomic closed-union `SourceId` value type + Flexible per-kind normalizer registry + pure
`BindingResolver` + Ports symbol-level import-slot check + untouched solver. Registry fork RESOLVED
(Corey 2026-08-01) → **coordinate-is-origin (Cargo's `(name,source)` model)**; `overrides {}` =
`[patch]` bridge; NO URL-inspection auto-unification; `content_hash` dedups identical bytes across
distinct source-ids (milpa's edge over Cargo). OCI-`source` field re-homed to audit metadata. New
slugs RES-BINDING-CONFLICT + RES-IMPORT-COLLISION + SRC-ID-MALFORMED; RES-PROVENANCE-CONFLICT removed.
11 slices S1–S11 defined in the RFC §10.

**STAGE: rfc-flow Stage 2 (architecture review, 2 rounds) — NEXT.**
**RESUME:** `/architect docs/rfc-origin-as-identity.md round 1`, then `round 2`, then
`/loop` tdd grind of S1–S11 (Python oracle → Rust mirror → conformance fixture per slice).
Open items for the architect rounds (RFC §11): (a) is subpath grammar S8 in-RFC or a dependent
mini-RFC; (b) confirm failure-path reverse-map pretty-printer in S3; (c) registry-coordinate
canonical prefix (`pkg+` vs `pkg://`) + registry component = base-URL vs alias (lockfile portability).
Do NOT re-derive the model or re-open the coordinate-is-origin decision — settled above.

**UNCOMMITTED now:** `docs/rfc-origin-as-identity.md` (NEW), this handoff, `spec/resolver-semantics.md`
§10 stopgap rewrite (superseded — will be re-rewritten for source-ids in S9), `BUG-root-authority-kdl-transitive.md`
(untracked — keep as the canonical repro fixture). Nothing committed; nothing pushed. Awaiting Corey.

---
## ⚠️ HISTORICAL / SUPERSEDED below — the CURRENT STATE above is authoritative. (Commit LISTS below are accurate; the DESIGN descriptions — tiers, validate-against-registry, "final" — are the wrong iterations that led here.)

# Provenance authority — validate-against-registry (#193) — handoff

## SHIPPED to milpa main (both impls, byte-identical, green)
- `1feffe4` resolution-semantics RFC · `1ff17bd` #193 provenance lattice · `f889621` OCI content-hash fallback · `31454de` root-satisfies-own-name (spec §14) + OCI source-URL provenance validation (registry-protocol §3.3, resolver-semantics §10 3-step, cli-contract §10.2).
- Final: Python 3498/0-fail; Rust workspace exit 0 (milpa-core 945, milpa-cli 162, milpa-conformance 224, bijection + corpus ok).

## ALL CODE SHIPPED (milpa + tianguis)
- milpa main: `31454de` (root-satisfies-own-name §14 + OCI source-URL data/resolver/publish), `79be709` (§3.5.3 OCI digest source inclusion). Python 3500/0-fail; Rust workspace exit 0 (946 milpa-core, bijection+corpus ok).
- tianguis main: `2770d3d` (OCI source write-path: model/kdl_io/addentry/cli + dispatch/handler.go + publish action + commit-entry workflow). Full Nim suite green. index.kdl untouched. Rebased cleanly over the daily vendor/attest bot commits.

## REMAINING — ONE live-CI step, Corey's to trigger
- **Publish a new softlink version through its (now source-recording) publish CI.** softlink's existing tianguis entry (0.11.0) has no `source` and can't be cleanly backfilled (mergeVendored idempotency discards a same-version re-add; a hand-edit is a ratchet mutation). A NEW version's first admission carries `source` as an ordinary append. This is a live OCI push + GH Actions + dispatch chain I can't run.
- **Then amoxtli resolves:** its transitive git-references softlink@main; once tianguis's softlink entry records `source`, milpa source-URL-matches git@main → agree → softlink resolves (no conflict). Then re-resolve amoxtli → commit ONLY its milpa.lock.
- **Bonus cleanup (softlink repo, Corey):** softlink can now DROP `overrides { pkg "softlink" local="." }` — root-satisfies-own-name (§14) makes it unnecessary.

## (historical) earlier remaining-notes
- **amoxtli STILL blocked on softlink:** the milpa RESOLVER now supports OCI source-URL match, but amoxtli won't resolve until softlink's tianguis OCI entry actually RECORDS its source url. Getting it there needs a LIVE tianguis-registry op: (a) manual backfill of tianguis index.kdl (may trip the append-only ratchet TNG-ENTRY-MUTATED), or (b) re-publish softlink via the new milpa publish (records source) + update the tianguis composite action to WRITE the source field into the index entry. Both are cross-repo, live-registry — confirm approach with Corey before mutating the registry. Interim alt: root-declare softlink in amoxtli milpa.kdl (tier-1) — but Corey said stay off amoxtli's milpa.kdl.
- **§3.5.3 ratchet-digest source inclusion (flagged by the OCI-data agent):** the oci canonical-violation digest doesn't include `source` — violation DETECTION is unaffected (full typed compare), only the habituation-suppression digest coalesces source-only-differing violations. Both impls, lockstep + differential fixture. Touches the LIVE ratchet's canonical digest (one-time re-alert side effect). Small; do-not-defer candidate but interacts with the tianguis work.
- **Follow-ups (Corey-gated GH issues):** workspace member required by an external transitive → TNG-NOT-FOUND (pre-existing, found by the root-self agent).


- **Stage:** COMPLETE — shipped in BOTH impls, byte-identical. Closes #193.
- **Final suites GREEN:** Python 3465/0-fail/33-skip; Rust workspace exit 0
  (milpa-core 921, milpa-cli 162, milpa-conformance 224, bijection + conformance
  corpus ok). Nothing committed — awaiting Corey.

## The design (final, Corey-approved as the best-in-class answer)

The frame is **authority**, not source-type. milpa's identity is content-hash;
provenance (url vs registry) is orthogonal metadata — so ranking source-*types*
into fixed tiers is arbitrary. The real question is *who is authorized to decide
a non-root name's source, and what happens when they disagree.*

```
Tier 1  Root      — explicit per-build human choice (deps / overrides)
Tier 2  Registry  — trusted DEFAULT (tianguis index), not an explicit choice
Tier 3  Self-declared url/tarball
```

**Core principle: milpa MUST NOT silently resolve a genuine source disagreement
over a non-root name.** It either accepts an *agreeing* claim or escalates to the
root.

- **Root (tier 1)** — declared the source; a disagreeing transitive is silently
  suppressed. Correct: it honors an explicit human choice, not a guess.
- **Registry (tier 2) — VALIDATE, don't win.** For a non-root name in the index,
  a transitive self-declared `git=`/`tarball=` source is validated against the
  registry's recorded source:
  - **agrees** (same repo — a different `ref` is still agreement, it just picks a
    version) → accepted, resolves normally (content-hash dedup unifies it with any
    registry-version candidate);
  - **disagrees** (different repo, or incomparable transport e.g. `git=` vs an
    OCI-only entry) → `RES-PROVENANCE-CONFLICT`; remedy = root-declare the name.
    Never silently redirect to the registry (would override a legit fork), never
    silently honor the transitive (would let a transitive substitute a registry
    name's source).
- **Not in registry (tier 3)** — one claim stands; two disagreeing → conflict.
- Orthogonal to the **attestation policy** (which governs *how much* to trust a
  registry resolution — strict / RES-UNATTESTED-METADATA). Do not fold it in.

**Why this beats the alternatives** (both explored + built, then rejected):
- *disagreement-only* (registry wins only if a competing named claim also exists):
  silently honors a lone transitive substitution, and had an unclosable mid-solve
  residual (a named-of-named claim revealed only during solve).
- *membership-based* (registry silently wins for any registry-known name):
  silently overrides a library's legitimate fork.
  Both make a **silent** choice on a genuine ambiguity. Validate-against-registry
  is the only one that never does — agree→accept, disagree→root-arbitrates. It
  also closes the residual **by construction**: validation is a static gate-time
  check vs the loaded index record, so a disagreeing tier-3 claim is conflicted at
  its own discovery and never becomes a candidate for a late claim to collide with.

## Mechanism (both impls, byte-identical)
- `validate_transitive_url_against_registry(name, url, pkg)` — gathers the git
  source urls recorded across ALL of the package's index versions; none (OCI-only /
  no provenance) → conflict (incomparable); else `normalize_git_source_url` (strip
  trailing `/` and `.git`, lowercase scheme+host, preserve path case) both sides and
  membership-check; match → accept, else → `RES-PROVENANCE-CONFLICT` (message names
  both sources + the root-declare remedy). Never compares `ref`/`commit_sha`.
- Wired at the url gate/dispatch point for a transitive (non-root) name that
  `lookup_bare`s to a definite `Package`; **agree bypasses the single-claim gate**
  so two agreeing pins at different refs coexist as distinct candidates. Ambiguous
  index result → named enumeration (TNG-AMBIGUOUS-NAME, orthogonal). Root names
  never validated (tier 1 silently wins). Transitive tarball/local never reach the
  BFS (M2 security gate) → not applicable.
- Python: `impls/python/milpa/resolver.py` (`_validate_transitive_url_against_registry`,
  `_normalize_git_source_url`, `_registry_git_provenances`; call site in the
  `kind == "url"` branch of `_run_bfs_wave_loop`). A latent concurrency bug surfaced
  (two same-name eager fetches racing on `deps_dir/<name>`, previously impossible
  because the gate serialized them) was root-cause-fixed: `_process_url_worker` takes
  an explicit `dest`, disambiguated per-wave only for a 2nd+ same-name claim.
- Rust: `impls/rust/crates/milpa-core/src/resolver.rs` (mirror; `gate_only` validates
  before the tier gate). Synchronous BFS → no dest race. The prior interim mechanisms
  (disagreement-only pre-solve `reconcile_tier2_over_tier3` sweep) are REMOVED in both.

## Fixtures + tests
- `conformance/spec-v1/fixture-448-url-agrees-with-registry-accepted` (agree → resolves)
  and `fixture-449-url-disagrees-with-registry-conflict` (disagree → RES-PROVENANCE-CONFLICT),
  blessed from the Python oracle, Rust byte-matches. Corpus: 0 regressions.
- Python `tests/test_provenance_lattice.py` (31 tests) + Rust `resolver_tests.rs`
  lattice tests: agree/disagree (both discovery orderings), mid-solve residual closed,
  lone-agrees / lone-disagrees, two-agreeing-pins-coexist, root-beats-both,
  url-vs-url-no-registry conflict, + normalize/validate unit tests. A4's transitive
  case updated (disagreeing transitive → conflict).

## Post-ship extension (in flight): OCI content-hash fallback
- SHIPPED core #193 committed+pushed as `1ff17bd` (feat: validate transitive provenance).
- **Real gap found by amoxtli:** a package published to tianguis via **OCI** (from a git
  repo) then referenced by that **git URL** by a transitive → the "incomparable transport
  (git vs OCI) → conflict" rule fires (softlink: amoxtli's crisol/nkdl chain git-references
  it; tianguis has it as OCI). git-softlink and OCI-softlink are the SAME package.
- **Fix (in flight, add1857439, Python-first):** when the registry entry has no comparable
  git source, validate by CONTENT IDENTITY instead of conflicting — compare the git source's
  `content_hash` (milpa already hashes every fetch) to the registry's recorded
  `IndexVersion.content_hash`. Same identity → accept; different → conflict; unavailable
  (legacy/empty) → conflict. Confirmed: `IndexVersion.content_hash` exists; OCI entry has no
  source URL. Spec §10 gets the incomparable-transport clause updated. Rust mirror after.
- **amoxtli lock: BLOCKED on this fix** — re-resolving amoxtli with shipped milpa (incl #193)
  fails RES-PROVENANCE-CONFLICT on softlink; once the OCI fallback lands, re-resolve → real
  versions → commit ONLY amoxtli's milpa.lock (Corey: their in-progress code-review work
  touches neither milpa.lock nor milpa.kdl, so the lock change is isolated).

## IN PROGRESS (Corey: "do 1 [OCI source-url] but do root-satisfies-own-name now as well")
Amoxtli finding: the OCI content-hash fallback (`f889621`) does NOT fix amoxtli —
softlink@main (git, content `2f1a4cfb`, v0.3.3) genuinely differs from the registry's
OCI softlink (`8ffc81bb`, v0.11.0); content-hash is version-specific so it can't tell
"same package newer version" from "different package". Root cause: `OciIndexProvenance`
records no SOURCE repo url. Two features now in flight:
- **Task 1 — OCI source-url (systemic fix for amoxtli):** record the source git url in
  OCI index entries (milpa publish → registry-protocol → tianguis backfill); resolver
  validates git-vs-OCI by SAME-REPO URL match (content-hash only as last resort). Then
  softlink@main url-matches the registry's softlink source → same package → version-solve,
  no conflict. Data layer: a05a58e5 (registry.py/publishing.py/registry-protocol.md).
  Resolver layer: AFTER root-satisfies-own-name frees resolver.py. tianguis backfill of
  softlink's source url + amoxtli re-resolve are the final (cross-repo) steps.
- **Task 2 — root-satisfies-own-name:** af03e9ce (resolver.py/resolver-semantics.md) —
  standalone root satisfies transitive requires on its own name (mirrors workspace member
  self-satisfy); retires softlink's `overrides { pkg "softlink" local="." }`.
Sequence: [A root-self-satisfy Py] + [B OCI-data Py] parallel → [Task1 resolver-validate Py]
→ Rust mirrors of both → tianguis softlink source-url backfill → amoxtli re-resolve + commit lock.

## Follow-up (now being done): root-satisfies-own-name
- softlink's own milpa.kdl needs `overrides { pkg "softlink" local="." }` because a transitive
  (proptest) `requires "softlink"` fetches a SECOND softlink instead of binding the root tree
  under build. milpa has member-satisfies-own-name (workspace, #25) but NOT root-satisfies-
  own-name (standalone) — a workspace-symmetry gap. With the rule the override is unnecessary.
  Subtlety: root's declared version must satisfy the transitive's constraint on its own name,
  else inconsistent-build ERROR (not fetch-a-second-copy). FILE as a GH issue (Corey-gated).
