# content-addressed-identity (Tier 3, Phase B–C) — handoff

- **Stage:** 4 (/code-review) ✅ COMPLETE — floor reached (0 Critical/High/Medium open; only deferred Lows #143/R2-3). RFC B–D ready to ship.   •   **Round:** 3 (2 review rounds + 1 verification)
- **Resume:** commit + push when Corey approves (STILL NOT committed — commit/push only when asked). SECOND PASS NOW IN PROGRESS — see `docs/rfc-pluggable-fetchers.handoff.md` (Stage 2, architect round 1 running 2026-06-15). This RFC's work remains uncommitted in the working tree.
- **Stage-4 outcome:** 13 round-1 findings (1C/5H/5M/2 security-adjacent) + 2 round-2 findings (1H R1-6, 1M R2-1) all FIXED; 2 refuted; 2 deferred-Low (#143 .gitattributes spec-escalation, build_store 12× wontfix). Final suite: Python 1651 pass / 1 baseline-fail (fixture-144) / 13 skip; Rust core 329 + cli 39 + conf-lib 13, corpus 160 pass (only 099+144 baseline); cross-impl divergences NONE. New fixtures 178 (ws-dedup), 179 (tarball-divergence), 180 (nimcfg src-dir-no-deps).
- **FINAL VERIFIED STATE (2026-06-15):** Python 1632 passed / 1 pre-existing fail (fixture-144) / 13 skip. Rust milpa-core 316 + cli 39 + conformance-lib 13 pass; conformance corpus fails ONLY on fixture-099 + fixture-144 (documented pre-existing baseline, see KNOWN-FAILING BASELINE below). **Cross-impl divergences: NONE** across all 18 slices.
- **Carried-forward small items (not blockers, for Stage 4 / follow-up):** (1) B-resolver named-vs-URL index-vs-tree disagreement *stderr warning* deferred (derive-from-tree-wins IS implemented); (2) dedicated mixed-declared+observed provenance fixture (behavior covered by 174/176); (3) GH #141 store-gc implementation; (4) GH #142 frozen manifest-coverage alias-awareness.
- **Next:** Stage 4 — `/code-review docs/rfc-content-addressed-identity.md` (all 18 slices landed; the
  per-slice ledger below is the full record). Compact/clear before starting.
- Round 2: 49 raw findings (4 lenses) → ~30 deduped, ALL applied to RFC; **zero genuine forks** (all goal-determined under the bar). Safe to `/compact` before Stage 3.

## Context
Driving **Tier 3** through `/rfc-flow`. Decision: sequence **content-addressed-identity Phase B–D first**, then **pluggable-fetchers F1–F3** as a second pass (one RFC at a time through the full flow).

Phase A already landed (#29–31). RFC `docs/rfc-content-addressed-identity.md` is phased but not yet sliced. This pass covers **Phase B (dedup) + Phase C (global store) + Phase D (multi-provenance, v1)**.

## Slices (REVISED by round-2 review — re-sliced; this is the /tdd plan)
Codebase is ahead of the RFC: **multihash = DONE; provenance{} schema parses N;
global store + symlink view = DONE**. Remaining work = resolver logic + spec
amendments + GC/observability. Round-2 split B-dedup into 3 and added a gating
exec-removal precursor. **Sequencing matters — see ordering at bottom.**

Phase A (corrective precursor — GATES everything):
- [x] A-exec-removal: DONE. Exec bit removed from identity (spec §1.2 `0x01` row dropped;
      §1.7 replaced with git transport-normalization NORMATIVE clause; both impls regular-file
      always `0x00`, symlink `0x80` kept). 2 tests rewritten to assert-opposite + new
      `test_no_execute_bit_affects_hash`. New oracle hash (both impls identical):
      `sha256:85f2eb93585a6870b118351b14b8e32a4f55d61809f1612aaca5bae3c3db61cd`.
      Conformance audit: zero exec files in corpus, no fixture changes needed.
      Gate green: Python 1486 pass; Rust identity 22/22 + conformance 151 pass.
      (Pre-existing-on-main failures fixture-144/099 confirmed unrelated via stash-verify.)

Phase B — dedup (3 slices, ordered B-schema → B-resolver → B-nimcfg):
- [x] B-schema: DONE. `aliases` dep-block field both impls (positional args, lex-sorted,
      omit-empty; emitted after requires/cond-require, before active_flags) + spec §3.8 +
      §2.4 order + new `conformance/spec-v1/fixture-172-lock-aliases-field` (uses new
      `lock-roundtrip` conformance verb added to both runners). SSOT: Python
      `_parse_identity_for_lockfile` DELETED → delegates to `parse_identity`, re-raises
      LOCK-DEP-IDENTITY-INVALID (proven by TestLockDepIdentityInvalidSSOT, 4 cases).
      Green: Python 1500 pass; Rust unit+integration+conformance 152 pass.
- [ ] B-resolver: post-fetch collapse same-identity → one node + aliases. Canonical by
      **BFS order** (workspace: workspace-manifest wins, then lex member order); `requires`
      re-derived from FETCHED TREE for both candidates then asserted equal; named-vs-URL
      (fetched tree wins, index disagreement = warning); override (match→2nd provenance,
      differ→replace node, NO "two nodes one name").
      **MAP FINDING (must survive compaction):** Rust ALREADY has a dedup pass
      `RefProvider::finalize()` (resolver.rs ~1475-1526) — but it's PRE-SPEC: canonical by
      `group.sort()` LEXICOGRAPHIC (must change to BFS-insertion order), NO requires-equality
      assertion, does NOT populate the new `aliases` field onto output deps (predates B-schema),
      and rm's `_deps/<other>` inline (B-nimcfg will own the atomic view rebuild). Python has
      NO dedup pass — insertion point is resolver.py after Step-6 BFS loop (~line 1045, before
      Step 7 / _build_graph). BFS-insertion order IS deterministic (declaration order +
      first-occurrence enqueue; NOT fetch-completion `as_completed` order). Why BFS over lex:
      user's root-declared name must win over an alphabetically-earlier transitive alias.
      ResolvedDep (lockfile.py ~257) has NO aliases field yet — add it (LockedDep already has it).
  → DONE. Python `discovery_order` list + `_dedup_candidates` (min by discovery index); Rust
    `finalize()` upgraded lex→BFS via `discovery_order: RefCell<Vec<String>>`. `ResolvedDep.aliases`
    added BOTH impls, populated in build_graph, emitted via LockedDep.aliases. requires-equality
    guard tree-derived. New `conformance/spec-v1/fixture-173-dedup-same-content-aliases`.
    Green: Python 1509 pass; Rust core 268 pass + conformance 153 pass. Bugfix: Python dedup
    `_deps/<alias>` cleanup uses lstat+unlink for symlinks (rmtree refuses symlinks).
    **REMAINING (small, tracked here not dropped):** named-vs-URL index-vs-tree disagreement
    WARNING deferred (derive-from-tree-wins IS implemented; only the stderr warning is pending).
    Pick up with D-provenance or as a quick follow-up.
- [x] B-nimcfg: DONE. `--path:` per alias (canonical first, aliases lex-order) + `_deps/<alias>`
      relative CAS symlinks, BOTH impls byte-identical. Single SSOT `rebuild_deps_view(graph,
      deps_dir, store)` — Python in resolver.py (called from resolve/resolve_workspace/frozen);
      Rust in frozen.rs+lib.rs (called from resolve_frozen/resolve_workspace_frozen + conformance
      runner). B-resolver inline `_deps/<other>` removal stopgap REMOVED both impls (rebuild is
      SSOT). fixture-173 expected/nim.cfg + _deps_structure.txt updated. Green: Python 1522 pass;
      Rust core 272 + conformance 153 pass.
      **VERIFY-RESOLVED (was a real gap, now fixed):** live Rust resolve()/resolve_workspace()/
      resolve_with_cert did NOT call rebuild_deps_view (only frozen paths + conformance runner did).
      Fixed root-cause: `store: &CaStore` threaded into all 3 live fns; each calls rebuild_deps_view
      internally (symmetric w/ Python). Store passed through resolve_default_strategy + Resolver trait
      + 7 CLI call sites; 3 redundant external runner rebuild calls REMOVED. New test
      `live_resolve_builds_alias_symlinks_and_removes_stale_deps` (milpa-cli). Rust green: core 272,
      cli 18, conformance 153.

### ✅ Phase A + Phase B COMPLETE (4 slices: A-exec-removal, B-schema, B-resolver, B-nimcfg).
### NEXT: Phase C — start with C-atomic (mandatory ordering #2: first among C; protects fresco fixture).

**KNOWN-FAILING BASELINE (not a regression — do NOT re-investigate):** Rust's `conformance_corpus`
integration test (crates/milpa-conformance/tests/corpus.rs) aggregates ALL fixtures and reports
`test result: FAILED` whenever ANY diverges. It currently fails ONLY on the two PRE-EXISTING
fixtures: fixture-099 (`RES-PROVENANCE-CONFLICT` → got `FETCH-ALL-FAILED`) and fixture-144
(`TNG-DEPDECL-FETCH-FAILED` → got `RES-UNATTESTED-METADATA`). These predate this RFC (verified on
clean main). Python SKIPs them as known-failing; the Rust harness counts them as FAIL — so any
background-validation run will show `OVERALL: FAIL` + `rust FAIL=1` with `Cross-impl divergences:
NONE`. That exact signature = green-for-our-purposes. A NEW failure = a fixture OTHER than 099/144,
or a cross-impl divergence. (fixtures 099/144 are out of scope for this RFC.)

Phase C — finish store surface (atomic FIRST; stage BEFORE D-fallback):
- [x] C-atomic: DONE. `write_lockfile` temp-in-parent-dir + os.replace/std::fs::rename, BOTH
      impls; EXDEV structurally impossible (temp always in target parent), documented in comment.
      Tests: no-leftover-temp + failure-cleanup (EISDIR) both impls. Lockfile CONTENT byte-identical
      (format_lockfile unchanged). Bonus SSOT: 7 Python CLI `_atomic_write` sites unified onto
      write_lockfile. Green: Python 1529 pass; Rust core 276 + conformance 153.
- [x] C-clean: DONE. Both impls already never-touch-CAS-correct (rmtree/remove_dir_all unlink
      symlinks, don't descend into targets) — deliverable is GUARD TESTS locking it:
      `(test_)clean_unlinks_symlink_never_deletes_cas_target` both impls. clean removes
      _deps/+nim.cfg, keeps milpa.lock, CAS untouched, idempotent. Green: Python 1534; Rust cli 22 +
      conformance 153.
- [x] C-store-ro: DONE. `store ls` (lex-sorted identities) + `store path <id-or-≥16-prefix>`
      (full/prefix/ambiguous/too-short→STORE-AMBIGUOUS-PREFIX, absent→CAS-NOT-IN-STORE) BOTH impls.
      New `STORE-AMBIGUOUS-PREFIX` in spec/errors.md + py errors.py + rust error.rs all_codes();
      bijection lint green both. SSOT CAStore.list_identities()+resolve_prefix(). Green: Python 1543;
      Rust cli 33 + conformance 153. **Conformance fixture DEFERRED:** `store` verb → Cmd::CliOnly
      (both runners skip); driving CLI verbs cross-impl needs a harness Cmd-enum extension (general
      harness enhancement, not slice-specific; 20 per-impl CLI tests cover behavior). Tracked here.
- [x] C-stage: DONE. `CAStore.scratch()` sole owner of `<cas-root>/_scratch/<unique>/` both impls
      (Python already had it as ctx-mgr; unified cas_admitting onto it + dropped shutil. Rust gained
      `ScratchDir` + `scratch()`; CasAdmittingFetcher dropped staging_root field/param; callers updated
      fake_fetcher.rs/main.rs). Cleanup-on-success (no leak), same-fs atomic admit. `_stage` grep clean.
      spec/identity.md §3.3/§3.4 NOTEs refreshed. Green: Python 1545; Rust core 281 + conformance 153.
      (Unblocks D-fallback.)
- [x] C-admit-idem: DONE. `admit()` idempotent both impls — explicit `canonical.is_dir()` pre-check
      (O(1) CAS hit) + OSError/ENOTEMPTY TOCTOU guard folding rename-race into the hit path (no raise);
      store never overwritten; scratch cleaned on hit (no leak). NORMATIVE clause spec/identity.md §3.3
      (step 3 + normative-surface item 8). Green: Python 1551; Rust core 287 + conformance 153.
- [x] C-verify: DONE. 4-state verify (pass / dangling is_symlink&&!exists / CAS-STORE-IO-ERROR on
      store-read I/O / genuinely-missing) via `_classify_dep_path`/`classify_dep_path` helper BOTH
      impls (lstat vs exists; Rust symlink_metadata vs metadata); identity-mismatch preserved. §6.4
      alias verify: each alias symlink must exist + resolve to canonical's store entry else
      VERIFY-ALIAS-SYMLINK-MISSING; aliases excluded from extra-entry scan. 2 new codes
      (CAS-STORE-IO-ERROR, VERIFY-ALIAS-SYMLINK-MISSING) in errors.md + both impls, bijection green.
      spec/lockfile-schema.md §6.2/§6.4 updated. State-(c) tested with REAL chmod-000 file (NO mock —
      honors CLAUDE.md no-mocking rule; skip-if-root via geteuid Python / stdlib perms-probe Rust).
      Found+fixed: Rust had no state-(c) test. Green: Python 1562; Rust core 10 c_verify tests +
      conformance 153.
- [x] C-gc: DONE (design-note slice). `docs/rfc-store-gc.md` mini-RFC settles all 3 points:
      (1) liveness = central `<cas-root>/projects.kdl` registry (self-registered on fetch/lock) →
      union of registered lockfiles' identities + `_deps/` symlink-walk belt-and-suspenders (catches
      admit→lock-write crash window); (2) sentinel BEFORE admit(): `place sentinel(uuid)→admit()→
      link()→clear`, sentinels at `<cas-root>/_sentinels/<uuid>` (identity+pid+ts), STORE-GC-ENTRY-IN-USE
      on guarded/live eviction; (3) `_scratch` + sentinel staleness mtime-gated age T=1h (--gc-stale-age).
      spec/identity.md §3.4 NOTE → references the mini-RFC. **GH issue #141** filed for deferred impl
      (incl. adding STORE-GC-ENTRY-IN-USE then). Bijection intact (code held back). No code/tests changed.

Phase D — multi-provenance semantics:
- [x] D-add: DONE. `add <dep> --mirror <url>` milpa.kdl-ONLY both impls (validate dep declared +
      URL-dep; reject local/member/tarball/named with new MAN-MIRROR-EDITABLE-PROVENANCE; idempotent;
      atomic via mutate_manifest_file; NO fetch/verify/lockfile). Dead MAN-ADD-MIRROR-IDENTITY-MISMATCH
      REMOVED (errors.md + both impls + conformance-fixtures.md note). §5.6 rewritten (manifest-only +
      declared→lockfile lifecycle NOTE). Bijection clean both. `add` is CliOnly (no resolver path) —
      per-impl CLI tests (5 each). Green: Python 1587; Rust core 33 + manifest 13 + conformance 153.
      Cross-impl divergences NONE.
- [x] D-lifecycle: DONE. `ResolvedDep` singular `provenance`→plural `provenances` tuple/Vec BOTH
      impls (SSOT; all readers updated: frozen/nimcfg/lockfile/show). resolve assembles candidate list
      `[primary, *manifest_mirrors, *prior_declared]` ordered-dedup; the candidate that fetched+verified
      = observed, rest = declared (no commit_sha, ref from manifest); dedup declared vs observed.
      Promotion = natural via recompute (mirror-wins→mirror observed, primary declared). Idempotent
      (prior declared carried forward). 12 tests (test_d_lifecycle.py DL-1..5+RT) + new
      `conformance/spec-v1/fixture-174-mirror-declared-provenance`. spec/lockfile-schema.md §4.0a added.
      Green: Python 1600; Rust conformance 154. Cross-impl divergences NONE.
      **NOTE for D-frozen:** plural-provenances model (was parked under D-frozen) landed HERE — D-frozen
      now only needs frozen.py/frozen.rs to PRESERVE all provenances (not [0]) + recreate alias symlinks.
- [x] D-fallback: DONE. Fallback loop RAISES FETCH-PROVENANCE-DIVERGENCE immediately on
      success-but-wrong-hash (NO try-next) — transport-fail still falls through; all-transport-fail→
      FETCH-ALL-FAILED preserved. Both impls per-provenance env.fetcher.fetch() (Rust already
      fetch_any_tracked, not fetch_any — just changed continue→Err). New FETCH-PROVENANCE-DIVERGENCE
      in errors.md + both impls, bijection clean. SSOT: old uncataloged `FETCH-IDENTITY-MISMATCH` raw
      literal (was only in resolver.py:1279, not in errors.md/errors.py) REPLACED. New fixtures 175
      (transport fallback) + 176 (divergence). Green: Python 1612; Rust core 305 + cli 33 + conformance
      156 pass. Cross-impl NONE. **RFC Acceptance criterion 3 ✓.**
- [x] D-provenance: DONE. `origin` field added to ALL 6 ProvenanceRecord variants (both impls);
      `self_mirrors` removed from LockedDep+ResolvedDep (both impls); read-compat parse converts
      legacy `self_mirrors` nodes → declared GitProvenanceRecords; emitter NEVER writes `self_mirrors`;
      provenance sort key `(origin_rank, kind_rank, primary, secondary)` SSOT both impls; `origin` always
      emitted FIRST; conformance fixtures all updated (55 milpa.lock files: `origin "observed"` added);
      new conformance fixture TBD (mixed declared+observed); `_prior_self_mirrors` renamed to
      `_prior_declared_mirror_urls` both impls; spec lockfile-schema.md §4 + §3.7 updated.
      Green: Python 1582 pass, 1 skip-known-fail (fixture-144); Rust core 297 pass + conformance 153 pass,
      2 pre-existing fails (fixture-099, fixture-144). ZERO cross-impl divergences.
- [x] D-frozen: DONE. Fixed REAL BUG: Python `_reconstruct_from_locked` dropped aliases (Rust was
      already correct) → frozen dedup diverged (Python lost alias symlinks + --path:). Now both impls'
      single-package AND workspace frozen paths carry `provenances` (full) + `aliases` (+dep_decl);
      alias symlinks materialize via rebuild_deps_view. New `conformance/spec-v1/fixture-177-frozen-dedup-aliases`
      (cross-impl guard). Green: Python 1622; Rust conformance 157. Cross-impl NONE.
      **FILED #142** (out-of-scope adjacent bug): frozen FROZEN-MANIFEST-DEP-NOT-IN-LOCK check matches
      lockfile dep NAMES only, not aliases → manifest declaring both names of a deduped pair fails frozen.
- [x] D-update-remove: DONE. `update <dep>` strips identity pin (re-resolves) but RETAINS declared
      provenances; `prior_declared_urls` filtered ∩ manifest-mirror-set (removed mirrors drop) both impls.
      SSOT alias→canonical helper (Python `resolve_alias_to_canonical`, Rust `canonical_name_for`) used by
      update+remove (no spurious LOCK-DEP-NOT-FOUND). remove-canonical warns per prior alias (still-live vs
      cleanup), removal proceeds. §5.7/§5.8 updated. update/remove CliOnly → per-impl tests (DR-1..6 both).
      Green: Python 1628; Rust cli 39 + conformance 157. Cross-impl NONE.
- [x] D-verify-note + ID-NON-UTF8-RELPATH (FINAL slice): DONE. verify confirmed identity-ONLY both impls
      (never inspects provenance/url/origin/commit) + NORMATIVE clause spec/lockfile-schema.md §6.2 + guard
      tests (multi-provenance/declared-origin bytes-match passes; tamper fails on identity). New
      ID-NON-UTF8-RELPATH (distinct from ID-NON-UTF8-SYMLINK-TARGET) in errors.md + both impls, bijection
      clean; identity.py/identity.rs raise coded error on non-UTF-8 relpath instead of crash/silent-hash.
      **Found+fixed divergence:** Rust was silently hashing non-UTF-8 path bytes while Python crashed — now
      both raise ID-NON-UTF8-RELPATH. Non-portable fixture → per-impl tests. Green: Python 1632; Rust core
      316 + cli 39 + conformance 157. Cross-impl NONE.

Cross-cutting (land with the relevant slice):
- [ ] Spec amendments: lockfile-schema (N provenances + **defined sort key**
      `(origin,kind,primary,secondary)` + origin field + aliases + §6.4 + remove self_mirrors),
      identity (exec-bit out, git-normalization, symlink no-norm, `_scratch`, admit idempotency,
      GC note ref), cli-contract (`milpa store`, `add --mirror`, update/remove, `show -v`),
      resolver-semantics (frozen preserves provenances+aliases), errors.md (8 new codes).
- [ ] Conformance fixtures per acceptance criterion (incl. CRLF-hash, two-`--path:`, alias
      round-trip). C-series MUST set MILPA_CACHE_DIR to tmp.
- [ ] Observability: `milpa show` lists all provenances + aliases; default 12 chars + `-v` full.
- [ ] ID-NON-UTF8-RELPATH (distinct from existing ID-NON-UTF8-SYMLINK-TARGET).

### Mandatory ordering (round-2 feasibility)
1. A-exec-removal → everything (identity must be byte-stable before any hash pinned)
2. C-atomic → first among C (protects fresco fixture)
3. C-stage → before D-fallback
4. B-schema → B-resolver → B-nimcfg
5. D-provenance origin-field shape (field-on-block) must be in spec before D-* impl
6. C-gc: own design note; blocks nothing

## Resolved decisions (round 1 — goal-determined under the bar, NOT opinion forks)
Corey corrected an over-polling: none of these were real forks. Resolved + defended in RFC
"Round-1 review: resolved decisions". All reverse a shipped/written decision.
1. **Exec bit EXCLUDED from identity** — not transport-independent (Windows core.filemode);
   not "what Nim code is this". Hash = (relpath, content) only. Reverses shipped Phase A
   spec/identity.md §1.7 + 0x01 mode marker → amend out + recompute.
2. **Link = relative symlink** — hardlink can't cross filesystems / dir-hardlink not POSIX.
   Already shipped. Ratified.
3. **self_mirrors (#79) UNIFIED into provenance** — SSOT. One list, origin discriminator
   observed|declared. Reverses #79 separate field.
4. **Schema evolves v1 in place, NO v2** — additive, zero external consumers
   ([[spec_versioning_deferred]]); no format break so conformance-fixtures §1.3 not triggered.

## Key decisions (this session)
- Tier 3 order: content-addressing B–D → pluggable fetchers F1–F3.
- Phase D INCLUDED in this pass.
- Round-1 review reframed all slices to actual code state (B1/D1/store shipped).

## Round-1 architect ledger (29 findings, 4 lenses)
| id | sev | finding | status |
|----|-----|---------|--------|
| 1 | C | Schema version hard-rejects ≠1; v2 spread across slices = flag-day landmine | resolved → in-place v1 (fork 4) |
| 2 | C | B1 multihash + D1 provenance{} schema already shipped; slices stale | applied (reconciliation note) |
| 3 | C | Store path wrong: RFC `store/sha256/ab/cd/` vs actual `cas/sha256/<hex>/` flat | applied |
| 4 | C | exec-bit not transport-independent cross-platform (Windows core.filemode) | resolved → EXCLUDE from identity (dec 1) |
| 5 | C | non-UTF-8 filename → uncoded UnicodeEncodeError crash | applied (ID-NON-UTF8-RELPATH) |
| 6 | C | SSOT: `_parse_identity_for_lockfile` dupes `parse_identity` | applied (B slice) |
| 7 | H | B2+B3 not independently testable → merge | applied |
| 8 | H | canonical name must be BFS order not fetch-completion (parallel nondeterminism) | applied |
| 9 | H | dedup must assert requires match before merge | applied |
| 10 | H | aliases invisible; nim.cfg must emit `--path:` per alias + `_deps/<alias>` symlink | applied |
| 11 | H | `milpa store gc` underspecified: liveness + GC/link race + locking | applied (separate slice, design-note) |
| 12 | H | write_lockfile non-atomic | applied (C-atomic) |
| 13 | H | D3 must split transport-fail vs hash-divergence (supply-chain signal) | applied (FETCH-PROVENANCE-DIVERGENCE) |
| 14 | H | offline-verify invariant broken by symlink view | applied (acceptance crit 5) |
| 15 | H | spec clauses reject proposals (v2, "exactly one provenance") | applied (spec-amendments section) |
| 16 | H | no conformance fixture story for B/C/D | applied (fixture plan) |
| 17 | H | error catalog missing B/C/D failure modes | applied (5 new codes) |
| 18 | H | fetch_any leaves CAS admission to caller; D3 winner unadmitted | applied (D-fallback) |
| 19 | M | _stage/ vs _scratch/ divergence | applied (C-stage) |
| 20 | M | D2 conflates manifest mirror vs lockfile provenance | applied (re-scoped D-add) |
| 21 | M | self_mirrors (#79) vs provenance SSOT overlap | resolved → unify into provenance (dec 3) |
| 22 | M | two-impl + corpus tax not in effort estimates | applied (revised estimates) |
| 23 | M | named-dep vs URL-dep dedup collision unspecified | applied (B item 5) |
| 24 | M | override (#50) × dedup interaction unspecified | applied (B item 6) |
| 25 | M | no observability for why-deduped / which-provenance | applied (show section) |
| 26 | M | dangling symlink misreported as missing | applied (C-verify) |
| 27 | M | show truncates hash to 8 chars (32-bit) | applied (→16) |
| 28 | L | cas.admit OSError re-raised uncoded | applied (CAS-ADMIT-IO-ERROR) |
| 29 | L | lockfile field order (version vs identity) diff ergonomics | noted, low-pri (deferred) |

## Round-2 architect ledger (4 lenses → ~30 deduped, ALL applied; 0 forks)
Round 2 hunted post-round-1 drift + new gaps. Notable: round-1's surgical edits left
4 internal contradictions (stale exec-bit/v2 prose); a NEW transport-independence hole
(git autocrlf/filemode) survives exec-bit removal; frozen path drops N-1 provenances.
| theme | sev | finding | resolution (applied to RFC) |
|---|---|---|---|
| consistency | C | "what content covers" prose still includes exec bit + `file_mode_canonical` | rewrote to `(relpath,content)` only |
| consistency | C | "issues this spawns" had exec-bit-refine, schema-v2, multihash-as-future | rewrote list to actual slices |
| consistency | H | "hash agility" §2 + "commits to" said schema bump / "Phase D introduces" | rewrote to in-place v1 / schema-already-parses |
| identity | C | git `core.autocrlf`/`core.filemode` unenforced → host-dependent hash | NORMATIVE `-c core.autocrlf=false -c core.filemode=false` clause |
| identity | C | A-exec-removal blast radius (spec+2 impls+oracle+fixtures) understated | made it a gating precursor slice w/ full enumeration + migration note |
| determinism | C | provenance emission sort key undefined → breaks zero-divergence | defined `(origin,kind,primary,secondary)` total order in RFC |
| determinism | H | alias KDL shape undesigned | `aliases` child node, lex, omit-empty; B-schema slice |
| resolver | C | `requires` equality has no canonical parse path; named-vs-URL unspecified | re-derive from fetched tree both sides; fetched-tree-wins + warn |
| resolver | M | override "distinct node under same name" = unrepresentable graph state | override replaces node; deleted the phrase |
| store | C | GC sentinel placed before link() not admit() → TOCTOU evicts new entry | corrected to before admit(); into GC design note |
| store | H | admit() idempotency + scratch orphan on CAS hit unspecified | NORMATIVE idempotent + caller drops scratch (C-admit-idem) |
| store | H | watched-project-set + `_scratch` staleness T undefined | both into GC design note (carved out) |
| store | M | store-mount I/O vs dangling vs corrupt vs missing conflated | 4-state verify + `CAS-STORE-IO-ERROR` |
| provenance | H | observed/declared per-lockfile vs per-CAS-entry ambiguous | per-lockfile annotation; CAS holds bytes only |
| provenance | H | declared lifecycle (when enters lockfile / promoted) unspecified | D-lifecycle: written declared-unverified, promoted on fetch |
| provenance | H | `self_mirrors` still in spec+both impls (Rust field+tests) | D-provenance: remove + read-compat parse→declared; Rust work noted |
| coverage | C | frozen.py/rs drop N-1 provenances + alias-unaware | D-frozen: carry full tuple + recreate alias symlinks |
| coverage | H | `update` drops accumulated mirrors; update/remove alias-blind | D-update-remove preserves + alias→canonical |
| coverage | H | `add --mirror` arg order inverted + cli-contract §5.6 conflict | fixed prose to `add <dep> --mirror <url>`; amend §5.6 |
| ergonomics | M | `store ls`/`path` blocked behind GC | split into C-store-ro, land now; `STORE-AMBIGUOUS-PREFIX` |
| ergonomics | M | widen 8→16 wrong axis | default 12 + `show -v` full hash |
| feasibility | C | B-dedup hides 3 sub-slices | split B-schema/B-resolver/B-nimcfg + ordering |
| feasibility | H | write_lockfile non-atomic in BOTH impls (RFC implied Python-only) | C-atomic covers both; sequence first |
| errors | M | no code for alias symlink missing | `VERIFY-ALIAS-SYMLINK-MISSING` |
| deferred | L | dep-block field order (identity/provenance adjacency) | NOT reordered — marginal diff gain vs fixture churn; recorded here |

## Review ledger (stage 4)
- **Round 1 (2026-06-15):** 5 lenses → ~30 raw → adversarially verified (5 refutation verifiers). 2 refuted.
- **Fix round 1 (2026-06-15):** all C/H/M + SA-1/SA-2 fixed via 4 parallel sonnet clusters. Consolidated suite GREEN:
  Python 1651 pass / 1 baseline-fail (fixture-144) / 13 skip; Rust core 327 + cli 39 + conf-lib 13, corpus 160 pass
  (only fixture-099+144 baseline regress); NEW fixtures 178/179/180 pass both; cross-impl divergences NONE.
- **Round 2 (2026-06-15):** re-review on changed scope (correctness/divergence, security on new archive parser, design/SSOT) — IN PROGRESS.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R1-1 | C | Python `resolve_workspace` skips Phase B dedup → cross-impl divergence | FIXED | _ws_record_discovery + _dedup_candidates wired into resolve_workspace; fixture-178 (both impls) |
| R1-2 | H | nimcfg trailing-newline divergence (self_src_dir + zero deps) | FIXED | Rust guard → `if lines.len()>2`; fixture-180 (both impls) |
| R1-3 | H | tarball identity-vs-pin slug divergence (D-fallback missed tarball path) | FIXED | Py tarball worker → FETCH-PROVENANCE-DIVERGENCE; fixture-179 (both impls) |
| R1-4 | H | `git_pin` drops identity pin for mirrored deps (both impls) | FIXED | both impls iterate all Git records, match url==primary&&ref; test_d_lifecycle TestMirrorSortsFirstPinStillReused |
| R1-5 | H | git transport-normalization NORMATIVE MUST unenforced | FIXED | `-c core.autocrlf=false -c core.filemode=false` SSOT in _run_git/run_git+run_git_in; CRLF tests both impls |
| R1-6 | H | ~130-line BFS wave-loop duplicated `resolve()`/`resolve_workspace()` (SSOT root cause) | FIXED | `_run_bfs_wave_loop` extracted (−46 net lines), called by both; `_Future2`/`_cast2` gone; R3 verified behavior-preserving |
| R2-1 | M | NEW (from SA-2 fix): PAX `kv_start=space+1` absolute offset → 2nd+ PAX record silently dropped → identity divergence | FIXED | safe_extract.rs `kv_start=(space-pos)+1`; 2 multi-record regression tests; R3 verified |
| R2-2 | L | `.gitattributes` `eol=crlf` overrides `core.autocrlf=false` on checkout (deterministic/host-indep; cross-provenance dedup edge) | deferred | FILED #143 (spec-escalation: §1.7 mandates exactly 2 flags; extending is a spec decision) |
| R2-3 | L | Rust `build_store()` called 12× (construction SSOT achieved; multiple stateless instances) | wontfix(now) | CaStore is path-only/stateless; revisit if it gains state |
| R1-7 | M | Python `resolve_workspace_frozen` missing frozen conditions 2-4 | FIXED | confirmed REAL gap; per-member alignment loop added; test_frozen_d_frozen TestWorkspaceFrozenConditions24 |
| R1-8 | M | `CasAdmittingFetcher.fetch_any` bypasses CAS admission gate | FIXED | option(b): own CAS-admit loop; 2 tests in TestFetchAnyDelegation |
| R1-9 | M | dead `if env.store is not None` guard skips rebuild_deps_view | FIXED | guards removed (resolver.py) |
| R1-10 | M | Python verify catches only OSError, not MilpaError → aborts early | FIXED | broadened handler; test_milpa_error_from_hash_recorded_as_divergence_loop_continues |
| R1-11 | M | Rust CLI builds `CaStore::new(cas_root())` 10× | FIXED | `build_store()` SSOT; build_registry uses it |
| SA-1 | H | decompression bomb: gunzip unbounded before size caps | FIXED | Rust `.take(decomp_cap)`→EXTRACT-SIZE-LIMIT; Py already guarded by tarfile header sizes (documented); no bijection change |
| SA-2 | M | Rust USTAR reader ignores POSIX prefix + GNU/PAX → identity divergence on long paths | FIXED | full prefix/@LongLink/PAX rewrite; 5 tests; safety checks preserved (round-2 security re-auditing) |
| R1-L | L | batch: identity.md §5 table missing 4 codes; CAS-ADMIT-IO-ERROR in RFC table but uncataloged; `_dedup_candidates` disk re-parse + `provider._candidates` reach-through (SSOT smell, NOT a correctness bug — refuted); MILPA_CACHE_DIR unvalidated; `_build_graph` LocalProvenance abs-path latent branch; discovery_order O(N) contains-scan; hardlink→symlink undocumented; frozen `cond_requires=()` by-design; Rust `.first()` Local/Registry asymmetry (unreachable) | open | low-pri polish |
| ~~RX-a~~ | ~~C~~ | Python dedup requires-equality guard spurious MILPA-INTERNAL | REFUTED | same content-hash ⟹ byte-identical manifest ⟹ identical requires; needs SHA collision |
| ~~RX-b~~ | ~~C~~ | Rust frozen Registry `.first()` misses non-first Registry; workspace path never checks | REFUTED | workspace checks via provenance_from_record; Registry+other-kind unreachable (writer never emits Registry) |
