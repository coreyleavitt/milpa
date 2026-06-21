# Workspace completion RFC — handoff

- **Stage:** 4 code-review — **ROUND 2: D-1/D-2 committed; containment unification IN FLIGHT**
  under mandate "fix through Medium, leave Lows" (Corey: "follow /rfc-flow as always").
- **FORK RESOLVED:** Corey approved **Option A** — canonicalize-based containment (follow symlinks,
  require member's REAL location under root). Security rationale: following symlinks MITIGATES the
  escape vector; the dangerous symlink case (untrusted fetched content) is the separate, already-
  hardened safe_extract path. Spec updated normatively; Python already did Option A, Rust brought up.
- **R2 FULLY COMMITTED:** `0237166` (D-1 Rust strip_dep_pin SSOT + D-2 Python cli-seed wrapper),
  `8cd9ca6` (containment Option A: R2-1 symlink incl. dangling, R2-2 equal-to-root→IS-WORKSPACE,
  D-3 Python helper dedup, spec rewrite, fixtures 286+288). Gates: Py 2134, Rust green zero divergence,
  fixture-288 differential both-pass, bijection green.
- **ROUND 3 re-review DONE — 0 Critical/High.** Security: containment SOUND, 8 vectors verified, no
  bypass. Correctness: all clean; found case-(c) symlinked-root divergence (Rust lexical cand vs
  canonical root → false PATH-ESCAPE for `pkg/..` under a symlinked root; Python correct → real
  cross-impl divergence, Linux-reproducible). Design: 0 bugs; asked for one deep `best_effort_resolve`
  helper + spec resolve-semantics + in-process project-dir coverage.
- **R3 FOLLOW-UP COMMITTED** (`e40c99d`): `best_effort_resolve` deep helper (canonicalize longest
  existing prefix + lexical remainder ≡ Python resolve(strict=False)); fixes symlinked-root divergence;
  +Linux-reproducible parity tests both impls; +normative spec sentence. Filed #167. Gates: Py 2136,
  Rust green zero divergence, bijection 8/8.
- **ROUND 4 final verify DONE — 0 Critical/High.** Security `a31c83a79ad101b93`: SOUND (cycle
  terminates depth-1, unwrap_or unreachable, all escape vectors → PATH-ESCAPE, starts_with
  component-wise). Correctness `a979765bfcb511fff`: 6 main cases correct; negligible cyclic-symlink
  slug divergence (FILED #168 — both reject, Rust safer, can't be milpa-created); Low: Rust lacks a
  `load_workspace_from_manifest` symlinked-root test. Design `a024ea00a6dbff4f2`: deep-helper goal MET;
  confirmed mid-path dangling Medium (I verified empirically: Python follows mid-path dangling →
  PATH-ESCAPE, Rust → DIR-MISSING); 2 Lows (unwrap_or comment, redundant symlink_metadata syscall).
- **R4 FOLLOW-UP COMMITTED** (`92440d3`): one-line fix — ancestor-walk branch of `best_effort_resolve`
  delegates to `best_effort_resolve(&ancestor)`, closing the GENERAL single-hop dangling case (mid-path
  + final) and unifying the dual-mechanism. +mid-path parity test both impls, +from_manifest Rust
  symlinked-root test, +unwrap_or comment, +spec generalized. Py 2137, Rust 699 zero divergence, bijection 8.
- **ROUND 5 final re-review IN FLIGHT** (Security `a2d974c1c81ef316c`, Correctness `a92748f33467d3e93`,
  Design `aa8a8a633965b3981`) — scoped to `git show 92440d3` (the one-line recursion): stack-DoS from
  deep member paths, new mid-path divergence, design unification. If clean → **FLOOR REACHED** →
  report Lows + STOP. If C/H/M → one more iter.
- **Commits this code-review (Stage 4):** R1 `d4f5024`,`5d536d5`,`c051bd4`,`5004632`,`c6e174b`,`bd9d3e7`,
  `3803418` · R2 `0237166`,`8cd9ca6` · R3 `e40c99d` · R4 `92440d3`. Issues filed: #167, #168.
- **Remaining Lows to report at floor:** F22–F29 (R1 deferred), R2 L1–L3 (fixpoint-param/atomically-
  comment/strip_dep_pin-docstring), R4 Lows (unwrap_or comment [being added], redundant syscall in
  ancestor-walk loop start). Mandate = "fix through Medium, leave Lows."
- **(historical) Resume (Stage 4):** containment-unification agent `a515848642724bbdd` DONE —
  Rust `is_under_root`→canonicalize+inclusive starts_with; Python D-3 helper dedup; spec normative
  rewrite; fixture-286 (equal-to-root→IS-WORKSPACE, differentially gated); fixture-288 symlink-escape
  (skipped 3× — see below); unit tests both impls. **Validate-diagnosis-first caught a residual
  divergence** → follow-up agent `a96cb02e2dc0ca115` IN FLIGHT:
    - ITEM 1: dangling member symlink (target outside root, nonexistent) → Python `resolve()` follows
      it → PATH-ESCAPE; Rust `candidate.exists()`=false → lexical → DIR-MISSING. DIVERGENCE. Fix:
      Rust read_link the dangling final component (lstat via symlink_metadata) to mirror Python;
      +parity tests both impls (dangling-outside→PATH-ESCAPE, dangling-inside→DIR-MISSING).
    - ITEM 2: fixture-288 was skipped in ALL 3 suites (corpus.py KNOWN_LIMITATIONS + 2 in-process
      guards). The differential harness (corpus.py→runner.py is project-dir-aware, black-box subproc)
      SHOULD drive it — agent verifying; if so, remove the corpus.py skip (keep 2 in-process guards).
  - After agent returns: verify+commit the whole containment pass; (b) final re-review round to floor
    (0 C/H/M); (c) then report Lows F22–F29 + R2 Lows L1–L3.
- **ROUND 2 re-review findings (3 agents: Security, Design, Correctness — 0 Critical/High):**
  - R2-1 (Sec+Design, Med): F16 containment DIVERGES — Python `(root/p).resolve()` follows
    symlinks (workspace.py:218/354) → rejects member symlink pointing outside; Rust
    `normalize_lexically` lexical-only (workspace.rs:48-49) → accepts. **= the FORK.**
  - R2-2 (Correctness, Med): `a/..`→root emits different slugs — Rust line 52 `!= norm_root`
    → PATH-ESCAPE; Python `is_relative_to` equal-as-inside → proceeds (→ IS-WORKSPACE/load-root).
    Clear-best: unify (lexically-equal-to-root → not an ESCAPE; route to IS-WORKSPACE/DOT). Lands w/ fork.
  - D-1 (Design, Med): Rust `strip_dep_pin` NOT extracted. **FIXED+COMMITTED** (`0237166`):
    extracted to milpa-core::lockfile, both cmd_update sites call it, +4 tests.
  - D-2 (Design, Med): Python `_compute_workspace_cli_seed` wrapper bypassed by `resolve_workspace`.
    **FIXED+COMMITTED** (`0237166`): routed through the wrapper, one SSOT route.
  - D-3 (Design, Med): Python containment block duplicated verbatim (workspace.py:211-252 & 347-388),
    no shared helper (Rust has `is_under_root`). Lands w/ containment unification.
  - R2 Lows (leave per mandate): L1 `_s4a_run_fixpoint` 19th param vs provider-encapsulation
    (Rust cleaner); L2 `apply_member_manifest_change` docstring says "atomically" (TOCTOU window);
    L3 `strip_dep_pin` docstring silent on tarball/OCI declared-mirror drop.
- **Fix waves (ROUND 1 — all committed, 7 commits `d4f5024`..`3803418`):**
  - A+B (5 commits `d4f5024`..`c6e174b`, Py 2118): F1✅ F2✅ F3✅ F4✅ F6✅ F8✅ F11✅ F12✅ F13✅ F14✅ F15✅ F17✅.
  - C-A (`bd9d3e7`, Py 2127, bijection lints green): F16✅ (new slug `WS-MEMBER-PATH-ESCAPE`,
    both impls + fixture-287), F7✅, F18✅ (fixture-284).
  - C-B (`3803418`, Py 2127, Rust corpus zero divergence): F5✅ (Rust frozen default-seed),
    F9✅ (strategy threading, incl. pre-existing single-pkg half), F10✅ (find_parent_workspace
    canonicalize continue), F19✅ (remove-member CWD-relative, BOTH impls + fixture-285),
    F20✅ (fixture-190→281 rename), F21✅ (TNG unreachable via CLI — investigated, no fixture forced).
  - **ALL 21 mandated findings (F1–F21, through Medium) fixed + committed.** Remaining: Lows F22–F29.
    Pre-allocated fixtures used: 282✅ 283✅ 284✅ 285✅ 287✅ (286 not needed — F21 report-back).
  Prior: all 19 slices complete (S1–S12, both impls, zero corpus divergence) + corpus-integrity
  fix `f5eec92` (72 un-ignored `expected/nim.cfg` oracles).
- **Closed:** #160, #159, #109, #93, #129, #81 (5 `closes #` commits + #109 via fixture).
  Deferred: #165 (`milpa show` member-scoping), #166 (ws+dev-deps fixture).
- **Commits (in order):** S1 `fcebd3b` · S1b `8d53627` · S2 `5ea9563` · S3 `15aaf6b` ·
  S4 `1e935ba` · S5 `8688cab` · S5b `224c4da` · S6 `78da655` · S7 `b8edcf5` · S8 `b6d731a` ·
  S9a `bcce03b` · S9b `6868370` · S10 `b994079` · S11a `713278c` · S11b `d39a0b3` ·
  S11c `a9ab0d1` · S11e `7b85e71` · S11d `f953538` · S12 `d81c3d2` · corpus-fix `f5eec92`

## Review ledger (Stage 4, round 1) — diff `8d53627^..f5eec92`
Severity after adversarial verification. Status: open until fix mandate.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| F1 | **C** | Py `resolve_workspace` omits `_s4a_run_fixpoint`. Deeper root cause: fixpoint scanned only `deps_dir/*/milpa.kdl`, so member-declared cross-pkg enables invisible in BOTH impls. Fixed: ws calls fixpoint (resolver.py:4001) + member manifests injected via `extra_manifests`/`member_manifests`, both impls; fixture-282; 0 oracle churn; gate green | **fixed** | resolver.py:4001 + resolver.rs seed_workspace; fixture-282; verified by control loop |
| F2 | **H** | Rust `format.rs` serializers write KDL strings raw (`format!("name \"{name}\"")`, member/url/ref) — no escaping; Python uses `_kdl_str`. `"`/`\`/ctrl char → malformed KDL from Rust only, re-parses wrong next load | open | VERIFIED: format.rs:23,69,81,192 |
| F3 | **H** | `spec/errors.md` TNG-NO-SATISFYING-VERSION trigger text (line 1125) contradicts resolver-semantics §2.1 enumerate-all — describes forbidden constraint pre-filter; 3rd impl would build wrong behavior | **fixed** | errors.md:1123 reworded to §2.1 enumerate-all semantics (inline) |
| F4 | **H** | SSOT: `_compute_root_active_seed` vs `_compute_workspace_cli_seed` (resolver.py:603–700) near-duplicate validate+seed with divergent error messages | **fixed** | `_compute_cli_active_seed` SSOT in resolver.py; both wrappers delegate; gate green |
| F5 | M | Rust ws frozen-flags check uses `{}` not member default-true closure when no CLI seed (resolver.rs:539–553) — misses member-default mismatch; diverges from `FilterCtx::build` | open | Rust-corr#1 |
| F6 | M | Py frozen alignment check iterates `MemberDep` entries (frozen.py:351) → misleading FROZEN-MANIFEST-DEP-NOT-IN-LOCK; should `continue` on MemberDep | open | Py-corr#4 |
| F7 | M | `load_workspace_with_member_override` uses `AssertionError` (workspace.py:462) — stripped by `-O`, untyped | open | Py-corr#5 |
| F8 | M | TOCTOU: `add-member` duplicate-name guard (cli.py:2722) racy vs inner `apply_workspace_manifest_change` reload; redundant double-load (Rust same, main.rs:1452) | open | Py-corr#6 + Rust-corr#5 |
| F9 | M | Rust `cmd_add`/`cmd_remove` hardcode `"maxver"` (main.rs:1184,1737) ignoring `--strategy` (also pre-existing single-pkg) | open | Rust-corr#2 |
| F10 | M | Rust `find_parent_workspace` early-returns None on a single member `canonicalize()` failure (main.rs:2102–2110) → member command silently runs standalone | open | Rust-corr#3 |
| F11 | M | Two ws-mutation orchestrations diverging atomicity: `apply_workspace_manifest_change` validates member dirs; `_cmd_{add,remove}_from_member_dir` (cli.py) skip that | open | design#5 |
| F12 | M | Pin-stripping dup across `cmd_update` paths (cli.py:2255,2354) — belongs as `lockfile.strip_dep_pin` | open | design#6 |
| F13 | M | `_FilteredMember` inline adapter + `type: ignore` (resolver.py:3749) papers over `_build_member_candidate` taking a bag not (manifest, abs_dir) | open | design#7 |
| F14 | M | Dead code: `_filter_manifest_by_profile`/`_filter_manifest_by_flags_only`/`_dep_matches_profile`/`_predicate_satisfied` + `_run_flag_gate` var (resolver.py:890–975) unreachable post-S2; docstrings ref them | open | VERIFIED: zero callers (design#3 rated H) |
| F15 | M | `Profile.flags` field (profile.py:99) read by nothing; docstring falsely claims resolver populates it | open | VERIFIED: zero readers (design#4 rated H) |
| F16 | M | Member path traversal: `member "../../x"` resolved (workspace.py:217) with no `is_relative_to(root)` containment → read any reachable `milpa.kdl`, poison shared lock | open | VERIFIED: security#1 |
| F17 | M | Py `_cmd_add_from_member_dir` mirror path passes member-local lock to `_cmd_add_mirror` (cli.py:2427) — safe today (no lock write) but latent D5 break | open | Py-corr#2 (latent) |
| F18 | M | Rust WS-MEMBER-DOT misses `"./"` (workspace.rs:75) → different slug than Py WS-MEMBER-DOT | open | DIV-2 |
| F19 | M | Rust `cmd_workspace_remove_member` lacks CWD-relative path arm Py has → WS-REMOVE-MEMBER-NOT-FOUND divergence | open | DIV-3 |
| F20 | M | fixture-190 sequence number reused (man-member-when-gated + s4a-multihop) — corpus uniqueness broken; renumber to 281 | open | VERIFIED: 2 dirs |
| F21 | M | `TNG-NO-SATISFYING-VERSION` has zero fixtures after §2.1 narrowed its trigger; residual (all-provenance-less) path unpinned | open | spec#3-C |
| F22 | L | Rust add-member MAN-NAME-MISSING/DUPLICATE-NAME use `return Err` not exit-1 `Ok(1)` pattern (main.rs:1378,1398) | open | Rust-corr#4 |
| F23 | L | Rust `resolve_workspace_with_cert` duplicates ws-validation/seed from `_inner` (resolver.rs:700–876) | open | Rust-corr#6 |
| F24 | L | Py `cpe.dep` emitted as unquoted KDL ident with misapplied `_kdl_str` (manifest.py:2561) — latent if charset relaxes | open | security#2 |
| F25 | L | Rust `clean` `remove_file(member/nim.cfg)` symlink/portability (main.rs:403) | open | security#3 |
| F26 | L | Rust missing orphan-member stderr warning Py emits (workspace.rs) | open | DIV-4 |
| F27 | L | WS-MEMBER-DUPLICATE-NAME payload asymmetry (Rust lacks `existing_member`) | open | DIV-5 |
| F28 | L | Stale spec cross-refs: resolver-semantics `§470` (now §492); fixture-259 comment `§11.1`→§11.5 | open | spec#2-B/3-D |
| F29 | L | `harness/corpus.py` fixture-117 KNOWN_LIMITATIONS skip stale — assertion infra now handles ws per-member nim.cfg; 2 oracles unverified black-box | open | spec#3-F (pre-existing) |

Verified-correct (dropped/non-findings): error-slug bijection CLEAN (5 new slugs in all 3 places); `.gitignore` oracle fix complete (91 tracked, 0 untracked); enumerate-all/SOLVE-CONFLICT parity; fixture-090 TNG→SOLVE-CONFLICT flip correct; absent-axis predicate parity; ActivationSource/RESOLVE-FLAG-CONFLICT payload parity; apply_workspace_manifest_change atomicity ordering; nimcfg self-src-dir ordering; fixture-172/264 KNOWN_LIMITATIONS skips legitimate (in-process-only verbs).

## Context (why this RFC exists)
#25 (workspace W1–W5) **already shipped** — CLAUDE.md's "Open question: #25 re-scoping"
is stale. The features RFC (#23) deferred a cluster of workspace×features work "until
#25 lands"; now unblocked. Corey chose **full scope (all 3 buckets)**. Thesis: every milpa
capability behaves identically on a standalone package or a workspace member — **eight**
asymmetries broken today (round 2 added the eighth: member-dir add/remove/update).

## Buckets → slices (re-sliced across both rounds)
- **A:** S1 `filter_manifest`/`FilterContext.build` smart constructor (Rust = signature ext;
  routes `resolve_with_cert` + runner.rs:463/714 + cmd_fetch) · S1b `MAN-MEMBER-WHEN-GATED`
  parse reject · S2 #160 two-site arm + frozen-flags `FROZEN-ACTIVE-FLAGS-MISMATCH` + frozen
  fixture · S3 §3.8 union + `RESOLVE-FLAG-CONFLICT` cross-member spec+fixture + non-member
  override fixture · S4 #159 `Profile.partial` + optional axes + negated-absent-axis fixture
- **B:** S5 ws==union (close #109) + `RES-WS-MEMBER-REF-UNKNOWN` dev_deps fix + named-dep→member
  constraint check + named-dep-via-index success fixture · S5b SPIKE (loop-safe: records slug,
  doesn't fail) resolve Phase-A error-path · S6 implement S5b target (BOTH impls change)
- **C:** S7 #93 member self_src_dir + multi-member emit ordering · S8 #129 Rust ws --certificate
  (parsed-JSON not bytes; harness gate) · S9a `format_workspace_manifest` serializer +
  roundtrip-Cmd decision · S9b `apply_workspace_manifest_change` orchestration (atomicity;
  dep S1+S2) · S10 `milpa workspace add-member/remove-member` (D4 grouped) + 3 new slugs +
  failure fixtures · S11a ws-root slug unification · S11b Python `update` parity + orphaned
  `verify` frozen-flags check · S11c Rust `clean` per-member nim.cfg · S11d `milpa show`
  member-scope → FOLLOW-UP ISSUE · **S11e member-dir add/remove/update → detect-and-delegate
  (D5; dep S9b+S11b)** · S12 CLAUDE.md de-stale

## Slices
- [x] **S1** `filter_manifest`/`FilterContext` shared helper (both impls) — `fcebd3b`
- [x] **S1b** `MAN-MEMBER-WHEN-GATED` parse rejection + fixture-190 — `8d53627`
- [x] **S2** flag-only arm → both ws sites + frozen path + frozen-flags mismatch; **closes #160**;
  fixtures 249–252 — `5ea9563`
- [x] **S3** §3.8 union pin (fixture-213, existing); cross-member `RESOLVE-FLAG-CONFLICT` + spec
  §11.6 (new code: `_s4c_check_flag_conflicts` call added to `resolve_workspace` Python; Rust
  already had it); non-member override success; fixtures 253–254 — HEAD
- [x] **S4** #159 `Profile.partial` constructor; `Profile` axes → `str | None`; Rust negated-absent-axis
  fix (`predicate_satisfied` + `predicate_satisfied_profile_only`); conformance runner uses
  `Profile.partial(...)` (not `from_environment`); all 4 `Profile(...)` test call sites →
  `Profile.partial(...)`; spec `resolver-semantics §3.C` normative note; fixtures 255–256; **closes #159** — `1e935ba`
- [x] **S5** ws==union parity (fixture-257, closes #109) + `RES-WS-MEMBER-REF-UNKNOWN` dev_deps
  fix (both impls + fixture-258) + named-dep→member constraint check `RES-WS-MEMBER-VERSION-CONSTRAINT`
  (new slug, both impls + fixture-259 + spec update) + named-dep-via-index success
  (fixture-260); Python 2056 pass; Rust corpus zero divergence — HEAD
- [x] **S5b** Phase-A error-slug divergence spike (loop-safe): Rust unit test +
  Python unit test both confirmed `TNG-NO-SATISFYING-VERSION` pre-S6 baseline — `224c4da`
- [x] **S6** enumerate-all Phase-A normative: Rust `process_named` passes `VersionSet::full()`
  to `resolve_named_all`; Python drops BFS pre-check at resolver.py:1372-1379; spec
  `resolver-semantics §2.1` new normative note; fixture-261 + fixture-090 updated to
  `SOLVE-CONFLICT`; Python 2058 pass; Rust 384 corpus pass, zero divergence — `78da655`
- [x] **S7** #93 per-member self_src_dir in `format_workspace_nimcfgs` (both impls);
  3-member fixture-262; updated fixtures 117, 178, 207, 208, 213, 214; spec §5.9 added;
  Python 2063 pass; Rust corpus zero divergence — **closes #93**
- [x] **S8** #129 Rust workspace `--certificate` (Rust-only code; both-impl fixture):
  `resolve_workspace_with_cert` added to `resolver.rs` + exported via `lib.rs`;
  `cmd_fetch_workspace_with_cert` added to `main.rs`, workspace branch routes through it
  when `cert_path` is Some; fixture-263-check-certificate-ws-success (`check-certificate`
  harness, 2-member workspace, cert includes members as resolved/witness entries);
  spec `cli-contract.md §2.5` new NORMATIVE paragraph; harness gate:
  `python -m harness` → PASS both impls (parsed JSON equal); Python 2064 pass; Rust
  384 corpus pass, zero divergence — **closes #129**
- [x] **S9a** `format_workspace_manifest` canonical serializer (both impls, byte-identical);
  `mutate_workspace_manifest_file` typed mutator (both impls); idempotence property test
  (Hypothesis, 200 examples); `workspace-manifest-roundtrip` Cmd + fixture-264; spec §8
  byte-stability note updated; Feasibility-F4 resolved as option (i) — standalone Cmd;
  Python 2083 pass; Rust 393 corpus pass, zero divergence — `feat(manifest): canonical WorkspaceManifest serializer + roundtrip Cmd (#81)`
- [x] **S9b** `apply_workspace_manifest_change` orchestration (validate→resolve-in-memory→write-manifest→write-lock);
  `load_workspace_from_manifest` helper (both impls); Design-F4 signature symmetry (no `validate`
  callable; same shape as single-package add/remove); refusal-lift scope (workspace-typed path
  allowed; package-typed path still refuses with MAN-MUTATE-WORKSPACE-REFUSED); 8 Python tests
  + 5 Rust tests covering atomicity (resolution failure → manifest/lock untouched), happy path,
  refusal-lift scoping; Python 2091 pass; Rust 398 unit pass + corpus zero divergence — `6868370`
- [x] **S10** `milpa workspace add-member <path>` / `milpa workspace remove-member <name|path>`
  (D4 grouped under `workspace` subcommand, both impls); 3 new error slugs
  (`WS-REMOVE-MEMBER-NOT-FOUND`, `WS-REMOVE-MEMBER-TARGET-EXISTS`, `WS-REMOVE-MEMBER-REFERENCED`)
  with full bijection sync (spec/errors.md + errors.py + Rust all_codes()); spec §5.10
  (cli-contract.md); 8 conformance fixtures (fixture-265 through fixture-272: 2 happy paths +
  6 failure paths); harness `_dispatch_cmd` workspace dispatch; fixture-172/fixture-264
  KNOWN_LIMITATIONS entries (lock-roundtrip/workspace-manifest-roundtrip have no CLI surface);
  11 Python unit tests + Rust CLI functions; Python 2102 pass; Rust 398+ unit pass + corpus
  zero divergence; black-box harness PASS on both impls (fixtures 265–272 all green) —
  `feat(cli): milpa workspace add-member/remove-member verbs (closes #81)`
- [x] **S11a** ws-root `add`/`remove` → canonical `MAN-MUTATE-WORKSPACE-REFUSED` slug (both impls);
  spec §5.6 + §5.7 normative notes; fixtures 273–274 (error, CliOnly, harness PASS both impls);
  Python 2102 pass; Rust corpus zero divergence — `713278c`
- [x] **S11b** Python `cmd_update` workspace re-resolve parity + `cmd_verify` frozen-flags check
  (Breadth-P2c); Rust `cmd_verify` workspace frozen-flags check; both in-process runners updated;
  spec §5.4 + §5.8 normative notes; fixtures 275–276 (CliOnly update + verify frozen-flags);
  Python 2103 pass; Rust corpus zero divergence — `d39a0b3`
- [x] **S11c** Rust `clean` per-member nim.cfg in workspace mode (Python already correct);
  `cmd_clean` calls `load_workspace` → removes `<ws.root>/_deps/` + each member nim.cfg;
  `clean` → Cmd::CliOnly in fixture.rs; `_assert_clean_fixture` in harness/assertions.py;
  fixture-277 (two-member workspace, pre-seeded nim.cfg); Python 2103 pass; Rust corpus zero
  divergence; harness PASS both impls — `a9ab0d1`
- [x] **S11e** member-dir `add`/`remove`/`update` → detect-and-delegate (D5; dep S9b+S11b);
  `load_workspace_with_member_override` (Python workspace.py) + `ws_with_member_override` /
  `find_parent_workspace` (Rust main.rs); `_cmd_add_from_member_dir` + `_cmd_remove_from_member_dir`
  (Python cli.py); Rust `cmd_add`/`cmd_remove`/`cmd_update` S11e branches; harness `project-dir`
  control file + `expected/absent` assertion; spec §5.6/§5.7/§5.8 S11e NORMATIVE notes;
  fixtures 278–280 (add/remove/update from member dir, harness PASS both impls, member-local
  lock absent); Python 2103 pass; Rust corpus zero divergence — `feat(cli): add/remove/update from a member dir detect-and-delegate to the workspace (the eighth asymmetry)`
- [x] **S11d** `milpa show` workspace behavior documented in `spec/cli-contract.md` §5.3:
  flat shared-graph dump at ws root; `LOCK-FILE-NOT-FOUND` from a lockless member dir.
  Actual code matches RFC description exactly (no discrepancy). Member-scoped output
  deferred to #165. Python 2103 pass; Rust corpus zero divergence — `f953538`
- [x] **S12** CLAUDE.md workspace-completion RFC section rewritten as COMPLETE (all 19 slices,
  both impls; #160/#159/#109/#93/#129/#81 closed; S11e eighth asymmetry closed; show
  member-scoping → #165); "Where to start" repointed to Tier 3 (#32-34) + F4+ (#43-46);
  `docs/comparison-vs-nimble-atlas.md` caveat updated (Tier 1+2 shipped). Python 2103 pass;
  Rust corpus zero divergence — `d81c3d2`
- **Progress: 19/19 done — ALL SLICES COMPLETE.**

**ALL SLICES COMPLETE — ready for Stage 4 /code-review**

## Forks — ALL RESOLVED (no open decisions)
- **D1** Phase-A → `SOLVE-CONFLICT` canonical, BOTH impls change (Rust enumerate-all + Python
  drops `:1187` pre-check).
- **D2** absent-axis predicate ⇒ `false` for positive AND negated (Rust negation changes).
- **D3** `when`-gated `member` ⇒ parse error `MAN-MEMBER-WHEN-GATED`.
- **D4** (round 2) member-management verbs → **grouped** `milpa workspace add-member/remove-member`.
- **D5** (round 2) member-dir `add`/`remove`/`update` → **detect-and-delegate** (full parity).
- Round-1 resolved: F-b typed fns · F-c full re-resolve · F-d show follow-up (S11d).

## Key decisions (round 2)
- `FilterContext.build(manifest, profile, *, cli_seed)` smart constructor — closes the
  per-member-flags footgun (must close against the *member's* flags, not the root's).
- Flag predicates owned solely by the flag gate (profile gate skips them) — no double-eval.
- Atomicity claim corrected: validate→resolve→write closes the *network*-failure window;
  a fs-write-failure window between the two writes remains (same as single-package).
- Certificate + manifest: parsed-JSON / byte-stable-serializer semantics; CliOnly fixtures
  gated by the black-box harness, NOT `./dev-rust test --workspace` (which skips them).
- Slug rename `WS-REMOVE-MEMBER-HAS-OVERRIDES`→`WS-REMOVE-MEMBER-TARGET-EXISTS`; added
  `WS-REMOVE-MEMBER-REFERENCED` (symmetric dangling member-edge); add-member no-name reuses
  `MAN-NAME-MISSING`. S3 slug `FLAG-CONFLICT`→`RESOLVE-FLAG-CONFLICT`.
- Split S9→S9a (serializer) + S9b (orchestration, dep S1+S2). Added S11e (eighth asymmetry).

## Follow-up issues (filed)
- #165 `milpa show` member-scoping (S11d).
- #166 workspace + dev-deps resolve fixture (Breadth-P3b).

## Review ledger (stage 4)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| -  | -   | (none yet) | - | - |
