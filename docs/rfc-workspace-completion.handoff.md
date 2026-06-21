# Workspace completion RFC — handoff

- **Stage:** 2 architect — **rounds 1 + 2 DONE** (4-lens team each round, fixes applied;
  D1/D2/D3 round 1, D4/D5 round 2, all confirmed by Corey) → **ready for Stage 3 `/tdd`**
- **Resume:** `/loop implement the next unimplemented RFC slice with /tdd, following the
  standing rules; after each slice report one progress line (e.g. "slice 4/8 done, 4
  remaining"); stop when every slice is implemented`

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
- [ ] S11d, S11e, S12 (remaining)
- **Progress: 16/19 done, 3 remaining.** All gates green each slice (Python 2103 pass; Rust
  corpus zero divergence).

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
