# Content-Addressed Metadata RFC — handoff

- **Stage:** 4 (code review) **🏁 FIX LOOP COMPLETE — FLOOR REACHED** (2026-06-13). Stage 3
  🏁 COMPLETE (S2–S7). 4 fix rounds; final re-review surfaced 0 Critical/High/Medium (only Lows).
  Mandate (Corey "fix as we always do") = fix High+Med, batch Lows. **ALL High+Medium fixed:**
  R1–R6,R8 (round 1) + D2/D5/D1/verify-ws/D4 (round 2) + D-F1/D-F2/D-F3 + runner SSOT (rounds 3–4).
  Filed issues: #128 (catalog ownership), #129 (cert+workspace no-op), #130 (harness cert divergence),
  #131 (workers bypass coordinator) — all pre-existing/orthogonal, deferred. R13 refuted (spec-faithful).
  **PLUS: root-caused + fixed the /tmp inode leak** (~14 mkdtemp sites + harness runner → RunResult.cleanup()
  SSOT + tmp_path; was exhausting tmpfs). Fixtures 145–151 added. Gates: python-ng 1291, frozen 950,
  rust --workspace green + clippy clean (2 pre-existing), harness BOTH modes OVERALL PASS / ZERO divergence.
  ALL UNCOMMITTED (Corey-gated) — natural commit point for the whole DepDecl feature + the temp-dir fix.
  **Resume:** review complete; awaiting Corey's commit decision (and the remaining Lows are below-floor/deferred).

## Review ledger (stage 4, round 1 — 4 lenses + 4 adversarial verifiers, 2026-06-13)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R1 | High | Workspace mode never enforces attestation policy — strict+workspace silent bypass (both impls) | **fixed** | resolve_workspace ORs flag/env+member-strict → enforce_attestation_policy; cli threads flag; spec §13.1 workspace rule; fixture-145; 0 divergence |
| R2 | High | Rust non-strict `TNG-DEPDECL-FETCH-FAILED` hard-fails instead of Nimble fallback | **fixed** | extract_requires catches FETCH-FAILED, falls back when !strict; integrity stays hard; `dep_decl_used` clears pin on fallback; fixture-146 |
| R3 | High | Schema version read via raw text-scan not DOM; Rust `unwrap_or(0)` fails OPEN on overflow | **fixed** | parse_dep_decl returns (EdgeSet, version) both impls; text-scan deleted (SSOT); rust `try_from→i64::MAX`→SCHEMA-UNSUPPORTED; fixture-147; R11 comments fixed here |
| R4 | Med | `milpa verify` ignores manifest `attestation-policy "strict"` (only flag/env) | **fixed** | cmd_verify loads manifest + effective_strict_policy SSOT (3 sites: cli, in-proc adapter, rust); fixture-148 |
| R5 | Med | No format validation on `dep_decl` index pointer → path-traversal read oracle | **fixed** | validate `sha256:[0-9a-f]{64}` at registry parse both impls; new `TNG-BAD-DEP-DECL` (full catalog+bijection); spec §3.2; fixture-149 (`../../etc/passwd`) |
| R6 | Med | `index_base_url` case-sensitivity divergence (rust case-sensitive vs py IGNORECASE) | **fixed** | rust ASCII-lowercases segment; spec/dep-decl.md §3.3 pins case-insensitive; unit tests both impls |
| R7 | Med | `spec/errors.md` generated from FROZEN `impls/python` catalog — structural inversion | **deferred→#128** | filed GH issue #128; genuinely rides #6 swap (per Corey rec) |
| R8 | Med | No size cap on DepDecl artifact fetch → OOM via compromised index | **fixed** | 1 MiB cap both impls (Content-Length early-reject + bounded read + curl --max-filesize); →FETCH-FAILED; spec §3.3.1; unit tests |
| —  | Low | clippy regression from R1/R2 (`too_many_arguments 8/7` on ResolveProvider::new + resolve_workspace) | **fixed** | ResolveProvider::new derives project_root (7 args); `ResolveParams` struct for resolve_workspace; no `#[allow]` |
| R9 | Low | Cache writes: rust non-atomic `fs::write`; py deterministic tmp-name race — self-healing via verify-on-read | deferred | below mandate floor; availability-only |
| R10 | Low | harness `_kdl_str` uppercase `\u{}` hex vs lockfile lowercase — latent (harness producer only) | deferred | below floor |
| R11 | Low | Stale "S4-i unreachable" comments misled 2 verifiers | **fixed** | corrected in R2/R3 (edge_sources.py:428/484 + rust) |
| R12 | Low | Minor: `_nimble2` alias; SCHEMA precedence; spec §6 NOTE wording; §13.1 env-var | deferred | below floor; cosmetic |
| R13 | — | `attestation.py` `milpa_kdl`-under-strict — both impls spec-faithful (§13.3 exempts MilpaKdl) | refuted | verifier quoted §13.3 verbatim; tighten-the-NOTE is a Corey spec-design call only |
| **Round 2 re-review (Correctness/Security/Design over the round-1 fix diff)** | | | | |
| D2 | High | Rust `--certificate` path drops BOTH strict enforcement AND DepDecl wiring (cmd_fetch_with_cert / resolve_with_cert) — `fetch --certificate --require-attested-metadata` silently skips S5 | **fixed** | threaded require_attested_metadata + dep_decl_store through cmd_fetch_with_cert→resolve_with_cert + enforce; python-ng `_execute_check_certificate` twin fixed inline; fixture-150 |
| SEC-vfy-ws | Med | Rust `cmd_verify` workspace mode ignored member `attestation-policy "strict"` (our R4 fix incomplete on rust verify+ws) | **fixed** | cmd_verify loads ws + workspace_any_member_strict; fixture-151 |
| D1 | Med | Rust strict-OR rule re-computed 3× (resolve_workspace ×2, cmd_verify inline env re-read) | **fixed** | effective_strict_policy + workspace_any_member_strict SSOT helpers; cmd_verify takes flag param |
| D4 | Med | `Extracted` 5-tuple (R2) + lossy `dep_decl_used` bool | **fixed** | replaced with struct carrying full EdgeSet; pin derived from edge_set.source |
| D5 | Med | python `_RE_OCI_DIGEST` == `_RE_DEP_DECL_POINTER` byte-identical (R5) | **fixed** | shared `_RE_SHA256_DIGEST`; eliminated 3rd copy in fetchers/oci.py; distinct codes preserved |
| #129/#130/#131 | Med | pre-existing/orthogonal: cert+workspace no-op, harness cert-divergence-blind, workers bypass resolve_edges | **deferred→issues** | filed; not bundled into DepDecl per "never bundle unrelated fixes" |
| **Round 3–4 re-review (over round-2 fix diff)** | | | | |
| D-F1 | Med | `effective_strict_policy` SSOT bypassed — resolve()/resolve_with_cert()/enforce inline the OR 3× | **fixed** | all 3 route through effective_strict_policy; grep-confirmed 0 inline copies in production resolver |
| D-F2 | Med | `resolve_with_cert` parallel-copied ~60 lines of `resolve` setup (the drift that caused D2) | **fixed** | `build_single_provider` + `ProviderOpts` struct; both entrypoints share setup, diverge only at solve |
| D-F3 | Low | `MILPA_REQUIRE_ATTESTED_METADATA` truthy-parse duplicated (main.rs + runner.rs) | **fixed** | `parse_env_bool` helper in milpa-core; both delegate |
| runner-SSOT | Med | conformance `Cmd::Verify` re-derived strict-OR inline (round-4 verifier) | **fixed** | delegates to effective_strict_policy / workspace_any_member_strict |
| temp-leak | — | ~14 `mkdtemp` sites + harness runner leaked /tmp dirs (no cleanup) → tmpfs inode exhaustion | **fixed** | RunResult.cleanup() SSOT + tmp_path/try-finally across test_identity*, differential, harness callers; 0-leak verified |
| Remaining Lows (deferred, below floor) | Low | malformed DepDecl constraint→VersionSet::full (not exploitable, hash-mismatch); `--frozen`+`--certificate` silent skip; cert SUCCESS+strict coverage gap; R9 cache-write race (self-healing); R10 harness `_kdl_str` uppercase hex; R12 cosmetics | open | below mandate floor; candidates for a future cleanup pass |
| — | — | Verified correct: full-sha256 equality (no truncation), verify-precedes-use (no TOCTOU), integrity failures (HASH/PARSE/SCHEMA) always hard in both impls, producer/consumer asymmetry (no consumer-side serializer) | pass | security + design lenses |
- **Stage-4 prep / open items to revisit in review:** (a) the milpa_kdl-under-strict
  predicate in `attestation.py` (S5 — subagent decided without escalating); (b) confirm the
  errors.md-generated-from-frozen-impl ownership is acceptable until the #6 swap (recorded
  earlier); (c) F6 `milpa show --verbose` edge-source introspection → still a candidate
  follow-up issue; (d) S8 tianguis companion issue (ingest `.nimble`→EdgeSet + publish) —
  file it sibling-side.
- **Resume:** `/loop implement the next unimplemented RFC slice in
  docs/rfc-content-addressed-metadata.md with /tdd, following the standing rules; after
  each slice report one progress line; stop when every slice is implemented`
- **GATE DISCIPLINE (learned S3b):** every slice's gates MUST include `cd impls/python-ng &&
  uv run pytest` (the in-process conformance adapter `test_conformance.py` exercises the
  resolver path the harness-via-CLI does not always reach). Don't accept "rust + default
  harness green" alone — the default harness runs frozen-python, and python-ng has its own
  in-process adapter that can lag the CLI wiring.
- **Stage-3 progress:** S2 ✓, S0 ✓, S1 ✓, S3a ✓, S4-i ✓, S3b ✓, S4-ii ✓, S5 ✓, **S6 ✓** (2026-06-13).
  **Next: S7 — LAST SLICE** (error catalog + conformance saturation): all new codes into
  `errors.md` / `errors.py` / rust catalog with raise sites + fixtures; **reconcile
  `conformance-fixtures.md §4`**; cross-impl Rust passes every new fixture. **Fold in the two
  deferred follow-ups:** (1) the strict-unreachable→`TNG-DEPDECL-FETCH-FAILED` **CLI** fixture
  (S5 deferral — behavior live, no corpus fixture yet); (2) audit every `TNG-DEPDECL-*` /
  `RES-UNATTESTED-METADATA` / `VERIFY-EDGE-MISMATCH` / `LOCK-DEPDECL-PIN-MISSING` code has a
  raise site AND a corpus fixture. **Remember GATE DISCIPLINE (run python-ng pytest + BOTH
  harness modes).** All uncommitted (Corey-gated). After S7 → loop stop-condition met → Stage 4
  (`/code-review`); also revisit the milpa_kdl-under-strict predicate (S5 note).
- **Corey's fork calls (2026-06-13):** F4 = **soft + strict flag** (hardening tracked in
  **issue #127**); naming = **DepDecl** (vocab family applied throughout); python-ng
  `.nimble` fallback = **keep the resolver fallback**. No open forks remain.
- **Recommended first slice:** **S2** (index `dep_decl` pointer parse) — verified
  lowest-risk forward-compat no-op wedge.

## Round 2 (applied 2026-06-13)
4 fresh lenses, briefed on round-1 changes to hunt residual weakness. Headline fix found
independently by **two** lenses (depth + design): a per-call `FallbackEdgeSource` cannot
enforce clause (a)'s graph-level "attested-wins" property → replaced with a
**resolver-scoped `edge_cache` + `resolve_edges` function** that probes the index
pointer parent-independently and seals one EdgeSet per (package,version). This also
**resolved former fork F7** (now spec-wording, normative in §3.5). Other applied fixes:
- **`DepDeclStore` protocol** (`get`+`is_cached`) replaces the bare `dmd_loader` callable —
  hosts the immutable-cache model + single hash-verify site (§3.5, §7).
- **`EdgeSource` signature honesty** — DepDecl case needs no `dep_path`; identity-fetch is
  orthogonal to edge-sourcing (the "no source fetch" claim = no *edge* parse, not no
  fetch) (§3.5).
- **Dropped the consumer-side `canonical_serialize` entirely** — would rot (resolve path
  never serializes) + kdl-py printer is nondeterministic so it'd be hand-rolled for zero
  value; oracle is **parse-only** (§3.2, S1).
- **Named the `Manifest→EdgeSet` transitive projection** normative (drops dev_deps +
  overrides at the seam) (§3.5).
- **`<index_base_url>` formally defined** (strip `*.kdl`/`index*`; OCI undefined → out of
  band) (§3.3).
- **Fixed the tautological offline verify** (storage-integrity ≠ drift-detection; report
  skipped, not passed) (§3.7.2); **prior-lock pin + cache-miss + offline → FETCH-ALL-FAILED**,
  not silent fallback (§3.7.1).
- **Heuristic char-level ordering precision** mandated in `spec/dep-decl.md §7` (3 impls must
  agree on `requires` order) (§5).
- **Schema version lives inside the hashed bytes** + index-vs-artifact agreement check
  (`TNG-DEPDECL-SCHEMA-MISMATCH`) (§3.2.1).
- **Strict-policy composition rule** (manifest OR flag; flag can't weaken; 2 error codes) (S5).
- **Slice ordering corrected**: S2 is the lowest-risk FIRST wedge (both index parsers
  verified to ignore unknown children); the `EdgeSource` seam (S4-i) precedes the
  `DepDeclEdgeSource` loader (S3b); S0 golden vector is **hand-authored** (no reference
  serializer → dropped that decision); cross-fixture equality test = `harness/test_dep_decl.py`.
- Breadth lens also added (round 2): `source` fidelity tag on EdgeSet, `spec/dep-decl.md` 7-section
  ToC, features(#23)-vs-when(#26) forward story, Store-GC exclusion, 5 `TNG-DEPDECL-*` codes.
- **Resolved F6** (milpa-show introspection → deferred to a follow-up issue; the tag keeps
  it free) and **F7** (edge_cache normative). Only F4 / naming / python-ng-fallback remain.

## Round 1 (applied 2026-06-12)
4 lenses (depth/breadth/design/feasibility). Big structural changes folded into the RFC:
- **Producer/consumer asymmetry** (§1, §3.2): resolver only *parses* + hashes received
  bytes; `canonical_serialize` is producer(tianguis)+spec-only. Kills the "both impls
  need a byte-identical KDL2 emitter" burden.
- **`EdgeSet` + `EdgeSource` seam** (§3.2/§3.5): name the anonymous edge tuple (SSOT);
  collapse the 3-branch priority rule into one injected `EdgeSource` +
  `FallbackEdgeSource` combinator. DepDecl = canonical_serialize(EdgeSet).
- **New `spec/dep-decl.md`** (§5.1): joint milpa↔tianguis contract owning canonicalization +
  the relocated `.nimble` heuristic; registry-protocol/manifest-grammar cross-ref it.
- **DepDecl artifact URL** (§3.3): `<index_base>/dep-decl/<hex>.kdl` — pointer was a hash with no
  address before. Immutable cache-forever (§3.3.1).
- **`dep_decl_schema_version`** (§3.2.1): resolves F5 (capabilities = future version, not a
  hash-unstable reserved slot).
- **Correctness clauses** (§3.5): (a) attested-DepDecl-wins across diamond/mixed-source
  paths; (b) override suppresses DepDecl lookup; (c) dev-deps by graph position not DepDecl hint.
- **`when`-block union + scoped §3.6 obligation**; honest pre-/post-#103 threat model
  (§6); rejected sign-the-source alternative (§2.3); §3.9 backfill/transition window;
  §4.1 migration path; verify error split (VERIFY-EDGE-MISMATCH / LOCK-DEPDECL-PIN-MISSING).
- **Slices re-sequenced** (§9): S3 split→S3a(fixture plumbing: `dep-decl/` slot+`MILPA_DEP_DECL_DIR`)
  /S3b(loader); S4 twin-fixture harness-equality + malformed-constraint constraint; S6
  adds `verify` cmd token; **S8 dropped from milpa slices** → tianguis issue (no milpa
  slice blocks on it at runtime).
- Resolved F1 (separate artifact+URL), F2 (pin now+error split), F3 (defer bump), F5.

## What this RFC is
Move the `.nimble`→declarative translation out of the resolver and into tianguis
ingest: a per-`(package,version)` **Dependency Declaration (DepDecl)**, content-
addressed (`dep_decl_hash`, orthogonal to source-tree identity), Rekor-attested on the
existing Sigstore flow, served as a separate content-addressed artifact pointed to
from the index version-node. Resolver consumes the verified DepDecl instead of parsing
`.nimble`; raw un-indexed git URLs keep the resolve-time `.nimble` fallback
(transitional, warned). Best-in-class = Go-modules/Nix/Sigstore shape, NOT PEP 658
(which is PyPI's legacy retrofit). Realizes `rfc-content-addressed-identity.md` Phase E
for metadata; feeds `rfc-beyond-pubgrub.md` D1/D2/D7.

## Slices (post-round-2 — see RFC §9; **recommended order: S2 → S0 → S1 → S3a → S4-i (seam) → S3b → S4-ii (gate) → S5 → S6 → S7**)
- [x] S2 index `dep_decl` + `dep_decl_schema_version` (forward-compat parse) — **DONE 2026-06-13**: `IndexVersion` (python-ng) + `IndexVersion` struct (rust) gain both optional fields; `_parse_version_node`/`parse_version_node` extract them; spec/registry-protocol.md §3.2 documents them forward-compat-optional (no schema bump); conformance fixture-129 (PASS both impls, 0 divergence). Gates: python-ng 1179 pass/5 skip, rust --workspace ok, mypy+clippy clean.
- [x] S0 `spec/dep-decl.md` (7-section ToC) + char-level canonicalization + v0 **hand-authored** golden vector + `make_dep_decl_fixture` test helper — **DONE 2026-06-13**: `spec/dep-decl.md` (7 §§); golden `conformance/spec-v1/dep-decl-golden/v0/example.kdl` + `meta.json` (hash `sha256:34a91f93…`, independently verified); `harness/dep_decl.py` (`EdgeSet`/`canonical_serialize`/`make_dep_decl_fixture`) + `harness/test_dep_decl.py` (27 tests). 5 `TNG-DEPDECL-*` codes registered in catalog → `spec/errors.md` regenerated; rust conformance DEFERRED-marks them (raised in S3b). **Pinned §2 rule-4 encodings:** named = `require "<name>" "<constraint>"`; url = `require (url)"<url>" ref="<ref>"`; requires are flat `require` children of `dep_decl` (no wrapper block); `src_dir ""` explicit when unset. Gates: harness 117 pass, differential Python 112/Rust 124 / 0 divergence, python(frozen) 949, rust --workspace green.
  - **NOTE for Corey (non-blocking):** `spec/errors.md` is generated from `impls/python/milpa/error_catalog.py` — i.e. the **frozen** impl is the current SSOT for the error-catalog *spec artifact*. That's a transitional wart the #6 rewrite will subsume (python-ng has its own `errors.py`). Editing the frozen catalog to register spec-level codes was correct given today's tooling; flagging in case you want an issue to move catalog ownership to spec/ or python-ng post-swap.
- [x] S1 `EdgeSet` type (+ in-mem `source` tag) + DepDecl **parse/verify** — **DONE 2026-06-13**: python-ng `milpa/dep_decl.py` (`EdgeSet`/`EdgeSource`/`NamedRequire`/`UrlRequire`/`parse_dep_decl`/`dep_decl_hash`, reuses `kdl_io.parse_kdl` + `hashlib.sha256`); rust `milpa-types` EdgeSet types + `milpa-core/src/dep_decl.rs` (reuses kdl crate + `sha2`). Parse-only oracle vs S0 golden vector green in BOTH impls (parse→EdgeSet equality + `sha256(bytes)==dep_decl_hash`). **`(url)` tag is the named/url discriminator.** All 5 `TNG-DEPDECL-*` codes now *declared* in both catalogs (rust bijection `rust_error_catalog_is_a_bijection_with_the_spec` ✓); **`TNG-DEPDECL-PARSE-ERROR` raise-site already wired** (KDL parse context) — S3b only needs the other 4 (HASH-MISMATCH/FETCH-FAILED/SCHEMA-MISMATCH/SCHEMA-UNSUPPORTED). Gates: python-ng 1192 pass/5 skip, mypy clean, rust --workspace 299 ok, clippy clean (2 pre-existing warnings unrelated), differential harness Python 112/Rust 124/0 divergence.
- [x] S3a fixture plumbing — **DONE 2026-06-13**: `harness/runner.py` `_build_env` injects `MILPA_DEP_DECL_DIR=<scratch>/dep-decl/` when a fixture has a `dep-decl/` dir (3-line mirror of the `MILPA_MOCKED_FETCHES`/`MILPA_INDEX_URL` block; existing `MILPA_*` host-strip auto-covers it — SSOT, no parallel path); `dep-decl/` copied verbatim into scratch like `mocked-fetches/`. Spec: `conformance-fixtures.md §2.11`, `cli-contract.md §8.4` + Appendix B (`FileDepDeclStore` reads `$MILPA_DEP_DECL_DIR/<sha256_hex>.kdl` — behavior is S3b). NO resolver code touched. Gates: harness 124 pass (+7), differential 0 divergence, python-ng 1192, rust --workspace green.
- [x] S4-i `EdgeSource` units + resolver-scoped `resolve_edges`/`edge_cache` + `Nimble`/`MilpaKdl` sources + transitive projection + clauses (a/b/c) — **DONE 2026-06-13**: python-ng `milpa/edge_sources.py` (+`test_edge_sources.py`); rust `milpa-core/src/edge_sources.rs` (14 inline tests). Resolver-core refactor **behavior-preserving** (existing test files only gained lines, 0 removed; refactored BFS dispatches through `resolve_edges` over `edge_cache` memo — clause (a) seal). `Nimble`/`MilpaKdl` sources wrap existing parse; `manifest_to_edgeset` = normative transitive projection (reads `deps` only, drops `dev_deps`+`overrides`, maps `src_dir`). Clause (b) override→fall-through, (c) dev-deps-by-graph-position. **`dep_decl` branch = structurally present, routed to an injected optional DepDecl source = None until S3b** (no fake stub). Spec: `resolver-semantics.md §4.2.1 step 2` amended. Conformance **fixture-130** (transitive milpa.kdl w/ dev-deps+overrides → lock has `requires "foo"` only; verified). Removed dead `build_from_*`/`from_nimble_constraint`/`find_nimble`. Gates: python-ng 1215 pass (+23)/5 skip, rust milpa-core 199 + workspace ok, mypy+clippy clean, differential 129 fixtures Python 113/Rust 125/0 divergence.
- [x] S3b `DepDeclEdgeSource` + `DepDeclStore` (`get`/`is_cached`); 5 codes — **DONE 2026-06-13**: python-ng `milpa/dep_decl_store.py` (`FileDepDeclStore`/`HttpDepDeclStore`/`make_dep_decl_store`; `get` = single hash-verify site) + `DepDeclEdgeSource` in `edge_sources.py` plugged into `resolve_edges` `dep_decl` branch; `cli._build_dep_decl_store` selects File (MILPA_DEP_DECL_DIR) vs Http (`<index_base_url>/dep-decl/<hex>.kdl` per §3.3). rust mirror in `milpa-core` (327 tests). 4 remaining raise sites wired: HASH-MISMATCH/FETCH-FAILED (in `get`), SCHEMA-MISMATCH/SCHEMA-UNSUPPORTED (in `DepDeclEdgeSource`); integrity failures are HARD (no fallback). Fixtures: 129 (happy pointer), 131 hash-mismatch, 132 parse-error, 133 schema-mismatch, 134 schema-unsupported (rust PASS; frozen-python known-failing per #6). **FETCH-FAILED CLI fixture deferred to S5** (strict-policy dependent). **CAUGHT+FIXED a verification gap:** subagent claimed green w/o running python-ng `uv run pytest` — its in-process conformance adapter `test_conformance.py::_build_env` didn't wire the `FileDepDeclStore` from the fixture `dep-decl/` dir (CLI path did, so harness passed but unit suite failed 131-134 "resolve succeeded"). 8-line `_build_env` fix (mirror S3a injection). Gates NOW: python-ng 1249 pass/5 skip + mypy clean, rust --workspace 327 ok + clippy clean, default harness 0 divergence, MILPA_PYTHON_NG=1 harness OVERALL PASS. **Lesson: a slice's gate set MUST include the active impl's own `uv run pytest`, not just rust + default harness.**
- [x] S4-ii differential gate — **DONE 2026-06-13**: twin corpus fixture pairs — clean (135 attested / 136 fallback → byte-identical lockfiles, verified) + when-block (137 attested=`bar` only / 138 fallback=`bar+extra` → divergence, resolver honors DepDecl over `.nimble`). New imperative cross-fixture capability in `harness/test_dep_decl.py` (`_resolve_lockfile` reuses `runner.run_fixture`; 6 DG tests × rust/python-ng). Fallback arms have NO malformed constraint. frozen-python known_failing += fixture-137 only (clean-attested passes via fallback-equality). Gates (independently re-verified): python-ng 1253 pass, harness/ 127 pass, differential frozen-python 116/0 + python-ng-active 133/0 **zero divergence both modes**, rust --workspace 327, mypy+clippy clean. Ingest union heuristic = tianguis (S8), not here.
- [x] S5 single summary warning + strict-policy composition — **DONE 2026-06-13**: new code `RES-UNATTESTED-METADATA` (all 3 catalogs); manifest `attestation-policy "strict"` (grammar + both parsers + rust emit); CLI `--require-attested-metadata` + conformance env `MILPA_REQUIRE_ATTESTED_METADATA` (cli-contract §8.5); effective policy = OR(manifest, flag/env), flag can't weaken — factored into `milpa/attestation.py::enforce_attestation_policy` (SSOT, deep module); `resolver-semantics.md §13`. Non-strict: ONE summary warning on `NimbleFallback` deps. Strict: `RES-UNATTESTED-METADATA`. **Non-strict unreachable-`dep_decl` fallback implemented** (edge_sources.py:484-494: FETCH-FAILED + non-strict → fall to Nimble; strict → hard FETCH-FAILED; integrity failures ALWAYS hard). Subagent caught+fixed the same in-process-adapter gap class as S3b (`_fixture_require_attested_metadata` in `_execute_fixture`) — gate discipline working. Fixtures 139 (warn) / 140 (strict-via-manifest) / 141 (strict-via-env). Gates (independently re-verified): python-ng 1256 pass/0 fail + mypy clean, harness/ 127, differential frozen-python 117/0 + python-ng-active 136/0 **zero divergence both modes**, rust --workspace 136 + clippy clean.
  - **S7 follow-up:** add the strict-unreachable→`TNG-DEPDECL-FETCH-FAILED` **CLI** fixture (behavior implemented + unit-tested; no corpus fixture yet — saturation belongs in S7).
  - **Stage-4 review note:** confirm the `milpa_kdl`-under-strict predicate in `attestation.py` is spec-faithful (subagent decided without escalating; spec text "(a) no dep_decl in index" is broad).
- [x] S6 lockfile `dep_decl` pin + verify graph-drift + **`verify` harness cmd token** — **DONE 2026-06-13**: additive `dep_decl "sha256:…"` per-dep lock record (emit-when-present, forward-compat parse, NO schema bump) both impls + `lockfile-schema.md`. Two new codes `VERIFY-EDGE-MISMATCH` (locked pin ≠ index current) + `LOCK-DEPDECL-PIN-MISSING` (pin present, index lacks dep_decl) registered all catalogs; `milpa verify` extended (evicted→refetch→FETCH-FAILED; offline edge-check reports SKIPPED not passed §3.7.2; drift §3.7.1: non-strict re-fetch current + warn, strict→VERIFY-EDGE-MISMATCH, cache-miss+offline→FETCH-ALL-FAILED no silent fallback). Harness `verify` cmd token (runner pre-phase = regular fetch + restore authored lock to warm CAS) + wired into python-ng in-process adapter `_execute_verify`. Fixtures 142 (edge-mismatch) / 143 (pin-missing). **DG1 (S4-ii) adapted — principled, NOT a relaxation:** clean pair is partial-attestation (qux via DepDecl both arms; bar via DepDecl in 135 vs `.nimble` in 136), so `_assert_clean_pair_identical` strips ONLY the `dep_decl` pin line and still asserts full equality of bar's resolution outcome (edges/version/identity/provenance/src_dir) — the faithfulness invariant is preserved. Gates (independently re-verified incl. the gate the subagent omitted): python-ng 1258 pass/0 fail + mypy clean, harness/ 127, rust --workspace 327 + clippy clean, differential frozen-python 113/0 + **python-ng-active 138/0 zero divergence both modes** (frozen known-fails 129/135/136/138/142/143 = can't emit pins/DepDecl — legitimate).
- [x] S7 error catalog + conformance saturation — **DONE 2026-06-13**: added `fixture-144-depdecl-fetch-failed` (strict + empty `dep-decl/` → `TNG-DEPDECL-FETCH-FAILED`); 8-code completeness audit (each has errors.md entry + raise sites both impls + ≥1 fixture + Rust passes); reconciled `conformance-fixtures.md §4`. **Control-loop caught + root-cause-fixed two latent gaps the grind had accumulated (no slice had run the frozen `impls/python` pytest since S3b):** (1) `RES-UNATTESTED-METADATA`/`VERIFY-EDGE-MISMATCH`/`LOCK-DEPDECL-PIN-MISSING` were hand-added to `errors.md` but never REGISTERED in the frozen catalog generator → registered in `resolver_codes.py`/`verify_codes.py`/`lockfile_codes.py` + per-prefix `KNOWN_UNTESTED` + bidirectional tombstones, regenerated `errors.md`; (2) all 14 DepDecl fixtures were silently failing the frozen impl's in-process `test_conformance.py` → added `_DEPDECL_PYTHON_FROZEN` skip set (mirrors `_KDL_2_0_ONLY`/`_TARBALL_TOFU`). Gates (independently verified): frozen-python **950 pass/0 fail**/40 skip, python-ng **1259 pass/0 fail**, rust --workspace ok + clippy clean, harness BOTH modes (frozen-python 113/0, rust 139/0, python-ng 139/0) **ZERO divergence**. Lesson saved → [[feedback_gate_active_impl_pytest]] (extended to cover the frozen impl).
- [ ] ~~S8~~ → **tianguis issue** (not a milpa slice; no milpa slice blocks on it at runtime)
- [ ] (follow-up, non-blocking) F6 `milpa show --verbose` edge-source introspection → file a GH issue

## Open forks
### Resolved (recorded, not awaiting Corey)
- **F1** separate content-addressed artifact + URL template `<index_base>/dep-decl/<hex>.kdl`
- **F2** lockfile pin now + `VERIFY-EDGE-MISMATCH` distinct from identity finding
- **F3** keep forward-compat-optional; bump `TIANGUIS_INDEX_SCHEMA_VERSION` 1→2 only after backfill
- **F5** NOT a reserved slot (hash-unstable) → future `dep_decl_schema_version` with its own vector
- **F6** (r2) milpa-show edge-source introspection → deferred to a follow-up GH issue (tag keeps it free)
- **F7** (r2) diamond coordination → normative `edge_cache` in §3.5 (spec-wording, not a fork)

### Resolved by Corey (2026-06-13) — no open forks remain
- **F4** = soft + strict flag; hardening to hard-fail at schema-v2 tracked in **issue #127**.
- **Naming** = **DepDecl** (full vocab family applied across RFC + handoff; `spec/dep-decl.md` writes it into the spec).
- **python-ng `.nimble` fallback** = keep the resolver fallback through the transition; `milpa adopt` is a separate future convenience.

**RFC ready for Stage 3 (implement slices).**

## Key decisions (this session)
- **DepDecl hash is a THIRD addressing axis, orthogonal to source-tree identity** — must
  NOT make source identity depend on deps (preserves "recomputable from bytes alone").
- **Per-version flat hashed declaration (go.mod-shaped), NOT a recursive Merkle DAG** —
  `requires` are declarations over ranges, not concrete child hashes; recursive
  content-addressing belongs to the resolved closure (lockfile), already done.
- **PEP 658 is the floor, not the ceiling** — Go/Nix/Sigstore is the reference; milpa
  already owns content-hash identity + Rekor transparency log + result certificate.
- **Resolver-side `.nimble` parsing is transitional** → resolves the rewrite's 11b
  nimble fork: park resolver-side MAN-NIMBLE-CONSTRAINT hardening, fix at ingest (S8).
- **Cross-repo contract = the canonicalization spec + `dep_decl_hash` algorithm (S14 §6.1).**

## Integration map (from grounding agent — for architect context)
- Identity = source tree only (S12); index encodes identity+provenance, **NOT edges**
  (`rfc-resolver-tianguis-swap.md` L39); transitive edges come from resolve-time
  `.nimble`/`milpa.kdl` parse (S6 §4.2.1, NORMATIVE — the clause this RFC amends).
- Rekor `{uuid;log_index;integrated_time}` already per index version-node; consumer-
  side verification is **issue #103** (open, shared w/ trust-federation RFC) — NOT a
  blocker for this RFC.
- Content-addressed-identity phases: A partial (#31 verify), B open (#32 dedup), C
  landed (S12 CAS), D reserved (#37 multi-prov), **E = this RFC's attestation, for metadata**.
- New RFC lives milpa-side (S14/S6/S5 + errors + conformance); tianguis implements ingest.

## Relationship to in-flight rewrite
`rfc-python-clean-room-rewrite` (11b/11c) is independent and still Corey-gated. This
RFC's spec slices S0–S2 touch no rewrite code (can proceed in parallel); S4+ start
after the swap. The 11b nimble-constraint fix is now **parked as transitional** here.

## Process
- **Stage 2 contract:** run `/architect docs/rfc-content-addressed-metadata.md round 1`
  then `round 2`; don't enter `/tdd` until both rounds are applied and forks resolved.
- Safe **/compact** point now (RFC + handoff on disk).
