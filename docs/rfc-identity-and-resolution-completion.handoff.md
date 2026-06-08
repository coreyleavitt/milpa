# rfc-identity-and-resolution-completion — handoff

- **Stage:** 3 tdd — **ALL SLICES IMPLEMENTED.** Phases 0+1+3 complete & pushed; **Phase 2 (P2.1+P2.2+
  P2.3) DONE, green, uncommitted.** Anchor series live on tianguis origin/main @ `9e277e0`.
- **Resume:** **stage 4 — `/code-review` over the RFC scope** (PhD-CS bar). Then the commit/push
  decision for the uncommitted Phase-2 tianguis working tree (Corey-gated), and Corey's one-time
  **Gate B manual smoke** for P2.1 (cosign-SAN jq path on a real signed publish). **Safe to `/compact`
  first.**
- **Uncommitted Phase-2 working tree (tianguis), all 20/20 suite + corpus 44/44 green:**
  `addentry.nim`, `alerts.nim`, `tianguis_cli.nim`, `tests/test_cmd_add_entry.nim`,
  `.github/workflows/commit-entry.yaml`, `dispatch/handler.go`, `dispatch/handler_test.go`,
  `docs/spec/index-format.md`, `spec/fixtures/derive-namespace.json`. RFC P2.3 text patched (milpa repo).

## Review ledger (stage 4 — `/code-review the RFC`, 2026-06-07)
6 reviewers (milpa correctness/design, tianguis correctness/design, security, spec-consistency) +
5 adversarial verifier passes. Severities post-verification.
- **Stage:** 4 review — **FIX LOOP round 1 IN PROGRESS.** Mandate (Corey): **fix through Medium, leave Low.**
- **Resume:** await the 2 fix agents (milpa: H1/H4/M3/M4/M7/M8/M11/M12 on host pytest; tianguis:
  C1/H2/H3/M1/M2/M5/M6/M9/M10 in 2.0.8 container), verify their claims, then re-review changed
  scope (Security+Design+correctness) → loop until 0 Crit/High/Med. Then file M13 issue (milpa
  workspace Phase-A/B migration). NOTHING committed (both repos). Gate-B manual smoke still pending.
- All findings `open` until fixes land + are verified; Low batch (L1-L11) intentionally deferred per mandate.

### Round 1 fix results (2026-06-07, 2 sonnet TDD agents, uncommitted)
**milpa (713 pass/6 skip):** H1 ✅fixed (degenerate ConflictChain at guard) · H4 ✅fixed (new `_on_new_url`
callback + `start_solve(on_new_named,on_new_url)`; URL transitives enrolled mid-solve) · M3 ✅fixed
(`_fetch_and_build_named_candidate` shared core; both callers delegate) · M4 ✅fixed (`start_solve` sets
both callbacks atomically) · M7 ✅fixed (semver-cause ConflictStep) · M11 ✅fixed (`sha256=expected_sha256`
+ round-trip test) · M12 ✅fixed (skip provenance-less, raise only if none) · **M8 ⛔ESCALATED→DEFERRED**:
bare-name `seen_named` collapse is unreachable — two same-bare-name deps hit TNG-AMBIGUOUS-NAME at
lookup_bare BEFORE seen_named; real fix = qualified `NamedDep(namespace,name)` through manifest+BFS+callback
= RFC scope. **→ file milpa issue, not fix-in-loop.**
**tianguis (248 pass):** C1 ✅fixed (`kdlEscapeString` in kdl_io applied to all emit + alert fields;
`isValidPackageName` allowlist exit-4 pre-I/O; phantom-block injection regression test re-parses to 1 literal
pkg) · H2 ✅fixed (predicate.json uses extracted SAN) · H3 ✅fixed (`"null"` guard) · M9 ✅fixed (heredoc-delim
GITHUB_OUTPUT) · M1 ✅fixed (strip `?`/`#` before path split + tests) · M2 ✅fixed (new SSOT `fileutil.atomicWrite`,
cmd_migrate de-duped, addentry uses it, defer .tmp cleanup → also closes a Low) · M5 ✅fixed (underivable
incoming + host/org stored → mokIdentityDrift) · M6 ✅fixed (`buildVendoredEntry precomputedNs` param, derive once)
· M10 ✅fixed (dup case 42 → non-github OIDC SAN positive case).
### Round 2 re-review (Security+Correctness+Design over changed scope) — DONE
**Correctness:** no regressions; all 16 fixes verified root-cause-correct (H4 seen_url dedup + fixpoint OK;
M3/M11/M12/M1/M5/M6 all correct). **Design:** fixes clean (`_fetch_and_build_named_candidate`/`start_solve`/
`fileutil` genuine SSOT wins). Surfaced 2 NEW Mediums + Low polish. **Security:** escaping complete (mirrors
nkdl byte-for-byte), workflow H2/H3/M9 sound, H4 protected by content-hash identity gate. Surfaced 2 NEW Mediums.
- **M14** (Med, security): `isValidPackageName` allowed `..` → registry-wide DoS (milpa read-side rejects `..`
  via `_RE_UNSAFE_NAME` → a `..` entry makes the whole index unparseable for all milpa users). NOT consumer
  path-traversal (milpa SSOT holds). → fixed round 3.
- **M15** (Med, security): predicate.json built by heredoc with verbatim `${{ }}` → JSON injection via
  version/oci_ref/upstream (quotes suffice) → Rekor audit corruption. → fixed round 3.
- **D6** (Med, design): `isValidPackageName` in command layer not shared home → other write paths bypass. → fixed round 3.
- Low (deferred per mandate, → file issues): nkdl doesn't export a standalone escape primitive (kdlEscapeString
  mirrors it, drift risk) → file nkdl issue; `buildVendoredEntry precomputedNs:string=""` sentinel → Option[string];
  `IdentityDrift.rederivedNamespace=""` conflates two failure modes → `mokDerivationFailure` variant; alerts.kdl
  bare writeFile → use fileutil.atomicWrite; cli.nim vendor-path bare writeFile.

### Round 3 fixes (tianguis, uncommitted) — DONE green
- **M14+D6** ✅ `isValidPackageName` moved to `kdl_io.nim` (SSOT serialization boundary), hardened to reject
  `.`/`..`/leading-dot/`..`-sequence (now agrees with milpa `is_safe_name`); addentry re-exports it; orchestrate
  vendor-write path now calls it (skip+log on reject). 9 unit + 2 integration tests, RED→GREEN.
- **M15** ✅ predicate.json via `jq -n --arg` (all 8 values escaped by jq); `${{ }}` routed through `env:` vars
  (also closes GitHub-expression-into-shell injection); signed_by = extracted SAN; SAN output → heredoc-delim form.

### Round 4 re-review (Security+Design over round-3 scope + full suite) — DONE
Full tianguis suite **20/20 green**. Nim code (validation, SSOT placement, all write paths) confirmed clean;
isValidPackageName is strictly more restrictive than milpa is_safe_name (write-read gap closed). Surfaced 3
workflow findings (all in commit-entry.yaml):
- **F1** (Med, security): "Add entry" step expanded `${{ }}` INLINE (not env-routed) → argv injection into the
  tianguis binary via caller-supplied `upstream`/`oci_ref` (a `"` smuggles extra flags). → **fixed inline**
  (env-routed ARG_* vars, same discipline as the predicate step). Binary guards (isValidPackageName/kdlEscape/
  last-wins --signed-by) bounded impact, but the vector is closed at the root.
- **F2** (Low): SIGNED_BY in cosign `--certificate-identity-regexp` — already env-routed; a `"` would break
  quoting but can't appear in a real SAN + fail-closed. **left (Low).**
- **F3** (Low): git commit message uses inline `${{ }}` → a `"` breaks the message (commit fails, cosmetic).
  **left (Low).**

## ✅ STAGE 4 FLOOR REACHED (2026-06-07) — 0 Critical / 0 High / 0 Medium open
4 fix rounds + 4 verified re-review rounds. **18 findings fixed** (1 Crit, 4 High, 13 Med — incl. M14/M15/D6/F1
found during re-review), all with regression tests where behavioral. milpa **713 pass/6 skip**, tianguis **20/20
files (248 tests)**. **Nothing committed (both repos).**

### Deferred (issues filed — defer-file-now)
- **milpa #108** — M8 qualified `NamedDep(namespace,name)` end-to-end (RFC-scope; current collapse unreachable).
- **milpa #109** — M3/M13 migrate `resolve_workspace` named deps to Phase A/B (backtracking parity); dedup already done.
- **nkdl #43** — export a public escape primitive so tianguis `kdlEscapeString` delegates (drift risk) instead of mirrors.

### Remaining Lows (deferred per mandate — not filed, recorded here)
predicate/commit-message/SIGNED_BY shell-quoting consistency (F2/F3) · `buildVendoredEntry precomputedNs:string=""`
→ Option[string] · `IdentityDrift.rederivedNamespace=""` → dedicated `mokDerivationFailure` variant · alerts.kdl +
cli.nim vendor-path bare `writeFile` → fileutil.atomicWrite · alerts exit-code conflation (1 vs 1) · dead
`saw_add` · `mhkUnexpectedSplit`/`forgePolicy.orgCount` dead generalizations · signed_by doc example abbreviated ·
Version.__iter__ drops pre · lookup_bare O(N) · semver leading-zero pre-release leniency · namespace.nim spec-pointer
→ index-format.md · corpus "Python later" comment · trailing-dot host fixture · parse_index empty-ns transitional note.

### Resume / next
- **Corey-gated:** commit/push decision for the full RFC working tree (milpa 4 files M + tianguis ~16 files M/new).
  Nothing committed. · **Gate-B manual smoke** (P2.1 cosign jq SAN path on a real signed publish) — only Corey can run.
- Optional: a Low-cleanup pass (batchable) before commit, or fold into the commit.

| id | sev | finding | file | status | proof / verify |
|----|-----|---------|------|--------|----------------|
| C1 | Crit | KDL injection: unescaped `name`/`namespace`/`signedBy` in hand-rolled KDL → corrupt shared index.kdl (DoS all milpa users) or potential phantom-`package`-block injection declaring arbitrary namespace (defeats P2.1 identity) | kdl_io.nim formatPackage, alerts.nim formatAlert | open | confirmed unescaped (2 agents); spoof-vs-DoS parser-dependent → fix=escape + regression test pins re-parse |
| H1 | High | `raise SolverError("…string…")` but `__init__` requires ConflictChain → render_conflict_chain(str) crash on >10k-iter guard, masks non-convergence diagnostic | solver.py:964 | open | verifier HOLDS; trigger = iteration guard |
| H2 | High | predicate.json records raw caller `signed_by` (l.181) not verified extracted SAN (l.163); `--certificate-identity-regexp="^${SIGNED_BY}@"` (l.130) attacker-loosenable → Rekor audit trail disagrees w/ index.kdl, identity-pin is theater (no ns-spoof post-P2.1) | commit-entry.yaml | open | self-verified by read |
| H3 | High | jq SAN path wrong → `jq -r` yields string `"null"`; `[[ -z "$SAN" ]]` passes it → `--signed-by=null` → derrNoOrg → every publish rejected (DoS). Ties to open Gate-B TODO | commit-entry.yaml:141-149 | open | guard is `-z`-only; fix=add `=="null"` + resolve Gate B |
| H4 | High | Phase-B `_materialize_stub` puts a named dep's URL `requires` (`sub_url_deps`) into dep_terms but never registers them as providers → `provider.versions(url_dep)==[]` → spurious `no-versions` SolverError for ANY indexed dep whose .nimble has a URL require | resolver.py:348-381 | open | verifier HOLDS; resolve() path (not just workspace) |
| M1 | Med | URL query/fragment (`?`/`#`) not stripped from path segments → poisoned ns `custom-forge.io/org?tenant=x`; breaks re-derive/collision match | namespace.nim:158-163 | open | verifier HOLDS; comment l.163 false |
| M2 | Med | non-atomic `writeFile(indexPath, …)` on live publish path (migrate path uses atomicWrite) → partial-write corruption window | addentry.nim:144 | open | verifier HOLDS |
| M3 | Med | `_process_named` duplicates `_materialize_stub` fetch+parse pipeline (SSOT); RFC says "follow-on" w/ no issue # | resolver.py:1571-1655 | open | clear duplication; min=delegate + file issue |
| M4 | Med | `_on_new_named` set as mutable attr after finalize() → silent transitive-drop if dependencies() runs first | resolver.py:714-738 | open | design; pass via ctor/start_solve |
| M5 | Med | identity guard skipped when re-derivation `isErr` → malformed provenance slips re-ingest past guard | merge.nim:125-133 | open | guard isOk-gated; failure should be mokIdentityDrift |
| M6 | Med | orchestrate re-derives namespace then buildVendoredEntry derives again (redundant, correctness-neutral SSOT) | orchestrate.nim:73 + merge.nim:62 | open | verifier HOLDS |
| M7 | Med | build_conflict_chain semver-conflict fallback → unexplained bare step; no structural test for semver path | solver.py:1255-1266 | open | add semver-prefix handler + test |
| M8 | Med | `seen_named: set[str]` bare-name dedup key structurally wrong once index tuple-keyed (masked by single surviving nimkdl) | resolver.py:540 | open | key on (ns,name) |
| M9 | Med | GITHUB_OUTPUT newline injection via multiline payload (latent — no downstream consumer) | commit-entry.yaml:104 | open | use heredoc-delim output |
| M10 | Med | no fixture for non-github OIDC SAN deriving valid ns → forge-agnostic claim untested | derive-namespace.json | open | verifier HOLDS; replace dup case 42 |
| M11 | Med | `TarballProvenance.expected_sha256` dropped (`sha256=None`) from lockfile → declared archive hash lost; can't reproduce archive check from lockfile alone | lockfile.py:232 | open | verifier HOLDS; one-line fix |
| M12 | Med | `resolve_named_all` raises TNG-NO-PROVENANCE inside the per-version loop → one provenance-less newest version blocks resolution even when older valid satisfying versions exist | tianguis_client.py:585-592 | open | verifier HOLDS; skip+warn, error only if none left |
| M13 | Med | `resolve_workspace` named deps use single-version `_process_named` → no backtracking; strictly weaker than resolve() for diamond graphs (same root as M3) | resolver.py:912-922 | open | migrate workspace to Phase A/B + file issue |
| L1-L11 | Low | predicate.json heredoc unescaped JSON (jq-build); alerts exit-code conflation (1 vs 1); atomicWrite no .tmp-cleanup defer; dead `saw_add`+misleading comment; `mhkUnexpectedSplit` dead variant; `forgePolicy` orgCount always 1; dup fixture 32≡42; signed_by example uses abbreviated form; deriveVersionNamespace/formatAlert/VendoredEntry-construction design-consistency cluster; Version.__iter__ drops pre silently + lookup_bare O(N); namespace.nim spec-pointer→RFC not index-format.md + corpus "Python later" comment + trailing-dot host fixture missing + parse_index empty-ns transitional note | various | open | polish batch |
| R1 | refuted | `_precedence_key` per-comparison alloc as a *bug* — O(1) for releases, trivial for pre | solver.py | refuted | verifier: not a bug |
| R2 | refuted | GitLab-CI-SAN as *live* spec/impl contradiction | namespace.nim:235 + index-format.md | refuted | latent only; no gitlab issuer trusted; #37 filed; spec consistent. Keep as Low code-comment landmine note |
| R3 | refuted | signed_by example = normative *contradiction* | index-format.md | refuted | illustrative imprecision → kept as L (polish) |
| R4 | refuted | branch-2 discriminant spec/code disagreement | namespace.nim:291 | refuted | they agree (signedBy-nonempty) |

## Slice progress (stage 3)
- [x] **P0.1** (milpa) — `VersionSet.all()`→`full()`; regression test drives `_extract_from_milpa_kdl`
      transitive bare-NamedDep path. Suite 617 pass / 6 skip.
- [x] **P0.2** (milpa docs, edit-only) — comparison doc: prerelease/build-meta/caret-tilde/narration
      → "planned (Phase 3)". (P3.4 flips shipped ones back to "built".)
- [x] **P0.3** (tianguis) — `deriveVersionNamespace` SSOT in namespace.nim; 5 tests RED→GREEN incl.
      vendored-anchor invariant (8-entry falsifiable loop — no proptest harness in tianguis).
- [x] **P0.4** (tianguis) — deleted dead `checkOidcGitAgreement` + `test_namespace_oidc.nim`;
      deferral note → rfc-package-identity.md (tianguis #39).
- [x] **P0.5** (tianguis+milpa docs, edit-only, **wants Corey sign-off**) — S6 = derive-all-per-version
      + regroup; index-format.md normative anchor algorithm; milpa identity-and-provenance.md
      org-rename = new-stale-entry (#36, not "rejected").
- [x] **P1.1** (tianguis) — MergeOutcome case-object sum + `mergeVendored→(index,outcome)` +
      checkIdentityStable wired first (priority mokIdentityDrift▸collision▸contentDrift▸added);
      guard fires only on host/org stored ns; overloaded formatAlert; 7 files (6 + addentry.nim).
      Suites green. Guard catches provenance↔stored-ns inconsistency (defense-in-depth, not rename).
- [x] **P1.2** (milpa) — parse_index tuple-key + TNG-AMBIGUOUS-NAME + lookup_bare→Package|AmbiguousName
      (verified landed: Package.namespace, AmbiguousName, Index.lookup/lookup_bare, resolve_named policy raise).
- [x] **P1.3** (tianguis) — pure `migrateIndex` in `src/tianguis/migrate.nim` + `MigrationHalt`;
      20 tests (gates 1–6b + 3 failure paths) green; regressions clean. `mhkUnexpectedSplit`
      unreachable given clean derivation (kept for completeness).
- [~] **P1.4** (tianguis) — **CODE DONE (TDD, uncommitted); EXECUTE+COMMIT still Corey-gated.**
      ✅ Built 2026-06-07 via sonnet /tdd: `src/tianguis/cmd_migrate.nim` (pure `buildMigrationReport`
      → `MigrationReport`, pure `renderDryRun`/`renderAuditRecord`, `atomicWrite`, `cmdMigrate(dir,
      execute)`; `--dry-run` default, `--execute` opt-in, both-artifact atomic regen via staging+rename,
      `index.kdl.bak`, audit record → `docs/spec/migrations/0001-32-identity.json`,
      `{.deprecated.}` + stderr notice). host/org-reject guard in `cmdAddEntry` (**exit 4**,
      `'/' notin args.namespace`, no mutation); test_cmd_add_entry.nim org-only fixtures converted to
      guard-rejection + new host/org positive case. New test_cmd_migrate.nim (28 tests). **Full tianguis
      suite 226/226 green** in container. **Independently verified:** guard + dispatch spot-checked;
      **read-only `migrate` dry-run against the REAL index → 2613→2614, splits: 1, `nimkdl →
      [github.com/coreyleavitt, github.com/greenm01]`, wrote nothing (git status clean re: index).**
      ⛔ **Remaining = operational, Corey-gated:** (1) commit the milpa grind so P1.2 is on milpa
      `main`; (2) pin commit-entry.yaml milpa checkout ≥P1.2 SHA; (3) `tianguis migrate --execute`
      + commit the migrated index = the new trust anchor. NOTHING committed yet (both repos).
- [x] **P1.5** (cross-repo smoke) — satisfied by the P1.4 consumer-verify: new P1.2 milpa
      parse_index reads all migrated pkgs, 0 non-host/org, `lookup_bare("nimkdl")` →
      AmbiguousName[coreyleavitt, greenm01]. (Post-P1.6 the coreyleavitt arm is gone — bare
      `nimkdl` now resolves uniquely to greenm01, which is the documented correct re-resolution.)
- [x] **P1.6** (tianguis) — **DONE + committed locally (6e1c054).** Hard-removed the stale
      `github.com/coreyleavitt` / nimkdl v0.1.4 block (OCI, author-signed, pre-`nkdl`-rename) by
      direct KDL edit (index.kdl −16). greenm01's `nimkdl` untouched. index.json regenerated;
      `project --check` green in the 2.0.8 container. Only one `package "nimkdl"` block remains.
- [x] **P2.1** (tianguis, 2026-06-07) — **Gate A DONE + verified green (20/20 files).** namespace now
      derived from the verified OIDC SAN in `cmdAddEntry` (`deriveNamespace(args.signedBy)`); `namespace`
      field + `--namespace` flag DROPPED (passing `--namespace` → exit 4 w/ message). Underivable SAN →
      **exit 4** + structured stderr (`reject: namespace-underivable signed_by=… reason=…`) +
      append to `alerts.kdl` (new `formatAlert`/`appendAlert` overload), index unchanged, reject fires
      BEFORE OCI pull. Workflow (`commit-entry.yaml`, Gate B): cosign verify now `--output json`,
      extracts `SAN=$(… | jq -r '.[0].optional.Subject')`, **loud-fails on empty SAN**, exports to
      `$GITHUB_OUTPUT`; add-entry uses extracted SAN as `--signed-by`, `--namespace` gone; `namespace`
      `workflow_dispatch` input + payload key removed. ⚠ **Gate B = Corey's one-time MANUAL smoke**:
      jq path `.[0].optional.Subject` UNVERIFIED vs real cosign v2.4.0 (TODO in workflow) — run a real
      signed publish, confirm SAN non-empty + derived namespace correct.
- [x] **P2.2** (tianguis Go, 2026-06-07) — **DONE + verified green** (go build+vet+test). Deleted the
      Go dispatch `deriveNamespace` (handler.go:157, org-only — the divergent 4th impl, *semantically
      wrong* vs host/org SSOT); dropped `"namespace"` from the dispatch inputs map (handler.go:115);
      fixed `handler_test.go:526` (removed `"namespace":"coreyleavitt"`). `function_test.go` had zero
      refs (confirmed). `strings` import retained (still used by auth-header parser).
- [x] **P2.3** (tianguis docs/fixtures, 2026-06-07) — **DONE + verified green (corpus 44/44, suite
      20/20).** Added 4 OIDC-SAN fixture cases to `spec/fixtures/derive-namespace.json` (cases 40–43):
      (a) GH Actions SAN w/ branch ref → github.com/coreyleavitt; (a) tag ref → github.com/greenm01;
      (c) empty → derrUnparseable; (c) malformed → derrUnparseable — all exercised by
      `tests/test_namespace_corpus.nim`. **Case (b) DROPPED** (the wrong spec assumption, below).
      Rewrote the `signed_by` NORMATIVE block in `docs/spec/index-format.md` (was a P2.3 placeholder):
      author-signed = parseable identity SAN from a trusted keyless-OIDC issuer (Fulcio+Rekor verified),
      canonical GH Actions form, forge-agnostic derivation vs separately-gated issuer-trust spelled out;
      milpa-vendored = freeform provenance, not an identity anchor. Patched RFC P2.3 text to delete the
      "non-github → error" framing + document the spec-error correction. **Phase 2 COMPLETE.**
  > **Spec-error correction (logged):** RFC case (b) "non-github.com SAN → derivation error" was a
  > WRONG assumption (`deriveNamespace` is host-agnostic — `example.com/owner/repo → example.com/owner`
  > via fallback; only empty/malformed→derrUnparseable, no-org→derrNoOrg, gitlab-depth>2→
  > derrGitlabNestedGroup error). Corey's reframing: author-signed namespace derives from a
  > Rekor-verified OIDC SAN; forge is irrelevant; the github-only-ness is a temporary OIDC-**issuer**
  > trust scope at cosign-verify (orthogonal to derivation). Case (b) dropped; RFC + index-format.md
  > patched to document the separation. **Nothing in Phase 2 committed yet (both repos).**
- [x] **P3.1a** (milpa) — `Version` → 3-field `NamedTuple` (drop-in); parse_version still drops
      pre/build (behavior preserved); `eq()` frozen at (M,m,p+1); 8 touch-points + Hypothesis
      strategies updated; 7 pin tests; suite 631/6. **SPEC CORRECTION:** RFC's 5-field vehicle is
      NOT a drop-in (Python tuple compare: `(1,0,0)==(1,0,0,(),())` is False) → used 3-field, pre/build
      DEFERRED TO P3.1b. RFC text P3.1a/b NOT edited (Corey's call).
- [x] **P3.1b** (milpa) — `Version` → custom-total-order class (drop-in for releases); full semver
      prerelease ordering; **eq() = closed-point singleton (CRITICAL fix landed)**; intervals now
      4-tuple (lo,hi,lo_closed,hi_closed); opt-in via floor; lossless lockfile round-trip. Property
      suite 15/15; full suite 674/6 (+43). Regression `eq(1.0.0).contains(1.0.1-rc.1) is False` pinned.
- [x] **P3.1c** (milpa) — operators `~ ^ != =` (compose existing combinators) + `||`/`|` disjunction
      (AND tighter than OR; OR previously raised, now unions). 18 tests; suite 692/6. `_normalize_constraint`
      already passed ~/^/!= through (RFC "strips" was inaccurate; they raised at _parse_clause). **P3.1 DONE.**
- [x] **P3.2** — multi-version named-dep provider. BFS **enumerate-then-solve** done: `resolve_named_all`
      → `list[IndexVersion]` (`resolve_named` delegates to `[0]`, dedup removed); new `_NamedDepStub` +
      `_MaterializedProvider.register_named_stubs`/`_materialize_stub` (Phase A stub enroll, no fetch →
      Phase B lazy fetch+parse on solver-select); `_enumerate_named` replaces immediate-fetch `_process_named`
      in `resolve()` BFS (synchronous — no I/O); `_on_new_named` callback enrolls late transitives (fixpoint).
      Backtracking now works for named deps; TNG-AMBIGUOUS-NAME preserved. `_process_named` retained for the
      `resolve_workspace()` path (not yet migrated). #100 already in §Deferred (line 847). Suite 701/6 (+9).
- [x] **P3.3** — strategy + backtracking for named deps. Mostly validation (SEMVER + SEMVER/prerelease-opt-in
      wiring already correct end-to-end) + ONE root-cause fix: `_on_new_named` now enumerates transitive named
      deps with constraint=None (was pre-filtering by parent's nimble constraint, which blocked the solver from
      ever seeing a _Conflict → no backtrack). Constraint enters as a solver incompatibility via parent dep_terms,
      not by shrinking the candidate set (correct PubGrub). 3 tests; suite 704/6 (+3). Multi-level backjumping
      stays deferred (#28/P3.5); S2 diamond is single-backtrack-level.
- [x] **P3.4** — structured ConflictChain narration (solver.py). `build_conflict_chain` builds
      `{package → list[Incompatibility]}` keyed on each package in an incompat's TERMS (not cause tag);
      returns `ConflictChain(steps: tuple[ConflictStep,...])` (ConflictStep = consequent pkg + parallel
      antecedents/antecedent_constraints + cause_tag). `SolverError(chain)` carries the structured chain;
      `render_conflict_chain(chain)->str` emits multi-line "Because…and…, …"; cli.py:_resolve_or_error prints
      it line-wise indented. Migrated 2 substring-based tests → structural assertions on the chain. comparison
      doc flipped: narration/caret-tilde/prerelease-opt-in = built, build-metadata = "parsed+preserved, ignored
      for ordering", proof-certificate stays research. Suite 707/6 (+3). **P3 DONE → all milpa-autonomous
      slices DONE.**
      LOW (noted, not blocking): empty-version-set step renders "root requires b (empty)" — accurate but
      could be polished; essential diamond step renders correctly.

## 🔑 PHASE 1 PUSHED — TRUST ANCHOR LIVE (2026-06-07)
- **milpa: PUSHED to main** (origin/main @ 130ecd1). 4 commits: docs, P1.2 client,
  P3.1/P3.4 solver, P0.1/P3.2/P3.3 resolver. Suite 707/6. **P1.2 deployed = deploy gate satisfied.**
- **tianguis: PUSHED to origin/main @ `9e277e0`** (`00a831f..9e277e0`). 8-commit anchor series.
  The anchor (`ae10a40`) + workflow milpa-pin (`130ecd1`, in `92943be`) + P1.6 yank (`9e277e0`)
  went live **atomically** — no window where a tuple-keyed index met a pre-P1.2 milpa.
- **⚠️ Bot-rebase wrinkle (handled):** a daily `milpa-bot` vendoring pass (`00a831f`, +612 entries)
  had landed on origin/main built on the PRE-migration base, so the original local anchor wasn't a
  fast-forward. Root-cause fix (migration is a pure transform T): rebased the 6 code/doc commits
  onto `00a831f`, **re-ran `tianguis migrate --execute`** against the bot-updated index (so the 612
  new entries are host/org-canonical), then re-applied the P1.6 yank. Result `2616→2617`, **same
  single split** `nimkdl → {coreyleavitt, greenm01}`; no new conflated identities from the new
  entries. `project --check` green; full tianguis suite 20/20 test files green in the 2.0.8
  container. Anchor commits were rewritten (`df13a35→ae10a40`, `6e1c054→9e277e0`) — fine, never
  pushed before; workflow pins a MILPA sha, not a tianguis sha.
- **Migration result:** 2616→2617, exactly 1 split `nimkdl → {greenm01, coreyleavitt}`; all
  namespaces host/org; `project --check` green; audit record at
  docs/spec/migrations/0001-32-identity.json. index.kdl.bak gitignored (local aid).
- **P1.6 live:** only `github.com/greenm01` nimkdl block remains on origin; bare `nimkdl` now
  re-resolves uniquely to greenm01 (the documented correct #32 repair). **Phase 1 COMPLETE.**
- **NEXT:** Phase 2 (#38 hardening) — `/tdd` P2.1 SAN-derivation → P2.2 drop Go deriveNamespace →
  P2.3 corpus SAN + normative signed_by. (P3 already done; Phase 2 is the last remaining phase.)

## ✅ ALL AUTONOMOUS SLICES COMPLETE (2026-06-07)
Implemented this grind (12 slices, all green, **nothing committed**): P0.1–P0.5, P1.1, P1.2, P1.3,
P3.1a/b/c, P3.2, P3.3, P3.4. milpa suite **707 passed / 6 skipped** (from 617 baseline). tianguis
slices (P0.3, P0.4, P1.1, P1.3) green via the Nim 2.0.8 container.
**Remaining slices are ALL Corey-gated (operational/commit) — the loop stops here by design.**

## Corey-gated (parked, awaiting go-ahead)
- **P1.4** run migration + commit trust anchor — needs commit go-ahead + P1.2 merged to milpa main
  + commit-entry.yaml milpa checkout pinned ≥P1.2 SHA first. Then P1.5/P1.6, then P2.x.

## Notes
- index.json = website projection only (site/scripts/build.py → tianguis.dev, per pages.yaml;
  parity.yaml keeps it in sync with canonical index.kdl). milpa reads index.kdl. The earlier
  "versionToJson drops partiallyResolved" note is a NON-ISSUE (resolver-internal field the site
  never renders) — dropped.

## Environment notes (stage 3)
- **No host Nim.** tianguis slices run in a container:
  `podman run --rm -v "$PWD":/work:Z -w /work docker.io/nimlang/nim:2.0.8 nim c -r --hints:off
  --warnings:off --nimcache:/work/.nimcache tests/test_FILE.nim` (image pulled; deps vendored in
  `_deps/`, resolved via nim.cfg; persistent `.nimcache/` for speed).
- milpa: `uv run pytest` (~6s) on host.
- **#97 already landed** (commits 5af86ad etc.); working tree clean except RFC docs (untracked).
- **Nothing committed** — all slice work left in working trees per standing rule (no go-ahead yet).

## Round 2 results (applied to the RFC — see §6 round-2 changelog for the full list)
- **Critical fix:** P3.1b — `VersionSet.eq(v)=[v,(M,m,p+1))` is UNSOUND under cargo prerelease order
  (`1.0.0 < 1.0.1-rc < 1.0.1` → `[1.0.0,1.0.1)` wrongly contains `1.0.1-rc`; every decision + `==`
  goes through `eq()`). Now: `eq()` must be a true singleton (closed point or domain-successor
  v_next) + property test `eq(v).contains(w) ⟺ w==v`. Verified against solver.py:124–127.
- **Three glances (resolved):** (1) the eq() soundness fix above; (2) intentional fail-closed
  author-publish freeze in P1.4→P2.1 window (coarse guard + org-only Go dispatch) — vendored
  unaffected, sequence P2.1 promptly; (3) P3.2 is a BFS re-architecture (enumerate-then-solve +
  transitive fixpoint, cargo/npm-standard), not a return-type change.
- **Other applied:** §1 P1.2-deploy-before-P1.4 CI gate + P3.1-parallel note; §4.2 MergeOutcome no
  longer bundles index → `mergeVendored` returns `(index, outcome)`; P1.1 acyclicity confirmed;
  P1.2 `lookup_bare → Package|AmbiguousName` (typed, no raise); P1.3 gate-5b example corrected
  (synthetic fixture); P1.4 atomic both-artifact regen + audit record + rollback-reapply + test
  fixture note; P2.1 observable rejection + Gate B manual-only; P2.2 Go is semantically-wrong not
  redundant; P2.3 concrete SAN cases; P3.1a NamedTuple vehicle + Hypothesis strategies + frozen eq()
  boundary; P3.4 structured ConflictChain + index-by-term-package + comparison-doc flip; Deferred
  +lockfile-namespace position.
- **Source-verified this round:** solver.py VersionSet.eq/contains (124–164); test_integration.py:171
  + test_tianguis_integration.py:37 (live `main` URL, no pin); handler.go:162 (Go deriveNamespace
  org-only); milpa has no Python deriveNamespace; realdriver.nim doesn't use MergeOutcome;
  namespace.nim imports only std + nkdl (alerts→namespace acyclic).

## Round 1 results (applied to the RFC — see RFC §6 changelog for the full list)
- **Cross-cutting:** §4.1 `deriveVersionNamespace` → `Result[string]` (not `ForgeRef`) + invariant
  pinned as a *property test*; §4.2 `Option[MergeAlert]` → closed `MergeOutcome` case object
  (compiler-exhaustive; `IdentityDrift`/`DriftAlert`/`IntraOrgCollision` stay in home modules;
  overloaded `formatAlert`); §4.3 `MigrationHalt` payload carries version+provenanceUrl.
- **Ordering (§1):** P3.1 split into P3.1a (type swap, green) / P3.1b (prerelease+opt-in) / P3.1c
  (operators+disjunction); P3.4 made SEQUENTIAL after P3.3 (same file); **window-closing host/org
  guard moved into P1.4's commit** (was P2.1).
- **Three behavior/scope changes worth Corey's glance (resolved, not forks):** (1) P1.1 guard is
  defense-in-depth, NOT org-rename handling — the prior "rename rejected by P1.1" was factually
  wrong; corrected everywhere, #36 owns rename. (2) Existing milpa.lock consumers re-resolve bare
  names; nimkdl→greenm01 re-resolve is the correct #32 repair (documented P1.5). (3) Guard timing
  moved to P1.4.
- **Slice sharpening:** P1.2 register-`TNG-AMBIGUOUS-NAME`-first + bijection lint + qualified
  lookup primary; P1.3 gates 1(in-memory)/1b(full-field identity)/5b(bijection on
  (version,content_hash))/6b(canonicalize pin); P1.4 `--execute` UX; P2.1 SAN-extraction ownership
  (workflow extracts, binary derives) + workflow-YAML gate + jq-path-verify-first + corrected rename
  note; P2.2 dropped wrong `function_test.go` cite; P3.2 provider-contract change explicit + #100
  multi-constraint boundary + `_deps`/nim.cfg note; P3.3 likely thin; P3.4 reverse-index algorithm
  (cause is a str tag, not a pointer) + multi-line CLI display.
- **Source-verified:** `namespaceString` exists (namespace.nim:31); `MergeOutcome` has 2 parallel
  Options (merge.nim:35–38); `IdentityDrift` in namespace.nim:187; test files
  test_namespace_oidc/test_vendor_{merge,alerts,orchestrate}.nim exist; milpa #100/#103/#28 open,
  **#90 CLOSED+unrelated** (wrong cite removed from RFC); tianguis #36/#38 open.
- **Issue filed (defer-file-now):** tianguis **#39** — cross-path git↔OIDC agreement check (was
  `checkOidcGitAgreement`, deleted P0.4).
- **RFC:** `milpa/docs/rfc-identity-and-resolution-completion.md` (cross-repo: tianguis + milpa).
- **Supersedes:** `tianguis/docs/rfc-identity-completion.md` (twice-reviewed; content carried
  forward). That doc + its handoff are marked SUPERSEDED.

## Why consolidated (Corey, 2026-06-07)
Three threads (tianguis #32 identity, #38 security, milpa resolver-core gaps) wrapped into ONE
RFC because the **ordering is the deliverable** and it's cross-repo. Earlier this session: #32
identity-completion passed architect rounds 1+2; the open escalation (`checkOidcGitAgreement`
unwireable) + the #38-split question were both resolved by Corey → delete the dead proc, and
**fold #38 back in** (don't split). Then Corey asked whether the *milpa resolver* is actually
best-in-class; grounded audit said identity layer yes, resolution core no → resolver-core work
added as Phase 3.

## Master ordering (the spine — see RFC §1 for the diagram + per-edge rationale)
- **Phase 0** (independent, first): P0.1 milpa `VersionSet.all()` crash fix; P0.2 correct
  comparison doc over-claims; P0.3 tianguis SSOT `deriveVersionNamespace`; P0.4 delete
  `checkOidcGitAgreement`; P0.5 correct S6 spec (precondition).
- **Phase 1** (identity migration): P1.1 immutability guard + MergeAlert (needs P0.3); P1.2
  milpa parse_index tuple-key (independent, gates P1.5); P1.3 pure migrateIndex (needs P0.3,
  P0.5); **P1.4 run migration + COMMIT = the cross-repo sync point / new trust anchor** (needs
  P1.3); P1.5 post-migration cross-repo smoke (needs P1.4 + P1.2); P1.6 yank stale entry.
- **Phase 2** (#38, right after P1.4 to close the write-back window): P2.1 author-signed ns from
  verified OIDC SAN + window guard; P2.2 delete Go dispatch deriveNamespace (4th impl); P2.3
  corpus SAN cases + normative signed_by format.
- **Phase 3** (milpa resolver core): P3.1 semver model (prerelease+build-meta+ `~ ^ != = ||`) =
  foundation; P3.2 multi-version named-dep provider (needs P1.2 + P3.1); P3.3 strategy +
  backtracking for named deps (needs P3.2); P3.4 PubGrub cause-chain narration (parallel).
  **Deferred:** P3.5 conflict-learning + backjumping → milpa#28 (perf, not correctness).

## Key decisions (carried + new)
- `checkOidcGitAgreement` DELETED (no reachable site; #38 closes without it).
- #38 FOLDED IN (Corey reversed the earlier split-out).
- Resolver core: narration IN (the differentiator we claim but lack); backjumping DEFERRED (#28).
- SSOT discriminant = provenance-presence, not the `attestation` string. `AttestationAnchor` sum
  rejected as over-machinery.
- One cross-repo sync point = P1.4 (migrated-index commit). Everything after consumes it.

## Verified against source (this session)
- model.nim: `Version.provenances: seq[Provenance]` (not scalar); `canonicalize` idempotent,
  sorts by (namespace,name). merge.nim: `mergeVendored(entry: VendoredEntry)`; line 99 is the
  loop match; `buildVendoredEntry` sets `upstream == provenances[0].url`. dispatch/handler.go:
  115/157 org-only Go `deriveNamespace`. milpa: `VersionSet.all()` missing (is `full()`);
  `parse_version` drops prereleases/build-meta; `Strategy` dead for named deps; `Assignment.cause`
  never walked for narration.

## Out of scope (recorded)
- #37 gitlab nested groups (0 in live index); #36 cross-identity unification; milpa #90
  transitive Local/Tarball/Member deps; profile-aware transitive filtering.

## Related/paused
- milpa #97 resolver→tianguis-index swap: stage-4-complete, ship-ready pending commit
  (uncommitted M lockfile.py/resolver.py/test_lockfile_v2.py). This RFC builds ON post-#97 milpa.
  See `milpa/docs/rfc-resolver-tianguis-swap.handoff.md`.
