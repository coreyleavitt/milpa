# rfc-identity-and-resolution-completion — handoff

- **Stage:** 3 tdd — **PHASE 0 COMPLETE** (P0.1–P0.5). Grinding slices via delegated sonnet /tdd
  subagents, one progress line each.
- **Resume:** stage 3 — `/loop implement the next unimplemented RFC slice from
  docs/rfc-identity-and-resolution-completion.md with /tdd, following the standing rules; report one
  progress line per slice; stop when every slice is implemented`. **Next slice = P1.1** (tianguis;
  needs P0.3 ✓). **Safe to `/compact` first.**
  Mind: P2.3 is **edit-only (no RED state)**; **P1.2 must merge+deploy before P1.4**
  (milpa integration tests hit live `main`); P3.1 can run parallel to Phase 0/1.

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
- [ ] P1.5 (cross-repo manual — needs committed index) ; P1.6 (tianguis — needs P1.4)
- [ ] P2.1 / P2.2 / P2.3 (#38 hardening) — **transitively P1.4-gated**: P2.1 "promotes" P1.4's
      host/org guard to SAN-derivation, so it should follow P1.4. Parked with P1.4.
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
