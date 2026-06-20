# Features / optional / patch (#23) — handoff

- **Stage:** 4 code-review — **✅ COMPLETE (FLOOR REACHED at round 11). AWAITING COREY'S
  COMMIT GO-AHEAD.** Mandate (Corey): fix all through Medium, loop until only trivial Lows remain.
  Floor = round 11 surfaced 0 Critical/High/Medium on the #23 surface (Design conclusively clean;
  Security's lone finding R11-S1 REFUTED; Cross-impl confirmed #23 surface byte-identical, 2
  out-of-scope substrate divergences FILED #164). Nothing committed; HEAD = `2e48e73` (DO NOT
  COMMIT until Corey asks). 11 review rounds total. Final state: **Python 1993 passed / 13 skipped
  / 1 xfailed; Rust all crates ok (62 conformance + 381 core + …); parks={fixture-099,144} (the 2
  pre-existing #154/#153 baseline reds, unrelated to #23); bijection intact (189 slugs).**
  **Resume (if reopened):** nothing pending — loop terminated at floor. Commit only on Corey's word.

## FINAL VERDICT (Stage 4 complete)
- **Floor reached round 11.** Severity trend by round: R1 (2C/6H/11M) → R2 (2C/1H/+M) → R3 (1C/1H/1M)
  → R4 (0C/2H/4M) → R5 (0C/1H[R5-H2]/…) → R6 (1H/2M) → R7 (0H/2M) → R8 (0H/2M) → R9 (0H/1M) →
  R10 (0H/1M) → **R11 (0C/0H/0M on #23 surface).**
- **Differential-blind-spot finds (both impls wrong identically — corpus-green but buggy; the
  high-value catches):** R5-H2 conditional local/tarball/member deps dropped `when` predicates;
  R6-F1 flag-predicate-ref check UrlDep-only in Python; R6-F3 MemberDep name injection; R7-D1
  optional-flag-clash scope; R7-S1 lockfile src_dir injection; R8-S1 lockfile dep-name/alias
  traversal; R10-X1 valid_dep_name `$`-vs-fullmatch (newline injection + divergence). All fixed
  cross-impl + TDD fixtures (215-242).
- **Spec-determined cross-impl alignments:** H3 Rust→identity-keying; R4-H1 Rust §470 absent-profile
  flag-only filtering; Option-A Rust CLI host-detection (cli-contract §8).
- **Filed follow-ups (out-of-#23-scope / deferred, all tracked):** #157 EdgeSet double-parse,
  #158 lockfile root_active_flags exact frozen check, #159 Python Profile optional-axes,
  #160 workspace+features arm, #161 dup-key KDL divergence, #162 deps/dev-deps spec hole,
  #163 format_manifest when-predicate round-trip, #164 float-as-int coercion divergence.
- **Remaining Lows (left per mandate):** FlagRequest.name parse-validation (no exploit path);
  DoS guard RuntimeError→MilpaError (conformance-invisible); lockfile active_flags parse-validation
  (defense-in-depth, emit-gate-protected); lazy imports (flag_enables_closure ×6,
  dep_passes_flag_predicates ×4); _desugar_dep closure mutable-state smell; valid_dep_name vs
  valid_flag_name naming skew; Rust MilpaKdlEdgeSource ignores ctx.active_flags (S4a corrects);
  multi-value partial-undeclared flag-pred fixture gap; non-slug error-message-wording nits;
  block-comment nesting-depth guard asymmetry (folded into #164).
- **DO NOT COMMIT** — entire working tree (all 11 rounds of fixes) awaits Corey's explicit go-ahead.

## POST-FLOOR (Corey reopened): clear Lows + fix the 3 real divergences
- ✓ **LOWS DONE+VERIFIED** (agent a5467d959ebac05a7): L1 hoisted 12 in-body imports → module-level
  (flag_enables_closure stays in manifest, dep_passes_flag_predicates in predicate.py leaf; grep-proven
  none remain); L2 `_desugar_dep`→ module-level `_desugar_one_dep` (explicit params); L3 S4a cap guard
  RuntimeError→MilpaError(MILPA-INTERNAL) both raise sites + test; L4 fixture-243 (multi-value/stacked-when
  undeclared flag → MAN-FLAG-UNDECLARED-REFERENCE). Gate: Python 1995 passed; Rust all ok; HEAD 2e48e73;
  parks={099,144}. NOTE: `when flag="a" "b"` — the 2nd value is a positional arg, silently ignored by
  BOTH impls (no divergence); multi-value-OR-in-when spelling is a latent grammar question (not chased).
- **Corey: FIX ALL THREE divergences now (#161,#163,#164).** Directions chosen (recommendable):
  #161 → Rust props() adopt KDL 2.0 last-wins (match kdl-py). #164 → integer fields REJECT `1.0`
  (Python aligns to Rust; reuse MAN-SPEC-VERSION-TYPE / MAN-DEP-TARBALL-STRIP; no new slug).
  #163 → serialize when-block predicates for all 5 dep forms in format_manifest + Rust serializer,
  strip optional auto-gate, + round-trip property test + fixture.
- ✓ **BATCH 1 DONE (agent a1eb54a4a51dcb87f) — verify in progress.** #161: Rust `props()` now
  KDL 2.0 last-wins (HashMap last-index dedup); fixture-244. #164: Python kdl-py switched to
  `nativeUntaggedValues=False` (so int `1` vs float `1.0` are distinguishable via kdl.Decimal.mantissa
  type); `_kdl_val_to_milpa` handles Decimal/Bool/Null; `value_as_strict_int` + isinstance-float checks
  at spec-version + strip_components → reject `1.0` (existing slugs MAN-SPEC-VERSION-TYPE /
  MAN-DEP-TARBALL-STRIP, no new slug); value_as_int keeps float-coercion for dep_decl/lockfile/registry
  callers; fixtures 245,246. Comment-nesting Low: Rust `kdl_block_comment_depth` added + wired at 4 call
  sites (MAN/TNG/LOCK/depdecl KDL-SYNTAX); fixture-247. Agent-claimed gate: Python 1999 passed; Rust all
  ok; HEAD 2e48e73; parks={099,144}. **Re-verifying myself (bg brbg2rhto) — #164 touched the core KDL
  value seam, so the conformance byte-identity check is the key proof.**
- **Batch 2 (NEXT, after batch-1 verify — shares manifest.py): #163** serializer round-trip — emit
  when-block predicates for all 5 dep forms in format_manifest (Python) + Rust serializer (format.rs),
  strip the optional auto-gate, + round-trip property test + fixture. Cross-impl byte-identical.
- HEAD must stay 2e48e73; DO NOT COMMIT. When all done: close #161/#163/#164; report to Corey.
- ✓ **BATCH 1 VERIFIED GREEN** (bg brbg2rhto): Python 1999 passed, Rust 13/13 ok no failures, HEAD
  2e48e73, parks={099,144}, fixtures 244-247. #161/#164/comment-nesting CLOSED. #164 core-seam change
  (nativeUntaggedValues=False) confirmed byte-identity-safe by full conformance corpus.
- **BATCH 2 (#163) RUNNING (agent a5ef0fcaf3b63d586):** serialize when-block predicates for all 5 dep
  forms in format_manifest (Python) + Rust format.rs; canonical form = `when <preds> { <dep> }` per dep
  (universal — member nodes take no inline props); strip optional auto-gate → `optional=#true`; round-trip
  PROPERTY test both impls + fixture; update any existing fixture/test that assumed the old
  predicate-dropping serializer. May STOP on a serialization-form fork.
- ⚠ **BATCH 2 (#163) AGENT CRASHED** (a5ef0fcaf3b63d586 died on transient 401 auth error after ~146s/
  23 tool-uses). It EDITED impls/python/milpa/manifest.py (mtime 00:03) but did NOT reach Rust format.rs
  → likely a ONE-SIDED partial #163 edit (Python only) that may break cross-impl byte-identity. manifest.py
  still IMPORTS OK (no syntax break). **RECOVERY IN PROGRESS:** running real gate check (bg bwfhsoay0:
  full pytest + rust conformance + manifest.py diff numstat) to determine if the partial edit broke the
  tree. 
  - If gates GREEN → partial edit was harmless/no-op → re-launch #163 fresh.
  - If gates RED → must surgically reconcile: the dead agent's #163 manifest.py edit must be completed
    (Python format_manifest when-block emission) AND mirrored in Rust format.rs, OR reverted. CANNOT
    `git checkout manifest.py` (would lose ALL 11 rounds of uncommitted work in that file). The fresh
    #163 agent should reconcile the partial state as step 0.
- Batch 1 (#161,#164,comment-nesting) CLOSED+VERIFIED (Python 1999, Rust green). HEAD 2e48e73.
- **DIAGNOSIS:** tree is GREEN (Python 1999, Rust unchanged/green) — the crashed agent's partial
  manifest.py edit (`_format_predicate_props` + inline-props emission in format_manifest) is DORMANT
  (no test exercises format-on-conditional-deps). NOT broken; just half-done + Python-only + untested.
  Inline-props form can't handle MemberDep (no node props allowed).
- **RECOVERY AGENT RUNNING (a40b5b97a442283ab):** complete #163 — switch to universal `when <preds>
  { dep }` block form (works for all 5 forms), mirror in Rust format.rs, optional auto-gate →
  `optional=#true`, round-trip property test BOTH impls + fixture (will exercise+validate the new code),
  update any existing fixture expecting old output. Byte-identical both impls.
- **✅ #163 COMPLETE + RE-VERIFIED (a40b5b97a442283ab returned; I re-ran both gates myself).**
  Canonical form = universal `when <preds> { <dep> }` block for NamedDep/LocalDep/TarballDep/MemberDep
  (UrlDep keeps inline props, unchanged). Rust format.rs mirrors byte-identically. Tests: Python
  `TestConditionalDepRoundTrip` (9 unit) + `test_conditional_dep_predicates_survive_round_trip`
  (Hypothesis, 150 ex); Rust 7 `*_round_trips` + `parse_format_parse_cycle_preserves_conditional_dep`.
  Fixture-248-when-named-dep-excluded added. **Independently verified:** Python 2010 passed / 13 skipped
  / 1 xfailed; Rust 62 conformance + 381 core + all crates 0 failed; HEAD `2e48e73`; parks={099,144};
  bijection green (test_errors.py + Rust error_codes_match_the_spec). ALL THREE divergences (#161 dup-key
  last-wins, #163 serializer round-trip, #164 float-as-int) now FIXED + verified.
- **Resume:** ALL fix work done + verified. Outstanding: close #161/#163/#164 (via `closes` in the
  commit), then await Corey's explicit COMMIT go-ahead. DO NOT COMMIT until Corey asks.

## Round 4 (current)
Rounds 1-3 done (R3a convergence Critical + R3b dead-slug both verified green:
Python 1977 passed, Rust all ok, HEAD 2e48e73, bijection intact, parks={099,144}).
Round-4 re-review (Security + Design + Cross-impl) returned **0 C / 2 H / 4 M / 3 L**.
Round-3 convergence Critical confirmed clean+symmetric; all bijection/ordering/identity
checks byte-identical. Disposition:
- ✓ **FIX-SEC DONE+VERIFIED:** Security-M — transitive `.nimble` `srcDir` now validated at
  edge-source boundary (both impls) via SSOT `contains_unsafe_char` (made `pub`/exposed, no
  regex dup); raises MAN-SRC-DIR-UNSAFE; fixture-227-nimble-srcdir-unsafe (red→green).
  Rust `NimbleEdgeSource::edges_for`/`resolve_edges` now return `Result` (4 `?` call sites
  in resolver.rs). Combined gate (FIX-SEC + FIX-DESIGN): Python 1977 passed; Rust all ok
  (51 conformance / 381 core); HEAD 2e48e73; parks={099,144}; fixture-227 not parked.
- **FIX-DESIGN (Python-only, refactor-under-green) — DONE except H-D1:**
  - ✓ H-D2a: trimmed apologetic comment-mass in `_check_frozen_active_flags_mismatch`
    (logic unchanged; exact check tracked in #158).
  - ✓ M-D1: folded `find_newly_admitted_deps` into `_s4a_run_fixpoint`/S4b one-pass (match Rust).
  - ✓ M-D2: removed dead `dep_name` param from `compute_cross_pkg_enables`; call+test sites updated.
  - Gate after FIX-DESIGN: Python 1977 passed; HEAD 2e48e73; zero Rust/fixture touched.
  - ⚠ **H-D1 REFUTED + escalated into R4-H1 (see below).** Agent correctly STOPPED:
    Python's `_filter_manifest_by_flags_only` and `_filter_manifest_by_profile` are NOT
    duplicates — they are semantically distinct (flag-only vs full-predicate). The flag-only
    one exists to honor resolver-semantics §470 (absent profile ⇒ predicate filtering disabled).
    Collapsing Python into Rust's synthetic-Profile pattern would BREAK §470. Design agent
    mis-diagnosed the direction.
- **R4-H1 (NEW, HIGH — cross-impl divergence + Rust §470 violation):** Rust's
  `resolve_with_features` `None if has_cli_features` arm (resolver.rs ~228-243) synthesizes
  an **all-None** `Profile` and runs full `filter_manifest_by_profile`, which PRUNES every
  `platform`/`arch`/`nim`/`milpa`-gated dep when `--features` is active and no
  `MILPA_TARGET_*` is set (the common Rust-CLI case — `profile_from_env()` returns None).
  Python includes those deps (flag-only filter). Violates **resolver-semantics.md §470
  NORMATIVE** ("absent profile ⇒ filtering disabled, every dep included regardless of
  predicates") + the byte-identity non-negotiable. Corpus doesn't cover features+absent-profile.
  **Spec-determined fix (NOT a fork):** Rust `None if has_cli_features` must do FLAG-ONLY
  filtering (active-flag closure via `dep_passes_flag_predicates`), no platform pruning —
  mirroring Python row 2. Add conformance fixture (features + absent profile + platform-gated
  dep). Add Python clarifying comment on the two filter fns so they're never "unified" again.
  Serialize AFTER FIX-SEC (both touch Rust + add a fixture).
  - ✓ **R4-H1 DONE+VERIFIED:** Rust arm rewritten to flag-only `retain` via SSOT
    `dep_passes_flag_predicates` (no synthetic Profile); BONUS the agent also fixed
    `milpa-conformance/src/runner.rs` `fixture_profile` (was returning `Some(all-None)` when
    only `MILPA_CLI_FEATURES` set — now returns `None`, mirroring CLI `profile_from_env`, so
    the absent-profile arm is actually exercised). Python: 21-line invariant comment above the
    two filter fns. fixture-228-features-absent-profile-platform-dep (red: Rust dropped
    platformlib → green: both impls emit flaglib+platformlib). Gate: Python 1978 passed; Rust
    all ok (51 conformance / 381 core); HEAD 2e48e73; parks={099,144}; fixture-228 not parked.

### Round-4 fix batch COMPLETE — all gates green. Round-5 re-review launching.

## Round 5 — PAUSED ON ESCALATION (profile host-default fork)
Round-5 re-review returned (Design + Cross-impl in; Security pending). The cross-impl
Medium traced to a **pre-existing cross-impl divergence #23 merely exposed**:

- **Spec:** cli-contract §8 (lines 888-930) + table 1215 — `MILPA_TARGET_*` default to
  **auto-detected host** (platform/arch); the NOTE names Python `Profile.from_environment`
  as the canonical reference. resolver-semantics §470 — a *genuinely absent* profile
  (conformance runner, NO env file) disables filtering.
- **Python = spec-correct** (`from_environment` does `... or _detect_platform()`).
- **Rust = NON-CONFORMANT**: `profile_from_env` returns None when no `MILPA_TARGET_*`;
  Rust has NO host detection (grep: no `env::consts::OS`/`ARCH`, no detect_platform). So
  Rust CLI never host-defaults → `milpa fetch --features X` (no target) includes
  platform-gated deps that Python prunes against host. Pre-existing (#26/profile-era),
  latent (all prior platform fixtures set MILPA_TARGET_PLATFORM explicitly).
- **My round-4 R4-H1 fix was directionally off**: made Rust's `None if has_cli_features`
  arm flag-only (include-all) citing §470 — correct for a TRUE absent profile (library/
  no-env), but it MASKED, not closed, the CLI host-default divergence.
- **fixture-228 is host-fragile** (I introduced it round 4): asserts `platform="linux"`
  dep unconditionally included under features-only env; passes only because this dev host
  is linux — would FAIL Python on mac/windows CI.

**COREY DECIDED → Option A: fix Rust host-detection now (root-cause, honor cli-contract §8).**
Decomposition (fixture survey: every target-setting fixture sets all 3 axes; NO partial-profile
fixture; fixture-228 is the only no-target case ⇒ partial-axis asymmetry is NOT corpus-exercised):
- **FIX-A1 (Rust-only, agent a77b9ccbfc3b42cd1):** Rust CLI `profile_from_env` host-defaults
  platform/arch (std::env::consts → Nim vocab map mirroring Python `_OS_MAP`/`_ARCH_MAP`
  OUTPUT: macos→macosx, x86_64→amd64, aarch64→arm64, x86→i386, …) + nim/milpa defaults, so
  the CLI Profile is always fully populated like Python. Pure mapping fns + unit tests. Corpus
  UNCHANGED (runner stays None for no-target → host-independent; CLI host-default is unit-tested,
  not corpus-tested). 
- **FIX-A2 (Python test+spec, agent a68298ca28cb11124):** Python conformance runner
  `_fixture_profile` returns None when no `MILPA_TARGET_*` set (mirror Rust runner) → fixture-228
  host-independent via §470 absent path. Sharpen resolver-semantics §470 note: absent ⇔ no
  `MILPA_TARGET_*` axis set (not merely "no env file").
- **R4-H1 Rust arm change KEPT** (§470-correct for genuine absent profile).
- **Follow-ups FILED:** #159 (Python Profile → optional axes; partial-profile parity; latent,
  #26 scope) and #160 (workspace seed path missing absent-profile+features arm; blocked on #25).
- ✓ **FIX-A1 + FIX-A2 DONE+VERIFIED.** Rust CLI host-defaults platform/arch (11 unit tests
  for the vocab map; macos→macosx, x86_64→amd64, aarch64→arm64, x86→i386), milpa_version→own
  version; corpus runner unchanged. Python runner returns None for no-target + §470 note
  sharpened; +1 unit test. Combined gate: Python 1979 passed; Rust all ok (62 incl. host-map
  tests / 381 core); HEAD 2e48e73; parks={099,144}; fixture-228 host-independent.
  - nim-version: Python cli.py calls `from_environment()` with NO nim arg → nim defaults to
    "0.0.0" (does NOT query `nim --version`); Rust leaves nim None (predicate-eval → matches
    nothing). Agree on all realistic (`>=`/`<`) cases; differ only on absurd `when nim="0.0.0"`
    plain-equality (corpus-invisible, covered by #159 Profile-optional-axes). No action.
- ✓ **FIX-DESIGN2 Fix-1 DONE:** compute_cross_pkg_enables signature tightened to
  (flags, active_flag_names)→dict[str,list[FlagRequest]]; call+4 test sites updated;
  Python 1979 green. Fix-2 STOPPED → surfaced **R5-H2** (below).
- **R5-H2 (NEW, HIGH — shared spec violation, BOTH impls, not a divergence):**
  spec/manifest-grammar §3.3 requires all FIVE dep forms support `when`-conditional syntax,
  but `LocalDep`/`TarballDep`/`MemberDep` carry NO predicates field in EITHER impl and the
  parsers DROP the enclosing `when` block's predicates for them. So `when flag="x" { mylib
  local="..." }` / `when platform="windows" { winlib local="..." }` include the dep
  UNCONDITIONALLY (masked by Python `getattr(dep,"predicates",())` + Rust `Dep::predicates()`
  catch-all empty). Corpus green because both wrong identically (shared-upstream blind spot).
  Spec-validated (§3.3 lines 311-312). In #23 surface (flag-gated optional/patch local/tarball).
  **FIX-COND (agent a1db21dfde104183d) — cross-impl TDD vertical:** add predicates to the 3
  variants + thread when-block preds in both parsers + extend Rust Dep::predicates() + replace
  Python getattr with direct access (completes the Dep-predicates contract) + shared
  host-independent fixtures (flag/platform-gated local/tarball/member, red→green) + verify
  optional-desugar interaction. Then round-6 re-review.
  - ✓ **R5-H2 / FIX-COND DONE+VERIFIED.** LocalDep/TarballDep/MemberDep (+NamedDep parser
    path) now carry+thread `when` predicates in BOTH impls; Rust Dep::predicates() 5-arm +
    expand_dep_child; Python getattr→direct everywhere (Dep-predicates contract closed).
    optional= is url/named-only (spec MAN-DEP-*-PROPS) → no desugar interaction; `when flag{
    named optional}` composes (AND) correctly. fixtures 229-232 (red→green). Gate: Python
    1983 passed; Rust all ok (62/381, 654 total); HEAD 2e48e73; parks={099,144}; fixture-115
    (NamedDep conditional) still green ⇒ no regression.

### Round 6 re-review — Design + Cross-impl IN (both independently found F1+F2); Security pending.
NOT the floor — 1 High + 1 Medium found (both in predicate handling, both clear-best/spec-determined):
- **R6-F1 (HIGH, cross-impl divergence — VERIFIED by me + both agents):** Python
  `_check_flag_predicate_references` (manifest.py:579-580) is `isinstance(dep, UrlDep)`-only;
  Rust (lib.rs:1094) walks ALL five forms across `deps`+`dev_deps` via `dep.predicates()`. So
  `when flag="undeclared" { mylib local/named/... }` → Rust raises MAN-FLAG-UNDECLARED-REFERENCE,
  Python accepts. Uncovered by corpus (229-232 use declared flags). **FIX (Python-only +
  fixture):** drop the isinstance guard, walk all five forms over deps AND dev_deps; update
  docstring; add fixture `when flag="undeclared"` on a LocalDep → MAN-FLAG-UNDECLARED-REFERENCE.
- **R6-F2 (MEDIUM, latent serialization divergence — VERIFIED by both agents):** Rust
  `merge_predicates` (lib.rs:1808) sorts inline+child predicates by name; Python (manifest.py
  ~1378) preserves source order. UrlDep with 2+ inline preds in non-alpha order → different
  predicate-tuple order (behaviorally inert — eval is existential — but diverges if predicates
  serialize into require/lockfile records). **FIX (decision: SOURCE ORDER both):** remove Rust's
  sort so both use source order (outer, inline, child as written); add NORMATIVE note to
  manifest-grammar §6; add fixture (UrlDep platform= before arch=). If removing the sort breaks
  a Rust dedup/equality test → agent STOPS + reports (would reconsider sorted-both).
- **R6-F3 (MEDIUM, nim.cfg injection, BOTH impls — Security agent):** MemberDep positional-arg
  name bypasses dep-name charset validation (member short-circuits before the check: Python
  manifest.py ~1241, Rust lib.rs ~1323). `member "foo\nbar"`/`member "--path:evil"` →
  ResolvedDep.name → nim.cfg `--path:` in workspace resolution. Same class as R2-C1, missed for
  member. **FIX (both impls):** validate member name vs SSOT charset at parse → MAN-DEP-NAME-INVALID
  (existing slug); fix wrong Rust comment lib.rs ~772; fixture (member bad name → parse error).
- Round-6 Lows/clean: host-vocab maps confirmed symmetric (no drift); MAN-NIMBLE-PARSE known
  Rust-unreachable asymmetry (corpus-exempt, not new); predicate threading symmetric for all
  5 forms except the F1 validation gap + F2 ordering; DoS bounded by KDL depth-32 nesting guard.
- ✓ **FIX-R6 DONE+VERIFIED (F1+F2+F3).** F1: Python `_check_flag_predicate_references` walks
  all 5 forms (guard removed). F2: Rust `merge_predicates` sort removed → source order both;
  manifest-grammar §6.6 NORMATIVE ordering clause (old §6.6→§6.7); 0 Rust regressions. F3:
  MemberDep name charset-validated both impls → MAN-DEP-NAME-INVALID; Rust comment ~772 fixed.
  fixtures 233 (undeclared-flag-on-local), 234 (predicate-source-order), 235 (member-bad-name).
  Gate: Python 1986 passed; Rust all ok (62/381); HEAD 2e48e73; parks={099,144}; bijection intact.

### Round 7 — Security IN (1 Medium R7-S1); Design + Cross-impl pending.
- **R7-S1 (MEDIUM, nim.cfg injection at lockfile trust boundary — BOTH impls, pre-existing/
  not-#23-specific):** lockfile READ path doesn't validate `src_dir` vs `contains_unsafe_char`
  (Python lockfile.py:512 `_parse_dep_scalar_str` for src_dir; Rust frozen.rs:346
  `locked.src_dir.clone()`). Manifest + edge-source paths validate (round-4), but a poisoned
  lockfile's src_dir → nimcfg `--path:` on frozen reconstruction. **Disposition pending full
  round-7** — if it's the only Medium, FIX it (mandate=fix-through-Medium; floor needs 0 M):
  add contains_unsafe_char guard on lockfile/frozen src_dir read in BOTH impls; likely needs a
  LOCK-SRC-DIR-UNSAFE slug (update all 3 catalog sources + bijection) or reuse an existing
  lockfile-validation slug; fixture (poisoned-lockfile src_dir → reject). Round-6 checks clean.

- **R7-D1 (MEDIUM, cross-impl divergence — Design agent, spec-VALIDATED):** Python
  `_desugar_optional_deps` namespace-hygiene check guards `isinstance(dep,(UrlDep,NamedDep))`
  (manifest.py:746), Rust walks all 5 forms. A non-optional Local/Tarball dep named == a
  declared flag → Rust raises MAN-DEP-OPTIONAL-FLAG-CLASH, Python accepts. spec/errors.md
  §463-464 says "a NON-OPTIONAL dep shares a name with a declared flag" — NO form restriction
  ⇒ **Rust correct, Python bug.** FIX (Python-only): compute is_optional (Url/Named-and-optional
  only), check `not is_optional and name in declared_flag_names` for ALL forms; + fixture
  (non-optional local dep named == declared flag → MAN-DEP-OPTIONAL-FLAG-CLASH).
- Round-7 Lows: R7-S1 reclassified Low by Design (Security said Medium — keeping Medium);
  flag_enables_closure lazy-imported at 6 sites (same class as carried import Low — leave/or
  move to predicate.py opportunistically).
- **Round-7 cross-impl agent: NO Critical/High.** 3 Lows: (1) dup-key prop divergence
  (Python kdl-py last-wins vs Rust kdl preserves-all → divergent predicates on `flag="a"
  flag="b"`; KDL substrate, not #23) → **FILED #161**; (2) missing fixture negated-flag on
  non-Url dep; (3) missing fixture undeclared-flag via dev-dep. Predicate ordering / member
  charset / 5-form scan all confirmed symmetric. Bijection intact.
- **FIX-R7 (agent aba3c7032d1f879d2) — cross-impl TDD batch:** R7-D1 (broaden Python
  optional-flag-clash to all 5 forms, spec-validated; fixture), R7-S1 (validate src_dir at
  lockfile-PARSE boundary both impls, reuse-or-add LOCK-SRC-DIR-UNSAFE slug + bijection;
  fixture), + 2 coverage fixtures (negated-flag-on-local, undeclared-flag-via-dev-dep; expected
  to pass immediately — if not, NEW divergence → STOP). Then round-8 re-review.
- Filed follow-ups now: #157,#158,#159,#160,#161.
- ✓ **FIX-R7 DONE+VERIFIED.** R7-D1: Python optional-flag-clash broadened to all 5 forms
  (is_optional = Url/Named-and-optional; check `not is_optional and name in declared_flags`);
  fixture-236. R7-S1: src_dir validated at lockfile-PARSE boundary BOTH impls (Python
  lockfile.py:522, Rust lockfile.rs:158) via SSOT contains_unsafe_char; NEW slug
  LOCK-SRC-DIR-UNSAFE in all 3 catalog sources (errors.md:423, errors.py:121, Rust error.rs:128)
  + raised → bijection intact; fixture-237. Coverage fixtures 238 (negated-flag-local) + 239
  (undeclared-flag-dev-deps) GREEN immediately in both impls (NO new divergence — confirms
  symmetry). Gate: Python 1990 passed; Rust all ok (62/381); HEAD 2e48e73; parks={099,144}.

### Round 8 — Design IN (1 Med + 2 Low); Security + Cross-impl pending.
- **R8-D1 (MEDIUM, SSOT violation — Python):** `contains_unsafe_char` declared SSOT (manifest.py:200)
  but bypassed by 2 in-module call sites (manifest.py:935, 2168) using `_UNSAFE_STRING_RE.search`
  directly. Inert today (same regex) but breaks SSOT discipline. FIX (Python-only): route both
  through `contains_unsafe_char`; restrict `_UNSAFE_STRING_RE` to the SSOT fn only.
- **R8-D2 (LOW):** Python optional-flag-clash hint "mark optional=#true" (manifest.py:756) invalid
  for Local/Tarball/Member; minor message-wording divergence from Rust (slug identical → NOT a
  byte-identity break; corpus compares slugs). FOLD into R8-D1 fix (cheap, co-located): branch the
  hint on isinstance((UrlDep,NamedDep)).
- **R8-D3 (LOW, leave per mandate):** `_desugar_dep` nested-closure mutable-state smell (manifest.py
  ~766) — pull to module-level helper w/ explicit out-params someday.
Trend converging: R6=1H+2M, R7=0H+2M, R8 so far 1M. All fixes through round 7 verified.
Filed follow-ups: #157-161.
- **Round-8 Cross-impl: ZERO byte-identity divergences** across #23 surface (all 6 blind-spot
  probes symmetric: deps+dev-deps, cross-pkg-enable-on-when-gated, optional-auto-flag vs
  cross-pkg-flag, multi-value flag pred on local, patch-on-when-gated, lockfile-roundtrip of
  predicates [predicates NOT serialized — correct]). Bijection intact incl LOCK-SRC-DIR-UNSAFE.
  1 Low: spec hole — dep non-optional in `deps` + optional in `dev-deps` (both impls agree/no
  error; spec undefined) → file a small spec-clarification issue (no divergence risk).
- **R8-S1 (MEDIUM, path-traversal + nim.cfg injection via poisoned lockfile; BOTH impls —
  Security agent):** lockfile dep `name` + `aliases` NOT charset-validated at parse (only src_dir
  was, R7-S1). `dep "../evil"` → nim.cfg `--path:"_deps/../evil"` + `_deps/../evil` symlink escape.
  CRITICAL: `../evil` has no control chars → must validate with DEP-NAME CHARSET (rejects `/`,`.`),
  not contains_unsafe_char. Security agent enumerated ALL lockfile fields → name+aliases are the
  LAST unvalidated reaching a sink (completes lockfile-hardening class). FIX (both impls): charset-
  validate name+aliases at lockfile parse → NEW slug LOCK-DEP-NAME-INVALID (3 catalog sources +
  bijection); fixture-240. STOP-guard given: confirm URL-tail-derived names can't legitimately
  contain non-charset chars before tightening.
- Filed deps/dev-deps spec-hole → **#162**. Filed follow-ups now: #157-162.
- ✓ **FIX-R8 DONE+VERIFIED.** R8-S1: lockfile dep name+aliases charset-validated at parse BOTH
  impls (Python lockfile.py:600/671 via new SSOT `valid_dep_name`, Rust lockfile.rs:176/432 via
  `valid_flag_name`) → NEW slug LOCK-DEP-NAME-INVALID in all 3 sources + raised; fixture-240.
  R8-D1: 2 manifest.py sites routed through `contains_unsafe_char` SSOT. R8-D2: optional-flag-clash
  hint branched. Gate: Python 1991 passed; Rust all ok (62/381 + all crates); HEAD 2e48e73;
  parks={099,144}; both LOCK slugs bijection-intact. Lockfile-hardening class COMPLETE (security
  agent enumerated all fields; name+aliases were the last).

### Round 9 — Design IN (1 Med R9-D1 + 1 Low); Security + Cross-impl pending.
- **R9-D1 (MEDIUM, SSOT gap — Python; same class as R8-D1):** FIX-R8 added `valid_dep_name`
  SSOT + routed `_parse_dep_node`+lockfile through it, but 2 sites still call
  `_FLAG_NAME_CHARSET_RE.match()` directly: `_parse_flags_block` (manifest.py:2109),
  `_parse_member_dep` (manifest.py:2289). Inert (same regex) but SSOT-discipline gap.
  **FIX (Python-only, COMPREHENSIVE to end the class):** route BOTH through `valid_dep_name`;
  grep ALL remaining direct `_FLAG_NAME_CHARSET_RE` + `_UNSAFE_STRING_RE` uses → route every one
  through its wrapper; fix the stale `_FLAG_NAME_CHARSET_RE` comment (it's the impl detail of
  `valid_dep_name`, not `contains_unsafe_char`). No fixture (inert refactor under green).
- **R9-D1-Low:** Python `valid_dep_name` vs Rust `valid_flag_name` naming skew (both validate
  dep+flag+member names, shared charset [A-Za-z0-9_-] — intentional). Leave (cosmetic).
- Design confirms rest of #23 module CLEAN after 8 rounds (flag model, S4a, optional desugar,
  conditional filtering, contains_unsafe_char fully routed, patch/override union, predicate.py leaf).
- **Round-9 Security: CLEAN — nothing above Low.** Final sink trace: all 5 dep forms +
  src_dir + aliases + provenance validated at both manifest+lockfile boundaries; active_flags→`-d:`
  gated by manifest-validated flag table (unvalidated lockfile values can't reach sink); git
  `--end-of-options`; KDL depth-32 + fixpoint bounds present. 1 Low (defense-in-depth: lockfile
  active_flags values not charset-validated at parse — unexploitable via emit gate; leave per mandate).
- **Round-9 Cross-impl: #23 surface BYTE-IDENTICAL — no divergences.** All 6 blind-spot scenarios
  (opt-out+cross-pkg, double cross-pkg-enable, optional-auto-flag in when, multi-value partial-
  undeclared, active_flags source-ordering, patch-by-alias[N/A]) byte-identical/covered. Bijection
  clean. 1 Low coverage gap: no fixture for LOCK-DEP-NAME-INVALID via unsafe ALIAS (path validated
  R8, untested by corpus) → folding fixture-241 in.
- **FIX-R9 (agent a65a10d9daf1dec24) — Python-only:** R9-D1 comprehensive SSOT routing (ALL direct
  _FLAG_NAME_CHARSET_RE + _UNSAFE_STRING_RE sites → wrappers; grep-proven none remain) + fixture-241
  (unsafe alias → LOCK-DEP-NAME-INVALID, expected green-immediately both impls). Then round-10.
- ✓ **FIX-R9 DONE+VERIFIED.** R9-D1 comprehensive SSOT routing — grep-proven only def+wrapper-internal
  uses of _FLAG_NAME_CHARSET_RE/_UNSAFE_STRING_RE remain; caught a 3rd bypass site (cli.py:1637) the
  reviewer missed. fixture-241 (unsafe alias) green-immediately both impls. Gate: Python 1992 passed;
  Rust all ok (62/381); HEAD 2e48e73; parks={099,144}.

### Round 10 — NOT the floor. Security CLEAN (0>Low). Design 0>Low (raised format_manifest
round-trip → FILED #163). Cross-impl found 1 NEW Medium R10-X1.
- **R10-X1 (MEDIUM — cross-impl divergence + Python nim.cfg newline injection):** `valid_dep_name`
  (manifest.py:222) uses `re.match(r"^[A-Za-z0-9_\-]+$")`; Python `$` matches before a trailing
  newline → `valid_dep_name("foo\n")`=True (Python accepts), Rust byte-check rejects → divergence;
  AND newline reaches nim.cfg via the SSOT (all name validation). **FIX (Python-only, 1 line):**
  fullmatch / `\Z` in valid_dep_name (heals all call sites incl lockfile+aliases) + fixture-242
  (dep name trailing \n → MAN-DEP-NAME-INVALID). Agent ad39ac36145784ac4 running.
- **R10-D1 → FILED #163:** format_manifest drops when-block predicates on rewrite (milpa
  add/remove/update silently un-conditions named/local/tarball/member deps; spec §8 round-trip;
  both impls symmetric; cross-impl serializer slice w/ round-trip property test — out of #23 core).
- Filed follow-ups now: #157-163.
- **RESUME:** verify FIX-R10-X1 (Python ~1993, Rust all ok, HEAD 2e48e73, parks={099,144},
  fixture-242 not parked, bijection); then round-11 re-review (floor candidate — R10 was 0H/0
  security-or-design-Medium, only the 1 cross-impl fullmatch Medium). If round-11 0 C/H/M → FINAL
  ledger + report + STOP (uncommitted, await Corey).
- ✓ **FIX-R10-X1 DONE+VERIFIED.** valid_dep_name → `_FLAG_NAME_CHARSET_RE.fullmatch(s)` (heals all
  name-validation sinks incl lockfile+aliases); Rust needed no change (byte-correct). fixture-242.
  Gate: Python 1993 passed; Rust all ok (62/381); HEAD 2e48e73; parks={099,144}.
### Round 11 re-review LAUNCHED (FLOOR-CONFIRMING). Security a203bca38c6ac6961,
Design a817e52b87a443df6, Cross-impl a8758fb05305c0c31. Trend: R8=0H+2M, R9=0H+1M, R10=0H+1M
(all last-of-class). Filed follow-ups: #157-163. If R11 0 C/H/M → FINAL ledger + report + STOP.
- **Round-11 Design: CONCLUSIVE — 0 new above Low.** Whole #23 module confirmed clean+symmetric.
- **Round-11 Security: R11-S1 REFUTED (recorded, dropped).** Agent claimed lockfile active_flags →
  nim.cfg -d: childless-convention injection, but MISREAD nimcfg.py:108-115: the childless
  `{dep.name}_{flag_name}` emit is INSIDE `if flag_name in dep_flag_table` (fires only for a
  DECLARED, charset-validated flag with empty defines), NOT when the name is absent. Injected
  non-declared active_flags values are SKIPPED. Both dep.name + declared flag_name are
  charset-clean. Matches round-9's correct Low assessment. Rust nimcfg.rs:82-93 same gate.
  → active_flags-not-validated-at-parse stays a LOW defense-in-depth item (leave per mandate).
- **Round-11 = 0 above Low** pending cross-impl (a8758fb05305c0c31). If clean → FLOOR.

### (R10 launch) Security a4559d201b42b8ae8, Design aba7a35071f568d31,
Cross-impl af8b366f40e02493d. Trend: R7=0H+2M, R8=0H+2M, R9=0H+1M(inert SSOT, fixed). R9 cross-impl
confirmed surface byte-identical; R9 security clean. R10 expected = floor (0 C/H/M).
If R10 clean → FINAL ledger + report + STOP (uncommitted, await Corey).
Filed follow-ups: #157-162. Remaining Lows (leave): FlagRequest.name parse-validation; DoS
RuntimeError→MilpaError; lockfile active_flags defense-in-depth (emit-gate-protected); lazy imports
(flag_enables_closure ×6, dep_passes_flag_predicates ×4); _desugar_dep closure smell;
valid_dep_name/valid_flag_name naming skew; MilpaKdlEdgeSource ignores ctx.active_flags (S4a corrects);
multi-value partial-undeclared flag-pred fixture gap; non-slug message-wording nits.

### (orig) Round 9 trend: R6=1H+2M, R7=0H+2M, R8=0H+2M (both Mediums were the
last-of-class lockfile/SSOT items). Lockfile trust boundary now fully hardened. Strong floor
candidate. Filed follow-ups: #157-162. Carried Lows (leave per mandate): FlagRequest.name
parse-validation; DoS RuntimeError→MilpaError; S4b break-invariant comment; lazy imports
(flag_enables_closure ×6, dep_passes_flag_predicates ×4); R8-D3 _desugar_dep closure smell;
Rust MilpaKdlEdgeSource ignores ctx.active_flags (S4a corrects); message-wording (non-slug) nits.

(launched: Security afe9fdda9e4ef0398, Design a949382efeb2a8b54,
Cross-impl afbdf2b8b22f15ffe — fresh blind-spot sweep over uncovered #23 behaviors:
negated/multi-value flag preds, optional+when composition, cross-pkg-enable on when-gated dep,
default-true+consumer-false). Rounds 5-6 each found new shared-blind-spot bugs, so not assuming
floor yet. Filed follow-ups: #157-160. Carried Lows (leave per mandate): FlagRequest.name
parse-validation; DoS RuntimeError→MilpaError; S4b break-invariant comment; lazy imports;
Rust MilpaKdlEdgeSource ignores ctx.active_flags.
Filed follow-ups: #157, #158, #159, #160. Carried Lows (per mandate, leave): FlagRequest.name
parse-validation; DoS RuntimeError→MilpaError; S4b break-invariant comment; lazy imports;
Rust MilpaKdlEdgeSource ignores ctx.active_flags (S4a corrects).

### Other round-5 findings (lower stakes, pending disposition after fork):
- Design-M: Rust workspace seed path lacks `None + has_cli_features` flag-filter arm
  (workspace+features not yet corpus-covered) → file issue before authoring those fixtures.
- Design-M: `compute_cross_pkg_enables` signature overstates deps (takes Manifest+full
  active_map, uses only flags+keys) — tighten so Rust can mirror as a free fn.
- Design-M: Python `Dep` union lacks shared `predicates` property/protocol — `getattr(...,())`
  would silently admit a new variant lacking the field.
- Design-L: S4b singleton-candidate `break` invariant only in a comment; lazy
  `dep_passes_flag_predicates` imports at 4 sites; S4b non-recursive-in-wave undocumented.
- Cross-impl-L: MilpaKdlEdgeSource Rust ignores ctx.active_flags (S4a corrects convergently);
  Rust NimbleEdgeSource error is ManifestError wrapper (slug byte-identical, OK).
- Carried Lows (per mandate): FlagRequest.name parse-validation; DoS RuntimeError→MilpaError;
  Rust dep_passes_flag_predicates privacy.
- **DEFERRED + FILED:** M-D3 → **#157** (EdgeSet carry flag decls, kill `_materialize`
  double-parse — seam change). H-D2b → **#158** (lockfile `root_active_flags` exact
  frozen check — spec amendment).
- **LEAVE (Low, per mandate):** FlagRequest.name parse-validation (no exploit path);
  DoS guard RuntimeError→MilpaError (conformance-invisible); Rust
  `dep_passes_flag_predicates` privacy asymmetry.
- **Round-1 fix status:**
  - ✓ **H1** (nim.cfg injection) FIXED by fix-agent B: parse-boundary validation,
    2 new slugs `MAN-FLAG-NAME-INVALID` + `MAN-FLAG-DEFINES-UNSAFE` (bijection synced),
    fixtures 217+218, spec/manifest-grammar.md §3.5 + spec/errors.md updated. Python
    1941 passed; Rust green. ⚠ Agent B added `fixture-215b` to Rust known_failing.txt
    citing Agent A WIP — **MUST reconcile** (verify 215/215b actually pass after A's C1
    fix; remove improper park so it can't mask a real failure).
  - ✓ **C1** FIXED+VERIFIED (agent A): unconditional dep_active_flags seeding, URL+named,
    both impls. fixtures 215 (cross-pkg) + 215b (named-dep). **Reconciled: fixture-215b
    was prematurely parked in Rust known_failing.txt — UNPARKED, corpus green.** Both gates green.
  - ✓ **C2** FIXED+VERIFIED (agent A): Rust live-path undeclared-features guard. fixture-216.
  - ✓ **H3** FIXED+VERIFIED (agent A): Rust dep_active_flags migrated to identity keys (NORMATIVE).
  - ⚠ **C1b** PARTIAL: agent A added CLI to the two serialize dicts but the **write site is
    still missing in BOTH impls** (ActivationSource.CLI/Cli is never recorded → `--features`
    flags don't enter conflict detection). Completion folded into agent C (record CLI source +
    SSOT conflict-check so `fetch --features X,Y` w/ conflict raises RESOLVE-FLAG-CONFLICT).
  - ✓ **H2** FIXED (agent C): `FlagRequest` moved into milpa-types, re-exported from
    milpa-manifest, `FlagRequestEntry` deleted, 2 conversion sites removed.
  - ✓ **M9** FIXED (agent C): override→pkey seam unified (`override_target_to_pkey` /
    `_override_target_to_pkey`), both impls.
  - ✓ **C1b** COMPLETE (agent C): shared `raise_if_flag_conflicts` SSOT helper; root CLI
    conflict check in resolve/resolve_with_features (bypasses dep_active_flags — root has no
    identity); `--features X,Y` w/ conflict → RESOLVE-FLAG-CONFLICT, `"cli"` in payload,
    byte-identical; 3 tests/impl RED-first. Python 1947 passed; Rust all green.
  - ✓ **M10** FIXED (agent G): spec — active_flags lex-order normative; errors.md triggers
    impl-name-free; least-fixpoint convergence clause (manifest-grammar §3.5).
  - ✓ **M1** (agent E): explicit cross-pkg-enables gate (transitive enable can't admit a
    new dep outside root closure) + tests. Residual (documented): a transitive dep can still
    enable flags in an ALREADY-admitted dep — conservative gate, doesn't need stricter.
  - ✓ **M2** (agent E): REAL — transitive `local=`/`tarball=` deps now dropped from BFS
    (`_enqueue_dep`), unifying with edge_sources transitive-projection rule; Rust already safe; tests.
  - ✓ **M3** (agent E): fixpoint cap now FAIL-LOUD on exhaustion (Python RuntimeError /
    Rust MILPA-INTERNAL). ⚠ re-review: error TYPES differ x-impl (not corpus-observable, internal guard).
  - ✓ **M4** (agent F2): new slug `CLI-FEATURE-FLAGS-CONFLICT` (bijection), both impls reject
    `--all-features`+`--no-default-features`, anti-hollow tests via real main(). CLI-only (no fixture).
  - ✓ **M5** (agent E): new slug `MAN-FLAG-CONFLICTS-SELF` (bijection), fixture-219, parse-time
    self-conflict reject, tests, byte-identical.
  - ✓ **M6** (agent E): dead-override (name not in graph) → warning, both impls, tests.
  - ✓ **M7** (agent E): member override in non-workspace → warning, both impls, tests.
  - ✓ **H4 + M8** FIXED (agent F): all flag-predicate eval routes through the single
    `dep_passes_flag_predicates` SSOT per impl (resolve + frozen + verify). Bonus: caught+fixed
    a latent bug — negated flag predicates were silently ignored in the Rust frozen/verify path.
  - **ROUND 1 COMPLETE: all 2 Critical + 6 High + 11 Medium fixed.** Integrated gate (all
    agents together): **Python 1969 passed / 13 skipped / 1 xfailed; Rust all suites green;
    HEAD `2e48e73` (nothing committed).**
  - **ROUND 2 re-review DONE.** Round-1 fixes verified CLOSED: C1 (seed), C2, H3, C1b, H2,
    H4+M8, M2, M3-sentinel, M5, M6, M7, M9-helper. New findings (being verified):
    - **R2-C1 (Critical, NEW)** = H1(d): non-optional **dep node names** not charset-validated →
      `"foo\nbar" git=…` injects nim.cfg `--path:`/`-d:` lines. Both impls. (round-1 H1 only
      covered flag names + defines values — incomplete.) manifest.py:1199 / Rust lib.rs:1282.
    - **R2-C2 (Critical, NEW)** = H1(e): transitive **`src_dir`** not validated → `src_dir
      "src\n--passC:-evil"` injects `--passC:` (code exec). Both impls (confirmed live). manifest.py:895
      → edge_sources → nimcfg.py:166.
    - **R2-H1 (High, NEW)**: Rust S4a fixpoint step-4 evaluates newly-gated edge admission against
      `new_active` only, not `merged` union (Python uses merged) → multi-predicate gated dep
      (`flag=A∧flag=B`, A prior/default, B new) dropped by Rust, kept by Python → divergence. Latent
      (corpus uses single-flag gates). resolver.py:1617-1644 vs resolver.rs:2718-2748. VERIFYING.
    - **R2-FORK (M1 residual, High)** — transitive dep enabling a sibling's **optional** dep (Cargo-
      standard cross-dep feature activation) → unexpected fetch. Security frames as confused-deputy;
      Cargo treats as a feature. **GENUINE FORK → escalate to Corey** (gate it vs keep Cargo parity).
    - **R2-M (Mediums, NEW):** C1b root conflict skips enables-closure (root flag enables not applied
      before conflict check; resolver.py:1979); M4/all Rust `return Ok(1)` diagnostics lack Python's
      `milpa:` stderr prefix (broader Python `milpa:` vs Rust `<CODE>:` prefix divergence — not
      corpus-checked; #23 part = route M4 through typed error, file broader prefix issue); fixpoint
      per-iteration work super-linear/unbounded (DoS on adversarial-wide manifests); H1(c) Unicode
      line seps U+2028/U+2029 not caught by `[\x00-\x1f\x7f]`.
    - **R2-Low:** H-A dead `_provenance_key_for_*` family (4 fns, 0 call sites) — delete; M-A Rust
      seed_root MemberTarget no-op needs explanatory comment.
  - **R2-C1, R2-C2, R2-H1 all CONFIRMED by verifiers.** Round-2 fix batch IN PROGRESS (3 agents,
    disjoint files): SecFix = R2-C1 (dep-name validation) + R2-C2 (src_dir validation) + R2-Unicode
    (U+2028/9), parse boundary, new slugs (MAN-DEP-NAME-INVALID / MAN-SRC-DIR-UNSAFE), fixtures,
    completeness audit of every manifest string → nim.cfg. ResFix = R2-H1 (Rust fixpoint union fix
    + multi-predicate fixture) + C1b-enables-chain (apply flag_enables_closure to root seed) + DoS
    width bound (fail-loud) + H-A (delete dead _provenance_key_* family). CliFix = M4 route through
    typed-error path (stop the eprintln bypass).
  - **R2-FORK RESOLVED (by-design, NOT escalated):** transitive dep enabling a sibling's optional
    dep = Cargo-standard cross-package feature activation, explicitly milpa's RFC model (fetched dep
    always already declared in tree, not attacker-chosen URL). wontfix-as-vuln. TODO: file tracking
    issue for future opt-in "feature-activation audit" gate + doc the trust model.
  - **TODO file issues (defer=file-now):** (1) cross-package optional-enable audit gate (future
    opt-in); (2) repo-wide `milpa:` (Py) vs `<CODE>:` (Rust) stderr-prefix divergence — pre-existing,
    out of #23 scope, not corpus-checked.
  - **ROUND 2 FIX BATCH COMPLETE:** ✓ R2-C1+R2-C2+R2-Unicode (SecFix — MAN-DEP-NAME-INVALID +
    MAN-SRC-DIR-UNSAFE slugs, parse-boundary validation of dep names + src_dir + U+2028/9,
    fixtures 223/224/225, fixture-199 reclassified, completeness audit done, bijection 8/8).
    ✓ R2-H1 (ResFix — Rust fixpoint reads merged set back for edge admission; fixture-220
    two-flag-union). ✓ C1b-enables-chain (ResFix — flag_enables_closure applied to root seed;
    test). ✓ DoS bound (ResFix — MAX_TOTAL_ACTIVATIONS=10_000 fail-loud both impls). ✓ H-A
    (ResFix — dead _provenance_key_* family deleted, 0 call sites confirmed). ✓ M4 stderr
    (CliFix — routed through typed-error Err path). Integrated gate: **Python 1976 passed /
    13 skipped / 1 xfailed; Rust 643 passed; HEAD 2e48e73; known_failing back to {099,144}.**
  - **R2-FORK resolved by-design → issue #155 filed** (future opt-in activation-audit gate).
    **Broad stderr prefix divergence → issue #156 filed** (repo-wide, out of #23 scope).
  - **ROUND 3 re-review DONE.** Security: ALL CLEAR (both injection criticals closed, completeness
    re-audit incl. lockfile-sourced strings — can't inject since must byte-match a validated name;
    DoS bound present; round-1 gates intact). Findings:
    - **R3-C (Critical, NEW)**: R2-H1 fix was INCOMPLETE — Rust fixpoint *convergence* check
      (resolver.rs ~2741-2749) still used `new_active.keys()` not the union (edge-admission was fixed,
      convergence missed). Dep with S3-seeded flag X + cross-pkg-enabled flag Y → Rust never converges
      → MILPA-INTERNAL; Python resolves → divergence+crash. Uncaught (fixture-220 has no S3 seeding).
      → agent R3a (fix convergence to use local union + fixture-226; also removes Finding-5 read-back).
    - **Finding 1 (High)**: parse-time MAN-DEP-OPTIONAL-INVALID-NAME raise now DEAD (subsumed by
      MAN-DEP-NAME-INVALID; member deps excluded from desugar). Slug stays live via `add --optional`
      CLI path. → agent R3b (remove dead branch + spec/docstrings).
    - **Finding 2 (Medium)**: Rust `valid_flag_name` private → CLI reinlines it. → agent R3b (export+import).
    - **Finding 5 (Low)**: R2-H1 read-back-from-store smell → folded into R3a (compute union locally).
    - CLEAN: fixture-199 reclassification, dep-name charset (no over-reject; fresco deps all match),
      C1b closure, DoS counters, cross-impl validation parity (charset/unsafe-char sets byte-identical).
  - ⏳ **ROUND 3 fix batch IN PROGRESS:** R3a (resolver.rs convergence + Finding-5 + fixture-226),
    R3b (manifest/CLI dead-slug + valid_flag_name export). Then round-4 re-review → 0-C/H/M floor.
    Gate: Python 1976, Rust 643, HEAD 2e48e73, known_failing={099,144}.
  - (superseded watch-items:)
    MAN-DEP-OPTIONAL-INVALID-NAME parse-branch now dead? (still raised via `add --optional` CLI
    path cli.py:1690/main.rs:911 — bijection OK, but parse branch manifest.py:746/lib.rs:796 may
    be unreachable → clean if dead); dep-name charset `[A-Za-z0-9_-]+` too strict? (verify no
    legit name broken); fixture-199 reclassification correctness; R2-H1/C1b-chain/DoS-bound
    correctness; any NEW issue from the round-2 fixes. Remaining Low: M-A (Rust seed_root member
    no-op comment), L1-L4 from round 1. Drive to 0-C/H/M floor.
- **S13 — doc sync** ✓ (docs-only). `comparison-vs-nimble-atlas.md`: features/optional
  + patch rows now "exceeds atlas" (Cargo-style union, cross-pkg `enables`, same-pkg
  `conflicts`, optional pruning, three-form override incl. identity-bearing member;
  #23 ✓); "Where milpa matches (and often exceeds)" para added; date bumped.
  `identity-and-provenance.md`: new "What identity is not" bullet — `active_flags` are
  build config, NOT source bytes; same `content_hash`/CAS key across feature sets; no
  per-feature CAS fan-out (cites `spec/identity.md §3.2`).
- **S12 — property tests** ✓ (Python-only, per milpa convention; Rust covered by corpus).
  New `impls/python/tests/test_features_properties.py`, 13 Hypothesis properties:
  union order-independence (4), closure idempotence + monotonicity (5), prune
  completeness (3). Reuses `flag_enables_closure`/`compute_dep_active_flags` SSOT (no
  parallel logic). **0 counterexamples** (clean — monotone fixpoint held). Gate: Python
  1937 passed / 13 skipped / 1 xfailed (baseline fixture-144); +13 tests, no regression.
- **S11 — workspace feature unification** ✓ (verified both gates + per-member nim.cfg).
  Shared-dep `active_flags` unions across all members (shared `dep_active_flags` map);
  `format_workspace_nimcfgs` emits unified `-d:` defines per member (reuses S6
  `build_flag_defines`); `WorkspaceManifest.flags {}` added + parsed + workspace-wide
  seeded. **Latent Rust bug fixed:** `materialize_named` wasn't populating
  `dep_active_flags` for named deps (Python was correct) — closed a cross-impl gap,
  exposed by fixture-214. fixtures 213 (two members→union) + 214 (workspace-root flags).
  Gates: Python 1924 passed / 1 xfailed; Rust corpus + bijection green.
- **Code-review item (S10, non-blocking):** Rust `cmd_verify` mismatch uses a *direct*
  `flag_enables_closure` check (the S9 `check_frozen_active_flags_mismatch` early-returns
  with no CLI features), separate from Python's path. verify is CLI-only (not in-process
  corpus), so x-impl parity isn't corpus-enforced — Stage 4 should confirm Python and
  Rust `verify` compute the SAME mismatch (SSOT the active-closure recompute).
- **S10 — subcommand awareness** ✓ (verified both full gates). `add --optional/--features`
  (pre-write clash check reuses S7 validation; writer output byte-identical x-impl);
  `remove` (optional auto-flag is parse-time → no phantom flag to clean); `update`
  threads locked `active_flags` (reproducibility); `show` prints `active_flags`;
  `verify` checks feature-membership mismatch → `FROZEN-ACTIVE-FLAGS-MISMATCH`. Mostly
  CLI-only verbs → unit-test coverage (corpus precedent). Gates: Python 1911 passed /
  1 xfailed; Rust full workspace green (377 core/151 conf/33 solver/8 types).
- **S9 — CLI feature selection** ✓ (verified both gates + ActivationSource parity +
  bijection). `--features`/`--no-default-features`/`--all-features` on fetch/lock/update,
  wired into the REAL CLI (anti-hollow: 4 e2e tests call real `main(argv)` — S6 lesson
  applied). `ResolveParams.features/no_default_features/all_features` (both impls);
  `CLI`/`Cli` = 4th ActivationSource variant (position parity preserved). `--frozen`+
  selection-mismatch → new `FROZEN-ACTIVE-FLAGS-MISMATCH` (bijection-synced; recompute-
  from-manifest+CLI vs stored, no lockfile field). fixtures 209–212; spec/cli-contract.md
  §2.7. Gates: Python 1898 passed / 1 xfailed; Rust corpus + bijection green.
- **Code-review item (S8b, non-blocking):** a `member` override in a *single-package*
  (non-workspace) manifest is a silent **no-op** (dep falls back to original source).
  Defensible (member needs a workspace), but silently ignoring a root's explicit
  patch is surface-don't-hide-adjacent — Stage 4 should decide if it should error.
- **S8b — `member` patch (workspace)** ✓ (verified both gates + member identity).
  MemberTarget routes through `resolve_workspace`/`seed_workspace` (member pre-
  registered as candidate; the 4 sites suppress external fetch). Lock records
  `MemberProvenanceRecord` **WITH** identity (drift-detected); `--frozen` **passes**
  (reproducible — NOT FROZEN-LOCAL-DEP); `RES-WS-OVERRIDE-MEMBER-COLLISION` exempts
  the intended member-override form (git/local on member name still errors).
  fixtures 207 (transitive→member, identity-bearing) + 208 (frozen passes). Gates:
  Python 1876 passed / 1 xfailed; Rust corpus + bijection green.
- **S8a — `local=` patch resolution** ✓ (verified both gates + corpus identity).
  LocalTarget wired at all 4 sites in both impls via `_apply_override`/`apply_override`
  (reuses LocalProvenance + `_process_local_worker`/`process_local` — no parallel
  path). Lock records `LocalProvenanceRecord` with **no identity**; lock-time
  non-reproducible warning; `--frozen` trips the **existing** `FROZEN-LOCAL-DEP`
  (frozen.py `_check_local_provenance` keys on provenance-record kind — no new slug,
  SSOT). fixtures 205 (transitive→local fork, no identity) + 206 (frozen error,
  checked-in `./mylib-fork/`). Gates: Python 1874 passed / 1 xfailed; Rust corpus green.
- **S8 — `Override` discriminated union** ✓ (verified both gates + bijection).
  `Override` = `name` + `GitTarget | LocalTarget | MemberTarget` (sum type, both
  impls). Non-git kinds raise "not yet wired (S8a/S8b)" at the 4 interception sites
  (`resolver.py` ~797/1037/1050/1483 + Rust) via a git-only helper; git path
  unchanged. `MAN-OVERRIDE-TARGET-AMBIGUOUS` (zero/multiple forms) bijection-synced;
  spec §3.4 rewritten. fixtures 202 (all-3-forms accept), 203 (mixed→ambiguous),
  204 (zero→ambiguous); fixture-035 reclassified (`ref=` alone = zero target →
  ambiguous). Gates: Python 1872 passed / 1 xfailed; Rust corpus + bijection green.
- **S7 — optional desugar** ✓ (verified both gates + pruning + bijection). Parse-time
  desugar: `optional=#true` → auto-flag (`default=#false`) + `flag="<dep>"` gate;
  surface `optional=#true` preserved through `format_manifest` round-trip (desugar is
  internal). Slugs `MAN-DEP-OPTIONAL-FLAG-CLASH` + `MAN-DEP-OPTIONAL-INVALID-NAME`
  bijection-synced. fixtures 198 (clash), 199 (invalid-name), 200 (absent→**not
  fetched**, no mocked-fetches dir + empty lock), 201 (present via enables). Gates:
  Python 1861 passed / 1 xfailed; Rust corpus + bijection green.
- **S6 was found HOLLOW and fixed:** the map-builder was test-only; the real CLI
  passed `flag_defines=None` so `milpa fetch` emitted zero `-d:` defines while the
  corpus passed via a harness-built map. Fixed: `build_flag_defines` is now a
  product fn (Python `nimcfg.py:130`, Rust `milpa-core/nimcfg.rs`), wired into
  `cli.py:527/581` + `main.rs:623/667`; test-only copies deleted (SSOT); anti-
  regression tests added. **Lesson: verify each slice's REAL CLI path, not just
  the corpus harness ([[feedback_gate_active_impl_pytest]]).**
- **S4c payload verified byte-identical** (divergence risk #3): both impls build
  `{dep, flag_a, flag_b, sources_a, sources_b}` with flag_a/flag_b lexicographic +
  sources sorted by enum-declaration-order. Corpus checks slug only; payload parity
  is unit-tested per-impl + confirmed by reading both. **Hardening candidate:** add
  a structured-payload differential fixture if the corpus runner gains payload
  assertion support (currently slug-only).
- **⚠ Cross-impl keying note (deferred — alias-folding territory):** Python keys
  `dep_active_flags` by **resolved identity**; Rust keys by **dep_name**. Identical
  results under single-consumer/no-alias scope (corpus byte-identical today). S5 landed
  without alias-folding because it's not needed until Phase B dedup/aliasing. Both impls
  use the same fallback (`compute_dep_active_flags(flags, [])`) for default-only active
  sets. Track dedup/alias reconciliation when Phase B lands.
- **Minor (fail-loud nit, low pri):** both impls' fixpoint silently exits at the
  50-iter cap instead of raising. Monotonicity guarantees convergence well under
  50, so it never triggers; consider raising-on-exhaustion for fail-loud.
- **SSOT cleanup candidate (low pri):** Rust now has TWO flag-request types —
  `milpa_manifest::FlagRequest` (parse) + `milpa_types::FlagRequestEntry` (resolve,
  S4b). Layering-forced (milpa-types can't dep on milpa-manifest), but ideally
  unify by moving the type into milpa-types and re-using it from milpa-manifest.
  Candidate for a hardening/refactor pass (Python has no such split).
- **⚠ Process note:** subagents have committed despite "DO NOT commit" — the S3
  agent did (reverted via `reset --soft`). Keep ALL slice work UNCOMMITTED; only
  commit when Corey explicitly asks. Re-verify each agent's gate claims.
- **Uncommitted working tree** holds S1–S6 (impls + spec + fixtures 185–197 +
  baseline park + RFC/handoff docs). HEAD = `2e48e73`. ~40 files; never committed.
- **Resume:** `/loop implement the next unimplemented RFC slice with /tdd,
  following the standing rules; after each slice report one progress line; stop
  when every slice is implemented`
- **Stage-3-start issues filed** ✓: #150 (weak-dep `dep?/feature`), #151
  (cross-package `conflicts`), #152 (`milpa features`/`--why-flag`).

## Baseline reds (pre-existing, NOT #23 — tracked + parked)
Discovered establishing the Stage-3 baseline at HEAD `2e48e73`:
- **#153** — fixture-144 depdecl-fetch-failed maps to `RES-UNATTESTED-METADATA`
  instead of `TNG-DEPDECL-FETCH-FAILED` (both impls). Parked: Python xfail
  (`_NOT_YET_WIRED_FIXTURE_NAMES`) + Rust `known_failing.txt`.
- **#154** — fixture-099 res-provenance-conflict wired in Python, not Rust
  (cross-impl gap). Parked: Rust `known_failing.txt` only.
Baseline is now clean-green in both impls so each slice's gate signal is
unambiguous; unpark when #153/#154 land.

## Done
- **S1 — `enables`/`conflicts` grammar** ✓ (verified both gates).
  - `FlagDecl` gains `enables` (same-pkg flag names + cross-pkg `CrossPkgEnable`
    dep→flag, reusing existing flag-request type) + `conflicts` fields, both impls.
  - Parse-time post-parse `MAN-FLAG-ENABLES-UNDECLARED` validation (forward-ref
    legal; dep-name diagnostic). `conflicts` parsed+round-tripped but its
    `MAN-FLAG-CONFLICTS-UNDECLARED` validation deferred to S4c.
  - New slug `MAN-FLAG-ENABLES-UNDECLARED` bijection-synced (spec/errors.md ↔
    Python errors.py ↔ Rust all_codes()).
  - `format_manifest` round-trips enables/conflicts (canonical single-node), both impls.
  - spec/manifest-grammar.md §3.5 updated (grammar + charset + post-parse rule).
  - Conformance fixtures 185 (accept), 186 (undeclared error), 187 (forward-ref).
  - Gates: Python 1708 passed / 1 xfailed (baseline); Rust conformance corpus +
    bijection green.
- **S2 — same-package `enables` closure** ✓ (verified both gates).
  - Pure fn `flag_enables_closure(flags, seed) → set` (worklist fixpoint,
    cycle-safe, O(|flags|)): Python `manifest.py`, Rust `milpa-manifest/src/lib.rs`.
  - Same-package only (cross-pkg `CrossPkgEnable` ignored until S3/S4a);
    `conflicts` not consulted (S4c). Default-true seeding = caller's job (SSOT).
  - 22 identical unit tests each impl (seed-incl, multi-hop, idempotence, cycles,
    order-independence). Conformance deferred to S5 (closure not observable via
    resolve until S3/S4a wire it) — honest, no fabricated fixture.
  - Gates: Python 1730 passed / 1 xfailed; Rust all crates ok, corpus 0 divergence.
- **S2.5 — transitive edge-filter divergence fix (§2.6)** ✓ (verified both gates,
  re-ran Rust corpus independently).
  - Python `_manifest_to_edgeset` (`edge_sources.py`) now filters transitive
    flag-gated deps by the dep-manifest's own default-true flags, matching Rust
    `build_edgeset_from_manifest`. Shared `dep_passes_flag_predicates` factored
    into `predicate.py` (SSOT — reused by edge_sources + resolver).
  - **Scope:** dep's-own-default-true-flags filter only (no cross-pkg activation
    yet — that's S3/S4a). Python catches up to Rust; no new behavior either side.
  - fixture-188 pins both directions (default-#false gate → subdep absent;
    default-#true gate → present; unconditional → present), byte-identical x-impl.
  - No existing-fixture regressions. Gates: Python 1734 passed / 1 xfailed; Rust
    corpus + bijection green.
- **S3 — cross-package request activation (direct deps, single-hop)** ✓ (verified
  both gates + ActivationSource parity independently).
  - `NamedDep.flag_requests` added both impls (reuses UrlDep's flag-request type);
    parsed + format round-tripped.
  - `dep_active_flags` map keyed by **resolved identity** (§3.1.2); per-flag
    activation **sources** tracked via `ActivationSource` enum — identical variants
    both impls: `DEFAULT` / `EDGE_REQUEST` / `ENABLES_RULE` (CLI variant deferred
    to S9). `compute_dep_active_flags` SSOT in resolver (both impls).
  - `EdgeSourceCtx.active_flags` added; `extract_requires` bypasses edge_cache when
    active_flags non-empty (flag-parameterized EdgeSets are consumer-specific).
  - **Single-hop only** — no recursive re-entry (that's S4a). fixture-189 pins a
    URL-dep flag request, byte-identical x-impl; plus unit tests
    (`test_s3_cross_pkg_activation.py`, Rust `tests.rs`).
  - Gates: Python 1768 passed / 1 xfailed; Rust all crates ok, corpus + bijection green.
- **S4a — interleaved dep×flag fixpoint (multi-hop, single-consumer)** ✓ (verified
  both gates + cap parity + Rust corpus independently; agent did NOT commit).
  - `_s4a_run_fixpoint` (Python `resolver.py:1144`) / `run_s4a_fixpoint` (Rust
    `resolver.rs:1949`) wrap the BFS loop: each iter loads fetched dep manifests,
    fires `compute_cross_pkg_enables` per active flag, recomputes
    `compute_dep_active_flags` (SSOT), admits newly-flag-gated edges (filter BEFORE
    EdgeSet build → sealed-once `edge_cache` preserved), re-runs BFS for new deps,
    until neither deps nor active_flags grow. `MAX_ITERS=50` safety belt (both).
  - **PubGrub runs once** post-convergence (pre-solver edge-admission only).
  - Thread-safety: Rust resolver is single-threaded for state mutation (ALL
    provider state is `RefCell` — `dep_active_flags` follows suit, correct);
    Python mutates flag state on the main thread (parallel = fetch I/O only).
    Determinism rests on single-threaded mutation + union commutativity.
  - fixture-190 (3-hop: feat→lib-b's `extra`→lib-c) byte-identical x-impl; 17
    Python unit tests (`test_s4a_fixpoint.py`) incl. order-independence + cycle
    termination. Gates: Python 1785 passed / 1 xfailed; Rust corpus + bijection green.
- **S4b — multi-consumer union + opt-out** ✓ (verified both gates + Rust corpus).
  - **Real bug found+fixed:** the provenance/dedup gate (`_check_provenance_gate`
    / Rust `gate()`+`seen_url`) dropped a 2nd consumer's `flag_requests` before
    S4b accumulation — single-consumer S4a had masked it. Now both impls union
    flag requests across consumers of the same shared dep (sources union too).
  - Rust: added `milpa_types::FlagRequestEntry` + `flag_requests` on `UrlRequire`
    (carried through `build_edgeset_from_manifest`→`edgeset_to_extracted`).
  - `flag "x" #false` confirmed = absence-of-request (contributes nothing, never a
    veto, never an error). Conflict-detection NOT here (S4c).
  - fixtures 191 (two consumers, different flags → union; both gated subdeps
    admitted) + 192 (opt-out overridden by another edge → flag stays on, no error),
    byte-identical x-impl. Gates: Python 1798 passed / 1 xfailed; Rust corpus green.
- **S4c — same-package `conflicts` + `RESOLVE-FLAG-CONFLICT`** ✓ (verified both
  gates + Rust corpus; NOT committed per standing rule).
  - **Parse-time (a) `MAN-FLAG-CONFLICTS-UNDECLARED`:** mirrors S1's
    `_check_flag_enables_references` pattern — post-parse pass over full flags
    table; forward references legal. New slug bijection-synced in all three:
    `spec/errors.md` ↔ `Python errors.py` ↔ Rust `all_codes()` (manifest crate).
    Python: `_check_flag_conflicts_references` called from `parse_manifest` after
    `_check_flag_enables_references`. Rust: equivalent loop after the enables check.
  - **Resolve-time (b) `RESOLVE-FLAG-CONFLICT`:** post-fixpoint validation pass
    (`_s4c_check_flag_conflicts` Python / `check_s4c_flag_conflicts` Rust) — called
    AFTER `_s4a_run_fixpoint` converges, BEFORE dedup/solver entry. Only reads the
    converged set; never retracts → monotonicity untouched + order-independent.
    Algorithm normative: for each dep D, for each flag f ∈ active(D), for each g in
    f.conflicts: if g ∈ active(D) → raise. Same-package only (#151 for cross-pkg).
  - **Key implementation detail:** `dep_active_flags` is seeded only when edge
    requests exist; both impls fall back to `compute_dep_active_flags(flags, ())` to
    derive defaults-only active set when no entry exists. This ensures default=#true
    conflicts (no consumer requests) are still caught.
  - **Error payload (normative, byte-identical x-impl):**
    `{dep, flag_a, flag_b, sources_a, sources_b}` where `flag_a` ≤ `flag_b` (lex
    order) and `sources_*` are sorted by enum declaration order: `["default",
    "edge_request", "enables_rule"]`. Python: `_ACTIVATION_SOURCE_ORDER` dict,
    `_serialize_sources()`. Rust: `CoreError::FlagConflict` struct with typed
    payload fields; `BTreeSet<ActivationSource>` already sorted by enum Ord.
  - **Symmetry:** conflict declared on one flag only still fires (the check on the
    declaring flag's `conflicts` list catches it regardless).
  - **Conformance fixtures:** 193 (`MAN-FLAG-CONFLICTS-UNDECLARED` parse-time
    error), 194 (`RESOLVE-FLAG-CONFLICT` both-defaults-true → error), 195
    (satisfiable, one side active → no false positive). Corpus runner checks slug
    only; **payload byte-identity verified via unit tests in both impls**
    (`test_s4c_conflicts.py` 16 tests Python; Rust `resolver_tests.rs` 7 new tests
    incl. `s4c_resolve_flag_conflict_payload_byte_identity` + edge_request payload).
  - Gates: Python 1817 passed / 1 xfailed; Rust all crates ok, corpus 0 divergence.

- **S5 — `active_flags` lockfile authority** ✓ (verified both gates + Rust corpus;
  NOT committed per standing rule).
  - **Python:** `_build_graph` now populates `ResolvedDep.active_flags` from
    `provider.dep_active_flags[cand.identity]`. Fallback: when `dep_active_flags` has
    no entry (dep with no consumer requests), reads the dep's `milpa.kdl` and calls
    `compute_dep_active_flags(flags, ())` to derive defaults-only active set.
    Lexicographically sorted (normative). Carried through `_locked_from_resolved` →
    lockfile emission unchanged (lockfile already emitted `active_flags`).
  - **Rust:** `active_flags: Vec<String>` added to `ResolvedDep` in `milpa-types`.
    `build_graph` populates it from `dep_active_flags[c.name]`, same fallback pattern
    (reads `self.deps_dir/<name>/milpa.kdl`). `locked_from_resolved` now uses
    `d.active_flags.clone()` instead of `Vec::new()`. `frozen.rs` carries
    `locked.active_flags.clone()` through the frozen path.
  - **Updated conformance fixtures:** 188, 189, 190, 191, 192, 195 — expected lockfiles
    now include `active_flags` lines for deps with active flags. Byte-identical x-impl.
  - **New conformance fixture 196:** `fixture-196-active-flags-lockfile-authority` —
    dep with alpha+beta (default=#true) and gamma (default=#false); lockfile records
    `active_flags "alpha" "beta"` (lex order); gamma absent.
  - **Unit tests:** Python `test_s5_active_flags_lockfile.py` (8 tests — single flag,
    multiple flags sorted, empty, edge_request, no flags, lockfile emission/round-trip).
    Rust `resolver_tests.rs` 5 new tests (single flag, multiple sorted, empty, edge
    request, lockfile emission). Both impls verify `active_flags` byte-identity.
  - Gates: Python 1826 passed / 1 xfailed; Rust all crates ok, corpus 0 divergence.

## Scope (decided)
All three knobs: features + optional + patch (AskUserQuestion 2026-06-15).

## Slices (RFC §7 — re-sliced + hardened in round 2; not yet implemented)
Stage A: S1 enables+conflicts grammar (+FlagDecl fields, format_manifest round-trip)
· S2 same-pkg closure · S2.5 align transitive edge filtering (divergence fix) ·
S3 cross-pkg activation **single-hop only** · **S4a interleaved fixpoint — ⚠
LARGEST (~2-3×), shared mutable state + thread-safety** · S4b unification+opt-out
· S4c **same-package** conflicts + RESOLVE-FLAG-CONFLICT(payload) · S5 active_flags
lock authority · S6 nim.cfg -d: (manifest threaded into emit_nim_cfg, childless
convention).
Stage B: S7 optional desugar (parse-time).
Stage C: S8 Override product→sum (**4 interception sites**) · S8a local= · S8b
member (workspace).
Stage D: S9 CLI --features/--no-default-features/--all-features · S10 subcommand
awareness (+add pre-write clash, remove phantom-flag note) · S11 workspace union.
Stage E (NEW): S12 property tests (commutativity/idempotence/prune) · S13 doc sync.

## Open forks (awaiting Corey)
- **None.** Round-2 decisions recorded in RFC §8 "Round-2 design decisions"
  (resolved, not forks). The only one worth Corey's eye: **cross-package
  `conflicts` deferred** (same-package mutual exclusion still ships) — flagged in
  §8 as a heads-up since he put `conflicts` in scope in round 1.

## Key round-2 fixes applied (from 4-lens review)
- **dep_active_flags keyed by resolved identity**, alias-folded to canonical
  before lockfile (closed the dedup/alias hole). Activation **sources** tracked.
- **conflicts → same-package only**; check algorithm + error payload normative;
  cross-package deferred.
- **optional presence vs feature-request** distinction made explicit (§3.2).
- **frozen check de-circularized**: recompute from manifest+CLI vs stored; no new
  lockfile field; local=+frozen reuses existing FROZEN-LOCAL-DEP.
- **nim.cfg**: defines stay in manifest (SSOT), childless → -d:<pkg>_<flag>,
  emit_nim_cfg gets the manifest; active_flags never change content_hash.
- enables args+children one node; split MAN-DEP-OPTIONAL-INVALID-NAME; dev-deps
  position; S12 property tests + S13 docs added; S4a re-flagged as the monster;
  S8 four interception sites; anchor ~:1476 → _enqueue_dep ~:1483.
- All code anchors re-verified against live source by the feasibility agent.

## Review ledger (stage 4) — round 1 (2026-06-19)
6 review dimensions (correctness, cross-impl fidelity, security, design/ergonomics,
error-catalog/spec, test-coverage) + 5 adversarial verifiers. Status legend:
open / fixed / deferred / wontfix / refuted.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| C1 | Critical | **default-true cross-pkg `enables` never fire.** S4a fixpoint reads `dep_active_flags`, which is only seeded when a consumer requests a flag. A dep with `default=#true` flag + cross-pkg enables, no consumer request → enables silently dropped, wrong graph. Worse: Python *named*-dep path seeds defaults (resolver.py:578-581) but URL deps don't (1338-1354 guard); Rust seeds neither (1520/1771 guards) → **Python-vs-Rust divergence** on named-dep default-true enables, uncaught by corpus. | open | CONFIRMED by verifier. Repro: root→lib-a (no req); lib-a `f1 default=#true enables{lib-b{flag g1}}`; lib-b gates lib-c on g1 → lib-c silently absent. Fix: unconditionally seed `compute_dep_active_flags(flags, ())` at fetch for every dep, both impls (Python URL path + both Rust paths). |
| C2 | Critical | **`milpa fetch --features <undeclared>` diverges.** spec/cli-contract.md:309 = flat MUST raise FROZEN-ACTIVE-FLAGS-MISMATCH (no frozen qualifier). Python raises on live path (resolver.py:644-678); Rust `resolve_with_features` (resolver.rs:123-140) silently `seed.extend(...)`, validates only on frozen path. | open | CONFIRMED. Repro: `milpa fetch --features bogus` (no --frozen) → Python errors, Rust exits 0. No live-path fixture (212 is frozen-only). Fix: add undeclared-name guard to Rust live path + live-path fixture. |
| H1 | High | **nim.cfg injection.** `defines` string values and `flags{}` block flag names are not validated; KDL decodes `\n`; format_nimcfg emits `-d:{sym}` / `-d:{pkg}_{flag}` with no escaping (Python nimcfg.py:115/124, Rust nimcfg.rs:109). A transitive dep with `default=#true` flag (seeded into active_flags via build_graph fallback resolver.py:3144) injects arbitrary nim.cfg lines → compiler-flag exec at next `nim c`. | open | CONFIRMED both impls, both vectors. Fix (root-cause): validate defines values + flag names newline-free / charset at parse boundary (`_parse_flags_block` / `parse_flag_decl`), reuse `_FLAG_NAME_CHARSET_RE`. |
| H2 | High | **`FlagRequest` (milpa-manifest) vs `FlagRequestEntry` (milpa-types)** — structurally identical, conversion tax at resolver.rs:2064/2124. SSOT violation; "layering-forced" is fixable. | open | Confirmed by reading. Fix: move `FlagRequest` into milpa-types (like Predicate), re-export from milpa-manifest, delete FlagRequestEntry. Rust-only. |
| H3 | High | **`dep_active_flags` keyed by identity (Python) vs dep_name (Rust).** Spec §3.1.2 names identity-keying normative; Rust deviates. Latent divergence under Phase B alias-fold + flags. Triangulated by 3 reviewers. | open | Real, latent (needs Phase B aliasing to bite). **Genuine fork:** align Rust→identity (honor spec) vs align Python→name (simpler, Rust's shape) + amend spec. Needs Corey. |
| H4 | High | **`verify` active-flag mismatch recompute is a parallel path** (not a divergence — same answer — but duplicated logic). Python `_check_frozen_active_flags_mismatch` inlines predicate eval (cli.py:665-673) instead of `dep_passes_flag_predicates`; Rust `cmd_verify` (main.rs:229-265) rolls its own instead of calling `check_frozen_active_flags_mismatch`. | open | Confirmed. Fix: route both through `dep_passes_flag_predicates` SSOT. |
| C1b | High | **`ActivationSource.CLI` half-wired (Python).** `_ACTIVATION_SOURCE_ORDER`/`_NAMES` (resolver.py:1720-1731) omit CLI → KeyError if it ever reaches `_serialize_sources`; but CLI is *never written* into dep_active_flags (grep: 0 hits), while Rust *does* serialize `Cli`. So `--features`-activated flags aren't recorded as a conflict source in Python → latent divergence + crash-in-waiting. | open | CONFIRMED latent. Fix: record CLI source in compute path + add CLI to both dicts (Python); confirm parity with Rust. |
| M1 | Medium | No root-authority gate on cross-pkg enables fixpoint (security). Refuted as default-true attack (C1 means it can't fire), but exploitable once a consumer requests any flag on a transitive dep → sibling force-activation/fetch. | open | Verifier: refuted-as-stated, real-but-narrower. Add root-authority scoping when C1 is fixed. |
| M2 | Medium | `local=` dep in a *transitive* manifest reaches BFS via `_collect_transitive_deps` (resolver.py:2543/2610) though edge_sources.py:333 drops it from EdgeSet — path-traversal/confused-deputy. | unverified | Security agent self-uncertain; needs a focused verify. |
| M3 | Medium | S4a fixpoint cap (50) bounds iterations, not total (dep×flag) admission width → crafted-manifest DoS. | open | Add absolute (dep,flag)-admission cap, both impls. |
| M4 | Medium | `--all-features` + `--no-default-features` together: `all_features` wins, `no_default_features` silently ignored (both impls). Cargo errors. | open | Reject the combination at CLI parse. |
| M5 | Medium | Self-conflict (`f conflicts=["f"]`) not rejected at parse; reaches S4c → nonsensical `flag_a==flag_b` payload. | open | Reject self-reference in `_check_flag_conflicts_references`. |
| M6 | Medium | Override naming a dep absent from the graph → silent no-op, no warning (both impls). | open | Warn/error on unmatched override. |
| M7 | Medium | `member` override in non-workspace manifest → silent no-op (handoff S8b watch-item). | open | Decide: error vs documented no-op. |
| M8 | Medium | `dep_passes_flag_predicates` not the SSOT it claims — `_predicate_satisfied` (resolver.py:783) and `_filter_manifest_by_flags_only` (754) inline the flag check. | open | Delegate both to the SSOT. |
| M9 | Medium | Override discriminated-union matched at 4 interception sites (resolver, both impls) — shallow seam. | open | Extract single `resolve_override_item()` seam. |
| M10 | Medium | Spec gaps: (a) lockfile-schema.md §3.6 doesn't mandate `active_flags` lex-order (both impls do it); (b) errors.md:456/465 "Triggered" cites private Python fn `_desugar_optional_deps`; (c) 50-iter cap behavior unspecified normatively. | open | Spec edits. |
| M11 | Medium | Test gaps that *let C1/C2 through*: no fixture for default-true cross-pkg enables; no live-path undeclared-`--features` fixture; no differential fixture for RESOLVE-FLAG-CONFLICT payload (corpus is slug-only). | open | Add fixtures (will close as part of C1/C2 fixes). |
| H3b/M | — | **Refuted/dropped:** same-pkg closure-incompleteness in later fixpoint iterations (every write goes through `compute_dep_active_flags` SSOT closure; monotone union preserves prior closures). Recorded, not presented. | refuted | Verifier traced all dep_active_flags write sites. |
| L1 | Low | Python `resolve()` mutates `provider._flag_requests_by_name` private attr directly. | open | Expose a setter. |
| L2 | Low | `active_flags` build_graph fallback silently writes empty if dep milpa.kdl missing (resolver.py:3138-3146 `except: pass`). | open | Fail-loud or log. |
| L3 | Low | Stray empty `{expected}/` dirs in fixtures 185/186/187. | open | Delete. |
| L4 | Low | Untested: enables cycles; non-ASCII flag names; member-override-in-non-workspace; fixpoint at cap. | open | Add edge-case tests. |
