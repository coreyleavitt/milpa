# RFC: GatedIndex construction invariant — handoff

- **Stage:** 4 (code-review) — round 1 verified; **mandate APPROVED** ("follow the mandate" = fix through Medium R1–R6, leave Lows R7–R8). Fix loop IN PROGRESS.
- **Progress:** S0..S4 DONE (9/9). RFC impl complete. #199 closes on next push. NOT pushed; not on GitHub.
- **Fix-loop status:** Round 1 ALL FIXES LANDED+VERIFIED. Waves 1-3 done (R1 warn-recovery+spec, R3 test-support guardrail, R4 Cmd::Verify sidecar, R2 acquire epoch-enforcement via shared mint_enforced + 8 D18-fixed fixtures 367-375, R5 py mint sentinel, R6 py load_index shim→test helper). **Harness caught fixture-469 mis-authoring** (R2's new fixture used index-trust off — epoch fold never runs under off; + no dep → real CLI never loads index): FIXED (off→warn so epoch genuinely evaluates; added to harness KNOWN_LIMITATIONS as in-process-tier, same as 367-375). Final authoritative verification ALL GREEN: py full exit 0, rust workspace exit 0, rust conformance exit 0, **harness OVERALL PASS / 0 divergences / 469 skipped**. Round 2 re-review (Correctness+Security+Design on fix diffs) RUNNING.
- **Ledger updates:** R1-R6 status→fixed. fixture-469 corrected. Lows R7/R8 deferred per mandate.
- **Round 2 re-review (3 lenses on fix diffs):** R1/R2/R6/R3/R4/fixture-469 CONFIRMED clean. Two NEW Medium findings (both reproduced):
  - **RR-1** (gated_index.py): R5 sentinel's "unforgeable/structurally impossible" claim is FALSE in Python — `dataclasses.replace(g, _verification=TRUSTED)` (copies valid _witness) + `from milpa.gated_index import _MINT_SENTINEL` both forge. Not externally exploitable (needs first-party source access); guard still stops accidental construction. FIX (running, a38f33d8): honest docstring + best-effort __replace__ block (py3.14) + corrected tests.
  - **RR-2** (test_conformance.py + runner.rs): adapter `_fixture_epoch_commitment_status` computes epoch status IGNORING policy → `acquire(off,ArmingInvalid)` raises in-process where real CLI (epoch_active=trust_active∧verifier) stays Unarmed/success. Conformance-parity landmine; fixture-469 off→warn routed AROUND it. FIX (running, ac083f7a): gate adapter status on trust_active both impls, mirror production; regression test.
  - Round-2 LOW nits (deferred): fold (index,verification,bundle_info)→struct to shed too_many_arguments; extract duplicated manifest-policy-pair read in runner.rs/test_conformance.py.
- **RR fixes DONE+VERIFIED.** RR-1 (a38f33d8): honest docstring, __replace__ rejected empirically (3.14 dataclasses.replace ignores it; only copy.replace uses it, 0 callers), tests pin the known escape hatches. RR-2 (ac083f7a): adapter gates epoch status on trust_active both impls, RED→GREEN both, acquire contract + fixture-469 warn untouched. No round-3 (RR fixes = docstrings + test-adapters + tests only, no production logic).
- **⭐ FLOOR REACHED — 0 Critical/High/Medium.** Authoritative merged verification ALL GREEN: py full exit 0, rust workspace exit 0, rust conformance exit 0, **harness OVERALL PASS / 0 divergences / 60 known-limitation skips (incl 469)**.
- **LOWs — Corey said "fix lows now" → ALL DONE+VERIFIED:** R7 (`Index::parse`→pub(crate), callers all in-crate), RR-Low-a (`FetchedIndex`/`_FetchedIndex` struct: apply_epoch_fold 7→5, mint_enforced 6→4, `#[allow(too_many_arguments)]` removed, both impls), RR-Low-b (`manifest_epoch_policies` helper unifies 4 sites), R8 (real gap confirmed — 142/143 were unrelated; added file:// unit + warn-two-read e2e pins, both impls, RED-verified). Cleanup agent + R8 agent both green. Release binary rebuilt. Final merged verification ALL GREEN: **harness OVERALL PASS / 0 divergences, py full exit 0, rust workspace exit 0** (release binary rebuilt first).

- **⭐⭐ REVIEW COMPLETE — nothing left to fix (0 Critical/High/Medium/Low open).** 2 review rounds + fix loop + Lows all landed & verified. Scope: 24 tracked files (+1481/−155) + new files (fixture-469, _index_cache_helpers.py, containment.rs), on top of the 10 committed RFC slices a163d4d..b317689. **ALL UNCOMMITTED** — nothing committed/pushed/posted. Awaiting Corey's commit/push call. #199 auto-closes on push (b317689).
- **STATE: all fixes UNCOMMITTED** (23 tracked M + 6 untracked, on top of the 10 committed RFC slices a163d4d..b317689). Nothing committed or pushed — awaiting Corey. #199 auto-closes on push (in b317689).
- **Resume (stage 4):** await Wave 1 agents → launch Wave 2 → Wave 3 → re-review; loop to floor. Spec fix folded into R1 (§3.4.2/§3.4.5 transient-transport-respects-policy clarification).
- **RFC:** `docs/rfc-trusted-index-invariant.md`  •  **Issue:** #199

## Review ledger (stage 4, round 1) — 4 lenses + 3 adversarial verifiers
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R1 | HIGH | Python `_refetch_with_recovery` hard-fails MILPA-INDEX-UNREACHABLE regardless of policy on a transient (non-404) transport blip during bundle recovery; Rust respects policy under `warn` (8ac691c). `milpa verify` under `index-trust "warn"` silently SKIPS the dep_decl drift check where Rust warns-and-continues. Contradicts §3.4.1 (S4) + RFC §2.3. Pre-dates RFC, never mirrored. | open | CONFIRMED (verifier a110ec6c). index_cache.py:1544-1570; rust index_cache.rs:1169-1262 |
| R2 | MED | `GatedIndex::acquire` STAMPS injected epoch status but never calls `enforce_epoch_commitment`/`check_epoch_ratchet_requirement` (cache path does); module doc over-claims "epoch phase ran + applied". Latent: only test runner calls acquire, no fixture drives non-clean status. Future `milpa verify --index-only` would inherit the hole. | open | CONFIRMED both impls (verifier a2b5d80). rust index_cache.rs:394-397; py index_cache.py:456-458 |
| R3 | MED | `test-support`/`for_test` linked into shipped `milpa` binary under workspace-wide build (`./dev-rust build --workspace`, CI `cargo test`) via Cargo feature unification; the compile-time-safety claim in gated_index.rs comment is false for that path; no CI lint (unlike Python grep). Not live-exploitable (no main.rs call site). | open | CONFIRMED empirically (security grep of built binary symbol). gated_index.rs:125-144 + Cargo.toml |
| R4 | MED | Rust conformance runner `Cmd::Verify` arm hardcodes `bundle_bytes=None`, never reads `index.kdl.bundle`; `Cmd::Resolve` (S3) + Python `_execute_verify` do. Test-adapter cross-impl asymmetry; latent (no cmd=verify fixture ships a bundle); production CLI + harness unaffected. | open | CONFIRMED latent (verifier a8a2896). runner.rs:1000-1006 |
| R5 | MED | Python `GatedIndex._mint` containment is a repo-local pytest grep, not a runtime guard — any code can construct the frozen dataclass directly; Rust is compile-time (pub(crate)+private fields). Add a mint sentinel checked in `__post_init__`. | open | Design F2 (unverified — design judgment). gated_index.py:66-135 |
| R6 | MED | Python `load_index` is a public legacy compat shim in the gate module returning bare `Index` (~150 test callers, 0 production); violates no-legacy-shim-pre-v1; more discoverable than `load_index_gated`. Rust scopes the equivalent to a private test helper. | open | Quality F1 (unverified — cleanliness). index_cache.py:1320-1349 |
| R7 | LOW | Rust `Index::parse` still fully `pub` + re-exported; RFC §2.1 decided it "becomes effectively private". Dormant (0 external callers). | open | Quality F3. registry.rs:299, lib.rs:125 |
| R8 | LOW | file:// bundle-missing classification asymmetry (py reclassifies absent file:// as 404, Rust keeps Other); strict fails-closed identically, warn diverges — largely subsumed by R1's fix. Wants a warn+absent-file://-read-twice fixture. | open | Security F2. index_cache.py:1671-1704, main.rs:3777-3801 |

**Refuted/dropped:** none — every presented finding survived verification (R5/R6/R7/R8 are design/cleanliness judgments not sent to a refutation verifier).

## The reframe
#199's premise (Rust gates lazily) is FALSIFIED — both impls gate eagerly at the
CLI acquisition layer; §3.4.1 already pins eager. Real defect: index trust is
enforced by convention at the periphery, not by construction at the boundary →
C1 coincidental cross-impl agreement, C2 in-process test bypass, C3 S4
strict-default dead on 62/74 resolve-tier fixtures. Fix: `GatedIndex` (renamed
from TrustedIndex) minted ONLY by the production gate module → ungated use
unrepresentable.

## Round 2 outcome (4 lenses, all applied; no forks)
- **Boundary inventory completed:** 4th Rust surface `lib.rs` pub trait Resolver/ResolveParams (pub `index` field — migrate or delete in S1a-ii); 2nd Python entry point `resolve_workspace` resolver.py:5643/:5778 (assert BOTH); 4th bypass `_execute_verify` test_conformance.py:2682 (S-Verify must reroute or verify pin is is_cli_only).
- **`off`-case type:** verification VerificationResult → `Option<VerificationResult>` (None⇔off; 8th enum variant would break to_slug totality) + single `is_cryptographically_trusted()` accessor (never read trust off bundle_info.is_some() — warn+DigestMismatch populates it).
- **Deref → `.index()` accessor:** grep-able, no silent coercion; Deref never saved Option<&Index>/field sites anyway (~17 hard resolver.rs edits either way). Python symmetric: `.index` property, unwrap inside edgeset_to_terms.
- **Epoch fold:** MUST preserve trust_active conditionality (off ⇒ no trust bundle exists ⇒ Unarmed untouched); genuinely NEW param threading (entry_trust_policy across 3 levels + Rust crate boundary) — explicit checklist, pin off+epoch=Unarmed.
- **Withdrew** §2.4 cmd_show_index_trust unification claim (fail-open display vs fail-closed mint; §8 exempts show; 3 lenses).
- **C3 corpus math corrected:** all 74 expect MAN-*/WS-* first, ZERO reach gate; "62" was fiction. Hole is TOTAL not partial → S3 is first-ever gate fixture; strengthens motivation.
- **Added:** Python for_test containment (outside milpa/, file://-guard, CI grep lint — no #[cfg(test)]); strict-SUCCESS corpus fixture; shared-corpus sequencing barrier; runner.rs:905 citation fix (already manifest-first); named Python negative tests; ripple corrected ~60 prod/~96 test; S1a split S1a-i(additive)/S1a-ii(atomic flip).

## Round 1 outcome (4 lenses, all applied to the RFC)
- **CRITICAL (design+depth+feasibility+breadth converge):** mint point is the
  ~4 production sites in `index_cache`/`index_ratchet_seam`, NOT a test-facing
  `acquire`. Private constructor scoped to the gate module; `load_*` return
  `GatedIndex`; `acquire` is a thin cache-free convenience on the same primitive.
- **CRITICAL live bug (breadth):** Python `_verify_dep_decl_pins` cli.py:3188
  calls `load_default_index()` bare = gate OFF; `milpa verify` under strict uses
  unverified index, diverges from Rust. → S-Verify slice + verify-tier pin.
- **HIGH (design+feasibility):** epoch_commitment_status is a post-parse `&mut`
  mutation → fold epoch phase INTO the mint; GatedIndex = passed trust+epoch.
- **HIGH naming (design+depth):** TrustedIndex lies under warn/off → GatedIndex
  + honest per-policy invariant (strict=verified, warn=verified-or-warned,
  off=no claim).
- **MEDIUM-HIGH (design):** shallow tag → carry VerificationResult +
  IndexBundleInfo; kills the duplicate re-derivation in cmd_show_index_trust.
- **Feasibility:** Rust ripple ~35 prod + ~90 test sites (not 15-20) → split
  S1 into mechanical S1a (green) + behavioral S1b. S0 = migrate 74 to warn FIRST
  (data-only no-op) so corpus never goes red. `acquire` = ~10-20 lines NEW code.
  Adapter parse-order inversion (index before manifest) → fix in S1b/S2b.
- **Corrections:** C3 only 62/74 reach gate (12 fail manifest-first); citation
  fixes. All 6 original forks (F1-F6) RESOLVED into the design — none open.

## Slices (Stage 3) — round-2 re-cut
- [x] S0 migrate 74 no-policy fixtures → `index-trust "warn"` (data-only; harmless, NOT gate coverage — S3 is). DONE: all 74 confirmed `MAN-*`/`WS-*` validation fixtures (73 MAN- + 1 WS-MEMBER-IS-WORKSPACE), 0 success-shaped — matches C3, contradicts the stale §3 body prose, which was corrected in the RFC-landing commit (§3 now states the 74 are validation fixtures that never reach the gate; migration is hygiene + defense-in-depth, not coverage). Green both impls (Python `EXIT=0`; Rust `milpa-conformance` all `test result: ok`).
- [x] S1a-i Rust type additive: GatedIndex (verification: Option<VerificationResult>) + `.index()` accessor + empty() + module-private `mint` + `#[cfg(test)] for_test`; NO return-type change (green). DONE: `milpa-core/src/gated_index.rs` (new module, re-exported at crate root); `mint` `pub(crate)` + `#[allow(dead_code)]` (unconsumed until S1a-ii); accessors `index()`/`verification()`/`bundle_info()`/`is_cryptographically_trusted()` (Some(Trusted) only). 5 unit tests. Green: `-p milpa-core` 1262/0, `--workspace` 1812/0. (sigstore vendored crate emits 9 pre-existing dead-code warnings — not ours.)
- [x] S1a-ii Rust flip+retrofit — DONE (13 files). Green: workspace 1813/0 (baseline 1812 + epoch-off pin), zero new warnings vs S1a-i baseline. Detail: mint at ~4 index_cache sites (GateDecision.index kept RAW; mint where load_index_with_history consumes it); epoch fold via `EpochCommitmentInputs<'a>` (Copy struct) + `apply_epoch_fold` in index_cache.rs — faithful mirror of old main.rs::apply_epoch_commitment_phase; `Option<EpochCommitmentInputs>` = trust_active guard (None⇔off); pin test `off_policy_with_epoch_pointer_present_leaves_status_unarmed`. resolver.rs entry points → `Option<&GatedIndex>` unwrap via `.index()` (ResolveProvider/binding leaves stay &Index); 5 anchors → `GatedIndex::empty()`; manifest_writer flipped. **DECISION: `Resolver` trait + `ResolveParams` + `impl Resolver for Milpa` DELETED (confirmed dead — 0 non-Milpa impls, 0 trait-object calls).** **DEVIATION (accepted): `for_test` gated `#[cfg(any(test, feature="test-support"))]` + new milpa-core `test-support` feature (empty), enabled ONLY by milpa-conformance (NOT milpa-cli — hole stays closed in shipped binary) because `#[cfg(test)]` can't cross to runner.rs.** runner.rs 2 bypass sites wrapped in `for_test` (still bypassing — real reroute is S1b). check --workspace clean.
- [x] S1b Rust cache-free acquire + runner reroute — DONE (2 files). Green: workspace 1816/0 (+3 tests), no new warnings, 207 shared fixtures intact. `GatedIndex::acquire(index_text, bundle_bytes, config, verifier, url, epoch_status)` at index_cache.rs:361 — reuses verify_and_enforce (verify-first/parse-after; None-bundle→BundleMissing→raises strict/warns warn; off⇒verification None; epoch injected). Both runner sites → acquire, manifest-first. RED→GREEN test `milpa_target_resolve_strict_index_trust_no_bundle_raises_bundle_missing` (runner.rs:3743). acquire is `pub` (real gate, not a bypass — legit cache-free entry per §2.1).
- [x] S2a Python type + enforcement — DONE (31 files: 6 prod, ~21 test retrofits, 4 new). `milpa/gated_index.py` frozen dataclass (`.index` property, `_mint`, `empty()`, `is_cryptographically_trusted()`). for_test containment: `tests/_gated_index_helpers.py` (outside milpa/) + `tests/test_gated_index_containment.py` grep-lint (no `_mint(`/raw `GatedIndex(` in milpa/ outside gate module). Epoch fold: `entry_trust_policy`/`epoch_verifier`/`epoch_expected_signer` threaded into `load_index_gated`, `_fold_epoch_commitment` at 4 mint sites, `_apply_epoch_commitment_phase` removed, trust_active guard preserved; pin `test_epoch_fold_never_runs_under_index_trust_off`. Both entry points raise TypeError on bare Index (resolver.py:3372/5697); negatives `test_resolve_rejects_bare_index_on_env` + `..._workspace_...`. edgeset_to_terms retyped. **DEVIATION (sound): `index_cache.load_index` stays bare-Index-returning but now DELEGATES through `load_index_gated` (gate runs) — a back-compat unwrap for ~100 cache-mechanics unit tests; NOT a MilpaEnv.index path (prod uses load_default_index→gated). Analogue of Rust's raw GateDecision.index.** MilpaEnv already frozen (0 ripple). Green: full suite EXIT=0, 0 failures; 207 shared fixtures intact. _build_env wrapped in for_test (still bypassing — real reroute is S2b).
- [x] S2b Python reroute _build_env, manifest-first — DONE (index_cache.py + test_conformance.py + test_gated_index_invariant.py). `index_cache.acquire(index_text, bundle_bytes, config, verifier, url, epoch_status)` (index_cache.py:386, mirrors Rust — reuses `_verify_and_enforce`, verify-first/parse-after, None-bundle→BundleMissing, off→None, epoch injected). `_build_env` rerouted onto acquire, manifest-first (`_fixture_index_trust_config` helper maps policy). RED→GREEN: `test_acquire_{strict_no_bundle_raises_bundle_missing, warn_no_bundle_mints_with_bundle_missing_verification, off_mints_without_verification}`. Green: full suite EXIT=0, 207 shared fixtures intact.
- [x] S-Verify — DONE (live §1.2 bug fix). Verified Python+Rust+harness (no divergence). Fix1: `_verify_dep_decl_pins` now takes project_dir + reuses `_load_index_for_verb` (DRY gated loader) instead of bare `load_default_index()` → strict+no-bundle fails closed (matches Rust main.rs:1109). Fix2: `_execute_verify` (test_conformance.py) rerouted parse_index→`index_cache.acquire`. Fix3: shared fixture `fixture-466-verify-index-trust-strict-bundle-missing` (verify+strict+no-bundle→TNG-INDEX-BUNDLE-MISSING, deps pre-seeded since fetch pre-phase also gates). **BONUS root-cause fix (index_cache.py): `urllib_bundle_http_get` misclassified an absent `file://` bundle as transient (not 404) → warn-mode `.no-bundle` marker never written → warm-cache second-read tripped crash-recovery→MILPA-INDEX-UNREACHABLE under warn (regressed fixtures 142/143). Fixed with `_file_url_to_path` + file://-aware 404 mapping; Rust already guards this.** Focused test `test_cli_index_trust.py::...test_strict_no_bundle_fails_closed_not_silently_trusted`. Subagent-reported: Python EXIT=0, Rust milpa-conformance green (28/0 incl 466), harness 403/403 both impls no divergence — RE-VERIFYING all three myself (esp. harness against a freshly-rebuilt release binary). Files: cli.py, index_cache.py, test_conformance.py, test_cli_index_trust.py, test_namespace_conflation_audit.py, +fixture-466.
- [x] S3 resolve-tier pins — DONE. `fixture-467-index-trust-strict-present-unconsumed` (strict+index+no-bundle+git-dep→TNG-INDEX-BUNDLE-MISSING; eager gate held in BOTH impls unmodified) + `fixture-468-index-trust-strict-verified-resolves` (strict + MILPA_INDEX_TRUST_MOCK_VERIFIER=trusted + index.kdl.bundle placeholder → named dep resolves, success). Caught a gate-on-harness gap: Rust runner Cmd::Resolve arm hardcoded `bundle_bytes: None` — fixed to read the sidecar (test-adapter only, milpa-conformance runner.rs, mirrors show-index-trust arm + Python _build_env; NOT production). Verified: Rust conformance 28/0, Python conformance EXIT=0, harness 405/405 both impls no divergence.
- [x] S4 spec + close #199 — DONE. registry-protocol.md §3.4.1: added two NORMATIVE clarifying notes — (a) per-policy meaning of a passed gate (strict=verified / warn=verified-or-warned / off=no-claim; MUST NOT over-read warn/off as strict); (b) online dep_decl drift check vs offline reverify (online load is FULLY gated, conditional on ≥1 dep_decl pin — no pins ⇒ no load, not an exception). §3.4.1 kept verbatim otherwise (no impl-shaped type-clause). Cross-ref fix: RFC §5 cited "§3.7.2" which doesn't exist in registry-protocol.md → used the real home `dep-decl.md §3.7` / VERIFY-EDGE-MISMATCH. No new slugs. Harness spec/bijection lints 82/0. No comparison-doc edit (GatedIndex is impl-quality, not a feature-matrix item). `closes #199` in commit.

## Shared-corpus barrier
S3 + S-Verify pins MUST NOT land in conformance/ until BOTH S1b AND S2b green (else the un-rerouted impl fails a shared fixture). S1(Rust)/S2(Python) otherwise per-impl independent.

## Corey context
- Decided: best-in-class scope; "architect round then grind." Both architect
  rounds now done (rfc-flow mandates 2; done). No open forks — every round-2
  finding was a clear-best fix.
- STANDING FLAG (not a blocker): scope is a ~10-slice cross-impl gate refactor
  (surgical newtype → S0..S4 incl. S1a-i/ii) + a LIVE Python verify security bug
  folded into S-Verify. Best-in-class already greenlit.
- Next: `/loop` grind stage 3. Recommend `/compact` first (context full after
  two 4-agent rounds).

## Key file:line map (verified across two Explore probes + 4 review lenses)
- Rust resolve sig `resolver.rs:89`; provider field `resolver.rs:1404`; real Index ctor `registry.rs:383`; default anchors `resolver.rs:265/881/1078/6412` + `frozen.rs:560`.
- Rust mint sites: `index_cache.rs:1184`, `index_ratchet_seam.rs:63`; gate `index_trust.rs:302/745/624`; private `verify_and_enforce` `index_cache.rs:300`; epoch `main.rs:3513`.
- Python: resolve reads `env.index` `resolver.py:3466`; `MilpaEnv.index` `context.py:80`; parser `registry.py:735`; mint `index_cache.py:882/956`; ratchet `index_ratchet_seam.py:100`; gate `index_trust.py:918`; private `_verify_and_enforce` `index_cache.py:324`; loader `index_cache.py:1392`; epoch `cli.py:1436`; **LIVE BUG** `_verify_dep_decl_pins` bare load `cli.py:3188`.
- Bypass sites: `test_conformance.py:624`, `runner.rs:507`, `runner.rs:905`.
- Deep-type source: `VerificationResult`/`IndexBundleInfo`/`describe_index_bundle` `index_trust.py:676` / `index_trust.rs:831` (the duplicate derivation to unify).
- Corpus: 207 resolve-tier (133 warn / 74 absent, of which 62 reach gate / 0 strict / 0 off); 0 bundles. Default strict (S4). Pin template `fixture-367`.
- Spec §3.4.1 `registry-protocol.md:938`; policy table §3.4.5 `:1150`; slug `errors.md:1463`.

## Gotchas
- GATE ON `harness/` — in-process bypasses the gate; only black-box catches it ([[feedback_gate_active_impl_pytest]]).
- NO-GIT for delegated agents ([[feedback_delegated_agents_no_git]]); control loop does all git.
- Python: `cd impls/python && uv run pytest`. Rust: `./dev-rust test --workspace`. Harness: repo-root `harness/`.
