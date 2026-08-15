# RFC: GatedIndex construction invariant — handoff

- **Stage:** 3 (tdd)   •   **Round:** architect rounds 1 & 2 APPLIED; no open forks
- **Progress:** S0, S1a-i DONE (2/9). Next: S1a-ii (Rust atomic flip + retrofit).
- **Resume:** `/loop implement the next unimplemented RFC slice of docs/rfc-trusted-index-invariant.md with /tdd, following the standing rules; after each slice report one progress line; stop when every slice is implemented`
- **RFC:** `docs/rfc-trusted-index-invariant.md`  •  **Issue:** #199

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
- [ ] S1a-ii Rust flip+retrofit ONE atomic green commit: load_*/maybe_index → GatedIndex; mint at ~4 sites; fold epoch (entry_trust_policy param + preserve trust_active conditionality); ~17 Deref-blind resolver.rs sites; **lib.rs Resolver/ResolveParams**; **manifest_writer.rs:289**; ~60 prod + ~96 test sites
- [ ] S1b Rust cache-free acquire; reroute runner bypass — runner.rs:507 IS inverted (flip manifest-first), runner.rs:905 already manifest-first (reroute only); RED strict+no-bundle
- [ ] S2a Python frozen-dataclass MilpaEnv + wrapper + `.index` property + `_mint` + contained for_test (outside milpa/, file://-guard, CI grep lint) + empty()/frozen.py:241 + fold epoch; assert at BOTH resolve() AND resolve_workspace(); retype edge_sources.py:745; named negative test/entry point
- [ ] S2b Python reroute _build_env, manifest-first
- [ ] S-Verify reroute _verify_dep_decl_pins (cli.py:3188, prod) AND _execute_verify parse_index (test_conformance.py:2682, 4th bypass); verify-tier strict pin; in-process + harness/
- [ ] S3 resolve-tier pins: #199 strict+present-unconsumed AND strict-SUCCESS (MILPA_INDEX_TRUST_MOCK_VERIFIER=trusted); in-process + harness/
- [ ] S4 spec §3.4.1 per-policy + verify-conditional clauses; close #199

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
