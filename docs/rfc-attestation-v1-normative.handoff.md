# Strict attestation (both axes), normative in v1 — handoff

- **RFC:** `docs/rfc-attestation-v1-normative.md`
- **Stage:** 1 (RFC + slicing) — **DRAFTED + architect rounds 1–3 APPLIED; ALL FORKS RESOLVED (round 3 = first adversarial review of D-Watermark itself; F1/F2 resolved by Corey 2026-08-04)**   •   **Round:** 3 done
- **Resume:** round-3 applied the mechanism-agnostic fixes (namespace in identity; commitment verification is index-scoped/once/composed-crypto/own-slug; commitment is a sidecar artifact; split S-Epoch → S-EpochCommitment + S-EpochGate; re-arm-as-new-field-not-mutation; S-Backdate re-scope) AND resolved the two escalated forks: **F1 → enumerated committed set `S`, membership `∈ S` (D17)**; **F2 → arming an epoch commitment requires `index-history=strict`, a scoped co-requirement NOT a default flip (D18)**; F-op → grandfather-all-at-re-arm. Both forced by structure (composed into one mechanism). `/tdd docs/rfc-attestation-v1-normative.md` from S1 is unblocked; **S-EpochCommitment additionally needs tianguis re-arm coordination** (commitment over `S` + production `index-history=strict`) before green. See "Round 3" below + RFC §8c "Round-3 escalations — RESOLVED".

## What this is
Reconcile + **complete** + flip: make **strict attestation normative in v1 on
BOTH trust axes** (`index-trust` + `entry-trust`). Round 1 corrected the draft's
false "code is built" premise; round 2 hardened the slicing against two critical
feasibility traps + a fall-through in the epoch predicate. See [[v1_critical_path]].

## §8b RESOLVED (D13) — was mis-posed as a fork
Trust root is a verification *input*, not implementation. Differential corpus feeds
**both impls the same committed root fixture** → unconditional identical-verdict
guarantee, no allow-list. Production keeps each impl's live root (Python TUF
auto-revocation preserved). Both goals met; false trade-off dissolved.

## §8c RESOLVED — D-Watermark adopted (Corey, 2026-08-04)
Epoch classification is a **Rekor-anchored pre-epoch set commitment**, not `published_at`.
- **Mechanism:** arming commits `C = hash(sorted pre-epoch entry identities
  (name,version,content_hash))`; `E` := the commitment snapshot's Rekor `integratedTime`;
  a resolve (whole index already local) offline-verifies the Rekor inclusion proof
  (§3.4.1 step-7 path), recomputes `C'`, requires `C' == C`. In-set ⇒ warn; not-in-set ⇒
  mandate; no-commitment-armed ⇒ warn-equiv; verification-failed ⇒ fail-closed.
- **Why binary (no third design):** the backdater IS the registry; no registry-signed-only
  artifact defeats it (set-once = TOFU-broken; self-signed watermark = signed by the
  attacker). TOFU-safe defeat of a malicious registry *requires* an external anchor —
  only three exist: transparency log (Rekor, in hand), witnesses (#187, deferred),
  per-consumer history (TOFU-broken). So: anchor-to-Rekor or accept-residual; flipping
  index-history is dominated.
- **Got simpler under stress-test:** no Merkle library (whole index local → membership lookup
  against the shipped enumerated set `S`, D17), no per-entry first-appearance (reintroduces TOFU).
  (Round-2's "decoupled from index-history / removes c1/c2" claim was FALSIFIED by round-3 depth
  C2 → F2/D18: the commitment's set-once-ness IS enforced by the ratchet, so arming requires
  index-history=strict. Rekor gives ordering; the ratchet gives uniqueness — complementary.)
- **Residuals (all bounded/pre-existing):** Rekor coupling scoped to already-Sigstore
  consumers + offline-embedded + reversible; set-once arming mistake (inherent to any
  epoch); #187 split-view (already deferred, strictly better than published_at's zero).
- **Cost accepted:** reopens D1/D5 (published_at demoted to informational); **re-arm the
  live production epoch** (timestamp → `(C, Rekor)`) + tianguis emits the commitment.
  Settle into spec (S2) + coordinate tianguis BEFORE S-Epoch, not before S1.
- **Applied to RFC:** §8c full writeup; D1/D5 supersession pointers; S-Epoch rewritten
  (set-commitment sub-builds; dropped the 9-site published_at plumbing); S1/S2/R4 aligned;
  S9 files the tianguis re-arm issue + #187 cross-link.

## Round 3 — first adversarial review OF D-Watermark (Corey adopted it via dialogue AFTER
the round-2 team ran, so it had never been reviewed). 4 lenses, all code-grounded. It is
NOT sound as written — five structural holes, two of which reopen Corey's own mechanism.

**Clear-best fixes APPLIED (mechanism-agnostic — hold under any F1 resolution):**
- **R3-a (crit, feas CRIT#1) — forgeable verification.** S-Epoch said "reuse
  `rekor_adapter::verify_entry_inclusion`"; that fn's OWN docstring says inclusion-alone does
  NOT bind the body to a signer, and Rekor is publicly writable ⇒ anyone forges a "committed"
  C. Fix: commitment auth must COMPOSE cert-chain + DSSE + inclusion (like
  `index_trust::verify_crypto`) w/ a re-arm signer identity. Applied §8c/S2/S-EpochCommitment.
- **R3-b (crit, C3/F2/F3/breadth#5) — commitment verify is index-scoped/once, mis-placed in
  per-candidate entry gate.** Needs whole parsed index, runs once/resolve, failure is
  index-integrity (but `EntryVerificationResult` has no index variant; violates R4 precedence).
  Fix: new index-gate phase (post-parse/pre-solve) producing `EpochCommitmentStatus`
  {Unarmed | Armed(C,E) | ArmingInvalid}; entry gate only READS it as `EpochMembership`
  {PreEpoch|PostEpoch}. New slug **`TNG-INDEX-EPOCH-COMMITMENT-INVALID`** (index family, NOT
  the ratchet slugs — the epoch-commitment-invalid slug is a distinct index-family slug; note D18 still couples set-once-ness to index-history). Applied D5/D9→split, R4/R5, S2.
- **R3-c (crit, feas CRIT#2/breadth#4) — commitment is a sidecar artifact, not a scalar
  field.** A Rekor proof (root_hash+hashes[]+checkpoint) isn't scalar KDL; needs the same
  sidecar fetch+cache class as `index.kdl.bundle`. Fix: new delta row + acquisition text;
  S-EpochCommitment is TWO builds (typed pointer on Index + sidecar path), sized like S-Acq.
- **R3-d (high, depth H1) — identity tuple drops `namespace`.** `(name,version,content_hash)`
  lets `mallory/leftpad` copy `alice/leftpad`'s bytes → identical tuple → dodges mandate;
  codebase key is `(namespace,name)`. Fix: tuple = `(namespace,name,version,content_hash)` +
  rejected-attack note. Also cross-impl determinism hazard if one impl re-adds ns silently.
- **R3-e (crit, breadth#1/#2) — re-arm collides w/ milpa's OWN set-once ratchet.**
  `attestation-epoch` is `OrderKind.SET_ONCE`, pinned by fixtures 389/409; mutating its shape
  timestamp→`(C,Rekor)` IS the `TNG-INDEX-ROOT-MUTATED` violation. Fix: commitment is a NEW
  sibling field w/ its OWN OrderKind (append-once), NOT a mutation of the timestamp; timestamp
  stays informational. New §3.5.1 delta row; audit fixtures 389/409. (Interregnum membership =
  F-op below.)
- **R3-f (high, H2/F4/feas) — S-Backdate/`TNG-ENTRY-BACKDATED` subsumed by D-Watermark's own
  fail-closed C′≠C** (the same "backdater IS the registry" argument §8c uses to justify the
  whole design), and OMITTED from §8c's supersession list. Fix: add to supersession list;
  re-scope S-Backdate to only a distinct non-epoch audit purpose or retire the slug.
- **R3-g (feas HIGH) — S-EpochCommitment's Rust build does NOT need S-RustCrypto's D7 patch**
  (it holds the C′ preimage locally → unpatched `verify_digest` works, like
  `index_trust.rs:547`). Stated so implementer neither blocks nor mis-reaches.
- **R3-h (F5/feas HIGH) — split S-Epoch:** S-EpochCommitment (index-scoped, the real tianguis
  dep) + S-EpochGate (entry-scoped membership predicate + EntryGateOutcome, testable vs
  synthetic `EpochCommitmentStatus`, NO cross-repo blocker → unblocks parallel work).
- **R3-i (M3/F9) — hash hygiene:** domain-separation prefix (`milpa-preepoch-v1:`), explicit
  set(dedup) vs list semantics, reuse `version.py` ordering for the sort key (not string sort).
- **R3-j (M1/breadth#6/#9/#11, naming) — smaller:** `verify` epoch re-derivation vs pinned
  snapshot (S5); tianguis dry-run/diff-of-set as an S9 acceptance criterion; workspace-resolve
  epoch fixture (S7); RES-REGISTRY-SHADOW non-interaction sentence (§3.6); spec prose reserves
  "watermark" for §3.5.4's publication watermark, uses "epoch commitment" for D-Watermark's
  mechanism (decision-record label "D-Watermark" kept).

**FORKS RESOLVED (Corey asked "clear best-in-class or something else?" → answer: forced by
structure, not a menu; both ARE listed options, arrived at by elimination; they compose):**
- **F1 → (b) enumerated committed set `S` (D17).** Load-bearing fact: **pre-epoch entries have
  NO transparency-log footprint** (they predate the mandate) → the grandfathered set MUST be
  explicitly enumerated + committed at arming; no temporal-anchor design works (can't use "own
  log position" — never logged; Merkle root needs per-entry inclusion AND non-membership proofs
  = rejected sparse-Merkle). Committing the whole small frozen `S` directly (`C=hash(S)`, ship
  `S` as the sidecar) gives membership AND non-membership for free, zero proof machinery.
  (a) per-entry flag = same trust model, more schema, drift risk → DOMINATED. (c) append-order =
  needs an authenticated ordering (itself an index-history=strict property) + is a fragile
  special case of a set commitment. `(b)` is the floor. Classification = "verify `S`
  (`hash(S)==C`, composed, Rekor-anchored), then `identity ∈ S`."
- **F2 → (a) scoped co-requirement (D18).** Reframe: the epoch commitment + append-only ratchet
  are ONE mechanism split across two knobs. Offline+TOFU-free defeat of re-arm equivocation is
  achievable ONLY via append-only-consistency; "earliest-in-Rekor" isn't offline-verifiable
  (registry mediates proofs), witnesses = #187 deferred. milpa has exactly one such mechanism —
  the ratchet's SET_ONCE. So the guarantee IS `index-history=strict`. ⇒ arming a commitment +
  entry-trust=strict REQUIRES index-history=strict (config error else). Coupling invariant, NOT
  a default flip (§3 non-goal preserved — unarmed registries untouched). (c) downgrade = ship
  the D1 claim as a footgun → rejected.
- **F-op → grandfather-all-at-re-arm.** `S` = every entry present at re-arm (2898 + interregnum);
  non-breaking; mandate applies only post-re-arm. S7 fixture pins it.
- **Composed (D17+D18):** epoch commitment = frozen enumerated set `S`, Rekor-anchored composed-
  verified sidecar in a new set-once field; classify `identity ∈ S`; arming requires
  index-history=strict. Ceiling = witnesses/gossip #187 (deferred). Applied to RFC: §8c
  escalations→RESOLVED, D1 claim corrected, D17/D18 added, §3 non-goal note, Mechanism +
  S2 + S-EpochCommitment (added the D18 config-error check + `S` sidecar) + R4 updated.

**Round 3 ledger**
| id | lens | sev | finding | disposition |
|----|------|-----|---------|-------------|
| C1/F1/feas3/br2 | all | crit | "pre-epoch-flagged" undefined; benign backfill → registry-wide outage | **F1 ESCALATED** (rec: enumerated set) |
| feas1 | feas | crit | inclusion-proof-only verification is forgeable (Rekor publicly writable) | R3-a applied (compose crypto) |
| C3/F2/F3/br5 | depth/dsgn/br | crit | commitment verify index-scoped/once but placed per-candidate; no index-family slug; violates R4 | R3-b applied (new phase+slug+type split) |
| feas2/br4 | feas/br | crit | commitment is sidecar artifact not scalar field | R3-c applied |
| br1/br2 | breadth | crit | re-arm mutates set-once `attestation-epoch` = ROOT-MUTATED (fixtures 389/409) | R3-e applied (new field+OrderKind) |
| C2 | depth | crit | malicious-registry-safety rests on index-history=strict, kept warn in v1 | **F2 ESCALATED** (rec: scoped co-req) |
| H1 | depth | high | identity tuple omits namespace → cross-ns impersonation | R3-d applied |
| H2/F4 | depth/dsgn | high | S-Backdate subsumed by D-Watermark; omitted from supersession list | R3-f applied |
| feas-rust | feas | high | S-EpochCommitment doesn't need S-RustCrypto patch (holds preimage) | R3-g applied |
| F5/feas | dsgn/feas | high | S-Epoch conflates index+entry work | R3-h applied (split) |
| br3 | breadth | high | entry-trust strict = functionally warn until tianguis re-arm ships | R3-j (R9/S9 honesty) |
| M3/F9 | depth/dsgn | med | no domain sep / set-vs-list / version-ordering reuse in C | R3-i applied |
| M1 | depth | med | verify epoch re-derivation unspecified | R3-j (S5) |
| M2 | depth | med | content_hash-correction interaction with C | R3-i note (immutability assumed) |
| br6 | breadth | med | tianguis set-attestation-epoch tool doesn't support new format | R3-j (S9 acceptance criterion) |
| F6 | dsgn | med | "D-Watermark" name collides w/ §3.5.4 publication watermark | R3-j (prose discipline; label kept) |
| F7 | dsgn | med | `attestation-epoch` field re-shape needs KDL grammar sketch | R3-e/R3-c (S2 grammar) |
| br7/br9 | breadth | low-med | no fresh-clone/TOFU + workspace epoch fixture | R3-j (S7 test) |
| br11 | breadth | low | entry-trust ∩ RES-REGISTRY-SHADOW non-interaction unstated | R3-j (§3.6 sentence) |
| br8/br12 | breadth | low(clear) | multi-registry non-issue; harness already generic | note-only (verified) |

## Round 2 outcome (headline)
4-lens review (depth/breadth/design/feasibility), all code-grounded. Unlike round 1
(false premise), round 2 found real gaps in an otherwise-sound RFC. Two **critical**:
- **Feas-C1** — S4's "corpus green" test was a false positive: the harness carve-out
  (`_fixture_entry_trust_config` returns None unless the field is *literally written*)
  never exercises the flipped default for un-migrated fixtures. Flip could ship broken
  with zero corpus signal. → S4 now must retrigger the carve-out on `effective_trust_policy`.
- **Feas-C2** — "~70+ fixtures" was ~3× low: real is **~228**, and it's an
  *index-trust* mechanical bulk-pin, not entry-trust (entry-trust self-resolves via
  no-epoch-armed). → S4 split into two different-shaped jobs.

## Round 2 edits applied to the RFC
- **§1** — named the real S-Epoch build surface (typed `attestation-epoch` doesn't
  exist in `parse_index`; only `index_ratchet_seam._raw_attestation_epoch` raw differ;
  `published_at` not on `_Candidate`'s 9 sites).
- **D2** — escape-hatch subsystem fix (entry bundles have no four-state freshness cache;
  named the 3 real hatches).
- **D3** — no-revocation NOTE + subject-cardinality=1 carried into normative §3.6.
- **D5** — epoch classification is a first-class build; **its `published_at` mechanism
  was later SUPERSEDED by D-Watermark** (§8c) → four `epoch_basis` values
  (in-pre-epoch-set / not-in-set / no-commitment-armed / commitment-verification-failed),
  composed `EntryGateOutcome` (D9), pinned per-`epoch_basis` remediation prose. (Round 2
  first hardened the five-branch published_at predicate — malformed-epoch fail-closed,
  tz-normalization — then D-Watermark replaced the whole boundary oracle.)
- **D6** — store-backend hint split (file vs http) + full `_HINT_MAP` audit (default `warn`, not `off`).
- **D7** — corrected patch shape (additive two-file `verify_digest`-body extract on
  async + blocking Verifier; NOT the subtractive #183 shape; `verify_entry_inclusion` is real reuse).
- **D9** — one composed `EntryGateOutcome` diagnostic type (not 3 parallel discriminators).
- **D10** — one shared §3.x gate-pipeline model; §3.4/§3.6 instantiate it (no prose-drift).
- **D11** — index-trust/entry-trust degradation asymmetry is correct-by-design (grace-on-absence
  = MITM strip bypass); documented + self-hosted `index-trust "off"` migration note.
- **D12** — "verified-at-resolve" scoped same-invocation only; cold `show` stays "claims"
  (avoids §3.9 claim/outcome conflation + set-once-epoch time travel).
- **R3** — worked-example policy table. **R3.5** — generic gate model (D10). **R4** —
  §3.6 instantiates the model + cross-axis precedence sentence + residuals + `EntryGateOutcome`.
  **R8** — D12 scoping. **R10** — cli-contract §5.4 `verify` attestation (was silent,
  contradicted §3.4.1). **R11** — conformance-fixtures.md real-crypto tier catalog.
- **S2/S3/S-Acq/S-Epoch/S-RustCrypto/S6/S4/S5/S8/S9** — all updated to match (see RFC §6).
- **§8** — (a) discharged (subsumed into S6 as sharpened subject-NAME risk); (b)/(c) escalated.

## /loop grind progress (2026-08-04)
RFC committed `8fb4038`. Delegating each slice to a sonnet subagent (NO-GIT); control loop verifies + commits. Harness run via repo-root `.venv/bin/python -m pytest harness/`. **Known-pre-existing baseline: 2 failed (`test_slice_c_seed.py` FROZEN-IDENTITY-NOT-IN-STORE) + 8 errors (`test_harness.py` 'git-protocol' unknown fixture cmd)** — unrelated to this RFC; a slice is green iff it adds passers and leaves exactly this baseline.
- **S1 done** `d2b36b7` — retired the dangling forward-refs; `harness/test_spec_attestation_reconcile.py` (11) pins them absent.
- **S2 done** `798f6e2` — §3.3a generic model, §3.4 reduced to instantiation, §3.6 entry gate, §3.4.8/9 epoch-commitment phase; `harness/test_spec_layer2_gate.py` (21). **Two NEW slugs introduced** (`TNG-INDEX-EPOCH-COMMITMENT-INVALID`, `TNG-INDEX-EPOCH-RATCHET-REQUIRED` for the D18 config error) → **S9 must add both to `errors.md` bijection** w/ raise-sites. New field `attestation-epoch-commitment` (Append-once §3.5.1 row) → **conformance must audit fixtures 389/409** so arming alongside unchanged `attestation-epoch` doesn't trip `TNG-INDEX-ROOT-MUTATED` (spec clause added; no fixture exercises the new field yet).
- **OBLIGATION for S3 (surfaced during S2 review):** §3.6.2's table splits crypto into stage 5 (cert-chain+DSSE) / 6 (signer-policy) / 7 (Rekor inclusion) and asserts 6-before-7 via first-failing-stage-wins. But the reference impl (`entry_trust.py:295-373`) delegates 5-7 to ONE `verify_dsse` call, distinguishing only `SignerMismatch` (policy_raised) vs `SignatureInvalid` — it does NOT guarantee a signer-before-Rekor total order. §3.3a's "observable outcome, not internal control flow" NOTE currently covers it, but S3 (verification-steps pin) MUST reconcile the exact 5/6/7 ordering against the single delegated call (confirm the impl reports SIGNER-MISMATCH when signer+Rekor both fail, or relax the normative order). S7's wrong-signer×bad-Rekor vector + S8 differential would trip a real mismatch.

## Slices (re-sequenced; order IS execution order)
- [x] S1 — reconcile §3.2 + retire ALL dangling forward-refs (R1,R2) — `d2b36b7`
- [x] S2 — §3.x generic gate model (D10) + new §3.6 epoch-aware, EntryGateOutcome, cross-axis precedence (R3.5,R4) — `798f6e2`
- [x] S3 — verification-steps normative pin (§3.6.2a) + leaf-cert caveat + no-revocation NOTE + subject-cardinality=1 (D3) — `43c580b`. **Stage-ordering obligation RESOLVED** (grounded in sigstore-python source): signer-policy is guaranteed before Rekor/DSSE ⇒ SIGNER-MISMATCH wins over those; cert-chain validity precedes signer-policy ⇒ chain failure → SIGNATURE-INVALID even with signer mismatch. No code change needed.

**SPEC TRANCHE (S1–S3) COMPLETE.** Spec is settled; next tranche = BUILDS (S-Acq → S-EpochCommitment/S-EpochGate → S-RustCrypto). Build slices need the full gates: `cd impls/python && uv run pytest` (~90s) AND `./dev-rust test` (Rust, podman). Next slice = **S-Acq** (MILPA_INDEX_URL 3-way wiring, both impls, `cli.py:1131`/`main.rs:3492`).
- [x] S-Acq — MILPA_INDEX_URL 3-way wiring + store-backend hint split + _HINT_MAP audit (C3/D6) — `66e2682`. Both impls: shared `_resolve_index_url_three_way`/`resolve_index_url_three_way` SSOT (dedup'd the sibling dep-decl store); `_bundle_missing_hint(cause, backend)` + `BundleStoreBackend` enum (Rust); escapes default to `warn`. Full Python suite exit 0 (NOTE: this env's `pytest -q` prints no final summary line — exit code IS the gate); Rust 1633 passed in-container.
      **Test-infra note:** full `uv run pytest` exceeds a 2-min foreground timeout (~3769 tests); run it `run_in_background: true` and gate on exit code, or run targeted files foreground.
- [x] S-EpochCommitment — **COMPLETE both impls**: Python `17e7df4` (full suite exit 0), Rust `ccd6f95` (`./dev-rust test --workspace` 1656 passed). **Byte-exact `C` parity PROVEN** via golden vectors V1–V4 (pinned in both impls). Rust confirmed `Version::Ord` ignores semver build metadata → the raw-version tiebreak (my Python determinism fix) was a real cross-impl requirement. Rust added `OrderKind::AppendOnce`; both slugs in Rust `error.rs all_codes()` (bijection green). **Live tianguis re-arm still pending** (S9 tracking issue) — not a code blocker. New `impls/python/milpa/epoch_commitment.py`; wired in `cli.py:_apply_epoch_commitment_phase` inside `_load_index_for_verb` (after index-trust, before selection). Both slugs in errors.py+errors.md (bijection green).
      **RUST MIRROR — reproduce the canonical `C` BYTE-FOR-BYTE (D16 determinism):**
      - Identity = `(namespace, name, version, content_hash)` (raw strings, verbatim).
      - `sorted_deduped(S)`: dedup = exact 4-tuple equality; **sort key = (namespace, name, version_precedence_key, content_hash, RAW version string)** — the raw version string is the FINAL tiebreak making the order TOTAL. **Critical:** without it, `1.0.0` vs `1.0.0+build` (precedence-equal, distinct) collide → input-order-dependent `C` → cross-impl divergence. Version precedence uses the Version ordering (parseable→`(0, *precedence)`, unparseable→`(1, raw)` bucket so the two never compare element-wise). Rust must match this bucketing + the raw tiebreak.
      - `canonical_bytes` = records joined by `\x1e` (RS); within a record, the 4 fields joined by `\x1f` (US); UTF-8. Preimage = `b"milpa-preepoch-v1:" + canonical_bytes`. `C = sha256(preimage)` lowercase hex.
      - Verify: pass `preimage` as `index_bytes` to the composed verifier (so it computes `sha256(preimage)==C` and binds bundle-subject==C); separately check on-index pointer==C; `E := integratedTime`. **Compose (Fulcio+DSSE+Rekor) against a dedicated re-arm signer — NOT inclusion-only.** Does NOT need S-RustCrypto (holds the S/C preimage locally → seed the unpatched `verify_digest` with preimage bytes, mirror `index_trust.rs:547`, R3-g).
      - Status `Unarmed|Armed(S,E)|ArmingInvalid`; ArmingInvalid ⇒ `TNG-INDEX-EPOCH-COMMITMENT-INVALID` (unconditional, before selection). D18: Armed+entry-strict+index-history≠strict ⇒ `TNG-INDEX-EPOCH-RATCHET-REQUIRED`.
      - Mirror the Python mock seam: env `MILPA_INDEX_EPOCH_MOCK_VERIFIER` (file://-only guard), re-arm signer `MILPA_INDEX_EPOCH_SIGNER` / `DEFAULT_REARM_SIGNER`. Unit matrix {Unarmed, Armed(valid), ArmingInvalid(bad-inclusion/bad-cert-DSSE/hash≠C/wrong-signer), D18 config-error} on synthetic status (NO tianguis).
      **Hard tianguis dep is only for going LIVE** (re-arm: commitment over `S` + production index-history=strict + dry-run/diff-of-`S` + interregnum grandfather-all + signer parity) — NOT for the synthetic-fixture unit matrix, which is this slice's green bar.
- [x] S-EpochGate — DONE `18eeb87` (Python exit 0; Rust core 1123 / conformance 0 fail). `classify_epoch_membership` + `effective_epoch_policy` (PostEpoch→configured, PreEpoch/Unarmed→warn-cap) + `EntryGateOutcome{result,epoch_membership,cause}` (D9), both impls, full matrix. **Armed 8 shared fixtures 367-375** (added `.epoch-commitment` sidecars whose `S` excludes the entry → PostEpoch → strict-fail preserved); both conformance runners wire the sidecar identically (`fixture_epoch_commitment_status`, mock crypto). Security: tamper→content_hash changes→falls out of `S`→PostEpoch→mandated.
- [x] S-RustCrypto — DONE `d85c06a`. Vendor patch: extracted `verify_digest_bytes(&[u8])` shared body; `verify_raw_digest` on async + blocking Verifier; Layer-1 unchanged (delegates via finalize); `entry_trust.rs` stages 5-7 wired (RecordingPolicy error map, offline). Crypto-safety invariant preserved (only skips `hasher.finalize()`). Tests: `verify_raw_digest` verifies the real `_oracle` bundle (patch positive proof); Layer-2 rejects tampered sig; **end-to-end Layer-2 positive is `#[ignore]` S6-GATED** (no real per-entry bundle in-repo). `./dev-rust test --workspace` 0 failed / 1 ignored. Tripwire comment in vendor patch (upstream issue = human follow-up, not filed).

### ✅ MINTING DONE (2026-08-04) — wall cleared for S6/S7/S4/S5
Real-crypto Layer-2 fixtures minted + committed (`6f4a977`): `conformance/spec-v1/_oracle/entry-attestation/{entry-attested-pkg.bundle, commitment.bundle, manifest.json}`. Minted via new milpa workflow `generate-entry-attestation-fixtures.yaml` (`infra` `42fe685`, fix `e7588d3`) using `sign_dsse` @ `sigstore==4.3.0` (= tianguis production parity = milpa's installed verifier). **Verified TRUSTED through milpa's OWN verifiers:** per-entry → `SigstoreEntryVerifier` TRUSTED (wrong-signer → SIGNER_MISMATCH); commitment → `verify_index_bundle` TRUSTED over the `S` preimage (subject == C). Signer SAN (= fixtures' `expected_signer`): `https://github.com/coreyleavitt/milpa/.github/workflows/generate-entry-attestation-fixtures.yaml@refs/heads/main`. Synthetic subjects: PASS entry `testns/attested-pkg@1.0.0` (`dag-sha256:9141…5772`); pre-epoch `S`={`testns/legacy-pkg@0.9.0` `dag-sha256:862b…06e4`}; `C`=`7d51aa49…2e8b`.
**NOW UNBLOCKED (autonomous /tdd):** S6 fixtures (use the minted bundles) → S7 FAIL matrix (derive by tampering; wrong-signer needs no 2nd identity) → un-ignore S-RustCrypto's `..._pending_s6` Rust test (verify the real per-entry bundle Trusted in Rust) → S4 flip + ~228 migration → S5 → S8 (+real-crypto differential) → S9.
**STILL live/Corey (small, non-blocking):** S6 prereq (ii) one real fetch+verify vs LIVE tianguis for the subject-NAME half (§8a); S9's production tianguis epoch re-arm.

### ⛔ (historical) COREY-GATED WALL — now cleared above
**S6/S7 require live-crypto minting** (OIDC/Fulcio/Rekor `dispatch→download→commit`) + reading tianguis `sign_statement.py` for signer parity + a real-registry NAME-verify — CANNOT be done unattended. **S4 (flip strict default) is gated behind S6/S7** (RFC §6/§7: "real-crypto fixtures exist before the flip they justify" — do NOT flip the security default without the proof). **S5 gated behind S4.** Also pending: the **live tianguis epoch re-arm** (S-EpochCommitment's production step). Unblocked remaining: **S-Backdate** (decision), **S8** (mock-seam differential — real-crypto differential add is S6-gated), **S9** (final cleanup — premature until the rest lands).
- [x] S6 — DONE `85ccf3c` (minting `6f4a977`). Per-impl real-crypto PASS tier (not shared corpus — real crypto can't be mock-mapped): both impls verify the minted bundles TRUSTED; Rust `_pending_s6` un-ignored. **Signer parity** = sign_dsse@4.3.0 (tianguis==milpa). **§8a discharged STATICALLY**: tianguis `buildEntrySubjectName` == milpa `build_entry_subject` byte-for-byte (documented mutual agreement) + prior softlink E2E — no flaky live fetch needed.
- [x] S7 — DONE `b10ddb2`. Real-crypto FAIL matrix both impls, all 10 vectors derived from the 2 minted bundles (unmodified-wrong-expected / byte-tampered / gate-level). Pre-epoch⇒WARN uses the REAL commitment bundle (Armed→PreEpoch→warn-cap); F-op interregnum = non-member⇒PostEpoch⇒mandated (published_at informational).
- [x] S-Backdate — **RETIRED** `0be3932` (spec-only). Decision resolved under the bar (vetoable): no distinct non-epoch purpose (published_at is informational; watermark inherits TOFU+omission holes), epoch-boundary purpose subsumed by ArmingInvalid → §3.5.4 states the retirement definitively; no slug defined (bijection green); 2 harness assertions pin it.

### 🛑 AUTONOMOUS GRIND STOPPED HERE — 8/14 slices done (2026-08-04)
**DONE (committed, in order):** RFC `8fb4038`; S1 `d2b36b7`; S2 `798f6e2`; S3 `43c580b`; S-Acq `66e2682`; S-EpochCommitment `17e7df4`(py)+`ccd6f95`(rust); S-EpochGate `18eeb87`; S-RustCrypto `d85c06a`; S-Backdate `0be3932` (+ handoff checkpoints). All spec + all builds landed and gated green (Python full-suite exit 0; Rust `--workspace` 0 failed).
**REMAINING 6 slices — ALL blocked on Corey's live-crypto action; loop stopped rather than re-hit the wall:**
1. **S6 (real-crypto strict-PASS fixtures)** — **COREY ACTION**: mint fresh per-entry + arming-commitment bundles via live OIDC/Fulcio/Rekor (`dispatch→download→commit`, like the Layer-1 `generate-attestation-fixture` flow). Prereqs: read tianguis `sign_statement.py` for **signer-toolchain parity** (cosign vs sigstore-python `sign_dsse` — differential blind spot) covering all THREE artifact types (index bundle, per-entry bundle, arming-commitment sidecar); one **real-registry NAME-verify** against live tianguis (2898 backfilled entries). Then S-RustCrypto's `#[ignore]`d `..._pending_s6` test un-ignores.
2. **S7 (real-crypto strict-FAIL matrix)** — needs S6's minted bundles (derive FAIL vectors by tampering) + an arming-commitment sidecar for the pre-epoch⇒warn row + an interregnum fixture.
3. **S4 (flip both defaults + corpus migration)** — gated behind S6/S7 (RFC: don't flip the security default before the real-crypto proof). Contains the **Feas-C1 harness carve-out fix** (`_fixture_entry_trust_config` must trigger on `effective_trust_policy`, not `explicit`) + the ~228-fixture index-shaped bulk `index-trust "warn"` codemod (Feas-C2).
4. **S5 (verify/show under strict)** — gated behind S4.
5. **S8 (differential attestation surface)** — mock-seam part is thin verify; real-crypto differential add needs S6; also the pre-existing `test_harness.py` `git-protocol` harness error (8 errors baseline) should be addressed here or noted.
6. **S9 (cleanup + doc reconcile)** — final close-out; **Corey territory**: file the upstream sigstore-rs raw-digest issue (S-RustCrypto tripwire), the break-glass follow-up issue; superseded-pointer to rfc-registry-trust-federation.md; self-hosted `index-trust "off"` note; **the live tianguis epoch re-arm** (commitment over `S` + production index-history=strict + dry-run/diff + interregnum + signer parity) with acceptance criteria; update comparison-vs-nimble-atlas.md; update [[v1_critical_path]] memory.
**RESUME:** after Corey mints S6 fixtures, `/loop` (or `/tdd`) resumes at S6→S7→S4→S5→S8→S9. Everything up to the real-crypto boundary is implemented and green.
- [ ] S4 — flip BOTH defaults; **fix harness carve-out false-positive (Feas-C1)**; ~228 index-shaped migration split from entry-trust free path (Feas-C2)
- [ ] S5 — verify/show under strict; verify-can't-self-heal remediation; no-epoch-armed notice; show --entry-trust parity-or-defer (R8,R10,D12)
- [ ] S8 — differential attestation surface; conditional on §8b (allow-list vs pin)
- [ ] S9 — doc reconcile incl. rfc-registry-trust-federation.md superseded-pointer + self-hosted migration note; break-glass follow-up issue; memory

## Round 2 review ledger
| id | lens | sev | finding | disposition |
|----|------|-----|---------|-------------|
| Feas-C1 | feas | crit | S4 corpus-green false positive (carve-out on `explicit`, not effective) | S4 retrigger on effective_trust_policy + prove-default test |
| Feas-C2 | feas | crit | ~228 not ~70; index-shaped not entry-shaped | S4 split into 2 jobs |
| D-H1 | depth | high | malformed-epoch fall-through (set-once typo permanently defeats mandate); no E parser; E not in tz clause | initially D5 fifth branch fail-closed; **now subsumed by D-Watermark** (commitment-verification-failed ⇒ fail-closed; no published_at/E parse at all) |
| D-H2/Feas-H5 | depth/feas | high | subject-NAME producer/verifier drift invisible to self-minted fixtures; signer toolchain (cosign vs sign_dsse) mismatch | S6 two prereqs (parity + real-registry verify) |
| D-H3/B-H2 | depth/breadth | high | "verified-at-resolve" reintroduces §3.9 conflation; verify can't self-heal on pre-flip lockfiles | D12 + R10 + S5 verify remediation |
| B-H1 | breadth | high | cli-contract §5.4 verify silent on attestation, contradicts §3.4.1 | R10 |
| B-H3 | breadth | high | index-trust has no self-hosted grace; asymmetric vs entry-trust | D11 (correct-by-design; document + migration note) |
| Feas-H3 | feas | high | S-Epoch real surface = new typed Index field + 9-site _Candidate plumbing | §1 + S-Epoch rewrite |
| Dsgn-H1 | design | high | epoch_basis promised explainable but only raw enum plumbed | D5 pinned per-basis prose |
| Dsgn-H2 | design | high | no-epoch-armed = silent strict→warn, zero observability (false confidence) | S5 one-time notice + show surface |
| D-MH4 | depth | med-high | §8c backdate residual understated: TOFU/CI get ZERO check, index-history-independent | §8c c2; D8 note |
| Dsgn-MH3 | design | med-high | 3 parallel ad-hoc discriminators (result/cause/epoch_basis) | D9 composed EntryGateOutcome |
| Feas-M4 | feas | med | "#183 patch shape" wrong (subtractive vs additive two-file) | D7 corrected + S-RustCrypto |
| D-M5 | depth | med | D2 cites four-state cache (Layer-1) for entry bundles | D2 rewrite |
| D-M6 | depth | med | no-revocation residual only in design-history RFC | D3 NOTE into §3.6 |
| B-M5 | breadth | med | cross-axis failure precedence never stated | R4/§3.6 normative sentence |
| B-M6 | breadth | med | S8 "identical slugs" contradicts §8b | S8 conditional + allow-list |
| Dsgn-M4 | design | med | §3.6 "mirroring §3.4" = prose restatement, drift risk | D10 shared model |
| Dsgn-M5 | design | med | Unattested hint recommends `off` (drastic) vs no-pin `warn` | D6 _HINT_MAP audit |
| B-M4 | breadth | med | show --entry-trust observability parity undecided | S5 parity-or-defer |
| Feas-M6 | feas | med(proc) | S6/S7 mint is manual live-infra, not RED-GREEN | S6 Corey-gated step named |
| D-LM7 | depth | low-med | unfetchable hint wrong for FileEntryBundleStore | D6 backend split |
| Dsgn-L6 | design | low | no worked example for effective-policy formula | R3 table |
| D-L8 | depth | low | multi-subject DSSE unaddressed | D3 cardinality=1 |
| B-L7 | breadth | low | conformance-fixtures.md catalog not updated | R11 |
| B-L8 | breadth | low | rfc-registry-trust-federation.md old default/criteria not in S9 | S9 |

## Round 1 outcome (retained for context)
Draft claimed "code is built, not new design"; 4-lens + code verification refuted on
three counts: **C1** epoch classification unbuilt both impls; **C2** Rust Layer-2
crypto stubbed (`entry_trust.rs:329`); **C3** `MILPA_INDEX_URL` 5-line wiring bug
misdiagnosed as acquisition-robustness gap. Decisions D1–D3 survived. Corey's two
forks: (1) one RFC reconcile+build+flip; (2) flip index-trust too (D4). D5–D8 + R1–R9
followed.

## Context pointers
- Verified code: `entry_trust.py` (no epoch), `entry_trust.rs:277-330` (stub),
  `cli.py:1131`/`main.rs:3492` (wiring), `index_trust.rs:77` (Layer-1 built),
  `registry.py:735` (epoch unparsed), `resolver.py` `_Candidate` 9 sites,
  `test_conformance.py:404`/`runner.rs:2377` (carve-out), `.vendor-sigstore`
  (`verify_digest` takes live `Sha256`; `verify_entry_inclusion` real),
  `_oracle/attestation/index.kdl.bundle` (`subject[0].name == "index.kdl"`, cosign-minted).
- Spec: `registry-protocol.md` §3.2/§3.4/§3.4.0/§3.4.1/§3.5.4/§3.6(new)/§3.x(new model),
  `cli-contract.md` §5.4/§8.6-8.8, `manifest-grammar.md` node lists,
  `lockfile-schema.md` §3.9, `conformance-fixtures.md`, `errors.md` TNG-ENTRY family.
- Design SSOT: `rfc-per-entry-attestation.md` (§1/§4/§5/§6/§7 + open Q2),
  `rfc-attestation-verifier.md` (§4 gap-3 cert caveat, §5 delegate-not-hand-roll),
  `rfc-registry-trust-federation.md` §6.1 (superseded default/criteria).
- 22 mock-seam entry-trust fixtures in `conformance/spec-v1/fixture-367..377`; tianguis
  `sign_statement.py` lives in the tianguis repo (read before S6).
