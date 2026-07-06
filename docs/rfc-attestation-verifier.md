# RFC: attestation-verifier completion — real SigstoreVerifier + offline Rekor inclusion verification

**Status**: Draft (Stage 1 — RFC + slicing; architect rounds 1 + 2 applied)
**Part of**: the registry-trust arc. Part 1 (`rfc-registry-trust-federation.md`, #103,
shipped `66f00ff`/`25bc246`/`9a0a755`) wired the trust *policy + gate*. This RFC
completes the actual *cryptographic verifier* behind that gate.
**Supersedes**: the "S4b NOT VIABLE" record in `afa06ae` (see Background).

## 1. Why this RFC exists

Part 1 shipped the whole-index trust gate — policy (`warn`/`strict`/`off`), cache
verify-every-read, DSSE subject-digest binding, the `IndexBundleVerifier` seam, and
the `MockVerifier` conformance path. But the **real** verifier is incomplete:

- **Rust**: `SigstoreVerifier::verify()` is an `unimplemented!()` placeholder (S4b,
  deferred). Under `strict` it fails closed with `TNG-INDEX-VERIFY-UNSUPPORTED`;
  under `warn` it loads the index ungated with a warning. It was blocked on
  sigstore-rs 0.11.0 gaps.
- **Python**: uses `sigstore-python`'s `Verifier.production(offline=True).verify_dsse`.
  **S0 (done) confirmed against source it fully meets §3.4.4 step 5**: `verify_dsse` →
  `_verify_common_signing_cert` → `entry._verify(rekor_keyring)` performs Merkle
  inclusion (leaf-hash chain to `root_hash`) **and** checkpoint verification (Rekor-key
  signature over the note + `checkpoint_hash == root_hash` cross-check), executed
  unconditionally; SET (`_verify_set`) is additionally checked *only when*
  `inclusion_promise` is present (Rekor v1) and correctly skipped for v2. sigstore-python
  4.3.0. So the Python Layer-1 is spec-complete; **the crypto gap is Rust-only.**

A 2026-07-03 spike against **sigstore 0.14.0**, re-verified during architect rounds 1+2
against the cloned source (`scratchpad/sigstore-rs/`), changed the picture:

- DSSE envelope verification — now supported (`BundleContent::Dsse` arm).
- Cert validity is checked internally by the high-level `Verifier` (with a precise
  limitation — see §4, gap-3 note: chain validity is verified at the leaf's own
  `not_before`, and only the leaf window is bounds-checked against `integratedTime`).
- **A public offline inclusion primitive exists** — but it is **not**
  `LogEntry::verify_inclusion` (see §4, corrected). The usable primitive is
  `rekor::models::InclusionProof::verify(entry: &[u8], rekor_key)`, which
  JCS-agnostically hashes the raw canonicalized-body bytes, verifies the Merkle
  inclusion proof, and verifies the signed checkpoint against the Rekor key.

So the Rust verifier is now **viable**, and this RFC makes milpa **actually meet
`spec/registry-protocol.md §3.4.4` step 5 (offline transparency verification)** in
Rust, matching what Python already does.

### 1.1 A second, separate gap this RFC surfaces: `milpa verify` is not wired

Round-1 exploration found that **neither impl** currently routes `milpa verify`
through the offline bundle reverify that `spec/registry-protocol.md` / Part-1 §6.7
claim it performs:

- Python `cmd_verify` → `_verify_dep_decl_pins` calls `load_default_index()` with
  **no verifier** — the gate is bypassed and the check that runs is online-only.
- Rust `cmd_verify` routes through `build_index_trust_gate` only for the online
  dep_decl edge check, not an offline reverify of the *cached bundle*.

S0's "Python Layer-1 is spec-complete" finding is about `verify_dsse`'s crypto in
isolation — it says nothing about whether `milpa verify` invokes it, and today it
does not, in either language. This is the one command whose entire purpose is
offline post-hoc audit (Part-1 §7.5 leans on it for post-incident remediation), so
the gap matters. **Resolved (§7 decision 2): wired in-scope here as slice Sv** —
leaving a shipped spec claim false is exactly the drift honor-the-spec forbids, and
the capability is a few lines once the real verifier lands.

### 1.2 Deployment sequencing (cross-repo dependency)

This RFC makes `strict` *really verify* and — after S4 — makes `warn`-mode Rust fetch
and crypto-check a real `.bundle` for the first time (today Rust `warn`+no-seam
short-circuits to `Ungated` and never fetches a bundle at all; see §6 S4). Both
depend on **tianguis actually serving `index.kdl.bundle`**, which is an open
cross-repo item (`coreyleavitt/tianguis`; tracked in the project-state memory).
Consequences to hold in view, not to solve here:

- **Python today already** constructs a real `SigstoreVerifier` on every non-conformance
  run, so `warn` users are *already* exposed to "bundle not yet served" behavior in
  production. Landing the Rust verifier brings Rust to the same state — it does not
  create the exposure, it equalizes it.
- Goal #3 ("strict now really verifies") is **operationally contingent** on the tianguis
  side shipping the bundle. Until it does, `strict` against production tianguis fails
  closed on a *missing* bundle (`TNG-INDEX-BUNDLE-MISSING`), which is correct
  fail-closed behavior but means the end-to-end path is not exercisable against prod.
- **Add a manual smoke test** (mirroring CLAUDE.md's "Real fresco verification" pattern):
  once both sides ship, verify a real `fetch` under `strict` against the production
  tianguis URL end-to-end, so this doesn't quietly ship as dead code. Recorded as a
  checklist item on S5, not a slice.

## 2. Goals

1. A real Rust `SigstoreVerifier`: DSSE + cert validity + signature + subject-digest +
   **offline Rekor inclusion-proof / checkpoint verification** via `InclusionProof::verify`.
2. A real, committed Sigstore trust root (Fulcio + CTFE + Rekor material) replacing
   today's `{"__placeholder__": true}` stub — stored in the **standard `trusted_root.json`
   format** (not a milpa-invented schema; see S1.5), with a documented, re-runnable
   population procedure and a key-retention discipline.
3. Remove the `unimplemented!()` placeholder and the `TNG-INDEX-VERIFY-UNSUPPORTED`
   fail-closed stopgap; `strict` now really verifies.
4. Contribute the inclusion-verification wiring **upstream** to sigstore-rs so
   milpa can eventually drop its own adapter — with a forcing function so the
   temporary adapter does not become permanent unowned debt.

## 3. Non-goals

- Part-2 per-entry attribution (`rfc-per-entry-attestation.md`).
- Live/online Rekor lookups — offline stays the model.
- Any change to the policy/authority model or the cache state machine (Part 1, done).
- **`milpa show --index-trust` performs no cryptographic verification.** `show` calls
  `describe_index_bundle` and reports what the bundle *claims*; `fetch`/`verify` are
  where trust is *enforced*. That boundary (no trust badge in `show`) is intentional and
  unchanged by a real verifier.
  - **But note a genuinely separate, cheap improvement this RFC's S2 unlocks:** today
    `show`'s `signer:`/`issuer:`/`subject-sha256:` fields are read *only* from the
    mock-only `_milpa_claims` fixture section, so a **real** bundle prints
    `(not available)` for all three (see `cli-contract.md §5.3a`,
    `index_trust.py:632-747`, `index_trust.rs:696-784`). S2 must parse the DER cert and
    the DSSE in-toto payload anyway — extracting SAN / issuer / `subject_sha256` from
    those is pure *decoding*, not verification, and does **not** cross the boundary above
    (it changes *which source* the descriptive field is read from, not whether `show`
    claims to have verified anything). This is deliberately **deferred to a follow-up
    issue** (filed per the defer-file-now discipline), kept out of this RFC's core so the
    verifier work stays focused — but §3 no longer forecloses it as "never," because it
    is adjacent, cheap, low-risk work sitting directly on top of S2. **Filed: #182.**
- Operator-facing trust documentation (emergency `off` bypass, rotation runbook) — the
  content lives in Part-1 §12.3 prose; surfacing it in a discoverable `docs/` operator
  page is out of scope here (candidate follow-up, noted so it isn't mistaken for done).

## 4. Background: the spike findings (baked in so they survive)

Three gaps were recorded against sigstore-rs 0.11.0 in `afa06ae`; status in **0.14.0**:

| Gap (0.11.0) | 0.14.0 status |
|---|---|
| DSSE bundles → `DsseUnsupported` | **CLOSED** — `BundleContent::Dsse { pae, subject_sha256_digest, .. }` arm; passing DSSE test suite (`bundle_v03.json`). |
| Rekor SET + Merkle inclusion = TODO (#285) | **PARTIAL** — #285 merged the proof *primitives* (`crypto/merkle/*`, public `InclusionProof::verify`), but they are **not wired** into the bundle verifier's step-5 TODO (`verifier.rs:198`). |
| `CertificatePool` `pub(crate)` (cert-at-time) | **MOOT for chaining** — the high-level `Verifier` does cert validation internally, so milpa needs no direct `CertificatePool` access. See the gap-3 note below for the *precise* (weaker-than-Part-1-text) guarantee it delivers. |

**gap-3 note — cert-at-`integratedTime` is narrower than Part-1's text.** `verifier.rs:147-161`
verifies the certificate chain at the **leaf cert's own `not_before`** (`issued_at =
tbs_certificate.validity.not_before`), and the code's step "7" (`verifier.rs:204-219`)
only bounds-checks the **leaf's** `[not_before, not_after]` window against
`integratedTime` — it does **not** re-verify the intermediate/root CA chain *at*
`integratedTime`. Part-1 §4 step-4 says "certificate validity MUST be checked at the
Rekor SET `integratedTime`," which is *stronger* than what the crate delivers chain-wise.
For Fulcio's ~10-minute ephemeral certs the two times coincide in practice, so this is an
**inherited crate limitation milpa accepts** (fixing it means patching upstream), recorded
here so the RFC does not overstate the guarantee. If a future threat model needs true
chain-at-`integratedTime`, that is an upstream change tracked alongside S7.

**The adapter — corrected in round 1, mechanics nailed down in round 2.** The RFC's
earliest plan (reconstruct a `rekor::models::LogEntry` and call
`LogEntry::verify_inclusion`) is **unimplementable** for milpa's bundles, confirmed
independently against source:

- `LogEntry::verify_inclusion` requires a populated `LogEntry.body: Body`, and `Body`
  (`rekor/models/log_entry.rs:71-81`) is a closed `#[serde(tag="kind")]` enum:
  `alpine|helm|jar|rfc3161|rpm|tuf|intoto|hashedrekord|rekord`. **There is no `dsse`
  variant.** tianguis's `cosign attest-blob` produces `kind:"dsse", apiVersion:"0.0.1"`
  (confirmed against the crate's own `bundle_v03.json` fixture and its
  `tlog_entry_for_dsse` gate at `bundle/verify/models.rs:409`). Deserializing a
  `"kind":"dsse"` body into `Body` fails "unknown variant" — the adapter cannot even
  construct its input.

- **The correct target is `rekor::models::InclusionProof::verify(entry: &[u8], rekor_key)`**
  (`rekor/models/inclusion_proof.rs:63`). It takes **raw bytes** — the tlog entry's
  `canonicalized_body`, verbatim, exactly as Python passes `entry._inner.canonicalized_body`
  — never touches the typed `Body` enum, and internally does
  `hash_leaf(entry)` → Merkle `verify_inclusion` → `checkpoint.verify_signature(rekor_key)`
  + `checkpoint.is_valid_for_proof` (root-hash cross-check). Confirmed present, `pub`,
  and matching this flow at `inclusion_proof.rs:63-95`.

- **Construction path (already-public surface only):** the semantic
  `rekor::models::InclusionProof` has **all-`pub` fields** (`inclusion_proof.rs:24-42`:
  `log_index`, `root_hash`, `tree_size`, `hashes`, `checkpoint`). The **simplest** buildable
  path is therefore a **direct struct literal** from the protobuf
  `TransparencyLogEntry.inclusion_proof` (raw `Vec<u8>` hashes/root_hash) — only the
  `checkpoint` field needs the indirect route, via the crate's `SignedCheckpoint`
  `Deserialize` impl (`checkpoint.rs:~215`; `SignedCheckpoint::decode` itself is
  `pub(crate)`, so `Deserialize` is the public door). The hex-string
  `RekorInclusionProof` → `TryFrom<&RekorInclusionProof> for InclusionProof`
  (`log_entry.rs:178`, confirmed `pub` and reachable) also works but forces a gratuitous
  hex-encode/hex-decode round trip; prefer the direct literal, use `TryFrom` only if it
  proves cleaner in practice. (Doc-accuracy nit for the S3 comment: that `TryFrom`
  internally calls `SignedCheckpoint::decode` *directly* via same-crate access, not via
  the public `Deserialize` — milpa uses `Deserialize` because milpa is out-of-crate. The
  *target* remains `InclusionProof::verify`.)

- **`InclusionProof` name collision (implementer hazard).** `bundle/verify/models.rs:26`
  imports `sigstore_protobuf_specs::...::rekor::v1::InclusionProof` (the raw protobuf wire
  type) under the *same name* as `sigstore::rekor::models::InclusionProof` (the semantic
  type with `.verify()`). The S3 adapter touches both. Its module MUST alias them
  (e.g. `use ...protobuf...::InclusionProof as ProtoInclusionProof`) and the doc comment
  MUST call the collision out, or a shadowing bug is nearly guaranteed.

**Composition binding — corrected in round 2 (the round-1 phrasing was unbuildable).**
Round 1 said "assert the extracted entry's `canonicalized_body` is byte-identical to what
`verify_digest` accepted." That is **not implementable**: `Verifier::verify_digest`
(`verifier.rs:117`) consumes `bundle: Bundle` **by value**, converts it to a
`pub(crate) CheckedBundle` internally, and returns only `VerificationResult =
Result<(), VerificationError>` (`bundle/verify/mod.rs:20`). It hands back **no**
`CheckedBundle`, `materials`, or validated `TransparencyLogEntry` — there is nothing on
the other side to compare against, and a "byte-identical" check between two deterministic
parses of the same bytes is trivially true and protects nothing. The **actual buildable
design** (all-public API):

1. Parse `bundle_bytes` **once** into the public `sigstore::bundle::Bundle`
   (`serde_json::from_slice`, idiomatic per the crate's own
   `tests/conformance/conformance.rs:163`).
2. Assert `verification_material.tlog_entries.len() == 1` — mirroring the crate's own gate
   (`bundle/verify/models.rs:285-288`, `BundleErrorKind::TlogEntry`). Because exactly-one-
   entry is structurally enforced on *both* sides, "same entry" is a **structural**
   guarantee, not a runtime byte comparison — there is no entry-selection ambiguity to
   worry about.
3. Thread that **same owned `Bundle` value** (or a `tlog_entries[0]` clone taken *before*
   the value is moved into `verify_digest`) through *both* the high-level `verify_digest`
   call **and** S3's `InclusionProof::verify`. The composition is sound because both
   operate on one parse of one byte string with a proven-singleton entry — never two
   independent re-parses.

Regression test still required: a validly-included but *differently-signed* Rekor entry
paired with an otherwise-valid DSSE envelope MUST be rejected (guards against a future
refactor that re-parses instead of threading).

**Error-taxonomy gap — new in round 2 (affects S2's slug precision).** milpa's
`VerificationResult` (`index_trust.rs:132-158`) needs to distinguish `DigestMismatch` from
`SigInvalid`. The crate **cannot** support that distinction through its public API: the
only re-exported error type is `VerificationError` (`verify/mod.rs:20`); its inner
`SignatureErrorKind`/`BundleErrorKind`/`CertificateErrorKind` are `pub` but nested inside
`pub(crate) mod models`, so they are **unnameable outside the crate** (grep-confirmed: no
re-export). Both "bad signature" (`SignatureErrorKind::VerificationFailed`) and "subject
digest mismatch" (`SignatureErrorKind::Transparency`, set in the DSSE arm at
`verifier.rs:66-84`) — *and* tlog/envelope-consistency failures inside
`tlog_entry_for_dsse` — collapse into one opaque `VerificationError::Signature(_)`,
separable only by fragile `Display`-text matching (which Part-1 §4 step-6 explicitly
forbids: "detect digest mismatch from the verified payload, NOT from exception message
text"). **Fix (S2):** milpa independently pre-derives and compares the subject digest
*before* calling the crate verifier — parse the DSSE payload's in-toto
`subject[0].digest.sha256` (a small hand-rolled JSON read; the crate's own
`InTotoStatementV1` is `pub(crate)`, so milpa parses the field itself — this is *reshaping
already-parsed data*, no crypto, §5.1-compliant) and compare to `sha256(index_bytes)`.
Only on a digest match does milpa call `verify_digest`; any `VerificationError::Signature(_)`
surfacing afterward is then unambiguously bucketed as `SigInvalid`. `SignerMismatch` is
*not* affected — `policy` is a fully `pub mod` (`policy.rs:163-164`), so a custom
SAN-matching `VerificationPolicy` is straightforward.

**Two soundness traps the adapter must guard (round-1 depth findings, refined in round 2):**

1. **Fail-open on absent proof under `offline=true`.** The crate's `tlog_entry_for_dsse`
   only rejects a missing `inclusion_proof` when `!offline`; under `offline=true`
   (milpa's *only* mode) a bundle whose `tlogEntries[0]` carries **no inclusion proof at
   all** passes step 4. **Round-2 refinement:** for **v0.2/v0.3-profile** bundles,
   `check_02_bundle` (`bundle/verify/models.rs:~330`) *already* rejects a missing
   `inclusion_proof`/`checkpoint` at `CheckedBundle` construction, before that fail-open
   branch is reachable — so the trap is **only live for v0.1-profile** bundles (which
   tolerate missing proof by design, relying on `inclusion_promise`/SET). milpa MUST
   therefore **state its accepted bundle profile** (see below); the explicit
   absent-proof rejection in S3 is retained as belt-and-suspenders but is *dead
   defense-in-depth* if milpa only accepts v0.2/v0.3.

2. **Composition binding** — see the corrected "parse once, thread the same value"
   design above. `InclusionProof::verify` alone only proves "*this body* was included in
   a checkpointed tree signed by this Rekor key"; it does not bind that body to the DSSE
   envelope/cert/signature. Threading one owned singleton-entry `Bundle` through both
   paths is what supplies the binding.

**Accepted bundle profile.** milpa accepts **v0.3** bundles (modern `cosign attest-blob`
output — `application/vnd.dev.sigstore.bundle.v0.3+json`), and MAY accept v0.2 (same
construction-time proof/checkpoint enforcement). milpa does **not** accept v0.1
(`inclusion_promise`/SET-only, no offline inclusion proof) — an offline-only verifier
cannot honor v0.1's online-promise model. S3's absent-proof negative test therefore
targets a v0.1-shaped fixture *to assert milpa rejects the profile itself*, not to
exercise a live fail-open on the accepted profiles.

**Rekor-key lookup contract (new in round 2).** `Verifier::new` (`verifier.rs:96-108`)
pulls only `trust_repo.fulcio_certs()` + `ctfe_keys()` — it **never** touches
`rekor_keys()`. So S3's adapter must **independently hold the trust root** and call
`.rekor_keys()` itself. The crate's own convention (`trust/sigstore/mod.rs:197-221`) keys
the `BTreeMap<String, Vec<u8>>` by `hex::encode(log_id.key_id)`, values = raw SPKI DER
(consumable by `CosignVerificationKey::try_from_der`). S1.5's parser MUST use the **exact
same `hex::encode(key_id)`** map-key convention, or S3's per-entry key lookup silently
finds nothing. Pinned here because it is precisely the kind of "two slices done apart,
silently incompatible" gap the slicing discipline exists to prevent.

**SET vs inclusion:** there is no public SET-verification primitive, but inclusion-proof +
signed-checkpoint IS the strong *offline* guarantee (SET is the weaker online promise).
§3.4.4 step 5 is satisfied by `InclusionProof::verify` alone. This matches Python, which
only checks the SET when an `inclusion_promise` is present (Rekor v1) and skips it for v2.

## 5. Strategy decision (the central fork)

Two clean routes to full compliance:

- **B-upstream** — wire `InclusionProof::verify` into the verifier's own step-5 TODO
  (`verifier.rs:198`), where the `TransparencyLogEntry` and trust root are already in
  scope. Cleanest (maintainers own it; it's their TODO), but carries merge/release
  latency we can't schedule around.
- **B-milpa** — put the adapter + `InclusionProof::verify` call in milpa's own
  `SigstoreVerifier`, after `verify()`. Full compliance immediately; milpa owns the
  reshaping glue, but the crypto underneath is the crate's audited primitive.

**Recommendation: both.** Ship B-milpa for immediate compliance (honor-the-spec: we
cannot leave `strict` on a fail-closed stopgap waiting for an upstream release); submit
the upstream PR in parallel; delete milpa's adapter when it releases. The duplication is
*temporal* (vendor → upstream → delete), not the parallel-mechanism kind the
audit-for-duplication discipline targets — provided S7 has a forcing function (below).

### 5.1 The hand-roll-vs-delegate principle (named, because it recurs)

Python delegates 100% of cert/DSSE/inclusion verification to sigstore-python; Rust must
call the low-level `InclusionProof::verify` itself because the high-level verifier's
step-5 is still a TODO. That asymmetry is legitimate under Part-1 §5.3 ("signature and
transparency-log verification MUST NOT be hand-rolled") **because the adapter reshapes
already-parsed protocol data — it reimplements zero cryptographic operations.** State
the rule generally, since Part 2 and future OCI/cosign work will hit the same
half-viable-upstream-API shape:

> An impl MAY write an adapter that reshapes already-parsed protocol data to satisfy an
> audited library's public API, provided it reimplements **no** cryptographic operation
> (hashing, signature math, canonicalization, Merkle verification) — all such logic MUST
> remain inside the library call. An impl MUST NOT hand-roll the crypto itself.
>
> **Composition clause (round-2 addition):** an adapter that composes multiple
> verification steps MUST operate on the *same underlying parsed artifact/bytes* across
> every step — never re-parse an independent copy and rebind one step's output to it.
> (This is the harder-to-see failure class that the composition-binding design in §4
> guards against; banning hand-rolled crypto alone does not cover it.)

Corollary for the conformance story: "one behavior, two impls" holds for *outcomes*
(both verify offline inclusion) but not for *code ownership* (Rust owns adapter code
Python doesn't). §10.1's policy-only shared corpus already scopes around this; the
per-impl integration tests (S5) and the cross-impl differential (S5.5) cover the rest.

## 6. Slices (Stage-1 slicing — `/tdd`-sized; re-sliced across rounds 1+2)

- **S0 — investigation. ✅ DONE (2026-07-03).** sigstore-python 4.3.0 `verify_dsse`
  verifies the inclusion proof + signed checkpoint (+ SET when present) offline. **Scope
  resolved: this RFC is "Rust catches up to Python" on crypto, plus the cross-cutting
  `milpa verify` wiring (§1.1) and the trust-root population (S1.5) that Part 1 left as
  a stub.**

- **S1 — dep bump + dependency hygiene (mechanical prelude, not a TDD slice).**
  - `sigstore` `0.11 → =0.14.x` in `milpa-core`, **pinned exact** (the S3 adapter depends
    on the crate's internal protobuf shapes; a silent minor bump could break it). Use the
    exact published 0.14 patch version, confirmed at bump time.
  - Add `sigstore_protobuf_specs` **explicitly** as a direct dep, pinned to the version
    sigstore-rs 0.14 resolves (upstream pins it as caret `"0.5"`; milpa hard-pins the
    resolved `=0.5.x` — *more* conservative than upstream, not "matching" its range) —
    because `sigstore::bundle` re-exports only `Bundle`, not `TransparencyLogEntry` /
    protobuf `InclusionProof` / `Checkpoint`, which S3 must destructure.
  - **Feature list — explicit, and it MUST include `rekor`.** `sigstore::rekor::models::{
    RekorInclusionProof, InclusionProof, checkpoint::SignedCheckpoint}` — S3's actual
    construction targets — are behind `#[cfg(feature = "rekor")]` (`lib.rs:268`), a
    *different* feature from `bundle`/`verify` (which gate the S2 high-level `Verifier`
    path). Enable both, or S2 compiles and S3 fails to compile a slice later. Replace
    implicit default features with the explicit list; **drop `native-tls`** and any
    online-fetch backend an offline-only verifier doesn't need. Record the rationale in
    the `deps-rationale` comment per §5.3.
  - **New transitive: `tokio`.** sigstore-rs's bundle verifier is async; its
    `blocking::Verifier` (`verifier.rs:269-345`) builds its own current-thread runtime
    per instance. `milpa-core`/`milpa-cli` have **zero** tokio today. No nested-runtime
    panic risk (milpa has no existing async context), but S1's gate must (a) note the new
    runtime weight and (b) confirm `sigstore`'s own tokio feature set (`features=["rt"]`)
    covers what `blocking::Verifier`'s `enable_all()` needs.
  - Gate: `cargo tree -d` shows no new duplicate/conflicting versions in the workspace
    (must be run with real network access, i.e. inside `./dev-rust`).
  - Existing Rust compiles; `MockVerifier` conformance path stays green; the
    `unimplemented!()` placeholder still stands. No behavior change.

- **S1.5 — real trust root via the STANDARD `trusted_root.json` (NEW; round-2 redesign).**
  Today `TrustBundle::production()` loads `{"__placeholder__": true}`. **Do not invent a
  milpa-specific trust schema** — the standard Sigstore `trusted_root.json` format already
  exists and sigstore-rs already parses it (`SigstoreTrustRoot::from_trusted_root_json_unchecked`,
  `trust/sigstore/mod.rs:99`, into a `TrustRoot` — the same trait `ManualTrustRoot`
  implements). This slice:
  - **Commits the raw `trusted_root.json` verbatim** as the embedded production trust
    material (Part-1 §3.1's build-time embedding, no runtime fetch). The standard format
    already carries Fulcio CAs / Rekor keys / CTFE keys as arrays with `validFor` time
    ranges — which *is* the "add new material on rotation, don't delete old" discipline,
    solved upstream, not something milpa hand-documents.
  - **Writes a small (~30-line) TDD-able mapper**, `trusted_root.json` bytes →
    `sigstore_protobuf_specs::...TrustedRoot` → `ManualTrustRoot { fulcio_certs,
    rekor_keys, ctfe_keys }` (shape at `trust/mod.rs:34`), mirroring
    `SigstoreTrustRoot::ca_keys`/`tlog_keys`/`is_timerange_valid`
    (`trust/sigstore/mod.rs:196-233,300-321`). This keeps the **runtime binary free of the
    `sigstore-trust-root` feature** (which pulls `tough`+`futures`+`async-trait` — genuine
    weight an offline verifier shouldn't carry, consistent with S1 dropping `native-tls`).
    **The mapper MUST key `rekor_keys` by `hex::encode(log_id.key_id)`** (see §4
    Rekor-key-lookup contract), tested against a fixture, or S3's lookup finds nothing.
  - **Population is a network-only `cargo run --example` (not a test).**
    `SigstoreTrustRoot::new()`/TUF fetch needs network, so the one-time regeneration script
    lives as an explicit example (may depend on `sigstore-trust-root` as an
    example/dev-only dep), **excluded from `cargo test` / `./dev-rust test`** so it never
    fights the hermetic-test discipline. Document the exact `cargo run --example …`
    invocation and the retention rule (add new material, keep old, so S5 fixtures still
    verify at their `integratedTime`).
  - Cross-reference Part-1 §12.3: this population script is the concrete tool that
    operationalizes §12.3's committed maintainer rotation process — one sentence so a
    future maintainer doesn't rediscover the link.

- **S2 — real verify() end-to-end, INCLUDING offline inclusion (round-2 merge of former
  S2 + S3; the §3.4.4-step-5 core).** *Round-1 split "real verify() without inclusion"
  then "add inclusion." Round 2 collapses them:* `Verifier::verify_digest` is monolithic
  and its step-5 is a no-op comment, so a "verify() without inclusion" intermediate would
  return `Trusted` for a bundle whose inclusion was **never checked** — a silent
  fail-open with no safe milestone to land as its own commit. There is no partial-
  correctness midpoint, so this ships as one atomic secure unit. Contents:
  - **Digest pre-check first** (§4 error-taxonomy fix): parse the DSSE in-toto
    `subject[0].digest.sha256`, compare to `sha256(index_bytes)`; mismatch ⇒
    `TNG-INDEX-DIGEST-MISMATCH` deterministically, *before* the crate call.
  - **Parse `bundle_bytes` once** into `sigstore::bundle::Bundle`; assert exactly one
    tlog entry; thread that same owned value through both the crate `verify_digest` call
    and the inclusion adapter (§4 composition-binding design).
  - **High-level verify** via `SigstoreVerifier` (cert validity + DSSE + signature +
    SAN policy), behind the `IndexBundleVerifier` seam. Any post-digest-check
    `VerificationError::Signature(_)` ⇒ `TNG-INDEX-SIGNATURE-INVALID`.
  - **Offline inclusion** via the adapter module (below) → `InclusionProof::verify(
    &entry.canonicalized_body, rekor_key)`, rekor_key looked up from S1.5's trust root.
  - **All steps execute; any step's failure aborts the whole call** (matches Python's
    single-function sequencing and §3.4.4 step order). Regression test: valid
    cert-chain-at-time + failing inclusion ⇒ overall failure, so a later refactor can't
    silently reorder into a fail-open.
  - Note: `TrustBundle` is `&'static [u8]` — each `verify()` reparses it into a typed
    trust root; acceptable (verification is per-resolve, not hot-path).
  - **The inclusion adapter lives in a dedicated module** (`milpa-core/src/rekor_adapter.rs`):
    - **Return type is a milpa domain enum**, not a bubbled crate error — e.g.
      `AdapterOutcome::{ Malformed(reason), CryptoInvalid, Included }` — so structural-vs-
      crypto classification lives at the boundary where the context is, matching the
      existing `VerificationResult::to_slug` SSOT (`index_trust.rs:177-196`) rather than
      leaking sigstore error-kind peeking into `SigstoreVerifier`.
    - One public function reshaping the singleton `&TransparencyLogEntry` → the
      `InclusionProof::verify` input (direct struct literal from `pub` fields; checkpoint
      via `SignedCheckpoint` `Deserialize`; §4 construction path). Aliases the protobuf
      vs semantic `InclusionProof` name collision (§4).
    - Doc comment states the invariant it preserves and cites the upstream gap
      (`verifier.rs:198`, sigstore-rs#285) it stands in for — so S7's deletion is a `rm`
      + one-call-site swap, not surgery on the 1442-line `index_trust.rs`.
    - **Structural** reshape failures (missing/renamed protobuf field, unrecognized
      shape, absent inclusion proof, a canonicalization mismatch that is a milpa bug not
      tamper) map to `TNG-INDEX-BUNDLE-MALFORMED` (pre-crypto, structural, per spec
      first-failure precedence). An adapter panic MUST NOT surface as a raw Rust panic /
      `MILPA-INTERNAL` — it must be a typed `TNG-INDEX-*` slug.
  - **Negative-test checklist** (resolves old open fork #5; vectors the crate itself
    treats as distinct, plus the round-1/round-2 traps):
    - tampered proof hash; wrong root hash; wrong Rekor key; malformed checkpoint;
    - `log_index` / `tree_size` tampering (crate tests these separately);
    - **inclusion proof entirely absent** — asserted against a **v0.1-shaped fixture**,
      to prove milpa rejects the profile (§4 accepted-profile + trap #1 refinement);
    - `kind != "dsse"` / `apiVersion != "0.0.1"` confusion (the gate is a string literal,
      so pin it with a test);
    - **JCS/canonicalization mismatch that computes a *different* body hash than Rekor
      signed** — the false-*accept* vector (not just false-reject); its own adversarial test;
    - **subject-digest mismatch** routed to `TNG-INDEX-DIGEST-MISMATCH` via the pre-check,
      *not* mis-slugged as `SIGNATURE-INVALID` (the §4 taxonomy trap);
    - composition: validly-included but differently-signed entry + valid DSSE envelope ⇒
      reject (the §4 threading regression test).

- **S4a — retire the stopgap: pure deletion (no fixture dependency).**
  - Delete `TNG-INDEX-VERIFY-UNSUPPORTED` from `errors.py` + `error.rs` + `spec/errors.md`
    (bijection lints must stay green — same one-shot discipline as *adding* a slug,
    reversed). Grep-confirmed no conformance fixture and no other call site references it.
  - Delete the no-seam dispatch branch and the `WARNED_VERIFY_UNSUPPORTED` thread-local
    from `milpa-cli/src/main.rs`'s `build_index_trust_gate`; delete the inline `main.rs`
    tests that assert the stopgap (~4035, ~4401-4437).
  - Simplify `IndexTrustGateOutcome::Ungated`: it currently means *both* "policy off"
    (legitimate) *and* "verifier unavailable, degraded" (stopgap); once the verifier is
    real the second meaning disappears and `Ungated` collapses to only "off." **Consider
    replacing the bespoke 2-variant enum + hand-written `Debug`** (`main.rs:2323-2341`)
    **with `Option<IndexTrustGateActive>`** — `Off ⟹ None`, `Active{..} ⟹ Some(..)` — same
    semantics, less boilerplate, no custom `Debug`.
  - **Update the `cli_index_trust.rs` module-level doc header** (`:1-29`, enumerates "six
    dispatch scenarios" incl. scenario 6 = `TNG-INDEX-VERIFY-UNSUPPORTED`) — not just the
    test bodies — so it doesn't describe a scenario that no longer exists.
  - Update spec §3.4.4 step-5 wording + the S4b known-limitation note.

- **S4b — rewrite the strict-path integration assertions (depends on S5's fixture).**
  *Split out from S4 in round 2: rewriting `cli_index_trust.rs` scenario 6 to prove
  `strict` genuinely fails needs a real bad bundle to fail on, which is exactly S5's
  deliverable — so this lands **after** S5, not before.*
  - Rewrite `milpa-cli/tests/cli_index_trust.rs` scenario 6 (currently asserts the exact
    `TNG-INDEX-VERIFY-UNSUPPORTED` text/exit; that branch is gone after S4a).
  - Add a CLI-level integration test proving `strict` really *fails* on a bad bundle
    end-to-end through `main.rs` (not just via `MockVerifier` in-process), using an S5
    negative fixture.

- **S5 — hermetic real-bundle fixture + per-impl integration test (create, not "flip").**
  Part 1's docstrings say the integration test is "gated at S5" but it was never
  delivered — in *either* impl (`_oracle/test_trust_bundle.json` is trust-root material,
  not a signed DSSE bundle). So both per-impl integration tests are **built from scratch**,
  not flipped from Mock. **Fixture strategy is decided (§7 decision 1): both layers.**
  - **(b) hermetic test-only CA / trust root** is the deterministic substrate for the
    adapter + verify plumbing and **all** S2 negatives (byte-flip / corrupt hash /
    truncate checkpoint / wrong root / tampered `log_index` …) — controllable fault
    injection, no dependence on public-good key longevity.
  - **(a) one real `cosign attest-blob` bundle** over a known index, pinned forever and
    verified against the **committed production `trusted_root.json`** (S1.5), as a single
    end-to-end smoke test that the *actual* embedded trust material + `hex(key_id)` map
    keys + real cert chain wire up. It stays green across rotations for free: verification
    is at the bundle's own `integratedTime`, and S1.5's append-only retention discipline
    keeps the historical Rekor key present — a committed fixture is frozen, zero
    per-rotation maintenance. One-time generation is a documented network step (like
    S1.5's population example), not recurring upkeep.
  - **Also carries the §1.2 manual smoke-test checklist item** (real `fetch` under
    `strict` against production tianguis, once tianguis serves the bundle).

- **S5.5 — cross-impl differential slug test (NEW in round 1; scope sharpened in round 2).**
  Python delegates internal step ordering to sigstore-python (a black box); Rust owns
  explicit ordering — *and round 2 surfaced the ordering is now milpa-authored on the Rust
  side* (digest pre-check → parse/singleton → high-level verify → inclusion), so the two
  impls' orderings are independently defined and can disagree on *which* slug wins for a
  bundle with *multiple simultaneous* faults (spec's first-failure precedence exists
  precisely because ordering is observable). The shared corpus can't catch this (Mock-only)
  and each per-impl test targets its own bundle. Add one committed crafted multi-fault
  bundle (fixed, needn't be hermetically regenerable) and assert both impls' real verifiers
  report the **same** slug. Mirror of the differential-blind-spot pattern.

- **S6 — Python defensive regression test (optional; decoupled).** Python already
  verifies inclusion; add a milpa-side test that a bundle with a tampered/absent inclusion
  proof is rejected, guarding against a future sigstore-python regression or a mis-wiring
  of our call. **No dependency on the Rust slices — may run in parallel with S1.**

- **S7 — upstream PR (parallel/external, non-blocking) *with a forcing function*.** Wire
  `InclusionProof::verify` into sigstore-rs `verifier.rs:198` step 5. To keep milpa's
  adapter from becoming permanent unowned debt (defer=file-now discipline):
  (a) file the sigstore-rs upstream issue **now**, as part of S2, with its number recorded
  here; (b) put `// TODO(milpa): delete when sigstore-rs ships wired inclusion in the
  bundle verifier; tracking: sigstore-rs#<N>` in `rekor_adapter.rs`; (c) a **soft**
  tripwire — a `#[test]` (NOT a `build.rs`/`compile_error!` hard gate, which would block
  all contributors over an orthogonal bump and train people to route around it) that fails
  once `sigstore` in `Cargo.toml` crosses a documented version floor, with an actionable
  message: *"check sigstore-rs#<N> status before bumping this floor; if wired inclusion
  shipped, delete rekor_adapter.rs."* Crossing the floor is a proxy signal, not proof the
  issue closed — the message says so.

- **Sv — wire `milpa verify` offline cache-bundle reverify, both impls (in scope; §7
  decision 2).** Route `cmd_verify` → offline reverify of the *cached* bundle through the
  real `SigstoreVerifier` in both impls, so the shipped Part-1 spec claim (`milpa verify`
  re-verifies offline) becomes true. Python `cmd_verify` → `_verify_dep_decl_pins`
  currently calls `load_default_index()` with **no verifier** (online-only); Rust
  `cmd_verify` routes through `build_index_trust_gate` for the online dep_decl edge check
  only. Both must additionally reverify the cached `index.kdl.bundle` offline. Lands after
  S2 (needs the real verifier). Add a per-impl test that `verify` on a tampered cached
  bundle fails offline.

## 7. Resolved decisions (no open forks)

Both items that rounds 1+2 carried as "forks" were re-tested against the goal (best-in-class
PhD-CS + honor-the-spec) and are **goal-determined, not preference-driven** — each apparent
fork rested on a caveat that dissolves under scrutiny. Recorded here as decisions, with the
defense, so they don't get relitigated.

1. **Fixture strategy (S5) → both layers.** The bar forces *both*, for independent reasons:
   - **(a) one real production-trust-root bundle is mandatory** — without it milpa's actual
     Fulcio/CTFE/Rekor wiring (the `trusted_root.json` mapper, `hex(key_id)` map keys, real
     cert chain) is never exercised end-to-end; that is the "units green, prod fails" hole a
     best-in-class verifier cannot ship with.
   - **(b) a hermetic test-only CA is mandatory** — the ~8 negative vectors need
     *controllable* fault injection; you cannot mint arbitrary faults from a public-good
     bundle, and pinning the negative suite to public-good key longevity is fragile.
   - The apparent trade-off ("appetite for rotation maintenance") was a **false axis**: a
     committed real bundle + pinned `trusted_root.json` snapshot is frozen — verification is
     at the bundle's own `integratedTime`, and S1.5's append-only retention keeps the
     historical Rekor key present, so the fixture stays green across rotations with **zero**
     per-rotation upkeep. One-time generation is a documented network step, not recurring
     work. Nothing left to weigh → decided.
2. **`milpa verify` routing (§1.1) → wired in-scope (slice Sv).** The shipped Part-1 spec
   already claims `milpa verify` re-verifies the cached bundle offline; neither impl does.
   The alternative ("soften the spec text") is the exact silent-downgrade move
   honor-the-spec / spec-vs-impl forbid (and milpa's been caught at twice). "Widens scope"
   is a **false axis**: this RFC is *attestation-verifier **completion***, so leaving the
   spec-promised audit path unwired is incompleteness, not scope-widening — and the verifier
   lands here regardless, making the wiring a few lines. Goal-determined → decided (a).

*(Old forks resolved earlier: SET-vs-inclusion → inclusion+checkpoint, matching Python;
adapter security bar → the S2 negative-test checklist; the "#103 overstated?" question → no,
closed by S0.)*

**One action item (not a fork):** file the follow-up GH issue for `show --index-trust`
real-field extraction (§3), per defer-file-now. Done at Stage-2 close (see handoff).

## 8. Connections

- **Part 1** (`rfc-registry-trust-federation.md`) — the gate this completes; reuse its
  `IndexBundleVerifier` seam, `MockVerifier`, trust-root embedding, verify/enforce split,
  and policy SSOT (all confirmed across rounds 1+2 to survive real crypto without
  interface churn). §12.3 rotation commitment is operationalized by S1.5's population script.
- **Part 2** (`rfc-per-entry-attestation.md`) — per-entry attribution; a real verifier
  here is a prerequisite. Note for whoever picks it up: the same adapter runs at
  once-per-*selected-dep* frequency there (vs. once-per-resolve here) — a perf
  consideration, not a correctness one.
- **`show --index-trust` real-field extraction** — the deferred follow-up noted in §3
  (#182); sits directly on S2's cert/DSSE decoding.
- **tianguis `index.kdl.bundle` delivery** — the cross-repo dependency of §1.2; Goal #3 is
  operationally contingent on it.
- **milpa Tier-4 ambition** — the upstream sigstore-rs PR is a concrete "contribute to the
  ecosystem, don't hand-roll crypto" contribution.
