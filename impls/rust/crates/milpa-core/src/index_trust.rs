//! Whole-index Sigstore bundle verifier — RFC: rfc-registry-trust-federation §11 S4.
//!
//! Rust parity with the Python S3 module (`impls/python/milpa/index_trust.py`).
//!
//! # Public surface
//!
//! - [`VerificationResult`] — 7-variant enum; `.value()` strings are byte-identical to the
//!   Python `VerificationResult.value` strings so the shared conformance `mock_verifier_result`
//!   field is cross-impl identical.
//! - [`IndexBundleVerifier`] — trait: the injected verifier seam.  Production code passes
//!   [`SigstoreVerifier`]; test/conformance code passes [`MockVerifier`].
//! - [`verify_index_bundle`] — pure function; never panics.  Implements spec §3.4.4 steps 1–3
//!   (JSON parse, integratedTime extract, freshness check) then delegates the real crypto
//!   (steps 4–6 + offline transparency step 5) to [`verify_crypto`].
//! - [`SigstoreVerifier`] — the real production verifier (sigstore-rs 0.14).  See the
//!   verifier note below.
//! - [`MockVerifier`] — test seam; returns a caller-supplied result, ignoring all inputs.
//!   This is the S7 conformance corpus seam (`mock_verifier_result` env field).
//! - [`IndexTrustConfig`] — struct: policy + trust_bundle + expected_signer + max_age.
//!   Does NOT contain a verifier field — verifier is an explicit param of
//!   `load_index(url, config, verifier, http_get, bundle_http_get)` (S6).
//! - [`TrustBundle`] — production (`include_bytes!` over the standard `_trust/trusted_root.json`)
//!   vs test (`_oracle/test_trust_bundle.json`). Factory methods: [`TrustBundle::production`] /
//!   [`TrustBundle::test`]. [`crate::trust_root::map_trusted_root`] reshapes the bytes into a
//!   `sigstore::trust::ManualTrustRoot` (S1.5).
//!
//! # The real verifier (RFC `rfc-attestation-verifier`, sigstore-rs 0.14)
//!
//! [`SigstoreVerifier`] performs real offline verification. [`verify_crypto`] runs, aborting
//! on the first failure:
//!
//! 1. Parse the bundle **once** into `sigstore::bundle::Bundle`; assert exactly one tlog
//!    entry (the §4 composition binding threads that same owned entry through both the
//!    high-level verify and the inclusion adapter — no independent re-parse).
//! 2. **Digest pre-check** — `sha256(index_bytes)` vs the DSSE in-toto subject digest →
//!    `DigestMismatch` deterministically, *before* the opaque crate call (§4 error-taxonomy
//!    fix: the crate collapses digest-mismatch and sig-fail into one unnameable error).
//! 3. **High-level verify** (`blocking::Verifier::verify_digest`) — cert chain + DSSE +
//!    signature + SAN/issuer policy (`policy::Identity`, wrapped in a `RecordingPolicy` so a
//!    policy rejection is `SignerMismatch`, everything else `SigInvalid`).
//! 4. **Offline transparency** (spec §3.4.4 step 5) — [`crate::rekor_adapter`] verifies the
//!    Rekor inclusion proof + signed checkpoint against the trust root's Rekor key. This is
//!    the piece milpa owns temporarily because sigstore-rs's own step 5 is still a TODO
//!    (`verifier.rs:198`, sigstore-rs#285). The adapter reshapes already-parsed protobuf into
//!    the crate's public `InclusionProof::verify` — **zero hand-rolled crypto** (§5.1).
//!
//! The Fulcio/CTFE trust material is the standard `trusted_root.json`
//! ([`TrustBundle::production`]) mapped by [`crate::trust_root::map_trusted_root`].
//! [`MockVerifier`] remains the conformance-corpus seam (RFC §10.1: the shared corpus tests
//! the policy state machine, not cryptography).
//!
//! **Known limitation (inherited, §4 gap-3):** the crate verifies the cert chain at the
//! leaf's own `not_before` and only bounds-checks the leaf window against `integratedTime`;
//! it does not re-verify the intermediate/root chain *at* `integratedTime`. For Fulcio's
//! ~10-minute ephemeral certs the two coincide. A true chain-at-`integratedTime` fix is an
//! upstream change (tracked with the S7 PR).
//!
//! # Slice boundary
//!
//! S4 does NOT add `TNG-INDEX-*` error codes to `errors.rs` or `spec/errors.md` — those
//! land in S6 co-committed with the raise sites in `index_cache.rs`.  The bijection test
//! (`rust_error_catalog_is_a_bijection_with_the_spec`) must remain green after this slice.
//!
//! RFC: `docs/rfc-registry-trust-federation.md` §4, §6.5, §10.1, §11 S4/S4b.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use milpa_manifest::TrustPolicy;
use sha2::{Digest, Sha256};
use sigstore::bundle::verify::policy::{Identity, VerificationPolicy};
use sigstore::bundle::verify::{blocking::Verifier, VerificationError};
use sigstore::rekor::apis::configuration::Configuration as RekorConfiguration;

use crate::error::{CoreError, MilpaError};
use crate::rekor_adapter::{verify_entry_inclusion, AdapterOutcome};
use crate::trust_root::map_trusted_root;

// ---------------------------------------------------------------------------
// DEFAULT_INDEX_SIGNER — canonical tianguis signing identity (spec §3.4.4 step 5)
// ---------------------------------------------------------------------------

/// Default expected SubjectAltName for the tianguis index Sigstore bundle.
///
/// This is the GitHub Actions OIDC workflow SAN for the tianguis
/// `reindex.yaml` CI workflow on the `main` branch.  It identifies the
/// signer that ran the attestation step — not the commit author.
///
/// Override via:
/// - `index-trust-signer "<san>"` in `milpa.kdl` (per-project).
/// - `MILPA_INDEX_TRUST_SIGNER=<san>` environment variable (process-level).
///
/// spec §3.4.4 step 5 — signer identity check.
pub const DEFAULT_INDEX_SIGNER: &str =
    "https://github.com/coreyleavitt/tianguis/.github/workflows/reindex.yaml\
     @refs/heads/main";

/// OIDC issuer pinned alongside the SAN in the signer-identity policy.
///
/// The tianguis attestation is keyless-signed via GitHub Actions, so the issuer is always
/// the GitHub Actions OIDC endpoint. Pinning it (not just the SAN) prevents a cert with a
/// matching SAN from a *different* issuer from satisfying the policy. **Byte-identical to
/// the Python impl's hardcoded issuer** (`index_trust.py` `Identity(..., issuer=...)`), so
/// both impls make the same accept/reject decision (S5.5 differential).
pub const DEFAULT_INDEX_ISSUER: &str = "https://token.actions.githubusercontent.com";

// ---------------------------------------------------------------------------
// VerificationResult — 7-variant enum (RFC §6.5)
// ---------------------------------------------------------------------------

/// 7-variant result type for whole-index Sigstore bundle verification.
///
/// RFC §6.5 maps each non-[`Trusted`] variant to a `TNG-INDEX-*` error slug.
/// The slug-raising dispatch (`enforce_index_trust`) lives in S6, not here.
///
/// The `.value()` string for each variant is byte-identical to the Python
/// `VerificationResult.value` strings so the shared conformance
/// `mock_verifier_result` field is cross-impl identical.
///
/// [`Trusted`]: VerificationResult::Trusted
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// All seven spec §3.4.4 verification steps passed.  The index bytes are trustworthy.
    Trusted,
    /// Cryptographic verification failed: bad Fulcio cert chain, cert was expired AT
    /// `integratedTime`, or Rekor inclusion proof invalid.
    ///
    /// A cert now-expired but valid at `integratedTime` MUST NOT trigger this variant
    /// (spec §3.4.4 step 4 — cert-at-SET-time requirement).
    SigInvalid,
    /// The bundle's DSSE in-toto `subject[0].digest.sha256` ≠ `sha256(index_bytes)`.
    /// Indicates tampering after attestation.
    DigestMismatch,
    /// The bundle cert's SubjectAltName ≠ `expected_signer`.
    SignerMismatch,
    /// `now − integratedTime ≥ max_age_seconds`.  Cryptographically valid but beyond
    /// the freshness window; indicates a rollback attack or a frozen CDN.
    /// Only returned when `max_age_seconds` is `Some`.
    BundleStale,
    /// No bundle sidecar was available alongside the index.  This variant is
    /// constructed by `load_index` (S6) when the bundle fetch 404s; `verify_index_bundle`
    /// is NOT called in that case.  Lives here so `enforce_index_trust`'s dispatch is
    /// total over all 7 cases.
    BundleMissing,
    /// The bundle JSON is unparseable or structurally invalid (pre-crypto failure,
    /// before any signature check is attempted).
    BundleMalformed,
}

impl VerificationResult {
    /// Returns the wire-format string value for this result.
    ///
    /// These strings are byte-identical to the Python `VerificationResult.value` strings
    /// so the shared conformance `mock_verifier_result` field is cross-impl identical.
    pub fn value(&self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::SigInvalid => "sig-invalid",
            Self::DigestMismatch => "digest-mismatch",
            Self::SignerMismatch => "signer-mismatch",
            Self::BundleStale => "bundle-stale",
            Self::BundleMissing => "bundle-missing",
            Self::BundleMalformed => "bundle-malformed",
        }
    }

    /// Map a non-Trusted result to its `TNG-INDEX-*` error slug (M5 SSOT).
    ///
    /// Single source of truth for the VerificationResult → slug bijection.
    /// Called by `enforce_index_trust` and conformance runners; eliminates
    /// the previously-triplicated inline `match` blocks.
    ///
    /// # Panics
    ///
    /// Panics on `Trusted` — callers must guard (Trusted has no TNG-INDEX-* slug).
    pub fn to_slug(&self) -> &'static str {
        match self {
            Self::BundleMissing => "TNG-INDEX-BUNDLE-MISSING",
            Self::BundleMalformed => "TNG-INDEX-BUNDLE-MALFORMED",
            Self::SigInvalid => "TNG-INDEX-SIGNATURE-INVALID",
            Self::DigestMismatch => "TNG-INDEX-DIGEST-MISMATCH",
            Self::SignerMismatch => "TNG-INDEX-SIGNER-MISMATCH",
            Self::BundleStale => "TNG-INDEX-BUNDLE-STALE",
            Self::Trusted => panic!("VerificationResult::Trusted has no TNG-INDEX-* slug"),
        }
    }

    /// Parse from the wire-format string (the `mock_verifier_result` env field).
    ///
    /// Returns `None` for unrecognized strings.
    pub fn from_value(s: &str) -> Option<Self> {
        match s {
            "trusted" => Some(Self::Trusted),
            "sig-invalid" => Some(Self::SigInvalid),
            "digest-mismatch" => Some(Self::DigestMismatch),
            "signer-mismatch" => Some(Self::SignerMismatch),
            "bundle-stale" => Some(Self::BundleStale),
            "bundle-missing" => Some(Self::BundleMissing),
            "bundle-malformed" => Some(Self::BundleMalformed),
            _ => None,
        }
    }
}

impl std::fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.value())
    }
}

// ---------------------------------------------------------------------------
// TrustBundle — PRODUCTION vs TEST trust root (RFC §3.1)
// ---------------------------------------------------------------------------

/// Fulcio CA root + Rekor public key bundle for offline bundle verification.
///
/// Never construct directly; use the factory methods so callsites document
/// which trust root they are intentionally using.
///
/// RFC §3.1: the trust bundle is NOT fetched at runtime; it is embedded at
/// build time and rotated only via an explicit milpa version update.
/// TUF-based root rotation is a future extension (RFC §12.3).
#[derive(Debug, Clone)]
pub struct TrustBundle {
    /// Raw JSON bytes of the Fulcio CA + Rekor public key bundle.
    pub raw_json: &'static [u8],
    /// Human-readable source tag: `"production"` or `"test"`.
    pub label: &'static str,
}

impl TrustBundle {
    /// Load the embedded production trust root from `_trust/trusted_root.json`.
    ///
    /// The bytes are the **standard Sigstore `trusted_root.json`** (Fulcio CAs +
    /// Rekor + CTFE keys, each with `validFor` ranges), embedded verbatim — NOT a
    /// milpa-invented schema. [`crate::trust_root::map_trusted_root`] reshapes them
    /// into the `sigstore::trust::ManualTrustRoot` the S2 verifier consumes.
    ///
    /// Regenerate with `src/_trust/regenerate-trusted-root.sh` (network-only maintainer
    /// tool; never run by the test gate). Rotation discipline: **append** new material, never delete old,
    /// so committed S5 fixtures keep verifying at their `integratedTime` (RFC S1.5,
    /// operationalizes Part-1 §12.3). Rotated only via a milpa version update — no
    /// runtime TUF fetch (RFC §3.1).
    ///
    /// Production code ONLY — test code MUST use [`TrustBundle::test`].
    pub fn production() -> Self {
        static PRODUCTION_BYTES: &[u8] = include_bytes!("_trust/trusted_root.json");
        TrustBundle {
            raw_json: PRODUCTION_BYTES,
            label: "production",
        }
    }

    /// Load the test trust bundle from `conformance/spec-v1/_oracle/test_trust_bundle.json`.
    ///
    /// Test code ONLY — production code MUST NEVER reference the test bundle.
    /// Populated in S5 alongside the integration test (RFC §12.2).
    ///
    /// If the oracle file does not exist yet (before S5), returns a placeholder.
    pub fn test() -> Self {
        // The oracle bundle is generated in S5; placeholder until then.
        static TEST_PLACEHOLDER: &[u8] = b"{\"__placeholder__\": true, \"__note__\": \"test oracle bundle -- generated in S5\"}";
        TrustBundle {
            raw_json: TEST_PLACEHOLDER,
            label: "test",
        }
    }
}

// ---------------------------------------------------------------------------
// IndexBundleVerifier — trait (RFC §10.1)
// ---------------------------------------------------------------------------

/// Injected verifier seam for whole-index attestation.
///
/// Production code passes [`SigstoreVerifier`] as the explicit `verifier`
/// parameter to `load_index`; test/conformance code passes [`MockVerifier`].
///
/// The two orthogonal seams (RFC §10.1, §3.2):
/// - `trust_bundle` — Fulcio CA + Rekor key bundle (trust ROOT seam).
///   Overridable via `MILPA_INDEX_TRUST_BUNDLE` / `index-trust-bundle`.
/// - `expected_signer` — SubjectAltName identity (signer IDENTITY seam).
///   Overridable via `MILPA_INDEX_TRUST_SIGNER` / `index-trust-signer`.
///
/// Changing one does not imply the other.
///
/// `max_age_seconds` is passed as `config.max_age_seconds` on network-fetch
/// paths, and as `None` on pure cache reads so committed test bundles never
/// go stale 7 days after commit.  [`MockVerifier`] ignores it.
pub trait IndexBundleVerifier {
    /// Verify the Sigstore bundle against `index_bytes`.
    ///
    /// - `index_bytes`: raw bytes of `index.kdl` (single-read invariant).
    /// - `bundle_bytes`: raw bytes of the `.bundle` sidecar (Sigstore bundle JSON).
    /// - `trust_bundle`: Fulcio CA + Rekor public key bundle (trust ROOT).
    /// - `expected_signer`: expected SubjectAltName (GitHub Actions OIDC workflow URL
    ///   or configured override).
    /// - `max_age_seconds`: freshness window in seconds.  Pass `None` on pure cache
    ///   reads to skip the wall-clock bound (spec §3.4.4 step 3, §7.2).
    fn verify(
        &self,
        index_bytes: &[u8],
        bundle_bytes: &[u8],
        trust_bundle: &TrustBundle,
        expected_signer: &str,
        max_age_seconds: Option<u64>,
    ) -> VerificationResult;
}

// ---------------------------------------------------------------------------
// Pure verification function — spec §3.4.4 steps 1–3; real crypto via verify_crypto
// ---------------------------------------------------------------------------

/// Verify a Sigstore bundle against `index_bytes`; return a [`VerificationResult`].
///
/// Implements spec §3.4.4 verification steps 1–3 correctly:
///
/// **Step 1** — Parse bundle JSON.  Non-JSON or non-object → [`BundleMalformed`]
/// (pre-crypto failure, distinct from a cryptographic failure).
///
/// **Step 2** — Extract `integratedTime` from
/// `verificationMaterial.tlogEntries[0].integratedTime`.  Missing or non-integer
/// → [`BundleMalformed`].  This is the anchor for cert-at-SET-time checking (spec
/// §3.4.4 step 4) — NOT wall-clock `now`.
///
/// **Step 3** — Freshness check: ONLY when `max_age_seconds` is `Some`.
/// If `now − integratedTime ≥ max_age_seconds` → [`BundleStale`].
/// Passing `None` skips this bound entirely (pure cache reads, offline safety —
/// spec §3.4.4 step 3, §7.2).
///
/// **Steps 4–6 + offline transparency step 5** — delegated to [`verify_crypto`]: digest
/// pre-check, high-level cert/DSSE/signature/SAN verification, and offline Rekor
/// inclusion-proof + checkpoint verification. Returns [`Trusted`] only if every step passes.
///
/// Never panics; returns a [`VerificationResult`] for every input.
///
/// [`BundleMalformed`]: VerificationResult::BundleMalformed
/// [`BundleStale`]: VerificationResult::BundleStale
/// [`SigInvalid`]: VerificationResult::SigInvalid
/// [`Trusted`]: VerificationResult::Trusted
pub fn verify_index_bundle(
    index_bytes: &[u8],
    bundle_bytes: &[u8],
    trust_bundle: &TrustBundle,
    expected_signer: &str,
    max_age_seconds: Option<u64>,
) -> VerificationResult {
    // Step 1: parse bundle JSON.
    let bundle_json: serde_json::Value = match serde_json::from_slice::<serde_json::Value>(bundle_bytes) {
        Ok(v) if v.is_object() => v,
        Ok(_) => return VerificationResult::BundleMalformed,
        Err(_) => return VerificationResult::BundleMalformed,
    };

    // Step 2: extract integratedTime from the first Rekor tlog entry.
    // This timestamp is the anchor for cert-at-SET-time checking (spec §3.4.4 step 4).
    let integrated_time: u64 = match extract_integrated_time(&bundle_json) {
        Some(t) => t,
        None => return VerificationResult::BundleMalformed,
    };

    // Step 3: freshness check — ONLY on the network-fetch path.
    // Pure cache reads (States 1 and 3) pass max_age_seconds=None: the
    // wall-clock bound is NOT re-asserted so offline/air-gapped invocations
    // never fail on staleness (spec §3.4.4 step 3, §7.2).
    if let Some(max_age) = max_age_seconds {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(integrated_time) >= max_age {
            return VerificationResult::BundleStale;
        }
    }

    // Steps 4–6 + offline transparency step 5: real cryptographic verification.
    // `bundle_json` (steps 1–3, freshness) and the Bundle parse inside `verify_crypto` are
    // two reads of the same bytes; the composition-critical invariant (one Bundle threaded
    // through both verify_digest AND inclusion) is upheld inside `verify_crypto` (RFC §4).
    let _ = integrated_time; // consumed by the freshness bound above; crypto re-derives from the Bundle.
    verify_crypto(index_bytes, bundle_bytes, trust_bundle, expected_signer)
}

/// Extract `integratedTime` from a parsed bundle JSON.
///
/// Returns `None` if the field is absent, null, or not parseable as a non-negative integer.
/// Handles both string-encoded integers (proto3 JSON: int64 → string) and native integers.
fn extract_integrated_time(bundle_json: &serde_json::Value) -> Option<u64> {
    let raw = &bundle_json["verificationMaterial"]["tlogEntries"][0]["integratedTime"];
    // Proto3 JSON encodes int64 as a string; accept both string and number forms.
    if let Some(s) = raw.as_str() {
        s.parse::<i64>().ok().and_then(|v| u64::try_from(v).ok())
    } else if let Some(n) = raw.as_i64() {
        u64::try_from(n).ok()
    } else {
        None
    }
}

/// A [`VerificationPolicy`] wrapper that records whether the inner policy's `verify`
/// rejected the certificate.
///
/// The crate collapses "SAN/issuer policy failed" and "signature failed" into one opaque
/// `VerificationError::Signature(_)` whose inner kinds are unnameable outside the crate
/// (RFC §4 error-taxonomy gap). So milpa cannot tell `SignerMismatch` from `SigInvalid`
/// from the returned error. This wrapper records the policy-vs-not signal at the call site
/// instead — byte-for-byte the same technique as the Python `_RecordingPolicy`.
struct RecordingPolicy<'a> {
    inner: &'a Identity,
    rejected: Cell<bool>,
}

impl<'a> RecordingPolicy<'a> {
    fn new(inner: &'a Identity) -> Self {
        Self {
            inner,
            rejected: Cell::new(false),
        }
    }
}

impl VerificationPolicy for RecordingPolicy<'_> {
    fn verify(
        &self,
        cert: &x509_cert::Certificate,
    ) -> sigstore::bundle::verify::policy::PolicyResult {
        let result = self.inner.verify(cert);
        if result.is_err() {
            self.rejected.set(true);
        }
        result
    }
}

/// Extract the in-toto `subject[0].digest.sha256` (lowercase hex) from the bundle's DSSE
/// envelope payload. Returns `None` if the bundle is not a DSSE envelope or the payload
/// has no sha256 subject digest.
///
/// This is *reshaping already-parsed data* (the crate's own `InTotoStatementV1` is
/// `pub(crate)`), not verification — RFC §5.1-compliant. It lets milpa deterministically
/// bucket a subject-digest mismatch as [`VerificationResult::DigestMismatch`] BEFORE the
/// opaque crate call, dodging the error-taxonomy trap (RFC §4).
fn extract_dsse_subject_sha256(bundle: &sigstore::bundle::Bundle) -> Option<String> {
    use sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content;
    let payload = match bundle.content.as_ref()? {
        Content::DsseEnvelope(env) => &env.payload,
        Content::MessageSignature(_) => return None,
    };
    let statement: serde_json::Value = serde_json::from_slice(payload).ok()?;
    statement["subject"]
        .get(0)?
        .get("digest")?
        .get("sha256")?
        .as_str()
        .map(|s| s.to_ascii_lowercase())
}

/// Real cryptographic verification (spec §3.4.4 steps 4–6 + offline transparency step 5).
///
/// Runs the pipeline in RFC §4 / spec §3.4.4 order, aborting on the first failure:
///
/// 1. **Parse the bundle once** into `sigstore::bundle::Bundle`; assert exactly one tlog
///    entry (mirrors the crate's own `BundleErrorKind::TlogEntry` gate). The single owned
///    entry is threaded through both the high-level verify and the inclusion adapter — the
///    §4 composition binding (no independent re-parse).
/// 2. **Digest pre-check**: `sha256(index_bytes)` vs the DSSE subject digest →
///    [`DigestMismatch`] deterministically, before the crate call (§4 taxonomy fix).
/// 3. **High-level verify** (`verify_digest`): cert chain + DSSE + signature + SAN/issuer
///    policy. A policy rejection → [`SignerMismatch`] (via [`RecordingPolicy`]); any other
///    `Signature(_)` → [`SigInvalid`].
/// 4. **Offline inclusion** via [`verify_entry_inclusion`] against the Rekor key looked up
///    from the trust root by `hex(log_id.key_id)` → crypto failure [`SigInvalid`],
///    structural failure [`BundleMalformed`].
///
/// Returns [`VerificationResult::Trusted`] only if every step passes. Never panics.
///
/// [`DigestMismatch`]: VerificationResult::DigestMismatch
/// [`SignerMismatch`]: VerificationResult::SignerMismatch
/// [`SigInvalid`]: VerificationResult::SigInvalid
/// [`BundleMalformed`]: VerificationResult::BundleMalformed
fn verify_crypto(
    index_bytes: &[u8],
    bundle_bytes: &[u8],
    trust_bundle: &TrustBundle,
    expected_signer: &str,
) -> VerificationResult {
    // (1) Parse ONCE.
    let bundle: sigstore::bundle::Bundle = match serde_json::from_slice(bundle_bytes) {
        Ok(b) => b,
        Err(_) => return VerificationResult::BundleMalformed,
    };

    // Singleton tlog entry — clone it now, before `bundle` is moved into `verify_digest`,
    // so the SAME entry is used for inclusion (composition binding, RFC §4).
    let entry = match bundle.verification_material.as_ref() {
        Some(vm) if vm.tlog_entries.len() == 1 => vm.tlog_entries[0].clone(),
        _ => return VerificationResult::BundleMalformed,
    };

    // (2) Digest pre-check.
    let subject_sha256 = match extract_dsse_subject_sha256(&bundle) {
        Some(h) => h,
        None => return VerificationResult::BundleMalformed,
    };
    let actual = hex::encode(Sha256::digest(index_bytes));
    if actual != subject_sha256 {
        return VerificationResult::DigestMismatch;
    }

    // Map the embedded (or overridden) trust root. The production root is committed and
    // known-good; a malformed *override* fails closed as SigInvalid (can't establish trust).
    let trust_root = match map_trusted_root(trust_bundle.raw_json) {
        Ok(t) => t,
        Err(_) => return VerificationResult::SigInvalid,
    };

    // Look up the Rekor key for this entry's log by hex(log_id.key_id) — clone before the
    // trust root is moved into the Verifier (which only consumes fulcio + ctfe keys).
    let rekor_key = match entry.log_id.as_ref() {
        Some(log_id) => match trust_root.rekor_keys.get(&hex::encode(&log_id.key_id)) {
            Some(k) => k.clone(),
            None => return VerificationResult::SigInvalid, // untrusted transparency log
        },
        None => return VerificationResult::BundleMalformed,
    };

    // (3) High-level verify: cert + DSSE + signature + SAN/issuer policy.
    let verifier = match Verifier::new(RekorConfiguration::default(), trust_root) {
        Ok(v) => v,
        Err(_) => return VerificationResult::SigInvalid,
    };
    let identity = Identity::new(expected_signer, DEFAULT_INDEX_ISSUER);
    let recording = RecordingPolicy::new(&identity);

    let mut hasher = Sha256::new();
    hasher.update(index_bytes);
    // offline = true: milpa never makes an online Rekor call (spec §3.4.4).
    if let Err(err) = verifier.verify_digest(hasher, bundle, &recording, true) {
        return match err {
            // Policy rejected the cert → SAN/issuer mismatch.
            _ if recording.rejected.get() => VerificationResult::SignerMismatch,
            // A pre-verify input error (should not happen — digest already computed).
            VerificationError::Input(_) => VerificationResult::SigInvalid,
            // Everything else — bad signature, cert chain, envelope consistency.
            _ => VerificationResult::SigInvalid,
        };
    }

    // (4) Offline transparency inclusion (spec §3.4.4 step 5) — the same singleton entry.
    match verify_entry_inclusion(&entry, &rekor_key) {
        AdapterOutcome::Included => VerificationResult::Trusted,
        AdapterOutcome::CryptoInvalid(_) => VerificationResult::SigInvalid,
        AdapterOutcome::Malformed(_) => VerificationResult::BundleMalformed,
    }
}

// ---------------------------------------------------------------------------
// SigstoreVerifier — production IndexBundleVerifier (RFC §11 S4)
// ---------------------------------------------------------------------------

/// Production verifier using `sigstore-rs` 0.14.
///
/// Performs real offline verification (RFC `rfc-attestation-verifier`): spec §3.4.4 steps
/// 1–3 (parse / integratedTime / freshness) plus the real crypto — cert chain + DSSE +
/// signature + SAN/issuer policy via the crate's high-level `Verifier`, and offline Rekor
/// inclusion-proof + signed-checkpoint verification via [`crate::rekor_adapter`]. See
/// [`verify_index_bundle`] / [`verify_crypto`].
///
/// `MockVerifier` remains the conformance-corpus seam (RFC §10.1: the shared corpus tests
/// the policy state machine, not cryptography).
pub struct SigstoreVerifier;

impl IndexBundleVerifier for SigstoreVerifier {
    fn verify(
        &self,
        index_bytes: &[u8],
        bundle_bytes: &[u8],
        trust_bundle: &TrustBundle,
        expected_signer: &str,
        max_age_seconds: Option<u64>,
    ) -> VerificationResult {
        verify_index_bundle(
            index_bytes,
            bundle_bytes,
            trust_bundle,
            expected_signer,
            max_age_seconds,
        )
    }
}

// ---------------------------------------------------------------------------
// MockVerifier — test IndexBundleVerifier (RFC §10.1)
// ---------------------------------------------------------------------------

/// Test verifier returning a caller-supplied [`VerificationResult`].
///
/// The seam the S7 conformance corpus drives via the `mock_verifier_result`
/// field in fixture `env`.  Ignores all parameters; result is externally
/// driven by the fixture scenario.
///
/// RFC §10.1: the shared corpus tests the POLICY STATE MACHINE only (not
/// cryptographic correctness); [`MockVerifier`] is the contract test point.
/// Deterministic offline-verifiable Sigstore bundles cannot be generated
/// without live Fulcio/Rekor infrastructure; the policy seam is tested
/// independently from the crypto implementation.
pub struct MockVerifier {
    result: VerificationResult,
}

impl MockVerifier {
    /// Creates a `MockVerifier` that returns `result` for every `verify` call.
    ///
    /// All parameters to `verify` are ignored; the result is externally driven.
    pub fn new(result: VerificationResult) -> Self {
        Self { result }
    }
}

impl IndexBundleVerifier for MockVerifier {
    fn verify(
        &self,
        _index_bytes: &[u8],
        _bundle_bytes: &[u8],
        _trust_bundle: &TrustBundle,
        _expected_signer: &str,
        _max_age_seconds: Option<u64>,
    ) -> VerificationResult {
        self.result
    }
}

// ---------------------------------------------------------------------------
// IndexTrustConfig — config bundle for load_index (verifier NOT a field)
// ---------------------------------------------------------------------------

/// Config bundle passed as one parameter to `load_index` (wired in S6).
///
/// Bundles the policy + trust root + expected signer + freshness window into
/// a single struct so `load_index` avoids parameter explosion
/// (RFC §7.2 revised signature).
///
/// **Verifier is NOT a field.**  The `verifier: &dyn IndexBundleVerifier` is an
/// EXPLICIT parameter of `load_index(url, config, verifier, http_get, bundle_http_get)` —
/// separate from `IndexTrustConfig`.  Reason: embedding a production default in config
/// would cause tests that forget to inject a mock to silently run against real
/// `SigstoreVerifier` (which panics in S4).  Explicit parameter makes the
/// seam impossible to miss (RFC §7.2, §10.1).
///
/// Does not import `context.rs`: this struct lives at the verifier layer,
/// below the resolver layer, and must not create a circular import.
#[derive(Debug, Clone)]
pub struct IndexTrustConfig {
    /// Effective trust policy: `Warn`, `Strict`, or `Off`.
    pub policy: TrustPolicy,
    /// Fulcio CA + Rekor public key bundle (trust ROOT seam; orthogonal to signer).
    pub trust_bundle: TrustBundle,
    /// Expected SubjectAltName identity (signer IDENTITY seam; orthogonal to trust root).
    pub expected_signer: String,
    /// Freshness window in seconds (default: 7 days = 604800 s).
    ///
    /// `load_index` passes this value on network-fetch paths and `None` on
    /// pure cache reads (States 1 and 3) to skip the wall-clock freshness bound.
    /// Overridable via `MILPA_INDEX_MAX_AGE` env var (wired in S6).
    pub max_age_seconds: u64,
}

impl IndexTrustConfig {
    /// The default freshness window: 7 days in seconds.
    pub const DEFAULT_MAX_AGE: u64 = 604800;

    /// Creates an `IndexTrustConfig` with the given policy, trust bundle, and signer.
    ///
    /// `max_age_seconds` defaults to [`DEFAULT_MAX_AGE`] (7 days).
    ///
    /// [`DEFAULT_MAX_AGE`]: IndexTrustConfig::DEFAULT_MAX_AGE
    pub fn new(policy: TrustPolicy, trust_bundle: TrustBundle, expected_signer: String) -> Self {
        Self {
            policy,
            trust_bundle,
            expected_signer,
            max_age_seconds: Self::DEFAULT_MAX_AGE,
        }
    }
}

// ---------------------------------------------------------------------------
// enforce_index_trust — 6-way result→slug dispatch  (RFC §6.5, §11 S6)
// ---------------------------------------------------------------------------

/// Per-invocation warn dedup set (RFC §6.1 "Warning dedup key").
///
/// At most one index-trust warning is emitted per unique `index_url` per process.
/// Thread-local: one CLI invocation is single-threaded at the resolution layer.
/// Tests reset this with [`_reset_warned_urls`] between cases.
thread_local! {
    static WARNED_URLS: RefCell<BTreeSet<String>> = RefCell::new(BTreeSet::new());
}

/// Clear the per-invocation warn dedup set.  **TEST USE ONLY.**
#[cfg(test)]
pub fn _reset_warned_urls() {
    WARNED_URLS.with(|w| w.borrow_mut().clear());
}

/// 6-way `VerificationResult` → `TNG-INDEX-*` slug dispatch (RFC §6.5).
///
/// Policy semantics (RFC §6.1):
///
/// - `Off`     → silent; verifier was not called; no warning, no raise.
/// - `Trusted` → silent; all six verification steps passed.
/// - `Warn`    → emit ONE machine-readable warning to stderr per unique
///               `index_url` per invocation (dedup key = `index_url`);
///               exit 0 (RFC "detection but not prevention").
/// - `Strict`  → return `Err(MilpaError)` with the appropriate `TNG-INDEX-*` slug.
///
/// # Parameters
///
/// - `result`     — The `VerificationResult` from the verifier (or constructed by
///                  `load_index` for the `BundleMissing` case when the bundle 404s).
/// - `policy`     — The effective trust policy for this invocation.
/// - `index_url`  — The index URL that triggered this verification (dedup key +
///                  error/warning context).
///
/// # Errors
///
/// Under `Strict` policy for any non-`Trusted` result.
pub fn enforce_index_trust(
    result: VerificationResult,
    policy: &TrustPolicy,
    index_url: &str,
) -> Result<(), MilpaError> {
    if *policy == TrustPolicy::Off || result == VerificationResult::Trusted {
        return Ok(());
    }

    // Slug via SSOT (M5 — single slug map lives on VerificationResult::to_slug).
    let slug = result.to_slug();

    // Human-readable hints (not exported; enforce_index_trust only).
    let hint: &'static str = match result {
        VerificationResult::BundleMissing => (
            "no attestation bundle for the index. \
             Run 'milpa fetch --refresh-index' to re-fetch with attestation, \
             or set 'index-trust \"off\"' in milpa.kdl to suppress."
        ),
        VerificationResult::BundleMalformed => (
            "the Sigstore bundle is not valid JSON or missing required fields."
        ),
        VerificationResult::SigInvalid => (
            "cryptographic verification of the index Sigstore bundle failed."
        ),
        VerificationResult::DigestMismatch => (
            "the bundle's attested subject digest does not match the index bytes \
             (tampering or mismatched bundle/index pair)."
        ),
        VerificationResult::SignerMismatch => (
            "the bundle signer identity does not match the expected signer. \
             Set 'index-trust-signer' in milpa.kdl or MILPA_INDEX_TRUST_SIGNER \
             to configure the expected SubjectAltName for a custom registry."
        ),
        VerificationResult::BundleStale => (
            "the index attestation bundle is beyond the maximum allowed age \
             (rollback attack or frozen CDN). \
             Run 'milpa fetch --refresh-index' to force a fresh fetch, \
             or increase MILPA_INDEX_MAX_AGE."
        ),
        VerificationResult::Trusted => unreachable!("handled above"),
    };

    if *policy == TrustPolicy::Strict {
        return Err(MilpaError::Core(CoreError::Tianguis(
            slug,
            format!(
                "index-trust strict: {slug} for index {index_url:?} — {hint}"
            ),
        )));
    }

    // policy == Warn: emit at most ONE warning per unique index_url per invocation.
    let already_warned = WARNED_URLS.with(|w| w.borrow().contains(index_url));
    if !already_warned {
        WARNED_URLS.with(|w| w.borrow_mut().insert(index_url.to_string()));
        eprintln!(
            "milpa: index-trust warning ({slug}): {hint} (index: {index_url:?})"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// IndexBundleInfo + describe_index_bundle + format_index_trust_info
// — pure JSON observability helpers for `milpa show --index-trust`
// ---------------------------------------------------------------------------
//
// These three items are the Rust counterpart of the Python helpers in
// `impls/python/milpa/index_trust.py`.  They produce byte-identical output
// for the same bundle bytes so the shared conformance fixtures pass for both
// impls.
//
// Fields extracted by pure JSON (no crypto, no network):
//   `integrated_time`  — `verificationMaterial.tlogEntries[0].integratedTime`
//   `rekor_log_index`  — `verificationMaterial.tlogEntries[0].logIndex`
//   `signer_san`       — `_milpa_claims.signer_san` (test/mock bundles)
//   `oidc_issuer`      — `_milpa_claims.oidc_issuer` (test/mock bundles)
//   `subject_sha256`   — `_milpa_claims.subject_sha256` (test/mock bundles)
//
// The `_milpa_claims` section is written into conformance fixture mock bundles
// so all five fields are available without X.509 parsing.  Real Sigstore
// bundles do NOT contain `_milpa_claims`; those fields appear as
// `"(not available)"` in both impls until a dedicated X.509 extraction path
// is added in a future slice.

/// Observable claims extracted from a Sigstore bundle — pure JSON, no crypto.
///
/// Rust parity with Python `IndexBundleInfo` in `impls/python/milpa/index_trust.py`.
#[derive(Debug, Clone)]
pub struct IndexBundleInfo {
    /// Rekor SET `integratedTime` (unix epoch seconds).
    ///
    /// Extracted from `verificationMaterial.tlogEntries[0].integratedTime`.
    /// Used to compute the freshness/staleness of the cached bundle.
    pub integrated_time: i64,

    /// Rekor transparency-log entry index.
    ///
    /// Extracted from `verificationMaterial.tlogEntries[0].logIndex`.
    /// `"(not available)"` when the field is absent.
    pub rekor_log_index: String,

    /// SHA-256 digest of the attested subject (index.kdl bytes).
    ///
    /// Extracted from `_milpa_claims.subject_sha256` in test/mock bundles.
    /// `None` when the field is absent.
    pub subject_sha256: Option<String>,

    /// SubjectAltName from the signing certificate (signer IDENTITY).
    ///
    /// Extracted from `_milpa_claims.signer_san` in test/mock bundles.
    /// `None` when the field is absent.
    pub signer_san: Option<String>,

    /// OIDC issuer from the signing certificate.
    ///
    /// Extracted from `_milpa_claims.oidc_issuer` in test/mock bundles.
    /// `None` when the field is absent.
    pub oidc_issuer: Option<String>,
}

/// Parse a Sigstore bundle JSON and extract observable claims.
///
/// Pure JSON extraction — no cryptographic operations, no network access.
/// Returns `None` if the bytes are not parseable as a JSON object or if the
/// mandatory `integratedTime` field is absent/invalid.
///
/// Rust parity with Python `describe_index_bundle` in `index_trust.py`.
/// Both impls use the SAME JSON paths so `format_index_trust_info` produces
/// byte-identical output for any given bundle bytes.
pub fn describe_index_bundle(bundle_bytes: &[u8]) -> Option<IndexBundleInfo> {
    let data: serde_json::Value = serde_json::from_slice(bundle_bytes).ok()?;
    let obj = data.as_object()?;
    let _ = obj; // confirm it's an object

    // Extract integratedTime (mandatory — same logic as verify_index_bundle spec §3.4.4 step 2).
    // Proto3 JSON encodes int64 as a string; accept both string and native integer.
    let integrated_time = extract_integrated_time(&data).and_then(|t| i64::try_from(t).ok())?;

    // Extract logIndex (Rekor entry reference); normalise to plain integer string.
    let rekor_log_index = {
        let raw = &data["verificationMaterial"]["tlogEntries"][0]["logIndex"];
        if let Some(s) = raw.as_str() {
            // Normalise: parse as i64 and re-stringify to match Python's `str(int(raw_li))`.
            s.parse::<i64>().map(|n| n.to_string()).unwrap_or_else(|_| s.to_string())
        } else if let Some(n) = raw.as_i64() {
            n.to_string()
        } else {
            "(not available)".to_string()
        }
    };

    // Extract signer/issuer/subject from `_milpa_claims` (test/mock section).
    let claims = &data["_milpa_claims"];
    let signer_san = claims["signer_san"].as_str().map(|s| s.to_string());
    let oidc_issuer = claims["oidc_issuer"].as_str().map(|s| s.to_string());
    let subject_sha256 = claims["subject_sha256"].as_str().map(|s| s.to_string());

    Some(IndexBundleInfo {
        integrated_time,
        rekor_log_index,
        subject_sha256,
        signer_san,
        oidc_issuer,
    })
}

/// Format the `milpa show --index-trust` observability output.
///
/// Produces a fixed-width label block where every label (including the colon)
/// is exactly 16 characters so values align in a column.  This layout is
/// byte-identical to the Python `format_index_trust_info` in `index_trust.py`.
///
/// Parameters:
/// - `index_url`    — index URL from `MILPA_INDEX_URL` or the default.
/// - `policy`       — effective index-trust policy string (`"warn"` / `"strict"` / `"off"`).
/// - `index_cached` — whether the index file is present in the local cache.
/// - `bundle_cached`— whether the Sigstore bundle sidecar is present.
/// - `info`         — parsed claims, or `None` when no bundle is cached.
/// - `now`          — current unix epoch seconds (injected for determinism).
/// - `max_age`      — freshness window in seconds (default 604800 = 7 days).
///
/// Returns a `String` with a trailing newline; all line endings are `\n`.
pub fn format_index_trust_info(
    index_url: &str,
    policy: &str,
    index_cached: bool,
    bundle_cached: bool,
    info: Option<&IndexBundleInfo>,
    now: i64,
    max_age: u64,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("index-url:      {index_url}"));
    lines.push(format!("policy:         {policy}"));
    lines.push(format!("index-cached:   {}", if index_cached { "yes" } else { "no" }));
    lines.push(format!("bundle-cached:  {}", if bundle_cached { "yes" } else { "no" }));

    if let Some(info) = info {
        lines.push(format!(
            "signer:         {}",
            info.signer_san.as_deref().unwrap_or("(not available)")
        ));
        lines.push(format!(
            "issuer:         {}",
            info.oidc_issuer.as_deref().unwrap_or("(not available)")
        ));
        lines.push(format!("integrated:     {}", info.integrated_time));
        lines.push(format!(
            "subject-sha256: {}",
            info.subject_sha256.as_deref().unwrap_or("(not available)")
        ));
        lines.push(format!("rekor-entry:    {}", info.rekor_log_index));
        // Item 7 (M10): use signed subtraction so future-dated bundles
        // (integratedTime > now) produce a negative age, which is < max_age
        // → "fresh".  Python: `age = now - info.integrated_time; age < max_age`.
        // The old `now.saturating_sub(…) as u64` wrapped negative ages to huge
        // positive values → false "stale".
        let age = now - info.integrated_time; // i64 arithmetic; negative when future-dated
        let freshness = if age < max_age as i64 { "fresh" } else { "stale" };
        lines.push(format!("freshness:      {freshness}"));
    }

    lines.join("\n") + "\n"
}

// ---------------------------------------------------------------------------
// Unit tests — parity with Python S3
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- VerificationResult wire string parity with Python ---

    #[test]
    fn trusted_value_matches_python() {
        assert_eq!(VerificationResult::Trusted.value(), "trusted");
    }

    #[test]
    fn sig_invalid_value_matches_python() {
        assert_eq!(VerificationResult::SigInvalid.value(), "sig-invalid");
    }

    #[test]
    fn digest_mismatch_value_matches_python() {
        assert_eq!(VerificationResult::DigestMismatch.value(), "digest-mismatch");
    }

    #[test]
    fn signer_mismatch_value_matches_python() {
        assert_eq!(VerificationResult::SignerMismatch.value(), "signer-mismatch");
    }

    #[test]
    fn bundle_stale_value_matches_python() {
        assert_eq!(VerificationResult::BundleStale.value(), "bundle-stale");
    }

    #[test]
    fn bundle_missing_value_matches_python() {
        assert_eq!(VerificationResult::BundleMissing.value(), "bundle-missing");
    }

    #[test]
    fn bundle_malformed_value_matches_python() {
        assert_eq!(VerificationResult::BundleMalformed.value(), "bundle-malformed");
    }

    // --- Real SigstoreVerifier (S2) — reachable-without-preimage cases ---
    //
    // The real `bundle_v03.json` fixture attests an artifact whose bytes are not shipped,
    // so through the PUBLIC `verify()` the digest pre-check always fires first. That makes
    // DigestMismatch + the structural rejections testable here; the full-green `Trusted`
    // verdict and SignerMismatch need a bundle over a KNOWN index and land in S5(a). The
    // real cert-chain + offline-inclusion crypto is already proven green in
    // `rekor_adapter::tests` (real inclusion) against this same fixture + trust root.

    const REAL_BUNDLE_V03: &[u8] = include_bytes!("testdata/bundle_v03.json");

    /// The committed real-bundle fixture directory (single source of truth; regenerated by
    /// `.github/workflows/generate-attestation-fixture.yaml`). Read at runtime — the bundle
    /// is shared with the Python impl, not duplicated into per-crate testdata.
    const FIXTURE_DIR: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../conformance/spec-v1/_oracle/attestation");
    /// The GitHub Actions workflow identity that signed the fixture bundle (keyless).
    const FIXTURE_SIGNER: &str =
        "https://github.com/coreyleavitt/milpa/.github/workflows/generate-attestation-fixture.yaml@refs/heads/main";

    /// S5(a): the real `cosign`-signed bundle verifies **Trusted** end-to-end against the
    /// embedded production trust root — the "units green, prod fails" hole a best-in-class
    /// verifier cannot ship with. Exercises the full production path (real Fulcio cert chain +
    /// SCT + DSSE signature + offline Rekor inclusion) and the two preimage-dependent negatives
    /// S2 could not reach (SignerMismatch and the green path itself).
    ///
    /// Requires the vendored sigstore patch (`.vendor-sigstore`, `[patch.crates-io]`) that drops
    /// the unsound DSSE envelopeHash re-serialization check — see that dir's MILPA-PATCH.md.
    #[test]
    fn s5_real_bundle_verifies_trusted_end_to_end() {
        let index = std::fs::read(format!("{FIXTURE_DIR}/index.kdl")).expect("fixture index");
        let bundle = std::fs::read(format!("{FIXTURE_DIR}/index.kdl.bundle")).expect("fixture bundle");

        // Full green.
        let r = SigstoreVerifier.verify(&index, &bundle, &TrustBundle::production(), FIXTURE_SIGNER, None);
        assert_eq!(r, VerificationResult::Trusted, "real bundle must verify Trusted, got {r:?}");

        // Wrong expected signer → SignerMismatch (reachable now that the digest matches).
        let r = SigstoreVerifier.verify(
            &index,
            &bundle,
            &TrustBundle::production(),
            "https://github.com/evil/repo/.github/workflows/x.yaml@refs/heads/main",
            None,
        );
        assert_eq!(r, VerificationResult::SignerMismatch, "wrong signer → SignerMismatch, got {r:?}");

        // Wrong index bytes → DigestMismatch (pre-check fires first).
        let r = SigstoreVerifier.verify(b"tampered index", &bundle, &TrustBundle::production(), FIXTURE_SIGNER, None);
        assert_eq!(r, VerificationResult::DigestMismatch, "wrong index → DigestMismatch, got {r:?}");
    }

    /// S5.5 cross-impl differential: the SAME committed multi-fault bundle (wrong subject digest
    /// + corrupt signature) must yield the SAME slug in both impls — `DigestMismatch`. Both impls
    /// check the subject-digest binding BEFORE cryptographic verification (spec §3.4.4 precedence),
    /// so the digest fault wins deterministically. The Python impl asserts the same on the same
    /// fixture (`test_index_trust.py::test_s55_*`) — the first-failure-precedence divergence class
    /// S5.5 exists to catch, now a defined guarantee.
    #[test]
    fn s5_5_multifault_bundle_same_slug_as_python() {
        let index = std::fs::read(format!("{FIXTURE_DIR}/index.kdl")).expect("fixture index");
        let bundle = std::fs::read(format!("{FIXTURE_DIR}/index.kdl.bundle.multifault"))
            .expect("multifault fixture");
        let r = SigstoreVerifier.verify(&index, &bundle, &TrustBundle::production(), FIXTURE_SIGNER, None);
        assert_eq!(r, VerificationResult::DigestMismatch, "both impls must agree: DigestMismatch, got {r:?}");
    }

    #[test]
    fn real_verifier_digest_mismatch_takes_precedence() {
        // A real, well-formed bundle but an index whose sha256 ≠ the attested subject.
        // Proves the digest pre-check runs (and wins) BEFORE the opaque crate call — so a
        // mismatch is deterministically DigestMismatch, never mis-slugged SigInvalid (§4).
        let out = SigstoreVerifier.verify(
            b"these are not the attested index bytes",
            REAL_BUNDLE_V03,
            &TrustBundle::production(),
            DEFAULT_INDEX_SIGNER,
            None, // pure cache read: skip the freshness bound
        );
        assert_eq!(out, VerificationResult::DigestMismatch, "got {out:?}");
    }

    #[test]
    fn real_verifier_non_json_bundle_is_malformed() {
        let out = SigstoreVerifier.verify(
            b"index",
            b"this is not a bundle",
            &TrustBundle::production(),
            DEFAULT_INDEX_SIGNER,
            None,
        );
        assert_eq!(out, VerificationResult::BundleMalformed, "got {out:?}");
    }

    #[test]
    fn real_verifier_multi_tlog_entry_is_malformed() {
        // Duplicate the single tlog entry → two entries. The singleton assertion must
        // reject (no entry-selection ambiguity, §4), and it fires before the digest check.
        let mut v: serde_json::Value = serde_json::from_slice(REAL_BUNDLE_V03).unwrap();
        let entries = v["verificationMaterial"]["tlogEntries"]
            .as_array_mut()
            .expect("tlogEntries array");
        let dup = entries[0].clone();
        entries.push(dup);
        let bytes = serde_json::to_vec(&v).unwrap();
        let out = SigstoreVerifier.verify(
            b"index",
            &bytes,
            &TrustBundle::production(),
            DEFAULT_INDEX_SIGNER,
            None,
        );
        assert_eq!(out, VerificationResult::BundleMalformed, "got {out:?}");
    }

    // Item 6 (M6): pin the DEFAULT_INDEX_SIGNER constant to the spec §3.4.4 step 5 value.
    #[test]
    fn default_index_signer_pin_matches_spec() {
        // Regression guard: the constant must be the tianguis reindex.yaml OIDC SAN.
        // Changing this accidentally would silently bypass signer-mismatch detection
        // for any consumer using the default signer.
        assert_eq!(
            DEFAULT_INDEX_SIGNER,
            "https://github.com/coreyleavitt/tianguis/.github/workflows/reindex.yaml\
             @refs/heads/main",
            "spec §3.4.4 step 5: DEFAULT_INDEX_SIGNER must match the tianguis reindex workflow"
        );
    }

    /// All 7 variants round-trip through from_value / value.
    #[test]
    fn all_variants_round_trip() {
        let variants = [
            VerificationResult::Trusted,
            VerificationResult::SigInvalid,
            VerificationResult::DigestMismatch,
            VerificationResult::SignerMismatch,
            VerificationResult::BundleStale,
            VerificationResult::BundleMissing,
            VerificationResult::BundleMalformed,
        ];
        for v in &variants {
            let s = v.value();
            let parsed = VerificationResult::from_value(s)
                .unwrap_or_else(|| panic!("from_value({s:?}) returned None"));
            assert_eq!(*v, parsed, "round-trip failed for {s:?}");
        }
    }

    // --- MockVerifier passthrough for all 7 variants ---

    #[test]
    fn mock_verifier_returns_configured_result() {
        let variants = [
            VerificationResult::Trusted,
            VerificationResult::SigInvalid,
            VerificationResult::DigestMismatch,
            VerificationResult::SignerMismatch,
            VerificationResult::BundleStale,
            VerificationResult::BundleMissing,
            VerificationResult::BundleMalformed,
        ];
        let trust_bundle = TrustBundle::test();
        for expected in &variants {
            let mock = MockVerifier::new(*expected);
            let got = mock.verify(b"index", b"bundle", &trust_bundle, "signer", Some(604800));
            assert_eq!(
                got, *expected,
                "MockVerifier should return the configured result"
            );
        }
    }

    #[test]
    fn mock_verifier_ignores_max_age_none() {
        let mock = MockVerifier::new(VerificationResult::Trusted);
        let trust_bundle = TrustBundle::test();
        // Even with None max_age (skip freshness), MockVerifier returns the configured result.
        let got = mock.verify(b"index", b"bundle", &trust_bundle, "signer", None);
        assert_eq!(got, VerificationResult::Trusted);
    }

    // --- verify_index_bundle: malformed bundle → BundleMalformed ---

    #[test]
    fn not_json_is_bundle_malformed() {
        let trust_bundle = TrustBundle::test();
        let result = verify_index_bundle(
            b"index",
            b"not valid json!!!",
            &trust_bundle,
            "signer",
            None,
        );
        assert_eq!(result, VerificationResult::BundleMalformed);
    }

    #[test]
    fn json_non_object_is_bundle_malformed() {
        let trust_bundle = TrustBundle::test();
        // JSON array is not a valid bundle object.
        let result = verify_index_bundle(b"index", b"[1, 2, 3]", &trust_bundle, "signer", None);
        assert_eq!(result, VerificationResult::BundleMalformed);
    }

    #[test]
    fn empty_bytes_is_bundle_malformed() {
        let trust_bundle = TrustBundle::test();
        let result = verify_index_bundle(b"index", b"", &trust_bundle, "signer", None);
        assert_eq!(result, VerificationResult::BundleMalformed);
    }

    // --- verify_index_bundle: missing/non-numeric integratedTime → BundleMalformed ---

    #[test]
    fn missing_tlog_entries_is_bundle_malformed() {
        let trust_bundle = TrustBundle::test();
        let bundle = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {}
        });
        let result = verify_index_bundle(
            b"index",
            bundle.to_string().as_bytes(),
            &trust_bundle,
            "signer",
            None,
        );
        assert_eq!(result, VerificationResult::BundleMalformed);
    }

    #[test]
    fn empty_tlog_entries_is_bundle_malformed() {
        let trust_bundle = TrustBundle::test();
        let bundle = serde_json::json!({
            "verificationMaterial": {
                "tlogEntries": []
            }
        });
        let result = verify_index_bundle(
            b"index",
            bundle.to_string().as_bytes(),
            &trust_bundle,
            "signer",
            None,
        );
        assert_eq!(result, VerificationResult::BundleMalformed);
    }

    #[test]
    fn non_numeric_integrated_time_is_bundle_malformed() {
        let trust_bundle = TrustBundle::test();
        let bundle = serde_json::json!({
            "verificationMaterial": {
                "tlogEntries": [{"integratedTime": "not-a-number"}]
            }
        });
        let result = verify_index_bundle(
            b"index",
            bundle.to_string().as_bytes(),
            &trust_bundle,
            "signer",
            None,
        );
        assert_eq!(result, VerificationResult::BundleMalformed);
    }

    #[test]
    fn missing_integrated_time_is_bundle_malformed() {
        let trust_bundle = TrustBundle::test();
        let bundle = serde_json::json!({
            "verificationMaterial": {
                "tlogEntries": [{"logIndex": "42"}]
            }
        });
        let result = verify_index_bundle(
            b"index",
            bundle.to_string().as_bytes(),
            &trust_bundle,
            "signer",
            None,
        );
        assert_eq!(result, VerificationResult::BundleMalformed);
    }

    // --- verify_index_bundle: freshness check ---

    /// Stale bundle + finite max_age → BundleStale.
    #[test]
    fn stale_bundle_with_max_age_returns_bundle_stale() {
        let trust_bundle = TrustBundle::test();
        // integratedTime = 1 (epoch + 1 second) — definitely stale relative to now.
        let bundle = serde_json::json!({
            "verificationMaterial": {
                "tlogEntries": [{"integratedTime": "1"}]
            }
        });
        let result = verify_index_bundle(
            b"index",
            bundle.to_string().as_bytes(),
            &trust_bundle,
            "signer",
            Some(604800), // 7-day max age
        );
        assert_eq!(result, VerificationResult::BundleStale);
    }

    /// Same stale bundle + None max_age → freshness NOT asserted, passes step 3.
    /// (This minimal bundle has no DSSE content, so `verify_crypto` returns BundleMalformed
    /// — the point of the test is only that `None` skips the freshness bound, i.e. NOT stale.)
    #[test]
    fn stale_bundle_with_none_max_age_is_not_stale() {
        let trust_bundle = TrustBundle::test();
        // integratedTime = 1 (epoch + 1 second) — stale by wall clock.
        let bundle = serde_json::json!({
            "verificationMaterial": {
                "tlogEntries": [{"integratedTime": "1"}]
            }
        });
        let result = verify_index_bundle(
            b"index",
            bundle.to_string().as_bytes(),
            &trust_bundle,
            "signer",
            None, // skip freshness
        );
        // Must NOT be BundleStale — freshness is skipped with None.
        assert_ne!(result, VerificationResult::BundleStale, "None max_age must skip freshness check");
    }

    /// Fresh bundle (integratedTime = now) + finite max_age → NOT stale.
    #[test]
    fn fresh_bundle_is_not_stale() {
        let trust_bundle = TrustBundle::test();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let bundle = serde_json::json!({
            "verificationMaterial": {
                "tlogEntries": [{"integratedTime": now.to_string()}]
            }
        });
        let result = verify_index_bundle(
            b"index",
            bundle.to_string().as_bytes(),
            &trust_bundle,
            "signer",
            Some(604800),
        );
        assert_ne!(result, VerificationResult::BundleStale, "fresh bundle must not be stale");
    }

    /// integratedTime as a native JSON number (some tools may emit without quotes).
    #[test]
    fn integer_integrated_time_is_accepted() {
        let trust_bundle = TrustBundle::test();
        let bundle = serde_json::json!({
            "verificationMaterial": {
                "tlogEntries": [{"integratedTime": 1}]
            }
        });
        let result = verify_index_bundle(
            b"index",
            bundle.to_string().as_bytes(),
            &trust_bundle,
            "signer",
            Some(604800), // will be stale since integratedTime=1
        );
        // Should be stale (integratedTime=1 is long ago), NOT malformed.
        assert_eq!(result, VerificationResult::BundleStale);
    }

    // --- IndexTrustConfig defaults ---

    #[test]
    fn index_trust_config_default_max_age() {
        let cfg = IndexTrustConfig::new(
            TrustPolicy::Warn,
            TrustBundle::test(),
            "signer".to_owned(),
        );
        assert_eq!(cfg.max_age_seconds, IndexTrustConfig::DEFAULT_MAX_AGE);
        assert_eq!(cfg.max_age_seconds, 604800);
    }

    // --- TrustBundle factory methods ---

    #[test]
    fn production_trust_bundle_loads() {
        let bundle = TrustBundle::production();
        assert_eq!(bundle.label, "production");
        assert!(!bundle.raw_json.is_empty());
    }

    #[test]
    fn test_trust_bundle_loads() {
        let bundle = TrustBundle::test();
        assert_eq!(bundle.label, "test");
        assert!(!bundle.raw_json.is_empty());
    }

    // ---------------------------------------------------------------------------
    // describe_index_bundle — Rust parity with Python unit tests
    // ---------------------------------------------------------------------------

    const SIGNER_SAN: &str = "https://github.com/coreyleavitt/tianguis/.github/workflows/reindex.yaml@refs/heads/main";
    const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
    const SUBJECT_SHA256: &str =
        "abc123deadbeefabc123deadbeefabc123deadbeefabc123deadbeefabc12345";

    fn mock_bundle_bytes() -> Vec<u8> {
        serde_json::json!({
            "verificationMaterial": {
                "tlogEntries": [{"integratedTime": "1735000000", "logIndex": "98765432"}]
            },
            "_milpa_claims": {
                "signer_san": SIGNER_SAN,
                "oidc_issuer": OIDC_ISSUER,
                "subject_sha256": SUBJECT_SHA256,
            }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn describe_full_mock_bundle() {
        let info = describe_index_bundle(&mock_bundle_bytes()).expect("should parse");
        assert_eq!(info.integrated_time, 1_735_000_000);
        assert_eq!(info.rekor_log_index, "98765432");
        assert_eq!(info.signer_san.as_deref(), Some(SIGNER_SAN));
        assert_eq!(info.oidc_issuer.as_deref(), Some(OIDC_ISSUER));
        assert_eq!(info.subject_sha256.as_deref(), Some(SUBJECT_SHA256));
    }

    #[test]
    fn describe_integer_integrated_time() {
        let bytes = serde_json::json!({
            "verificationMaterial": {
                "tlogEntries": [{"integratedTime": 1_735_000_000_i64, "logIndex": "42"}]
            }
        })
        .to_string()
        .into_bytes();
        let info = describe_index_bundle(&bytes).expect("should parse");
        assert_eq!(info.integrated_time, 1_735_000_000);
        assert_eq!(info.rekor_log_index, "42");
    }

    #[test]
    fn describe_no_milpa_claims_fields_are_none() {
        let bytes = serde_json::json!({
            "verificationMaterial": {
                "tlogEntries": [{"integratedTime": "1735000000", "logIndex": "1"}]
            }
        })
        .to_string()
        .into_bytes();
        let info = describe_index_bundle(&bytes).expect("should parse");
        assert!(info.signer_san.is_none());
        assert!(info.oidc_issuer.is_none());
        assert!(info.subject_sha256.is_none());
        assert_eq!(info.rekor_log_index, "1");
    }

    #[test]
    fn describe_missing_log_index_shows_not_available() {
        let bytes = serde_json::json!({
            "verificationMaterial": {
                "tlogEntries": [{"integratedTime": "1735000000"}]
            }
        })
        .to_string()
        .into_bytes();
        let info = describe_index_bundle(&bytes).expect("should parse");
        assert_eq!(info.rekor_log_index, "(not available)");
    }

    #[test]
    fn describe_not_json_returns_none() {
        assert!(describe_index_bundle(b"not valid json!!!").is_none());
    }

    #[test]
    fn describe_json_array_returns_none() {
        assert!(describe_index_bundle(b"[\"not\", \"an\", \"object\"]").is_none());
    }

    #[test]
    fn describe_missing_integrated_time_returns_none() {
        let bytes = serde_json::json!({"verificationMaterial": {"tlogEntries": [{"logIndex": "1"}]}})
            .to_string()
            .into_bytes();
        assert!(describe_index_bundle(&bytes).is_none());
    }

    #[test]
    fn describe_empty_tlog_entries_returns_none() {
        let bytes = serde_json::json!({"verificationMaterial": {"tlogEntries": []}})
            .to_string()
            .into_bytes();
        assert!(describe_index_bundle(&bytes).is_none());
    }

    #[test]
    fn describe_empty_bytes_returns_none() {
        assert!(describe_index_bundle(b"").is_none());
    }

    // ---------------------------------------------------------------------------
    // format_index_trust_info — byte-identical to Python
    // ---------------------------------------------------------------------------

    #[test]
    fn format_no_bundle() {
        let out = format_index_trust_info(
            "https://example.com/index.kdl",
            "warn",
            false,
            false,
            None,
            1_735_001_000,
            604800,
        );
        assert_eq!(
            out,
            "index-url:      https://example.com/index.kdl\n\
             policy:         warn\n\
             index-cached:   no\n\
             bundle-cached:  no\n"
        );
    }

    #[test]
    fn format_fresh_bundle() {
        let info = IndexBundleInfo {
            integrated_time: 1_735_000_000,
            rekor_log_index: "98765432".to_string(),
            subject_sha256: Some(SUBJECT_SHA256.to_string()),
            signer_san: Some(SIGNER_SAN.to_string()),
            oidc_issuer: Some(OIDC_ISSUER.to_string()),
        };
        let out = format_index_trust_info(
            "https://mock.example.com/index.kdl",
            "warn",
            true,
            true,
            Some(&info),
            1_735_001_000, // age = 1000 s < 604800
            604800,
        );
        assert!(out.ends_with("freshness:      fresh\n"));
        assert!(out.contains("policy:         warn\n"));
        assert!(out.contains(&format!("signer:         {SIGNER_SAN}\n")));
        assert!(out.contains("integrated:     1735000000\n"));
        assert!(out.contains("rekor-entry:    98765432\n"));
    }

    #[test]
    fn format_stale_bundle() {
        let info = IndexBundleInfo {
            integrated_time: 1_735_000_000,
            rekor_log_index: "98765432".to_string(),
            subject_sha256: Some(SUBJECT_SHA256.to_string()),
            signer_san: Some(SIGNER_SAN.to_string()),
            oidc_issuer: Some(OIDC_ISSUER.to_string()),
        };
        let out = format_index_trust_info(
            "https://mock.example.com/index.kdl",
            "strict",
            true,
            true,
            Some(&info),
            1_735_700_000, // age = 700000 s > 604800
            604800,
        );
        assert!(out.ends_with("freshness:      stale\n"));
        assert!(out.contains("policy:         strict\n"));
    }

    #[test]
    fn format_not_available_fields() {
        let info = IndexBundleInfo {
            integrated_time: 1_735_000_000,
            rekor_log_index: "99".to_string(),
            subject_sha256: None,
            signer_san: None,
            oidc_issuer: None,
        };
        let out = format_index_trust_info(
            "https://x.example.com/index.kdl",
            "warn",
            true,
            true,
            Some(&info),
            1_735_001_000,
            604800,
        );
        assert!(out.contains("signer:         (not available)\n"));
        assert!(out.contains("issuer:         (not available)\n"));
        assert!(out.contains("subject-sha256: (not available)\n"));
    }

    // Item 7 (M10): future-dated integratedTime must be treated as "fresh"
    // (not "stale") in both impls.  Python: `age = now - integrated_time`;
    // negative age → `age < max_age` → True → "fresh".  The Rust bug was
    // `now.saturating_sub(integrated_time) as u64` which wraps to a huge u64
    // for negative ages → reports "stale" instead.
    #[test]
    fn format_future_dated_integrated_time_is_fresh() {
        let now: i64 = 1_735_000_000;
        let info = IndexBundleInfo {
            integrated_time: now + 1000, // 1000 seconds in the future
            rekor_log_index: "1".to_string(),
            subject_sha256: None,
            signer_san: None,
            oidc_issuer: None,
        };
        let out = format_index_trust_info(
            "https://example.com/index.kdl",
            "warn",
            true,
            true,
            Some(&info),
            now,
            604800,
        );
        assert!(
            out.ends_with("freshness:      fresh\n"),
            "future-dated integratedTime must be 'fresh', got: {out:?}"
        );
    }

    #[test]
    fn format_label_alignment_all_lines_column_16() {
        let info = IndexBundleInfo {
            integrated_time: 1_735_000_000,
            rekor_log_index: "98765432".to_string(),
            subject_sha256: Some(SUBJECT_SHA256.to_string()),
            signer_san: Some(SIGNER_SAN.to_string()),
            oidc_issuer: Some(OIDC_ISSUER.to_string()),
        };
        let out = format_index_trust_info(
            "https://mock.example.com/index.kdl",
            "warn",
            true,
            true,
            Some(&info),
            1_735_001_000,
            604800,
        );
        for line in out.trim_end_matches('\n').split('\n') {
            assert!(
                line.len() > 16,
                "Line too short: {line:?}"
            );
            let bytes = line.as_bytes();
            assert_eq!(
                bytes[15], b' ',
                "Column 16 alignment broken: {line:?}; char at index 15 is {:?}",
                bytes[15] as char
            );
        }
    }
}
