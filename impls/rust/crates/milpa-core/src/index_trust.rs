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
//! - [`verify_index_bundle`] — pure function; never panics.  Implements RFC §4 steps 1–3
//!   (JSON parse, integratedTime extract, freshness check) correctly.  Steps 4–6
//!   (crypto) are stubbed pending S4b (see below).
//! - [`SigstoreVerifier`] — **S4b ACTIVE**: placeholder; always panics with
//!   `unimplemented!`.  See the S4b note below.
//! - [`MockVerifier`] — test seam; returns a caller-supplied result, ignoring all inputs.
//!   This is the S7 conformance corpus seam (`mock_verifier_result` env field).
//! - [`IndexTrustConfig`] — struct: policy + trust_bundle + expected_signer + max_age.
//!   Does NOT contain a verifier field — verifier is an explicit param of
//!   `load_index(url, config, verifier, http_get, bundle_http_get)` (S6).
//! - [`TrustBundle`] — production (`include_bytes!` over `_trust/trust_bundle.json` PLACEHOLDER)
//!   vs test (`_oracle/test_trust_bundle.json`). Factory methods: [`TrustBundle::production`] /
//!   [`TrustBundle::test`].
//!
//! # S4b ACTIVE — SigstoreVerifier is a placeholder
//!
//! The S4 spike found that `sigstore-rs` 0.11.0 does **NOT** support DSSE/in-toto attestation
//! bundles produced by `cosign attest-blob`:
//!
//! - [`bundle::verify::models::BundleErrorKind::DsseUnsupported`] is returned for any bundle
//!   whose `content` is a DSSE envelope (all `cosign attest-blob` output).
//! - Only `Content::MessageSignature` (hashedrekord / `cosign sign-blob` format) is handled.
//! - Bundle v0.3 format is rejected (`BundleProfileErrorKind::Unknown`).
//!
//! What IS confirmed:
//! - Offline flag (`verify(input, bundle, policy, offline=true)`) exists: ✓
//! - Cert-at-SET-time: confirmed in `verifier.rs` step 7: cert expiry checked against
//!   `log_entry.integrated_time`, NOT wall-clock.  ✓
//! - `blocking::Verifier` (sync): ✓
//! - `ManualTrustRoot` for custom trust roots: ✓
//! - `Identity` policy (SubjectAltName + OIDC issuer): ✓
//!
//! S4b will retrofit a real `SigstoreVerifier` using either:
//!   (a) a newer sigstore-rs version that supports DSSE/in-toto attestation bundles, or
//!   (b) an alternative approach that meets the same requirements.
//! Conformance stays green via [`MockVerifier`].
//!
//! # Slice boundary
//!
//! S4 does NOT add `TNG-INDEX-*` error codes to `errors.rs` or `spec/errors.md` — those
//! land in S6 co-committed with the raise sites in `index_cache.rs`.  The bijection test
//! (`rust_error_catalog_is_a_bijection_with_the_spec`) must remain green after this slice.
//!
//! RFC: `docs/rfc-registry-trust-federation.md` §4, §6.5, §10.1, §11 S4/S4b.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use milpa_manifest::TrustPolicy;

use crate::error::{CoreError, MilpaError};

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
    /// All six RFC §4 verification steps passed.  The index bytes are trustworthy.
    Trusted,
    /// Cryptographic verification failed: bad Fulcio cert chain, cert was expired AT
    /// `integratedTime`, or Rekor inclusion proof invalid.
    ///
    /// A cert now-expired but valid at `integratedTime` MUST NOT trigger this variant
    /// (RFC §4 step 2 — cert-at-SET-time requirement).
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
    /// Load the embedded production trust bundle from `_trust/trust_bundle.json`.
    ///
    /// **NOTE:** The current file is a PLACEHOLDER (contains `{"__placeholder__": true}`).
    /// Replace with the real Sigstore public-instance Fulcio + Rekor bundle before S5/S6
    /// wires production use. See RFC §3.1 and §12.3.
    ///
    /// Production code ONLY — test code MUST use [`TrustBundle::test`].
    pub fn production() -> Self {
        // deps-rationale: embedded at build time; no runtime network fetch.
        // The placeholder is clearly marked; real bundle gated at S5/S6.
        // RFC §3.1: the trust bundle is embedded via `include_bytes!` and rotated
        // only via a milpa version update (TUF-based rotation is future work, RFC §12.3).
        static PRODUCTION_BYTES: &[u8] =
            include_bytes!("_trust/trust_bundle.json");
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
    ///   reads to skip the wall-clock bound (RFC §4 step 6, §7.2).
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
// Pure verification function — RFC §4 steps 1–3; crypto stubbed (S4b)
// ---------------------------------------------------------------------------

/// Verify a Sigstore bundle against `index_bytes`; return a [`VerificationResult`].
///
/// Implements RFC §4 verification steps 1–3 correctly:
///
/// **Step 1** — Parse bundle JSON.  Non-JSON or non-object → [`BundleMalformed`]
/// (pre-crypto failure, distinct from a cryptographic failure).
///
/// **Step 2** — Extract `integratedTime` from
/// `verificationMaterial.tlogEntries[0].integratedTime`.  Missing or non-integer
/// → [`BundleMalformed`].  This is the anchor for cert-at-SET-time checking (RFC §4
/// step 2) — NOT wall-clock `now`.
///
/// **Step 3** — Freshness check: ONLY when `max_age_seconds` is `Some`.
/// If `now − integratedTime ≥ max_age_seconds` → [`BundleStale`].
/// Passing `None` skips this bound entirely (pure cache reads, offline safety —
/// RFC §4 step 6, §7.2).
///
/// **Steps 4–6 — S4b ACTIVE**: crypto verification is stubbed.  The sigstore-rs 0.11.0
/// crate does not support DSSE/in-toto attestation bundles (`cosign attest-blob` format);
/// see the module-level S4b note.  Returns [`SigInvalid`] for all bundles that pass
/// steps 1–3.  This is conservative (no false [`Trusted`] results).
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
    // This timestamp is the anchor for cert-at-SET-time checking (RFC §4 step 2).
    let integrated_time: u64 = match extract_integrated_time(&bundle_json) {
        Some(t) => t,
        None => return VerificationResult::BundleMalformed,
    };

    // Step 3: freshness check — ONLY on the network-fetch path.
    // Pure cache reads (States 1 and 3) pass max_age_seconds=None: the
    // wall-clock bound is NOT re-asserted so offline/air-gapped invocations
    // never fail on staleness (RFC §4 step 6, §7.2).
    if let Some(max_age) = max_age_seconds {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(integrated_time) >= max_age {
            return VerificationResult::BundleStale;
        }
    }

    // Steps 4–6: S4b ACTIVE — crypto verification placeholder.
    // sigstore-rs 0.11.0 does not support DSSE/in-toto attestation bundles.
    // See the module-level S4b note. Returns SigInvalid conservatively (no false Trusted).
    _crypto_stub_s4b(index_bytes, &bundle_json, trust_bundle, expected_signer, integrated_time)
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

/// S4b placeholder for steps 4–6 crypto verification.
///
/// Returns [`VerificationResult::SigInvalid`] conservatively.
/// S4b will replace this with real DSSE/in-toto verification using either
/// a newer sigstore-rs version or an alternative approach.
///
/// RFC §11 S4b: "Rust SigstoreVerifier retrofit (CONDITIONAL)".
#[allow(unused_variables)]
fn _crypto_stub_s4b(
    index_bytes: &[u8],
    bundle_json: &serde_json::Value,
    trust_bundle: &TrustBundle,
    expected_signer: &str,
    integrated_time: u64,
) -> VerificationResult {
    // S4b TODO: implement real DSSE/in-toto verification.
    // sigstore-rs 0.11.0 DsseUnsupported gap — see module-level S4b note.
    // Options for S4b:
    //   (a) newer sigstore-rs with DSSE support
    //   (b) manual DSSE envelope signature verification using sigstore crypto primitives
    VerificationResult::SigInvalid
}

// ---------------------------------------------------------------------------
// SigstoreVerifier — production IndexBundleVerifier (RFC §11 S4)
// ---------------------------------------------------------------------------

/// Production verifier using `sigstore-rs`.
///
/// # S4b ACTIVE — this is a placeholder that panics
///
/// The S4 spike confirmed that sigstore-rs 0.11.0 does NOT support DSSE/in-toto
/// attestation bundles from `cosign attest-blob` (`BundleErrorKind::DsseUnsupported`).
/// Per RFC §11 S4b, `SigstoreVerifier` is a clearly-marked placeholder until S4b
/// retrofits the real implementation.
///
/// Calling `SigstoreVerifier::verify()` will panic with `unimplemented!`.
/// Use [`MockVerifier`] for all tests and conformance fixtures.
///
/// S4b will retrofit a real implementation using either:
///   (a) a newer sigstore-rs version with DSSE support, or
///   (b) an alternative crate or approach.
///
/// RFC §11 S4/S4b.
pub struct SigstoreVerifier;

impl IndexBundleVerifier for SigstoreVerifier {
    fn verify(
        &self,
        _index_bytes: &[u8],
        _bundle_bytes: &[u8],
        _trust_bundle: &TrustBundle,
        _expected_signer: &str,
        _max_age_seconds: Option<u64>,
    ) -> VerificationResult {
        // S4b ACTIVE: sigstore-rs 0.11.0 does not support DSSE/in-toto attestation bundles.
        // The `cosign attest-blob` bundle format (Content::DsseEnvelope) returns
        // BundleErrorKind::DsseUnsupported in the current sigstore-rs API.
        //
        // S4b will retrofit this once DSSE support lands upstream or an alternative
        // approach is identified. Until then, this will panic if called.
        //
        // All conformance tests and policy tests use MockVerifier; this code path
        // is not reached in testing.
        //
        // RFC §11 S4b: "Rust SigstoreVerifier retrofit (CONDITIONAL)".
        unimplemented!(
            "SigstoreVerifier: S4b ACTIVE — sigstore-rs 0.11.0 does not support \
             DSSE/in-toto attestation bundles (BundleErrorKind::DsseUnsupported). \
             Use MockVerifier for tests. See RFC docs/rfc-registry-trust-federation.md §11 S4b."
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

    // Map VerificationResult → (slug, human_hint).
    let (slug, hint): (&'static str, &'static str) = match result {
        VerificationResult::BundleMissing => (
            "TNG-INDEX-BUNDLE-MISSING",
            "no attestation bundle for the index. \
             Run 'milpa fetch --refresh-index' to re-fetch with attestation, \
             or set 'index-trust \"off\"' in milpa.kdl to suppress.",
        ),
        VerificationResult::BundleMalformed => (
            "TNG-INDEX-BUNDLE-MALFORMED",
            "the Sigstore bundle is not valid JSON or missing required fields.",
        ),
        VerificationResult::SigInvalid => (
            "TNG-INDEX-SIGNATURE-INVALID",
            "cryptographic verification of the index Sigstore bundle failed.",
        ),
        VerificationResult::DigestMismatch => (
            "TNG-INDEX-DIGEST-MISMATCH",
            "the bundle's attested subject digest does not match the index bytes \
             (tampering or mismatched bundle/index pair).",
        ),
        VerificationResult::SignerMismatch => (
            "TNG-INDEX-SIGNER-MISMATCH",
            "the bundle signer identity does not match the expected signer. \
             Set 'index-trust-signer' in milpa.kdl or MILPA_INDEX_TRUST_SIGNER \
             to configure the expected SubjectAltName for a custom registry.",
        ),
        VerificationResult::BundleStale => (
            "TNG-INDEX-BUNDLE-STALE",
            "the index attestation bundle is beyond the maximum allowed age \
             (rollback attack or frozen CDN). \
             Run 'milpa fetch --refresh-index' to force a fresh fetch, \
             or increase MILPA_INDEX_MAX_AGE.",
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
    /// (Steps 4–6 return SigInvalid due to S4b stub — that's the expected result.)
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
        // Steps 4–6 return SigInvalid due to S4b stub.
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
}
