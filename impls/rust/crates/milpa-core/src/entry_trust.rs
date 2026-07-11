//! Per-entry Sigstore attestation gate — RFC `rfc-per-entry-attestation.md`, P3a.
//!
//! Rust parity with the Python `entry_trust.py` module.
//!
//! # Public surface
//!
//! - [`EntryVerificationResult`] — 8-variant GATE-level result type (`Trusted`
//!   + 7 slugged failure states). NOT an extension of
//!   [`crate::index_trust::VerificationResult`] — see "Type reuse decision"
//!   below.
//! - [`VerifierOutcome`] — 6-variant VERIFIER-domain result type (CR18): the
//!   proper subset of `EntryVerificationResult` a real verifier can ever
//!   produce (excludes the two gate-only states `Unattested`/`BundleMissing`,
//!   which the gate decides before ever calling the verifier). A dedicated
//!   type rather than a doc-comment convention makes that exclusion
//!   type-checked, not merely documented.
//! - [`EntrySubject`] — `{name, sha256}`, the two-coordinate subject binding
//!   (RFC §1).
//! - [`EntryBundleVerifier`] — trait: the injected verifier seam (RFC §6).
//!   Returns [`VerifierOutcome`]. Production code passes
//!   [`SigstoreEntryVerifier`]; test/conformance code passes
//!   [`MockEntryVerifier`].
//! - [`SigstoreEntryVerifier`] — production verifier. See "Extract-or-decline
//!   decision" below for why real-crypto verification is P3b-gated.
//! - [`MockEntryVerifier`] — test verifier: keyed per-subject outcome scripting.
//! - [`EntryTrustConfig`] — config bundle threaded through the resolver.
//! - [`evaluate_entry_attestation`] — runs gate stages 0-7 (RFC §5 table) for
//!   one selected registry-resolved dep.
//! - [`enforce_entry_trust`] — warn/strict slug dispatch (mirrors
//!   [`crate::index_trust::enforce_index_trust`]).
//!
//! # Type reuse decision
//!
//! Rather than adding entry-only variants onto the shared
//! [`crate::index_trust::VerificationResult`] enum, this module defines its OWN
//! [`EntryVerificationResult`] with the same PATTERN (sealed enum + `to_slug`
//! map + `enforce_*` dispatch + keyed mock verifier) but a domain proper to
//! entries: entries need subject-NAME binding (§1) that whole-index
//! verification has no concept of, and freshness is structurally inapplicable
//! (§6). A parallel type with the identical shape gives the "extends from Part
//! 1" reuse at the PATTERN level without polluting Part 1's sealed domain.
//!
//! # Extract-or-decline decision (RFC §6)
//!
//! [`SigstoreEntryVerifier`] implements the pre-crypto pipeline stages (bundle
//! JSON parse, DSSE-envelope-payload subject-digest + subject-name binding —
//! RFC §1 NORMATIVE: BOTH coordinates checked BEFORE any cryptographic
//! verification) exactly, duplicating the parse/DSSE shape from
//! `index_trust.rs`'s `verify_crypto` rather than extracting a shared helper —
//! same rationale as the Python module's own decline-to-extract.
//!
//! The cryptographic stages (5-7: cert chain + DSSE signature + Rekor
//! inclusion) are NOT wired to real `sigstore-rs` verification in this slice.
//! Structural reason: `sigstore-rs`'s only public verify entry points
//! (`Verifier::verify_digest` / `verify`) require the caller to supply a live
//! `Sha256` hasher over the REAL preimage bytes of the attested artifact — the
//! crate recomputes the digest internally and compares it to the DSSE
//! subject claim. For the index-attestation path (`index_trust.rs`) milpa has
//! those preimage bytes (the fetched `index.kdl` text). For a PER-ENTRY
//! attestation, the "artifact" is the dep's already-resolved `content_hash` —
//! milpa does not have (and should not need) the raw source tree just to
//! verify a signature over a digest it already trusts structurally (the
//! pre-crypto stage above already asserts the DSSE payload's claimed digest
//! equals the expected subject). The crate has no public "verify this DSSE
//! envelope against an already-known digest" entry point (only the
//! crate-private `verify_bundle_content` takes raw digest bytes directly).
//! Exposing/patching that seam (the same class of upstream gap the vendored
//! `.vendor-sigstore` patch already fixes for the index path's `envelopeHash`
//! check) is P3b work, gated on real per-entry bundles existing to validate
//! against (tianguis delivery, P4). Until then [`SigstoreEntryVerifier`]
//! deterministically returns [`EntryVerificationResult::SignatureInvalid`]
//! after a bundle passes the pre-crypto stages — never silently reports
//! [`EntryVerificationResult::Trusted`] for a bundle it cannot actually verify
//! cryptographically (fail-closed). This path is not exercised by the shared
//! conformance corpus (every fixture drives [`MockEntryVerifier`]) and is
//! unit-tested here only for the pre-crypto malformed/mismatch cases, mirroring
//! the Python module's own P3a test scope.
//!
//! RFC: `docs/rfc-per-entry-attestation.md` §1, §5, §6, §7.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};

use base64::Engine;
use milpa_manifest::TrustPolicy;
use milpa_types::{AttestationKind, EntryAttestation};

use crate::entry_bundle_store::EntryBundleStore;
use crate::error::CoreError;
use crate::index_trust::TrustBundle;
use crate::MilpaError;

// ---------------------------------------------------------------------------
// EntryVerificationResult — 8-variant sealed enum (RFC §5 table)
// ---------------------------------------------------------------------------

/// 8-variant result type for per-entry Sigstore bundle verification.
///
/// RFC §5 maps each non-[`Trusted`] variant to a `TNG-ENTRY-*` slug. Stage 1b
/// (`TNG-ENTRY-BUNDLE-PIN-MISMATCH`) has no variant here — see the module
/// docstring and [`evaluate_entry_attestation`]: it is a security invariant
/// raised unconditionally by [`crate::entry_bundle_store`], never returned as
/// a policy-gateable result.
///
/// [`Trusted`]: EntryVerificationResult::Trusted
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryVerificationResult {
    Trusted,
    Unattested,
    BundleMissing,
    BundleMalformed,
    DigestMismatch,
    SubjectMismatch,
    SignatureInvalid,
    SignerMismatch,
}

impl EntryVerificationResult {
    /// Map a non-`Trusted` result to its `TNG-ENTRY-*` slug (SSOT).
    ///
    /// # Panics
    /// Panics on `Trusted` — callers must guard (no slug by design).
    pub fn to_slug(&self) -> &'static str {
        match self {
            Self::Unattested => "TNG-ENTRY-UNATTESTED",
            Self::BundleMissing => "TNG-ENTRY-BUNDLE-MISSING",
            Self::BundleMalformed => "TNG-ENTRY-BUNDLE-MALFORMED",
            Self::DigestMismatch => "TNG-ENTRY-DIGEST-MISMATCH",
            Self::SubjectMismatch => "TNG-ENTRY-SUBJECT-MISMATCH",
            Self::SignatureInvalid => "TNG-ENTRY-SIGNATURE-INVALID",
            Self::SignerMismatch => "TNG-ENTRY-SIGNER-MISMATCH",
            Self::Trusted => panic!("EntryVerificationResult::Trusted has no TNG-ENTRY-* slug"),
        }
    }

}

// ---------------------------------------------------------------------------
// VerifierOutcome — the 6-variant VERIFIER-domain result (CR18)
// ---------------------------------------------------------------------------

/// The 6-variant result a real verifier ([`EntryBundleVerifier::verify`]) can
/// ever produce — a proper SUBSET of [`EntryVerificationResult`]'s 8 gate-level
/// variants, missing `Unattested` and `BundleMissing` (gate-level states the
/// gate decides BEFORE ever calling the verifier; see
/// [`evaluate_entry_attestation`]).
///
/// CR18: this used to be fenced by a doc comment on
/// `EntryVerificationResult::from_verifier_value` alone ("never `Unattested`
/// or `BundleMissing`") — true by convention, not by the type system. Giving
/// the verifier domain its OWN type makes a verifier returning a gate-only
/// state UNREPRESENTABLE: [`EntryBundleVerifier::verify`],
/// [`SigstoreEntryVerifier`], and [`MockEntryVerifier`] all return
/// `VerifierOutcome` natively; [`From<VerifierOutcome> for EntryVerificationResult`]
/// is the one widening step, applied once at the gate boundary
/// ([`evaluate_entry_attestation`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierOutcome {
    Trusted,
    BundleMalformed,
    DigestMismatch,
    SubjectMismatch,
    SignatureInvalid,
    SignerMismatch,
}

impl VerifierOutcome {
    /// Parse from the wire-format string used by the conformance mock-VERIFIER
    /// seam (`MILPA_ENTRY_TRUST_MOCK_MAP` / `MILPA_ENTRY_TRUST_MOCK_DEFAULT`).
    ///
    /// Total over this type's 6-value domain — the same set
    /// [`EntryBundleVerifier::verify`] is documented to return. `Unattested`
    /// and `BundleMissing` are not representable here at all (not merely
    /// "not accepted by this parser") — they are gate-level states that
    /// `evaluate_entry_attestation` decides BEFORE ever calling the verifier.
    pub fn from_wire_value(s: &str) -> Option<Self> {
        match s {
            "trusted" => Some(Self::Trusted),
            "bundle-malformed" => Some(Self::BundleMalformed),
            "digest-mismatch" => Some(Self::DigestMismatch),
            "subject-mismatch" => Some(Self::SubjectMismatch),
            "signature-invalid" => Some(Self::SignatureInvalid),
            "signer-mismatch" => Some(Self::SignerMismatch),
            _ => None,
        }
    }
}

impl From<VerifierOutcome> for EntryVerificationResult {
    fn from(v: VerifierOutcome) -> Self {
        match v {
            VerifierOutcome::Trusted => Self::Trusted,
            VerifierOutcome::BundleMalformed => Self::BundleMalformed,
            VerifierOutcome::DigestMismatch => Self::DigestMismatch,
            VerifierOutcome::SubjectMismatch => Self::SubjectMismatch,
            VerifierOutcome::SignatureInvalid => Self::SignatureInvalid,
            VerifierOutcome::SignerMismatch => Self::SignerMismatch,
        }
    }
}

// ---------------------------------------------------------------------------
// EntrySubject — the two-coordinate subject binding (RFC §1)
// ---------------------------------------------------------------------------

/// `{name, sha256}` subject binding for one selected registry entry.
///
/// `name` — `pkg:tianguis/<namespace>/<name>@<version>` (RFC §1).
/// `sha256` — hex digest of `content_hash` (NO `sha256:`/`dag-sha256:` prefix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySubject {
    pub name: String,
    pub sha256: String,
}

/// Build the [`EntrySubject`] for one selected entry (RFC §1 coordinate format).
///
/// `content_hash` is milpa's canonical identity string, `dag-sha256:<64-hex>`
/// (identity.md §2.1) — extraction uses
/// [`crate::identity::split_identity_scheme`], the same scheme-agnostic split
/// `parse_identity` itself uses (never a hardcoded `sha256:` prefix strip,
/// which would silently no-op on the real `dag-sha256:` form and leak the
/// algorithm prefix into the subject digest). Unlike `parse_identity`, this
/// does NOT enforce `SUPPORTED_ALGORITHMS` — building a subject coordinate
/// doesn't need that coupling — but a `content_hash` with no `':'` separator
/// at all is a genuinely malformed input and must raise `ID-NO-ALGORITHM-
/// PREFIX`, not silently produce an empty (or whole-string) digest.
pub fn build_entry_subject(
    namespace: &str,
    name: &str,
    version: &str,
    content_hash: &str,
) -> Result<EntrySubject, CoreError> {
    let (_, hex_digest) = crate::identity::split_identity_scheme(content_hash)?;
    Ok(EntrySubject {
        name: format!("pkg:tianguis/{namespace}/{name}@{version}"),
        sha256: hex_digest.to_string(),
    })
}

// ---------------------------------------------------------------------------
// EntryBundleVerifier — trait (RFC §6)
// ---------------------------------------------------------------------------

/// Injected verifier seam for per-entry attestation (RFC §6).
///
/// Deliberately narrower than [`crate::index_trust::IndexBundleVerifier`]: no
/// freshness parameter (a per-entry bundle binds an immutable subject — RFC
/// §6), and the caller supplies the expected *subject* (name + digest) rather
/// than raw bytes to hash. Expected-signer derivation (pinned `signed_by` vs
/// the resolved vendor-bot identity) stays in the gate
/// ([`evaluate_entry_attestation`]), not the verifier — so the verifier stays
/// kind-agnostic.
pub trait EntryBundleVerifier: Send + Sync {
    /// Verify the Sigstore bundle against `subject`.
    ///
    /// Returns a [`VerifierOutcome`] — CR18: the verifier-domain type makes
    /// `Unattested`/`BundleMissing` (gate-level states the caller never asks
    /// the verifier about) UNREPRESENTABLE here, not merely undocumented.
    fn verify(
        &self,
        subject: &EntrySubject,
        bundle_bytes: &[u8],
        trust_bundle: &TrustBundle,
        expected_signer: &str,
    ) -> VerifierOutcome;
}

// ---------------------------------------------------------------------------
// SigstoreEntryVerifier — production EntryBundleVerifier (RFC §6)
// ---------------------------------------------------------------------------

/// Production verifier. See the module docstring's "Extract-or-decline
/// decision" for why cryptographic verification (stages 5-7) is P3b-gated.
pub struct SigstoreEntryVerifier;

impl EntryBundleVerifier for SigstoreEntryVerifier {
    fn verify(
        &self,
        subject: &EntrySubject,
        bundle_bytes: &[u8],
        _trust_bundle: &TrustBundle,
        _expected_signer: &str,
    ) -> VerifierOutcome {
        // Stage 2: parse bundle JSON.
        let bundle_json: serde_json::Value = match serde_json::from_slice(bundle_bytes) {
            Ok(v @ serde_json::Value::Object(_)) => v,
            _ => return VerifierOutcome::BundleMalformed,
        };

        // Pre-crypto subject checks (stages 3 + 4 — RFC §1 NORMATIVE: BOTH
        // coordinates checked BEFORE any cryptographic verification). Reads
        // the UNVERIFIED DSSE payload — sound because we only ask "does this
        // bundle even claim our subject?" (mirrors index_trust.rs's
        // pre-check rationale, §3.4.4 precedent).
        let Some(payload_b64) = bundle_json["dsseEnvelope"]["payload"].as_str() else {
            return VerifierOutcome::BundleMalformed;
        };
        let Ok(payload_bytes) = base64::engine::general_purpose::STANDARD.decode(payload_b64) else {
            return VerifierOutcome::BundleMalformed;
        };
        let Ok(payload_json) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) else {
            return VerifierOutcome::BundleMalformed;
        };
        let Some(subjects) = payload_json["subject"].as_array() else {
            return VerifierOutcome::DigestMismatch;
        };
        let Some(first) = subjects.first() else {
            return VerifierOutcome::DigestMismatch;
        };
        let Some(claimed_sha256) = first["digest"]["sha256"].as_str() else {
            return VerifierOutcome::DigestMismatch;
        };
        if claimed_sha256 != subject.sha256 {
            return VerifierOutcome::DigestMismatch;
        }
        let Some(claimed_name) = first["name"].as_str() else {
            return VerifierOutcome::SubjectMismatch;
        };
        if claimed_name != subject.name {
            return VerifierOutcome::SubjectMismatch;
        }

        // Stages 5-7 (cert chain + DSSE signature + Rekor inclusion): P3b-gated
        // — see the module docstring's "Extract-or-decline decision". A
        // structurally valid bundle that reaches here has passed every
        // pre-crypto check but has NOT been cryptographically verified;
        // fail-closed rather than report Trusted.
        VerifierOutcome::SignatureInvalid
    }
}

// ---------------------------------------------------------------------------
// MockEntryVerifier — keyed per-subject outcome scripting (RFC Conformance)
// ---------------------------------------------------------------------------

/// Test [`EntryBundleVerifier`]: keyed per-subject outcome scripting.
///
/// RFC Conformance section, seam extension (i): "the mock's outcome becomes a
/// keyed per-subject map... a mixed resolve needs different verdicts per
/// entry". `by_subject` maps the subject `name` string (the
/// `pkg:tianguis/...` coordinate) to a result; entries not in the map get
/// `default`.
pub struct MockEntryVerifier {
    default: VerifierOutcome,
    by_subject: HashMap<String, VerifierOutcome>,
}

impl MockEntryVerifier {
    pub fn new(default: VerifierOutcome, by_subject: HashMap<String, VerifierOutcome>) -> Self {
        Self { default, by_subject }
    }
}

impl EntryBundleVerifier for MockEntryVerifier {
    fn verify(
        &self,
        subject: &EntrySubject,
        _bundle_bytes: &[u8],
        _trust_bundle: &TrustBundle,
        _expected_signer: &str,
    ) -> VerifierOutcome {
        self.by_subject.get(&subject.name).copied().unwrap_or(self.default)
    }
}

// ---------------------------------------------------------------------------
// EntryTrustConfig — config bundle threaded through the resolver (RFC §4)
// ---------------------------------------------------------------------------

/// Config bundle for the entry-trust gate — threaded through `resolve_*`
/// (RFC §3: the gate fires at the selection step, INSIDE the resolver, unlike
/// index-trust which gates at index load, before the resolver runs).
///
/// `verifier` and `bundle_store` are explicit fields here (unlike
/// [`crate::index_trust::IndexTrustConfig`], which keeps the verifier as a
/// separate parameter) — the entry-trust gate has no single call site
/// analogous to `load_index`, so bundling everything the gate needs into one
/// threadable object is the seam that avoids parameter explosion across
/// `resolve_with_features` / `resolve_workspace_with_features` / `build_graph`.
pub struct EntryTrustConfig {
    pub policy: TrustPolicy,
    pub trust_bundle: TrustBundle,
    pub expected_vendor_signer: String,
    pub verifier: Box<dyn EntryBundleVerifier>,
    /// `None` disables bundle acquisition entirely (every attested entry with
    /// a `bundle` pin resolves as `BundleMissing`/unfetchable).
    pub bundle_store: Option<Box<dyn EntryBundleStore>>,
}

// ---------------------------------------------------------------------------
// evaluate_entry_attestation — the gate pipeline (RFC §5 stages 0-7)
// ---------------------------------------------------------------------------

/// Run gate stages 0-7 for one selected registry-resolved dep.
///
/// Returns `Ok((result, cause))`. `cause` is populated only for
/// `BundleMissing` (`"no-pin"` when the entry is attested but carries no
/// `bundle` pin yet; `"unfetchable"` when a pin is present but the bundle
/// could not be fetched).
///
/// Stage 1b (`TNG-ENTRY-BUNDLE-PIN-MISMATCH`) is NOT captured in the `Ok`
/// return — the bundle store raises it unconditionally (SECURITY INVARIANT,
/// RFC §5); it propagates as `Err(_)` straight out of this function,
/// bypassing warn/strict policy entirely (mirrors `TNG-DEPDECL-HASH-MISMATCH`'s
/// severity model).
#[allow(clippy::too_many_arguments)]
pub fn evaluate_entry_attestation(
    attestation: Option<&EntryAttestation>,
    content_hash: &str,
    namespace: &str,
    name: &str,
    version: &str,
    verifier: &dyn EntryBundleVerifier,
    bundle_store: Option<&dyn EntryBundleStore>,
    trust_bundle: &TrustBundle,
    expected_vendor_signer: &str,
) -> Result<(EntryVerificationResult, Option<String>), MilpaError> {
    // Stage 0: attestation record absent (or collapsed to unattested at parse time).
    let Some(att) = attestation else {
        return Ok((EntryVerificationResult::Unattested, None));
    };

    // Stage 1: bundle acquisition.
    let Some(pin) = att.bundle_pin.as_deref() else {
        return Ok((EntryVerificationResult::BundleMissing, Some("no-pin".to_string())));
    };
    let Some(store) = bundle_store else {
        return Ok((EntryVerificationResult::BundleMissing, Some("unfetchable".to_string())));
    };
    let bundle_bytes = match store.get(pin) {
        Ok(b) => b,
        Err(e) => {
            if e.code() == "TNG-ENTRY-BUNDLE-PIN-MISMATCH" {
                return Err(e); // stage 1b: unconditional hard error, never policy-gated
            }
            return Ok((EntryVerificationResult::BundleMissing, Some("unfetchable".to_string())));
        }
    };

    // Stages 2-7: bundle parse + subject binding + crypto, delegated to the verifier.
    let subject = build_entry_subject(namespace, name, version, content_hash)?;
    let expected_signer = match &att.kind {
        AttestationKind::AuthorSigned { signer } => signer.as_str(),
        AttestationKind::MilpaVendored => expected_vendor_signer,
    };
    // CR18: verifier.verify returns the narrower VerifierOutcome; widen to the
    // gate-level EntryVerificationResult here, at the one gate boundary.
    let result: EntryVerificationResult = verifier.verify(&subject, &bundle_bytes, trust_bundle, expected_signer).into();
    Ok((result, None))
}

// ---------------------------------------------------------------------------
// enforce_entry_trust — warn/strict slug dispatch (mirrors enforce_index_trust)
// ---------------------------------------------------------------------------

/// Per-invocation warn dedup set: at most one entry-trust warning per unique
/// `(namespace, name, version)` per invocation (mirrors index-trust's
/// per-URL dedup, RFC §5).
thread_local! {
    static WARNED_ENTRIES: RefCell<BTreeSet<(String, String, String)>> = RefCell::new(BTreeSet::new());
}

/// Clear the per-invocation warn dedup set. **TEST USE ONLY.**
#[cfg(test)]
pub fn _reset_warned_entries() {
    WARNED_ENTRIES.with(|w| w.borrow_mut().clear());
}

fn hint_for(result: EntryVerificationResult) -> &'static str {
    match result {
        EntryVerificationResult::Unattested => {
            "no attestation record for this entry. Set 'entry-trust \"off\"' in \
             milpa.kdl to suppress, or wait for the author/vendor-bot to publish \
             an attested entry."
        }
        EntryVerificationResult::BundleMissing => {
            "the entry is attested but its Sigstore bundle is unavailable. \
             Run 'milpa fetch --refresh-index' to retry, or set 'entry-trust \
             \"off\"' in milpa.kdl to suppress."
        }
        EntryVerificationResult::BundleMalformed => {
            "the per-entry Sigstore bundle is not valid JSON or missing required fields."
        }
        EntryVerificationResult::DigestMismatch => {
            "the bundle's attested subject digest does not match this entry's \
             content_hash (tampering or mismatched bundle/entry pair)."
        }
        EntryVerificationResult::SubjectMismatch => {
            "the bundle's attested subject package identity does not match this \
             entry's coordinate (possible cross-package replay)."
        }
        EntryVerificationResult::SignatureInvalid => {
            "cryptographic verification of the per-entry Sigstore bundle failed."
        }
        EntryVerificationResult::SignerMismatch => {
            "the bundle signer identity does not match the expected signer for \
             this entry's attestation kind."
        }
        EntryVerificationResult::Trusted => unreachable!("handled by caller"),
    }
}

/// warn/strict slug dispatch for one selected entry's gate outcome.
///
/// - `Off`      → silent; the caller should not even invoke the gate, but
///                this guard makes the function total regardless.
/// - `Trusted`  → silent.
/// - `Warn`     → emit ONE warning to stderr per unique `(namespace, name,
///                version)` per invocation; return `Ok(())`.
/// - `Strict`   → return `Err(MilpaError)` with the appropriate `TNG-ENTRY-*` slug.
pub fn enforce_entry_trust(
    result: EntryVerificationResult,
    policy: &TrustPolicy,
    namespace: &str,
    name: &str,
    version: &str,
    cause: Option<&str>,
) -> Result<(), MilpaError> {
    if *policy == TrustPolicy::Off || result == EntryVerificationResult::Trusted {
        return Ok(());
    }

    let slug = result.to_slug();
    let coordinate = format!("pkg:tianguis/{namespace}/{name}@{version}");
    let mut hint = hint_for(result).to_string();
    if let Some(c) = cause {
        hint = format!("{hint} (cause: {c})");
    }

    if *policy == TrustPolicy::Strict {
        return Err(MilpaError::Core(CoreError::Tianguis(
            slug,
            format!("entry-trust strict: {slug} for {coordinate:?} — {hint}"),
        )));
    }

    let key = (namespace.to_string(), name.to_string(), version.to_string());
    let already_warned = WARNED_ENTRIES.with(|w| w.borrow().contains(&key));
    if !already_warned {
        WARNED_ENTRIES.with(|w| w.borrow_mut().insert(key));
        eprintln!("milpa: entry-trust warning ({slug}): {hint} (entry: {coordinate:?})");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_slug_matches_spec_catalog() {
        assert_eq!(EntryVerificationResult::Unattested.to_slug(), "TNG-ENTRY-UNATTESTED");
        assert_eq!(EntryVerificationResult::BundleMissing.to_slug(), "TNG-ENTRY-BUNDLE-MISSING");
        assert_eq!(EntryVerificationResult::BundleMalformed.to_slug(), "TNG-ENTRY-BUNDLE-MALFORMED");
        assert_eq!(EntryVerificationResult::DigestMismatch.to_slug(), "TNG-ENTRY-DIGEST-MISMATCH");
        assert_eq!(EntryVerificationResult::SubjectMismatch.to_slug(), "TNG-ENTRY-SUBJECT-MISMATCH");
        assert_eq!(EntryVerificationResult::SignatureInvalid.to_slug(), "TNG-ENTRY-SIGNATURE-INVALID");
        assert_eq!(EntryVerificationResult::SignerMismatch.to_slug(), "TNG-ENTRY-SIGNER-MISMATCH");
    }

    #[test]
    #[should_panic(expected = "no TNG-ENTRY-* slug")]
    fn to_slug_panics_on_trusted() {
        let _ = EntryVerificationResult::Trusted.to_slug();
    }

    #[test]
    fn build_entry_subject_strips_scheme_agnostically() {
        let s = build_entry_subject("ns1", "bar", "2.0.0", "dag-sha256:abcd").unwrap();
        assert_eq!(s.name, "pkg:tianguis/ns1/bar@2.0.0");
        assert_eq!(s.sha256, "abcd");
    }

    #[test]
    fn build_entry_subject_rejects_missing_scheme_separator() {
        // CR12/2: no ':' at all must raise ID-NO-ALGORITHM-PREFIX, not
        // silently produce an empty or whole-string digest.
        let err = build_entry_subject("ns1", "bar", "2.0.0", "not-a-valid-identity").unwrap_err();
        assert_eq!(err.code(), "ID-NO-ALGORITHM-PREFIX");
    }

    #[test]
    fn sigstore_entry_verifier_malformed_json_is_bundle_malformed() {
        let subject = EntrySubject { name: "pkg:tianguis/ns1/bar@2.0.0".into(), sha256: "abcd".into() };
        let result = SigstoreEntryVerifier.verify(&subject, b"not json", &TrustBundle::test(), "signer");
        assert_eq!(result, VerifierOutcome::BundleMalformed);
    }

    #[test]
    fn sigstore_entry_verifier_missing_dsse_is_bundle_malformed() {
        let subject = EntrySubject { name: "pkg:tianguis/ns1/bar@2.0.0".into(), sha256: "abcd".into() };
        let result = SigstoreEntryVerifier.verify(&subject, b"{}", &TrustBundle::test(), "signer");
        assert_eq!(result, VerifierOutcome::BundleMalformed);
    }

    fn make_dsse_bundle(subject_sha256: &str, subject_name: &str) -> Vec<u8> {
        let statement = serde_json::json!({
            "subject": [{"digest": {"sha256": subject_sha256}, "name": subject_name}],
        });
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(statement.to_string());
        let bundle = serde_json::json!({
            "dsseEnvelope": {"payload": payload_b64, "signatures": []},
        });
        serde_json::to_vec(&bundle).unwrap()
    }

    #[test]
    fn sigstore_entry_verifier_digest_mismatch_precedes_subject_check() {
        let subject = EntrySubject { name: "pkg:tianguis/ns1/bar@2.0.0".into(), sha256: "expected".into() };
        let bundle = make_dsse_bundle("wrong", "pkg:tianguis/ns1/bar@2.0.0");
        let result = SigstoreEntryVerifier.verify(&subject, &bundle, &TrustBundle::test(), "signer");
        assert_eq!(result, VerifierOutcome::DigestMismatch);
    }

    #[test]
    fn sigstore_entry_verifier_subject_mismatch() {
        let subject = EntrySubject { name: "pkg:tianguis/ns1/bar@2.0.0".into(), sha256: "abcd".into() };
        let bundle = make_dsse_bundle("abcd", "pkg:tianguis/ns1/OTHER@2.0.0");
        let result = SigstoreEntryVerifier.verify(&subject, &bundle, &TrustBundle::test(), "signer");
        assert_eq!(result, VerifierOutcome::SubjectMismatch);
    }

    #[test]
    fn sigstore_entry_verifier_matching_subject_fails_closed_not_trusted() {
        // A bundle that passes every pre-crypto check but was never
        // cryptographically verified must NEVER report Trusted (P3b-gated).
        let subject = EntrySubject { name: "pkg:tianguis/ns1/bar@2.0.0".into(), sha256: "abcd".into() };
        let bundle = make_dsse_bundle("abcd", "pkg:tianguis/ns1/bar@2.0.0");
        let result = SigstoreEntryVerifier.verify(&subject, &bundle, &TrustBundle::test(), "signer");
        assert_eq!(result, VerifierOutcome::SignatureInvalid);
    }

    #[test]
    fn mock_verifier_keyed_by_subject() {
        let mut by_subject = HashMap::new();
        by_subject.insert("pkg:tianguis/ns1/bar@2.0.0".to_string(), VerifierOutcome::SignerMismatch);
        let mock = MockEntryVerifier::new(VerifierOutcome::Trusted, by_subject);

        let matched = EntrySubject { name: "pkg:tianguis/ns1/bar@2.0.0".into(), sha256: "x".into() };
        let unmatched = EntrySubject { name: "pkg:tianguis/ns1/other@1.0.0".into(), sha256: "x".into() };
        assert_eq!(
            mock.verify(&matched, b"", &TrustBundle::test(), "s"),
            VerifierOutcome::SignerMismatch
        );
        assert_eq!(
            mock.verify(&unmatched, b"", &TrustBundle::test(), "s"),
            VerifierOutcome::Trusted
        );
    }

    /// CR18: gate-only states are UNREPRESENTABLE in the verifier domain, not
    /// merely undocumented. `VerifierOutcome::from_wire_value` has no arm for
    /// "unattested"/"bundle-missing" (they aren't variants of the type at
    /// all), so a fixture/CLI author cannot script a mock verifier to
    /// produce a gate-only state even by typo'ing a wire string — the type
    /// system rejects it, where the old `EntryVerificationResult::
    /// from_verifier_value` only rejected it by convention (a doc comment).
    #[test]
    fn verifier_outcome_cannot_parse_gate_only_states() {
        assert_eq!(VerifierOutcome::from_wire_value("unattested"), None);
        assert_eq!(VerifierOutcome::from_wire_value("bundle-missing"), None);
    }

    /// CR18: `EntryBundleVerifier::verify` — the trait every verifier
    /// (mock and production) implements — returns `VerifierOutcome` natively;
    /// this compiles only because the trait signature itself is typed to the
    /// 6-variant domain, which is the type-level enforcement CR18 asks for.
    #[test]
    fn mock_verifier_return_type_is_verifier_outcome() {
        let subject = EntrySubject { name: "pkg:tianguis/ns1/bar@2.0.0".into(), sha256: "x".into() };
        let mock = MockEntryVerifier::new(VerifierOutcome::Trusted, HashMap::new());
        let outcome: VerifierOutcome = mock.verify(&subject, b"", &TrustBundle::test(), "s");
        assert_eq!(outcome, VerifierOutcome::Trusted);
    }

    #[test]
    fn evaluate_stage0_unattested() {
        let (result, cause) = evaluate_entry_attestation(
            None, "dag-sha256:abcd", "ns1", "bar", "2.0.0",
            &MockEntryVerifier::new(VerifierOutcome::Trusted, HashMap::new()),
            None, &TrustBundle::test(), "vendor-signer",
        ).unwrap();
        assert_eq!(result, EntryVerificationResult::Unattested);
        assert_eq!(cause, None);
    }

    #[test]
    fn evaluate_stage1_bundle_missing_no_pin() {
        let att = EntryAttestation { kind: AttestationKind::MilpaVendored, rekor: None, bundle_pin: None };
        let (result, cause) = evaluate_entry_attestation(
            Some(&att), "dag-sha256:abcd", "ns1", "bar", "2.0.0",
            &MockEntryVerifier::new(VerifierOutcome::Trusted, HashMap::new()),
            None, &TrustBundle::test(), "vendor-signer",
        ).unwrap();
        assert_eq!(result, EntryVerificationResult::BundleMissing);
        assert_eq!(cause.as_deref(), Some("no-pin"));
    }

    #[test]
    fn evaluate_stage1_bundle_missing_unfetchable_when_pin_present_no_store() {
        let att = EntryAttestation {
            kind: AttestationKind::MilpaVendored,
            rekor: None,
            bundle_pin: Some("a".repeat(64)),
        };
        let (result, cause) = evaluate_entry_attestation(
            Some(&att), "dag-sha256:abcd", "ns1", "bar", "2.0.0",
            &MockEntryVerifier::new(VerifierOutcome::Trusted, HashMap::new()),
            None, &TrustBundle::test(), "vendor-signer",
        ).unwrap();
        assert_eq!(result, EntryVerificationResult::BundleMissing);
        assert_eq!(cause.as_deref(), Some("unfetchable"));
    }

    #[test]
    fn evaluate_pin_mismatch_propagates_unconditionally() {
        use crate::entry_bundle_store::FileEntryBundleStore;
        let tmp = tempfile::tempdir().unwrap();
        // No file written: FileEntryBundleStore.get raises TNG-ENTRY-BUNDLE-MISSING
        // (unfetchable), not pin-mismatch, when the file is simply absent — write
        // a WRONG-content file under the pin's name to trigger a real mismatch.
        let pin = "a".repeat(64);
        std::fs::write(tmp.path().join(format!("{pin}.bundle")), b"wrong bytes").unwrap();
        let store = FileEntryBundleStore::new(tmp.path());
        let att = EntryAttestation {
            kind: AttestationKind::MilpaVendored,
            rekor: None,
            bundle_pin: Some(pin),
        };
        let err = evaluate_entry_attestation(
            Some(&att), "dag-sha256:abcd", "ns1", "bar", "2.0.0",
            &MockEntryVerifier::new(VerifierOutcome::Trusted, HashMap::new()),
            Some(&store), &TrustBundle::test(), "vendor-signer",
        ).unwrap_err();
        assert_eq!(err.code(), "TNG-ENTRY-BUNDLE-PIN-MISMATCH");
    }

    #[test]
    fn enforce_off_is_silent() {
        enforce_entry_trust(
            EntryVerificationResult::Unattested, &TrustPolicy::Off, "ns1", "bar", "2.0.0", None,
        ).expect("off must never raise");
    }

    #[test]
    fn enforce_trusted_is_silent_even_under_strict() {
        enforce_entry_trust(
            EntryVerificationResult::Trusted, &TrustPolicy::Strict, "ns1", "bar", "2.0.0", None,
        ).expect("trusted must never raise");
    }

    #[test]
    fn enforce_strict_raises_slug() {
        let err = enforce_entry_trust(
            EntryVerificationResult::SignerMismatch, &TrustPolicy::Strict, "ns1", "bar", "2.0.0", None,
        ).unwrap_err();
        assert_eq!(err.code(), "TNG-ENTRY-SIGNER-MISMATCH");
    }

    #[test]
    fn enforce_warn_never_raises() {
        _reset_warned_entries();
        enforce_entry_trust(
            EntryVerificationResult::Unattested, &TrustPolicy::Warn, "ns1", "warntest", "2.0.0", None,
        ).expect("warn must not raise");
    }
}
