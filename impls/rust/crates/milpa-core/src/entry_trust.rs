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

use crate::entry_bundle_store::{BundleStoreBackend, EntryBundleStore};
use crate::epoch_commitment::{EpochCommitmentStatus, PreEpochIdentity};
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
// EpochMembership — S-EpochGate (RFC §6, D14/D17; spec §3.6.3 NORMATIVE)
// ---------------------------------------------------------------------------

/// `PreEpoch | PostEpoch` — spec §3.6.3 NORMATIVE (`EpochMembership`).
///
/// Populated (`Some`) only when the index's [`EpochCommitmentStatus`] is
/// `Armed(S, E)`; `Unarmed` maps to `None` (no third variant — see
/// [`classify_epoch_membership`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochMembership {
    PreEpoch,
    PostEpoch,
}

/// S-EpochGate membership classification (RFC §6 D14/D17; spec §3.4.8
/// NORMATIVE "membership is a local set lookup" + §3.6.3 NORMATIVE
/// `EpochMembership`).
///
/// `Armed(S, E)` + `identity in S` -> `PreEpoch` (a plain local
/// set-containment test against the already-verified `S` — no
/// recomputation, no proof machinery, D17). `Armed(S, E)` + `identity not in
/// S` -> `PostEpoch`. `Unarmed` -> `None`: "no commitment is armed" is a
/// fact about the INDEX, already fully captured by `EpochCommitmentStatus`
/// itself, not a per-entry classification (D14) — every entry from that
/// registry is then warn-equivalent under the SAME D1/D11 rule §3.4.8
/// states normatively for the whole registry (see [`effective_epoch_policy`]).
///
/// `ArmingInvalid` never reaches this function in production — spec §3.6.4
/// NORMATIVE cross-axis precedence: an `ArmingInvalid` aborts the WHOLE
/// resolve (`TNG-INDEX-EPOCH-COMMITMENT-INVALID`) before any candidate is
/// selected, so the entry gate never runs on that resolve at all.
/// Defensively treated identically to `Unarmed` (`None`) here anyway,
/// rather than panicking, so this function stays total and pure.
pub fn classify_epoch_membership(
    status: &EpochCommitmentStatus,
    identity: &PreEpochIdentity,
) -> Option<EpochMembership> {
    match status {
        EpochCommitmentStatus::Armed { identities, .. } => {
            if identities.contains(identity) {
                Some(EpochMembership::PreEpoch)
            } else {
                Some(EpochMembership::PostEpoch)
            }
        }
        EpochCommitmentStatus::Unarmed | EpochCommitmentStatus::ArmingInvalid { .. } => None,
    }
}

/// S-EpochGate policy downgrade (RFC §6; spec §3.6.3 NORMATIVE).
///
/// `PostEpoch` -> the configured policy, UNCHANGED (the mandate applies:
/// under `Strict` an unattested/unverifiable post-epoch entry hard-fails).
///
/// `PreEpoch` or `None` (`Unarmed`) -> capped at `Warn`: `Strict` downgrades
/// to `Warn`, `Warn` stays `Warn`, `Off` stays `Off`. "`PreEpoch` stays
/// warn-territory even under entry-trust 'strict'" (a fixed, shrinking
/// grandfathered population) and "`Unarmed` ... is warn-equivalent for
/// every candidate from that registry" (spec §3.6.3 NORMATIVE
/// `EpochMembership`).
///
/// SECURITY RATIONALE (why this downgrade cannot be exploited): membership
/// is decided over the frozen, composed-verified set `S`, keyed on the full
/// `(namespace, name, version, content_hash)` identity tuple —
/// `content_hash` included. Tampering with a grandfathered entry's bytes
/// changes its `content_hash`, so the tampered identity no longer matches
/// any member of `S` and reclassifies as `PostEpoch` on the next resolve,
/// where the mandate applies in full. A pre-epoch entry can only ever be
/// the SAME bytes the registry committed to at arming time.
pub fn effective_epoch_policy(policy: &TrustPolicy, membership: Option<EpochMembership>) -> TrustPolicy {
    if membership == Some(EpochMembership::PostEpoch) {
        return policy.clone();
    }
    if *policy == TrustPolicy::Off {
        TrustPolicy::Off
    } else {
        TrustPolicy::Warn
    }
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
// EntryGateOutcome — the D9 composed gate diagnostic (spec §3.6.3 NORMATIVE)
// ---------------------------------------------------------------------------

/// The gate's SOLE return shape (D9, spec §3.6.3 NORMATIVE
/// `EntryGateOutcome`) — one composed diagnostic, not independently threaded
/// `(result, cause)` fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryGateOutcome {
    /// `Trusted` or one of the seven `TNG-ENTRY-*` failure variants.
    pub result: EntryVerificationResult,
    /// See [`classify_epoch_membership`].
    pub epoch_membership: Option<EpochMembership>,
    /// Populated only when `result` is `BundleMissing`
    /// (`"no-pin"` | `"unfetchable"`).
    pub cause: Option<String>,
}

// ---------------------------------------------------------------------------
// evaluate_entry_attestation — the gate pipeline (RFC §5 stages 0-7)
// ---------------------------------------------------------------------------

/// Run gate stages 0-7 for one selected registry-resolved dep.
///
/// Returns an [`EntryGateOutcome`] (D9) — `cause` is populated only for
/// `BundleMissing` (`"no-pin"` when the entry is attested but carries no
/// `bundle` pin yet; `"unfetchable"` when a pin is present but the bundle
/// could not be fetched).
///
/// `epoch_status` (S-EpochGate, RFC §6 D14/D17): the once-per-resolve
/// [`EpochCommitmentStatus`] this candidate's registry produced
/// (`Index.epoch_commitment_status`) — classified into
/// `EntryGateOutcome.epoch_membership` via [`classify_epoch_membership`],
/// using the identity `(namespace, name, version, content_hash)` (spec
/// §3.4.8's identity tuple, byte-exact per S2/D16 hygiene). Classification
/// runs unconditionally, BEFORE stage 0 — membership is a fact about the
/// candidate's identity alone, independent of whether it happens to carry
/// an attestation record at all (an `Unattested` post-epoch entry is still
/// `PostEpoch`, which is exactly the row the mandate must catch).
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
    epoch_status: &EpochCommitmentStatus,
) -> Result<EntryGateOutcome, MilpaError> {
    let identity = PreEpochIdentity {
        namespace: namespace.to_string(),
        name: name.to_string(),
        version: version.to_string(),
        content_hash: content_hash.to_string(),
    };
    let epoch_membership = classify_epoch_membership(epoch_status, &identity);

    // Stage 0: attestation record absent (or collapsed to unattested at parse time).
    let Some(att) = attestation else {
        return Ok(EntryGateOutcome { result: EntryVerificationResult::Unattested, epoch_membership, cause: None });
    };

    // Stage 1: bundle acquisition.
    let Some(pin) = att.bundle_pin.as_deref() else {
        return Ok(EntryGateOutcome {
            result: EntryVerificationResult::BundleMissing,
            epoch_membership,
            cause: Some("no-pin".to_string()),
        });
    };
    let Some(store) = bundle_store else {
        return Ok(EntryGateOutcome {
            result: EntryVerificationResult::BundleMissing,
            epoch_membership,
            cause: Some("unfetchable".to_string()),
        });
    };
    let bundle_bytes = match store.get(pin) {
        Ok(b) => b,
        Err(e) => {
            if e.code() == "TNG-ENTRY-BUNDLE-PIN-MISMATCH" {
                return Err(e); // stage 1b: unconditional hard error, never policy-gated
            }
            return Ok(EntryGateOutcome {
                result: EntryVerificationResult::BundleMissing,
                epoch_membership,
                cause: Some("unfetchable".to_string()),
            });
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
    Ok(EntryGateOutcome { result, epoch_membership, cause: None })
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

/// Static hints for results whose remediation text does not depend on
/// `cause`/bundle-store backend. `BundleMissing` is deliberately absent —
/// its hint is cause- and backend-dependent (see `bundle_missing_hint`, D6).
///
/// D6 audit: every "escape" hint below recommends the NARROWER
/// `entry-trust "warn"` (preserves the audit trail strict exists to
/// produce), never the permanent kill-switch `entry-trust "off"` — reserve
/// `"off"` language for genuinely-permanent deliberate opt-outs, which none
/// of these are.
fn hint_for(result: EntryVerificationResult) -> String {
    match result {
        EntryVerificationResult::Unattested => {
            "no attestation record for this entry. Set 'entry-trust \"warn\"' in \
             milpa.kdl to accept it without an attestation while still recording \
             a warning, or wait for the author/vendor-bot to publish an attested \
             entry."
                .to_string()
        }
        EntryVerificationResult::BundleMalformed => {
            "the per-entry Sigstore bundle is not valid JSON or missing required fields."
                .to_string()
        }
        EntryVerificationResult::DigestMismatch => {
            "the bundle's attested subject digest does not match this entry's \
             content_hash (tampering or mismatched bundle/entry pair)."
                .to_string()
        }
        EntryVerificationResult::SubjectMismatch => {
            "the bundle's attested subject package identity does not match this \
             entry's coordinate (possible cross-package replay)."
                .to_string()
        }
        EntryVerificationResult::SignatureInvalid => {
            "cryptographic verification of the per-entry Sigstore bundle failed.".to_string()
        }
        EntryVerificationResult::SignerMismatch => {
            "the bundle signer identity does not match the expected signer for \
             this entry's attestation kind."
                .to_string()
        }
        EntryVerificationResult::BundleMissing => {
            unreachable!("BundleMissing routes through bundle_missing_hint, not hint_for")
        }
        EntryVerificationResult::Trusted => unreachable!("handled by caller"),
    }
}

/// D6 cause × store-backend hint for `BundleMissing` (RFC S-Acq).
///
/// `cause == "no-pin"`: the registry itself has not published a bundle for
/// this entry yet — independent of which store backend is configured.
///
/// `cause == "unfetchable"`: the remediation depends on the store backend
/// that failed to produce bytes:
/// - `HttpEntryBundleStore` (production mirror): a fetch failure is usually
///   a transient network condition — retrying via `milpa fetch` is
///   meaningful remediation. `--refresh-index` is NOT recommended: it only
///   bypasses the INDEX cache TTL and is a no-op for the content-addressed
///   bundle store (which has no TTL to bypass).
/// - `FileEntryBundleStore` (`MILPA_ENTRY_BUNDLE_DIR`, air-gapped): a
///   genuinely-absent local file is NOT transient — retrying deterministically
///   re-fails. The hint names the operator-populated mirror instead.
/// - No store configured at all (`--no-index`, an explicitly-empty
///   `MILPA_INDEX_URL`, and no `MILPA_ENTRY_BUNDLE_DIR`): neither retrying
///   nor an operator mirror applies — the hint says to configure a source.
fn bundle_missing_hint(cause: Option<&str>, backend: Option<BundleStoreBackend>) -> String {
    if cause == Some("no-pin") {
        return "the registry has not published a Sigstore bundle for this entry \
                yet. Set 'entry-trust \"warn\"' in milpa.kdl, or wait for the \
                registry's attestation backfill to publish one."
            .to_string();
    }
    match backend {
        Some(BundleStoreBackend::File) => {
            "the attestation bundle is missing from the local mirror \
             (MILPA_ENTRY_BUNDLE_DIR); this will not resolve itself — ask the \
             operator to populate the mirror with this entry's bundle, or set \
             'entry-trust \"warn\"' in milpa.kdl to suppress."
                .to_string()
        }
        Some(BundleStoreBackend::Http) => {
            "the attestation mirror was unreachable; this is usually transient \
             — re-run 'milpa fetch'. If it keeps failing, set 'entry-trust \
             \"warn\"' in milpa.kdl to suppress."
                .to_string()
        }
        None => "no attestation-bundle source is configured for this invocation \
                  (no index, and MILPA_ENTRY_BUNDLE_DIR is unset) — configure one, \
                  or set 'entry-trust \"warn\"' in milpa.kdl to suppress."
            .to_string(),
    }
}

/// Pinned remediation prose keyed by epoch membership (RFC §6 S-EpochGate).
///
/// `PostEpoch`: the mandate-context sentence a strict failure needs — WHY
/// this particular entry is not eligible for the grandfathered downgrade.
/// `PreEpoch`: the symmetric explanation for why a failing pre-epoch entry
/// stays a warning even under `entry-trust "strict"` (observability for the
/// capped-policy case — not itself a failure explanation). `None`
/// (`Unarmed`): no epoch context to add.
fn epoch_membership_hint_suffix(membership: Option<EpochMembership>) -> &'static str {
    match membership {
        Some(EpochMembership::PostEpoch) => {
            " This version is not in the registry's committed pre-epoch set, so it must \
             carry a verifiable attestation."
        }
        Some(EpochMembership::PreEpoch) => {
            " This version is in the registry's committed pre-epoch (grandfathered) set, \
             so this stays a warning even under entry-trust \"strict\"."
        }
        None => "",
    }
}

/// warn/strict slug dispatch for one selected entry's gate outcome (D9).
///
/// - `Off`      → silent; the caller should not even invoke the gate, but
///                this guard makes the function total regardless.
/// - `Trusted`  → silent.
/// - `Warn`     → emit ONE warning to stderr per unique `(namespace, name,
///                version)` per invocation; return `Ok(())`.
/// - `Strict`   → return `Err(MilpaError)` with the appropriate `TNG-ENTRY-*` slug.
///
/// S-EpochGate (RFC §6, spec §3.6.3 NORMATIVE): before dispatching, the
/// configured `policy` is passed through [`effective_epoch_policy`] with
/// `outcome.epoch_membership` — `PostEpoch` keeps the configured policy (the
/// mandate applies); `PreEpoch`/`None` (`Unarmed`) caps it at `Warn` (a
/// fixed, shrinking grandfathered population never hard-fails).
///
/// `bundle_store` is the store the gate acquired (or failed to acquire)
/// bytes from — passed through ONLY so a `BundleMissing` result can select
/// the D6 cause × backend hint text (`bundle_missing_hint`); it has no
/// bearing on any other result.
pub fn enforce_entry_trust(
    outcome: &EntryGateOutcome,
    policy: &TrustPolicy,
    namespace: &str,
    name: &str,
    version: &str,
    bundle_store: Option<&dyn EntryBundleStore>,
) -> Result<(), MilpaError> {
    if *policy == TrustPolicy::Off || outcome.result == EntryVerificationResult::Trusted {
        return Ok(());
    }

    let effective_policy = effective_epoch_policy(policy, outcome.epoch_membership);
    if effective_policy == TrustPolicy::Off || outcome.result == EntryVerificationResult::Trusted {
        return Ok(());
    }

    let slug = outcome.result.to_slug();
    let coordinate = format!("pkg:tianguis/{namespace}/{name}@{version}");
    let mut hint = if outcome.result == EntryVerificationResult::BundleMissing {
        bundle_missing_hint(outcome.cause.as_deref(), bundle_store.map(|s| s.backend()))
    } else {
        hint_for(outcome.result)
    };
    if let Some(c) = &outcome.cause {
        hint = format!("{hint} (cause: {c})");
    }
    hint = format!("{hint}{}", epoch_membership_hint_suffix(outcome.epoch_membership));

    if effective_policy == TrustPolicy::Strict {
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

    /// Test helper: build an [`EntryGateOutcome`] with a given result,
    /// defaulting ``epoch_membership`` to `PostEpoch` — the configured
    /// policy applies unchanged (no S-EpochGate warn-cap in effect) — so the
    /// many pre-existing policy-dispatch tests below (which predate
    /// S-EpochGate and are about generic warn/strict/off behavior, not
    /// epoch-membership gating) keep exercising that behavior unperturbed.
    /// The dedicated S-EpochGate matrix overrides this explicitly per row.
    fn outcome(result: EntryVerificationResult) -> EntryGateOutcome {
        EntryGateOutcome { result, epoch_membership: Some(EpochMembership::PostEpoch), cause: None }
    }

    fn outcome_with(
        result: EntryVerificationResult,
        epoch_membership: Option<EpochMembership>,
        cause: Option<&str>,
    ) -> EntryGateOutcome {
        EntryGateOutcome { result, epoch_membership, cause: cause.map(str::to_string) }
    }

    #[test]
    fn evaluate_stage0_unattested() {
        let outcome = evaluate_entry_attestation(
            None, "dag-sha256:abcd", "ns1", "bar", "2.0.0",
            &MockEntryVerifier::new(VerifierOutcome::Trusted, HashMap::new()),
            None, &TrustBundle::test(), "vendor-signer", &EpochCommitmentStatus::default(),
        ).unwrap();
        assert_eq!(outcome.result, EntryVerificationResult::Unattested);
        assert_eq!(outcome.cause, None);
        assert_eq!(outcome.epoch_membership, None);
    }

    #[test]
    fn evaluate_stage1_bundle_missing_no_pin() {
        let att = EntryAttestation { kind: AttestationKind::MilpaVendored, rekor: None, bundle_pin: None };
        let outcome = evaluate_entry_attestation(
            Some(&att), "dag-sha256:abcd", "ns1", "bar", "2.0.0",
            &MockEntryVerifier::new(VerifierOutcome::Trusted, HashMap::new()),
            None, &TrustBundle::test(), "vendor-signer", &EpochCommitmentStatus::default(),
        ).unwrap();
        assert_eq!(outcome.result, EntryVerificationResult::BundleMissing);
        assert_eq!(outcome.cause.as_deref(), Some("no-pin"));
    }

    #[test]
    fn evaluate_stage1_bundle_missing_unfetchable_when_pin_present_no_store() {
        let att = EntryAttestation {
            kind: AttestationKind::MilpaVendored,
            rekor: None,
            bundle_pin: Some("a".repeat(64)),
        };
        let outcome = evaluate_entry_attestation(
            Some(&att), "dag-sha256:abcd", "ns1", "bar", "2.0.0",
            &MockEntryVerifier::new(VerifierOutcome::Trusted, HashMap::new()),
            None, &TrustBundle::test(), "vendor-signer", &EpochCommitmentStatus::default(),
        ).unwrap();
        assert_eq!(outcome.result, EntryVerificationResult::BundleMissing);
        assert_eq!(outcome.cause.as_deref(), Some("unfetchable"));
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
            Some(&store), &TrustBundle::test(), "vendor-signer", &EpochCommitmentStatus::default(),
        ).unwrap_err();
        assert_eq!(err.code(), "TNG-ENTRY-BUNDLE-PIN-MISMATCH");
    }

    #[test]
    fn enforce_off_is_silent() {
        enforce_entry_trust(
            &outcome(EntryVerificationResult::Unattested), &TrustPolicy::Off, "ns1", "bar", "2.0.0", None,
        ).expect("off must never raise");
    }

    #[test]
    fn enforce_trusted_is_silent_even_under_strict() {
        enforce_entry_trust(
            &outcome(EntryVerificationResult::Trusted), &TrustPolicy::Strict, "ns1", "bar", "2.0.0", None,
        ).expect("trusted must never raise");
    }

    #[test]
    fn enforce_strict_raises_slug() {
        let err = enforce_entry_trust(
            &outcome(EntryVerificationResult::SignerMismatch), &TrustPolicy::Strict, "ns1", "bar", "2.0.0", None,
        ).unwrap_err();
        assert_eq!(err.code(), "TNG-ENTRY-SIGNER-MISMATCH");
    }

    #[test]
    fn enforce_warn_never_raises() {
        _reset_warned_entries();
        enforce_entry_trust(
            &outcome(EntryVerificationResult::Unattested), &TrustPolicy::Warn, "ns1", "warntest", "2.0.0", None,
        ).expect("warn must not raise");
    }

    // -----------------------------------------------------------------------
    // D6 remediation-hint audit (RFC attestation-v1-normative.md §6 S-Acq).
    //
    // Two changes under test:
    //   1. Every "escape" hint that used to recommend the permanent
    //      kill-switch 'entry-trust "off"' now recommends the narrower
    //      'entry-trust "warn"' (preserves the audit trail strict exists to
    //      produce). A deliberate behavior change, not a regression.
    //   2. BundleMissing's hint now varies by (cause, bundle-store backend):
    //      no-pin is backend-independent; unfetchable splits HTTP (transient,
    //      "re-run fetch") vs File (operator-populated air-gapped mirror, NOT
    //      transient) vs no-store-configured. '--refresh-index' is never
    //      recommended — it bypasses the INDEX cache TTL only, a no-op for
    //      the content-addressed bundle store.
    // -----------------------------------------------------------------------

    struct StubStore(BundleStoreBackend);
    impl EntryBundleStore for StubStore {
        fn get(&self, _bundle_pin: &str) -> Result<Vec<u8>, MilpaError> {
            unreachable!("hint tests never call get()")
        }
        fn is_cached(&self, _bundle_pin: &str) -> bool {
            false
        }
        fn backend(&self) -> BundleStoreBackend {
            self.0
        }
    }

    #[test]
    fn unattested_hint_recommends_warn_not_off() {
        _reset_warned_entries();
        enforce_entry_trust(
            &outcome(EntryVerificationResult::Unattested), &TrustPolicy::Warn, "ns1", "foo", "1.0.0", None,
        ).unwrap();
        assert_eq!(hint_for(EntryVerificationResult::Unattested).contains("entry-trust \"warn\""), true);
        assert_eq!(hint_for(EntryVerificationResult::Unattested).contains("entry-trust \"off\""), false);
    }

    #[test]
    fn bundle_missing_no_pin_hint_recommends_warn_not_off() {
        let hint = bundle_missing_hint(Some("no-pin"), None);
        assert!(hint.contains("has not published"));
        assert!(hint.contains("entry-trust \"warn\""));
        assert!(!hint.contains("entry-trust \"off\""));
        assert!(!hint.contains("--refresh-index"));
    }

    #[test]
    fn bundle_missing_unfetchable_http_backend_hint_is_transient() {
        let hint = bundle_missing_hint(Some("unfetchable"), Some(BundleStoreBackend::Http));
        assert!(hint.contains("re-run 'milpa fetch'"));
        assert!(!hint.contains("--refresh-index"));
        assert!(!hint.contains("entry-trust \"off\""));
    }

    #[test]
    fn bundle_missing_unfetchable_file_backend_hint_names_operator_mirror() {
        let hint = bundle_missing_hint(Some("unfetchable"), Some(BundleStoreBackend::File));
        assert!(hint.contains("MILPA_ENTRY_BUNDLE_DIR"));
        assert!(hint.contains("operator"));
        // A genuinely-absent local mirror file is not transient: retrying
        // deterministically re-fails, so the hint must not suggest re-fetching.
        assert!(!hint.contains("re-run 'milpa fetch'"));
        assert!(!hint.contains("entry-trust \"off\""));
    }

    #[test]
    fn bundle_missing_unfetchable_no_store_configured_hint() {
        let hint = bundle_missing_hint(Some("unfetchable"), None);
        assert!(hint.contains("no attestation-bundle source is configured"));
        assert!(!hint.contains("entry-trust \"off\""));
    }

    #[test]
    fn enforce_bundle_missing_threads_backend_into_hint() {
        // End-to-end: enforce_entry_trust (not just bundle_missing_hint
        // directly) selects the File-backend hint when given a File store.
        _reset_warned_entries();
        let store: Box<dyn EntryBundleStore> = Box::new(StubStore(BundleStoreBackend::File));
        enforce_entry_trust(
            &outcome_with(EntryVerificationResult::BundleMissing, Some(EpochMembership::PostEpoch), Some("unfetchable")),
            &TrustPolicy::Warn,
            "ns1",
            "foo",
            "1.0.0",
            Some(store.as_ref()),
        ).unwrap();
    }

    // -------------------------------------------------------------------
    // S-EpochGate (RFC attestation-v1-normative.md §6, D14/D17): membership
    // classification + the warn-cap downgrade. Spec: registry-protocol.md
    // §3.4.8 (local set lookup) and §3.6.3 (EntryGateOutcome / EpochMembership
    // NORMATIVE clauses).
    // -------------------------------------------------------------------

    fn id(namespace: &str, name: &str, version: &str, content_hash: &str) -> PreEpochIdentity {
        PreEpochIdentity {
            namespace: namespace.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            content_hash: content_hash.to_string(),
        }
    }

    const CH: &str = "dag-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_CH: &str = "dag-sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn the_identity() -> PreEpochIdentity {
        id("ns1", "foo", "1.0.0", CH)
    }

    mod classify_membership {
        use super::*;

        #[test]
        fn armed_member_is_pre_epoch() {
            let status = EpochCommitmentStatus::Armed {
                identities: [the_identity()].into_iter().collect(),
                integrated_time: 1700000000,
            };
            assert_eq!(classify_epoch_membership(&status, &the_identity()), Some(EpochMembership::PreEpoch));
        }

        #[test]
        fn armed_non_member_is_post_epoch() {
            let status = EpochCommitmentStatus::Armed {
                identities: [id("ns1", "other", "2.0.0", OTHER_CH)].into_iter().collect(),
                integrated_time: 1700000000,
            };
            assert_eq!(classify_epoch_membership(&status, &the_identity()), Some(EpochMembership::PostEpoch));
        }

        #[test]
        fn armed_empty_set_is_post_epoch() {
            let status = EpochCommitmentStatus::Armed { identities: Default::default(), integrated_time: 1700000000 };
            assert_eq!(classify_epoch_membership(&status, &the_identity()), Some(EpochMembership::PostEpoch));
        }

        #[test]
        fn unarmed_is_none() {
            assert_eq!(classify_epoch_membership(&EpochCommitmentStatus::Unarmed, &the_identity()), None);
        }

        #[test]
        fn arming_invalid_is_none_defensively() {
            let status = EpochCommitmentStatus::ArmingInvalid { reason: "x".to_string() };
            assert_eq!(classify_epoch_membership(&status, &the_identity()), None);
        }

        #[test]
        fn sensitive_to_every_identity_field() {
            let status = EpochCommitmentStatus::Armed {
                identities: [the_identity()].into_iter().collect(),
                integrated_time: 1700000000,
            };
            assert_eq!(classify_epoch_membership(&status, &id("ns2", "foo", "1.0.0", CH)), Some(EpochMembership::PostEpoch));
            assert_eq!(classify_epoch_membership(&status, &id("ns1", "bar", "1.0.0", CH)), Some(EpochMembership::PostEpoch));
            assert_eq!(classify_epoch_membership(&status, &id("ns1", "foo", "2.0.0", CH)), Some(EpochMembership::PostEpoch));
            assert_eq!(classify_epoch_membership(&status, &id("ns1", "foo", "1.0.0", OTHER_CH)), Some(EpochMembership::PostEpoch));
        }
    }

    mod effective_policy {
        use super::*;

        #[test]
        fn post_epoch_is_unchanged() {
            for policy in [TrustPolicy::Off, TrustPolicy::Warn, TrustPolicy::Strict] {
                assert_eq!(effective_epoch_policy(&policy, Some(EpochMembership::PostEpoch)), policy);
            }
        }

        #[test]
        fn off_stays_off_regardless_of_membership() {
            assert_eq!(effective_epoch_policy(&TrustPolicy::Off, Some(EpochMembership::PreEpoch)), TrustPolicy::Off);
            assert_eq!(effective_epoch_policy(&TrustPolicy::Off, None), TrustPolicy::Off);
        }

        #[test]
        fn warn_stays_warn_regardless_of_membership() {
            assert_eq!(effective_epoch_policy(&TrustPolicy::Warn, Some(EpochMembership::PreEpoch)), TrustPolicy::Warn);
            assert_eq!(effective_epoch_policy(&TrustPolicy::Warn, None), TrustPolicy::Warn);
        }

        #[test]
        fn strict_downgrades_to_warn_for_pre_epoch_or_unarmed() {
            assert_eq!(effective_epoch_policy(&TrustPolicy::Strict, Some(EpochMembership::PreEpoch)), TrustPolicy::Warn);
            assert_eq!(effective_epoch_policy(&TrustPolicy::Strict, None), TrustPolicy::Warn);
        }
    }

    /// The full impl-level unit matrix (RFC §6 S-EpochGate *Test*):
    /// {PreEpoch, PostEpoch, Unarmed} x {Warn, Strict} x {attested, unattested}.
    mod full_matrix {
        use super::*;

        fn status_for(membership: Option<EpochMembership>) -> EpochCommitmentStatus {
            match membership {
                None => EpochCommitmentStatus::Unarmed,
                Some(EpochMembership::PreEpoch) => EpochCommitmentStatus::Armed {
                    identities: [the_identity()].into_iter().collect(),
                    integrated_time: 1700000000,
                },
                Some(EpochMembership::PostEpoch) => EpochCommitmentStatus::Armed {
                    identities: [id("ns1", "other", "9.9.9", OTHER_CH)].into_iter().collect(),
                    integrated_time: 1700000000,
                },
            }
        }

        fn evaluate_unattested(membership: Option<EpochMembership>) -> EntryGateOutcome {
            evaluate_entry_attestation(
                None, CH, "ns1", "foo", "1.0.0",
                &MockEntryVerifier::new(VerifierOutcome::Trusted, HashMap::new()),
                None, &TrustBundle::test(), "vendor-bot", &status_for(membership),
            ).unwrap()
        }

        #[test]
        fn post_epoch_strict_unattested_hard_fails() {
            let outcome = evaluate_unattested(Some(EpochMembership::PostEpoch));
            assert_eq!(outcome.result, EntryVerificationResult::Unattested);
            assert_eq!(outcome.epoch_membership, Some(EpochMembership::PostEpoch));
            let err = enforce_entry_trust(&outcome, &TrustPolicy::Strict, "ns1", "foo", "1.0.0", None).unwrap_err();
            assert_eq!(err.code(), "TNG-ENTRY-UNATTESTED");
        }

        #[test]
        fn pre_epoch_strict_unattested_warns_not_raises() {
            _reset_warned_entries();
            let outcome = evaluate_unattested(Some(EpochMembership::PreEpoch));
            assert_eq!(outcome.epoch_membership, Some(EpochMembership::PreEpoch));
            enforce_entry_trust(&outcome, &TrustPolicy::Strict, "ns1", "foo", "1.0.0", None)
                .expect("PreEpoch must stay warn-territory even under strict");
        }

        #[test]
        fn unarmed_strict_unattested_warns_not_raises() {
            _reset_warned_entries();
            let outcome = evaluate_unattested(None);
            assert_eq!(outcome.epoch_membership, None);
            enforce_entry_trust(&outcome, &TrustPolicy::Strict, "ns1", "foo", "1.0.0", None)
                .expect("Unarmed must be warn-equivalent even under strict");
        }

        #[test]
        fn post_epoch_mandate_hint_is_pinned() {
            let outcome = evaluate_unattested(Some(EpochMembership::PostEpoch));
            let err = enforce_entry_trust(&outcome, &TrustPolicy::Strict, "ns1", "foo", "1.0.0", None).unwrap_err();
            let msg = err.message();
            assert!(msg.contains("not in the registry's committed pre-epoch set"), "{msg}");
            assert!(msg.contains("must carry a verifiable attestation"), "{msg}");
        }

        #[test]
        fn attested_trusted_passes_under_strict_regardless_of_membership() {
            for membership in [Some(EpochMembership::PreEpoch), Some(EpochMembership::PostEpoch), None] {
                _reset_warned_entries();
                let tmp = tempfile::tempdir().unwrap();
                let bundle_bytes = b"any-bytes-mock-does-not-inspect".to_vec();
                let pin = {
                    use sha2::{Digest, Sha256};
                    hex::encode(Sha256::digest(&bundle_bytes))
                };
                std::fs::write(tmp.path().join(format!("{pin}.bundle")), &bundle_bytes).unwrap();
                let store = crate::entry_bundle_store::FileEntryBundleStore::new(tmp.path());
                let att = EntryAttestation { kind: AttestationKind::MilpaVendored, rekor: None, bundle_pin: Some(pin) };

                let outcome = evaluate_entry_attestation(
                    Some(&att), CH, "ns1", "foo", "1.0.0",
                    &MockEntryVerifier::new(VerifierOutcome::Trusted, HashMap::new()),
                    Some(&store), &TrustBundle::test(), "vendor-bot", &status_for(membership),
                ).unwrap();
                assert_eq!(outcome.result, EntryVerificationResult::Trusted);
                enforce_entry_trust(&outcome, &TrustPolicy::Strict, "ns1", "foo", "1.0.0", None)
                    .expect("Trusted must never raise/warn regardless of membership");
            }
        }

        #[test]
        fn warn_policy_never_raises_regardless_of_membership() {
            for membership in [Some(EpochMembership::PreEpoch), Some(EpochMembership::PostEpoch), None] {
                _reset_warned_entries();
                let outcome = evaluate_unattested(membership);
                enforce_entry_trust(&outcome, &TrustPolicy::Warn, "ns1", "foo", "1.0.0", None)
                    .expect("warn must never raise");
            }
        }

        #[test]
        fn off_policy_never_raises_regardless_of_membership() {
            for membership in [Some(EpochMembership::PreEpoch), Some(EpochMembership::PostEpoch), None] {
                let outcome = evaluate_unattested(membership);
                enforce_entry_trust(&outcome, &TrustPolicy::Off, "ns1", "foo", "1.0.0", None)
                    .expect("off must never raise");
            }
        }
    }
}
