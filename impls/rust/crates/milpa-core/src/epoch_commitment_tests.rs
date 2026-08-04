//! Unit tests for `epoch_commitment.rs`.
//!
//! Two tiers:
//! 1. **Golden `C` vectors** (V1-V4) — the cross-impl byte-exactness gate
//!    (D16). Each digest is asserted against the exact lowercase-hex string
//!    the Python reference impl produces for the same logical `S`.
//! 2. **Unit matrix** — `evaluate_epoch_commitment` / `enforce_epoch_commitment`
//!    / `check_epoch_ratchet_requirement` against a `MockVerifier`, entirely
//!    synthetic (no tianguis, no network).

use super::*;
use crate::index_trust::MockVerifier;

fn id_(namespace: &str, name: &str, version: &str, content_hash: &str) -> PreEpochIdentity {
    PreEpochIdentity {
        namespace: namespace.to_string(),
        name: name.to_string(),
        version: version.to_string(),
        content_hash: content_hash.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Golden C vectors (D16) — byte-exact cross-impl parity gate
// ---------------------------------------------------------------------------

#[test]
fn golden_v1_two_entries_order_independent() {
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    let alice = id_("alice", "leftpad", "1.0.0", &format!("dag-sha256:{a}"));
    let bob = id_("bob", "rightpad", "2.0.0", &format!("dag-sha256:{b}"));

    // Passed REVERSED to prove order-independence (sorting, not input order,
    // determines the preimage).
    let identities = vec![bob.clone(), alice.clone()];

    let expected_preimage = format!(
        "milpa-preepoch-v1:alice\u{1f}leftpad\u{1f}1.0.0\u{1f}dag-sha256:{a}\u{1e}bob\u{1f}rightpad\u{1f}2.0.0\u{1f}dag-sha256:{b}"
    );
    assert_eq!(canonical_preimage(&identities), expected_preimage.into_bytes());

    assert_eq!(
        commitment_digest(&identities),
        "53f35143feda939da3ecf1009a769ae01d522751a696b935fb8c8a881d44a6b9"
    );
}

#[test]
fn golden_v2_tie_case_precedence_equal_raw_distinct() {
    let c = "c".repeat(64);
    let build = id_("acme", "x", "1.0.0+build", &format!("dag-sha256:{c}"));
    let plain = id_("acme", "x", "1.0.0", &format!("dag-sha256:{c}"));

    // Passed REVERSED.
    let identities = vec![build, plain];

    assert_eq!(
        commitment_digest(&identities),
        "17f9ae521c99bbc7051444de207b36830c18c66315aee5b2e87f89b57c7ce06a"
    );
}

#[test]
fn golden_v3_empty_set() {
    let identities: Vec<PreEpochIdentity> = Vec::new();
    assert_eq!(canonical_bytes(&identities), Vec::<u8>::new());
    assert_eq!(
        commitment_digest(&identities),
        "d5c23594d424a16e23b6c470c0c2d3040b7df729a58b7b36954d99a31f3ad7ea"
    );
}

#[test]
fn golden_v4_namespace_sensitivity() {
    let d = "d".repeat(64);
    let alice = vec![id_("alice", "pkg", "1.2.3", &format!("dag-sha256:{d}"))];
    let mallory = vec![id_("mallory", "pkg", "1.2.3", &format!("dag-sha256:{d}"))];

    assert_eq!(
        commitment_digest(&alice),
        "bc9526e48be666d8cfba8c4a3005ddc5992796a3fa038ba0a9e783cffd14d254"
    );
    assert_eq!(
        commitment_digest(&mallory),
        "8dd8314500a2ab22caf34da0cd34314ba079b676ab5eb28234926062ee07e7ad"
    );
    assert_ne!(commitment_digest(&alice), commitment_digest(&mallory));
}

#[test]
fn dedup_exact_duplicates_collapse() {
    let h = "e".repeat(64);
    let id1 = id_("ns", "pkg", "1.0.0", &format!("dag-sha256:{h}"));
    let identities = vec![id1.clone(), id1.clone(), id1];
    let deduped = sorted_deduped(&identities);
    assert_eq!(deduped.len(), 1);
}

// ---------------------------------------------------------------------------
// Sidecar payload parsing
// ---------------------------------------------------------------------------

fn valid_sidecar_json(identities: &[PreEpochIdentity], bundle: serde_json::Value) -> Vec<u8> {
    let identities_json: Vec<serde_json::Value> = identities
        .iter()
        .map(|i| {
            serde_json::json!({
                "namespace": i.namespace,
                "name": i.name,
                "version": i.version,
                "content_hash": i.content_hash,
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "identities": identities_json,
        "bundle": bundle,
    }))
    .unwrap()
}

fn fake_bundle(integrated_time: i64) -> serde_json::Value {
    serde_json::json!({
        "verificationMaterial": {
            "tlogEntries": [{"integratedTime": integrated_time.to_string()}]
        }
    })
}

#[test]
fn parse_sidecar_payload_rejects_non_json() {
    assert!(parse_sidecar_payload(b"not json").is_none());
}

#[test]
fn parse_sidecar_payload_rejects_missing_identities() {
    let bytes = serde_json::to_vec(&serde_json::json!({"bundle": {}})).unwrap();
    assert!(parse_sidecar_payload(&bytes).is_none());
}

#[test]
fn parse_sidecar_payload_rejects_non_object_bundle() {
    let bytes = serde_json::to_vec(&serde_json::json!({"identities": [], "bundle": "nope"})).unwrap();
    assert!(parse_sidecar_payload(&bytes).is_none());
}

#[test]
fn parse_sidecar_payload_accepts_well_formed() {
    let h = "1".repeat(64);
    let identities = vec![id_("ns", "pkg", "1.0.0", &format!("dag-sha256:{h}"))];
    let bytes = valid_sidecar_json(&identities, fake_bundle(1_700_000_000));
    let parsed = parse_sidecar_payload(&bytes);
    assert!(parsed.is_some());
    let (parsed_ids, _bundle_bytes) = parsed.unwrap();
    assert_eq!(parsed_ids, identities);
}

// ---------------------------------------------------------------------------
// Unit matrix: evaluate_epoch_commitment against MockVerifier (synthetic,
// NO tianguis) — {Unarmed, Armed(valid), ArmingInvalid(bad-inclusion/
// bad-cert-DSSE/hash!=C/wrong-signer), D18 config-error}.
// ---------------------------------------------------------------------------

const SIGNER: &str = "https://example.test/signer";

#[test]
fn matrix_unarmed_when_pointer_absent() {
    let verifier = MockVerifier::new(VerificationResult::Trusted);
    let status = evaluate_epoch_commitment(None, None, false, &verifier, &TrustBundle::test(), SIGNER);
    assert_eq!(status, EpochCommitmentStatus::Unarmed);
    assert!(enforce_epoch_commitment(&status).is_ok());
}

#[test]
fn matrix_armed_on_full_success() {
    let h = "2".repeat(64);
    let identities = vec![id_("ns", "pkg", "1.0.0", &format!("dag-sha256:{h}"))];
    let pointer = commitment_digest(&identities);
    let sidecar = valid_sidecar_json(&identities, fake_bundle(1_700_000_000));
    let verifier = MockVerifier::new(VerificationResult::Trusted);

    let status = evaluate_epoch_commitment(Some(&pointer), Some(&sidecar), false, &verifier, &TrustBundle::test(), SIGNER);

    match &status {
        EpochCommitmentStatus::Armed { identities: got, integrated_time } => {
            assert_eq!(got.len(), 1);
            assert!(got.contains(&identities[0]));
            assert_eq!(*integrated_time, 1_700_000_000);
        }
        other => panic!("expected Armed, got {other:?}"),
    }
    assert!(enforce_epoch_commitment(&status).is_ok());
}

#[test]
fn matrix_arming_invalid_malformed_pointer() {
    let verifier = MockVerifier::new(VerificationResult::Trusted);
    let status = evaluate_epoch_commitment(Some("not-hex"), None, false, &verifier, &TrustBundle::test(), SIGNER);
    assert!(matches!(status, EpochCommitmentStatus::ArmingInvalid { .. }));
    assert!(enforce_epoch_commitment(&status).is_err());
}

#[test]
fn matrix_arming_invalid_unfetchable_sidecar() {
    let pointer = "0".repeat(64);
    let verifier = MockVerifier::new(VerificationResult::Trusted);
    let status = evaluate_epoch_commitment(Some(&pointer), None, true, &verifier, &TrustBundle::test(), SIGNER);
    assert!(matches!(status, EpochCommitmentStatus::ArmingInvalid { .. }));
}

#[test]
fn matrix_arming_invalid_sidecar_malformed() {
    let pointer = "0".repeat(64);
    let verifier = MockVerifier::new(VerificationResult::Trusted);
    let status = evaluate_epoch_commitment(Some(&pointer), Some(b"not json"), false, &verifier, &TrustBundle::test(), SIGNER);
    assert!(matches!(status, EpochCommitmentStatus::ArmingInvalid { .. }));
}

#[test]
fn matrix_arming_invalid_hash_mismatch() {
    let h = "3".repeat(64);
    let identities = vec![id_("ns", "pkg", "1.0.0", &format!("dag-sha256:{h}"))];
    // Pointer deliberately wrong — does not match commitment_digest(identities).
    let wrong_pointer = "f".repeat(64);
    let sidecar = valid_sidecar_json(&identities, fake_bundle(1_700_000_000));
    let verifier = MockVerifier::new(VerificationResult::Trusted);

    let status = evaluate_epoch_commitment(Some(&wrong_pointer), Some(&sidecar), false, &verifier, &TrustBundle::test(), SIGNER);
    match &status {
        EpochCommitmentStatus::ArmingInvalid { reason } => assert_eq!(reason, "hash(S) != C"),
        other => panic!("expected ArmingInvalid(hash(S) != C), got {other:?}"),
    }
}

#[test]
fn matrix_arming_invalid_bad_cert_dsse() {
    // "bad-cert-DSSE" — the composed verifier reports a signature failure.
    let h = "4".repeat(64);
    let identities = vec![id_("ns", "pkg", "1.0.0", &format!("dag-sha256:{h}"))];
    let pointer = commitment_digest(&identities);
    let sidecar = valid_sidecar_json(&identities, fake_bundle(1_700_000_000));
    let verifier = MockVerifier::new(VerificationResult::SigInvalid);

    let status = evaluate_epoch_commitment(Some(&pointer), Some(&sidecar), false, &verifier, &TrustBundle::test(), SIGNER);
    assert!(matches!(status, EpochCommitmentStatus::ArmingInvalid { .. }));
    assert!(enforce_epoch_commitment(&status).is_err());
}

#[test]
fn matrix_arming_invalid_wrong_signer() {
    let h = "5".repeat(64);
    let identities = vec![id_("ns", "pkg", "1.0.0", &format!("dag-sha256:{h}"))];
    let pointer = commitment_digest(&identities);
    let sidecar = valid_sidecar_json(&identities, fake_bundle(1_700_000_000));
    let verifier = MockVerifier::new(VerificationResult::SignerMismatch);

    let status = evaluate_epoch_commitment(Some(&pointer), Some(&sidecar), false, &verifier, &TrustBundle::test(), SIGNER);
    match &status {
        EpochCommitmentStatus::ArmingInvalid { reason } => assert_eq!(reason, "signer-mismatch"),
        other => panic!("expected ArmingInvalid(signer-mismatch), got {other:?}"),
    }
}

#[test]
fn matrix_arming_invalid_bad_inclusion() {
    // "bad-inclusion" — modeled as a bundle-malformed composed-verify result
    // (offline Rekor inclusion-proof failure surfaces as a crypto/structural
    // rejection through the SAME MockVerifier seam index-trust uses).
    let h = "6".repeat(64);
    let identities = vec![id_("ns", "pkg", "1.0.0", &format!("dag-sha256:{h}"))];
    let pointer = commitment_digest(&identities);
    let sidecar = valid_sidecar_json(&identities, fake_bundle(1_700_000_000));
    let verifier = MockVerifier::new(VerificationResult::BundleMalformed);

    let status = evaluate_epoch_commitment(Some(&pointer), Some(&sidecar), false, &verifier, &TrustBundle::test(), SIGNER);
    assert!(matches!(status, EpochCommitmentStatus::ArmingInvalid { .. }));
}

// ---------------------------------------------------------------------------
// D18 co-requirement — check_epoch_ratchet_requirement
// ---------------------------------------------------------------------------

fn armed_status() -> EpochCommitmentStatus {
    EpochCommitmentStatus::Armed { identities: HashSet::new(), integrated_time: 1_700_000_000 }
}

#[test]
fn d18_unarmed_never_triggers() {
    assert!(check_epoch_ratchet_requirement(&EpochCommitmentStatus::Unarmed, &TrustPolicy::Strict, &TrustPolicy::Warn).is_ok());
}

#[test]
fn d18_armed_entry_warn_never_triggers() {
    assert!(check_epoch_ratchet_requirement(&armed_status(), &TrustPolicy::Warn, &TrustPolicy::Warn).is_ok());
}

#[test]
fn d18_armed_strict_with_strict_history_ok() {
    assert!(check_epoch_ratchet_requirement(&armed_status(), &TrustPolicy::Strict, &TrustPolicy::Strict).is_ok());
}

#[test]
fn d18_config_error_armed_strict_without_strict_history() {
    let err = check_epoch_ratchet_requirement(&armed_status(), &TrustPolicy::Strict, &TrustPolicy::Warn);
    assert!(err.is_err());
    assert_eq!(err.unwrap_err().code(), "TNG-INDEX-EPOCH-RATCHET-REQUIRED");
}

#[test]
fn d18_config_error_armed_strict_with_off_history() {
    let err = check_epoch_ratchet_requirement(&armed_status(), &TrustPolicy::Strict, &TrustPolicy::Off);
    assert!(err.is_err());
    assert_eq!(err.unwrap_err().code(), "TNG-INDEX-EPOCH-RATCHET-REQUIRED");
}
