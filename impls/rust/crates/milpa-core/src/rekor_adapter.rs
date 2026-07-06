//! Offline Rekor inclusion-proof adapter (RFC `rfc-attestation-verifier` S2 / §4).
//!
//! This is the piece milpa owns *temporarily* because sigstore-rs's own bundle
//! verifier leaves its transparency-log step 5 as a TODO (`verifier.rs:198`,
//! sigstore-rs#285 landed the primitives but did not wire them into the verifier).
//! The adapter reshapes the already-parsed protobuf `TransparencyLogEntry` into the
//! crate's public **semantic** `rekor::models::InclusionProof` and calls its audited
//! `verify()` — it reimplements **no** cryptography (§5.1 hand-roll-vs-delegate: all
//! hashing / Merkle / checkpoint-signature math stays inside the crate call).
//!
//! ## Name-collision hazard (§4)
//! There are TWO `InclusionProof` types in scope: the raw **protobuf** wire type
//! (`sigstore_protobuf_specs::…rekor::v1::InclusionProof`, aliased [`ProtoInclusionProof`]
//! here) and the **semantic** type with `.verify()`
//! (`sigstore::rekor::models::InclusionProof`). They are NOT interchangeable; the alias
//! keeps them apart.
//!
//! ## Composition binding (§4)
//! `verify_entry_inclusion` on its own only proves "*this canonicalized body* was
//! included in a checkpointed tree signed by this Rekor key." It does NOT bind that body
//! to the DSSE envelope/cert. S2's caller supplies the binding by threading the SAME
//! owned singleton `Bundle` value through both the high-level `verify_digest` and this
//! adapter — never re-parsing an independent copy.
//!
//! TODO(milpa): delete this module when sigstore-rs ships wired inclusion verification in
//! its bundle verifier; tracking: sigstore-rs#285 (S7 forcing function).

use sigstore::crypto::CosignVerificationKey;
use sigstore::rekor::models::checkpoint::SignedCheckpoint;
use sigstore::rekor::models::InclusionProof;
use sigstore_protobuf_specs::dev::sigstore::rekor::v1::{
    InclusionProof as ProtoInclusionProof, TransparencyLogEntry,
};

/// Result of reshaping + verifying one tlog entry's offline inclusion proof.
///
/// A milpa **domain** enum, not a bubbled crate error: structural-vs-crypto
/// classification happens here (where the context is), so `SigstoreVerifier` maps it
/// straight onto the `VerificationResult` SSOT without peeking at sigstore error kinds.
///
/// The `String` reasons are diagnostic context at the failure site (and asserted by the
/// adapter's own tests for failure-precision). milpa's fixed `VerificationResult` enum has
/// no free-form detail channel to surface them through, so `verify_crypto` maps by variant
/// only — hence `allow(dead_code)` on the payloads until a richer error channel exists.
#[derive(Debug)]
#[allow(dead_code)] // reason strings are diagnostic-only; see note above
pub(crate) enum AdapterOutcome {
    /// The body is included in a checkpointed tree signed by the expected Rekor key.
    Included,
    /// Reshape succeeded but the cryptographic inclusion/checkpoint check failed
    /// (tampered proof, wrong root, wrong key, bad checkpoint signature). → crypto slug.
    CryptoInvalid(String),
    /// The entry could not be reshaped into a verifiable proof (missing/renamed field,
    /// wrong-width hash, absent proof or checkpoint, undecodable checkpoint). This is a
    /// **pre-crypto structural** failure → `TNG-INDEX-BUNDLE-MALFORMED`.
    Malformed(String),
}

/// Verify the offline Rekor inclusion proof carried by `entry` against `rekor_key_der`
/// (raw SPKI DER, looked up by `hex(log_id.key_id)` from the trust root — §4 contract).
///
/// Never panics; every failure is a typed [`AdapterOutcome`], never a raw Rust panic or
/// `MILPA-INTERNAL`.
pub(crate) fn verify_entry_inclusion(
    entry: &TransparencyLogEntry,
    rekor_key_der: &[u8],
) -> AdapterOutcome {
    let Some(proto) = entry.inclusion_proof.as_ref() else {
        // Belt-and-suspenders: v0.2/v0.3 bundles reject this at CheckedBundle
        // construction, but an offline-only verifier must never fail *open* on a
        // v0.1-shaped entry that carries no proof (§4 trap #1).
        return AdapterOutcome::Malformed("tlog entry carries no inclusion proof".to_string());
    };

    let semantic = match reshape(proto) {
        Ok(p) => p,
        Err(reason) => return AdapterOutcome::Malformed(reason),
    };

    let key = match CosignVerificationKey::try_from_der(rekor_key_der) {
        Ok(k) => k,
        Err(e) => return AdapterOutcome::Malformed(format!("rekor key is not valid SPKI DER: {e}")),
    };

    match semantic.verify(&entry.canonicalized_body, &key) {
        Ok(()) => AdapterOutcome::Included,
        Err(e) => AdapterOutcome::CryptoInvalid(format!("offline inclusion verification failed: {e}")),
    }
}

/// Reshape the protobuf inclusion proof into the semantic type. Structural failures
/// (wrong-width hashes, absent/undecodable checkpoint) return an error string.
fn reshape(proto: &ProtoInclusionProof) -> Result<InclusionProof, String> {
    let root_hash: [u8; 32] = proto
        .root_hash
        .as_slice()
        .try_into()
        .map_err(|_| "inclusion proof root_hash is not 32 bytes".to_string())?;

    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(proto.hashes.len());
    for (i, h) in proto.hashes.iter().enumerate() {
        let h: [u8; 32] = h
            .as_slice()
            .try_into()
            .map_err(|_| format!("inclusion proof hash[{i}] is not 32 bytes"))?;
        hashes.push(h);
    }

    // The checkpoint envelope is a signed-note string; the crate's `SignedCheckpoint`
    // `Deserialize` impl (its only public constructor — `decode` is pub(crate)) parses it
    // from a JSON string value.
    let cp = proto
        .checkpoint
        .as_ref()
        .ok_or_else(|| "inclusion proof carries no checkpoint".to_string())?;
    let checkpoint: SignedCheckpoint =
        serde_json::from_value(serde_json::Value::String(cp.envelope.clone()))
            .map_err(|e| format!("checkpoint note did not decode: {e}"))?;

    Ok(InclusionProof::new(
        proto.log_index,
        root_hash,
        proto.tree_size as u64,
        hashes,
        Some(checkpoint),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_root::map_trusted_root;
    use sigstore::bundle::Bundle;

    const REAL_BUNDLE_V03: &str = include_str!("testdata/bundle_v03.json");
    const PRODUCTION_TRUSTED_ROOT: &[u8] = include_bytes!("_trust/trusted_root.json");
    /// The rekor `log_id` of `bundle_v03.json` — equal to the rekor key in the embedded
    /// production trust root, which is *why* this real proof verifies offline.
    const BUNDLE_REKOR_KEY_ID: &str =
        "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d";

    fn parse_bundle() -> Bundle {
        serde_json::from_str(REAL_BUNDLE_V03).expect("fixture bundle must parse")
    }

    fn prod_rekor_key() -> Vec<u8> {
        let root = map_trusted_root(PRODUCTION_TRUSTED_ROOT).expect("prod trust root maps");
        root.rekor_keys
            .get(BUNDLE_REKOR_KEY_ID)
            .expect("bundle's rekor key must be in the embedded trust root")
            .clone()
    }

    fn first_entry(bundle: &Bundle) -> &TransparencyLogEntry {
        bundle
            .verification_material
            .as_ref()
            .expect("verification material")
            .tlog_entries
            .first()
            .expect("one tlog entry")
    }

    #[test]
    fn real_bundle_inclusion_verifies_against_embedded_trust_root() {
        let bundle = parse_bundle();
        let out = verify_entry_inclusion(first_entry(&bundle), &prod_rekor_key());
        assert!(
            matches!(out, AdapterOutcome::Included),
            "real inclusion proof + checkpoint must verify against the real rekor key, got {out:?}"
        );
    }

    #[test]
    fn wrong_rekor_key_is_crypto_invalid() {
        let bundle = parse_bundle();
        // A valid P256 SPKI DER but the wrong key: reuse a CTFE key from the trust root.
        let root = map_trusted_root(PRODUCTION_TRUSTED_ROOT).unwrap();
        let wrong = root.ctfe_keys.values().next().expect("a ctfe key").clone();
        let out = verify_entry_inclusion(first_entry(&bundle), &wrong);
        assert!(
            matches!(out, AdapterOutcome::CryptoInvalid(_)),
            "checkpoint signed by rekor key must not verify under a different key, got {out:?}"
        );
    }

    #[test]
    fn tampered_root_hash_is_crypto_invalid() {
        let mut bundle = parse_bundle();
        // Flip the proof's root_hash: the checkpoint↔proof cross-check must fail.
        let proof = bundle
            .verification_material
            .as_mut()
            .unwrap()
            .tlog_entries
            .get_mut(0)
            .unwrap()
            .inclusion_proof
            .as_mut()
            .unwrap();
        proof.root_hash[0] ^= 0xff;
        let out = verify_entry_inclusion(first_entry(&bundle), &prod_rekor_key());
        assert!(
            matches!(out, AdapterOutcome::CryptoInvalid(_)),
            "a tampered root_hash must fail verification, got {out:?}"
        );
    }

    #[test]
    fn wrong_width_proof_hash_is_malformed() {
        let mut bundle = parse_bundle();
        let proof = bundle
            .verification_material
            .as_mut()
            .unwrap()
            .tlog_entries
            .get_mut(0)
            .unwrap()
            .inclusion_proof
            .as_mut()
            .unwrap();
        proof.root_hash.truncate(31); // no longer 32 bytes
        let out = verify_entry_inclusion(first_entry(&bundle), &prod_rekor_key());
        assert!(
            matches!(out, AdapterOutcome::Malformed(_)),
            "a wrong-width root_hash is a structural (pre-crypto) failure, got {out:?}"
        );
    }

    /// S7 forcing function — a **soft** tripwire so this vendored adapter does not become
    /// permanent unowned debt. It fails (with an actionable message, not a build break) the
    /// moment the pinned `sigstore` version is bumped off the documented floor, prompting a
    /// check of whether upstream wired inclusion into its bundle verifier (sigstore-rs#285;
    /// the step-5 TODO at `verifier.rs:198` this adapter stands in for).
    ///
    /// Crossing the floor is a *proxy* signal, not proof the gap closed — the message says so.
    /// Deliberately a `#[test]`, NOT a `build.rs`/`compile_error!` hard gate (which would block
    /// every contributor over an orthogonal bump and train people to route around it).
    #[test]
    fn sigstore_version_floor_tripwire() {
        /// The `sigstore` version whose bundle verifier still leaves transparency step 5 a
        /// TODO — i.e. the version for which milpa's `rekor_adapter` is required.
        const FLOOR: &str = "=0.14.0";
        let cargo_toml = include_str!("../Cargo.toml");
        let pinned = cargo_toml
            .lines()
            .find(|l| l.trim_start().starts_with("sigstore = "))
            .and_then(|l| l.split("version = \"").nth(1))
            .and_then(|rest| rest.split('"').next())
            .expect("milpa-core Cargo.toml must pin `sigstore` with an explicit version");
        assert_eq!(
            pinned, FLOOR,
            "sigstore was bumped from {FLOOR} to {pinned}. Before accepting this bump, check \
             sigstore-rs#285: if the bundle verifier now wires offline inclusion \
             (verifier.rs step 5), DELETE src/rekor_adapter.rs and call the crate's verifier \
             directly. If it still doesn't, update FLOOR here to the new pinned version."
        );
    }

    #[test]
    fn absent_inclusion_proof_is_malformed_not_fail_open() {
        let mut bundle = parse_bundle();
        bundle
            .verification_material
            .as_mut()
            .unwrap()
            .tlog_entries
            .get_mut(0)
            .unwrap()
            .inclusion_proof = None;
        let out = verify_entry_inclusion(first_entry(&bundle), &prod_rekor_key());
        assert!(
            matches!(out, AdapterOutcome::Malformed(_)),
            "an offline verifier must NOT pass an entry with no inclusion proof, got {out:?}"
        );
    }
}
