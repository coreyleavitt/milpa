//! Standard Sigstore `trusted_root.json` → [`ManualTrustRoot`] mapper (RFC
//! `rfc-attestation-verifier` S1.5).
//!
//! milpa embeds the production Sigstore trust material in the **standard**
//! `trusted_root.json` format (`src/_trust/trusted_root.json`) rather than a
//! milpa-invented schema. This module reshapes those bytes into the
//! `sigstore::trust::ManualTrustRoot` the high-level `Verifier` (S2) consumes —
//! **no cryptographic operation**, pure data reshaping (§5.1 hand-roll-vs-delegate).
//!
//! It mirrors sigstore-rs's own `SigstoreTrustRoot::{fulcio_certs, rekor_keys,
//! ctfe_keys}` (`trust/sigstore/mod.rs`) with **one deliberate divergence**: this
//! mapper does **not** time-filter keys/certs to "valid now". milpa verifies a
//! bundle offline at the bundle's own `integratedTime`, and looks Rekor keys up by
//! explicit `hex(log_id.key_id)` — so a bundle signed under a now-rotated key must
//! still resolve its (possibly expired) key. Time-filtering would silently drop
//! historical keys and break offline verification of older bundles. The append-only
//! retention discipline in S1.5 (keep old material on rotation) depends on this.
//!
//! Runtime stays free of the `sigstore-trust-root` crate feature (tough + futures +
//! async-trait): that feature is for online TUF fetch, which milpa does at build
//! material-population time only (`examples/populate_trust_root.rs`), never at runtime.

use std::collections::BTreeMap;

use rustls_pki_types::CertificateDer;
use sigstore::trust::ManualTrustRoot;
use sigstore_protobuf_specs::dev::sigstore::trustroot::v1::{TransparencyLogInstance, TrustedRoot};

use crate::error::{CoreError, MilpaError};

/// Reshape standard `trusted_root.json` bytes into a [`ManualTrustRoot`].
///
/// - **Fulcio certs** — every CA's full cert chain, expired included (a cert may
///   have been valid when a historical bundle was signed). Empty ⇒ error: a trust
///   root with no Fulcio CA cannot anchor any verification.
/// - **Rekor / CTFE keys** — every tlog / ctlog instance, keyed by
///   `hex(log_id.key_id)` (the exact convention S2's inclusion adapter uses for
///   per-entry key lookup — §4 Rekor-key-lookup contract), value = raw SPKI DER.
///
/// The embedded production trust root is committed and known-good, so a parse/shape
/// failure here is a milpa packaging invariant violation, surfaced as the
/// `MILPA-INTERNAL` sentinel — **not** a `TNG-INDEX-*` slug (those describe the
/// attestation bundle + policy, a distinct concern). Never panics.
pub(crate) fn map_trusted_root(json: &[u8]) -> Result<ManualTrustRoot<'static>, MilpaError> {
    let root: TrustedRoot = serde_json::from_slice(json).map_err(|e| {
        MilpaError::Core(CoreError::Tianguis(
            "MILPA-INTERNAL",
            format!("embedded Sigstore trust root is not valid trusted_root.json: {e}"),
        ))
    })?;

    let fulcio_certs: Vec<CertificateDer<'static>> = root
        .certificate_authorities
        .iter()
        .flat_map(|ca| ca.cert_chain.as_ref())
        .flat_map(|chain| chain.certificates.iter())
        .map(|cert| CertificateDer::from(cert.raw_bytes.clone()).into_owned())
        .collect();

    if fulcio_certs.is_empty() {
        return Err(MilpaError::Core(CoreError::Tianguis(
            "MILPA-INTERNAL",
            "embedded Sigstore trust root contains no Fulcio CA certificates".to_string(),
        )));
    }

    Ok(ManualTrustRoot {
        fulcio_certs,
        rekor_keys: collect_tlog_keys(&root.tlogs),
        ctfe_keys: collect_tlog_keys(&root.ctlogs),
    })
}

/// Collect `(hex(key_id) → raw SPKI DER)` for every tlog/ctlog instance that carries
/// both a `log_id` and a `public_key.raw_bytes`. No time filter (see module note).
fn collect_tlog_keys(tlogs: &[TransparencyLogInstance]) -> BTreeMap<String, Vec<u8>> {
    tlogs
        .iter()
        .filter_map(|tlog| {
            let key_id = tlog
                .log_id
                .as_ref()
                .map(|log_id| hex::encode(log_id.key_id.as_slice()))?;
            let raw = tlog
                .public_key
                .as_ref()
                .and_then(|pk| pk.raw_bytes.as_ref())?;
            Some((key_id, raw.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real embedded production trust root — the exact bytes S2's verifier maps.
    const PRODUCTION_TRUSTED_ROOT: &[u8] = include_bytes!("_trust/trusted_root.json");

    /// The rekor `log_id.key_id` present in the embedded production trust root, hex.
    /// Pinned so a silent trust-root swap that drops the rekor key fails loudly.
    const PROD_REKOR_KEY_ID: &str =
        "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d";

    #[test]
    fn maps_production_trusted_root_to_nonempty_materials() {
        let root = map_trusted_root(PRODUCTION_TRUSTED_ROOT).expect("prod trust root must map");
        // 3 Fulcio certs, 1 rekor key, 2 CTFE keys in this snapshot.
        assert_eq!(root.fulcio_certs.len(), 3, "fulcio cert chain count");
        assert_eq!(root.rekor_keys.len(), 1, "rekor key count");
        assert_eq!(root.ctfe_keys.len(), 2, "ctfe key count");
    }

    #[test]
    fn rekor_key_is_keyed_by_hex_log_id() {
        let root = map_trusted_root(PRODUCTION_TRUSTED_ROOT).unwrap();
        let key = root
            .rekor_keys
            .get(PROD_REKOR_KEY_ID)
            .expect("rekor key must be looked up by hex(log_id.key_id) — the S2 adapter contract");
        assert!(!key.is_empty(), "rekor key SPKI DER must be non-empty");
    }

    #[test]
    fn malformed_trusted_root_is_internal_not_tng_slug() {
        let err = map_trusted_root(b"{ not json").unwrap_err();
        assert_eq!(
            err.code(),
            "MILPA-INTERNAL",
            "a malformed embedded trust root is a packaging invariant, not a TNG-INDEX-* error"
        );
    }

    #[test]
    fn empty_trusted_root_rejected_for_missing_fulcio() {
        // Structurally valid JSON, but no CAs / tlogs.
        let err = map_trusted_root(br#"{"mediaType":"x","tlogs":[],"certificateAuthorities":[],"ctlogs":[]}"#)
            .unwrap_err();
        assert_eq!(err.code(), "MILPA-INTERNAL");
        let MilpaError::Core(CoreError::Tianguis(_, msg)) = &err else {
            panic!("expected CoreError::Tianguis, got {err:?}");
        };
        assert!(msg.contains("no Fulcio CA"), "message was: {msg}");
    }
}
