//! Unit tests for the 4-state index cache + S6 trust gate.
//!
//! Injected `http_get` + `bundle_http_get` + clock drive each state without a
//! network or wall-clock.  `MockVerifier` drives the crypto side so
//! `SigstoreVerifier` (S4b placeholder) is never invoked.

use super::*;
use std::cell::RefCell;

use crate::index_trust::{
    _reset_warned_urls, IndexTrustConfig, MockVerifier, TrustBundle, VerificationResult,
};
use milpa_manifest::TrustPolicy;

const URL: &str = "https://example.test/index.kdl";
const INDEX: &str = "schema_version 1\npackage \"bar\" {\n    version \"1.0.0\"\n}\n";
const BUNDLE: &[u8] = b"{\"fake\":\"bundle\"}";

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// An http_get that serves `INDEX` bytes and counts calls.
fn counting_get(calls: &RefCell<usize>) -> impl Fn(&str) -> Result<Vec<u8>, String> + '_ {
    move |_url| {
        *calls.borrow_mut() += 1;
        Ok(INDEX.as_bytes().to_vec())
    }
}

/// A bundle_http_get that always returns `BUNDLE`.
fn ok_bundle(_url: &str) -> Result<Vec<u8>, BundleError> {
    Ok(BUNDLE.to_vec())
}

/// A bundle_http_get that always 404s.
fn not_found_bundle(_url: &str) -> Result<Vec<u8>, BundleError> {
    Err(BundleError::NotFound)
}

/// A bundle_http_get that always errors (non-404).
fn err_bundle(_url: &str) -> Result<Vec<u8>, BundleError> {
    Err(BundleError::Other("network error".into()))
}

/// Build an `IndexTrustConfig` for a given policy (test trust bundle + default signer).
fn cfg(policy: TrustPolicy) -> IndexTrustConfig {
    IndexTrustConfig::new(
        policy,
        TrustBundle::test(),
        "https://github.com/test/.github/workflows/test.yaml@refs/heads/main".into(),
    )
}

/// Convenience wrapper: load_index with no trust gate (backwards-compat path).
fn load(
    url: &str,
    cache_dir: &std::path::Path,
    http_get: HttpGet<'_>,
    ttl: u64,
    now: u64,
) -> Result<Index, MilpaError> {
    load_index(url, cache_dir, http_get, ttl, now, None, None, None, false)
}

// ---------------------------------------------------------------------------
// Existing 4-state cache tests (updated for bytes-returning HttpGet)
// ---------------------------------------------------------------------------

#[test]
fn missing_then_fresh_uses_one_fetch() {
    let d = tmp();
    let calls = RefCell::new(0);
    let get = counting_get(&calls);

    // Missing → fetch + populate.
    let idx = load(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000).unwrap();
    assert_eq!(idx.packages.len(), 1);
    assert_eq!(*calls.borrow(), 1);

    // Fresh (age 0 < ttl) → served from cache, no second fetch.
    let idx2 = load(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000).unwrap();
    assert_eq!(idx2.packages.len(), 1);
    assert_eq!(*calls.borrow(), 1, "fresh cache must not re-fetch");
}

#[test]
fn stale_cache_refetches() {
    let d = tmp();
    let calls = RefCell::new(0);
    let get = counting_get(&calls);

    load(URL, d.path(), &get, 100, 1000).unwrap(); // mtime=1000
    assert_eq!(*calls.borrow(), 1);

    // now=1000+100+1 → age 101 >= ttl 100 → stale → refetch.
    load(URL, d.path(), &get, 100, 1101).unwrap();
    assert_eq!(*calls.borrow(), 2, "stale cache must re-fetch");
}

#[test]
fn offline_fallback_serves_stale_cache() {
    let d = tmp();
    // Populate with a working fetch.
    {
        let calls = RefCell::new(0);
        load(URL, d.path(), &counting_get(&calls), 100, 1000).unwrap();
    }
    // Now the network is down AND the cache is stale → fall back to it.
    let failing = |_: &str| -> Result<Vec<u8>, String> { Err("network down".into()) };
    let idx = load(URL, d.path(), &failing, 100, 9999).unwrap();
    assert_eq!(
        idx.packages.len(),
        1,
        "stale-but-available cache beats a hard error"
    );
}

#[test]
fn offline_with_no_cache_is_unreachable() {
    let d = tmp();
    let failing = |_: &str| -> Result<Vec<u8>, String> { Err("network down".into()) };
    let err = load(URL, d.path(), &failing, 100, 1000).unwrap_err();
    assert_eq!(err.code(), "MILPA-INDEX-UNREACHABLE");
}

#[test]
fn fetched_index_parse_errors_surface_tng_codes() {
    let d = tmp();
    let bad = |_: &str| -> Result<Vec<u8>, String> { Ok(b"schema_version 99\n".to_vec()) };
    let err = load(URL, d.path(), &bad, 100, 1000).unwrap_err();
    assert_eq!(err.code(), "TNG-SCHEMA-UNKNOWN");
}

#[test]
fn cache_path_is_stable_and_url_derived() {
    let d = tmp();
    let a = cache_path_for(URL, d.path());
    let b = cache_path_for(URL, d.path());
    assert_eq!(a, b);
    assert_ne!(a, cache_path_for("https://other.test/index.kdl", d.path()));
    assert!(a.to_string_lossy().ends_with(".index.kdl"));
}

#[test]
fn index_url_from_env_defaults_without_override() {
    std::env::remove_var("MILPA_INDEX_URL");
    assert_eq!(index_url_from_env(), DEFAULT_INDEX_URL);
}

// ---------------------------------------------------------------------------
// Bundle URL derivation (RFC §7.3)
// ---------------------------------------------------------------------------

#[test]
fn derive_bundle_url_plain() {
    assert_eq!(
        derive_bundle_url("https://host/index.kdl"),
        "https://host/index.kdl.bundle"
    );
}

#[test]
fn derive_bundle_url_with_query() {
    assert_eq!(
        derive_bundle_url("https://host/index.kdl?ref=main"),
        "https://host/index.kdl.bundle?ref=main"
    );
}

#[test]
fn derive_bundle_url_with_fragment() {
    assert_eq!(
        derive_bundle_url("https://host/index.kdl#frag"),
        "https://host/index.kdl.bundle#frag"
    );
}

#[test]
fn derive_bundle_url_with_query_and_fragment() {
    assert_eq!(
        derive_bundle_url("https://host/index.kdl?ref=main#frag"),
        "https://host/index.kdl.bundle?ref=main#frag"
    );
}

// ---------------------------------------------------------------------------
// S6: trust gate — policy Off (no-op gate)
// ---------------------------------------------------------------------------

#[test]
fn trust_off_ignores_bundle_entirely() {
    // With policy=Off the gate must be inactive even when verifier is provided.
    // We pass a verifier that would panic if called, to confirm it's never invoked.
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());

    struct PanicVerifier;
    impl IndexBundleVerifier for PanicVerifier {
        fn verify(
            &self,
            _: &[u8],
            _: &[u8],
            _: &crate::index_trust::TrustBundle,
            _: &str,
            _: Option<u64>,
        ) -> VerificationResult {
            panic!("verifier must not be called when policy=Off")
        }
    }

    let result = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Off)),
        Some(&PanicVerifier),
        Some(&ok_bundle as BundleHttpGet<'_>),
        false,
    );
    assert!(result.is_ok(), "trust-off must never raise: {:?}", result);
}

// ---------------------------------------------------------------------------
// S6: trust gate — Warn policy
// ---------------------------------------------------------------------------

#[test]
fn warn_trusted_is_silent() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::Trusted);

    let result = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Warn)),
        Some(&mock),
        Some(&ok_bundle as BundleHttpGet<'_>),
        false,
    );
    assert!(result.is_ok(), "Trusted + Warn must succeed: {:?}", result);
}

#[test]
fn warn_sig_invalid_does_not_raise() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::SigInvalid);

    let result = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Warn)),
        Some(&mock),
        Some(&ok_bundle as BundleHttpGet<'_>),
        false,
    );
    // Warn policy: warning printed but no error raised.
    assert!(
        result.is_ok(),
        "SigInvalid + Warn must NOT raise: {:?}",
        result
    );
}

#[test]
fn warn_bundle_missing_404_writes_no_bundle_marker() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::Trusted);

    // Bundle 404 → should write .no-bundle marker under Warn.
    let result = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Warn)),
        Some(&mock),
        Some(&not_found_bundle as BundleHttpGet<'_>),
        false,
    );
    assert!(result.is_ok(), "bundle 404 + Warn must not raise: {:?}", result);

    // .no-bundle marker must be on disk.
    let cache_file = cache_path_for(URL, d.path());
    assert!(
        no_bundle_marker_path(&cache_file).exists(),
        ".no-bundle marker must be written under Warn when bundle 404s"
    );
    // .bundle sidecar must NOT be present.
    assert!(
        !bundle_path(&cache_file).exists(),
        ".bundle must not be written when the server 404s"
    );
}

// ---------------------------------------------------------------------------
// S6: trust gate — Strict policy
// ---------------------------------------------------------------------------

#[test]
fn strict_trusted_succeeds() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::Trusted);

    let result = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Strict)),
        Some(&mock),
        Some(&ok_bundle as BundleHttpGet<'_>),
        false,
    );
    assert!(result.is_ok(), "Trusted + Strict must succeed: {:?}", result);
}

#[test]
fn strict_sig_invalid_raises() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::SigInvalid);

    let err = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Strict)),
        Some(&mock),
        Some(&ok_bundle as BundleHttpGet<'_>),
        false,
    )
    .unwrap_err();
    assert_eq!(err.code(), "TNG-INDEX-SIGNATURE-INVALID");
}

#[test]
fn strict_digest_mismatch_raises() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::DigestMismatch);

    let err = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Strict)),
        Some(&mock),
        Some(&ok_bundle as BundleHttpGet<'_>),
        false,
    )
    .unwrap_err();
    assert_eq!(err.code(), "TNG-INDEX-DIGEST-MISMATCH");
}

#[test]
fn strict_signer_mismatch_raises() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::SignerMismatch);

    let err = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Strict)),
        Some(&mock),
        Some(&ok_bundle as BundleHttpGet<'_>),
        false,
    )
    .unwrap_err();
    assert_eq!(err.code(), "TNG-INDEX-SIGNER-MISMATCH");
}

#[test]
fn strict_bundle_stale_raises() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::BundleStale);

    let err = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Strict)),
        Some(&mock),
        Some(&ok_bundle as BundleHttpGet<'_>),
        false,
    )
    .unwrap_err();
    assert_eq!(err.code(), "TNG-INDEX-BUNDLE-STALE");
}

#[test]
fn strict_bundle_malformed_raises() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::BundleMalformed);

    let err = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Strict)),
        Some(&mock),
        Some(&ok_bundle as BundleHttpGet<'_>),
        false,
    )
    .unwrap_err();
    assert_eq!(err.code(), "TNG-INDEX-BUNDLE-MALFORMED");
}

#[test]
fn strict_bundle_404_raises_bundle_missing() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::Trusted);

    let err = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Strict)),
        Some(&mock),
        Some(&not_found_bundle as BundleHttpGet<'_>),
        false,
    )
    .unwrap_err();
    assert_eq!(err.code(), "TNG-INDEX-BUNDLE-MISSING");
}

// ---------------------------------------------------------------------------
// S6: --refresh-index forces re-fetch bypassing TTL
// ---------------------------------------------------------------------------

#[test]
fn refresh_flag_bypasses_fresh_cache() {
    let d = tmp();
    let calls = RefCell::new(0);
    let get = counting_get(&calls);

    // Populate fresh cache.
    load(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000).unwrap();
    assert_eq!(*calls.borrow(), 1);

    // --refresh-index: even though still within TTL, must re-fetch.
    load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        None,
        None,
        None,
        true, // refresh=true
    )
    .unwrap();
    assert_eq!(*calls.borrow(), 2, "--refresh-index must bypass TTL");
}

// ---------------------------------------------------------------------------
// S6: fresh-cache bundle verification (crypto on every read)
// ---------------------------------------------------------------------------

#[test]
fn fresh_cache_still_verifies_bundle() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock_ok = MockVerifier::new(VerificationResult::Trusted);

    // First fetch: Trusted — populate cache + bundle sidecar.
    load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Strict)),
        Some(&mock_ok),
        Some(&ok_bundle as BundleHttpGet<'_>),
        false,
    )
    .unwrap();

    // Second read from fresh cache with a SigInvalid verifier — must still raise.
    let mock_bad = MockVerifier::new(VerificationResult::SigInvalid);
    let err = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000, // same timestamp → still fresh
        Some(&cfg(TrustPolicy::Strict)),
        Some(&mock_bad),
        Some(&ok_bundle as BundleHttpGet<'_>),
        false,
    )
    .unwrap_err();
    assert_eq!(
        err.code(),
        "TNG-INDEX-SIGNATURE-INVALID",
        "fresh-cache read must re-verify the bundle"
    );
}
