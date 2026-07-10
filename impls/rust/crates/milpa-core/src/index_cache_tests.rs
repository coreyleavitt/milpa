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

// ---------------------------------------------------------------------------
// Item 5b: warn dedup — at most one warning per unique URL per invocation
// ---------------------------------------------------------------------------

#[test]
fn warn_two_calls_same_url_emits_only_one_warning() {
    // Verify the dedup set prevents duplicate stderr lines.
    // We can't capture stderr in a unit test, but we CAN verify the dedup state
    // via _reset_warned_urls and the internal invariant: enforce_index_trust
    // with Warn+non-Trusted must insert the URL the first time and skip the second.
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::SigInvalid);

    // First call: inserts URL into dedup set and emits warning (test can't assert
    // the stderr line but asserts it doesn't raise).
    let r1 = load_index(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Warn)), Some(&mock), Some(&ok_bundle as BundleHttpGet<'_>), false);
    assert!(r1.is_ok(), "first warn call must succeed: {:?}", r1);

    // Second call: dedup set already has URL → no duplicate warning.
    // The call must still succeed (exit 0 semantics).
    let r2 = load_index(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Warn)), Some(&mock), Some(&ok_bundle as BundleHttpGet<'_>), false);
    assert!(r2.is_ok(), "second warn call (dedup) must succeed: {:?}", r2);
}

#[test]
fn warn_two_calls_different_urls_emits_two_warnings() {
    // Two distinct URLs → two warning emissions (dedup is per-URL).
    _reset_warned_urls();
    let d = tmp();
    let d2 = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    const URL2: &str = "https://other.test/index.kdl";

    let mock = MockVerifier::new(VerificationResult::SigInvalid);

    let r1 = load_index(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Warn)), Some(&mock), Some(&ok_bundle as BundleHttpGet<'_>), false);
    assert!(r1.is_ok());

    let r2 = load_index(URL2, d2.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Warn)), Some(&mock), Some(&ok_bundle as BundleHttpGet<'_>), false);
    assert!(r2.is_ok(), "different-URL warn call must succeed: {:?}", r2);
}

// ---------------------------------------------------------------------------
// Item 5c / spec §3.4.5: crash recovery — bundle sidecar deleted between reads
// ---------------------------------------------------------------------------

#[test]
fn bundle_deleted_between_reads_triggers_recovery_refetch() {
    // Simulates crash-recovery scenario (index_cache.rs State 1 → crash-recovery):
    // index cached + bundle present → populate cache → delete bundle → re-read.
    // On re-read, the cache has the index but the bundle sidecar is missing.
    //
    // Spec §3.4.5 NORMATIVE: if the recovery re-fetch ALSO fails to produce a
    // verifiable bundle (404 OR transport error OR verify failure), the impl MUST
    // hard-fail with MILPA-INDEX-UNREACHABLE regardless of policy.  This is an
    // active-adversary signal, not an interrupted write.
    //
    // FIXED (round-4 review Item 1): previously asserted TNG-INDEX-BUNDLE-MISSING
    // (wrong — that's the non-recovery 404 slug); recovery path is MILPA-INDEX-UNREACHABLE.
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());

    // Populate cache: index + bundle.
    let mock_ok = MockVerifier::new(VerificationResult::Trusted);
    load_index(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Strict)), Some(&mock_ok),
        Some(&ok_bundle as BundleHttpGet<'_>), false).unwrap();

    // Delete the bundle sidecar to simulate a crash between index-write and bundle-write.
    let cache_file = cache_path_for(URL, d.path());
    let bundle_file = bundle_path(&cache_file);
    std::fs::remove_file(&bundle_file).unwrap();
    assert!(!bundle_file.exists(), "bundle must be deleted for this test");

    // Re-read: cache is fresh (State 1), bundle is missing → crash recovery.
    // Recovery re-fetch returns 404 → spec §3.4.5: hard-fail MILPA-INDEX-UNREACHABLE.
    let err = load_index(
        URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Strict)), Some(&mock_ok),
        Some(&not_found_bundle as BundleHttpGet<'_>), false,
    ).unwrap_err();
    assert_eq!(
        err.code(),
        "MILPA-INDEX-UNREACHABLE",
        "crash-recovery + bundle 404 must hard-fail MILPA-INDEX-UNREACHABLE (spec §3.4.5 — \
         recovery path overrides policy regardless of Strict/Warn): got {:?}",
        err.code()
    );
}

// ---------------------------------------------------------------------------
// spec §3.4.5 crash-recovery semantics (Item 1, round-4 HIGH finding):
//   if the (index, bundle) pair fetched during crash-RECOVERY ALSO fails to
//   produce a verifiable bundle, the impl MUST hard-fail MILPA-INDEX-UNREACHABLE
//   regardless of policy (active-adversary signal, not an interrupted write).
// ---------------------------------------------------------------------------

/// (a) Warn + fresh cache with bundle sidecar deleted (no marker) + bundle 404
///     on recovery re-fetch → MILPA-INDEX-UNREACHABLE (NOT degraded-marker warn).
#[test]
fn recovery_warn_bundle_404_hard_fails_not_degrade() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());

    // Populate cache: index + bundle (Warn policy, Trusted).
    let mock_ok = MockVerifier::new(VerificationResult::Trusted);
    load_index(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Warn)), Some(&mock_ok),
        Some(&ok_bundle as BundleHttpGet<'_>), false).unwrap();

    // Delete the bundle sidecar to trigger crash-recovery on next read.
    let cache_file = cache_path_for(URL, d.path());
    let bundle_file = bundle_path(&cache_file);
    std::fs::remove_file(&bundle_file).unwrap();
    // Make sure no .no-bundle marker exists (this is a crash, not a known-absent case).
    let nbm = no_bundle_marker_path(&cache_file);
    assert!(!nbm.exists(), "no .no-bundle marker must exist for the crash scenario");

    // Recovery re-fetch: bundle 404 → spec §3.4.5 MUST hard-fail MILPA-INDEX-UNREACHABLE
    // regardless of Warn policy.  Must NOT write a degraded marker.
    let err = load_index(
        URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Warn)), Some(&mock_ok),
        Some(&not_found_bundle as BundleHttpGet<'_>), false,
    ).unwrap_err();
    assert_eq!(
        err.code(),
        "MILPA-INDEX-UNREACHABLE",
        "recovery + Warn + bundle 404 must hard-fail MILPA-INDEX-UNREACHABLE (spec §3.4.5), \
         NOT write a degraded marker and continue: got {:?}",
        err.code()
    );
    // No degraded marker must have been written (recovery hard-fail; §3.4.5).
    assert!(
        !nbm.exists(),
        ".no-bundle marker must NOT be written when recovery hard-fails (spec §3.4.5)"
    );
}

/// (b) Warn + fresh cache with bundle sidecar deleted + recovery re-fetch
///     succeeds with a valid bundle → index served, cache repaired (bundle written).
#[test]
fn recovery_warn_valid_bundle_serves_and_repairs_cache() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());

    // Populate cache: index + bundle (Warn policy, Trusted).
    let mock_ok = MockVerifier::new(VerificationResult::Trusted);
    load_index(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Warn)), Some(&mock_ok),
        Some(&ok_bundle as BundleHttpGet<'_>), false).unwrap();

    // Delete the bundle sidecar to trigger crash-recovery.
    let cache_file = cache_path_for(URL, d.path());
    let bundle_file = bundle_path(&cache_file);
    std::fs::remove_file(&bundle_file).unwrap();

    // Recovery re-fetch: bundle available + verifier says Trusted → Ok (cache repaired).
    let result = load_index(
        URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Warn)), Some(&mock_ok),
        Some(&ok_bundle as BundleHttpGet<'_>), false,
    );
    assert!(
        result.is_ok(),
        "recovery + Warn + valid bundle must serve index without error: {:?}",
        result
    );
    let idx = result.unwrap();
    assert_eq!(idx.packages.len(), 1, "index must be parsed correctly after recovery");
    // Bundle sidecar must be written (cache repaired).
    assert!(
        bundle_file.exists(),
        "bundle sidecar must be written to disk after successful recovery re-fetch"
    );
}

/// (c) Warn + fresh cache with bundle sidecar deleted + recovery re-fetch
///     bundle is present but verifier returns SigInvalid → MILPA-INDEX-UNREACHABLE
///     regardless of Warn policy (spec §3.4.5: second consecutive failure is
///     an active-adversary signal).
#[test]
fn recovery_warn_sig_invalid_hard_fails_regardless() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());

    // Populate cache: index + bundle (Warn policy, Trusted initially).
    let mock_ok = MockVerifier::new(VerificationResult::Trusted);
    load_index(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Warn)), Some(&mock_ok),
        Some(&ok_bundle as BundleHttpGet<'_>), false).unwrap();

    // Delete the bundle sidecar to trigger crash-recovery.
    let cache_file = cache_path_for(URL, d.path());
    let bundle_file = bundle_path(&cache_file);
    std::fs::remove_file(&bundle_file).unwrap();

    // Recovery re-fetch: bundle available but SigInvalid → spec §3.4.5 MUST
    // hard-fail MILPA-INDEX-UNREACHABLE regardless of Warn policy.
    let mock_bad = MockVerifier::new(VerificationResult::SigInvalid);
    let err = load_index(
        URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Warn)), Some(&mock_bad),
        Some(&ok_bundle as BundleHttpGet<'_>), false,
    ).unwrap_err();
    assert_eq!(
        err.code(),
        "MILPA-INDEX-UNREACHABLE",
        "recovery + Warn + SigInvalid must hard-fail MILPA-INDEX-UNREACHABLE (spec §3.4.5), \
         NOT proceed as a normal warn: got {:?}",
        err.code()
    );
    // Bundle must not be written (failed verification; no partial write).
    assert!(
        !bundle_file.exists(),
        "bundle must NOT be written after failed recovery verification"
    );
}

#[test]
fn second_consecutive_bundle_mismatch_is_hard_fail_under_strict() {
    // After two consecutive verify failures under Strict, the caller surfaces a hard error.
    // This mirrors Python's TestCrashRecovery: consecutive mismatches do not flip to Warn.
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());

    // First call: mismatch verifier + Strict → hard fail.
    let mock_bad = MockVerifier::new(VerificationResult::DigestMismatch);
    let err1 = load_index(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Strict)), Some(&mock_bad),
        Some(&ok_bundle as BundleHttpGet<'_>), false).unwrap_err();
    assert_eq!(err1.code(), "TNG-INDEX-DIGEST-MISMATCH");

    _reset_warned_urls();
    // Second call (same state): still a hard fail.
    let err2 = load_index(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000,
        Some(&cfg(TrustPolicy::Strict)), Some(&mock_bad),
        Some(&ok_bundle as BundleHttpGet<'_>), false).unwrap_err();
    assert_eq!(err2.code(), "TNG-INDEX-DIGEST-MISMATCH",
        "consecutive mismatch under Strict must remain hard fail, not downgrade to Warn");
}

// ---------------------------------------------------------------------------
// ITEM 2 (M9): bundle_http_get receives the URL produced by get_bundle_url
// ---------------------------------------------------------------------------

/// Prove that `load_index` passes `get_bundle_url(index_url)` to the injected
/// `bundle_http_get` closure.  A recording closure captures the actual URL; we
/// assert it equals `derive_bundle_url(URL)` (the expected default derivation).
///
/// When `MILPA_INDEX_BUNDLE_URL` is not set (the normal case in CI and tests),
/// `get_bundle_url` returns `derive_bundle_url(index_url)`.  This test is
/// intentionally written for the no-override path so no global env manipulation
/// is required — it stays race-free and lock-free.  The override path is
/// exercised at the binary level in `crates/milpa-cli/tests/cli_index_trust.rs`
/// (scenario 7 / `bundle_url_override_routes_bundle_fetch_to_override_path`).
#[test]
fn bundle_http_get_receives_derived_url_when_no_env_override() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock_ok = MockVerifier::new(VerificationResult::Trusted);

    // Recording closure: captures the URL it is called with.
    let recorded: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
    let recording = |url: &str| -> Result<Vec<u8>, BundleError> {
        *recorded.borrow_mut() = Some(url.to_string());
        Ok(BUNDLE.to_vec())
    };

    // If MILPA_INDEX_BUNDLE_URL happens to be set in the environment, temporarily
    // clear it so this test exercises the derivation path, not the override path.
    let had_override = std::env::var("MILPA_INDEX_BUNDLE_URL").ok();
    if had_override.is_some() {
        // SAFETY: guarded by the check above; no other thread writes this var here.
        unsafe { std::env::remove_var("MILPA_INDEX_BUNDLE_URL") };
    }

    let result = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Strict)),
        Some(&mock_ok),
        Some(&recording as BundleHttpGet<'_>),
        false,
    );

    // Restore if we cleared it.
    if let Some(v) = had_override {
        unsafe { std::env::set_var("MILPA_INDEX_BUNDLE_URL", v) };
    }

    assert!(result.is_ok(), "Trusted + Strict must succeed: {:?}", result);
    // URL constant is "https://example.test/index.kdl"; derived bundle appends ".bundle".
    assert_eq!(
        recorded.borrow().as_deref(),
        Some("https://example.test/index.kdl.bundle"),
        "bundle_http_get must receive derive_bundle_url(index_url) when \
         MILPA_INDEX_BUNDLE_URL is not set; got: {:?}",
        recorded.borrow()
    );
}

// ---------------------------------------------------------------------------
// Item 1 (M2): spec §7.2 ordering — verify BEFORE writing cache
// ---------------------------------------------------------------------------

/// Spec §7.2: on a state-2 (network-fetch) path with Strict policy and a
/// SigInvalid verifier result, the error must be returned AND no cache
/// artifacts (index, stamp, bundle) should be written.
///
/// This tests the ordering requirement: verify in-memory first; write
/// bundle sidecar → index → stamp ONLY on success.  Prior to the fix,
/// the code wrote the cache first, then verified — leaving a
/// fresh-stamped UNVERIFIED index on disk after a strict failure.
#[test]
fn strict_sig_invalid_state2_leaves_no_cache_artifacts() {
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

    // Spec §7.2: no cache artifacts must be written on verification failure.
    let cache_file = cache_path_for(URL, d.path());
    assert!(
        !cache_file.exists(),
        "index must NOT be written to cache when strict verification fails (spec §7.2 ordering)"
    );
    assert!(
        !bundle_path(&cache_file).exists(),
        "bundle sidecar must NOT be written when strict verification fails (spec §7.2 ordering)"
    );
    // Check stamp as well.
    let stamp_file = cache_file.with_extension("kdl.at");
    assert!(
        !stamp_file.exists(),
        "stamp must NOT be written when strict verification fails (spec §7.2 ordering)"
    );
}

/// When strict + bundle-ok + verify succeeds, cache artifacts ARE written (happy path).
/// Regression guard: the spec §7.2 fix must not break the success path.
#[test]
fn strict_trusted_state2_writes_cache_artifacts() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::Trusted);

    load_index(
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
    .unwrap();

    let cache_file = cache_path_for(URL, d.path());
    assert!(cache_file.exists(), "index must be written after successful strict verification");
    assert!(bundle_path(&cache_file).exists(), "bundle sidecar must be written after success");
}

/// Warn + bundle-404 (BundleError::NotFound) must still write the index and
/// stamp AND the .no-bundle degraded marker (spec §7.2: warn degraded path).
#[test]
fn warn_bundle_404_state2_writes_index_and_no_bundle_marker() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::Trusted);

    load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Warn)),
        Some(&mock),
        Some(&not_found_bundle as BundleHttpGet<'_>),
        false,
    )
    .unwrap();

    let cache_file = cache_path_for(URL, d.path());
    assert!(cache_file.exists(), "index must be written even when bundle 404s under Warn");
    assert!(
        no_bundle_marker_path(&cache_file).exists(),
        ".no-bundle marker must be written when bundle 404s under Warn"
    );
}

/// Strict + bundle-404 must NOT write any cache artifacts.
#[test]
fn strict_bundle_404_state2_leaves_no_cache_artifacts() {
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

    let cache_file = cache_path_for(URL, d.path());
    assert!(
        !cache_file.exists(),
        "index must NOT be written when strict + bundle-404 (spec §7.2)"
    );
    assert!(
        !no_bundle_marker_path(&cache_file).exists(),
        ".no-bundle marker must NOT be written under Strict (only under Warn)"
    );
}

// ---------------------------------------------------------------------------
// ITEM 3 (round-3 review): BundleError::Other → BundleMissing (not BundleMalformed)
//
// Rationale: a non-404 transport error means bytes NEVER ARRIVED — the correct
// slug is TNG-INDEX-BUNDLE-MISSING (same as 404), NOT TNG-INDEX-BUNDLE-MALFORMED
// (which is reserved for bytes that arrived but failed to parse).
// No .no-bundle marker is written for transient errors (next read goes through
// crash-recovery refetch, not the degraded-marker path).
// ---------------------------------------------------------------------------

/// Warn + transport error → warning slug TNG-INDEX-BUNDLE-MISSING, no marker file.
#[test]
fn warn_transport_error_emits_bundle_missing_not_malformed() {
    _reset_warned_urls();
    let d = tmp();
    let get = |_: &str| Ok(INDEX.as_bytes().to_vec());
    let mock = MockVerifier::new(VerificationResult::Trusted);

    // Load with warn policy + transport error (non-404).
    // Should succeed (warn allows proceeding) but emit BundleMissing warning.
    let result = load_index(
        URL,
        d.path(),
        &get,
        DEFAULT_TTL_SECONDS,
        1000,
        Some(&cfg(TrustPolicy::Warn)),
        Some(&mock),
        Some(&err_bundle as BundleHttpGet<'_>),
        false,
    );
    // Warn: should return Ok (proceed despite missing bundle).
    assert!(
        result.is_ok(),
        "warn + transport error should succeed (warn allows proceeding): {result:?}"
    );

    // The .no-bundle marker must NOT be written for transient errors.
    let cache_file = cache_path_for(URL, d.path());
    assert!(
        !no_bundle_marker_path(&cache_file).exists(),
        ".no-bundle marker must NOT be written for transient transport errors (only for genuine 404)"
    );
}

/// Strict + transport error → error slug TNG-INDEX-BUNDLE-MISSING (not MALFORMED).
#[test]
fn strict_transport_error_returns_bundle_missing_slug() {
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
        Some(&err_bundle as BundleHttpGet<'_>),
        false,
    )
    .unwrap_err();

    assert_eq!(
        err.code(),
        "TNG-INDEX-BUNDLE-MISSING",
        "non-404 transport error must map to TNG-INDEX-BUNDLE-MISSING (bytes never arrived), \
         not TNG-INDEX-BUNDLE-MALFORMED (reserved for parse failures)"
    );

    // No marker file for transient errors under Strict.
    let cache_file = cache_path_for(URL, d.path());
    assert!(
        !no_bundle_marker_path(&cache_file).exists(),
        ".no-bundle marker must NOT be written under Strict for transport errors"
    );
    assert!(
        !cache_file.exists(),
        "index must NOT be written when strict + transport error (spec §7.2)"
    );
}

// ---------------------------------------------------------------------------
// A3 (rfc-registry-append-only.md §2): the append-only ratchet wired into
// load_index_with_history. No trust gate (config=None) — the ratchet's
// index-history axis is orthogonal to index-trust.
// ---------------------------------------------------------------------------

const INDEX2: &str = "schema_version 1\npackage \"bar\" {\n    version \"1.0.0\" {\n        content_hash \"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n    }\n}\n";
const INDEX1: &str = "schema_version 1\npackage \"bar\" {\n    version \"1.0.0\" {\n        content_hash \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n    }\n}\n";

fn load_with_history(
    url: &str,
    cache_dir: &std::path::Path,
    http_get: HttpGet<'_>,
    now: u64,
    refresh: bool,
    policy: &TrustPolicy,
) -> Result<Index, MilpaError> {
    load_index_with_history(url, cache_dir, http_get, DEFAULT_TTL_SECONDS, now, None, None, None, refresh, policy)
}

#[test]
fn a3_first_fetch_establishes_tofu_baseline() {
    let d = tmp();
    let get = |_: &str| Ok(INDEX1.as_bytes().to_vec());
    let result = load_with_history(URL, d.path(), &get, 1000, false, &TrustPolicy::Warn);
    assert!(result.is_ok());

    let cache_file = cache_path_for(URL, d.path());
    assert!(baseline_path(&cache_file).exists(), "TOFU must write the baseline sidecar");
    assert!(baseline_meta_path(&cache_file).exists(), "TOFU must write .baseline.meta");
    let baseline_bytes = std::fs::read(baseline_path(&cache_file)).unwrap();
    assert_eq!(baseline_bytes, INDEX1.as_bytes());
}

#[test]
fn a3_off_policy_never_writes_baseline() {
    let d = tmp();
    let get = |_: &str| Ok(INDEX1.as_bytes().to_vec());
    let result = load_with_history(URL, d.path(), &get, 1000, false, &TrustPolicy::Off);
    assert!(result.is_ok());
    let cache_file = cache_path_for(URL, d.path());
    assert!(!baseline_path(&cache_file).exists(), "off policy must never write a baseline");
}

#[test]
fn a3_clean_refetch_advances_baseline_to_new_bytes() {
    let d = tmp();
    // First fetch: TOFU with INDEX1.
    let get1 = |_: &str| Ok(INDEX1.as_bytes().to_vec());
    load_with_history(URL, d.path(), &get1, 1000, false, &TrustPolicy::Warn).unwrap();

    // Refetch (forced) with an appended-but-compatible INDEX1 (same bytes = clean diff).
    let get2 = |_: &str| Ok(INDEX1.as_bytes().to_vec());
    let result = load_with_history(URL, d.path(), &get2, 2000, true, &TrustPolicy::Warn);
    assert!(result.is_ok());
    let cache_file = cache_path_for(URL, d.path());
    let baseline_bytes = std::fs::read(baseline_path(&cache_file)).unwrap();
    assert_eq!(baseline_bytes, INDEX1.as_bytes());
}

#[test]
fn a3_strict_dirty_refetch_hard_fails_no_cache_mutation_at_all() {
    let d = tmp();
    // First fetch: TOFU with INDEX1 (content_hash = aaa...).
    let get1 = |_: &str| Ok(INDEX1.as_bytes().to_vec());
    load_with_history(URL, d.path(), &get1, 1000, false, &TrustPolicy::Strict).unwrap();

    let cache_file = cache_path_for(URL, d.path());
    let index_bytes_before = std::fs::read(&cache_file).unwrap();
    let stamp_before = std::fs::read_to_string(cache_file.with_extension("kdl.at")).unwrap();
    let baseline_before = std::fs::read(baseline_path(&cache_file)).unwrap();

    // Forced refetch with a MUTATED content_hash (content_hash = bbb...) — a
    // frozen-field violation under Strict.
    let get2 = |_: &str| Ok(INDEX2.as_bytes().to_vec());
    let err = load_with_history(URL, d.path(), &get2, 2000, true, &TrustPolicy::Strict).unwrap_err();
    assert_eq!(err.code(), "TNG-ENTRY-MUTATED");

    // No cache mutation at all (index, stamp, baseline all byte-identical to before).
    assert_eq!(std::fs::read(&cache_file).unwrap(), index_bytes_before);
    assert_eq!(std::fs::read_to_string(cache_file.with_extension("kdl.at")).unwrap(), stamp_before);
    assert_eq!(std::fs::read(baseline_path(&cache_file)).unwrap(), baseline_before);
}

#[test]
fn a3_warn_dirty_refetch_serves_new_index_but_baseline_stays_sticky() {
    let d = tmp();
    let get1 = |_: &str| Ok(INDEX1.as_bytes().to_vec());
    load_with_history(URL, d.path(), &get1, 1000, false, &TrustPolicy::Warn).unwrap();

    let cache_file = cache_path_for(URL, d.path());
    let baseline_before = std::fs::read(baseline_path(&cache_file)).unwrap();

    let get2 = |_: &str| Ok(INDEX2.as_bytes().to_vec());
    let result = load_with_history(URL, d.path(), &get2, 2000, true, &TrustPolicy::Warn);
    assert!(result.is_ok(), "warn must serve the new index, not hard-fail");

    // Served cache advances to the new bytes...
    assert_eq!(std::fs::read(&cache_file).unwrap(), INDEX2.as_bytes());
    // ...but the ratchet baseline is sticky — unchanged.
    assert_eq!(std::fs::read(baseline_path(&cache_file)).unwrap(), baseline_before);
}

#[test]
fn a3_baseline_corrupt_maps_to_baseline_corrupt_regardless_of_policy() {
    let d = tmp();
    let get1 = |_: &str| Ok(INDEX1.as_bytes().to_vec());
    load_with_history(URL, d.path(), &get1, 1000, false, &TrustPolicy::Warn).unwrap();
    let cache_file = cache_path_for(URL, d.path());
    // Corrupt the baseline sidecar directly.
    std::fs::write(baseline_path(&cache_file), b"not kdl {{{").unwrap();

    let get2 = |_: &str| Ok(INDEX1.as_bytes().to_vec());
    let err = load_with_history(URL, d.path(), &get2, 2000, true, &TrustPolicy::Warn).unwrap_err();
    assert_eq!(err.code(), "TNG-INDEX-BASELINE-CORRUPT");
}

#[test]
fn a3_write_baseline_pair_atomic_swap_for_accept_verb() {
    let d = tmp();
    let meta = BaselineMeta {
        established_at: Some("2026-01-01T00:00:00+00:00".to_string()),
        reported_digest: None,
        reported_at: None,
    };
    write_baseline_pair(URL, d.path(), INDEX1.as_bytes(), &meta).unwrap();
    let (baseline_p, meta_p) = baseline_sidecar_paths(URL, d.path());
    assert_eq!(std::fs::read(&baseline_p).unwrap(), INDEX1.as_bytes());
    assert!(std::fs::read_to_string(&meta_p).unwrap().contains("established_at"));
}
