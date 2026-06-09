//! Unit tests for the 4-state index cache (S8/S13). Injected `http_get` + clock
//! drive each state without a network or wall-clock.

use super::*;
use std::cell::RefCell;

const URL: &str = "https://example.test/index.kdl";
const INDEX: &str = "schema_version 1\npackage \"bar\" {\n    version \"1.0.0\"\n}\n";

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// An http_get that serves `INDEX` and counts calls.
fn counting_get(calls: &RefCell<usize>) -> impl Fn(&str) -> Result<String, String> + '_ {
    move |_url| {
        *calls.borrow_mut() += 1;
        Ok(INDEX.to_string())
    }
}

#[test]
fn missing_then_fresh_uses_one_fetch() {
    let d = tmp();
    let calls = RefCell::new(0);
    let get = counting_get(&calls);

    // Missing → fetch + populate.
    let idx = load_index(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000).unwrap();
    assert_eq!(idx.packages.len(), 1);
    assert_eq!(*calls.borrow(), 1);

    // Fresh (age 0 < ttl) → served from cache, no second fetch.
    let idx2 = load_index(URL, d.path(), &get, DEFAULT_TTL_SECONDS, 1000).unwrap();
    assert_eq!(idx2.packages.len(), 1);
    assert_eq!(*calls.borrow(), 1, "fresh cache must not re-fetch");
}

#[test]
fn stale_cache_refetches() {
    let d = tmp();
    let calls = RefCell::new(0);
    let get = counting_get(&calls);

    load_index(URL, d.path(), &get, 100, 1000).unwrap(); // mtime=1000
    assert_eq!(*calls.borrow(), 1);

    // now=1000+100+1 → age 101 >= ttl 100 → stale → refetch.
    load_index(URL, d.path(), &get, 100, 1101).unwrap();
    assert_eq!(*calls.borrow(), 2, "stale cache must re-fetch");
}

#[test]
fn offline_fallback_serves_stale_cache() {
    let d = tmp();
    // Populate with a working fetch.
    {
        let calls = RefCell::new(0);
        load_index(URL, d.path(), &counting_get(&calls), 100, 1000).unwrap();
    }
    // Now the network is down AND the cache is stale → fall back to it.
    let failing = |_: &str| -> Result<String, String> { Err("network down".into()) };
    let idx = load_index(URL, d.path(), &failing, 100, 9999).unwrap();
    assert_eq!(
        idx.packages.len(),
        1,
        "stale-but-available cache beats a hard error"
    );
}

#[test]
fn offline_with_no_cache_is_unreachable() {
    let d = tmp();
    let failing = |_: &str| -> Result<String, String> { Err("network down".into()) };
    let err = load_index(URL, d.path(), &failing, 100, 1000).unwrap_err();
    // Non-catalog runtime sentinel (not a spec error code).
    assert_eq!(err.code(), "MILPA-INDEX-UNREACHABLE");
}

#[test]
fn fetched_index_parse_errors_surface_tng_codes() {
    let d = tmp();
    let bad = |_: &str| -> Result<String, String> { Ok("schema_version 99\n".into()) };
    let err = load_index(URL, d.path(), &bad, 100, 1000).unwrap_err();
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
    // No override set in this process → the default URL.
    std::env::remove_var("MILPA_INDEX_URL");
    assert_eq!(index_url_from_env(), DEFAULT_INDEX_URL);
}
