//! `EntryBundleStore` trait + `FileEntryBundleStore` + `HttpEntryBundleStore` (P3a).
//!
//! RFC: `docs/rfc-per-entry-attestation.md` §7 — per-entry Sigstore bundles are
//! content-addressed leaves pinned from the signed index (the second instance of
//! the registry's two-tier pattern: mutable signed map → immutable hash-pinned
//! artifacts; DepDecl was the first).
//!
//! Mirrors `impls/python/milpa/entry_bundle_store.py`. This module intentionally
//! DUPLICATES `dep_decl_store.rs`'s shape (fetch-or-cache + hash-verify trait
//! pair) rather than generalizing it into one parametrized artifact store — the
//! same extract-or-decline decision the Python module records: refactoring the
//! already-battle-tested `dep_decl_store.rs` now would risk that module for no
//! test-coverage gain in P3a (bundle HTTP-production correctness is untestable
//! before P4 ships real bundles). Revisit the generalized extraction once both
//! HTTP stores have real-world mileage (P4).
//!
//! SECURITY INVARIANT (NORMATIVE): `TNG-ENTRY-BUNDLE-PIN-MISMATCH` is raised
//! HERE and ONLY HERE (`verify`), and is ALWAYS a hard error — never
//! policy-gated, not even under `entry-trust "warn"` (RFC §5 NORMATIVE,
//! mirroring the `TNG-DEPDECL-HASH-MISMATCH` severity model).
//! `TNG-ENTRY-BUNDLE-MISSING` (cause `unfetchable`) is raised here for fetch
//! failures; the caller (the `entry-trust` gate in `entry_trust.rs`) applies
//! policy to that one.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::CoreError;
use crate::MilpaError;

// ---------------------------------------------------------------------------
// EntryBundleStore trait
// ---------------------------------------------------------------------------

/// Discriminates which concrete `EntryBundleStore` backend is configured —
/// used ONLY for the D6 `BundleMissing` remediation-hint text
/// (`entry_trust::enforce_entry_trust`), never for acquisition/verification
/// logic. The hint differs because retrying is meaningful for the HTTP
/// mirror (a plausibly transient network failure) but not for a local
/// air-gapped mirror (a genuinely-absent file re-fails deterministically).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleStoreBackend {
    Http,
    File,
}

/// Sealed fetch-or-cache + hash-verify seam for per-entry attestation bundles.
///
/// `get` is the ONE site where `sha256(bytes) == bundle_pin` is verified.
///
/// # Errors
/// - `TNG-ENTRY-BUNDLE-MISSING` (cause `unfetchable`) — bundle not found /
///   not reachable. The `entry-trust` gate applies warn/strict policy to this one.
/// - `TNG-ENTRY-BUNDLE-PIN-MISMATCH` — `sha256(bytes) != bundle_pin`; always a
///   hard error (SECURITY INVARIANT — no policy fallback, not even under warn).
pub trait EntryBundleStore: Send + Sync {
    /// Fetch bundle bytes for `bundle_pin` (bare lowercase hex, no `sha256:`
    /// prefix), verify the hash, and return the bytes.
    fn get(&self, bundle_pin: &str) -> Result<Vec<u8>, MilpaError>;

    /// Return `true` iff the bundle is present locally (no network probe).
    /// Used by `milpa verify`'s offline re-verification (RFC §7).
    fn is_cached(&self, bundle_pin: &str) -> bool;

    /// Which concrete backend this is (D6 remediation-hint selection only).
    fn backend(&self) -> BundleStoreBackend;
}

// ---------------------------------------------------------------------------
// verify — THE ONE hash-verify site (SECURITY INVARIANT)
// ---------------------------------------------------------------------------

/// Verify that `sha256(bundle_bytes) == bundle_pin`. This is the ONE site
/// where `TNG-ENTRY-BUNDLE-PIN-MISMATCH` is raised. `bundle_pin` is bare
/// lowercase hex (no `sha256:` prefix — `registry.rs`'s bundle-pin parser
/// already validates and stores it in that form).
fn verify(bundle_bytes: &[u8], bundle_pin: &str) -> Result<(), MilpaError> {
    let computed = hex::encode(Sha256::digest(bundle_bytes));
    if computed != bundle_pin {
        return Err(MilpaError::Core(CoreError::Tianguis(
            "TNG-ENTRY-BUNDLE-PIN-MISMATCH",
            format!(
                "attestation bundle hash mismatch: expected {bundle_pin:?} but \
                 computed {computed:?} — the delivery path served different \
                 bytes than the Layer-1-verified index committed to"
            ),
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// FileEntryBundleStore
// ---------------------------------------------------------------------------

/// Reads `<dir>/<sha256_hex>.bundle` — no network, still hash-verifies.
///
/// Selected when `MILPA_ENTRY_BUNDLE_DIR` is set (the mirror of
/// `MILPA_DEP_DECL_DIR`, RFC §7). Used by the conformance harness (P3a) and
/// any air-gapped / local-mirror deployment.
///
/// The file's bytes are hash-verified on every read (not just on first
/// cache-miss) so a corrupted local file raises `TNG-ENTRY-BUNDLE-PIN-MISMATCH`
/// rather than being silently passed to the verifier.
pub struct FileEntryBundleStore {
    dir: PathBuf,
}

impl FileEntryBundleStore {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        FileEntryBundleStore {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    fn path_for(&self, bundle_pin: &str) -> PathBuf {
        self.dir.join(format!("{bundle_pin}.bundle"))
    }
}

impl EntryBundleStore for FileEntryBundleStore {
    fn get(&self, bundle_pin: &str) -> Result<Vec<u8>, MilpaError> {
        let path = self.path_for(bundle_pin);
        let bytes = std::fs::read(&path).map_err(|e| {
            MilpaError::Core(CoreError::Tianguis(
                "TNG-ENTRY-BUNDLE-MISSING",
                format!(
                    "attestation bundle not found at {} (pin {bundle_pin:?}) — \
                     check MILPA_ENTRY_BUNDLE_DIR: {e}",
                    path.display()
                ),
            ))
        })?;
        verify(&bytes, bundle_pin)?;
        Ok(bytes)
    }

    fn is_cached(&self, bundle_pin: &str) -> bool {
        self.path_for(bundle_pin).is_file()
    }

    fn backend(&self) -> BundleStoreBackend {
        BundleStoreBackend::File
    }
}

// ---------------------------------------------------------------------------
// HttpEntryBundleStore
// ---------------------------------------------------------------------------

/// Maximum size of a per-entry attestation bundle fetched over HTTP.
///
/// A placeholder, not a measured-corpus figure — no real per-entry Sigstore
/// bundle exists yet (P4-gated). A Sigstore bundle (cert chain + inclusion
/// proof + SET) is meaningfully larger than a DepDecl KDL text (~10s of
/// KiB), so the DepDecl cap (1 MiB) is not reused verbatim; 4 MiB is a
/// conservative ceiling pending real measurement at P4.
const ENTRY_BUNDLE_MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

/// Production entry-bundle store: fetch from HTTP + immutable cache.
///
/// Artifact URL = `<base_url>/attestation/<sha256_hex>.bundle` (RFC §7, same
/// derivation convention as `dep-decl/`). Cache is
/// `<cache_dir>/<sha256_hex>.bundle` — immutable forever, no TTL.
///
/// Transport: subprocess `curl` (mirrors `dep_decl_store.rs`'s
/// `http_get_bytes`, same pattern as the tianguis index client). Supports
/// `http://`, `https://`, and `file://` schemes.
pub struct HttpEntryBundleStore {
    base_url: String,
    cache_dir: Option<PathBuf>,
}

impl HttpEntryBundleStore {
    pub fn new(base_url: impl Into<String>, cache_dir: Option<PathBuf>) -> Self {
        HttpEntryBundleStore {
            base_url: base_url.into(),
            cache_dir,
        }
    }

    fn artifact_url(&self, bundle_pin: &str) -> String {
        format!("{}attestation/{bundle_pin}.bundle", self.base_url)
    }

    fn cache_path(&self, bundle_pin: &str) -> Option<PathBuf> {
        self.cache_dir
            .as_ref()
            .map(|d| d.join(format!("{bundle_pin}.bundle")))
    }
}

impl EntryBundleStore for HttpEntryBundleStore {
    fn get(&self, bundle_pin: &str) -> Result<Vec<u8>, MilpaError> {
        // Cache-first (immutable: a hit is always valid; no staleness check).
        // CR16: cached-read + self-heal is shared with HttpDepDeclStore via
        // crate::atomic_cache::read_verified_or_self_heal — a locally
        // corrupt/unreadable cache entry (e.g. a truncated write left behind
        // by the pre-unique-temp-name concurrency race, or plain disk
        // corruption) is discarded and treated as a cache miss so the caller
        // re-fetches, rather than a permanent hard failure. A mismatch on
        // FRESHLY FETCHED bytes below (the server genuinely served the wrong
        // content) stays a hard error via `?` — that call never goes through
        // the self-heal primitive.
        if let Some(cache_path) = self.cache_path(bundle_pin) {
            if let Some(cached) =
                crate::atomic_cache::read_verified_or_self_heal(&cache_path, |b| verify(b, bundle_pin))
            {
                return Ok(cached);
            }
        }

        let url = self.artifact_url(bundle_pin);
        let bytes = http_get_bytes(&url, bundle_pin)?;
        verify(&bytes, bundle_pin)?;

        // Atomic best-effort cache write (unique-per-write temp sibling +
        // rename — registry-protocol §3.5.2 NORMATIVE (concurrency); a
        // write failure is non-fatal, the bytes were already verified).
        if let Some(cache_path) = self.cache_path(bundle_pin) {
            if let Some(parent) = cache_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = crate::atomic_cache::atomic_write_bytes(&cache_path, &bytes);
        }

        Ok(bytes)
    }

    fn is_cached(&self, bundle_pin: &str) -> bool {
        self.cache_path(bundle_pin)
            .map(|p| p.is_file())
            .unwrap_or(false)
    }

    fn backend(&self) -> BundleStoreBackend {
        BundleStoreBackend::Http
    }
}

/// Minimal synchronous HTTP GET returning raw bytes, with a size cap.
/// Mirrors `dep_decl_store::http_get_bytes`.
fn http_get_bytes(url: &str, bundle_pin: &str) -> Result<Vec<u8>, MilpaError> {
    if let Some(path_str) = url.strip_prefix("file://") {
        let bytes = std::fs::read(path_str).map_err(|e| {
            MilpaError::Core(CoreError::Tianguis(
                "TNG-ENTRY-BUNDLE-MISSING",
                format!("attestation bundle {bundle_pin:?} fetch failed from {url}: {e}"),
            ))
        })?;
        if bytes.len() > ENTRY_BUNDLE_MAX_ARTIFACT_BYTES {
            return Err(MilpaError::Core(CoreError::Tianguis(
                "TNG-ENTRY-BUNDLE-MISSING",
                format!(
                    "attestation bundle {bundle_pin:?} from {url} exceeds the \
                     {ENTRY_BUNDLE_MAX_ARTIFACT_BYTES}-byte cap ({} bytes) — \
                     rejecting to prevent resource exhaustion",
                    bytes.len()
                ),
            )));
        }
        return Ok(bytes);
    }

    let max_str = ENTRY_BUNDLE_MAX_ARTIFACT_BYTES.to_string();
    let out = std::process::Command::new("curl")
        .args(["-fsSL", "--max-filesize", &max_str, url])
        .output()
        .map_err(|e| {
            MilpaError::Core(CoreError::Tianguis(
                "TNG-ENTRY-BUNDLE-MISSING",
                format!("attestation bundle {bundle_pin:?}: curl failed: {e}"),
            ))
        })?;
    if !out.status.success() {
        return Err(MilpaError::Core(CoreError::Tianguis(
            "TNG-ENTRY-BUNDLE-MISSING",
            format!(
                "attestation bundle {bundle_pin:?} fetch failed from {url}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        )));
    }
    if out.stdout.len() > ENTRY_BUNDLE_MAX_ARTIFACT_BYTES {
        return Err(MilpaError::Core(CoreError::Tianguis(
            "TNG-ENTRY-BUNDLE-MISSING",
            format!(
                "attestation bundle {bundle_pin:?} from {url} exceeds the \
                 {ENTRY_BUNDLE_MAX_ARTIFACT_BYTES}-byte cap ({} bytes) — \
                 rejecting to prevent resource exhaustion",
                out.stdout.len()
            ),
        )));
    }
    Ok(out.stdout)
}

// ---------------------------------------------------------------------------
// entry_bundle_store_from_paths — store selection (mirrors dep_decl_store_from_paths)
// ---------------------------------------------------------------------------

/// Select the `EntryBundleStore` given resolved paths/URLs. Mirrors
/// `entry_bundle_store.py::entry_bundle_store_from_paths`.
///
/// Priority:
/// 0. `no_index` → `None` (no index ⇒ no registry-resolved deps ⇒ the
///    entry-trust gate never runs).
/// 1. `entry_bundle_dir` is `Some` and a directory → `FileEntryBundleStore`.
/// 2. `index_url` non-empty → `HttpEntryBundleStore` derived via
///    `dep_decl_store::index_base_url` (same §3.3 URL-derivation rule).
/// 3. Otherwise → `None`.
pub fn entry_bundle_store_from_paths(
    entry_bundle_dir: Option<&Path>,
    index_url: Option<&str>,
    no_index: bool,
) -> Option<Box<dyn EntryBundleStore>> {
    if no_index {
        return None;
    }
    if let Some(dir) = entry_bundle_dir {
        if dir.is_dir() {
            return Some(Box::new(FileEntryBundleStore::new(dir)));
        }
    }
    if let Some(url) = index_url {
        if !url.is_empty() {
            let base = crate::dep_decl_store::index_base_url(url);
            return Some(Box::new(HttpEntryBundleStore::new(base, default_entry_bundle_cache_dir())));
        }
    }
    None
}

/// `$MILPA_CACHE_DIR/attestation/` if `MILPA_CACHE_DIR` is set, else
/// `$XDG_CACHE_HOME/milpa/attestation/` or `$HOME/.cache/milpa/attestation/`.
/// Mirrors `dep_decl_store::default_dep_decl_cache_dir` with a different
/// sub-directory (the bundle store's native key).
fn default_entry_bundle_cache_dir() -> Option<PathBuf> {
    if let Ok(d) = std::env::var("MILPA_CACHE_DIR") {
        if !d.is_empty() {
            return Some(PathBuf::from(d).join("attestation"));
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("milpa").join("attestation"));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return Some(PathBuf::from(home).join(".cache").join("milpa").join("attestation"));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle_hash(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn verify_happy_path() {
        let data = b"{\"fake\":\"bundle\"}";
        let hash = bundle_hash(data);
        assert!(verify(data, &hash).is_ok());
    }

    #[test]
    fn verify_mismatch_raises_pin_mismatch() {
        let data = b"{\"fake\":\"bundle\"}";
        let wrong = "0".repeat(64);
        let err = verify(data, &wrong).unwrap_err();
        assert_eq!(err.code(), "TNG-ENTRY-BUNDLE-PIN-MISMATCH");
    }

    #[test]
    fn file_store_get_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let data = b"{\"fake\":\"bundle\"}";
        let hash = bundle_hash(data);
        std::fs::write(tmp.path().join(format!("{hash}.bundle")), data).unwrap();

        let store = FileEntryBundleStore::new(tmp.path());
        let got = store.get(&hash).unwrap();
        assert_eq!(got, data);
        assert!(store.is_cached(&hash));
    }

    #[test]
    fn file_store_get_missing_raises_bundle_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileEntryBundleStore::new(tmp.path());
        let hash = "a".repeat(64);
        let err = store.get(&hash).unwrap_err();
        assert_eq!(err.code(), "TNG-ENTRY-BUNDLE-MISSING");
        assert!(!store.is_cached(&hash));
    }

    #[test]
    fn file_store_corrupted_bytes_raise_pin_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let data = b"{\"fake\":\"bundle\"}";
        let hash = bundle_hash(data);
        // Write DIFFERENT bytes under the hash's filename (simulated corruption).
        std::fs::write(tmp.path().join(format!("{hash}.bundle")), b"corrupted").unwrap();

        let store = FileEntryBundleStore::new(tmp.path());
        let err = store.get(&hash).unwrap_err();
        assert_eq!(err.code(), "TNG-ENTRY-BUNDLE-PIN-MISMATCH");
    }

    // -----------------------------------------------------------------------
    // HttpEntryBundleStore — file:// transport (no live network)
    // -----------------------------------------------------------------------

    #[test]
    fn http_store_file_url_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let data = b"{\"fake\":\"bundle\"}";
        let hash = bundle_hash(data);
        let origin = tmp.path().join("origin");
        std::fs::create_dir_all(origin.join("attestation")).unwrap();
        std::fs::write(origin.join("attestation").join(format!("{hash}.bundle")), data).unwrap();
        let cache_dir = tmp.path().join("cache");

        let base_url = format!("file://{}/", origin.to_str().unwrap());
        let store = HttpEntryBundleStore::new(base_url, Some(cache_dir.clone()));
        let got = store.get(&hash).unwrap();
        assert_eq!(got, data);
        assert!(store.is_cached(&hash));
        assert_eq!(std::fs::read(cache_dir.join(format!("{hash}.bundle"))).unwrap(), data);
    }

    #[test]
    fn http_store_cache_hit_avoids_network() {
        let tmp = tempfile::tempdir().unwrap();
        let data = b"{\"fake\":\"bundle\"}";
        let hash = bundle_hash(data);
        let cache_dir = tmp.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(cache_dir.join(format!("{hash}.bundle")), data).unwrap();

        // base_url is unreachable; cache has the bundle, so get() must not hit it.
        let store = HttpEntryBundleStore::new("https://unreachable.invalid/", Some(cache_dir));
        let got = store.get(&hash).unwrap();
        assert_eq!(got, data);
    }

    // -----------------------------------------------------------------------
    // CR4 — fixed-temp-filename race (registry-protocol §3.5.2 NORMATIVE
    // (concurrency)): a locally-corrupt cache entry must self-heal rather
    // than poison forever, and concurrent fetches of the same uncached
    // bundle must never tear a partial write into the final cache path.
    // -----------------------------------------------------------------------

    #[test]
    fn http_store_corrupted_cache_self_heals_by_refetching() {
        let tmp = tempfile::tempdir().unwrap();
        let data = b"{\"fake\":\"bundle\"}";
        let hash = bundle_hash(data);
        let origin = tmp.path().join("origin");
        std::fs::create_dir_all(origin.join("attestation")).unwrap();
        std::fs::write(origin.join("attestation").join(format!("{hash}.bundle")), data).unwrap();
        let cache_dir = tmp.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        // Simulate a truncated/corrupt cache entry under the correct pin.
        std::fs::write(cache_dir.join(format!("{hash}.bundle")), b"truncated garbage").unwrap();

        let base_url = format!("file://{}/", origin.to_str().unwrap());
        let store = HttpEntryBundleStore::new(base_url, Some(cache_dir.clone()));
        let got = store.get(&hash).unwrap();
        assert_eq!(got, data);
        // Cache is repaired: a subsequent get (origin removed) still succeeds.
        std::fs::remove_file(origin.join("attestation").join(format!("{hash}.bundle"))).unwrap();
        assert_eq!(store.get(&hash).unwrap(), data);
    }

    #[test]
    fn http_store_server_content_mismatch_stays_hard_error() {
        let tmp = tempfile::tempdir().unwrap();
        let data = b"{\"fake\":\"bundle\"}";
        let hash = bundle_hash(data);
        let origin = tmp.path().join("origin");
        std::fs::create_dir_all(origin.join("attestation")).unwrap();
        // Origin serves bytes that do NOT hash to `hash` — genuine fetch
        // mismatch, nothing pre-cached.
        std::fs::write(
            origin.join("attestation").join(format!("{hash}.bundle")),
            b"wrong content entirely",
        )
        .unwrap();
        let cache_dir = tmp.path().join("cache");

        let base_url = format!("file://{}/", origin.to_str().unwrap());
        let store = HttpEntryBundleStore::new(base_url, Some(cache_dir.clone()));
        let err = store.get(&hash).unwrap_err();
        assert_eq!(err.code(), "TNG-ENTRY-BUNDLE-PIN-MISMATCH");
        assert!(!store.is_cached(&hash));
    }

    #[test]
    fn http_store_concurrent_fetch_of_same_pin_never_corrupts_cache() {
        // Regression for the fixed-temp-name race (CR4): N threads racing a
        // fetch of the SAME uncached bundle must all succeed with the
        // correct bytes, and the final on-disk cache entry must never be a
        // torn/interleaved write (each writer now uses a per-write-unique
        // temp sibling — crate::atomic_cache — so no two writers can share
        // a temp file).
        let tmp = tempfile::tempdir().unwrap();
        let data = vec![b'Q'; 65536];
        let hash = bundle_hash(&data);
        let origin = tmp.path().join("origin");
        std::fs::create_dir_all(origin.join("attestation")).unwrap();
        std::fs::write(origin.join("attestation").join(format!("{hash}.bundle")), &data).unwrap();
        let cache_dir = tmp.path().join("cache");

        let base_url = format!("file://{}/", origin.to_str().unwrap());
        let store = std::sync::Arc::new(HttpEntryBundleStore::new(base_url, Some(cache_dir.clone())));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let store = std::sync::Arc::clone(&store);
                let hash = hash.clone();
                std::thread::spawn(move || store.get(&hash))
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap().unwrap(), data);
        }
        let cached = std::fs::read(cache_dir.join(format!("{hash}.bundle"))).unwrap();
        assert_eq!(cached, data, "final cache entry must be a complete write, never torn");
    }

    #[test]
    fn from_paths_no_index_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(entry_bundle_store_from_paths(Some(tmp.path()), Some("file:///x"), true).is_none());
    }

    #[test]
    fn from_paths_prefers_dir_over_url() {
        let tmp = tempfile::tempdir().unwrap();
        let store = entry_bundle_store_from_paths(Some(tmp.path()), Some("file:///x/index.kdl"), false);
        assert!(store.is_some());
    }

    #[test]
    fn from_paths_falls_back_to_url() {
        let store = entry_bundle_store_from_paths(None, Some("file:///x/index.kdl"), false);
        assert!(store.is_some());
    }

    #[test]
    fn from_paths_nothing_returns_none() {
        assert!(entry_bundle_store_from_paths(None, None, false).is_none());
    }
}
