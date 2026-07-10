//! DepDeclStore trait + FileDepDeclStore + HttpDepDeclStore (S3b).
//!
//! The `DepDeclStore` trait has ONE sealed responsibility:
//! `get(dep_decl_hash_str) -> Result<Vec<u8>, MilpaError>`
//! which fetch+cache+hash-verifies the artifact.
//!
//! SECURITY: `TNG-DEPDECL-HASH-MISMATCH` is raised in exactly ONE place
//! (`verify()`) — inside `get()`. This invariant MUST NOT be moved to callers.
//!
//! Mirrors `milpa/dep_decl_store.py` in `impls/python`.

use std::path::{Path, PathBuf};

use crate::dep_decl::dep_decl_hash;
use crate::error::CoreError;
use crate::MilpaError;

// ---------------------------------------------------------------------------
// DepDeclStore trait
// ---------------------------------------------------------------------------

/// Fetch + cache + hash-verify a DepDecl artifact (S3b normative interface).
///
/// `get` is the ONE sealed responsibility: it fetches the artifact (from disk
/// or network), verifies the hash, and returns the raw bytes on success.
///
/// SECURITY INVARIANT: `TNG-DEPDECL-HASH-MISMATCH` is raised inside `get`
/// (via `verify()`) and NOWHERE ELSE. Callers receive either verified bytes
/// or an error — there is no "unverified" path.
pub trait DepDeclStore: Send + Sync {
    /// Fetch the artifact identified by `dep_decl_hash_str` (a `"sha256:<hex>"` string).
    ///
    /// Returns the raw artifact bytes (KDL UTF-8), hash-verified.
    ///
    /// # Errors
    /// - `TNG-DEPDECL-FETCH-FAILED` — artifact not found / unreachable.
    /// - `TNG-DEPDECL-HASH-MISMATCH` — artifact found but hash doesn't match.
    fn get(&self, dep_decl_hash_str: &str) -> Result<Vec<u8>, MilpaError>;

    /// Return `true` if the artifact is already available locally (no I/O needed).
    fn is_cached(&self, dep_decl_hash_str: &str) -> bool;
}

// ---------------------------------------------------------------------------
// Verification helper — THE ONE hash-verify site (SECURITY INVARIANT)
// ---------------------------------------------------------------------------

/// Verify that `artifact_bytes` hashes to `dep_decl_hash_str`.
///
/// SECURITY: this is the **single site** where `TNG-DEPDECL-HASH-MISMATCH`
/// is raised. `DepDeclStore` implementations MUST call this after every fetch
/// (including cache hits) and MUST NOT inline the comparison elsewhere.
pub fn verify(artifact_bytes: &[u8], dep_decl_hash_str: &str) -> Result<(), MilpaError> {
    let computed = dep_decl_hash(artifact_bytes);
    if computed != dep_decl_hash_str {
        return Err(MilpaError::Core(CoreError::DepDecl(
            "TNG-DEPDECL-HASH-MISMATCH",
            format!(
                "DepDecl artifact hash mismatch: expected {dep_decl_hash_str:?} \
                 but computed {computed:?} — artifact may be corrupted or tampered"
            ),
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// _hex_of — extract hex digest from "sha256:<hex>" string
// ---------------------------------------------------------------------------

fn hex_of(dep_decl_hash_str: &str) -> &str {
    dep_decl_hash_str
        .strip_prefix("sha256:")
        .unwrap_or(dep_decl_hash_str)
}

// ---------------------------------------------------------------------------
// FileDepDeclStore
// ---------------------------------------------------------------------------

/// Reads DepDecl artifacts from `<dir>/<sha256_hex>.kdl` (no network).
///
/// Selected when `MILPA_DEP_DECL_DIR` is set. Used by the conformance harness
/// (which populates the dir from the fixture's `dep-decl/` tree) and for
/// air-gapped environments.
pub struct FileDepDeclStore {
    dir: PathBuf,
}

impl FileDepDeclStore {
    /// Create a new `FileDepDeclStore` rooted at `dir`.
    pub fn new(dir: impl AsRef<Path>) -> Self {
        FileDepDeclStore {
            dir: dir.as_ref().to_path_buf(),
        }
    }
}

impl DepDeclStore for FileDepDeclStore {
    fn get(&self, dep_decl_hash_str: &str) -> Result<Vec<u8>, MilpaError> {
        let hex = hex_of(dep_decl_hash_str);
        let path = self.dir.join(format!("{hex}.kdl"));
        let bytes = std::fs::read(&path).map_err(|e| {
            MilpaError::Core(CoreError::DepDecl(
                "TNG-DEPDECL-FETCH-FAILED",
                format!(
                    "DepDecl artifact {dep_decl_hash_str:?} not found in \
                     file store at {}: {e}",
                    path.display()
                ),
            ))
        })?;
        verify(&bytes, dep_decl_hash_str)?;
        Ok(bytes)
    }

    fn is_cached(&self, dep_decl_hash_str: &str) -> bool {
        let hex = hex_of(dep_decl_hash_str);
        self.dir.join(format!("{hex}.kdl")).is_file()
    }
}

// ---------------------------------------------------------------------------
// HttpDepDeclStore
// ---------------------------------------------------------------------------

/// Fetches DepDecl artifacts via HTTP from `<base_url>/dep-decl/<sha256_hex>.kdl`.
///
/// Artifacts are immutable (content-addressed); once verified they are cached
/// forever at `<cache_dir>/<sha256_hex>.kdl`. Selected when `MILPA_INDEX_URL`
/// is set but `MILPA_DEP_DECL_DIR` is not.
pub struct HttpDepDeclStore {
    base_url: String,
    cache_dir: Option<PathBuf>,
}

impl HttpDepDeclStore {
    /// Create a new `HttpDepDeclStore` with the given base URL and optional cache dir.
    ///
    /// `base_url` is derived from `MILPA_INDEX_URL` via `index_base_url()`.
    /// `cache_dir` is where verified artifacts are stored for offline reuse.
    pub fn new(base_url: impl Into<String>, cache_dir: Option<PathBuf>) -> Self {
        HttpDepDeclStore {
            base_url: base_url.into(),
            cache_dir,
        }
    }
}

impl DepDeclStore for HttpDepDeclStore {
    fn get(&self, dep_decl_hash_str: &str) -> Result<Vec<u8>, MilpaError> {
        let hex = hex_of(dep_decl_hash_str);

        // Check cache first (immutable artifacts: no TTL, no re-fetch needed).
        if let Some(ref cache_dir) = self.cache_dir {
            let cache_path = cache_dir.join(format!("{hex}.kdl"));
            if cache_path.is_file() {
                let bytes = std::fs::read(&cache_path).map_err(|e| {
                    MilpaError::Core(CoreError::DepDecl(
                        "TNG-DEPDECL-FETCH-FAILED",
                        format!("DepDecl cache read failed for {dep_decl_hash_str:?}: {e}"),
                    ))
                })?;
                // SECURITY: verify even from cache (detect disk corruption / tampering)
                match verify(&bytes, dep_decl_hash_str) {
                    Ok(()) => return Ok(bytes),
                    Err(_) => {
                        // Locally-corrupt cache entry (e.g. a truncated write
                        // left behind by the pre-unique-temp-name concurrency
                        // race, or plain disk corruption) — self-heal by
                        // discarding it and falling through to re-fetch,
                        // rather than a permanent hard failure. A mismatch on
                        // FRESHLY FETCHED bytes below (the server genuinely
                        // served the wrong content) stays a hard error via `?`.
                        let _ = std::fs::remove_file(&cache_path);
                    }
                }
            }
        }

        // Network fetch: derive artifact URL from base_url + hash.
        let url = format!("{}dep-decl/{hex}.kdl", self.base_url);
        let bytes = http_get_bytes(&url, dep_decl_hash_str)?;
        verify(&bytes, dep_decl_hash_str)?;

        // Write to cache (best-effort: cache write failures are non-fatal).
        // Atomic: unique-per-write temp sibling + rename (registry-protocol
        // §3.5.2 NORMATIVE (concurrency)) — a bare `fs::write` to the final
        // path (the pre-fix behavior here) is not just non-atomic under a
        // fixed temp name, it has NO temp file at all, so a concurrent
        // reader can observe a partial write directly at the cache path.
        if let Some(ref cache_dir) = self.cache_dir {
            if let Err(e) = std::fs::create_dir_all(cache_dir) {
                eprintln!("milpa: dep-decl cache dir create failed: {e}");
            } else {
                let cache_path = cache_dir.join(format!("{hex}.kdl"));
                if let Err(e) = crate::atomic_cache::atomic_write_bytes(&cache_path, &bytes) {
                    eprintln!("milpa: dep-decl cache write failed: {e}");
                }
            }
        }

        Ok(bytes)
    }

    fn is_cached(&self, dep_decl_hash_str: &str) -> bool {
        let hex = hex_of(dep_decl_hash_str);
        if let Some(ref cache_dir) = self.cache_dir {
            return cache_dir.join(format!("{hex}.kdl")).is_file();
        }
        false
    }
}

/// Maximum size of a DepDecl artifact fetched over HTTP (spec §3.3.1 NORMATIVE).
///
/// A legitimate DepDecl is KDL text with a handful of `require` nodes — well
/// under 10 KiB in practice.  1 MiB is a generous-but-safe ceiling that admits
/// any plausible future growth while bounding the resource-exhaustion surface:
/// a compromised or misconfigured index can point `dep_decl` at an arbitrary
/// URL, so we must never buffer an unbounded response body.
///
/// On exceed: `TNG-DEPDECL-FETCH-FAILED` (non-strict path may fall back to
/// `.nimble`; strict mode is always a hard fail — same policy as other fetch
/// failures).
const DEP_DECL_MAX_ARTIFACT_BYTES: usize = 1024 * 1024; // 1 MiB

/// Minimal synchronous HTTP GET returning raw bytes.
///
/// Mirrors the CLI's `curl`-based fetch (same subprocess pattern used for
/// the tianguis index client). Returns `TNG-DEPDECL-FETCH-FAILED` on any
/// network or HTTP error.
///
/// R8: enforces `DEP_DECL_MAX_ARTIFACT_BYTES` on every response.
fn http_get_bytes(url: &str, dep_decl_hash_str: &str) -> Result<Vec<u8>, MilpaError> {
    // file:// URLs: read from disk directly (used in tests + conformance fixtures).
    if let Some(path_str) = url.strip_prefix("file://") {
        let bytes = std::fs::read(path_str).map_err(|e| {
            MilpaError::Core(CoreError::DepDecl(
                "TNG-DEPDECL-FETCH-FAILED",
                format!("DepDecl artifact {dep_decl_hash_str:?} fetch failed from {url}: {e}"),
            ))
        })?;
        // R8: apply size cap even for file:// (consistent policy).
        if bytes.len() > DEP_DECL_MAX_ARTIFACT_BYTES {
            return Err(MilpaError::Core(CoreError::DepDecl(
                "TNG-DEPDECL-FETCH-FAILED",
                format!(
                    "DepDecl artifact {dep_decl_hash_str:?} from {url} exceeds the \
                     {DEP_DECL_MAX_ARTIFACT_BYTES}-byte cap ({} bytes) — \
                     rejecting to prevent resource exhaustion",
                    bytes.len()
                ),
            )));
        }
        return Ok(bytes);
    }

    // HTTP/HTTPS: subprocess curl with --max-filesize cap (mirrors tianguis
    // index client transport).  `--max-filesize` makes curl exit non-zero
    // before the cap is exceeded; we also check stdout length as a second line
    // of defence (Content-Length lies are a known attack vector).
    let max_str = DEP_DECL_MAX_ARTIFACT_BYTES.to_string();
    let out = std::process::Command::new("curl")
        .args(["-fsSL", "--max-filesize", &max_str, url])
        .output()
        .map_err(|e| {
            MilpaError::Core(CoreError::DepDecl(
                "TNG-DEPDECL-FETCH-FAILED",
                format!("DepDecl artifact {dep_decl_hash_str:?}: curl failed: {e}"),
            ))
        })?;
    if !out.status.success() {
        return Err(MilpaError::Core(CoreError::DepDecl(
            "TNG-DEPDECL-FETCH-FAILED",
            format!(
                "DepDecl artifact {dep_decl_hash_str:?} fetch failed from {url}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        )));
    }
    // Second-line defence: verify curl didn't silently exceed the cap.
    if out.stdout.len() > DEP_DECL_MAX_ARTIFACT_BYTES {
        return Err(MilpaError::Core(CoreError::DepDecl(
            "TNG-DEPDECL-FETCH-FAILED",
            format!(
                "DepDecl artifact {dep_decl_hash_str:?} from {url} exceeds the \
                 {DEP_DECL_MAX_ARTIFACT_BYTES}-byte cap ({} bytes) — \
                 rejecting to prevent resource exhaustion",
                out.stdout.len()
            ),
        )));
    }
    Ok(out.stdout)
}

// ---------------------------------------------------------------------------
// index_base_url — RFC §3.3 derivation
// ---------------------------------------------------------------------------

/// Derive the DepDecl artifact base URL from the index URL (RFC §3.3).
///
/// The base URL is the index URL with the last path segment removed if it
/// matches `*.kdl` or `index*`, else the index URL with `/` appended.
///
/// Examples:
///   `"https://example.com/index.kdl"` → `"https://example.com/"`
///   `"https://example.com/v1/index.kdl"` → `"https://example.com/v1/"`
///   `"https://example.com/registry"` → `"https://example.com/registry/"`
///   `"file:///tmp/index.kdl"` → `"file:///tmp/"`
pub fn index_base_url(milpa_index_url: &str) -> String {
    // Strip any query string / fragment for the path analysis.
    let path_part = milpa_index_url
        .split('?')
        .next()
        .unwrap_or(milpa_index_url)
        .split('#')
        .next()
        .unwrap_or(milpa_index_url);

    // Split at the last '/'.
    if let Some(slash_pos) = path_part.rfind('/') {
        let last_seg = &path_part[slash_pos + 1..];
        // R6: Match *.kdl or index* case-insensitively (spec §3.3 NORMATIVE).
        // ASCII-lowercase is correct: URL path segments are ASCII by construction
        // (percent-encoded otherwise); `to_ascii_lowercase` is allocation-free
        // for purely-ASCII strings in most Rust implementations.
        let last_seg_lc = last_seg.to_ascii_lowercase();
        if last_seg_lc.ends_with(".kdl") || last_seg_lc.starts_with("index") {
            let prefix = &milpa_index_url[..slash_pos + 1];
            return prefix.to_string();
        }
    }

    // No matching last segment: append '/'.
    if milpa_index_url.ends_with('/') {
        milpa_index_url.to_string()
    } else {
        format!("{milpa_index_url}/")
    }
}

// ---------------------------------------------------------------------------
// make_dep_decl_store — factory for the CLI
// ---------------------------------------------------------------------------

/// Build an `HttpDepDeclStore` from the index URL (§3.3 base derivation).
///
/// Cache dir is `$MILPA_CACHE_DIR/dep-decl/` if `MILPA_CACHE_DIR` is set,
/// else `$XDG_CACHE_HOME/milpa/dep-decl/` or `$HOME/.cache/milpa/dep-decl/`.
pub fn make_dep_decl_store(milpa_index_url: &str) -> HttpDepDeclStore {
    let base = index_base_url(milpa_index_url);
    let cache_dir = default_dep_decl_cache_dir();
    HttpDepDeclStore::new(base, cache_dir)
}

fn default_dep_decl_cache_dir() -> Option<PathBuf> {
    // MILPA_CACHE_DIR overrides everything.
    if let Ok(d) = std::env::var("MILPA_CACHE_DIR") {
        if !d.is_empty() {
            return Some(PathBuf::from(d).join("dep-decl"));
        }
    }
    // XDG / HOME fallback.
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("milpa").join("dep-decl"));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return Some(PathBuf::from(home).join(".cache").join("milpa").join("dep-decl"));
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

    // -----------------------------------------------------------------------
    // verify helper
    // -----------------------------------------------------------------------

    #[test]
    fn verify_happy_path() {
        let data = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"src\"\n}\n";
        let hash = dep_decl_hash(data);
        assert!(verify(data, &hash).is_ok());
    }

    #[test]
    fn verify_mismatch_raises_hash_mismatch() {
        let data = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"src\"\n}\n";
        let wrong_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let err = verify(data, wrong_hash).unwrap_err();
        assert_eq!(err.code(), "TNG-DEPDECL-HASH-MISMATCH");
    }

    // -----------------------------------------------------------------------
    // FileDepDeclStore
    // -----------------------------------------------------------------------

    #[test]
    fn file_store_get_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let data = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"src\"\n}\n";
        let hash = dep_decl_hash(data);
        let hex = hash.strip_prefix("sha256:").unwrap();
        std::fs::write(tmp.path().join(format!("{hex}.kdl")), data).unwrap();

        let store = FileDepDeclStore::new(tmp.path());
        let got = store.get(&hash).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn file_store_get_missing_raises_fetch_failed() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileDepDeclStore::new(tmp.path());
        let err = store.get("sha256:0000000000000000000000000000000000000000000000000000000000000000").unwrap_err();
        assert_eq!(err.code(), "TNG-DEPDECL-FETCH-FAILED");
    }

    #[test]
    fn file_store_get_corrupted_raises_hash_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        // Use the hash of valid data but write corrupted bytes.
        let valid = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"src\"\n}\n";
        let hash = dep_decl_hash(valid);
        let hex = hash.strip_prefix("sha256:").unwrap();
        // Write corrupted content.
        std::fs::write(tmp.path().join(format!("{hex}.kdl")), b"corrupted content").unwrap();

        let store = FileDepDeclStore::new(tmp.path());
        let err = store.get(&hash).unwrap_err();
        assert_eq!(err.code(), "TNG-DEPDECL-HASH-MISMATCH");
    }

    #[test]
    fn file_store_is_cached_true_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let data = b"dep_decl { dep_decl_schema_version 0 src_dir \"\" }\n";
        let hash = dep_decl_hash(data);
        let hex = hash.strip_prefix("sha256:").unwrap();
        std::fs::write(tmp.path().join(format!("{hex}.kdl")), data).unwrap();
        let store = FileDepDeclStore::new(tmp.path());
        assert!(store.is_cached(&hash));
    }

    #[test]
    fn file_store_is_cached_false_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileDepDeclStore::new(tmp.path());
        assert!(!store.is_cached("sha256:0000000000000000000000000000000000000000000000000000000000000000"));
    }

    // -----------------------------------------------------------------------
    // index_base_url
    // -----------------------------------------------------------------------

    #[test]
    fn base_url_strips_kdl_segment() {
        assert_eq!(
            index_base_url("https://example.com/index.kdl"),
            "https://example.com/"
        );
    }

    #[test]
    fn base_url_strips_versioned_index_kdl() {
        assert_eq!(
            index_base_url("https://example.com/v1/index.kdl"),
            "https://example.com/v1/"
        );
    }

    #[test]
    fn base_url_strips_any_kdl_segment() {
        assert_eq!(
            index_base_url("https://example.com/v1/registry.kdl"),
            "https://example.com/v1/"
        );
    }

    #[test]
    fn base_url_strips_index_prefix_segment() {
        assert_eq!(
            index_base_url("https://example.com/index"),
            "https://example.com/"
        );
    }

    #[test]
    fn base_url_appends_slash_for_non_index_segment() {
        assert_eq!(
            index_base_url("https://example.com/registry"),
            "https://example.com/registry/"
        );
    }

    #[test]
    fn base_url_file_url() {
        assert_eq!(
            index_base_url("file:///tmp/index.kdl"),
            "file:///tmp/"
        );
    }

    #[test]
    fn base_url_already_slash_terminated() {
        assert_eq!(
            index_base_url("https://example.com/registry/"),
            "https://example.com/registry/"
        );
    }

    // -----------------------------------------------------------------------
    // HttpDepDeclStore with file:// URLs (offline test)
    // -----------------------------------------------------------------------

    #[test]
    fn http_store_file_url_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let data = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"src\"\n}\n";
        let hash = dep_decl_hash(data);
        let hex = hash.strip_prefix("sha256:").unwrap();
        let dep_decl_dir = tmp.path().join("dep-decl");
        std::fs::create_dir_all(&dep_decl_dir).unwrap();
        std::fs::write(dep_decl_dir.join(format!("{hex}.kdl")), data).unwrap();

        // base_url points to the dep-decl/ dir: get() fetches via file:// URL.
        let base_url = format!("file://{}/", tmp.path().to_str().unwrap());
        let store = HttpDepDeclStore::new(base_url, None);
        let got = store.get(&hash).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn http_store_cache_hit_avoids_network() {
        let tmp = tempfile::tempdir().unwrap();
        let data = b"dep_decl { dep_decl_schema_version 0 src_dir \"\" }\n";
        let hash = dep_decl_hash(data);
        let hex = hash.strip_prefix("sha256:").unwrap();

        // Pre-populate cache dir.
        let cache_dir = tmp.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(cache_dir.join(format!("{hex}.kdl")), data).unwrap();

        // base_url is unreachable (no real network); cache_dir has the artifact.
        let store = HttpDepDeclStore::new("https://unreachable.invalid/", Some(cache_dir.clone()));
        let got = store.get(&hash).unwrap();
        assert_eq!(got, data);
        assert!(store.is_cached(&hash));
    }

    #[test]
    fn http_store_fetch_failed_unreachable() {
        let store = HttpDepDeclStore::new(
            "https://unreachable.invalid/",
            None,
        );
        let err = store.get("sha256:0000000000000000000000000000000000000000000000000000000000000000").unwrap_err();
        assert_eq!(err.code(), "TNG-DEPDECL-FETCH-FAILED");
    }

    // -----------------------------------------------------------------------
    // CR4 — fixed-temp-filename race (registry-protocol §3.5.2 NORMATIVE
    // (concurrency)): a locally-corrupt cache entry must self-heal rather
    // than poison forever, and concurrent fetches of the same uncached
    // artifact must never tear a partial write into the final cache path.
    // (The pre-fix Rust cache write here was even more exposed than the
    // "fixed temp name" pattern: it wrote `std::fs::write` directly to the
    // final cache path with NO temp file at all.)
    // -----------------------------------------------------------------------

    #[test]
    fn http_store_corrupted_cache_self_heals_by_refetching() {
        let tmp = tempfile::tempdir().unwrap();
        let data = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"src\"\n}\n";
        let hash = dep_decl_hash(data);
        let hex = hash.strip_prefix("sha256:").unwrap();
        let dep_decl_dir = tmp.path().join("dep-decl");
        std::fs::create_dir_all(&dep_decl_dir).unwrap();
        std::fs::write(dep_decl_dir.join(format!("{hex}.kdl")), data).unwrap();
        let cache_dir = tmp.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        // Simulate a truncated/corrupt cache entry under the correct hash name.
        std::fs::write(cache_dir.join(format!("{hex}.kdl")), b"truncated garbage").unwrap();

        let base_url = format!("file://{}/", tmp.path().to_str().unwrap());
        let store = HttpDepDeclStore::new(base_url, Some(cache_dir.clone()));
        let got = store.get(&hash).unwrap();
        assert_eq!(got, data);
        // Cache is repaired: a subsequent get (origin removed) still succeeds.
        std::fs::remove_file(dep_decl_dir.join(format!("{hex}.kdl"))).unwrap();
        assert_eq!(store.get(&hash).unwrap(), data);
    }

    #[test]
    fn http_store_server_content_mismatch_stays_hard_error() {
        let tmp = tempfile::tempdir().unwrap();
        let data = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"src\"\n}\n";
        let hash = dep_decl_hash(data);
        let hex = hash.strip_prefix("sha256:").unwrap();
        let dep_decl_dir = tmp.path().join("dep-decl");
        std::fs::create_dir_all(&dep_decl_dir).unwrap();
        // Origin serves bytes that do NOT hash to `hash` — genuine fetch
        // mismatch, nothing pre-cached.
        std::fs::write(dep_decl_dir.join(format!("{hex}.kdl")), b"wrong content entirely").unwrap();
        let cache_dir = tmp.path().join("cache");

        let base_url = format!("file://{}/", tmp.path().to_str().unwrap());
        let store = HttpDepDeclStore::new(base_url, Some(cache_dir.clone()));
        let err = store.get(&hash).unwrap_err();
        assert_eq!(err.code(), "TNG-DEPDECL-HASH-MISMATCH");
        assert!(!cache_dir.join(format!("{hex}.kdl")).is_file());
    }

    #[test]
    fn http_store_concurrent_fetch_of_same_hash_never_corrupts_cache() {
        // Regression for CR4: N threads racing a fetch of the SAME uncached
        // artifact must all succeed with the correct bytes, and the final
        // on-disk cache entry must never be a torn/interleaved write.
        let tmp = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
        let hash = dep_decl_hash(&data);
        let hex = hash.strip_prefix("sha256:").unwrap().to_string();
        let dep_decl_dir = tmp.path().join("dep-decl");
        std::fs::create_dir_all(&dep_decl_dir).unwrap();
        std::fs::write(dep_decl_dir.join(format!("{hex}.kdl")), &data).unwrap();
        let cache_dir = tmp.path().join("cache");

        let base_url = format!("file://{}/", tmp.path().to_str().unwrap());
        let store = std::sync::Arc::new(HttpDepDeclStore::new(base_url, Some(cache_dir.clone())));

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
        let cached = std::fs::read(cache_dir.join(format!("{hex}.kdl"))).unwrap();
        assert_eq!(cached, data, "final cache entry must be a complete write, never torn");
    }

    // -----------------------------------------------------------------------
    // R6 — index_base_url case-insensitivity (spec §3.3 NORMATIVE)
    // -----------------------------------------------------------------------

    #[test]
    fn base_url_strips_mixed_case_kdl_segment() {
        // "Index.KDL" — all-caps extension, capital I
        assert_eq!(
            index_base_url("https://example.com/tianguis/main/Index.KDL"),
            "https://example.com/tianguis/main/"
        );
    }

    #[test]
    fn base_url_strips_uppercase_kdl_segment() {
        // "INDEX.kdl" — uppercase basename, lowercase extension
        assert_eq!(
            index_base_url("https://example.com/tianguis/main/INDEX.kdl"),
            "https://example.com/tianguis/main/"
        );
    }

    #[test]
    fn base_url_strips_lowercase_kdl_extension_uppercase_base() {
        // "index.KDL" — lowercase base, uppercase extension
        assert_eq!(
            index_base_url("https://example.com/tianguis/main/index.KDL"),
            "https://example.com/tianguis/main/"
        );
    }

    #[test]
    fn base_url_strips_mixed_case_non_index_kdl_segment() {
        // "Registry.KDL" — non-"index" basename, uppercase extension
        assert_eq!(
            index_base_url("https://example.com/custom/Registry.KDL"),
            "https://example.com/custom/"
        );
    }

    #[test]
    fn base_url_strips_uppercase_index_prefix_segment() {
        // "INDEX" — all-caps index* basename
        assert_eq!(
            index_base_url("https://example.com/registry/INDEX"),
            "https://example.com/registry/"
        );
    }

    #[test]
    fn base_url_strips_mixed_case_index_prefix_segment() {
        // "Index-v2" — mixed-case index* basename
        assert_eq!(
            index_base_url("https://example.com/registry/Index-v2"),
            "https://example.com/registry/"
        );
    }

    // -----------------------------------------------------------------------
    // R8 — size cap on file:// fetch (inline; network tests are integration-only)
    // -----------------------------------------------------------------------

    #[test]
    fn file_store_oversized_artifact_raises_fetch_failed() {
        // Write a file larger than DEP_DECL_MAX_ARTIFACT_BYTES and confirm that
        // FileDepDeclStore.get raises TNG-DEPDECL-FETCH-FAILED.
        //
        // NOTE: FileDepDeclStore reads with std::fs::read (no streaming cap), so
        // the size check happens in the store's get() method via http_get_bytes
        // for HttpDepDeclStore.  FileDepDeclStore doesn't pass through
        // http_get_bytes; it is NOT subject to the cap (it reads from a trusted
        // local directory set by the operator via MILPA_DEP_DECL_DIR).  The cap
        // is a transport-level defence against remote resource exhaustion, not a
        // local-file-size constraint.
        //
        // The canonical cap test for file:// is the http_store_file_url path
        // (HttpDepDeclStore with a file:// base_url) — that goes through
        // http_get_bytes and IS subject to the cap.
        let tmp = tempfile::tempdir().unwrap();

        // Build an oversized body and write it to the HttpDepDeclStore serve dir.
        let oversized: Vec<u8> = vec![b'x'; DEP_DECL_MAX_ARTIFACT_BYTES + 1];
        let hash = dep_decl_hash(&oversized);
        let hex = hash.strip_prefix("sha256:").unwrap();

        // Serve via file:// URL through HttpDepDeclStore.
        let dep_decl_dir = tmp.path().join("dep-decl");
        std::fs::create_dir_all(&dep_decl_dir).unwrap();
        std::fs::write(dep_decl_dir.join(format!("{hex}.kdl")), &oversized).unwrap();

        let base_url = format!("file://{}/", tmp.path().to_str().unwrap());
        let store = HttpDepDeclStore::new(base_url, None);
        let err = store.get(&hash).unwrap_err();
        assert_eq!(err.code(), "TNG-DEPDECL-FETCH-FAILED");
        // Error message must mention the cap.
        let msg = format!("{err:?}");
        assert!(
            msg.contains("exceeds") || msg.contains(&DEP_DECL_MAX_ARTIFACT_BYTES.to_string()),
            "expected size-cap message, got: {msg}"
        );
    }

    #[test]
    fn http_store_file_url_at_cap_succeeds() {
        // A body of exactly DEP_DECL_MAX_ARTIFACT_BYTES must NOT be rejected.
        let tmp = tempfile::tempdir().unwrap();
        let exact: Vec<u8> = vec![b'z'; DEP_DECL_MAX_ARTIFACT_BYTES];
        let hash = dep_decl_hash(&exact);
        let hex = hash.strip_prefix("sha256:").unwrap();

        let dep_decl_dir = tmp.path().join("dep-decl");
        std::fs::create_dir_all(&dep_decl_dir).unwrap();
        std::fs::write(dep_decl_dir.join(format!("{hex}.kdl")), &exact).unwrap();

        let base_url = format!("file://{}/", tmp.path().to_str().unwrap());
        let store = HttpDepDeclStore::new(base_url, None);
        // Should succeed (at-cap is allowed) and hash-verify passes.
        let got = store.get(&hash).unwrap();
        assert_eq!(got, exact);
    }
}
