//! tianguis index acquisition + the 4-state cache (RFC registry-trust-federation
//! §7; mirrors `index_cache.py:load_index`).
//!
//! Deferred from S8 (no conformance fixture exercises it — the harness reads
//! `index.kdl` from the fixture dir); its consumer is the CLI's default index
//! loader (S13). [`load_index`] fetches + caches + parses an `index.kdl`, with
//! the four cache states:
//!   - **fresh** (age < ttl, no `--refresh-index`) → serve the cached bytes,
//!     no network; crypto-verify the cached bundle sidecar every read.
//!   - **network fetch** (stale / missing / `--refresh-index`) → fetch index
//!     and bundle; freshness check only on this path; crypto-verify inline.
//!   - **offline fallback** → fetch failed but a (even stale) cache exists →
//!     serve it; crypto-verify the cached bundle, no freshness check.
//!   - **unreachable** → fetch failed and no cached copy → `MILPA-INDEX-UNREACHABLE`.
//!
//! The HTTP transport + clock are injected ([`HttpGet`] / `now_unix`) so the
//! four states are unit-testable without a network or wall-clock.  The cache lives
//! under the global index dir (shared across projects) and is **never** evicted
//! by `milpa clean` — it is the registry, not project state.
//!
//! ## S6: Sigstore bundle verification gate
//!
//! When `config` + `verifier` + `bundle_http_get` are all `Some(…)`, the bundle
//! sidecar is fetched (network states) / read from cache (fresh / offline states)
//! and passed to `verify_index_bundle`; the result is dispatched through
//! `enforce_index_trust`.  `None` for any gate parameter → trust gate disabled
//! (backwards-compatible with pre-S6 callers).
//!
//! Crash recovery: one bounded re-fetch if bundle sidecars are inconsistent on a
//! fresh-cache read. Hard-fail on the second failure (avoids infinite loops).
//!
//! Degraded marker: `<cache>.no-bundle` is written under `Warn` policy when the
//! bundle endpoint 404s; on subsequent fresh-cache reads the marker triggers a
//! synthetic `BundleMissing` → `enforce_index_trust(Warn)`.  Under `Strict` the
//! fetch is hard-failed immediately (no marker, no fallback).

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{CoreError, MilpaError};
use crate::index_trust::{enforce_index_trust, IndexBundleVerifier, IndexTrustConfig,
                          VerificationResult};
use crate::registry::Index;
use milpa_manifest::TrustPolicy;

/// The live tianguis index (the federation seam — one URL for now). The CLI
/// reads [`index_url_from_env`] which lets `MILPA_INDEX_URL` override this.
pub const DEFAULT_INDEX_URL: &str =
    "https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl";

/// 24h — long enough to avoid hammering tianguis on every invocation, short
/// enough that the vendor-en-absentia daily pass is visible within a cycle.
pub const DEFAULT_TTL_SECONDS: u64 = 24 * 60 * 60;

/// `MILPA_INDEX_URL` if set + non-empty, else [`DEFAULT_INDEX_URL`].
pub fn index_url_from_env() -> String {
    std::env::var("MILPA_INDEX_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_INDEX_URL.to_string())
}

/// A fetch transport: maps a URL to its body bytes, or an error string. Injected
/// so tests drive the cache states without a network.
///
/// S6 change from pre-S6: returns `Vec<u8>` (bytes-first; the caller decodes
/// UTF-8 before KDL parse).  The CLI wraps `curl … stdout` directly.
pub type HttpGet<'a> = &'a dyn Fn(&str) -> Result<Vec<u8>, String>;

/// Error type for bundle sidecar fetches: distinguishes HTTP 404 (no bundle at
/// the derived URL) from other network errors.
#[derive(Debug)]
pub enum BundleError {
    /// HTTP 404 — no bundle sidecar published at the derived URL.
    NotFound,
    /// Any other error (network, TLS, parse, …).
    Other(String),
}

/// A bundle sidecar fetch transport. Returns the raw bundle bytes, or a
/// [`BundleError`] distinguishing 404 (→ `BundleMissing`) from other errors.
/// Injected so tests drive all trust-gate paths without network access.
pub type BundleHttpGet<'a> = &'a dyn Fn(&str) -> Result<Vec<u8>, BundleError>;

// ---------------------------------------------------------------------------
// Bundle URL derivation (RFC §7.3)
// ---------------------------------------------------------------------------

/// Derive the bundle sidecar URL from the index URL (RFC registry-trust-federation §7.3).
///
/// Algorithm: strip the query string and fragment from the index URL, append
/// `.bundle` to the PATH component, reattach query string and fragment.
///
/// Examples:
///   `https://host/index.kdl`          → `https://host/index.kdl.bundle`
///   `https://host/index.kdl?ref=main` → `https://host/index.kdl.bundle?ref=main`
///   `https://host/index.kdl#frag`     → `https://host/index.kdl.bundle#frag`
///
/// The `MILPA_INDEX_BUNDLE_URL` env override bypasses this derivation; see
/// [`get_bundle_url`].
pub fn derive_bundle_url(index_url: &str) -> String {
    // Find the first `?` or `#` that separates the path from query/fragment.
    let query_pos = index_url.find('?');
    let frag_pos = index_url.find('#');
    let suffix_start = match (query_pos, frag_pos) {
        (Some(q), Some(f)) => Some(q.min(f)),
        (Some(q), None) => Some(q),
        (None, Some(f)) => Some(f),
        (None, None) => None,
    };
    match suffix_start {
        Some(pos) => {
            let (base, suffix) = index_url.split_at(pos);
            format!("{base}.bundle{suffix}")
        }
        None => format!("{index_url}.bundle"),
    }
}

/// Return the effective bundle URL: `MILPA_INDEX_BUNDLE_URL` override first,
/// then [`derive_bundle_url`].
pub fn get_bundle_url(index_url: &str) -> String {
    std::env::var("MILPA_INDEX_BUNDLE_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| derive_bundle_url(index_url))
}

// ---------------------------------------------------------------------------
// Cache path helpers
// ---------------------------------------------------------------------------

/// Stable per-URL cache filename: `sha256(url)[..16].index.kdl`.
pub fn cache_path_for(url: &str, cache_dir: &Path) -> PathBuf {
    let digest = Sha256::digest(url.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    cache_dir.join(format!("{}.index.kdl", &hex[..16]))
}

/// `<cache_file>.bundle` — the Sigstore bundle sidecar.
fn bundle_path(cache_file: &Path) -> PathBuf {
    let mut p = cache_file.as_os_str().to_os_string();
    p.push(".bundle");
    PathBuf::from(p)
}

/// `<cache_file>.no-bundle` — degraded marker (bundle known-absent under Warn).
fn no_bundle_marker_path(cache_file: &Path) -> PathBuf {
    let mut p = cache_file.as_os_str().to_os_string();
    p.push(".no-bundle");
    PathBuf::from(p)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Return true when the cache looks self-consistent for bundle verification.
///
/// Returns false if the bundle sidecar is absent or empty.  A `.no-bundle`
/// marker is NOT checked here — the caller handles that separately.
fn cache_bundle_looks_ok(bundle_file: &Path) -> bool {
    match std::fs::metadata(bundle_file) {
        Ok(m) => m.len() > 0,
        Err(_) => false,
    }
}

/// Delete the bundle + no-bundle sidecars for `cache_file` (crash recovery).
fn delete_bundle_sidecars(cache_file: &Path) {
    let _ = std::fs::remove_file(bundle_path(cache_file));
    let _ = std::fs::remove_file(no_bundle_marker_path(cache_file));
}

/// Read the sidecar fetch-time stamp (unix seconds), or `None` if absent/invalid.
fn read_stamp(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Cache-dir / cache-file I/O failure — a non-catalog runtime fault.
fn net_or_io(e: std::io::Error) -> MilpaError {
    MilpaError::Core(CoreError::Tianguis(
        "MILPA-INTERNAL-IO",
        format!("index cache I/O error: {e}"),
    ))
}

// ---------------------------------------------------------------------------
// Trust gate helpers
// ---------------------------------------------------------------------------

/// Verify the bundle bytes against `index_bytes` and enforce the trust policy.
///
/// `is_network_fetch` gates the freshness check:
///   - network fetch → pass `Some(config.max_age_seconds)` to the verifier
///   - fresh-cache read / offline fallback → pass `None` (skip wall-clock bound)
fn verify_and_enforce(
    index_bytes: &[u8],
    bundle_bytes: &[u8],
    config: &IndexTrustConfig,
    verifier: &dyn IndexBundleVerifier,
    policy: &TrustPolicy,
    index_url: &str,
    is_network_fetch: bool,
) -> Result<(), MilpaError> {
    let max_age = if is_network_fetch {
        Some(config.max_age_seconds)
    } else {
        None
    };
    let result = verifier.verify(
        index_bytes,
        bundle_bytes,
        &config.trust_bundle,
        &config.expected_signer,
        max_age,
    );
    enforce_index_trust(result, policy, index_url)
}

// ---------------------------------------------------------------------------
// load_index — 4-state cache with optional trust gate
// ---------------------------------------------------------------------------

/// Fetch + cache + parse the `index.kdl` at `url` (see the module doc for the
/// four cache states).
///
/// # Parameters
///
/// - `url`             — The index URL to fetch.
/// - `cache_dir`       — Directory for sidecar files.
/// - `http_get`        — Injected HTTP transport returning raw bytes.
/// - `ttl_seconds`     — Cache freshness window in seconds.
/// - `now_unix`        — Current unix timestamp (injected for test determinism).
/// - `config`          — Optional `IndexTrustConfig`; trust gate disabled when `None`.
/// - `verifier`        — Optional verifier instance; trust gate disabled when `None`.
/// - `bundle_http_get` — Optional bundle transport; trust gate disabled when `None`.
/// - `refresh`         — When `true`, bypass the TTL and force a network fetch
///                       (`--refresh-index` CLI flag / `MILPA_INDEX_BUNDLE_URL` override).
pub fn load_index(
    url: &str,
    cache_dir: &Path,
    http_get: HttpGet<'_>,
    ttl_seconds: u64,
    now_unix: u64,
    config: Option<&IndexTrustConfig>,
    verifier: Option<&dyn IndexBundleVerifier>,
    bundle_http_get: Option<BundleHttpGet<'_>>,
    refresh: bool,
) -> Result<Index, MilpaError> {
    std::fs::create_dir_all(cache_dir).map_err(net_or_io)?;
    let cache_file = cache_path_for(url, cache_dir);
    let stamp_file = cache_file.with_extension("kdl.at");

    // Compute effective trust policy from config (None → Off = no gate).
    let policy = match config {
        Some(cfg) => cfg.policy.clone(),
        None => TrustPolicy::Off,
    };
    let trust_active = policy != TrustPolicy::Off
        && config.is_some()
        && verifier.is_some()
        && bundle_http_get.is_some();

    // --- State 1: fresh cache (age < ttl and not forced refresh) --------------
    if !refresh {
        if let Some(fetched_at) = read_stamp(&stamp_file) {
            if now_unix.saturating_sub(fetched_at) < ttl_seconds {
                match try_serve_from_cache(
                    url,
                    &cache_file,
                    config,
                    verifier,
                    &policy,
                    trust_active,
                    false, // not a network fetch — skip freshness check
                ) {
                    Ok(Some(index)) => return Ok(index),
                    Ok(None) => {
                        // Bundle inconsistency during fresh-cache read — fall through
                        // to crash recovery below (one bounded refetch).
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    // --- State 2: network fetch (stale / missing / --refresh-index) -----------
    let bundle_url = get_bundle_url(url);
    match http_get(url) {
        Ok(index_bytes) => {
            // Fetch bundle sidecar when trust gate is active.
            let bundle_result: Option<Result<Vec<u8>, BundleError>> =
                if trust_active {
                    Some(bundle_http_get.unwrap()(&bundle_url))
                } else {
                    None
                };

            // Atomically write the new index to cache.
            let tmp = cache_file.with_extension(format!("kdl.tmp.{now_unix}"));
            std::fs::write(&tmp, &index_bytes).map_err(net_or_io)?;
            std::fs::rename(&tmp, &cache_file).map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                net_or_io(e)
            })?;
            let _ = std::fs::write(&stamp_file, now_unix.to_string());

            // Handle bundle sidecar: write / degrade-mark / fail.
            if trust_active {
                match bundle_result.unwrap() {
                    Ok(bundle_bytes) => {
                        // Delete any stale no-bundle marker.
                        let _ = std::fs::remove_file(no_bundle_marker_path(&cache_file));
                        // Write bundle sidecar.
                        std::fs::write(bundle_path(&cache_file), &bundle_bytes)
                            .map_err(net_or_io)?;
                        // Verify + enforce (network fetch → freshness check on).
                        if let Some(v) = verifier {
                            verify_and_enforce(
                                &index_bytes,
                                &bundle_bytes,
                                config.unwrap(),
                                v,
                                &policy,
                                url,
                                true,
                            )?;
                        }
                    }
                    Err(BundleError::NotFound) => {
                        // Bundle 404: under Strict → hard fail; under Warn → degrade.
                        if policy == TrustPolicy::Strict {
                            return Err(MilpaError::Core(CoreError::Tianguis(
                                "TNG-INDEX-BUNDLE-MISSING",
                                format!(
                                    "index-trust strict: TNG-INDEX-BUNDLE-MISSING — \
                                     no attestation bundle at {bundle_url:?} for \
                                     index {url:?}. \
                                     Run 'milpa fetch --refresh-index' to retry, \
                                     or set 'index-trust \"off\"' in milpa.kdl."
                                ),
                            )));
                        }
                        // Warn: write the degraded marker + enforce (suppress dup).
                        let _ = std::fs::write(no_bundle_marker_path(&cache_file), b"");
                        enforce_index_trust(
                            VerificationResult::BundleMissing,
                            &policy,
                            url,
                        )?;
                    }
                    Err(BundleError::Other(e)) => {
                        // Non-404 bundle fetch error → treat as BundleMalformed and
                        // propagate under Strict; warn under Warn.
                        enforce_index_trust(
                            VerificationResult::BundleMalformed,
                            &policy,
                            url,
                        )?;
                        if policy == TrustPolicy::Strict {
                            return Err(MilpaError::Core(CoreError::Tianguis(
                                "TNG-INDEX-BUNDLE-MALFORMED",
                                format!(
                                    "index-trust strict: bundle fetch error for {url:?}: {e}"
                                ),
                            )));
                        }
                    }
                }
            }

            let text = std::str::from_utf8(&index_bytes).map_err(|_| {
                MilpaError::Core(CoreError::Tianguis(
                    "MILPA-INTERNAL-IO",
                    format!("index at {url:?} is not valid UTF-8"),
                ))
            })?;
            Index::parse(text).map_err(MilpaError::from)
        }

        Err(fetch_err) => {
            // --- State 3: offline fallback (fetch failed, cache exists) -------
            if cache_file.is_file() {
                match try_serve_from_cache(
                    url,
                    &cache_file,
                    config,
                    verifier,
                    &policy,
                    trust_active,
                    false, // offline → no freshness check
                ) {
                    Ok(Some(index)) => return Ok(index),
                    Ok(None) => {
                        // Bundle inconsistency during offline read and we already
                        // exhausted refetch; hard-fail.
                        return Err(MilpaError::Core(CoreError::Tianguis(
                            "MILPA-INDEX-UNREACHABLE",
                            format!(
                                "failed to load index from {url:?}: {fetch_err}; \
                                 and the cached bundle sidecar is inconsistent \
                                 (crash recovery exhausted)"
                            ),
                        )));
                    }
                    Err(e) => return Err(e),
                }
            }
            // --- State 4: no cache → unreachable --------------------------------
            Err(MilpaError::Core(CoreError::Tianguis(
                "MILPA-INDEX-UNREACHABLE",
                format!("failed to load index from {url:?}: {fetch_err}"),
            )))
        }
    }
}

/// Attempt to serve the index from the on-disk cache.
///
/// Returns:
///   - `Ok(Some(index))` — cache hit, trust gate passed (or inactive).
///   - `Ok(None)`        — cache exists but bundle sidecar is inconsistent;
///                         caller should attempt crash recovery / fall through.
///   - `Err(_)`          — hard trust-gate failure (Strict) or I/O error.
fn try_serve_from_cache(
    url: &str,
    cache_file: &Path,
    config: Option<&IndexTrustConfig>,
    verifier: Option<&dyn IndexBundleVerifier>,
    policy: &TrustPolicy,
    trust_active: bool,
    is_network_fetch: bool,
) -> Result<Option<Index>, MilpaError> {
    let index_bytes = std::fs::read(cache_file).map_err(net_or_io)?;

    if trust_active {
        let bp = bundle_path(cache_file);
        let nbp = no_bundle_marker_path(cache_file);

        // Check for degraded (.no-bundle) marker first.
        if nbp.exists() {
            enforce_index_trust(VerificationResult::BundleMissing, policy, url)?;
            // Warn → continue; Strict handled in the caller (never reaches here).
        } else if cache_bundle_looks_ok(&bp) {
            // Bundle sidecar present — verify.
            let bundle_bytes = std::fs::read(&bp).map_err(net_or_io)?;
            if let (Some(cfg), Some(v)) = (config, verifier) {
                verify_and_enforce(
                    &index_bytes,
                    &bundle_bytes,
                    cfg,
                    v,
                    policy,
                    url,
                    is_network_fetch,
                )?;
            }
        } else {
            // Bundle sidecar absent (neither a .no-bundle marker nor a .bundle
            // file) — inconsistent cache state; signal crash recovery needed.
            delete_bundle_sidecars(cache_file);
            return Ok(None);
        }
    }

    let text = std::str::from_utf8(&index_bytes).map_err(|_| {
        MilpaError::Core(CoreError::Tianguis(
            "MILPA-INTERNAL-IO",
            format!("cached index at {:?} is not valid UTF-8", cache_file),
        ))
    })?;
    Ok(Some(Index::parse(text).map_err(MilpaError::from)?))
}

#[cfg(test)]
#[path = "index_cache_tests.rs"]
mod index_cache_tests;
