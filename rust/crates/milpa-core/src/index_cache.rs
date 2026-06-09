//! tianguis index acquisition + the 4-state cache (RFC §6 S8/S13; mirrors
//! `tianguis_client.py:load_index`).
//!
//! Deferred from S8 (no conformance fixture exercises it — the harness reads
//! `index.kdl` from the fixture dir); its consumer is the CLI's default index
//! loader (S13). [`load_index`] fetches + caches + parses an `index.kdl`, with
//! the four cache states:
//!   - **fresh** (age < ttl) → serve the cached bytes, no network;
//!   - **stale** (age ≥ ttl) → re-fetch, overwrite the cache;
//!   - **missing** → fetch, populate;
//!   - **offline-fallback** → fetch failed but a (even stale) cache exists →
//!     serve it rather than hard-failing.
//!
//! The HTTP transport + clock are injected ([`HttpGet`] / `now_unix`) so the
//! four states are unit-testable without a network or wall-clock. The cache lives
//! under the global index dir (shared across projects) and is **never** evicted
//! by `milpa clean` — it is the registry, not project state.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{CoreError, MilpaError};
use crate::registry::Index;

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

/// A fetch transport: maps a URL to its body text, or an error string. Injected
/// so tests drive the cache states without a network.
pub type HttpGet<'a> = &'a dyn Fn(&str) -> Result<String, String>;

/// Stable per-URL cache filename: `sha256(url)[..16].index.kdl` (filesystem-safe
/// across arbitrary URL shapes).
pub fn cache_path_for(url: &str, cache_dir: &Path) -> PathBuf {
    let digest = Sha256::digest(url.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    cache_dir.join(format!("{}.index.kdl", &hex[..16]))
}

/// Fetch + cache + parse the `index.kdl` at `url` (see the module doc for the
/// four cache states). `now_unix` is the current time in seconds (injected for
/// test determinism); the freshly-written cache entry's mtime is stamped to it.
pub fn load_index(
    url: &str,
    cache_dir: &Path,
    http_get: HttpGet<'_>,
    ttl_seconds: u64,
    now_unix: u64,
) -> Result<Index, MilpaError> {
    std::fs::create_dir_all(cache_dir).map_err(net_or_io)?;
    let cache_file = cache_path_for(url, cache_dir);
    let stamp_file = cache_file.with_extension("at");

    // Fresh cache → serve without network. The fetch time is recorded in a
    // sidecar `.at` file (not the fs mtime) so age is controlled by the injected
    // `now_unix` clock — deterministic, and MSRV-safe (no `File::set_modified`).
    if let Some(fetched_at) = read_stamp(&stamp_file) {
        if now_unix.saturating_sub(fetched_at) < ttl_seconds {
            let text = std::fs::read_to_string(&cache_file).map_err(net_or_io)?;
            return Index::parse(&text).map_err(MilpaError::from);
        }
    }

    // Stale / missing → fetch; on fetch failure fall back to any cached copy.
    let text = match http_get(url) {
        Ok(t) => t,
        Err(e) => {
            if cache_file.is_file() {
                let cached = std::fs::read_to_string(&cache_file).map_err(net_or_io)?;
                return Index::parse(&cached).map_err(MilpaError::from);
            }
            return Err(MilpaError::Core(CoreError::Tianguis(
                // Non-catalog sentinel: index acquisition failure is a CLI
                // runtime error, not a spec error code (kept out of all_codes()).
                "MILPA-INDEX-UNREACHABLE",
                format!("failed to load index from {url}: {e}"),
            )));
        }
    };

    // Atomic write: temp sibling + rename, so a concurrent reader never sees a
    // half-written file. Then stamp mtime to the injected clock.
    let tmp = cache_file.with_extension(format!("kdl.tmp.{now_unix}"));
    std::fs::write(&tmp, &text).map_err(net_or_io)?;
    std::fs::rename(&tmp, &cache_file).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        net_or_io(e)
    })?;
    // Record the fetch time so freshness is governed by the injected clock.
    let _ = std::fs::write(&stamp_file, now_unix.to_string());

    Index::parse(&text).map_err(MilpaError::from)
}

/// Read the sidecar fetch-time stamp (unix seconds), or `None` if absent/invalid.
fn read_stamp(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Cache-dir / cache-file I/O failure — a non-catalog runtime fault (same
/// treatment as the `MILPA-INTERNAL-IO` sentinel elsewhere).
fn net_or_io(e: std::io::Error) -> MilpaError {
    MilpaError::Core(CoreError::Tianguis(
        "MILPA-INTERNAL-IO",
        format!("index cache I/O error: {e}"),
    ))
}

#[cfg(test)]
#[path = "index_cache_tests.rs"]
mod index_cache_tests;
