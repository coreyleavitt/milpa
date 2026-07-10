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
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use crate::error::{CoreError, MilpaError};
use crate::index_ratchet_seam::{evaluate_gate, parse_baseline_meta, BaselineMeta, GateDecision};
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
///
/// `pub` so `cmd_show_index_trust` can locate the cached bundle without
/// reconstructing the `.bundle` suffix inline (Item 5b SSOT).
pub fn bundle_path(cache_file: &Path) -> PathBuf {
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

/// `<cache_file>.baseline` — the append-only ratchet baseline sidecar (A3,
/// registry-protocol §3.5.2/§6): a full copy of the last index that passed
/// the ratchet cleanly.
fn baseline_path(cache_file: &Path) -> PathBuf {
    let mut p = cache_file.as_os_str().to_os_string();
    p.push(".baseline");
    PathBuf::from(p)
}

/// `<cache_file>.baseline.meta` — the ratchet baseline metadata sidecar (A3,
/// registry-protocol §3.5.2/§6): `established_at`/`reported_digest`/
/// `reported_at`, written atomically as a unit.
fn baseline_meta_path(cache_file: &Path) -> PathBuf {
    let mut p = cache_file.as_os_str().to_os_string();
    p.push(".baseline.meta");
    PathBuf::from(p)
}

/// Public accessor for the ratchet baseline sidecar pair's paths for `url`
/// — the ONE naming authority both the ordinary ratchet-gated fetch path
/// (`run_ratchet_gate`/`apply_ratchet_writes`, below) and `milpa index
/// status`/`accept` (the CLI, A3) use, so the two never drift
/// (registry-protocol §6 NORMATIVE).
pub fn baseline_sidecar_paths(url: &str, cache_dir: &Path) -> (PathBuf, PathBuf) {
    let cache_file = cache_path_for(url, cache_dir);
    (baseline_path(&cache_file), baseline_meta_path(&cache_file))
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
// Internal write helper (Item 4 — extracted from ×4 inline occurrences)
// ---------------------------------------------------------------------------

/// A per-write-unique sibling temp path for `path` (PID + monotonic counter
/// + wall-clock nanos).
///
/// registry-protocol §3.5.2 NORMATIVE (concurrency): a FIXED temp sibling
/// name lets two concurrent writers interleave partial writes before either
/// renames — a hazard for every index-cache write (bundle sidecar, index
/// file, and the baseline pair). Every write in this module goes through
/// this helper (via [`atomic_write_bytes`]) so no site can regress to a
/// fixed name. Mirrors `index_cache.py::_unique_temp_path` (PID + random
/// suffix); the atomic-rename safety property does not depend on
/// cryptographic randomness, only on no two concurrent writers choosing the
/// SAME temp name — PID + a process-local monotonic counter + nanosecond
/// timestamp is sufficient.
static TEMP_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(path: &Path) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = TEMP_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = path.as_os_str().to_os_string();
    p.push(format!(".tmp.{pid}.{nanos}.{counter}"));
    PathBuf::from(p)
}

/// Write `data` to `path` atomically (unique sibling tmp + rename). Used for
/// EVERY index-cache sidecar write (bundle, index, baseline, `.baseline.meta`)
/// per registry-protocol §3.5.2 NORMATIVE (concurrency).
fn atomic_write_bytes(path: &Path, data: &[u8]) -> Result<(), MilpaError> {
    let tmp = unique_temp_path(path);
    std::fs::write(&tmp, data).map_err(net_or_io)?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        net_or_io(e)
    })
}

/// Atomic index-cache write: tmp write → rename (atomic on POSIX) → stamp write.
///
/// Write order: index bytes → stamp. The stamp file is written LAST so that a
/// crash between the rename and the stamp write is correctly detected as a
/// "stale" cache entry on the next read (no stamp ⇒ missing ⇒ refetch).
///
/// Item 4: extracted from the four state-2 arms that previously inlined this
/// sequence verbatim.  The `.bundle` sidecar write (when present) is handled
/// BEFORE calling this helper (spec §7.2 write order: bundle → index → stamp).
fn write_index_to_cache(
    cache_file: &Path,
    index_bytes: &[u8],
    stamp_file: &Path,
    now_unix: u64,
) -> Result<(), MilpaError> {
    atomic_write_bytes(cache_file, index_bytes)?;
    let _ = std::fs::write(stamp_file, now_unix.to_string());
    Ok(())
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

/// Re-verify the ALREADY-CACHED index attestation bundle, fully offline (Sv,
/// `rfc-attestation-verifier`).
///
/// Reads the on-disk cached `index.kdl` + `index.kdl.bundle` and re-runs bundle
/// verification + policy enforcement with freshness DISABLED (`is_network_fetch =
/// false`) — the offline post-incident audit path `milpa verify` provides (Part-1
/// §7.5). It **never** touches the network and does **not** go through the cache
/// state machine (no fetch, no TTL, no stale-refresh), so it cannot change any
/// Part-1 cache behavior.
///
/// No-op when `config.policy == Off` or when nothing is cached for `url`. A
/// recorded bundle-404 (`.no-bundle` marker) or an absent sidecar enforces
/// `BundleMissing`; a present-but-invalid bundle raises the mapped `TNG-INDEX-*`
/// slug under `Strict` (warns under `Warn`).
pub fn reverify_cached_index(
    url: &str,
    cache_dir: &Path,
    config: &IndexTrustConfig,
    verifier: &dyn IndexBundleVerifier,
) -> Result<(), MilpaError> {
    if config.policy == TrustPolicy::Off {
        return Ok(());
    }
    let cache_file = cache_path_for(url, cache_dir);
    if !cache_file.exists() {
        return Ok(()); // nothing cached to reverify — and we must not fetch here
    }
    let index_bytes = std::fs::read(&cache_file).map_err(|e| {
        MilpaError::Core(CoreError::Tianguis(
            "MILPA-INTERNAL",
            format!("could not read cached index {}: {e}", cache_file.display()),
        ))
    })?;
    if no_bundle_marker_path(&cache_file).exists() {
        return enforce_index_trust(VerificationResult::BundleMissing, &config.policy, url);
    }
    match std::fs::read(bundle_path(&cache_file)) {
        Ok(bundle_bytes) => verify_and_enforce(
            &index_bytes,
            &bundle_bytes,
            config,
            verifier,
            &config.policy,
            url,
            false,
        ),
        Err(_) => enforce_index_trust(VerificationResult::BundleMissing, &config.policy, url),
    }
}

// ---------------------------------------------------------------------------
// Append-only ratchet gate (registry-protocol §3.5.2, rfc-registry-append-
// only.md §2, slice A3). `index_ratchet_seam.rs` is pure computation (no
// I/O); this module owns every read/write of the baseline sidecar pair,
// mirroring how it already owns the bundle/index/stamp sidecars. Mirrors
// `index_cache.py::_run_ratchet_gate` / `_apply_ratchet_writes`.
// ---------------------------------------------------------------------------

/// Parse-at-gate + the append-only ratchet check. Reads the baseline
/// sidecar pair (when `policy` is not `Off`); performs NO writes.
///
/// Errors: decode/parse failure on the candidate (any policy),
/// `TNG-INDEX-BASELINE-CORRUPT` (any policy except `Off`), or the primary
/// violation's slug under `Strict` — in every case BEFORE the caller has
/// written anything to the cache.
fn run_ratchet_gate(
    policy: &TrustPolicy,
    cache_file: &Path,
    candidate_bytes: &[u8],
    now_unix: u64,
    url: &str,
) -> Result<GateDecision, MilpaError> {
    let candidate_text = std::str::from_utf8(candidate_bytes).map_err(|e| {
        MilpaError::Core(CoreError::Tianguis(
            "TNG-KDL-SYNTAX",
            format!("index bytes from {url:?} are not valid UTF-8: {e}"),
        ))
    })?;

    let baseline_p = baseline_path(cache_file);
    let meta_p = baseline_meta_path(cache_file);

    let baseline_text: Option<String> = if *policy != TrustPolicy::Off && baseline_p.is_file() {
        let raw = std::fs::read(&baseline_p).map_err(net_or_io)?;
        let decoded = std::str::from_utf8(&raw).map_err(|e| {
            MilpaError::Core(CoreError::Tianguis(
                "TNG-INDEX-BASELINE-CORRUPT",
                format!(
                    "baseline sidecar at {} is not valid UTF-8: {e}; \
                     re-establish the trust anchor via `milpa index accept`",
                    baseline_p.display()
                ),
            ))
        })?;
        Some(decoded.to_string())
    } else {
        None
    };

    // .meta is advisory (§3.5.2 NORMATIVE): a decode failure here is
    // self-healing (treated as unset), never an error.
    let existing_meta = if *policy != TrustPolicy::Off && meta_p.is_file() {
        std::fs::read_to_string(&meta_p)
            .map(|text| parse_baseline_meta(&text))
            .unwrap_or_default()
    } else {
        BaselineMeta::default()
    };

    evaluate_gate(
        policy,
        candidate_text,
        baseline_text.as_deref(),
        &existing_meta,
        now_unix as i64,
        url,
    )
}

/// Write the baseline sidecar pair per `decision` (write ordering steps
/// 5-6 — MUST be called strictly after the index file write, and only for
/// the writer callers that just wrote a genuinely-new candidate: TOFU
/// establishment and clean-diff sticky-advance always set `advance`; a
/// `warn`-dirty new-digest report sets only `new_meta`). A no-op when
/// neither is set (`Off` policy, or a recurring warn).
fn apply_ratchet_writes(cache_file: &Path, decision: &GateDecision, candidate_bytes: &[u8]) -> Result<(), MilpaError> {
    if !decision.advance && decision.new_meta.is_none() {
        return Ok(());
    }
    if decision.advance {
        // Full copy of the candidate bytes ACTUALLY SERVED (never a
        // re-serialization) — §3.5.2 NORMATIVE (write ordering).
        atomic_write_bytes(&baseline_path(cache_file), candidate_bytes)?;
    }
    if let Some(meta) = &decision.new_meta {
        atomic_write_bytes(&baseline_meta_path(cache_file), meta.render().as_bytes())?;
    }
    Ok(())
}

/// Atomically swap the ratchet baseline pair for `url` — the ONLY mutation
/// `milpa index accept` performs (cli-contract.md §5.12; registry-protocol
/// §6 NORMATIVE). Each sidecar goes through the same per-write-unique-
/// temp-name atomic writer ([`atomic_write_bytes`]) the ordinary ratchet
/// gate uses (§3.5.2 NORMATIVE (concurrency)) — write order is baseline
/// then `.meta`, matching [`apply_ratchet_writes`].
///
/// Errors with `TNG-INDEX-BASELINE-WRITE-FAILED` — loud and distinct,
/// never a silent no-op — wrapping any I/O failure. Because each write is
/// atomic (temp + rename) and the baseline is attempted first, a failure
/// creating/renaming the FIRST temp file leaves the previous pair
/// completely untouched; a failure on the second (`.meta`) write after a
/// successful baseline swap is covered by `.meta`'s documented
/// advisory/self-healing semantics.
pub fn write_baseline_pair(
    url: &str,
    cache_dir: &Path,
    candidate_bytes: &[u8],
    meta: &BaselineMeta,
) -> Result<(), MilpaError> {
    let (baseline_p, meta_p) = baseline_sidecar_paths(url, cache_dir);
    let write = || -> Result<(), MilpaError> {
        std::fs::create_dir_all(cache_dir).map_err(net_or_io)?;
        atomic_write_bytes(&baseline_p, candidate_bytes)?;
        atomic_write_bytes(&meta_p, meta.render().as_bytes())?;
        Ok(())
    };
    write().map_err(|e| {
        MilpaError::Core(CoreError::Tianguis(
            "TNG-INDEX-BASELINE-WRITE-FAILED",
            format!(
                "failed to write the append-only ratchet baseline for {url:?}: {e:?} \
                 — the previous baseline pair (if any) is left intact"
            ),
        ))
    })
}

/// Force a network fetch of `url` and verify it under the effective
/// index-trust policy — WITHOUT any cache mutation (no bundle sidecar, no
/// index write, no freshness stamp, no ratchet baseline touched).
///
/// This is the shared fetch-and-verify primitive for `milpa index status
/// --refresh` / `milpa index accept` (cli-contract.md §5.12, A3): both need
/// "what would a forced refresh find" as plain text to diff against the
/// local baseline, without any of [`load_index_with_history`]'s State-2
/// cache side effects — the `--refresh-index` precedent applied to a
/// read-only probe. Reuses [`verify_and_enforce`] (the SAME trust-
/// enforcement call site the ordinary fetch path uses) rather than
/// re-implementing policy dispatch.
///
/// Errors with a bare-network-failure wrapping (`MILPA-INDEX-UNREACHABLE`)
/// or the mapped `TNG-INDEX-*` slug on a trust-gate failure — both BEFORE
/// any cache mutation is ever attempted.
pub fn fetch_verified_candidate_text(
    url: &str,
    http_get: HttpGet<'_>,
    bundle_http_get: Option<BundleHttpGet<'_>>,
    config: Option<&IndexTrustConfig>,
    verifier: Option<&dyn IndexBundleVerifier>,
) -> Result<String, MilpaError> {
    let fetched_bytes = http_get(url).map_err(|e| {
        MilpaError::Core(CoreError::Tianguis(
            "MILPA-INDEX-UNREACHABLE",
            format!("failed to fetch index candidate from {url:?}: {e}"),
        ))
    })?;

    if let (Some(config), Some(verifier)) = (config, verifier) {
        let bundle_url = get_bundle_url(url);
        let fetched_bundle: Option<Vec<u8>> = bundle_http_get.and_then(|get| get(&bundle_url).ok());
        match fetched_bundle {
            None => {
                enforce_index_trust(VerificationResult::BundleMissing, &config.policy, url)?;
            }
            Some(bundle_bytes) => {
                verify_and_enforce(&fetched_bytes, &bundle_bytes, config, verifier, &config.policy, url, true)?;
            }
        }
    }

    String::from_utf8(fetched_bytes).map_err(|e| {
        MilpaError::Core(CoreError::Tianguis(
            "TNG-KDL-SYNTAX",
            format!("index bytes from {url:?} are not valid UTF-8: {e}"),
        ))
    })
}

// ---------------------------------------------------------------------------
// load_index — 4-state cache with optional trust gate
// ---------------------------------------------------------------------------

/// Fetch + cache + parse the `index.kdl` at `url` — the pre-A3 signature,
/// preserved for the ~35 existing call sites (`index_cache_tests.rs`) that
/// don't opt into the append-only ratchet. Delegates to
/// [`load_index_with_history`] with `index_history_policy = Off` (mirrors
/// Python's `load_index(..., index_history_policy: str = "off")` default
/// parameter — Rust has no default arguments, so the "low-level function's
/// pre-A2d behavior for callers that don't opt in" is expressed as a thin
/// wrapper instead of a default value).
///
/// See [`load_index_with_history`] for the parameter docs and the four
/// cache states.
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
    load_index_with_history(
        url,
        cache_dir,
        http_get,
        ttl_seconds,
        now_unix,
        config,
        verifier,
        bundle_http_get,
        refresh,
        &TrustPolicy::Off,
    )
}

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
/// - `index_history_policy` — A3 (`rfc-registry-append-only.md` §2;
///                       registry-protocol §3.5.2): the append-only ratchet's
///                       own policy axis, orthogonal to `index-trust`. Runs
///                       on EVERY network-fetch path (this function's State-2
///                       body, including the `is_recovery` crash-recovery
///                       re-fetch — ONE function, both flows gated), never on
///                       a pure cache read (States 1/3).
#[allow(clippy::too_many_arguments)]
pub fn load_index_with_history(
    url: &str,
    cache_dir: &Path,
    http_get: HttpGet<'_>,
    ttl_seconds: u64,
    now_unix: u64,
    config: Option<&IndexTrustConfig>,
    verifier: Option<&dyn IndexBundleVerifier>,
    bundle_http_get: Option<BundleHttpGet<'_>>,
    refresh: bool,
    index_history_policy: &TrustPolicy,
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

    // Track whether we arrived at State 2 via crash-recovery (State 1 → Ok(None)).
    // Spec §3.4.5 NORMATIVE: if the (index, bundle) pair fetched during a
    // crash-RECOVERY re-fetch ALSO fails verification, the impl MUST hard-fail
    // with MILPA-INDEX-UNREACHABLE regardless of policy (active-adversary signal).
    let mut is_recovery = false;

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
                        is_recovery = true;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    // --- State 2: network fetch (stale / missing / --refresh-index) -----------
    //
    // Spec §7.2 ordering: verify in-memory FIRST; write to cache ONLY on success.
    // Prior to this fix the cache was written before verification, leaving a
    // fresh-stamped UNVERIFIED index on disk after a strict failure.
    //
    // Spec §3.4.5: when is_recovery=true, any bundle failure (404, transport error,
    // or verification failure) is a hard MILPA-INDEX-UNREACHABLE regardless of policy.
    let bundle_url = get_bundle_url(url);
    match http_get(url) {
        Ok(index_bytes) => {
            // Fetch bundle sidecar when trust gate is active (both fetches are in-memory;
            // no cache mutation yet).
            let bundle_result: Option<Result<Vec<u8>, BundleError>> =
                if trust_active {
                    Some(bundle_http_get.unwrap()(&bundle_url))
                } else {
                    None
                };

            // A3 (registry-protocol §3.5.2, rfc-registry-append-only.md §2):
            // the append-only ratchet gate's outcome for whichever branch
            // below actually persists — set exactly once, immediately after
            // Layer-1 (index-trust) succeeds and BEFORE that branch's first
            // cache write (including the bundle sidecar write), so a
            // strict-rejected candidate or an unparseable candidate never
            // reaches ANY write. Runs identically on the ordinary State-2
            // fetch and the `is_recovery` crash-recovery re-fetch — ONE
            // function, both flows gated (no second seam).
            //
            // The `None` init is never actually read (every reachable path
            // below sets it before the final `.expect()`, or returns early
            // via `?`) — `#[allow]` documents that this is by construction,
            // not an oversight.
            #[allow(unused_assignments)]
            let mut ratchet_decision: Option<GateDecision> = None;

            // Spec §7.2: resolve the trust-gate disposition entirely in-memory before
            // touching the cache.  Each arm either returns an error (no cache write)
            // or completes the appropriate cache write on success.
            if trust_active {
                match bundle_result.unwrap() {
                    Ok(bundle_bytes) => {
                        // config and verifier are always Some here (trust_active asserts it).
                        let cfg_ref = config.expect("config must be Some when trust_active");
                        let ver_ref = verifier.expect("verifier must be Some when trust_active");

                        // Spec §3.4.5 NORMATIVE: on the crash-recovery path, check the raw
                        // verification result BEFORE dispatching through policy.  Any non-Trusted
                        // result on a recovery re-fetch MUST hard-fail MILPA-INDEX-UNREACHABLE
                        // regardless of Warn/Strict policy (active-adversary signal).
                        if is_recovery {
                            let max_age = Some(cfg_ref.max_age_seconds);
                            let raw = ver_ref.verify(
                                &index_bytes,
                                &bundle_bytes,
                                &cfg_ref.trust_bundle,
                                &cfg_ref.expected_signer,
                                max_age,
                            );
                            if raw != VerificationResult::Trusted {
                                return Err(MilpaError::Core(CoreError::Tianguis(
                                    "MILPA-INDEX-UNREACHABLE",
                                    format!(
                                        "crash-recovery: second consecutive bundle failure \
                                         for {url:?} (result={:?}) — hard-fail \
                                         (active-adversary signal per spec §3.4.5)",
                                        raw.value()
                                    ),
                                )));
                            }
                            // Trusted on recovery: run the ratchet gate (parse-at-gate;
                            // a strict violation or unparseable candidate raises here,
                            // BEFORE any write), then write cache and proceed normally.
                            let decision = run_ratchet_gate(
                                index_history_policy,
                                &cache_file,
                                &index_bytes,
                                now_unix,
                                url,
                            )?;
                            let _ = std::fs::remove_file(no_bundle_marker_path(&cache_file));
                            atomic_write_bytes(&bundle_path(&cache_file), &bundle_bytes)?;
                            write_index_to_cache(&cache_file, &index_bytes, &stamp_file, now_unix)?;
                            ratchet_decision = Some(decision);
                        } else {
                            // Non-recovery: normal verify-and-enforce (policy gates errors).
                            // On failure (Strict): return error WITHOUT writing anything.
                            verify_and_enforce(
                                &index_bytes,
                                &bundle_bytes,
                                cfg_ref,
                                ver_ref,
                                &policy,
                                url,
                                true,
                            )?;
                            // Verification passed (or Warn — enforce returned Ok). Run the
                            // ratchet gate next (parse-at-gate, before ANY write).
                            let decision = run_ratchet_gate(
                                index_history_policy,
                                &cache_file,
                                &index_bytes,
                                now_unix,
                                url,
                            )?;
                            // Spec §7.2 write order: bundle sidecar → index → stamp.
                            let _ = std::fs::remove_file(no_bundle_marker_path(&cache_file));
                            atomic_write_bytes(&bundle_path(&cache_file), &bundle_bytes)?;
                            write_index_to_cache(&cache_file, &index_bytes, &stamp_file, now_unix)?;
                            ratchet_decision = Some(decision);
                        }
                    }
                    Err(BundleError::NotFound) => {
                        // Bundle 404.
                        // Spec §3.4.5: on the crash-recovery path, 404 is a hard-fail
                        // MILPA-INDEX-UNREACHABLE regardless of policy (second consecutive
                        // miss is an active-adversary signal).  Do NOT write any marker.
                        if is_recovery {
                            return Err(MilpaError::Core(CoreError::Tianguis(
                                "MILPA-INDEX-UNREACHABLE",
                                format!(
                                    "crash-recovery: bundle still unavailable (404) at \
                                     {bundle_url:?} for index {url:?} — hard-fail \
                                     (active-adversary signal per spec §3.4.5)"
                                ),
                            )));
                        }
                        // Non-recovery 404: under Strict → hard fail (no cache write).
                        // Under Warn → write degraded state (index + stamp + .no-bundle marker).
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
                        // Warn: run the ratchet gate first (before the degraded-marker
                        // write — parse-at-gate applies here too), then write degraded
                        // marker + index + stamp.
                        let decision = run_ratchet_gate(
                            index_history_policy,
                            &cache_file,
                            &index_bytes,
                            now_unix,
                            url,
                        )?;
                        let _ = std::fs::write(no_bundle_marker_path(&cache_file), b"");
                        write_index_to_cache(&cache_file, &index_bytes, &stamp_file, now_unix)?;
                        enforce_index_trust(VerificationResult::BundleMissing, &policy, url)?;
                        ratchet_decision = Some(decision);
                    }
                    Err(BundleError::Other(_e)) => {
                        // Non-404 transport error: bytes never arrived → BundleMissing
                        // (BundleMalformed is reserved for bytes that arrived but don't parse).
                        //
                        // Spec §3.4.5: on the crash-recovery path, transport error is a
                        // hard-fail MILPA-INDEX-UNREACHABLE regardless of policy.
                        if is_recovery {
                            return Err(MilpaError::Core(CoreError::Tianguis(
                                "MILPA-INDEX-UNREACHABLE",
                                format!(
                                    "crash-recovery: bundle transport error at \
                                     {bundle_url:?} for index {url:?} — hard-fail \
                                     (active-adversary signal per spec §3.4.5)"
                                ),
                            )));
                        }
                        // Non-recovery transport error: no .no-bundle marker (transient;
                        // next read goes through crash-recovery refetch without degraded side-channel).
                        // Strict: fail closed — no cache write, no marker.
                        // Warn: emit warning, then run the ratchet gate, then write index + stamp.
                        enforce_index_trust(VerificationResult::BundleMissing, &policy, url)?;
                        // Reached only under Warn (Strict already returned via `?`).
                        let decision = run_ratchet_gate(
                            index_history_policy,
                            &cache_file,
                            &index_bytes,
                            now_unix,
                            url,
                        )?;
                        write_index_to_cache(&cache_file, &index_bytes, &stamp_file, now_unix)?;
                        ratchet_decision = Some(decision);
                    }
                }
            } else {
                // No trust gate: run the ratchet gate (its own policy axis is
                // independent of index-trust), then write index + stamp.
                let decision = run_ratchet_gate(
                    index_history_policy,
                    &cache_file,
                    &index_bytes,
                    now_unix,
                    url,
                )?;
                write_index_to_cache(&cache_file, &index_bytes, &stamp_file, now_unix)?;
                ratchet_decision = Some(decision);
            }

            // Sticky-advance the ratchet baseline (only on a clean diff /
            // TOFU — write ordering steps 5-6, strictly after the index
            // write above so the baseline only ever reflects content
            // actually served).
            let decision = ratchet_decision
                .expect("every branch above that reaches here set ratchet_decision");
            apply_ratchet_writes(&cache_file, &decision, &index_bytes)?;
            Ok(decision.index)
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
            // config and verifier are always Some here: trust_active asserts it
            // (trust_active = policy≠Off && config.is_some() && verifier.is_some()).
            // The inner Option-check was dead code (Item 5a); removed.
            let bundle_bytes = std::fs::read(&bp).map_err(net_or_io)?;
            verify_and_enforce(
                &index_bytes,
                &bundle_bytes,
                config.expect("config must be Some when trust_active"),
                verifier.expect("verifier must be Some when trust_active"),
                policy,
                url,
                is_network_fetch,
            )?;
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
