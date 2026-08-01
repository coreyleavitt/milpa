//! Real transport fetchers + the dispatching registry (RFC §6 S14c; mirrors
//! `milpa/fetchers/{local,git,...}.py` + the `FetcherRegistry` dispatch).
//!
//! [`DefaultRegistry`] matches the closed [`Provenance`] enum and routes to a
//! per-transport fetch. Identity is **never** reported by a fetcher — the caller
//! (resolver / CAS) computes it from the materialized bytes, so a fetcher can't
//! lie about content (RFC §4.6).
//!
//! **This sub-slice wires Local + Git** (both offline-testable: Local is a pure
//! directory copy; Git drives the `git` CLI, exercised against *local* repos in
//! tests — no network). Tarball (http + gzip + safe_extract) and OCI (oras) land
//! in the next sub-slice; their dispatch arms return a clearly-marked
//! non-catalog placeholder until then.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use flate2::read::GzDecoder;
use milpa_types::Provenance;

/// Magic-byte signatures for compressed archive formats
/// (spec/manifest-grammar.md §TarballDep).
const MAGIC_GZIP: &[u8] = &[0x1f, 0x8b];
const MAGIC_BZ2: &[u8] = &[0x42, 0x5a, 0x68]; // "BZh"
const MAGIC_XZ: &[u8] = &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
/// ZIP local-file-header magic (`PK\x03\x04`). `TarballFetcher` is `.tar.*`
/// only; a ZIP archive is an unsupported format and MUST be rejected with
/// `FETCH-EXTRACT-FAILED` rather than silently producing an empty tree.
const MAGIC_ZIP: &[u8] = &[0x50, 0x4b, 0x03, 0x04];
use sha2::{Digest, Sha256};

// R2-06: `DECOMP_CAP_OVERHEAD` is now defined in `safe_extract.rs` as the single
// source of truth (pub(crate) const).  It is used here via `Limits::decomp_cap()`
// (which adds the overhead) — there is no separate local copy in this module.

/// Maximum compressed bytes accepted from a single HTTP download before the
/// request is rejected (R4 — finding: uncapped compressed download DoS).
///
/// Set to `Limits::max_total_size * 4` (4 GiB) — a conservative upper bound
/// given typical archive compression ratios.  Both impls use the SAME value
/// for cross-impl byte-identity (Python `MAX_COMPRESSED_BYTES` = same formula).
///
/// Enforced by `fetch_tarball` (and its `_with_cap` variant) after the
/// transport call: if `len(bytes) > MAX_COMPRESSED_BYTES`, raises
/// `FETCH-DOWNLOAD-FAILED` before any decompression or extraction.
///
/// The mocked / build-mode fetchers bypass `http_get` entirely and are
/// unaffected.
pub const MAX_COMPRESSED_BYTES: u64 = crate::safe_extract::Limits::DEFAULT_MAX_TOTAL_SIZE * 4;

/// Decompress `src` using `decoder` (any `Read`) into a `Vec<u8>`, enforcing
/// the SA-1 decompression-bomb cap (`Limits::max_total_size + DECOMP_CAP_OVERHEAD`).
///
/// Returns `Ok(bytes)` or a transport-coded `FetchError`. This is the single
/// source of truth for the cap formula and the `EXTRACT-SIZE-LIMIT` raise on
/// cap breach — both `fetch_tarball` (gzip / bzip2) and `fetch_oci` (gzip) call
/// this instead of maintaining parallel inline copies.
fn decompress_capped(
    decoder: impl Read,
    decomp_cap: u64,
    name: &str,
    format: &str,
) -> Result<Vec<u8>, FetchError> {
    // R1-08: admit a stream of EXACTLY decomp_cap bytes; reject ONLY > decomp_cap.
    // Read up to decomp_cap+1 bytes; if we get more than decomp_cap the stream
    // exceeded the cap. This matches Python's semantics: `read(decomp_cap+1)` then
    // `if len > decomp_cap: raise`.  The +1 read is harmless overhead.
    let mut out = Vec::new();
    let n = decoder
        .take(decomp_cap + 1)
        .read_to_end(&mut out)
        .map_err(|e| {
            FetchError::Transport(
                "FETCH-EXTRACT-FAILED",
                format!("fetching {name:?}: {format} decompress: {e}"),
            )
        })?;
    if n as u64 > decomp_cap {
        return Err(size_limit_error(name, decomp_cap));
    }
    Ok(out)
}

/// Construct the canonical `EXTRACT-SIZE-LIMIT` error for a decompression-bomb
/// cap breach. Single definition shared by `decompress_capped` (Read-based) and
/// `decompress_capped_write` (Write-based) so the slug and message format are
/// identical regardless of which codec path triggered the cap.
#[inline]
fn size_limit_error(name: &str, decomp_cap: u64) -> FetchError {
    FetchError::Transport(
        "EXTRACT-SIZE-LIMIT",
        format!(
            "fetching {name:?}: decompressed archive exceeds cap ({decomp_cap} bytes); \
             possible decompression bomb"
        ),
    )
}

/// Decompress an lzma-alone (FORMAT_ALONE / LZMA1) stream `src` into a
/// `Vec<u8>`, enforcing the SA-1 decompression-bomb cap.
///
/// lzma-alone has NO reliable magic bytes (the first byte is a "properties"
/// byte that varies by encoder settings).  This function is called as a
/// FALLBACK when none of the reliable magics (gzip/bz2/xz) match: if
/// `lzma_rs::lzma_decompress` succeeds, the result is a lzma-alone stream;
/// if it fails, the caller falls through to plain-tar.
///
/// Uses the same `LimitedWriter` cap mechanism as `decompress_capped_xz`
/// (xz uses the same lzma-rs crate; LZMA1 and XZ are sibling formats).
///
/// R3-design-L1 NOTE: these two functions share identical structure and differ
/// only in the lzma-rs function called and the format label in the error
/// message.  A clean helper-with-fn-parameter unification is blocked by
/// lzma-rs's generic signature: both `lzma_decompress` and `xz_decompress`
/// are generic over `R: BufRead + Sized` and `W: Write`, so they have
/// higher-ranked lifetime requirements that prevent coercion to a concrete fn
/// pointer type *or* to `impl FnOnce` with the concrete types we supply.
/// Attempting to use `FnOnce(&mut BufReader<&[u8]>, &mut LimitedWriter<'_>)`
/// fails with "implementation of FnOnce is not general enough" because the
/// lzma-rs generics introduce additional lifetime variables.  The cleanest
/// approach would require the lzma-rs API to expose a `dyn`-friendly trait or
/// the functions to be concretised, neither of which we control.  The
/// functions are kept as parallel peers — each three-line body + shared SSOT
/// for cap/slug/message via `size_limit_error` — the duplication is minimal
/// and the alternatives are worse.
pub(crate) fn decompress_capped_lzma(
    src: &[u8],
    decomp_cap: u64,
    name: &str,
) -> Result<Vec<u8>, FetchError> {
    let mut buf = Vec::new();
    let mut limited = LimitedWriter::new(&mut buf, decomp_cap);
    let result = lzma_rs::lzma_decompress(&mut std::io::BufReader::new(src), &mut limited);
    if limited.limit_hit() {
        return Err(size_limit_error(name, decomp_cap));
    }
    result.map_err(|e| {
        FetchError::Transport(
            "FETCH-EXTRACT-FAILED",
            format!("fetching {name:?}: lzma-alone decompress: {e}"),
        )
    })?;
    Ok(buf)
}

/// Decompress an xz stream `src` into a `Vec<u8>`, enforcing the SA-1
/// decompression-bomb cap.  See `decompress_capped_lzma` for the R3-design-L1
/// note on why these two functions remain as parallel peers.
fn decompress_capped_xz(
    src: &[u8],
    decomp_cap: u64,
    name: &str,
) -> Result<Vec<u8>, FetchError> {
    let mut buf = Vec::new();
    let mut limited = LimitedWriter::new(&mut buf, decomp_cap);
    let result = lzma_rs::xz_decompress(&mut std::io::BufReader::new(src), &mut limited);
    if limited.limit_hit() {
        return Err(size_limit_error(name, decomp_cap));
    }
    result.map_err(|e| {
        FetchError::Transport(
            "FETCH-EXTRACT-FAILED",
            format!("fetching {name:?}: xz decompress: {e}"),
        )
    })?;
    Ok(buf)
}

use crate::dag_identity::{MaterializedEntry, MODE_EXECUTABLE, MODE_REGULAR, MODE_SYMLINK};
use crate::fetch::{FetchError, FetcherRegistry, Receipt};
use crate::safe_extract::{extract_tar, Limits};

/// git ls-tree blob mode → epoch-2 mode-byte (spec/identity.md §1.8.2.1).
/// `100644` regular → 0x00, `100755` executable → 0x01, `120000` symlink → 0x80.
/// Any other (unexpected) mode is treated as a regular blob (0x00) — matching the
/// permissive disk-write branch.
fn git_mode_to_byte(mode: &str) -> u8 {
    match mode {
        "100755" => MODE_EXECUTABLE,
        "120000" => MODE_SYMLINK,
        _ => MODE_REGULAR,
    }
}

fn transport(code: &'static str, message: impl Into<String>) -> FetchError {
    FetchError::Transport(code, message.into())
}

/// Typed error for the [`HttpGet`] transport seam.
///
/// R1-22: replaces the string-sentinel protocol (`SIZE_EXCEEDED_PREFIX` prefix
/// embedded in `Err(String)`) with a first-class variant.  `fetch_tarball`'s
/// `map_err` can now pattern-match rather than doing a string-prefix check,
/// and tests that inject errors can use `HttpGetError::Other` directly.
#[derive(Debug, Clone)]
pub enum HttpGetError {
    /// The server's compressed body exceeded the download cap.  Maps to the
    /// security-distinct `FETCH-DOWNLOAD-SIZE-EXCEEDED` slug (not the generic
    /// network-failure `FETCH-DOWNLOAD-FAILED`).
    SizeExceeded(String),
    /// Any other transport failure (network error, curl non-zero exit, etc.).
    /// Maps to `FETCH-DOWNLOAD-FAILED`.
    Other(String),
}

/// A byte-fetching transport (an injected seam, like the index cache's): maps a
/// URL to its bytes, or a typed [`HttpGetError`]. `DefaultRegistry::with_curl`
/// uses the `curl` CLI; tests inject a closure.
pub type HttpGet = Box<dyn Fn(&str) -> Result<Vec<u8>, HttpGetError>>;

/// The reference [`FetcherRegistry`]: dispatch the closed `Provenance` enum to a
/// per-transport fetch. Carries an [`HttpGet`] for the tarball transport.
pub struct DefaultRegistry {
    http_get: HttpGet,
}

impl DefaultRegistry {
    /// A registry whose tarball downloads use a custom byte transport.
    pub fn new(http_get: impl Fn(&str) -> Result<Vec<u8>, HttpGetError> + 'static) -> Self {
        DefaultRegistry {
            http_get: Box::new(http_get),
        }
    }

    /// The production registry: tarball downloads shell out to `curl -fsSL`.
    ///
    /// H1 — streaming bounded read: spawns curl with `Stdio::piped()` stdout and
    /// reads in chunks, aborting (killing curl) as soon as the cumulative byte
    /// count exceeds `MAX_COMPRESSED_BYTES`.  The process never buffers more than
    /// `MAX_COMPRESSED_BYTES + chunk_size` bytes from an oversized response.
    ///
    /// On cap breach, returns `Err(HttpGetError::SizeExceeded(...))` so
    /// `fetch_tarball` can pattern-match the variant rather than string-matching
    /// a prefix.
    pub fn with_curl() -> Self {
        DefaultRegistry::new(curl_streaming_transport(MAX_COMPRESSED_BYTES))
    }
}

/// Chunk size for the streaming curl read (64 KiB).  Memory bound per response:
/// at most `compressed_cap + CURL_CHUNK_SIZE` bytes before abort.
const CURL_CHUNK_SIZE: usize = 65_536;

/// Build a streaming curl transport bounded to `compressed_cap` bytes.
///
/// The returned closure spawns curl with a piped stdout, reads in
/// `CURL_CHUNK_SIZE` chunks, and kills the process the moment the cumulative
/// read exceeds `compressed_cap`.  On cap breach the closure returns
/// `Err(HttpGetError::SizeExceeded(...))` so the call site can pattern-match
/// the variant rather than inspect a string prefix.
pub(crate) fn curl_streaming_transport(
    compressed_cap: u64,
) -> impl Fn(&str) -> Result<Vec<u8>, HttpGetError> + 'static {
    move |url: &str| {
        let mut child = Command::new("curl")
            .args(["-fsSL", url])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| HttpGetError::Other(format!("cannot run curl: {e}")))?;

        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; CURL_CHUNK_SIZE];

        loop {
            let n = stdout.read(&mut chunk).map_err(|e| HttpGetError::Other(format!("curl read: {e}")))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() as u64 > compressed_cap {
                // Kill curl immediately — no further bytes are read.
                let _ = child.kill();
                let _ = child.wait();
                return Err(HttpGetError::SizeExceeded(format!(
                    "compressed body ({} bytes read so far) \
                     exceeds download cap ({compressed_cap} bytes); request aborted",
                    buf.len()
                )));
            }
        }
        drop(stdout);

        let status = child.wait().map_err(|e| HttpGetError::Other(format!("curl wait: {e}")))?;
        if status.success() {
            Ok(buf)
        } else {
            let stderr = child
                .stderr
                .take()
                .map(|mut s| {
                    let mut v = Vec::new();
                    let _ = s.read_to_end(&mut v);
                    String::from_utf8_lossy(&v).trim().to_string()
                })
                .unwrap_or_default();
            Err(HttpGetError::Other(format!("curl failed: {stderr}")))
        }
    }
}

impl FetcherRegistry for DefaultRegistry {
    /// Dispatch to the per-transport fetcher, then compute and attach the
    /// content identity for CAS-admissible provenances (git / tarball / OCI).
    ///
    /// A0 architectural pin: this is the single site where `compute_content_hash`
    /// is called in the fetch path. Both `CasAdmittingFetcher::fetch` (for
    /// production CAS admission) and `milpa hash` (via the inner registry) read
    /// the identity from `Receipt::identity` — they MUST NOT call
    /// `compute_content_hash` themselves (spec/cli-contract.md §5.11 NORMATIVE).
    fn fetch(&self, name: &str, p: &Provenance, dest: &Path) -> Result<Receipt, FetchError> {
        let mut receipt = match p {
            Provenance::Local { path } => fetch_local(name, Path::new(path), dest)?,
            Provenance::Git {
                url,
                ref_spec,
                commit_sha,
            } => fetch_git(name, url, ref_spec, commit_sha.as_deref(), dest)?,
            Provenance::Tarball {
                url,
                expected_sha256,
                strip_components,
            } => fetch_tarball(
                name,
                url,
                expected_sha256.as_deref(),
                *strip_components,
                dest,
                self.http_get.as_ref(),
            )?,
            Provenance::Oci {
                registry,
                repository,
                digest,
                ..
            } => fetch_oci(name, registry, repository, digest, dest)?,
        };
        // Compute content identity for CAS-admissible provenances. Local/editable
        // sources carry no stable identity (lockfile-schema.md §4.3 NORMATIVE).
        if p.cas_admissible() {
            use crate::identity::compute_content_hash;
            receipt.identity = Some(compute_content_hash(dest).map_err(|e| {
                FetchError::Failed(format!(
                    "DefaultRegistry: compute identity for {name:?}: {}",
                    e.message()
                ))
            })?);
        }
        Ok(receipt)
    }
}

/// Create a live symlink at `dest` pointing at the absolute resolved source
/// directory (mirrors `LocalFetcher.fetch → dest.symlink_to(p.path.resolve())`).
/// Plugin-contract §1.2 (non-admissible): local deps MUST NOT be copied —
/// `dest` is a symlink so the user's in-progress edits remain live.
/// `FETCH-LOCAL-PATH-NOT-FOUND` / `FETCH-LOCAL-PATH-NOT-DIR` on a bad source.
pub fn fetch_local(name: &str, src: &Path, dest: &Path) -> Result<Receipt, FetchError> {
    // Resolve to absolute before checking, so relative paths work.
    let abs_src = src.canonicalize().map_err(|_| {
        transport(
            "FETCH-LOCAL-PATH-NOT-FOUND",
            format!(
                "fetching {name:?}: local source path does not exist: {}",
                src.display()
            ),
        )
    })?;
    if !abs_src.is_dir() {
        return Err(transport(
            "FETCH-LOCAL-PATH-NOT-DIR",
            format!(
                "fetching {name:?}: local source path is not a directory: {}",
                src.display()
            ),
        ));
    }
    // Remove any stale entry at dest (symlink, file, or directory).
    clear_dest(dest).map_err(|e| transport("FETCH-LOCAL-PATH-NOT-DIR", e))?;
    // Create a fresh symlink: dest → abs_src (absolute, so it is stable
    // regardless of the working directory at access time).
    std::os::unix::fs::symlink(&abs_src, dest).map_err(|e| {
        transport(
            "FETCH-LOCAL-PATH-NOT-DIR",
            format!("fetching {name:?}: cannot create symlink {dest:?} → {abs_src:?}: {e}"),
        )
    })?;
    // A local symlink carries no resolved ref and no identity; its provenance
    // evidence is the declared path, recorded by the resolver.
    Ok(Receipt::default())
}

// ---------------------------------------------------------------------------
// Object-store materialization (H3c, spec/identity.md §1.7,
// plugin-contract.md §2.3/§2.4)
// ---------------------------------------------------------------------------

/// The exact first line of a Git-LFS pointer file.
/// A blob is an LFS pointer iff it starts with this exact byte sequence
/// (plugin-contract.md §2.3.2 — first-line exact match).
const LFS_POINTER_FIRST_LINE: &[u8] = b"version https://git-lfs.github.com/spec/v1\n";

/// Materialize a git commit's tree from the object store into `dest`.
///
/// This is the **single chokepoint** for blob writing, fixed-mode, LFS
/// detection, symlink-escape containment, and submodule recursion (H5).
/// `fetch_git` produces its output tree EXCLUSIVELY via this function
/// (plugin-contract.md §2.4.1 NORMATIVE).
///
/// # Arguments
/// - `repo`             — path to the `--no-checkout` clone scratch holding
///                        the object store (`.git/`); NOT the output tree.
/// - `commit`           — commit SHA to materialize.
/// - `dest`             — clean output tree directory (caller must create it);
///                        MUST NOT contain `.git`.
/// - `submodule_fetch`  — H5 recursion seam.  Called with `(resolved_url, sha)`
///                        for each mode-160000 gitlink; `None` skips recursion.
/// - `superproject_url` — H5: the remote URL of this repo (used to resolve
///                        relative `url = ../sibling` entries in `.gitmodules`).
///                        Required when `submodule_fetch` is `Some` and the
///                        repo has submodules with relative URLs.
///
/// # Returns
/// `Ok(path → sha)` map (submodule path relative to dest root, POSIX) for every
/// mode-160000 gitlink recursed. Empty when no submodules or `submodule_fetch`
/// is `None`.
///
/// # Errors
/// - `FETCH-GIT-FAILED`            — `git ls-tree` or `git cat-file --batch` failed.
/// - `EXTRACT-SYMLINK-ESCAPE`      — a committed symlink's target escapes `dest`.
/// - `FETCH-GIT-LFS-POINTER`       — a blob is a Git-LFS pointer.
/// - `FETCH-GIT-SUBMODULE-FAILED`  — submodule URL unresolvable or fetch failed.
pub fn materialize_git_tree(
    repo: &Path,
    commit: &str,
    dest: &Path,
    submodule_fetch: Option<&dyn Fn(&str, &str) -> Result<PathBuf, FetchError>>,
    superproject_url: Option<&str>,
) -> Result<std::collections::HashMap<String, String>, FetchError> {
    // R2-01: pass the ancestor-path visited set (empty at the root).
    // Each child receives its OWN CLONE of the set (with the child's key added)
    // so siblings do NOT see each other's keys — only a true ancestor repeat
    // (same (url,sha) on the current recursion path) triggers the cycle guard.
    materialize_git_tree_inner(repo, commit, dest, submodule_fetch, superproject_url, 0, &std::collections::HashSet::new())
}

/// R1-03: maximum submodule recursion depth (load-bearing: alternating chains
/// use distinct SHAs, so only depth limits them — not the visited-set alone).
const MAX_SUBMODULE_DEPTH: usize = 16;

/// The git **materialize seam** (RFC slice B2-git): read a commit's tree from the
/// object store into a buffered `Vec<MaterializedEntry>` (spec §1.8.4).
///
/// This is the single source of truth for git tree enumeration. Both consumers
/// read from here: [`materialize_git_tree`] writes the entries to `dest/` (the CAS
/// path), and the epoch-2 DAG builder ([`crate::dag_identity::compute_dag_identity`])
/// computes the `dag-sha256:` identity over them.
///
/// Submodules (mode-160000 gitlinks) are recursed via `submodule_fetch` and their
/// committed blobs spliced into the sequence under the gitlink's path prefix (spec
/// §1.8.7); the DAG builder then folds them into a subtree whose root `H_tree`
/// becomes the gitlink's child digest. URLs + pinned SHAs are returned separately
/// as PROVENANCE (the `path → sha` map).
pub fn enumerate_git_entries(
    repo: &Path,
    commit: &str,
    submodule_fetch: Option<&dyn Fn(&str, &str) -> Result<PathBuf, FetchError>>,
    superproject_url: Option<&str>,
) -> Result<(Vec<MaterializedEntry>, std::collections::HashMap<String, String>), FetchError> {
    enumerate_git_entries_inner(
        repo,
        commit,
        submodule_fetch,
        superproject_url,
        0,
        &std::collections::HashSet::new(),
    )
}

/// Internal implementation with depth and ancestor-path visited-set tracking (R1-03, R2-01).
///
/// `visited` is the set of `(resolved_url, commit_sha)` pairs on the CURRENT
/// RECURSION PATH (ancestor chain).  Each child receives its OWN CLONE of the
/// set with the child's key pre-inserted, so siblings do NOT share keys —
/// only a repeat on the ancestor chain triggers `FETCH-GIT-SUBMODULE-FAILED`.
/// This matches Python's `child_seen = seen | {visit_key}` pattern exactly.
fn enumerate_git_entries_inner(
    repo: &Path,
    commit: &str,
    submodule_fetch: Option<&dyn Fn(&str, &str) -> Result<PathBuf, FetchError>>,
    superproject_url: Option<&str>,
    depth: usize,
    visited: &std::collections::HashSet<(String, String)>,
) -> Result<(Vec<MaterializedEntry>, std::collections::HashMap<String, String>), FetchError> {
    use std::collections::HashMap;

    // -----------------------------------------------------------------------
    // Step 1: ls-tree -r — enumerate (mode, type, sha, path) for every entry
    // -----------------------------------------------------------------------
    // R1-15: use -z (NUL-delimited) to disable C-quoting of exotic filenames.
    // With -z each entry is "<mode> SP <type> SP <sha> TAB <path> NUL".
    // This preserves path bytes faithfully (no C-quoting, no lossy UTF-8 round-trip).
    let ls_out = Command::new("git")
        .arg("-C").arg(repo)
        .args(["ls-tree", "-r", "-z", "--end-of-options", commit])
        .output()
        .map_err(|e| transport("FETCH-GIT-FAILED",
            format!("git ls-tree for commit {commit:?}: cannot spawn git: {e}")))?;
    if !ls_out.status.success() {
        return Err(transport(
            "FETCH-GIT-FAILED",
            format!(
                "git ls-tree failed for commit {commit:?}: {}",
                String::from_utf8_lossy(&ls_out.stderr).trim()
            ),
        ));
    }

    // Parse ls-tree -z output: each record is "<mode> <type> <sha>\t<path>\0"
    // Split on NUL; each non-empty record contains a TAB separating meta from path.
    // Path bytes are preserved as-is (no C-quoting with -z).
    let mut blobs: Vec<(String, String, String, String)> = Vec::new(); // (mode, type, sha, path)
    let mut gitlinks: Vec<(String, String, String, String)> = Vec::new();

    for record in ls_out.stdout.split(|&b| b == b'\0') {
        if record.is_empty() {
            continue;
        }
        // Find the tab separator between meta and path.
        let tab_pos = match record.iter().position(|&b| b == b'\t') {
            Some(p) => p,
            None => continue,
        };
        let meta_bytes = &record[..tab_pos];
        let path_bytes = &record[tab_pos + 1..];
        // meta is always ASCII (mode/type/sha are hex+letters).
        let meta = match std::str::from_utf8(meta_bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // NEW-C: non-UTF-8 relpaths are rejected as errors (spec/identity.md
        // §ID-NON-UTF8-RELPATH).  `ls-tree -z` delivers raw path bytes without
        // C-quoting; if those bytes are not valid UTF-8 we raise the error code
        // immediately rather than falling back to `from_utf8_lossy` (which
        // silently substitutes U+FFFD, producing a wrong content_hash with no
        // error).  Both impls now reject non-UTF-8 relpaths identically.
        let entry_path = match std::str::from_utf8(path_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => {
                // Represent the offending bytes as escaped hex for the error message.
                let hex: String = path_bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                return Err(transport(
                    "ID-NON-UTF8-RELPATH",
                    format!(
                        "git tree entry has a non-UTF-8 path (raw bytes: {hex}); \
                         milpa requires UTF-8 relpaths for content addressing"
                    ),
                ));
            }
        };
        let parts: Vec<&str> = meta.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let (mode, _obj_type, sha) = (parts[0], parts[1], parts[2]);

        if mode == "160000" {
            gitlinks.push((mode.to_string(), _obj_type.to_string(), sha.to_string(), entry_path));
        } else {
            blobs.push((mode.to_string(), _obj_type.to_string(), sha.to_string(), entry_path));
        }
    }

    // -----------------------------------------------------------------------
    // Step 2: cat-file --batch — ONE subprocess for ALL blobs
    //
    // Protocol: write newline-delimited SHAs to stdin; read back a framed
    // stream from stdout.  Each object frame is:
    //   "<sha> <type> <size>\n" — header line
    //   <size bytes of content>  — raw blob content (binary-safe)
    //   "\n"                     — trailing separator between objects
    //
    // We use the header's <size> field to read EXACTLY that many bytes per
    // object, then consume the trailing "\n" separator.  This is the safe
    // binary-correct approach — do NOT use line-by-line reading here.
    // -----------------------------------------------------------------------
    let mut blob_bytes: HashMap<String, Vec<u8>> = HashMap::new();

    if !blobs.is_empty() {
        let batch_shas: Vec<&str> = blobs.iter().map(|(_, _, sha, _)| sha.as_str()).collect();
        let batch_input = {
            let mut v = Vec::new();
            for sha in &batch_shas {
                v.extend_from_slice(sha.as_bytes());
                v.push(b'\n');
            }
            v
        };

        // R1-02: cat-file --batch deadlock prevention.
        // git interleaves read/write on its pipe pair; if we write ALL of stdin
        // before draining stdout, git's stdout buffer (~64 KiB) fills and both
        // sides block — a classic pipe deadlock that manifests at ~20-50 real
        // source files.  Fix: write stdin on a separate thread concurrently with
        // draining stdout via wait_with_output().  The writer thread owns the
        // ChildStdin handle; dropping it closes the pipe, signalling EOF to git.
        let cat_out = {
            let mut child = Command::new("git")
                .arg("-C").arg(repo)
                .args(["cat-file", "--batch"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| transport("FETCH-GIT-FAILED",
                    format!("git cat-file --batch for commit {commit:?}: spawn: {e}")))?;

            // Take stdin before spawning writer thread (Option<ChildStdin>).
            let mut stdin = child.stdin.take().expect("piped stdin");
            let writer_input = batch_input.clone();
            let writer = std::thread::spawn(move || {
                use std::io::Write as _;
                // Write all SHAs then drop stdin — closes the pipe → git sees EOF.
                let _ = stdin.write_all(&writer_input);
                // Explicit drop for clarity; happens automatically when `stdin`
                // goes out of scope.  The `move` captured the ChildStdin, so
                // the pipe is closed when this thread exits.
            });

            // Drain stdout + stderr concurrently with the writer (the key fix).
            let out = child.wait_with_output()
                .map_err(|e| transport("FETCH-GIT-FAILED",
                    format!("git cat-file --batch for commit {commit:?}: wait: {e}")))?;

            // Join the writer thread and propagate any panic.  A broken-pipe
            // write error is benign (git closed stdin after processing all SHAs)
            // and is already covered by the exit-status check below — only a
            // thread panic (programming error) must be surfaced here.
            writer.join().expect("cat-file stdin writer thread panicked");
            out
        };

        if !cat_out.status.success() {
            return Err(transport(
                "FETCH-GIT-FAILED",
                format!(
                    "git cat-file --batch failed for commit {commit:?}: {}",
                    String::from_utf8_lossy(&cat_out.stderr).trim()
                ),
            ));
        }

        // Parse the framed --batch output stream.
        // Each object: "<sha> <type> <size>\n<content bytes>\n"
        let data = &cat_out.stdout;
        let mut pos = 0usize;

        for sha in &batch_shas {
            // Find the newline that terminates the header line.
            let nl = match data[pos..].iter().position(|&b| b == b'\n') {
                Some(i) => pos + i,
                None => {
                    return Err(transport(
                        "FETCH-GIT-FAILED",
                        format!(
                            "git cat-file --batch: truncated header for SHA {sha:?} \
                             at byte {pos}"
                        ),
                    ));
                }
            };
            let header = match std::str::from_utf8(&data[pos..nl]) {
                Ok(s) => s,
                Err(_) => return Err(transport(
                    "FETCH-GIT-FAILED",
                    format!("git cat-file --batch: non-UTF-8 header for SHA {sha:?}"),
                )),
            };
            pos = nl + 1;

            // Header format: "<sha> <type> <size>" or "<sha> missing"
            let header_parts: Vec<&str> = header.split_whitespace().collect();
            if header_parts.len() >= 2 && header_parts[1] == "missing" {
                return Err(transport(
                    "FETCH-GIT-FAILED",
                    format!("git cat-file --batch: SHA {sha:?} reported missing"),
                ));
            }
            if header_parts.len() < 3 {
                return Err(transport(
                    "FETCH-GIT-FAILED",
                    format!(
                        "git cat-file --batch: unexpected header {:?} for SHA {sha:?}",
                        header
                    ),
                ));
            }
            // R1-19: parse size as u64 (not usize directly) so a 32-bit target
            // cannot truncate the value before the bounds check below.  Then
            // convert to usize via try_into(); a size that exceeds usize::MAX is
            // impossible on any platform with a reasonable git object, so the
            // FETCH-GIT-FAILED error is the correct response.
            let obj_size_u64: u64 = header_parts[2].parse().map_err(|_| {
                transport(
                    "FETCH-GIT-FAILED",
                    format!(
                        "git cat-file --batch: unparseable size {:?} for SHA {sha:?}",
                        header_parts[2]
                    ),
                )
            })?;
            let obj_size: usize = obj_size_u64.try_into().map_err(|_| {
                transport(
                    "FETCH-GIT-FAILED",
                    format!(
                        "git cat-file --batch: object size {obj_size_u64} overflows \
                         platform usize for SHA {sha:?}"
                    ),
                )
            })?;

            // Read exactly obj_size bytes.
            if pos + obj_size > data.len() {
                return Err(transport(
                    "FETCH-GIT-FAILED",
                    format!(
                        "git cat-file --batch: data for SHA {sha:?} truncated \
                         (expected {obj_size} bytes at pos {pos}, stream has {} bytes)",
                        data.len()
                    ),
                ));
            }
            let content = data[pos..pos + obj_size].to_vec();
            pos += obj_size;
            // Skip the trailing newline separator between objects.
            if pos < data.len() && data[pos] == b'\n' {
                pos += 1;
            }
            blob_bytes.insert(sha.to_string(), content);
        }
    }

    // -----------------------------------------------------------------------
    // Step 3: build the buffered materialized entry sequence
    // -----------------------------------------------------------------------
    // The git mode → mode-byte mapping is the SSOT for the exec/symlink bit that
    // epoch-2 identity depends on (spec §1.8.2.1). LFS detection + on-disk-mode
    // writing + path containment are the DISK consumer's concern
    // (`materialize_git_tree`), not the abstract entry sequence.
    let mut gitlink_results: HashMap<String, String> = HashMap::new();
    let mut entries: Vec<MaterializedEntry> = Vec::with_capacity(blobs.len());

    for (mode, _obj_type, sha, entry_path) in &blobs {
        let content = match blob_bytes.get(sha.as_str()) {
            Some(b) => b.clone(),
            None => return Err(transport(
                "FETCH-GIT-FAILED",
                format!("cat-file result missing for SHA {sha:?} (path {entry_path:?})"),
            )),
        };
        entries.push(MaterializedEntry {
            relpath: entry_path.clone(),
            mode_byte: git_mode_to_byte(mode),
            content,
        });
    }

    // -----------------------------------------------------------------------
    // Step 4: gitlinks — submodule recursion (H5)
    // -----------------------------------------------------------------------
    if !gitlinks.is_empty() {
        if let Some(ref fetch_fn) = submodule_fetch {
            // Parse .gitmodules from the object store (NOT from disk): its bytes
            // were read in Step 2. .gitmodules is committed content, a regular
            // blob at the repo root (relpath ".gitmodules").
            let gitmodules_bytes: Vec<u8> = blobs
                .iter()
                .find(|(_, _, _, p)| p == ".gitmodules")
                .and_then(|(_, _, sha, _)| blob_bytes.get(sha.as_str()).cloned())
                .unwrap_or_default();
            let submodule_url_map = parse_gitmodules(&gitmodules_bytes);

            for (_mode, _obj_type, sha, entry_path) in &gitlinks {
                // Resolve the submodule URL from .gitmodules by path.
                let raw_url = match submodule_url_map.get(entry_path.as_str()) {
                    Some(u) => u.clone(),
                    None => {
                        return Err(transport(
                            "FETCH-GIT-SUBMODULE-FAILED",
                            format!(
                                "submodule at {entry_path:?} has no entry in .gitmodules \
                                 (or .gitmodules is absent); cannot resolve URL \
                                 [submodule_path={entry_path:?}] [submodule_url=(unknown)]"
                            ),
                        ));
                    }
                };
                let resolved_url = resolve_submodule_url(&raw_url, superproject_url)
                    .map_err(|e| transport(
                        "FETCH-GIT-SUBMODULE-FAILED",
                        format!(
                            "cannot resolve relative submodule URL {raw_url:?} for \
                             {entry_path:?}: {e} \
                             [submodule_path={entry_path:?}] [submodule_url={raw_url:?}]"
                        ),
                    ))?;

                // R1-03: depth cap — load-bearing even when (url, sha) pairs repeat
                // in alternating chains using distinct SHAs at each level.
                if depth >= MAX_SUBMODULE_DEPTH {
                    return Err(transport(
                        "FETCH-GIT-SUBMODULE-FAILED",
                        format!(
                            "submodule recursion depth {depth} exceeds cap ({MAX_SUBMODULE_DEPTH}) \
                             at {entry_path:?} [submodule_path={entry_path:?}] \
                             [submodule_url={resolved_url:?}]"
                        ),
                    ));
                }
                // R2-01: cycle guard — detect (url, sha) repeating on the CURRENT
                // ANCESTOR PATH only.  A sibling submodule with the same (url, sha)
                // is legitimate (diamond pattern); an ancestor repeat is a cycle.
                //
                // Implementation: check whether the key is already in the ancestor set
                // (`visited`).  If yes → cycle → reject.  If no → build a CHILD-LOCAL
                // copy (`child_visited = visited + {visit_key}`) and pass that copy to
                // the recursive call.  The parent's `visited` is never mutated, so the
                // next sibling starts with the same clean ancestor set.
                //
                // This matches Python exactly: `child_seen = seen | {visit_key}`.
                let visit_key = (resolved_url.clone(), sha.clone());
                if visited.contains(&visit_key) {
                    return Err(transport(
                        "FETCH-GIT-SUBMODULE-FAILED",
                        format!(
                            "submodule cycle detected: ({resolved_url:?}, {sha:?}) already on \
                             the ancestor path \
                             [submodule_path={entry_path:?}] [submodule_url={resolved_url:?}]"
                        ),
                    ));
                }
                // Build the child's ancestor-path set: parent's keys + this child's key.
                let mut child_visited = visited.clone();
                child_visited.insert(visit_key);

                let sub_scratch = fetch_fn(&resolved_url, sha)?;

                // Recurse via the SAME seam: enumerate the submodule's tree, then
                // splice its entries in under the gitlink path prefix (spec §1.8.7).
                let (sub_entries, sub_results) = enumerate_git_entries_inner(
                    &sub_scratch,
                    sha,
                    submodule_fetch.as_ref().map(|f| f as &dyn Fn(&str, &str) -> Result<PathBuf, FetchError>),
                    Some(&resolved_url),
                    depth + 1,
                    &child_visited,
                )?;
                for sub_entry in sub_entries {
                    entries.push(MaterializedEntry {
                        relpath: format!("{entry_path}/{}", sub_entry.relpath),
                        mode_byte: sub_entry.mode_byte,
                        content: sub_entry.content,
                    });
                }
                gitlink_results.insert(entry_path.clone(), sha.clone());
                // Accumulate nested results with prefixed paths.
                for (nested_path, nested_sha) in sub_results {
                    gitlink_results.insert(
                        format!("{entry_path}/{nested_path}"),
                        nested_sha,
                    );
                }
            }
        }
    }
    // If submodule_fetch is None, gitlinks are silently skipped (H3c behaviour).

    Ok((entries, gitlink_results))
}

/// Materialize a git commit's tree from the object store into `dest`.
///
/// Thin disk-writing consumer of the [`enumerate_git_entries`] seam (RFC slice
/// B2-git): it enumerates once, then writes each buffered entry to `dest/` with
/// fixed on-disk modes + the path/symlink/LFS safety checks. `fetch_git` produces
/// its output tree EXCLUSIVELY via this function (plugin-contract.md §2.4.1).
///
/// Disk contract (spec/identity.md §1.7.4): mode-byte 0x00 → 0o644, 0x01 → 0o755,
/// 0x80 (symlink) → lexical containment check before write. Entry paths are
/// lexically checked against `dest_root` BEFORE any write (EXTRACT-ZIP-SLIP, R1-01).
fn materialize_git_tree_inner(
    repo: &Path,
    commit: &str,
    dest: &Path,
    submodule_fetch: Option<&dyn Fn(&str, &str) -> Result<PathBuf, FetchError>>,
    superproject_url: Option<&str>,
    depth: usize,
    visited: &std::collections::HashSet<(String, String)>,
) -> Result<std::collections::HashMap<String, String>, FetchError> {
    use crate::safe_extract::normalize_lexical;

    // Canonicalize dest so prefix comparisons are reliable.
    let dest_root = std::fs::canonicalize(dest).unwrap_or_else(|_| normalize_lexical(dest));

    let (entries, gitlink_results) = enumerate_git_entries_inner(
        repo,
        commit,
        submodule_fetch,
        superproject_url,
        depth,
        visited,
    )?;

    for entry in &entries {
        // R1-01 NORMATIVE: lexical containment check BEFORE any write. Reject
        // absolute entry paths and `..`-escape paths.
        let joined = dest_root.join(&entry.relpath);
        let normalized = normalize_lexical(&joined);
        if !normalized.starts_with(&dest_root) {
            return Err(transport(
                "EXTRACT-ZIP-SLIP",
                format!(
                    "git ls-tree entry {:?} resolves outside destination: \
                     {} not under {} (zip-slip rejected)",
                    entry.relpath,
                    normalized.display(),
                    dest_root.display()
                ),
            ));
        }
        let abs_dest = dest_root.join(&entry.relpath);

        if entry.mode_byte == MODE_SYMLINK {
            // Symlink: blob bytes are the link-target string.
            materialize_symlink(&entry.relpath, &entry.content, &abs_dest, &dest_root)?;
        } else {
            // Regular or executable blob.
            // LFS first-line detection (plugin-contract.md §2.3.2).
            check_lfs(&entry.relpath, &entry.content)?;
            if let Some(parent) = abs_dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| transport(
                    "FETCH-GIT-FAILED",
                    format!("creating parent for {:?}: {e}", entry.relpath),
                ))?;
            }
            std::fs::write(&abs_dest, &entry.content).map_err(|e| transport(
                "FETCH-GIT-FAILED",
                format!("writing {:?}: {e}", entry.relpath),
            ))?;
            // Fixed on-disk mode (spec §1.7.4): 0o755 for executable, else 0o644.
            let on_disk_mode: u32 = if entry.mode_byte == MODE_EXECUTABLE { 0o755 } else { 0o644 };
            std::fs::set_permissions(&abs_dest, std::fs::Permissions::from_mode(on_disk_mode))
                .map_err(|e| transport(
                    "FETCH-GIT-FAILED",
                    format!("chmod {:?}: {e}", entry.relpath),
                ))?;
        }
    }

    Ok(gitlink_results)
}

/// Parse a `.gitmodules` blob into a `{path → url}` map.
///
/// `.gitmodules` uses a gitconfig-format subset:
/// ```text
/// [submodule "<name>"]
///     path = <path>
///     url = <url>
/// ```
/// Pure text parsing — no shell execution, no eval. Entries without both
/// `path` and `url` are silently skipped. Mirrors Python `_parse_gitmodules`.
pub fn parse_gitmodules(content: &[u8]) -> std::collections::HashMap<String, String> {
    let mut result = std::collections::HashMap::new();
    let text = String::from_utf8_lossy(content);

    let mut current_path: Option<String> = None;
    let mut current_url: Option<String> = None;

    for line in text.lines() {
        let stripped = line.trim();
        if stripped.starts_with("[submodule ") {
            // Flush previous section if complete.
            if let (Some(p), Some(u)) = (current_path.take(), current_url.take()) {
                result.insert(p, u);
            }
            current_path = None;
            current_url = None;
        } else if stripped.contains('=') && !stripped.starts_with('[') {
            if let Some(eq_pos) = stripped.find('=') {
                let key = stripped[..eq_pos].trim();
                let value = stripped[eq_pos + 1..].trim();
                if key == "path" {
                    current_path = Some(value.to_string());
                } else if key == "url" {
                    current_url = Some(value.to_string());
                }
            }
        }
    }
    // Flush final section.
    if let (Some(p), Some(u)) = (current_path, current_url) {
        result.insert(p, u);
    }
    result
}

/// Resolve a submodule URL from `.gitmodules` against the superproject URL.
///
/// Mirrors git-submodule.sh `resolve_relative_url`:
/// - Absolute URLs (contain `://` or start with `/` or are SCP-style) pass through.
/// - Relative URLs (`./` or `../`) are resolved against `dirname(superproject_url)`
///   where dirname strips the last `/`-delimited path component.
///   The path arithmetic is performed on the URL's path component alone (scheme
///   and host are preserved).
///
/// Returns `Ok(resolved_url)` or `Err(message)` if relative and no superproject_url.
pub fn resolve_submodule_url(
    raw_url: &str,
    superproject_url: Option<&str>,
) -> Result<String, String> {
    // Absolute URL detection.
    let is_absolute = raw_url.contains("://")
        || raw_url.starts_with('/')
        || (!raw_url.starts_with("./") && !raw_url.starts_with("../")
            && raw_url.split(':').next().map_or(false, |s| s.contains('@')));

    if is_absolute {
        return Ok(raw_url.to_string());
    }

    let superproject_url = match superproject_url {
        Some(u) => u,
        None => {
            return Err(format!(
                "Cannot resolve relative submodule URL {raw_url:?}: superproject_url is None"
            ));
        }
    };

    // Strip last path component from superproject_url (mirrors `${remote%/*}`).
    let last_slash = match superproject_url.rfind('/') {
        Some(i) => i,
        None => {
            return Ok(format!("{}/{}", superproject_url, raw_url));
        }
    };
    let remoteurl = &superproject_url[..last_slash];

    // Split scheme+host from the path component.
    if let Some(scheme_end_pos) = remoteurl.find("://") {
        let scheme_end = scheme_end_pos + 3;
        let scheme_host_str = &remoteurl[..scheme_end];  // e.g. "https://"
        let after_scheme = &remoteurl[scheme_end..];     // e.g. "github.com/org"
        let (host_part, url_path) = match after_scheme.find('/') {
            Some(p) => (&after_scheme[..p], &after_scheme[p..]),
            None => (after_scheme, "/"),
        };
        let base = format!("{}{}", scheme_host_str, host_part);
        // Join path with raw_url and normalize.
        let joined = format!("{}/{}", url_path.trim_end_matches('/'), raw_url);
        let resolved_path = normalize_url_path(&joined);
        Ok(format!("{}{}", base, resolved_path))
    } else {
        // No scheme (bare path).
        let joined = format!("{}/{}", remoteurl.trim_end_matches('/'), raw_url);
        Ok(normalize_url_path(&joined))
    }
}

/// POSIX-style path normalization for URL path components.
/// Resolves `.` and `..` segments and collapses consecutive slashes,
/// converging with Python's `posixpath.normpath` behavior (R1-16).
fn normalize_url_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let absolute = path.starts_with('/');
    for segment in path.split('/') {
        match segment {
            // R1-16: empty segments from consecutive slashes (e.g. "//") are
            // collapsed by treating them the same as "." — skip.
            "" | "." => {}
            ".." => { parts.pop(); }
            s => parts.push(s),
        }
    }
    let result = parts.join("/");
    if absolute {
        format!("/{}", result)
    } else {
        result
    }
}

/// Check if `content` is a Git-LFS pointer and raise `FETCH-GIT-LFS-POINTER`
/// if so. A blob is a pointer iff its first line is exactly the LFS version
/// header (plugin-contract.md §2.3.2).
fn check_lfs(entry_path: &str, content: &[u8]) -> Result<(), FetchError> {
    if content.starts_with(LFS_POINTER_FIRST_LINE) {
        return Err(transport(
            "FETCH-GIT-LFS-POINTER",
            format!(
                "dep uses Git LFS at path {entry_path:?}: milpa reads the git object \
                 store directly and cannot fetch LFS blobs — vendor a plain-git mirror \
                 or use a local= path"
            ),
        ));
    }
    Ok(())
}

/// Write a mode-120000 symlink blob to disk after lexical containment check
/// (plugin-contract.md §2.3.3 — same containment logic as SafeExtractor).
fn materialize_symlink(
    entry_path: &str,
    blob: &[u8],
    abs_dest: &Path,
    dest_root: &Path,
) -> Result<(), FetchError> {
    use crate::safe_extract::normalize_lexical;

    let link_target = match std::str::from_utf8(blob) {
        Ok(s) => s,
        Err(_) => {
            return Err(transport(
                "EXTRACT-SYMLINK-ESCAPE",
                format!(
                    "symlink {entry_path:?} has a non-UTF-8 target; cannot check containment"
                ),
            ));
        }
    };

    // Lexical containment check: parent of abs_dest joined with the link target,
    // all `.` and `..` resolved WITHOUT following filesystem symlinks.
    let parent = abs_dest.parent().unwrap_or(dest_root);
    let resolved_target = normalize_lexical(&parent.join(link_target));
    let under_dest = resolved_target.starts_with(dest_root);
    if !under_dest {
        return Err(transport(
            "EXTRACT-SYMLINK-ESCAPE",
            format!(
                "symlink {entry_path:?} → {link_target:?} resolves outside \
                 destination: {} not under {}",
                resolved_target.display(),
                dest_root.display()
            ),
        ));
    }

    // Write the symlink.
    if let Some(p) = abs_dest.parent() {
        std::fs::create_dir_all(p).map_err(|e| transport(
            "FETCH-GIT-FAILED",
            format!("creating parent for symlink {entry_path:?}: {e}"),
        ))?;
    }
    let _ = std::fs::remove_file(abs_dest);
    std::os::unix::fs::symlink(link_target, abs_dest).map_err(|e| transport(
        "FETCH-GIT-FAILED",
        format!("creating symlink {entry_path:?}: {e}"),
    ))?;
    Ok(())
}

/// Clone `url` into a scratch dir with `--no-checkout`, resolve the commit,
/// materialize the object store into `dest`, then clean up the scratch.
/// Returns a `Receipt` with `resolved_ref = Some(commit_sha)`.
///
/// This is the H3c object-store implementation — mirrors Python `GitFetcher.fetch`.
/// No working-tree checkout is created; `materialize_git_tree` reads blobs
/// directly from the `.git/` object store, so no smudge filters can apply
/// (spec/identity.md §1.7 NORMATIVE).
///
/// `FETCH-GIT-FAILED` on a clone/fetch failure; `FETCH-GIT-COMMIT-ABSENT` if
/// the pinned commit isn't present after exhaustive fetch (H4 chain).
pub fn fetch_git(
    name: &str,
    url: &str,
    ref_spec: &str,
    commit_sha: Option<&str>,
    dest: &Path,
) -> Result<Receipt, FetchError> {
    clear_dest(dest).map_err(|e| transport("FETCH-GIT-FAILED", e))?;

    // Allocate a clone scratch directory alongside dest.  The scratch holds
    // `.git/` (the object store); the output tree (`dest`) is separate and
    // MUST NOT contain `.git` (spec/identity.md §1.7.1 NORMATIVE: two distinct
    // scratch dirs).
    let scratch_parent = dest.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("_scratch_{}", dest.file_name().and_then(|n| n.to_str()).unwrap_or("dep")));
    let _ = std::fs::remove_dir_all(&scratch_parent);
    std::fs::create_dir_all(&scratch_parent).map_err(|e| transport(
        "FETCH-GIT-FAILED",
        format!("fetching {name:?}: cannot create clone scratch parent: {e}"),
    ))?;

    // Unique scratch dir within the parent (mirrors Python's tempfile.mkdtemp).
    let clone_scratch = scratch_parent.join("clone");

    // Cleanup guard: remove scratch on exit regardless of success or failure.
    // (Using a struct with Drop so we don't need to duplicate cleanup on each
    //  early-return path.)
    struct ScratchGuard(PathBuf);
    impl Drop for ScratchGuard {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }
    let _guard = ScratchGuard(scratch_parent.clone());

    // Clone --no-checkout: object store only, no working tree, no smudge.
    // Full-depth clone (precision fix b — H4): no --depth flag.
    // R5: --end-of-options before the URL.
    git_status(name, Command::new("git").args([
        "clone", "-q", "--no-checkout", "--end-of-options",
        url, &clone_scratch.to_string_lossy(),
    ]))?;

    // Resolve the commit SHA.
    let commit = match commit_sha {
        Some(sha) => {
            // Exact-commit pin: run the 4-step ensure_commit_present chain.
            ensure_commit_present(name, url, sha, &clone_scratch)?;
            sha.to_string()
        }
        None => {
            // Mutable-ref tip: resolve the ref to a commit SHA.
            // The full clone already fetched every branch, tag, and reachable
            // object, so a branch tip, tag, or any commit SHA (full OR short)
            // reachable from history usually resolves locally — no fetch needed.
            // Only fetch explicitly when the ref is not yet present (e.g. a PR
            // ref / hidden namespace the default clone didn't bring down).  This
            // also avoids `git fetch origin <short-sha>`, which servers reject
            // outright (they accept full SHAs via allowReachableSHA1InWant but
            // not abbreviated ones).
            match try_resolve_ref(&clone_scratch, ref_spec) {
                Some(sha) => sha,
                None => {
                    git_status(name, Command::new("git").arg("-C").arg(&clone_scratch).args([
                        "fetch", "-q", "origin", "--end-of-options", ref_spec,
                    ]))?;
                    git_resolve_ref(&clone_scratch, ref_spec, name)?
                }
            }
        }
    };

    // D4 (resolution-semantics RFC §3 Axis D): read the resolved commit's own
    // committer date off the object store already present in clone_scratch —
    // a bounded transport addition, no extra network round trip. Must happen
    // before ScratchGuard's Drop cleans up clone_scratch on return.
    //
    // L2: best-effort, NOT `?`. This transport function has no idea whether
    // the caller's resolve even has an `exclude_newer` bound in play —
    // `committer_date`'s only consumer is the resolver's exclude-newer
    // validation (`resolver.rs::process_url`), which is `Option`-typed on
    // both sides already. Propagating a `git log` hiccup here as
    // `FETCH-GIT-FAILED` would fail the WHOLE fetch even for a resolve that
    // never asked for a time bound at all. Degrade a read failure to `None`
    // instead; the resolver fails closed (still raises `RES-EXCLUDE-NEWER-PIN`)
    // when a bound IS set but the date came back unreadable, so the
    // exclude-newer safety property is not silently bypassed — only a fetch
    // that doesn't need the date is spared.
    let committer_date = git_committer_date(name, url, &clone_scratch, &commit).ok();

    // Materialize the object-store tree into dest.
    std::fs::create_dir_all(dest).map_err(|e| transport(
        "FETCH-GIT-FAILED",
        format!("fetching {name:?}: cannot create dest: {e}"),
    ))?;

    // H5: build the submodule_fetch closure.  For each (url, sha) pair,
    // clone the submodule into a scratch dir under scratch_parent and return it.
    // ScratchGuard cleans up scratch_parent (and all sub-clones) on exit.
    let scratch_parent_for_sub = scratch_parent.clone();
    // R1-10: use an atomic counter for unique sub-scratch dir names rather than
    // subsec_nanos() — two submodules in the same nanosecond would collide.
    let sub_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let submodule_fetch_fn = move |sub_url: &str, sub_sha: &str| -> Result<PathBuf, FetchError> {
        // R1-10: guaranteed-unique dir via incrementing counter.
        let idx = sub_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let sub_scratch = scratch_parent_for_sub.join(format!("sub_{idx}"));
        // Use git clone with --no-checkout.
        let clone_out = std::process::Command::new("git")
            .args(["clone", "-q", "--no-checkout", "--end-of-options",
                   sub_url, &sub_scratch.to_string_lossy()])
            .output()
            .map_err(|e| transport(
                "FETCH-GIT-SUBMODULE-FAILED",
                format!(
                    "submodule clone from {sub_url:?}: cannot spawn git: {e} \
                     [submodule_url={sub_url:?}]"
                ),
            ))?;
        if !clone_out.status.success() {
            return Err(transport(
                "FETCH-GIT-SUBMODULE-FAILED",
                format!(
                    "submodule clone from {sub_url:?} failed: {} \
                     [submodule_url={sub_url:?}]",
                    String::from_utf8_lossy(&clone_out.stderr).trim()
                ),
            ));
        }
        // R1-05: ensure the pinned submodule SHA is present after cloning.
        // `git clone` fetches the default branch; the pinned commit may be on a
        // non-default branch or not yet present (server requires allowReachableSHA1InWant).
        // Raise FETCH-GIT-SUBMODULE-FAILED (not FETCH-GIT-FAILED) on genuine absence —
        // canonical slug for submodule resolution failures.
        if !sub_sha.is_empty() {
            // Use a lightweight wrapper: if not present after clone, try fetching.
            if !commit_present(&sub_scratch, sub_sha) {
                // Try a targeted fetch first (best-effort).
                let _ = std::process::Command::new("git")
                    .arg("-C").arg(&sub_scratch)
                    .args(["fetch", "-q", "origin", "--end-of-options", sub_sha])
                    .output();
                if !commit_present(&sub_scratch, sub_sha) {
                    // Full fetch.
                    let _ = std::process::Command::new("git")
                        .arg("-C").arg(&sub_scratch)
                        .args(["fetch", "-q", "origin"])
                        .output();
                }
                if !commit_present(&sub_scratch, sub_sha) {
                    return Err(transport(
                        "FETCH-GIT-SUBMODULE-FAILED",
                        format!(
                            "submodule from {sub_url:?}: pinned commit {sub_sha} not found \
                             even after full history fetch \
                             [submodule_url={sub_url:?}]"
                        ),
                    ));
                }
            }
        }
        Ok(sub_scratch)
    };

    // R1-04: capture the submodule SHAs returned by materialize_git_tree so
    // the Receipt can carry them to transport_to_record → lockfile.
    let raw_submodule_shas = materialize_git_tree(
        &clone_scratch,
        &commit,
        dest,
        Some(&submodule_fetch_fn),
        Some(url),
    )?;

    // Path-sort the submodule SHAs (spec NORMATIVE: deterministic order).
    let mut submodule_shas: Vec<(String, String)> = raw_submodule_shas.into_iter().collect();
    submodule_shas.sort_by(|a, b| a.0.cmp(&b.0));

    // Scratch is cleaned by ScratchGuard::drop.
    Ok(Receipt {
        resolved_ref: Some(commit),
        archive_sha256: None,
        submodule_shas,
        identity: None,
        committer_date,
    })
}

/// D4 (resolution-semantics RFC §3 Axis D / §6 D-D1): return the committer
/// date of `commit` in `repo` (a `--no-checkout` clone scratch holding the
/// object store).
///
/// **Committer date, NEVER an annotated tag's tagger date.** `%cI` is git's
/// own strict-ISO-8601 committer-date format for `git log`, run against a
/// *commit* object — `commit` here is always an already-peeled `^{commit}`
/// SHA (both the exact-pin `ensure_commit_present` path and the ref-
/// resolution `try_resolve_ref`/`git_resolve_ref` paths dereference through
/// any tag object before this point), so there is no tag object in the loop
/// for this to accidentally read a tagger date from.
fn git_committer_date(
    name: &str,
    url: &str,
    repo: &Path,
    commit: &str,
) -> Result<milpa_types::Timestamp, FetchError> {
    let out = Command::new("git")
        .arg("-C").arg(repo)
        .args(["log", "-1", "--format=%cI", "--end-of-options", commit])
        .output()
        .map_err(|e| transport(
            "FETCH-GIT-FAILED",
            format!("fetching {name:?} from {url:?}: cannot spawn git log: {e}"),
        ))?;
    if !out.status.success() {
        return Err(transport(
            "FETCH-GIT-FAILED",
            format!(
                "fetching {name:?} from {url:?}: reading committer date for commit {commit:?} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim(),
            ),
        ));
    }
    let raw = String::from_utf8_lossy(&out.stdout);
    milpa_types::parse_iso8601_timestamp(raw.trim()).ok_or_else(|| transport(
        "FETCH-GIT-FAILED",
        format!(
            "fetching {name:?} from {url:?}: git log produced an unparseable committer date {:?} for commit {commit:?}",
            raw.trim(),
        ),
    ))
}

/// Ensure `sha` is present in the local repo at `dest`, using a 4-step
/// exhaustive fetch strategy that mirrors Python's `_ensure_commit_present`.
///
/// Steps:
///   1. `git cat-file -e <sha>^{commit}` — cheap local check.
///   2. Targeted `git fetch origin <sha>` — works when the server supports
///      `uploadpack.allowReachableSHA1InWant` (GitHub / GitLab).
///   3. Full history: `git fetch --unshallow origin` (if shallow), then
///      `git fetch origin` to pull any remaining refs.
///   4. Re-check; if still absent raise `FETCH-GIT-COMMIT-ABSENT`.
///
/// Precision fix (a) — narrow soft-fail on `--unshallow`:
/// `git fetch --unshallow` on an already-complete (non-shallow) clone fails
/// with a specific message ("--unshallow on a complete repository does not
/// make sense").  That benign failure is swallowed so a full-depth clone
/// running the fallback doesn't spuriously error.  ANY OTHER fetch failure
/// (network error, auth failure, etc.) is propagated as `FETCH-GIT-FAILED`.
fn ensure_commit_present(name: &str, url: &str, sha: &str, dest: &Path) -> Result<(), FetchError> {
    // Step 1: cheap local presence check.
    // R5: --end-of-options before the object spec for flag-injection safety.
    if commit_present(dest, sha) {
        return Ok(());
    }

    // Step 2: targeted fetch (server-side reachable SHA support).
    // R5: --end-of-options before the SHA refspec.
    let targeted = std::process::Command::new("git")
        .arg("-C").arg(dest)
        .args(["fetch", "-q", "origin", "--end-of-options", sha])
        .output();
    if matches!(&targeted, Ok(o) if o.status.success()) {
        // R1-14: re-verify presence after a successful step-2 fetch.
        // `git fetch origin <sha>` can exit 0 while the server ignored the SHA
        // (no allowReachableSHA1InWant), leaving the commit absent.  Only return
        // Ok if the commit is actually present now; otherwise fall through to
        // steps 3-4 which do a full unshallow+refetch.
        if commit_present(dest, sha) {
            return Ok(());
        }
    }
    // Step 2 failure (or success-but-absent) is non-fatal (targeted SHA fetch
    // is best-effort; many servers don't support it) — fall through to step 3.

    // Step 3a: `git fetch --unshallow origin` — expands a shallow clone to
    // full depth.  On a non-shallow clone this fails with a specific "does not
    // make sense" message; swallow ONLY that benign case (precision fix a).
    let unshallow = std::process::Command::new("git")
        .arg("-C").arg(dest)
        .args(["fetch", "-q", "--unshallow", "origin"])
        .output();
    match &unshallow {
        Ok(o) if !o.status.success() => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            // Benign case: the repo is already complete (full-depth clone).
            // Git prints "fatal: --unshallow on a complete repository does not
            // make sense" (or a locale variant).  Swallow this specific error.
            let is_already_complete = stderr.contains("does not make sense")
                || stderr.contains("complete repository");
            if !is_already_complete {
                // Real fetch failure (network, auth, …) — propagate it.
                return Err(transport(
                    "FETCH-GIT-FAILED",
                    format!(
                        "fetching {name:?} from {url:?}: git fetch --unshallow failed: {}",
                        stderr.trim()
                    ),
                ));
            }
            // Already complete — fall through to step 3b.
        }
        Err(e) => {
            // Could not even spawn git — propagate.
            return Err(transport(
                "FETCH-GIT-FAILED",
                format!("fetching {name:?}: cannot run git fetch --unshallow: {e}"),
            ));
        }
        Ok(_) => {} // --unshallow succeeded; fall through to step 3b.
    }

    // Step 3b: plain `git fetch origin` — pulls any new refs since the clone.
    // Failure here is non-fatal (best-effort); step 4 does the definitive check.
    let _ = std::process::Command::new("git")
        .arg("-C").arg(dest)
        .args(["fetch", "-q", "origin"])
        .output();

    // Step 4: re-check after full history fetch.
    if commit_present(dest, sha) {
        return Ok(());
    }

    Err(transport(
        "FETCH-GIT-COMMIT-ABSENT",
        format!(
            "fetching {name:?}: commit {sha} not found in {url:?} even after \
             full history fetch — the pin may be stale or the commit was \
             force-pushed away"
        ),
    ))
}

fn git_status(name: &str, cmd: &mut Command) -> Result<(), FetchError> {
    let out = cmd.output().map_err(|e| {
        transport(
            "FETCH-GIT-FAILED",
            format!("fetching {name:?}: cannot run git: {e}"),
        )
    })?;
    if out.status.success() {
        Ok(())
    } else {
        Err(transport(
            "FETCH-GIT-FAILED",
            format!(
                "fetching {name:?}: git failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ))
    }
}

/// `git cat-file -e <sha>^{commit}` — true iff the commit object exists.
/// R5: `--end-of-options` is inserted before the object spec for consistency,
/// even though the `^{commit}` suffix makes it unparseable as a flag.
fn commit_present(dir: &Path, sha: &str) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["cat-file", "-e", "--end-of-options", &format!("{sha}^{{commit}}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Try to resolve *ref_spec* against the object store at *repo* without fetching.
///
/// Mirrors Python's `_try_resolve_ref`.  Does NOT consult `FETCH_HEAD` — a
/// `git clone` leaves a stale `FETCH_HEAD` pointing at the default branch, so
/// consulting it would mis-resolve any non-default-branch ref.
///
/// Tries in order:
/// 1. `refs/remotes/origin/<ref>^{commit}` — branch tips from the full clone.
/// 2. `<ref>^{commit}` — resolves tags, full SHAs, and short SHAs already
///    present in the object store (git expands abbreviated OIDs internally).
///
/// Returns `Some(sha)` on success, `None` when a targeted `git fetch` is needed.
/// R5: `--end-of-options` before the ref so refs starting with `-` are not
/// parsed as flags.
fn try_resolve_ref(repo: &Path, ref_spec: &str) -> Option<String> {
    // 1. Remote-tracking branch tip (populated by the full clone).
    let out1 = Command::new("git")
        .arg("-C").arg(repo)
        .args(["rev-parse", "--verify", "--quiet", "--end-of-options",
               &format!("refs/remotes/origin/{ref_spec}^{{commit}}")])
        .output()
        .ok()?;
    if out1.status.success() {
        let sha = String::from_utf8_lossy(&out1.stdout).trim().to_string();
        if !sha.is_empty() {
            return Some(sha);
        }
    }

    // 2. Direct resolution — covers tags, full SHAs, and short SHAs present
    //    in the object store.
    let out2 = Command::new("git")
        .arg("-C").arg(repo)
        .args(["rev-parse", "--verify", "--quiet", "--end-of-options",
               &format!("{ref_spec}^{{commit}}")])
        .output()
        .ok()?;
    if out2.status.success() {
        let sha = String::from_utf8_lossy(&out2.stdout).trim().to_string();
        if !sha.is_empty() {
            return Some(sha);
        }
    }

    None
}

/// Resolve a ref name to a commit SHA in the object store at `repo`.
///
/// Mirrors Python's `_git_resolve_ref`: tries FETCH_HEAD first (populated by
/// the preceding `git fetch origin <ref>`), then falls back to
/// `refs/remotes/origin/<ref>`, then a plain `rev-parse <ref>`.
/// R5: `--end-of-options` before the ref so a ref starting with `-` is not
/// parsed as a flag.
fn git_resolve_ref(repo: &Path, ref_spec: &str, name: &str) -> Result<String, FetchError> {
    // Try FETCH_HEAD first (written by the preceding git fetch).
    let fetch_head = repo.join(".git").join("FETCH_HEAD");
    if fetch_head.exists() {
        if let Ok(text) = std::fs::read_to_string(&fetch_head) {
            if let Some(line) = text.lines().next() {
                let sha = line.split_whitespace().next().unwrap_or("");
                if sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Ok(sha.to_string());
                }
            }
        }
    }

    // Fallback: refs/remotes/origin/<ref>.
    let result = Command::new("git")
        .arg("-C").arg(repo)
        .args(["rev-parse", "--end-of-options",
               &format!("refs/remotes/origin/{ref_spec}")])
        .output();
    if let Ok(out) = result {
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
        }
    }

    // Final fallback: try the ref name directly.
    let result2 = Command::new("git")
        .arg("-C").arg(repo)
        .args(["rev-parse", "--end-of-options", ref_spec])
        .output();
    if let Ok(out) = result2 {
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
        }
    }

    Err(transport(
        "FETCH-GIT-FAILED",
        format!("fetching {name:?}: could not resolve ref {ref_spec:?} to a commit SHA"),
    ))
}

/// A `Write` adapter that stops accepting bytes once `limit` is reached.
/// Used by the xz decompression path for SA-1 bomb-guard (lzma-rs uses a
/// Write-based API rather than a Read-based decoder).
struct LimitedWriter<'a> {
    inner: &'a mut Vec<u8>,
    limit: u64,
    written: u64,
    hit: bool,
}

impl<'a> LimitedWriter<'a> {
    fn new(inner: &'a mut Vec<u8>, limit: u64) -> Self {
        LimitedWriter { inner, limit, written: 0, hit: false }
    }
    fn limit_hit(&self) -> bool {
        self.hit
    }
}

impl std::io::Write for LimitedWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // R1-08: admit EXACTLY limit bytes; fire only when written WOULD EXCEED limit.
        // `remaining` is how many more bytes we can accept before exceeding the cap.
        // If `buf.len() <= remaining`: accept all bytes (even if remaining == 0 and
        // buf is empty). If `buf.len() > remaining`: accept exactly `remaining` bytes
        // if remaining > 0, then set limit_hit; if remaining == 0 we're already full.
        //
        // This matches Python: admit stream of exactly `decomp_cap` bytes, reject
        // only `> decomp_cap`.  The old code fired at `>= limit` (off-by-one).
        if self.written > self.limit {
            // Already over — shouldn't happen if the logic below is correct, but
            // guard defensively.
            self.hit = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "decompression cap exceeded",
            ));
        }
        let remaining = self.limit - self.written; // bytes still acceptable
        if buf.len() as u64 <= remaining {
            // All of buf fits without exceeding the cap.
            self.inner.extend_from_slice(buf);
            self.written += buf.len() as u64;
            Ok(buf.len())
        } else {
            // buf would push us over the cap. Accept what fits, then signal error.
            let n = remaining as usize;
            if n > 0 {
                self.inner.extend_from_slice(&buf[..n]);
                self.written += n as u64;
            }
            self.hit = true;
            Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "decompression cap exceeded",
            ))
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Download a tarball, verify its sha256 (before extraction), gunzip if needed,
/// and safe-extract into `dest` (mirrors `TarballFetcher`). `FETCH-DOWNLOAD-FAILED`
/// on transport error; `FETCH-SHA256-MISMATCH` if the declared hash differs (the
/// archive is rejected BEFORE any extraction); `FETCH-EXTRACT-FAILED` wrapping any
/// `safe_extract` violation.
///
/// Uses `MAX_COMPRESSED_BYTES` as the download cap. For testing with a custom
/// cap, use [`fetch_tarball_with_cap`].
pub fn fetch_tarball(
    name: &str,
    url: &str,
    expected_sha256: Option<&str>,
    strip_components: u32,
    dest: &Path,
    http_get: &dyn Fn(&str) -> Result<Vec<u8>, HttpGetError>,
) -> Result<Receipt, FetchError> {
    fetch_tarball_with_cap(name, url, expected_sha256, strip_components, dest, http_get, MAX_COMPRESSED_BYTES)
}

/// Like [`fetch_tarball`] but with an explicit `compressed_cap` (R4 — allows
/// tests to inject a tiny cap without requiring a 4 GiB download).
pub fn fetch_tarball_with_cap(
    name: &str,
    url: &str,
    expected_sha256: Option<&str>,
    strip_components: u32,
    dest: &Path,
    http_get: &dyn Fn(&str) -> Result<Vec<u8>, HttpGetError>,
    compressed_cap: u64,
) -> Result<Receipt, FetchError> {
    fetch_tarball_with_decomp_cap(
        name,
        url,
        expected_sha256,
        strip_components,
        dest,
        http_get,
        compressed_cap,
        Limits::default().decomp_cap(),
    )
}

/// Like [`fetch_tarball_with_cap`] but also accepts an explicit `decomp_cap`
/// (R4 / R3-02 — allows tests to trigger the lzma-alone decompressor-level
/// size guard through the full public fetch path without needing a file that
/// decompresses to the production cap of ~4 GiB).
///
/// The production path always calls this via `fetch_tarball_with_cap` with
/// `Limits::default().decomp_cap()`; this variant is `pub(crate)` so tests
/// can inject a tiny cap without touching the production default.
pub(crate) fn fetch_tarball_with_decomp_cap(
    name: &str,
    url: &str,
    expected_sha256: Option<&str>,
    strip_components: u32,
    dest: &Path,
    http_get: &dyn Fn(&str) -> Result<Vec<u8>, HttpGetError>,
    compressed_cap: u64,
    decomp_cap: u64,
) -> Result<Receipt, FetchError> {
    let bytes = http_get(url).map_err(|e| {
        // R1-22: match on the typed HttpGetError variant rather than a string prefix.
        match e {
            HttpGetError::SizeExceeded(msg) => transport(
                "FETCH-DOWNLOAD-SIZE-EXCEEDED",
                format!("fetching {name:?} from {url}: {msg}"),
            ),
            HttpGetError::Other(msg) => transport(
                "FETCH-DOWNLOAD-FAILED",
                format!("fetching {name:?} from {url}: {msg}"),
            ),
        }
    })?;

    // H1: cap the compressed body before decompression.  The production http_get
    // (curl streaming) aborts and raises FETCH-DOWNLOAD-SIZE-EXCEEDED before
    // reading beyond the cap; this check covers injected transports (tests,
    // mocked fetchers) that return bytes directly without streaming.
    // FETCH-DOWNLOAD-SIZE-EXCEEDED is distinct from FETCH-DOWNLOAD-FAILED so a
    // security size-cap rejection is not conflated with a network failure.
    if bytes.len() as u64 > compressed_cap {
        return Err(transport(
            "FETCH-DOWNLOAD-SIZE-EXCEEDED",
            format!(
                "fetching {name:?} from {url}: compressed body ({} bytes) exceeds \
                 download cap ({compressed_cap} bytes); possible oversized mirror",
                bytes.len()
            ),
        ));
    }

    // Compute the archive digest once: it gates an existing pin (below) AND is
    // returned as the TOFU receipt so the resolver can record/preserve it
    // (`lockfile-schema.md §5`).
    let actual_sha = sha256_hex(&bytes);

    if let Some(expected) = expected_sha256 {
        // Accept a bare hex digest or a `sha256:`-prefixed one; normalize to
        // lowercase so UPPERCASE or mixed-case pins from the manifest/lockfile
        // are accepted (case-insensitive comparison, both sides already lowercase
        // from sha256_hex, so only `want` needs lowercasing).
        let want = expected.strip_prefix("sha256:").unwrap_or(expected).to_lowercase();
        if actual_sha != want {
            return Err(transport(
                "FETCH-SHA256-MISMATCH",
                format!(
                    "fetching {name:?}: archive sha256 mismatch — expected {expected}, got {actual_sha} \
                     (URL {url}); rejected before extraction"
                ),
            ));
        }
    }

    // Unsupported-format guard: ZIP archives are not supported by TarballFetcher.
    // A `.zip` URL today fails with an empty-extraction silent success (Rust's
    // TarEntries sees < 512 bytes and returns zero entries → Ok-empty).  Detect
    // the ZIP magic bytes early and raise FETCH-EXTRACT-FAILED with an actionable
    // message rather than silently producing an empty dep tree (H0 §zip-guard).
    if bytes.starts_with(MAGIC_ZIP) {
        return Err(transport(
            "FETCH-EXTRACT-FAILED",
            format!(
                "fetching {name:?}: unsupported archive format: .zip \
                 (TarballFetcher accepts .tar.gz / .tar.bz2 / .tar.xz / .tar only; \
                 use a tarball URL or a git= dep)"
            ),
        ));
    }

    // Detect compression format by magic bytes, decompress with a size cap,
    // then feed the raw tar bytes to extract_tar.
    //
    // Supported formats (spec/manifest-grammar.md §TarballDep):
    //   gzip  — magic 1f 8b
    //   bzip2 — magic 42 5a 68 ("BZh")
    //   xz    — magic fd 37 7a 58 5a 00
    //   uncompressed tar — no magic match (fall through)
    //
    // SA-1 decompression-bomb guard: all decoders go through `decompress_capped`
    // (the module-level SSOT) which wraps the decoder in `.take(decomp_cap)`.
    // The cap formula (max_total_size + DECOMP_CAP_OVERHEAD) lives in exactly one
    // place; fetch_oci uses the same helper so there is no parallel copy.
    // R1-12 / R3-02: decomp_cap is a parameter (callers supply
    // `Limits::default().decomp_cap()` for the production default; tests inject
    // a small cap to exercise the lzma-alone decompressor guard end-to-end).

    let tar_bytes = decompress_tar_archive(&bytes, decomp_cap, name)?;

    clear_dest(dest).map_err(|e| transport("FETCH-EXTRACT-FAILED", e))?;
    extract_tar(&tar_bytes, dest, strip_components, Limits::default()).map_err(|e| {
        let _ = std::fs::remove_dir_all(dest);
        // Re-key any EXTRACT-* (or other) failure as the tarball-transport code.
        transport(
            "FETCH-EXTRACT-FAILED",
            format!("fetching {name:?}: safe extraction failed ({})", e.code()),
        )
    })?;
    Ok(Receipt {
        archive_sha256: Some(actual_sha),
        ..Default::default()
    })
}

/// Pull an OCI artifact via `oras` and safe-extract its single source tarball
/// (mirrors `OciFetcher`). `FETCH-OCI-PULL-FAILED` (incl. `oras` absent);
/// `FETCH-OCI-NO-TARBALL` / `FETCH-OCI-AMBIGUOUS-TARBALL` on 0 / >1 `*.tar.gz`.
pub fn fetch_oci(
    name: &str,
    registry: &str,
    repository: &str,
    digest: &str,
    dest: &Path,
) -> Result<Receipt, FetchError> {
    // R5: validate that registry and repository do not start with '-' so they
    // cannot be interpreted as option flags by oras.  oras does not document
    // --end-of-options, so we use an input-validation guard (mirrors
    // Python's validate_oci_field / TNG-UNSAFE-OCI-FIELD).
    // NOTE: `digest` is deliberately NOT checked here — it is format-validated
    // (`sha256:<64 hex>`) at the registry layer (`validate_oci_digest` →
    // TNG-BAD-OCI-DIGEST), which already rejects any `-`-prefixed or malformed
    // value, exactly as the Python impl does. Adding a leading-`-` check here
    // would diverge from Python (it would fire TNG-UNSAFE-OCI-FIELD instead of
    // TNG-BAD-OCI-DIGEST for a `-`-prefixed digest).
    for (field_name, field_val) in [("registry", registry), ("repository", repository)] {
        if field_val.starts_with('-') {
            return Err(transport(
                "TNG-UNSAFE-OCI-FIELD",
                format!("fetching {name:?}: OCI {field_name} {field_val:?} starts with '-'; rejected as potentially malicious"),
            ));
        }
    }

    let oci_ref = format!("{registry}/{repository}@{digest}");
    let scratch = dest
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".{name}.oci-pull"));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch)
        .map_err(|e| transport("FETCH-OCI-PULL-FAILED", format!("oci scratch: {e}")))?;

    let pull = Command::new("oras")
        .args(["pull", &oci_ref, "--output"])
        .arg(&scratch)
        .output();
    let ok = matches!(&pull, Ok(o) if o.status.success());
    if !ok {
        let detail = match &pull {
            Ok(o) => String::from_utf8_lossy(&o.stderr).trim().to_string(),
            Err(e) => format!("cannot run oras: {e}"),
        };
        let _ = std::fs::remove_dir_all(&scratch);
        return Err(transport(
            "FETCH-OCI-PULL-FAILED",
            format!("oras pull failed for {name:?} ({oci_ref}): {detail}"),
        ));
    }

    let mut tarballs: Vec<std::path::PathBuf> = std::fs::read_dir(&scratch)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.to_string_lossy().ends_with(".tar.gz"))
                .collect()
        })
        .unwrap_or_default();
    tarballs.sort();

    let result = match tarballs.as_slice() {
        [] => Err(transport(
            "FETCH-OCI-NO-TARBALL",
            format!("OCI artifact {oci_ref} contained no *.tar.gz"),
        )),
        [one] => {
            let bytes = std::fs::read(one).map_err(|e| {
                transport(
                    "FETCH-OCI-PULL-FAILED",
                    format!("reading pulled tarball: {e}"),
                )
            })?;
            // SA-1: use the shared decompress_capped helper — same cap formula
            // (DECOMP_CAP_OVERHEAD) and same EXTRACT-SIZE-LIMIT slug as fetch_tarball.
            // This is the fix for R2: no parallel inline copy of the cap logic.
            // R1-12: single source of truth for the decompression cap formula.
            let oci_decomp_cap: u64 = Limits::default().decomp_cap();
            let tar = decompress_capped(GzDecoder::new(&bytes[..]), oci_decomp_cap, name, "gunzip")
                .map_err(|e| {
                    let _ = std::fs::remove_dir_all(&scratch);
                    e
                })?;
            clear_dest(dest).map_err(|e| transport("FETCH-EXTRACT-FAILED", e))?;
            extract_tar(&tar, dest, 0, Limits::default())
                .map(|_| Receipt::default())
                .map_err(|e| transport("FETCH-EXTRACT-FAILED", e.code().to_string()))
        }
        many => Err(transport(
            "FETCH-OCI-AMBIGUOUS-TARBALL",
            format!(
                "OCI artifact {oci_ref} has {} *.tar.gz files; ambiguous",
                many.len()
            ),
        )),
    };
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

/// Decompress a tarball archive's raw bytes into uncompressed tar bytes, applying
/// the SA-1 decompression-bomb cap. Single source of truth for the magic-byte
/// format dispatch (gzip / bzip2 / xz / lzma-alone / plain tar) shared by
/// [`fetch_tarball`] and [`enumerate_tarball_entries`].
fn decompress_tar_archive(
    bytes: &[u8],
    decomp_cap: u64,
    name: &str,
) -> Result<Vec<u8>, FetchError> {
    if bytes.starts_with(MAGIC_GZIP) {
        decompress_capped(GzDecoder::new(bytes), decomp_cap, name, "gzip")
    } else if bytes.starts_with(MAGIC_BZ2) {
        decompress_capped(bzip2_rs::DecoderReader::new(bytes), decomp_cap, name, "bzip2")
    } else if bytes.starts_with(MAGIC_XZ) {
        // lzma-rs uses a Write-based API (xz_decompress); route through
        // decompress_capped_xz so cap/slug/message are the same SSOT as gzip/bzip2.
        decompress_capped_xz(bytes, decomp_cap, name)
    } else {
        // R2-02/NEW-D: lzma-alone (`.tar.lzma`, FORMAT_ALONE / LZMA1) has NO
        // reliable magic bytes. Attempt-decode; on EXTRACT-SIZE-LIMIT propagate,
        // on any other error treat as uncompressed tar (fall through).
        match decompress_capped_lzma(bytes, decomp_cap, name) {
            Ok(decompressed) => Ok(decompressed),
            Err(e) if e.code() == "EXTRACT-SIZE-LIMIT" => Err(e),
            Err(_) => Ok(bytes.to_vec()),
        }
    }
}

/// The tarball **materialize seam** (RFC slice B2-tarball): read an archive's
/// members into a buffered `Vec<MaterializedEntry>` (spec §1.8.4), feeding the
/// epoch-2 DAG builder ([`crate::dag_identity::compute_dag_identity`]).
///
/// The tarball sibling of [`enumerate_git_entries`]: it produces the same abstract
/// `(relpath, mode_byte, content)` sequence from a `.tar(.gz/.bz2/.xz)` archive,
/// applying the same content rules so identity is **transport-independent** (spec
/// §1.1): a git tree and a faithful tarball of the same source bytes hash to the
/// same `dag-sha256:`. Decompression reuses [`decompress_tar_archive`] (SSOT) and
/// the tar parse reuses [`crate::safe_extract::tar_materialize_entries`] (the same
/// USTAR reader as `extract_tar`).
///
/// LOSSY-ARCHIVE RULE (spec/identity.md §1.8.10): the exec bit is part of epoch-2
/// identity. A `.tar` records POSIX modes faithfully; an archive format that drops
/// exec bits (e.g. `.zip`) materializes a *genuinely different* tree (every file
/// `0x00`) and hashes differently — correct behaviour, not a bug. `.zip` is
/// rejected upstream by [`fetch_tarball`]; only the exec-bit-faithful tar family
/// feeds this seam.
pub fn enumerate_tarball_entries(
    archive: &[u8],
    strip_components: u32,
    limits: Limits,
) -> Result<Vec<MaterializedEntry>, FetchError> {
    let tar_bytes = decompress_tar_archive(archive, limits.decomp_cap(), "tarball-materialize")?;
    crate::safe_extract::tar_materialize_entries(&tar_bytes, strip_components).map_err(|e| {
        transport(
            "FETCH-EXTRACT-FAILED",
            format!("tarball materialize seam: tar parse failed ({})", e.code()),
        )
    })
}

// The local-path **materialize seam** is the canonical on-disk identity walk:
// it lives in `identity::enumerate_local_entries` (the single source of truth for
// turning on-disk bytes + POSIX modes into a `MaterializedEntry` sequence, with
// proper ID-NON-UTF8-* coded errors), and `compute_content_hash` uses it. The
// local sibling of the object-store seams `enumerate_git_entries` /
// `enumerate_tarball_entries` is therefore identity's walk — not a second copy
// here (single source of truth).

/// The OCI **materialize seam** — a coded not-implemented STUB (RFC slice B2-oci).
///
/// Every other transport (git / tarball / local) has a real epoch-2 materializer
/// feeding [`crate::dag_identity::compute_dag_identity`]. OCI does NOT: there is no
/// epoch-2 OCI fetcher path yet (the OCI dag-oracle conformance tier stays
/// SKIPPED), so asking for the OCI seam is a clear coded not-implemented condition.
///
/// NOTE (slug): there is no `FETCH-*-NOT-IMPLEMENTED` slug in `spec/errors.md`, and
/// the error-catalog discipline forbids minting one carelessly. This stub returns
/// the non-catalog [`FetchError::Failed`] marker; if the OCI epoch-2 materializer
/// is ever built (B2-oci proper), a catalog slug is a deliberate spec decision made
/// then, not now.
pub fn enumerate_oci_entries(
    _registry: &str,
    _repository: &str,
    _digest: &str,
) -> Result<Vec<MaterializedEntry>, FetchError> {
    Err(FetchError::Failed(
        "OCI epoch-2 materialize seam is not implemented (RFC identity-conformance \
         B2-oci is a stub; there is no epoch-2 OCI fetcher path yet)"
            .to_string(),
    ))
}

// ---------------------------------------------------------------------------
// CAS-admitting fetcher wrapper (issue #2 / differential-conformance-harness RFC)
// ---------------------------------------------------------------------------

/// A [`FetcherRegistry`] wrapper that admits every fetched tree into a
/// [`CaStore`] and replaces `dest` with a relative CAS symlink.
///
/// The inner registry materializes content into a scratch directory allocated
/// via [`CaStore::scratch`] (C-stage, identity.md §3.4); the wrapper then:
///   1. Allocates a unique scratch subdir via `store.scratch()` under
///      `<cas_root>/_scratch/<uuid>/` — same filesystem as `sha256/`, so the
///      subsequent rename(2) in `admit()` is atomic (no EXDEV).
///   2. Fetches content into the scratch subdir.
///   3. Computes the content hash of the scratch tree.
///   4. Admits the scratch tree into `store` (move-via-rename, duplicate is no-op).
///   5. Removes any stale `dest` and creates a relative symlink at `dest` →
///      the store entry.
///   6. Cleans up the scratch subdir (admit moves it on success; we remove any remnant).
///
/// `CaStore::scratch()` is the sole owner of transient pre-admission space.
/// No external `staging_root` parameter is needed or accepted (C-stage SSOT).
///
/// This is the CAS layer used by the CLI when `MILPA_MOCKED_FETCHES` is set,
/// producing the same `_deps/<name>` → CAS symlink structure that the
/// conformance harness's `FakeFetcher` produces (single source of truth for
/// the CAS logic lives in `store.rs`; this wrapper just orchestrates).
pub struct CasAdmittingFetcher<R> {
    inner: R,
    store: crate::store::CaStore,
}

impl<R: FetcherRegistry> CasAdmittingFetcher<R> {
    /// Wrap `inner` so every successful fetch is admitted into `store`.
    ///
    /// Staging is handled internally via [`CaStore::scratch`] — no external
    /// `staging_root` parameter is required (C-stage: CaStore owns staging).
    pub fn new(inner: R, store: crate::store::CaStore) -> Self {
        CasAdmittingFetcher { inner, store }
    }

    /// Return a reference to the inner [`FetcherRegistry`].
    ///
    /// A0 architectural pin: `milpa hash` (and tests that need to probe
    /// `Receipt::identity` without CAS side-effects) call the inner registry
    /// directly. Callers MUST read identity from `Receipt::identity` — they
    /// must NOT call `compute_content_hash` themselves
    /// (spec/cli-contract.md §5.11 NORMATIVE).
    pub fn inner(&self) -> &R {
        &self.inner
    }
}

impl<R: FetcherRegistry> FetcherRegistry for CasAdmittingFetcher<R> {
    fn fetch(&self, name: &str, p: &milpa_types::Provenance, dest: &Path) -> Result<Receipt, FetchError> {
        if p.cas_admissible() {
            // Immutable source (Git / Tarball / OCI): allocate a scratch subdir
            // via CaStore::scratch() — under <cas_root>/_scratch/<uuid>/ — which is
            // on the same filesystem as sha256/, guaranteeing atomic rename(2) in admit().
            // spec/plugin-contract.md §4; spec/identity.md §3.4, §3.5; C-stage.
            let scratch = self.store.scratch().map_err(|e| {
                FetchError::Failed(format!("CasAdmittingFetcher: allocate scratch: {}", e.message()))
            })?;

            let receipt = match self.inner.fetch(name, p, &scratch.path) {
                Ok(r) => r,
                Err(e) => {
                    // Clean up scratch on fetch failure (C-stage: no leaked dirs).
                    let _ = std::fs::remove_dir_all(&scratch.path);
                    return Err(e);
                }
            };

            // R1-07: spec §2.4.2 NORMATIVE — walk the staged tree, sum regular-file
            // sizes, and raise FETCH-DOWNLOAD-SIZE-EXCEEDED if total > cap.
            // Cap source: Limits::default().max_total_size (uncompressed ceiling).
            // Mirrors Python's CasAdmittingFetcher staged-tree size check.
            {
                let cap = Limits::default().max_total_size;
                let total = walk_tree_size(&scratch.path);
                if total > cap {
                    let _ = std::fs::remove_dir_all(&scratch.path);
                    return Err(transport(
                        "FETCH-DOWNLOAD-SIZE-EXCEEDED",
                        format!(
                            "fetching {name:?}: staged tree size ({total} bytes) exceeds \
                             uncompressed cap ({cap} bytes); possible oversized dep"
                        ),
                    ));
                }
            }

            // Prefer the identity pre-computed by the inner registry (A0 pin:
            // `DefaultRegistry::fetch` sets `Receipt::identity` so `milpa hash`
            // and this path share the same hash derivation). Fall back to
            // `compute_content_hash` for inner registries that do not set identity
            // (e.g. `MockedFetcher`, `FakeFetcher`) — keeps backward compat.
            let identity = if let Some(id) = receipt.identity.clone() {
                id
            } else {
                use crate::identity::compute_content_hash;
                compute_content_hash(&scratch.path).map_err(|e| {
                    let _ = std::fs::remove_dir_all(&scratch.path);
                    FetchError::Failed(format!(
                        "CasAdmittingFetcher: hash scratch tree: {}",
                        e.message()
                    ))
                })?
            };
            let admit_result = self.store.admit(&scratch.path, &identity).map_err(|e| {
                let _ = std::fs::remove_dir_all(&scratch.path);
                FetchError::Failed(format!("CasAdmittingFetcher: admit to CAS: {}", e.message()))
            })?;
            // `admit` moves the scratch dir on success (rename); clean up any remnant.
            let _ = std::fs::remove_dir_all(&scratch.path);
            drop(admit_result);

            // Create the relative CAS symlink at dest.
            self.store.link(&identity, dest).map_err(|e| {
                FetchError::Failed(format!("CasAdmittingFetcher: link _deps entry: {}", e.message()))
            })?;

            Ok(receipt)
        } else {
            // Editable / Local provenance: do NOT admit to CAS — the dep must stay
            // as a real working directory so the user's in-progress edits remain live.
            // spec/plugin-contract.md §4: "editable sources MUST declare
            // cas_admissible = False … Admitting would silently freeze user edits."
            self.inner.fetch(name, p, dest)
        }
    }
}

// ---------------------------------------------------------------------------
// Mocked transport (issue #2 / differential-conformance-harness RFC)
// ---------------------------------------------------------------------------

/// Encode a `(url, ref_spec)` pair to its `mocked-fetches/` subdirectory name
/// (conformance-fixtures.md §2.3.1). Every character outside `[A-Za-z0-9._-]`
/// is replaced with `_`; a literal `@` separates the encoded URL from the
/// encoded ref.
///
/// This is the **production single source of truth** — `milpa-conformance`
/// re-exports this function rather than maintaining a parallel copy.
pub fn url_key(url: &str, ref_spec: &str) -> String {
    fn sanitize(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }
    format!("{}@{}", sanitize(url), sanitize(ref_spec))
}

/// Encode an OCI `(registry, repository, digest)` triple to its
/// `mocked-fetches/` subdirectory name (conformance-fixtures.md §2.3.5).
///
/// Mirrors the git/tarball key split: `registry/repository` is the "location"
/// half and `digest` is the "pointer" half — reusing [`url_key`] as the single
/// SSOT sanitizer rather than a parallel encoder. Unlike a git ref, an OCI
/// digest is already an immutable content pointer, so it slots directly into
/// the position `url_key` treats as the ref.
pub fn oci_key(registry: &str, repository: &str, digest: &str) -> String {
    url_key(&format!("{registry}/{repository}"), digest)
}

/// A [`FetcherRegistry`] backed by a `mocked-fetches/` fixture tree.
///
/// When `MILPA_MOCKED_FETCHES=<dir>` is set, `milpa-cli` wraps the resolution
/// with this registry instead of [`DefaultRegistry`]. Every fetch is satisfied
/// offline from `<dir>/<url_key(url, ref)>/`:
///
/// 1. Read `<key>/sha` — the commit SHA to return in the receipt when the
///    request is unpinned (no `commit_sha` on the incoming `Provenance::Git`).
/// 2. Copy `<key>/content/` verbatim into `dest` (if the sub-directory exists).
/// 3. Copy `<key>/<name>.nimble` into `dest` if present.
/// 4. Read `<key>/committer_date` (optional, D6 — resolution-semantics RFC
///    §3 Axis D) — an ISO 8601 timestamp returned as `Receipt.committer_date`,
///    so a mocked git fixture can drive `exclude_newer` validation (D4)
///    without a real git repo. Absent -> `None`.
/// 5. D-D2 additive extension: when the request IS pinned (`commit_sha =
///    Some(sha)`, i.e. git-pin reuse per `_git_pin_for_url_dep`), the pin is
///    echoed back verbatim as `resolved_ref` (never `<key>/sha`'s value) —
///    mirroring the real `GitFetcher`. Its committer date prefers an optional
///    `<key>/committer_date@<sha>` override file over the flat
///    `<key>/committer_date`, letting a fixture distinguish "the pinned
///    commit's own date" from "the ref's current tip date". Absent override
///    file -> falls back to the flat file, same as the unpinned case.
/// 6. Return a `Receipt` with `resolved_ref` set per the above.
///
/// If the key directory is missing, returns `FETCH-MOCK-MISSING`. All four
/// `Provenance` kinds are handled: `Git`, `Tarball`, `Local` (delegates to the
/// real `fetch_local`, no mock), and `Oci` (conformance-fixtures.md §2.3.5).
///
/// `milpa-conformance`'s `FakeFetcher` also delegates to [`stage_mock`] for
/// the core logic, then additionally admits the staged tree into the CAS and
/// symlinks `dest` → the store entry.
pub struct MockedFetcher {
    mocked_fetches_dir: std::path::PathBuf,
}

impl MockedFetcher {
    pub fn new(mocked_fetches_dir: impl Into<std::path::PathBuf>) -> Self {
        MockedFetcher {
            mocked_fetches_dir: mocked_fetches_dir.into(),
        }
    }
}

impl FetcherRegistry for MockedFetcher {
    fn fetch(&self, name: &str, p: &Provenance, dest: &Path) -> Result<Receipt, FetchError> {
        // Resolve the mock key dir and the receipt fields per transport. Git keys
        // on (url, ref) and returns a commit SHA; tarball keys on (url, "") and
        // returns the recorded archive sha256 (gating an existing pin first,
        // exactly like the real `fetch_tarball` — conformance-fixtures.md §2.3.4).
        let (key_dir, receipt) = match p {
            Provenance::Git {
                url,
                ref_spec,
                commit_sha,
            } => {
                let (sha, key_dir) = resolve_mock_key(&self.mocked_fetches_dir, url, ref_spec)?;
                // D-D2 (resolution-semantics RFC §3 Axis D / §6 D-D2, additive
                // extension): when the incoming Provenance carries an exact
                // commit_sha pin (git-pin reuse), echo it back verbatim —
                // exactly like the real GitFetcher, which always checks out
                // and reports precisely the pinned SHA it was given, never
                // the ref's current tip. Every pre-existing fixture that
                // exercises pin-reuse writes its flat `sha` file equal to the
                // pin it constructs, so this is a no-op for all of them.
                let resolved_ref = commit_sha.clone().unwrap_or(sha);
                // D6 (resolution-semantics RFC §3 Axis D): an optional
                // `committer_date` file lets a mocked git fixture drive
                // `exclude_newer` validation (D4) without a real git repo.
                // Absent -> None (pre-D6 default, no-op for that check).
                //
                // D-D2 additive extension: when pinned, prefer a per-commit-sha
                // override file `committer_date@<sha>` if the fixture provides
                // one — lets a fixture distinguish "the pinned commit's own
                // committer date" from "the ref's current tip date". Absent ->
                // falls back to the flat `committer_date` file (today's
                // default, unaffected by commit_sha).
                let committer_date_path = commit_sha
                    .as_ref()
                    .map(|sha| key_dir.join(format!("committer_date@{sha}")))
                    .filter(|p| p.is_file())
                    .unwrap_or_else(|| key_dir.join("committer_date"));
                let committer_date = std::fs::read_to_string(committer_date_path)
                    .ok()
                    .and_then(|s| milpa_types::parse_iso8601_timestamp(s.trim()));
                (
                    key_dir,
                    Receipt {
                        resolved_ref: Some(resolved_ref),
                        committer_date,
                        ..Default::default()
                    },
                )
            }
            Provenance::Tarball {
                url,
                expected_sha256,
                strip_components,
            } => {
                let key_dir =
                    resolve_tarball_mock_key_dir(&self.mocked_fetches_dir, url)?;

                // S4a (rfc-conformance-parity.md) — shared real-extractor injection.
                // Both raw-bytes mode and build-mode call ``fetch_tarball`` with an
                // injected closure; this inner macro captures the shared call site so
                // neither branch duplicates the injection pattern.
                macro_rules! run_archive_bytes_through_real_fetcher {
                    ($bytes:expr) => {{
                        let archive_bytes: Vec<u8> = $bytes;
                        let url_str = url.clone();
                        return fetch_tarball(
                            name,
                            &url_str,
                            None, // raw-bytes / build mode: no prior pin (first-fetch)
                            *strip_components,
                            dest,
                            &move |_: &str| Ok(archive_bytes.clone()),
                        );
                    }};
                }

                // Raw-bytes mode: when an ``archive`` file is present, feed its
                // raw bytes through the REAL ``fetch_tarball`` decode path —
                // enabling tests that supply a corrupt or crafted archive and need
                // the real extractor to handle (or reject) it.  Takes PRECEDENCE
                // over ``format`` (build mode) and ``archive_sha256`` (copy mode)
                // — checked FIRST.  The mocked fetcher does NOT pre-validate or
                // swallow — raw bytes go straight to the real extractor, which
                // raises FETCH-EXTRACT-FAILED on corruption.
                let archive_path = key_dir.join("archive");
                if archive_path.is_file() {
                    let bytes = std::fs::read(&archive_path).map_err(|e| {
                        FetchError::Failed(format!(
                            "raw-bytes mode: cannot read {}: {e}",
                            archive_path.display()
                        ))
                    })?;
                    run_archive_bytes_through_real_fetcher!(bytes);
                }

                // Build-mode: when a ``format`` file is present, build a real
                // archive from ``content/`` and run it through the REAL
                // ``fetch_tarball`` decode path (SSOT: production extractor, not a
                // parallel copy).  The encoder-dependent archive sha256 is NOT
                // gated against ``expected_sha256`` here — build-mode fixtures
                // never have a prior pin (they are first-fetch).  The lockfile
                // comparison redacts the pin field via TARBALL_SHA256_PLACEHOLDER
                // to keep expected/ stable across Python (zlib) and Rust
                // (flate2/lzma-rs) encoders.
                let fmt_path = key_dir.join("format");
                if fmt_path.is_file() {
                    let fmt = std::fs::read_to_string(&fmt_path)
                        .map_err(|e| FetchError::Failed(format!("build-mode: read format: {e}")))?;
                    let fmt = fmt.trim().to_string();
                    let archive_bytes = build_archive_bytes(&key_dir, &fmt)?;
                    run_archive_bytes_through_real_fetcher!(archive_bytes);
                }

                // Normal (copy) mode.
                let archive_sha = std::fs::read_to_string(key_dir.join("archive_sha256"))
                    .map_err(|e| FetchError::Failed(format!(
                        "mock fixture: cannot read {}/archive_sha256: {e}",
                        key_dir.display()
                    )))?
                    .trim()
                    .to_lowercase();
                if let Some(expected) = expected_sha256 {
                    let want = expected.strip_prefix("sha256:").unwrap_or(expected).to_lowercase();
                    if want != archive_sha {
                        return Err(FetchError::Transport(
                            "FETCH-SHA256-MISMATCH",
                            format!(
                                "mocked fetch {name:?}: archive sha256 mismatch — \
                                 expected {expected}, got {archive_sha} (URL {url})"
                            ),
                        ));
                    }
                }
                (
                    key_dir,
                    Receipt {
                        archive_sha256: Some(archive_sha),
                        ..Default::default()
                    },
                )
            }
            Provenance::Local { path } => {
                // Local deps are filesystem-native: the fixture ships the target
                // dir on disk (e.g. fixture-205's mylib-fork/), so delegate to the
                // REAL fetch_local (symlink) — mirrors the production dispatch and
                // Python's mocked_registry. There is nothing to mock. (Slice C "205".)
                return fetch_local(name, Path::new(path), dest);
            }
            Provenance::Oci {
                registry,
                repository,
                digest,
                ..
            } => {
                // conformance-fixtures.md §2.3.5: keyed on (registry/repository,
                // digest) — no separate receipt-input file, since the digest is
                // already the immutable pointer the caller supplied. Mirrors
                // fetch_oci's real receipt shape: the lockfile's Oci record is
                // built directly from Provenance::Oci (resolver.rs), never from
                // the receipt, so `Receipt::default()` is correct here too.
                let key_dir = self.mocked_fetches_dir.join(oci_key(registry, repository, digest));
                if !key_dir.is_dir() {
                    return Err(FetchError::Transport(
                        "FETCH-MOCK-MISSING",
                        format!(
                            "mocked fetch: no OCI fixture for {registry}/{repository}@{digest} \
                             (expected dir: {})",
                            key_dir.display()
                        ),
                    ));
                }
                (key_dir, Receipt::default())
            }
        };
        clear_dest(dest).map_err(|e| FetchError::Failed(e))?;
        std::fs::create_dir_all(dest)
            .map_err(|e| FetchError::Failed(format!("MockedFetcher: cannot create dest: {e}")))?;
        stage_mock_content(name, &key_dir, dest)?;
        Ok(receipt)
    }
}

/// Resolve the `(url, ref_spec)` pair to its `mocked-fetches/<key>/` directory
/// and read its `sha` file. Returns `(sha, key_dir)`.
///
/// `FETCH-MOCK-MISSING` if the key directory does not exist.
pub fn resolve_mock_key(
    mocked_fetches_dir: &Path,
    url: &str,
    ref_spec: &str,
) -> Result<(String, std::path::PathBuf), FetchError> {
    let key_dir = mocked_fetches_dir.join(url_key(url, ref_spec));
    if !key_dir.is_dir() {
        return Err(FetchError::Transport(
            "FETCH-MOCK-MISSING",
            format!(
                "mocked fetch: no fixture for {url:?} @ {ref_spec:?} \
                 (expected dir: {})",
                key_dir.display()
            ),
        ));
    }
    let sha = std::fs::read_to_string(key_dir.join("sha"))
        .map_err(|e| {
            FetchError::Failed(format!(
                "mock fixture: cannot read {}/sha: {e}",
                key_dir.display()
            ))
        })?
        .trim()
        .to_string();
    Ok((sha, key_dir))
}

/// Resolve a tarball URL to its `mocked-fetches/<url_key(url, "")>/` directory.
/// Used by the build-mode path in [`MockedFetcher`] where the archive sha256
/// is computed at build time, not read from disk.
///
/// `FETCH-MOCK-MISSING` if the key directory does not exist.
fn resolve_tarball_mock_key_dir(
    mocked_fetches_dir: &Path,
    url: &str,
) -> Result<std::path::PathBuf, FetchError> {
    let key_dir = mocked_fetches_dir.join(url_key(url, ""));
    if !key_dir.is_dir() {
        return Err(FetchError::Transport(
            "FETCH-MOCK-MISSING",
            format!(
                "mocked fetch: no tarball fixture for {url:?} \
                 (expected dir: {})",
                key_dir.display()
            ),
        ));
    }
    Ok(key_dir)
}

/// Build a real tar archive from ``key_dir/content/`` (and sibling ``*.nimble``
/// files) in the given compression format (``gz`` or ``xz``).
///
/// This is **test infra** — the ENCODER lives here.  The DECODER is the
/// production ``fetch_tarball`` path (SSOT per standing rules).
///
/// Returns the raw archive bytes.
fn build_archive_bytes(key_dir: &Path, fmt: &str) -> Result<Vec<u8>, FetchError> {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let content_dir = key_dir.join("content");

    // Helper: collect files to archive = content/* sorted + sibling *.nimble
    let mut entries: Vec<(std::path::PathBuf, String)> = Vec::new();
    if content_dir.is_dir() {
        collect_tree_entries(&content_dir, &content_dir, &mut entries)
            .map_err(|e| FetchError::Failed(format!("build-mode: walk content: {e}")))?;
    }
    // Sibling *.nimble files
    if let Ok(rd) = std::fs::read_dir(key_dir) {
        let mut nimble_entries: Vec<_> = rd
            .flatten()
            .filter(|e| {
                e.path().extension().and_then(|s| s.to_str()) == Some("nimble")
            })
            .collect();
        nimble_entries.sort_by_key(|e| e.file_name());
        for entry in nimble_entries {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            entries.push((path, name));
        }
    }

    match fmt {
        "gz" => {
            let mut compressed = Vec::new();
            {
                let enc = GzEncoder::new(&mut compressed, Compression::default());
                let mut ar = tar::Builder::new(enc);
                for (src, arcname) in &entries {
                    ar.append_path_with_name(src, arcname)
                        .map_err(|e| FetchError::Failed(format!("build-mode gz: append {arcname}: {e}")))?;
                }
                ar.finish()
                    .map_err(|e| FetchError::Failed(format!("build-mode gz: finish: {e}")))?;
            }
            Ok(compressed)
        }
        "xz" => {
            // Build uncompressed tar first, then compress with lzma-rs.
            let mut tar_bytes = Vec::new();
            {
                let mut ar = tar::Builder::new(&mut tar_bytes);
                for (src, arcname) in &entries {
                    ar.append_path_with_name(src, arcname)
                        .map_err(|e| FetchError::Failed(format!("build-mode xz: append {arcname}: {e}")))?;
                }
                ar.finish()
                    .map_err(|e| FetchError::Failed(format!("build-mode xz: finish: {e}")))?;
            }
            let mut compressed = Vec::new();
            lzma_rs::xz_compress(
                &mut std::io::BufReader::new(tar_bytes.as_slice()),
                &mut compressed,
            )
            .map_err(|e| FetchError::Failed(format!("build-mode xz: compress: {e}")))?;
            Ok(compressed)
        }
        other => Err(FetchError::Failed(format!(
            "build-mode: unsupported format {other:?}; expected gz or xz"
        ))),
    }
}

/// Recursively collect (absolute_path, archive_name) pairs from `root`,
/// sorted lexicographically by archive name.
fn collect_tree_entries(
    root: &Path,
    base: &Path,
    out: &mut Vec<(std::path::PathBuf, String)>,
) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(root)?.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let rel = path.strip_prefix(base).unwrap_or(&path);
        let arcname = rel.to_string_lossy().into_owned();
        if path.is_dir() {
            collect_tree_entries(&path, base, out)?;
        } else if path.is_file() {
            out.push((path, arcname));
        }
    }
    Ok(())
}

/// Stage the mocked bytes from `key_dir` into `dest`: copy `content/` verbatim,
/// then copy `<name>.nimble` if present. `dest` must already exist.
///
/// Used by both [`MockedFetcher`] (copy-to-dest path) and `milpa-conformance`'s
/// `FakeFetcher` (stage-then-CAS-admit path) — the single source of truth for
/// the byte-staging step.
pub fn stage_mock_content(name: &str, key_dir: &Path, dest: &Path) -> Result<(), FetchError> {
    let content = key_dir.join("content");
    if content.is_dir() {
        copy_tree(&content, dest)
            .map_err(|e| FetchError::Failed(format!("mock fixture: copy content: {e}")))?;
    }
    let nimble_src = key_dir.join(format!("{name}.nimble"));
    if nimble_src.is_file() {
        std::fs::copy(&nimble_src, dest.join(format!("{name}.nimble")))
            .map_err(|e| FetchError::Failed(format!("mock fixture: copy nimble: {e}")))?;
    }
    Ok(())
}

/// Mocked default-branch (ref) discovery (conformance-fixtures.md §2.3.3,
/// cli-contract.md §8.4). When `MILPA_MOCKED_FETCHES` is set, `add --git`
/// answers `git ls-remote --symref HEAD` from the mock tree with no network:
/// it finds the unique `mocked-fetches/<key>/` entry whose encoded URL matches
/// `url` and returns that entry's ref (the ref component of the §2.3.1 URL-key).
///
/// SSOT: the very same `mocked-fetches/<key>/` entry is then read at fetch time
/// for its `sha` — there is no separate ref→SHA table. Returns the ref string.
///
/// Errors (non-catalog `Failed`) if no entry, or more than one entry, matches
/// `url` — the caller surfaces this as a default-branch-discovery failure
/// (cli-contract §5.6: exit 1), exactly as a network discovery failure would.
pub fn mocked_default_branch(mocked_fetches_dir: &Path, url: &str) -> Result<String, FetchError> {
    // url_key encodes (url, ref) as "<san(url)>@<san(ref)>"; the URL portion is
    // everything before the LAST '@'. Match on the sanitized URL so this stays
    // the single source of truth with url_key (no parallel decode).
    let want_url = url_key(url, "");
    // want_url == "<san(url)>@" — strip the trailing '@' to get the URL prefix.
    let want_prefix = want_url.trim_end_matches('@').to_string();

    let read = std::fs::read_dir(mocked_fetches_dir).map_err(|e| {
        FetchError::Failed(format!(
            "mocked ref-resolution: cannot read {}: {e}",
            mocked_fetches_dir.display()
        ))
    })?;

    let mut matches: Vec<String> = Vec::new();
    for entry in read.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        // Split on the LAST '@': the separator url_key inserts between url+ref.
        if let Some(at) = name.rfind('@') {
            let (enc_url, enc_ref) = (&name[..at], &name[at + 1..]);
            if enc_url == want_prefix {
                matches.push(enc_ref.to_string());
            }
        }
    }

    match matches.len() {
        1 => Ok(matches.pop().unwrap()),
        0 => Err(FetchError::Failed(format!(
            "mocked ref-resolution: no mocked-fetches entry for url {url:?} \
             (looked under {})",
            mocked_fetches_dir.display()
        ))),
        n => Err(FetchError::Failed(format!(
            "mocked ref-resolution: {n} mocked-fetches entries match url {url:?}; \
             pass --ref explicitly to disambiguate"
        ))),
    }
}

/// R1-07: walk a directory tree and sum the sizes of all regular files
/// (not following symlinks). Used by `CasAdmittingFetcher` to enforce the
/// spec §2.4.2 NORMATIVE staged-tree size cap before CAS admission.
pub(crate) fn walk_tree_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else { return 0; };
    let mut total = 0u64;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if meta.file_type().is_symlink() {
            // Symlinks: count their size as 0 — they point elsewhere.
            continue;
        }
        if meta.is_dir() {
            total += walk_tree_size(&path);
        } else if meta.is_file() {
            total += meta.len();
        }
    }
    total
}

/// Lowercase hex sha256 of `bytes` (no `sha256:` prefix).
fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Remove `dest` if present (symlink-safe), leaving the parent intact.
fn clear_dest(dest: &Path) -> Result<(), String> {
    let Ok(meta) = std::fs::symlink_metadata(dest) else {
        return Ok(());
    };
    let ft = meta.file_type();
    let res = if ft.is_symlink() || ft.is_file() {
        std::fs::remove_file(dest)
    } else {
        std::fs::remove_dir_all(dest)
    };
    res.map_err(|e| format!("cannot clear {}: {e}", dest.display()))
}

/// Recursively copy `src`'s contents into `dst`, preserving symlinks.
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            let target = std::fs::read_link(&from)?;
            let _ = std::fs::remove_file(&to);
            std::os::unix::fs::symlink(target, &to)?;
        } else if ft.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "fetchers_tests.rs"]
mod fetchers_tests;
