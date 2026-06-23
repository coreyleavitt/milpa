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
use std::path::Path;
use std::process::Command;

use flate2::read::GzDecoder;
use milpa_types::Provenance;

/// Magic-byte signatures for compressed archive formats
/// (spec/manifest-grammar.md §TarballDep).
const MAGIC_GZIP: &[u8] = &[0x1f, 0x8b];
const MAGIC_BZ2: &[u8] = &[0x42, 0x5a, 0x68]; // "BZh"
const MAGIC_XZ: &[u8] = &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
use sha2::{Digest, Sha256};

/// Overhead added to `Limits::max_total_size` to compute the decompression-bomb
/// cap — one tar header block (512 B) to leave room for tar framing around file
/// data (SA-1). This is the single definition; both `fetch_tarball` and
/// `fetch_oci` derive their cap from it via `decompress_capped`.
const DECOMP_CAP_OVERHEAD: u64 = 512;

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
    let mut out = Vec::new();
    let n = decoder
        .take(decomp_cap)
        .read_to_end(&mut out)
        .map_err(|e| {
            FetchError::Transport(
                "FETCH-EXTRACT-FAILED",
                format!("fetching {name:?}: {format} decompress: {e}"),
            )
        })?;
    if n as u64 >= decomp_cap {
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

/// Write-based sibling of `decompress_capped` for the xz/lzma path.
///
/// lzma-rs's `xz_decompress` requires a `Sized + BufRead` source and returns
/// `lzma_rs::error::Error` (not `std::io::Error`), so a generic closure
/// approach would not unify the signatures cleanly.  Instead this function
/// hard-wires the lzma-rs call while sharing the SAME cap constant
/// (`decomp_cap`), the SAME `EXTRACT-SIZE-LIMIT` slug, and the SAME error
/// message template as `decompress_capped` via `size_limit_error` — eliminating
/// the three parallel inline copies that R19 flagged.
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

use crate::fetch::{FetchError, FetcherRegistry, Receipt};
use crate::safe_extract::{extract_tar, Limits};

fn transport(code: &'static str, message: impl Into<String>) -> FetchError {
    FetchError::Transport(code, message.into())
}

/// A byte-fetching transport (an injected seam, like the index cache's): maps a
/// URL to its bytes, or an error string. `DefaultRegistry::with_curl` uses the
/// `curl` CLI; tests inject a closure.
pub type HttpGet = Box<dyn Fn(&str) -> Result<Vec<u8>, String>>;

/// The reference [`FetcherRegistry`]: dispatch the closed `Provenance` enum to a
/// per-transport fetch. Carries an [`HttpGet`] for the tarball transport.
pub struct DefaultRegistry {
    http_get: HttpGet,
}

impl DefaultRegistry {
    /// A registry whose tarball downloads use a custom byte transport.
    pub fn new(http_get: impl Fn(&str) -> Result<Vec<u8>, String> + 'static) -> Self {
        DefaultRegistry {
            http_get: Box::new(http_get),
        }
    }

    /// The production registry: tarball downloads shell out to `curl -fsSL`.
    ///
    /// R4: `--max-filesize` is passed to curl so the server cannot force a
    /// download larger than `MAX_COMPRESSED_BYTES` before the compressed-body
    /// cap check in `fetch_tarball_with_cap` fires.
    pub fn with_curl() -> Self {
        DefaultRegistry::new(|url| {
            let out = Command::new("curl")
                .args(["-fsSL", &format!("--max-filesize={MAX_COMPRESSED_BYTES}"), url])
                .output()
                .map_err(|e| format!("cannot run curl: {e}"))?;
            if out.status.success() {
                Ok(out.stdout)
            } else {
                Err(format!(
                    "curl failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ))
            }
        })
    }
}

impl FetcherRegistry for DefaultRegistry {
    fn fetch(&self, name: &str, p: &Provenance, dest: &Path) -> Result<Receipt, FetchError> {
        match p {
            Provenance::Local { path } => fetch_local(name, Path::new(path), dest),
            Provenance::Git {
                url,
                ref_spec,
                commit_sha,
            } => fetch_git(name, url, ref_spec, commit_sha.as_deref(), dest),
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
            ),
            Provenance::Oci {
                registry,
                repository,
                digest,
            } => fetch_oci(name, registry, repository, digest, dest),
        }
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
    Ok(Receipt {
        resolved_ref: None,
        archive_sha256: None,
    })
}

/// Clone `url` into `dest` and check out the pinned commit (or `ref_spec`).
/// `FETCH-GIT-FAILED` on a clone/checkout failure; `FETCH-GIT-COMMIT-ABSENT` if
/// the pinned commit isn't present after cloning. Mirrors `GitFetcher`.
pub fn fetch_git(
    name: &str,
    url: &str,
    ref_spec: &str,
    commit_sha: Option<&str>,
    dest: &Path,
) -> Result<Receipt, FetchError> {
    clear_dest(dest).map_err(|e| transport("FETCH-GIT-FAILED", e))?;
    // R5: --end-of-options before the URL so a URL starting with '-' cannot
    // be misinterpreted as an option flag (git clone >= 2.24).
    run_git(name, &["clone", "-q", "--end-of-options", url, &dest.to_string_lossy()])?;

    match commit_sha {
        Some(sha) => {
            // Exact-commit pin (Invariant 2): verify the commit is present
            // before checkout, so an absent pin is a clear coded error.
            if !commit_present(dest, sha) {
                let _ = std::fs::remove_dir_all(dest);
                return Err(transport(
                    "FETCH-GIT-COMMIT-ABSENT",
                    format!("fetching {name:?}: pinned commit {sha} not present in {url}"),
                ));
            }
            // R5: --end-of-options before commit SHA so a SHA starting with '-'
            // is not parsed as an option flag (git checkout >= 2.24).
            run_git_in(name, dest, &["checkout", "-q", "--end-of-options", sha])?;
        }
        None => {
            // R5: --end-of-options before ref so a ref like '-evil' or '--detach'
            // is treated as a ref name, not a flag (git checkout >= 2.24).
            run_git_in(name, dest, &["checkout", "-q", "--end-of-options", ref_spec])?;
        }
    }

    Ok(Receipt {
        resolved_ref: git_head_sha(dest),
        archive_sha256: None,
    })
}

/// Transport flags injected into every git invocation that materializes or
/// checks out content (spec/identity.md §1.7 NORMATIVE MUST): prevents the host
/// git config from perturbing the materialized bytes or the resulting identity
/// hash regardless of OS/user settings.
pub(crate) const GIT_TRANSPORT_FLAGS: &[&str] = &[
    "-c", "core.autocrlf=false",
    "-c", "core.filemode=false",
];

fn run_git(name: &str, args: &[&str]) -> Result<(), FetchError> {
    git_status(name, Command::new("git").args(GIT_TRANSPORT_FLAGS).args(args))
}

fn run_git_in(name: &str, dir: &Path, args: &[&str]) -> Result<(), FetchError> {
    git_status(
        name,
        Command::new("git")
            .args(GIT_TRANSPORT_FLAGS)
            .arg("-C")
            .arg(dir)
            .args(args),
    )
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

fn git_head_sha(dir: &Path) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
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
        let remaining = self.limit.saturating_sub(self.written);
        if remaining == 0 {
            self.hit = true;
            // Return a write error to abort lzma_rs mid-stream.
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "decompression cap exceeded",
            ));
        }
        let n = (buf.len() as u64).min(remaining) as usize;
        self.inner.extend_from_slice(&buf[..n]);
        self.written += n as u64;
        if n < buf.len() {
            self.hit = true;
        }
        Ok(n)
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
    http_get: &dyn Fn(&str) -> Result<Vec<u8>, String>,
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
    http_get: &dyn Fn(&str) -> Result<Vec<u8>, String>,
    compressed_cap: u64,
) -> Result<Receipt, FetchError> {
    let bytes = http_get(url).map_err(|e| {
        transport(
            "FETCH-DOWNLOAD-FAILED",
            format!("fetching {name:?} from {url}: {e}"),
        )
    })?;

    // R4: cap the compressed body before decompression.  The production http_get
    // (curl) already enforces this via --max-filesize; the cap here catches
    // injected transports (tests, mocked fetchers that return bytes directly)
    // and serves as a safety net if the transport doesn't self-limit.
    if bytes.len() as u64 > compressed_cap {
        return Err(transport(
            "FETCH-DOWNLOAD-FAILED",
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
    let decomp_cap: u64 = Limits::default().max_total_size + DECOMP_CAP_OVERHEAD;

    let tar_bytes = if bytes.starts_with(MAGIC_GZIP) {
        decompress_capped(GzDecoder::new(&bytes[..]), decomp_cap, name, "gzip")?
    } else if bytes.starts_with(MAGIC_BZ2) {
        decompress_capped(
            bzip2_rs::DecoderReader::new(&bytes[..]),
            decomp_cap,
            name,
            "bzip2",
        )?
    } else if bytes.starts_with(MAGIC_XZ) {
        // lzma-rs uses a Write-based API (xz_decompress) rather than a Read-based
        // decoder; route through decompress_capped_xz so cap constant, slug, and
        // error message are the same SSOT as gzip/bzip2 — eliminating the parallel
        // inline copy that R19 flagged.
        decompress_capped_xz(&bytes[..], decomp_cap, name)?
    } else {
        bytes
    };

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
        resolved_ref: None,
        archive_sha256: Some(actual_sha),
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
            let oci_decomp_cap: u64 = Limits::default().max_total_size + DECOMP_CAP_OVERHEAD;
            let tar = decompress_capped(GzDecoder::new(&bytes[..]), oci_decomp_cap, name, "gunzip")
                .map_err(|e| {
                    let _ = std::fs::remove_dir_all(&scratch);
                    e
                })?;
            clear_dest(dest).map_err(|e| transport("FETCH-EXTRACT-FAILED", e))?;
            extract_tar(&tar, dest, 0, Limits::default())
                .map(|_| Receipt {
                    resolved_ref: None,
                    archive_sha256: None,
                })
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

            // Compute the identity and admit to the CAS.
            use crate::identity::compute_content_hash;
            let identity = compute_content_hash(&scratch.path).map_err(|e| {
                let _ = std::fs::remove_dir_all(&scratch.path);
                FetchError::Failed(format!("CasAdmittingFetcher: hash scratch tree: {}", e.message()))
            })?;
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

/// A [`FetcherRegistry`] backed by a `mocked-fetches/` fixture tree.
///
/// When `MILPA_MOCKED_FETCHES=<dir>` is set, `milpa-cli` wraps the resolution
/// with this registry instead of [`DefaultRegistry`]. Every fetch is satisfied
/// offline from `<dir>/<url_key(url, ref)>/`:
///
/// 1. Read `<key>/sha` — the commit SHA to return in the receipt.
/// 2. Copy `<key>/content/` verbatim into `dest` (if the sub-directory exists).
/// 3. Copy `<key>/<name>.nimble` into `dest` if present.
/// 4. Return a `Receipt` with `resolved_ref = Some(sha)`.
///
/// If the key directory is missing, returns `FETCH-MOCK-MISSING`.
/// Only `Provenance::Git` is supported; any other provenance yields a clear
/// (non-catalog) error.
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
            Provenance::Git { url, ref_spec, .. } => {
                let (sha, key_dir) = resolve_mock_key(&self.mocked_fetches_dir, url, ref_spec)?;
                (
                    key_dir,
                    Receipt {
                        resolved_ref: Some(sha),
                        archive_sha256: None,
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
                        resolved_ref: None,
                        archive_sha256: Some(archive_sha),
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
            other => {
                return Err(FetchError::Failed(format!(
                    "MockedFetcher: unsupported provenance kind: {other:?}; \
                     only Git, Tarball, and Local provenance are handled"
                )));
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
