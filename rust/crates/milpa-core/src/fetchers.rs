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
use sha2::{Digest, Sha256};

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
    pub fn with_curl() -> Self {
        DefaultRegistry::new(|url| {
            let out = Command::new("curl")
                .args(["-fsSL", url])
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

/// Copy a local source tree into `dest` (mirrors `LocalFetcher`).
/// `FETCH-LOCAL-PATH-NOT-FOUND` / `FETCH-LOCAL-PATH-NOT-DIR` on a bad source.
pub fn fetch_local(name: &str, src: &Path, dest: &Path) -> Result<Receipt, FetchError> {
    if !src.exists() {
        return Err(transport(
            "FETCH-LOCAL-PATH-NOT-FOUND",
            format!(
                "fetching {name:?}: local source path does not exist: {}",
                src.display()
            ),
        ));
    }
    if !src.is_dir() {
        return Err(transport(
            "FETCH-LOCAL-PATH-NOT-DIR",
            format!(
                "fetching {name:?}: local source path is not a directory: {}",
                src.display()
            ),
        ));
    }
    clear_dest(dest).map_err(|e| transport("FETCH-LOCAL-PATH-NOT-DIR", e))?;
    copy_tree(src, dest)
        .map_err(|e| transport("FETCH-LOCAL-PATH-NOT-DIR", format!("copying {name:?}: {e}")))?;
    // A local copy carries no resolved ref; its provenance evidence is the
    // declared path, recorded by the resolver.
    Ok(Receipt { resolved_ref: None })
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
    run_git(name, &["clone", "-q", url, &dest.to_string_lossy()])?;

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
            run_git_in(name, dest, &["checkout", "-q", sha])?;
        }
        None => {
            run_git_in(name, dest, &["checkout", "-q", ref_spec])?;
        }
    }

    Ok(Receipt {
        resolved_ref: git_head_sha(dest),
    })
}

fn run_git(name: &str, args: &[&str]) -> Result<(), FetchError> {
    git_status(name, Command::new("git").args(args))
}

fn run_git_in(name: &str, dir: &Path, args: &[&str]) -> Result<(), FetchError> {
    git_status(name, Command::new("git").arg("-C").arg(dir).args(args))
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
fn commit_present(dir: &Path, sha: &str) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["cat-file", "-e", &format!("{sha}^{{commit}}")])
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

/// Download a tarball, verify its sha256 (before extraction), gunzip if needed,
/// and safe-extract into `dest` (mirrors `TarballFetcher`). `FETCH-DOWNLOAD-FAILED`
/// on transport error; `FETCH-SHA256-MISMATCH` if the declared hash differs (the
/// archive is rejected BEFORE any extraction); `FETCH-EXTRACT-FAILED` wrapping any
/// `safe_extract` violation.
pub fn fetch_tarball(
    name: &str,
    url: &str,
    expected_sha256: Option<&str>,
    strip_components: u32,
    dest: &Path,
    http_get: &dyn Fn(&str) -> Result<Vec<u8>, String>,
) -> Result<Receipt, FetchError> {
    let bytes = http_get(url).map_err(|e| {
        transport(
            "FETCH-DOWNLOAD-FAILED",
            format!("fetching {name:?} from {url}: {e}"),
        )
    })?;

    if let Some(expected) = expected_sha256 {
        let actual = sha256_hex(&bytes);
        // Accept a bare hex digest or a `sha256:`-prefixed one.
        let want = expected.strip_prefix("sha256:").unwrap_or(expected);
        if actual != want {
            return Err(transport(
                "FETCH-SHA256-MISMATCH",
                format!(
                    "fetching {name:?}: archive sha256 mismatch — expected {expected}, got {actual} \
                     (URL {url}); rejected before extraction"
                ),
            ));
        }
    }

    // gzip magic (1f 8b) → decompress; else treat the bytes as a raw tar.
    let tar_bytes = if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        let mut out = Vec::new();
        GzDecoder::new(&bytes[..])
            .read_to_end(&mut out)
            .map_err(|e| {
                transport(
                    "FETCH-EXTRACT-FAILED",
                    format!("fetching {name:?}: gunzip: {e}"),
                )
            })?;
        out
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
    Ok(Receipt { resolved_ref: None })
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
            let mut tar = Vec::new();
            GzDecoder::new(&bytes[..])
                .read_to_end(&mut tar)
                .map_err(|e| transport("FETCH-EXTRACT-FAILED", format!("gunzip: {e}")))?;
            clear_dest(dest).map_err(|e| transport("FETCH-EXTRACT-FAILED", e))?;
            extract_tar(&tar, dest, 0, Limits::default())
                .map(|_| Receipt { resolved_ref: None })
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
