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

use std::path::Path;
use std::process::Command;

use milpa_types::Provenance;

use crate::fetch::{FetchError, FetcherRegistry, Receipt};

fn transport(code: &'static str, message: impl Into<String>) -> FetchError {
    FetchError::Transport(code, message.into())
}

/// The reference [`FetcherRegistry`]: dispatch by transport kind.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultRegistry;

impl FetcherRegistry for DefaultRegistry {
    fn fetch(&self, name: &str, p: &Provenance, dest: &Path) -> Result<Receipt, FetchError> {
        match p {
            Provenance::Local { path } => fetch_local(name, Path::new(path), dest),
            Provenance::Git {
                url,
                ref_spec,
                commit_sha,
            } => fetch_git(name, url, ref_spec, commit_sha.as_deref(), dest),
            Provenance::Tarball { .. } => Err(FetchError::Failed(
                "tarball fetcher not yet wired (S14c-next)".into(),
            )),
            Provenance::Oci { .. } => Err(FetchError::Failed(
                "oci fetcher not yet wired (S14c-next)".into(),
            )),
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
