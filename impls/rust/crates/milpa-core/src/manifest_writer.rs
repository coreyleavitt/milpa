//! Manifest mutation (RFC §6 S13; `milpa/manifest_writer.py`).
//!
//! The write side of the manifest-mutating verbs (`add` / `remove` / `update`):
//! read `milpa.kdl`, apply a pure `Manifest → Manifest` transform, and write the
//! canonical re-render ([`milpa_manifest::format_manifest`]). The mutation
//! guards refuse anything that would lose information or isn't a mutable package
//! manifest. Hand-written comments are **not** preserved across a rewrite (the
//! formatter is declarative); [`WriteResult::comments_lost`] lets the CLI warn.

use std::path::{Path, PathBuf};

use milpa_manifest::{format_manifest, format_workspace_manifest, Manifest, ManifestDoc, Workspace};

use crate::error::MilpaError;

fn man(code: &'static str, message: impl Into<String>) -> MilpaError {
    MilpaError::Manifest(milpa_manifest::ManifestError::new(code, message.into()))
}

/// What a mutation did to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResult {
    pub path: PathBuf,
    /// Hand-written `//` comment lines dropped by the declarative re-render.
    pub comments_lost: usize,
}

/// Read `milpa.kdl` at `path`, apply `mutator`, and write the canonical
/// re-render atomically (mirrors `manifest_writer.py:mutate_manifest_file`).
///
/// Refuses: a missing file (`MAN-MUTATE-FILE-NOT-FOUND`), a `.nimble` (its
/// NimScript can't be safely round-tripped — `MAN-MUTATE-NIMBLE-REFUSED`), and a
/// workspace manifest (a pure container — `MAN-MUTATE-WORKSPACE-REFUSED`). A
/// malformed package manifest surfaces its `MAN-*` parse code.
pub fn mutate_manifest_file<F>(path: &Path, mutator: F) -> Result<WriteResult, MilpaError>
where
    F: FnOnce(Manifest) -> Manifest,
{
    if !path.exists() {
        return Err(man(
            "MAN-MUTATE-FILE-NOT-FOUND",
            format!(
                "manifest file not found: {} — create a milpa.kdl first",
                path.display()
            ),
        ));
    }
    if path.extension().is_some_and(|e| e == "nimble") {
        return Err(man(
            "MAN-MUTATE-NIMBLE-REFUSED",
            format!(
                "refusing to mutate a .nimble file ({}); promote to milpa.kdl first",
                path.display()
            ),
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|e| {
        man(
            "MAN-MUTATE-FILE-NOT-FOUND",
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    let manifest = match milpa_manifest::parse_document(&text)? {
        ManifestDoc::Workspace(_) => {
            return Err(man(
                "MAN-MUTATE-WORKSPACE-REFUSED",
                format!(
                    "{}: workspace manifests are pure containers and cannot be mutated",
                    path.display()
                ),
            ));
        }
        ManifestDoc::Package(m) => m,
    };

    let new_manifest = mutator(manifest);
    let rendered = format_manifest(&new_manifest);
    let before = count_comments(&text);
    write_manifest(&new_manifest, path)?;
    let after = count_comments(&rendered);

    Ok(WriteResult {
        path: path.to_path_buf(),
        comments_lost: before.saturating_sub(after),
    })
}

/// Atomically write `manifest`'s canonical `milpa.kdl` render to `path`
/// (temp-file + rename, so a concurrent reader never sees a partial file).
pub fn write_manifest(manifest: &Manifest, path: &Path) -> Result<(), MilpaError> {
    let text = format_manifest(manifest);
    let tmp = path.with_extension("kdl.tmp");
    std::fs::write(&tmp, &text).map_err(|e| io_err(&tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        io_err(path, e)
    })?;
    Ok(())
}

fn io_err(path: &Path, e: std::io::Error) -> MilpaError {
    // Manifest-write I/O failures are uncoded in the spec (like the other
    // MILPA-INTERNAL-IO sentinels); surface via MAN-MUTATE-FILE-NOT-FOUND's
    // domain only when the path is genuinely absent — here it is a write fault.
    MilpaError::Core(crate::error::CoreError::Resolver(
        "MILPA-INTERNAL-IO",
        format!("cannot write manifest {}: {e}", path.display()),
    ))
}

/// Add a mirror URL to an existing URL dep — **pure manifest mutation** (mirrors
/// `cli.py:_cmd_add_mirror` post D-add).
///
/// No fetch, no identity verification, no lockfile write.  The mirror is
/// recorded as an author CLAIM ("declared" mirror) in `milpa.kdl`.  It enters
/// the lockfile as a `declared` provenance on the next `milpa lock`
/// (D-lifecycle slice) and is verified at USE time (D-fallback).
///
/// Rejects if `dep_name` is:
/// - not declared in `milpa.kdl` (`MAN-MIRROR-EDITABLE-PROVENANCE`)
/// - a local/member dep that cannot carry mirrors (`MAN-MIRROR-EDITABLE-PROVENANCE`)
///
/// Idempotent: if `mirror_url` is already in the dep's mirrors, returns `Ok(())`
/// without rewriting the file.
pub fn add_mirror(project_dir: &Path, dep_name: &str, mirror_url: &str) -> Result<(), MilpaError> {
    let manifest_kdl = project_dir.join("milpa.kdl");
    let manifest = match milpa_manifest::parse_document(
        &std::fs::read_to_string(&manifest_kdl).map_err(|e| {
            man(
                "MAN-MUTATE-FILE-NOT-FOUND",
                format!("cannot read {}: {e}", manifest_kdl.display()),
            )
        })?,
    )? {
        ManifestDoc::Package(m) => m,
        ManifestDoc::Workspace(_) => {
            return Err(man(
                "MAN-MUTATE-WORKSPACE-REFUSED",
                "add --mirror is not valid on a workspace manifest".to_string(),
            ));
        }
    };

    // Validate: dep must be a UrlDep declared in milpa.kdl.
    match manifest.deps.iter().find(|d| d.name() == dep_name) {
        None => {
            return Err(man(
                "MAN-MIRROR-EDITABLE-PROVENANCE",
                format!("add --mirror: dep {dep_name:?} not declared in milpa.kdl"),
            ));
        }
        Some(milpa_manifest::Dep::Url(u)) if u.mirrors.contains(&mirror_url.to_string()) => {
            // Idempotent — already a mirror, nothing to write.
            return Ok(());
        }
        Some(milpa_manifest::Dep::Url(_)) => {}
        _ => {
            // Local, Member, Named, Tarball — cannot carry mirrors.
            return Err(man(
                "MAN-MIRROR-EDITABLE-PROVENANCE",
                format!(
                    "add --mirror: {dep_name:?} is not a git URL dep — \
                     only URL deps (git=...) can carry mirrors"
                ),
            ));
        }
    }

    // Append mirror to the dep in milpa.kdl — no fetch, no lockfile write.
    let url = mirror_url.to_string();
    mutate_manifest_file(&manifest_kdl, move |mut m| {
        for d in &mut m.deps {
            if let milpa_manifest::Dep::Url(u) = d {
                if u.name == dep_name && !u.mirrors.contains(&url) {
                    u.mirrors.push(url.clone());
                }
            }
        }
        m
    })?;
    Ok(())
}

/// Read a **workspace** `milpa.kdl` at `path`, apply `mutator`, and write the
/// canonical re-render atomically (typed analog of [`mutate_manifest_file`] for
/// the workspace role — mirrors `manifest_writer.py:mutate_workspace_manifest_file`).
///
/// Refuses: a missing file (`MAN-MUTATE-FILE-NOT-FOUND`), a `.nimble`
/// (`MAN-MUTATE-NIMBLE-REFUSED`), and a *package* manifest
/// (`MAN-MUTATE-WORKSPACE-REFUSED`). A malformed workspace manifest surfaces
/// its `MAN-*` parse code.
pub fn mutate_workspace_manifest_file<F>(path: &Path, mutator: F) -> Result<WriteResult, MilpaError>
where
    F: FnOnce(Workspace) -> Workspace,
{
    if !path.exists() {
        return Err(man(
            "MAN-MUTATE-FILE-NOT-FOUND",
            format!(
                "manifest file not found: {} — create a milpa.kdl first",
                path.display()
            ),
        ));
    }
    if path.extension().is_some_and(|e| e == "nimble") {
        return Err(man(
            "MAN-MUTATE-NIMBLE-REFUSED",
            format!(
                "refusing to mutate a .nimble file ({}); promote to milpa.kdl first",
                path.display()
            ),
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|e| {
        man(
            "MAN-MUTATE-FILE-NOT-FOUND",
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    let ws = match milpa_manifest::parse_document(&text)? {
        ManifestDoc::Package(_) => {
            return Err(man(
                "MAN-MUTATE-WORKSPACE-REFUSED",
                format!(
                    "{}: not a workspace manifest — use mutate_manifest_file for package manifests",
                    path.display()
                ),
            ));
        }
        ManifestDoc::Workspace(w) => w,
    };

    let new_ws = mutator(ws);
    let rendered = format_workspace_manifest(&new_ws);
    let before = count_comments(&text);
    let tmp = path.with_extension("kdl.tmp");
    std::fs::write(&tmp, &rendered).map_err(|e| io_err(&tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        io_err(path, e)
    })?;
    let after = count_comments(&rendered);

    Ok(WriteResult {
        path: path.to_path_buf(),
        comments_lost: before.saturating_sub(after),
    })
}

/// Count `//`-comment lines (trimmed-leading), the comment-loss heuristic.
fn count_comments(text: &str) -> usize {
    text.lines()
        .filter(|l| l.trim_start().starts_with("//"))
        .count()
}

#[cfg(test)]
#[path = "manifest_writer_tests.rs"]
mod manifest_writer_tests;
