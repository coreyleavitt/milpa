//! Manifest mutation (RFC §6 S13; `milpa/manifest_writer.py`).
//! S9b (workspace-completion §3.F): `apply_workspace_manifest_change`.
//!
//! The write side of the manifest-mutating verbs (`add` / `remove` / `update`):
//! read `milpa.kdl`, apply a pure `Manifest → Manifest` transform, and write the
//! canonical re-render ([`milpa_manifest::format_manifest`]). The mutation
//! guards refuse anything that would lose information or isn't a mutable package
//! manifest. Hand-written comments are **not** preserved across a rewrite (the
//! formatter is declarative); [`WriteResult::comments_lost`] lets the CLI warn.
//!
//! [`apply_workspace_manifest_change`] is the workspace orchestration analog of
//! the single-package add/remove inlined in `cmd_add`/`cmd_remove` in `main.rs`.
//! Atomicity ordering (§3.F): *validate → resolve-in-memory → write-manifest →
//! write-lock.* Resolution happens before any on-disk write, so a network or
//! resolution failure leaves the manifest untouched.

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

// ---------------------------------------------------------------------------
// S9b — apply_workspace_manifest_change: workspace orchestration primitive
// ---------------------------------------------------------------------------

/// Workspace orchestration analog of the single-package add/remove ordering.
///
/// Atomicity ordering (RFC: workspace-completion §3.F):
/// *validate → workspace-resolve with the proposed manifest in memory →
/// write manifest → write lock.*
///
/// Resolution happens **before** any on-disk mutation, so a network or
/// resolution failure leaves the manifest (and lock) untouched.  The only
/// residual window is an fs-write failure between the manifest write and the
/// lock write — identical to what single-package add/remove already accept;
/// it is not eliminated, only minimized.
///
/// **Signature symmetry (Design-F4):** the same shape as the inlined
/// single-package add/remove orchestration (no separate `validate` callable
/// on either path; validation is implicit in "the mutated doc resolves").
///
/// Returns `(ResolvedGraph, WriteResult)` on success; raises [`MilpaError`]
/// on any failure, leaving ALL on-disk files unmodified.
#[allow(clippy::too_many_arguments)]
pub fn apply_workspace_manifest_change<F>(
    root: &Path,
    index: Option<&crate::registry::Index>,
    fetcher: &dyn crate::fetch::FetcherRegistry,
    profile: Option<&milpa_manifest::Profile>,
    prior: Option<&milpa_types::Lockfile>,
    strategy: milpa_solver::Strategy,
    store: &crate::store::CaStore,
    require_attested_metadata: bool,
    mutate: F,
) -> Result<(milpa_types::ResolvedGraph, WriteResult), MilpaError>
where
    F: FnOnce(Workspace) -> Workspace,
{
    // Step 1: Read the workspace manifest text (for comment-loss counting and
    // for handing the Workspace value to the mutator).
    let manifest_path = root.join("milpa.kdl");
    let original_text = std::fs::read_to_string(&manifest_path).map_err(|_| {
        man(
            "WS-NO-MANIFEST",
            format!("no milpa.kdl at workspace root {}", root.display()),
        )
    })?;

    // Step 2: Parse the workspace manifest, handing the Workspace value to the
    // mutator.  Package manifests are refused before the mutator is called.
    let current_parsed_ws = match milpa_manifest::parse_document(&original_text)? {
        ManifestDoc::Workspace(w) => w,
        ManifestDoc::Package(_) => {
            return Err(man(
                "WS-NOT-A-WORKSPACE",
                format!("{}: not a workspace manifest", manifest_path.display()),
            ));
        }
    };

    // Step 3: Apply the mutation (pure transform on the Workspace value).
    let proposed_ws_manifest = mutate(current_parsed_ws);

    // Step 4: Build the proposed LoadedWorkspace by reading member manifests
    // from disk for the proposed member list.  This validates member dirs exist
    // and have milpa.kdl before resolution — raises WS-MEMBER-* on topology
    // errors, leaving disk untouched.
    let proposed_ws =
        crate::workspace::load_workspace_from_manifest(root, &proposed_ws_manifest)?;

    // Step 5: Resolve the proposed workspace IN MEMORY.  Any resolution or
    // network failure raises here — manifest and lock are still unmodified.
    let deps_dir = root.join("_deps");
    let graph = crate::resolver::resolve_workspace(
        &proposed_ws,
        index,
        fetcher,
        profile,
        prior,
        strategy,
        &deps_dir,
        require_attested_metadata,
        store,
    )?;

    // Step 6: Resolution succeeded — commit both outputs atomically.
    // Write manifest first, then lock.
    let rendered = format_workspace_manifest(&proposed_ws_manifest);
    let before = count_comments(&original_text);
    let tmp = manifest_path.with_extension("kdl.tmp");
    std::fs::write(&tmp, &rendered).map_err(|e| io_err(&tmp, e))?;
    std::fs::rename(&tmp, &manifest_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        io_err(&manifest_path, e)
    })?;
    let after = count_comments(&rendered);

    let lock_path = root.join("milpa.lock");
    crate::lockfile::write_lockfile(
        &crate::lockfile::from_graph(&graph, strategy.as_str()),
        &lock_path,
    )?;

    let wr = WriteResult {
        path: manifest_path,
        comments_lost: before.saturating_sub(after),
    };
    Ok((graph, wr))
}

#[cfg(test)]
#[path = "manifest_writer_tests.rs"]
mod manifest_writer_tests;
