//! Workspace member loading + structural validation (RFC §6 S11; `milpa/workspace.py`).
//!
//! [`load_workspace`] reads a workspace `milpa.kdl` and each declared member's
//! package manifest, returning a fully-validated [`LoadedWorkspace`]. Topology
//! problems are coded `WS-*` disqualifications. This is the structural layer;
//! the multi-member union *resolve* (and per-member nim.cfg) is S11b.
//!
//! Discovery (`find_workspace_root` / `workspace_containing`) is a CLI concern
//! (S13) — the conformance harness always knows the workspace root (the fixture
//! dir), so only loading + validation lives here.

use std::path::{Path, PathBuf};

use milpa_manifest::{Manifest, Override};

use crate::error::{CoreError, MilpaError};

fn ws(code: &'static str, message: impl Into<String>) -> MilpaError {
    MilpaError::Core(CoreError::Workspace(code, message.into()))
}

/// Lexically normalize a path by resolving `..` and `.` components without
/// touching the filesystem (unlike `canonicalize`, which requires paths to exist).
/// Used as the fallback for non-existent paths in the `WS-MEMBER-PATH-ESCAPE`
/// containment check.
fn normalize_lexically(path: &std::path::Path) -> std::path::PathBuf {
    use std::path::Component;
    let mut normalized = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                // Pop only if the last component is a normal segment (not root/prefix).
                match normalized.components().next_back() {
                    Some(Component::Normal(_)) => { normalized.pop(); }
                    _ => { normalized.push(".."); }
                }
            }
            Component::CurDir => {} // skip "."
            other => normalized.push(other),
        }
    }
    normalized
}

/// Return true if `candidate` is at or within `root` — inclusive (equal-to-root
/// returns true, letting the caller fall through to the `WS-MEMBER-IS-WORKSPACE`
/// check).
///
/// Algorithm (Option A — matches Python `workspace.py` `resolve(strict=False)`):
///   1. Canonicalize `root` (root always exists at load time).
///   2. Resolve `candidate` to a real path via one of three strategies:
///      a. `candidate.exists()` (follows symlinks) → true: the target is reachable,
///         use `canonicalize()` which follows all symlinks to the true location.
///      b. `candidate` is a **dangling symlink** (lstat succeeds; stat fails):
///         read the link target, canonicalize the parent dir (lexical fallback if
///         the parent also doesn't exist), join the target, normalize lexically.
///         This mirrors Python's `resolve(strict=False)` which follows symlinks for
///         existing portions and normalises `..` lexically for the rest — a dangling
///         `link -> ../../outside-nonexistent` still resolves to a path outside the
///         root and must yield WS-MEMBER-PATH-ESCAPE, not WS-MEMBER-DIR-MISSING.
///      c. Neither (ordinary non-existent path): `normalize_lexically` so that
///         `../../escape` is still caught and a non-existent normal path inside the
///         workspace is NOT a false escape (it proceeds to `WS-MEMBER-DIR-MISSING`).
///   3. Return `real_cand.starts_with(real_root)` — inclusive.
fn is_under_root(root: &std::path::Path, candidate: &std::path::PathBuf) -> bool {
    // Step 1: canonicalize root (always exists).
    let real_root = match root.canonicalize() {
        Ok(r) => r,
        // If root itself can't be canonicalized (extremely unusual in practice),
        // fall back to lexical comparison against the original root path.
        Err(_) => normalize_lexically(root),
    };

    // Step 2: resolve candidate.
    let real_cand = if candidate.exists() {
        // (a) Existing target (follows symlinks through the whole chain).
        match candidate.canonicalize() {
            Ok(c) => c,
            Err(_) => normalize_lexically(candidate),
        }
    } else {
        // `candidate.exists()` uses stat (follows symlinks).  If it returned
        // false, the path either doesn't exist at all OR is a dangling symlink
        // (lstat would succeed; stat fails because the target is absent).
        // Dangling symlink: read the link, resolve its target relative to the
        // canonicalized parent, normalise lexically.  This mirrors Python's
        // `resolve(strict=False)` so that a dangling `link -> ../../outside`
        // resolves outside the root and is correctly rejected.
        let dangling_resolved = candidate
            .symlink_metadata()  // lstat — succeeds even when target is missing
            .ok()
            .filter(|m| m.file_type().is_symlink())
            .and_then(|_| std::fs::read_link(candidate).ok())
            .map(|link_target| {
                // The link target may be relative — it must be resolved relative
                // to the symlink's own parent directory.
                let parent = candidate.parent().unwrap_or(candidate.as_path());
                let real_parent = match parent.canonicalize() {
                    Ok(p) => p,
                    Err(_) => normalize_lexically(parent),
                };
                normalize_lexically(&real_parent.join(&link_target))
            });

        match dangling_resolved {
            Some(r) => r,
            // (c) Ordinary non-existent path: lexical normalization only.
            None => normalize_lexically(candidate),
        }
    };

    // Step 3: inclusive starts_with (equal-to-root → true → NOT an escape;
    // falls through to the WS-MEMBER-IS-WORKSPACE manifest-parse check).
    real_cand.starts_with(&real_root)
}

/// A workspace member as it exists on disk: its intrinsic `name` (from the
/// member's manifest), the as-declared workspace-relative `path` (preserved for
/// lockfile portability), the absolute `directory`, and the loaded `manifest`.
#[derive(Debug, Clone)]
pub struct LoadedMember {
    pub name: String,
    pub path: String,
    pub directory: PathBuf,
    pub manifest: Manifest,
}

/// A loaded, structurally-validated workspace.
#[derive(Debug, Clone)]
pub struct LoadedWorkspace {
    pub root: PathBuf,
    pub members: Vec<LoadedMember>,
    pub overrides: Vec<Override>,
    /// S11 (RFC #23 §3.8): workspace-root flags {}. Default-true flags
    /// activate workspace-wide via their enables_cross_pkg targets.
    pub flags: Vec<milpa_manifest::FlagDecl>,
}

/// Load and structurally validate the workspace at `root`.
///
/// Reads `<root>/milpa.kdl` as a workspace manifest, then each declared member's
/// package manifest from `<root>/<member-path>/milpa.kdl`, in declaration order.
/// Mirrors `workspace.py:load_workspace`. Member-manifest *grammar* errors
/// propagate as the underlying `MAN-*`; topology errors are `WS-*`.
pub fn load_workspace(root: &Path) -> Result<LoadedWorkspace, MilpaError> {
    let workspace_kdl = root.join("milpa.kdl");
    let text = std::fs::read_to_string(&workspace_kdl).map_err(|_| {
        ws(
            "WS-NO-MANIFEST",
            format!("no milpa.kdl at workspace root {}", root.display()),
        )
    })?;

    let parsed = match milpa_manifest::parse_document(&text)? {
        milpa_manifest::ManifestDoc::Workspace(w) => w,
        milpa_manifest::ManifestDoc::Package(_) => {
            return Err(ws(
                "WS-NOT-A-WORKSPACE",
                format!(
                    "{} is a package manifest, not a workspace",
                    workspace_kdl.display()
                ),
            ));
        }
    };

    let mut members: Vec<LoadedMember> = Vec::new();
    let mut seen_names: Vec<String> = Vec::new();
    for member_path in &parsed.members {
        // §WS-MEMBER-DOT: reject "." and "./" before the containment check.
        if member_path == "." || member_path == "./" {
            return Err(ws(
                "WS-MEMBER-DOT",
                "member \".\" is not supported — the workspace root is a pure container and \
                 cannot also be a package; place it in a subdirectory and list that instead",
            ));
        }
        let member_dir = root.join(member_path);
        // §WS-MEMBER-PATH-ESCAPE: canonicalize-based containment check before
        // dir-existence.  is_under_root uses canonicalize (follows symlinks for
        // existing paths, lexical fallback for non-existent paths) and returns
        // true when candidate == root (inclusive), letting root-resolving paths
        // fall through to the WS-MEMBER-IS-WORKSPACE manifest-parse check.
        if !is_under_root(root, &member_dir) {
            return Err(ws(
                "WS-MEMBER-PATH-ESCAPE",
                format!(
                    "workspace member {member_path:?} resolves outside the workspace root",
                ),
            ));
        }
        // Use a lexically-normalized path for filesystem operations (is_dir,
        // milpa.kdl discovery).  This handles "pkg/.." style paths where "pkg"
        // may not exist on disk — the raw join fails is_dir() because the OS
        // can't traverse a non-existent intermediate component.
        //
        // The stored `directory` in LoadedMember keeps the original raw join so
        // nim.cfg generation is not affected.
        let effective_dir = normalize_lexically(&member_dir);
        if !effective_dir.is_dir() {
            return Err(ws(
                "WS-MEMBER-DIR-MISSING",
                format!(
                    "workspace member {member_path:?} has no directory at {}",
                    effective_dir.display()
                ),
            ));
        }
        let member_kdl = effective_dir.join("milpa.kdl");
        if !member_kdl.is_file() {
            return Err(ws(
                "WS-MEMBER-NO-MANIFEST",
                format!(
                    "workspace member {member_path:?} has no milpa.kdl at {}",
                    member_kdl.display()
                ),
            ));
        }
        let member_text = std::fs::read_to_string(&member_kdl).map_err(|e| {
            ws(
                "WS-MEMBER-NO-MANIFEST",
                format!("workspace member {member_path:?} milpa.kdl unreadable: {e}"),
            )
        })?;
        let manifest = match milpa_manifest::parse_document(&member_text)? {
            milpa_manifest::ManifestDoc::Workspace(_) => {
                return Err(ws(
                    "WS-MEMBER-IS-WORKSPACE",
                    format!("workspace member {member_path:?} is itself a workspace — nested workspaces are not supported"),
                ));
            }
            milpa_manifest::ManifestDoc::Package(m) => m,
        };
        if !manifest.overrides.is_empty() {
            return Err(ws(
                "WS-MEMBER-HAS-OVERRIDES",
                format!(
                    "workspace member {:?} declares its own `overrides` block — \
                     overrides may only appear at the workspace root",
                    manifest.name.as_deref().unwrap_or(member_path)
                ),
            ));
        }
        let name = manifest.name.clone().unwrap_or_default();
        if seen_names.contains(&name) {
            return Err(ws(
                "WS-MEMBER-DUPLICATE-NAME",
                format!("workspace has two members claiming name {name:?}"),
            ));
        }
        seen_names.push(name.clone());
        members.push(LoadedMember {
            name,
            path: member_path.clone(),
            directory: member_dir,
            manifest,
        });
    }

    Ok(LoadedWorkspace {
        root: root.to_path_buf(),
        members,
        overrides: parsed.overrides,
        flags: parsed.flags,  // S11: workspace-root flags
    })
}

/// Build a [`LoadedWorkspace`] from an already-parsed [`milpa_manifest::Workspace`]
/// without reading the workspace manifest from disk.  Member manifests are still
/// loaded from disk.
///
/// Mirrors `workspace.py:load_workspace_from_manifest` — used by
/// [`crate::manifest_writer::apply_workspace_manifest_change`] to construct a
/// proposed `LoadedWorkspace` from a mutated manifest *before* any on-disk write,
/// so that resolution can fail cleanly without touching the manifest file.
pub fn load_workspace_from_manifest(
    root: &Path,
    parsed: &milpa_manifest::Workspace,
) -> Result<LoadedWorkspace, MilpaError> {
    let mut members: Vec<LoadedMember> = Vec::new();
    let mut seen_names: Vec<String> = Vec::new();
    for member_path in &parsed.members {
        // §WS-MEMBER-DOT: reject "." and "./" before the containment check.
        if member_path == "." || member_path == "./" {
            return Err(ws(
                "WS-MEMBER-DOT",
                "member \".\" is not supported — the workspace root is a pure container and \
                 cannot also be a package; place it in a subdirectory and list that instead",
            ));
        }
        let member_dir = root.join(member_path);
        // §WS-MEMBER-PATH-ESCAPE: canonicalize-based containment check before dir-existence.
        if !is_under_root(root, &member_dir) {
            return Err(ws(
                "WS-MEMBER-PATH-ESCAPE",
                format!(
                    "workspace member {member_path:?} resolves outside the workspace root",
                ),
            ));
        }
        // Lexically normalize for filesystem operations only (see load_workspace above).
        let effective_dir = normalize_lexically(&member_dir);
        if !effective_dir.is_dir() {
            return Err(ws(
                "WS-MEMBER-DIR-MISSING",
                format!(
                    "workspace member {member_path:?} has no directory at {}",
                    effective_dir.display()
                ),
            ));
        }
        let member_kdl = effective_dir.join("milpa.kdl");
        if !member_kdl.is_file() {
            return Err(ws(
                "WS-MEMBER-NO-MANIFEST",
                format!(
                    "workspace member {member_path:?} has no milpa.kdl at {}",
                    member_kdl.display()
                ),
            ));
        }
        let member_text = std::fs::read_to_string(&member_kdl).map_err(|e| {
            ws(
                "WS-MEMBER-NO-MANIFEST",
                format!("workspace member {member_path:?} milpa.kdl unreadable: {e}"),
            )
        })?;
        let manifest = match milpa_manifest::parse_document(&member_text)? {
            milpa_manifest::ManifestDoc::Workspace(_) => {
                return Err(ws(
                    "WS-MEMBER-IS-WORKSPACE",
                    format!("workspace member {member_path:?} is itself a workspace — nested workspaces are not supported"),
                ));
            }
            milpa_manifest::ManifestDoc::Package(m) => m,
        };
        if !manifest.overrides.is_empty() {
            return Err(ws(
                "WS-MEMBER-HAS-OVERRIDES",
                format!(
                    "workspace member {:?} declares its own `overrides` block — \
                     overrides may only appear at the workspace root",
                    manifest.name.as_deref().unwrap_or(member_path)
                ),
            ));
        }
        let name = manifest.name.clone().unwrap_or_default();
        if seen_names.contains(&name) {
            return Err(ws(
                "WS-MEMBER-DUPLICATE-NAME",
                format!("workspace has two members claiming name {name:?}"),
            ));
        }
        seen_names.push(name.clone());
        members.push(LoadedMember {
            name,
            path: member_path.clone(),
            directory: member_dir,
            manifest,
        });
    }

    Ok(LoadedWorkspace {
        root: root.to_path_buf(),
        members,
        overrides: parsed.overrides.clone(),
        flags: parsed.flags.clone(),
    })
}

#[cfg(test)]
#[path = "workspace_tests.rs"]
mod workspace_tests;
