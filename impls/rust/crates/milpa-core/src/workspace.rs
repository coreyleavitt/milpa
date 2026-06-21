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

/// Best-effort path resolution mirroring Python `Path.resolve(strict=False)`.
///
/// Finds the **longest existing ancestor prefix** of `path`, canonicalizes it
/// (following all symlinks via `fs::canonicalize`), then appends the remaining
/// non-existent suffix and normalizes lexically.  For a final component that is
/// a **dangling symlink** (lstat succeeds, stat fails), the symlink target is
/// read, joined onto the canonicalized parent, and normalized lexically —
/// matching Python's behaviour of following dangling links to their (absent)
/// targets so that an outside-pointing dangling symlink is still detected as an
/// escape.
///
/// Key correctness property: the existing portion of the path is **always**
/// canonicalized (all symlinks resolved), so any symlinks in intermediate
/// components of `path` are followed through.  This is what Python's `resolve()`
/// does, and it is why `best_effort_resolve(root/pkg/..)` yields the same
/// canonical root that `canonicalize(root)` yields even when `root` is a
/// symlink.
fn best_effort_resolve(path: &std::path::Path) -> std::path::PathBuf {
    use std::path::Component;

    // Fast path: path exists (stat succeeds, symlinks followed).
    if path.exists() {
        return path.canonicalize().unwrap_or_else(|_| normalize_lexically(path));
    }

    // Walk ancestors from `path` upward to find the longest prefix that exists.
    // `path.ancestors()` yields path, parent, grandparent, …, root.
    // The first ancestor for which `symlink_metadata` succeeds (i.e. exists on
    // disk, even as a dangling symlink) is our split point.
    //
    // We need to be careful: `path.ancestors()` starts at `path` itself.
    // We already know `path` doesn't exist via stat, but its lstat might succeed
    // (dangling symlink case).  Handle that first.
    let dangling = path
        .symlink_metadata()
        .ok()
        .filter(|m| m.file_type().is_symlink())
        .and_then(|_| std::fs::read_link(path).ok());
    if let Some(link_target) = dangling {
        // Dangling symlink: canonicalize the real parent, join the link target,
        // normalize lexically.  This is how Python resolve(strict=False) handles
        // dangling symlinks: it reads the link and appends the target to the
        // resolved parent, even though the target doesn't exist.
        let parent = path.parent().unwrap_or(path);
        let real_parent = best_effort_resolve(parent);
        let joined = if link_target.is_absolute() {
            link_target
        } else {
            real_parent.join(link_target)
        };
        return normalize_lexically(&joined);
    }

    // Ordinary non-existent path: find the longest existing ancestor prefix.
    // Collect ancestor components so we can reconstruct the suffix.
    let components: Vec<Component> = path.components().collect();
    // Try progressively shorter prefixes (from full path down to root).
    // `path.ancestors()` gives us the prefix paths in descending length order.
    // We pair each with the number of components that it has, so we know how
    // many trailing components to re-append.
    let mut found: Option<(std::path::PathBuf, usize)> = None;
    for ancestor in path.ancestors() {
        // Check whether this ancestor exists (lstat is enough — we just need to
        // know if the path node exists on the inode table).
        if ancestor.symlink_metadata().is_ok() {
            let ancestor_components: Vec<Component> = ancestor.components().collect();
            let prefix_len = ancestor_components.len();
            found = Some((ancestor.to_path_buf(), prefix_len));
            break;
        }
    }

    match found {
        Some((ancestor, prefix_len)) => {
            // Canonicalize the existing prefix (follows all symlinks in it).
            let real_prefix = ancestor
                .canonicalize()
                .unwrap_or_else(|_| normalize_lexically(&ancestor));
            // Re-append the non-existent suffix components.
            let suffix: std::path::PathBuf = components[prefix_len..].iter().collect();
            normalize_lexically(&real_prefix.join(suffix))
        }
        None => {
            // No ancestor exists at all (e.g. /nonexistent/a/b on a system where
            // /nonexistent doesn't exist).  Fall back to pure lexical normalization.
            normalize_lexically(path)
        }
    }
}

/// Return true if `candidate` is at or within `root` — inclusive (equal-to-root
/// returns true, letting the caller fall through to the `WS-MEMBER-IS-WORKSPACE`
/// check).
///
/// Algorithm (Option A — mirrors Python `workspace.py` `_member_path_is_under_root`
/// which calls `Path.resolve(strict=False)`):
///   1. `best_effort_resolve(root)` — root always exists, so this equals `canonicalize(root)`.
///   2. `best_effort_resolve(candidate)` — canonicalizes the longest existing
///      prefix of candidate (following symlinks in it), then appends the remaining
///      non-existent components and normalizes lexically.  This is the structural
///      mirror of Python's `(root / rel).resolve()`.
///   3. Return `real_cand.starts_with(real_root)` — inclusive.
///
/// Correctness for the symlinked-root case: if `root` is a symlink to `realroot`
/// and candidate = `root/pkg/..`, then:
///   - `best_effort_resolve(root)` = `canonicalize(root)` = `realroot`
///   - `best_effort_resolve(root/pkg/..)`: `root` is the longest existing prefix
///     (pkg does not exist), so prefix is canonicalized to `realroot`, suffix is
///     `pkg/..`, joined → `realroot/pkg/..`, normalized → `realroot`.
///   - `realroot.starts_with(realroot)` → true → NOT an escape.
fn is_under_root(root: &std::path::Path, candidate: &std::path::PathBuf) -> bool {
    let real_root = best_effort_resolve(root);
    let real_cand = best_effort_resolve(candidate);
    // Inclusive: equal-to-root is NOT an escape; falls through to WS-MEMBER-IS-WORKSPACE.
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
