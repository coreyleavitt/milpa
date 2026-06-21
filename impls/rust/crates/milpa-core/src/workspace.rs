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
/// Used for the `WS-MEMBER-PATH-ESCAPE` containment check.
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

/// Return true if `candidate` is contained within `root` (lexically, after
/// normalizing both paths).  A path that *equals* the root (same directory)
/// is NOT considered contained — workspace root cannot be a member.
fn is_under_root(root: &std::path::Path, candidate: &std::path::PathBuf) -> bool {
    let norm_root = normalize_lexically(root);
    let norm_cand = normalize_lexically(candidate);
    // starts_with checks every component, so /a/b starts_with /a/b is true (same dir).
    // We want strict containment: candidate must have at least one extra component.
    norm_cand != norm_root && norm_cand.starts_with(&norm_root)
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
        // §WS-MEMBER-PATH-ESCAPE: lexical containment check before dir-existence.
        if !is_under_root(root, &member_dir) {
            return Err(ws(
                "WS-MEMBER-PATH-ESCAPE",
                format!(
                    "workspace member {member_path:?} resolves outside the workspace root",
                ),
            ));
        }
        if !member_dir.is_dir() {
            return Err(ws(
                "WS-MEMBER-DIR-MISSING",
                format!(
                    "workspace member {member_path:?} has no directory at {}",
                    member_dir.display()
                ),
            ));
        }
        let member_kdl = member_dir.join("milpa.kdl");
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
        // §WS-MEMBER-PATH-ESCAPE: lexical containment check before dir-existence.
        if !is_under_root(root, &member_dir) {
            return Err(ws(
                "WS-MEMBER-PATH-ESCAPE",
                format!(
                    "workspace member {member_path:?} resolves outside the workspace root",
                ),
            ));
        }
        if !member_dir.is_dir() {
            return Err(ws(
                "WS-MEMBER-DIR-MISSING",
                format!(
                    "workspace member {member_path:?} has no directory at {}",
                    member_dir.display()
                ),
            ));
        }
        let member_kdl = member_dir.join("milpa.kdl");
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
