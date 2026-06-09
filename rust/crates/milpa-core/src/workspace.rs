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
        if member_path == "." {
            return Err(ws(
                "WS-MEMBER-DOT",
                "member \".\" is not supported — the workspace root is a pure container and \
                 cannot also be a package; place it in a subdirectory and list that instead",
            ));
        }
        let member_dir = root.join(member_path);
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
    })
}

#[cfg(test)]
#[path = "workspace_tests.rs"]
mod workspace_tests;
