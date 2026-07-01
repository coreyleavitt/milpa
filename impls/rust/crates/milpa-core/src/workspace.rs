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

/// Best-effort path resolution using stat (not lstat) to find the longest existing prefix.
///
/// Finds the **longest stat-existing ancestor prefix** of `path`, canonicalizes it
/// (following all symlinks via `fs::canonicalize`), then appends the remaining
/// non-existent suffix and normalizes lexically.
///
/// **Critical invariant (spec §11.0, S4, #168):** `metadata()` (stat, follows symlinks)
/// is used — NOT `symlink_metadata()` (lstat) — to determine which prefix "exists."
/// This means dangling symlinks (stat fails, target absent) and cyclic symlinks
/// (stat fails, ELOOP) are treated as **non-existent**.  Their longest stat-existing
/// prefix is the parent directory, and the result is `canonical_parent / symlink_name`
/// — i.e. the path stays inside its parent, never following the broken link.
///
/// Consequences for the `WS-MEMBER-PATH-ESCAPE` containment check:
/// - An **existing** symlink pointing outside the root: stat succeeds → fast path →
///   `canonicalize()` returns the real outside path → escape detected correctly.
/// - A **dangling** symlink (outside-pointing, target absent): stat fails → longest
///   stat-existing prefix = parent dir → result is inside parent → no escape →
///   `WS-MEMBER-DIR-MISSING`.
/// - A **cyclic** symlink (ELOOP): stat fails → same as dangling → `WS-MEMBER-DIR-MISSING`.
///
/// Key correctness property: the existing portion of the path is **always**
/// canonicalized (all symlinks resolved), so any live symlinks in intermediate
/// components of `path` are followed through.  This ensures
/// `best_effort_resolve(root/pkg/..)` yields the same canonical root that
/// `canonicalize(root)` yields even when `root` is a symlink.
fn best_effort_resolve(path: &std::path::Path) -> std::path::PathBuf {
    use std::path::Component;

    // Fast path: path stat-exists (stat succeeds, all symlinks followed).
    if path.exists() {
        return path.canonicalize().unwrap_or_else(|_| normalize_lexically(path));
    }

    // Ordinary non-existent (or dangling/cyclic symlink) path:
    // find the longest ancestor prefix for which stat() succeeds.
    //
    // `path.ancestors()` yields path, parent, grandparent, …, root.
    // Using `metadata()` (= stat) means dangling/cyclic symlinks at any
    // position in the path are skipped over (their stat fails → not found).
    let components: Vec<Component> = path.components().collect();
    let mut found: Option<(std::path::PathBuf, usize)> = None;
    for ancestor in path.ancestors() {
        // Use metadata() (stat, follows symlinks) — NOT symlink_metadata() (lstat).
        // Dangling and cyclic symlinks are excluded because stat fails for them.
        if ancestor.metadata().is_ok() {
            let ancestor_components: Vec<Component> = ancestor.components().collect();
            let prefix_len = ancestor_components.len();
            found = Some((ancestor.to_path_buf(), prefix_len));
            break;
        }
    }

    match found {
        Some((ancestor, prefix_len)) => {
            // Recursively resolve the existing ancestor prefix.  This handles any
            // live mid-path symlinks: `ancestor` stat-exists, so `best_effort_resolve`
            // takes the fast path and returns `canonicalize(ancestor)`.
            // Termination is guaranteed because `ancestor` is a STRICT prefix of
            // `path` (strictly fewer components).
            let real_prefix = best_effort_resolve(&ancestor);
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
/// Algorithm (spec §11.0, S4, #168 — mirrors Python `workspace.py` `_member_path_is_under_root`):
///   1. `best_effort_resolve(root)` — root always exists, so this equals `canonicalize(root)`.
///   2. `best_effort_resolve(candidate)` — stat-based: canonicalizes the longest
///      stat-existing prefix of candidate (following live symlinks), then appends
///      the remaining non-existent (or dangling/cyclic) suffix and normalizes lexically.
///      Dangling and cyclic symlinks are treated as non-existent (stat fails for them).
///   3. Return `real_cand.starts_with(real_root)` — inclusive.
///
/// Correctness for the symlinked-root case: if `root` is a symlink to `realroot`
/// and candidate = `root/pkg/..`, then:
///   - `best_effort_resolve(root)` = `canonicalize(root)` = `realroot`
///   - `best_effort_resolve(root/pkg/..)`: `root` is the longest stat-existing prefix
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

    // S6: workspace index-trust validation (RFC registry-trust-federation §6.4a).
    // Raise WS-INDEX-CONFLICTING-SIGNERS if members disagree on signer/bundle
    // identity BEFORE any network fetch (manifest-consistency error).
    check_conflicting_signers(root, &members)?;

    Ok(LoadedWorkspace {
        root: root.to_path_buf(),
        members,
        overrides: parsed.overrides.clone(),
        flags: parsed.flags.clone(),
    })
}

// ---------------------------------------------------------------------------
// S6: workspace index-trust merge + conflicting-signers check
// ---------------------------------------------------------------------------

/// Return the MAX of root + all member `index_trust_policy` values.
///
/// `strict > warn > off` (RFC registry-trust-federation §6.4a).  A workspace
/// where root=`warn` and any member=`strict` resolves under `strict`.  The
/// returned value is the effective policy for the whole workspace invocation.
pub fn merge_workspace_index_trust_policy(
    root_policy: &milpa_manifest::TrustPolicy,
    member_policies: &[milpa_manifest::TrustPolicy],
) -> milpa_manifest::TrustPolicy {
    use milpa_manifest::TrustPolicy;
    fn rank(p: &TrustPolicy) -> u8 {
        match p {
            TrustPolicy::Strict => 2,
            TrustPolicy::Warn => 1,
            TrustPolicy::Off => 0,
        }
    }
    let mut best = root_policy.clone();
    for p in member_policies {
        if rank(p) > rank(&best) {
            best = p.clone();
        }
    }
    best
}

/// Raise `WS-INDEX-CONFLICTING-SIGNERS` if workspace members disagree on
/// `index_trust_signer` or `index_trust_bundle`.
///
/// Only non-`None` values are compared; a member that does not declare a signer
/// cannot conflict with one that does (the non-declaring member inherits the
/// default, which is an operator/env concern, not a manifest conflict).
///
/// This is a manifest-consistency check and is raised BEFORE any index fetch
/// (RFC §6.4a).
pub fn check_conflicting_signers(
    workspace_root: &Path,
    members: &[LoadedMember],
) -> Result<(), MilpaError> {
    // Collect { signer_value → [member_path, ...] }.
    let mut signer_to_members: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut bundle_to_members: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();

    for member in members {
        if let Some(ref signer) = member.manifest.index_trust_signer {
            signer_to_members
                .entry(signer.clone())
                .or_default()
                .push(member.path.clone());
        }
        if let Some(ref bundle) = member.manifest.index_trust_bundle {
            bundle_to_members
                .entry(bundle.clone())
                .or_default()
                .push(member.path.clone());
        }
    }

    if signer_to_members.len() > 1 {
        let mut entries: Vec<_> = signer_to_members.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let (signer_a, members_a) = &entries[0];
        let (signer_b, members_b) = &entries[1];
        return Err(ws(
            "WS-INDEX-CONFLICTING-SIGNERS",
            format!(
                "workspace members declare conflicting index-trust-signer values: \
                 {:?} (in {:?}) vs {:?} (in {:?}). \
                 All members sharing an index URL must agree on the signer identity. \
                 workspace root: {}",
                signer_a,
                members_a,
                signer_b,
                members_b,
                workspace_root.display()
            ),
        ));
    }

    if bundle_to_members.len() > 1 {
        let mut entries: Vec<_> = bundle_to_members.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let (bundle_a, members_a) = &entries[0];
        let (bundle_b, members_b) = &entries[1];
        return Err(ws(
            "WS-INDEX-CONFLICTING-SIGNERS",
            format!(
                "workspace members declare conflicting index-trust-bundle values: \
                 {:?} (in {:?}) vs {:?} (in {:?}). \
                 All members sharing an index URL must agree on the trust-bundle. \
                 workspace root: {}",
                bundle_a,
                members_a,
                bundle_b,
                members_b,
                workspace_root.display()
            ),
        ));
    }

    Ok(())
}

#[cfg(test)]
#[path = "workspace_tests.rs"]
mod workspace_tests;
