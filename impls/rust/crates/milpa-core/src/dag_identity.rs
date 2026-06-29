//! Epoch-2 canonical content Merkle-DAG identity — the production builder.
//!
//! RFC `rfc-identity-conformance-authority` slice B2-git; `spec/identity.md` §1.8.
//! This is milpa-rust's **production** epoch-2 identity builder and the single
//! source of truth for the canonical Merkle-DAG digest in this impl.
//!
//! Two pieces live here:
//! * [`MaterializedEntry`] — the **materialize seam** type. Every per-transport
//!   materializer (git first, then tarball / local / oci) produces a *buffered,
//!   fully-collected* `Vec<MaterializedEntry>` (spec §1.8.4: not a streaming hash
//!   feed). The DAG builder is a pure function over it.
//! * [`compute_dag_identity`] — the pure builder: group the flat entry sequence by
//!   directory, build tree nodes **bottom-up**, sort each level's immediate
//!   children by **leaf name** (NOT full relpath — spec §1.8.3, the top cross-impl
//!   divergence risk), apply the empty-directory-omission rule, and return the
//!   root `H_tree` as `dag-sha256:<hex>`.
//!
//! DISCIPLINE — this builder is **independent** of the conformance oracle
//! (`conformance/spec-v1/_oracle/dag_sha256_reference.py`): it neither imports the
//! oracle nor is imported by it. Their agreement on the hand-frozen pinned digests
//! is the differential check (an oracle that shares code with the impl cannot catch
//! a shared bug). It is transcribed directly from the spec §1.8 byte tables, and
//! must stay byte-for-byte identical to the Python builder (`milpa/dag_identity.py`).
//!
//! Staging note (B2): epoch-2 is NOT yet the default emission. `compute_content_hash`
//! in `identity.rs` still emits the interim epoch-1 flat digest; this builder is
//! exercised only by the `dag-oracle` conformance tier until B-cutover.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::error::CoreError;

/// Mode bytes (spec/identity.md §1.8.2.1 — the four-valued type tag).
pub const MODE_REGULAR: u8 = 0x00;
pub const MODE_EXECUTABLE: u8 = 0x01;
pub const MODE_SYMLINK: u8 = 0x80;
pub const MODE_TREE: u8 = 0x40;

/// Leaf-name byte ceiling (spec/identity.md §1.8.8 — ID-NAME-TOO-LONG).
pub const NAME_BYTE_CEILING: usize = 4096;

/// Path component whose presence excludes an entry at any depth (spec §1.4/§1.8.6).
const GIT_COMPONENT: &str = ".git";

/// One materialized blob or symlink — the unit of the materialize seam.
///
/// A per-transport materializer yields a buffered `Vec<MaterializedEntry>` for the
/// whole tree; the DAG builder is a pure function over it (spec §1.8.4). The seam
/// carries **only** blob/symlink leaves — subtree (mode `0x40`) nodes are
/// synthesised by the builder from the relpath structure, never emitted by a
/// materializer.
#[derive(Debug, Clone)]
pub struct MaterializedEntry {
    /// POSIX relative path from the tree root (`/` separators, no leading `/`).
    pub relpath: String,
    /// One of `MODE_REGULAR` (0x00), `MODE_EXECUTABLE` (0x01), `MODE_SYMLINK` (0x80).
    pub mode_byte: u8,
    /// Raw blob bytes; for a symlink, the UTF-8 link-target string (§1.8.1).
    pub content: Vec<u8>,
}

impl MaterializedEntry {
    pub fn new(relpath: impl Into<String>, mode_byte: u8, content: Vec<u8>) -> Self {
        Self { relpath: relpath.into(), mode_byte, content }
    }
}

/// A directory node under construction: leaf blobs + named subdirectories.
#[derive(Default)]
struct Node {
    /// leaf name -> (mode_byte, content) for blob/symlink children.
    blobs: HashMap<String, (u8, Vec<u8>)>,
    /// leaf name -> child node for subdirectory children.
    subdirs: HashMap<String, Node>,
}

/// UTF-8-encode a leaf name, enforcing the §1.8.8 byte ceiling.
fn check_name(name: &str) -> Result<Vec<u8>, CoreError> {
    let bytes = name.as_bytes();
    if bytes.len() > NAME_BYTE_CEILING {
        return Err(CoreError::Identity(
            "ID-NAME-TOO-LONG",
            format!(
                "path component {name:?} is {} bytes, exceeding the {NAME_BYTE_CEILING}-byte \
                 epoch-2 leaf-name ceiling (spec/identity.md §1.8.8)",
                bytes.len()
            ),
        ));
    }
    Ok(bytes.to_vec())
}

/// Insert one materialized entry into the nested tree at its path components.
fn insert(root: &mut Node, parts: &[&str], mode_byte: u8, content: Vec<u8>) -> Result<(), CoreError> {
    let (dirs, leaf) = parts.split_at(parts.len() - 1);
    let mut node = root;
    for component in dirs {
        check_name(component)?; // interior component names are entry names too
        node = node.subdirs.entry((*component).to_string()).or_default();
    }
    check_name(leaf[0])?;
    node.blobs.insert(leaf[0].to_string(), (mode_byte, content));
    Ok(())
}

/// Serialize one tree-node entry per the §1.8.2 byte layout.
fn encode_entry(name_bytes: &[u8], mode_byte: u8, child_digest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + name_bytes.len() + 1 + 32);
    out.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(name_bytes);
    out.push(mode_byte);
    out.extend_from_slice(child_digest);
    out
}

/// Return `(H_tree, is_empty)` for a directory node (spec §1.8.2–§1.8.5).
///
/// `is_empty` is `true` when the node has no entries after recursively omitting
/// empty subdirectories — the signal a parent uses to drop it (§1.8.5).
fn hash_tree(node: &Node) -> Result<([u8; 32], bool), CoreError> {
    // (name_bytes, mode_byte, child_digest_raw)
    let mut items: Vec<(Vec<u8>, u8, [u8; 32])> = Vec::new();

    // Blob/symlink children: H_blob = sha256(content) (§1.8.1).
    for (leaf, (mode_byte, content)) in &node.blobs {
        let name_bytes = check_name(leaf)?;
        let digest: [u8; 32] = Sha256::digest(content).into();
        items.push((name_bytes, *mode_byte, digest));
    }

    // Subtree children (mode 0x40). Empty subtrees contribute NO entry (§1.8.5).
    for (leaf, sub) in &node.subdirs {
        let (sub_digest, sub_empty) = hash_tree(sub)?;
        if sub_empty {
            continue;
        }
        let name_bytes = check_name(leaf)?;
        items.push((name_bytes, MODE_TREE, sub_digest));
    }

    // §1.8.3: ascending UTF-8 byte order of the LEAF NAME (not the full relpath).
    items.sort_by(|a, b| a.0.cmp(&b.0));

    let mut blob = Vec::new();
    for (name_bytes, mode_byte, digest) in &items {
        blob.extend_from_slice(&encode_entry(name_bytes, *mode_byte, digest));
    }
    let digest: [u8; 32] = Sha256::digest(&blob).into();
    Ok((digest, items.is_empty()))
}

/// Compute the epoch-2 `dag-sha256:` identity of a materialized sequence.
///
/// Pure function over a buffered `&[MaterializedEntry]` (spec §1.8.4). Groups
/// entries by directory, builds tree nodes bottom-up, sorts each level's children
/// by leaf name (§1.8.3), omits empty subdirectories (§1.8.5), and returns the root
/// `H_tree` as `dag-sha256:<64-lowercase-hex>` (§2.1).
///
/// The empty source tree yields `dag-sha256:` + `sha256(b"")` (§1.8.5).
///
/// # Errors
/// `ID-NAME-TOO-LONG` — a path component exceeds 4096 bytes (§1.8.8).
pub fn compute_dag_identity(entries: &[MaterializedEntry]) -> Result<String, CoreError> {
    let mut root = Node::default();
    for entry in entries {
        let parts: Vec<&str> = entry.relpath.split('/').collect();
        // §1.8.6 (inherits §1.4): drop any path with a `.git` component, any depth.
        if parts.iter().any(|p| *p == GIT_COMPONENT) {
            continue;
        }
        // Materializers emit only blob mode-bytes (0x00/0x01/0x80); a 0x40 here is
        // a programming error. This invariant is unreachable from the seam.
        debug_assert!(
            entry.mode_byte == MODE_REGULAR
                || entry.mode_byte == MODE_EXECUTABLE
                || entry.mode_byte == MODE_SYMLINK,
            "materialized entry {:?} has non-blob mode-byte {:#04x}",
            entry.relpath,
            entry.mode_byte
        );
        insert(&mut root, &parts, entry.mode_byte, entry.content.clone())?;
    }

    let (digest, _empty) = hash_tree(&root)?;
    Ok(format!("dag-sha256:{}", hex_lower(&digest)))
}

/// Lowercase hex of a 32-byte digest (avoids pulling in a formatting dependency).
fn hex_lower(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_ROOT_PIN: &str =
        "dag-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const NESTED_PIN: &str =
        "dag-sha256:e3213019260649b72bb0295aaec004eb20a625dd55fcd4bac9e35df96bce316f";

    fn nested() -> Vec<MaterializedEntry> {
        vec![
            MaterializedEntry::new("a.txt", MODE_REGULAR, b"alpha\n".to_vec()),
            MaterializedEntry::new("a/b.txt", MODE_REGULAR, b"beta\n".to_vec()),
            MaterializedEntry::new("a/run.sh", MODE_EXECUTABLE, b"#!/bin/sh\necho hi\n".to_vec()),
            MaterializedEntry::new("link", MODE_SYMLINK, b"a/b.txt".to_vec()),
        ]
    }

    #[test]
    fn empty_tree_is_pinned_empty_root() {
        assert_eq!(compute_dag_identity(&[]).unwrap(), EMPTY_ROOT_PIN);
    }

    #[test]
    fn nested_tree_reproduces_pinned_oracle_digest() {
        assert_eq!(compute_dag_identity(&nested()).unwrap(), NESTED_PIN);
    }

    #[test]
    fn builder_invariant_to_stream_order() {
        // §1.8.3: the builder re-sorts each level by leaf name, so a reversed
        // stream yields the same digest (a naive full-relpath builder would not).
        let mut rev = nested();
        rev.reverse();
        assert_eq!(compute_dag_identity(&rev).unwrap(), NESTED_PIN);
    }

    #[test]
    fn executable_bit_changes_identity() {
        let reg = compute_dag_identity(&[MaterializedEntry::new(
            "run.sh", MODE_REGULAR, b"#!/bin/sh\n".to_vec(),
        )])
        .unwrap();
        let exe = compute_dag_identity(&[MaterializedEntry::new(
            "run.sh", MODE_EXECUTABLE, b"#!/bin/sh\n".to_vec(),
        )])
        .unwrap();
        assert_ne!(reg, exe);
    }

    #[test]
    fn symlink_differs_from_regular_same_bytes() {
        let reg = compute_dag_identity(&[MaterializedEntry::new(
            "x", MODE_REGULAR, b"target".to_vec(),
        )])
        .unwrap();
        let sym = compute_dag_identity(&[MaterializedEntry::new(
            "x", MODE_SYMLINK, b"target".to_vec(),
        )])
        .unwrap();
        assert_ne!(reg, sym);
    }

    #[test]
    fn dot_git_excluded_at_any_depth() {
        let base = vec![MaterializedEntry::new("src/main.nim", MODE_REGULAR, b"echo\n".to_vec())];
        let mut polluted = base.clone();
        polluted.push(MaterializedEntry::new(".git/HEAD", MODE_REGULAR, b"ref\n".to_vec()));
        polluted.push(MaterializedEntry::new("vendor/x/.git/config", MODE_REGULAR, b"junk\n".to_vec()));
        assert_eq!(
            compute_dag_identity(&base).unwrap(),
            compute_dag_identity(&polluted).unwrap()
        );
    }

    #[test]
    fn empty_subdir_omitted() {
        let base = vec![MaterializedEntry::new("a.txt", MODE_REGULAR, b"alpha\n".to_vec())];
        let mut with_empty = base.clone();
        with_empty.push(MaterializedEntry::new("empty/.git/x", MODE_REGULAR, b"junk\n".to_vec()));
        assert_eq!(
            compute_dag_identity(&base).unwrap(),
            compute_dag_identity(&with_empty).unwrap()
        );
    }

    #[test]
    fn name_too_long_raises() {
        let too_long = "x".repeat(4097);
        let err = compute_dag_identity(&[MaterializedEntry::new(
            too_long, MODE_REGULAR, b"data".to_vec(),
        )])
        .unwrap_err();
        assert_eq!(err.code(), "ID-NAME-TOO-LONG");
    }

    #[test]
    fn name_at_ceiling_accepted() {
        let at_ceiling = "x".repeat(4096);
        let out = compute_dag_identity(&[MaterializedEntry::new(
            at_ceiling, MODE_REGULAR, b"data".to_vec(),
        )])
        .unwrap();
        assert!(out.starts_with("dag-sha256:"));
        assert_eq!(out.len(), "dag-sha256:".len() + 64);
    }
}
