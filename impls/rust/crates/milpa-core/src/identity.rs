//! Content-addressed identity (RFC §4.1; identity.md). The byte-exact content
//! hash algorithm lives ONLY here (SSOT). Two-table algorithm-agility dispatch
//! (`SUPPORTED_ALGORITHMS` + digest lengths, not a hardcoded `== "sha256"`) so
//! future multihash is a one-file change (identity.md §2.3).
//!
//! S4: the canonical byte-stream walk + sha256 digest, plus the identity-string
//! validator (`parse_identity`). The byte layout is normative — see identity.md
//! §1.2: per entry `<relpath> 0x00 <mode-marker> 0x00 <content> 0x00`, entries
//! in ascending raw-byte relpath order, fed to a single live sha256 accumulator.

use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::dag_identity::{
    compute_dag_identity, MaterializedEntry, MODE_EXECUTABLE, MODE_REGULAR, MODE_SYMLINK,
};
use crate::error::CoreError;

/// Hash algorithms milpa understands, with their hex digest length. New
/// algorithms are added here and nowhere else.
pub const SUPPORTED_ALGORITHMS: &[(&str, usize)] = &[("dag-sha256", 64)];

/// Non-catalog sentinel for filesystem I/O failures encountered while walking a
/// tree to hash it. identity.md §5 catalogs no code for this: the Python
/// reference simply propagates a raw `OSError` (`p.read_bytes()` / `p.stat()` /
/// `os.readlink()` are unguarded). It is unreachable on a freshly-materialized
/// tree and not fixture-expressible, so it is deliberately kept OUT of
/// `CoreError::all_codes()` — it is an infrastructure failure, not a catalog
/// condition. The `MILPA-INTERNAL-` prefix marks it as non-catalog. Shared with
/// `store.rs`, whose mkdir/rename/symlink I/O the spec likewise leaves uncoded.
pub(crate) const INTERNAL_IO: &str = "MILPA-INTERNAL-IO";

/// Split an identity string into its raw `(algorithm, digest)` halves on the
/// first `':'` (identity.md §2.2 rule 2) — WITHOUT enforcing the
/// canonical-scheme allowlist (`SUPPORTED_ALGORITHMS`; rules 3-5). This is the
/// shared validation seam for callers that only need the raw scheme split and
/// must not silently no-op on malformed input — currently `parse_identity`
/// itself, and `entry_trust::build_entry_subject`, which extracts a hex digest
/// from a `content_hash` without needing (or wanting) to couple itself to
/// `SUPPORTED_ALGORITHMS`.
///
/// Raises `ID-NO-ALGORITHM-PREFIX` when there is no `':'` separator at all —
/// the failure mode a bare `split_once(':').unwrap_or(...)` would otherwise
/// swallow silently.
pub fn split_identity_scheme(s: &str) -> Result<(&str, &str), CoreError> {
    s.split_once(':').ok_or_else(|| {
        CoreError::Identity(
            "ID-NO-ALGORITHM-PREFIX",
            format!(
                "identity {s:?} is missing the algorithm prefix; \
                 expected '<algorithm>:<digest>' (e.g. 'sha256:abc...')"
            ),
        )
    })
}

/// Validate a multihash-encoded identity string against the `<algorithm>:<digest>`
/// grammar (identity.md §2.2). Returns the `(algorithm, digest)` split on success.
///
/// The Python reference's `ID-NOT-A-STRING` check is unreachable here: the input
/// is statically a `&str`, so the type system enforces it. The remaining four
/// codes mirror `identity.py:parse_identity`.
pub fn parse_identity(s: &str) -> Result<(&str, &str), CoreError> {
    let (algorithm, digest) = split_identity_scheme(s)?;
    let Some((_, expected_len)) = SUPPORTED_ALGORITHMS.iter().find(|(a, _)| *a == algorithm) else {
        let allowed: Vec<&str> = SUPPORTED_ALGORITHMS.iter().map(|(a, _)| *a).collect();
        return Err(CoreError::Identity(
            "ID-UNSUPPORTED-ALGORITHM",
            format!(
                "identity {s:?} uses unsupported algorithm {algorithm:?} (supported: {})",
                allowed.join(", ")
            ),
        ));
    };
    if digest.len() != *expected_len {
        return Err(CoreError::Identity(
            "ID-WRONG-DIGEST-LENGTH",
            format!(
                "identity {s:?}: {algorithm} digest must be exactly {expected_len} \
                 hex characters, got {}",
                digest.len()
            ),
        ));
    }
    if !digest
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CoreError::Identity(
            "ID-NON-HEX-DIGEST",
            format!("identity {s:?}: digest must be lowercase hex characters (0-9, a-f)"),
        ));
    }
    Ok((algorithm, digest))
}

/// Compute the canonical content Merkle-DAG identity of a source tree, returning
/// `"dag-sha256:<64-hex>"` (identity.md §1.8 / §2.1).
///
/// The on-disk tree is walked into a buffered `Vec<MaterializedEntry>` by
/// [`enumerate_local_entries`] (the canonical disk walk) and folded by
/// [`crate::dag_identity::compute_dag_identity`]. The STEP-1 invariant (a
/// git-materialized on-disk tree hashed here equals the git object-store
/// enumeration) is what lets every transport, plus CAS verify, share this one
/// identity site.
pub fn compute_content_hash(root: &Path) -> Result<String, CoreError> {
    compute_dag_identity(&enumerate_local_entries(root)?)
}

/// The canonical on-disk walk (the local materialize seam): walk `root` into a
/// buffered `Vec<MaterializedEntry>` (spec §1.8.4) feeding the epoch-2 DAG builder.
///
/// Single source of truth for turning real on-disk bytes + POSIX mode bits into
/// the materialize seam. [`compute_content_hash`] uses it, and the local transport
/// is exactly this walk applied to a local source dir — the local sibling of the
/// object-store seams [`crate::fetchers::enumerate_git_entries`] /
/// [`crate::fetchers::enumerate_tarball_entries`]. Mode mapping (spec §1.8.2.1):
/// a regular file with any POSIX execute bit (`st_mode & 0o111`) → `0x01`, else
/// `0x00`; a symlink → `0x80` with the `read_link` target string bytes (not
/// followed). A `.git` component is skipped at any depth (§1.8.6). Non-UTF-8
/// names / symlink targets are coded errors (cross-impl contract with Python).
pub fn enumerate_local_entries(root: &Path) -> Result<Vec<MaterializedEntry>, CoreError> {
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<MaterializedEntry>) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;

    let mut children: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| {
            CoreError::Identity(
                INTERNAL_IO,
                format!("cannot read directory {}: {e}", dir.display()),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            CoreError::Identity(
                INTERNAL_IO,
                format!("cannot read entry under {}: {e}", dir.display()),
            )
        })?;
    // Stream order is irrelevant (the builder re-sorts each level by leaf name);
    // a stable sort keeps the walk deterministic.
    children.sort_by_key(|e| e.file_name());

    for ent in children {
        let path = ent.path();
        // §1.8.6 (inherits §1.4): exclude `.git` (and anything beneath it) at any depth.
        if path.file_name().map(|n| n == ".git").unwrap_or(false) {
            continue;
        }
        // §1.3 / spec/errors.md ID-NON-UTF8-RELPATH: the relpath is encoded as
        // UTF-8 (cross-impl contract with Python). On Linux, filenames are raw
        // byte sequences; validate before constructing the entry so both impls
        // raise the same coded error rather than silently diverging.
        let rb = relpath_bytes(root, &path);
        let relpath = match std::str::from_utf8(&rb) {
            Ok(s) => s.to_string(),
            Err(_) => {
                return Err(CoreError::Identity(
                    "ID-NON-UTF8-RELPATH",
                    format!(
                        "file path {:?} is not valid UTF-8 — cannot compute a content hash",
                        String::from_utf8_lossy(&rb)
                    ),
                ))
            }
        };
        // symlink_metadata does NOT follow the link, so a symlink — even to a
        // directory — reports as a symlink and becomes a leaf entry.
        let meta = std::fs::symlink_metadata(&path).map_err(|e| {
            CoreError::Identity(INTERNAL_IO, format!("cannot stat {}: {e}", path.display()))
        })?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            // §1.5/§1.8.1: hash the link-target string as UTF-8 bytes; do not follow.
            let target = std::fs::read_link(&path).map_err(|e| {
                CoreError::Identity(
                    INTERNAL_IO,
                    format!("cannot readlink {}: {e}", path.display()),
                )
            })?;
            let target_str = target.into_os_string().into_string().map_err(|_| {
                CoreError::Identity(
                    "ID-NON-UTF8-SYMLINK-TARGET",
                    format!(
                        "symlink target at {relpath:?} is not valid UTF-8 \
                         — cannot compute a content hash"
                    ),
                )
            })?;
            out.push(MaterializedEntry {
                relpath,
                mode_byte: MODE_SYMLINK,
                content: target_str.into_bytes(),
            });
        } else if ft.is_dir() {
            walk(root, &path, out)?;
        } else if ft.is_file() {
            let content = std::fs::read(&path).map_err(|e| {
                CoreError::Identity(
                    INTERNAL_IO,
                    format!("cannot read file {}: {e}", path.display()),
                )
            })?;
            // §1.8.2.1: the executable bit is part of epoch-2 identity.
            let mode_byte = if meta.permissions().mode() & 0o111 != 0 {
                MODE_EXECUTABLE
            } else {
                MODE_REGULAR
            };
            out.push(MaterializedEntry {
                relpath,
                mode_byte,
                content,
            });
        }
        // else: fifo/socket/device — not representable; skipped, as Python's
        // is_file()/is_symlink() pair would also skip them.
    }
    Ok(())
}

/// The POSIX relative path from `root` to `path`, as raw bytes. On Linux a
/// filename's OS bytes equal its UTF-8 encoding when valid; using the raw bytes
/// both matches the spec's UTF-8 clause for valid paths and gives the exact
/// byte-order the §1.3 sort requires, with no lossy conversion.
fn relpath_bytes(root: &Path, path: &Path) -> Vec<u8> {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.as_os_str().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    // Owner-execute bit — used only by test helper `write` to create fixture
    // files with the exec bit set; the bit itself is no longer part of identity
    // (Resolved Decision 1).
    const S_IXUSR: u32 = 0o100;

    #[test]
    fn dag_sha256_is_supported_with_64_hex_chars() {
        assert_eq!(
            SUPPORTED_ALGORITHMS.iter().find(|(a, _)| *a == "dag-sha256"),
            Some(&("dag-sha256", 64))
        );
    }

    #[test]
    fn sha256_is_not_in_supported_algorithms() {
        assert!(
            SUPPORTED_ALGORITHMS.iter().all(|(a, _)| *a != "sha256"),
            "stale sha256 must not be in SUPPORTED_ALGORITHMS"
        );
    }

    // --- parse_identity (mirrors test_identity_validator.py) -----------------

    #[test]
    fn parse_identity_accepts_dag_sha256_canonical_form() {
        let valid = format!("dag-sha256:{}", "a".repeat(64));
        assert_eq!(
            parse_identity(&valid).unwrap(),
            ("dag-sha256", &"a".repeat(64)[..])
        );
    }

    #[test]
    fn parse_identity_rejects_stale_sha256_prefix() {
        let stale = format!("sha256:{}", "a".repeat(64));
        let e = parse_identity(&stale).unwrap_err();
        assert_eq!(e.code(), "ID-UNSUPPORTED-ALGORITHM");
    }

    #[test]
    fn parse_identity_rejects_unknown_algorithm() {
        let e = parse_identity(&format!("md5:{}", "a".repeat(32))).unwrap_err();
        assert_eq!(e.code(), "ID-UNSUPPORTED-ALGORITHM");
    }

    #[test]
    fn parse_identity_rejects_bare_hex_no_prefix() {
        let e = parse_identity(&"a".repeat(64)).unwrap_err();
        assert_eq!(e.code(), "ID-NO-ALGORITHM-PREFIX");
    }

    #[test]
    fn parse_identity_rejects_wrong_length_digest() {
        let e = parse_identity("dag-sha256:abc123").unwrap_err();
        assert_eq!(e.code(), "ID-WRONG-DIGEST-LENGTH");
    }

    #[test]
    fn parse_identity_rejects_non_hex_characters_in_digest() {
        let e = parse_identity(&format!("dag-sha256:{}", "Z".repeat(64))).unwrap_err();
        assert_eq!(e.code(), "ID-NON-HEX-DIGEST");
    }

    // --- compute_content_hash (mirrors test_identity.py) ---------------------

    fn write(path: &Path, content: &str, executable: bool) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
        if executable {
            let mut p = fs::metadata(path).unwrap().permissions();
            p.set_mode(p.mode() | S_IXUSR);
            fs::set_permissions(path, p).unwrap();
        }
    }

    fn tmp() -> std::path::PathBuf {
        // Unique scratch under the cargo target tmp; index-free via a counter.
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("milpa-id-test-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn executable_bit_changes_content_hash() {
        // Epoch 2 (§1.8.2): the exec bit IS part of identity. A regular file
        // (0x00) and an executable file (0x01) with identical bytes hash
        // differently — a deliberate correction over interim epoch 1.
        let root = tmp();
        let (a, b) = (root.join("a"), root.join("b"));
        write(&a.join("script.sh"), "#!/bin/sh\necho hi\n", false);
        write(&b.join("script.sh"), "#!/bin/sh\necho hi\n", true);
        assert_ne!(
            compute_content_hash(&a).unwrap(),
            compute_content_hash(&b).unwrap()
        );
    }

    #[test]
    fn identical_trees_produce_identical_hashes() {
        let root = tmp();
        let (a, b) = (root.join("a"), root.join("b"));
        let files = [
            (
                "src/main.nim",
                "import std/strutils\nproc main() = echo \"hi\"\n",
                false,
            ),
            ("README.md", "# project\n", false),
            (
                "scripts/run.sh",
                "#!/bin/sh\nexec nim r src/main.nim\n",
                true,
            ),
        ];
        for (rel, content, exec) in files {
            write(&a.join(rel), content, exec);
            write(&b.join(rel), content, exec);
        }
        assert_eq!(
            compute_content_hash(&a).unwrap(),
            compute_content_hash(&b).unwrap()
        );
    }

    #[test]
    fn dot_git_directory_excluded() {
        let root = tmp();
        let (a, b) = (root.join("a"), root.join("b"));
        write(&a.join("src/main.nim"), "echo 'hi'\n", false);
        write(&b.join("src/main.nim"), "echo 'hi'\n", false);
        write(&b.join(".git/HEAD"), "ref: refs/heads/main\n", false);
        write(&b.join(".git/objects/ab/cd1234"), "binary junk", false);
        assert_eq!(
            compute_content_hash(&a).unwrap(),
            compute_content_hash(&b).unwrap()
        );
    }

    #[test]
    fn symlink_hashed_by_target_not_followed() {
        let root = tmp();
        let (a, b) = (root.join("a"), root.join("b"));
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        fs::write(a.join("real.txt"), "hello\n").unwrap();
        symlink("real.txt", a.join("link")).unwrap();
        fs::write(b.join("real.txt"), "hello\n").unwrap();
        symlink("different_target", b.join("link")).unwrap();
        assert_ne!(
            compute_content_hash(&a).unwrap(),
            compute_content_hash(&b).unwrap()
        );
    }

    #[test]
    fn symlink_vs_regular_file_with_same_content_differ() {
        let root = tmp();
        let (a, b) = (root.join("a"), root.join("b"));
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        fs::write(a.join("entry"), "target").unwrap();
        symlink("target", b.join("entry")).unwrap();
        assert_ne!(
            compute_content_hash(&a).unwrap(),
            compute_content_hash(&b).unwrap()
        );
    }

    #[test]
    fn symlink_pointing_outside_tree_does_not_crash() {
        let root = tmp();
        let a = root.join("a");
        fs::create_dir_all(&a).unwrap();
        symlink("/nonexistent/elsewhere", a.join("broken")).unwrap();
        let h = compute_content_hash(&a).unwrap();
        let digest = h.strip_prefix("dag-sha256:").unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn byte_parity_with_python_oracle() {
        // The digest below is produced by the Python reference impl
        // (milpa.identity.compute_content_hash) over a tree with one regular
        // file, one executable file, a symlink, and an excluded `.git/`. If the
        // Rust byte stream ever drifts from the spec, this breaks. Regenerate
        // ONLY by re-running the oracle on the identical tree.
        let a = tmp().join("t");
        write(
            &a.join("src/main.nim"),
            "import std/strutils\nproc main() = echo \"hi\"\n",
            false,
        );
        write(&a.join("README.md"), "# project\n", false);
        write(
            &a.join("run.sh"),
            "#!/bin/sh\nexec nim r src/main.nim\n",
            true,
        );
        symlink("src/main.nim", a.join("mainlink")).unwrap();
        write(&a.join(".git/HEAD"), "junk\n", false);
        assert_eq!(
            compute_content_hash(&a).unwrap(),
            "dag-sha256:10c68c24594e4ab384f0672a67b738eab5190e0837a3e09dd27e89eb1172791a"
        );
    }

    #[test]
    fn empty_tree_hashes_the_empty_stream() {
        let root = tmp();
        let a = root.join("a");
        fs::create_dir_all(&a).unwrap();
        // Empty tree = the zero-entry Merkle-DAG root (§1.8.5): sha256(b"").
        assert_eq!(
            compute_content_hash(&a).unwrap(),
            "dag-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // --- ID-NON-UTF8-RELPATH (spec/errors.md; distinct from
    // --- ID-NON-UTF8-SYMLINK-TARGET which covers symlink *targets*)

    #[test]
    fn non_utf8_relpath_in_regular_file_raises_coded_error() {
        // A source tree containing a file whose *name* (not content) contains
        // non-UTF-8 bytes must raise ID-NON-UTF8-RELPATH, not panic or silently
        // produce a wrong hash.  Mirrors the Python test and the
        // ID-NON-UTF8-SYMLINK-TARGET test pattern.
        //
        // This test creates a file via raw OS bytes (std::fs + OsStr::from_bytes).
        // Skip gracefully if the filesystem rejects the bytes (vfat, some WSL
        // mounts), analogous to the Python "pytest.skip" branch.
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;

        let root = tmp();
        let a = root.join("a");
        fs::create_dir_all(&a).unwrap();

        // Build a file path with a raw non-UTF-8 byte (0xff) in the name.
        let bad_name = OsStr::from_bytes(b"\xff\xfe");
        let bad_path = a.join(bad_name);
        match fs::write(&bad_path, b"content") {
            Err(_) => {
                // Filesystem rejected the non-UTF-8 name — skip gracefully.
                return;
            }
            Ok(()) => {}
        }

        let err = compute_content_hash(&a).unwrap_err();
        assert_eq!(
            err.code(),
            "ID-NON-UTF8-RELPATH",
            "expected ID-NON-UTF8-RELPATH, got {:?}",
            err
        );
    }

    #[test]
    fn non_utf8_relpath_in_symlink_name_raises_coded_error() {
        // A symlink whose *name* (not target) contains non-UTF-8 bytes must also
        // raise ID-NON-UTF8-RELPATH.  The relpath check fires before the
        // symlink-target check, so the symlink-target itself is irrelevant here.
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;

        let root = tmp();
        let a = root.join("a");
        fs::create_dir_all(&a).unwrap();

        let bad_name = OsStr::from_bytes(b"\xff\xfe");
        let bad_link_path = a.join(bad_name);
        match symlink("some_target", &bad_link_path) {
            Err(_) => {
                // Filesystem rejected the non-UTF-8 name — skip gracefully.
                return;
            }
            Ok(()) => {}
        }

        let err = compute_content_hash(&a).unwrap_err();
        assert_eq!(
            err.code(),
            "ID-NON-UTF8-RELPATH",
            "expected ID-NON-UTF8-RELPATH, got {:?}",
            err
        );
    }

    #[test]
    fn non_utf8_symlink_target_still_raises_symlink_target_code() {
        // Sanity: a symlink with a VALID UTF-8 name but a NON-UTF-8 target
        // still raises ID-NON-UTF8-SYMLINK-TARGET (not ID-NON-UTF8-RELPATH),
        // confirming the two codes are distinct and the right one fires first.
        let root = tmp();
        let a = root.join("a");
        fs::create_dir_all(&a).unwrap();

        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;
        let bad_target = OsStr::from_bytes(b"\xff\xfe");
        // valid UTF-8 link name, non-UTF-8 target
        match std::os::unix::fs::symlink(bad_target, a.join("valid_name_link")) {
            Err(_) => return, // filesystem rejected the target bytes — skip
            Ok(()) => {}
        }

        let err = compute_content_hash(&a).unwrap_err();
        assert_eq!(
            err.code(),
            "ID-NON-UTF8-SYMLINK-TARGET",
            "expected ID-NON-UTF8-SYMLINK-TARGET for non-UTF-8 target, got {:?}",
            err
        );
    }
}
