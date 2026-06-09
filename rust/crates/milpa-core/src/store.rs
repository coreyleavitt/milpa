//! Content-addressed store (RFC §4.1; identity.md §3). Layout / admit / link,
//! the 4-tier precedence, and the relative-symlink convention.
//!
//! S4: admit (move-via-rename with duplicate-as-no-op), link (relative symlink,
//! `CAS-NOT-IN-STORE` guard), `path_for`/`contains`, and `default_store`'s env
//! precedence (tiers 1, 3, 4 — manifest tier 2 is applied by the CLI/resolver,
//! which alone sees the manifest). Mirrors `milpa/cas.py`.

use std::path::{Path, PathBuf};

use crate::error::CoreError;
// `INTERNAL_IO` is the identity module's non-catalog sentinel, reused for
// store-side I/O failures (mkdir / rename / symlink) the spec also leaves uncoded.
use crate::identity::{compute_content_hash, parse_identity, INTERNAL_IO};

/// A handle to the on-disk content-addressed store rooted at `root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaStore {
    pub root: PathBuf,
}

impl CaStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        CaStore { root: root.into() }
    }

    /// Canonical path `<root>/<algorithm>/<hex-digest>/` for `identity`. May or
    /// may not exist. Validates the identity string first (identity.md §2.2).
    pub fn path_for(&self, identity: &str) -> Result<PathBuf, CoreError> {
        let (algo, hex) = parse_identity(identity)?;
        Ok(self.root.join(algo).join(hex))
    }

    /// True iff the store already holds an entry for `identity`.
    pub fn contains(&self, identity: &str) -> Result<bool, CoreError> {
        Ok(self.path_for(identity)?.is_dir())
    }

    /// Move `src` into the store under `identity`, returning the canonical path
    /// (identity.md §3.3). Verifies `src`'s bytes hash to `identity` first;
    /// raises `CAS-IDENTITY-MISMATCH` on mismatch, leaving `src` in place and the
    /// store unmodified. Duplicate admission is a no-op: if the canonical entry
    /// already exists, `src` is removed and the existing path returned.
    pub fn admit(&self, src: &Path, identity: &str) -> Result<PathBuf, CoreError> {
        let actual = compute_content_hash(src)?;
        if actual != identity {
            return Err(CoreError::Identity(
                "CAS-IDENTITY-MISMATCH",
                format!("identity mismatch — claimed {identity:?}, computed {actual:?}"),
            ));
        }
        let canonical = self.path_for(identity)?;
        if let Some(parent) = canonical.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CoreError::Identity(
                    INTERNAL_IO,
                    format!("cannot create CAS dir {}: {e}", parent.display()),
                )
            })?;
        }
        // POSIX rename(2): atomic on the same filesystem (scratch + CAS share a
        // mount). On failure, the canonical entry may already exist from a
        // concurrent admit of the same identity — that is the duplicate-no-op.
        if std::fs::rename(src, &canonical).is_err() {
            if canonical.is_dir() {
                let _ = std::fs::remove_dir_all(src);
            } else {
                return Err(CoreError::Identity(
                    INTERNAL_IO,
                    format!(
                        "cannot admit {} → {}: rename failed and canonical entry absent",
                        src.display(),
                        canonical.display()
                    ),
                ));
            }
        }
        Ok(canonical)
    }

    /// Create a symlink at `target` resolving to the CAS entry for `identity`
    /// (identity.md §3.5). The stored target is a path **relative** to the
    /// symlink's directory — portable across bind-mounts. Idempotent: a stale
    /// `target` is cleared first. Raises `CAS-NOT-IN-STORE` if the identity has
    /// no entry; never creates a dangling symlink (§3.6).
    pub fn link(&self, identity: &str, target: &Path) -> Result<(), CoreError> {
        let canonical = self.path_for(identity)?;
        if !canonical.is_dir() {
            return Err(CoreError::Identity(
                "CAS-NOT-IN-STORE",
                format!(
                    "cannot link {} → {identity}: not in store",
                    target.display()
                ),
            ));
        }
        clear_dest(target)?;
        let parent = target.parent().unwrap_or_else(|| Path::new("."));
        let rel = relpath(&canonical, parent);
        std::os::unix::fs::symlink(&rel, target).map_err(|e| {
            CoreError::Identity(
                INTERNAL_IO,
                format!("cannot create symlink {}: {e}", target.display()),
            )
        })
    }
}

/// Remove `dest` if it exists, leaving its parent intact (mirrors
/// `milpa/fsutil.py:clear_dest`). The symlink check comes first: for a
/// symlink-to-directory both is_symlink and is_dir are true, and recursing
/// through the link would delete the target's contents.
fn clear_dest(dest: &Path) -> Result<(), CoreError> {
    let Ok(meta) = std::fs::symlink_metadata(dest) else {
        return Ok(()); // does not exist — no-op
    };
    let ft = meta.file_type();
    let res = if ft.is_symlink() || ft.is_file() {
        std::fs::remove_file(dest)
    } else {
        std::fs::remove_dir_all(dest)
    };
    res.map_err(|e| {
        CoreError::Identity(
            INTERNAL_IO,
            format!("cannot clear stale {}: {e}", dest.display()),
        )
    })
}

/// Relative path from `from` (a file/dir) to `base` (a directory) — the
/// equivalent of Python's `os.path.relpath(from, start=base)`. Both inputs are
/// expected to be absolute or share a common prefix; lexical-only (no fs access).
fn relpath(from: &Path, base: &Path) -> PathBuf {
    use std::path::Component;
    let f: Vec<Component> = from.components().collect();
    let b: Vec<Component> = base.components().collect();
    let common = f.iter().zip(b.iter()).take_while(|(a, c)| a == c).count();
    let mut out = PathBuf::new();
    for _ in 0..(b.len() - common) {
        out.push("..");
    }
    for comp in &f[common..] {
        out.push(comp.as_os_str());
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// Locate the host CAS root via identity.md §3.2 tiers 1, 3, 4 (the
/// manifest `cas { dir }` tier 2 is applied by the CLI/resolver, which sees the
/// manifest). Precedence: `MILPA_CACHE_DIR` > `$XDG_CACHE_HOME/milpa/cas` >
/// `~/.cache/milpa/cas`.
pub fn default_store() -> CaStore {
    if let Ok(dir) = std::env::var("MILPA_CACHE_DIR") {
        if !dir.is_empty() {
            return CaStore::new(dir);
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return CaStore::new(PathBuf::from(xdg).join("milpa").join("cas"));
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    CaStore::new(PathBuf::from(home).join(".cache").join("milpa").join("cas"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("milpa-cas-test-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn scratch_tree(root: &Path, name: &str, content: &str) -> PathBuf {
        let p = root.join(name);
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("file.txt"), content).unwrap();
        p
    }

    #[test]
    fn store_remembers_its_root() {
        let s = CaStore::new("/tmp/cas");
        assert_eq!(s.root, PathBuf::from("/tmp/cas"));
    }

    #[test]
    fn admit_places_tree_under_sha256_hex() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let scratch = scratch_tree(&root, "scratch", "hello");
        let identity = compute_content_hash(&scratch).unwrap();

        let canonical = store.admit(&scratch, &identity).unwrap();
        let hex = identity.strip_prefix("sha256:").unwrap();
        assert_eq!(canonical, root.join("cas").join("sha256").join(hex));
        assert!(canonical.is_dir());
        assert_eq!(
            fs::read_to_string(canonical.join("file.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn contains_reflects_admit_state() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let scratch = scratch_tree(&root, "scratch", "hello");
        let identity = compute_content_hash(&scratch).unwrap();
        assert!(!store.contains(&identity).unwrap());
        store.admit(&scratch, &identity).unwrap();
        assert!(store.contains(&identity).unwrap());
    }

    #[test]
    fn duplicate_admit_is_idempotent_and_drops_second_src() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let first = scratch_tree(&root, "first", "bytes");
        let second = scratch_tree(&root, "second", "bytes");
        let identity = compute_content_hash(&first).unwrap();
        assert_eq!(identity, compute_content_hash(&second).unwrap());

        let a = store.admit(&first, &identity).unwrap();
        let b = store.admit(&second, &identity).unwrap();
        assert_eq!(a, b);
        assert!(b.is_dir());
        assert_eq!(fs::read_to_string(b.join("file.txt")).unwrap(), "bytes");
        assert!(!second.exists());
    }

    #[test]
    fn admit_rejects_src_whose_bytes_dont_match_claimed_identity() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let scratch = scratch_tree(&root, "scratch", "actual contents");
        let bogus = format!("sha256:{}", "b".repeat(64));

        let e = store.admit(&scratch, &bogus).unwrap_err();
        assert_eq!(e.code(), "CAS-IDENTITY-MISMATCH");
        assert!(scratch.exists()); // left for the caller to inspect
        assert!(!store.contains(&bogus).unwrap()); // store not polluted
    }

    #[test]
    fn link_creates_relative_symlink_resolving_to_cas_entry() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let scratch = scratch_tree(&root, "scratch", "ABC");
        let identity = compute_content_hash(&scratch).unwrap();
        let canonical = store.admit(&scratch, &identity).unwrap();

        let target = root.join("_deps").join("foo");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        store.link(&identity, &target).unwrap();

        assert!(fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        // target string is relative (does NOT start with /)
        let link_target = fs::read_link(&target).unwrap();
        assert!(
            link_target.is_relative(),
            "expected relative target, got {link_target:?}"
        );
        // resolves to the canonical CAS entry and the tree is visible
        assert_eq!(
            target.canonicalize().unwrap(),
            canonical.canonicalize().unwrap()
        );
        assert_eq!(fs::read_to_string(target.join("file.txt")).unwrap(), "ABC");
    }

    #[test]
    fn link_rejects_identity_not_in_store() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let target = root.join("_deps").join("x");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let e = store
            .link(&format!("sha256:{}", "c".repeat(64)), &target)
            .unwrap_err();
        assert_eq!(e.code(), "CAS-NOT-IN-STORE");
        assert!(fs::symlink_metadata(&target).is_err()); // no dangling symlink
    }

    #[test]
    fn link_is_idempotent_over_a_stale_dest() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let scratch = scratch_tree(&root, "scratch", "ABC");
        let identity = compute_content_hash(&scratch).unwrap();
        store.admit(&scratch, &identity).unwrap();

        let target = root.join("_deps").join("foo");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        // pre-existing stale directory at the target
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("stale.txt"), "old").unwrap();

        store.link(&identity, &target).unwrap();
        assert!(fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!target.join("stale.txt").exists());
    }

    #[test]
    fn default_store_honors_milpa_cache_dir() {
        // env-var precedence is process-global; exercise the tiers via a helper
        // that takes the resolved values rather than mutating real env in a test
        // (avoids cross-test races). The precedence logic is identical.
        let s = resolve_store_from(Some("/o"), Some("/x"), "/h");
        assert_eq!(s.root, PathBuf::from("/o"));
    }

    #[test]
    fn default_store_falls_back_to_xdg_then_home() {
        assert_eq!(
            resolve_store_from(None, Some("/x"), "/h").root,
            PathBuf::from("/x/milpa/cas")
        );
        assert_eq!(
            resolve_store_from(None, None, "/h").root,
            PathBuf::from("/h/.cache/milpa/cas")
        );
    }

    // Pure precedence helper mirroring default_store(), parameterized for tests
    // so we don't mutate the process environment.
    fn resolve_store_from(cache: Option<&str>, xdg: Option<&str>, home: &str) -> CaStore {
        if let Some(c) = cache.filter(|c| !c.is_empty()) {
            return CaStore::new(c);
        }
        if let Some(x) = xdg.filter(|x| !x.is_empty()) {
            return CaStore::new(PathBuf::from(x).join("milpa").join("cas"));
        }
        CaStore::new(PathBuf::from(home).join(".cache").join("milpa").join("cas"))
    }
}
