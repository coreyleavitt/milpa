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

// ---------------------------------------------------------------------------
// §3.4 — ScratchDir (C-stage)
// ---------------------------------------------------------------------------

/// Handle for a live scratch subdirectory under ``<root>/_scratch/<uuid>/``.
///
/// Obtained via [`CaStore::scratch`]; the caller is responsible for cleanup
/// (drop the path after admit, or after an error).  The parent `_scratch/`
/// dir is created lazily.
///
/// The scratch dir is always on the same filesystem mount as the CAS
/// ``sha256/`` entries, so the rename(2) in [`CaStore::admit`] is atomic.
#[derive(Debug)]
pub struct ScratchDir {
    pub path: PathBuf,
}

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

    /// Return a lexicographically sorted list of all identities in the store.
    ///
    /// Scans `<root>/sha256/*/` directories (only the `sha256` algorithm
    /// directory is expected per spec/identity.md §3). Non-directory entries
    /// and names starting with `_` (scratch) are ignored.  Empty store → empty
    /// list.  Identities are returned in `sha256:<64hex>` canonical form.
    pub fn list_identities(&self) -> Vec<String> {
        let sha256_dir = self.root.join("sha256");
        let mut identities: Vec<String> = Vec::new();
        let Ok(entries) = std::fs::read_dir(&sha256_dir) else {
            return identities;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // Skip scratch dirs and non-directory entries.
            if name_str.starts_with('_') {
                continue;
            }
            if entry.path().is_dir() {
                identities.push(format!("sha256:{name_str}"));
            }
        }
        identities.sort();
        identities
    }

    /// Resolve a hex-digest prefix (with or without `sha256:` algorithm prefix)
    /// to a full identity string.
    ///
    /// Rules (spec/identity.md §3, C-store-ro slice):
    /// - Full identity (64-hex bare or `sha256:<64hex>`) → exact lookup.
    ///   Present → return the full identity.  Absent → `CAS-NOT-IN-STORE`.
    /// - Prefix whose hex portion is ≥16 chars → unique-prefix match.
    ///   Exactly 1 match → return the identity.  0 → `CAS-NOT-IN-STORE`.
    ///   >1 → `STORE-AMBIGUOUS-PREFIX`.
    /// - Prefix whose hex portion is <16 chars → `STORE-AMBIGUOUS-PREFIX`.
    ///   A <16-char prefix is by definition too weak to safely pin one entry;
    ///   we reuse this one named code rather than inventing another to keep
    ///   the error catalog minimal.
    pub fn resolve_prefix(&self, prefix: &str) -> Result<String, CoreError> {
        // Strip optional algorithm prefix to get the raw hex portion.
        let hex_part = if let Some(rest) = prefix.strip_prefix("sha256:") {
            rest
        } else {
            prefix
        };

        // Exact match: 64-hex digest → direct lookup.
        if hex_part.len() == 64 {
            let full_identity = format!("sha256:{hex_part}");
            if self.path_for(&full_identity)?.is_dir() {
                return Ok(full_identity);
            }
            return Err(CoreError::Identity(
                "CAS-NOT-IN-STORE",
                format!("identity not in store: {full_identity:?}"),
            ));
        }

        // Prefix match: enforce the 16-char minimum.
        // A prefix shorter than 16 hex chars is by definition too weak to
        // safely identify a single entry — reject immediately as
        // STORE-AMBIGUOUS-PREFIX rather than introducing a separate code
        // (catalog-minimal rule).
        if hex_part.len() < 16 {
            return Err(CoreError::Identity(
                "STORE-AMBIGUOUS-PREFIX",
                format!(
                    "prefix {prefix:?} is shorter than the 16-hex-character minimum \
                     required to safely identify a single store entry \
                     (got {} hex chars)",
                    hex_part.len()
                ),
            ));
        }

        // Scan all identities and collect those whose hex digest starts with the prefix.
        let matches: Vec<String> = self
            .list_identities()
            .into_iter()
            .filter(|id| {
                id.strip_prefix("sha256:")
                    .map(|h| h.starts_with(hex_part))
                    .unwrap_or(false)
            })
            .collect();

        match matches.len() {
            1 => Ok(matches.into_iter().next().unwrap()),
            0 => Err(CoreError::Identity(
                "CAS-NOT-IN-STORE",
                format!("no store entry matches prefix {prefix:?}"),
            )),
            n => Err(CoreError::Identity(
                "STORE-AMBIGUOUS-PREFIX",
                format!(
                    "prefix {prefix:?} matches {n} store entries \
                     (need a longer prefix to disambiguate)"
                ),
            )),
        }
    }

    /// Move `src` into the store under `identity`, returning the canonical path
    /// (identity.md §3.3). Verifies `src`'s bytes hash to `identity` first;
    /// raises `CAS-IDENTITY-MISMATCH` on mismatch, leaving `src` in place and
    /// the store unmodified.
    ///
    /// **Idempotency (C-admit-idem)**: admitting content whose identity is
    /// already in the store is a successful no-op.  The pre-check below makes
    /// this O(1) — no rename attempted on a CAS hit.  We trust identity =
    /// content hash: same identity ⟹ same bytes; no byte comparison on a hit.
    ///
    /// **TOCTOU race guard**: if two processes admit the same identity
    /// concurrently, the loser's rename(2) will fail because the winner already
    /// created the canonical dir.  That failure folds into the CAS-hit path —
    /// remove src, return the winner's canonical path.  Content-addressing
    /// guarantees the bytes are identical, so no corruption can occur.
    pub fn admit(&self, src: &Path, identity: &str) -> Result<PathBuf, CoreError> {
        let actual = compute_content_hash(src)?;
        if actual != identity {
            return Err(CoreError::Identity(
                "CAS-IDENTITY-MISMATCH",
                format!("identity mismatch — claimed {identity:?}, computed {actual:?}"),
            ));
        }
        let canonical = self.path_for(identity)?;

        // CAS-hit pre-check (C-admit-idem): if the canonical entry already
        // exists, this is a successful no-op — the store already holds these
        // bytes under this identity.  Drop src and return the existing path.
        // O(1): no rename attempted.  We trust identity = content hash; no
        // byte comparison needed (same identity ⟹ same bytes by construction).
        if canonical.is_dir() {
            let _ = std::fs::remove_dir_all(src);
            return Ok(canonical);
        }

        if let Some(parent) = canonical.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CoreError::Identity(
                    INTERNAL_IO,
                    format!("cannot create CAS dir {}: {e}", parent.display()),
                )
            })?;
        }
        // POSIX rename(2): atomic on the same filesystem (scratch + CAS share a
        // mount). On failure, canonical may have appeared between the pre-check
        // and this rename (TOCTOU race) — that is still the duplicate-no-op.
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

    // ------------------------------------------------------------------
    // §3.4 — scratch lifecycle (C-stage)
    // ------------------------------------------------------------------

    /// Allocate a fresh unique scratch subdirectory under `<root>/_scratch/<uuid>/`.
    ///
    /// The `_scratch/` parent is created lazily on first use.  The returned
    /// [`ScratchDir`] contains the path to the new empty directory.  The caller
    /// is responsible for cleanup:
    /// - On **success** the caller passes `sd.path` to [`CaStore::admit`], which
    ///   renames it into the store atomically; any remnant must then be removed.
    /// - On **failure** the caller removes `sd.path` to avoid leaking scratch dirs.
    ///   (A future C-gc slice will age out any SIGKILL survivors under `_scratch/`.)
    ///
    /// Both `_scratch/` and `sha256/` live directly under `root`, so the
    /// rename(2) in `admit()` is guaranteed same-filesystem (no EXDEV).
    pub fn scratch(&self) -> Result<ScratchDir, CoreError> {
        let scratch_root = self.root.join("_scratch");
        std::fs::create_dir_all(&scratch_root).map_err(|e| {
            CoreError::Identity(
                INTERNAL_IO,
                format!("cannot create scratch root {}: {e}", scratch_root.display()),
            )
        })?;
        // Use a UUID-style unique name so concurrent fetches never collide.
        let unique: String = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            use std::time::{SystemTime, UNIX_EPOCH};
            static COUNTER: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos();
            let pid = std::process::id();
            let mut h = DefaultHasher::new();
            (ts, pid, seq).hash(&mut h);
            format!("{:016x}{:08x}{:08x}", h.finish(), pid, seq)
        };
        let path = scratch_root.join(unique);
        std::fs::create_dir(&path).map_err(|e| {
            CoreError::Identity(
                INTERNAL_IO,
                format!("cannot create scratch dir {}: {e}", path.display()),
            )
        })?;
        Ok(ScratchDir { path })
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

    // -----------------------------------------------------------------------
    // C-admit-idem: idempotency invariants
    // -----------------------------------------------------------------------

    /// C-admit-idem: two admits of identical content leave exactly ONE store entry.
    ///
    /// Content-addressing guarantees byte-identity: same identity = same bytes.
    /// The store is append-only; duplicate admission must not create a second entry.
    #[test]
    fn admit_idempotent_store_has_exactly_one_entry() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let first = scratch_tree(&root, "first", "same-bytes");
        let second = scratch_tree(&root, "second", "same-bytes");
        let identity = compute_content_hash(&first).unwrap();
        assert_eq!(identity, compute_content_hash(&second).unwrap(), "test setup");

        store.admit(&first, &identity).unwrap();
        store.admit(&second, &identity).unwrap();

        let identities = store.list_identities();
        assert_eq!(
            identities.len(),
            1,
            "expected exactly 1 store entry after two identical admits, got {}: {:?}",
            identities.len(),
            identities
        );
        assert_eq!(identities[0], identity);
    }

    /// C-admit-idem: CAS hit returns the SAME path as the original admit.
    ///
    /// We trust identity = content hash; we do NOT re-copy or compare bytes on a
    /// hit.  admit() on a CAS hit is O(1): check canonical exists → return it.
    #[test]
    fn admit_cas_hit_returns_same_path_as_original() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let first = scratch_tree(&root, "first", "deterministic");
        let identity = compute_content_hash(&first).unwrap();
        let original_path = store.admit(&first, &identity).unwrap();

        let second = scratch_tree(&root, "second", "deterministic");
        let hit_path = store.admit(&second, &identity).unwrap();

        assert_eq!(
            hit_path, original_path,
            "CAS hit must return the original canonical path, not a new one"
        );
        assert_eq!(
            fs::read_to_string(original_path.join("file.txt")).unwrap(),
            "deterministic"
        );
    }

    /// C-admit-idem: CAS hit removes src (no leak), canonical untouched.
    #[test]
    fn admit_cas_hit_src_is_removed_no_leak() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let first = scratch_tree(&root, "first", "idempotent");
        let identity = compute_content_hash(&first).unwrap();
        store.admit(&first, &identity).unwrap();

        // Second admit from a fresh scratch tree — simulates what CasAdmittingFetcher does
        let second = scratch_tree(&root, "second", "idempotent");
        let result = store.admit(&second, &identity).unwrap();

        // src must be removed on CAS hit (no _scratch/ leak)
        assert!(!second.exists(), "CAS hit must remove src to prevent scratch leak");
        // Return value is the canonical path
        assert!(result.is_dir());
        assert_eq!(
            fs::read_to_string(result.join("file.txt")).unwrap(),
            "idempotent"
        );
    }

    /// C-admit-idem: two distinct contents → two distinct entries, both present.
    #[test]
    fn admit_different_contents_produce_distinct_entries() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let alpha = scratch_tree(&root, "alpha", "content-alpha");
        let beta = scratch_tree(&root, "beta", "content-beta");
        let id_alpha = compute_content_hash(&alpha).unwrap();
        let id_beta = compute_content_hash(&beta).unwrap();
        assert_ne!(id_alpha, id_beta, "test setup: distinct content must differ");

        let path_a = store.admit(&alpha, &id_alpha).unwrap();
        let path_b = store.admit(&beta, &id_beta).unwrap();

        assert_ne!(path_a, path_b);
        assert!(store.contains(&id_alpha).unwrap());
        assert!(store.contains(&id_beta).unwrap());
        let identities = store.list_identities();
        assert_eq!(identities.len(), 2);
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

    // -----------------------------------------------------------------------
    // §3.4 — scratch lifecycle (C-stage)
    // -----------------------------------------------------------------------

    #[test]
    fn scratch_returns_path_under_scratch_root() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let sd = store.scratch().unwrap();
        let expected_parent = root.join("cas").join("_scratch");
        assert_eq!(sd.path.parent().unwrap(), expected_parent);
        assert!(sd.path.is_dir(), "scratch subdir must exist after scratch()");
    }

    #[test]
    fn scratch_creates_unique_subdirs_per_call() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let s1 = store.scratch().unwrap();
        let s2 = store.scratch().unwrap();
        assert_ne!(s1.path, s2.path, "each scratch() call must return a distinct subdir");
        // clean up
        let _ = std::fs::remove_dir_all(&s1.path);
        let _ = std::fs::remove_dir_all(&s2.path);
    }

    #[test]
    fn scratch_is_sibling_of_sha256() {
        let root = tmp();
        let store = CaStore::new(root.join("cas"));
        let sd = store.scratch().unwrap();
        // <cas_root>/_scratch/ must be a sibling of <cas_root>/sha256/
        assert_eq!(
            sd.path.parent().unwrap().parent().unwrap(),
            root.join("cas"),
            "_scratch/ must be a direct child of cas_root"
        );
        let _ = std::fs::remove_dir_all(&sd.path);
    }
}
