//! Shared atomic-write primitives for content-addressed / cache stores.
//!
//! Single source of truth for the per-write-unique-temp-name write pattern
//! used by every fetch-or-cache store in milpa: [`crate::index_cache`]
//! (index + bundle + baseline sidecars), [`crate::dep_decl_store`]
//! (`HttpDepDeclStore`), and [`crate::entry_bundle_store`]
//! (`HttpEntryBundleStore`).
//!
//! registry-protocol §3.5.2 NORMATIVE (concurrency): a FIXED temp sibling
//! name lets two concurrent writers interleave partial writes before either
//! renames — if one writer crashes mid-write, the OTHER writer's rename can
//! land a truncated/interleaved file at the final path. For a
//! content-addressed cache keyed by a hash pin, that produces a poisoned
//! entry: the next read fails hash verification with a hard,
//! non-self-healing error even though both writers were fetching genuine
//! content. Every write in the stores named above MUST go through this
//! module (directly, or via [`atomic_write_bytes`]) so no call site can
//! regress to a fixed name.
//!
//! Mirrors `impls/python/milpa/atomic_cache.py`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A per-write-unique sibling temp path for `path` (PID + wall-clock nanos +
/// a process-local monotonic counter).
///
/// The atomic-rename safety property does not depend on cryptographic
/// randomness, only on no two concurrent writers choosing the SAME temp
/// name — PID + a process-local monotonic counter + nanosecond timestamp is
/// sufficient. Mirrors `atomic_cache.py::unique_temp_path` (PID + random
/// suffix).
static TEMP_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn unique_temp_path(path: &Path) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = TEMP_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = path.as_os_str().to_os_string();
    p.push(format!(".tmp.{pid}.{nanos}.{counter}"));
    PathBuf::from(p)
}

/// Write `data` to `path` atomically (unique sibling tmp + rename).
///
/// On failure, the temp file is best-effort removed and the `io::Error` is
/// returned. Callers that want a write failure to be non-fatal (e.g. "the
/// bytes were already hash-verified; a cache-write error shouldn't fail the
/// whole operation") should map/ignore the `Err` at the call site — this
/// function always surfaces the error rather than silently swallowing it, so
/// that decision stays visible at each caller.
pub fn atomic_write_bytes(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = unique_temp_path(path);
    // CR19: clean up the temp file on ANY failure — both the write itself
    // (disk full / quota — the earlier fix only cleaned up on rename
    // failure) and the rename — before propagating the original error.
    // Mirrors `atomic_cache.py::atomic_write_bytes`, which already cleans up
    // on both branches.
    if let Err(e) = std::fs::write(&tmp, data) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e
    })
}

/// Read+verify a cached file, self-healing a locally-corrupt entry (CR16).
///
/// This is the SHARED cached-read half of the fetch-or-cache pattern (the
/// write half is [`atomic_write_bytes`] above). Both `HttpDepDeclStore` and
/// `HttpEntryBundleStore` fetch-or-cache an immutable, hash-pinned artifact;
/// both need identical cached-read behavior, so it lives here once.
/// Mirrors `atomic_cache.py::read_verified_or_self_heal`.
///
/// Behavior:
/// - Cache miss (file absent, or unreadable) → `None` (caller falls through
///   to fetch).
/// - Cache hit, `verify_fn(bytes)` returns `Err` → the file is a locally
///   corrupt entry (e.g. a truncated write left behind by the
///   pre-unique-temp-name concurrency race, or plain disk corruption).
///   Self-heal: remove it and return `None` so the caller re-fetches,
///   rather than a permanent hard failure.
/// - Cache hit, `verify_fn(bytes)` returns `Ok` → the verified bytes.
///
/// CRITICAL INVARIANT: self-heal applies ONLY to this cached-read path. A
/// verify failure on bytes the caller just fetched fresh from the network
/// (the server genuinely served the wrong content) MUST NOT go through this
/// function — that call site invokes its own verify directly (via `?`) and
/// lets the error propagate as a hard error. Routing freshly-fetched bytes
/// through this function would silently discard evidence of a real
/// delivery-path/server compromise.
pub fn read_verified_or_self_heal<E>(
    cache_path: &Path,
    verify_fn: impl FnOnce(&[u8]) -> Result<(), E>,
) -> Option<Vec<u8>> {
    let cached = std::fs::read(cache_path).ok()?;
    match verify_fn(&cached) {
        Ok(()) => Some(cached),
        Err(_) => {
            // Locally-corrupt cache entry: self-heal by discarding it.
            let _ = std::fs::remove_file(cache_path);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_temp_path_never_repeats() {
        let target = Path::new("/nonexistent/dir/some.artifact");
        let mut names = std::collections::HashSet::new();
        for _ in 0..200 {
            names.insert(unique_temp_path(target));
        }
        assert_eq!(names.len(), 200, "temp sibling names must be per-write-unique, not fixed");
    }

    #[test]
    fn two_interleaved_writers_never_tear() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let target = tmp_dir.path().join("shared.artifact");
        let content_a = vec![b'A'; 5000];
        let content_b = vec![b'B'; 5000];

        let tmp_a = unique_temp_path(&target);
        let tmp_b = unique_temp_path(&target);
        assert_ne!(tmp_a, tmp_b, "two writers must not share a temp sibling");

        std::fs::write(&tmp_a, &content_a).unwrap();
        std::fs::write(&tmp_b, &content_b).unwrap();
        assert_eq!(std::fs::read(&tmp_a).unwrap(), content_a);
        assert_eq!(std::fs::read(&tmp_b).unwrap(), content_b);
    }

    #[test]
    fn atomic_write_bytes_round_trips() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let target = tmp_dir.path().join("out.bin");
        atomic_write_bytes(&target, b"hello world").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello world");
    }

    #[test]
    fn atomic_write_bytes_leaves_no_temp_on_success() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let target = tmp_dir.path().join("out.bin");
        atomic_write_bytes(&target, b"payload").unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(tmp_dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p != &target)
            .collect();
        assert!(leftovers.is_empty(), "leftover files: {leftovers:?}");
    }

    #[test]
    fn atomic_write_bytes_failure_returns_err() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let target = tmp_dir.path().join("nonexistent-subdir").join("out.bin");
        assert!(atomic_write_bytes(&target, b"payload").is_err());
        assert!(!target.exists());
    }

    // -----------------------------------------------------------------------
    // CR19 — temp-file cleanup on ANY failure (write OR rename), not just
    // rename. The write path can't be forced to fail deterministically after
    // partially creating the temp file (no disk-full/quota simulation
    // available here — the temp filename embeds a live PID+nanos+counter we
    // can't precompute to pre-seed a conflicting inode), so this test locks
    // the RENAME-failure cleanup path, and the write-failure branch is a
    // symmetric code-level guarantee (see `atomic_write_bytes` above: both
    // branches now call the identical `remove_file` best-effort cleanup
    // before propagating the error — mirrors `atomic_cache.py`, which cleans
    // up on both branches with one shared `except OSError` block).
    // -----------------------------------------------------------------------

    #[test]
    fn atomic_write_bytes_rename_failure_cleans_up_temp() {
        let tmp_dir = tempfile::tempdir().unwrap();
        // Make the target path itself an existing, non-empty directory so
        // that `fs::rename(tmp, target)` fails (can't rename a file onto a
        // directory) — this forces the RENAME branch to error out after the
        // WRITE has already succeeded (the temp file exists on disk).
        let target = tmp_dir.path().join("target_is_a_dir");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("occupant"), b"keeps dir non-empty").unwrap();

        let result = atomic_write_bytes(&target, b"payload");
        assert!(result.is_err(), "rename onto an existing directory must fail");

        // No `.tmp.` sibling should remain in tmp_dir after the failure.
        let leftovers: Vec<_> = std::fs::read_dir(tmp_dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p != &target)
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp file must be cleaned up on rename failure, found: {leftovers:?}"
        );
    }

    // -----------------------------------------------------------------------
    // CR16 — read_verified_or_self_heal
    // -----------------------------------------------------------------------

    #[test]
    fn read_verified_or_self_heal_absent_file_is_cache_miss() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let cache_path = tmp_dir.path().join("missing.bin");
        let got = read_verified_or_self_heal(&cache_path, |_: &[u8]| -> Result<(), ()> { Ok(()) });
        assert!(got.is_none());
    }

    #[test]
    fn read_verified_or_self_heal_valid_bytes_returned() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let cache_path = tmp_dir.path().join("valid.bin");
        std::fs::write(&cache_path, b"good bytes").unwrap();

        let got = read_verified_or_self_heal(&cache_path, |b: &[u8]| -> Result<(), ()> {
            if b == b"good bytes" {
                Ok(())
            } else {
                Err(())
            }
        });
        assert_eq!(got, Some(b"good bytes".to_vec()));
        assert!(cache_path.is_file(), "a valid entry must not be removed");
    }

    #[test]
    fn read_verified_or_self_heal_corrupt_bytes_unlinked_and_none() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let cache_path = tmp_dir.path().join("corrupt.bin");
        std::fs::write(&cache_path, b"corrupt garbage").unwrap();

        let got = read_verified_or_self_heal(&cache_path, |b: &[u8]| -> Result<(), ()> {
            if b == b"good bytes" {
                Ok(())
            } else {
                Err(())
            }
        });
        assert!(got.is_none());
        assert!(
            !cache_path.is_file(),
            "a locally-corrupt cache entry must be self-healed (unlinked)"
        );
    }
}
