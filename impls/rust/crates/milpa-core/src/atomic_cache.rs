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
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e
    })
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
}
