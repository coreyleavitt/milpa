//! [`FakeFetcher`] — a `milpa_core::FetcherRegistry` backed by a fixture's
//! `mocked-fetches/` tree (conformance-fixtures.md §2.3). For each fetch it:
//!   1. Records the `(name, url, ref)` call for fixture assertions.
//!   2. Delegates the actual fetch + CAS admit + symlink creation to
//!      [`milpa_core::CasAdmittingFetcher`] wrapping a
//!      [`milpa_core::MockedFetcher`] — the single source of truth for the
//!      stage → hash → admit → link orchestration (no parallel copy here).
//!
//! `FakeFetcher` is responsible ONLY for call recording; the transport and CAS
//! orchestration live entirely in `milpa-core`.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use milpa_core::{
    CaStore, CasAdmittingFetcher, FetchError, FetcherRegistry, MockedFetcher, Receipt,
};
use milpa_core::fetchers::fetch_local;
use milpa_types::Provenance;

/// Records each `(name, url, ref)` call so a fixture can assert fetch behavior
/// (e.g. that a conditional-excluded dep is never fetched).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FetchCall {
    pub name: String,
    pub url: String,
    pub ref_spec: String,
}

/// Fake fetcher: reads from `mocked-fetches/`, admits into a CAS, and symlinks
/// `_deps/<name>` → the store entry. Call recording is the only responsibility
/// of this type; the transport + CAS orchestration delegates to the inner
/// `CasAdmittingFetcher<MockedFetcher>` (single source of truth).
///
/// Local deps are NOT mocked — the real `fetch_local` is used with the path
/// rebased from `scratch_root` to `fixture_dir` (where the source tree lives).
pub struct FakeFetcher {
    inner: CasAdmittingFetcher<MockedFetcher>,
    calls: RefCell<Vec<FetchCall>>,
    /// The fixture directory: source trees for local deps live here.
    fixture_dir: PathBuf,
    /// The scratch root: the resolver computes local paths relative to
    /// `deps_dir.parent()` = scratch root. We rebase to `fixture_dir`.
    scratch_root: PathBuf,
}

impl FakeFetcher {
    pub fn new(
        mocked_fetches_dir: impl Into<PathBuf>,
        cas_root: impl Into<PathBuf>,
        fixture_dir: impl Into<PathBuf>,
        scratch_root: impl Into<PathBuf>,
    ) -> Self {
        let mocked_fetches_dir = mocked_fetches_dir.into();
        let cas_root = cas_root.into();
        // C-stage: CasAdmittingFetcher owns staging via CaStore::scratch() —
        // no external staging_root parameter needed.
        let inner = CasAdmittingFetcher::new(
            MockedFetcher::new(&mocked_fetches_dir),
            CaStore::new(cas_root),
        );
        FakeFetcher {
            inner,
            calls: RefCell::new(Vec::new()),
            fixture_dir: fixture_dir.into(),
            scratch_root: scratch_root.into(),
        }
    }

    /// The fetch calls recorded so far, in order.
    pub fn calls(&self) -> Vec<FetchCall> {
        self.calls.borrow().clone()
    }
}

impl FetcherRegistry for FakeFetcher {
    fn fetch(&self, name: &str, p: &Provenance, dest: &Path) -> Result<Receipt, FetchError> {
        match p {
            // Local deps: use the REAL fetch_local (no mock, no CAS admission).
            // The resolver already resolved the relative path against scratch_root;
            // rebase it to fixture_dir so it points at the in-fixture source tree.
            Provenance::Local { path } => {
                let abs_path = Path::new(path);
                // The resolver computes: project_root.join(dep.path) where
                // project_root = deps_dir.parent() = scratch_root.  Strip the
                // scratch_root prefix and re-join under fixture_dir.
                let rebased = if let Ok(rel) = abs_path.strip_prefix(&self.scratch_root) {
                    self.fixture_dir.join(rel)
                } else {
                    // Path was already absolute and not under scratch_root
                    // (e.g. someone passed an absolute fixture path directly).
                    abs_path.to_path_buf()
                };
                fetch_local(name, &rebased, dest)
            }

            // Git and tarball: delegate to the inner CasAdmittingFetcher<MockedFetcher>.
            // Record call only on success (mirrors old behaviour).
            Provenance::Git { url, ref_spec, .. } => {
                let receipt = self.inner.fetch(name, p, dest)?;
                self.calls.borrow_mut().push(FetchCall {
                    name: name.to_string(),
                    url: url.clone(),
                    ref_spec: ref_spec.clone(),
                });
                Ok(receipt)
            }
            Provenance::Tarball { url, .. } => {
                let receipt = self.inner.fetch(name, p, dest)?;
                self.calls.borrow_mut().push(FetchCall {
                    name: name.to_string(),
                    url: url.clone(),
                    ref_spec: String::new(),
                });
                Ok(receipt)
            }
            Provenance::Oci {
                registry,
                repository,
                digest,
                ..
            } => {
                let receipt = self.inner.fetch(name, p, dest)?;
                self.calls.borrow_mut().push(FetchCall {
                    name: name.to_string(),
                    url: format!("{registry}/{repository}"),
                    ref_spec: digest.clone(),
                });
                Ok(receipt)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urlkey::url_key;

    #[test]
    fn copies_content_and_returns_sha() {
        let tmp = tempfile::tempdir().unwrap();
        let mocked = tmp.path().join("mocked-fetches");
        let key = url_key("https://github.com/example/foo.git", "main");
        let key_dir = mocked.join(&key);
        std::fs::create_dir_all(key_dir.join("content")).unwrap();
        std::fs::write(
            key_dir.join("sha"),
            "abcdef1234567890abcdef1234567890abcdef12\n",
        )
        .unwrap();
        std::fs::write(key_dir.join("content").join("foo.nim"), b"# src").unwrap();
        std::fs::write(key_dir.join("foo.nimble"), b"version = \"1.0.0\"").unwrap();

        let fetcher = FakeFetcher::new(&mocked, tmp.path().join(".cas"), tmp.path(), tmp.path());
        // The resolver guarantees `_deps/` exists before fetch; mirror that.
        std::fs::create_dir_all(tmp.path().join("_deps")).unwrap();
        let dest = tmp.path().join("_deps").join("foo");
        let p = Provenance::Git {
            url: "https://github.com/example/foo.git".into(),
            ref_spec: "main".into(),
            commit_sha: None,
        };
        let receipt = FetcherRegistry::fetch(&fetcher, "foo", &p, &dest).unwrap();

        assert_eq!(
            receipt.resolved_ref.as_deref(),
            Some("abcdef1234567890abcdef1234567890abcdef12")
        );
        // dest is now a CAS symlink; reads follow it into the store.
        assert!(std::fs::symlink_metadata(&dest)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(dest.join("foo.nim")).unwrap(), b"# src");
        // The `.nimble` is materialized at the tree root (and IS hashed).
        assert!(dest.join("foo.nimble").is_file());
        assert_eq!(fetcher.calls().len(), 1);
        assert_eq!(fetcher.calls()[0].name, "foo");
    }

    #[test]
    fn missing_mock_is_fetch_mock_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let fetcher = FakeFetcher::new(tmp.path().join("mocked-fetches"), tmp.path().join(".cas"), tmp.path(), tmp.path());
        let p = Provenance::Git {
            url: "https://example.com/x.git".into(),
            ref_spec: "main".into(),
            commit_sha: None,
        };
        let err = FetcherRegistry::fetch(&fetcher, "x", &p, &tmp.path().join("dest")).unwrap_err();
        // Production code emits FETCH-MOCK-MISSING (not the old FETCH-FAILED).
        assert_eq!(err.code(), "FETCH-MOCK-MISSING");
    }

    fn stage_tarball_mock(mocked: &Path, url: &str, archive_sha: &str) {
        let key_dir = mocked.join(url_key(url, ""));
        std::fs::create_dir_all(key_dir.join("content")).unwrap();
        std::fs::write(key_dir.join("archive_sha256"), format!("{archive_sha}\n")).unwrap();
        std::fs::write(key_dir.join("content").join("foo.nim"), b"# src").unwrap();
    }

    #[test]
    fn tarball_mock_returns_archive_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let mocked = tmp.path().join("mocked-fetches");
        let url = "https://example.com/foo.tar.gz";
        stage_tarball_mock(&mocked, url, "abc123");
        let fetcher = FakeFetcher::new(&mocked, tmp.path().join(".cas"), tmp.path(), tmp.path());
        std::fs::create_dir_all(tmp.path().join("_deps")).unwrap();
        let dest = tmp.path().join("_deps").join("foo");
        let p = Provenance::Tarball {
            url: url.into(),
            expected_sha256: None,
            strip_components: 0,
        };
        let receipt = FetcherRegistry::fetch(&fetcher, "foo", &p, &dest).unwrap();
        assert_eq!(receipt.archive_sha256.as_deref(), Some("abc123"));
        assert_eq!(std::fs::read(dest.join("foo.nim")).unwrap(), b"# src");
        assert_eq!(fetcher.calls()[0].url, url);
    }

    #[test]
    fn tarball_mock_pin_mismatch_is_sha256_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let mocked = tmp.path().join("mocked-fetches");
        let url = "https://example.com/foo.tar.gz";
        stage_tarball_mock(&mocked, url, "actual_sha");
        let fetcher = FakeFetcher::new(&mocked, tmp.path().join(".cas"), tmp.path(), tmp.path());
        std::fs::create_dir_all(tmp.path().join("_deps")).unwrap();
        let dest = tmp.path().join("_deps").join("foo");
        let p = Provenance::Tarball {
            url: url.into(),
            expected_sha256: Some("declared_sha".into()),
            strip_components: 0,
        };
        let err = FetcherRegistry::fetch(&fetcher, "foo", &p, &dest).unwrap_err();
        assert_eq!(err.code(), "FETCH-SHA256-MISMATCH");
    }
}
