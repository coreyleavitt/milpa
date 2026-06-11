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
pub struct FakeFetcher {
    inner: CasAdmittingFetcher<MockedFetcher>,
    calls: RefCell<Vec<FetchCall>>,
}

impl FakeFetcher {
    pub fn new(mocked_fetches_dir: impl Into<PathBuf>, cas_root: impl Into<PathBuf>) -> Self {
        let mocked_fetches_dir = mocked_fetches_dir.into();
        let cas_root = cas_root.into();
        // staging_root: parent of cas_root keeps staging on the same filesystem
        // as the CAS so that admit()'s rename(2) is atomic.
        let staging_root = cas_root
            .parent()
            .unwrap_or(&cas_root)
            .to_path_buf();
        let inner = CasAdmittingFetcher::new(
            MockedFetcher::new(&mocked_fetches_dir),
            CaStore::new(cas_root),
            staging_root,
        );
        FakeFetcher {
            inner,
            calls: RefCell::new(Vec::new()),
        }
    }

    /// The fetch calls recorded so far, in order.
    pub fn calls(&self) -> Vec<FetchCall> {
        self.calls.borrow().clone()
    }
}

impl FetcherRegistry for FakeFetcher {
    fn fetch(&self, name: &str, p: &Provenance, dest: &Path) -> Result<Receipt, FetchError> {
        // The conformance corpus mocks git provenance exclusively (§2.3).
        let (url, ref_spec) = match p {
            Provenance::Git { url, ref_spec, .. } => (url.as_str(), ref_spec.as_str()),
            other => {
                return Err(FetchError::Failed(format!(
                    "FakeFetcher: unmocked provenance kind: {other:?}"
                )));
            }
        };

        // Delegate the full stage → hash → admit → link orchestration to the
        // inner CasAdmittingFetcher<MockedFetcher> (single source of truth).
        // Record the call only on success so that missing-key errors (which
        // the inner fetcher will surface as FETCH-MOCK-MISSING) don't produce
        // a spurious call record — mirrors the old FakeFetcher behaviour.
        let receipt = self.inner.fetch(name, p, dest)?;
        self.calls.borrow_mut().push(FetchCall {
            name: name.to_string(),
            url: url.to_string(),
            ref_spec: ref_spec.to_string(),
        });
        Ok(receipt)
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

        let fetcher = FakeFetcher::new(&mocked, tmp.path().join(".cas"));
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
        let fetcher = FakeFetcher::new(tmp.path().join("mocked-fetches"), tmp.path().join(".cas"));
        let p = Provenance::Git {
            url: "https://example.com/x.git".into(),
            ref_spec: "main".into(),
            commit_sha: None,
        };
        let err = FetcherRegistry::fetch(&fetcher, "x", &p, &tmp.path().join("dest")).unwrap_err();
        // Production code emits FETCH-MOCK-MISSING (not the old FETCH-FAILED).
        assert_eq!(err.code(), "FETCH-MOCK-MISSING");
    }
}
