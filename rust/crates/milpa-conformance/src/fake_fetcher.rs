//! [`FakeFetcher`] — a `milpa_core::Fetcher` backed by a fixture's
//! `mocked-fetches/` tree (conformance-fixtures.md §2.3). One impl of the real
//! `Fetcher` trait, so it proves the trait shape and is injected exactly where a
//! real transport would be. For each fetch it:
//!   1. encodes `(url, ref)` to the subdirectory key (`urlkey`),
//!   2. reads `<key>/sha` (the returned commit SHA),
//!   3. copies `<key>/content/` verbatim into `dest`,
//!   4. copies `<key>/<name>.nimble` into `dest` if present,
//!   5. returns a `Receipt` carrying the SHA.
//!
//! It never reports an identity — identity is computed by the caller from the
//! materialized bytes (RFC §4.6), so a fake cannot lie about content.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use milpa_core::{FetchError, Fetcher, FetcherRegistry, Receipt};
use milpa_types::Provenance;

use crate::urlkey::url_key;

/// Records each `(name, url, ref)` call so a fixture can assert fetch behavior
/// (e.g. that a conditional-excluded dep is never fetched).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FetchCall {
    pub name: String,
    pub url: String,
    pub ref_spec: String,
}

/// Fake fetcher reading mocked returns from `mocked-fetches/`.
pub struct FakeFetcher {
    mocked_fetches_dir: PathBuf,
    calls: RefCell<Vec<FetchCall>>,
}

impl FakeFetcher {
    pub fn new(mocked_fetches_dir: impl Into<PathBuf>) -> Self {
        FakeFetcher {
            mocked_fetches_dir: mocked_fetches_dir.into(),
            calls: RefCell::new(Vec::new()),
        }
    }

    /// The fetch calls recorded so far, in order.
    pub fn calls(&self) -> Vec<FetchCall> {
        self.calls.borrow().clone()
    }
}

impl Fetcher for FakeFetcher {
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

        let key_dir = self.mocked_fetches_dir.join(url_key(url, ref_spec));
        if !key_dir.is_dir() {
            return Err(FetchError::Failed(format!(
                "FakeFetcher: no mock for {url:?} @ {ref_spec:?} (expected dir: {})",
                key_dir.display()
            )));
        }

        let sha = std::fs::read_to_string(key_dir.join("sha"))
            .map_err(|e| FetchError::Failed(format!("FakeFetcher: cannot read sha: {e}")))?
            .trim()
            .to_string();

        self.calls.borrow_mut().push(FetchCall {
            name: name.to_string(),
            url: url.to_string(),
            ref_spec: ref_spec.to_string(),
        });

        std::fs::create_dir_all(dest)
            .map_err(|e| FetchError::Failed(format!("FakeFetcher: cannot create dest: {e}")))?;

        // Copy the content/ tree verbatim (§2.3.2). It is the identity ground
        // truth, so a byte-exact copy is required.
        let content = key_dir.join("content");
        if content.is_dir() {
            copy_tree(&content, dest)
                .map_err(|e| FetchError::Failed(format!("FakeFetcher: copy content: {e}")))?;
        }

        // The dep's own `<name>.nimble` lives beside content/ as an authoring
        // convenience; it is materialized at the tree root and IS hashed (§2.3.2).
        let nimble = key_dir.join(format!("{name}.nimble"));
        if nimble.is_file() {
            std::fs::copy(&nimble, dest.join(format!("{name}.nimble")))
                .map_err(|e| FetchError::Failed(format!("FakeFetcher: copy nimble: {e}")))?;
        }

        Ok(Receipt {
            resolved_ref: Some(sha),
        })
    }
}

/// The fake mocks every transport from one `mocked-fetches/` tree, so it *is*
/// the whole registry in a fixture run — there is nothing to dispatch between.
/// (The real `FetcherRegistry` that routes a `Provenance` to a per-transport
/// `Fetcher` lands in S14, where the real transports it dispatches to exist.)
impl FetcherRegistry for FakeFetcher {
    fn fetch(&self, name: &str, p: &Provenance, dest: &Path) -> Result<Receipt, FetchError> {
        Fetcher::fetch(self, name, p, dest)
    }
}

/// Recursively copy the contents of `src` into `dst` (both must be dirs).
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let fetcher = FakeFetcher::new(&mocked);
        let dest = tmp.path().join("dest");
        let p = Provenance::Git {
            url: "https://github.com/example/foo.git".into(),
            ref_spec: "main".into(),
            commit_sha: None,
        };
        let receipt = Fetcher::fetch(&fetcher, "foo", &p, &dest).unwrap();

        assert_eq!(
            receipt.resolved_ref.as_deref(),
            Some("abcdef1234567890abcdef1234567890abcdef12")
        );
        assert_eq!(std::fs::read(dest.join("foo.nim")).unwrap(), b"# src");
        // The `.nimble` is materialized at the tree root (and would be hashed).
        assert!(dest.join("foo.nimble").is_file());
        assert_eq!(fetcher.calls().len(), 1);
        assert_eq!(fetcher.calls()[0].name, "foo");
    }

    #[test]
    fn missing_mock_is_a_fetch_error() {
        let tmp = tempfile::tempdir().unwrap();
        let fetcher = FakeFetcher::new(tmp.path().join("mocked-fetches"));
        let p = Provenance::Git {
            url: "https://example.com/x.git".into(),
            ref_spec: "main".into(),
            commit_sha: None,
        };
        let err = Fetcher::fetch(&fetcher, "x", &p, &tmp.path().join("dest")).unwrap_err();
        assert_eq!(err.code(), "FETCH-FAILED");
    }
}
