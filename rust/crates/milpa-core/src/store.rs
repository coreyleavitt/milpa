//! Content-addressed store (RFC §4.1; identity.md §3). Layout / admit / link,
//! the 4-tier precedence, scratch lifecycle, and the UTF-8 symlink guard land
//! in S4.
//!
//! S1 (scaffold): the `CaStore` handle + admit signature exist.

use std::path::{Path, PathBuf};

use crate::error::CoreError;

/// A handle to the on-disk content-addressed store rooted at `root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaStore {
    pub root: PathBuf,
}

impl CaStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        CaStore { root: root.into() }
    }

    /// Admit a materialized tree at `src` under its content hash, returning the
    /// in-store path (S4).
    pub fn admit(&self, _src: &Path, _identity: &str) -> Result<PathBuf, CoreError> {
        unimplemented!("CaStore::admit lands in S4")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_remembers_its_root() {
        let s = CaStore::new("/tmp/cas");
        assert_eq!(s.root, PathBuf::from("/tmp/cas"));
    }
}
