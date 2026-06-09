//! Content-addressed identity (RFC §4.1; identity.md). The byte-exact content
//! hash algorithm lives ONLY here (SSOT). Two-table algorithm-agility dispatch
//! (`SUPPORTED_ALGORITHMS` + digest lengths, not a hardcoded `== "sha256"`) so
//! future multihash is a one-file change (identity.md §2.3).
//!
//! S1 (scaffold): the table and signature exist; the tree walk lands in S4.

use std::path::Path;

use crate::error::CoreError;

/// Hash algorithms milpa understands, with their hex digest length. New
/// algorithms are added here and nowhere else.
pub const SUPPORTED_ALGORITHMS: &[(&str, usize)] = &[("sha256", 64)];

/// Compute the content hash of a source tree, returning `"<algo>:<hex>"`.
/// (S4 implements the canonical tree walk + digest.)
pub fn compute_content_hash(_root: &Path) -> Result<String, CoreError> {
    unimplemented!("compute_content_hash lands in S4")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_supported_with_64_hex_chars() {
        assert_eq!(
            SUPPORTED_ALGORITHMS.iter().find(|(a, _)| *a == "sha256"),
            Some(&("sha256", 64))
        );
    }
}
