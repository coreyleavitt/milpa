//! `milpa-manifest` — `milpa.kdl` + `.nimble` parsing and the manifest data
//! model (RFC §4.1). `kdl-rs` is an *implementation detail* of the `parse_*`
//! functions (S0(a) decision: use the crate for parse only); the parsed
//! `Manifest` is a milpa-owned struct, never a re-exported `kdl-rs` AST, and
//! no emission code ever depends on `kdl-rs` (byte-exact emit is hand-rolled
//! in `milpa-core`).
//!
//! S1 (scaffold): type skeletons + stubbed `parse_*`. The grammar lands in S3.

use milpa_types::Version;

/// One declared dependency edge in a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepReq {
    pub name: String,
    /// Constraint text as written (parsed into a `VersionSet` by the solver).
    pub constraint: Option<String>,
}

/// A parsed `milpa.kdl` package manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    pub name: String,
    pub kind: String,
    pub version: Option<Version>,
    pub src_dir: String,
    pub deps: Vec<DepReq>,
    pub dev_deps: Vec<DepReq>,
}

/// One workspace member (name + on-disk subdirectory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub path: String,
}

/// A parsed workspace root (`workspace { member … }`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Workspace {
    pub members: Vec<Member>,
}

/// The build profile (nim version + active feature flags) used to evaluate
/// `when`/predicate blocks. Absent profile ⇒ all conditional deps included
/// (RFC §4.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    pub nim_version: Option<Version>,
    pub flags: Vec<String>,
}

/// Manifest-layer errors. Each carries a stable catalog `code()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// File could not be read (`MAN-FILE-UNREADABLE`).
    FileUnreadable(String),
    /// KDL/structural parse failure. S1/S2 skeleton uses the real generic
    /// KDL-syntax slug (`MAN-KDL-SYNTAX`, the code fixture-001 asserts); S3 fans
    /// this into the ~62 granular structural `MAN-*` codes.
    Parse(String),
    /// A `.nimble` translation failed (`MAN-NIMBLE-PARSE`).
    NimbleParse(String),
}

impl ManifestError {
    pub fn code(&self) -> &'static str {
        match self {
            ManifestError::FileUnreadable(_) => "MAN-FILE-UNREADABLE",
            ManifestError::Parse(_) => "MAN-KDL-SYNTAX",
            ManifestError::NimbleParse(_) => "MAN-NIMBLE-PARSE",
        }
    }

    /// Every catalog code this domain can emit (parity companion to `code()`).
    /// S3 fans the generic parse code out into the ~62 granular `MAN-*` grammar
    /// codes; this list grows with them so the conformance parity check stays a
    /// true bijection against `docs/spec/errors.md` (S12). Every entry MUST be a
    /// real spec slug.
    pub fn all_codes() -> &'static [&'static str] {
        &["MAN-FILE-UNREADABLE", "MAN-KDL-SYNTAX", "MAN-NIMBLE-PARSE"]
    }
}

/// Parse `milpa.kdl` text into a `Manifest` (S3).
pub fn parse_manifest(_text: &str) -> Result<Manifest, ManifestError> {
    unimplemented!("parse_manifest lands in S3")
}

/// Parse a workspace-root `milpa.kdl` into a `Workspace` (S3/S11).
pub fn parse_workspace(_text: &str) -> Result<Workspace, ManifestError> {
    unimplemented!("parse_workspace lands in S3/S11")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_error_codes_are_stable() {
        assert_eq!(
            ManifestError::FileUnreadable("x".into()).code(),
            "MAN-FILE-UNREADABLE"
        );
        assert_eq!(ManifestError::Parse("x".into()).code(), "MAN-KDL-SYNTAX");
    }
}
