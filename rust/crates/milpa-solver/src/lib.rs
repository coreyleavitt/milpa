//! `milpa-solver` — version parsing + constraint algebra + the PubGrub seam
//! (RFC §4.1/§4.6). `VersionSet`'s `contains`/`intersection`/`complement` and
//! its `pubgrub::DependencyProvider` wiring are the type's *inherent* methods;
//! Rust's orphan rule keeps them in the crate that owns the type. Only the raw
//! `Version` newtype is shared (via `milpa-types`).
//!
//! S1 (scaffold): type skeletons + stubbed entry points. The algebra (S6) and
//! the `DependencyProvider` impl (S7, wired per the S0(b) decision to use
//! `pubgrub` 0.4.0 with `prioritize` = BFS order P) land in their slices.

use milpa_types::Version;

/// Version-selection strategy (resolver-semantics §4.2). `Maxver` is the
/// default and the only one exercised by the canonical-selection fixtures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Strategy {
    #[default]
    Maxver,
    Minver,
}

impl Strategy {
    /// Canonical lockfile spelling (`strategy "maxver"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Strategy::Maxver => "maxver",
            Strategy::Minver => "minver",
        }
    }
}

/// A set of versions, expressed as the spec's constraint algebra. The single
/// source of truth for constraint matching: nothing outside this type decides
/// whether a `Version` satisfies a constraint (S6 fills in the intervals).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionSet {
    // Interval representation lands in S6.
}

impl VersionSet {
    /// The set containing every version.
    pub fn full() -> Self {
        VersionSet::default()
    }

    /// Whether `version` is a member. (S6.)
    pub fn contains(&self, _version: &Version) -> bool {
        unimplemented!("VersionSet::contains lands in S6")
    }
}

/// Errors from parsing/solving. Carries a stable `code()` for catalog parity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolverError {
    /// A version string is not parseable.
    BadVersion(String),
    /// No assignment satisfies the constraints.
    Conflict(String),
}

impl SolverError {
    pub fn code(&self) -> &'static str {
        match self {
            SolverError::BadVersion(_) => "SOLVE-BAD-VERSION",
            SolverError::Conflict(_) => "SOLVE-CONFLICT",
        }
    }
}

/// Parse a version string into the canonical `Version` (S6).
pub fn parse_version(_text: &str) -> Result<Version, SolverError> {
    unimplemented!("parse_version lands in S6")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategy_default_is_maxver() {
        assert_eq!(Strategy::default(), Strategy::Maxver);
        assert_eq!(Strategy::Maxver.as_str(), "maxver");
    }

    #[test]
    fn solver_error_codes_are_stable() {
        assert_eq!(SolverError::Conflict("x".into()).code(), "SOLVE-CONFLICT");
    }
}
