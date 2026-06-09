//! The boundary error model (RFC §4.6): per-domain enums + one wrapper.
//!
//! Lower crates' fns return `Result<_, DomainError>`; the conversion to the
//! `MilpaError` boundary type happens here via `?` and the `From` impls below
//! (this is the only crate that can write them without a dependency cycle).
//! The harness asserts on `.code()` only — the spec never checks message text
//! (conformance-fixtures §3.1) — so the wrapper is per-*domain*, not per-*code*,
//! and stays bounded as the catalog grows.

use milpa_manifest::ManifestError;
use milpa_solver::SolverError;

use crate::fetch::FetchError;

/// Errors local to `milpa-core`'s own modules (identity/CAS, lockfile,
/// resolver glue, registry). Split into finer enums as those slices land; for
/// S1 a single skeleton carries the stable codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// Lockfile parse/validation failure (`LOCK-*`).
    Lockfile(&'static str, String),
    /// Identity/CAS failure (`CAS-*` / `ID-*`).
    Identity(&'static str, String),
    /// Resolver-orchestration failure (`RES-*`).
    Resolver(&'static str, String),
    /// Registry/index read failure (`TNG-*`).
    Tianguis(&'static str, String),
}

impl CoreError {
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::Lockfile(c, _)
            | CoreError::Identity(c, _)
            | CoreError::Resolver(c, _)
            | CoreError::Tianguis(c, _) => c,
        }
    }

    /// Every catalog code `milpa-core`'s own domains can emit (parity companion
    /// to `code()`). Each variant carries a dynamic `&'static str` slug, so this
    /// is the hand-maintained enumeration of the `LOCK-*`/`ID-*`/`CAS-*`/`RES-*`/
    /// `TNG-*` codes as their slices wire them. Empty until S4/S5a/S7b/S8 land
    /// real raises; grown there and completed to a bijection in S12.
    pub fn all_codes() -> &'static [&'static str] {
        &[]
    }
}

/// The boundary wrapper every public API returns. `code()` delegates to the
/// wrapped domain error, giving the harness one uniform `.code()` surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MilpaError {
    Manifest(ManifestError),
    Solver(SolverError),
    Fetch(FetchError),
    Core(CoreError),
}

impl MilpaError {
    pub fn code(&self) -> &'static str {
        match self {
            MilpaError::Manifest(e) => e.code(),
            MilpaError::Solver(e) => e.code(),
            MilpaError::Fetch(e) => e.code(),
            MilpaError::Core(e) => e.code(),
        }
    }
}

impl From<ManifestError> for MilpaError {
    fn from(e: ManifestError) -> Self {
        MilpaError::Manifest(e)
    }
}

impl From<SolverError> for MilpaError {
    fn from(e: SolverError) -> Self {
        MilpaError::Solver(e)
    }
}

impl From<FetchError> for MilpaError {
    fn from(e: FetchError) -> Self {
        MilpaError::Fetch(e)
    }
}

impl From<CoreError> for MilpaError {
    fn from(e: CoreError) -> Self {
        MilpaError::Core(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_delegates_code_across_domains() {
        let m: MilpaError = ManifestError::Parse("x".into()).into();
        assert_eq!(m.code(), "MAN-KDL-SYNTAX");

        let s: MilpaError = SolverError::Conflict("x".into()).into();
        assert_eq!(s.code(), "SOLVE-CONFLICT");

        let c: MilpaError = CoreError::Lockfile("LOCK-KDL-SYNTAX", "x".into()).into();
        assert_eq!(c.code(), "LOCK-KDL-SYNTAX");
    }
}
