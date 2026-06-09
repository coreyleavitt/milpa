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
    /// Frozen-path disqualification (`FROZEN-*`).
    Frozen(&'static str, String),
}

impl CoreError {
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::Lockfile(c, _)
            | CoreError::Identity(c, _)
            | CoreError::Resolver(c, _)
            | CoreError::Tianguis(c, _)
            | CoreError::Frozen(c, _) => c,
        }
    }

    /// The human-readable diagnostic message (never compared by the conformance
    /// harness — for logs and for composing nested diagnostics).
    pub fn message(&self) -> &str {
        match self {
            CoreError::Lockfile(_, m)
            | CoreError::Identity(_, m)
            | CoreError::Resolver(_, m)
            | CoreError::Tianguis(_, m)
            | CoreError::Frozen(_, m) => m,
        }
    }

    /// Every catalog code `milpa-core`'s own domains can emit (parity companion
    /// to `code()`). Each variant carries a dynamic `&'static str` slug, so this
    /// is the hand-maintained enumeration of the `LOCK-*`/`ID-*`/`CAS-*`/`RES-*`/
    /// `TNG-*` codes as their slices wire them. Grown per-slice; completed to a
    /// bijection with `errors.md` in S12.
    ///
    /// S4 added the identity + CAS codes. Deliberately excluded:
    /// `ID-NOT-A-STRING` (unreachable — `parse_identity` takes a `&str`, so the
    /// type system enforces it statically) and the `MILPA-INTERNAL-IO` sentinel
    /// (a non-catalog infrastructure failure the spec leaves uncoded; see
    /// `identity.rs`). `CAS-DIR-MISSING`/`CAS-DIR-TYPE` are manifest-`cas{dir}`
    /// validation codes, wired with the resolver/CLI tier-2 path, not here.
    pub fn all_codes() -> &'static [&'static str] {
        &[
            // identity (identity.md §2.2 / §1.5)
            "ID-NO-ALGORITHM-PREFIX",
            "ID-UNSUPPORTED-ALGORITHM",
            "ID-WRONG-DIGEST-LENGTH",
            "ID-NON-HEX-DIGEST",
            "ID-NON-UTF8-SYMLINK-TARGET",
            // CAS (identity.md §3.3 / §3.6)
            "CAS-IDENTITY-MISMATCH",
            "CAS-NOT-IN-STORE",
            // lockfile parse (lockfile-schema §2–§4) — S5a. The two file-IO
            // codes (LOCK-FILE-NOT-FOUND / LOCK-FILE-UNREADABLE) are emitted by
            // `load_lockfile`, the disk wrapper, and are included here too. The
            // verify/frozen codes (LOCK-GRAPH-MISMATCH, FROZEN-*) wire in S7/S10.
            "LOCK-KDL-SYNTAX",
            "LOCK-VERSION-MISSING",
            "LOCK-VERSION-UNSUPPORTED",
            "LOCK-FIELD-ARITY",
            "LOCK-FIELD-TYPE",
            "LOCK-DEP-NAME-ARITY",
            "LOCK-DEP-FIELD-ARITY",
            "LOCK-DEP-IDENTITY-INVALID",
            "LOCK-PROV-FIELD-ARITY",
            "LOCK-PROV-KIND-MISSING",
            "LOCK-PROV-KIND-UNKNOWN",
            "LOCK-PROV-FIELD-MISSING",
            "LOCK-FILE-NOT-FOUND",
            "LOCK-FILE-UNREADABLE",
            // resolver orchestration (resolver-semantics §3/§10) — S7b. The
            // workspace RES-WS-* codes wire with the workspace path in S11.
            "RES-NO-INDEX",
            "RES-PROVENANCE-CONFLICT",
            // tianguis index reader (registry-protocol §2–§4) — S8. The parse-
            // time validators + the resolve-time policy. TNG-BAD-VERSION is in
            // the catalog but unraised by both impls (reserved); not listed here
            // since the union enumerates only codes this impl can emit.
            "TNG-SCHEMA-UNKNOWN",
            "TNG-UNSAFE-NAME",
            "TNG-BAD-COMMIT-SHA",
            "TNG-BAD-OCI-DIGEST",
            "TNG-UNSAFE-URL",
            "TNG-UNSAFE-REF",
            "TNG-UNSAFE-OCI-FIELD",
            "TNG-NOT-FOUND",
            "TNG-AMBIGUOUS-NAME",
            "TNG-NO-SATISFYING-VERSION",
            "TNG-NO-PROVENANCE",
            "TNG-NO-IDENTITY",
            // frozen path (frozen-semantics) — S10, single-package. The two
            // workspace-member disqualifications (FROZEN-MEMBER-NOT-IN-WORKSPACE /
            // FROZEN-MEMBER-IDENTITY-DRIFT) are raised only by
            // resolve_workspace_frozen, which lands with the workspace member
            // loader in S11 — added then (subset rule: list only codes emitted).
            "FROZEN-STRATEGY-MISMATCH",
            "FROZEN-MANIFEST-DEP-NOT-IN-LOCK",
            "FROZEN-LOCKED-VERSION-UNPARSEABLE",
            "FROZEN-CONSTRAINT-UNSATISFIED",
            "FROZEN-MEMBER-DEP",
            "FROZEN-LOCAL-DEP",
            "FROZEN-IDENTITY-NOT-IN-STORE",
            "FROZEN-LEGACY-REGISTRY-PROVENANCE",
        ]
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
        let m: MilpaError = ManifestError::new("MAN-KDL-SYNTAX", "x").into();
        assert_eq!(m.code(), "MAN-KDL-SYNTAX");

        let s: MilpaError = SolverError::Conflict("x".into()).into();
        assert_eq!(s.code(), "SOLVE-CONFLICT");

        let c: MilpaError = CoreError::Lockfile("LOCK-KDL-SYNTAX", "x".into()).into();
        assert_eq!(c.code(), "LOCK-KDL-SYNTAX");
    }
}
