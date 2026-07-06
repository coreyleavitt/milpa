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
    /// Workspace topology / structural failure (`WS-*`).
    Workspace(&'static str, String),
    /// DepDecl artifact parse/verify failure (`TNG-DEPDECL-*`; spec/dep-decl.md §6).
    /// Raise sites for all five codes are S3b; S1 only wires `TNG-DEPDECL-PARSE-ERROR`
    /// (propagated from `parse_dep_decl` for KDL syntax / structural errors).
    DepDecl(&'static str, String),
    /// S4c: post-fixpoint mutual-exclusion conflict (`RESOLVE-FLAG-CONFLICT`).
    /// Carries structured payload for byte-identity unit tests (RFC #23 §5 risk #3):
    ///   dep, flag_a, flag_b (lexicographic order), sources_a, sources_b
    ///   (sorted by enum declaration order: default, edge_request, enables_rule).
    FlagConflict {
        dep: String,
        flag_a: String,
        flag_b: String,
        sources_a: Vec<String>,
        sources_b: Vec<String>,
    },
}

impl CoreError {
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::Lockfile(c, _)
            | CoreError::Identity(c, _)
            | CoreError::Resolver(c, _)
            | CoreError::Tianguis(c, _)
            | CoreError::Frozen(c, _)
            | CoreError::Workspace(c, _)
            | CoreError::DepDecl(c, _) => c,
            CoreError::FlagConflict { .. } => "RESOLVE-FLAG-CONFLICT",
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
            | CoreError::Frozen(_, m)
            | CoreError::Workspace(_, m)
            | CoreError::DepDecl(_, m) => m,
            CoreError::FlagConflict { .. } => {
                // The payload fields (dep, flag_a, flag_b, sources_*) carry
                // all diagnostic info; conformance only checks code(), not message.
                "mutually exclusive flags co-active after fixpoint"
            }
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
            "ID-NON-UTF8-RELPATH",
            "ID-NON-UTF8-SYMLINK-TARGET",
            // ID-NAME-TOO-LONG: epoch-2 Merkle-DAG leaf-name ceiling (§1.8.8).
            "ID-NAME-TOO-LONG",
            // CAS (identity.md §3.3 / §3.6)
            "CAS-IDENTITY-MISMATCH",
            "CAS-NOT-IN-STORE",
            // CAS store inspection (C-store-ro slice, Phase C)
            "STORE-AMBIGUOUS-PREFIX",
            // C-verify: symlink-state classification (RFC Phase C §6 item 6 + §6.4)
            "CAS-STORE-IO-ERROR",
            "VERIFY-ALIAS-SYMLINK-MISSING",
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
            // submodule node structural errors (wrong arg count / non-string path /
            // missing-or-invalid sha=); distinct from scalar-field arity.
            "LOCK-SUBMODULE-FIELD-INVALID",
            "LOCK-PROV-KIND-MISSING",
            "LOCK-PROV-KIND-UNKNOWN",
            "LOCK-PROV-FIELD-MISSING",
            "LOCK-STRATEGY-MISSING",
            // lockfile dep name/alias charset validation (mirrors MAN-DEP-NAME-INVALID;
            // R8-S1 security fix — path traversal + nim.cfg injection via poisoned lock).
            "LOCK-DEP-NAME-INVALID",
            // lockfile src_dir unsafe-char validation (mirrors MAN-SRC-DIR-UNSAFE).
            "LOCK-SRC-DIR-UNSAFE",
            "LOCK-FILE-NOT-FOUND",
            "LOCK-FILE-UNREADABLE",
            // verify path (lockfile ⟷ resolved graph) — S13.
            "LOCK-GRAPH-MISMATCH",
            // resolver orchestration (resolver-semantics §3/§10) — S7b. The
            // workspace RES-WS-* codes wire with the workspace path in S11.
            "RES-NO-INDEX",
            "RES-PROVENANCE-CONFLICT",
            // S4c: post-fixpoint mutual-exclusion check (RFC #23 §3.1.4).
            "RESOLVE-FLAG-CONFLICT",
            // S5: attestation policy enforcement — strict mode raises this when
            // any resolved dep fell back to un-attested .nimble metadata.
            "RES-UNATTESTED-METADATA",
            // workspace resolve-time checks (resolver §11) — S11b.
            "RES-WS-NO-INDEX",
            "RES-WS-OVERRIDE-MEMBER-COLLISION",
            "RES-WS-MEMBER-REF-UNKNOWN",
            // S5: named-dep → member auto-coerce constraint check (Breadth-P1c).
            "RES-WS-MEMBER-VERSION-CONSTRAINT",
            // tianguis index reader (registry-protocol §2–§4) — S8. The parse-
            // time validators + the resolve-time policy. TNG-BAD-VERSION is in
            // the catalog but unraised by both impls (reserved); not listed here
            // since the union enumerates only codes this impl can emit.
            "TNG-KDL-SYNTAX",
            "TNG-SCHEMA-UNKNOWN",
            "TNG-UNSAFE-NAME",
            "TNG-BAD-COMMIT-SHA",
            "TNG-BAD-OCI-DIGEST",
            "TNG-BAD-DEP-DECL",
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
            "FROZEN-ACTIVE-FLAGS-MISMATCH",
            "FROZEN-STRATEGY-MISMATCH",
            "FROZEN-MANIFEST-DEP-NOT-IN-LOCK",
            "FROZEN-LOCKED-VERSION-UNPARSEABLE",
            "FROZEN-CONSTRAINT-UNSATISFIED",
            "FROZEN-MEMBER-DEP",
            "FROZEN-LOCAL-DEP",
            "FROZEN-IDENTITY-NOT-IN-STORE",
            // workspace-frozen disqualifications (S11b)
            "FROZEN-MEMBER-NOT-IN-WORKSPACE",
            "FROZEN-MEMBER-IDENTITY-DRIFT",
            // workspace topology (workspace-semantics) — S11a loader. The
            // resolve-time RES-WS-* codes live in the resolver domain; the two
            // workspace-frozen FROZEN-MEMBER-* codes land in S11b.
            "WS-NO-MANIFEST",
            "WS-NOT-A-WORKSPACE",
            "WS-MEMBER-DOT",
            "WS-MEMBER-DIR-MISSING",
            "WS-MEMBER-NO-MANIFEST",
            "WS-MEMBER-IS-WORKSPACE",
            "WS-MEMBER-HAS-OVERRIDES",
            "WS-MEMBER-DUPLICATE-NAME",
            "WS-MEMBER-PATH-ESCAPE",
            // S10 (workspace-completion §3.F): workspace add-member/remove-member
            // refusal slugs.  Raised by the CLI mutation path (not by the workspace
            // loader or resolver — those are topology errors above).
            "WS-REMOVE-MEMBER-NOT-FOUND",
            "WS-REMOVE-MEMBER-TARGET-EXISTS",
            "WS-REMOVE-MEMBER-REFERENCED",
            // frozen fast-path precondition failures (Gap-1 / S1c). These are
            // the two missing-precondition codes: no lockfile and no CAS.
            "FROZEN-NO-LOCKFILE",
            "FROZEN-NO-CAS",
            // verify verb (Gap-1 / S1c). Emitted by cmd_verify when _deps/
            // is absent (nothing fetched yet).
            "VERIFY-DEPS-DIR-MISSING",
            // S6: dep_decl edge-drift detection (spec §3.7 / rfc-content-addressed-metadata).
            // VERIFY-EDGE-MISMATCH: locked dep_decl pin ≠ live index dep_decl pointer.
            "VERIFY-EDGE-MISMATCH",
            // LOCK-DEPDECL-PIN-MISSING: dep_decl pin present in lock but index
            // version-node lacks a dep_decl pointer (DepDecl retracted / rolled back).
            "LOCK-DEPDECL-PIN-MISSING",
            // lockfile verb (update/add --mirror): dep absent in the lock.
            "LOCK-DEP-NOT-FOUND",
            // DepDecl artifact parse/verify (spec/dep-decl.md §6) — S1 wires
            // TNG-DEPDECL-PARSE-ERROR; remaining four raise sites are S3b.
            "TNG-DEPDECL-PARSE-ERROR",
            "TNG-DEPDECL-HASH-MISMATCH",
            "TNG-DEPDECL-FETCH-FAILED",
            "TNG-DEPDECL-SCHEMA-MISMATCH",
            "TNG-DEPDECL-SCHEMA-UNSUPPORTED",
            // CLI-layer argument-validation errors (spec/errors.md §CLI).
            // CLI-FEATURE-FLAGS-CONFLICT: --all-features + --no-default-features together.
            "CLI-FEATURE-FLAGS-CONFLICT",
            // CLI-SOURCE-SPEC-INVALID: malformed source-spec tokens for `milpa hash`
            // (spec/cli-contract.md §5.11; A0 slice).
            "CLI-SOURCE-SPEC-INVALID",
            // internal / panic sentinels (Gap-1 R4 / S1c). MILPA-INTERNAL is
            // the outermost catch-all; INTERNAL-PANIC fires from the panic hook.
            "MILPA-INTERNAL",
            "INTERNAL-PANIC",
            // index unreachable (registry-protocol §6 / §4 swallow-exemption):
            // network failure with no cached fallback. Emitted by load_index /
            // index_cache; swallowed by maybe_index (→ treat index as absent).
            // Catalog entry satisfies the bijection invariant; no terminal fixture.
            "MILPA-INDEX-UNREACHABLE",
            // S6 (Rust mirror of Python S5): tianguis index attestation failure codes
            // (RFC rfc-registry-trust-federation §6 / §10, spec/errors.md TNG-INDEX-*).
            // Emitted by enforce_index_trust / load_index when the Sigstore bundle
            // sidecar is absent, malformed, cryptographically invalid, digest-mismatching,
            // signer-mismatching, or beyond the max-age window.
            "TNG-INDEX-BUNDLE-MISSING",
            "TNG-INDEX-BUNDLE-MALFORMED",
            "TNG-INDEX-SIGNATURE-INVALID",
            "TNG-INDEX-DIGEST-MISMATCH",
            "TNG-INDEX-SIGNER-MISMATCH",
            "TNG-INDEX-BUNDLE-STALE",
            // S8: workspace index-trust root-authority validation (RFC §6.4a,
            // spec §3.4.7). Emitted by check_member_index_trust_declarations in
            // workspace.rs when a workspace MEMBER declares index-trust /
            // index-trust-signer / index-trust-bundle — that field is a
            // workspace-ROOT-only policy (manifest-structure error; raised
            // before any index fetch).
            "WS-INDEX-TRUST-ON-MEMBER",
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
