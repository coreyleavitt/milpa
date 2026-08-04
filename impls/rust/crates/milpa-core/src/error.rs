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
    /// `SourceId` wire-form / grammar failure (`SRC-*`; rfc-origin-as-identity.md
    /// §4.1, S1). Its own domain (not folded into `Resolver`) because it is a
    /// pure grammar/parse concern — mirrors Python's dedicated `SRC` errors.md
    /// section.
    SourceId(&'static str, String),
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
    /// Append-only ratchet violation under `index-history "strict"`
    /// (`TNG-INDEX-ROOT-MUTATED` / `TNG-INDEX-ROLLBACK` / `TNG-ENTRY-MUTATED`;
    /// registry-protocol §3.5.2/§3.5.3, `rfc-registry-append-only.md` A4b).
    /// Carries the canonical violation digest (§3.5.3 NORMATIVE (canonical
    /// violation digest)) as structured data — never scraped from message
    /// text, per this module's design note above — so conformance fixtures
    /// can assert cross-impl digest equality on the `strict` path the same
    /// way Python's `MilpaError.context["digest"]` already does.
    RatchetViolation { code: &'static str, message: String, digest: String },
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
            | CoreError::DepDecl(c, _)
            | CoreError::SourceId(c, _) => c,
            CoreError::FlagConflict { .. } => "RESOLVE-FLAG-CONFLICT",
            CoreError::RatchetViolation { code, .. } => code,
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
            | CoreError::DepDecl(_, m)
            | CoreError::SourceId(_, m) => m,
            CoreError::FlagConflict { .. } => {
                // The payload fields (dep, flag_a, flag_b, sources_*) carry
                // all diagnostic info; conformance only checks code(), not message.
                "mutually exclusive flags co-active after fixpoint"
            }
            CoreError::RatchetViolation { message, .. } => message,
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
            // LOCK-SRC-* (rfc-origin-as-identity.md §7, S5): the structured
            // `source { … }` node's own parse errors — mirrors LOCK-PROV-*
            // 1:1 but kept as distinct slugs (a different node kind).
            "LOCK-SRC-FIELD-ARITY",
            "LOCK-SRC-FIELD-MISSING",
            "LOCK-SRC-KIND-MISSING",
            "LOCK-SRC-KIND-UNKNOWN",
            "LOCK-FILE-NOT-FOUND",
            "LOCK-FILE-UNREADABLE",
            // verify path (lockfile ⟷ resolved graph) — S13.
            "LOCK-GRAPH-MISMATCH",
            // resolver orchestration (resolver-semantics §3/§10) — S7b. The
            // workspace RES-WS-* codes wire with the workspace path in S11.
            // D3 (resolution-semantics RFC §3 Axis D / §4 stage 2): the
            // exclude-newer hard cut on index/named candidates, applied at
            // the enumeration layer. A DISTINCT error class from
            // TNG-NO-SATISFYING-VERSION — fires only when the time-bound
            // itself empties an otherwise-non-empty candidate set.
            // BindingResolver arbitration (rfc-origin-as-identity.md §4.3) — S2,
            // wired into the live resolve()/resolve_workspace() path at S3a.
            // Raised by `binding::BindingResolver::submit` when two transitive
            // claims disagree on a dep's source-id and no root claim exists to
            // arbitrate.
            "RES-BINDING-CONFLICT",
            // M6 / S5b (rfc-origin-as-identity.md §10 item 12 / B10): a root
            // `overrides {}` entry naming a dep absent from the FINAL resolved
            // graph is dead config (typo, or an orphaned override left behind
            // after the dep it targeted was removed). Warn-only, non-fatal —
            // same pattern as RES-REGISTRY-SHADOW's default policy. Checked
            // post-resolve in both `resolve` and `resolve_workspace_inner`
            // (the workspace path had no equivalent check before this slice).
            "RES-DEAD-OVERRIDE",
            "RES-EXCLUDE-NEWER-EMPTY",
            // D4 (resolution-semantics RFC §3 Axis D / §6 D-D1/D-D2): a git/
            // url dep is pinned to one resolved commit (no candidate set),
            // so exclude-newer VALIDATES that commit's committer date rather
            // than filtering a list — fires unconditionally (no fallback)
            // when the committer date exceeds the bound.
            "RES-EXCLUDE-NEWER-PIN",
            // S6 (rfc-origin-as-identity.md §4.6): the v1 directory-slot
            // floor of the import-slot check — lockfile::check_directory_
            // slot_collisions. CAVEAT (durable, §4.6/G9): a non-firing run
            // means "no directory-slot collision," NEVER "no import
            // collision" (a symbol-level collision across two differently-
            // named slots is unchecked until the S7 SymbolProviderPort).
            "RES-IMPORT-COLLISION",
            // B3 (resolution-semantics RFC §3 Axis B / §6 D-B2): `--locked`
            // drift guard — identity + provenance based, never version-label.
            "RES-LOCKED-DRIFT",
            // D3 (rfc-origin-as-identity.md §4.4.1): a `member "<name>"` dep
            // declared in a single-package (non-workspace) manifest. Raised at
            // root-seed time in both impls (Python drops silently pre-fix; Rust
            // pushed an unsatisfiable term → cryptic SOLVE-CONFLICT).
            "RES-MEMBER-OUTSIDE-WORKSPACE",
            "RES-NO-INDEX",
            // Registry-shadow tripwire (rfc-origin-as-identity.md §6.1/§11
            // D-Fork1) — S3c. Raised by `binding::check_registry_shadow` under
            // `attestation-policy strict` when a transitive git=/tarball=/oci=
            // claim's bare name shadows a registry-owned coordinate with no
            // matching recorded upstream source (default policy: warn only).
            "RES-REGISTRY-SHADOW",
            // §14.3 (resolver-semantics §14 "root satisfies its own name"):
            // a transitive `Named` claim on the standalone root's own name
            // carries a version constraint the root's own declared version
            // does not satisfy. Mirrors RES-WS-MEMBER-VERSION-CONSTRAINT
            // exactly, with the root's own self-candidate in place of a
            // workspace member. Raised in `resolver.rs`'s `gate_only`.
            "RES-ROOT-SELF-VERSION-CONSTRAINT",
            // S4c: post-fixpoint mutual-exclusion check (RFC #23 §3.1.4).
            "RESOLVE-FLAG-CONFLICT",
            // S5: attestation policy enforcement — strict mode raises this when
            // any resolved dep fell back to un-attested .nimble metadata.
            "RES-UNATTESTED-METADATA",
            // A4 (resolver-semantics RFC §3 Axis A (c)): a version-unknown
            // git/url/local/tarball dep is constrained by an accumulated
            // range that is non-full() at its (last-scheduled) decision
            // point, with no declared version to satisfy it. Built by
            // version_unknown_constrained_err from
            // SolverError::VersionUnknownConstrained (never surfaced as
            // MilpaError::Solver — see that variant's doc comment).
            "RES-VERSION-UNKNOWN-CONSTRAINED",
            // workspace resolve-time checks (resolver §11) — S11b.
            "RES-WS-NO-INDEX",
            "RES-WS-OVERRIDE-MEMBER-COLLISION",
            "RES-WS-MEMBER-REF-UNKNOWN",
            // S5: named-dep → member auto-coerce constraint check (Breadth-P1c).
            "RES-WS-MEMBER-VERSION-CONSTRAINT",
            // SourceId wire-form grammar (rfc-origin-as-identity.md §4.1) — S1.
            "SRC-ID-MALFORMED",
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
            // CR2 fix: registry string fields (namespace, version, provenance
            // url/ref/registry/repository, rekor uuid/log_index/integrated_time)
            // reject ASCII control characters at the parse boundary — these are
            // exactly the delimiter bytes the append-only ratchet's canonical
            // violation digest (registry-protocol §3.5.3) uses.
            "TNG-UNSAFE-CONTROL-CHAR",
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
            // D5 (resolution-semantics RFC §3 Axis D / §7 D5): baseline sourced
            // from the manifest's effective `resolution { exclude-newer }`,
            // mirroring FROZEN-STRATEGY-MISMATCH exactly (C3b).
            "FROZEN-EXCLUDE-NEWER-MISMATCH",
            "FROZEN-MANIFEST-DEP-NOT-IN-LOCK",
            "FROZEN-LOCKED-VERSION-UNPARSEABLE",
            "FROZEN-CONSTRAINT-UNSATISFIED",
            "FROZEN-MEMBER-DEP",
            "FROZEN-LOCAL-DEP",
            "FROZEN-IDENTITY-NOT-IN-STORE",
            // workspace-frozen disqualifications (S11b)
            "FROZEN-MEMBER-NOT-IN-WORKSPACE",
            "FROZEN-MEMBER-IDENTITY-DRIFT",
            // rfc-origin-as-identity.md §7.1 D2/D3 (S5): checked FIRST —
            // an unresolved registry alias must never be misreported as a
            // coordinate mismatch.
            "FROZEN-REGISTRY-ALIAS-UNRESOLVED",
            // rfc-origin-as-identity.md §7.1 D2 (S5): normalize_source
            // (declared-AFTER-override) must equal the lockfile record's
            // source_id, or frozen/verify fails closed.
            "FROZEN-SOURCE-ID-MISMATCH",
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
            // update/remove given a bare name that is ambiguous across namespaces
            // (two same-bare-name deps under different namespaces). Python CLI
            // raises this; the Rust CLI's namespace-aware arg handling is #189,
            // but the code is registered here to keep the spec↔catalog bijection.
            "LOCK-DEP-AMBIGUOUS-NAME",
            // DepDecl artifact parse/verify (spec/dep-decl.md §6) — S1 wires
            // TNG-DEPDECL-PARSE-ERROR; remaining four raise sites are S3b.
            "TNG-DEPDECL-PARSE-ERROR",
            "TNG-DEPDECL-HASH-MISMATCH",
            "TNG-DEPDECL-FETCH-FAILED",
            "TNG-DEPDECL-SCHEMA-MISMATCH",
            "TNG-DEPDECL-SCHEMA-UNSUPPORTED",
            // CLI-layer argument-validation errors (spec/errors.md §CLI).
            // CLI-EXCLUDE-NEWER-INVALID: malformed `--exclude-newer <ts>` value
            // (fetch/lock only, D2, resolution-semantics RFC §3 Axis D) — distinct
            // from the manifest's own MAN-RESOLUTION-EXCLUDE-NEWER-INVALID.
            "CLI-EXCLUDE-NEWER-INVALID",
            // CLI-FEATURE-FLAGS-CONFLICT: --all-features + --no-default-features together.
            "CLI-FEATURE-FLAGS-CONFLICT",
            // CLI-LOCKED-UPGRADE-CONFLICT: --locked + --upgrade together (B4,
            // resolution-semantics RFC §3 Axis B / D-B3) — one forbids
            // deviation from the committed lock, the other forces it.
            "CLI-LOCKED-UPGRADE-CONFLICT",
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
            // P3a (RFC per-entry-attestation.md §5): per-entry Sigstore
            // attestation gate. Emitted by enforce_entry_trust /
            // evaluate_entry_attestation (entry_trust.rs) when the selected
            // registry-resolved dep's attestation record is absent, its bundle
            // is unavailable or fails one of the pre-crypto / crypto checks.
            "TNG-ENTRY-UNATTESTED",
            "TNG-ENTRY-BUNDLE-MISSING",
            "TNG-ENTRY-BUNDLE-PIN-MISMATCH",
            "TNG-ENTRY-BUNDLE-MALFORMED",
            "TNG-ENTRY-DIGEST-MISMATCH",
            "TNG-ENTRY-SUBJECT-MISMATCH",
            "TNG-ENTRY-SIGNATURE-INVALID",
            "TNG-ENTRY-SIGNER-MISMATCH",
            // P3a: workspace entry-trust root-authority validation (RFC §4).
            // Emitted by check_member_entry_trust_declarations in workspace.rs
            // when a workspace MEMBER declares entry-trust — that field is a
            // workspace-ROOT-only policy, mirroring WS-INDEX-TRUST-ON-MEMBER.
            "WS-ENTRY-TRUST-ON-MEMBER",
            // A3 (rfc-registry-append-only.md; registry-protocol §3.5): the
            // append-only invariant & consumer ratchet. Emitted by the
            // index-cache ratchet gate (index_ratchet_seam.rs, wired inside
            // index_cache.rs::load_index) when a candidate index fails to
            // dominate the locally-cached baseline under the effective
            // `index-history` policy.
            "TNG-INDEX-ROOT-MUTATED",
            "TNG-INDEX-ROLLBACK",
            "TNG-ENTRY-MUTATED",
            // A3: the baseline sidecar exists but is unparseable/truncated —
            // hard-fails regardless of `index-history` policy (§3.5.2
            // NORMATIVE (baseline corruption is not TOFU)).
            "TNG-INDEX-BASELINE-CORRUPT",
            // A3: workspace index-history root-authority validation. Emitted
            // by check_member_index_history_declarations in workspace.rs
            // when a workspace MEMBER declares `index-history` — that field
            // is a workspace-ROOT-only policy, mirroring
            // WS-INDEX-TRUST-ON-MEMBER / WS-ENTRY-TRUST-ON-MEMBER.
            "WS-INDEX-HISTORY-ON-MEMBER",
            // W1 (rfc-resolution-semantics.md §3 Axis W, §5): workspace
            // resolution-block root-authority validation. Emitted by
            // check_member_resolution_declarations in workspace.rs when a
            // workspace MEMBER declares a `resolution { }` block — that
            // block is a workspace-ROOT-only policy (one shared lock, one
            // resolution policy), mirroring WS-INDEX-TRUST-ON-MEMBER /
            // WS-ENTRY-TRUST-ON-MEMBER / WS-INDEX-HISTORY-ON-MEMBER for the
            // sibling root-only-policy axes. Deliberately kept the dominant
            // `MAN-` prefix (the RFC's own §5 slug enumeration —
            // `resolution { }` is itself a `MAN-RESOLUTION-*`-owned manifest
            // construct) rather than the `WS-*-ON-MEMBER` naming used by
            // those unrelated fields; still raised from CoreError::Workspace
            // like its siblings since it fires at workspace-load time, not
            // manifest-parse time.
            "MAN-RESOLUTION-MEMBER-SCOPE",
            // A3 (cli-contract.md §5.12): the `milpa index status`/`milpa
            // index accept` verb family. NOT-CONFIGURED is the `--no-index`
            // (or empty MILPA_INDEX_URL) hard error both verbs raise (no
            // index to load or compare against). BASELINE-WRITE-FAILED is
            // `accept`'s loud, distinct error on an I/O failure during its
            // atomic baseline-pair swap (never a silent no-op).
            "TNG-INDEX-NOT-CONFIGURED",
            "TNG-INDEX-BASELINE-WRITE-FAILED",
            // S-EpochCommitment (rfc-attestation-v1-normative.md §6, D14-D18;
            // registry-protocol §3.4.8/§3.4.9): the index-gate pre-epoch set
            // arming phase. COMMITMENT-INVALID is the unconditional
            // fail-closed abort on a present-but-unverifiable
            // `attestation-epoch-commitment` pointer. RATCHET-REQUIRED is
            // the D18 co-requirement config error (Armed + entry-trust
            // "strict" without index-history "strict"). Emitted by
            // `epoch_commitment::enforce_epoch_commitment` /
            // `epoch_commitment::check_epoch_ratchet_requirement`.
            "TNG-INDEX-EPOCH-COMMITMENT-INVALID",
            "TNG-INDEX-EPOCH-RATCHET-REQUIRED",
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

    /// The human-readable diagnostic message, when available (never
    /// compared by the conformance harness — for logs and for composing
    /// nested diagnostics, e.g. `source_id::normalize_source`'s validation
    /// failures). Only `CoreError` currently exposes a
    /// message string; the other three domains expose `.code()` only
    /// (message text is genuinely never conformance-checked), so this
    /// falls back to the code itself rather than growing a `.message()`
    /// method on every domain error type for one call site.
    pub fn message(&self) -> &str {
        match self {
            MilpaError::Core(e) => e.message(),
            other => other.code(),
        }
    }

    /// The canonical violation digest (§3.5.3 NORMATIVE (canonical violation
    /// digest)), when this error is a `strict`-policy append-only ratchet
    /// violation (`CoreError::RatchetViolation`). `None` for every other
    /// error — mirrors Python's `MilpaError.context.get("digest")`, as
    /// structured data rather than a message-text scrape (see
    /// `CoreError::RatchetViolation`'s doc comment).
    pub fn ratchet_digest(&self) -> Option<&str> {
        match self {
            MilpaError::Core(CoreError::RatchetViolation { digest, .. }) => Some(digest.as_str()),
            _ => None,
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
