//! `milpa-manifest` — `milpa.kdl` + `.nimble` parsing and the manifest data
//! model (RFC §4.1, spec `spec/manifest-grammar.md`). `kdl` (kdl-rs) is an
//! *implementation detail* of the `parse_*` functions (S0(a) decision: use the
//! crate for parse only); the parsed [`Manifest`] / [`Workspace`] are
//! milpa-owned structs, never a re-exported `kdl-rs` AST, and no emission code
//! ever depends on `kdl-rs` (byte-exact emit is hand-rolled in `milpa-core`).
//!
//! S3 lands the full package + workspace grammar and every structural `MAN-*`
//! error code, mirroring the reference parser (`milpa/manifest.py`). The model
//! deliberately tracks the Python reference field-for-field so the two
//! implementations stay one design.

use std::collections::BTreeSet;

use kdl::{KdlDocument, KdlEntry, KdlNode, KdlValue};

use milpa_solver::{parse_version, Strategy, VersionSet};
use milpa_types::{parse_iso8601_timestamp, Timestamp, Version};

pub mod format;
pub mod nimble;
pub mod trust;

pub use format::{format_manifest, format_workspace_manifest};
pub use trust::{parse_trust_policy, TrustPolicy};
// Re-export Predicate from milpa-types (the new SSOT) so all existing
// references to `milpa_manifest::Predicate` and `crate::Predicate` compile
// unchanged.
pub use milpa_types::Predicate;
// Re-export FlagRequest from milpa-types (the new SSOT) so all existing
// references to `milpa_manifest::FlagRequest` and `crate::FlagRequest`
// compile unchanged.
pub use milpa_types::FlagRequest;
pub use milpa_types::DepKey;

/// Highest manifest spec-version epoch this implementation understands
/// (grammar §4.4). Bumped only for breaking semantic changes; additive
/// evolution stays within an epoch via the P3 forward-unknown properties.
pub const MANIFEST_SPEC_VERSION: i64 = 1;

// ---------------------------------------------------------------------------
// Data model — mirrors `milpa/manifest.py` (one design, two impls).
// ---------------------------------------------------------------------------

/// A dep declared by git URL + ref (grammar §3.2 UrlDep).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlDep {
    pub name: String,
    pub git: String,
    pub git_ref: String,
    pub mirrors: Vec<String>,
    pub predicates: Vec<Predicate>,
    pub flag_requests: Vec<FlagRequest>,
    /// S7 (RFC #23 §3.2): retained for round-trip serialization.
    /// The parse-time desugar injects the auto-flag + gate predicate;
    /// `format_manifest` emits `optional=#true` instead of the gate.
    pub optional: bool,
    /// A3b (§3 Axis A (b) step 4): a user-supplied declared-version
    /// annotation, consulted by `declared_version_for` only when the fetched
    /// package's own manifest/tag (steps 1-3) yield none. `None` when absent
    /// (the common case).
    pub version: Option<Version>,
    /// `subpath` (rfc-origin-as-identity.md §4.1/S8): the dep lives at this
    /// location INSIDE the fetched tree, not the repo root. `None` (the
    /// common case) means the repo root. Threaded into
    /// `FetchableOrigin::Git.subpath` at source-id construction
    /// (`binding.rs`); escape-guarded (no `..`, no absolute path) by
    /// `source_id::normalize_source` at resolve time — the parser itself
    /// does not validate the string (single validation boundary, mirroring
    /// `source_id.rs`'s module docs). Mirrors Python's `UrlDep.subpath`.
    pub subpath: Option<String>,
}

/// A dep resolved through the tianguis index by name (grammar §3.2 NamedDep).
///
/// Two fields capture the constraint (mirrors `manifest.py:NamedDep`):
/// - `constraint` — the raw string from the manifest, preserved for round-trip
///   emit (e.g. `">= 0.5.0"`). `None` = any version.
/// - `parsed_constraint` — the pre-parsed `VersionSet`, guaranteed valid at
///   parse time. `None` iff `constraint` is `None`. The manifest parser rejects
///   an unparseable string at the parse boundary with `MAN-DEP-NAMED-CONSTRAINT`;
///   the resolver consumes this field directly and never re-parses manifest deps.
/// - `flag_requests` — consumer feature-flag requests (§3.1.5 S3 RFC #23),
///   structurally identical to `UrlDep.flag_requests` (SSOT: reuses `FlagRequest`).
/// - `namespace` — S5b: registry namespace qualifier.  `None` = bare-name
///   lookup (current default); `Some("ns")` = qualified lookup that bypasses
///   `TNG-AMBIGUOUS-NAME`.  Populated from `namespace="..."` attribute or
///   slash-shorthand desugar at parse time.
#[derive(Debug, Clone)]
pub struct NamedDep {
    pub name: String,
    /// Raw constraint string, preserved for KDL round-trip emit. `None` = any.
    pub constraint: Option<String>,
    /// Pre-parsed `VersionSet`; `None` iff `constraint` is `None`.
    pub parsed_constraint: Option<VersionSet>,
    /// Consumer feature-flag requests on this dep (§3.1.5, S3 RFC #23).
    /// Structurally identical to `UrlDep.flag_requests` — reuses `FlagRequest` (SSOT).
    pub flag_requests: Vec<FlagRequest>,
    /// S7 (RFC #23 §3.2): retained for round-trip. Desugar injects gate predicate.
    pub optional: bool,
    /// S7: auto-injected gate predicate from optional desugaring (flag=<depname>).
    /// The resolver uses this via `dep.predicates()` for flag-filtering.
    pub predicates: Vec<Predicate>,
    /// S5b: namespace qualifier from `namespace="..."` attribute or slash-shorthand.
    /// `None` = default (bare-name lookup, all pre-S5b deps).
    pub namespace: Option<String>,
}

impl PartialEq for NamedDep {
    fn eq(&self, other: &Self) -> bool {
        // Compare by name + raw constraint string + namespace (mirrors Python).
        self.name == other.name && self.constraint == other.constraint
            && self.namespace == other.namespace
    }
}

impl Eq for NamedDep {}

/// A dep declared by local filesystem path (grammar §3.2 LocalDep).
///
/// `predicates` are evaluated before the dep is passed to the solver
/// (§6.3 NORMATIVE: all five dep forms support `when`-conditional syntax).
/// Populated from enclosing `when` block predicates in `expand_dep_child`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDep {
    pub name: String,
    pub path: String,
    pub predicates: Vec<Predicate>,
    /// A3b (§3 Axis A (b) step 4) — see `UrlDep::version` for the rationale.
    pub version: Option<Version>,
}

/// A dep declared by tarball URL (grammar §3.2 TarballDep).
///
/// `predicates` are evaluated before the dep is passed to the solver
/// (§6.3 NORMATIVE: all five dep forms support `when`-conditional syntax).
/// Populated from enclosing `when` block predicates in `expand_dep_child`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarballDep {
    pub name: String,
    pub url: String,
    pub sha256: Option<String>,
    pub strip_components: u32,
    pub predicates: Vec<Predicate>,
    /// A3b (§3 Axis A (b) step 4) — see `UrlDep::version` for the rationale.
    pub version: Option<Version>,
    /// `subpath` (rfc-origin-as-identity.md §4.1/S8) — see `UrlDep::subpath`
    /// for the full rationale; threaded into `FetchableOrigin::Tarball.subpath`.
    pub subpath: Option<String>,
}

/// A workspace-internal member reference (grammar §3.2 MemberDep).
///
/// `predicates` are evaluated before the dep is passed to the solver
/// (§6.3 NORMATIVE: all five dep forms support `when`-conditional syntax).
/// Populated from enclosing `when` block predicates in `expand_dep_child`.
/// Note: MAN-DEP-MEMBER-PROPS still forbids properties directly ON the member
/// node — predicates come exclusively from enclosing `when` blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberDep {
    pub name: String,
    pub predicates: Vec<Predicate>,
}

/// A declared dependency edge — one of the five disjoint forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dep {
    Url(UrlDep),
    Named(NamedDep),
    Local(LocalDep),
    Tarball(TarballDep),
    Member(MemberDep),
}

impl Dep {
    pub fn name(&self) -> &str {
        match self {
            Dep::Url(d) => &d.name,
            Dep::Named(d) => &d.name,
            Dep::Local(d) => &d.name,
            Dep::Tarball(d) => &d.name,
            Dep::Member(d) => &d.name,
        }
    }

    /// The conditional predicates on this dep.
    ///
    /// All five dep forms carry predicates (§6.3 NORMATIVE: all five dep forms
    /// support `when`-conditional syntax). Direct field access across all arms.
    pub fn predicates(&self) -> &[Predicate] {
        match self {
            Dep::Url(d) => &d.predicates,
            Dep::Named(d) => &d.predicates,
            Dep::Local(d) => &d.predicates,
            Dep::Tarball(d) => &d.predicates,
            Dep::Member(d) => &d.predicates,
        }
    }
}

/// Discriminated union of override target kinds (S8/S8b, RFC #23 §3.3 +
/// rfc-origin-as-identity.md §7 B5 "overrides {} is the sole rebind bridge").
///
/// Exactly one variant per `pkg` rule; zero or multiple forms raise
/// `MAN-OVERRIDE-TARGET-AMBIGUOUS`. Mirrors Python's `manifest.OverrideTarget`
/// six-way union function-for-function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideTarget {
    /// `pkg "name" git=(url)"..." ref="..." [subpath="<p>"]` — git fork.
    /// Identity-bearing; CAS-admissible.
    Git { url: String, git_ref: String, subpath: Option<String> },
    /// `pkg "name" local="<relative-path>"` — local filesystem path.
    /// Liveness-only; NOT CAS-admissible; non-reproducible for external consumers.
    /// Resolution wired in S8a.
    Local { path: String },
    /// `pkg "name" { member "<member-name>" }` — workspace member.
    /// Identity-bearing; NOT CAS-admissible.
    /// Resolution wired in S8b.
    Member { member_name: String },
    /// `pkg "name" oci="<registry>/<repository>" digest="sha256:..." [subpath="<p>"]`
    /// (rfc-origin-as-identity.md §7 B5, S8b) — a fixed OCI artifact.
    /// Identity-bearing; CAS-admissible; resolved as a direct,
    /// index-independent OCI pull (no first-class manifest `oci=` dep form —
    /// only this override target).
    Oci { registry: String, repository: String, digest: String, subpath: Option<String> },
    /// `pkg "name" tarball=(url)"<URL>" [sha256="<hex>"] [strip_components=<N>]
    /// [subpath="<p>"]` (rfc-origin-as-identity.md §7 B5, S8b) — mirrors
    /// `TarballDep` field-for-field. Identity-bearing; CAS-admissible.
    Tarball { url: String, sha256: Option<String>, strip_components: u32, subpath: Option<String> },
    /// `pkg "name" named="<registry-name>" [namespace="<ns>"]`
    /// (rfc-origin-as-identity.md §7 B5, S8b) — redirect a dep TO a tianguis
    /// registry coordinate (the inverse of the other five forms). No
    /// `subpath` — a registry entry is already scoped to exactly its
    /// published subtree. Composes with `Override.version` (D-A3): when set,
    /// becomes an EXACT `== <version>` constraint on the redirected lookup.
    Registry { name: String, namespace: Option<String> },
}

/// A `pkg`-form override (S8/S8b discriminated union, grammar §3.4 +
/// rfc-origin-as-identity.md §7 B5).
///
/// `name` is the dep to intercept; `target` is exactly one of the six
/// `OverrideTarget` variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    pub name: String,
    pub target: OverrideTarget,
    /// A3b (§3 Axis A (b) step 4, D-A3): a `version=` annotation on the
    /// override rule itself — orthogonal to `target` (label vs redirect).
    /// When this override redirects a dep, the Axis-A precedence re-runs
    /// against the override target's manifest; this is that target's step 4.
    pub version: Option<Version>,
}

/// A cross-package flag-activation entry inside an `enables` node (S1 RFC #23 §3.1.1).
///
/// Reuses [`FlagRequest`] for the per-flag requests (SSOT — structurally identical to
/// the §3.6 consumer flag request form already on `UrlDep.flag_requests`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossPkgEnable {
    /// The dep node-name (the KDL identifier naming the dependency).
    pub dep: String,
    /// The `flag` children on that dep node.
    pub flag_requests: Vec<FlagRequest>,
}

/// A named feature flag declared by a package (grammar §3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagDecl {
    pub name: String,
    pub default: bool,
    pub description: String,
    pub defines: Vec<String>,
    /// Same-package flag names this flag enables when active (S1 RFC #23 §3.1.1).
    /// Multiple `enables` nodes union into this vec.
    pub enables_same_pkg: Vec<String>,
    /// Cross-package dep→flag activation entries (S1 RFC #23 §3.1.1).
    pub enables_cross_pkg: Vec<CrossPkgEnable>,
    /// Same-package flag names that cannot be co-active with this flag (S1 RFC #23 §3.1.4).
    pub conflicts: Vec<String>,
}

/// Manifest-level resolution policy (`resolution { }` block).
///
/// First appearance of this block (C3, rfc-resolution-semantics.md §3 Axis C
/// / §5) carried only `strategy`; D1 (§3 Axis D) adds `exclude_newer` as a
/// sibling field, no block-parser reshape needed. Root-only for a workspace
/// (one shared lock, one resolution policy) — a member-level `resolution`
/// block is reserved for rejection in a later slice (Axis D/W1), not built
/// here.
///
/// `strategy`/`exclude_newer` are each `None` when the block was declared
/// but did not name that child (or the block itself is absent — see
/// `Manifest::resolution`/`Workspace::resolution`, both `None` when no
/// `resolution { }` node was declared at all).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Resolution {
    pub strategy: Option<Strategy>,
    pub exclude_newer: Option<Timestamp>,
}

/// A parsed `milpa.kdl` package manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub name: Option<String>,
    pub kind: String,
    pub src_dir: String,
    pub deps: Vec<Dep>,
    pub dev_deps: Vec<Dep>,
    pub overrides: Vec<Override>,
    pub flags: Vec<FlagDecl>,
    pub self_mirrors: Vec<String>,
    pub cas_dir: String,
    pub spec_version: i64,
    pub spec_version_explicit: bool,
    /// A1 (rfc-resolution-semantics.md §3 Axis A (b) step 1): the package's own
    /// declared release version, parsed from a top-level `version "x.y.z"`
    /// node. `None` means no version declared (version-unknown) — not an
    /// error. Distinct from `spec_version` (the manifest schema epoch) and
    /// orthogonal to content-hash identity (spec/identity.md §4.1).
    pub version: Option<Version>,
    /// S5: attestation policy from `attestation-policy "warn"|"strict"|"off"` (default: warn).
    /// S1 (RFC rfc-registry-trust-federation): renamed from `AttestationPolicy`;
    /// the user-facing "permissive" value is renamed to "warn" (pre-v1 breaking cutover).
    pub attestation_policy: TrustPolicy,
    /// S6: whole-index trust policy from `index-trust "warn"|"strict"|"off"` (default: warn).
    /// RFC registry-trust-federation §6.4.
    pub index_trust_policy: TrustPolicy,
    /// S6: expected SubjectAltName override from `index-trust-signer "<identity>"` (RFC §3.2).
    /// `None` means use the default pinned vendor-bot identity.
    pub index_trust_signer: Option<String>,
    /// S6: trust-root override (file:// path) from `index-trust-bundle "<path>"` (RFC §3.2).
    /// `None` means use the embedded production trust bundle.
    pub index_trust_bundle: Option<String>,
    /// S8 (RFC registry-trust-federation §6.4a, spec §3.4.7): `true` iff the source
    /// declared an `index-trust` node explicitly (absent-stays-absent, not
    /// value-based). This distinguishes an explicit `index-trust "warn"` (which
    /// still matches the default) from a genuinely absent node — the workspace
    /// member-declaration check (`WS-INDEX-TRUST-ON-MEMBER`) fires on WHERE the
    /// field is declared, not what value it holds, so it needs this flag rather
    /// than just testing `index_trust_policy != Warn`.
    pub index_trust_policy_explicit: bool,
    /// P3a (RFC per-entry-attestation.md §4): per-entry author-attribution
    /// gate policy from `entry-trust "warn"|"strict"|"off"` (default: warn).
    /// Root-scoped like `index_trust_policy` (one shared graph, one trust
    /// posture) but simpler — no signer/bundle sub-fields.
    pub entry_trust_policy: TrustPolicy,
    /// `true` iff the source declared an `entry-trust` node explicitly
    /// (absent-stays-absent, mirrors `index_trust_policy_explicit`). A
    /// workspace MEMBER manifest that explicitly declares `entry-trust
    /// "warn"` must still raise `WS-ENTRY-TRUST-ON-MEMBER` even though the
    /// value matches the default.
    pub entry_trust_policy_explicit: bool,
    /// A3 (rfc-registry-append-only.md §2; registry-protocol §3.5.2): the
    /// append-only consumer ratchet's policy axis from `index-history
    /// "warn"|"strict"|"off"` (default: warn). Root-scoped like
    /// `index_trust_policy`/`entry_trust_policy` — one shared baseline per
    /// effective index URL, not per member.
    pub index_history_policy: TrustPolicy,
    /// `true` iff the source declared an `index-history` node explicitly
    /// (absent-stays-absent, mirrors `entry_trust_policy_explicit`). A
    /// workspace MEMBER manifest that explicitly declares `index-history
    /// "warn"` must still raise `WS-INDEX-HISTORY-ON-MEMBER` even though the
    /// value matches the default.
    pub index_history_policy_explicit: bool,
    /// S7: flag names that were auto-injected by optional-dep desugaring.
    /// `format_manifest` skips these from the `flags {}` block (they're implied
    /// by `optional=#true` on the dep; serializing them would cause a re-parse clash).
    pub optional_auto_flags: std::collections::BTreeSet<String>,
    /// C3 (rfc-resolution-semantics.md §3 Axis C / §5): manifest-level
    /// resolution policy (`resolution { strategy "..." }`). `None` means no
    /// `resolution { }` node was declared at all.
    pub resolution: Option<Resolution>,
    /// S7 (rfc-origin-as-identity.md §4.6): the package's own declared Nim
    /// import symbols, from a top-level `provides { module "x" ... }` block.
    /// Consumed by `ManifestDeclaredSymbolProvider` (`import_slot.rs`).
    /// Empty (the default) means this manifest declares no `provides` block.
    /// Package-only — a workspace root has no `provides` concept (mirrors
    /// Python's `Manifest.provides`; `WorkspaceManifest` has no such field).
    pub provides: Vec<String>,
}

/// A parsed workspace-root `milpa.kdl` (grammar §7). Pure container: member
/// directory paths + optional workspace-level overrides. Member *names* are
/// intrinsic to each member's own manifest and resolved at workspace-load
/// time (S11) — at parse time a member is just its path.
///
/// S11 (RFC #23 §3.8): workspace root may carry a `flags {}` block whose
/// default-true activations apply workspace-wide. Reuses `FlagDecl` (SSOT —
/// no parallel flag type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    pub members: Vec<String>,
    pub overrides: Vec<Override>,
    pub flags: Vec<FlagDecl>,  // S11: workspace-root flags (§3.8)
    /// Optional workspace root name (grammar §7 `name` node).
    /// `None` when absent; `Some(name)` when declared.
    pub name: Option<String>,
    /// S8 (RFC registry-trust-federation §6.4a, spec §3.4.7 root-authority model):
    /// the workspace root IS the resolution root for index-trust purposes, so it
    /// — and ONLY it — may declare `index-trust` / `index-trust-signer` /
    /// `index-trust-bundle`. Defaults to `Strict` when the node is absent (S4;
    /// same default as the package-manifest field). No merge across members: this
    /// single value IS the effective policy for the whole workspace invocation.
    pub index_trust_policy: TrustPolicy,
    /// S8: expected SubjectAltName override from the workspace-root
    /// `index-trust-signer "<identity>"` node.
    pub index_trust_signer: Option<String>,
    /// S8: trust-root override (file:// path) from the workspace-root
    /// `index-trust-bundle "<path>"` node.
    pub index_trust_bundle: Option<String>,
    /// Medium code-review finding (mirrors `Manifest::index_trust_policy_explicit`
    /// and Python's `WorkspaceManifest.index_trust_policy_explicit`): `true`
    /// iff the workspace root source declared an `index-trust` node
    /// explicitly (absent-stays-absent, not value-based). Without this,
    /// `format_workspace_manifest` cannot distinguish an explicit
    /// `index-trust "warn"` (legal, redundant with the default, but
    /// hand-authored and expected to survive a rewrite) from a genuinely
    /// absent node — `milpa workspace add-member`/`remove-member` would
    /// silently drop the former on the next `milpa.kdl` rewrite.
    pub index_trust_policy_explicit: bool,
    /// P3a (RFC per-entry-attestation.md §4): entry-trust, declared ONLY on
    /// the resolution root — same root-authority model as index-trust. A
    /// member manifest declaring it raises `WS-ENTRY-TRUST-ON-MEMBER` at
    /// workspace-load time (`workspace.rs`, not this module).
    pub entry_trust_policy: TrustPolicy,
    /// `true` iff the source declared an `entry-trust` node (absent-stays-
    /// absent rule, mirrors `Manifest::entry_trust_policy_explicit`).
    pub entry_trust_policy_explicit: bool,
    /// A3 (rfc-registry-append-only.md §2): index-history, declared ONLY on
    /// the resolution root — same root-authority model as index-trust /
    /// entry-trust. A member manifest declaring it raises
    /// `WS-INDEX-HISTORY-ON-MEMBER` at workspace-load time (`workspace.rs`).
    pub index_history_policy: TrustPolicy,
    /// `true` iff the source declared an `index-history` node (absent-stays-
    /// absent rule, mirrors `Manifest::index_history_policy_explicit`).
    pub index_history_policy_explicit: bool,
    /// C3 (rfc-resolution-semantics.md §3 Axis C / §5, Axis W): root-only
    /// resolution policy — see `Manifest::resolution` for the field's
    /// semantics; identical here, just declared on the workspace root.
    pub resolution: Option<Resolution>,
}

impl Default for Workspace {
    /// Hand-written (not derived) so the trust-policy defaults match the parse
    /// defaults exactly (SSOT): S4 flipped `index-trust`/`entry-trust` to
    /// `Strict`, while `index-history` stays `Warn`. A derived `Default` would
    /// use `TrustPolicy::default()` for all three, silently disagreeing with
    /// what parsing an absent node yields.
    fn default() -> Self {
        Self {
            members: Vec::new(),
            overrides: Vec::new(),
            flags: Vec::new(),
            name: None,
            index_trust_policy: TrustPolicy::Strict,
            index_trust_signer: None,
            index_trust_bundle: None,
            index_trust_policy_explicit: false,
            entry_trust_policy: TrustPolicy::Strict,
            entry_trust_policy_explicit: false,
            index_history_policy: TrustPolicy::Warn,
            index_history_policy_explicit: false,
            resolution: None,
        }
    }
}

/// The two disjoint manifest roles (grammar §1). Detected by the presence of a
/// top-level `workspace { }` node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestDoc {
    Package(Manifest),
    Workspace(Workspace),
}

/// The build profile used to evaluate `when`/predicate blocks. Absent profile
/// ⇒ all conditional deps included (RFC §4.4). This carries the inputs; the
/// predicate *evaluation* against a profile is a resolver concern (S7b/S13,
/// fixture-115). Mirrors the four `MILPA_TARGET_*` axes of the Python `Profile`
/// (platform / arch / nim / milpa) plus the active feature `flags`. Each axis is
/// `Option`: an absent axis matches no predicate of that name (the resolver's
/// `getattr(profile, name, None)`-equivalent).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    pub platform: Option<String>,
    pub arch: Option<String>,
    pub nim_version: Option<Version>,
    pub milpa_version: Option<Version>,
    pub flags: Vec<String>,
}

// ---------------------------------------------------------------------------
// Error model — one struct carrying a stable catalog code (mirrors the Python
// `ManifestError(message, code=...)` shape). Conformance compares `.code()`
// only; message text is informational.
// ---------------------------------------------------------------------------

/// A manifest parse / schema-validation failure carrying a stable
/// `spec/errors.md` slug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    pub code: &'static str,
    pub message: String,
}

impl ManifestError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        ManifestError {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    /// Every catalog code this domain can currently emit (parity companion to
    /// `code()`, read by the conformance subset/bijection check). Every entry
    /// MUST be a real slug in `spec/errors.md`. The file-I/O, mutation,
    /// and `.nimble`-IO codes (`MAN-FILE-*`, `MAN-NO-MANIFEST`,
    /// `MAN-NIMBLE-AMBIGUOUS`, `MAN-MUTATE-*`, `MAN-MIRROR-EDITABLE-PROVENANCE`) are NOT
    /// listed: they are raised by the CLI discovery / mutation layers (S13/D-add),
    /// not by the pure-text parser, and are unit-test-only (not
    /// fixture-expressible).
    pub fn all_codes() -> &'static [&'static str] {
        MAN_CODES
    }
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for ManifestError {}

/// The structural `MAN-*` codes the text parser can emit. Kept as the SSOT for
/// `all_codes()`; ordered roughly by grammar section for auditability.
const MAN_CODES: &[&str] = &[
    "MAN-KDL-SYNTAX",
    // Raised by the resolver (S7b) when a transitive `.nimble` `requires`
    // carries a malformed version constraint — surfaced as a `ManifestError`
    // (the slug is `MAN-*`) so the boundary stays one domain. Not produced by
    // the milpa.kdl text parser, but it IS a code this domain emits.
    "MAN-NIMBLE-CONSTRAINT",
    // Manifest discovery / loading (milpa-core `discovery`) — S13. Emitted via
    // `ManifestError` (the MAN-* domain) though raised from the integration crate.
    "MAN-FILE-NOT-FOUND",
    "MAN-FILE-UNREADABLE",
    "MAN-NO-MANIFEST",
    "MAN-NIMBLE-AMBIGUOUS",
    // Manifest mutation (milpa-core `manifest_writer`) — S13.
    "MAN-MUTATE-FILE-NOT-FOUND",
    "MAN-MUTATE-NIMBLE-REFUSED",
    "MAN-MUTATE-WORKSPACE-REFUSED",
    // `milpa add --git` duplicate-dep guard (CLI cmd_add) — Gap-1/S1c.
    "MAN-ADD-DEP-EXISTS",
    // `milpa remove` absent-dep guard (CLI cmd_remove) — Gap-1/S1c.
    "MAN-REMOVE-DEP-ABSENT",
    // `milpa add --mirror` editable-provenance guard (CLI cmd_add) — D-add.
    "MAN-MIRROR-EDITABLE-PROVENANCE",
    "MAN-URL-ARG-TYPE",
    "MAN-UNKNOWN-TOP-LEVEL",
    "MAN-NAME-MISSING",
    "MAN-NAME-DUPLICATE",
    "MAN-NAME-TYPE",
    "MAN-KIND-ARITY",
    "MAN-KIND-INVALID",
    "MAN-SRC-DIR-TYPE",
    "MAN-SRC-DIR-UNSAFE",
    "MAN-CAS-DIR-MISSING",
    "MAN-CAS-DIR-TYPE",
    "MAN-SPEC-VERSION-TYPE",
    "MAN-SPEC-VERSION-UNSUPPORTED",
    "MAN-PACKAGE-VERSION-INVALID",
    "MAN-DEP-DUPLICATE",
    "MAN-DEP-NAME-INVALID",
    "MAN-DEP-OPTIONAL-FLAG-CLASH",
    "MAN-DEP-OPTIONAL-INVALID-NAME",
    "MAN-DEP-UNKNOWN-PROPS",
    "MAN-DEP-REF-MISSING",
    "MAN-DEP-LOCAL-PATH",
    "MAN-DEP-TARBALL-URL",
    "MAN-DEP-TARBALL-SHA",
    "MAN-DEP-TARBALL-STRIP",
    "MAN-DEP-MEMBER-PROPS",
    "MAN-DEP-MEMBER-ARITY",
    "MAN-MEMBER-WHEN-GATED",
    "MAN-DEP-NAMED-PROPS",
    "MAN-DEP-NAMED-CONSTRAINT",
    "MAN-DEP-NAMED-ARITY",
    "MAN-DEP-MIRROR-ARITY",
    "MAN-DEP-FLAG-NAME-MISSING",
    "MAN-DEP-FLAG-TOO-MANY-ARGS",
    "MAN-DEP-FLAG-BOOL",
    "MAN-DEP-UNKNOWN-CHILD",
    "MAN-DEP-VERSION-INVALID",
    "MAN-GIT-URL-NO-SCHEME",
    "MAN-GIT-URL-BAD-SCHEME",
    "MAN-OVERRIDE-KIND",
    "MAN-OVERRIDE-ARITY",
    "MAN-OVERRIDE-UNKNOWN-PROPS",
    "MAN-OVERRIDE-TARGET-AMBIGUOUS",
    "MAN-OVERRIDE-GIT-MISSING",
    "MAN-OVERRIDE-REF-MISSING",
    "MAN-OVERRIDE-DUPLICATE",
    // S8b (rfc-origin-as-identity.md §7 B5): the three extended override
    // target kinds (oci/tarball/named-registry) — mirrors Python's
    // manifest.py exactly.
    "MAN-OVERRIDE-OCI-MALFORMED",
    "MAN-OVERRIDE-DIGEST-MISSING",
    "MAN-OVERRIDE-NAMED-MISSING",
    // S7 (rfc-origin-as-identity.md §4.6): the `provides { module "x" }`
    // manifest block.
    "MAN-PROVIDES-UNKNOWN-NODE",
    "MAN-PROVIDES-MODULE-ARITY",
    "MAN-FLAG-CONFLICTS-UNDECLARED",
    "MAN-FLAG-CONFLICTS-SELF",
    "MAN-FLAG-DEFINES-UNSAFE",
    "MAN-FLAG-DUPLICATE",
    "MAN-FLAG-ENABLES-UNDECLARED",
    "MAN-FLAG-NAME-INVALID",
    "MAN-FLAG-POS-ARGS",
    "MAN-FLAG-UNKNOWN-PROPS",
    "MAN-FLAG-DEFAULT-TYPE",
    "MAN-FLAG-DESCRIPTION-TYPE",
    "MAN-FLAG-UNKNOWN-CHILD",
    "MAN-FLAG-DEFINES-ARG-TYPE",
    "MAN-FLAG-UNDECLARED-REFERENCE",
    "MAN-PREDICATE-UNKNOWN",
    "MAN-PREDICATE-VALUE-TYPE",
    "MAN-PREDICATE-UNSUPPORTED-ANNOTATION",
    "MAN-PREDICATE-CHILD-NO-ARGS",
    "MAN-PREDICATE-CHILD-ARG-TYPE",
    "MAN-PREDICATE-MIXED-NEGATION",
    "MAN-PREDICATE-FORM-CONFLICT",
    "MAN-MIRRORS-UNKNOWN-CHILD",
    "MAN-MIRRORS-ARITY",
    "MAN-WORKSPACE-IN-PACKAGE",
    "MAN-WORKSPACE-HAS-DEPS-OR-KIND",
    "MAN-WORKSPACE-UNKNOWN-NODE",
    "MAN-WORKSPACE-MEMBER-ARITY",
    "MAN-WORKSPACE-MEMBER-DUPLICATE",
    "MAN-WORKSPACE-UNKNOWN-TOP-LEVEL",
    "MAN-RESOLUTION-BLOCK-INVALID",
    "MAN-RESOLUTION-EXCLUDE-NEWER-INVALID",
    "MAN-RESOLUTION-STRATEGY-INVALID",
];

fn err(code: &'static str, message: impl Into<String>) -> ManifestError {
    ManifestError::new(code, message)
}

// ---------------------------------------------------------------------------
// kdl-rs access helpers. In kdl-rs a node's `entries()` mixes positional
// arguments (`entry.name() == None`) with properties (`entry.name() == Some`).
// ---------------------------------------------------------------------------

/// Positional arguments of a node, in source order.
fn args(node: &KdlNode) -> Vec<&KdlEntry> {
    node.entries()
        .iter()
        .filter(|e| e.name().is_none())
        .collect()
}

/// Property entries of a node as `(key, entry)`, in source order with
/// last-wins deduplication.
///
/// KDL 2.0 §5.5: when the same property key appears more than once on a node,
/// the last occurrence wins; earlier occurrences are discarded.  This mirrors
/// `kdl-py`'s dict-update semantics so both implementations produce byte-identical
/// output for manifests with duplicate property keys.
fn props(node: &KdlNode) -> Vec<(&str, &KdlEntry)> {
    // Collect all property entries in source order, then keep only the last
    // occurrence of each key (last-wins).  We walk the list twice: once
    // forward to note which index is the last occurrence of each key, then
    // once more to emit only those entries.
    let all: Vec<(&str, &KdlEntry)> = node
        .entries()
        .iter()
        .filter_map(|e| e.name().map(|n| (n.value(), e)))
        .collect();
    // Record the index of the last occurrence for each key.
    let mut last_idx: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    for (i, (k, _)) in all.iter().enumerate() {
        last_idx.insert(k, i);
    }
    // Emit only entries whose index matches the last occurrence of their key.
    all.into_iter()
        .enumerate()
        .filter(|(i, (k, _))| last_idx.get(k) == Some(i))
        .map(|(_, pair)| pair)
        .collect()
}

/// The set of property keys present on a node.
fn prop_names(node: &KdlNode) -> BTreeSet<&str> {
    props(node).into_iter().map(|(k, _)| k).collect()
}

/// Look up a property by key (last-wins, mirroring kdl-py's dict semantics).
fn prop<'a>(node: &'a KdlNode, key: &str) -> Option<&'a KdlEntry> {
    props(node)
        .into_iter()
        .rev()
        .find(|(k, _)| *k == key)
        .map(|(_, e)| e)
}

/// The `(annotation)` type tag on an entry's value, if any (`(url)`, `(not)`).
fn entry_ty(entry: &KdlEntry) -> Option<&str> {
    entry.ty().map(|t| t.value())
}

/// The child nodes of a node's `{ }` block (empty when there is no block).
fn children(node: &KdlNode) -> Vec<&KdlNode> {
    node.children()
        .map(|d| d.nodes().iter().collect())
        .unwrap_or_default()
}

const PREDICATE_PROPS: &[&str] = &["platform", "arch", "nim", "milpa", "flag"];
const URL_DEP_PROPS: &[&str] = &["git", "ref", "platform", "arch", "nim", "milpa", "flag", "optional", "version", "subpath"];
const FLAG_DECL_PROPS: &[&str] = &["default", "description"];
const VALID_KINDS: &[&str] = &["library", "application"];
const VALID_GIT_SCHEMES: &[&str] = &["https", "http", "ssh", "git"];
const PACKAGE_TOP_LEVEL: &[&str] = &[
    "deps",
    "dev-deps",
    "kind",
    "overrides",
    "name",
    "src_dir",
    "flags",
    "mirrors",
    "cas",
    "spec-version",
    // A1 (rfc-resolution-semantics.md §3 Axis A / §5): the package's own
    // declared release version — orthogonal to "spec-version" (the schema
    // epoch). Absent = version-unknown (not an error).
    "version",
    "attestation-policy",
    "index-trust",
    "index-trust-signer",
    "index-trust-bundle",
    // P3a (RFC per-entry-attestation.md §4): per-entry attestation gate.
    "entry-trust",
    // A3 (rfc-registry-append-only.md §2): the append-only consumer ratchet.
    "index-history",
    // C3 (rfc-resolution-semantics.md §3 Axis C / §5): manifest-level
    // resolution policy block. First appearance carries only `strategy`;
    // Axis D's `exclude-newer` extends it in a later slice.
    "resolution",
    // S7 (rfc-origin-as-identity.md §4.6): the package's own declared Nim
    // import symbols.
    "provides",
];
const WORKSPACE_TOP_LEVEL: &[&str] = &[
    "workspace",
    "name",
    "overrides",
    "spec-version",
    "flags",
    "index-trust",
    "index-trust-signer",
    "index-trust-bundle",
    // P3a: per-entry attestation gate, legal ONLY on the workspace root.
    "entry-trust",
    // A3: the append-only consumer ratchet, legal ONLY on the workspace root.
    "index-history",
    // C3 (rfc-resolution-semantics.md §3 Axis C / §5, Axis W): manifest
    // resolution policy — root-only for a workspace (one shared lock, one
    // resolution policy). A member-level `resolution` block is reserved for
    // rejection in a later slice (Axis D/W1).
    "resolution",
];

// ---------------------------------------------------------------------------
// Entry points.
// ---------------------------------------------------------------------------

/// Parse a `milpa.kdl` source into either role (grammar §1). A document with a
/// top-level `workspace` node is a workspace; otherwise a package. This is the
/// auto-detecting entry point the resolver/CLI use.
pub fn parse_document(text: &str) -> Result<ManifestDoc, ManifestError> {
    let doc = parse_kdl(text)?;
    if doc.nodes().iter().any(|n| n.name().value() == "workspace") {
        Ok(ManifestDoc::Workspace(parse_workspace_doc(&doc)?))
    } else {
        Ok(ManifestDoc::Package(parse_manifest_doc(&doc)?))
    }
}

/// Parse a `milpa.kdl` source as a **package** manifest. A `workspace` block on
/// this path is an error (`MAN-WORKSPACE-IN-PACKAGE`) — use [`parse_document`]
/// to accept either role.
pub fn parse_manifest(text: &str) -> Result<Manifest, ManifestError> {
    let doc = parse_kdl(text)?;
    parse_manifest_doc(&doc)
}

/// Parse a `milpa.kdl` source as a **workspace** root.
pub fn parse_workspace(text: &str) -> Result<Workspace, ManifestError> {
    let doc = parse_kdl(text)?;
    parse_workspace_doc(&doc)
}

/// Monotone least-fixpoint of same-package `enables` over one manifest's flag table.
///
/// S2 (RFC #23 §7 + §3.1.2).
///
/// # Arguments
/// - `flags`: the `FlagDecl` slice from a single manifest.
/// - `seed`: the starting active-flag-name set (e.g. default-true flags,
///   CLI-requested flags, or a cross-package request set).
///
/// # Returns
/// The closure: `seed` ∪ every same-package flag reachable by following
/// `enables_same_pkg` edges from any active flag, to a fixed point.
///
/// # Properties (§3.1.2)
/// - **Seed inclusion**: result ⊇ seed.
/// - **Transitive**: follows multi-hop `enables` chains.
/// - **Idempotence**: `closure(closure(S)) == closure(S)`.
/// - **Cycle termination**: `a enables b, b enables a` → `{a, b}` in O(n).
/// - **Order-independence**: result is independent of flag declaration order
///   (union is commutative).
/// - **Cross-package ignored**: `enables_cross_pkg` entries are NOT followed
///   here — they are activated at resolve time in S3/S4a.
/// - **Unknown targets skipped**: any `enables` target not in the flag table
///   is silently ignored (post-parse validation ensures this is unreachable in
///   practice, but the function is safe on partially-built tables).
///
/// # Design note
/// The caller seeds from `default=true` flags
/// (`flags.iter().filter(|f| f.default).map(|f| &f.name)`).
/// Default-seeding is the caller's responsibility — this function is a
/// single-responsibility SSOT for the fixpoint only.
pub fn flag_enables_closure(
    flags: &[FlagDecl],
    seed: &std::collections::HashSet<String>,
) -> std::collections::HashSet<String> {
    use std::collections::{HashMap, HashSet};

    // Build a name→enables_same_pkg lookup for O(1) access.
    let enables_by_name: HashMap<&str, &[String]> = flags
        .iter()
        .map(|fd| (fd.name.as_str(), fd.enables_same_pkg.as_slice()))
        .collect();

    let mut active: HashSet<String> = seed.clone();
    let mut worklist: Vec<String> = seed.iter().cloned().collect();

    while let Some(flag_name) = worklist.pop() {
        if let Some(targets) = enables_by_name.get(flag_name.as_str()) {
            for target in *targets {
                // Only follow same-pkg targets that are actually declared.
                if !active.contains(target) && enables_by_name.contains_key(target.as_str()) {
                    active.insert(target.clone());
                    worklist.push(target.clone());
                }
            }
        }
    }
    active
}

/// Maximum structural `{` brace nesting depth accepted before handing input to
/// the KDL parser.  kdl-rs 6.7.1 is recursive-descent with no internal depth
/// limit; empirical measurement shows it stack-overflows at depth ≈ 50 in
/// debug builds (OS-level SIGABRT — not a catchable panic).  Any real
/// `milpa.kdl`, `milpa.lock`, or `index.kdl` nests at most 4–5 levels deep;
/// 32 is an extremely generous ceiling that simultaneously ensures no
/// real-world document is rejected and that maliciously-crafted deeply-nested
/// input is rejected as `MAN-KDL-SYNTAX` (or `LOCK-KDL-SYNTAX` /
/// `TNG-KDL-SYNTAX`) instead of crashing the process.
///
/// Used by all three KDL parse entry points milpa owns (manifest, lockfile,
/// index).  Single source of truth.
pub const KDL_MAX_NESTING_DEPTH: usize = 32;

/// Return the maximum structural `{` brace nesting depth observed in `text`.
///
/// This is a conservative O(n) pre-scan: it counts every `{` and `}` byte
/// regardless of whether it appears inside a string literal or comment.  It
/// therefore *over-counts* (a `{` inside a KDL string still increments the
/// depth), making it a safe upper bound for the purpose of a guard — any input
/// that passes this check has a *true* structural depth ≤ the reported value,
/// so if the reported value ≤ [`KDL_MAX_NESTING_DEPTH`] the recursive-descent
/// parser will not overflow its call stack.
pub fn kdl_brace_depth(text: &str) -> usize {
    let mut depth: usize = 0;
    let mut max: usize = 0;
    for b in text.bytes() {
        match b {
            b'{' => {
                depth += 1;
                if depth > max {
                    max = depth;
                }
            }
            b'}' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    max
}

/// Return the maximum `/* */` block-comment nesting depth observed in `text`.
///
/// Like [`kdl_brace_depth`], this is a conservative O(n) pre-scan that counts
/// every `/*` and `*/` byte-pair regardless of context (strings, other comments).
/// It over-counts, so it is a safe upper bound.
///
/// KDL 2.0 allows nested block comments (`/* /* */ */`).  kdl-rs is
/// recursive-descent with no internal depth limit; deeply-nested block comments
/// cause the same stack overflow risk as deeply-nested braces.  This guard
/// mirrors Python's `_check_nesting_depth` which tracks both vectors
/// independently.
pub fn kdl_block_comment_depth(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut depth: usize = 0;
    let mut max: usize = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'/' && bytes[i + 1] == b'*' {
            depth += 1;
            if depth > max {
                max = depth;
            }
            i += 2;
            continue;
        }
        if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            depth = depth.saturating_sub(1);
            i += 2;
            continue;
        }
        i += 1;
    }
    max
}

fn parse_kdl(text: &str) -> Result<KdlDocument, ManifestError> {
    // Depth guard: kdl-rs 6.7.1 is recursive-descent with no internal stack
    // limit; deeply-nested input causes an OS stack overflow (SIGABRT — not
    // a catchable panic).  Reject before calling the parser.
    // Both brace depth AND block-comment depth are checked, mirroring Python's
    // `_check_nesting_depth` which tracks both vectors independently.
    if kdl_brace_depth(text) > KDL_MAX_NESTING_DEPTH {
        return Err(err(
            "MAN-KDL-SYNTAX",
            format!(
                "KDL input exceeds maximum nesting depth ({KDL_MAX_NESTING_DEPTH})"
            ),
        ));
    }
    if kdl_block_comment_depth(text) > KDL_MAX_NESTING_DEPTH {
        return Err(err(
            "MAN-KDL-SYNTAX",
            format!(
                "KDL input exceeds maximum block-comment nesting depth ({KDL_MAX_NESTING_DEPTH})"
            ),
        ));
    }
    // KDL **2.0** (grammar §1; #123 migrated from 1.0) — native `parse`.
    // Boolean keywords are `#true`/`#false`; bare `true`/`false` are reserved
    // and rejected as syntax errors.
    KdlDocument::parse(text).map_err(|e| err("MAN-KDL-SYNTAX", format!("KDL syntax error: {e}")))
}

// ---------------------------------------------------------------------------
// Workspace document.
// ---------------------------------------------------------------------------

/// Shared parser for the `index-trust "<policy>"` node (package and
/// workspace-root manifests both accept it — SSOT, no duplication).
fn parse_index_trust_node(node: &KdlNode) -> Result<TrustPolicy, ManifestError> {
    let a = args(node);
    let val = a.first().and_then(|e| e.value().as_string());
    if a.len() != 1 || val.is_none() {
        return Err(err(
            "MAN-UNKNOWN-TOP-LEVEL",
            "'index-trust' takes exactly one string argument \
             ('warn', 'strict', or 'off')",
        ));
    }
    parse_trust_policy(val.unwrap(), "index-trust").map_err(|e| err("MAN-UNKNOWN-TOP-LEVEL", e))
}

/// Shared parser for the `index-trust-signer "<identity>"` node.
fn parse_index_trust_signer_node(node: &KdlNode) -> Result<String, ManifestError> {
    let a = args(node);
    let val = a.first().and_then(|e| e.value().as_string());
    if a.len() != 1 || val.is_none() {
        return Err(err(
            "MAN-UNKNOWN-TOP-LEVEL",
            "'index-trust-signer' takes exactly one string argument \
             (GitHub Actions OIDC workflow URL / expected SubjectAltName)",
        ));
    }
    Ok(val.unwrap().to_string())
}

/// Shared parser for the `index-trust-bundle "<file://path>"` node.
fn parse_index_trust_bundle_node(node: &KdlNode) -> Result<String, ManifestError> {
    let a = args(node);
    let val = a.first().and_then(|e| e.value().as_string());
    if a.len() != 1 || val.is_none() {
        return Err(err(
            "MAN-UNKNOWN-TOP-LEVEL",
            "'index-trust-bundle' takes exactly one string argument \
             (file:// path to Fulcio CA + Rekor public key bundle)",
        ));
    }
    Ok(val.unwrap().to_string())
}

/// Shared parser for the `entry-trust "<policy>"` node (package and
/// workspace-root manifests both accept it). P3a (RFC per-entry-attestation.md
/// §4): shares the `TrustPolicy` type + `parse_trust_policy` mechanism with
/// index-trust / attestation-policy, on its own axis.
fn parse_entry_trust_node(node: &KdlNode) -> Result<TrustPolicy, ManifestError> {
    let a = args(node);
    let val = a.first().and_then(|e| e.value().as_string());
    if a.len() != 1 || val.is_none() {
        return Err(err(
            "MAN-UNKNOWN-TOP-LEVEL",
            "'entry-trust' takes exactly one string argument \
             ('warn', 'strict', or 'off')",
        ));
    }
    parse_trust_policy(val.unwrap(), "entry-trust").map_err(|e| err("MAN-UNKNOWN-TOP-LEVEL", e))
}

/// Shared parser for the `index-history "<policy>"` node (package and
/// workspace-root manifests both accept it). A3 (rfc-registry-append-only.md
/// §2): shares the `TrustPolicy` type + `parse_trust_policy` mechanism with
/// entry-trust / index-trust / attestation-policy, on its own axis.
fn parse_index_history_node(node: &KdlNode) -> Result<TrustPolicy, ManifestError> {
    let a = args(node);
    let val = a.first().and_then(|e| e.value().as_string());
    if a.len() != 1 || val.is_none() {
        return Err(err(
            "MAN-UNKNOWN-TOP-LEVEL",
            "'index-history' takes exactly one string argument \
             ('warn', 'strict', or 'off')",
        ));
    }
    parse_trust_policy(val.unwrap(), "index-history").map_err(|e| err("MAN-UNKNOWN-TOP-LEVEL", e))
}

fn parse_workspace_doc(doc: &KdlDocument) -> Result<Workspace, ManifestError> {
    let mut members: Vec<String> = Vec::new();
    let mut overrides: Vec<Override> = Vec::new();
    let mut seen_override_names: BTreeSet<String> = BTreeSet::new();
    let mut ws_flags: Vec<FlagDecl> = Vec::new();
    let mut ws_name: Option<String> = None;
    // S8 (RFC registry-trust-federation §6.4a): root-authority index-trust fields.
    let mut ws_index_trust_policy = TrustPolicy::Strict;
    let mut ws_index_trust_signer: Option<String> = None;
    let mut ws_index_trust_bundle: Option<String> = None;
    let mut ws_index_trust_policy_explicit = false;
    // P3a (RFC per-entry-attestation.md §4): root-authority entry-trust field.
    let mut ws_entry_trust_policy = TrustPolicy::Strict;
    let mut ws_entry_trust_policy_explicit = false;
    // A3 (rfc-registry-append-only.md §2): root-authority index-history field.
    let mut ws_index_history_policy = TrustPolicy::Warn;
    let mut ws_index_history_policy_explicit = false;
    // C3 (rfc-resolution-semantics.md §3 Axis C / §5): root-only resolution
    // policy block.
    let mut ws_resolution: Option<Resolution> = None;

    for node in doc.nodes() {
        match node.name().value() {
            "spec-version" => {
                check_spec_version(node)?;
            }
            "deps" | "kind" => {
                return Err(err(
                    "MAN-WORKSPACE-HAS-DEPS-OR-KIND",
                    format!(
                        "a workspace manifest must not declare {:?} — workspaces \
                         are pure containers, not packages",
                        node.name().value()
                    ),
                ));
            }
            "index-trust" => {
                ws_index_trust_policy = parse_index_trust_node(node)?;
                ws_index_trust_policy_explicit = true;
            }
            "index-trust-signer" => {
                ws_index_trust_signer = Some(parse_index_trust_signer_node(node)?);
            }
            "index-trust-bundle" => {
                ws_index_trust_bundle = Some(parse_index_trust_bundle_node(node)?);
            }
            "entry-trust" => {
                // P3a (RFC per-entry-attestation.md §4): root-authority policy.
                ws_entry_trust_policy = parse_entry_trust_node(node)?;
                ws_entry_trust_policy_explicit = true;
            }
            "index-history" => {
                // A3 (rfc-registry-append-only.md §2): root-authority policy.
                ws_index_history_policy = parse_index_history_node(node)?;
                ws_index_history_policy_explicit = true;
            }
            "resolution" => {
                // C3 (rfc-resolution-semantics.md §3 Axis C / §5): root-only
                // resolution policy block.
                ws_resolution = Some(check_resolution_block(node)?);
            }
            "workspace" => {
                for child in children(node) {
                    if child.name().value() != "member" {
                        return Err(err(
                            "MAN-WORKSPACE-UNKNOWN-NODE",
                            format!(
                                "unknown node {:?} in workspace block (allowed: 'member')",
                                child.name().value()
                            ),
                        ));
                    }
                    let a = args(child);
                    if a.len() != 1 || a[0].value().as_string().is_none() {
                        return Err(err(
                            "MAN-WORKSPACE-MEMBER-ARITY",
                            "workspace 'member' takes exactly one positional string \
                             argument (the member directory path)",
                        ));
                    }
                    let path = a[0].value().as_string().unwrap().to_string();
                    if members.contains(&path) {
                        return Err(err(
                            "MAN-WORKSPACE-MEMBER-DUPLICATE",
                            format!("duplicate workspace member {path:?}"),
                        ));
                    }
                    members.push(path);
                }
            }
            "overrides" => {
                for child in children(node) {
                    let ov = parse_override(child)?;
                    if !seen_override_names.insert(ov.name.clone()) {
                        return Err(err(
                            "MAN-OVERRIDE-DUPLICATE",
                            format!("duplicate override for {:?}", ov.name),
                        ));
                    }
                    let ov = finish_override_version(child, ov)?;
                    overrides.push(ov);
                }
            }
            "flags" => {
                // S11 (RFC #23 §3.8): workspace-root flags {}.
                // Reuses parse_flag_decl (SSOT).
                for child in children(node) {
                    ws_flags.push(parse_flag_decl(child)?);
                }
            }
            "name" => {
                // grammar §7: optional workspace root name.
                let a = args(node);
                if !a.is_empty() {
                    if let Some(s) = a[0].value().as_string() {
                        ws_name = Some(s.to_string());
                    }
                }
            }
            other => {
                return Err(err(
                    "MAN-WORKSPACE-UNKNOWN-TOP-LEVEL",
                    format!(
                        "unknown top-level node {other:?} in workspace manifest \
                         (allowed: {})",
                        WORKSPACE_TOP_LEVEL.join(", ")
                    ),
                ));
            }
        }
    }

    Ok(Workspace {
        members,
        overrides,
        flags: ws_flags,
        name: ws_name,
        index_trust_policy: ws_index_trust_policy,
        index_trust_signer: ws_index_trust_signer,
        index_trust_bundle: ws_index_trust_bundle,
        index_trust_policy_explicit: ws_index_trust_policy_explicit,
        entry_trust_policy: ws_entry_trust_policy,
        entry_trust_policy_explicit: ws_entry_trust_policy_explicit,
        index_history_policy: ws_index_history_policy,
        index_history_policy_explicit: ws_index_history_policy_explicit,
        resolution: ws_resolution,
    })
}

// ---------------------------------------------------------------------------
// Package document.
// ---------------------------------------------------------------------------

/// S7 (RFC #23 §3.2): parse-time desugaring of `optional=#true` deps.
///
/// Desugaring rules:
/// 1. Namespace hygiene: non-optional deps must not share a name with any
///    declared flag (raises `MAN-DEP-OPTIONAL-FLAG-CLASH`).
/// 2. For each optional dep:
///    a. Clash check: name must not collide with any already-declared or
///       already-auto-injected flag (raises `MAN-DEP-OPTIONAL-FLAG-CLASH`).
///    b. Auto-inject a `FlagDecl { name: dep.name, default: false }`.
///    c. Inject a gate predicate `flag=<depname>` onto the dep (idempotent).
/// 3. Returns `(deps, dev_deps, updated_flags, auto_flag_names)`.
///
/// Note: charset validation (`[A-Za-z0-9_-]+`) is performed earlier by the
/// dep-name parser (`MAN-DEP-NAME-INVALID`), which runs for ALL five dep forms
/// (UrlDep, NamedDep, LocalDep, TarballDep, MemberDep) before optional
/// desugaring.  `MAN-DEP-OPTIONAL-INVALID-NAME` is only raised by
/// `milpa add --optional` when the supplied name violates the flag-name charset.
fn desugar_optional_deps(
    deps: Vec<Dep>,
    dev_deps: Vec<Dep>,
    mut flags: Vec<FlagDecl>,
    declared: &BTreeSet<String>,
) -> Result<(Vec<Dep>, Vec<Dep>, Vec<FlagDecl>, std::collections::BTreeSet<String>), ManifestError>
{
    use std::collections::BTreeSet;

    // Namespace hygiene: non-optional deps must not share names with declared flags.
    for dep in deps.iter().chain(dev_deps.iter()) {
        let is_optional = match dep {
            Dep::Url(u) => u.optional,
            Dep::Named(n) => n.optional,
            _ => false,
        };
        if !is_optional && declared.contains(dep.name()) {
            return Err(err(
                "MAN-DEP-OPTIONAL-FLAG-CLASH",
                format!(
                    "dep {:?} shares a name with a declared flag — rename the dep or the flag",
                    dep.name()
                ),
            ));
        }
    }

    let mut injected: BTreeSet<String> = BTreeSet::new();

    let desugar_dep = |dep: Dep,
                       flags: &mut Vec<FlagDecl>,
                       injected: &mut BTreeSet<String>|
     -> Result<Dep, ManifestError> {
        let is_optional = match &dep {
            Dep::Url(u) => u.optional,
            Dep::Named(n) => n.optional,
            _ => false,
        };
        if !is_optional {
            return Ok(dep);
        }
        let dep_nm = dep.name().to_string();

        // 1. Clash check.
        if declared.contains(&dep_nm) || injected.contains(&dep_nm) {
            return Err(err(
                "MAN-DEP-OPTIONAL-FLAG-CLASH",
                format!(
                    "optional dep {dep_nm:?}: name collides with an already-declared flag"
                ),
            ));
        }

        // 2. Inject auto-flag.
        injected.insert(dep_nm.clone());
        flags.push(FlagDecl {
            name: dep_nm.clone(),
            default: false,
            description: String::new(),
            defines: Vec::new(),
            enables_same_pkg: Vec::new(),
            enables_cross_pkg: Vec::new(),
            conflicts: Vec::new(),
        });

        // 3. Inject gate predicate (idempotent).
        let gate_pred = Predicate {
            name: "flag".to_string(),
            values: vec![dep_nm.clone()],
            negated: false,
        };

        match dep {
            Dep::Url(mut u) => {
                if !u.predicates.contains(&gate_pred) {
                    u.predicates.push(gate_pred);
                }
                Ok(Dep::Url(u))
            }
            Dep::Named(mut n) => {
                if !n.predicates.contains(&gate_pred) {
                    n.predicates.push(gate_pred);
                }
                Ok(Dep::Named(n))
            }
            other => Ok(other),
        }
    };

    let mut new_deps = Vec::with_capacity(deps.len());
    for dep in deps {
        new_deps.push(desugar_dep(dep, &mut flags, &mut injected)?);
    }
    let mut new_dev_deps = Vec::with_capacity(dev_deps.len());
    for dep in dev_deps {
        new_dev_deps.push(desugar_dep(dep, &mut flags, &mut injected)?);
    }

    Ok((new_deps, new_dev_deps, flags, injected))
}

fn parse_manifest_doc(doc: &KdlDocument) -> Result<Manifest, ManifestError> {
    let mut deps: Vec<Dep> = Vec::new();
    let mut dev_deps: Vec<Dep> = Vec::new();
    let mut overrides: Vec<Override> = Vec::new();
    let mut flags: Vec<FlagDecl> = Vec::new();
    let mut self_mirrors: Vec<String> = Vec::new();
    let mut kind: String = "library".to_string();
    let mut name: Option<String> = None;
    let mut src_dir = String::new();
    let mut cas_dir = String::new();
    let mut spec_version: i64 = 1;
    let mut spec_version_explicit = false;
    // A1: top-level package `version` field (§3 Axis A (b) step 1).
    let mut version: Option<Version> = None;
    let mut attestation_policy = TrustPolicy::Warn;
    let mut index_trust_policy = TrustPolicy::Strict;
    let mut index_trust_signer: Option<String> = None;
    let mut index_trust_bundle: Option<String> = None;
    let mut index_trust_policy_explicit = false;
    // P3a (RFC per-entry-attestation.md §4): entry-trust node.
    let mut entry_trust_policy = TrustPolicy::Strict;
    let mut entry_trust_policy_explicit = false;
    // A3 (rfc-registry-append-only.md §2): index-history node.
    let mut index_history_policy = TrustPolicy::Warn;
    let mut index_history_policy_explicit = false;
    // C3 (rfc-resolution-semantics.md §3 Axis C / §5): resolution { } block.
    let mut resolution: Option<Resolution> = None;
    // S7 (rfc-origin-as-identity.md §4.6): provides { module "x" } block.
    let mut provides: Vec<String> = Vec::new();

    // S5b: seen_names key is the solver variable (namespace::name or bare name),
    // so two qualified deps with the same bare name but different namespaces
    // are NOT considered duplicates (matches Python _parse_dep_block logic).
    // M1: route through DepKey::solver_var() — SOLE join site for "::" (SSOT).
    let dep_unique_key = |dep: &Dep| -> String {
        match dep {
            Dep::Named(n) => DepKey { name: n.name.clone(), namespace: n.namespace.clone() }.solver_var(),
            other => other.name().to_string(),
        }
    };
    let mut seen_names: BTreeSet<String> = BTreeSet::new();
    let mut seen_dev_dep_names: BTreeSet<String> = BTreeSet::new();
    let mut seen_override_names: BTreeSet<String> = BTreeSet::new();
    let mut seen_flag_names: BTreeSet<String> = BTreeSet::new();

    for node in doc.nodes() {
        match node.name().value() {
            "spec-version" => {
                spec_version = check_spec_version(node)?;
                spec_version_explicit = true;
            }
            "version" => {
                // A1: the package's own declared release version, distinct
                // from "spec-version" (the schema epoch). milpa.kdl is
                // milpa's own strict manifest format, so a malformed value is
                // a hard parse error — unlike the `.nimble` compat scanner,
                // which falls through to version-unknown (totality contract).
                version = Some(check_package_version(node)?);
            }
            "name" => {
                if name.is_some() {
                    return Err(err(
                        "MAN-NAME-DUPLICATE",
                        "duplicate top-level 'name' node — only one allowed",
                    ));
                }
                let a = args(node);
                let val = a.first().and_then(|e| e.value().as_string());
                if a.len() != 1 || val.is_none() {
                    return Err(err(
                        "MAN-NAME-TYPE",
                        "'name' takes exactly one positional string argument",
                    ));
                }
                name = Some(val.unwrap().to_string());
            }
            "src_dir" => {
                let a = args(node);
                let val = a.first().and_then(|e| e.value().as_string());
                if a.len() != 1 || val.is_none() {
                    return Err(err(
                        "MAN-SRC-DIR-TYPE",
                        "'src_dir' takes exactly one positional string argument",
                    ));
                }
                let v = val.unwrap();
                // R2-C2 + R2-Unicode fix: reject control chars and Unicode line
                // separators — src_dir flows verbatim to nim.cfg --path: lines.
                if contains_unsafe_char(v) {
                    return Err(err(
                        "MAN-SRC-DIR-UNSAFE",
                        format!(
                            "'src_dir' value contains a control character or \
                             Unicode line separator (U+2028/U+2029) — this would allow \
                             nim.cfg injection; rejected at parse boundary"
                        ),
                    ));
                }
                src_dir = v.to_string();
            }
            "cas" => {
                cas_dir = parse_cas(node)?;
            }
            "kind" => {
                kind = parse_kind(node)?;
            }
            "deps" => {
                for child in children(node) {
                    for dep in expand_dep_child(child, &[])? {
                        let key = dep_unique_key(&dep);
                        if !seen_names.insert(key.clone()) {
                            return Err(err(
                                "MAN-DEP-DUPLICATE",
                                format!("duplicate dep {:?} in manifest", dep.name()),
                            ));
                        }
                        deps.push(dep);
                    }
                }
            }
            "dev-deps" => {
                for child in children(node) {
                    for dep in expand_dep_child(child, &[])? {
                        let key = dep_unique_key(&dep);
                        if !seen_dev_dep_names.insert(key.clone()) {
                            return Err(err(
                                "MAN-DEP-DUPLICATE",
                                format!("duplicate dep {:?} in manifest", dep.name()),
                            ));
                        }
                        dev_deps.push(dep);
                    }
                }
            }
            "overrides" => {
                for child in children(node) {
                    let ov = parse_override(child)?;
                    if !seen_override_names.insert(ov.name.clone()) {
                        return Err(err(
                            "MAN-OVERRIDE-DUPLICATE",
                            format!("duplicate override for {:?}", ov.name),
                        ));
                    }
                    let ov = finish_override_version(child, ov)?;
                    overrides.push(ov);
                }
            }
            "flags" => {
                for child in children(node) {
                    let fd = parse_flag_decl(child)?;
                    if !seen_flag_names.insert(fd.name.clone()) {
                        return Err(err(
                            "MAN-FLAG-DUPLICATE",
                            format!("duplicate flag declaration {:?}", fd.name),
                        ));
                    }
                    flags.push(fd);
                }
            }
            "mirrors" => {
                for child in children(node) {
                    if child.name().value() != "mirror" {
                        return Err(err(
                            "MAN-MIRRORS-UNKNOWN-CHILD",
                            format!(
                                "unknown child node {:?} in mirrors block (allowed: 'mirror')",
                                child.name().value()
                            ),
                        ));
                    }
                    let a = args(child);
                    if a.len() != 1 {
                        return Err(err(
                            "MAN-MIRRORS-ARITY",
                            "top-level 'mirror' takes exactly one positional URL argument",
                        ));
                    }
                    self_mirrors.push(url_arg("top-level mirrors", "mirror", a[0])?);
                }
            }
            "provides" => {
                // S7 (rfc-origin-as-identity.md §4.6): the package's own
                // declared Nim import symbols. Each child MUST be named
                // `module` and carry exactly one string argument.
                for child in children(node) {
                    if child.name().value() != "module" {
                        return Err(err(
                            "MAN-PROVIDES-UNKNOWN-NODE",
                            format!(
                                "unknown node {:?} in 'provides' block (only 'module' is allowed)",
                                child.name().value()
                            ),
                        ));
                    }
                    let a = args(child);
                    let val = a.first().and_then(|e| e.value().as_string());
                    if a.len() != 1 || val.is_none() {
                        return Err(err(
                            "MAN-PROVIDES-MODULE-ARITY",
                            "'provides.module' takes exactly one positional string argument \
                             (a Nim-importable module path)",
                        ));
                    }
                    provides.push(val.unwrap().to_string());
                }
            }
            "attestation-policy" => {
                let a = args(node);
                let val = a.first().and_then(|e| e.value().as_string());
                if a.len() != 1 || val.is_none() {
                    return Err(err(
                        "MAN-UNKNOWN-TOP-LEVEL",
                        "'attestation-policy' takes exactly one string argument \
                         ('warn', 'strict', or 'off')",
                    ));
                }
                attestation_policy = parse_trust_policy(val.unwrap(), "attestation-policy")
                    .map_err(|e| err("MAN-UNKNOWN-TOP-LEVEL", e))?;
            }
            "index-trust" => {
                index_trust_policy = parse_index_trust_node(node)?;
                index_trust_policy_explicit = true;
            }
            "index-trust-signer" => {
                index_trust_signer = Some(parse_index_trust_signer_node(node)?);
            }
            "index-trust-bundle" => {
                index_trust_bundle = Some(parse_index_trust_bundle_node(node)?);
            }
            "entry-trust" => {
                // P3a: per-entry author-attribution gate policy (RFC §4).
                entry_trust_policy = parse_entry_trust_node(node)?;
                entry_trust_policy_explicit = true;
            }
            "index-history" => {
                // A3: the append-only consumer ratchet policy (RFC §2).
                index_history_policy = parse_index_history_node(node)?;
                index_history_policy_explicit = true;
            }
            "resolution" => {
                // C3 (rfc-resolution-semantics.md §3 Axis C / §5): manifest
                // resolution policy block.
                resolution = Some(check_resolution_block(node)?);
            }
            "workspace" => {
                return Err(err(
                    "MAN-WORKSPACE-IN-PACKAGE",
                    "'workspace' block found in a package manifest — workspace and \
                     package roles are disjoint; use parse_document to accept either",
                ));
            }
            other => {
                return Err(err(
                    "MAN-UNKNOWN-TOP-LEVEL",
                    format!(
                        "unknown top-level node {other:?} (allowed: {})",
                        PACKAGE_TOP_LEVEL.join(", ")
                    ),
                ));
            }
        }
    }

    if name.is_none() {
        return Err(err(
            "MAN-NAME-MISSING",
            "package manifest is missing required top-level 'name' node",
        ));
    }

    // S7 (RFC #23 §3.2): parse-time optional desugaring.
    // Runs FIRST among the post-parse passes so auto-injected flag names are
    // visible to the reference checks (enables, conflicts, flag predicates) below.
    let dep_names: BTreeSet<String> = deps
        .iter()
        .chain(dev_deps.iter())
        .filter_map(|d| match d {
            Dep::Member(_) => None,
            d => Some(d.name().to_string()),
        })
        .collect();

    // Pre-desugar declared flag set (subset of what the desugar function needs
    // to perform namespace-hygiene checks).
    let pre_desugar_declared: BTreeSet<String> =
        flags.iter().map(|f| f.name.clone()).collect();

    let (deps, dev_deps, flags, optional_auto_flags) =
        desugar_optional_deps(deps, dev_deps, flags, &pre_desugar_declared)?;

    // Recompute `declared` after desugar (auto-injected flags are now visible).
    let declared: BTreeSet<String> = flags.iter().map(|f| f.name.clone()).collect();

    // `when flag="X"` must reference a declared flag (grammar §3.5).
    // Runs AFTER desugar so auto-gate predicates don't falsely trigger this.
    for dep in deps.iter().chain(dev_deps.iter()) {
        for pred in dep.predicates() {
            if pred.name != "flag" {
                continue;
            }
            for v in &pred.values {
                if !declared.contains(v.as_str()) {
                    return Err(err(
                        "MAN-FLAG-UNDECLARED-REFERENCE",
                        format!(
                            "dep {:?}: `when flag={v:?}` references an undeclared flag",
                            dep.name()
                        ),
                    ));
                }
            }
        }
    }

    // S1 (RFC #23 §3.1.1): Post-parse validation for `enables` bare same-pkg names.
    // Runs AFTER desugar so `enables "optlib"` for `optlib optional=#true` dep is valid.
    for fd in &flags {
        for flag_name_ref in &fd.enables_same_pkg {
            if !declared.contains(flag_name_ref.as_str()) {
                let base = format!(
                    "flag {:?}: enables references undeclared flag {:?}",
                    fd.name, flag_name_ref
                );
                let msg = if dep_names.contains(flag_name_ref.as_str()) {
                    format!(
                        "{base} ({flag_name_ref:?} is a dependency, not a flag\
                         — add optional=#true to make it a feature)"
                    )
                } else {
                    base
                };
                return Err(err("MAN-FLAG-ENABLES-UNDECLARED", msg));
            }
        }
    }

    // M5: Post-parse validation for `conflicts` bare same-pkg names.
    // Forward references are legal (we validate AFTER the full flags table is built).
    // Same-package only — cross-package conflicts deferred (#151).
    // Self-reference (flag conflicts with itself) is rejected first (MAN-FLAG-CONFLICTS-SELF).
    for fd in &flags {
        for flag_name_ref in &fd.conflicts {
            if flag_name_ref == &fd.name {
                return Err(err(
                    "MAN-FLAG-CONFLICTS-SELF",
                    format!(
                        "flag {:?}: conflicts with itself — a flag cannot list its own name in conflicts",
                        fd.name
                    ),
                ));
            }
            if !declared.contains(flag_name_ref.as_str()) {
                return Err(err(
                    "MAN-FLAG-CONFLICTS-UNDECLARED",
                    format!(
                        "flag {:?}: conflicts references undeclared flag {:?}",
                        fd.name, flag_name_ref
                    ),
                ));
            }
        }
    }

    Ok(Manifest {
        name,
        kind,
        src_dir,
        deps,
        dev_deps,
        overrides,
        flags,
        self_mirrors,
        cas_dir,
        spec_version,
        spec_version_explicit,
        version,
        attestation_policy,
        index_trust_policy,
        index_trust_signer,
        index_trust_bundle,
        index_trust_policy_explicit,
        entry_trust_policy,
        entry_trust_policy_explicit,
        index_history_policy,
        index_history_policy_explicit,
        optional_auto_flags,
        resolution,
        provides,
    })
}

fn parse_cas(node: &KdlNode) -> Result<String, ManifestError> {
    let dir_node = children(node)
        .into_iter()
        .find(|c| c.name().value() == "dir")
        .ok_or_else(|| {
            err(
                "MAN-CAS-DIR-MISSING",
                "'cas' block requires a 'dir' child node",
            )
        })?;
    let a = args(dir_node);
    let val = a.first().and_then(|e| e.value().as_string());
    if a.len() != 1 || val.is_none() {
        return Err(err(
            "MAN-CAS-DIR-TYPE",
            "'cas.dir' takes exactly one positional string argument",
        ));
    }
    Ok(val.unwrap().to_string())
}

fn parse_kind(node: &KdlNode) -> Result<String, ManifestError> {
    let a = args(node);
    if a.len() != 1 {
        return Err(err(
            "MAN-KIND-ARITY",
            format!("'kind' takes exactly one value (got {})", a.len()),
        ));
    }
    match a[0].value().as_string() {
        Some(v) if VALID_KINDS.contains(&v) => Ok(v.to_string()),
        other => Err(err(
            "MAN-KIND-INVALID",
            format!(
                "invalid kind {:?} (allowed: {})",
                other.unwrap_or("<non-string>"),
                VALID_KINDS.join(", ")
            ),
        )),
    }
}

fn check_spec_version(node: &KdlNode) -> Result<i64, ManifestError> {
    let a = args(node);
    if a.len() != 1 {
        return Err(err(
            "MAN-SPEC-VERSION-TYPE",
            format!(
                "'spec-version' takes exactly one positional integer argument \
                 (got {} args)",
                a.len()
            ),
        ));
    }
    let raw = match a[0].value() {
        KdlValue::Integer(i) => *i,
        other => {
            return Err(err(
                "MAN-SPEC-VERSION-TYPE",
                format!("'spec-version' argument must be an integer; got {other}"),
            ));
        }
    };
    let epoch = i64::try_from(raw).map_err(|_| {
        err(
            "MAN-SPEC-VERSION-TYPE",
            format!("'spec-version' is out of range; got {raw}"),
        )
    })?;
    if epoch < 1 {
        return Err(err(
            "MAN-SPEC-VERSION-TYPE",
            format!("'spec-version' must be >= 1; got {epoch}"),
        ));
    }
    if epoch > MANIFEST_SPEC_VERSION {
        return Err(err(
            "MAN-SPEC-VERSION-UNSUPPORTED",
            format!(
                "manifest declares spec-version {epoch} but this implementation \
                 only supports up to spec-version {MANIFEST_SPEC_VERSION}"
            ),
        ));
    }
    Ok(epoch)
}

/// Parse a top-level `version "x.y.z"` node (A1 §3 Axis A (b) step 1).
///
/// `milpa.kdl` is milpa's own strict manifest format, so a malformed value is
/// a hard parse error (`MAN-PACKAGE-VERSION-INVALID`) — unlike the `.nimble`
/// compat adapter, which falls through to version-unknown for a malformed
/// `version` (totality contract, `nimble.rs`). Reuses `milpa_solver::parse_version`,
/// the single source of truth for the semver grammar — no parallel parser.
fn check_package_version(node: &KdlNode) -> Result<Version, ManifestError> {
    let a = args(node);
    let val = a.first().and_then(|e| e.value().as_string());
    if a.len() != 1 || val.is_none() {
        return Err(err(
            "MAN-PACKAGE-VERSION-INVALID",
            "'version' takes exactly one positional string argument (e.g. \"1.2.3\")",
        ));
    }
    let raw = val.unwrap();
    parse_version(raw).ok_or_else(|| {
        err(
            "MAN-PACKAGE-VERSION-INVALID",
            format!("'version' value {raw:?} is not a valid semver version (expected 'x.y.z')"),
        )
    })
}

/// Recognized children of a `resolution { }` block (C3 §3 Axis C / D1 §3
/// Axis D / §5).
const RESOLUTION_KNOWN_CHILDREN: &[&str] = &["strategy", "exclude-newer"];

/// Parse a `strategy "<value>"` child of a `resolution { }` block.
///
/// Malformed arity/type or an unrecognized wire value is a hard parse error
/// (`MAN-RESOLUTION-STRATEGY-INVALID`) — mirrors `check_package_version`'s
/// strictness (`milpa.kdl` is milpa's own strict format).
fn check_resolution_strategy(node: &KdlNode) -> Result<Strategy, ManifestError> {
    let a = args(node);
    let val = a.first().and_then(|e| e.value().as_string());
    if a.len() != 1 || val.is_none() {
        return Err(err(
            "MAN-RESOLUTION-STRATEGY-INVALID",
            "'resolution.strategy' takes exactly one positional string argument \
             ('maxver', 'minver', 'semver', or 'lowest-direct')",
        ));
    }
    let raw = val.unwrap();
    Strategy::parse(raw).ok_or_else(|| {
        err(
            "MAN-RESOLUTION-STRATEGY-INVALID",
            format!(
                "'resolution.strategy' value {raw:?} is not a recognized strategy \
                 (expected 'maxver', 'minver', 'semver', or 'lowest-direct')"
            ),
        )
    })
}

/// Parse an `exclude-newer "<ts>"` child of a `resolution { }` block.
///
/// Malformed arity/type or an unparseable ISO 8601 timestamp is a hard
/// parse error (`MAN-RESOLUTION-EXCLUDE-NEWER-INVALID`) — mirrors
/// `check_resolution_strategy`'s strictness. Reuses the shared
/// `milpa_types::parse_iso8601_timestamp` (D0) rather than a second parser.
fn check_resolution_exclude_newer(node: &KdlNode) -> Result<Timestamp, ManifestError> {
    let a = args(node);
    let val = a.first().and_then(|e| e.value().as_string());
    if a.len() != 1 || val.is_none() {
        return Err(err(
            "MAN-RESOLUTION-EXCLUDE-NEWER-INVALID",
            "'resolution.exclude-newer' takes exactly one positional string argument \
             (an ISO 8601 timestamp)",
        ));
    }
    let raw = val.unwrap();
    parse_iso8601_timestamp(raw).ok_or_else(|| {
        err(
            "MAN-RESOLUTION-EXCLUDE-NEWER-INVALID",
            format!(
                "'resolution.exclude-newer' value {raw:?} is not a parseable ISO 8601 timestamp"
            ),
        )
    })
}

/// Parse a `resolution { }` block (C3 §3 Axis C / D1 §3 Axis D / §5).
///
/// Unknown child node, or a duplicate `strategy`/`exclude-newer` child, is a
/// hard parse error (`MAN-RESOLUTION-BLOCK-INVALID`) — a single clear
/// failure mode for "this block is malformed", distinct from a malformed
/// VALUE inside a recognized child (`MAN-RESOLUTION-STRATEGY-INVALID` /
/// `MAN-RESOLUTION-EXCLUDE-NEWER-INVALID`).
fn check_resolution_block(node: &KdlNode) -> Result<Resolution, ManifestError> {
    let mut strategy: Option<Strategy> = None;
    let mut exclude_newer: Option<Timestamp> = None;
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for child in children(node) {
        let child_nm = child.name().value();
        if !RESOLUTION_KNOWN_CHILDREN.contains(&child_nm) || seen.contains(child_nm) {
            return Err(err(
                "MAN-RESOLUTION-BLOCK-INVALID",
                format!(
                    "unknown or duplicate node {child_nm:?} in 'resolution' block \
                     (allowed: {}, each at most once)",
                    RESOLUTION_KNOWN_CHILDREN.join(", ")
                ),
            ));
        }
        seen.insert(child_nm);
        match child_nm {
            "strategy" => strategy = Some(check_resolution_strategy(child)?),
            "exclude-newer" => exclude_newer = Some(check_resolution_exclude_newer(child)?),
            _ => unreachable!("guarded by RESOLUTION_KNOWN_CHILDREN above"),
        }
    }
    Ok(Resolution {
        strategy,
        exclude_newer,
    })
}

/// Parse an optional `version=` property (A3b §3 Axis A (b) step 4).
///
/// Valid on git/url/local/tarball dep declarations and on `overrides { pkg
/// … version= }` rules (§5 grammar; D-A3) — every call site passes its own
/// `context` string for the error message (e.g. `dep "foo"` or `override for
/// "foo"`). Absent → `None` (steps 1-3 already tried by
/// `declared_version_for`; the annotation is a last-resort escape hatch).
///
/// `milpa.kdl` is milpa's own strict manifest format, so a malformed value is
/// a hard parse error (`MAN-DEP-VERSION-INVALID`) — same rationale as
/// `check_package_version`'s `MAN-PACKAGE-VERSION-INVALID`, reusing the same
/// `parse_version` (single source of truth for the semver grammar).
fn parse_dep_version_prop(node: &KdlNode, context: &str) -> Result<Option<Version>, ManifestError> {
    let Some(entry) = prop(node, "version") else {
        return Ok(None);
    };
    let Some(raw) = entry.value().as_string() else {
        return Err(err(
            "MAN-DEP-VERSION-INVALID",
            format!("{context}: 'version=' must be a string"),
        ));
    };
    match parse_version(raw) {
        Some(v) => Ok(Some(v)),
        None => Err(err(
            "MAN-DEP-VERSION-INVALID",
            format!("{context}: 'version=' value {raw:?} is not a valid semver version (expected 'x.y.z')"),
        )),
    }
}

// ---------------------------------------------------------------------------
// Dep parsing.
// ---------------------------------------------------------------------------

/// Yield one or more deps from a child of a `deps`/`dev-deps` block, expanding
/// `when` grouping blocks (predicates compose with AND) (grammar §6.3).
fn expand_dep_child(child: &KdlNode, inherited: &[Predicate]) -> Result<Vec<Dep>, ManifestError> {
    if child.name().value() == "when" {
        let block_preds = parse_predicates_from_props(child, "<when block>")?;
        let mut all = inherited.to_vec();
        all.extend(block_preds);
        let mut out = Vec::new();
        for grandchild in children(child) {
            out.extend(expand_dep_child(grandchild, &all)?);
        }
        return Ok(out);
    }
    // S1b: reject a `member` node nested inside a `when` block.
    // Members are unconditional workspace topology — their presence cannot be
    // conditional on platform, arch, flags, or any other predicate.  Silently
    // dropping or honoring the predicates would violate user intent; reject at
    // parse time with MAN-MEMBER-WHEN-GATED instead.
    if !inherited.is_empty() && child.name().value() == "member" {
        return Err(err(
            "MAN-MEMBER-WHEN-GATED",
            "'member' dep cannot be placed inside a 'when' block — workspace \
             members are unconditional topology present in every resolution; \
             move the 'member' declaration outside the 'when' block",
        ));
    }
    let mut dep = parse_dep(child)?;
    if !inherited.is_empty() {
        // Thread inherited when-block predicates into the four dep forms that
        // support when-conditional syntax.
        // §6.3 NORMATIVE: UrlDep, NamedDep, LocalDep, TarballDep support
        // when-conditional syntax.  MemberDep is rejected above.
        match dep {
            Dep::Url(ref mut u) => {
                let mut merged = inherited.to_vec();
                merged.append(&mut u.predicates);
                u.predicates = merged;
            }
            Dep::Named(ref mut n) => {
                let mut merged = inherited.to_vec();
                merged.append(&mut n.predicates);
                n.predicates = merged;
            }
            Dep::Local(ref mut l) => {
                let mut merged = inherited.to_vec();
                merged.append(&mut l.predicates);
                l.predicates = merged;
            }
            Dep::Tarball(ref mut t) => {
                let mut merged = inherited.to_vec();
                merged.append(&mut t.predicates);
                t.predicates = merged;
            }
            Dep::Member(_) => {
                // Unreachable: member inside a when block is rejected above.
                unreachable!("MAN-MEMBER-WHEN-GATED should have been raised");
            }
        }
    }
    Ok(vec![dep])
}

/// Disambiguate and parse one dep node (grammar §3.2 ordered rules).
fn parse_dep(node: &KdlNode) -> Result<Dep, ManifestError> {
    if node.name().value() == "member" {
        return Ok(Dep::Member(parse_member_dep(node)?));
    }
    // S5b: slash-shorthand desugar (manifest-grammar.md §3.2 NamedDep).
    // ``"core/pkg"`` desugars to namespace="core", name="pkg" at parse time.
    // The desugar happens before the charset check so downstream only sees the
    // attribute form.  A name with more than one `/` or empty parts is malformed.
    let raw_node_name = node.name().value();
    let (dep_nm, slash_namespace): (&str, Option<String>) = if raw_node_name.contains('/') {
        let parts: Vec<&str> = raw_node_name.splitn(3, '/').collect();
        // splitn(3) gives at most 3 parts; if we get 3, there are ≥2 slashes.
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty()
            || raw_node_name.matches('/').count() != 1
        {
            return Err(err(
                "MAN-DEP-NAME-INVALID",
                format!(
                    "dep {raw_node_name:?}: qualified dep names must have exactly one '/' \
                     separator with non-empty namespace and package name parts (e.g. \"core/pkg\")"
                ),
            ));
        }
        let ns_part = parts[0];
        let name_part = parts[1];
        if !valid_flag_name(ns_part) {
            return Err(err(
                "MAN-DEP-NAME-INVALID",
                format!("dep {raw_node_name:?}: namespace part {ns_part:?} must match [A-Za-z0-9_-]+"),
            ));
        }
        if !valid_flag_name(name_part) {
            return Err(err(
                "MAN-DEP-NAME-INVALID",
                format!("dep {raw_node_name:?}: name part {name_part:?} must match [A-Za-z0-9_-]+"),
            ));
        }
        (name_part, Some(ns_part.to_string()))
    } else {
        // R2-C1 security fix: validate dep name charset at parse boundary.
        // KDL 2.0 quoted node names can contain chars outside [A-Za-z0-9_-].
        // A dep name with \n (or other nim.cfg-significant char) would inject content
        // via --path:"_deps/<name>" and -d:<pkg>_<flag> emit lines in nimcfg.rs.
        let dep_nm = raw_node_name;
        if !valid_flag_name(dep_nm) {
            return Err(err(
                "MAN-DEP-NAME-INVALID",
                format!(
                    "dep {dep_nm:?}: dep names must match [A-Za-z0-9_-]+ \
                     (no spaces, control characters, or nim.cfg-significant chars)"
                ),
            ));
        }
        (dep_nm, None)
    };
    let names = prop_names(node);
    if names.contains("git") {
        Ok(Dep::Url(parse_url_dep_with_name(node, dep_nm)?))
    } else if names.contains("local") {
        Ok(Dep::Local(parse_local_dep_with_name(node, dep_nm)?))
    } else if names.contains("tarball") {
        Ok(Dep::Tarball(parse_tarball_dep_with_name(node, dep_nm)?))
    } else {
        Ok(Dep::Named(parse_named_dep_with_name(node, dep_nm, slash_namespace)?))
    }
}

/// Thin wrapper: parse a UrlDep from a node whose name may have been desugared.
fn parse_url_dep_with_name(node: &KdlNode, dep_nm: &str) -> Result<UrlDep, ManifestError> {
    parse_url_dep_inner(node, dep_nm)
}

fn parse_url_dep(node: &KdlNode) -> Result<UrlDep, ManifestError> {
    let nm = node.name().value();
    parse_url_dep_inner(node, nm)
}

fn parse_url_dep_inner(node: &KdlNode, dep_nm: &str) -> Result<UrlDep, ManifestError> {
    let name = dep_nm.to_string();
    let extra: Vec<&str> = prop_names(node)
        .into_iter()
        .filter(|p| !URL_DEP_PROPS.contains(p))
        .collect();
    if !extra.is_empty() {
        return Err(err(
            "MAN-DEP-UNKNOWN-PROPS",
            format!("dep {name:?}: unknown property/properties {extra:?}"),
        ));
    }
    let ref_entry = prop(node, "ref").ok_or_else(|| {
        err(
            "MAN-DEP-REF-MISSING",
            format!("dep {name:?}: missing required property 'ref'"),
        )
    })?;
    let git = url_arg(&format!("dep {name:?}"), "git", prop(node, "git").unwrap())?;
    validate_git_url(&name, &git)?;
    let git_ref = ref_entry
        .value()
        .as_string()
        .ok_or_else(|| {
            err(
                "MAN-DEP-REF-MISSING",
                format!("dep {name:?}: 'ref' must be a string"),
            )
        })?
        .to_string();

    let (mirrors, child_preds, flag_requests) = parse_url_dep_children(&name, node)?;
    let inline_preds = parse_predicates_subset(node, &format!("dep {name:?}"))?;
    let predicates = merge_predicates(&name, inline_preds, child_preds)?;

    // optional= (bool, default false): parsed here, desugared post-parse.
    let optional = match prop(node, "optional") {
        None => false,
        Some(e) => match e.value() {
            KdlValue::Bool(b) => *b,
            _ => {
                return Err(err(
                    "MAN-DEP-UNKNOWN-PROPS",
                    format!("dep {name:?}: 'optional=' must be a boolean (#true or #false)"),
                ));
            }
        },
    };

    // A3b: version= annotation (§3 Axis A (b) step 4).
    let version = parse_dep_version_prop(node, &format!("dep {name:?}"))?;

    // subpath= (rfc-origin-as-identity.md §4.1/S8): dep lives at this
    // location INSIDE the fetched tree, not the repo root. NOT validated
    // here — `source_id::normalize_source` is the sole validation boundary
    // (escape-guard: no `..`, no absolute path); the parser only checks that
    // a present value is a string.
    let subpath = parse_subpath_prop(node, &format!("dep {name:?}"))?;

    Ok(UrlDep {
        name,
        git,
        git_ref,
        mirrors,
        predicates,
        flag_requests,
        optional,
        version,
        subpath,
    })
}

/// Parse an optional `subpath="<path>"` property, shared by `UrlDep`/
/// `TarballDep`/override parsing (rfc-origin-as-identity.md §4.1/S8-S8b).
/// Returns `Ok(None)` when the property is absent; `Err(bad_type_code)` when
/// present but not a string. `bad_type_code` differs by caller (dep grammar
/// uses `MAN-DEP-UNKNOWN-PROPS`; override grammar uses
/// `MAN-OVERRIDE-UNKNOWN-PROPS`) — mirrors Python's inline `subpath=` parsing
/// in `_parse_url_dep`/`_parse_tarball_dep`/`_parse_overrides_block`.
fn parse_subpath_prop_coded(
    node: &KdlNode,
    context: &str,
    bad_type_code: &'static str,
) -> Result<Option<String>, ManifestError> {
    match prop(node, "subpath") {
        None => Ok(None),
        Some(e) => match e.value().as_string() {
            Some(s) => Ok(Some(s.to_string())),
            None => Err(err(bad_type_code, format!("{context}: 'subpath=' must be a string"))),
        },
    }
}

fn parse_subpath_prop(node: &KdlNode, context: &str) -> Result<Option<String>, ManifestError> {
    parse_subpath_prop_coded(node, context, "MAN-DEP-UNKNOWN-PROPS")
}

#[allow(clippy::type_complexity)]
fn parse_url_dep_children(
    dep_name: &str,
    node: &KdlNode,
) -> Result<(Vec<String>, Vec<Predicate>, Vec<FlagRequest>), ManifestError> {
    let mut mirrors = Vec::new();
    let mut child_preds = Vec::new();
    let mut flag_requests = Vec::new();
    for child in children(node) {
        match child.name().value() {
            "mirror" => {
                let a = args(child);
                if a.len() != 1 {
                    return Err(err(
                        "MAN-DEP-MIRROR-ARITY",
                        format!("dep {dep_name:?}: 'mirror' takes exactly one positional argument"),
                    ));
                }
                mirrors.push(url_arg(dep_name, "mirror", a[0])?);
            }
            "flag" => flag_requests.push(parse_flag_request(dep_name, child)?),
            n if PREDICATE_PROPS.contains(&n) => {
                child_preds.push(parse_predicate_child_node(
                    &format!("dep {dep_name:?}"),
                    child,
                )?);
            }
            other => {
                return Err(err(
                    "MAN-DEP-UNKNOWN-CHILD",
                    format!("dep {dep_name:?}: unknown child node {other:?}"),
                ));
            }
        }
    }
    Ok((mirrors, child_preds, flag_requests))
}

fn parse_flag_request(dep_name: &str, node: &KdlNode) -> Result<FlagRequest, ManifestError> {
    let a = args(node);
    let name = a.first().and_then(|e| e.value().as_string());
    if name.is_none() {
        return Err(err(
            "MAN-DEP-FLAG-NAME-MISSING",
            format!("dep {dep_name:?}: 'flag' requires a quoted name as the first argument"),
        ));
    }
    if a.len() > 2 {
        return Err(err(
            "MAN-DEP-FLAG-TOO-MANY-ARGS",
            format!("dep {dep_name:?}: 'flag' takes at most two args (name, optional bool)"),
        ));
    }
    let mut enabled = true;
    if a.len() == 2 {
        match a[1].value() {
            KdlValue::Bool(b) => enabled = *b,
            _ => {
                return Err(err(
                    "MAN-DEP-FLAG-BOOL",
                    format!("dep {dep_name:?}: 'flag' second arg must be a boolean"),
                ));
            }
        }
    }
    Ok(FlagRequest {
        name: name.unwrap().to_string(),
        enabled,
    })
}

fn parse_local_dep_with_name(node: &KdlNode, dep_nm: &str) -> Result<LocalDep, ManifestError> {
    parse_local_dep_inner(node, dep_nm)
}

fn parse_local_dep(node: &KdlNode) -> Result<LocalDep, ManifestError> {
    parse_local_dep_inner(node, node.name().value())
}

fn parse_local_dep_inner(node: &KdlNode, dep_nm: &str) -> Result<LocalDep, ManifestError> {
    let name = dep_nm.to_string();
    let extra: Vec<&str> = prop_names(node)
        .into_iter()
        .filter(|p| *p != "local" && *p != "version")
        .collect();
    if !extra.is_empty() {
        return Err(err(
            "MAN-DEP-UNKNOWN-PROPS",
            format!("dep {name:?}: unknown property/properties {extra:?} on a local dep"),
        ));
    }
    // A3b: version= annotation (§3 Axis A (b) step 4).
    let version = parse_dep_version_prop(node, &format!("dep {name:?}"))?;
    match prop(node, "local").unwrap().value().as_string() {
        Some(p) if !p.is_empty() => Ok(LocalDep {
            name,
            path: p.to_string(),
            predicates: vec![], // Populated by expand_dep_child from when-block.
            version,
        }),
        _ => Err(err(
            "MAN-DEP-LOCAL-PATH",
            format!("dep {name:?}: 'local' property must be a non-empty string path"),
        )),
    }
}

fn parse_tarball_dep_with_name(node: &KdlNode, dep_nm: &str) -> Result<TarballDep, ManifestError> {
    parse_tarball_dep_inner(node, dep_nm)
}

fn parse_tarball_dep(node: &KdlNode) -> Result<TarballDep, ManifestError> {
    parse_tarball_dep_inner(node, node.name().value())
}

fn parse_tarball_dep_inner(node: &KdlNode, dep_nm: &str) -> Result<TarballDep, ManifestError> {
    let name = dep_nm.to_string();
    let allowed = ["tarball", "sha256", "strip_components", "version", "subpath"];
    let extra: Vec<&str> = prop_names(node)
        .into_iter()
        .filter(|p| !allowed.contains(p))
        .collect();
    if !extra.is_empty() {
        return Err(err(
            "MAN-DEP-UNKNOWN-PROPS",
            format!("dep {name:?}: unknown property/properties {extra:?} on a tarball dep"),
        ));
    }
    let url = url_arg(
        &format!("dep {name:?}"),
        "tarball",
        prop(node, "tarball").unwrap(),
    )?;
    if url.is_empty() {
        return Err(err(
            "MAN-DEP-TARBALL-URL",
            format!("dep {name:?}: 'tarball' must be a non-empty URL string"),
        ));
    }
    let sha256 = match prop(node, "sha256") {
        None => None,
        Some(e) => match e.value().as_string() {
            Some(s) => Some(s.to_string()),
            None => {
                return Err(err(
                    "MAN-DEP-TARBALL-SHA",
                    format!("dep {name:?}: 'sha256' must be a string when provided"),
                ));
            }
        },
    };
    let strip_components = match prop(node, "strip_components") {
        None => 0u32,
        Some(e) => match e.value() {
            KdlValue::Integer(i) if *i >= 0 => u32::try_from(*i).map_err(|_| {
                err(
                    "MAN-DEP-TARBALL-STRIP",
                    format!("dep {name:?}: 'strip_components' out of range"),
                )
            })?,
            _ => {
                return Err(err(
                    "MAN-DEP-TARBALL-STRIP",
                    format!("dep {name:?}: 'strip_components' must be a non-negative integer"),
                ));
            }
        },
    };
    // A3b: version= annotation (§3 Axis A (b) step 4).
    let version = parse_dep_version_prop(node, &format!("dep {name:?}"))?;
    // subpath= (rfc-origin-as-identity.md §4.1/S8) — see UrlDep's subpath
    // parsing for the full rationale (not validated here).
    let subpath = parse_subpath_prop(node, &format!("dep {name:?}"))?;
    Ok(TarballDep {
        name,
        url,
        sha256,
        strip_components,
        predicates: vec![], // Populated by expand_dep_child from when-block.
        version,
        subpath,
    })
}

fn parse_member_dep(node: &KdlNode) -> Result<MemberDep, ManifestError> {
    if !props(node).is_empty() {
        return Err(err(
            "MAN-DEP-MEMBER-PROPS",
            "'member' dep takes no properties",
        ));
    }
    let a = args(node);
    let val = a.first().and_then(|e| e.value().as_string());
    if a.len() != 1 || val.is_none() {
        return Err(err(
            "MAN-DEP-MEMBER-ARITY",
            "'member' dep takes exactly one positional string argument",
        ));
    }
    // R6-F3 security fix: validate member name charset at parse boundary.
    // The name flows to ResolvedDep.name → nimcfg --path: lines, same
    // injection class as the R2-C1 dep-name fix.  Reuse SSOT charset predicate.
    let nm = val.unwrap();
    if !valid_flag_name(nm) {
        return Err(err(
            "MAN-DEP-NAME-INVALID",
            format!(
                "member {nm:?}: dep names must match [A-Za-z0-9_-]+ \
                 (no spaces, control characters, or nim.cfg-significant chars)"
            ),
        ));
    }
    Ok(MemberDep {
        name: nm.to_string(),
        predicates: vec![], // Populated by expand_dep_child from when-block.
    })
}

/// S5b entry point: parse a NamedDep when the dep-name may have been desugared.
/// `slash_namespace` is `Some("ns")` when the node name contained a `/` and was
/// split by `parse_dep`; `None` for bare names.  The `namespace=` property is
/// also accepted and takes precedence if both are present (error if they conflict).
fn parse_named_dep_with_name(
    node: &KdlNode,
    dep_nm: &str,
    slash_namespace: Option<String>,
) -> Result<NamedDep, ManifestError> {
    let name = dep_nm.to_string();
    // S5b: parse the `namespace=` attribute.
    let attr_namespace: Option<String> = match prop(node, "namespace") {
        None => None,
        Some(e) => match e.value().as_string() {
            Some(ns) if !ns.is_empty() => {
                if !valid_flag_name(ns) {
                    return Err(err(
                        "MAN-DEP-NAME-INVALID",
                        format!(
                            "dep {name:?}: namespace {ns:?} must match [A-Za-z0-9_-]+"
                        ),
                    ));
                }
                Some(ns.to_string())
            }
            Some(_) => {
                return Err(err(
                    "MAN-DEP-NAMED-PROPS",
                    format!("dep {name:?}: 'namespace=' must be a non-empty string"),
                ));
            }
            None => {
                return Err(err(
                    "MAN-DEP-NAMED-PROPS",
                    format!("dep {name:?}: 'namespace=' must be a string value"),
                ));
            }
        },
    };
    // M2 fix: if both slash and attribute namespace sources are present AND they
    // disagree, raise MAN-DEP-NAME-INVALID. Agreement or single-source is fine.
    let namespace: Option<String> = match (attr_namespace, slash_namespace) {
        (Some(a), Some(s)) if a != s => {
            return Err(err(
                "MAN-DEP-NAME-INVALID",
                format!(
                    "dep {name:?}: slash namespace {s:?} and namespace= attribute {a:?} disagree — \
                     use one or the other, or ensure they match"
                ),
            ));
        }
        (Some(a), _) => Some(a),
        (_, s) => s,
    };

    // Only `optional` and `namespace` are valid properties on NamedDep.
    for (key, _) in props(node) {
        if key != "optional" && key != "namespace" {
            return Err(err(
                "MAN-DEP-NAMED-PROPS",
                format!("dep {name:?}: unknown property/properties {key:?} on a named dep"),
            ));
        }
    }
    let optional = match prop(node, "optional") {
        None => false,
        Some(e) => match e.value() {
            KdlValue::Bool(b) => *b,
            _ => {
                return Err(err(
                    "MAN-DEP-NAMED-PROPS",
                    format!("dep {name:?}: 'optional=' must be a boolean (#true or #false)"),
                ));
            }
        },
    };
    let a = args(node);
    let (constraint, parsed_constraint) = match a.len() {
        0 => (None, None),
        1 => {
            let raw_str = match a[0].value().as_string() {
                Some(c) => c.to_string(),
                None => {
                    return Err(err(
                        "MAN-DEP-NAMED-CONSTRAINT",
                        format!("dep {name:?}: version constraint must be a quoted string"),
                    ));
                }
            };
            // Parse at the manifest-parse boundary: wrong-type OR unparseable
            // string both map to MAN-DEP-NAMED-CONSTRAINT (spec §errors.md).
            let parsed = VersionSet::from_constraint(Some(&raw_str)).map_err(|e| {
                err(
                    "MAN-DEP-NAMED-CONSTRAINT",
                    format!("dep {name:?}: invalid version constraint {raw_str:?}: {e}"),
                )
            })?;
            (Some(raw_str), Some(parsed))
        }
        n => {
            return Err(err(
                "MAN-DEP-NAMED-ARITY",
                format!("dep {name:?}: named deps take at most one positional argument; got {n}"),
            ))
        }
    };
    // Parse children: only ``flag`` child nodes accepted (§3.1.5, S3 RFC #23).
    let mut flag_requests: Vec<FlagRequest> = Vec::new();
    for child in children(node) {
        let child_nm = child.name().value();
        if child_nm == "flag" {
            flag_requests.push(parse_flag_request(&name, child)?);
        } else {
            return Err(err(
                "MAN-DEP-UNKNOWN-CHILD",
                format!(
                    "dep {name:?}: unknown child node {child_nm:?}; only \"flag\" is valid on a named dep"
                ),
            ));
        }
    }
    Ok(NamedDep {
        name,
        constraint,
        parsed_constraint,
        flag_requests,
        optional,
        predicates: Vec::new(), // Populated by desugar pass in parse_manifest_doc.
        namespace,
    })
}

fn parse_named_dep(node: &KdlNode) -> Result<NamedDep, ManifestError> {
    parse_named_dep_with_name(node, node.name().value(), None)
}

// ---------------------------------------------------------------------------
// Predicates.
// ---------------------------------------------------------------------------

/// Parse predicate properties from any node's props (used for `when` blocks).
fn parse_predicates_from_props(
    node: &KdlNode,
    context: &str,
) -> Result<Vec<Predicate>, ManifestError> {
    let mut preds = Vec::new();
    for (key, entry) in props(node) {
        if !PREDICATE_PROPS.contains(&key) {
            return Err(err(
                "MAN-PREDICATE-UNKNOWN",
                format!("{context}: unknown predicate {key:?}"),
            ));
        }
        preds.push(predicate_from_entry(context, key, entry)?);
    }
    Ok(preds)
}

/// Parse only the predicate-named subset of a node's props (used on UrlDeps,
/// where `git`/`ref` props coexist and are handled separately).
fn parse_predicates_subset(node: &KdlNode, context: &str) -> Result<Vec<Predicate>, ManifestError> {
    let mut preds = Vec::new();
    for (key, entry) in props(node) {
        if !PREDICATE_PROPS.contains(&key) {
            continue;
        }
        preds.push(predicate_from_entry(context, key, entry)?);
    }
    Ok(preds)
}

fn predicate_from_entry(
    context: &str,
    key: &str,
    entry: &KdlEntry,
) -> Result<Predicate, ManifestError> {
    let value = match entry.value().as_string() {
        Some(s) => s.to_string(),
        None => {
            return Err(err(
                "MAN-PREDICATE-VALUE-TYPE",
                format!("{context}: predicate {key:?} value must be a string"),
            ));
        }
    };
    let negated = match entry_ty(entry) {
        None => false,
        Some("not") => true,
        Some(other) => {
            return Err(err(
                "MAN-PREDICATE-UNSUPPORTED-ANNOTATION",
                format!("{context}: predicate {key:?} unsupported type annotation ({other:?}); only (not) is recognized"),
            ));
        }
    };
    Ok(Predicate {
        name: key.to_string(),
        values: vec![value],
        negated,
    })
}

/// Parse a child-node predicate (`platform "linux" "macosx"`) with OR semantics
/// and per-arg `(not)` agreement (grammar §6.2).
fn parse_predicate_child_node(context: &str, child: &KdlNode) -> Result<Predicate, ManifestError> {
    let key = child.name().value();
    if !PREDICATE_PROPS.contains(&key) {
        return Err(err(
            "MAN-PREDICATE-UNKNOWN",
            format!("{context}: unknown predicate {key:?} as child node"),
        ));
    }
    let a = args(child);
    if a.is_empty() {
        return Err(err(
            "MAN-PREDICATE-CHILD-NO-ARGS",
            format!(
                "{context}: predicate child node {key:?} requires at least one positional argument"
            ),
        ));
    }
    let mut values = Vec::new();
    let mut negations = Vec::new();
    for entry in a {
        let value = match entry.value().as_string() {
            Some(s) => s.to_string(),
            None => {
                return Err(err(
                    "MAN-PREDICATE-CHILD-ARG-TYPE",
                    format!("{context}: predicate {key:?} arg must be a string"),
                ));
            }
        };
        let neg = match entry_ty(entry) {
            None => false,
            Some("not") => true,
            Some(other) => {
                return Err(err(
                    "MAN-PREDICATE-UNSUPPORTED-ANNOTATION",
                    format!("{context}: predicate {key:?} unsupported type annotation ({other:?}); only (not) is recognized"),
                ));
            }
        };
        values.push(value);
        negations.push(neg);
    }
    if negations.iter().any(|n| *n != negations[0]) {
        return Err(err(
            "MAN-PREDICATE-MIXED-NEGATION",
            format!("{context}: predicate {key:?} mixes (not) and bare args — all args must agree on negation"),
        ));
    }
    Ok(Predicate {
        name: key.to_string(),
        values,
        negated: negations[0],
    })
}

/// Combine inline + child-node predicates; reject a name appearing in both
/// forms; sort by name for structural stability (grammar §6.3 NOTE).
fn merge_predicates(
    dep_name: &str,
    inline: Vec<Predicate>,
    child: Vec<Predicate>,
) -> Result<Vec<Predicate>, ManifestError> {
    let inline_names: BTreeSet<&str> = inline.iter().map(|p| p.name.as_str()).collect();
    let child_names: BTreeSet<&str> = child.iter().map(|p| p.name.as_str()).collect();
    let overlap: Vec<&&str> = inline_names.intersection(&child_names).collect();
    if !overlap.is_empty() {
        return Err(err(
            "MAN-PREDICATE-FORM-CONFLICT",
            format!("dep {dep_name:?}: predicate(s) {overlap:?} declared in both inline and child-node form — pick one form per predicate"),
        ));
    }
    // Preserve source order: inline predicates first, then child predicates,
    // each in source order.  Predicate evaluation is order-independent
    // (conjunction), so this is for representational determinism only.
    // spec/manifest-grammar.md §6 (NORMATIVE): predicate order is source order.
    let mut all = inline;
    all.extend(child);
    Ok(all)
}

// ---------------------------------------------------------------------------
// Flags + overrides.
// ---------------------------------------------------------------------------

/// Regex-equivalent: [A-Za-z0-9_-]+
pub fn valid_flag_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Returns true if `s` contains a character that must not appear in nim.cfg lines.
///
/// Covers:
/// - ASCII control chars (0x00–0x1F and 0x7F) — H1 fix (original)
/// - Unicode line separators U+2028 / U+2029 — R2-Unicode broadening
///
/// Used for `defines` values (H1+R2-Unicode) and `src_dir` values (R2-C2+R2-Unicode),
/// including `.nimble`-sourced `srcDir` values validated at the edge-source boundary.
/// Public so `milpa-core`'s `NimbleEdgeSource` can reuse without re-implementing (SSOT).
pub fn contains_unsafe_char(s: &str) -> bool {
    for ch in s.chars() {
        let c = ch as u32;
        if c < 0x20 || c == 0x7f || c == 0x2028 || c == 0x2029 {
            return true;
        }
    }
    false
}

fn parse_flag_decl(node: &KdlNode) -> Result<FlagDecl, ManifestError> {
    let name = node.name().value().to_string();

    // H1 security fix: validate flag name charset at parse boundary.
    // KDL 2.0 quoted node names can contain chars outside [A-Za-z0-9_-].
    // A malicious dep could declare a flag with an illegal name (containing
    // newlines or nim.cfg-significant chars) to inject content via the
    // childless-convention emit: -d:<pkg>_<flagname>.
    if !valid_flag_name(&name) {
        return Err(err(
            "MAN-FLAG-NAME-INVALID",
            format!(
                "flag {name:?}: flag names must match [A-Za-z0-9_-]+ \
                 (no spaces, special characters, or control characters)"
            ),
        ));
    }

    if !args(node).is_empty() {
        return Err(err(
            "MAN-FLAG-POS-ARGS",
            format!("flag {name:?}: positional args not allowed"),
        ));
    }
    let extra: Vec<&str> = prop_names(node)
        .into_iter()
        .filter(|p| !FLAG_DECL_PROPS.contains(p))
        .collect();
    if !extra.is_empty() {
        return Err(err(
            "MAN-FLAG-UNKNOWN-PROPS",
            format!("flag {name:?}: unknown property/properties {extra:?}"),
        ));
    }
    let default = match prop(node, "default") {
        None => false,
        Some(e) => match e.value() {
            KdlValue::Bool(b) => *b,
            _ => {
                return Err(err(
                    "MAN-FLAG-DEFAULT-TYPE",
                    format!("flag {name:?}: 'default' must be a boolean"),
                ));
            }
        },
    };
    let description = match prop(node, "description") {
        None => String::new(),
        Some(e) => match e.value().as_string() {
            Some(s) => s.to_string(),
            None => {
                return Err(err(
                    "MAN-FLAG-DESCRIPTION-TYPE",
                    format!("flag {name:?}: 'description' must be a string"),
                ));
            }
        },
    };
    let mut defines = Vec::new();
    let mut enables_same_pkg: Vec<String> = Vec::new();
    let mut enables_cross_pkg: Vec<CrossPkgEnable> = Vec::new();
    let mut conflicts: Vec<String> = Vec::new();

    for child in children(node) {
        match child.name().value() {
            "defines" => {
                for entry in args(child) {
                    match entry.value().as_string() {
                        Some(s) => {
                            // H1 + R2-Unicode fix: reject control chars and Unicode line
                            // separators at parse boundary. An embedded \n (or any control
                            // char, or U+2028/U+2029) in a defines value would be emitted
                            // verbatim to nim.cfg, injecting arbitrary compiler flags → code exec.
                            if contains_unsafe_char(s) {
                                return Err(err(
                                    "MAN-FLAG-DEFINES-UNSAFE",
                                    format!(
                                        "flag {name:?}: 'defines' arg contains a control \
                                         character or Unicode line separator (0x00–0x1F, 0x7F, \
                                         U+2028, U+2029) \
                                         — nim.cfg injection rejected at parse boundary"
                                    ),
                                ));
                            }
                            defines.push(s.to_string())
                        }
                        None => {
                            return Err(err(
                                "MAN-FLAG-DEFINES-ARG-TYPE",
                                format!("flag {name:?}: 'defines' args must be strings"),
                            ));
                        }
                    }
                }
            }
            "enables" => {
                // Bare string args = same-package flag names.
                for entry in args(child) {
                    match entry.value().as_string() {
                        Some(s) => enables_same_pkg.push(s.to_string()),
                        None => {
                            return Err(err(
                                "MAN-FLAG-UNKNOWN-CHILD",
                                format!("flag {name:?}: 'enables' args must be strings"),
                            ));
                        }
                    }
                }
                // Children = cross-package dep→flag entries.
                for dep_node in children(child) {
                    let dep_name = dep_node.name().value().to_string();
                    let mut flag_reqs: Vec<FlagRequest> = Vec::new();
                    for flag_child in children(dep_node) {
                        if flag_child.name().value() != "flag" {
                            return Err(err(
                                "MAN-FLAG-UNKNOWN-CHILD",
                                format!(
                                    "flag {name:?}: enables cross-pkg dep {dep_name:?} \
                                     has unknown child {:?} (only 'flag' is allowed)",
                                    flag_child.name().value()
                                ),
                            ));
                        }
                        flag_reqs.push(parse_flag_request(
                            &format!("{name}→{dep_name}"),
                            flag_child,
                        )?);
                    }
                    enables_cross_pkg.push(CrossPkgEnable {
                        dep: dep_name,
                        flag_requests: flag_reqs,
                    });
                }
            }
            "conflicts" => {
                // Bare string args = same-package flag names this flag conflicts with.
                for entry in args(child) {
                    match entry.value().as_string() {
                        Some(s) => conflicts.push(s.to_string()),
                        None => {
                            return Err(err(
                                "MAN-FLAG-UNKNOWN-CHILD",
                                format!("flag {name:?}: 'conflicts' args must be strings"),
                            ));
                        }
                    }
                }
            }
            other => {
                return Err(err(
                    "MAN-FLAG-UNKNOWN-CHILD",
                    format!(
                        "flag {name:?}: unknown child node {other:?} \
                         (allowed: 'defines', 'enables', 'conflicts')"
                    ),
                ));
            }
        }
    }
    Ok(FlagDecl {
        name,
        default,
        description,
        defines,
        enables_same_pkg,
        enables_cross_pkg,
        conflicts,
    })
}

/// Known property keys on a `pkg` override node across all target forms
/// (S8/S8b, rfc-origin-as-identity.md §7 B5 — the six target kinds).
/// A3b: `version` is valid on every target form (D-A3 — orthogonal to which
/// redirect form is chosen; labels that target's step 4).
const OVERRIDE_KNOWN_PROPS: &[&str] = &[
    "git", "ref", "local", "version", "subpath",
    "oci", "digest", "tarball", "sha256", "strip_components",
    "named", "namespace",
];

/// Split an `oci=` override value `<registry>/<repository>` on its FIRST
/// `/`. Deliberately a small local duplicate of `source_spec::split_oci_target`
/// (same "first-'/'-is-the-registry-boundary" rule) — `milpa-manifest` is pure
/// grammar and must not depend on `milpa-core`'s fetchers-adjacent
/// `source_spec` module (layering; mirrors Python's own local duplicate in
/// `manifest.py::_split_oci_coordinate`, which documents the identical
/// rationale).
fn split_oci_coordinate(token: &str, pkg_name: &str) -> Result<(String, String), ManifestError> {
    match token.find('/') {
        Some(pos) if pos > 0 && pos + 1 < token.len() => {
            Ok((token[..pos].to_string(), token[pos + 1..].to_string()))
        }
        _ => Err(err(
            "MAN-OVERRIDE-OCI-MALFORMED",
            format!(
                "override for {pkg_name:?}: 'oci=' must be '<registry>/<repository>' \
                 (non-empty on both sides of the first '/'); got {token:?}"
            ),
        )),
    }
}

fn parse_override(node: &KdlNode) -> Result<Override, ManifestError> {
    if node.name().value() != "pkg" {
        return Err(err(
            "MAN-OVERRIDE-KIND",
            format!(
                "unknown override kind {:?} (supported: 'pkg')",
                node.name().value()
            ),
        ));
    }
    let a = args(node);
    let name = a.first().and_then(|e| e.value().as_string());
    if a.len() != 1 || name.is_none() {
        return Err(err(
            "MAN-OVERRIDE-ARITY",
            "pkg override takes one positional argument (the dep name)",
        ));
    }
    let name = name.unwrap().to_string();

    // Reject unknown properties first.
    let extra: Vec<&str> = prop_names(node)
        .into_iter()
        .filter(|p| !OVERRIDE_KNOWN_PROPS.contains(p))
        .collect();
    if !extra.is_empty() {
        return Err(err(
            "MAN-OVERRIDE-UNKNOWN-PROPS",
            format!("override for {name:?}: unknown property/properties {extra:?}"),
        ));
    }

    // Detect which target forms are present.
    let has_git = prop(node, "git").is_some();
    let has_local = prop(node, "local").is_some();
    let has_oci = prop(node, "oci").is_some();
    let has_tarball = prop(node, "tarball").is_some();
    let has_named = prop(node, "named").is_some();
    let child_nodes = children(node);
    let member_children: Vec<_> = child_nodes
        .iter()
        .filter(|c| c.name().value() == "member")
        .collect();
    let has_member = !member_children.is_empty();

    let target_count = [has_git, has_local, has_member, has_oci, has_tarball, has_named]
        .iter()
        .filter(|&&b| b)
        .count();
    if target_count != 1 {
        return Err(err(
            "MAN-OVERRIDE-TARGET-AMBIGUOUS",
            format!(
                "override for {name:?}: exactly one provenance form is required \
                 (git, local, member, oci, tarball, or named/registry); got {} ({})",
                target_count,
                if target_count == 0 { "none" } else { "multiple forms mixed" }
            ),
        ));
    }

    // subpath= — valid on git/oci/tarball forms only (mirrors SourceId:
    // Local/Member/Registry carry no subpath concept). Parsed once, here,
    // since it's shared across those three forms.
    let subpath = parse_subpath_prop_coded(node, &format!("override for {name:?}"), "MAN-OVERRIDE-UNKNOWN-PROPS")?;
    if subpath.is_some() && !(has_git || has_oci || has_tarball) {
        return Err(err(
            "MAN-OVERRIDE-UNKNOWN-PROPS",
            format!(
                "override for {name:?}: 'subpath=' is only valid on the git, oci, \
                 or tarball override forms"
            ),
        ));
    }

    let target = if has_git {
        let git_entry = prop(node, "git").unwrap();
        let ref_entry = prop(node, "ref").ok_or_else(|| {
            err(
                "MAN-OVERRIDE-REF-MISSING",
                format!("override for {name:?}: missing required property 'ref'"),
            )
        })?;
        let url = url_arg(&format!("override {name:?}"), "git", git_entry)?;
        validate_git_url(&name, &url)?;
        let git_ref = ref_entry
            .value()
            .as_string()
            .ok_or_else(|| {
                err(
                    "MAN-OVERRIDE-REF-MISSING",
                    format!("override for {name:?}: 'ref' must be a string"),
                )
            })?
            .to_string();
        OverrideTarget::Git { url, git_ref, subpath }
    } else if has_local {
        let local_entry = prop(node, "local").unwrap();
        let path = local_entry
            .value()
            .as_string()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                err(
                    "MAN-DEP-LOCAL-PATH",
                    format!("override for {name:?}: 'local=' must be a non-empty string path"),
                )
            })?
            .to_string();
        OverrideTarget::Local { path }
    } else if has_oci {
        let oci_entry = prop(node, "oci").unwrap();
        let oci_coord = oci_entry
            .value()
            .as_string()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                err(
                    "MAN-OVERRIDE-OCI-MALFORMED",
                    format!(
                        "override for {name:?}: 'oci=' must be a non-empty \
                         '<registry>/<repository>' string"
                    ),
                )
            })?;
        let (registry, repository) = split_oci_coordinate(oci_coord, &name)?;
        let digest = prop(node, "digest")
            .and_then(|e| e.value().as_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                err(
                    "MAN-OVERRIDE-DIGEST-MISSING",
                    format!(
                        "override for {name:?}: oci form requires a 'digest=' property \
                         (sha256:<64-hex>)"
                    ),
                )
            })?
            .to_string();
        OverrideTarget::Oci { registry, repository, digest, subpath }
    } else if has_tarball {
        let tarball_entry = prop(node, "tarball").unwrap();
        let url = url_arg(&format!("override {name:?}"), "tarball", tarball_entry)?;
        if url.is_empty() {
            return Err(err(
                "MAN-DEP-TARBALL-URL",
                format!("override for {name:?}: 'tarball=' URL must not be empty"),
            ));
        }
        let sha256 = match prop(node, "sha256") {
            None => None,
            Some(e) => match e.value().as_string() {
                Some(s) => Some(s.to_string()),
                None => {
                    return Err(err(
                        "MAN-DEP-TARBALL-SHA",
                        format!("override for {name:?}: 'sha256=' must be a string"),
                    ));
                }
            },
        };
        let strip_components = match prop(node, "strip_components") {
            None => 0u32,
            Some(e) => match e.value() {
                KdlValue::Integer(i) if *i >= 0 => u32::try_from(*i).map_err(|_| {
                    err(
                        "MAN-DEP-TARBALL-STRIP",
                        format!("override for {name:?}: 'strip_components=' out of range"),
                    )
                })?,
                _ => {
                    return Err(err(
                        "MAN-DEP-TARBALL-STRIP",
                        format!(
                            "override for {name:?}: 'strip_components=' must be a \
                             non-negative integer"
                        ),
                    ));
                }
            },
        };
        OverrideTarget::Tarball { url, sha256, strip_components, subpath }
    } else if has_named {
        let named_name = prop(node, "named")
            .and_then(|e| e.value().as_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                err(
                    "MAN-OVERRIDE-NAMED-MISSING",
                    format!(
                        "override for {name:?}: 'named=' must be a non-empty string \
                         (the registry package name to redirect to)"
                    ),
                )
            })?
            .to_string();
        let namespace = prop(node, "namespace").and_then(|e| e.value().as_string()).map(str::to_string);
        OverrideTarget::Registry { name: named_name, namespace }
    } else {
        // has_member
        let mc = member_children[0];
        let mc_args = args(mc);
        let member_name = mc_args
            .first()
            .and_then(|e| e.value().as_string())
            .filter(|_| mc_args.len() == 1)
            .ok_or_else(|| {
                err(
                    "MAN-DEP-MEMBER-ARITY",
                    format!(
                        "override for {name:?}: 'member' child takes exactly one \
                         positional string argument (the workspace member name)"
                    ),
                )
            })?
            .to_string();
        OverrideTarget::Member { member_name }
    };

    // NOTE: `version=` is intentionally NOT parsed here. It's parsed by the
    // caller AFTER the duplicate-name check (see `parse_override`/call
    // sites below) so that a duplicate override name is reported before a
    // malformed `version=` on the duplicate entry (D5 divergence fix vs.
    // the Python impl, which orders duplicate-check before version-parse).
    Ok(Override { name, target, version: None })
}

/// Parse one `pkg` override node's target form (everything except
/// `version=`), then the caller checks the duplicate-name invariant, then
/// calls `finish_override_version` to fill in `version=`. Splitting the
/// version parse out of `parse_override` itself is what lets the caller's
/// duplicate-name check run before a malformed `version=` on the *same*
/// (duplicate) entry would otherwise raise MAN-DEP-VERSION-INVALID first.
fn finish_override_version(node: &KdlNode, mut ov: Override) -> Result<Override, ManifestError> {
    // A3b: version= annotation on the override rule (§3 Axis A (b) step 4,
    // D-A3) — valid regardless of which target form was selected above.
    ov.version = parse_dep_version_prop(node, &format!("override for {:?}", ov.name))?;
    Ok(ov)
}

// ---------------------------------------------------------------------------
// Shared validators.
// ---------------------------------------------------------------------------

/// Normalize a URL argument: accept a string value (plain or `(url)`-annotated);
/// reject a non-string value or any other type annotation (grammar §2).
fn url_arg(context: &str, field: &str, entry: &KdlEntry) -> Result<String, ManifestError> {
    // S3 strict: ONLY the (url)-annotated form is accepted.
    match entry.value().as_string() {
        Some(s) => match entry_ty(entry) {
            Some("url") => Ok(s.to_string()),
            None => Err(err(
                "MAN-URL-ARG-TYPE",
                format!("{context}: {field:?} must be a (url)-annotated URL string, not a plain string"),
            )),
            Some(other) => Err(err(
                "MAN-URL-ARG-TYPE",
                format!("{context}: {field:?} has unsupported type annotation ({other:?}); only (url) is recognized"),
            )),
        },
        None => Err(err(
            "MAN-URL-ARG-TYPE",
            format!("{context}: {field:?} expects a (url)-annotated URL string"),
        )),
    }
}

fn validate_git_url(dep_name: &str, url: &str) -> Result<(), ManifestError> {
    let scheme = url.split_once("://").map(|(s, _)| s);
    match scheme {
        None => Err(err(
            "MAN-GIT-URL-NO-SCHEME",
            format!("dep {dep_name:?}: git URL {url:?} has no scheme"),
        )),
        Some(s) if VALID_GIT_SCHEMES.contains(&s) => Ok(()),
        Some(s) => Err(err(
            "MAN-GIT-URL-BAD-SCHEME",
            format!("dep {dep_name:?}: git URL {url:?} has unsupported scheme {s:?}"),
        )),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fuzz_tests;
