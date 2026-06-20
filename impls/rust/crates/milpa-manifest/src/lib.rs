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

use milpa_solver::VersionSet;
use milpa_types::Version;

pub mod format;
pub mod nimble;

pub use format::format_manifest;
// Re-export Predicate from milpa-types (the new SSOT) so all existing
// references to `milpa_manifest::Predicate` and `crate::Predicate` compile
// unchanged.
pub use milpa_types::Predicate;
// Re-export FlagRequest from milpa-types (the new SSOT) so all existing
// references to `milpa_manifest::FlagRequest` and `crate::FlagRequest`
// compile unchanged.
pub use milpa_types::FlagRequest;

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
}

impl PartialEq for NamedDep {
    fn eq(&self, other: &Self) -> bool {
        // Compare by name + raw constraint string only (mirrors Python's
        // `compare=False` on `constraint_set`; the parsed form is deterministic
        // from the raw string so excluding it preserves test ergonomics).
        self.name == other.name && self.constraint == other.constraint
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

/// Discriminated union of override target kinds (S8, RFC #23 §3.3).
///
/// Exactly one variant per `pkg` rule; zero or multiple forms raise
/// `MAN-OVERRIDE-TARGET-AMBIGUOUS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideTarget {
    /// `pkg "name" git=(url)"..." ref="..."` — git fork.
    /// Identity-bearing; CAS-admissible.
    Git { url: String, git_ref: String },
    /// `pkg "name" local="<relative-path>"` — local filesystem path.
    /// Liveness-only; NOT CAS-admissible; non-reproducible for external consumers.
    /// Resolution wired in S8a.
    Local { path: String },
    /// `pkg "name" { member "<member-name>" }` — workspace member.
    /// Identity-bearing; NOT CAS-admissible.
    /// Resolution wired in S8b.
    Member { member_name: String },
}

/// A `pkg`-form override (S8 discriminated union, grammar §3.4).
///
/// `name` is the dep to intercept; `target` is exactly one of
/// `Git`, `Local`, or `Member`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    pub name: String,
    pub target: OverrideTarget,
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
    /// S5: attestation policy from `attestation-policy "strict"|"permissive"` (default: permissive).
    pub attestation_policy: AttestationPolicy,
    /// S7: flag names that were auto-injected by optional-dep desugaring.
    /// `format_manifest` skips these from the `flags {}` block (they're implied
    /// by `optional=#true` on the dep; serializing them would cause a re-parse clash).
    pub optional_auto_flags: std::collections::BTreeSet<String>,
}

/// S5: Attestation policy — controls fallback-warning vs. hard-error behaviour
/// for deps resolved from un-attested `.nimble` metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AttestationPolicy {
    #[default]
    Permissive,
    Strict,
}

/// A parsed workspace-root `milpa.kdl` (grammar §7). Pure container: member
/// directory paths + optional workspace-level overrides. Member *names* are
/// intrinsic to each member's own manifest and resolved at workspace-load
/// time (S11) — at parse time a member is just its path.
///
/// S11 (RFC #23 §3.8): workspace root may carry a `flags {}` block whose
/// default-true activations apply workspace-wide. Reuses `FlagDecl` (SSOT —
/// no parallel flag type).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Workspace {
    pub members: Vec<String>,
    pub overrides: Vec<Override>,
    pub flags: Vec<FlagDecl>,  // S11: workspace-root flags (§3.8)
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
    "MAN-DEP-NAMED-PROPS",
    "MAN-DEP-NAMED-CONSTRAINT",
    "MAN-DEP-NAMED-ARITY",
    "MAN-DEP-MIRROR-ARITY",
    "MAN-DEP-FLAG-NAME-MISSING",
    "MAN-DEP-FLAG-TOO-MANY-ARGS",
    "MAN-DEP-FLAG-BOOL",
    "MAN-DEP-UNKNOWN-CHILD",
    "MAN-GIT-URL-NO-SCHEME",
    "MAN-GIT-URL-BAD-SCHEME",
    "MAN-OVERRIDE-KIND",
    "MAN-OVERRIDE-ARITY",
    "MAN-OVERRIDE-UNKNOWN-PROPS",
    "MAN-OVERRIDE-TARGET-AMBIGUOUS",
    "MAN-OVERRIDE-GIT-MISSING",
    "MAN-OVERRIDE-REF-MISSING",
    "MAN-OVERRIDE-DUPLICATE",
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
const URL_DEP_PROPS: &[&str] = &["git", "ref", "platform", "arch", "nim", "milpa", "flag", "optional"];
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
    "attestation-policy",
];
const WORKSPACE_TOP_LEVEL: &[&str] = &["workspace", "name", "overrides", "spec-version", "flags"];

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

fn parse_workspace_doc(doc: &KdlDocument) -> Result<Workspace, ManifestError> {
    let mut members: Vec<String> = Vec::new();
    let mut overrides: Vec<Override> = Vec::new();
    let mut seen_override_names: BTreeSet<String> = BTreeSet::new();
    let mut ws_flags: Vec<FlagDecl> = Vec::new();

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
            "name" => { /* informational only (grammar §7); accepted, discarded */ }
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

    Ok(Workspace { members, overrides, flags: ws_flags })
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
    let mut attestation_policy = AttestationPolicy::Permissive;

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
                        if !seen_names.insert(dep.name().to_string()) {
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
                        if !seen_dev_dep_names.insert(dep.name().to_string()) {
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
            "attestation-policy" => {
                let a = args(node);
                let val = a.first().and_then(|e| e.value().as_string());
                if a.len() != 1 || val.is_none() {
                    return Err(err(
                        "MAN-UNKNOWN-TOP-LEVEL",
                        "'attestation-policy' takes exactly one string argument \
                         ('permissive' or 'strict')",
                    ));
                }
                attestation_policy = match val.unwrap() {
                    "permissive" => AttestationPolicy::Permissive,
                    "strict" => AttestationPolicy::Strict,
                    other => {
                        return Err(err(
                            "MAN-UNKNOWN-TOP-LEVEL",
                            format!(
                                "'attestation-policy' must be 'permissive' or 'strict', got {other:?}"
                            ),
                        ));
                    }
                };
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
        attestation_policy,
        optional_auto_flags,
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
    let mut dep = parse_dep(child)?;
    if !inherited.is_empty() {
        // Thread inherited when-block predicates into all five dep forms.
        // §6.3 NORMATIVE: all five forms (UrlDep, NamedDep, LocalDep, TarballDep,
        // MemberDep) support when-conditional syntax.  Inherited predicates are
        // prepended (outer predicates come first; dep's own predicates follow).
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
            Dep::Member(ref mut m) => {
                let mut merged = inherited.to_vec();
                merged.append(&mut m.predicates);
                m.predicates = merged;
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
    // R2-C1 security fix: validate dep name charset at parse boundary.
    // KDL 2.0 quoted node names can contain chars outside [A-Za-z0-9_-].
    // A dep name with \n (or other nim.cfg-significant char) would inject content
    // via --path:"_deps/<name>" and -d:<pkg>_<flag> emit lines in nimcfg.rs.
    let dep_nm = node.name().value();
    if !valid_flag_name(dep_nm) {
        return Err(err(
            "MAN-DEP-NAME-INVALID",
            format!(
                "dep {dep_nm:?}: dep names must match [A-Za-z0-9_-]+ \
                 (no spaces, control characters, or nim.cfg-significant chars)"
            ),
        ));
    }
    let names = prop_names(node);
    if names.contains("git") {
        Ok(Dep::Url(parse_url_dep(node)?))
    } else if names.contains("local") {
        Ok(Dep::Local(parse_local_dep(node)?))
    } else if names.contains("tarball") {
        Ok(Dep::Tarball(parse_tarball_dep(node)?))
    } else {
        Ok(Dep::Named(parse_named_dep(node)?))
    }
}

fn parse_url_dep(node: &KdlNode) -> Result<UrlDep, ManifestError> {
    let name = node.name().value().to_string();
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

    Ok(UrlDep {
        name,
        git,
        git_ref,
        mirrors,
        predicates,
        flag_requests,
        optional,
    })
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

fn parse_local_dep(node: &KdlNode) -> Result<LocalDep, ManifestError> {
    let name = node.name().value().to_string();
    let extra: Vec<&str> = prop_names(node)
        .into_iter()
        .filter(|p| *p != "local")
        .collect();
    if !extra.is_empty() {
        return Err(err(
            "MAN-DEP-UNKNOWN-PROPS",
            format!("dep {name:?}: unknown property/properties {extra:?} on a local dep"),
        ));
    }
    match prop(node, "local").unwrap().value().as_string() {
        Some(p) if !p.is_empty() => Ok(LocalDep {
            name,
            path: p.to_string(),
            predicates: vec![], // Populated by expand_dep_child from when-block.
        }),
        _ => Err(err(
            "MAN-DEP-LOCAL-PATH",
            format!("dep {name:?}: 'local' property must be a non-empty string path"),
        )),
    }
}

fn parse_tarball_dep(node: &KdlNode) -> Result<TarballDep, ManifestError> {
    let name = node.name().value().to_string();
    let allowed = ["tarball", "sha256", "strip_components"];
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
    Ok(TarballDep {
        name,
        url,
        sha256,
        strip_components,
        predicates: vec![], // Populated by expand_dep_child from when-block.
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

fn parse_named_dep(node: &KdlNode) -> Result<NamedDep, ManifestError> {
    let name = node.name().value().to_string();
    // Only `optional` is a valid property on NamedDep (git= routes to UrlDep).
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
    // Any property besides `optional` is an error.
    for (key, _) in props(node) {
        if key != "optional" {
            return Err(err(
                "MAN-DEP-NAMED-PROPS",
                format!("dep {name:?}: unknown property/properties {key:?} on a named dep"),
            ));
        }
    }
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
                format!("dep {name:?}: unknown child node {child_nm:?}; only \"flag\" is valid on a named dep"),
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
    })
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

/// Known property keys on a `pkg` override node across all target forms.
const OVERRIDE_KNOWN_PROPS: &[&str] = &["git", "ref", "local"];

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
    let child_nodes = children(node);
    let member_children: Vec<_> = child_nodes
        .iter()
        .filter(|c| c.name().value() == "member")
        .collect();
    let has_member = !member_children.is_empty();

    let target_count = [has_git, has_local, has_member]
        .iter()
        .filter(|&&b| b)
        .count();
    if target_count != 1 {
        return Err(err(
            "MAN-OVERRIDE-TARGET-AMBIGUOUS",
            format!(
                "override for {name:?}: exactly one provenance form is required \
                 (git, local, or member); got {} ({})",
                target_count,
                if target_count == 0 { "none" } else { "multiple forms mixed" }
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
        OverrideTarget::Git { url, git_ref }
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

    Ok(Override { name, target })
}

// ---------------------------------------------------------------------------
// Shared validators.
// ---------------------------------------------------------------------------

/// Normalize a URL argument: accept a string value (plain or `(url)`-annotated);
/// reject a non-string value or any other type annotation (grammar §2).
fn url_arg(context: &str, field: &str, entry: &KdlEntry) -> Result<String, ManifestError> {
    match entry.value().as_string() {
        Some(s) => match entry_ty(entry) {
            None | Some("url") => Ok(s.to_string()),
            Some(other) => Err(err(
                "MAN-URL-ARG-TYPE",
                format!("{context}: {field:?} has unsupported type annotation ({other:?}); only (url) is recognized"),
            )),
        },
        None => Err(err(
            "MAN-URL-ARG-TYPE",
            format!("{context}: {field:?} expects a URL string (plain or (url)-annotated)"),
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
