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

/// Highest manifest spec-version epoch this implementation understands
/// (grammar §4.4). Bumped only for breaking semantic changes; additive
/// evolution stays within an epoch via the P3 forward-unknown properties.
pub const MANIFEST_SPEC_VERSION: i64 = 1;

// ---------------------------------------------------------------------------
// Data model — mirrors `milpa/manifest.py` (one design, two impls).
// ---------------------------------------------------------------------------

/// A consumer's request for a specific flag state on a dep (grammar §3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagRequest {
    pub name: String,
    pub enabled: bool,
}

/// A dep declared by git URL + ref (grammar §3.2 UrlDep).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlDep {
    pub name: String,
    pub git: String,
    pub git_ref: String,
    pub mirrors: Vec<String>,
    pub predicates: Vec<Predicate>,
    pub flag_requests: Vec<FlagRequest>,
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
#[derive(Debug, Clone)]
pub struct NamedDep {
    pub name: String,
    /// Raw constraint string, preserved for KDL round-trip emit. `None` = any.
    pub constraint: Option<String>,
    /// Pre-parsed `VersionSet`; `None` iff `constraint` is `None`.
    pub parsed_constraint: Option<VersionSet>,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDep {
    pub name: String,
    pub path: String,
}

/// A dep declared by tarball URL (grammar §3.2 TarballDep).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarballDep {
    pub name: String,
    pub url: String,
    pub sha256: Option<String>,
    pub strip_components: u32,
}

/// A workspace-internal member reference (grammar §3.2 MemberDep).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberDep {
    pub name: String,
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

    /// The conditional predicates on this dep (only UrlDep carries them today).
    pub fn predicates(&self) -> &[Predicate] {
        match self {
            Dep::Url(d) => &d.predicates,
            _ => &[],
        }
    }
}

/// A `pkg`-form override (grammar §3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    pub name: String,
    pub git: String,
    pub git_ref: String,
}

/// A named feature flag declared by a package (grammar §3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagDecl {
    pub name: String,
    pub default: bool,
    pub description: String,
    pub defines: Vec<String>,
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Workspace {
    pub members: Vec<String>,
    pub overrides: Vec<Override>,
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
    "MAN-CAS-DIR-MISSING",
    "MAN-CAS-DIR-TYPE",
    "MAN-SPEC-VERSION-TYPE",
    "MAN-SPEC-VERSION-UNSUPPORTED",
    "MAN-DEP-DUPLICATE",
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
    "MAN-OVERRIDE-GIT-MISSING",
    "MAN-OVERRIDE-REF-MISSING",
    "MAN-OVERRIDE-DUPLICATE",
    "MAN-FLAG-DUPLICATE",
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

/// Property entries of a node as `(key, entry)`, in source order. Duplicate
/// keys are preserved; [`prop`] applies last-wins for lookups.
fn props(node: &KdlNode) -> Vec<(&str, &KdlEntry)> {
    node.entries()
        .iter()
        .filter_map(|e| e.name().map(|n| (n.value(), e)))
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
const URL_DEP_PROPS: &[&str] = &["git", "ref", "platform", "arch", "nim", "milpa", "flag"];
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
const WORKSPACE_TOP_LEVEL: &[&str] = &["workspace", "name", "overrides", "spec-version"];

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

fn parse_kdl(text: &str) -> Result<KdlDocument, ManifestError> {
    // Depth guard: kdl-rs 6.7.1 is recursive-descent with no internal stack
    // limit; deeply-nested input causes an OS stack overflow (SIGABRT — not
    // a catchable panic).  Reject before calling the parser.
    if kdl_brace_depth(text) > KDL_MAX_NESTING_DEPTH {
        return Err(err(
            "MAN-KDL-SYNTAX",
            format!(
                "KDL input exceeds maximum nesting depth ({KDL_MAX_NESTING_DEPTH})"
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

    Ok(Workspace { members, overrides })
}

// ---------------------------------------------------------------------------
// Package document.
// ---------------------------------------------------------------------------

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
                src_dir = val.unwrap().to_string();
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

    // `when flag="X"` must reference a declared flag (grammar §3.5).
    let declared: BTreeSet<&str> = flags.iter().map(|f| f.name.as_str()).collect();
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
        if let Dep::Url(ref mut u) = dep {
            let mut merged = inherited.to_vec();
            merged.append(&mut u.predicates);
            u.predicates = merged;
        }
    }
    Ok(vec![dep])
}

/// Disambiguate and parse one dep node (grammar §3.2 ordered rules).
fn parse_dep(node: &KdlNode) -> Result<Dep, ManifestError> {
    if node.name().value() == "member" {
        return Ok(Dep::Member(parse_member_dep(node)?));
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

    Ok(UrlDep {
        name,
        git,
        git_ref,
        mirrors,
        predicates,
        flag_requests,
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
    Ok(MemberDep {
        name: val.unwrap().to_string(),
    })
}

fn parse_named_dep(node: &KdlNode) -> Result<NamedDep, ManifestError> {
    let name = node.name().value().to_string();
    if !props(node).is_empty() {
        return Err(err(
            "MAN-DEP-NAMED-PROPS",
            format!("dep {name:?}: unknown property/properties on a named dep"),
        ));
    }
    let a = args(node);
    match a.len() {
        0 => Ok(NamedDep {
            name,
            constraint: None,
            parsed_constraint: None,
        }),
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
            Ok(NamedDep {
                name,
                constraint: Some(raw_str),
                parsed_constraint: Some(parsed),
            })
        }
        n => Err(err(
            "MAN-DEP-NAMED-ARITY",
            format!("dep {name:?}: named deps take at most one positional argument; got {n}"),
        )),
    }
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
    let mut all = inline;
    all.extend(child);
    all.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(all)
}

// ---------------------------------------------------------------------------
// Flags + overrides.
// ---------------------------------------------------------------------------

fn parse_flag_decl(node: &KdlNode) -> Result<FlagDecl, ManifestError> {
    let name = node.name().value().to_string();
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
    for child in children(node) {
        if child.name().value() != "defines" {
            return Err(err(
                "MAN-FLAG-UNKNOWN-CHILD",
                format!(
                    "flag {name:?}: unknown child node {:?} (allowed: 'defines')",
                    child.name().value()
                ),
            ));
        }
        for entry in args(child) {
            match entry.value().as_string() {
                Some(s) => defines.push(s.to_string()),
                None => {
                    return Err(err(
                        "MAN-FLAG-DEFINES-ARG-TYPE",
                        format!("flag {name:?}: 'defines' args must be strings"),
                    ));
                }
            }
        }
    }
    Ok(FlagDecl {
        name,
        default,
        description,
        defines,
    })
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
    let extra: Vec<&str> = prop_names(node)
        .into_iter()
        .filter(|p| !URL_DEP_PROPS.contains(p))
        .collect();
    if !extra.is_empty() {
        return Err(err(
            "MAN-OVERRIDE-UNKNOWN-PROPS",
            format!("override for {name:?}: unknown property/properties {extra:?}"),
        ));
    }
    let git_entry = prop(node, "git").ok_or_else(|| {
        err(
            "MAN-OVERRIDE-GIT-MISSING",
            format!("override for {name:?}: missing required property 'git'"),
        )
    })?;
    let ref_entry = prop(node, "ref").ok_or_else(|| {
        err(
            "MAN-OVERRIDE-REF-MISSING",
            format!("override for {name:?}: missing required property 'ref'"),
        )
    })?;
    let git = url_arg(&format!("override {name:?}"), "git", git_entry)?;
    validate_git_url(&name, &git)?;
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
    Ok(Override { name, git, git_ref })
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
