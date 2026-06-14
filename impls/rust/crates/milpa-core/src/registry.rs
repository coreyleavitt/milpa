//! tianguis `index.kdl` reader (RFC §6 S8; `spec/registry-protocol.md`).
//!
//! The index is the authoritative named-package registry: per-version
//! `content_hash` (identity) + preference-ordered transport provenances. Mirrors
//! `milpa/tianguis_client.py`'s *parse + resolve* contract. Every attacker-
//! supplied string (names, URLs, refs, OCI fields, commit shas) is validated at
//! this trust boundary — before it can reach subprocess argv or the `_deps/`
//! filesystem — so the rest of the system can trust an [`Index`] once parsed.
//!
//! **Index acquisition (the 4-state network cache + `MILPA_INDEX_URL` override)
//! is deliberately NOT here.** No conformance fixture exercises it — the harness
//! reads `index.kdl` from the fixture directory — and its only consumer is the
//! CLI's index loader (S13). Building it now would be an unwired, consumer-less
//! module; it lands with the CLI that drives it. The fetcher-dispatch
//! `FetcherRegistry` is likewise deferred to S14, where real transports exist to
//! dispatch to (a registry with no fetchers to resolve to is meaningless).

use kdl::{KdlDocument, KdlNode};
use milpa_manifest::{kdl_brace_depth, KDL_MAX_NESTING_DEPTH};
use milpa_solver::{parse_version, VersionSet};
use milpa_types::Provenance;

use crate::error::CoreError;

/// The only index schema version this milpa understands. A document declaring a
/// *higher* version is refused (`TNG-SCHEMA-UNKNOWN`) rather than silently
/// misread; lower-or-equal reads forward-compatibly (registry-protocol §2.1).
pub const TIANGUIS_INDEX_SCHEMA_VERSION: i128 = 1;

fn tng(code: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::Tianguis(code, message.into())
}

// ---------------------------------------------------------------------------
// Trust-boundary validators (single source of truth — called from parse)
// ---------------------------------------------------------------------------

/// True iff `name` is safe as a path component under `_deps/`. Names containing
/// `..`, `/`, `\`, or that are absolute would escape the sandbox. Single source
/// of truth for the safe-name rule (registry-protocol §3.3); the resolver's
/// URL-derived-name check shares the same predicate.
pub fn is_safe_name(name: &str) -> bool {
    !(name.contains("..")
        || name.contains('/')
        || name.contains('\\')
        || std::path::Path::new(name).is_absolute())
}

fn validate_safe_name(name: &str) -> Result<(), CoreError> {
    if is_safe_name(name) {
        Ok(())
    } else {
        Err(tng(
            "TNG-UNSAFE-NAME",
            format!(
                "package name {name:?} contains path-traversal characters \
                 (`..`, `/`, `\\`, or absolute path) — unsafe under _deps/"
            ),
        ))
    }
}

/// Reject a value beginning with `-` — git/oras would read it as a flag
/// (flag-injection). `code` is the field-specific TNG slug.
fn validate_no_leading_dash(value: &str, field: &str, code: &'static str) -> Result<(), CoreError> {
    if value.starts_with('-') {
        Err(tng(
            code,
            format!("{field} {value:?} begins with `-` (flag injection)"),
        ))
    } else {
        Ok(())
    }
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_commit_sha(sha: &str) -> Result<(), CoreError> {
    if is_lower_hex(sha, 40) {
        Ok(())
    } else {
        Err(tng(
            "TNG-BAD-COMMIT-SHA",
            format!("commit_sha {sha:?} is not exactly 40 lowercase hex characters"),
        ))
    }
}

fn validate_oci_digest(digest: &str) -> Result<(), CoreError> {
    let ok = digest
        .strip_prefix("sha256:")
        .is_some_and(|hex| is_lower_hex(hex, 64));
    if ok {
        Ok(())
    } else {
        Err(tng(
            "TNG-BAD-OCI-DIGEST",
            format!("OCI digest {digest:?} is not in `sha256:<64 hex>` format"),
        ))
    }
}

/// Validate a `dep_decl` pointer from the index version-node.
///
/// The pointer MUST be `sha256:` followed by exactly 64 lowercase hex
/// characters (registry-protocol §3.2 NORMATIVE).  Anything else —
/// including path-traversal payloads like `sha256:../../etc/passwd` or
/// abbreviated / uppercase hex — is rejected here at parse time before the
/// value can reach `FileDepDeclStore` (filesystem path) or `HttpDepDeclStore`
/// (URL path segment).
fn validate_dep_decl_pointer(pointer: &str) -> Result<(), CoreError> {
    let ok = pointer
        .strip_prefix("sha256:")
        .is_some_and(|hex| is_lower_hex(hex, 64));
    if ok {
        Ok(())
    } else {
        Err(tng(
            "TNG-BAD-DEP-DECL",
            format!(
                "dep_decl pointer {pointer:?} is not in `sha256:<64 lowercase hex>` format \
                 — path-traversal or malformed pointer rejected at parse boundary"
            ),
        ))
    }
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// One published version of a package. `provenances` is **preference-ordered**
/// (index node order): element 0 is canonical, the rest mirrors. Callers MUST
/// NOT reorder — the identity gate makes any mirror yielding different bytes a
/// hard error, so ordered fall-through is safe (registry-protocol §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexVersion {
    pub version: String,
    /// `sha256:…`; empty when the index entry declares no identity (caught as
    /// `TNG-NO-IDENTITY` when such a version is selected, never silently).
    pub content_hash: String,
    pub provenances: Vec<Provenance>,
    /// Optional hash pointer (`sha256:…`) to the DepDecl artifact for this
    /// version (registry-protocol §3.2.3).  `None` when absent (forward-compat:
    /// old index entries omit it).
    pub dep_decl: Option<String>,
    /// The DepDecl schema version integer that produced `dep_decl`
    /// (registry-protocol §3.2.1).  `None` when absent.
    pub dep_decl_schema_version: Option<i64>,
}

/// A package: a `(namespace, name)` identity plus its versions (newest-first).
/// Two packages may share a bare `name` under different namespaces — that is the
/// real identity, never silently collapsed (registry-protocol §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub namespace: String,
    pub versions: Vec<IndexVersion>,
}

/// The outcome of a bare-name (namespace-unqualified) lookup. A typed result,
/// **not** an exception: the primitive stays raise-free so a future multi-version
/// provider can enumerate candidates while backtracking; policy (which TNG error
/// to raise) lives in the caller (`resolve_named_all`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BareLookup {
    Found(Package),
    Ambiguous(Vec<String>),
    NotFound,
}

/// The parsed registry index, in document order for deterministic iteration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index {
    pub packages: Vec<Package>,
}

impl Index {
    /// Parse an `index.kdl` document into an [`Index`] (registry-protocol §2–§4).
    ///
    /// Validates the schema version, then every package: the name is safe-checked
    /// and each version's provenances are sanitized at this trust boundary
    /// (`TNG-UNSAFE-NAME` / `TNG-BAD-COMMIT-SHA` / `TNG-BAD-OCI-DIGEST` /
    /// `TNG-UNSAFE-URL` / `TNG-UNSAFE-REF` / `TNG-UNSAFE-OCI-FIELD`). Duplicate
    /// versions keep the first (forward-compat skip); unknown provenance kinds
    /// are ignored (a transport this milpa can't fetch shouldn't be fatal — other
    /// provenances on the same version may still be usable). Versions sort
    /// newest-first by semver, unparseable trailing in document order.
    pub fn parse(text: &str) -> Result<Index, CoreError> {
        // Depth guard — see milpa_manifest::KDL_MAX_NESTING_DEPTH for rationale.
        if kdl_brace_depth(text) > KDL_MAX_NESTING_DEPTH {
            return Err(tng(
                "TNG-KDL-SYNTAX",
                format!("KDL input exceeds maximum nesting depth ({KDL_MAX_NESTING_DEPTH})"),
            ));
        }
        let doc = KdlDocument::parse(text)
            .map_err(|e| tng("TNG-KDL-SYNTAX", format!("index KDL syntax error: {e}")))?;

        check_schema_version(&doc)?;

        let mut packages: Vec<Package> = Vec::new();
        for node in doc.nodes() {
            if node.name().value() != "package" {
                continue;
            }
            // A non-string (or missing) package name is a malformed entry; skip
            // it (mirrors the Python warn-and-skip — Rust has no warnings channel).
            let Some(name) = first_arg_str(node) else {
                continue;
            };
            // Reject path-traversal names at the boundary (hard error — a crafted
            // `..`-name is an active attack vector, not a formatting quirk).
            validate_safe_name(&name)?;
            let namespace = child_arg_str(node, "namespace").unwrap_or_default();

            let mut versions: Vec<IndexVersion> = Vec::new();
            let mut seen: Vec<String> = Vec::new();
            for child in children(node) {
                if child.name().value() != "version" {
                    continue;
                }
                let Some(ver) = first_arg_str(child) else {
                    continue;
                };
                if seen.contains(&ver) {
                    continue; // duplicate-version tolerance: keep the first
                }
                seen.push(ver.clone());
                versions.push(parse_version_node(&ver, child)?);
            }

            // Newest-first: parseable versions descending, then unparseable in
            // document order (no heterogeneous sentinel).
            let (mut parseable, unparseable): (Vec<_>, Vec<_>) = versions
                .into_iter()
                .partition(|v| parse_version(&v.version).is_some());
            parseable.sort_by(|a, b| {
                parse_version(&b.version)
                    .unwrap()
                    .cmp(&parse_version(&a.version).unwrap())
            });
            parseable.extend(unparseable);

            packages.push(Package {
                name,
                namespace,
                versions: parseable,
            });
        }
        Ok(Index { packages })
    }

    /// Look up by bare `name` (registry-protocol §3.2). Raise-free.
    pub fn lookup_bare(&self, name: &str) -> BareLookup {
        let matches: Vec<&Package> = self.packages.iter().filter(|p| p.name == name).collect();
        match matches.as_slice() {
            [] => BareLookup::NotFound,
            [one] => BareLookup::Found((*one).clone()),
            many => BareLookup::Ambiguous(many.iter().map(|p| p.namespace.clone()).collect()),
        }
    }

    /// Resolve `name` against `vs`, returning ALL satisfying versions newest-first
    /// (the Phase-A enumerate step for the two-phase provider).
    ///
    /// Mirrors `tianguis_client.resolve_named_all`: not-in-index → `TNG-NOT-FOUND`;
    /// a bare-name collision → `TNG-AMBIGUOUS-NAME`; satisfying versions that lack
    /// provenance are skipped, and if *none* with provenance remain →
    /// `TNG-NO-PROVENANCE` (when some were skipped) or `TNG-NO-SATISFYING-VERSION`.
    /// Per-version identity (`content_hash`) is **not** checked here — that gate
    /// (`TNG-NO-IDENTITY`) fires when a version is actually selected for fetch.
    pub fn resolve_named_all(
        &self,
        name: &str,
        vs: &VersionSet,
        constraint_desc: Option<&str>,
    ) -> Result<Vec<IndexVersion>, CoreError> {
        let pkg = match self.lookup_bare(name) {
            BareLookup::NotFound => {
                return Err(tng(
                    "TNG-NOT-FOUND",
                    format!("package {name:?} is not in the tianguis index"),
                ));
            }
            BareLookup::Ambiguous(mut nss) => {
                nss.sort();
                return Err(tng(
                    "TNG-AMBIGUOUS-NAME",
                    format!(
                        "package {name:?} matches multiple namespaces: {} — \
                         use a namespace-qualified reference",
                        nss.join(", ")
                    ),
                ));
            }
            BareLookup::Found(pkg) => pkg,
        };

        let mut satisfying: Vec<IndexVersion> = Vec::new();
        let mut provenance_less: Vec<String> = Vec::new();
        for v in &pkg.versions {
            let Some(parsed) = parse_version(&v.version) else {
                continue;
            };
            if vs.contains(&parsed) {
                if v.provenances.is_empty() {
                    provenance_less.push(v.version.clone());
                    continue;
                }
                satisfying.push(v.clone());
            }
        }

        if satisfying.is_empty() {
            if !provenance_less.is_empty() {
                return Err(tng(
                    "TNG-NO-PROVENANCE",
                    format!(
                        "{name:?} has no fetchable version satisfying {constraint_desc:?} — \
                         all satisfying versions lack provenance: {}",
                        provenance_less.join(", ")
                    ),
                ));
            }
            return Err(tng(
                "TNG-NO-SATISFYING-VERSION",
                format!(
                    "no version of {name:?} satisfies constraint {constraint_desc:?} (available: {})",
                    pkg.versions
                        .iter()
                        .map(|v| v.version.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
        Ok(satisfying)
    }
}

// ---------------------------------------------------------------------------
// Parse helpers
// ---------------------------------------------------------------------------

/// Refuse an index whose declared `schema_version` exceeds the supported epoch.
/// A missing node is tolerated (legacy/minimal indexes predate the field).
fn check_schema_version(doc: &KdlDocument) -> Result<(), CoreError> {
    for node in doc.nodes() {
        if node.name().value() != "schema_version" {
            continue;
        }
        if let Some(v) = node.entries().iter().find(|e| e.name().is_none()) {
            if let Some(n) = v.value().as_integer() {
                if n > TIANGUIS_INDEX_SCHEMA_VERSION {
                    return Err(tng(
                        "TNG-SCHEMA-UNKNOWN",
                        format!(
                            "index declares schema_version {n}, but this milpa understands \
                             at most {TIANGUIS_INDEX_SCHEMA_VERSION} — upgrade milpa"
                        ),
                    ));
                }
            }
        }
        return Ok(());
    }
    Ok(())
}

fn parse_version_node(ver: &str, node: &KdlNode) -> Result<IndexVersion, CoreError> {
    let content_hash = child_arg_str(node, "content_hash").unwrap_or_default();
    let dep_decl_raw = child_arg_str(node, "dep_decl").filter(|s| !s.is_empty());
    if let Some(ref ptr) = dep_decl_raw {
        validate_dep_decl_pointer(ptr)?;
    }
    let dep_decl = dep_decl_raw;
    let dep_decl_schema_version = child_arg_i64(node, "dep_decl_schema_version");
    let mut provenances: Vec<Provenance> = Vec::new();
    for child in children(node) {
        if child.name().value() != "provenance" {
            continue;
        }
        match child_arg_str(child, "kind").as_deref() {
            Some("git") => {
                let url = child_arg_str(child, "url").unwrap_or_default();
                let git_ref = child_arg_str(child, "ref").unwrap_or_default();
                let commit = child_arg_str(child, "commit_sha");
                validate_no_leading_dash(&url, "git url", "TNG-UNSAFE-URL")?;
                validate_no_leading_dash(&git_ref, "git ref", "TNG-UNSAFE-REF")?;
                if let Some(sha) = &commit {
                    validate_commit_sha(sha)?;
                }
                provenances.push(Provenance::Git {
                    url,
                    ref_spec: git_ref,
                    commit_sha: commit,
                });
            }
            Some("oci") => {
                let registry = child_arg_str(child, "registry").unwrap_or_default();
                let repository = child_arg_str(child, "repository").unwrap_or_default();
                let digest = child_arg_str(child, "digest").unwrap_or_default();
                validate_no_leading_dash(&registry, "oci registry", "TNG-UNSAFE-OCI-FIELD")?;
                validate_no_leading_dash(&repository, "oci repository", "TNG-UNSAFE-OCI-FIELD")?;
                validate_oci_digest(&digest)?;
                provenances.push(Provenance::Oci {
                    registry,
                    repository,
                    digest,
                });
            }
            // Unknown / missing kind: forward-compat skip.
            _ => {}
        }
    }
    Ok(IndexVersion {
        version: ver.to_string(),
        content_hash,
        provenances,
        dep_decl,
        dep_decl_schema_version,
    })
}

/// First positional argument of `node` as a string, or `None`.
fn first_arg_str(node: &KdlNode) -> Option<String> {
    node.entries()
        .iter()
        .find(|e| e.name().is_none())
        .and_then(|e| e.value().as_string())
        .map(str::to_string)
}

/// First positional arg (string) of `node`'s child named `child_name`.
/// Accepts both bare strings and `(url)`-annotated values (kdl-rs keeps the
/// annotation on the entry type; `.as_string()` returns the value either way).
fn child_arg_str(node: &KdlNode, child_name: &str) -> Option<String> {
    children(node)
        .into_iter()
        .find(|c| c.name().value() == child_name)
        .and_then(first_arg_str)
}

/// First positional arg (integer) of `node`'s child named `child_name`, or
/// `None` when the child is absent or its first arg is not an integer.
/// `kdl-rs` returns integers as `i128`; we narrow to `i64` (all valid
/// schema version values fit; `dep_decl_schema_version` is a small non-negative
/// integer per registry-protocol §3.2.1).
fn child_arg_i64(node: &KdlNode, child_name: &str) -> Option<i64> {
    children(node)
        .into_iter()
        .find(|c| c.name().value() == child_name)
        .and_then(|child| {
            child
                .entries()
                .iter()
                .find(|e| e.name().is_none())
                .and_then(|e| e.value().as_integer())
                .and_then(|v| i64::try_from(v).ok())
        })
}

fn children(node: &KdlNode) -> Vec<&KdlNode> {
    node.children()
        .map(|d| d.nodes().iter().collect())
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod registry_tests;
