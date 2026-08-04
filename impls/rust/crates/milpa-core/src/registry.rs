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
use milpa_manifest::{kdl_block_comment_depth, kdl_brace_depth, KDL_MAX_NESTING_DEPTH};
use milpa_solver::{parse_version, VersionSet};
use milpa_types::{AttestationKind, EntryAttestation, Provenance, RekorRef};
// D0 (rfc-resolution-semantics.md Axis D prerequisite): `Timestamp` +
// `parse_iso8601_timestamp` moved to `milpa-types` so `milpa-manifest` can
// reach them too (D1) without a crate cycle. Re-exported here for back-compat
// — all existing `crate::registry::{Timestamp, parse_iso8601_timestamp}` /
// `milpa_core::registry::{Timestamp, parse_iso8601_timestamp}` references
// compile unchanged.
pub use milpa_types::{parse_iso8601_timestamp, Timestamp};

use crate::epoch_commitment::EpochCommitmentStatus;
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

/// True iff `s` contains an ASCII control character (U+0000-U+001F
/// inclusive, or U+007F).
fn has_control_char(s: &str) -> bool {
    s.chars().any(|c| (c as u32) <= 0x1f || c as u32 == 0x7f)
}

/// Reject a value containing an ASCII control character (U+0000-U+001F or
/// U+007F). Registry string fields are attacker-controlled network input
/// (`index.kdl` is fetched, not authored locally); KDL 2.0's `\u{XXXX}`
/// escape syntax can deliver a literal control character through an
/// otherwise well-formed string literal — these are exactly the delimiter
/// bytes the append-only ratchet's canonical violation digest
/// (registry-protocol §3.5.3) and its non-scalar renderings use (TAB, LF,
/// `\x1f`, `\x1e`, `\x01`). Rejected at the parse boundary (registry-protocol
/// §3.3 NORMATIVE (control-character rejection)) so no downstream consumer —
/// ratchet comparison, digest rendering, CLI output — ever sees one. A
/// single, field-independent slug covers every field this validator guards
/// (same economy `TNG-UNSAFE-OCI-FIELD` already applies across its own two
/// fields).
pub(crate) fn validate_no_control_chars(value: &str, field: &str) -> Result<(), CoreError> {
    if has_control_char(value) {
        Err(tng(
            "TNG-UNSAFE-CONTROL-CHAR",
            format!(
                "{field} {value:?} contains an ASCII control character \
                 (U+0000-U+001F or U+007F) — rejected at parse boundary"
            ),
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

pub(crate) fn validate_oci_digest(digest: &str) -> Result<(), CoreError> {
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
    /// RFC per-entry-attestation.md P2 (registry-protocol §3.2): the per-entry
    /// Layer 2 attribution CLAIM, or `None` when the entry carries no
    /// attestation record, OR when a present record failed the closed-set /
    /// structural-validity check and conservatively collapsed to unattested.
    pub attestation: Option<EntryAttestation>,
    /// P3a (RFC per-entry-attestation.md §1): the enclosing `Package`'s
    /// namespace — always the REAL resolved namespace, even when the
    /// manifest dep declaration was a bare (unqualified) name. Distinct from
    /// the dep-key namespace tracked elsewhere (which records only whether
    /// the manifest EXPLICITLY qualified the dep). Needed so the entry-trust
    /// gate can build the exact `pkg:tianguis/<namespace>/<name>@<version>`
    /// subject coordinate (§1) for a bare-name dep.
    pub namespace: String,
    /// A2a (registry-protocol §3.2 "published_at"): ISO 8601 publication
    /// timestamp, parse-to-typed. `None` when absent OR malformed — a
    /// malformed value MUST NOT raise (the parser's ordinary optional-scalar
    /// robustness posture). Also the SET_ONCE input the A3 ratchet compares
    /// (`ratchet.rs`); the DIGEST-relevant raw served string is captured
    /// separately by [`raw_published_at`] (never derived from this typed
    /// value, which does not round-trip losslessly to source text).
    pub published_at: Option<Timestamp>,
    /// A2a (registry-protocol §3.2 "Yank triple"): defaults to `false`. A
    /// malformed (non-boolean) value MUST NOT raise — surfaced as the
    /// default.
    pub yanked: bool,
    /// A2a: ISO 8601 timestamp of the yank, or `None` when absent/malformed.
    pub yanked_at: Option<Timestamp>,
    /// A2a: free-text yank explanation, or `None` when absent.
    pub yanked_reason: Option<String>,
    /// A3 (`rfc-registry-append-only.md`): the RAW served text of the
    /// `published_at` child argument, exactly as it appears in the document
    /// — never derived from `published_at` above (whose typed
    /// representation does not round-trip losslessly to source text, e.g. a
    /// `Z`-suffixed offset). `None` iff the child node is absent (mirrors
    /// `published_at`'s own absence, regardless of whether the raw text
    /// happened to be malformed — a malformed-but-present raw string is
    /// still the digest-relevant "value exactly as served"). Consumed only
    /// by `ratchet.rs`'s canonical-digest seam; not part of the type's
    /// public equality contract for any other purpose.
    pub published_at_raw: Option<String>,
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
///
/// `epoch_commitment_status` — the S-EpochCommitment index-gate phase's
/// output (`rfc-attestation-v1-normative.md` §6, D14; registry-protocol
/// §3.4.8). Defaults to `Unarmed` — `Index::parse` itself never computes
/// this (parsing is pure, offline, and crypto-free); the caller that owns
/// sidecar acquisition + composed verification (the CLI / `index_cache.rs`,
/// once per resolve) overwrites this field with the real computed status
/// AFTER `Index::parse` returns. Mirrors `registry.py::Index.epoch_commitment_status`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index {
    pub packages: Vec<Package>,
    pub epoch_commitment_status: EpochCommitmentStatus,
}

impl Index {
    /// Parse an `index.kdl` document into an [`Index`] (registry-protocol §2–§4).
    ///
    /// Validates the schema version, then every package: the name is safe-checked
    /// and each version's provenances are sanitized at this trust boundary
    /// (`TNG-UNSAFE-NAME` / `TNG-BAD-COMMIT-SHA` / `TNG-BAD-OCI-DIGEST` /
    /// `TNG-UNSAFE-URL` / `TNG-UNSAFE-REF` / `TNG-UNSAFE-OCI-FIELD`). EVERY
    /// free-text field — `name`, `namespace`, a version string, `content_hash`,
    /// git `url`/`ref`, oci `registry`/`repository`, `signed_by`, rekor
    /// `uuid`/`log_index`/`integrated_time`, `yanked_reason` — is
    /// charset-checked for ASCII control characters (`TNG-UNSAFE-CONTROL-CHAR`
    /// — registry-protocol §3.3 NORMATIVE). `attestation-epoch` (a
    /// document-root free-text field this type does not surface — see
    /// `index_ratchet_seam::raw_attestation_epoch`) gets the identical check
    /// at its own re-walk site. Fields anchored by a hex/format shape regex
    /// (`commit_sha`, oci `digest`, `dep_decl` pointer, `bundle sha256=`) are
    /// safe by construction and deliberately NOT charset-checked. This is a
    /// COMPLETE enumeration (registry-protocol §3.3 NORMATIVE): a new
    /// free-text field added to the grammar MUST extend this list. Duplicate
    /// versions keep the first (forward-compat skip); unknown provenance kinds
    /// are ignored (a transport this milpa can't fetch shouldn't be fatal — other
    /// provenances on the same version may still be usable). Versions sort
    /// newest-first by semver, unparseable trailing in document order.
    pub fn parse(text: &str) -> Result<Index, CoreError> {
        // Depth guard — see milpa_manifest::KDL_MAX_NESTING_DEPTH for rationale.
        // Both brace depth and block-comment depth are checked (mirrors Python).
        if kdl_brace_depth(text) > KDL_MAX_NESTING_DEPTH {
            return Err(tng(
                "TNG-KDL-SYNTAX",
                format!("KDL input exceeds maximum nesting depth ({KDL_MAX_NESTING_DEPTH})"),
            ));
        }
        if kdl_block_comment_depth(text) > KDL_MAX_NESTING_DEPTH {
            return Err(tng(
                "TNG-KDL-SYNTAX",
                format!("KDL input exceeds maximum block-comment nesting depth ({KDL_MAX_NESTING_DEPTH})"),
            ));
        }
        let doc = KdlDocument::parse(text)
            .map_err(|e| tng("TNG-KDL-SYNTAX", format!("index KDL syntax error: {e}")))?;

        check_schema_version(&doc)?;

        let mut packages: Vec<Package> = Vec::new();
        // RFC per-entry-attestation.md P2 (registry-protocol §3.2 NORMATIVE
        // "parse boundary shape"): the version-node parser returns collapse
        // diagnostics; `Index::parse`'s PUBLIC signature stays a bare `Index`
        // (deliberate scope decision — mirrors the Python impl), so
        // diagnostics accumulate here and surface via the established
        // `[milpa] warning:` eprintln convention instead of a return value.
        let mut diagnostics: Vec<String> = Vec::new();
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
            validate_no_control_chars(&name, "name")?;
            let namespace = child_arg_str(node, "namespace").unwrap_or_default();
            validate_no_control_chars(&namespace, "namespace")?;

            let mut versions: Vec<IndexVersion> = Vec::new();
            let mut seen: Vec<String> = Vec::new();
            for child in children(node) {
                if child.name().value() != "version" {
                    continue;
                }
                let Some(ver) = first_arg_str(child) else {
                    continue;
                };
                validate_no_control_chars(&ver, "version")?;
                if seen.contains(&ver) {
                    continue; // duplicate-version tolerance: keep the first
                }
                seen.push(ver.clone());
                let (iv, iv_diagnostics) = parse_version_node(&namespace, &name, &ver, child)?;
                diagnostics.extend(iv_diagnostics);
                versions.push(iv);
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
        for diag in &diagnostics {
            eprintln!("[milpa] warning: {diag}");
        }
        Ok(Index { packages, epoch_commitment_status: EpochCommitmentStatus::Unarmed })
    }

    /// Look up by bare `name` (registry-protocol §3.2). Raise-free.
    /// Shared constraint-filtering core for both named-lookup entry points
    /// (registry-protocol §5.2 / §5.2 NORMATIVE yank clause). Single source
    /// of truth so `resolve_named_all` (bare) and `resolve_named_all_qualified`
    /// (S5b) never drift on selection semantics — the exact bug class §5.2's
    /// yank clause calls out ("the qualified path is exactly where a
    /// parallel-logic miss has happened before").
    ///
    /// Yank exclusion happens first, unconditionally of `vs` (§5.2 NORMATIVE:
    /// "excluded ... before ordering and constraint matching") — a yanked
    /// version never becomes a candidate regardless of whether it would
    /// otherwise satisfy the constraint. Returns
    /// `(satisfying, provenance_less_version_strings, yanked_excluded)`.
    ///
    /// `yanked_excluded` (CR13/5) is scoped to the DIAGNOSTIC use case only:
    /// it collects a yanked version iff it WOULD have satisfied `vs` had it
    /// not been yanked. Selection semantics are unaffected — yank exclusion
    /// above still happens unconditionally, before matching — this scoping
    /// only prevents the "(excluded as yanked: …)" message from citing
    /// yanked versions that would have failed the constraint anyway (e.g. a
    /// yanked 1.0.0 listed for a ^2.0.0 failure), which is misleading noise.
    fn filter_candidates(
        versions: &[IndexVersion],
        vs: &VersionSet,
    ) -> (Vec<IndexVersion>, Vec<String>, Vec<IndexVersion>) {
        let mut satisfying: Vec<IndexVersion> = Vec::new();
        let mut provenance_less: Vec<String> = Vec::new();
        let mut yanked_excluded: Vec<IndexVersion> = Vec::new();

        for v in versions {
            let Some(parsed) = parse_version(&v.version) else {
                continue; // unparseable version strings skipped (§5.2 NORMATIVE)
            };
            if v.yanked {
                if vs.contains(&parsed) {
                    yanked_excluded.push(v.clone());
                }
                continue;
            }
            if vs.contains(&parsed) {
                if v.provenances.is_empty() {
                    provenance_less.push(v.version.clone());
                    continue;
                }
                satisfying.push(v.clone());
            }
        }

        (satisfying, provenance_less, yanked_excluded)
    }

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

        let (satisfying, provenance_less, yanked_excluded) =
            Self::filter_candidates(&pkg.versions, vs);

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
            let mut message = format!(
                "no version of {name:?} satisfies constraint {constraint_desc:?} (available: {})",
                pkg.versions
                    .iter()
                    .map(|v| v.version.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if !yanked_excluded.is_empty() {
                message.push_str(&format!(
                    " (excluded as yanked: {})",
                    format_yanked_excluded(&yanked_excluded)
                ));
            }
            return Err(tng("TNG-NO-SATISFYING-VERSION", message));
        }
        Ok(satisfying)
    }

    /// S5b: qualified (namespace, name) lookup — never returns `TNG-AMBIGUOUS-NAME`.
    /// Returns `None` when the exact `(namespace, name)` pair is absent from the index.
    pub fn lookup_qualified(&self, namespace: &str, name: &str) -> Option<Package> {
        self.packages
            .iter()
            .find(|p| p.name == name && p.namespace == namespace)
            .cloned()
    }

    /// S5b: resolve a qualified `(namespace, name)` dep.  Bypasses bare-name
    /// collision detection — the caller already asserts the exact namespace.
    pub fn resolve_named_all_qualified(
        &self,
        namespace: &str,
        name: &str,
        vs: &VersionSet,
        constraint_desc: Option<&str>,
    ) -> Result<Vec<IndexVersion>, CoreError> {
        let qualified = format!("{namespace}/{name}");
        let pkg = match self.lookup_qualified(namespace, name) {
            Some(p) => p,
            None => {
                return Err(tng(
                    "TNG-NOT-FOUND",
                    format!("package {qualified:?} is not in the tianguis index"),
                ));
            }
        };

        let (satisfying, provenance_less, yanked_excluded) =
            Self::filter_candidates(&pkg.versions, vs);

        if satisfying.is_empty() {
            if !provenance_less.is_empty() {
                return Err(tng(
                    "TNG-NO-PROVENANCE",
                    format!(
                        "{qualified:?} has no fetchable version satisfying {constraint_desc:?} — \
                         all satisfying versions lack provenance: {}",
                        provenance_less.join(", ")
                    ),
                ));
            }
            let mut message = format!(
                "no version of {qualified:?} satisfies constraint {constraint_desc:?} (available: {})",
                pkg.versions
                    .iter()
                    .map(|v| v.version.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if !yanked_excluded.is_empty() {
                message.push_str(&format!(
                    " (excluded as yanked: {})",
                    format_yanked_excluded(&yanked_excluded)
                ));
            }
            return Err(tng("TNG-NO-SATISFYING-VERSION", message));
        }
        Ok(satisfying)
    }
}

/// D3 (resolution-semantics RFC §3 Axis D / §4 stage 2): the exclude-newer
/// hard cut at the enumeration layer.
///
/// Drops every candidate whose `published_at` is not provably `<=
/// exclude_newer` *before* the solver ever sees the candidate set ("the
/// enumeration layer drops candidates with `published_at > ts` *before* the
/// solver sees them"). `exclude_newer: None` is a no-op (returns `versions`
/// unchanged, 0 dropped) — the overwhelmingly common case, not a filter over
/// an empty bound.
///
/// **Fail-closed (§6 D-D3).** `published_at`'s ordinary optional-scalar
/// posture is *permissive*: absent-or-malformed collapses to `None` with no
/// diagnostic (see `IndexVersion::published_at`'s own doc comment). That
/// default is deliberately OVERRIDDEN here — a candidate whose publication
/// timestamp cannot be established fails the "provably predates
/// `exclude_newer`" test by construction, so it is EXCLUDED, never
/// permissively kept.
///
/// Returns `(kept, dropped_count)`. The caller (`process_named`, the
/// enumeration site) raises `RES-EXCLUDE-NEWER-EMPTY` when `dropped_count`
/// empties an otherwise-non-empty candidate set — a DISTINCT error class
/// from `TNG-NO-SATISFYING-VERSION` on purpose (§4 stage placement: this
/// filter runs against the constraint-blind stage-1 enumeration, before the
/// solver's own accumulated-constraint filter at stage 3, so a caller can
/// tell "no version ever satisfied the constraints" from "versions existed
/// but the time-bound excluded them all").
pub fn filter_by_exclude_newer(
    versions: &[IndexVersion],
    exclude_newer: Option<Timestamp>,
) -> (Vec<IndexVersion>, usize) {
    let Some(ts) = exclude_newer else {
        return (versions.to_vec(), 0);
    };
    let kept: Vec<IndexVersion> = versions
        .iter()
        .filter(|iv| iv.published_at.is_some_and(|pa| pa <= ts))
        .cloned()
        .collect();
    let dropped = versions.len() - kept.len();
    (kept, dropped)
}

/// Render the yanked-but-excluded segment of a `TNG-NO-SATISFYING-VERSION`
/// message (registry-protocol §5.2 / §3.2 `yanked_reason` "surfaced ... in
/// the TNG-NO-SATISFYING-VERSION message when relevant").
fn format_yanked_excluded(yanked_excluded: &[IndexVersion]) -> String {
    yanked_excluded
        .iter()
        .map(|v| match &v.yanked_reason {
            Some(r) => format!("{} ({r})", v.version),
            None => v.version.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
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

/// Parse one `version "<ver>" { … }` node into an `IndexVersion`.
///
/// Returns `(IndexVersion, collapse diagnostics)` — registry-protocol §3.2
/// NORMATIVE "parse boundary shape". The diagnostics list is non-empty only
/// when the entry's attestation record collapsed (closed-set violation,
/// structurally-invalid `author-signed`, or a malformed `bundle` pin).
fn parse_version_node(
    namespace: &str,
    pkg_name: &str,
    ver: &str,
    node: &KdlNode,
) -> Result<(IndexVersion, Vec<String>), CoreError> {
    let content_hash = child_arg_str(node, "content_hash").unwrap_or_default();
    validate_no_control_chars(&content_hash, "content_hash")?;
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
                validate_no_control_chars(&url, "git url")?;
                validate_no_control_chars(&git_ref, "git ref")?;
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
                // Optional `source` child (registry-protocol §3.3): the git
                // repository this artifact was packed and published from.
                // Accepts both plain-string and `(url)`-annotated form —
                // `child_arg_str` already strips the annotation transparently
                // (same helper `url`'s git-provenance parsing above uses).
                let source_url = child_arg_str(child, "source");
                validate_no_control_chars(&registry, "oci registry")?;
                validate_no_control_chars(&repository, "oci repository")?;
                if let Some(ref s) = source_url {
                    validate_no_control_chars(s, "oci source")?;
                }
                validate_no_leading_dash(&registry, "oci registry", "TNG-UNSAFE-OCI-FIELD")?;
                validate_no_leading_dash(&repository, "oci repository", "TNG-UNSAFE-OCI-FIELD")?;
                validate_oci_digest(&digest)?;
                provenances.push(Provenance::Oci {
                    registry,
                    repository,
                    digest,
                    source_url,
                });
            }
            // Unknown / missing kind: forward-compat skip.
            _ => {}
        }
    }
    let (attestation, diagnostics) = parse_entry_attestation(namespace, pkg_name, ver, node)?;

    // A2a (registry-protocol §3.2 "published_at" / "Yank triple"): parse-to-
    // typed, malformed -> None/default, never a hard error.
    let published_at_raw = child_arg_str(node, "published_at");
    let published_at = published_at_raw.as_deref().and_then(parse_iso8601_timestamp);
    let yanked = child_arg_bool(node, "yanked").unwrap_or(false);
    let yanked_at = child_arg_str(node, "yanked_at")
        .as_deref()
        .and_then(parse_iso8601_timestamp);
    let yanked_reason = child_arg_str(node, "yanked_reason");
    if let Some(ref reason) = yanked_reason {
        validate_no_control_chars(reason, "yanked_reason")?;
    }

    Ok((
        IndexVersion {
            version: ver.to_string(),
            content_hash,
            provenances,
            dep_decl,
            dep_decl_schema_version,
            attestation,
            // P3a: the enclosing Package's real namespace (always populated,
            // even for bare/unqualified index entries — namespace "" then).
            namespace: namespace.to_string(),
            published_at,
            yanked,
            yanked_at,
            yanked_reason,
            published_at_raw,
        },
        diagnostics,
    ))
}

/// Parse the `attestation`/`signed_by`/`rekor`/`bundle` sibling child nodes of
/// one `version` node into an `EntryAttestation` or `None` (registry-protocol
/// §3.2 NORMATIVE).
///
/// Conservative collapse: an unrecognized `attestation` kind, or
/// `"author-signed"` with no `signed_by`, collapses the WHOLE record to
/// `None` (unattested) with an observable diagnostic. A malformed `bundle`
/// pin is narrower — it collapses only the bundle pin to `None`, never the
/// enclosing kind/signer pairing (registry-protocol §3.2 NORMATIVE).
fn parse_entry_attestation(
    namespace: &str,
    pkg_name: &str,
    ver: &str,
    node: &KdlNode,
) -> Result<(Option<EntryAttestation>, Vec<String>), CoreError> {
    let coordinate = format!("pkg:tianguis/{namespace}/{pkg_name}@{ver}");
    let mut diagnostics: Vec<String> = Vec::new();

    let attestation_label = child_arg_str(node, "attestation");
    let rekor = parse_rekor_block(node)?;
    let (bundle_pin, bundle_diag) = parse_bundle_pin(node, &coordinate);

    let Some(label) = attestation_label else {
        // No attestation kind: a lone `rekor` block or malformed `bundle`
        // sibling (if any) does not construct an EntryAttestation — there is
        // no kind to tag it with (§3.2 NORMATIVE). The bundle-pin diagnostic
        // is therefore suppressed too (CR13/6): it would otherwise fire for a
        // lone malformed `bundle` sibling even though no EntryAttestation is
        // ever built in this shape — spurious noise, not a real collapse.
        return Ok((None, diagnostics));
    };

    diagnostics.extend(bundle_diag);

    let kind: AttestationKind = match label.as_str() {
        "author-signed" => {
            let signed_by = child_arg_str(node, "signed_by");
            match signed_by {
                Some(signer) if !signer.is_empty() => {
                    validate_no_control_chars(&signer, "signed_by")?;
                    AttestationKind::AuthorSigned { signer }
                }
                _ => {
                    diagnostics.push(format!(
                        "attestation claim for {coordinate} collapsed to unattested: \
                         \"author-signed\" with no signed_by (registry-protocol §3.2)"
                    ));
                    return Ok((None, diagnostics));
                }
            }
        }
        "milpa-vendored" => AttestationKind::MilpaVendored,
        other => {
            diagnostics.push(format!(
                "attestation claim for {coordinate} collapsed to unattested: \
                 unrecognized kind {other:?} (registry-protocol §3.2)"
            ));
            return Ok((None, diagnostics));
        }
    };

    Ok((
        Some(EntryAttestation {
            kind,
            rekor,
            bundle_pin,
        }),
        diagnostics,
    ))
}

/// Parse the optional `rekor { uuid; log_index; integrated_time }` block.
fn parse_rekor_block(node: &KdlNode) -> Result<Option<RekorRef>, CoreError> {
    for child in children(node) {
        if child.name().value() == "rekor" {
            let uuid = child_arg_str(child, "uuid").unwrap_or_default();
            let log_index = child_arg_str(child, "log_index").unwrap_or_default();
            let integrated_time = child_arg_str(child, "integrated_time").unwrap_or_default();
            validate_no_control_chars(&uuid, "rekor uuid")?;
            validate_no_control_chars(&log_index, "rekor log_index")?;
            validate_no_control_chars(&integrated_time, "rekor integrated_time")?;
            return Ok(Some(RekorRef {
                uuid,
                log_index,
                integrated_time,
            }));
        }
    }
    Ok(None)
}

/// Parse the optional `bundle sha256="<64-hex>"` delivery-integrity pin.
///
/// A malformed value normalizes to `None` with a diagnostic, WITHOUT
/// collapsing the enclosing kind/signer pairing (registry-protocol §3.2
/// NORMATIVE — an absent bundle pin is the ordinary, expected pre-delivery
/// state, not evidence of a malformed claim).
fn parse_bundle_pin(node: &KdlNode, coordinate: &str) -> (Option<String>, Vec<String>) {
    for child in children(node) {
        if child.name().value() != "bundle" {
            continue;
        }
        let Some(raw) = child_prop_str(child, "sha256") else {
            return (None, Vec::new());
        };
        if is_lower_hex(&raw, 64) {
            return (Some(raw), Vec::new());
        }
        return (
            None,
            vec![format!(
                "bundle pin for {coordinate} dropped: malformed sha256 value \
                 {raw:?} (registry-protocol §3.2)"
            )],
        );
    }
    (None, Vec::new())
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

/// Named property `key="…"` (not a positional arg) on `node`, as a string, or
/// `None` if absent / wrong type. Used for `bundle sha256="<64-hex>"`, whose
/// value is a KDL property rather than a positional argument.
fn child_prop_str(node: &KdlNode, key: &str) -> Option<String> {
    node.entries()
        .iter()
        .find(|e| e.name().map(|n| n.value()) == Some(key))
        .and_then(|e| e.value().as_string())
        .map(str::to_string)
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

/// First positional arg (boolean) of `node`'s child named `child_name`, or
/// `None` when the child is absent or its first arg is not a boolean
/// (registry-protocol §3.2 — `yanked`'s robustness posture: a malformed
/// value MUST NOT raise, it surfaces as absent).
fn child_arg_bool(node: &KdlNode, child_name: &str) -> Option<bool> {
    children(node)
        .into_iter()
        .find(|c| c.name().value() == child_name)
        .and_then(|child| {
            child
                .entries()
                .iter()
                .find(|e| e.name().is_none())
                .and_then(|e| e.value().as_bool())
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
