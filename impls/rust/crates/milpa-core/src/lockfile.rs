//! `milpa.lock` parsing (RFC §6 S5a).
//!
//! Reads the reproducible-build snapshot per `spec/lockfile-schema.md`,
//! mirroring the Python `lockfile.py` parse path. **Parse only** — canonical
//! serialization (the emit path) is S5b. The grammar is KDL 1.0, so this uses
//! `KdlDocument::parse_v1` (same decision as the manifest parser, S3: KDL 2.0's
//! `parse` decodes bare `true`/`false` as strings).
//!
//! Every `LOCK-*` slug this raises is enumerated in [`crate::error::CoreError::all_codes`]
//! and defined in `spec/errors.md`.

use kdl::{KdlDocument, KdlNode, KdlValue};
use milpa_manifest::{contains_unsafe_char, valid_flag_name, kdl_block_comment_depth, kdl_brace_depth, KDL_MAX_NESTING_DEPTH};
use milpa_solver::VersionSource;
use milpa_types::{
    format_iso8601_timestamp, parse_iso8601_timestamp, AttestationKind, FetchableOrigin,
    LockAttestation, LockedDep, Lockfile, ProvenanceRecord, RekorRef, ResolvedDep, ResolvedGraph,
    SourceId, Timestamp, LOCKFILE_SCHEMA_VERSION,
};

use crate::error::CoreError;
use crate::identity::parse_identity;

type LockResult<T> = Result<T, CoreError>;

fn err(code: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::Lockfile(code, message.into())
}

/// Parse `milpa.lock` text into a [`Lockfile`] (lockfile-schema §2–§4).
///
/// Mirrors `lockfile.py:parse_lockfile`: scan the top-level nodes, then validate
/// the schema version *after* the scan. S3 strict: both `version` and `strategy`
/// are required; missing `strategy` raises `LOCK-STRATEGY-MISSING`.
pub fn parse_lockfile(text: &str) -> LockResult<Lockfile> {
    // Depth guard — see milpa_manifest::KDL_MAX_NESTING_DEPTH for rationale.
    // Both brace depth and block-comment depth are checked (mirrors Python).
    if kdl_brace_depth(text) > KDL_MAX_NESTING_DEPTH {
        return Err(err(
            "LOCK-KDL-SYNTAX",
            format!("KDL input exceeds maximum nesting depth ({KDL_MAX_NESTING_DEPTH})"),
        ));
    }
    if kdl_block_comment_depth(text) > KDL_MAX_NESTING_DEPTH {
        return Err(err(
            "LOCK-KDL-SYNTAX",
            format!("KDL input exceeds maximum block-comment nesting depth ({KDL_MAX_NESTING_DEPTH})"),
        ));
    }
    let doc = KdlDocument::parse(text)
        .map_err(|e| err("LOCK-KDL-SYNTAX", format!("KDL syntax error: {e}")))?;

    let mut deps: Vec<LockedDep> = Vec::new();
    let mut strategy: Option<String> = None;
    let mut version: Option<u32> = None;
    let mut exclude_newer: Option<Timestamp> = None;

    for node in doc.nodes() {
        match node.name().value() {
            "version" => version = Some(scalar_u32(node, "version")?),
            "strategy" => {
                // Accept any well-formed single-string arg.
                let a = args(node);
                if let [entry] = a.as_slice() {
                    if let Some(s) = entry.value().as_string() {
                        strategy = Some(s.to_string());
                    }
                }
            }
            "exclude_newer" => exclude_newer = Some(scalar_timestamp(node, "exclude_newer")?),
            "dep" => deps.push(parse_dep(node)?),
            _ => {}
        }
    }

    let version = version.ok_or_else(|| {
        err(
            "LOCK-VERSION-MISSING",
            "lockfile missing required 'version' node",
        )
    })?;
    if version != LOCKFILE_SCHEMA_VERSION {
        return Err(err(
            "LOCK-VERSION-UNSUPPORTED",
            format!(
                "unsupported lockfile schema version {version} \
                 (this milpa understands version {LOCKFILE_SCHEMA_VERSION})"
            ),
        ));
    }
    let strategy = strategy.ok_or_else(|| {
        err(
            "LOCK-STRATEGY-MISSING",
            "lockfile missing required 'strategy' node; regenerate via 'milpa fetch'",
        )
    })?;

    Ok(Lockfile {
        version,
        strategy,
        exclude_newer,
        deps,
    })
}

/// D5 (resolution-semantics RFC §3 Axis D / §5): the OPTIONAL top-level
/// `exclude_newer "<ts>"` node. Unlike `strategy` (required), a present-but-
/// malformed node is a hard parse error (arity → `LOCK-FIELD-ARITY`, wrong
/// type or an unparseable ISO 8601 timestamp → `LOCK-FIELD-TYPE`) — mirrors
/// `scalar_u32`'s exact error-shape convention for a scalar top-level field.
fn scalar_timestamp(node: &KdlNode, field: &str) -> LockResult<Timestamp> {
    let a = args(node);
    let [entry] = a.as_slice() else {
        return Err(err(
            "LOCK-FIELD-ARITY",
            format!("{field:?} takes exactly one value"),
        ));
    };
    let raw = match entry.value().as_string() {
        Some(s) => s,
        None => {
            return Err(err(
                "LOCK-FIELD-TYPE",
                format!("{field:?} must be a string (got {})", entry.value()),
            ));
        }
    };
    parse_iso8601_timestamp(raw).ok_or_else(|| {
        err(
            "LOCK-FIELD-TYPE",
            format!("{field:?} value {raw:?} is not a valid ISO 8601 timestamp"),
        )
    })
}

/// A top-level integer scalar field (`version`). Wrong arity → `LOCK-FIELD-ARITY`;
/// a non-integer KDL value → `LOCK-FIELD-TYPE` (spec §2.1; a numeric *string* is
/// not an integer value, so it is a type error — Rust is the stricter, more
/// spec-conformant reading here).
fn scalar_u32(node: &KdlNode, field: &str) -> LockResult<u32> {
    let a = args(node);
    let [entry] = a.as_slice() else {
        return Err(err(
            "LOCK-FIELD-ARITY",
            format!("{field:?} takes exactly one value"),
        ));
    };
    let raw = match entry.value() {
        KdlValue::Integer(i) => *i,
        other => {
            return Err(err(
                "LOCK-FIELD-TYPE",
                format!("{field:?} must be an integer (got {other})"),
            ));
        }
    };
    u32::try_from(raw).map_err(|_| {
        err(
            "LOCK-FIELD-TYPE",
            format!("{field:?} is out of range (got {raw})"),
        )
    })
}

/// Parse one `dep "name" { … }` block (lockfile-schema §3).
fn parse_dep(node: &KdlNode) -> LockResult<LockedDep> {
    let name = dep_name(node)?;
    let mut namespace: Option<String> = None; // C1: qualified dep namespace (§3.9)
    let mut identity: Option<String> = None;
    let mut version = String::from("0.0.0");
    let mut src_dir = String::new();
    let mut requires: Vec<String> = Vec::new();
    let mut active_flags: Vec<String> = Vec::new();
    let mut dep_decl: Option<String> = None; // S6: additive dep_decl pin (§3.7)
    let mut cond_requires: Vec<milpa_types::CondRequire> = Vec::new(); // S4
    let mut aliases: Vec<String> = Vec::new(); // Phase B: alternate names
    let mut provenances: Vec<ProvenanceRecord> = Vec::new();
    let mut attestation: Option<LockAttestation> = None; // RFC per-entry-attestation.md P2 (§3.9)
    let mut declared_version_source: Option<String> = None; // A5: sibling source for `version`
    let mut source_id: Option<SourceId> = None; // S5: structured on-disk source-id (§4.1/§7)

    for child in children(node) {
        match child.name().value() {
            "namespace" => {
                // C1: parse the optional namespace child node (§3.9).
                // Form: `namespace "<ns>"` — exactly one string arg.
                // Security: validate charset at the lockfile parse boundary.
                // A poisoned milpa.lock with namespace "ns/../../x" would
                // escape _deps/ via dep_dir_name → "@ns/../../x/<name>".
                // Reuse valid_flag_name ([A-Za-z0-9_-]+), same predicate as
                // dep names and aliases (LOCK-DEP-NAME-INVALID).
                // Malformed (wrong arity / non-string) silently ignored.
                if let Some(ns_val) = args(child)
                    .first()
                    .and_then(|e| e.value().as_string().map(str::to_string))
                {
                    if !ns_val.is_empty() {
                        if !valid_flag_name(&ns_val) {
                            return Err(err(
                                "LOCK-DEP-NAME-INVALID",
                                format!(
                                    "dep {:?}: lockfile 'namespace' value {:?} \
                                     contains characters outside [A-Za-z0-9_-] — \
                                     rejected to prevent path traversal via a poisoned milpa.lock",
                                    name, ns_val
                                ),
                            ));
                        }
                        namespace = Some(ns_val);
                    }
                }
            }
            "identity" => {
                let val = scalar_str(child, &name, "identity")?;
                // Reuse the identity grammar validator (§3.1); any ID-* failure
                // surfaces as the lockfile-level LOCK-DEP-IDENTITY-INVALID, and
                // the validated multihash string is stored verbatim.
                parse_identity(&val).map_err(|e| {
                    err(
                        "LOCK-DEP-IDENTITY-INVALID",
                        format!("dep {name:?}: invalid identity — {}", e.message()),
                    )
                })?;
                identity = Some(val);
            }
            "version" => version = scalar_str(child, &name, "version")?,
            // A5: forward-compat lenient parse (mirrors the attestation
            // `kind` collapse convention, lockfile-schema §3.9) — an
            // unrecognized value or malformed arity silently collapses to
            // None rather than raising; no new error slug is warranted for
            // a purely additive/diagnostic field.
            "declared_version_source" => {
                declared_version_source = args(child)
                    .first()
                    .and_then(|e| e.value().as_string())
                    .and_then(|s| VersionSource::from_str_lenient(s))
                    .map(|s| s.as_str().to_string());
            }
            "src_dir" => {
                let s = scalar_str(child, &name, "src_dir")?;
                // Security: validate src_dir at the lockfile parse boundary.
                // A poisoned milpa.lock with unsafe chars in src_dir would flow
                // to nim.cfg --path: on frozen reconstruction.  Reuse SSOT
                // predicate (contains_unsafe_char from milpa-manifest); mirrors
                // Python lockfile.py.
                if !s.is_empty() && contains_unsafe_char(&s) {
                    return Err(err(
                        "LOCK-SRC-DIR-UNSAFE",
                        format!(
                            "dep {name:?}: lockfile 'src_dir' value contains a \
                             control character or line separator — rejected to \
                             prevent nim.cfg injection via a poisoned milpa.lock"
                        ),
                    ));
                }
                src_dir = s;
            }
            "requires" => requires = string_args(child),
            "aliases" => {
                let mut v = string_args(child);
                // R8-S1 security fix: validate each alias against dep-name charset.
                // Aliases reach the same filesystem and nim.cfg sinks as the primary name.
                for alias in &v {
                    if !valid_flag_name(alias) {
                        return Err(err(
                            "LOCK-DEP-NAME-INVALID",
                            format!(
                                "dep alias {:?} contains characters outside [A-Za-z0-9_-] — \
                                 rejected to prevent path traversal and nim.cfg injection via a \
                                 poisoned milpa.lock",
                                alias
                            ),
                        ));
                    }
                }
                v.sort();
                aliases = v;
            }
            "active_flags" => active_flags = string_args(child),
            // S3 purge: legacy `self_mirrors` nodes are silently ignored (§3.7).
            "self_mirrors" => {}
            // S6: dep_decl pin — forward-compat: silently skip absent/malformed.
            "dep_decl" => {
                dep_decl = args(child)
                    .first()
                    .and_then(|e| e.value().as_string().map(str::to_string));
            }
            // S4: cond-require annotation — lenient/forward-compat parse.
            "cond-require" => {
                if let Some(cr) = parse_cond_require(child) {
                    cond_requires.push(cr);
                }
            }
            // RFC origin-as-identity §4.1/§7 (S5): structured on-disk
            // source-id — field-by-field into the frozen SourceId struct,
            // never a flat-string parse.
            "source" => {
                source_id = Some(parse_source_block(child, &name)?);
            }
            "provenance" => provenances.push(parse_provenance(child, &name)?),
            // RFC per-entry-attestation.md P2 (lockfile-schema §3.9): the
            // per-entry attestation CLAIM block. Malformed → None + a
            // `[milpa] warning:` diagnostic (conservative collapse, mirrors
            // registry-protocol §3.2's posture applied here to the lockfile).
            "attestation" => {
                attestation = parse_lock_attestation(child, &name);
            }
            _ => {}
        }
    }

    Ok(LockedDep {
        name,
        namespace,
        identity,
        version,
        src_dir,
        requires,
        provenances,
        active_flags,
        dep_decl,
        cond_requires,
        aliases,
        attestation,
        declared_version_source,
        source_id,
    })
}

/// Kind labels recognized by a `source { … }` block's `kind` discriminator
/// (RFC origin-as-identity §4.1/§7, S5). Mirrors Python's
/// `lockfile._SOURCE_KIND_LABELS`.
const SOURCE_KIND_LABELS: &str = "git, oci, tarball, local, registry, member";

/// Parse a `source { kind "…"; … }` block into a typed `SourceId` (RFC
/// origin-as-identity §4.1/§7, S5). Mirrors Python's
/// `lockfile._parse_source_block` function-for-function.
///
/// Structural (arity/missing-field) errors raise `LOCK-SRC-*`; the parsed
/// RAW value is then passed through `source_id::normalize_source` (the sole
/// validation boundary), which raises `SRC-ID-MALFORMED` on a malformed
/// subpath / namespace / registry component.
fn parse_source_block(node: &KdlNode, dep_name: &str) -> LockResult<SourceId> {
    let mut fields: Vec<(&str, String)> = Vec::new();
    for child in children(node) {
        let a = args(child);
        let [entry] = a.as_slice() else {
            return Err(err(
                "LOCK-SRC-FIELD-ARITY",
                format!(
                    "dep {dep_name:?}: source field {:?} must have exactly one value",
                    child.name().value()
                ),
            ));
        };
        match entry.value().as_string() {
            Some(s) => fields.push((child.name().value(), s.to_string())),
            None => {
                return Err(err(
                    "LOCK-SRC-FIELD-ARITY",
                    format!(
                        "dep {dep_name:?}: source field {:?} must be a string",
                        child.name().value()
                    ),
                ));
            }
        }
    }

    let get = |key: &str| -> Option<String> {
        fields.iter().rev().find(|(k, _)| *k == key).map(|(_, v)| v.clone())
    };

    let kind = get("kind").ok_or_else(|| {
        err(
            "LOCK-SRC-KIND-MISSING",
            format!("dep {dep_name:?}: source block missing 'kind' discriminator"),
        )
    })?;

    let required = |key: &str| -> LockResult<String> {
        get(key).ok_or_else(|| {
            err(
                "LOCK-SRC-FIELD-MISSING",
                format!(
                    "dep {dep_name:?}: source block (kind={kind:?}) missing required field {key:?}"
                ),
            )
        })
    };

    let raw = match kind.as_str() {
        "git" => SourceId::Fetchable(FetchableOrigin::Git {
            url: required("url")?,
            subpath: get("subpath"),
        }),
        "oci" => SourceId::Fetchable(FetchableOrigin::Oci {
            registry: required("registry")?,
            repository: required("repository")?,
            subpath: get("subpath"),
        }),
        "tarball" => SourceId::Fetchable(FetchableOrigin::Tarball {
            url: required("url")?,
            subpath: get("subpath"),
        }),
        "local" => SourceId::Fetchable(FetchableOrigin::Local { path: required("path")? }),
        "registry" => SourceId::Fetchable(FetchableOrigin::Registry {
            registry: required("registry")?,
            namespace: get("namespace"),
            name: required("name")?,
        }),
        "member" => SourceId::Member { member_name: required("name")? },
        other => {
            return Err(err(
                "LOCK-SRC-KIND-UNKNOWN",
                format!(
                    "dep {dep_name:?}: unknown source kind {other:?} (known: {SOURCE_KIND_LABELS})"
                ),
            ));
        }
    };

    crate::source_id::normalize_source(&raw).map_err(|e| match e {
        crate::error::MilpaError::Core(c) => c,
        other => err("SRC-ID-MALFORMED", format!("{other:?}")),
    })
}

/// Parse the `attestation { kind; signer; rekor { … } }` block (§3.9).
///
/// Malformed input (unrecognized `kind`, or `"author-signed"` with no
/// `signer`) collapses to `None` with a diagnostic naming `dep_name` — the
/// same conservative-collapse posture registry-protocol.md §3.2 defines for
/// index parsing, applied here to a lockfile being read (lockfile-schema.md
/// §3.9 NORMATIVE).
fn parse_lock_attestation(node: &KdlNode, dep_name: &str) -> Option<LockAttestation> {
    let mut kind_label: Option<String> = None;
    let mut signer: Option<String> = None;
    let mut rekor: Option<RekorRef> = None;
    let mut bundle_pin: Option<String> = None;
    let mut namespace = String::new();

    for child in children(node) {
        match child.name().value() {
            "kind" => {
                kind_label = args(child)
                    .first()
                    .and_then(|e| e.value().as_string().map(str::to_string));
            }
            "signer" => {
                signer = args(child)
                    .first()
                    .and_then(|e| e.value().as_string().map(str::to_string));
            }
            "rekor" => {
                rekor = Some(parse_lock_rekor_block(child));
            }
            // P3a (lockfile-schema §3.9 addition): delivery-integrity pin.
            "bundle" => {
                bundle_pin = child
                    .entries()
                    .iter()
                    .find(|e| e.name().map(|n| n.value()) == Some("sha256"))
                    .and_then(|e| e.value().as_string())
                    .map(str::to_string);
            }
            // P3a: the entry's REAL index namespace — absent on P2-vintage
            // lockfiles (forward-compat: defaults to "").
            "namespace" => {
                namespace = args(child)
                    .first()
                    .and_then(|e| e.value().as_string().map(str::to_string))
                    .unwrap_or_default();
            }
            _ => {}
        }
    }

    match kind_label.as_deref() {
        Some("author-signed") => match signer {
            Some(s) if !s.is_empty() => Some(LockAttestation {
                kind: AttestationKind::AuthorSigned { signer: s },
                rekor,
                bundle_pin,
                namespace,
            }),
            _ => {
                eprintln!(
                    "[milpa] warning: dep {dep_name:?}: lockfile attestation block \
                     collapsed to absent — \"author-signed\" with no signer \
                     (lockfile-schema §3.9)"
                );
                None
            }
        },
        Some("milpa-vendored") => Some(LockAttestation {
            kind: AttestationKind::MilpaVendored,
            rekor,
            bundle_pin,
            namespace,
        }),
        other => {
            eprintln!(
                "[milpa] warning: dep {dep_name:?}: lockfile attestation block \
                 collapsed to absent — unrecognized kind {other:?} (lockfile-schema §3.9)"
            );
            None
        }
    }
}

/// Parse the nested `rekor { uuid; log_index; integrated_time }` block.
fn parse_lock_rekor_block(node: &KdlNode) -> RekorRef {
    let scalar = |name: &str| -> String {
        children(node)
            .into_iter()
            .find(|c| c.name().value() == name)
            .and_then(|c| args(c).first().and_then(|e| e.value().as_string().map(str::to_string)))
            .unwrap_or_default()
    };
    RekorRef {
        uuid: scalar("uuid"),
        log_index: scalar("log_index"),
        integrated_time: scalar("integrated_time"),
    }
}

/// Known predicate-name vocabulary (M1: whitelist for untrusted lockfile input).
///
/// On PARSE, any `cond-require` prop key that is NOT in this set is silently
/// dropped (forward-compat lenient — same spirit as "skip unknown child nodes").
/// This closes the injection path: a crafted key with spaces, control chars, or
/// ANSI sequences could otherwise round-trip into the lockfile or terminal.
/// Mirrors `lockfile.py:_KNOWN_PREDICATE_NAMES`.
const KNOWN_PREDICATE_NAMES: &[&str] = &["platform", "arch", "nim", "milpa", "flag"];

fn is_known_predicate(name: &str) -> bool {
    KNOWN_PREDICATE_NAMES.contains(&name)
}

/// Parse a `cond-require` child node into a [`milpa_types::CondRequire`] (RFC §3.4 / S4).
///
/// Inline form (props): `cond-require "name" platform="linux"`.
/// Block form (when children): `cond-require "name" { when platform="macosx" when ... }`.
/// Returns `None` (lenient/forward-compat) for malformed nodes.
///
/// M1: predicate prop keys are whitelist-validated against `KNOWN_PREDICATE_NAMES`
/// before being accepted — unknown keys are silently dropped.
fn parse_cond_require(node: &KdlNode) -> Option<milpa_types::CondRequire> {
    // arg0 = require name
    let name = args(node).first()?.value().as_string()?.to_string();
    let mut predicates: Vec<milpa_types::Predicate> = Vec::new();
    let child_nodes: Vec<&KdlNode> = node.children().map(|d| d.nodes()).into_iter().flatten().collect();

    if !child_nodes.is_empty() {
        // Block form: each child must be a "when" node with exactly one prop.
        for child in child_nodes {
            if child.name().value() != "when" {
                continue; // skip unknown children (forward compat)
            }
            for entry in child.entries() {
                let Some(key) = entry.name() else { continue };
                // M1: whitelist-validate the predicate name.
                if !is_known_predicate(key.value()) {
                    continue;
                }
                let Some(val) = entry.value().as_string() else { continue };
                let tag = entry.ty().map(|t| t.value());
                predicates.push(milpa_types::Predicate {
                    name: key.value().to_string(),
                    values: vec![val.to_string()],
                    negated: tag == Some("not"),
                });
            }
        }
    } else {
        // Inline form: props on the node itself.
        for entry in node.entries() {
            let Some(key) = entry.name() else { continue };
            // M1: whitelist-validate the predicate name.
            if !is_known_predicate(key.value()) {
                continue;
            }
            let Some(val) = entry.value().as_string() else { continue };
            let tag = entry.ty().map(|t| t.value());
            predicates.push(milpa_types::Predicate {
                name: key.value().to_string(),
                values: vec![val.to_string()],
                negated: tag == Some("not"),
            });
        }
    }

    if predicates.is_empty() {
        return None;
    }
    Some(milpa_types::CondRequire { name, predicates })
}

/// Parse a `provenance { kind "…" … }` block (lockfile-schema §4). Each child
/// node MUST carry exactly one value (`LOCK-PROV-FIELD-ARITY`); the `kind`
/// discriminator selects the record shape and which fields are required.
///
/// H5: `submodule "<path>" sha="<40hex>"` child nodes are collected separately
/// (1 positional arg + `sha=` property); they do NOT participate in the flat
/// one-value-per-field rule and are only meaningful for `kind "git"`.
fn parse_provenance(node: &KdlNode, dep_name: &str) -> LockResult<ProvenanceRecord> {
    // Collect each child's single value (last-wins, mirroring the Python dict).
    // H5: `submodule` nodes are collected separately.
    let mut fields: Vec<(&str, String)> = Vec::new();
    let mut submodule_shas: Vec<(String, String)> = Vec::new();
    for child in children(node) {
        if child.name().value() == "submodule" {
            // submodule "<path>" sha="<40hex>"
            // Structural validation: exactly one positional string arg (path) and
            // a `sha=` property with a string value are required.  Any deviation
            // raises LOCK-SUBMODULE-FIELD-INVALID (distinct from the scalar-field
            // arity code used by other provenance child nodes).
            let a = args(child);
            // Wrong arg count (not exactly 1) or non-string first arg.
            let sub_path = match a.as_slice() {
                [entry] => match entry.value().as_string() {
                    Some(s) => s.to_string(),
                    None => {
                        return Err(err(
                            "LOCK-SUBMODULE-FIELD-INVALID",
                            format!(
                                "dep {dep_name:?}: submodule path must be a string \
                                 (got a non-string value)"
                            ),
                        ));
                    }
                },
                _ => {
                    return Err(err(
                        "LOCK-SUBMODULE-FIELD-INVALID",
                        format!(
                            "dep {dep_name:?}: submodule node requires exactly one \
                             positional string argument (the path); got {}",
                            a.len()
                        ),
                    ));
                }
            };
            // Missing or non-string sha= property.
            let sub_sha = child
                .entries()
                .iter()
                .find(|e| e.name().map(|n| n.value()) == Some("sha"))
                .and_then(|e| e.value().as_string())
                .map(|s| s.to_string());
            let sub_sha = match sub_sha {
                Some(s) => s,
                None => {
                    return Err(err(
                        "LOCK-SUBMODULE-FIELD-INVALID",
                        format!(
                            "dep {dep_name:?}: submodule {:?} missing required \
                             sha= property (or sha= is not a string)",
                            sub_path
                        ),
                    ));
                }
            };
            submodule_shas.push((sub_path, sub_sha));
            continue;
        }
        let a = args(child);
        let [entry] = a.as_slice() else {
            return Err(err(
                "LOCK-PROV-FIELD-ARITY",
                format!(
                    "dep {dep_name:?}: provenance field {:?} must have exactly one value",
                    child.name().value()
                ),
            ));
        };
        // A non-string value is recorded as absent: `required` then reports
        // LOCK-PROV-FIELD-MISSING, matching the Python `_required_str` behavior.
        if let Some(s) = entry.value().as_string() {
            fields.push((child.name().value(), s.to_string()));
        }
    }
    // Ensure path-sorted order (matches lockfile-schema §4.1 normative order).
    submodule_shas.sort_by(|a, b| a.0.cmp(&b.0));

    let get = |key: &str| -> Option<String> {
        fields
            .iter()
            .rev()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone())
    };
    let required = |key: &str| -> LockResult<String> {
        get(key).ok_or_else(|| {
            err(
                "LOCK-PROV-FIELD-MISSING",
                format!("dep {dep_name:?}: provenance missing required field {key:?}"),
            )
        })
    };

    let kind = get("kind").ok_or_else(|| {
        err(
            "LOCK-PROV-KIND-MISSING",
            format!("dep {dep_name:?}: provenance block missing 'kind' discriminator"),
        )
    })?;

    // S3 strict: `origin` is required; raises LOCK-PROV-FIELD-MISSING when absent.
    let origin = required("origin")?;

    match kind.as_str() {
        "git" => Ok(ProvenanceRecord::Git {
            url: required("url")?,
            ref_spec: get("ref"),
            commit_sha: get("commit_sha"),
            origin,
            submodule_shas,
        }),
        "tarball" => Ok(ProvenanceRecord::Tarball {
            url: required("url")?,
            sha256: get("sha256"),
            origin,
        }),
        "local" => Ok(ProvenanceRecord::Local {
            path: required("path")?,
            origin,
        }),
        "member" => Ok(ProvenanceRecord::Member {
            name: required("name")?,
            origin,
        }),
        "oci" => Ok(ProvenanceRecord::Oci {
            registry: required("registry")?,
            repository: required("repository")?,
            digest: required("digest")?,
            origin,
        }),
        "root" => Ok(ProvenanceRecord::Root {
            name: required("name")?,
            origin,
        }),
        other => Err(err(
            "LOCK-PROV-KIND-UNKNOWN",
            format!(
                "dep {dep_name:?}: unknown provenance kind {other:?} \
                 (known: git, tarball, local, member, oci, root)"
            ),
        )),
    }
}

/// The single positional string name of a `dep` node (`LOCK-DEP-NAME-ARITY`).
///
/// After extracting the string, validates it against the dep-name charset
/// `[A-Za-z0-9_-]+` (SSOT: `valid_flag_name` in `milpa-manifest`).  A poisoned
/// lockfile with `dep "../evil"` (containing `/`) would otherwise flow to
/// `nim.cfg --path:` via string concat and to the filesystem via
/// `deps_dir / name`.  The charset predicate (not `contains_unsafe_char`) is
/// used because `/` and `.` are not control characters.
/// Mirrors the Python `lockfile.py::_require_dep_name` R8-S1 fix.
fn dep_name(node: &KdlNode) -> LockResult<String> {
    let a = args(node);
    let name = match a.as_slice() {
        [entry] => entry
            .value()
            .as_string()
            .map(str::to_string)
            .ok_or_else(|| {
                err(
                    "LOCK-DEP-NAME-ARITY",
                    "dep node requires exactly one string argument (the name)",
                )
            })?,
        _ => {
            return Err(err(
                "LOCK-DEP-NAME-ARITY",
                "dep node requires exactly one string argument (the name)",
            ))
        }
    };
    // R8-S1 security fix: validate dep name charset at the lockfile parse boundary.
    if !valid_flag_name(&name) {
        return Err(err(
            "LOCK-DEP-NAME-INVALID",
            format!(
                "dep name {:?} contains characters outside [A-Za-z0-9_-] — \
                 rejected to prevent path traversal and nim.cfg injection via a \
                 poisoned milpa.lock",
                name
            ),
        ));
    }
    Ok(name)
}

/// A dep-child scalar string field (`identity`/`version`/`src_dir`).
/// Wrong arity or non-string → `LOCK-DEP-FIELD-ARITY`.
fn scalar_str(node: &KdlNode, dep_name: &str, field: &str) -> LockResult<String> {
    let a = args(node);
    match a.as_slice() {
        [entry] => entry
            .value()
            .as_string()
            .map(str::to_string)
            .ok_or_else(|| {
                err(
                    "LOCK-DEP-FIELD-ARITY",
                    format!("dep {dep_name:?} field {field:?} must have exactly one string value"),
                )
            }),
        _ => Err(err(
            "LOCK-DEP-FIELD-ARITY",
            format!("dep {dep_name:?} field {field:?} must have exactly one string value"),
        )),
    }
}

/// Positional string arguments of a node, in source order (non-string args are
/// skipped — matches the Python `tuple(a for a in args if isinstance(a, str))`).
/// `self_mirrors` may be `(url)`-annotated; the annotation is metadata on the
/// value, so `as_string()` still yields the plain URL (spec §3.6).
fn string_args(node: &KdlNode) -> Vec<String> {
    args(node)
        .iter()
        .filter_map(|e| e.value().as_string().map(str::to_string))
        .collect()
}

/// Read and parse a lockfile from disk (mirrors `lockfile.py:load_lockfile`).
/// A missing path → `LOCK-FILE-NOT-FOUND`; any other OS read error →
/// `LOCK-FILE-UNREADABLE`. These two codes are not fixture-expressible (you
/// cannot commit a missing/unreadable file to the corpus), so they are covered
/// by unit tests only.
pub fn load_lockfile(path: &std::path::Path) -> LockResult<Lockfile> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            err(
                "LOCK-FILE-NOT-FOUND",
                format!("lockfile not found: {}", path.display()),
            )
        } else {
            err(
                "LOCK-FILE-UNREADABLE",
                format!("cannot read lockfile {}: {e}", path.display()),
            )
        }
    })?;
    parse_lockfile(&text)
}

// ---------------------------------------------------------------------------
// Formatter (RFC §6 S5b) — canonical byte-exact serialization.
//
// Mirrors `lockfile.py:format_lockfile` / `_format_provenance_fields` /
// `_kdl_str`. The output is byte-identical to the Python oracle per
// lockfile-schema §2.4: the always-on header, `version`/`strategy`, a blank
// line, then each dep block (fields in fixed order, optional fields omitted
// when absent), with a single trailing `\n`. Deps and `requires` are NOT sorted
// here — that canonicalization lives in `from_graph` (the ResolvedGraph→Lockfile
// bridge, deferred to S6/S7 since it needs `Version`→semver formatting); a
// `Lockfile` reaches the formatter already in canonical order, so emit is a pure
// structural rendering and a parse→format→parse round-trip is the identity.
// ---------------------------------------------------------------------------

/// The always-emitted first line (lockfile-schema §2.4 / §7.4). SSOT for the
/// header so parse and emit cannot drift.
const HEADER: &str = "// generated by milpa; reproducible build snapshot";

/// D-provenance sort key: `(origin_rank, kind_rank, primary, secondary)`.
///
/// Mirrors `lockfile.py:_provenance_sort_key` exactly for zero cross-impl
/// divergence.  `primary` and `secondary` are computed over the KDL-escaped
/// string form (via `kdl_str`) so sort order matches emission order.
///
/// origin_rank: "declared"→0, "observed"→1, unknown→99.
/// kind_rank:   "git"→0, "tarball"→1, "oci"→2, "local"→3, "member"→4,
///              "root"→5, unknown→99.
fn provenance_sort_key(p: &ProvenanceRecord) -> (u8, u8, String, String) {
    let origin_rank = match p.origin() {
        "declared" => 0u8,
        "observed" => 1u8,
        _ => 99u8,
    };
    let kind_rank = match p {
        ProvenanceRecord::Git { .. } => 0u8,
        ProvenanceRecord::Tarball { .. } => 1u8,
        ProvenanceRecord::Oci { .. } => 2u8,
        ProvenanceRecord::Local { .. } => 3u8,
        ProvenanceRecord::Member { .. } => 4u8,
        ProvenanceRecord::Root { .. } => 5u8,
    };
    let (primary, secondary) = match p {
        ProvenanceRecord::Git { url, ref_spec, .. } => (
            kdl_str(url),
            ref_spec.as_deref().map(kdl_str).unwrap_or_default(),
        ),
        ProvenanceRecord::Tarball { url, .. } => (kdl_str(url), String::new()),
        ProvenanceRecord::Oci { registry, repository, digest, .. } => (
            kdl_str(&format!("{registry}/{repository}")),
            kdl_str(digest),
        ),
        ProvenanceRecord::Local { path, .. } => (kdl_str(path), String::new()),
        ProvenanceRecord::Member { name, .. } => (kdl_str(name), String::new()),
        ProvenanceRecord::Root { name, .. } => (kdl_str(name), String::new()),
    };
    (origin_rank, kind_rank, primary, secondary)
}

/// Render a [`Lockfile`] to canonical KDL text (lockfile-schema §2.4).
/// Byte-identical to `lockfile.py:format_lockfile` for the same data.
pub fn format_lockfile(lockfile: &Lockfile) -> String {
    let mut lines: Vec<String> = vec![
        HEADER.to_string(),
        format!("version {}", lockfile.version),
        format!("strategy {}", kdl_str(&lockfile.strategy)),
    ];
    // D5 (resolution-semantics RFC §3 Axis D / §5): optional top-level
    // `exclude_newer` node — emitted only when the effective time-bound was
    // set (never a sentinel), positioned right after `strategy` and before
    // the blank line separating the header from the dep blocks.
    if let Some(ts) = &lockfile.exclude_newer {
        lines.push(format!("exclude_newer {}", kdl_str(&format_iso8601_timestamp(ts))));
    }
    lines.push(String::new());
    for dep in &lockfile.deps {
        lines.push(format!("dep {} {{", kdl_str(&dep.name)));
        // C1: emit namespace child FIRST (before identity) to match Python's
        // emission order (lockfile-schema §3.9 / fixture-311/314).
        if let Some(ns) = &dep.namespace {
            lines.push(format!("    namespace {}", kdl_str(ns)));
        }
        // RFC origin-as-identity §4.1/§7 (S5): the structured on-disk
        // SourceId, typed children (uv's model). Positioned right after
        // namespace, before identity. Omitted only for a lockfile predating
        // S5 (forward-compat; a conformant S5+ emitter always writes it).
        if let Some(sid) = &dep.source_id {
            lines.push("    source {".to_string());
            for field in format_source_fields(sid) {
                lines.push(format!("        {field}"));
            }
            lines.push("    }".to_string());
        }
        if let Some(identity) = &dep.identity {
            lines.push(format!("    identity {}", kdl_str(identity)));
        }
        lines.push(format!("    version {}", kdl_str(&dep.version)));
        // A5: declared_version_source — the sibling field to version, emitted
        // only when a source exists (a version-unknown dep's "0.0.0" carries
        // no source at all, §5 NORMATIVE — the unambiguous boundary pairing).
        if let Some(src) = &dep.declared_version_source {
            lines.push(format!("    declared_version_source {}", kdl_str(src)));
        }
        lines.push(format!("    src_dir {}", kdl_str(&dep.src_dir)));
        if dep.requires.is_empty() {
            lines.push("    requires".to_string());
        } else {
            lines.push(format!("    requires {}", join_kdl(&dep.requires)));
        }
        // S4: cond-require — additive annotation nodes, sorted by name.
        // Emitted immediately after requires. Omitted when empty (byte-identical
        // for deps with no conditional requires).
        // C1 fix: sort by (name, predicate-string) for a total order — same-name
        // entries (dep in ≥2 when-branches) are deterministically ordered by their
        // canonical predicate string, giving byte-identical output across impls.
        let mut sorted_cond: Vec<&milpa_types::CondRequire> = dep.cond_requires.iter().collect();
        sorted_cond.sort_by_key(|cr| cond_require_sort_key(cr));
        for cr in sorted_cond {
            for line in format_cond_require(cr) {
                lines.push(line);
            }
        }
        // Phase B: aliases — alternate dep names for deduped deps (§3.8).
        // Omitted when empty; args are lex-sorted by convention.
        if !dep.aliases.is_empty() {
            let mut sorted_aliases = dep.aliases.clone();
            sorted_aliases.sort();
            lines.push(format!("    aliases {}", join_kdl(&sorted_aliases)));
        }
        if !dep.active_flags.is_empty() {
            lines.push(format!("    active_flags {}", join_kdl(&dep.active_flags)));
        }
        // RFC per-entry-attestation.md P2 (lockfile-schema §3.9): the per-entry
        // Layer 2 claim. Positioned after active_flags, before dep_decl/
        // provenance blocks (lockfile-schema §2.4).
        if let Some(att) = &dep.attestation {
            for line in format_lock_attestation(att) {
                lines.push(line);
            }
        }
        // S6: emit dep_decl pin before provenance (§3.7).
        if let Some(dd) = &dep.dep_decl {
            lines.push(format!("    dep_decl {}", kdl_str(dd)));
        }
        // D-provenance: sort provenances by (origin_rank, kind_rank, primary, secondary)
        // before emitting — deterministic output per lockfile-schema §4.0.
        let mut sorted_provs: Vec<&ProvenanceRecord> = dep.provenances.iter().collect();
        sorted_provs.sort_by_key(|p| provenance_sort_key(p));
        for prov in sorted_provs {
            lines.push("    provenance {".to_string());
            for field in format_provenance_fields(prov) {
                lines.push(format!("        {field}"));
            }
            lines.push("    }".to_string());
        }
        lines.push("}".to_string());
        lines.push(String::new());
    }
    lines.join("\n")
}

/// Emit the `attestation { kind; signer; rekor { … } }` block (§3.9).
///
/// `signer` is emitted only for `AuthorSigned` (absent for `MilpaVendored` —
/// mirrors the source index record's structural invariant). The nested
/// `rekor` block is omitted entirely when the source index entry carried none.
fn format_lock_attestation(att: &LockAttestation) -> Vec<String> {
    let mut out = vec!["    attestation {".to_string()];
    match &att.kind {
        AttestationKind::AuthorSigned { signer } => {
            out.push(format!("        kind {}", kdl_str("author-signed")));
            out.push(format!("        signer {}", kdl_str(signer)));
        }
        AttestationKind::MilpaVendored => {
            out.push(format!("        kind {}", kdl_str("milpa-vendored")));
        }
    }
    if let Some(rekor) = &att.rekor {
        out.push("        rekor {".to_string());
        out.push(format!("            uuid {}", kdl_str(&rekor.uuid)));
        out.push(format!("            log_index {}", kdl_str(&rekor.log_index)));
        out.push(format!(
            "            integrated_time {}",
            kdl_str(&rekor.integrated_time)
        ));
        out.push("        }".to_string());
    }
    if let Some(pin) = &att.bundle_pin {
        // P3a: delivery-integrity pin (lockfile-schema §3.9 P3a addition).
        out.push(format!("        bundle sha256={}", kdl_str(pin)));
    }
    // P3a: the entry's REAL index namespace — always emitted (mandatory,
    // like `kind`), even when empty (an unqualified index entry legitimately
    // has namespace ""); needed by `milpa verify`'s offline re-verification
    // (§7) to rebuild the exact subject coordinate with no index available.
    out.push(format!("        namespace {}", kdl_str(&att.namespace)));
    out.push("    }".to_string());
    out
}

/// Total sort key for a `CondRequire`: `(name, canonical-predicate-string)`.
///
/// Using name alone is NOT a total order when same-name entries exist (a dep
/// in ≥2 when-branches).  The predicate string makes the key total and
/// deterministic across impls regardless of source order (C1 fix, §2.4).
///
/// Delegates to `format_predicate_prop` so KDL string escaping is shared with
/// the emitter — sort order cannot drift from emission order even if a value
/// ever contains `"` or `\`.  `pub(crate)` so `resolver.rs` can reuse the
/// same SSOT instead of reimplementing (C1 fix).
pub(crate) fn cond_require_sort_key(cr: &milpa_types::CondRequire) -> (String, String) {
    let pred_str = cr
        .predicates
        .iter()
        .map(|p| format_predicate_prop(p))
        .collect::<Vec<_>>()
        .join(",");
    (cr.name.clone(), pred_str)
}

/// Emit a single predicate as `key="value"` or `key=(not)"value"` (RFC §3.4.1).
///
/// The value is `pred.values[0]` — every predicate produced by this pipeline is
/// single-value (v0 invariant per spec §3.5 / lockfile-schema §3.5). Multi-value
/// (OR) predicates are not supported in v0; the guard below panics on violation
/// so it surfaces early rather than silently truncating values[1:] (M4 fix).
/// Negation uses the KDL type-annotation form `(not)"value"` — verbatim from
/// `manifest-grammar.md §6`.
fn format_predicate_prop(pred: &milpa_types::Predicate) -> String {
    if pred.values.len() != 1 {
        panic!(
            "format_predicate_prop: predicate {:?} has {} values but only single-value \
             predicates are supported in v0 (spec §3.5). Multi-value (OR) emission is not \
             implemented.",
            pred.name,
            pred.values.len()
        );
    }
    let val = kdl_str(&pred.values[0]);
    if pred.negated {
        format!("{}=(not){}", pred.name, val)
    } else {
        format!("{}={}", pred.name, val)
    }
}

/// Emit a `cond-require` node (RFC §3.4.1).
///
/// Single predicate → inline property form:
///     `    cond-require "name" key="value"`
///
/// Multiple predicates (AND) → block form:
///     `    cond-require "name" {`
///     `        when key="value"`
///     `        ...`
///     `    }`
fn format_cond_require(cr: &milpa_types::CondRequire) -> Vec<String> {
    let name_str = kdl_str(&cr.name);
    if cr.predicates.len() == 1 {
        let prop = format_predicate_prop(&cr.predicates[0]);
        vec![format!("    cond-require {name_str} {prop}")]
    } else {
        let mut out = vec![format!("    cond-require {name_str} {{")];
        for pred in &cr.predicates {
            let prop = format_predicate_prop(pred);
            out.push(format!("        when {prop}"));
        }
        out.push("    }".to_string());
        out
    }
}

/// Emit `kind` + kind-specific typed children for a `source { … }` block
/// (RFC origin-as-identity §4.1/§7, S5 — NORMATIVE, both impls MUST match
/// byte-for-byte). Mirrors Python's `_format_source_fields`.
///
/// Field order per kind: git/tarball = kind/url/subpath?; oci =
/// kind/registry/repository/subpath?; local = kind/path; registry =
/// kind/registry/namespace?/name; member = kind/name.
///
/// URL-bearing fields carry the `(url)` KDL type annotation
/// ([[kdl_url_convention]]); the parser reads the string content regardless
/// of tag.
fn format_source_fields(sid: &SourceId) -> Vec<String> {
    match sid {
        SourceId::Fetchable(FetchableOrigin::Git { url, subpath }) => {
            let mut out = vec![format!("kind {}", kdl_str("git")), format!("url (url){}", kdl_str(url))];
            if let Some(sp) = subpath {
                out.push(format!("subpath {}", kdl_str(sp)));
            }
            out
        }
        SourceId::Fetchable(FetchableOrigin::Oci { registry, repository, subpath }) => {
            let mut out = vec![
                format!("kind {}", kdl_str("oci")),
                format!("registry {}", kdl_str(registry)),
                format!("repository {}", kdl_str(repository)),
            ];
            if let Some(sp) = subpath {
                out.push(format!("subpath {}", kdl_str(sp)));
            }
            out
        }
        SourceId::Fetchable(FetchableOrigin::Tarball { url, subpath }) => {
            let mut out = vec![format!("kind {}", kdl_str("tarball")), format!("url (url){}", kdl_str(url))];
            if let Some(sp) = subpath {
                out.push(format!("subpath {}", kdl_str(sp)));
            }
            out
        }
        SourceId::Fetchable(FetchableOrigin::Local { path }) => {
            vec![format!("kind {}", kdl_str("local")), format!("path {}", kdl_str(path))]
        }
        SourceId::Fetchable(FetchableOrigin::Registry { registry, namespace, name }) => {
            let mut out = vec![format!("kind {}", kdl_str("registry")), format!("registry {}", kdl_str(registry))];
            if let Some(ns) = namespace {
                out.push(format!("namespace {}", kdl_str(ns)));
            }
            out.push(format!("name {}", kdl_str(name)));
            out
        }
        SourceId::Member { member_name } => {
            vec![format!("kind {}", kdl_str("member")), format!("name {}", kdl_str(member_name))]
        }
    }
}

/// The `kind` discriminator + kind-specific fields for one provenance block,
/// in canonical field order (lockfile-schema §4). Optional fields omitted when
/// `None`. Mirrors `_format_provenance_fields`.
fn format_provenance_fields(p: &ProvenanceRecord) -> Vec<String> {
    let mut out = Vec::new();
    match p {
        ProvenanceRecord::Git {
            url,
            ref_spec,
            commit_sha,
            origin,
            submodule_shas,
        } => {
            out.push(format!("origin {}", kdl_str(origin)));
            out.push(format!("kind {}", kdl_str("git")));
            out.push(format!("url {}", kdl_str(url)));
            if let Some(r) = ref_spec {
                out.push(format!("ref {}", kdl_str(r)));
            }
            if let Some(c) = commit_sha {
                out.push(format!("commit_sha {}", kdl_str(c)));
            }
            // H5: emit submodule nodes path-sorted (lockfile-schema §4.1).
            for (sub_path, sub_sha) in submodule_shas {
                out.push(format!(
                    "submodule {} sha={}",
                    kdl_str(sub_path),
                    kdl_str(sub_sha)
                ));
            }
        }
        ProvenanceRecord::Tarball { url, sha256, origin } => {
            out.push(format!("origin {}", kdl_str(origin)));
            out.push(format!("kind {}", kdl_str("tarball")));
            out.push(format!("url {}", kdl_str(url)));
            if let Some(s) = sha256 {
                out.push(format!("sha256 {}", kdl_str(s)));
            }
        }
        ProvenanceRecord::Local { path, origin } => {
            out.push(format!("origin {}", kdl_str(origin)));
            out.push(format!("kind {}", kdl_str("local")));
            out.push(format!("path {}", kdl_str(path)));
        }
        ProvenanceRecord::Member { name, origin } => {
            out.push(format!("origin {}", kdl_str(origin)));
            out.push(format!("kind {}", kdl_str("member")));
            out.push(format!("name {}", kdl_str(name)));
        }
        ProvenanceRecord::Oci {
            registry,
            repository,
            digest,
            origin,
        } => {
            out.push(format!("origin {}", kdl_str(origin)));
            out.push(format!("kind {}", kdl_str("oci")));
            out.push(format!("registry {}", kdl_str(registry)));
            out.push(format!("repository {}", kdl_str(repository)));
            out.push(format!("digest {}", kdl_str(digest)));
        }
        ProvenanceRecord::Root { name, origin } => {
            out.push(format!("origin {}", kdl_str(origin)));
            out.push(format!("kind {}", kdl_str("root")));
            out.push(format!("name {}", kdl_str(name)));
        }
    }
    out
}

/// Join string values as space-separated KDL string literals.
fn join_kdl(values: &[String]) -> String {
    values
        .iter()
        .map(|v| kdl_str(v))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Return `s` as a double-quoted, KDL-escaped string literal (R11,
/// lockfile-schema §7 / errors.md). The single source of truth for emitting a
/// KDL string value — the parser unescapes on read, so the writer MUST escape
/// on write or the round-trip breaks.
///
/// Mirrors `lockfile.py:_kdl_str` exactly:
///   `\\` → `\\\\`, `"` → `\\"`, U+0000–U+001F → `\u{N}` (hex, no named
///   escapes). All other code points are emitted verbatim. No named escapes
///   (`\n`, `\t`, `\r`, `\b`, `\f`) — using `\u{..}` for ALL control chars
///   keeps the Python and Rust outputs byte-identical (lockfile-schema §2.4).
fn kdl_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Write canonical lockfile KDL to `path` atomically, creating parent dirs.
/// Returns the path on success.
///
/// Atomic discipline: format the content, write to a sibling temp file in the
/// same directory as `path` (named `<stem>.tmp.<pid>`), then
/// `std::fs::rename(tmp, path)` — a POSIX atomic rename.  The temp file lives
/// in the target's parent so the rename is always same-filesystem; EXDEV
/// (cross-device rename failure) is structurally impossible.  If formatting
/// or the write raises, the temp file is removed before the error propagates —
/// no temp files are ever left behind.
///
/// Filesystem I/O failures are uncoded in the spec (Python propagates the raw
/// `OSError`), so they surface as the non-catalog `MILPA-INTERNAL-IO`
/// sentinel — kept OUT of `all_codes()`, consistent with the identity/CAS I/O
/// treatment (S4).
pub fn write_lockfile(
    lockfile: &Lockfile,
    path: &std::path::Path,
) -> LockResult<std::path::PathBuf> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                err(
                    crate::identity::INTERNAL_IO,
                    format!("cannot create lockfile parent {}: {e}", parent.display()),
                )
            })?;
        }
    }

    // Build a unique temp path in the same directory as the target so that
    // std::fs::rename is always same-filesystem (EXDEV structurally impossible).
    let tmp = {
        let stem = path
            .file_name()
            .map(|n| format!("{}.tmp.{}", n.to_string_lossy(), std::process::id()))
            .unwrap_or_else(|| format!("milpa.lock.tmp.{}", std::process::id()));
        match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.join(&stem),
            _ => std::path::PathBuf::from(&stem),
        }
    };

    let content = format_lockfile(lockfile);
    let write_result = std::fs::write(&tmp, &content);
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(err(
            crate::identity::INTERNAL_IO,
            format!("cannot write lockfile temp {}: {e}", tmp.display()),
        ));
    }

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err(
            crate::identity::INTERNAL_IO,
            format!(
                "cannot rename lockfile temp {} -> {}: {e}",
                tmp.display(),
                path.display()
            ),
        ));
    }

    Ok(path.to_path_buf())
}

// ---------------------------------------------------------------------------
// from_graph — bridge ResolvedGraph → canonical Lockfile (S7c emission glue)
// ---------------------------------------------------------------------------

/// Convert a resolved graph into a canonical [`Lockfile`].
///
/// Mirrors `lockfile.py:from_graph` / `_locked_from_resolved` /
/// `_provenance_from_resolved`. Deps are sorted by name and each dep's
/// `requires` lexicographically (resolver-semantics §4.4 / lockfile-schema
/// §3.4): the resolver accumulates both in topological / BFS-arrival order,
/// which is not a stable cross-implementation key, so the lockfile imposes the
/// single canonical ordering here — the same graph always renders byte-identical
/// text. `strategy` records which resolution strategy produced this lockfile.
///
/// The four transport [`Provenance`] kinds map onto their [`ProvenanceRecord`]
/// counterparts. The `Member` and `Registry` records have **no** transport
/// `Provenance` source — they are produced only by the workspace resolve (S11)
/// and the legacy read path, never from a resolved graph, so they cannot arise
/// here.
/// `exclude_newer` (D5, resolution-semantics RFC §3 Axis D / §5): the
/// EFFECTIVE time-bound this resolve ran under, recorded verbatim into the
/// lockfile's top-level `exclude_newer` node (`None` ⇒ the node is omitted
/// entirely by `format_lockfile` — never a sentinel timestamp).
pub fn from_graph(
    graph: &ResolvedGraph,
    strategy: &str,
    exclude_newer: Option<Timestamp>,
) -> Lockfile {
    let mut deps: Vec<LockedDep> = graph.deps.iter().map(locked_from_resolved).collect();
    // C1: sort by (namespace, name) so two qualified deps with the same bare name
    // (e.g. ns1::bar and ns2::bar) land in a stable, deterministic order.
    // Mirrors Python `key=lambda d: (d.namespace or "", d.name)`.
    deps.sort_by(|a, b| {
        let a_ns = a.namespace.as_deref().unwrap_or("");
        let b_ns = b.namespace.as_deref().unwrap_or("");
        a_ns.cmp(b_ns).then(a.name.cmp(&b.name))
    });
    Lockfile {
        version: LOCKFILE_SCHEMA_VERSION,
        strategy: strategy.to_string(),
        exclude_newer,
        deps,
    }
}

/// A dep shape carrying `name`/`aliases`/`provenances` — implemented by both
/// [`ResolvedDep`] (in-memory) and [`LockedDep`] (on-disk) so
/// `format_dep_origin`/`collapse_notes` read identically from either.
///
/// RFC origin-as-identity.md §4.7/B3 (S3a-req): when the slot projection
/// collapses two declared labels reaching one origin into a single canonical
/// dep, dropping the non-canonical label MUST be visible, never silent
/// ("the collapse is visible, never a silent disappearance"). Mirrors the
/// Python `format_dep_origin`/`collapse_notes` (which duck-type on the same
/// two fields) — single source of truth for both `resolve()`'s post-build
/// stderr trace and `milpa show`, so the note text never drifts between them.
pub trait AliasedDep {
    fn dep_name(&self) -> &str;
    fn dep_aliases(&self) -> &[String];
    fn dep_provenances(&self) -> &[ProvenanceRecord];
}

impl AliasedDep for ResolvedDep {
    fn dep_name(&self) -> &str {
        &self.name
    }
    fn dep_aliases(&self) -> &[String] {
        &self.aliases
    }
    fn dep_provenances(&self) -> &[ProvenanceRecord] {
        &self.provenances
    }
}

impl AliasedDep for LockedDep {
    fn dep_name(&self) -> &str {
        &self.name
    }
    fn dep_aliases(&self) -> &[String] {
        &self.aliases
    }
    fn dep_provenances(&self) -> &[ProvenanceRecord] {
        &self.provenances
    }
}

/// Human-readable origin string for *dep* — `git+<url>`, `tar+<url>`,
/// `oci+<registry>/<repository>`, `file+<path>`, `member+<name>`, or
/// `root+<name>`.
///
/// Deliberately mirrors `source_id`'s canonical wire-format prefixes
/// (RFC origin-as-identity.md §4.1) WITHOUT depending on `source_id` — it is
/// derived from the dep's own OBSERVED `ProvenanceRecord` (falling back to
/// the first record, or the dep's own name when there are none) so it reads
/// identically whether called on an in-memory `ResolvedDep` (which also
/// carries a `source_id`, not yet threaded to disk — that is a later slice)
/// or an on-disk `LockedDep` reconstructed by `milpa show`.
pub fn format_dep_origin<D: AliasedDep>(dep: &D) -> String {
    let provenances = dep.dep_provenances();
    let observed = provenances
        .iter()
        .find(|p| p.origin() == "observed")
        .or_else(|| provenances.first());
    match observed {
        None => dep.dep_name().to_string(),
        Some(ProvenanceRecord::Git { url, .. }) => format!("git+{url}"),
        Some(ProvenanceRecord::Tarball { url, .. }) => format!("tar+{url}"),
        Some(ProvenanceRecord::Oci {
            registry,
            repository,
            ..
        }) => format!("oci+{registry}/{repository}"),
        Some(ProvenanceRecord::Local { path, .. }) => format!("file+{path}"),
        Some(ProvenanceRecord::Member { name, .. }) => format!("member+{name}"),
        Some(ProvenanceRecord::Root { name, .. }) => format!("root+{name}"),
    }
}

/// One low-severity note per alias the §4.7 slot projection dropped.
///
/// E.g. `"'z3lib' and 'nimz3' both name git+https://…nim-z3; used 'nimz3'"`
/// — the exact shape RFC origin-as-identity.md §4.7 specifies. Empty for a
/// dep with no aliases. Notes are emitted in (canonical dep name, alias)
/// lexicographic order — deterministic regardless of BFS/dict ordering.
pub fn collapse_notes<D: AliasedDep>(deps: &[D]) -> Vec<String> {
    let mut order: Vec<&D> = deps.iter().collect();
    order.sort_by(|a, b| a.dep_name().cmp(b.dep_name()));
    let mut notes = Vec::new();
    for dep in order {
        if dep.dep_aliases().is_empty() {
            continue;
        }
        let origin = format_dep_origin(dep);
        let mut aliases: Vec<&String> = dep.dep_aliases().iter().collect();
        aliases.sort();
        for alias in aliases {
            notes.push(format!(
                "'{alias}' and '{}' both name {origin}; used '{}'",
                dep.dep_name(),
                dep.dep_name()
            ));
        }
    }
    notes
}

/// The single diagnostic label for `dep`'s origin — mirrors Python's
/// `_dep_origin_label` (used by [`check_directory_slot_collisions`], below).
///
/// Prefers `format_source_id` (`source_id.rs`, the SAME formatter
/// `RES-BINDING-CONFLICT`/`FROZEN-SOURCE-ID-MISMATCH` reuse) when
/// `dep.source_id` is populated (every fresh `resolve()`/`resolve_workspace()`
/// dep, S3a+). Falls back to the provenance-derived `format_dep_origin`
/// (above) when it is not — the frozen/verify reconstruction path
/// (`frozen.rs`), whose `ResolvedDep` has no `source_id` until a later slice
/// threads the lockfile's structured source node onto it.
pub(crate) fn dep_origin_label(dep: &ResolvedDep) -> String {
    match &dep.source_id {
        Some(sid) => crate::source_id::format_source_id(sid),
        None => format_dep_origin(dep),
    }
}

/// The v1 **directory-slot** floor of the import-slot check
/// (`rfc-origin-as-identity.md` §4.6, S6) — `RES-IMPORT-COLLISION`.
/// Mirrors Python's `lockfile.check_directory_slot_collisions`
/// function-for-function (§9 cross-impl discipline).
///
/// A plain function, no port: two distinct origins that would materialize
/// into the identical `_deps/<slot>/` directory (`dep_dir_name(name,
/// namespace)` — the SAME SSOT `rebuild_deps_view` uses to lay out
/// `_deps/`) cannot coexist, because the second write would silently clobber
/// the first. The complete, symbol-level check (comparing actual exported
/// Nim module paths behind a `SymbolProviderPort`) is a later slice ("S7")
/// — this floor is retained afterward as its cheap directory-level
/// pre-filter, never deleted (§4.6 round-2 fix — G9).
///
/// **The `content_hash` short-circuit (§4.6, CRITICAL):** two origins that
/// project to the same slot but fetch **byte-identical** trees are the exact
/// same-bytes/different-origin case §3.3 celebrates as milpa's edge over
/// Cargo (already realized post-solve by the S4b dedup pass, which folds any
/// such pair into one canonical dep + alias before this function ever runs)
/// — they cannot produce a Nim symbol conflict and MUST NOT raise. This
/// function re-asserts that invariant directly, rather than trusting the
/// caller never to invoke it on data the dedup pass hasn't deduped (e.g. a
/// hand-edited or future-corrupted lockfile reconstructed by the frozen
/// path, which runs no dedup pass at all): it raises ONLY when a shared slot
/// ALSO disagrees on `identity` (content_hash) — never on slot alone. An
/// EMPTY identity (`ResolvedDep::identity` has no `Option` — `frozen.rs`'s
/// `resolved_from_locked` maps a missing `LockedDep.identity` to `""`) can
/// never be proven equal to anything, so it does NOT short-circuit — mirrors
/// Python's `None`-is-never-proven-equal rule exactly.
///
/// **Runs on fresh AND frozen graphs, no deferral (§10 S6 "F4"):** this
/// function's only inputs are `ResolvedDep.name`/`.namespace` (the slot) and
/// `.identity` (the raise/no-raise decision) — both already present on a
/// frozen-reconstructed `ResolvedDep` (`frozen.rs`'s `resolved_from_locked`)
/// exactly as they are on a fresh one. Naming the colliding origins uses
/// `dep_origin_label` (above), which falls back to the provenance-derived
/// `format_dep_origin` when `source_id` is absent (frozen, pre-S5) — so no
/// new `SourceId` reconstruction plumbing is needed in `frozen.rs` to get
/// full coverage today: this floor is wired into `resolve_frozen`/
/// `resolve_workspace_frozen` (`frozen.rs`) exactly like `resolve()`/
/// `resolve_workspace()` (`resolver.rs`), all four call sites, from this
/// slice onward.
///
/// **Durable caveat (§4.6/G9 — also in spec/errors.md):** this is a
/// *partial* proxy for "two packages export the same Nim symbol" — a slot
/// collision implies a symbol collision, but the converse does not hold (two
/// differently-named slots can still export the identical module, evading
/// this floor). A non-raising call means "no directory-slot collision,"
/// **never** "no import collision" in general.
pub fn check_directory_slot_collisions(resolved: &ResolvedGraph) -> Result<(), CoreError> {
    use milpa_types::dep_dir_name;
    use std::collections::BTreeMap;

    let mut by_slot: BTreeMap<String, Vec<&ResolvedDep>> = BTreeMap::new();
    for dep in &resolved.deps {
        let slot = dep_dir_name(&dep.name, dep.namespace.as_deref());
        by_slot.entry(slot).or_default().push(dep);
    }

    for (slot, group) in by_slot {
        if group.len() < 2 {
            continue;
        }
        // content_hash short-circuit: every member must share ONE non-empty
        // identity to be provably byte-identical. An empty identity (missing
        // content hash) can never be proven equal, so it does NOT short-circuit.
        let first_identity = &group[0].identity;
        let all_same_and_known =
            !first_identity.is_empty() && group.iter().all(|d| &d.identity == first_identity);
        if all_same_and_known {
            continue;
        }
        let existing = dep_origin_label(group[0]);
        let conflicting = dep_origin_label(group[1]);
        // A resolver-domain code (mirrors RES-BINDING-CONFLICT in binding.rs),
        // not a lockfile-parse error — deliberately NOT the module's `err()`
        // helper, which always tags `CoreError::Lockfile`.
        return Err(CoreError::Resolver(
            "RES-IMPORT-COLLISION",
            format!(
                "directory-slot collision at '_deps/{slot}/': {existing} and {conflicting} have \
                 different content and cannot both materialize into this slot — give one an \
                 explicit, distinct dep label (or reconcile via `overrides {{}}`) to separate \
                 them (note: this checks directory slots only, not full Nim-symbol import \
                 collisions — a clean run here does not rule out a symbol collision across two \
                 differently-named slots)"
            ),
        ));
    }
    Ok(())
}

/// Convert a solver-var form requires name (`"ns::name"`) to lockfile-safe
/// slash form (`"ns/name"`). Bare dep names (no `::`) are returned unchanged.
/// This is the SOLE conversion site — matches Python `_req_name_to_lockfile`.
fn req_name_to_lockfile(s: &str) -> String {
    match s.split_once("::") {
        Some((ns, name)) => format!("{}/{}", ns, name),
        None => s.to_string(),
    }
}

/// Translate one flat [`ResolvedDep`] into a structured [`LockedDep`].
fn locked_from_resolved(d: &ResolvedDep) -> LockedDep {
    // C1: convert solver_var form ("ns::name") to lockfile-safe slash form
    // ("ns/name") — solver vars must not appear in the lockfile.
    let mut requires: Vec<String> = d.requires.iter().map(|r| req_name_to_lockfile(r)).collect();
    requires.sort();
    // S4: carry cond_requires; sort by total key (name, predicate-string) for
    // byte-exact determinism when same-name entries exist (C1 fix).
    let mut cond_requires = d.cond_requires.clone();
    cond_requires.sort_by_key(|cr| cond_require_sort_key(cr));
    LockedDep {
        name: d.name.clone(),
        // C1: carry namespace for qualified named deps.
        namespace: d.namespace.clone(),
        // Every fetched/member dep in a resolved graph is content-hashed; an
        // empty identity means either the synthetic root (already dropped by
        // `build_graph`) or a `Root`-kind self-reference (§14.5: the
        // standalone root carries no separate identity of its own).
        identity: opt(&d.identity),
        version: d.version.to_string(),
        src_dir: d.src_dir.clone(),
        requires,
        // D-lifecycle: `ResolvedDep.provenances` is already the full set of
        // emission-level records (observed + declared mirrors). Direct clone.
        provenances: d.provenances.clone(),
        // S5 (RFC #23 §4): carry active_flags from the resolved dep (populated by
        // build_graph from the converged dep_active_flags map). Already lex-sorted.
        active_flags: d.active_flags.clone(),
        // S6: carry dep_decl pin from the resolved dep (set only when
        // the edge was sourced from a DepDecl artifact).
        dep_decl: d.dep_decl.clone(),
        // S4: carry cond_requires (sorted by (name, canonical-predicate-string)).
        cond_requires,
        // Phase B: carry aliases from the resolver's dedup pass (lex-sorted).
        // The resolver populates ResolvedDep.aliases via finalize(); from_graph
        // carries them through so the lockfile emits the aliases line.
        aliases: d.aliases.clone(),
        // RFC per-entry-attestation.md P2/P3a: narrow EntryAttestation
        // (index-side) to LockAttestation (lockfile-side). P3a: bundle_pin
        // NOW round-trips too (lockfile-schema §3.9 P3a addition) — `milpa
        // verify`'s offline re-verification needs it downstream of a live
        // resolve. RFC origin-as-identity §4.4 (B2/G10): namespace is now
        // derived from `d.source_id`'s namespace (the entry's REAL index
        // namespace, distinct from d.namespace which is manifest-
        // qualification only) — the deleted `registry_namespace` field's
        // successor.
        attestation: d.attestation.as_ref().map(|a| LockAttestation {
            kind: a.kind.clone(),
            rekor: a.rekor.clone(),
            bundle_pin: a.bundle_pin.clone(),
            namespace: match &d.source_id {
                Some(SourceId::Fetchable(FetchableOrigin::Registry { namespace, .. })) => {
                    namespace.clone().unwrap_or_default()
                }
                _ => String::new(),
            },
        }),
        // A5: carry the sibling declared-version source straight through —
        // never recomputed at the lockfile boundary.
        declared_version_source: d.declared_version_source.clone(),
        // RFC origin-as-identity §4.1/§7 (S5): carry the binding phase's
        // accepted SourceId straight through to the on-disk structured form.
        source_id: d.source_id.clone(),
    }
}

/// Map a field that is `""` when absent onto the lockfile's
/// "None-when-omitted, never empty string" optional-field convention.
fn opt(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

// ---------------------------------------------------------------------------
// verify — lockfile ⟷ graph / disk (S13)
// ---------------------------------------------------------------------------

/// Confirm a resolved graph matches the lockfile dep-for-dep (mirrors
/// `lockfile.py:verify_against_graph`). Any divergence — a dep in one but not the
/// other, or an identity mismatch — is `LOCK-GRAPH-MISMATCH`. Used by `milpa lock`
/// / `milpa verify` to assert the lockfile is in sync with a fresh resolve.
pub fn verify_against_graph(lockfile: &Lockfile, graph: &ResolvedGraph) -> Result<(), CoreError> {
    use milpa_types::dep_dir_name;
    use std::collections::BTreeMap;
    // C1: key by dep_dir_name (namespace-aware) so two qualified deps with the
    // same bare name (ns1::bar, ns2::bar) are kept distinct in the map.
    let locked: BTreeMap<String, &LockedDep> =
        lockfile.deps.iter().map(|d| (dep_dir_name(&d.name, d.namespace.as_deref()), d)).collect();
    let resolved: BTreeMap<String, &ResolvedDep> =
        graph.deps.iter().map(|d| (dep_dir_name(&d.name, d.namespace.as_deref()), d)).collect();

    let mut errors: Vec<String> = Vec::new();
    for name in resolved.keys() {
        if !locked.contains_key(name.as_str()) {
            errors.push(format!(
                "unexpected dep {name:?} in resolved graph (not in lockfile)"
            ));
        }
    }
    for name in locked.keys() {
        if !resolved.contains_key(name.as_str()) {
            errors.push(format!(
                "locked dep {name:?} is missing from resolved graph"
            ));
        }
    }
    for (name, r) in &resolved {
        if let Some(l) = locked.get(name.as_str()) {
            if l.identity.as_deref() != Some(r.identity.as_str()) {
                errors.push(format!(
                    "identity mismatch for {name:?}: locked={:?}, actual={:?}",
                    l.identity, r.identity
                ));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(err(
            "LOCK-GRAPH-MISMATCH",
            format!(
                "lockfile does not match resolved graph:\n  {}",
                errors.join("\n  ")
            ),
        ))
    }
}

/// `--locked` guard (resolution-semantics RFC §3 Axis B / §6 D-B2).
///
/// `--locked` always performs a REAL resolve (with the B2 minimal-change/
/// prior-lock preference already applied via the resolver's own `prior`
/// threading) and then asserts the result is IDENTICAL to the committed
/// lock — distinct from `frozen`, which skips solving entirely and only
/// reconstructs.
///
/// **Drift is identity-based (D-B2), never version-label-based:** the
/// comparison keys on `identity` (content hash) + the canonicalized
/// `provenances` set only. The version string is deliberately NEVER
/// consulted — the one-time Axis-A `0.0.1`->real-declared-version relabel
/// of an identity-unchanged git/url/local/tarball dep is therefore
/// compatible, not drift.
///
/// Provenances are compared after sorting each side by the same canonical
/// `provenance_sort_key` the emitter uses (lockfile-schema.md §4.0) —
/// `graph.deps[i].provenances` is observed-first/unsorted (sorted only at
/// KDL emission time), while `prior.deps[i].provenances` was parsed back
/// from already-canonically-sorted text, so comparing raw Vec order would
/// produce false-positive drift.
///
/// Returns `RES-LOCKED-DRIFT` naming every drifted/added/removed package,
/// or — when `prior` is `None` — because there is no committed lockfile to
/// reproduce against at all (a best-in-class CI guard cannot assert
/// reproducibility with nothing to reproduce).
///
/// `exclude_newer` is the EFFECTIVE time-bound this `--locked` resolve just
/// ran under (D5, §6 D-D3 no-silent-drop). Dropping a previously-recorded
/// bound RELAXES semantics (silently un-freezes the project), so — unlike
/// identity/provenance, which are compared per-dep above — this is a single
/// whole-lockfile comparison: `prior.exclude_newer` present but the new
/// effective value absent (or a genuinely different timestamp) is drift.
pub fn check_locked_drift(
    prior: Option<&Lockfile>,
    graph: &ResolvedGraph,
    exclude_newer: Option<Timestamp>,
) -> Result<(), CoreError> {
    use milpa_types::dep_dir_name;
    use std::collections::BTreeMap;

    let Some(prior) = prior else {
        return Err(err(
            "RES-LOCKED-DRIFT",
            "--locked requires a committed milpa.lock to verify against, but \
             none was found; run `milpa lock` (or `milpa fetch`/`milpa lock` \
             without --locked) to create one"
                .to_string(),
        ));
    };

    let locked: BTreeMap<String, &LockedDep> = prior
        .deps
        .iter()
        .map(|d| (dep_dir_name(&d.name, d.namespace.as_deref()), d))
        .collect();
    let resolved: BTreeMap<String, &ResolvedDep> = graph
        .deps
        .iter()
        .map(|d| (dep_dir_name(&d.name, d.namespace.as_deref()), d))
        .collect();

    let mut drifted: Vec<String> = Vec::new();
    for name in resolved.keys() {
        if !locked.contains_key(name.as_str()) {
            drifted.push(format!(
                "{name}: added — resolved but absent from the committed lockfile"
            ));
        }
    }
    for name in locked.keys() {
        if !resolved.contains_key(name.as_str()) {
            drifted.push(format!(
                "{name}: removed — present in the committed lockfile, absent from the resolve"
            ));
        }
    }
    for (name, r) in &resolved {
        let Some(l) = locked.get(name.as_str()) else { continue };
        // D-B2: identity + provenance ONLY — the version label is never
        // consulted (a version relabel with unchanged identity is not drift).
        if l.identity.as_deref() != Some(r.identity.as_str()) {
            drifted.push(format!(
                "{name}: identity changed — lockfile={:?}, resolve={:?}",
                l.identity, r.identity
            ));
            continue;
        }
        let mut locked_provs = l.provenances.clone();
        locked_provs.sort_by_key(provenance_sort_key);
        let mut actual_provs = r.provenances.clone();
        actual_provs.sort_by_key(provenance_sort_key);
        if locked_provs != actual_provs {
            drifted.push(format!(
                "{name}: provenance changed — lockfile={locked_provs:?}, resolve={actual_provs:?}"
            ));
        }
    }

    // D5 (§6 D-D3 no-silent-drop): a dropped or changed `exclude_newer` bound
    // is drift too, compared once for the whole lockfile (not per-dep).
    if prior.exclude_newer != exclude_newer {
        drifted.push(format!(
            "exclude_newer: changed — lockfile={:?}, resolve={:?}",
            prior.exclude_newer, exclude_newer
        ));
    }

    if drifted.is_empty() {
        Ok(())
    } else {
        Err(err(
            "RES-LOCKED-DRIFT",
            format!(
                "--locked: resolved graph deviates from the committed lockfile:\n  {}",
                drifted.join("\n  ")
            ),
        ))
    }
}

/// Classify a single `_deps/<name>` path into one of the four states defined
/// by RFC rfc-content-addressed-identity.md Phase C §6 item 6.
///
/// Returns `Some(divergence_string)` for states (b) and (d); returns `None`
/// for states (a) and (c) — state (a) meaning "proceed to identity check",
/// state (c) meaning "proceed to hash and catch I/O error there".
///
/// Uses `symlink_metadata` (lstat, does NOT follow symlinks) to distinguish
/// (b) from (d), then `metadata` (follows) to check reachability.
fn classify_dep_path(dep_path: &std::path::Path, deps_dir: &std::path::Path) -> Option<String> {
    let name = dep_path.file_name().unwrap_or_default().to_string_lossy();
    // lstat: does NOT follow symlinks → tells us if _deps/<name> IS a symlink.
    let lstat = std::fs::symlink_metadata(dep_path);
    let is_link = lstat.as_ref().map(|m| m.file_type().is_symlink()).unwrap_or(false);
    let lstat_exists = lstat.is_ok();

    if !lstat_exists {
        // State (d): nothing at _deps/<name> at all.
        return Some(format!("{name}: missing from {}/", deps_dir.display()));
    }

    if is_link {
        // Check if the symlink target is reachable (stat, follows symlinks).
        let target_exists = dep_path.exists(); // follows
        if !target_exists {
            // State (b): dangling symlink.
            return Some(format!(
                "{name}: dangling symlink — store entry gone or store not mounted \
                (target: {})",
                dep_path.display()
            ));
        }
    }

    // State (a): reachable (either a plain dir/file, or a symlink with a live target).
    // Proceed to identity hash in the caller; I/O errors there become state (c).
    None
}

/// Return `true` iff the dep has at least one `Local` provenance record.
///
/// Used by `verify_lockfile_against_deps` to dispatch on provenance kind
/// (lockfile-schema §6.2 NORMATIVE: local → liveness-only; others →
/// identity hash-compare). Mirrors `lockfile.py:_is_local_dep`.
fn is_local_dep(locked: &LockedDep) -> bool {
    locked
        .provenances
        .iter()
        .any(|p| matches!(p, ProvenanceRecord::Local { .. }))
}

/// Liveness check for a local-provenance dep (lockfile-schema §6.2.1).
///
/// Returns `Some(divergence)` for states (b), (c), (d); returns `None` for
/// state (a) (symlink present + target is a reachable directory).
///
/// States:
///   (a) symlink present + target dir reachable → None (pass)
///   (b) dangling symlink (is_symlink true, exists false) → "dangling"
///   (c) plain dir, not a symlink → "expected symlink, found directory"
///   (d) no entry at all → "missing from"
///
/// Mirrors `lockfile.py:_verify_local_dep_liveness`.
fn verify_local_dep_liveness(name: &str, dep_path: &std::path::Path) -> Option<String> {
    let is_link = std::fs::symlink_metadata(dep_path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    let exists = dep_path.exists(); // follows symlinks

    if is_link && !exists {
        // State (b): dangling — source tree deleted or moved.
        return Some(format!(
            "{name}: dangling symlink — source tree gone or moved (target: {})",
            dep_path.display()
        ));
    }

    if !is_link && !exists {
        // State (d): genuinely absent.
        return Some(format!(
            "{name}: missing from {}/",
            dep_path.parent().unwrap_or(dep_path).display()
        ));
    }

    if !is_link && exists {
        // State (c): plain directory (or file) — not a symlink.
        return Some(format!(
            "{name}: expected symlink to source tree, found plain directory at {}",
            dep_path.display()
        ));
    }

    // is_link && exists: state (a) — live symlink to an existing dir.
    None
}

/// Verify each locked dep's on-disk bytes (under `deps_dir/<name>`) hash to its
/// recorded identity, and that no extra non-dotfile entries exist (mirrors
/// `lockfile.py:verify_lockfile_against_deps`). Returns the list of divergence
/// messages — empty means verified. This is `milpa verify`'s primitive; the CLI
/// prints the divergences and exits 1 (no single catalog code — it is a report).
///
/// Dispatches on provenance kind (lockfile-schema §6.2 NORMATIVE):
///   LOCAL deps → liveness-only (`verify_local_dep_liveness`): symlink to dir;
///     plain dir = divergence; dangling/missing = divergence. NO hash compare.
///   All other deps → four-state structural check + identity hash-compare:
///     (a) symlink present + store readable ⇒ pass (proceed to identity check)
///     (b) dangling symlink (lstat ok, stat fails) ⇒ "dangling" divergence
///     (c) symlink resolves but compute_content_hash returns I/O error ⇒ CAS-STORE-IO-ERROR
///     (d) nothing at _deps/<name> ⇒ "missing from" divergence
///
/// §6.4 alias verification: for each alias `a` in `dep.aliases`, `_deps/<a>`
/// must be a symlink pointing at the same store entry as the canonical
/// `_deps/<name>`. Absent, dangling, or wrong-target alias ⇒
/// VERIFY-ALIAS-SYMLINK-MISSING divergence. Alias names are excluded from the
/// extra-dep scan.
pub fn verify_lockfile_against_deps(
    lockfile: &Lockfile,
    deps_dir: &std::path::Path,
) -> Vec<String> {
    use milpa_types::dep_dir_name;
    use std::collections::BTreeSet;
    let mut divergences: Vec<String> = Vec::new();

    // Build the full expected-name set: canonical dep_dir_names + all alias names.
    // C1: use dep_dir_name so qualified deps are keyed as "@ns/name".
    // Used by the extra-dep scan to exclude both.
    let mut expected_names: BTreeSet<String> = BTreeSet::new();
    for dep in &lockfile.deps {
        expected_names.insert(dep_dir_name(&dep.name, dep.namespace.as_deref()));
        for alias in &dep.aliases {
            expected_names.insert(alias.clone());
        }
    }

    for locked in &lockfile.deps {
        // C1: use dep_dir_name so qualified deps are found at "_deps/@ns/name".
        let dir_name = dep_dir_name(&locked.name, locked.namespace.as_deref());
        let dep_path = deps_dir.join(&dir_name);

        // --- dispatch on provenance kind (lockfile-schema §6.2 NORMATIVE) ---
        if is_local_dep(locked) {
            // LOCAL: liveness-only (§6.2.1). No hash compare.
            if let Some(div) = verify_local_dep_liveness(&locked.name, &dep_path) {
                divergences.push(div);
            }
            // Skip alias verification for local deps (they have no CAS store entry
            // to alias-point at; aliases are a Phase B CAS-dedup construct).
            continue;
        }

        // --- four-state structural classification (non-local) ---
        if let Some(structural) = classify_dep_path(&dep_path, deps_dir) {
            divergences.push(structural);
            continue;
        }

        // State (a) or plain dir/file: attempt identity hash.
        // I/O errors from compute_content_hash (slug MILPA-INTERNAL-IO) are
        // classified as state (c): CAS-STORE-IO-ERROR.  Non-I/O errors (e.g.
        // ID-NON-UTF8-SYMLINK-TARGET) pass through as generic "cannot hash".
        let canonical_realpath: Option<std::path::PathBuf>;
        match crate::identity::compute_content_hash(&dep_path) {
            Ok(actual) => {
                canonical_realpath = std::fs::canonicalize(&dep_path).ok();
                if locked.identity.as_deref() != Some(actual.as_str()) {
                    divergences.push(format!(
                        "{}: identity mismatch — lockfile says {:?}, actual {:?}",
                        locked.name, locked.identity, actual
                    ));
                }
            }
            Err(e) if e.code() == crate::identity::INTERNAL_IO => {
                // State (c): store entry readable at the symlink level but
                // I/O failed while hashing (e.g. network mount offline).
                canonical_realpath = None;
                divergences.push(format!(
                    "{}: [CAS-STORE-IO-ERROR] I/O error reading store entry — {}",
                    locked.name,
                    e.message()
                ));
            }
            Err(e) => {
                canonical_realpath = std::fs::canonicalize(&dep_path).ok();
                divergences.push(format!("{}: cannot hash — {}", locked.name, e.message()));
            }
        }

        // --- §6.4 alias verification ---
        let mut sorted_aliases = locked.aliases.clone();
        sorted_aliases.sort();
        for alias in &sorted_aliases {
            let alias_path = deps_dir.join(alias);
            // lstat to distinguish dangling from absent.
            let alias_lstat = std::fs::symlink_metadata(&alias_path);
            let alias_is_link = alias_lstat
                .as_ref()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            let alias_lstat_ok = alias_lstat.is_ok();
            let alias_target_ok = alias_path.exists(); // follows symlink

            if !alias_lstat_ok || (alias_is_link && !alias_target_ok) {
                // Missing or dangling alias.
                divergences.push(format!(
                    "{alias}: [VERIFY-ALIAS-SYMLINK-MISSING] alias symlink \
                    absent or dangling for canonical '{}'",
                    locked.name
                ));
                continue;
            }

            // Alias exists: verify it points at the same store entry as canonical.
            let alias_real = std::fs::canonicalize(&alias_path).ok();
            if canonical_realpath.is_none()
                || alias_real.is_none()
                || alias_real != canonical_realpath
            {
                divergences.push(format!(
                    "{alias}: [VERIFY-ALIAS-SYMLINK-MISSING] alias symlink \
                    points to different store entry than canonical '{}'",
                    locked.name
                ));
            }
        }
    }

    // --- extra-dep scan (excludes hidden entries + all expected names) ---
    // C1: namespace directories (@ns/) may contain multiple entries; check
    // their children (as @ns/name) rather than the dir itself.
    if let Ok(rd) = std::fs::read_dir(deps_dir) {
        let mut extras: Vec<String> = Vec::new();
        for entry in rd.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            if name.starts_with('@') && entry.path().is_dir() {
                // Namespace directory: check each child independently.
                if let Ok(children_rd) = std::fs::read_dir(entry.path()) {
                    for child in children_rd.filter_map(|e| e.ok()) {
                        let child_name = child.file_name().to_string_lossy().into_owned();
                        let compound = format!("{}/{}", name, child_name);
                        if !expected_names.contains(compound.as_str()) {
                            extras.push(compound);
                        }
                    }
                }
            } else if !expected_names.contains(name.as_str()) {
                extras.push(name);
            }
        }
        extras.sort();
        for n in extras {
            divergences.push(format!(
                "{n}: extra dep in {}/ not in lockfile",
                deps_dir.display()
            ));
        }
    }
    divergences
}

// --- kdl-rs access helpers (mirroring milpa-manifest) ---

/// Positional arguments of a node (entries with no property name), in order.
fn args(node: &KdlNode) -> Vec<&kdl::KdlEntry> {
    node.entries()
        .iter()
        .filter(|e| e.name().is_none())
        .collect()
}

/// The child nodes of a node's `{ }` block (empty when there is none).
fn children(node: &KdlNode) -> Vec<&KdlNode> {
    node.children()
        .map(|d| d.nodes().iter().collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// strip_dep_pin — SSOT for the "drop one dep's pin" operation (F12)
// ---------------------------------------------------------------------------

/// Return a copy of `lockfile` with the named dep's pin stripped.
///
/// The stripped entry retains only `ProvenanceRecord::Git` entries with
/// `origin == "declared"` (declared mirrors).  `identity` is set to `None`
/// so the resolver treats the dep as un-pinned and re-resolves it fresh.
/// The declared provenances survive so `_prior_declared_mirror_urls` can
/// carry them forward (Phase D item 5).
///
/// The dep at `canonical_name` MUST already exist in `lockfile.deps`; the
/// caller is responsible for alias→canonical resolution and the "not found"
/// guard (both call sites already perform these steps before invoking this
/// function).
///
/// Mirrors `lockfile.py:strip_dep_pin`.
pub fn strip_dep_pin(lockfile: Lockfile, canonical_name: &str) -> Lockfile {
    let updated = lockfile
        .deps
        .iter()
        .find(|d| d.name == canonical_name)
        .expect("strip_dep_pin: caller must ensure dep exists in lockfile")
        .clone();
    let declared_provs: Vec<ProvenanceRecord> = updated
        .provenances
        .iter()
        .filter(|p| matches!(p, ProvenanceRecord::Git { origin, .. } if origin == "declared"))
        .cloned()
        .collect();
    let pin_stripped = LockedDep {
        identity: None,
        provenances: declared_provs,
        ..updated
    };
    let mut new_deps: Vec<LockedDep> = lockfile
        .deps
        .into_iter()
        .filter(|d| d.name != canonical_name)
        .collect();
    new_deps.push(pin_stripped);
    Lockfile {
        deps: new_deps,
        ..lockfile
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_ID: &str =
        "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn parses_a_full_dep_with_git_provenance() {
        let text = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\n\
             dep \"foo\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"1.2.3\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires \"bar\" \"baz\"\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/foo.git\"\n\
             \x20       ref \"main\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lock = parse_lockfile(&text).unwrap();
        assert_eq!(lock.version, 1);
        assert_eq!(lock.strategy, "maxver");
        assert_eq!(lock.deps.len(), 1);
        let dep = &lock.deps[0];
        assert_eq!(dep.name, "foo");
        assert_eq!(dep.identity.as_deref(), Some(VALID_ID));
        assert_eq!(dep.version, "1.2.3");
        assert_eq!(dep.src_dir, "src");
        assert_eq!(dep.requires, vec!["bar", "baz"]);
        assert_eq!(
            dep.provenances,
            vec![ProvenanceRecord::Git {
                url: "https://example.com/foo.git".into(),
                ref_spec: Some("main".into()),
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            }]
        );
    }

    #[test]
    fn absent_identity_is_none_and_bare_requires_is_empty() {
        let text = "version 1\nstrategy \"maxver\"\n\
                    dep \"foo\" {\n    version \"0.0.1\"\n    src_dir \"\"\n    requires\n    \
                    provenance {\n        origin \"observed\"\n        kind \"local\"\n        path \"../foo\"\n    }\n}\n";
        let lock = parse_lockfile(text).unwrap();
        let dep = &lock.deps[0];
        assert_eq!(dep.identity, None);
        assert!(dep.requires.is_empty());
        assert_eq!(
            dep.provenances,
            vec![ProvenanceRecord::Local {
                path: "../foo".into(),
                origin: "observed".into(),
            }]
        );
    }

    #[test]
    fn strategy_absent_raises_lock_strategy_missing() {
        let err = parse_lockfile("version 1\n").unwrap_err();
        assert_eq!(err.code(), "LOCK-STRATEGY-MISSING");
    }

    // --- D5 (resolution-semantics RFC §3 Axis D / §5): top-level exclude_newer ---

    #[test]
    fn exclude_newer_absent_by_default() {
        let lock = parse_lockfile("version 1\nstrategy \"maxver\"\n").unwrap();
        assert_eq!(lock.exclude_newer, None);
    }

    #[test]
    fn exclude_newer_parses_present_node() {
        let lock = parse_lockfile(
            "version 1\nstrategy \"maxver\"\nexclude_newer \"2026-01-01T00:00:00Z\"\n",
        )
        .unwrap();
        assert_eq!(
            lock.exclude_newer,
            Some(parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap())
        );
    }

    #[test]
    fn exclude_newer_wrong_arity_raises_lock_field_arity() {
        let err = parse_lockfile(
            "version 1\nstrategy \"maxver\"\nexclude_newer \"a\" \"b\"\n",
        )
        .unwrap_err();
        assert_eq!(err.code(), "LOCK-FIELD-ARITY");
    }

    #[test]
    fn exclude_newer_non_string_raises_lock_field_type() {
        let err = parse_lockfile("version 1\nstrategy \"maxver\"\nexclude_newer 42\n").unwrap_err();
        assert_eq!(err.code(), "LOCK-FIELD-TYPE");
    }

    #[test]
    fn exclude_newer_unparseable_timestamp_raises_lock_field_type() {
        let err =
            parse_lockfile("version 1\nstrategy \"maxver\"\nexclude_newer \"not-a-date\"\n")
                .unwrap_err();
        assert_eq!(err.code(), "LOCK-FIELD-TYPE");
    }

    #[test]
    fn exclude_newer_omitted_from_emission_when_absent() {
        let lock = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![] };
        let text = format_lockfile(&lock);
        assert!(!text.contains("exclude_newer"), "text: {text}");
    }

    #[test]
    fn exclude_newer_emitted_right_after_strategy_when_present() {
        let ts = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        let lock = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: Some(ts), deps: vec![] };
        let text = format_lockfile(&lock);
        assert_eq!(
            text,
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\
             exclude_newer \"2026-01-01T00:00:00Z\"\n"
        );
    }

    #[test]
    fn exclude_newer_round_trips_through_format_and_parse() {
        let ts = parse_iso8601_timestamp("2026-06-15T12:34:56Z").unwrap();
        let lock = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: Some(ts), deps: vec![] };
        let text = format_lockfile(&lock);
        let reparsed = parse_lockfile(&text).unwrap();
        assert_eq!(reparsed.exclude_newer, Some(ts));
    }

    #[test]
    fn from_graph_carries_exclude_newer_through() {
        let graph = ResolvedGraph { deps: vec![] };
        let ts = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        let lock = from_graph(&graph, "maxver", Some(ts));
        assert_eq!(lock.exclude_newer, Some(ts));
        let lock_none = from_graph(&graph, "maxver", None);
        assert_eq!(lock_none.exclude_newer, None);
    }

    #[test]
    fn self_mirrors_silently_ignored() {
        // S3 purge: legacy `self_mirrors` nodes are silently ignored (§3.7).
        let text = "version 1\nstrategy \"maxver\"\n\
                    dep \"foo\" {\n    version \"0.0.1\"\n    src_dir \"\"\n    requires\n    \
                    self_mirrors (url)\"https://a.example/foo.git\" \"https://b.example/foo.git\"\n    \
                    provenance {\n        origin \"observed\"\n        kind \"git\"\n        url \"https://example.com/foo.git\"\n    }\n}\n";
        let lock = parse_lockfile(text).unwrap();
        // Only the explicit provenance block is counted; self_mirrors is ignored.
        assert_eq!(lock.deps[0].provenances.len(), 1);
        assert_eq!(lock.deps[0].provenances[0].origin(), "observed");
    }

    #[test]
    fn accepts_every_provenance_kind() {
        for (kind_block, want) in [
            (
                "origin \"observed\"\n        kind \"tarball\"\n        url \"https://e/x.tar.gz\"\n        sha256 \"abc\"",
                ProvenanceRecord::Tarball {
                    url: "https://e/x.tar.gz".into(),
                    sha256: Some("abc".into()),
                    origin: "observed".into(),
                },
            ),
            (
                "origin \"observed\"\n        kind \"member\"\n        name \"liba\"",
                ProvenanceRecord::Member {
                    name: "liba".into(),
                    origin: "observed".into(),
                },
            ),
            (
                "origin \"observed\"\n        kind \"oci\"\n        registry \"r\"\n        repository \"o/p\"\n        digest \"sha256:d\"",
                ProvenanceRecord::Oci {
                    registry: "r".into(),
                    repository: "o/p".into(),
                    digest: "sha256:d".into(),
                    origin: "observed".into(),
                },
            ),
        ] {
            let text = format!(
                "version 1\nstrategy \"maxver\"\ndep \"foo\" {{\n    version \"0.0.1\"\n    src_dir \"\"\n    requires\n    provenance {{\n        {kind_block}\n    }}\n}}\n"
            );
            let lock = parse_lockfile(&text).unwrap();
            assert_eq!(lock.deps[0].provenances, vec![want]);
        }
    }

    #[test]
    fn registry_kind_raises_lock_prov_kind_unknown() {
        // S3 purge: registry kind is no longer recognized.
        let text = "version 1\nstrategy \"maxver\"\n\
                    dep \"foo\" {\n    version \"0.0.1\"\n    src_dir \"\"\n    requires\n    \
                    provenance {\n        origin \"observed\"\n        kind \"registry\"\n        name \"n\"\n    }\n}\n";
        let err = parse_lockfile(text).unwrap_err();
        assert_eq!(err.code(), "LOCK-PROV-KIND-UNKNOWN");
    }

    // --- error-path coverage (the 12 LOCK-* parse codes) ---

    fn code_of(text: &str) -> &'static str {
        parse_lockfile(text).unwrap_err().code()
    }

    #[test]
    fn error_codes_match_the_spec() {
        assert_eq!(code_of("{ not valid kdl }}}"), "LOCK-KDL-SYNTAX");
        assert_eq!(code_of("strategy \"maxver\"\n"), "LOCK-VERSION-MISSING");
        assert_eq!(code_of("version 99\n"), "LOCK-VERSION-UNSUPPORTED");
        assert_eq!(code_of("version\n"), "LOCK-FIELD-ARITY");
        assert_eq!(code_of("version \"x\"\n"), "LOCK-FIELD-TYPE");
        // LOCK-STRATEGY-MISSING: version present but strategy absent.
        assert_eq!(code_of("version 1\n"), "LOCK-STRATEGY-MISSING");
        assert_eq!(
            code_of("version 1\nstrategy \"maxver\"\ndep {\n    version \"0.0.1\"\n}\n"),
            "LOCK-DEP-NAME-ARITY"
        );
        assert_eq!(
            code_of("version 1\nstrategy \"maxver\"\ndep \"foo\" {\n    version \"0.0.1\" \"extra\"\n}\n"),
            "LOCK-DEP-FIELD-ARITY"
        );
        assert_eq!(
            code_of("version 1\nstrategy \"maxver\"\ndep \"foo\" {\n    identity \"not-a-multihash\"\n}\n"),
            "LOCK-DEP-IDENTITY-INVALID"
        );
        assert_eq!(
            code_of("version 1\nstrategy \"maxver\"\ndep \"foo\" {\n    provenance {\n        kind \"git\" \"extra\"\n    }\n}\n"),
            "LOCK-PROV-FIELD-ARITY"
        );
        assert_eq!(
            code_of("version 1\nstrategy \"maxver\"\ndep \"foo\" {\n    provenance {\n        url \"https://e/x.git\"\n    }\n}\n"),
            "LOCK-PROV-KIND-MISSING"
        );
        // LOCK-PROV-KIND-UNKNOWN: origin present but unknown kind.
        assert_eq!(
            code_of("version 1\nstrategy \"maxver\"\ndep \"foo\" {\n    provenance {\n        origin \"observed\"\n        kind \"ftp\"\n    }\n}\n"),
            "LOCK-PROV-KIND-UNKNOWN"
        );
        // LOCK-PROV-FIELD-MISSING: kind present, origin missing (S3 strict).
        assert_eq!(
            code_of("version 1\nstrategy \"maxver\"\ndep \"foo\" {\n    provenance {\n        kind \"git\"\n    }\n}\n"),
            "LOCK-PROV-FIELD-MISSING"
        );
        // LOCK-PROV-FIELD-MISSING: origin present, url missing.
        assert_eq!(
            code_of("version 1\nstrategy \"maxver\"\ndep \"foo\" {\n    provenance {\n        origin \"observed\"\n        kind \"git\"\n        ref \"main\"\n    }\n}\n"),
            "LOCK-PROV-FIELD-MISSING"
        );
        // LOCK-SUBMODULE-FIELD-INVALID: submodule node with zero args (missing path).
        assert_eq!(
            code_of(
                "version 1\nstrategy \"maxver\"\ndep \"foo\" {\n    provenance {\n        origin \"observed\"\n        kind \"git\"\n        \
                 url \"https://e/x.git\"\n        submodule sha=\"abc\"\n    }\n}\n"
            ),
            "LOCK-SUBMODULE-FIELD-INVALID"
        );
        // LOCK-SUBMODULE-FIELD-INVALID: submodule node missing sha= property.
        assert_eq!(
            code_of(
                "version 1\nstrategy \"maxver\"\ndep \"foo\" {\n    provenance {\n        origin \"observed\"\n        kind \"git\"\n        \
                 url \"https://e/x.git\"\n        submodule \"vendor/lib\"\n    }\n}\n"
            ),
            "LOCK-SUBMODULE-FIELD-INVALID"
        );
        // Scalar-field arity errors still use LOCK-PROV-FIELD-ARITY (not the new slug).
        assert_eq!(
            code_of("version 1\nstrategy \"maxver\"\ndep \"foo\" {\n    provenance {\n        kind \"git\" \"extra\"\n    }\n}\n"),
            "LOCK-PROV-FIELD-ARITY"
        );
    }

    // --- emit (S5b) ---

    /// A hand-built Lockfile exercising every optional field + a git provenance,
    /// to pin the exact canonical byte layout (lockfile-schema §2.4).
    fn sample_lockfile() -> Lockfile {
        Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![LockedDep {
            source_id: None,
                declared_version_source: None,
                name: "foo".into(),
                namespace: None,
                identity: Some(VALID_ID.into()),
                version: "1.2.3".into(),
                src_dir: "src".into(),
                requires: vec!["bar".into(), "baz".into()],
                provenances: vec![ProvenanceRecord::Git {
                    url: "https://example.com/foo.git".into(),
                    ref_spec: Some("main".into()),
                    commit_sha: Some("deadbeef".into()),
                    origin: "observed".into(),
                    submodule_shas: vec![],
                }],
                active_flags: vec!["ssl".into()],
                dep_decl: None,
                cond_requires: vec![],
                aliases: vec![],
                attestation: None,
            }],
        }
    }

    #[test]
    fn format_is_byte_exact() {
        let want = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\
             \n\
             dep \"foo\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"1.2.3\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires \"bar\" \"baz\"\n\
             \x20   active_flags \"ssl\"\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/foo.git\"\n\
             \x20       ref \"main\"\n\
             \x20       commit_sha \"deadbeef\"\n\
             \x20   }}\n\
             }}\n"
        );
        assert_eq!(format_lockfile(&sample_lockfile()), want);
    }

    #[test]
    fn empty_lockfile_ends_after_strategy() {
        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![],
        };
        assert_eq!(
            format_lockfile(&lock),
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n"
        );
    }

    #[test]
    fn optional_fields_omitted_when_absent() {
        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![LockedDep {
            source_id: None,
                declared_version_source: None,
                name: "foo".into(),
                namespace: None,
                identity: None,
                version: "0.0.1".into(),
                src_dir: String::new(),
                requires: vec![],
                provenances: vec![ProvenanceRecord::Local {
                    path: "../foo".into(),
                    origin: "observed".into(),
                }],
                active_flags: vec![],
                dep_decl: None,
                cond_requires: vec![],
                aliases: vec![],
                attestation: None,
            }],
        };
        let text = format_lockfile(&lock);
        assert!(!text.contains("identity"));
        assert!(!text.contains("active_flags"));
        assert!(!text.contains("self_mirrors"));
        // bare `requires` line (no args) is still emitted
        assert!(text.contains("    requires\n"));
    }

    #[test]
    fn kdl_escaping_round_trips() {
        // Every escape class: quote, backslash, and control chars.
        // All control chars U+0000–U+001F must become \u{N} — NO named escapes
        // (\n, \t, \r, \b, \f). This mirrors lockfile.py:_kdl_str exactly
        // (lockfile-schema §2.4 / H3 fix).
        //
        // name must be clean (valid charset [A-Za-z0-9_-]+): LOCK-DEP-NAME-INVALID
        // now rejects any dep name containing chars outside the charset at parse time.
        // src_dir must be clean (empty): LOCK-SRC-DIR-UNSAFE rejects control chars.
        // KDL escaping for control chars is exercised through version/url/requires,
        // which are not validated against a charset restriction.
        let nasty = "a\"b\\c\nd\re\tf\x08g\x0ch\x01i";
        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![LockedDep {
            source_id: None,
                declared_version_source: None,
                name: "safe-name".into(),  // must be clean: LOCK-DEP-NAME-INVALID rejects non-charset chars
                namespace: None,
                identity: None,
                version: nasty.into(),
                src_dir: String::new(), // must be clean: LOCK-SRC-DIR-UNSAFE rejects control chars
                requires: vec![nasty.into()],
                provenances: vec![ProvenanceRecord::Git {
                    url: nasty.into(),
                    ref_spec: None,
                    commit_sha: None,
                    origin: "observed".into(),
                    submodule_shas: vec![],
                }],
                active_flags: vec![],
                dep_decl: None,
                cond_requires: vec![],
                aliases: vec![],
                attestation: None,
            }],
        };
        let text = format_lockfile(&lock);
        // All control chars go through \u{..}, never named escapes.
        assert!(text.contains("\\u{1}"),  "SOH must be \\u{{1}}: {text:?}");
        assert!(text.contains("\\u{8}"),  "BS must be \\u{{8}}: {text:?}");
        assert!(text.contains("\\u{9}"),  "HT must be \\u{{9}}: {text:?}");
        assert!(text.contains("\\u{a}"),  "LF must be \\u{{a}}: {text:?}");
        assert!(text.contains("\\u{c}"),  "FF must be \\u{{c}}: {text:?}");
        assert!(text.contains("\\u{d}"),  "CR must be \\u{{d}}: {text:?}");
        // Named escapes must NOT appear (byte-identity with Python).
        assert!(!text.contains("\\n"),  "must not emit \\n: {text:?}");
        assert!(!text.contains("\\t"),  "must not emit \\t: {text:?}");
        assert!(!text.contains("\\r"),  "must not emit \\r: {text:?}");
        assert!(!text.contains("\\b"),  "must not emit \\b: {text:?}");
        assert!(!text.contains("\\f"),  "must not emit \\f: {text:?}");
        // The emitted text is valid KDL that parses back to the same data.
        let reparsed = parse_lockfile(&text).unwrap();
        assert_eq!(reparsed.deps[0].name, "safe-name");
        assert_eq!(reparsed.deps[0].version, nasty);
        assert_eq!(reparsed.deps[0].src_dir, ""); // src_dir was kept clean
        assert_eq!(reparsed.deps[0].requires, vec![nasty.to_string()]);
    }

    #[test]
    fn kdl_str_control_chars_match_python_newline_and_tab() {
        // H3 regression: \n must emit \u{a}, \t must emit \u{9} (matching
        // lockfile.py:_kdl_str). The previous Rust impl emitted \\n / \\t,
        // breaking byte-identity with Python.
        let with_newline_and_tab = "ref\nwith\ttabs";
        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![LockedDep {
            source_id: None,
                declared_version_source: None,
                name: "foo".into(),
                namespace: None,
                identity: None,
                version: "0.0.1".into(),
                src_dir: String::new(),
                requires: vec![],
                provenances: vec![ProvenanceRecord::Git {
                    url: "https://example.com/foo.git".into(),
                    ref_spec: Some(with_newline_and_tab.into()),
                    commit_sha: None,
                    origin: "observed".into(),
                    submodule_shas: vec![],
                }],
                active_flags: vec![],
                dep_decl: None,
                cond_requires: vec![],
                aliases: vec![],
                attestation: None,
            }],
        };
        let text = format_lockfile(&lock);
        // Must use \u{a} for \n and \u{9} for \t — matching Python's _kdl_str.
        assert!(text.contains("\\u{a}"), "newline must be \\u{{a}}: {text:?}");
        assert!(text.contains("\\u{9}"), "tab must be \\u{{9}}: {text:?}");
        assert!(!text.contains("\\n"),   "must not emit \\n: {text:?}");
        assert!(!text.contains("\\t"),   "must not emit \\t: {text:?}");
        // Round-trip: the emitted KDL must parse back to the original ref.
        let reparsed = parse_lockfile(&text).unwrap();
        let prov = &reparsed.deps[0].provenances[0];
        if let ProvenanceRecord::Git { ref_spec, origin, .. } = prov {
            assert_eq!(ref_spec.as_deref(), Some(with_newline_and_tab));
            assert_eq!(origin, "observed");
        } else {
            panic!("expected git provenance");
        }
    }

    #[test]
    fn parse_format_parse_is_identity() {
        let original = sample_lockfile();
        let text = format_lockfile(&original);
        let reparsed = parse_lockfile(&text).unwrap();
        assert_eq!(reparsed, original);
        // And format is a fixed point: formatting the reparse is byte-identical.
        assert_eq!(format_lockfile(&reparsed), text);
    }

    #[test]
    fn every_provenance_kind_round_trips() {
        let kinds = vec![
            ProvenanceRecord::Tarball {
                url: "https://e/x.tar.gz".into(),
                sha256: Some("abc".into()),
                origin: "observed".into(),
            },
            ProvenanceRecord::Member {
                name: "liba".into(),
                origin: "observed".into(),
            },
            ProvenanceRecord::Oci {
                registry: "r".into(),
                repository: "o/p".into(),
                digest: "sha256:d".into(),
                origin: "observed".into(),
            },
        ];
        for prov in kinds {
            let lock = Lockfile {
                version: 1,
                strategy: "maxver".into(),
                exclude_newer: None,
                deps: vec![LockedDep {
            source_id: None,
                    declared_version_source: None,
                    name: "foo".into(),
                    namespace: None,
                    identity: None,
                    version: "0.0.1".into(),
                    src_dir: String::new(),
                    requires: vec![],
                    provenances: vec![prov.clone()],
                    active_flags: vec![],
                    dep_decl: None,
                    cond_requires: vec![],
                    aliases: vec![],
                    attestation: None,
                }],
            };
            let reparsed = parse_lockfile(&format_lockfile(&lock)).unwrap();
            assert_eq!(reparsed.deps[0].provenances, vec![prov]);
        }
    }

    #[test]
    fn write_lockfile_creates_parents_and_reads_back() {
        let dir = std::env::temp_dir().join("milpa-s5b-write-test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("milpa.lock");
        let written = write_lockfile(&sample_lockfile(), &path).unwrap();
        assert_eq!(written, path);
        let back = load_lockfile(&path).unwrap();
        assert_eq!(back, sample_lockfile());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_lockfile_missing_path_is_not_found() {
        let missing = std::path::Path::new("/nonexistent/milpa.lock.does-not-exist");
        assert_eq!(
            load_lockfile(missing).unwrap_err().code(),
            "LOCK-FILE-NOT-FOUND"
        );
    }

    // --- from_graph (S7c emission glue) ---

    use milpa_types::Version;

    fn rdep(name: &str, prov: ProvenanceRecord, requires: Vec<&str>) -> ResolvedDep {
        ResolvedDep {
            declared_version_source: None,
            source_id: None,
            name: name.into(),
            namespace: None,
            identity: format!("dag-sha256:{}", "0".repeat(63) + "1"),
            version: Version::release(0, 0, 1),
            src_dir: "src".into(),
            requires: requires.into_iter().map(String::from).collect(),
            provenances: vec![prov],
            dep_decl: None,
            cond_requires: vec![],
            aliases: vec![],
            active_flags: vec![],
            attestation: None,
        }
    }

    fn git(url: &str, ref_spec: &str, sha: Option<&str>) -> ProvenanceRecord {
        ProvenanceRecord::Git {
            url: url.into(),
            ref_spec: opt(ref_spec),
            commit_sha: sha.map(String::from),
            origin: "observed".into(),
            submodule_shas: vec![],
        }
    }

    #[test]
    fn from_graph_sorts_deps_by_name_and_requires_lexicographically() {
        // Graph arrives in topological (non-lexicographic) order; from_graph
        // must impose the canonical ordering (§4.4).
        let graph = ResolvedGraph {
            deps: vec![
                rdep("zlib", git("https://e/zlib.git", "main", None), vec![]),
                rdep(
                    "alpha",
                    git("https://e/alpha.git", "main", None),
                    vec!["gamma", "beta"],
                ),
            ],
        };
        let lock = from_graph(&graph, "maxver", None);
        assert_eq!(lock.version, LOCKFILE_SCHEMA_VERSION);
        assert_eq!(lock.strategy, "maxver");
        let names: Vec<&str> = lock.deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "zlib"]);
        // requires sorted lexicographically, not in arrival order.
        assert_eq!(lock.deps[0].requires, vec!["beta", "gamma"]);
    }

    #[test]
    fn from_graph_records_strategy_and_singleton_version() {
        let graph = ResolvedGraph {
            deps: vec![rdep(
                "foo",
                git("https://e/foo.git", "v1", Some("deadbeef")),
                vec![],
            )],
        };
        let lock = from_graph(&graph, "minver", None);
        assert_eq!(lock.strategy, "minver");
        let dep = &lock.deps[0];
        assert_eq!(dep.version, "0.0.1");
        assert!(dep.identity.is_some());
        // Resolver-enrichment fields are emitted empty until the feature work.
        assert!(dep.active_flags.is_empty());
    }

    #[test]
    fn from_graph_carries_each_provenance_record_arm() {
        let graph = ResolvedGraph {
            deps: vec![
                rdep("g", git("https://e/g.git", "main", Some("abc123")), vec![]),
                rdep(
                    "t",
                    ProvenanceRecord::Tarball {
                        url: "https://e/t.tar.gz".into(),
                        sha256: Some("sha256:tar".into()),
                        origin: "observed".into(),
                    },
                    vec![],
                ),
                rdep(
                    "l",
                    ProvenanceRecord::Local {
                        path: "../liba".into(),
                        origin: "observed".into(),
                    },
                    vec![],
                ),
                rdep(
                    "m",
                    ProvenanceRecord::Member {
                        name: "liba".into(),
                        origin: "observed".into(),
                    },
                    vec![],
                ),
                rdep(
                    "o",
                    ProvenanceRecord::Oci {
                        registry: "ghcr.io".into(),
                        repository: "org/pkg".into(),
                        digest: "sha256:dig".into(),
                        origin: "observed".into(),
                    },
                    vec![],
                ),
                rdep(
                    "r",
                    ProvenanceRecord::Root {
                        name: "r".into(),
                        origin: "observed".into(),
                    },
                    vec![],
                ),
            ],
        };
        let lock = from_graph(&graph, "maxver", None);
        let by_name = |n: &str| {
            lock.deps
                .iter()
                .find(|d| d.name == n)
                .unwrap()
                .provenances
                .clone()
        };
        assert_eq!(
            by_name("g"),
            vec![ProvenanceRecord::Git {
                url: "https://e/g.git".into(),
                ref_spec: Some("main".into()),
                commit_sha: Some("abc123".into()),
                origin: "observed".into(),
                submodule_shas: vec![],
            }]
        );
        assert_eq!(
            by_name("t"),
            vec![ProvenanceRecord::Tarball {
                url: "https://e/t.tar.gz".into(),
                sha256: Some("sha256:tar".into()),
                origin: "observed".into(),
            }]
        );
        assert_eq!(
            by_name("l"),
            vec![ProvenanceRecord::Local {
                path: "../liba".into(),
                origin: "observed".into(),
            }]
        );
        assert_eq!(
            by_name("m"),
            vec![ProvenanceRecord::Member {
                name: "liba".into(),
                origin: "observed".into(),
            }]
        );
        assert_eq!(
            by_name("o"),
            vec![ProvenanceRecord::Oci {
                registry: "ghcr.io".into(),
                repository: "org/pkg".into(),
                digest: "sha256:dig".into(),
                origin: "observed".into(),
            }]
        );
        assert_eq!(
            by_name("r"),
            vec![ProvenanceRecord::Root {
                name: "r".into(),
                origin: "observed".into(),
            }]
        );
    }

    #[test]
    fn from_graph_empty_git_ref_becomes_none() {
        let graph = ResolvedGraph {
            deps: vec![rdep("foo", git("https://e/foo.git", "", None), vec![])],
        };
        let lock = from_graph(&graph, "maxver", None);
        assert_eq!(
            lock.deps[0].provenances,
            vec![ProvenanceRecord::Git {
                url: "https://e/foo.git".into(),
                ref_spec: None,
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            }]
        );
    }

    #[test]
    fn verify_against_graph_matches_and_mismatches() {
        let graph = ResolvedGraph {
            deps: vec![rdep(
                "foo",
                git("https://e/foo.git", "v1", Some("c1")),
                vec![],
            )],
        };
        let lock = from_graph(&graph, "maxver", None);
        // A lockfile produced from the graph matches it.
        assert!(verify_against_graph(&lock, &graph).is_ok());

        // A dep missing from the graph diverges.
        let empty = ResolvedGraph { deps: vec![] };
        assert_eq!(
            verify_against_graph(&lock, &empty).unwrap_err().code(),
            "LOCK-GRAPH-MISMATCH"
        );

        // An identity mismatch diverges.
        let mut drifted = lock.clone();
        drifted.deps[0].identity = Some("dag-sha256:different".into());
        assert_eq!(
            verify_against_graph(&drifted, &graph).unwrap_err().code(),
            "LOCK-GRAPH-MISMATCH"
        );
    }

    // -------------------------------------------------------------------------
    // B3 (resolution-semantics RFC §3 Axis B / §6 D-B2): check_locked_drift
    // -------------------------------------------------------------------------

    #[test]
    fn check_locked_drift_matching_graph_passes() {
        let graph = ResolvedGraph {
            deps: vec![rdep("foo", git("https://e/foo.git", "v1", Some("c1")), vec![])],
        };
        let lock = from_graph(&graph, "maxver", None);
        assert!(check_locked_drift(Some(&lock), &graph, None).is_ok());
    }

    #[test]
    fn check_locked_drift_no_prior_lock_raises() {
        let graph = ResolvedGraph {
            deps: vec![rdep("foo", git("https://e/foo.git", "v1", Some("c1")), vec![])],
        };
        assert_eq!(
            check_locked_drift(None, &graph, None).unwrap_err().code(),
            "RES-LOCKED-DRIFT"
        );
    }

    #[test]
    fn check_locked_drift_empty_both_passes() {
        let graph = ResolvedGraph { deps: vec![] };
        let lock = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![] };
        assert!(check_locked_drift(Some(&lock), &graph, None).is_ok());
    }

    #[test]
    fn check_locked_drift_version_relabel_with_unchanged_identity_is_not_drift() {
        // The headline D-B2 case: the one-time Axis-A 0.0.1 -> real-declared-
        // version relabel of an identity-unchanged dep must NOT be reported
        // as drift — only identity + provenance are compared, never `version`.
        let graph = ResolvedGraph {
            deps: vec![rdep("foo", git("https://e/foo.git", "v1", Some("c1")), vec![])],
        };
        let mut lock = from_graph(&graph, "maxver", None);
        lock.deps[0].version = "0.0.1".into();
        lock.deps[0].declared_version_source = None;
        // graph's resolved version (e.g. "1.2.3" post-relabel) differs from
        // the lock's recorded "0.0.1" — must still pass.
        let mut relabeled_graph = graph.clone();
        relabeled_graph.deps[0].version = milpa_types::Version::release(1, 2, 3);
        assert!(check_locked_drift(Some(&lock), &relabeled_graph, None).is_ok());
    }

    #[test]
    fn check_locked_drift_identity_change_raises_naming_the_package() {
        let graph = ResolvedGraph {
            deps: vec![rdep("foo", git("https://e/foo.git", "v1", Some("c1")), vec![])],
        };
        let lock = from_graph(&graph, "maxver", None);
        let mut drifted_graph = graph.clone();
        drifted_graph.deps[0].identity = format!("dag-sha256:{}", "b".repeat(64));
        let err = check_locked_drift(Some(&lock), &drifted_graph, None).unwrap_err();
        assert_eq!(err.code(), "RES-LOCKED-DRIFT");
        assert!(err.message().contains("foo"));
    }

    #[test]
    fn check_locked_drift_provenance_change_with_unchanged_identity_raises() {
        // A different commit_sha — same content identity — IS drift (D-B2:
        // identity + provenance, not identity alone).
        let graph = ResolvedGraph {
            deps: vec![rdep("foo", git("https://e/foo.git", "v1", Some("c1")), vec![])],
        };
        let lock = from_graph(&graph, "maxver", None);
        let mut drifted_graph = graph.clone();
        drifted_graph.deps[0].provenances = vec![git("https://e/foo.git", "v1", Some("c2"))];
        let err = check_locked_drift(Some(&lock), &drifted_graph, None).unwrap_err();
        assert_eq!(err.code(), "RES-LOCKED-DRIFT");
        assert!(err.message().contains("foo"));
    }

    #[test]
    fn check_locked_drift_added_dep_raises() {
        let lock = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![] };
        let graph = ResolvedGraph {
            deps: vec![rdep("foo", git("https://e/foo.git", "v1", Some("c1")), vec![])],
        };
        let err = check_locked_drift(Some(&lock), &graph, None).unwrap_err();
        assert_eq!(err.code(), "RES-LOCKED-DRIFT");
        assert!(err.message().contains("foo"));
    }

    #[test]
    fn check_locked_drift_removed_dep_raises() {
        let graph = ResolvedGraph {
            deps: vec![rdep("foo", git("https://e/foo.git", "v1", Some("c1")), vec![])],
        };
        let lock = from_graph(&graph, "maxver", None);
        let empty = ResolvedGraph { deps: vec![] };
        let err = check_locked_drift(Some(&lock), &empty, None).unwrap_err();
        assert_eq!(err.code(), "RES-LOCKED-DRIFT");
        assert!(err.message().contains("foo"));
    }

    #[test]
    fn check_locked_drift_provenance_order_is_not_significant() {
        // The lockfile's provenances arrive pre-sorted (canonical KDL emit
        // order); the graph's arrive observed-first (unsorted until
        // emission). Comparing raw Vec order would produce false-positive
        // drift — the check must canonicalize both sides first.
        let p_git = git("https://e/foo.git", "v1", Some("c1"));
        let p_declared = ProvenanceRecord::Git {
            url: "https://mirror.e/foo.git".into(),
            ref_spec: opt("v1"),
            commit_sha: None,
            origin: "declared".into(),
            submodule_shas: vec![],
        };
        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![LockedDep {
            source_id: None,
                declared_version_source: None,
                name: "foo".into(),
                namespace: None,
                identity: Some(format!("dag-sha256:{}", "0".repeat(63) + "1")),
                version: "0.0.1".into(),
                src_dir: "src".into(),
                requires: vec![],
                // Canonical order: declared before observed.
                provenances: vec![p_declared.clone(), p_git.clone()],
                active_flags: vec![],
                dep_decl: None,
                cond_requires: vec![],
                aliases: vec![],
                attestation: None,
            }],
        };
        // Graph side: observed-first (unsorted), as the resolver actually builds it.
        let graph = ResolvedGraph {
            deps: vec![rdep("foo", p_git, vec![])],
        };
        let mut graph = graph;
        graph.deps[0].provenances = vec![graph.deps[0].provenances[0].clone(), p_declared];
        assert!(check_locked_drift(Some(&lock), &graph, None).is_ok());
    }

    // -------------------------------------------------------------------------
    // D5 (resolution-semantics RFC §3 Axis D / §6 D-D3): no-silent-drop —
    // a dropped or changed `exclude_newer` is drift too, compared once for
    // the whole lockfile (not per-dep).
    // -------------------------------------------------------------------------

    #[test]
    fn check_locked_drift_dropped_exclude_newer_raises() {
        let ts = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        let graph = ResolvedGraph { deps: vec![] };
        let lock = from_graph(&graph, "maxver", Some(ts));
        // The new resolve's effective exclude_newer is None — a silent drop.
        let err = check_locked_drift(Some(&lock), &graph, None).unwrap_err();
        assert_eq!(err.code(), "RES-LOCKED-DRIFT");
        assert!(err.message().contains("exclude_newer"), "message: {}", err.message());
    }

    #[test]
    fn check_locked_drift_changed_exclude_newer_raises() {
        let ts_old = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        let ts_new = parse_iso8601_timestamp("2027-01-01T00:00:00Z").unwrap();
        let graph = ResolvedGraph { deps: vec![] };
        let lock = from_graph(&graph, "maxver", Some(ts_old));
        let err = check_locked_drift(Some(&lock), &graph, Some(ts_new)).unwrap_err();
        assert_eq!(err.code(), "RES-LOCKED-DRIFT");
    }

    #[test]
    fn check_locked_drift_unchanged_exclude_newer_passes() {
        let ts = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        let graph = ResolvedGraph { deps: vec![] };
        let lock = from_graph(&graph, "maxver", Some(ts));
        assert!(check_locked_drift(Some(&lock), &graph, Some(ts)).is_ok());
    }

    #[test]
    fn check_locked_drift_newly_added_exclude_newer_raises() {
        // The inverse direction: TIGHTENING a bound that wasn't there before
        // is also a real divergence from the committed lock (still surfaced
        // as drift, even though it makes the resolve MORE restrictive — the
        // `--locked` contract is "reproduce exactly what's committed", not
        // "only complain about relaxations").
        let ts = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        let graph = ResolvedGraph { deps: vec![] };
        let lock = from_graph(&graph, "maxver", None);
        let err = check_locked_drift(Some(&lock), &graph, Some(ts)).unwrap_err();
        assert_eq!(err.code(), "RES-LOCKED-DRIFT");
    }

    #[test]
    fn verify_lockfile_against_deps_reports_divergences() {
        let dir = std::env::temp_dir().join("milpa-s13-verify-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![LockedDep {
            source_id: None,
                declared_version_source: None,
                name: "foo".into(),
                namespace: None,
                identity: Some("dag-sha256:00".into()),
                version: "0.0.1".into(),
                src_dir: String::new(),
                requires: vec![],
                provenances: vec![ProvenanceRecord::Local { path: "x".into(), origin: "observed".into() }],
                active_flags: vec![],
                dep_decl: None,
                cond_requires: vec![],
                aliases: vec![],
                attestation: None,
            }],
        };
        // foo is not on disk → "missing" divergence.
        let d = verify_lockfile_against_deps(&lock, &dir);
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("foo") && d[0].contains("missing"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------
    // C-verify: four symlink states + alias verification
    // (RFC rfc-content-addressed-identity.md Phase C §6 item 6 + §6.4)
    // -------------------------------------------------------------------------

    /// Build a minimal LockedDep for verify tests.
    fn make_verify_dep(name: &str, aliases: Vec<String>) -> LockedDep {
        LockedDep {
            source_id: None,
            declared_version_source: None,
            name: name.into(),
            namespace: None,
            identity: Some(VALID_ID.into()),
            version: "1.0.0".into(),
            src_dir: String::new(),
            requires: vec![],
            provenances: vec![ProvenanceRecord::Git {
                url: "https://example.com/x.git".into(),
                ref_spec: None,
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            }],
            active_flags: vec![],
            dep_decl: None,
            cond_requires: vec![],
            aliases,
            attestation: None,
        }
    }

    /// Create a fake CAS store entry dir with one file so compute_content_hash
    /// returns a real (non-empty) hash.
    fn make_store_entry(root: &std::path::Path, tag: &str) -> std::path::PathBuf {
        let entry = root.join("store").join(tag);
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("lib.nim"), format!("# {tag}\n")).unwrap();
        entry
    }

    #[test]
    fn c_verify_pass_symlink_present_and_readable() {
        // State (a): _deps/<name> is a symlink + store entry is readable → no
        // dangling / missing / CAS-STORE-IO-ERROR divergence.
        let dir = std::env::temp_dir().join("milpa-cverify-pass");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();

        let store_entry = make_store_entry(&dir, "foo");
        std::os::unix::fs::symlink(&store_entry, deps_dir.join("foo")).unwrap();

        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![make_verify_dep("foo", vec![])],
        };
        let d = verify_lockfile_against_deps(&lock, &deps_dir);
        // Only possible divergence is identity mismatch (our fake tree won't
        // hash to VALID_ID); no structural errors.
        assert!(
            !d.iter().any(|s| s.contains("dangling")),
            "unexpected dangling: {d:?}"
        );
        assert!(
            !d.iter().any(|s| s.starts_with("foo: missing")),
            "unexpected missing: {d:?}"
        );
        assert!(
            !d.iter().any(|s| s.contains("CAS-STORE-IO-ERROR")),
            "unexpected IO error: {d:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn c_verify_dangling_symlink_distinct_from_missing() {
        // State (b): _deps/<name> is a symlink but the store entry is deleted →
        // divergence says "dangling", NOT "missing from".
        let dir = std::env::temp_dir().join("milpa-cverify-dangling");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();

        let store_entry = make_store_entry(&dir, "foo");
        std::os::unix::fs::symlink(&store_entry, deps_dir.join("foo")).unwrap();
        // Delete the store entry so the symlink dangles.
        std::fs::remove_dir_all(&store_entry).unwrap();

        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![make_verify_dep("foo", vec![])],
        };
        let d = verify_lockfile_against_deps(&lock, &deps_dir);
        assert_eq!(d.len(), 1, "expected exactly 1 divergence: {d:?}");
        assert!(d[0].contains("foo"), "expected 'foo' in divergence: {d:?}");
        assert!(d[0].contains("dangling"), "expected 'dangling': {d:?}");
        // Must NOT look like the "genuinely missing" divergence.
        assert!(
            !d[0].starts_with("foo: missing"),
            "dangling reported as plain-missing: {d:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn c_verify_genuinely_missing_no_entry() {
        // State (d): no _deps/<name> at all → "missing from" divergence.
        let dir = std::env::temp_dir().join("milpa-cverify-genuinely-missing");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();
        // No file, no symlink, no dir at deps_dir/foo

        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![make_verify_dep("foo", vec![])],
        };
        let d = verify_lockfile_against_deps(&lock, &deps_dir);
        assert_eq!(d.len(), 1, "expected exactly 1 divergence: {d:?}");
        assert!(d[0].starts_with("foo: missing"), "expected 'foo: missing': {d:?}");
        assert!(!d[0].contains("dangling"), "got dangling for absent: {d:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn c_verify_dangling_not_reported_as_extra() {
        // A dangling symlink that IS in the lockfile must not appear as "extra".
        let dir = std::env::temp_dir().join("milpa-cverify-dangling-noextra");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();

        let store_entry = make_store_entry(&dir, "foo");
        std::os::unix::fs::symlink(&store_entry, deps_dir.join("foo")).unwrap();
        std::fs::remove_dir_all(&store_entry).unwrap();

        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![make_verify_dep("foo", vec![])],
        };
        let d = verify_lockfile_against_deps(&lock, &deps_dir);
        assert_eq!(d.len(), 1, "expected only 1 divergence (dangling): {d:?}");
        // Must be the dangling divergence, NOT an "extra dep" divergence.
        assert!(d[0].contains("dangling"), "expected dangling divergence: {d:?}");
        assert!(!d[0].contains("extra dep in"), "dangling reported as extra: {d:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Probe whether POSIX file permissions are actually enforced for us.
    /// Returns false when running as root (root bypasses the read bit), in
    /// which case the chmod-000 I/O-error test is a no-op and must be skipped.
    /// stdlib-only — avoids pulling in libc/nix just for geteuid().
    fn perms_enforced() -> bool {
        use std::os::unix::fs::PermissionsExt;
        let probe = std::env::temp_dir()
            .join(format!("milpa-perm-probe-{}", std::process::id()));
        std::fs::write(&probe, b"x").unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o000)).unwrap();
        let blocked = std::fs::read(&probe).is_err();
        // Restore + clean up.
        let _ = std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o644));
        let _ = std::fs::remove_file(&probe);
        blocked
    }

    #[test]
    fn c_verify_store_io_error_classified_correctly() {
        // State (c): symlink resolves but reading the store entry raises a
        // GENUINE I/O error (no mocking) — a chmod-000 regular FILE inside the
        // store entry.  read_dir succeeds, but std::fs::read on the unreadable
        // file returns a PermissionDenied error (the same I/O class as a
        // network mount going offline mid-read).  verify must classify it as
        // CAS-STORE-IO-ERROR, not content-mismatch or dangling.
        use std::os::unix::fs::PermissionsExt;
        if !perms_enforced() {
            // Running as root: POSIX perms are bypassed, the chmod is a no-op.
            eprintln!("skipping c_verify_store_io_error_classified_correctly: perms not enforced (root)");
            return;
        }

        let dir = std::env::temp_dir().join("milpa-cverify-ioerror");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();

        let store_entry = make_store_entry(&dir, "foo");
        let unreadable = store_entry.join("lib.nim");
        std::os::unix::fs::symlink(&store_entry, deps_dir.join("foo")).unwrap();

        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();

        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![make_verify_dep("foo", vec![])],
        };
        let d = verify_lockfile_against_deps(&lock, &deps_dir);

        // Restore the mode so the tmp tree can be cleaned up.
        let _ = std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644));

        assert_eq!(d.len(), 1, "expected exactly 1 divergence: {d:?}");
        assert!(d[0].contains("foo"), "expected 'foo' in divergence: {d:?}");
        assert!(
            d[0].contains("CAS-STORE-IO-ERROR"),
            "expected CAS-STORE-IO-ERROR: {d:?}"
        );
        assert!(!d[0].contains("dangling"), "must not be dangling: {d:?}");
        assert!(
            !d[0].starts_with("foo: missing"),
            "must not be missing: {d:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn c_verify_alias_present_and_correct_no_divergence() {
        // Alias symlink pointing at the same store entry → no alias divergence.
        let dir = std::env::temp_dir().join("milpa-cverify-alias-ok");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();

        let store_entry = make_store_entry(&dir, "foo-store");
        std::os::unix::fs::symlink(&store_entry, deps_dir.join("foo")).unwrap();
        std::os::unix::fs::symlink(&store_entry, deps_dir.join("foo-alias")).unwrap();

        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![make_verify_dep("foo", vec!["foo-alias".into()])],
        };
        let d = verify_lockfile_against_deps(&lock, &deps_dir);
        let alias_divs: Vec<_> = d.iter().filter(|s| s.contains("VERIFY-ALIAS-SYMLINK-MISSING")).collect();
        assert!(alias_divs.is_empty(), "unexpected alias divergence: {d:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn c_verify_alias_absent_reports_verify_alias_symlink_missing() {
        // Missing alias → VERIFY-ALIAS-SYMLINK-MISSING.
        let dir = std::env::temp_dir().join("milpa-cverify-alias-absent");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();

        let store_entry = make_store_entry(&dir, "foo-store");
        std::os::unix::fs::symlink(&store_entry, deps_dir.join("foo")).unwrap();
        // alias NOT created

        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![make_verify_dep("foo", vec!["foo-alias".into()])],
        };
        let d = verify_lockfile_against_deps(&lock, &deps_dir);
        let alias_divs: Vec<_> = d.iter().filter(|s| s.contains("VERIFY-ALIAS-SYMLINK-MISSING")).collect();
        assert_eq!(alias_divs.len(), 1, "expected 1 alias divergence: {d:?}");
        assert!(alias_divs[0].contains("foo-alias"), "expected 'foo-alias': {d:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn c_verify_alias_wrong_target_reports_verify_alias_symlink_missing() {
        // Alias points at a different store entry → VERIFY-ALIAS-SYMLINK-MISSING.
        let dir = std::env::temp_dir().join("milpa-cverify-alias-wrong");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();

        let store_foo = make_store_entry(&dir, "foo-store");
        let store_other = make_store_entry(&dir, "other-store");
        std::os::unix::fs::symlink(&store_foo, deps_dir.join("foo")).unwrap();
        std::os::unix::fs::symlink(&store_other, deps_dir.join("foo-alias")).unwrap();

        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![make_verify_dep("foo", vec!["foo-alias".into()])],
        };
        let d = verify_lockfile_against_deps(&lock, &deps_dir);
        let alias_divs: Vec<_> = d.iter().filter(|s| s.contains("VERIFY-ALIAS-SYMLINK-MISSING")).collect();
        assert_eq!(alias_divs.len(), 1, "expected 1 alias divergence: {d:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn c_verify_alias_not_reported_as_extra() {
        // Alias symlinks must NOT appear as extra-dep divergences.
        let dir = std::env::temp_dir().join("milpa-cverify-alias-noextra");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();

        let store_entry = make_store_entry(&dir, "foo-store");
        std::os::unix::fs::symlink(&store_entry, deps_dir.join("foo")).unwrap();
        std::os::unix::fs::symlink(&store_entry, deps_dir.join("foo-alias")).unwrap();

        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![make_verify_dep("foo", vec!["foo-alias".into()])],
        };
        let d = verify_lockfile_against_deps(&lock, &deps_dir);
        let extra_divs: Vec<_> = d.iter().filter(|s| s.contains("extra")).collect();
        assert!(extra_divs.is_empty(), "alias reported as extra: {d:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn c_verify_dangling_alias_reports_verify_alias_symlink_missing() {
        // Dangling alias → VERIFY-ALIAS-SYMLINK-MISSING.
        let dir = std::env::temp_dir().join("milpa-cverify-alias-dangling");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();

        let store_entry = make_store_entry(&dir, "foo-store");
        let alias_target = make_store_entry(&dir, "alias-store");
        std::os::unix::fs::symlink(&store_entry, deps_dir.join("foo")).unwrap();
        std::os::unix::fs::symlink(&alias_target, deps_dir.join("foo-alias")).unwrap();
        std::fs::remove_dir_all(&alias_target).unwrap(); // make alias dangle

        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![make_verify_dep("foo", vec!["foo-alias".into()])],
        };
        let d = verify_lockfile_against_deps(&lock, &deps_dir);
        let alias_divs: Vec<_> = d.iter().filter(|s| s.contains("VERIFY-ALIAS-SYMLINK-MISSING")).collect();
        assert_eq!(alias_divs.len(), 1, "expected alias divergence: {d:?}");
        assert!(alias_divs[0].contains("foo-alias"), "expected 'foo-alias': {d:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------
    // D-verify-note guard tests
    // (RFC rfc-content-addressed-identity.md Phase D §7;
    //  lockfile-schema.md §6.2 NORMATIVE: verification checks identity ONLY)
    // -------------------------------------------------------------------------

    /// Build a LockedDep with multiple provenances (observed + declared) to guard
    /// that verify passes based on identity alone and ignores provenance metadata.
    fn make_verify_dep_multi_prov(name: &str, identity: &str) -> LockedDep {
        LockedDep {
            source_id: None,
            declared_version_source: None,
            name: name.into(),
            namespace: None,
            identity: Some(identity.into()),
            version: "1.0.0".into(),
            src_dir: String::new(),
            requires: vec![],
            provenances: vec![
                ProvenanceRecord::Git {
                    url: "https://github.com/example/foo.git".into(),
                    ref_spec: Some("main".into()),
                    commit_sha: Some("deadbeef1234567890deadbeef1234567890dead".into()),
                    origin: "observed".into(),
                    submodule_shas: vec![],
                },
                ProvenanceRecord::Git {
                    url: "https://mirror.example.com/foo-mirror.git".into(),
                    ref_spec: None,
                    commit_sha: None,
                    origin: "declared".into(),
                    submodule_shas: vec![],
                },
            ],
            active_flags: vec![],
            dep_decl: None,
            cond_requires: vec![],
            aliases: vec![],
            attestation: None,
        }
    }

    #[test]
    fn d_verify_note_passes_on_identity_match_regardless_of_provenance() {
        // D-verify-note: a dep with multiple provenances (observed + declared
        // mirror) passes verify when bytes match the locked identity.
        // Provenance count / kind / origin must NOT cause a false divergence.
        use std::io::Write;

        let dir = std::env::temp_dir()
            .join(format!("milpa-d-verify-note-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();

        // Create a real dep directory and compute its actual identity.
        let dep_dir = deps_dir.join("foo");
        std::fs::create_dir_all(&dep_dir).unwrap();
        let mut f = std::fs::File::create(dep_dir.join("lib.nim")).unwrap();
        f.write_all(b"# foo\n").unwrap();
        drop(f);

        let actual_identity = crate::identity::compute_content_hash(&dep_dir).unwrap();
        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![make_verify_dep_multi_prov("foo", &actual_identity)],
        };
        let d = verify_lockfile_against_deps(&lock, &deps_dir);
        assert!(
            d.is_empty(),
            "verify must pass when bytes match identity, \
             regardless of provenance count or origin; divergences: {d:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn d_verify_note_fails_on_identity_mismatch_not_provenance() {
        // D-verify-note: tampering the bytes causes an identity-mismatch divergence.
        // The divergence must be about identity, not any provenance field.
        use std::io::Write;

        let dir = std::env::temp_dir()
            .join(format!("milpa-d-verify-note-mismatch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();

        let dep_dir = deps_dir.join("foo");
        std::fs::create_dir_all(&dep_dir).unwrap();
        let mut f = std::fs::File::create(dep_dir.join("lib.nim")).unwrap();
        f.write_all(b"# foo\n").unwrap();
        drop(f);

        // Lock to a WRONG identity (simulating tampered bytes).
        let wrong_identity = format!("dag-sha256:{}", "a".repeat(64));
        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![make_verify_dep_multi_prov("foo", &wrong_identity)],
        };
        let d = verify_lockfile_against_deps(&lock, &deps_dir);
        assert_eq!(d.len(), 1, "expected exactly one divergence: {d:?}");
        assert!(
            d[0].contains("identity mismatch"),
            "divergence must be about identity, not provenance: {:?}",
            d[0]
        );
        // Provenance fields must not appear in the divergence message.
        for field in &["url", "commit_sha", "origin", "ref", "kind", "provenance"] {
            assert!(
                !d[0].contains(field),
                "divergence must not mention provenance field {field:?}: {:?}",
                d[0]
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn d_verify_note_declared_origin_provenance_does_not_fail_verify() {
        // D-verify-note: a dep with only a 'declared' origin provenance passes
        // verify when bytes match — 'declared' vs 'observed' is irrelevant.
        use std::io::Write;

        let dir = std::env::temp_dir()
            .join(format!("milpa-d-verify-note-declared-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();

        let dep_dir = deps_dir.join("foo");
        std::fs::create_dir_all(&dep_dir).unwrap();
        let mut f = std::fs::File::create(dep_dir.join("lib.nim")).unwrap();
        f.write_all(b"# declared-origin\n").unwrap();
        drop(f);

        let actual_identity = crate::identity::compute_content_hash(&dep_dir).unwrap();
        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![LockedDep {
            source_id: None,
                declared_version_source: None,
                name: "foo".into(),
                namespace: None,
                identity: Some(actual_identity),
                version: "1.0.0".into(),
                src_dir: String::new(),
                requires: vec![],
                provenances: vec![ProvenanceRecord::Git {
                    url: "https://mirror.example.com/foo.git".into(),
                    ref_spec: None,
                    commit_sha: None,
                    origin: "declared".into(),  // only declared, never observed
                    submodule_shas: vec![],
                }],
                active_flags: vec![],
                dep_decl: None,
                cond_requires: vec![],
                aliases: vec![],
                attestation: None,
            }],
        };
        let d = verify_lockfile_against_deps(&lock, &deps_dir);
        assert!(
            d.is_empty(),
            "verify must pass based on identity alone; 'declared' origin must not fail: {d:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_graph_output_round_trips_through_format_and_parse() {
        let graph = ResolvedGraph {
            deps: vec![
                rdep(
                    "beta",
                    git("https://e/beta.git", "v2", Some("c2")),
                    vec!["alpha"],
                ),
                rdep(
                    "alpha",
                    git("https://e/alpha.git", "v1", Some("c1")),
                    vec![],
                ),
            ],
        };
        let lock = from_graph(&graph, "maxver", None);
        let text = format_lockfile(&lock);
        let reparsed = parse_lockfile(&text).unwrap();
        assert_eq!(reparsed, lock);
        // Canonical: deps sorted, so alpha precedes beta in the emitted text.
        assert!(text.find("dep \"alpha\"").unwrap() < text.find("dep \"beta\"").unwrap());
    }

    // -------------------------------------------------------------------------
    // S4 — CondRequire data model + formatter + parser + round-trip
    // (RFC rfc-conditional-requires.md §3.4 / §3.4.1 / §3.4.2)
    // -------------------------------------------------------------------------

    fn make_locked(cond_requires: Vec<milpa_types::CondRequire>) -> LockedDep {
        LockedDep {
            source_id: None,
            declared_version_source: None,
            name: "qux".into(),
            namespace: None,
            identity: Some(VALID_ID.into()),
            version: "1.0.0".into(),
            src_dir: "src".into(),
            requires: vec!["bar".into(), "extra".into()],
            provenances: vec![ProvenanceRecord::Git {
                url: "https://example.com/qux.git".into(),
                ref_spec: None,
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            }],
            active_flags: vec![],
            dep_decl: None,
            cond_requires,
            aliases: vec![],
            attestation: None,
        }
    }

    fn pred(name: &str, value: &str, negated: bool) -> milpa_types::Predicate {
        milpa_types::Predicate {
            name: name.into(),
            values: vec![value.into()],
            negated,
        }
    }

    fn cr(name: &str, predicates: Vec<milpa_types::Predicate>) -> milpa_types::CondRequire {
        milpa_types::CondRequire {
            name: name.into(),
            predicates,
        }
    }

    #[test]
    fn s4_no_cond_requires_emits_nothing_new() {
        let dep = make_locked(vec![]);
        let lf = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![dep],
        };
        let text = format_lockfile(&lf);
        assert!(!text.contains("cond-require"));
        // requires line unchanged
        assert!(text.contains("    requires \"bar\" \"extra\""));
    }

    #[test]
    fn s4_single_predicate_inline_not_negated() {
        let dep = make_locked(vec![cr("extra", vec![pred("platform", "linux", false)])]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(text.contains("    cond-require \"extra\" platform=\"linux\""), "got:\n{text}");
    }

    #[test]
    fn s4_single_predicate_inline_negated() {
        let dep = make_locked(vec![cr("extra", vec![pred("platform", "linux", true)])]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(text.contains("    cond-require \"extra\" platform=(not)\"linux\""), "got:\n{text}");
    }

    #[test]
    fn s4_multi_predicate_block_form_byte_exact() {
        // Pinned canonical block form per RFC §3.4.1.
        let dep = make_locked(vec![cr(
            "macstuff",
            vec![
                pred("platform", "macosx", false),
                pred("platform", "linux", true),
            ],
        )]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        let expected_block = "    cond-require \"macstuff\" {\n        when platform=\"macosx\"\n        when platform=(not)\"linux\"\n    }";
        assert!(text.contains(expected_block), "got:\n{text}");
    }

    #[test]
    fn s4_cond_require_after_requires_line() {
        let dep = make_locked(vec![cr("extra", vec![pred("platform", "linux", false)])]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        let req_pos = text.find("    requires \"bar\" \"extra\"").unwrap();
        let cr_pos = text.find("    cond-require \"extra\"").unwrap();
        assert!(cr_pos > req_pos);
    }

    #[test]
    fn s4_parse_inline_not_negated() {
        let sample = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\
             \n\
             dep \"qux\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"1.0.0\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires \"bar\" \"extra\"\n\
             \x20   cond-require \"extra\" platform=\"linux\"\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/qux.git\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        let dep = &lf.deps[0];
        assert_eq!(dep.cond_requires.len(), 1);
        let cr = &dep.cond_requires[0];
        assert_eq!(cr.name, "extra");
        assert_eq!(cr.predicates.len(), 1);
        assert_eq!(cr.predicates[0].name, "platform");
        assert_eq!(cr.predicates[0].values, vec!["linux".to_string()]);
        assert!(!cr.predicates[0].negated);
    }

    #[test]
    fn s4_parse_inline_negated() {
        let sample = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\
             \n\
             dep \"qux\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"1.0.0\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires \"bar\" \"extra\"\n\
             \x20   cond-require \"extra\" platform=(not)\"linux\"\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/qux.git\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        assert!(lf.deps[0].cond_requires[0].predicates[0].negated);
    }

    #[test]
    fn s4_parse_block_multi_clause() {
        let sample = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\
             \n\
             dep \"qux\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"1.0.0\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires \"bar\" \"macstuff\"\n\
             \x20   cond-require \"macstuff\" {{\n\
             \x20       when platform=\"macosx\"\n\
             \x20       when platform=(not)\"linux\"\n\
             \x20   }}\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/qux.git\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        let cr = &lf.deps[0].cond_requires[0];
        assert_eq!(cr.name, "macstuff");
        assert_eq!(cr.predicates.len(), 2);
        assert_eq!(cr.predicates[0], milpa_types::Predicate { name: "platform".into(), values: vec!["macosx".into()], negated: false });
        assert_eq!(cr.predicates[1], milpa_types::Predicate { name: "platform".into(), values: vec!["linux".into()], negated: true });
    }

    #[test]
    fn s4_round_trip_inline_single() {
        let dep = make_locked(vec![cr("extra", vec![pred("platform", "linux", false)])]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let reparsed = parse_lockfile(&format_lockfile(&lf)).unwrap();
        assert_eq!(reparsed.deps[0].cond_requires, lf.deps[0].cond_requires);
    }

    #[test]
    fn s4_round_trip_negated() {
        let dep = make_locked(vec![cr("extra", vec![pred("platform", "linux", true)])]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let reparsed = parse_lockfile(&format_lockfile(&lf)).unwrap();
        assert!(reparsed.deps[0].cond_requires[0].predicates[0].negated);
    }

    #[test]
    fn s4_round_trip_block_multi() {
        let dep = make_locked(vec![cr(
            "macstuff",
            vec![
                pred("platform", "macosx", false),
                pred("platform", "linux", true),
            ],
        )]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let reparsed = parse_lockfile(&format_lockfile(&lf)).unwrap();
        assert_eq!(reparsed.deps[0].cond_requires, lf.deps[0].cond_requires);
    }

    #[test]
    fn s4_format_parse_format_identity_inline() {
        // format(parse(text)) == text for the pinned canonical inline sample.
        let sample = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\
             \n\
             dep \"qux\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"1.0.0\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires \"bar\" \"extra\"\n\
             \x20   cond-require \"extra\" platform=\"linux\"\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/qux.git\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        assert_eq!(format_lockfile(&lf), sample);
    }

    #[test]
    fn s4_format_parse_format_identity_block() {
        // format(parse(text)) == text for the pinned canonical block sample.
        let sample = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\
             \n\
             dep \"qux\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"1.0.0\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires \"bar\" \"macstuff\"\n\
             \x20   cond-require \"macstuff\" {{\n\
             \x20       when platform=\"macosx\"\n\
             \x20       when platform=(not)\"linux\"\n\
             \x20   }}\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/qux.git\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        assert_eq!(format_lockfile(&lf), sample);
    }

    #[test]
    fn s4_requires_line_unchanged_with_cond() {
        // requires line must be byte-identical with or without cond_requires.
        let dep_no_cond = make_locked(vec![]);
        let dep_with_cond = make_locked(vec![cr("extra", vec![pred("platform", "linux", false)])]);
        let text_no = format_lockfile(&Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep_no_cond] });
        let text_with = format_lockfile(&Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep_with_cond] });
        assert!(text_no.contains("    requires \"bar\" \"extra\""));
        assert!(text_with.contains("    requires \"bar\" \"extra\""));
    }

    // -------------------------------------------------------------------------
    // M1 — predicate name whitelist on parse
    // -------------------------------------------------------------------------

    #[test]
    fn m1_unknown_predicate_key_dropped_inline() {
        // A crafted cond-require with an unknown key must be dropped (the whole
        // predicate is dropped; if it was the only predicate, the CondRequire is
        // None → not appended).
        let sample = format!(
            "version 1\n\
             strategy \"maxver\"\n\
             dep \"foo\" {{\n\
             \x20   version \"0.0.1\"\n\
             \x20   src_dir \"\"\n\
             \x20   requires\n\
             \x20   cond-require \"bar\" evilkey=\"value\"\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"local\"\n\
             \x20       path \"../foo\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        // evilkey is outside the whitelist → predicate dropped → cond_requires empty
        assert!(
            lf.deps[0].cond_requires.is_empty(),
            "unknown predicate key must be dropped: {:?}",
            lf.deps[0].cond_requires
        );
    }

    #[test]
    fn m1_unknown_predicate_key_dropped_block_form() {
        // Block-form when-child with an unknown key is also dropped.
        let sample = format!(
            "version 1\n\
             strategy \"maxver\"\n\
             dep \"foo\" {{\n\
             \x20   version \"0.0.1\"\n\
             \x20   src_dir \"\"\n\
             \x20   requires\n\
             \x20   cond-require \"bar\" {{\n\
             \x20       when evilkey=\"value\"\n\
             \x20   }}\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"local\"\n\
             \x20       path \"../foo\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        assert!(
            lf.deps[0].cond_requires.is_empty(),
            "unknown predicate key in block form must be dropped: {:?}",
            lf.deps[0].cond_requires
        );
    }

    #[test]
    fn m1_known_predicate_key_kept() {
        // A cond-require with a known key (platform) must be accepted.
        let sample = format!(
            "version 1\n\
             strategy \"maxver\"\n\
             dep \"foo\" {{\n\
             \x20   version \"0.0.1\"\n\
             \x20   src_dir \"\"\n\
             \x20   requires\n\
             \x20   cond-require \"bar\" platform=\"linux\"\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"local\"\n\
             \x20       path \"../foo\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        assert_eq!(lf.deps[0].cond_requires.len(), 1);
        assert_eq!(lf.deps[0].cond_requires[0].predicates[0].name, "platform");
    }

    // -------------------------------------------------------------------------
    // M7 — multiple cond-require records emit in deterministic sorted order
    // -------------------------------------------------------------------------

    #[test]
    fn m7_multiple_cond_requires_sorted_by_name() {
        // Mirrors test_multiple_cond_requires_sorted_by_name in Python.
        // Insert in reverse order (zlib before asm) — emit must be sorted (asm before zlib).
        let cr_zlib = cr("zlib", vec![pred("platform", "linux", false)]);
        let cr_asm  = cr("asm",  vec![pred("arch", "amd64", false)]);
        let dep = make_locked(vec![cr_zlib, cr_asm]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        let asm_pos  = text.find("cond-require \"asm\"").expect("asm not found");
        let zlib_pos = text.find("cond-require \"zlib\"").expect("zlib not found");
        assert!(asm_pos < zlib_pos, "asm must precede zlib (sorted by name):\n{text}");
    }

    #[test]
    fn m7_same_name_two_entries_sorted_by_predicate_string() {
        // Same name (C1 fix): two entries for "foo" — one platform=linux, one
        // platform=macosx.  The (name, pred-string) total order must be stable
        // regardless of insertion order.
        let cr_mac   = cr("foo", vec![pred("platform", "macosx", false)]);
        let cr_linux = cr("foo", vec![pred("platform", "linux",  false)]);
        let dep1 = make_locked(vec![cr_mac.clone(), cr_linux.clone()]);
        let dep2 = make_locked(vec![cr_linux, cr_mac]);
        let text1 = format_lockfile(&Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep1] });
        let text2 = format_lockfile(&Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep2] });
        assert_eq!(text1, text2, "insertion-order must not affect output");
    }

    // -------------------------------------------------------------------------
    // M7 — malformed cond-require: robust parse, no panic
    // -------------------------------------------------------------------------

    #[test]
    fn m7_malformed_no_name_arg() {
        // cond-require node with no positional arg → None → not appended.
        let sample = format!(
            "version 1\n\
             strategy \"maxver\"\n\
             dep \"foo\" {{\n\
             \x20   version \"0.0.1\"\n\
             \x20   src_dir \"\"\n\
             \x20   requires\n\
             \x20   cond-require platform=\"linux\"\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"local\"\n\
             \x20       path \"../foo\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        // No name arg → the whole cond-require is skipped gracefully.
        assert!(lf.deps[0].cond_requires.is_empty());
    }

    #[test]
    fn m7_malformed_block_non_when_child_skipped() {
        // A block child that is NOT "when" must be silently skipped (forward compat).
        let sample = format!(
            "version 1\n\
             strategy \"maxver\"\n\
             dep \"foo\" {{\n\
             \x20   version \"0.0.1\"\n\
             \x20   src_dir \"\"\n\
             \x20   requires\n\
             \x20   cond-require \"bar\" {{\n\
             \x20       unknown-child platform=\"linux\"\n\
             \x20       when platform=\"macosx\"\n\
             \x20   }}\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"local\"\n\
             \x20       path \"../foo\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        // unknown-child skipped; when platform=macosx accepted.
        assert_eq!(lf.deps[0].cond_requires.len(), 1);
        assert_eq!(lf.deps[0].cond_requires[0].predicates.len(), 1);
        assert_eq!(lf.deps[0].cond_requires[0].predicates[0].name, "platform");
        assert_eq!(lf.deps[0].cond_requires[0].predicates[0].values, vec!["macosx"]);
    }

    #[test]
    fn m7_malformed_when_child_with_no_props_yields_no_predicate() {
        // A "when" child with no recognised props → empty predicates → CondRequire is None.
        let sample = format!(
            "version 1\n\
             strategy \"maxver\"\n\
             dep \"foo\" {{\n\
             \x20   version \"0.0.1\"\n\
             \x20   src_dir \"\"\n\
             \x20   requires\n\
             \x20   cond-require \"bar\" {{\n\
             \x20       when\n\
             \x20   }}\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"local\"\n\
             \x20       path \"../foo\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        // No predicates → None → not appended.
        assert!(lf.deps[0].cond_requires.is_empty());
    }

    // -------------------------------------------------------------------------
    // Phase B — aliases field (lockfile-schema §3.8)
    // -------------------------------------------------------------------------

    fn make_locked_with_aliases(aliases: Vec<String>) -> LockedDep {
        LockedDep {
            source_id: None,
            declared_version_source: None,
            name: "foo".into(),
            namespace: None,
            identity: Some(VALID_ID.into()),
            version: "1.0.0".into(),
            src_dir: "src".into(),
            requires: vec![],
            provenances: vec![ProvenanceRecord::Git {
                url: "https://example.com/foo.git".into(),
                ref_spec: None,
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            }],
            active_flags: vec![],
            dep_decl: None,
            cond_requires: vec![],
            aliases,
            attestation: None,
        }
    }

    #[test]
    fn aliases_empty_omitted_from_output() {
        let dep = make_locked_with_aliases(vec![]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(!text.contains("aliases"), "expected no aliases line: {text:?}");
    }

    #[test]
    fn aliases_emitted_when_non_empty() {
        let dep = make_locked_with_aliases(vec!["bar".into(), "baz".into()]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(text.contains("    aliases \"bar\" \"baz\""), "got:\n{text}");
    }

    #[test]
    fn aliases_emitted_lex_sorted() {
        // Constructed in non-sorted order; emitter must sort.
        let dep = make_locked_with_aliases(vec!["zebra".into(), "alpha".into(), "mango".into()]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(text.contains("    aliases \"alpha\" \"mango\" \"zebra\""), "got:\n{text}");
    }

    #[test]
    fn aliases_position_after_cond_requires_before_active_flags() {
        // Field order: requires → cond-require* → aliases → active_flags
        let dep = LockedDep {
            source_id: None,
            declared_version_source: None,
            name: "foo".into(),
            namespace: None,
            identity: Some(VALID_ID.into()),
            version: "1.0.0".into(),
            src_dir: "src".into(),
            requires: vec!["bar".into()],
            provenances: vec![ProvenanceRecord::Git {
                url: "https://example.com/foo.git".into(),
                ref_spec: None,
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            }],
            active_flags: vec!["ssl".into()],
            dep_decl: None,
            cond_requires: vec![cr("bar", vec![pred("platform", "linux", false)])],
            aliases: vec!["baz".into()],
            attestation: None,
        };
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        let cr_pos = text.find("    cond-require \"bar\"").unwrap();
        let aliases_pos = text.find("    aliases \"baz\"").unwrap();
        let flags_pos = text.find("    active_flags \"ssl\"").unwrap();
        assert!(cr_pos < aliases_pos, "cond-require must precede aliases: {text:?}");
        assert!(aliases_pos < flags_pos, "aliases must precede active_flags: {text:?}");
    }

    #[test]
    fn aliases_round_trips_parse_format_parse() {
        let dep = make_locked_with_aliases(vec!["alpha".into(), "beta".into()]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text1 = format_lockfile(&lf);
        let lf2 = parse_lockfile(&text1).unwrap();
        let text2 = format_lockfile(&lf2);
        assert_eq!(text1, text2, "round-trip not byte-identical");
        assert_eq!(lf2.deps[0].aliases, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn aliases_sorted_on_parse() {
        // Parser must sort aliases lexicographically.
        let sample = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\
             \n\
             dep \"foo\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"1.0.0\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires\n\
             \x20   aliases \"zebra\" \"alpha\"\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/foo.git\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        assert_eq!(lf.deps[0].aliases, vec!["alpha".to_string(), "zebra".to_string()]);
    }

    // -----------------------------------------------------------------------
    // S3a-req (RFC origin-as-identity.md §4.7/B3) — format_dep_origin /
    // collapse_notes: the alias-collapse note visible on `milpa show` / the
    // resolve trace. Mirrors Python's TestFormatDepOrigin/TestCollapseNotes.
    // -----------------------------------------------------------------------

    #[test]
    fn format_dep_origin_git_provenance() {
        let dep = make_locked_with_aliases(vec![]);
        assert_eq!(format_dep_origin(&dep), "git+https://example.com/foo.git");
    }

    #[test]
    fn format_dep_origin_tarball_provenance() {
        let mut dep = make_locked_with_aliases(vec![]);
        dep.provenances = vec![ProvenanceRecord::Tarball {
            url: "https://example.com/foo.tar.gz".into(),
            sha256: None,
            origin: "observed".into(),
        }];
        assert_eq!(format_dep_origin(&dep), "tar+https://example.com/foo.tar.gz");
    }

    #[test]
    fn format_dep_origin_oci_provenance() {
        let mut dep = make_locked_with_aliases(vec![]);
        dep.provenances = vec![ProvenanceRecord::Oci {
            registry: "ghcr.io".into(),
            repository: "acme/foo".into(),
            digest: format!("sha256:{}", "a".repeat(64)),
            origin: "observed".into(),
        }];
        assert_eq!(format_dep_origin(&dep), "oci+ghcr.io/acme/foo");
    }

    #[test]
    fn format_dep_origin_prefers_observed_over_declared() {
        let mut dep = make_locked_with_aliases(vec![]);
        dep.provenances = vec![
            ProvenanceRecord::Git {
                url: "https://mirror.example.com/foo.git".into(),
                ref_spec: None,
                commit_sha: None,
                origin: "declared".into(),
                submodule_shas: vec![],
            },
            ProvenanceRecord::Git {
                url: "https://example.com/foo.git".into(),
                ref_spec: None,
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            },
        ];
        assert_eq!(format_dep_origin(&dep), "git+https://example.com/foo.git");
    }

    #[test]
    fn format_dep_origin_no_provenance_falls_back_to_name() {
        let mut dep = make_locked_with_aliases(vec![]);
        dep.provenances = vec![];
        assert_eq!(format_dep_origin(&dep), "foo");
    }

    #[test]
    fn collapse_notes_empty_when_no_aliases() {
        let dep = make_locked_with_aliases(vec![]);
        assert!(collapse_notes(&[dep]).is_empty());
    }

    #[test]
    fn collapse_notes_one_note_per_alias() {
        let dep = make_locked_with_aliases(vec!["bar".into(), "baz".into()]);
        let notes = collapse_notes(&[dep]);
        assert_eq!(
            notes,
            vec![
                "'bar' and 'foo' both name git+https://example.com/foo.git; used 'foo'"
                    .to_string(),
                "'baz' and 'foo' both name git+https://example.com/foo.git; used 'foo'"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn collapse_notes_deterministic_order_across_deps() {
        // Notes are ordered by canonical dep name, regardless of input order.
        let mut dep_z = make_locked_with_aliases(vec!["zzz-alias".into()]);
        dep_z.name = "zzz".into();
        let mut dep_a = make_locked_with_aliases(vec!["aaa-alias".into()]);
        dep_a.name = "aaa".into();
        let notes = collapse_notes(&[dep_z, dep_a]);
        assert!(notes[0].starts_with("'aaa-alias'"), "got: {notes:?}");
        assert!(notes[1].starts_with("'zzz-alias'"), "got: {notes:?}");
    }

    // -----------------------------------------------------------------------
    // S6 (rfc-origin-as-identity.md §4.6/§10) — check_directory_slot_collisions.
    // Mirrors Python's test_s6_import_slot_collision.py.
    // -----------------------------------------------------------------------

    fn git_source(url: &str) -> milpa_types::SourceId {
        milpa_types::SourceId::Fetchable(milpa_types::FetchableOrigin::Git {
            url: url.into(),
            subpath: None,
        })
    }

    fn s6_dep(name: &str, identity: &str, source_id: Option<milpa_types::SourceId>, url: &str) -> ResolvedDep {
        let mut dep = rdep(name, git(url, "main", None), vec![]);
        dep.identity = identity.into();
        dep.source_id = source_id;
        dep
    }

    #[test]
    fn s6_raises_on_different_content_same_slot() {
        let a = s6_dep("foo", &format!("sha256:{}", "a".repeat(64)), Some(git_source("https://example.com/a.git")), "https://example.com/a.git");
        let b = s6_dep("foo", &format!("sha256:{}", "b".repeat(64)), Some(git_source("https://example.com/b.git")), "https://example.com/b.git");
        let graph = ResolvedGraph { deps: vec![a, b] };

        let err = check_directory_slot_collisions(&graph).unwrap_err();
        assert_eq!(err.code(), "RES-IMPORT-COLLISION");
        assert!(err.message().contains("example.com/a"));
        assert!(err.message().contains("example.com/b"));
        assert!(err.message().contains("symbol"), "must carry the directory-slot-only caveat: {}", err.message());
    }

    #[test]
    fn s6_content_hash_short_circuit_no_raise() {
        // Same slot, distinct source-ids, SAME identity — fixture-458's shape.
        let same_id = format!("sha256:{}", "a".repeat(64));
        let a = s6_dep("chronos", &same_id, Some(git_source("https://example.com/chronos.git")), "https://example.com/chronos.git");
        let b = s6_dep("chronos", &same_id, Some(git_source("https://example.com/chronos-fork.git")), "https://example.com/chronos-fork.git");
        let graph = ResolvedGraph { deps: vec![a, b] };

        assert!(check_directory_slot_collisions(&graph).is_ok());
    }

    #[test]
    fn s6_empty_identity_is_not_proven_equal() {
        // An empty identity (frozen.rs's unwrap_or_default() sentinel for a
        // missing LockedDep.identity) can never be proven equal to another
        // dep's identity — the short-circuit must not fire on "both unknown".
        let a = s6_dep("foo", "", Some(git_source("https://example.com/a.git")), "https://example.com/a.git");
        let b = s6_dep("foo", "", Some(git_source("https://example.com/b.git")), "https://example.com/b.git");
        let graph = ResolvedGraph { deps: vec![a, b] };

        let err = check_directory_slot_collisions(&graph).unwrap_err();
        assert_eq!(err.code(), "RES-IMPORT-COLLISION");
    }

    #[test]
    fn s6_ordinary_graph_no_raise() {
        let a = s6_dep("foo", &format!("sha256:{}", "a".repeat(64)), None, "https://example.com/a.git");
        let b = s6_dep("bar", &format!("sha256:{}", "b".repeat(64)), None, "https://example.com/b.git");
        let graph = ResolvedGraph { deps: vec![a, b] };

        assert!(check_directory_slot_collisions(&graph).is_ok());
    }

    #[test]
    fn s6_namespace_disambiguates_bare_name_collision() {
        // Two deps named "baz" in DIFFERENT namespaces project to distinct
        // "_deps/@ns/baz" slots (dep_dir_name's own collision-free design).
        let mut a = s6_dep("baz", &format!("sha256:{}", "a".repeat(64)), None, "https://example.com/a.git");
        a.namespace = Some("ns1".into());
        let mut b = s6_dep("baz", &format!("sha256:{}", "b".repeat(64)), None, "https://example.com/b.git");
        b.namespace = Some("ns2".into());
        let graph = ResolvedGraph { deps: vec![a, b] };

        assert!(check_directory_slot_collisions(&graph).is_ok());
    }

    #[test]
    fn s6_falls_back_to_format_dep_origin_when_source_id_absent() {
        // Frozen path (pre a later slice): source_id is None, so the label
        // must fall back to format_dep_origin (provenance-derived) rather
        // than panicking or omitting the origin from the message.
        let a = s6_dep("foo", &format!("sha256:{}", "a".repeat(64)), None, "https://example.com/a.git");
        let b = s6_dep("foo", &format!("sha256:{}", "b".repeat(64)), None, "https://example.com/b.git");
        let graph = ResolvedGraph { deps: vec![a, b] };

        let err = check_directory_slot_collisions(&graph).unwrap_err();
        assert!(err.message().contains("git+https://example.com/a.git"));
        assert!(err.message().contains("git+https://example.com/b.git"));
    }

    // -----------------------------------------------------------------------
    // A5 (resolution-semantics RFC §3 Axis A (b) / §5) — declared_version_source
    // field: the sibling to `version` naming WHICH precedence step produced it.
    // -----------------------------------------------------------------------

    fn make_locked_with_dvs(version: &str, declared_version_source: Option<String>) -> LockedDep {
        LockedDep {
            source_id: None,
            declared_version_source,
            name: "foo".into(),
            namespace: None,
            identity: Some(VALID_ID.into()),
            version: version.into(),
            src_dir: "src".into(),
            requires: vec![],
            provenances: vec![ProvenanceRecord::Git {
                url: "https://example.com/foo.git".into(),
                ref_spec: None,
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            }],
            active_flags: vec![],
            dep_decl: None,
            cond_requires: vec![],
            aliases: vec![],
            attestation: None,
        }
    }

    #[test]
    fn dvs_emitted_when_present() {
        let dep = make_locked_with_dvs("1.0.0", Some("nimble".into()));
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(
            text.contains("    declared_version_source \"nimble\""),
            "got:\n{text}"
        );
    }

    #[test]
    fn dvs_omitted_when_absent() {
        let dep = make_locked_with_dvs("1.0.0", None);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(
            !text.contains("declared_version_source"),
            "expected no declared_version_source line: {text:?}"
        );
    }

    #[test]
    fn dvs_each_precedence_value_round_trips() {
        for source in ["manifest", "nimble", "tag", "annotation"] {
            let dep = make_locked_with_dvs("1.0.0", Some(source.into()));
            let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
            let text1 = format_lockfile(&lf);
            let lf2 = parse_lockfile(&text1).unwrap();
            assert_eq!(lf2.deps[0].declared_version_source, Some(source.to_string()));
            let text2 = format_lockfile(&lf2);
            assert_eq!(text1, text2);
        }
    }

    #[test]
    fn dvs_positioned_immediately_after_version() {
        let dep = make_locked_with_dvs("1.0.0", Some("tag".into()));
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        let version_pos = text.find("    version \"1.0.0\"").unwrap();
        let dvs_pos = text.find("    declared_version_source \"tag\"").unwrap();
        let src_dir_pos = text.find("    src_dir \"src\"").unwrap();
        assert!(version_pos < dvs_pos, "version must precede declared_version_source: {text:?}");
        assert!(dvs_pos < src_dir_pos, "declared_version_source must precede src_dir: {text:?}");
    }

    #[test]
    fn dvs_version_unknown_pairing_0_0_0_and_no_source() {
        // §5 NORMATIVE: version-unknown emits the absent-version literal
        // "0.0.0" with declared_version_source omitted entirely — a
        // combination no Known case ever produces (a Known always names its
        // source).
        let dep = make_locked_with_dvs("0.0.0", None);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(text.contains("    version \"0.0.0\""), "got:\n{text}");
        assert!(!text.contains("declared_version_source"), "got:\n{text}");
        let lf2 = parse_lockfile(&text).unwrap();
        assert_eq!(lf2.deps[0].version, "0.0.0");
        assert_eq!(lf2.deps[0].declared_version_source, None);
    }

    #[test]
    fn dvs_parse_from_kdl() {
        let sample = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\
             \n\
             dep \"foo\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"1.2.3\"\n\
             \x20   declared_version_source \"annotation\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/foo.git\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        assert_eq!(lf.deps[0].version, "1.2.3");
        assert_eq!(lf.deps[0].declared_version_source, Some("annotation".to_string()));
    }

    #[test]
    fn dvs_unrecognized_value_collapses_to_none() {
        // Forward-compat: an unrecognized declared_version_source value
        // (e.g. from a future format revision) collapses to None rather
        // than raising — no new error slug is warranted for a purely
        // additive field (mirrors the attestation `kind` collapse
        // convention).
        let sample = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\
             \n\
             dep \"foo\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"1.2.3\"\n\
             \x20   declared_version_source \"from-the-future\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/foo.git\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        assert_eq!(lf.deps[0].declared_version_source, None);
    }

    #[test]
    fn dvs_absent_node_still_tolerated() {
        // Forward-compat baseline: a lockfile with no declared_version_source
        // node at all (pre-A5 shape) still parses fine — additive, no bump.
        let sample = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\
             \n\
             dep \"foo\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"0.0.1\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/foo.git\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        assert_eq!(lf.deps[0].declared_version_source, None);
    }

    // -----------------------------------------------------------------------
    // C-atomic: write_lockfile atomicity (Phase C, first slice)
    //
    // Behaviors:
    //   B1 (tracer): round-trip via parse_lockfile(format_lockfile(...)).
    //   B2 (atomicity): no leftover temp files after a successful write.
    //   B3 (failure cleanup): temp file is cleaned up on failure; existing
    //       target is untouched.
    // -----------------------------------------------------------------------

    /// B1 (tracer): write_lockfile produces a file whose content round-trips.
    #[test]
    fn write_lockfile_atomic_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("milpa.lock");
        let lf = sample_lockfile();
        let returned = write_lockfile(&lf, &path).unwrap();
        assert_eq!(returned, path);
        let reparsed = load_lockfile(&path).unwrap();
        assert_eq!(reparsed, lf);
    }

    /// B2 (atomicity): after a successful write no sibling temp files remain.
    ///
    /// The temp file lives in the same directory as the target so that
    /// `std::fs::rename` is always same-filesystem (EXDEV structurally
    /// impossible).  Checking that only `milpa.lock` exists in the directory
    /// proves the rename completed and the temp was not left behind.
    #[test]
    fn write_lockfile_atomic_no_leftover_temp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("milpa.lock");
        write_lockfile(&sample_lockfile(), &path).unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(entries.is_empty(), "temp files left behind: {entries:?}");
    }

    /// B2 variant: no leftover temp when an existing lockfile is replaced.
    #[test]
    fn write_lockfile_atomic_no_leftover_temp_on_overwrite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("milpa.lock");
        std::fs::write(&path, b"old content").unwrap();
        write_lockfile(&sample_lockfile(), &path).unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(entries.is_empty(), "temp files left behind: {entries:?}");
        // Confirm the old content was fully replaced.
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("old content"));
    }

    /// B3 (failure cleanup): if the rename step fails, no temp file is left
    /// behind.
    ///
    /// We simulate a rename failure by making the *target path* collide with an
    /// existing directory — `rename` will fail with EISDIR (cannot replace a
    /// directory with a file).  This exercises the post-write-pre-rename error
    /// branch: the temp file is written successfully, then `rename` fails, and
    /// the cleanup code must remove the temp.
    #[test]
    fn write_lockfile_atomic_failure_cleans_temp_on_rename_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Make the target path an existing directory so rename fails.
        let path = dir.path().join("milpa.lock");
        std::fs::create_dir(&path).unwrap();

        let result = write_lockfile(&sample_lockfile(), &path);
        // rename(file, dir) fails on Linux with EISDIR.
        assert!(result.is_err(), "expected write to fail when target is a dir");

        // No temp files must remain in the parent directory.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left after failure: {leftovers:?}");
    }

    // -----------------------------------------------------------------------
    // Local-dep liveness verify (lockfile-schema §6.2.1, #26 local-no-identity)
    //
    // verify_lockfile_against_deps dispatches on provenance kind:
    //   LOCAL → liveness-only (symlink to dir; plain dir = divergence; dangling = divergence)
    //   others → hash-compare (unchanged)
    // -----------------------------------------------------------------------

    /// Helper: a minimal LockedDep with LocalProvenanceRecord and no identity.
    fn local_locked_dep(name: &str, path: &str) -> LockedDep {
        LockedDep {
            source_id: None,
            declared_version_source: None,
            name: name.to_string(),
            namespace: None,
            identity: None, // local deps carry NO identity
            version: "0.0.1".to_string(),
            src_dir: String::new(),
            requires: Vec::new(),
            provenances: vec![ProvenanceRecord::Local {
                path: path.to_string(),
                origin: "observed".to_string(),
            }],
            active_flags: Vec::new(),
            dep_decl: None,
            cond_requires: Vec::new(),
            aliases: Vec::new(),
            attestation: None,
        }
    }

    #[test]
    fn verify_local_dep_symlink_to_dir_passes() {
        // State (a): symlink present + target is a reachable directory → no divergence.
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        let deps_dir = d.path().join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();
        let dep_path = deps_dir.join("mylib");
        std::os::unix::fs::symlink(&src, &dep_path).unwrap();

        let lf = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![local_locked_dep("mylib", "../src")],
        };
        let divs = verify_lockfile_against_deps(&lf, &deps_dir);
        assert!(divs.is_empty(), "live symlink must pass verify: {divs:?}");
    }

    #[test]
    fn verify_local_dep_dangling_symlink_is_divergence() {
        // State (b): dangling symlink → divergence (source tree gone or moved).
        let d = tempfile::tempdir().unwrap();
        let deps_dir = d.path().join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();
        let dep_path = deps_dir.join("mylib");
        // Point at a non-existent path.
        std::os::unix::fs::symlink(d.path().join("nonexistent"), &dep_path).unwrap();

        let lf = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![local_locked_dep("mylib", "../nonexistent")],
        };
        let divs = verify_lockfile_against_deps(&lf, &deps_dir);
        assert_eq!(divs.len(), 1, "dangling symlink must produce one divergence");
        assert!(
            divs[0].contains("dangling"),
            "divergence must mention 'dangling': {:?}",
            divs[0]
        );
    }

    #[test]
    fn verify_local_dep_plain_dir_not_symlink_is_divergence() {
        // State (c): plain directory at dest (not a symlink) → divergence.
        // This catches the case where a previous non-symlink fetch was replaced
        // by a local dep without cleaning up the stale directory.
        let d = tempfile::tempdir().unwrap();
        let deps_dir = d.path().join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();
        let dep_path = deps_dir.join("mylib");
        // Create a plain directory (not a symlink).
        std::fs::create_dir_all(&dep_path).unwrap();

        let lf = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![local_locked_dep("mylib", "../src")],
        };
        let divs = verify_lockfile_against_deps(&lf, &deps_dir);
        assert_eq!(divs.len(), 1, "plain dir must produce one divergence");
        assert!(
            divs[0].contains("expected symlink") || divs[0].contains("plain directory"),
            "divergence must mention expected symlink vs plain dir: {:?}",
            divs[0]
        );
    }

    #[test]
    fn verify_local_dep_missing_is_divergence() {
        // State (d): nothing at _deps/<name> → divergence.
        let d = tempfile::tempdir().unwrap();
        let deps_dir = d.path().join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();
        // Do NOT create dep_path at all.

        let lf = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![local_locked_dep("mylib", "../src")],
        };
        let divs = verify_lockfile_against_deps(&lf, &deps_dir);
        assert_eq!(divs.len(), 1, "missing dep must produce one divergence");
        assert!(
            divs[0].contains("missing"),
            "divergence must mention 'missing': {:?}",
            divs[0]
        );
    }

    #[test]
    fn verify_local_dep_does_not_hash_identity() {
        // LOCAL deps must NOT be hash-compared even if they happen to have
        // content that would produce a valid identity — liveness-only (§6.2.1).
        // (In practice local deps in a lockfile always have identity=None,
        // but the dispatch must be based on provenance kind, not identity presence.)
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("x.nim"), b"data").unwrap();
        let deps_dir = d.path().join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();
        let dep_path = deps_dir.join("mylib");
        std::os::unix::fs::symlink(&src, &dep_path).unwrap();

        // Even if we put a bogus identity on a local dep, verify must NOT diverge
        // on identity mismatch — it only checks liveness.
        let mut dep = local_locked_dep("mylib", "../src");
        dep.identity = Some(VALID_ID.to_string()); // deliberate mismatch with actual content
        let lf = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![dep],
        };
        let divs = verify_lockfile_against_deps(&lf, &deps_dir);
        // Must pass (symlink is live) — no hash mismatch divergence for local.
        assert!(
            divs.is_empty(),
            "local dep verify must be liveness-only, not hash-compare: {divs:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // strip_dep_pin tests
    // ---------------------------------------------------------------------------

    fn make_git_prov(origin: &str) -> ProvenanceRecord {
        ProvenanceRecord::Git {
            url: "https://example.com/foo.git".into(),
            ref_spec: Some("main".into()),
            commit_sha: Some("abc123".into()),
            origin: origin.into(),
            submodule_shas: vec![],
        }
    }

    fn make_locked_dep(name: &str, identity: Option<&str>, provs: Vec<ProvenanceRecord>) -> LockedDep {
        LockedDep {
            source_id: None,
            declared_version_source: None,
            name: name.into(),
            namespace: None,
            version: "1.0.0".into(),
            src_dir: "src".into(),
            requires: vec![],
            aliases: vec![],
            identity: identity.map(String::from),
            active_flags: vec![],
            dep_decl: None,
            cond_requires: vec![],
            provenances: provs,
            attestation: None,
        }
    }

    /// A dep with a declared Git provenance keeps only that declared record after
    /// strip_dep_pin; identity is cleared.
    #[test]
    fn strip_dep_pin_keeps_declared_provenance_clears_identity() {
        let declared = make_git_prov("declared");
        let dep = make_locked_dep("foo", Some(VALID_ID), vec![declared.clone()]);
        let lf = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![dep],
        };

        let result = strip_dep_pin(lf, "foo");

        assert_eq!(result.deps.len(), 1);
        let stripped = &result.deps[0];
        assert_eq!(stripped.name, "foo");
        assert!(stripped.identity.is_none(), "identity must be cleared");
        assert_eq!(stripped.provenances.len(), 1);
        assert_eq!(stripped.provenances[0], declared);
    }

    /// A dep with only a resolved/non-declared Git provenance has it dropped;
    /// identity is cleared and no provenances survive.
    #[test]
    fn strip_dep_pin_drops_resolved_provenances() {
        let resolved = make_git_prov("resolved");
        let dep = make_locked_dep("bar", Some(VALID_ID), vec![resolved]);
        let lf = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![dep],
        };

        let result = strip_dep_pin(lf, "bar");

        let stripped = &result.deps[0];
        assert!(stripped.identity.is_none(), "identity must be cleared");
        assert!(
            stripped.provenances.is_empty(),
            "non-declared provenance must be dropped: {:?}",
            stripped.provenances
        );
    }

    /// Mixed declared + resolved provenances: only declared Git records survive.
    #[test]
    fn strip_dep_pin_keeps_declared_drops_resolved_mixed() {
        let declared = make_git_prov("declared");
        let resolved = make_git_prov("resolved");
        let dep = make_locked_dep("baz", Some(VALID_ID), vec![declared.clone(), resolved]);
        let lf = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![dep],
        };

        let result = strip_dep_pin(lf, "baz");

        let stripped = &result.deps[0];
        assert!(stripped.identity.is_none());
        assert_eq!(stripped.provenances, vec![declared]);
    }

    /// Other deps in the lockfile are unchanged after stripping one dep's pin.
    #[test]
    fn strip_dep_pin_leaves_other_deps_unchanged() {
        let dep_a = make_locked_dep("a", Some(VALID_ID), vec![make_git_prov("resolved")]);
        let dep_b = make_locked_dep("b", Some(VALID_ID), vec![make_git_prov("declared")]);
        let lf = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![dep_a, dep_b.clone()],
        };

        let result = strip_dep_pin(lf, "a");

        // dep_b must be entirely unchanged
        let b = result.deps.iter().find(|d| d.name == "b").unwrap();
        assert_eq!(b.identity.as_deref(), Some(VALID_ID));
        assert_eq!(b.provenances, dep_b.provenances);
    }

    // -------------------------------------------------------------------------
    // RFC per-entry-attestation.md P2 — LockedDep.attestation (lockfile-schema §3.9)
    // -------------------------------------------------------------------------

    fn make_locked_dep_with_attestation(attestation: Option<LockAttestation>) -> LockedDep {
        let mut dep = make_locked_dep("foo", Some(VALID_ID), vec![make_git_prov("observed")]);
        dep.attestation = attestation;
        dep
    }

    #[test]
    fn test_attestation_default_none() {
        let dep = make_locked_dep_with_attestation(None);
        assert!(dep.attestation.is_none());
    }

    #[test]
    fn test_attestation_omitted_when_none() {
        let dep = make_locked_dep_with_attestation(None);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(!text.contains("attestation"));
    }

    #[test]
    fn test_author_signed_emitted_with_signer() {
        let att = LockAttestation {
            kind: AttestationKind::AuthorSigned { signer: "https://example.com/wf.yaml".into() },
            rekor: None,
            bundle_pin: None,
            namespace: String::new(),
        };
        let dep = make_locked_dep_with_attestation(Some(att));
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(text.contains("    attestation {"));
        assert!(text.contains("        kind \"author-signed\""));
        assert!(text.contains("        signer \"https://example.com/wf.yaml\""));
        assert!(!text.contains("rekor"));
    }

    #[test]
    fn test_milpa_vendored_emitted_without_signer() {
        let att = LockAttestation {
            kind: AttestationKind::MilpaVendored,
            rekor: None,
            bundle_pin: None,
            namespace: String::new(),
        };
        let dep = make_locked_dep_with_attestation(Some(att));
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(text.contains("        kind \"milpa-vendored\""));
        assert!(!text.contains("signer"));
    }

    #[test]
    fn test_rekor_block_emitted_when_present() {
        let att = LockAttestation {
            kind: AttestationKind::AuthorSigned { signer: "https://example.com/wf.yaml".into() },
            rekor: Some(RekorRef {
                uuid: "abc123".into(),
                log_index: "42".into(),
                integrated_time: "1000".into(),
            }),
            bundle_pin: None,
            namespace: String::new(),
        };
        let dep = make_locked_dep_with_attestation(Some(att));
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(text.contains("        rekor {"));
        assert!(text.contains("            uuid \"abc123\""));
        assert!(text.contains("            log_index \"42\""));
        assert!(text.contains("            integrated_time \"1000\""));
    }

    #[test]
    fn test_rekor_block_omitted_when_absent() {
        let att = LockAttestation {
            kind: AttestationKind::AuthorSigned { signer: "https://example.com/wf.yaml".into() },
            rekor: None,
            bundle_pin: None,
            namespace: String::new(),
        };
        let dep = make_locked_dep_with_attestation(Some(att));
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(!text.contains("rekor"));
    }

    #[test]
    fn test_position_after_active_flags_before_provenance() {
        let dep = LockedDep {
            source_id: None,
            declared_version_source: None,
            name: "foo".into(),
            namespace: None,
            identity: Some(VALID_ID.into()),
            version: "1.0.0".into(),
            src_dir: "src".into(),
            requires: vec![],
            provenances: vec![ProvenanceRecord::Git {
                url: "https://example.com/foo.git".into(),
                ref_spec: None,
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            }],
            active_flags: vec!["ssl".into()],
            dep_decl: None,
            cond_requires: vec![],
            aliases: vec![],
            attestation: Some(LockAttestation {
                kind: AttestationKind::MilpaVendored,
                rekor: None,
                bundle_pin: None,
                namespace: String::new(),
            }),
        };
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text = format_lockfile(&lf);
        let flags_pos = text.find("    active_flags \"ssl\"").unwrap();
        let att_pos = text.find("    attestation {").unwrap();
        let prov_pos = text.find("    provenance {").unwrap();
        assert!(
            flags_pos < att_pos && att_pos < prov_pos,
            "expected active_flags < attestation < provenance\nflags_pos={flags_pos}, \
             att_pos={att_pos}, prov_pos={prov_pos}\ntext:\n{text}"
        );
    }

    #[test]
    fn test_round_trip_parse_format_identical_author_signed() {
        let att = LockAttestation {
            kind: AttestationKind::AuthorSigned { signer: "https://example.com/wf.yaml".into() },
            rekor: Some(RekorRef { uuid: "abc".into(), log_index: "1".into(), integrated_time: "2".into() }),
            bundle_pin: None,
            namespace: String::new(),
        };
        let dep = make_locked_dep_with_attestation(Some(att.clone()));
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text1 = format_lockfile(&lf);
        let lf2 = parse_lockfile(&text1).unwrap();
        let text2 = format_lockfile(&lf2);
        assert_eq!(text1, text2);
        assert_eq!(lf2.deps[0].attestation, Some(att));
    }

    #[test]
    fn test_round_trip_parse_format_identical_milpa_vendored() {
        let att = LockAttestation {
            kind: AttestationKind::MilpaVendored,
            rekor: None,
            bundle_pin: None,
            namespace: String::new(),
        };
        let dep = make_locked_dep_with_attestation(Some(att.clone()));
        let lf = Lockfile { version: 1, strategy: "maxver".into(), exclude_newer: None, deps: vec![dep] };
        let text1 = format_lockfile(&lf);
        let lf2 = parse_lockfile(&text1).unwrap();
        let text2 = format_lockfile(&lf2);
        assert_eq!(text1, text2);
        assert_eq!(lf2.deps[0].attestation, Some(att));
    }

    #[test]
    fn test_malformed_unrecognized_kind_collapses_to_absent() {
        let text = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\n\
             dep \"foo\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"1.0.0\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires\n\
             \x20   attestation {{\n\
             \x20       kind \"bogus-kind\"\n\
             \x20   }}\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/foo.git\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&text).unwrap();
        assert!(lf.deps[0].attestation.is_none());
    }

    #[test]
    fn test_malformed_author_signed_missing_signer_collapses_to_absent() {
        let text = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\n\
             dep \"foo\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"1.0.0\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires\n\
             \x20   attestation {{\n\
             \x20       kind \"author-signed\"\n\
             \x20   }}\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/foo.git\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&text).unwrap();
        assert!(lf.deps[0].attestation.is_none());
    }

    #[test]
    fn test_older_parser_forward_compat_skip() {
        // An unrecognized `attestation` node is skipped like any other unknown
        // child node — a lockfile with the block still parses successfully.
        let text = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\n\
             strategy \"maxver\"\n\n\
             dep \"foo\" {{\n\
             \x20   identity \"{VALID_ID}\"\n\
             \x20   version \"1.0.0\"\n\
             \x20   src_dir \"src\"\n\
             \x20   requires\n\
             \x20   attestation {{\n\
             \x20       kind \"milpa-vendored\"\n\
             \x20   }}\n\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/foo.git\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&text).unwrap();
        assert_eq!(lf.deps[0].name, "foo");
        assert_eq!(
            lf.deps[0].attestation,
            Some(LockAttestation {
                kind: AttestationKind::MilpaVendored,
                rekor: None,
                bundle_pin: None,
                namespace: String::new(),
            })
        );
    }

    #[test]
    fn test_locked_from_resolved_carries_bundle_pin_and_namespace() {
        // P3a (RFC per-entry-attestation.md §7, lockfile-schema §3.9 addition):
        // `locked_from_resolved` now carries `bundle_pin` through (it no
        // longer drops it — needed for `milpa verify`'s offline
        // re-verification). RFC origin-as-identity §4.4 (B2/G10, S5): folds
        // `source_id`'s namespace (the deleted `registry_namespace` field's
        // successor) into `LockAttestation::namespace`.
        let entry_att = milpa_types::EntryAttestation {
            kind: AttestationKind::AuthorSigned { signer: "https://example.com/wf.yaml".into() },
            rekor: Some(RekorRef { uuid: "u".into(), log_index: "1".into(), integrated_time: "2".into() }),
            bundle_pin: Some("a".repeat(64)),
        };
        let resolved = ResolvedDep {
            declared_version_source: None,
            source_id: Some(SourceId::Fetchable(FetchableOrigin::Registry {
                registry: "tianguis".into(),
                namespace: Some("ns1".into()),
                name: "foo".into(),
            })),
            name: "foo".into(),
            namespace: None,
            identity: VALID_ID.into(),
            version: milpa_types::Version::release(1, 0, 0),
            src_dir: "src".into(),
            requires: vec![],
            provenances: vec![ProvenanceRecord::Git {
                url: "https://example.com/foo.git".into(),
                ref_spec: None,
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            }],
            dep_decl: None,
            cond_requires: vec![],
            aliases: vec![],
            active_flags: vec![],
            attestation: Some(entry_att),
        };
        let graph = ResolvedGraph { deps: vec![resolved] };
        let lf = from_graph(&graph, "maxver", None);
        let locked_att = lf.deps[0].attestation.as_ref().expect("claim must be carried");
        assert_eq!(
            locked_att,
            &LockAttestation {
                kind: AttestationKind::AuthorSigned { signer: "https://example.com/wf.yaml".into() },
                rekor: Some(RekorRef {
                    uuid: "u".into(),
                    log_index: "1".into(),
                    integrated_time: "2".into()
                }),
                bundle_pin: Some("a".repeat(64)),
                namespace: "ns1".into(),
            }
        );
    }

    #[test]
    fn test_unattested_entry_has_no_lockfile_block() {
        let resolved = ResolvedDep {
            declared_version_source: None,
            source_id: None,
            name: "foo".into(),
            namespace: None,
            identity: VALID_ID.into(),
            version: milpa_types::Version::release(1, 0, 0),
            src_dir: "src".into(),
            requires: vec![],
            provenances: vec![ProvenanceRecord::Git {
                url: "https://example.com/foo.git".into(),
                ref_spec: None,
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            }],
            dep_decl: None,
            cond_requires: vec![],
            aliases: vec![],
            active_flags: vec![],
            attestation: None,
        };
        let graph = ResolvedGraph { deps: vec![resolved] };
        let lf = from_graph(&graph, "maxver", None);
        assert!(lf.deps[0].attestation.is_none());
    }
}
