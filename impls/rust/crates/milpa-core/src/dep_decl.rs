//! DepDecl artifact parser and `dep_decl_hash` helper (S1 consumer side).
//!
//! Implements the **consumer** half of `spec/dep-decl.md`:
//!   - `parse_dep_decl(bytes) -> EdgeSet` — parse a DepDecl artifact (§2).
//!   - `dep_decl_hash(bytes) -> String` — compute `"sha256:" + hex(sha256(bytes))` (§3).
//!
//! **No serializer here.** The resolver never re-serializes; `canonical_serialize`
//! is a producer + harness obligation (spec Appendix B).
//!
//! **SSOT discipline:**
//!   - KDL parsing: reuses `kdl::KdlDocument::parse` — the same crate entry point
//!     used by `milpa-manifest` and `milpa-core::registry`. No new KDL machinery.
//!   - SHA-256: reuses `sha2::Sha256` — the same crate entry point used by
//!     `milpa-core::identity::compute_content_hash`. Same encoding:
//!     `"sha256:" + hex`. No parallel hasher.
//!   - Depth guard: reuses `milpa_manifest::kdl_brace_depth` +
//!     `milpa_manifest::KDL_MAX_NESTING_DEPTH` — the SSOT nesting-depth guard.
//!
//! **S3b note:** error-raising wrappers for `TNG-DEPDECL-HASH-MISMATCH` and the
//! other four `TNG-DEPDECL-*` codes are S3b deliverables. This module is the
//! happy-path parse path; the `dep_decl_hash` helper is a pure compute+compare
//! function — callers raise S3b errors on mismatch. KDL syntax errors propagate
//! as `CoreError::DepDecl("TNG-DEPDECL-PARSE-ERROR", …)`.

use kdl::{KdlDocument, KdlNode};
use milpa_manifest::{kdl_brace_depth, KDL_MAX_NESTING_DEPTH};
use milpa_types::{EdgeSet, NamedRequire, RequireEntry, UrlRequire};
use sha2::{Digest, Sha256};

use crate::error::CoreError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum `dep_decl_schema_version` this implementation understands (§4.3).
/// Only v0 is defined in this spec version.
pub const MAX_DEP_DECL_SCHEMA_VERSION: i64 = 0;

// ---------------------------------------------------------------------------
// dep_decl_hash — §3 (SSOT: same sha2::Sha256 as identity.rs)
// ---------------------------------------------------------------------------

/// Compute `dep_decl_hash` = `"sha256:" + hex(sha256(artifact_bytes))`.
///
/// Encoding is identical to `content_hash` in `spec/identity.md §2.1`:
/// same algorithm, same lowercase-hex format, same `"sha256:"` prefix.
/// SSOT: uses `sha2::Sha256` — the same crate as `identity::compute_content_hash`.
///
/// This is a **pure compute helper** for S1. The error-raising wrapper
/// (`TNG-DEPDECL-HASH-MISMATCH` on mismatch vs. the index pointer) is S3b.
pub fn dep_decl_hash(artifact_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(artifact_bytes);
    format!("sha256:{:x}", h.finalize())
}

// ---------------------------------------------------------------------------
// parse_dep_decl — happy-path DepDecl artifact parser (§2)
// ---------------------------------------------------------------------------

/// Parse a DepDecl artifact from raw bytes into an `(EdgeSet, schema_version)` pair.
///
/// Parses the KDL 2.0 document shape defined in `spec/dep-decl.md §2`:
/// ```text
/// dep_decl {
///     dep_decl_schema_version 0
///     src_dir "..."
///     require "name" "constraint"
///     require (url)"url" ref="ref"
/// }
/// ```
///
/// Returns `(EdgeSet, i64)` where the `i64` is the `dep_decl_schema_version`
/// integer read from the **parsed KDL DOM** (NOT from a secondary text-scan).
/// When the node is absent, the schema version defaults to `0` (forward-compat
/// §4.3). Callers (`DepDeclEdgeSource`) use this value for §4.3
/// SCHEMA-UNSUPPORTED and §5 SCHEMA-MISMATCH checks.
///
/// **SSOT design:** schema version is extracted once from the DOM and returned
/// alongside the `EdgeSet`. There is no secondary text-scan of the bytes.
///
/// **Overflow safety:** if the KDL integer value does not fit in `i64`, this
/// function returns `i64::MAX` (saturating), ensuring the
/// `artifact_schema_version > MAX_DEP_DECL_SCHEMA_VERSION` check in
/// `DepDeclEdgeSource` ALWAYS fires for out-of-range values — never silently
/// accepts them as v0 (the fail-open bug in the old `unwrap_or(0)` approach).
///
/// **KDL parsing** uses `kdl::KdlDocument::parse` (the same crate used by
/// `milpa-manifest` and `registry`). Any KDL syntax error is wrapped as
/// `CoreError::DepDecl("TNG-DEPDECL-PARSE-ERROR", …)`.
///
/// **Error raise sites for S3b** (NOT raised here):
///   - `TNG-DEPDECL-HASH-MISMATCH` — hash verification before parse
///   - `TNG-DEPDECL-SCHEMA-UNSUPPORTED` — schema version check §4.3
///   - `TNG-DEPDECL-SCHEMA-MISMATCH` — consistency check §5
///
/// # Errors
/// Returns `CoreError::DepDecl("TNG-DEPDECL-PARSE-ERROR", …)` on any
/// KDL syntax error, nesting-depth violation, or structural non-conformance.
pub fn parse_dep_decl(artifact_bytes: &[u8]) -> Result<(EdgeSet, i64), CoreError> {
    let text = std::str::from_utf8(artifact_bytes).map_err(|e| {
        CoreError::DepDecl(
            "TNG-DEPDECL-PARSE-ERROR",
            format!("DepDecl artifact is not valid UTF-8: {e}"),
        )
    })?;

    // Depth guard (mirrors milpa-manifest's parse_kdl): kdl-rs is recursive-
    // descent with no internal stack limit; deeply-nested input causes SIGABRT.
    if kdl_brace_depth(text) > KDL_MAX_NESTING_DEPTH {
        return Err(CoreError::DepDecl(
            "TNG-DEPDECL-PARSE-ERROR",
            format!("KDL input exceeds maximum nesting depth ({KDL_MAX_NESTING_DEPTH})"),
        ));
    }

    let doc = KdlDocument::parse(text).map_err(|e| {
        CoreError::DepDecl(
            "TNG-DEPDECL-PARSE-ERROR",
            format!("KDL syntax error: {e}"),
        )
    })?;

    parse_dep_decl_doc(&doc)
}

fn parse_dep_decl_doc(doc: &KdlDocument) -> Result<(EdgeSet, i64), CoreError> {
    let top: Vec<&KdlNode> = doc.nodes().iter().collect();
    if top.len() != 1 || top[0].name().value() != "dep_decl" {
        return Err(CoreError::DepDecl(
            "TNG-DEPDECL-PARSE-ERROR",
            "DepDecl artifact must have a single top-level 'dep_decl' node".to_string(),
        ));
    }

    let dep_decl_node = top[0];
    let children = match dep_decl_node.children() {
        Some(c) => c.nodes(),
        None => &[],
    };

    let mut src_dir = String::new();
    let mut requires: Vec<RequireEntry> = Vec::new();
    // Default per §4.3 forward-compat: treat missing version as v0.
    let mut schema_version: i64 = 0;

    for child in children {
        match child.name().value() {
            "dep_decl_schema_version" => {
                // Read from DOM — the SSOT integer node value.
                // Overflow safety: if the KDL integer value exceeds i64::MAX,
                // use i64::MAX (saturating) so the SCHEMA-UNSUPPORTED check
                // always fires. Never use unwrap_or(0) (fail-open bug R3).
                if let Some(entry) = child.entries().first() {
                    schema_version = match entry.value() {
                        kdl::KdlValue::Integer(n) => {
                            // kdl-rs 6.x represents KDL integers as i128.
                            // Saturate to i64::MAX if out of range (overflow-safe).
                            i64::try_from(*n).unwrap_or(i64::MAX)
                        }
                        _ => 0, // Non-integer value: treat as absent (forward-compat).
                    };
                }
            }
            "src_dir" => {
                if let Some(val) = child.entries().first() {
                    if let Some(s) = val.value().as_string() {
                        src_dir = s.to_string();
                    }
                }
            }
            "require" => {
                if let Some(entry) = parse_require_node(child) {
                    requires.push(entry);
                }
            }
            // Unknown child nodes: forward-compat ignore (schema evolution §1.1)
            _ => {}
        }
    }

    Ok((EdgeSet::from_dep_decl(requires, src_dir), schema_version))
}

/// Parse a single `require` child node into a `RequireEntry`.
///
/// Two forms (spec §2 Rule 4):
/// - `require "<name>" "<constraint>"` → `RequireEntry::Named`
/// - `require (url)"<url>" ref="<ref>"` → `RequireEntry::Url`
///
/// Disambiguation: the URL form has a `(url)` KDL type annotation on the
/// first positional arg. A bare double-quoted string (no annotation) is named.
///
/// Returns `None` for unrecognized forms (forward-compat tolerance).
fn parse_require_node(node: &KdlNode) -> Option<RequireEntry> {
    // Collect positional args (no key) in order.
    let pos_args: Vec<&kdl::KdlEntry> = node
        .entries()
        .iter()
        .filter(|e| e.name().is_none())
        .collect();

    if pos_args.is_empty() {
        return None;
    }

    let first = pos_args[0];
    let first_type = first.ty().map(|t| t.value());

    if first_type == Some("url") {
        // URL form: require (url)"<url>" ref="<ref>"
        let url = first.value().as_string()?.to_string();
        // Property `ref=`
        let ref_ = node
            .entries()
            .iter()
            .find(|e| e.name().map(|n| n.value()) == Some("ref"))
            .and_then(|e| e.value().as_string())
            .unwrap_or("")
            .to_string();
        Some(RequireEntry::Url(UrlRequire { url, ref_, predicates: Vec::new() }))
    } else {
        // Named form: require "<name>" "<constraint>"
        let name = first.value().as_string()?.to_string();
        let constraint_str = pos_args
            .get(1)
            .and_then(|e| e.value().as_string())
            .unwrap_or("")
            .to_string();
        Some(RequireEntry::Named(NamedRequire { name, constraint_str, predicates: Vec::new() }))
    }
}

// ---------------------------------------------------------------------------
// Tests — S1 conformance oracle
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use milpa_types::EdgeSource;
    use std::path::PathBuf;

    // -----------------------------------------------------------------------
    // Corpus path — mirrors how other milpa-core tests find the conformance dir
    // -----------------------------------------------------------------------

    fn repo_root() -> PathBuf {
        // This file: impls/rust/crates/milpa-core/src/dep_decl.rs
        // repo root:  ../../../../../
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..") // crates/
            .join("..") // rust/
            .join("..") // impls/
            .join("..") // repo root
    }

    fn golden_dir() -> PathBuf {
        repo_root()
            .join("conformance")
            .join("spec-v1")
            .join("dep-decl-golden")
            .join("v0")
    }

    // -----------------------------------------------------------------------
    // S0 golden vector: hand-constructed expected values (spec/dep-decl.md §A)
    // Hard-coded — NOT read from meta.json — so a corrupted meta.json cannot
    // mask a parser bug.
    // -----------------------------------------------------------------------

    const EXPECTED_DEP_DECL_HASH: &str =
        "sha256:34a91f93fc03cadbd69379b97cdbac82110070ead8595038f0cc203e72d346bd";

    fn expected_edge_set() -> EdgeSet {
        EdgeSet::from_dep_decl(
            vec![
                RequireEntry::Named(NamedRequire {
                    name: "results".to_string(),
                    constraint_str: ">= 0.5.0".to_string(),
                    predicates: Vec::new(),
                }),
                RequireEntry::Named(NamedRequire {
                    name: "stew".to_string(),
                    constraint_str: ">= 0.1 & < 1.0".to_string(),
                    predicates: Vec::new(),
                }),
                RequireEntry::Url(UrlRequire {
                    url: "https://github.com/status-im/nim-chronos.git".to_string(),
                    ref_: "v3.2.0".to_string(),
                    predicates: Vec::new(),
                }),
            ],
            "src".to_string(),
        )
    }

    // -----------------------------------------------------------------------
    // Oracle: parse the S0 golden vector
    // -----------------------------------------------------------------------

    #[test]
    fn golden_corpus_files_exist() {
        let dir = golden_dir();
        assert!(
            dir.join("example.kdl").is_file(),
            "Golden KDL not found: {:?}",
            dir.join("example.kdl")
        );
        assert!(
            dir.join("meta.json").is_file(),
            "Meta JSON not found: {:?}",
            dir.join("meta.json")
        );
    }

    #[test]
    fn parse_dep_decl_golden_vector() {
        let raw = std::fs::read(golden_dir().join("example.kdl")).unwrap();
        let (result, schema_version) = parse_dep_decl(&raw).unwrap();
        assert_eq!(
            result,
            expected_edge_set(),
            "EdgeSet mismatch: got {result:?}"
        );
        assert_eq!(schema_version, 0, "golden vector schema_version must be 0");
    }

    #[test]
    fn dep_decl_hash_golden_vector() {
        let raw = std::fs::read(golden_dir().join("example.kdl")).unwrap();
        let computed = dep_decl_hash(&raw);
        assert_eq!(
            computed, EXPECTED_DEP_DECL_HASH,
            "Hash mismatch: got {computed}"
        );
    }

    #[test]
    fn parse_dep_decl_source_tag_is_dep_decl() {
        let raw = std::fs::read(golden_dir().join("example.kdl")).unwrap();
        let (result, _schema_version) = parse_dep_decl(&raw).unwrap();
        assert_eq!(result.source, EdgeSource::DepDecl);
    }

    // -----------------------------------------------------------------------
    // Cross-check meta.json (second oracle)
    // -----------------------------------------------------------------------

    #[test]
    fn meta_json_dep_decl_hash_matches_golden_constant() {
        let meta_text =
            std::fs::read_to_string(golden_dir().join("meta.json")).unwrap();
        // Simple extraction — avoid a JSON dep for one field.
        assert!(
            meta_text.contains(EXPECTED_DEP_DECL_HASH),
            "meta.json does not contain expected hash {EXPECTED_DEP_DECL_HASH}"
        );
    }

    // -----------------------------------------------------------------------
    // Unit tests for edge-case parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_empty_requires() {
        let kdl = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"\"\n}\n";
        let (result, schema_version) = parse_dep_decl(kdl).unwrap();
        assert_eq!(
            result,
            EdgeSet::from_dep_decl(vec![], String::new())
        );
        assert_eq!(schema_version, 0);
    }

    #[test]
    fn parse_only_named_requires() {
        let kdl = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"\"\n    require \"foo\" \">= 1.0.0\"\n    require \"bar\" \"\"\n}\n";
        let (result, _) = parse_dep_decl(kdl).unwrap();
        assert_eq!(
            result.requires,
            vec![
                RequireEntry::Named(NamedRequire {
                    name: "foo".into(),
                    constraint_str: ">= 1.0.0".into(),
                    predicates: Vec::new(),
                }),
                RequireEntry::Named(NamedRequire {
                    name: "bar".into(),
                    constraint_str: "".into(),
                    predicates: Vec::new(),
                }),
            ]
        );
    }

    #[test]
    fn parse_only_url_requires() {
        let kdl = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"\"\n    require (url)\"https://example.com/pkg.git\" ref=\"main\"\n}\n";
        let (result, _) = parse_dep_decl(kdl).unwrap();
        assert_eq!(
            result.requires,
            vec![RequireEntry::Url(UrlRequire {
                url: "https://example.com/pkg.git".into(),
                ref_: "main".into(),
                predicates: Vec::new(),
            })]
        );
    }

    #[test]
    fn dep_decl_hash_is_sha256_prefixed() {
        let h = dep_decl_hash(b"any bytes");
        assert!(h.starts_with("sha256:"), "hash should start with sha256:");
        let digest = h.strip_prefix("sha256:").unwrap();
        assert_eq!(digest.len(), 64);
        assert!(
            digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "digest must be lowercase hex"
        );
    }

    #[test]
    fn dep_decl_hash_deterministic() {
        let data = b"dep_decl { dep_decl_schema_version 0\n    src_dir \"\" }\n";
        assert_eq!(dep_decl_hash(data), dep_decl_hash(data));
    }

    #[test]
    fn dep_decl_hash_distinct_for_different_bytes() {
        let a = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"\"\n}\n";
        let b = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"src\"\n}\n";
        assert_ne!(dep_decl_hash(a), dep_decl_hash(b));
    }

    #[test]
    fn parse_dep_decl_rejects_non_utf8() {
        let bad = b"\xff\xfe invalid utf8";
        let err = parse_dep_decl(bad).unwrap_err();
        assert_eq!(err.code(), "TNG-DEPDECL-PARSE-ERROR");
    }

    #[test]
    fn parse_dep_decl_rejects_wrong_top_level_node() {
        let kdl = b"not_dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"\"\n}\n";
        let err = parse_dep_decl(kdl).unwrap_err();
        assert_eq!(err.code(), "TNG-DEPDECL-PARSE-ERROR");
    }

    #[test]
    fn edge_source_dep_decl_variant_exists() {
        let es = EdgeSet::from_dep_decl(vec![], String::new());
        assert_eq!(es.source, EdgeSource::DepDecl);
    }

    // -----------------------------------------------------------------------
    // R3: parse_dep_decl surfaces schema version from DOM (not a text-scan)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dep_decl_returns_schema_version_from_dom() {
        // parse_dep_decl must return (EdgeSet, schema_version: i64).
        let kdl = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"\"\n}\n";
        let (es, schema_version) = parse_dep_decl(kdl).unwrap();
        assert_eq!(schema_version, 0);
        assert_eq!(es.source, EdgeSource::DepDecl);
    }

    #[test]
    fn parse_dep_decl_returns_correct_schema_version() {
        // Non-zero version: ensures we read from the DOM node, not a default.
        let kdl = b"dep_decl {\n    dep_decl_schema_version 7\n    src_dir \"\"\n}\n";
        let (_es, schema_version) = parse_dep_decl(kdl).unwrap();
        assert_eq!(schema_version, 7);
    }

    #[test]
    fn parse_dep_decl_schema_version_absent_defaults_to_zero() {
        // spec/dep-decl.md §4.3 forward-compat: absent version → 0.
        let kdl = b"dep_decl {\n    src_dir \"\"\n}\n";
        let (_es, schema_version) = parse_dep_decl(kdl).unwrap();
        assert_eq!(schema_version, 0);
    }

    #[test]
    fn parse_dep_decl_keyword_in_string_value_not_confused() {
        // R3 regression: text-scan would match 'dep_decl_schema_version 99'
        // inside the src_dir string value, returning 99 instead of the actual
        // DOM node value 0.  DOM-sourced implementation is immune.
        let kdl =
            b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"dep_decl_schema_version 99\"\n}\n";
        let (_es, schema_version) = parse_dep_decl(kdl).unwrap();
        assert_eq!(
            schema_version, 0,
            "schema_version must come from the DOM node, not a text-scan inside src_dir"
        );
    }

    #[test]
    fn parse_dep_decl_keyword_in_require_arg_not_confused() {
        // R3 regression: text-scan could match keyword inside a require argument.
        let kdl =
            b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"\"\n    require \"dep_decl_schema_version\" \"99\"\n}\n";
        let (_es, schema_version) = parse_dep_decl(kdl).unwrap();
        assert_eq!(
            schema_version, 0,
            "schema_version must come from the DOM node, not a text-scan inside a require arg"
        );
    }

    #[test]
    fn parse_dep_decl_overflow_i64_max_not_zero() {
        // R3 overflow fix: an artifact declaring dep_decl_schema_version > i64::MAX
        // must NOT be silently accepted as v0 (the old `unwrap_or(0)` bug).
        // kdl-rs parses integers as i128; values > i64::MAX are saturated to
        // i64::MAX (still > MAX_DEP_DECL_SCHEMA_VERSION=0).
        // Note: kdl-rs may reject a literal > i128::MAX at parse time, which is
        // also acceptable — the point is it must NOT return 0.
        //
        // We use i64::MAX + 1 expressed as the decimal string to ensure overflow.
        let version_str = format!("{}", i64::MAX as i128 + 1);
        let kdl = format!(
            "dep_decl {{\n    dep_decl_schema_version {version_str}\n    src_dir \"\"\n}}\n"
        );
        match parse_dep_decl(kdl.as_bytes()) {
            Ok((_es, schema_version)) => {
                assert!(
                    schema_version > MAX_DEP_DECL_SCHEMA_VERSION,
                    "overflow schema_version must be > MAX (not silently 0); got {schema_version}"
                );
            }
            Err(e) => {
                // kdl-rs rejecting the value at parse time is also acceptable —
                // the PARSE-ERROR path still prevents fail-open.
                assert_eq!(
                    e.code(),
                    "TNG-DEPDECL-PARSE-ERROR",
                    "overflow should produce PARSE-ERROR or SCHEMA-UNSUPPORTED, not some other error"
                );
            }
        }
    }
}
