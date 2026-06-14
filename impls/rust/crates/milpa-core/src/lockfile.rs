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
use milpa_manifest::{kdl_brace_depth, KDL_MAX_NESTING_DEPTH};
use milpa_types::{
    LockedDep, Lockfile, ProvenanceRecord, ResolvedDep, ResolvedGraph, LOCKFILE_SCHEMA_VERSION,
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
/// the schema version *after* the scan so a malformed `dep`/`version` node
/// encountered earlier reports first. `strategy` defaults to `"maxver"` and a
/// malformed `strategy` node is silently ignored (spec §2.2: tolerate pre-v1.0
/// lockfiles that predate the always-emitted node).
pub fn parse_lockfile(text: &str) -> LockResult<Lockfile> {
    // Depth guard — see milpa_manifest::KDL_MAX_NESTING_DEPTH for rationale.
    if kdl_brace_depth(text) > KDL_MAX_NESTING_DEPTH {
        return Err(err(
            "LOCK-KDL-SYNTAX",
            format!("KDL input exceeds maximum nesting depth ({KDL_MAX_NESTING_DEPTH})"),
        ));
    }
    let doc = KdlDocument::parse(text)
        .map_err(|e| err("LOCK-KDL-SYNTAX", format!("KDL syntax error: {e}")))?;

    let mut deps: Vec<LockedDep> = Vec::new();
    let mut strategy = String::from("maxver");
    let mut version: Option<u32> = None;

    for node in doc.nodes() {
        match node.name().value() {
            "version" => version = Some(scalar_u32(node, "version")?),
            "strategy" => {
                // Set only on a well-formed single-string arg; otherwise keep
                // the default (no error — §2.2).
                let a = args(node);
                if let [entry] = a.as_slice() {
                    if let Some(s) = entry.value().as_string() {
                        strategy = s.to_string();
                    }
                }
            }
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

    Ok(Lockfile {
        version,
        strategy,
        deps,
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
    let mut identity: Option<String> = None;
    let mut version = String::from("0.0.0");
    let mut src_dir = String::new();
    let mut requires: Vec<String> = Vec::new();
    let mut active_flags: Vec<String> = Vec::new();
    let mut self_mirrors: Vec<String> = Vec::new();
    let mut dep_decl: Option<String> = None; // S6: additive dep_decl pin (§3.7)
    let mut cond_requires: Vec<milpa_types::CondRequire> = Vec::new(); // S4
    let mut provenances: Vec<ProvenanceRecord> = Vec::new();

    for child in children(node) {
        match child.name().value() {
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
            "src_dir" => src_dir = scalar_str(child, &name, "src_dir")?,
            "requires" => requires = string_args(child),
            "active_flags" => active_flags = string_args(child),
            "self_mirrors" => self_mirrors = string_args(child),
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
            "provenance" => provenances.push(parse_provenance(child, &name)?),
            _ => {}
        }
    }

    Ok(LockedDep {
        name,
        identity,
        version,
        src_dir,
        requires,
        provenances,
        active_flags,
        self_mirrors,
        dep_decl,
        cond_requires,
    })
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
fn parse_provenance(node: &KdlNode, dep_name: &str) -> LockResult<ProvenanceRecord> {
    // Collect each child's single value (last-wins, mirroring the Python dict).
    let mut fields: Vec<(&str, String)> = Vec::new();
    for child in children(node) {
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

    match kind.as_str() {
        "git" => Ok(ProvenanceRecord::Git {
            url: required("url")?,
            ref_spec: get("ref"),
            commit_sha: get("commit_sha"),
        }),
        "tarball" => Ok(ProvenanceRecord::Tarball {
            url: required("url")?,
            sha256: get("sha256"),
        }),
        "local" => Ok(ProvenanceRecord::Local {
            path: required("path")?,
        }),
        "member" => Ok(ProvenanceRecord::Member {
            name: required("name")?,
        }),
        "oci" => Ok(ProvenanceRecord::Oci {
            registry: required("registry")?,
            repository: required("repository")?,
            digest: required("digest")?,
        }),
        "registry" => Ok(ProvenanceRecord::Registry {
            name: required("name")?,
            tag: get("tag"),
            commit_sha: get("commit_sha"),
        }),
        other => Err(err(
            "LOCK-PROV-KIND-UNKNOWN",
            format!(
                "dep {dep_name:?}: unknown provenance kind {other:?} \
                 (supported: git, tarball, local, member, oci, registry)"
            ),
        )),
    }
}

/// The single positional string name of a `dep` node (`LOCK-DEP-NAME-ARITY`).
fn dep_name(node: &KdlNode) -> LockResult<String> {
    let a = args(node);
    match a.as_slice() {
        [entry] => entry
            .value()
            .as_string()
            .map(str::to_string)
            .ok_or_else(|| {
                err(
                    "LOCK-DEP-NAME-ARITY",
                    "dep node requires exactly one string argument (the name)",
                )
            }),
        _ => Err(err(
            "LOCK-DEP-NAME-ARITY",
            "dep node requires exactly one string argument (the name)",
        )),
    }
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

/// Render a [`Lockfile`] to canonical KDL text (lockfile-schema §2.4).
/// Byte-identical to `lockfile.py:format_lockfile` for the same data.
pub fn format_lockfile(lockfile: &Lockfile) -> String {
    let mut lines: Vec<String> = vec![
        HEADER.to_string(),
        format!("version {}", lockfile.version),
        format!("strategy {}", kdl_str(&lockfile.strategy)),
        String::new(),
    ];
    for dep in &lockfile.deps {
        lines.push(format!("dep {} {{", kdl_str(&dep.name)));
        if let Some(identity) = &dep.identity {
            lines.push(format!("    identity {}", kdl_str(identity)));
        }
        lines.push(format!("    version {}", kdl_str(&dep.version)));
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
        if !dep.active_flags.is_empty() {
            lines.push(format!("    active_flags {}", join_kdl(&dep.active_flags)));
        }
        if !dep.self_mirrors.is_empty() {
            let sm = dep
                .self_mirrors
                .iter()
                .map(|u| format!("(url){}", kdl_str(u)))
                .collect::<Vec<_>>()
                .join(" ");
            lines.push(format!("    self_mirrors {sm}"));
        }
        // S6: emit dep_decl pin between self_mirrors and provenance (§3.7).
        if let Some(dd) = &dep.dep_decl {
            lines.push(format!("    dep_decl {}", kdl_str(dd)));
        }
        for prov in &dep.provenances {
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
        } => {
            out.push(format!("kind {}", kdl_str("git")));
            out.push(format!("url {}", kdl_str(url)));
            if let Some(r) = ref_spec {
                out.push(format!("ref {}", kdl_str(r)));
            }
            if let Some(c) = commit_sha {
                out.push(format!("commit_sha {}", kdl_str(c)));
            }
        }
        ProvenanceRecord::Tarball { url, sha256 } => {
            out.push(format!("kind {}", kdl_str("tarball")));
            out.push(format!("url {}", kdl_str(url)));
            if let Some(s) = sha256 {
                out.push(format!("sha256 {}", kdl_str(s)));
            }
        }
        ProvenanceRecord::Local { path } => {
            out.push(format!("kind {}", kdl_str("local")));
            out.push(format!("path {}", kdl_str(path)));
        }
        ProvenanceRecord::Member { name } => {
            out.push(format!("kind {}", kdl_str("member")));
            out.push(format!("name {}", kdl_str(name)));
        }
        ProvenanceRecord::Oci {
            registry,
            repository,
            digest,
        } => {
            out.push(format!("kind {}", kdl_str("oci")));
            out.push(format!("registry {}", kdl_str(registry)));
            out.push(format!("repository {}", kdl_str(repository)));
            out.push(format!("digest {}", kdl_str(digest)));
        }
        ProvenanceRecord::Registry {
            name,
            tag,
            commit_sha,
        } => {
            out.push(format!("kind {}", kdl_str("registry")));
            out.push(format!("name {}", kdl_str(name)));
            if let Some(t) = tag {
                out.push(format!("tag {}", kdl_str(t)));
            }
            if let Some(c) = commit_sha {
                out.push(format!("commit_sha {}", kdl_str(c)));
            }
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

/// Write canonical lockfile KDL to `path`, creating parent dirs (mirrors
/// `lockfile.py:write_lockfile`). Returns the path on success. Filesystem I/O
/// failures are uncoded in the spec (Python propagates the raw `OSError`), so
/// they surface as the non-catalog `MILPA-INTERNAL-IO` sentinel — kept OUT of
/// `all_codes()`, consistent with the identity/CAS I/O treatment (S4).
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
    std::fs::write(path, format_lockfile(lockfile)).map_err(|e| {
        err(
            crate::identity::INTERNAL_IO,
            format!("cannot write lockfile {}: {e}", path.display()),
        )
    })?;
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
pub fn from_graph(graph: &ResolvedGraph, strategy: &str) -> Lockfile {
    let mut deps: Vec<LockedDep> = graph.deps.iter().map(locked_from_resolved).collect();
    deps.sort_by(|a, b| a.name.cmp(&b.name));
    Lockfile {
        version: LOCKFILE_SCHEMA_VERSION,
        strategy: strategy.to_string(),
        deps,
    }
}

/// Translate one flat [`ResolvedDep`] into a structured [`LockedDep`].
fn locked_from_resolved(d: &ResolvedDep) -> LockedDep {
    let mut requires = d.requires.clone();
    requires.sort();
    // S4: carry cond_requires; sort by total key (name, predicate-string) for
    // byte-exact determinism when same-name entries exist (C1 fix).
    let mut cond_requires = d.cond_requires.clone();
    cond_requires.sort_by_key(|cr| cond_require_sort_key(cr));
    LockedDep {
        name: d.name.clone(),
        // Every dep in a resolved graph is content-hashed; an empty identity
        // would only be the synthetic root, which `build_graph` already drops.
        identity: opt(&d.identity),
        version: d.version.to_string(),
        src_dir: d.src_dir.clone(),
        requires,
        // `ResolvedDep.provenance` is already the emission-level record (the
        // resolver mapped transport→record at graph-build time), so this is a
        // direct clone — no per-kind dispatch here.
        provenances: vec![d.provenance.clone()],
        // #23 active feature flags and #79 self-mirrors are resolver-enrichment
        // concerns not yet carried on `ResolvedDep`; emitted empty (the Python
        // default for deps that declare neither). Threading them through lands
        // with the feature-flag work that exercises them — no current fixture
        // resolves a flag-carrying or self-mirroring dep.
        active_flags: Vec::new(),
        self_mirrors: Vec::new(),
        // S6: carry dep_decl pin from the resolved dep (set only when
        // the edge was sourced from a DepDecl artifact).
        dep_decl: d.dep_decl.clone(),
        // S4: carry cond_requires (sorted by (name, canonical-predicate-string)).
        cond_requires,
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
    use std::collections::BTreeMap;
    let locked: BTreeMap<&str, &LockedDep> =
        lockfile.deps.iter().map(|d| (d.name.as_str(), d)).collect();
    let resolved: BTreeMap<&str, &ResolvedDep> =
        graph.deps.iter().map(|d| (d.name.as_str(), d)).collect();

    let mut errors: Vec<String> = Vec::new();
    for name in resolved.keys() {
        if !locked.contains_key(name) {
            errors.push(format!(
                "unexpected dep {name:?} in resolved graph (not in lockfile)"
            ));
        }
    }
    for name in locked.keys() {
        if !resolved.contains_key(name) {
            errors.push(format!(
                "locked dep {name:?} is missing from resolved graph"
            ));
        }
    }
    for (name, r) in &resolved {
        if let Some(l) = locked.get(name) {
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

/// Verify each locked dep's on-disk bytes (under `deps_dir/<name>`) hash to its
/// recorded identity, and that no extra non-dotfile entries exist (mirrors
/// `lockfile.py:verify_lockfile_against_deps`). Returns the list of divergence
/// messages — empty means verified. This is `milpa verify`'s primitive; the CLI
/// prints the divergences and exits 1 (no single catalog code — it is a report).
pub fn verify_lockfile_against_deps(
    lockfile: &Lockfile,
    deps_dir: &std::path::Path,
) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut divergences: Vec<String> = Vec::new();
    let locked_names: BTreeSet<&str> = lockfile.deps.iter().map(|d| d.name.as_str()).collect();

    for locked in &lockfile.deps {
        let dep_path = deps_dir.join(&locked.name);
        if !dep_path.exists() {
            divergences.push(format!(
                "{}: missing from {}/",
                locked.name,
                deps_dir.display()
            ));
            continue;
        }
        match crate::identity::compute_content_hash(&dep_path) {
            Ok(actual) => {
                if locked.identity.as_deref() != Some(actual.as_str()) {
                    divergences.push(format!(
                        "{}: identity mismatch — lockfile says {:?}, actual {:?}",
                        locked.name, locked.identity, actual
                    ));
                }
            }
            Err(e) => divergences.push(format!("{}: cannot hash — {}", locked.name, e.message())),
        }
    }

    if let Ok(rd) = std::fs::read_dir(deps_dir) {
        let mut extras: Vec<String> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.') && !locked_names.contains(n.as_str()))
            .collect();
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

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_ID: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000001";

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
            }]
        );
    }

    #[test]
    fn absent_identity_is_none_and_bare_requires_is_empty() {
        let text = "version 1\nstrategy \"maxver\"\n\
                    dep \"foo\" {\n    version \"0.0.1\"\n    src_dir \"\"\n    requires\n    \
                    provenance {\n        kind \"local\"\n        path \"../foo\"\n    }\n}\n";
        let lock = parse_lockfile(text).unwrap();
        let dep = &lock.deps[0];
        assert_eq!(dep.identity, None);
        assert!(dep.requires.is_empty());
        assert_eq!(
            dep.provenances,
            vec![ProvenanceRecord::Local {
                path: "../foo".into()
            }]
        );
    }

    #[test]
    fn strategy_defaults_to_maxver_when_absent() {
        let lock = parse_lockfile("version 1\n").unwrap();
        assert_eq!(lock.strategy, "maxver");
        assert!(lock.deps.is_empty());
    }

    #[test]
    fn self_mirrors_accepts_url_annotated_and_plain() {
        let text = "version 1\n\
                    dep \"foo\" {\n    version \"0.0.1\"\n    src_dir \"\"\n    requires\n    \
                    self_mirrors (url)\"https://a.example/foo.git\" \"https://b.example/foo.git\"\n    \
                    provenance {\n        kind \"git\"\n        url \"https://example.com/foo.git\"\n    }\n}\n";
        let lock = parse_lockfile(text).unwrap();
        assert_eq!(
            lock.deps[0].self_mirrors,
            vec!["https://a.example/foo.git", "https://b.example/foo.git"]
        );
    }

    #[test]
    fn accepts_every_provenance_kind() {
        for (kind_block, want) in [
            (
                "kind \"tarball\"\n        url \"https://e/x.tar.gz\"\n        sha256 \"abc\"",
                ProvenanceRecord::Tarball {
                    url: "https://e/x.tar.gz".into(),
                    sha256: Some("abc".into()),
                },
            ),
            (
                "kind \"member\"\n        name \"liba\"",
                ProvenanceRecord::Member {
                    name: "liba".into(),
                },
            ),
            (
                "kind \"oci\"\n        registry \"r\"\n        repository \"o/p\"\n        digest \"sha256:d\"",
                ProvenanceRecord::Oci {
                    registry: "r".into(),
                    repository: "o/p".into(),
                    digest: "sha256:d".into(),
                },
            ),
            (
                "kind \"registry\"\n        name \"n\"\n        tag \"v1\"",
                ProvenanceRecord::Registry {
                    name: "n".into(),
                    tag: Some("v1".into()),
                    commit_sha: None,
                },
            ),
        ] {
            let text = format!(
                "version 1\ndep \"foo\" {{\n    version \"0.0.1\"\n    src_dir \"\"\n    requires\n    provenance {{\n        {kind_block}\n    }}\n}}\n"
            );
            let lock = parse_lockfile(&text).unwrap();
            assert_eq!(lock.deps[0].provenances, vec![want]);
        }
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
        assert_eq!(
            code_of("version 1\ndep {\n    version \"0.0.1\"\n}\n"),
            "LOCK-DEP-NAME-ARITY"
        );
        assert_eq!(
            code_of("version 1\ndep \"foo\" {\n    version \"0.0.1\" \"extra\"\n}\n"),
            "LOCK-DEP-FIELD-ARITY"
        );
        assert_eq!(
            code_of("version 1\ndep \"foo\" {\n    identity \"not-a-multihash\"\n}\n"),
            "LOCK-DEP-IDENTITY-INVALID"
        );
        assert_eq!(
            code_of("version 1\ndep \"foo\" {\n    provenance {\n        kind \"git\" \"extra\"\n    }\n}\n"),
            "LOCK-PROV-FIELD-ARITY"
        );
        assert_eq!(
            code_of("version 1\ndep \"foo\" {\n    provenance {\n        url \"https://e/x.git\"\n    }\n}\n"),
            "LOCK-PROV-KIND-MISSING"
        );
        assert_eq!(
            code_of("version 1\ndep \"foo\" {\n    provenance {\n        kind \"ftp\"\n    }\n}\n"),
            "LOCK-PROV-KIND-UNKNOWN"
        );
        assert_eq!(
            code_of("version 1\ndep \"foo\" {\n    provenance {\n        kind \"git\"\n        ref \"main\"\n    }\n}\n"),
            "LOCK-PROV-FIELD-MISSING"
        );
    }

    // --- emit (S5b) ---

    /// A hand-built Lockfile exercising every optional field + a git provenance,
    /// to pin the exact canonical byte layout (lockfile-schema §2.4).
    fn sample_lockfile() -> Lockfile {
        Lockfile {
            version: 1,
            strategy: "maxver".into(),
            deps: vec![LockedDep {
                name: "foo".into(),
                identity: Some(VALID_ID.into()),
                version: "1.2.3".into(),
                src_dir: "src".into(),
                requires: vec!["bar".into(), "baz".into()],
                provenances: vec![ProvenanceRecord::Git {
                    url: "https://example.com/foo.git".into(),
                    ref_spec: Some("main".into()),
                    commit_sha: Some("deadbeef".into()),
                }],
                active_flags: vec!["ssl".into()],
                self_mirrors: vec!["https://mirror.example/foo.git".into()],
                dep_decl: None,
                cond_requires: vec![],
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
             \x20   self_mirrors (url)\"https://mirror.example/foo.git\"\n\
             \x20   provenance {{\n\
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
            deps: vec![LockedDep {
                name: "foo".into(),
                identity: None,
                version: "0.0.1".into(),
                src_dir: String::new(),
                requires: vec![],
                provenances: vec![ProvenanceRecord::Local {
                    path: "../foo".into(),
                }],
                active_flags: vec![],
                self_mirrors: vec![],
                dep_decl: None,
                cond_requires: vec![],
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
        let nasty = "a\"b\\c\nd\re\tf\x08g\x0ch\x01i";
        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            deps: vec![LockedDep {
                name: nasty.into(),
                identity: None,
                version: nasty.into(),
                src_dir: nasty.into(),
                requires: vec![nasty.into()],
                provenances: vec![ProvenanceRecord::Git {
                    url: nasty.into(),
                    ref_spec: None,
                    commit_sha: None,
                }],
                active_flags: vec![],
                self_mirrors: vec![],
                dep_decl: None,
                cond_requires: vec![],
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
        assert_eq!(reparsed.deps[0].name, nasty);
        assert_eq!(reparsed.deps[0].version, nasty);
        assert_eq!(reparsed.deps[0].src_dir, nasty);
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
            deps: vec![LockedDep {
                name: "foo".into(),
                identity: None,
                version: "0.0.1".into(),
                src_dir: String::new(),
                requires: vec![],
                provenances: vec![ProvenanceRecord::Git {
                    url: "https://example.com/foo.git".into(),
                    ref_spec: Some(with_newline_and_tab.into()),
                    commit_sha: None,
                }],
                active_flags: vec![],
                self_mirrors: vec![],
                dep_decl: None,
                cond_requires: vec![],
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
        if let ProvenanceRecord::Git { ref_spec, .. } = prov {
            assert_eq!(ref_spec.as_deref(), Some(with_newline_and_tab));
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
            },
            ProvenanceRecord::Member {
                name: "liba".into(),
            },
            ProvenanceRecord::Oci {
                registry: "r".into(),
                repository: "o/p".into(),
                digest: "sha256:d".into(),
            },
            ProvenanceRecord::Registry {
                name: "n".into(),
                tag: Some("v1".into()),
                commit_sha: None,
            },
        ];
        for prov in kinds {
            let lock = Lockfile {
                version: 1,
                strategy: "maxver".into(),
                deps: vec![LockedDep {
                    name: "foo".into(),
                    identity: None,
                    version: "0.0.1".into(),
                    src_dir: String::new(),
                    requires: vec![],
                    provenances: vec![prov.clone()],
                    active_flags: vec![],
                    self_mirrors: vec![],
                    dep_decl: None,
                    cond_requires: vec![],
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
            name: name.into(),
            identity: format!("sha256:{}", "0".repeat(63) + "1"),
            version: Version::release(0, 0, 1),
            src_dir: "src".into(),
            requires: requires.into_iter().map(String::from).collect(),
            provenance: prov,
            dep_decl: None,
            cond_requires: vec![],
        }
    }

    fn git(url: &str, ref_spec: &str, sha: Option<&str>) -> ProvenanceRecord {
        ProvenanceRecord::Git {
            url: url.into(),
            ref_spec: opt(ref_spec),
            commit_sha: sha.map(String::from),
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
        let lock = from_graph(&graph, "maxver");
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
        let lock = from_graph(&graph, "minver");
        assert_eq!(lock.strategy, "minver");
        let dep = &lock.deps[0];
        assert_eq!(dep.version, "0.0.1");
        assert!(dep.identity.is_some());
        // Resolver-enrichment fields are emitted empty until the feature work.
        assert!(dep.active_flags.is_empty());
        assert!(dep.self_mirrors.is_empty());
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
                    },
                    vec![],
                ),
                rdep(
                    "l",
                    ProvenanceRecord::Local {
                        path: "../liba".into(),
                    },
                    vec![],
                ),
                rdep(
                    "m",
                    ProvenanceRecord::Member {
                        name: "liba".into(),
                    },
                    vec![],
                ),
                rdep(
                    "o",
                    ProvenanceRecord::Oci {
                        registry: "ghcr.io".into(),
                        repository: "org/pkg".into(),
                        digest: "sha256:dig".into(),
                    },
                    vec![],
                ),
            ],
        };
        let lock = from_graph(&graph, "maxver");
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
            }]
        );
        assert_eq!(
            by_name("t"),
            vec![ProvenanceRecord::Tarball {
                url: "https://e/t.tar.gz".into(),
                sha256: Some("sha256:tar".into()),
            }]
        );
        assert_eq!(
            by_name("l"),
            vec![ProvenanceRecord::Local {
                path: "../liba".into()
            }]
        );
        assert_eq!(
            by_name("m"),
            vec![ProvenanceRecord::Member {
                name: "liba".into()
            }]
        );
        assert_eq!(
            by_name("o"),
            vec![ProvenanceRecord::Oci {
                registry: "ghcr.io".into(),
                repository: "org/pkg".into(),
                digest: "sha256:dig".into(),
            }]
        );
    }

    #[test]
    fn from_graph_empty_git_ref_becomes_none() {
        let graph = ResolvedGraph {
            deps: vec![rdep("foo", git("https://e/foo.git", "", None), vec![])],
        };
        let lock = from_graph(&graph, "maxver");
        assert_eq!(
            lock.deps[0].provenances,
            vec![ProvenanceRecord::Git {
                url: "https://e/foo.git".into(),
                ref_spec: None,
                commit_sha: None,
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
        let lock = from_graph(&graph, "maxver");
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
        drifted.deps[0].identity = Some("sha256:different".into());
        assert_eq!(
            verify_against_graph(&drifted, &graph).unwrap_err().code(),
            "LOCK-GRAPH-MISMATCH"
        );
    }

    #[test]
    fn verify_lockfile_against_deps_reports_divergences() {
        let dir = std::env::temp_dir().join("milpa-s13-verify-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lock = Lockfile {
            version: 1,
            strategy: "maxver".into(),
            deps: vec![LockedDep {
                name: "foo".into(),
                identity: Some("sha256:00".into()),
                version: "0.0.1".into(),
                src_dir: String::new(),
                requires: vec![],
                provenances: vec![ProvenanceRecord::Local { path: "x".into() }],
                active_flags: vec![],
                self_mirrors: vec![],
                dep_decl: None,
                cond_requires: vec![],
            }],
        };
        // foo is not on disk → "missing" divergence.
        let d = verify_lockfile_against_deps(&lock, &dir);
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("foo") && d[0].contains("missing"));
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
        let lock = from_graph(&graph, "maxver");
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
            name: "qux".into(),
            identity: Some(VALID_ID.into()),
            version: "1.0.0".into(),
            src_dir: "src".into(),
            requires: vec!["bar".into(), "extra".into()],
            provenances: vec![ProvenanceRecord::Git {
                url: "https://example.com/qux.git".into(),
                ref_spec: None,
                commit_sha: None,
            }],
            active_flags: vec![],
            self_mirrors: vec![],
            dep_decl: None,
            cond_requires,
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
        let lf = Lockfile { version: 1, strategy: "maxver".into(), deps: vec![dep] };
        let text = format_lockfile(&lf);
        assert!(text.contains("    cond-require \"extra\" platform=\"linux\""), "got:\n{text}");
    }

    #[test]
    fn s4_single_predicate_inline_negated() {
        let dep = make_locked(vec![cr("extra", vec![pred("platform", "linux", true)])]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), deps: vec![dep] };
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
        let lf = Lockfile { version: 1, strategy: "maxver".into(), deps: vec![dep] };
        let text = format_lockfile(&lf);
        let expected_block = "    cond-require \"macstuff\" {\n        when platform=\"macosx\"\n        when platform=(not)\"linux\"\n    }";
        assert!(text.contains(expected_block), "got:\n{text}");
    }

    #[test]
    fn s4_cond_require_after_requires_line() {
        let dep = make_locked(vec![cr("extra", vec![pred("platform", "linux", false)])]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), deps: vec![dep] };
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
        let lf = Lockfile { version: 1, strategy: "maxver".into(), deps: vec![dep] };
        let reparsed = parse_lockfile(&format_lockfile(&lf)).unwrap();
        assert_eq!(reparsed.deps[0].cond_requires, lf.deps[0].cond_requires);
    }

    #[test]
    fn s4_round_trip_negated() {
        let dep = make_locked(vec![cr("extra", vec![pred("platform", "linux", true)])]);
        let lf = Lockfile { version: 1, strategy: "maxver".into(), deps: vec![dep] };
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
        let lf = Lockfile { version: 1, strategy: "maxver".into(), deps: vec![dep] };
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
        let text_no = format_lockfile(&Lockfile { version: 1, strategy: "maxver".into(), deps: vec![dep_no_cond] });
        let text_with = format_lockfile(&Lockfile { version: 1, strategy: "maxver".into(), deps: vec![dep_with_cond] });
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
             dep \"foo\" {{\n\
             \x20   version \"0.0.1\"\n\
             \x20   src_dir \"\"\n\
             \x20   requires\n\
             \x20   cond-require \"bar\" evilkey=\"value\"\n\
             \x20   provenance {{\n\
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
             dep \"foo\" {{\n\
             \x20   version \"0.0.1\"\n\
             \x20   src_dir \"\"\n\
             \x20   requires\n\
             \x20   cond-require \"bar\" {{\n\
             \x20       when evilkey=\"value\"\n\
             \x20   }}\n\
             \x20   provenance {{\n\
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
             dep \"foo\" {{\n\
             \x20   version \"0.0.1\"\n\
             \x20   src_dir \"\"\n\
             \x20   requires\n\
             \x20   cond-require \"bar\" platform=\"linux\"\n\
             \x20   provenance {{\n\
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
        let lf = Lockfile { version: 1, strategy: "maxver".into(), deps: vec![dep] };
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
        let text1 = format_lockfile(&Lockfile { version: 1, strategy: "maxver".into(), deps: vec![dep1] });
        let text2 = format_lockfile(&Lockfile { version: 1, strategy: "maxver".into(), deps: vec![dep2] });
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
             dep \"foo\" {{\n\
             \x20   version \"0.0.1\"\n\
             \x20   src_dir \"\"\n\
             \x20   requires\n\
             \x20   cond-require platform=\"linux\"\n\
             \x20   provenance {{\n\
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
             dep \"foo\" {{\n\
             \x20   version \"0.0.1\"\n\
             \x20   src_dir \"\"\n\
             \x20   requires\n\
             \x20   cond-require \"bar\" {{\n\
             \x20       unknown-child platform=\"linux\"\n\
             \x20       when platform=\"macosx\"\n\
             \x20   }}\n\
             \x20   provenance {{\n\
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
             dep \"foo\" {{\n\
             \x20   version \"0.0.1\"\n\
             \x20   src_dir \"\"\n\
             \x20   requires\n\
             \x20   cond-require \"bar\" {{\n\
             \x20       when\n\
             \x20   }}\n\
             \x20   provenance {{\n\
             \x20       kind \"local\"\n\
             \x20       path \"../foo\"\n\
             \x20   }}\n\
             }}\n"
        );
        let lf = parse_lockfile(&sample).unwrap();
        // No predicates → None → not appended.
        assert!(lf.deps[0].cond_requires.is_empty());
    }
}
