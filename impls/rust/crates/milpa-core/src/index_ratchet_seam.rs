//! index-history ratchet seam — bridges a parsed `Index` to `ratchet::IndexState`,
//! and decides what the index-cache gate should do with the result
//! (registry-protocol §3.5.2/§3.5.3, `rfc-registry-append-only.md` slice A3).
//! Mirrors `impls/python/milpa/index_ratchet_seam.py`.
//!
//! This module is **pure computation**: it never touches the filesystem.
//! `index_cache.rs` owns every read and write of the baseline sidecar pair
//! (mirroring how it already owns the bundle/index/stamp sidecars); this
//! module answers "what does this text parse to" and "what should happen
//! given a policy, a candidate, and an optional baseline" as data (or an
//! `Err(MilpaError)`), and `index_cache.rs` acts on the answer.
//!
//! Two responsibilities:
//!
//! 1. **State extraction** ([`build_index_state`]) — parses `text` with
//!    `Index::parse` (registry.rs's own validated parser — single source of
//!    truth for structural validation) and folds the result into a
//!    `ratchet::IndexState`. Unlike the Python impl (whose `IndexVersion`
//!    retains only typed values, forcing a separate raw-KDL re-walk for
//!    `published_at`), Rust's `IndexVersion` already carries
//!    `published_at_raw` alongside the typed `published_at` (registry.rs),
//!    so this module needs only TWO extra raw lookups — the document-root
//!    `schema_version` integer and `attestation-epoch` string, neither of
//!    which `Index` itself retains. `attestation`/`rekor` get their own
//!    canonical (never `Debug`-derived) rendering per §3.5.3 NORMATIVE
//!    (canonical rendering for non-scalar candidate values) — see
//!    [`attestation_canonical_raw`] / [`rekor_canonical_raw`] below, live as
//!    of A6 alongside the `attestation`/`rekor`/`attestation-epoch` rows'
//!    enforcement (registry-protocol §3.5.1 NORMATIVE (staged enforcement)).
//!
//! 2. **The gate decision** ([`evaluate_gate`]) — TOFU establishment, the
//!    sticky-advance clean/dirty branch, warn's new-vs-recurring habituation
//!    defense, and strict's hard-fail. Returns a [`GateDecision`] the caller
//!    acts on: which bytes (if any) to write to the baseline sidecar, what
//!    to write to `.baseline.meta`, and what (if anything) to print to stderr.

use kdl::KdlDocument;
use milpa_manifest::TrustPolicy;

use crate::error::{CoreError, MilpaError};
use crate::ratchet::{
    canonical_digest, AttestationValue, Baseline, EntryKey, FieldValue, IndexState, RatchetEntry,
    RawField, Transition, Violation,
};
use crate::registry::{validate_no_control_chars, Index};

fn tng(code: &'static str, message: impl Into<String>) -> MilpaError {
    MilpaError::Core(CoreError::Tianguis(code, message.into()))
}

// ---------------------------------------------------------------------------
// Candidate/baseline text -> (typed Index, ratchet IndexState)
// ---------------------------------------------------------------------------

/// Parse `text` (already UTF-8-decoded index bytes) into both the typed,
/// validated [`Index`] (`Index::parse` — raises the usual `TNG-*` codes on
/// malformed input) and the ratchet [`IndexState`].
///
/// This IS the parse-at-gate seam (registry-protocol §3.5.2 NORMATIVE (the
/// check)): an error here means the candidate is never written to the cache
/// — the caller must not have touched disk yet.
pub fn build_index_state(text: &str) -> Result<(Index, IndexState), MilpaError> {
    let index = Index::parse(text).map_err(MilpaError::from)?;
    let schema_version = raw_schema_version(text)?;
    let attestation_epoch = raw_attestation_epoch(text)?;
    Ok((index.clone(), index_state_from(schema_version, attestation_epoch, &index)))
}

/// The document-root `schema_version` integer, or `None` if absent (the
/// ordinal-non-decreasing dominance function treats `None` as the spec
/// default `1` — registry-protocol §3.5.1 root-field table). A SEPARATE
/// re-walk because `Index` (registry.rs) does not retain this root field —
/// it is consumed for validation only (`check_schema_version`), never
/// exposed on the parsed type.
fn raw_schema_version(text: &str) -> Result<Option<i64>, MilpaError> {
    let doc = KdlDocument::parse(text)
        .map_err(|e| tng("TNG-KDL-SYNTAX", format!("index KDL syntax error: {e}")))?;
    for node in doc.nodes() {
        if node.name().value() != "schema_version" {
            continue;
        }
        return Ok(node
            .entries()
            .iter()
            .find(|e| e.name().is_none())
            .and_then(|e| e.value().as_integer())
            .and_then(|v| i64::try_from(v).ok()));
    }
    Ok(None)
}

/// The document-root `attestation-epoch` string, or `None` if absent
/// (`rfc-per-entry-attestation.md` open question 2; registry-protocol
/// §3.5.1 root-field table — set-once, live as of A6). An opaque epoch
/// identifier: no reformatting margin, so the typed value doubles as its
/// own raw digest rendering (the scalar-field convention). A SEPARATE
/// re-walk for the same reason as `raw_schema_version` — `Index` does not
/// retain this root field.
///
/// This is the ONLY site that ever extracts `attestation-epoch` — it lives
/// outside every `package` node, so `Index::parse`'s own charset pass never
/// sees it. It feeds the root pseudo-entry's canonical violation digest
/// (§3.5.3) as a raw, unescaped scalar, so this is ALSO the only site that
/// can charset-check it — the same `TNG-UNSAFE-CONTROL-CHAR` guard
/// `Index::parse` applies to every other free-text field (registry-protocol
/// §3.3 NORMATIVE).
fn raw_attestation_epoch(text: &str) -> Result<Option<String>, MilpaError> {
    let doc = KdlDocument::parse(text)
        .map_err(|e| tng("TNG-KDL-SYNTAX", format!("index KDL syntax error: {e}")))?;
    for node in doc.nodes() {
        if node.name().value() != "attestation-epoch" {
            continue;
        }
        let epoch = node
            .entries()
            .iter()
            .find(|e| e.name().is_none())
            .and_then(|e| e.value().as_string())
            .map(str::to_string);
        if let Some(ref e) = epoch {
            validate_no_control_chars(e, "attestation-epoch").map_err(MilpaError::from)?;
        }
        return Ok(epoch);
    }
    Ok(None)
}

fn index_state_from(schema_version: Option<i64>, attestation_epoch: Option<String>, index: &Index) -> IndexState {
    let mut state = IndexState::new();

    let mut root = RatchetEntry::new();
    if let Some(v) = schema_version {
        root = root.set("schema_version", RawField::new(FieldValue::Int(v)));
    }
    if let Some(e) = attestation_epoch {
        root = root.set("attestation-epoch", RawField::new(FieldValue::Str(e)));
    }
    state.insert(EntryKey::root(), root);

    for pkg in &index.packages {
        for iv in &pkg.versions {
            let key = EntryKey::new(iv.namespace.clone(), pkg.name.clone(), iv.version.clone());
            let mut entry = RatchetEntry::new();
            if !iv.content_hash.is_empty() {
                entry = entry.set("content_hash", RawField::new(FieldValue::Str(iv.content_hash.clone())));
            }
            if let Some(ts) = iv.published_at {
                let encoded = ts.unix_seconds.saturating_mul(1_000_000_000).saturating_add(i64::from(ts.nanos));
                let raw = iv.published_at_raw.clone().unwrap_or_default();
                entry = entry.set("published_at", RawField::with_raw(FieldValue::Int(encoded), raw));
            }
            if let Some(d) = &iv.dep_decl {
                entry = entry.set("dep_decl", RawField::new(FieldValue::Str(d.clone())));
            }
            if let Some(v) = iv.dep_decl_schema_version {
                entry = entry.set("dep_decl_schema_version", RawField::new(FieldValue::Int(v)));
            }
            if !iv.provenances.is_empty() {
                let raw = provenance_canonical_raw(&iv.provenances);
                entry = entry.set(
                    "provenances",
                    RawField::with_raw(FieldValue::ProvenanceList(iv.provenances.clone()), raw),
                );
            }
            entry = entry.set("yanked", RawField::new(FieldValue::Bool(iv.yanked)));
            if let Some(r) = &iv.yanked_reason {
                entry = entry.set("yanked_reason", RawField::new(FieldValue::Str(r.clone())));
            }
            if let Some(att) = &iv.attestation {
                let raw = attestation_canonical_raw(Some(att));
                entry = entry.set(
                    "attestation",
                    RawField::with_raw(FieldValue::Attestation(encode_attestation(att)), raw),
                );
                if let Some(r) = &att.rekor {
                    let raw = rekor_canonical_raw(Some(r));
                    entry = entry.set("rekor", RawField::with_raw(FieldValue::Rekor(r.clone()), raw));
                }
            }
            state.insert(key, entry);
        }
    }
    state
}

/// Canonical, cross-impl-identical rendering of a provenance multiset for
/// the §3.5.3 canonical violation digest (NORMATIVE (canonical rendering
/// for non-scalar candidate values)) — the MUST-RESOLVE item flagged at A3:
/// `FieldValue::ProvenanceList`'s `raw_str()` fallback is Rust's `Debug`
/// format for `Vec<Provenance>`, which diverges byte-for-byte from Python's
/// dataclass-tuple `str()` fallback for identical semantic content — this
/// function supplies the `raw` explicitly so that fallback is never reached
/// in production. Each record is encoded as
/// `<kind>\x1f<field1>\x1f<field2>\x1f<field3>[\x1f<field4>]` in the
/// record's own declared field order (git: url, ref, commit_sha; oci:
/// registry, repository, digest, source; an absent optional field renders
/// as the empty string); records are sorted lexicographically by their own
/// encoding (never by document position — order is advisory-mutable,
/// §3.5.1) and joined with `\x1e`. The `oci` instantiation's `source` field
/// was added closing the digest-collision gap tracked at registry-protocol
/// §3.5.3 (two violations differing only in `source` used to hash
/// identically). Mirrors `index_ratchet_seam.py::_provenance_canonical_raw`
/// byte-for-byte.
fn provenance_canonical_raw(provenances: &[milpa_types::Provenance]) -> String {
    use milpa_types::Provenance;
    let mut encoded: Vec<String> = provenances
        .iter()
        .map(|p| match p {
            Provenance::Git { url, ref_spec, commit_sha } => {
                format!("git\u{1f}{url}\u{1f}{ref_spec}\u{1f}{}", commit_sha.as_deref().unwrap_or(""))
            }
            Provenance::Oci { registry, repository, digest, source_url } => {
                format!(
                    "oci\u{1f}{registry}\u{1f}{repository}\u{1f}{digest}\u{1f}{}",
                    source_url.as_deref().unwrap_or("")
                )
            }
            // registry.rs's index parser only ever constructs Git/Oci provenance
            // records (§3.3); unreachable here but the match must stay
            // exhaustive since `Provenance` is a shared closed enum (RFC §4.6).
            Provenance::Tarball { .. } | Provenance::Local { .. } => {
                format!("unrecognized\u{1f}{p:?}")
            }
        })
        .collect();
    encoded.sort();
    encoded.join("\u{1e}")
}

fn encode_attestation(att: &milpa_types::EntryAttestation) -> AttestationValue {
    use milpa_types::AttestationKind;
    match &att.kind {
        AttestationKind::AuthorSigned { signer } => AttestationValue {
            kind: "author-signed".to_string(),
            signer: Some(signer.clone()),
            bundle_pin: att.bundle_pin.clone(),
        },
        AttestationKind::MilpaVendored => AttestationValue {
            kind: "milpa-vendored".to_string(),
            signer: None,
            bundle_pin: att.bundle_pin.clone(),
        },
    }
}

/// Canonical, cross-impl-identical rendering of an `EntryAttestation` for
/// the §3.5.3 canonical violation digest (NORMATIVE (canonical rendering
/// for non-scalar candidate values) — the `attestation` instantiation, live
/// as of A6): a single closed field set — `kind`, `signer` (`author-signed`
/// only, empty for `milpa-vendored`), `bundle_pin` (empty when unset) —
/// encoded as `<kind>\x1f<signer>\x1f<bundle_pin>`. Empty string when
/// `attestation` is absent, consistent with the scalar-field absent-
/// component convention. Mirrors
/// `index_ratchet_seam.py::_attestation_canonical_raw` byte-for-byte.
fn attestation_canonical_raw(att: Option<&milpa_types::EntryAttestation>) -> String {
    use milpa_types::AttestationKind;
    let Some(att) = att else {
        return String::new();
    };
    let (kind, signer) = match &att.kind {
        AttestationKind::AuthorSigned { signer } => ("author-signed", signer.as_str()),
        AttestationKind::MilpaVendored => ("milpa-vendored", ""),
    };
    format!("{kind}\u{1f}{signer}\u{1f}{}", att.bundle_pin.as_deref().unwrap_or(""))
}

/// Canonical rendering of the `rekor` block for the canonical violation
/// digest (§3.5.3 NORMATIVE (canonical rendering for non-scalar candidate
/// values) — the `rekor` instantiation, live as of A6): the same
/// closed-field-set method, field order `uuid`, `log_index`,
/// `integrated_time`, joined by `\x1f`. Empty string when `rekor` is
/// absent. Mirrors `index_ratchet_seam.py::_rekor_canonical_raw`
/// byte-for-byte.
fn rekor_canonical_raw(rekor: Option<&milpa_types::RekorRef>) -> String {
    let Some(r) = rekor else {
        return String::new();
    };
    format!("{}\u{1f}{}\u{1f}{}", r.uuid, r.log_index, r.integrated_time)
}

// ---------------------------------------------------------------------------
// Baseline parse — corruption maps to TNG-INDEX-BASELINE-CORRUPT, never a
// raw parse slug (registry-protocol §3.5.2 NORMATIVE (baseline corruption
// is not TOFU)).
// ---------------------------------------------------------------------------

pub fn parse_baseline(text: &str) -> Result<IndexState, MilpaError> {
    match build_index_state(text) {
        Ok((_, state)) => Ok(state),
        Err(e) => {
            let hint = if e.code() == "TNG-SCHEMA-UNKNOWN" {
                " (possible version skew — baseline was written by a newer milpa)"
            } else {
                ""
            };
            Err(tng(
                "TNG-INDEX-BASELINE-CORRUPT",
                format!(
                    "baseline sidecar is unparseable or truncated{hint}; \
                     re-establish the trust anchor via `milpa index accept`"
                ),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// .baseline.meta — advisory (registry-protocol §3.5.2 NORMATIVE: missing or
// stale relative to .baseline self-heals to "unset", never an error).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BaselineMeta {
    pub established_at: Option<String>,
    pub reported_digest: Option<String>,
    pub reported_at: Option<String>,
}

impl BaselineMeta {
    pub fn render(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        if let Some(v) = &self.established_at {
            lines.push(format!("established_at \"{v}\""));
        }
        if let Some(v) = &self.reported_digest {
            lines.push(format!("reported_digest \"{v}\""));
        }
        if let Some(v) = &self.reported_at {
            lines.push(format!("reported_at \"{v}\""));
        }
        if lines.is_empty() {
            String::new()
        } else {
            let mut out = lines.join("\n");
            out.push('\n');
            out
        }
    }
}

/// Best-effort parse of `.baseline.meta`. NEVER raises — any corruption
/// self-heals to an unset reported-set.
pub fn parse_baseline_meta(text: &str) -> BaselineMeta {
    let Ok(doc) = KdlDocument::parse(text) else {
        return BaselineMeta::default();
    };
    let top = |name: &str| -> Option<String> {
        doc.nodes().iter().find(|n| n.name().value() == name).and_then(|n| {
            n.entries()
                .iter()
                .find(|e| e.name().is_none())
                .and_then(|e| e.value().as_string())
                .map(str::to_string)
        })
    };
    BaselineMeta {
        established_at: top("established_at"),
        reported_digest: top("reported_digest"),
        reported_at: top("reported_at"),
    }
}

/// Howard Hinnant's `civil_from_days` inverse — (year, month, day) for days
/// since the Unix epoch (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// ISO-8601 UTC rendering matching Python's
/// `datetime.fromtimestamp(now_unix, tz=UTC).isoformat()` — `+00:00`, not
/// `Z` (Python's `isoformat()` never emits the `Z` shorthand).
pub fn iso_timestamp(now_unix: i64) -> String {
    let days = now_unix.div_euclid(86400);
    let secs_of_day = now_unix.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}+00:00")
}

// ---------------------------------------------------------------------------
// The gate decision
// ---------------------------------------------------------------------------

/// What `index_cache.rs` should do after a successful gate evaluation.
///
/// `index` is always populated (parse-at-gate's typed result) so the caller
/// never re-parses. `advance` says whether to write a NEW baseline (only on
/// a clean diff or TOFU establishment — sticky-advance, §3.5.2). `new_meta`
/// is what to (over)write to `.baseline.meta`; `None` means leave the
/// existing file untouched (the *recurring*-warn case, and the
/// `off`-policy no-op case).
#[derive(Debug, Clone)]
pub struct GateDecision {
    pub index: Index,
    pub advance: bool,
    pub new_meta: Option<BaselineMeta>,
    /// Pre-formatted diagnostic text the caller should print to stderr AFTER
    /// the ordinary warn-path writes complete (mirrors index_ratchet_seam.py's
    /// `warn_message`). `None` means nothing to print.
    pub warn_message: Option<String>,
}

/// The full §3.5.2 decision, given already-read baseline/meta text
/// (`baseline_text` is `None` exactly when the baseline sidecar is absent,
/// i.e. TOFU). Touches no filesystem I/O.
///
/// This function is NOT entirely stdout/stderr-free: it prints
/// yank-transition notices ([`print_yank_notice`]) directly and
/// immediately, because registry-protocol §3.5.3 requires those to fire
/// "under `warn` and `strict` alike" — including the `strict` path below,
/// which returns `Err` before ever producing a `GateDecision`, so there is
/// no later "caller prints it" point to defer to for that one diagnostic.
/// Every OTHER diagnostic is pure data, not a direct print: the warn-path
/// violation message comes back via [`GateDecision::warn_message`] for the
/// caller to print AFTER the ordinary warn-path writes complete (see that
/// field's doc comment); the strict-path message rides the returned `Err`
/// itself, for whatever prints that error.
///
/// Errors:
///   - the ordinary `TNG-*` parse/validation slug if `candidate_text`
///     doesn't parse (parse-at-gate — happens regardless of `policy`);
///   - `TNG-INDEX-BASELINE-CORRUPT` if `baseline_text` is present but
///     unparseable (regardless of `policy`, except `off` never reaches this
///     branch since it never reads the baseline);
///   - the primary violation's slug (`TNG-INDEX-ROOT-MUTATED` /
///     `TNG-INDEX-ROLLBACK` / `TNG-ENTRY-MUTATED`) under `strict`.
///
/// In every erroring case the caller MUST NOT have written anything to the
/// cache yet (registry-protocol §3.5.2 NORMATIVE (the check) / per-policy
/// `strict` row: "no cache mutation at all").
#[allow(clippy::too_many_arguments)]
pub fn evaluate_gate(
    policy: &TrustPolicy,
    candidate_text: &str,
    baseline_text: Option<&str>,
    existing_meta: &BaselineMeta,
    now_unix: i64,
    url: &str,
) -> Result<GateDecision, MilpaError> {
    let (index, candidate_state) = build_index_state(candidate_text)?; // parse-at-gate

    if *policy == TrustPolicy::Off {
        return Ok(GateDecision { index, advance: false, new_meta: None, warn_message: None });
    }

    let Some(baseline_text) = baseline_text else {
        // TOFU: first contact ever for this URL — nothing to diff, nothing
        // to alarm on. Establishes the trust anchor.
        let meta = BaselineMeta {
            established_at: Some(iso_timestamp(now_unix)),
            reported_digest: None,
            reported_at: None,
        };
        return Ok(GateDecision { index, advance: true, new_meta: Some(meta), warn_message: None });
    };

    let baseline_state = parse_baseline(baseline_text)?; // may raise BASELINE-CORRUPT
    let outcome = Baseline::new(baseline_state).check(&candidate_state);

    for transition in &outcome.transitions {
        print_yank_notice(transition);
    }

    if outcome.clean() {
        // `.filter(|s| !s.is_empty())` (not just `Option`-emptiness) is
        // deliberate: an empty-string `established_at` (hand-corrupted
        // meta, or a pre-this-fix write) self-heals the same as an absent
        // one, rather than freezing the corruption in place forever.
        // Mirrors Python's `existing_meta.established_at or
        // iso_timestamp(now_unix)` (`index_ratchet_seam.py`).
        let meta = BaselineMeta {
            established_at: Some(
                existing_meta
                    .established_at
                    .clone()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| iso_timestamp(now_unix)),
            ),
            reported_digest: None,
            reported_at: None,
        };
        return Ok(GateDecision { index, advance: true, new_meta: Some(meta), warn_message: None });
    }

    let digest = canonical_digest(&outcome.violations);
    let recurring = existing_meta.reported_digest.as_deref() == Some(digest.as_str());
    let message = format_violation_message(&outcome.violations, &digest, recurring, existing_meta.reported_at.as_deref());

    if *policy == TrustPolicy::Strict {
        // Structured digest (registry-protocol §3.5.3 NORMATIVE (canonical
        // violation digest)), not embedded-in-message-text — mirrors
        // Python's `MilpaError(..., digest=digest, ...)` context kwarg
        // (`index_ratchet_seam.py::evaluate_gate`). See
        // `CoreError::RatchetViolation`'s doc comment for why this is a
        // dedicated variant rather than `tng()`'s 2-tuple `Tianguis`.
        return Err(MilpaError::Core(CoreError::RatchetViolation {
            code: outcome.violations[0].class,
            message: format!("{message}\n  index: {url:?}"),
            digest,
        }));
    }

    // warn: serve the new index (bundle/index/stamp advance as usual); the
    // baseline itself stays sticky (advance=false); .meta only rewrites on
    // a NEW digest (habituation defense). The diagnostic itself is NOT
    // printed here — it rides back as `warn_message` for the caller
    // (`index_cache.rs`'s `apply_ratchet_writes`) to print AFTER the
    // writes below complete.
    let new_meta = if recurring {
        None
    } else {
        Some(BaselineMeta {
            established_at: existing_meta.established_at.clone(),
            reported_digest: Some(digest),
            reported_at: Some(iso_timestamp(now_unix)),
        })
    };
    Ok(GateDecision { index, advance: false, new_meta, warn_message: Some(message) })
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// §3.5.3 NORMATIVE (yank-transition notices are not errors): fires under
/// `warn` and `strict` alike, never affects the exit code, never blocks the
/// baseline from advancing.
pub fn print_yank_notice(t: &Transition) {
    let coord = format!("{}/{}@{}", t.entry_key.namespace, t.entry_key.name, t.entry_key.version);
    let reason = t.reason.as_deref().map(|r| format!(" ({r})")).unwrap_or_default();
    eprintln!("[milpa] warning: yank-state changed: {coord} — {}{reason}", t.direction);
}

/// Human-readable diagnostic. Message wording is NOT byte-normative (only
/// the slug + structured payload are); both required remediation hints
/// (§3.5.3 NORMATIVE (remediation hints required)) are always present.
fn format_violation_message(violations: &[Violation], digest: &str, recurring: bool, reported_at: Option<&str>) -> String {
    let primary = &violations[0];
    let coord = if primary.entry_key == EntryKey::root() {
        "<document root>".to_string()
    } else {
        format!("{}/{}@{}", primary.entry_key.namespace, primary.entry_key.name, primary.entry_key.version)
    };
    let field_part = if primary.field.is_empty() {
        String::new()
    } else {
        format!(" field={:?}", primary.field)
    };
    let mut lines = vec![format!(
        "[milpa] warning: index-history violation ({}) at {coord}{field_part}: {}",
        primary.class, primary.kind
    )];
    if violations.len() > 1 {
        lines.push(format!("  ...and {} more violation(s) in this diff", violations.len() - 1));
    }
    if recurring {
        lines.push(format!(
            "  recurring (first reported {}); digest unchanged: {digest}",
            reported_at.unwrap_or("unknown")
        ));
    } else {
        lines.push(format!("  digest={digest}"));
    }
    lines.push(
        "  remedy: revert the mutation upstream, or run `milpa index accept` \
         after out-of-band confirmation that this history rewrite is legitimate"
            .to_string(),
    );
    lines.join("\n")
}

#[cfg(test)]
#[path = "index_ratchet_seam_tests.rs"]
mod index_ratchet_seam_tests;
