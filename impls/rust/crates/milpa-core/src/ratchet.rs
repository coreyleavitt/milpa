//! Consumer ratchet — pure in-memory dominance-fold engine (registry-protocol
//! §3.5, `rfc-registry-append-only.md` slice A2b/A3).
//!
//! Mirrors `impls/python/milpa/ratchet.py` field-for-field, including the
//! canonical violation digest (§3.5.3 NORMATIVE) which MUST produce identical
//! bytes across implementations. This module is a **standalone** engine: no
//! filesystem I/O, no sidecar lifecycle, no `index-history` policy plumbing,
//! no CLI. It answers exactly one question — "does *candidate* legally
//! dominate *baseline*?" — and reports the answer as data.
//!
//! Staged rows (`attestation`, `rekor`, `attestation-epoch`) are tagged
//! `staged: true` in the lattice and excluded from [`Baseline::check`] by
//! default (registry-protocol §3.5.1 NORMATIVE (staged enforcement)); pass
//! `include_staged: true` to exercise the full lattice — used only by this
//! module's own tests. Production call sites (A3's index-cache seam) must
//! not flip that flag before A6.

use std::collections::BTreeMap;
use std::collections::HashMap;

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Order-kind tags (registry-protocol §3.5.1) — five DISJOINT tags.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderKind {
    SetOnce,
    AttestationMonotone,
    AppendOnlyMultiset,
    AdvisoryMutable,
    OrdinalNonDecreasing,
}

// ---------------------------------------------------------------------------
// Violation classes (§3.5.3) and sub-class "kind" discriminators — plain
// string constants, matching `ratchet.py`'s posture (these are not yet
// declared in `error.rs`'s `all_codes()` bijection catalog as slugs; A3 adds
// the 3 raise-site slugs there, see `error.rs`).
// ---------------------------------------------------------------------------

pub const ROOT_MUTATED: &str = "TNG-INDEX-ROOT-MUTATED";
pub const ROLLBACK: &str = "TNG-INDEX-ROLLBACK";
pub const ENTRY_MUTATED: &str = "TNG-ENTRY-MUTATED";

fn class_rank(class: &str) -> u8 {
    match class {
        ROOT_MUTATED => 0,
        ROLLBACK => 1,
        ENTRY_MUTATED => 2,
        _ => 255,
    }
}

/// Closed set (§3.5.3 NORMATIVE (structured payload)).
pub const FROZEN_CHANGED: &str = "frozen-changed";
pub const FROZEN_UNSET: &str = "frozen-unset";
pub const MONOTONE_STRIPPED: &str = "monotone-stripped";
pub const MONOTONE_REATTRIBUTED: &str = "monotone-reattributed";
pub const MONOTONE_DOWNGRADED: &str = "monotone-downgraded";
pub const MONOTONE_REPINNED: &str = "monotone-repinned";
pub const PROVENANCE_REMOVED: &str = "provenance-removed";
pub const ROOT_FIELD_CHANGED: &str = "root-field-changed";

// ---------------------------------------------------------------------------
// Entry key (§3.5.1 NORMATIVE (entry key))
// ---------------------------------------------------------------------------

/// `(namespace, name, raw version string)` — the entry key. Keying on the raw
/// version string (not a parsed/normalized version) means a cosmetic
/// re-spelling is a disappearance-plus-appearance under this key, caught as
/// rollback, not silently matched (§3.5.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryKey {
    pub namespace: String,
    pub name: String,
    pub version: String,
}

impl EntryKey {
    pub fn new(namespace: impl Into<String>, name: impl Into<String>, version: impl Into<String>) -> Self {
        EntryKey {
            namespace: namespace.into(),
            name: name.into(),
            version: version.into(),
        }
    }

    /// The reserved empty key document-root fields fold under (§3.5.1
    /// NORMATIVE (root-level fields)) — exactly the key §3.5.3's composite
    /// ordering already assigns root violations.
    pub fn root() -> Self {
        EntryKey::new("", "", "")
    }

    pub fn is_root(&self) -> bool {
        self.namespace.is_empty() && self.name.is_empty() && self.version.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Input shape: RawField / RatchetEntry / IndexState
// ---------------------------------------------------------------------------

/// The typed value used for dominance comparison. `None` is the canonical
/// absent sentinel for EVERY order kind — callers MUST normalize
/// domain-specific empties (e.g. `IndexVersion.content_hash == ""`) to
/// `None` before constructing a [`RatchetEntry`].
#[derive(Debug, PartialEq, Eq)]
pub enum FieldValue {
    Str(String),
    Int(i64),
    Bool(bool),
    StrList(Vec<String>),
    Attestation(AttestationValue),
}

/// Structural snapshot of an `EntryAttestation` for ratchet comparison.
/// `kind` is `"author-signed"` or `"milpa-vendored"`; `signer` is `None` for
/// vendored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationValue {
    pub kind: String,
    pub signer: Option<String>,
    pub bundle_pin: Option<String>,
}

/// One field's value on one entry snapshot (baseline OR candidate side).
///
/// `raw` is the "raw document string exactly as served" the canonical
/// digest requires. Falls back to a `Display`-style rendering of `value`
/// via [`RawField::raw_str`] when omitted.
#[derive(Debug, Clone, Default)]
pub struct RawField {
    pub value: Option<FieldValue>,
    pub raw: Option<String>,
}

impl RawField {
    pub fn absent() -> Self {
        RawField::default()
    }

    pub fn new(value: FieldValue) -> Self {
        RawField {
            value: Some(value),
            raw: None,
        }
    }

    pub fn with_raw(value: FieldValue, raw: impl Into<String>) -> Self {
        RawField {
            value: Some(value),
            raw: Some(raw.into()),
        }
    }

    /// The digest-ready raw string: `""` when absent, else `raw` or a
    /// rendering of `value`.
    pub fn raw_str(&self) -> String {
        let Some(value) = &self.value else {
            return String::new();
        };
        if let Some(raw) = &self.raw {
            return raw.clone();
        }
        match value {
            FieldValue::Str(s) => s.clone(),
            FieldValue::Int(i) => i.to_string(),
            FieldValue::Bool(b) => b.to_string(),
            FieldValue::StrList(items) => {
                // Only reached when no explicit raw was supplied; mirrors
                // Python's `str(value)` fallback for a tuple — not exercised
                // by production call sites (provenances always compare, never
                // digest-render, since they're never Frozen).
                format!("{items:?}")
            }
            FieldValue::Attestation(a) => format!("{a:?}"),
        }
    }
}

/// One entry's (or the reserved root pseudo-entry's) field snapshot. A field
/// absent from the map is equivalent to an explicit absent [`RawField`].
#[derive(Debug, Clone, Default)]
pub struct RatchetEntry {
    pub fields: HashMap<String, RawField>,
}

impl RatchetEntry {
    pub fn new() -> Self {
        RatchetEntry::default()
    }

    pub fn set(mut self, name: impl Into<String>, field: RawField) -> Self {
        self.fields.insert(name.into(), field);
        self
    }

    pub fn get(&self, name: &str) -> RawField {
        self.fields.get(name).cloned().unwrap_or_default()
    }
}

// Manual Clone for RawField's FieldValue (Attestation variant is Clone too).
impl Clone for FieldValue {
    fn clone(&self) -> Self {
        match self {
            FieldValue::Str(s) => FieldValue::Str(s.clone()),
            FieldValue::Int(i) => FieldValue::Int(*i),
            FieldValue::Bool(b) => FieldValue::Bool(*b),
            FieldValue::StrList(v) => FieldValue::StrList(v.clone()),
            FieldValue::Attestation(a) => FieldValue::Attestation(a.clone()),
        }
    }
}

/// A parsed index state: every observed entry key (INCLUDING the reserved
/// root key for document-root fields, if any are set) mapped to its field
/// snapshot.
pub type IndexState = BTreeMap<EntryKey, RatchetEntry>;

// ---------------------------------------------------------------------------
// Violations, transitions, outcome
// ---------------------------------------------------------------------------

/// `(class, entry_key, field, kind, baseline_value, candidate_value)`
/// (§3.5.3 NORMATIVE (structured payload)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub class: &'static str,
    pub entry_key: EntryKey,
    pub field: String,
    pub kind: &'static str,
    pub baseline_value: String,
    pub candidate_value: String,
}

/// A legal advisory-mutable transition surfaced for the caller to report —
/// never a violation, never blocks `advanced` (§3.5.3 NORMATIVE
/// (yank-transition notices are not errors)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub entry_key: EntryKey,
    pub kind: &'static str, // "yank"
    pub direction: &'static str, // "yanked" | "unyanked"
    pub reason: Option<String>,
}

/// `Baseline::check(candidate) -> RatchetOutcome` — the verdict. Monomorphic:
/// one index shape, one outcome shape. `violations` IS the verdict;
/// `advanced` is true iff `violations` is empty (sticky-advance,
/// §3.5.2) — *writing* the advanced baseline is the caller's job.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RatchetOutcome {
    pub violations: Vec<Violation>,
    pub advanced: bool,
    pub transitions: Vec<Transition>,
}

impl RatchetOutcome {
    pub fn clean(&self) -> bool {
        self.violations.is_empty()
    }
}

// ---------------------------------------------------------------------------
// The lattice (registry-protocol §3.5.1's table, transcribed as data).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct FieldSpec {
    kind: OrderKind,
    /// True = enforcement deferred to `rfc-registry-append-only.md`'s A6
    /// slice (§3.5.1 NORMATIVE (staged enforcement)).
    staged: bool,
}

const fn spec(kind: OrderKind) -> FieldSpec {
    FieldSpec { kind, staged: false }
}
const fn staged_spec(kind: OrderKind) -> FieldSpec {
    FieldSpec { kind, staged: true }
}

/// NOTE: `dep_decl` / `dep_decl_schema_version` are NOT listed here — they
/// move in lockstep (§3.5.1) and are handled as one composite field via
/// [`LOCKSTEP_GROUPS`], reported under the primary name `"dep_decl"`.
fn lattice() -> Vec<(&'static str, FieldSpec)> {
    vec![
        // --- Frozen / set-once (entry-level) ---
        ("content_hash", spec(OrderKind::SetOnce)),
        ("published_at", spec(OrderKind::SetOnce)),
        ("rekor", staged_spec(OrderKind::SetOnce)),
        // --- Attestation-monotone (entry-level) ---
        ("attestation", staged_spec(OrderKind::AttestationMonotone)),
        // --- Append-only-multiset (entry-level) ---
        ("provenances", spec(OrderKind::AppendOnlyMultiset)),
        // --- Advisory-mutable (entry-level) — never violates; yank
        //     transitions are surfaced separately (see `yank_transition`).
        ("yanked", spec(OrderKind::AdvisoryMutable)),
        // --- Root fields (document-level, reserved empty key) ---
        ("schema_version", spec(OrderKind::OrdinalNonDecreasing)),
        ("attestation-epoch", staged_spec(OrderKind::SetOnce)),
    ]
}

/// Field groups that move in lockstep (§3.5.1: "`dep_decl` **together with**
/// `dep_decl_schema_version`" — mutating one alone is a violation even
/// though neither, read alone, "changed" from a legal prior value). Reported
/// under the group's first member's name.
const LOCKSTEP_GROUPS: &[&[&str]] = &[&["dep_decl", "dep_decl_schema_version"]];

// ---------------------------------------------------------------------------
// Per-order-kind dominance functions.
// ---------------------------------------------------------------------------

fn dominates_set_once(baseline: Option<&FieldValue>, candidate: Option<&FieldValue>) -> Option<&'static str> {
    match (baseline, candidate) {
        (None, _) => None, // absent -> anything: legal, exactly once per baseline
        (Some(_), None) => Some(FROZEN_UNSET),
        (Some(b), Some(c)) => {
            if b != c {
                Some(FROZEN_CHANGED)
            } else {
                None
            }
        }
    }
}

fn as_i64(v: Option<&FieldValue>) -> i64 {
    match v {
        Some(FieldValue::Int(i)) => *i,
        _ => 1, // absent ≡ spec default 1 (§3.5.1 root-field table, schema_version row)
    }
}

fn dominates_ordinal(baseline: Option<&FieldValue>, candidate: Option<&FieldValue>) -> Option<&'static str> {
    let b = as_i64(baseline);
    let c = as_i64(candidate);
    if c < b {
        Some(ROOT_FIELD_CHANGED)
    } else {
        None
    }
}

fn dominates_attestation(baseline: Option<&FieldValue>, candidate: Option<&FieldValue>) -> Option<&'static str> {
    let b = match baseline {
        None => return None, // None -> anything: legal (backfill/upgrade)
        Some(FieldValue::Attestation(a)) => a,
        Some(_) => return None,
    };
    let c = match candidate {
        None => return Some(MONOTONE_STRIPPED),
        Some(FieldValue::Attestation(a)) => a,
        Some(_) => return None,
    };
    if b.kind == c.kind {
        if b.kind == "author-signed" && b.signer != c.signer {
            return Some(MONOTONE_REATTRIBUTED);
        }
        // same kind (and, for author-signed, same signer): the bundle pin
        // must be structurally equal — a same-kind pin swap is a violation.
        if b.bundle_pin != c.bundle_pin {
            return Some(MONOTONE_REPINNED);
        }
        return None;
    }
    if b.kind == "author-signed" && c.kind == "milpa-vendored" {
        return Some(MONOTONE_DOWNGRADED);
    }
    None // milpa-vendored -> author-signed: upgrade, legal
}

fn as_str_list(v: Option<&FieldValue>) -> Vec<String> {
    match v {
        Some(FieldValue::StrList(items)) => items.clone(),
        _ => Vec::new(),
    }
}

fn dominates_multiset(baseline: Option<&FieldValue>, candidate: Option<&FieldValue>) -> Option<&'static str> {
    let b_items = as_str_list(baseline);
    let c_items = as_str_list(candidate);
    let mut b_counts: HashMap<&str, usize> = HashMap::new();
    for item in &b_items {
        *b_counts.entry(item.as_str()).or_insert(0) += 1;
    }
    let mut c_counts: HashMap<&str, usize> = HashMap::new();
    for item in &c_items {
        *c_counts.entry(item.as_str()).or_insert(0) += 1;
    }
    for (item, count) in &b_counts {
        if c_counts.get(item).copied().unwrap_or(0) < *count {
            return Some(PROVENANCE_REMOVED);
        }
    }
    None
}

fn dominates_advisory(_baseline: Option<&FieldValue>, _candidate: Option<&FieldValue>) -> Option<&'static str> {
    None // everything comparable, both directions legal
}

fn dispatch(kind: OrderKind, baseline: Option<&FieldValue>, candidate: Option<&FieldValue>) -> Option<&'static str> {
    match kind {
        OrderKind::SetOnce => dominates_set_once(baseline, candidate),
        OrderKind::OrdinalNonDecreasing => dominates_ordinal(baseline, candidate),
        OrderKind::AttestationMonotone => dominates_attestation(baseline, candidate),
        OrderKind::AppendOnlyMultiset => dominates_multiset(baseline, candidate),
        OrderKind::AdvisoryMutable => dominates_advisory(baseline, candidate),
    }
}

// ---------------------------------------------------------------------------
// The generic dominance fold (§3.5.1 NORMATIVE (dominance fold)).
// ---------------------------------------------------------------------------

fn dominates_entry(
    key: &EntryKey,
    baseline_entry: &RatchetEntry,
    candidate_entry: &RatchetEntry,
    include_staged: bool,
) -> Vec<Violation> {
    let is_root = key.is_root();
    let cls = if is_root { ROOT_MUTATED } else { ENTRY_MUTATED };
    let mut violations: Vec<Violation> = Vec::new();

    for group in LOCKSTEP_GROUPS {
        let b_vals: Vec<Option<FieldValue>> = group.iter().map(|f| baseline_entry.get(f).value).collect();
        let c_vals: Vec<Option<FieldValue>> = group.iter().map(|f| candidate_entry.get(f).value).collect();
        let b_composite = if b_vals.iter().any(|v| v.is_some()) {
            Some(())
        } else {
            None
        };
        let c_composite = if c_vals.iter().any(|v| v.is_some()) {
            Some(())
        } else {
            None
        };
        // The composite is a presence-only comparison (set-once over "any
        // member set"); once BOTH sides are present, per-member equality
        // (all members equal) governs FROZEN_CHANGED — mirrors ratchet.py's
        // tuple equality over `(b_vals) != (c_vals)`.
        let kind: Option<&'static str> = match (b_composite, c_composite) {
            (None, _) => None,
            (Some(_), None) => Some(FROZEN_UNSET),
            (Some(_), Some(_)) => {
                if b_vals != c_vals {
                    Some(FROZEN_CHANGED)
                } else {
                    None
                }
            }
        };
        if let Some(kind) = kind {
            let reported = if is_root { ROOT_FIELD_CHANGED } else { kind };
            violations.push(Violation {
                class: cls,
                entry_key: key.clone(),
                field: group[0].to_string(),
                kind: reported,
                baseline_value: baseline_entry.get(group[0]).raw_str(),
                candidate_value: candidate_entry.get(group[0]).raw_str(),
            });
        }
    }

    for (field_name, fspec) in lattice() {
        if fspec.staged && !include_staged {
            continue;
        }
        let b_field = baseline_entry.get(field_name);
        let c_field = candidate_entry.get(field_name);
        if let Some(kind) = dispatch(fspec.kind, b_field.value.as_ref(), c_field.value.as_ref()) {
            let reported = if is_root { ROOT_FIELD_CHANGED } else { kind };
            violations.push(Violation {
                class: cls,
                entry_key: key.clone(),
                field: field_name.to_string(),
                kind: reported,
                baseline_value: b_field.raw_str(),
                candidate_value: c_field.raw_str(),
            });
        }
    }

    violations
}

/// Presence dominance failure (§3.5.1): a baseline entry key with no
/// candidate counterpart. Presence is tagged Frozen alongside the ordinary
/// fields, so this reuses `frozen-unset`'s shape; `field=""` denotes the
/// entry's own presence dimension, not a named field.
fn rollback_violation(key: &EntryKey) -> Violation {
    Violation {
        class: ROLLBACK,
        entry_key: key.clone(),
        field: String::new(),
        kind: FROZEN_UNSET,
        baseline_value: "present".to_string(),
        candidate_value: String::new(),
    }
}

fn yank_transition(key: &EntryKey, baseline_entry: &RatchetEntry, candidate_entry: &RatchetEntry) -> Option<Transition> {
    let b = matches!(baseline_entry.get("yanked").value, Some(FieldValue::Bool(true)));
    let c = matches!(candidate_entry.get("yanked").value, Some(FieldValue::Bool(true)));
    if b == c {
        return None;
    }
    let str_of = |v: Option<FieldValue>| -> Option<String> {
        match v {
            Some(FieldValue::Str(s)) => Some(s),
            _ => None,
        }
    };
    if c {
        let reason = str_of(candidate_entry.get("yanked_reason").value);
        Some(Transition {
            entry_key: key.clone(),
            kind: "yank",
            direction: "yanked",
            reason,
        })
    } else {
        let reason = str_of(baseline_entry.get("yanked_reason").value);
        Some(Transition {
            entry_key: key.clone(),
            kind: "yank",
            direction: "unyanked",
            reason,
        })
    }
}

fn sort_key(v: &Violation) -> (u8, &str, &str, &str, &str) {
    (
        class_rank(v.class),
        v.entry_key.namespace.as_str(),
        v.entry_key.name.as_str(),
        v.entry_key.version.as_str(),
        v.field.as_str(),
    )
}

// ---------------------------------------------------------------------------
// Baseline — the public engine entry point.
// ---------------------------------------------------------------------------

/// Wraps a baseline [`IndexState`]. `.check(candidate)` diffs it against a
/// candidate state and returns a [`RatchetOutcome`]. Pure and side-effect
/// free.
pub struct Baseline {
    state: IndexState,
}

impl Baseline {
    pub fn new(state: IndexState) -> Self {
        Baseline { state }
    }

    pub fn check(&self, candidate: &IndexState) -> RatchetOutcome {
        self.check_with(candidate, false)
    }

    pub fn check_with(&self, candidate: &IndexState, include_staged: bool) -> RatchetOutcome {
        let mut violations: Vec<Violation> = Vec::new();
        let mut transitions: Vec<Transition> = Vec::new();

        let empty = RatchetEntry::new();
        let root_baseline = self.state.get(&EntryKey::root()).unwrap_or(&empty);
        let root_candidate = candidate.get(&EntryKey::root()).unwrap_or(&empty);
        violations.extend(dominates_entry(&EntryKey::root(), root_baseline, root_candidate, include_staged));

        for (key, b_entry) in &self.state {
            if key.is_root() {
                continue;
            }
            match candidate.get(key) {
                None => {
                    violations.push(rollback_violation(key));
                    continue;
                }
                Some(c_entry) => {
                    violations.extend(dominates_entry(key, b_entry, c_entry, include_staged));
                    if let Some(t) = yank_transition(key, b_entry, c_entry) {
                        transitions.push(t);
                    }
                }
            }
        }

        violations.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
        let advanced = violations.is_empty();
        RatchetOutcome {
            violations,
            advanced,
            transitions,
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical violation digest (§3.5.3 NORMATIVE (canonical violation digest))
// ---------------------------------------------------------------------------

/// sha256 over the UTF-8 concatenation of one `\n`-terminated, tab-joined
/// line per violation, in composite-key order:
/// `(class, namespace, name, version, field, kind, candidate_value)`.
/// `baseline_value` is deliberately excluded (the baseline is frozen while
/// violations persist, so it adds no discriminating information).
pub fn canonical_digest(violations: &[Violation]) -> String {
    let mut ordered: Vec<&Violation> = violations.iter().collect();
    ordered.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    let mut buf = String::new();
    for v in ordered {
        buf.push_str(v.class);
        buf.push('\t');
        buf.push_str(&v.entry_key.namespace);
        buf.push('\t');
        buf.push_str(&v.entry_key.name);
        buf.push('\t');
        buf.push_str(&v.entry_key.version);
        buf.push('\t');
        buf.push_str(&v.field);
        buf.push('\t');
        buf.push_str(v.kind);
        buf.push('\t');
        buf.push_str(&v.candidate_value);
        buf.push('\n');
    }
    let digest = Sha256::digest(buf.as_bytes());
    hex::encode(digest)
}

#[cfg(test)]
#[path = "ratchet_tests.rs"]
mod ratchet_tests;
