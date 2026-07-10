//! Unit tests for `milpa-core::ratchet` — A2b/A3 (rfc-registry-append-only.md).
//!
//! Ports `impls/python/tests/test_ratchet.py` behavior-for-behavior,
//! including the hand-computed canonical-digest vectors (§3.5.3 NORMATIVE)
//! which MUST produce identical sha256 hex across both implementations.

use super::*;

fn v1() -> EntryKey {
    EntryKey::new("acme", "foo", "1.0.0")
}
fn v2() -> EntryKey {
    EntryKey::new("acme", "foo", "2.0.0")
}

fn s(v: &str) -> FieldValue {
    FieldValue::Str(v.to_string())
}
fn i(v: i64) -> FieldValue {
    FieldValue::Int(v)
}
fn b(v: bool) -> FieldValue {
    FieldValue::Bool(v)
}

fn entry(fields: &[(&str, FieldValue)]) -> RatchetEntry {
    let mut e = RatchetEntry::new();
    for (k, val) in fields {
        e.fields.insert((*k).to_string(), RawField::new(val.clone()));
    }
    e
}

fn hash64(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}

// ---------------------------------------------------------------------------
// Clean append advances
// ---------------------------------------------------------------------------

#[test]
fn clean_append_advances() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[("content_hash", s(&hash64('a')))]));
    let mut candidate = IndexState::new();
    candidate.insert(v1(), entry(&[("content_hash", s(&hash64('a')))]));
    candidate.insert(v2(), entry(&[("content_hash", s(&hash64('b')))]));

    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(outcome.violations.is_empty());
    assert!(outcome.advanced);
}

#[test]
fn frozen_backfill_is_legal() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[]));
    let mut candidate = IndexState::new();
    candidate.insert(v1(), entry(&[("content_hash", s(&hash64('a')))]));

    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(outcome.violations.is_empty());
    assert!(outcome.advanced);
}

// ---------------------------------------------------------------------------
// Presence dominance — rollback
// ---------------------------------------------------------------------------

#[test]
fn removed_version_is_rollback_violation() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[("content_hash", s(&hash64('a')))]));
    baseline.insert(v2(), entry(&[("content_hash", s(&hash64('b')))]));
    let mut candidate = IndexState::new();
    candidate.insert(v1(), entry(&[("content_hash", s(&hash64('a')))]));

    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(!outcome.advanced);
    assert_eq!(outcome.violations.len(), 1);
    let v = &outcome.violations[0];
    assert_eq!(v.class, ROLLBACK);
    assert_eq!(v.entry_key, v2());
    assert_eq!(v.field, "");
    assert_eq!(v.kind, FROZEN_UNSET);
    assert_eq!(v.candidate_value, "");
}

// ---------------------------------------------------------------------------
// Set-once (Frozen) fields
// ---------------------------------------------------------------------------

#[test]
fn set_once_field_mutated_is_violation() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[("content_hash", s(&hash64('a')))]));
    let mut candidate = IndexState::new();
    candidate.insert(v1(), entry(&[("content_hash", s(&hash64('c')))]));

    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(!outcome.advanced);
    assert_eq!(outcome.violations.len(), 1);
    let v = &outcome.violations[0];
    assert_eq!(v.class, ENTRY_MUTATED);
    assert_eq!(v.field, "content_hash");
    assert_eq!(v.kind, FROZEN_CHANGED);
    assert_eq!(v.baseline_value, hash64('a'));
    assert_eq!(v.candidate_value, hash64('c'));
}

#[test]
fn set_once_field_unset_is_violation() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[("content_hash", s(&hash64('a')))]));
    let mut candidate = IndexState::new();
    candidate.insert(v1(), entry(&[]));

    let outcome = Baseline::new(baseline).check(&candidate);
    let v = &outcome.violations[0];
    assert_eq!(v.kind, FROZEN_UNSET);
    assert_eq!(v.candidate_value, "");
}

#[test]
fn dep_decl_lockstep_group_backfill_legal() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[]));
    let mut candidate = IndexState::new();
    candidate.insert(
        v1(),
        entry(&[("dep_decl", s(&hash64('d'))), ("dep_decl_schema_version", i(1))]),
    );

    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(outcome.violations.is_empty());
}

#[test]
fn dep_decl_schema_version_alone_changing_is_violation() {
    let mut baseline = IndexState::new();
    baseline.insert(
        v1(),
        entry(&[("dep_decl", s(&hash64('d'))), ("dep_decl_schema_version", i(1))]),
    );
    let mut candidate = IndexState::new();
    candidate.insert(
        v1(),
        entry(&[("dep_decl", s(&hash64('d'))), ("dep_decl_schema_version", i(2))]),
    );

    let outcome = Baseline::new(baseline).check(&candidate);
    assert_eq!(outcome.violations.len(), 1);
    let v = &outcome.violations[0];
    assert_eq!(v.field, "dep_decl");
    assert_eq!(v.kind, FROZEN_CHANGED);
    assert_eq!(v.class, ENTRY_MUTATED);
}

// ---------------------------------------------------------------------------
// Ordinal-non-decreasing root field (schema_version)
// ---------------------------------------------------------------------------

#[test]
fn schema_version_regression_is_violation() {
    let mut baseline = IndexState::new();
    baseline.insert(EntryKey::root(), entry(&[("schema_version", i(2))]));
    let mut candidate = IndexState::new();
    candidate.insert(EntryKey::root(), entry(&[("schema_version", i(1))]));

    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(!outcome.advanced);
    let v = &outcome.violations[0];
    assert_eq!(v.class, ROOT_MUTATED);
    assert_eq!(v.entry_key, EntryKey::root());
    assert_eq!(v.field, "schema_version");
    assert_eq!(v.kind, ROOT_FIELD_CHANGED);
}

#[test]
fn schema_version_equal_is_clean() {
    let mut baseline = IndexState::new();
    baseline.insert(EntryKey::root(), entry(&[("schema_version", i(2))]));
    let mut candidate = IndexState::new();
    candidate.insert(EntryKey::root(), entry(&[("schema_version", i(2))]));

    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(outcome.violations.is_empty());
}

#[test]
fn schema_version_absent_is_default_one() {
    let mut root_absent_both = IndexState::new();
    root_absent_both.insert(EntryKey::root(), entry(&[]));
    let outcome = Baseline::new(root_absent_both.clone()).check(&root_absent_both);
    assert!(outcome.violations.is_empty());

    let mut baseline_one = IndexState::new();
    baseline_one.insert(EntryKey::root(), entry(&[("schema_version", i(1))]));
    let mut candidate_absent = IndexState::new();
    candidate_absent.insert(EntryKey::root(), entry(&[]));
    let outcome = Baseline::new(baseline_one).check(&candidate_absent);
    assert!(outcome.violations.is_empty());

    let mut baseline_two = IndexState::new();
    baseline_two.insert(EntryKey::root(), entry(&[("schema_version", i(2))]));
    let outcome = Baseline::new(baseline_two).check(&candidate_absent);
    assert_eq!(outcome.violations.len(), 1);
    assert_eq!(outcome.violations[0].kind, ROOT_FIELD_CHANGED);

    let mut root_absent = IndexState::new();
    root_absent.insert(EntryKey::root(), entry(&[]));
    let mut candidate_two = IndexState::new();
    candidate_two.insert(EntryKey::root(), entry(&[("schema_version", i(2))]));
    let outcome = Baseline::new(root_absent).check(&candidate_two);
    assert!(outcome.violations.is_empty());
}

// ---------------------------------------------------------------------------
// Attestation-monotone — staged pre-A6
// ---------------------------------------------------------------------------

fn att(kind: &str, signer: Option<&str>, bundle_pin: Option<&str>) -> FieldValue {
    FieldValue::Attestation(AttestationValue {
        kind: kind.to_string(),
        signer: signer.map(str::to_string),
        bundle_pin: bundle_pin.map(str::to_string),
    })
}

#[test]
fn attestation_unenforced_by_default_pre_a6() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[("attestation", att("milpa-vendored", None, None))]));
    let mut candidate = IndexState::new();
    candidate.insert(v1(), entry(&[]));

    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(outcome.violations.is_empty());
}

#[test]
fn attestation_upgrades_legal_under_include_staged() {
    let cases: Vec<(Option<FieldValue>, FieldValue)> = vec![
        (None, att("milpa-vendored", None, None)),
        (None, att("author-signed", Some("alice"), None)),
        (
            Some(att("milpa-vendored", None, None)),
            att("author-signed", Some("alice"), None),
        ),
    ];
    for (baseline_val, candidate_val) in cases {
        let mut baseline = IndexState::new();
        let mut b_entry = RatchetEntry::new();
        if let Some(v) = baseline_val {
            b_entry = b_entry.set("attestation", RawField::new(v));
        }
        baseline.insert(v1(), b_entry);
        let mut candidate = IndexState::new();
        candidate.insert(v1(), entry(&[("attestation", candidate_val)]));

        let outcome = Baseline::new(baseline).check_with(&candidate, true);
        assert!(outcome.violations.is_empty());
    }
}

#[test]
fn attestation_strip_forbidden_under_include_staged() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[("attestation", att("milpa-vendored", None, None))]));
    let mut candidate = IndexState::new();
    candidate.insert(v1(), entry(&[]));

    let outcome = Baseline::new(baseline).check_with(&candidate, true);
    assert_eq!(outcome.violations.len(), 1);
    assert_eq!(outcome.violations[0].kind, MONOTONE_STRIPPED);
}

#[test]
fn attestation_reattribution_forbidden_under_include_staged() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[("attestation", att("author-signed", Some("alice"), None))]));
    let mut candidate = IndexState::new();
    candidate.insert(v1(), entry(&[("attestation", att("author-signed", Some("bob"), None))]));

    let outcome = Baseline::new(baseline).check_with(&candidate, true);
    assert_eq!(outcome.violations.len(), 1);
    assert_eq!(outcome.violations[0].kind, MONOTONE_REATTRIBUTED);
}

#[test]
fn attestation_downgrade_forbidden_under_include_staged() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[("attestation", att("author-signed", Some("alice"), None))]));
    let mut candidate = IndexState::new();
    candidate.insert(v1(), entry(&[("attestation", att("milpa-vendored", None, None))]));

    let outcome = Baseline::new(baseline).check_with(&candidate, true);
    assert_eq!(outcome.violations.len(), 1);
    assert_eq!(outcome.violations[0].kind, MONOTONE_DOWNGRADED);
}

#[test]
fn attestation_repin_forbidden_under_include_staged() {
    let mut baseline = IndexState::new();
    baseline.insert(
        v1(),
        entry(&[("attestation", att("author-signed", Some("alice"), Some("p1")))]),
    );
    let mut candidate = IndexState::new();
    candidate.insert(
        v1(),
        entry(&[("attestation", att("author-signed", Some("alice"), Some("p2")))]),
    );

    let outcome = Baseline::new(baseline).check_with(&candidate, true);
    assert_eq!(outcome.violations.len(), 1);
    assert_eq!(outcome.violations[0].kind, MONOTONE_REPINNED);
}

#[test]
fn attestation_vendored_signer_rotation_unconstrained_under_include_staged() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[("attestation", att("milpa-vendored", None, None))]));
    let mut candidate = IndexState::new();
    candidate.insert(v1(), entry(&[("attestation", att("milpa-vendored", None, None))]));

    let outcome = Baseline::new(baseline).check_with(&candidate, true);
    assert!(outcome.violations.is_empty());
}

// ---------------------------------------------------------------------------
// Append-only-multiset provenance
// ---------------------------------------------------------------------------

fn provs(items: &[&str]) -> FieldValue {
    FieldValue::StrList(items.iter().map(|s| s.to_string()).collect())
}

#[test]
fn provenance_append_is_legal() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[("provenances", provs(&["git|url1|ref1|sha1"]))]));
    let mut candidate = IndexState::new();
    candidate.insert(
        v1(),
        entry(&[("provenances", provs(&["git|url1|ref1|sha1", "git|url2|ref1|sha1"]))]),
    );

    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(outcome.violations.is_empty());
}

#[test]
fn provenance_in_place_mutation_is_removal_violation() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[("provenances", provs(&["git|url1|ref1|sha1"]))]));
    let mut candidate = IndexState::new();
    candidate.insert(v1(), entry(&[("provenances", provs(&["git|url1|ref1|sha-mutated"]))]));

    let outcome = Baseline::new(baseline).check(&candidate);
    assert_eq!(outcome.violations.len(), 1);
    let v = &outcome.violations[0];
    assert_eq!(v.field, "provenances");
    assert_eq!(v.kind, PROVENANCE_REMOVED);
}

#[test]
fn provenance_reorder_is_legal() {
    let mut baseline = IndexState::new();
    baseline.insert(
        v1(),
        entry(&[("provenances", provs(&["git|url1|ref1|sha1", "git|url2|ref1|sha1"]))]),
    );
    let mut candidate = IndexState::new();
    candidate.insert(
        v1(),
        entry(&[("provenances", provs(&["git|url2|ref1|sha1", "git|url1|ref1|sha1"]))]),
    );

    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(outcome.violations.is_empty());
}

// ---------------------------------------------------------------------------
// Advisory-mutable yank triple — transitions, never violations
// ---------------------------------------------------------------------------

#[test]
fn yank_transition_is_surfaced_not_a_violation() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[("yanked", b(false))]));
    let mut candidate = IndexState::new();
    candidate.insert(
        v1(),
        entry(&[("yanked", b(true)), ("yanked_reason", s("CVE-2026-0001"))]),
    );

    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(outcome.violations.is_empty());
    assert!(outcome.advanced);
    assert_eq!(outcome.transitions.len(), 1);
    let t = &outcome.transitions[0];
    assert_eq!(t.entry_key, v1());
    assert_eq!(t.direction, "yanked");
    assert_eq!(t.reason.as_deref(), Some("CVE-2026-0001"));
}

#[test]
fn unyank_transition_carries_baseline_reason() {
    let mut baseline = IndexState::new();
    baseline.insert(
        v1(),
        entry(&[("yanked", b(true)), ("yanked_reason", s("CVE-2026-0001"))]),
    );
    let mut candidate = IndexState::new();
    candidate.insert(v1(), entry(&[("yanked", b(false))]));

    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(outcome.violations.is_empty());
    let t = &outcome.transitions[0];
    assert_eq!(t.direction, "unyanked");
    assert_eq!(t.reason.as_deref(), Some("CVE-2026-0001"));
}

#[test]
fn no_yank_change_is_no_transition() {
    let mut baseline = IndexState::new();
    baseline.insert(v1(), entry(&[("yanked", b(false))]));
    let mut candidate = IndexState::new();
    candidate.insert(v1(), entry(&[("yanked", b(false))]));

    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(outcome.transitions.is_empty());
}

// ---------------------------------------------------------------------------
// Root-field fold under the reserved empty key
// ---------------------------------------------------------------------------

#[test]
fn root_fields_fold_under_reserved_empty_key_with_tiebreak() {
    let mut baseline = IndexState::new();
    baseline.insert(
        EntryKey::root(),
        entry(&[("schema_version", i(2)), ("attestation-epoch", s("E1"))]),
    );
    let mut candidate = IndexState::new();
    candidate.insert(
        EntryKey::root(),
        entry(&[("schema_version", i(1)), ("attestation-epoch", s("E2"))]),
    );

    let outcome = Baseline::new(baseline).check_with(&candidate, true);
    assert!(!outcome.advanced);
    assert_eq!(outcome.violations.len(), 2);
    let fields: Vec<&str> = outcome.violations.iter().map(|v| v.field.as_str()).collect();
    assert_eq!(fields, vec!["attestation-epoch", "schema_version"]);
    assert!(outcome.violations.iter().all(|v| v.class == ROOT_MUTATED));
    assert!(outcome.violations.iter().all(|v| v.entry_key == EntryKey::root()));
    assert!(outcome.violations.iter().all(|v| v.kind == ROOT_FIELD_CHANGED));
}

#[test]
fn attestation_epoch_set_once_under_include_staged() {
    let mut baseline = IndexState::new();
    baseline.insert(EntryKey::root(), entry(&[("attestation-epoch", s("E1"))]));
    let mut candidate = IndexState::new();
    candidate.insert(EntryKey::root(), entry(&[("attestation-epoch", s("E2"))]));

    let outcome = Baseline::new(baseline.clone()).check_with(&candidate, true);
    assert_eq!(outcome.violations.len(), 1);
    assert_eq!(outcome.violations[0].field, "attestation-epoch");
    assert_eq!(outcome.violations[0].kind, ROOT_FIELD_CHANGED);

    // unenforced by default (pre-A6):
    let outcome = Baseline::new(baseline).check(&candidate);
    assert!(outcome.violations.is_empty());
}

// ---------------------------------------------------------------------------
// Composite ordering — the spec's worked example
// ---------------------------------------------------------------------------

#[test]
fn composite_ordering_worked_example() {
    let aaa = EntryKey::new("ns", "aaa", "1.0.0");
    let zzz = EntryKey::new("ns", "zzz", "1.0.0");
    let mut baseline = IndexState::new();
    baseline.insert(aaa.clone(), entry(&[("content_hash", s(&hash64('a')))]));
    baseline.insert(zzz.clone(), entry(&[("content_hash", s(&hash64('b')))]));
    let mut candidate = IndexState::new();
    candidate.insert(aaa.clone(), entry(&[("content_hash", s(&hash64('c')))]));
    // zzz is absent from the candidate: rollback.

    let outcome = Baseline::new(baseline).check(&candidate);
    assert_eq!(outcome.violations.len(), 2);
    let (first, second) = (&outcome.violations[0], &outcome.violations[1]);
    assert_eq!(first.class, ROLLBACK);
    assert_eq!(first.entry_key, zzz);
    assert_eq!(second.class, ENTRY_MUTATED);
    assert_eq!(second.entry_key, aaa);
}

// ---------------------------------------------------------------------------
// Canonical violation digest — hand-computed vectors (§3.5.3 NORMATIVE).
// These MUST match `impls/python/tests/test_ratchet.py`'s vectors exactly.
// ---------------------------------------------------------------------------

#[test]
fn canonical_digest_hand_computed_vector() {
    let v = Violation {
        class: ENTRY_MUTATED,
        entry_key: EntryKey::new("acme", "foo", "1.0.0"),
        field: "content_hash".to_string(),
        kind: FROZEN_CHANGED,
        baseline_value: hash64('a'),
        candidate_value: hash64('c'),
    };
    let expected_line = format!(
        "TNG-ENTRY-MUTATED\tacme\tfoo\t1.0.0\tcontent_hash\tfrozen-changed\t{}\n",
        hash64('c')
    );
    let expected = {
        let digest = Sha256::digest(expected_line.as_bytes());
        hex::encode(digest)
    };
    assert_eq!(canonical_digest(&[v]), expected);
}

#[test]
fn canonical_digest_multi_violation_vector_matches_composite_order() {
    let aaa = EntryKey::new("ns", "aaa", "1.0.0");
    let zzz = EntryKey::new("ns", "zzz", "1.0.0");
    let entry_violation = Violation {
        class: ENTRY_MUTATED,
        entry_key: aaa.clone(),
        field: "content_hash".to_string(),
        kind: FROZEN_CHANGED,
        baseline_value: hash64('a'),
        candidate_value: hash64('c'),
    };
    let rollback_violation = Violation {
        class: ROLLBACK,
        entry_key: zzz.clone(),
        field: String::new(),
        kind: FROZEN_UNSET,
        baseline_value: "present".to_string(),
        candidate_value: String::new(),
    };
    let expected_text = format!(
        "TNG-INDEX-ROLLBACK\tns\tzzz\t1.0.0\t\tfrozen-unset\t\n\
         TNG-ENTRY-MUTATED\tns\taaa\t1.0.0\tcontent_hash\tfrozen-changed\t{}\n",
        hash64('c')
    );
    let expected = hex::encode(Sha256::digest(expected_text.as_bytes()));
    // order given to canonical_digest need not be pre-sorted — it sorts.
    assert_eq!(canonical_digest(&[entry_violation, rollback_violation]), expected);
}

#[test]
fn digest_changes_on_remutation_of_same_field() {
    let key = EntryKey::new("acme", "foo", "1.0.0");
    let v2 = Violation {
        class: ENTRY_MUTATED,
        entry_key: key.clone(),
        field: "content_hash".to_string(),
        kind: FROZEN_CHANGED,
        baseline_value: hash64('a'),
        candidate_value: hash64('b'),
    };
    let v3 = Violation {
        class: ENTRY_MUTATED,
        entry_key: key,
        field: "content_hash".to_string(),
        kind: FROZEN_CHANGED,
        baseline_value: hash64('a'),
        candidate_value: hash64('c'),
    };
    assert_ne!(canonical_digest(&[v2]), canonical_digest(&[v3]));
}

#[test]
fn digest_unaffected_by_baseline_value_change() {
    let key = EntryKey::new("acme", "foo", "1.0.0");
    let v_a = Violation {
        class: ENTRY_MUTATED,
        entry_key: key.clone(),
        field: "content_hash".to_string(),
        kind: FROZEN_CHANGED,
        baseline_value: hash64('a'),
        candidate_value: hash64('c'),
    };
    let v_b = Violation {
        class: ENTRY_MUTATED,
        entry_key: key,
        field: "content_hash".to_string(),
        kind: FROZEN_CHANGED,
        baseline_value: hash64('z'),
        candidate_value: hash64('c'),
    };
    assert_eq!(canonical_digest(&[v_a]), canonical_digest(&[v_b]));
}
