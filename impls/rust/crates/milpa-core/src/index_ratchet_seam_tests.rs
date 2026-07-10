//! Unit tests for `milpa-core::index_ratchet_seam` — A3 (rfc-registry-append-only.md).
//! Mirrors `impls/python/tests/test_index_history_ratchet.py` (32 tests) at a
//! representative-coverage level: TOFU, clean sticky-advance, warn habituation
//! (new vs recurring), strict hard-fail, baseline corruption, and yank notices.

use super::*;
use milpa_manifest::TrustPolicy;

const ID1: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ID2: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ID3: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn index_text(hash: &str) -> String {
    format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{hash}\"\n\
         \x20   }}\n\
         }}\n"
    )
}

#[test]
fn tofu_establishes_trust_anchor_no_write_yet() {
    let candidate = index_text(ID1);
    let existing_meta = BaselineMeta::default();
    let decision = evaluate_gate(&TrustPolicy::Warn, &candidate, None, &existing_meta, 1_000, "u").unwrap();
    assert!(decision.advance);
    assert!(decision.new_meta.is_some());
    assert!(decision.new_meta.unwrap().established_at.is_some());
}

#[test]
fn off_policy_never_reads_baseline_no_advance() {
    let candidate = index_text(ID1);
    let existing_meta = BaselineMeta::default();
    // baseline_text is Some but must never be consulted under "off" — pass a
    // deliberately corrupt string to prove it's never parsed.
    let decision = evaluate_gate(&TrustPolicy::Off, &candidate, Some("not kdl {{{"), &existing_meta, 1_000, "u").unwrap();
    assert!(!decision.advance);
    assert!(decision.new_meta.is_none());
}

#[test]
fn clean_diff_advances_baseline() {
    let baseline = index_text(ID1);
    let candidate = index_text(ID1);
    let existing_meta = BaselineMeta { established_at: Some("t0".to_string()), ..Default::default() };
    let decision = evaluate_gate(&TrustPolicy::Warn, &candidate, Some(&baseline), &existing_meta, 2_000, "u").unwrap();
    assert!(decision.advance);
    let meta = decision.new_meta.unwrap();
    assert_eq!(meta.established_at.as_deref(), Some("t0"));
    assert!(meta.reported_digest.is_none());
}

#[test]
fn warn_dirty_diff_does_not_advance_reports_new_digest() {
    let baseline = index_text(ID1);
    let candidate = index_text(ID2); // content_hash mutated
    let existing_meta = BaselineMeta::default();
    let decision = evaluate_gate(&TrustPolicy::Warn, &candidate, Some(&baseline), &existing_meta, 3_000, "u").unwrap();
    assert!(!decision.advance);
    let meta = decision.new_meta.expect("new digest must be recorded");
    assert!(meta.reported_digest.is_some());
    assert!(meta.reported_at.is_some());
}

#[test]
fn warn_recurring_same_digest_does_not_rewrite_meta() {
    let baseline = index_text(ID1);
    let candidate = index_text(ID2);
    let (_, candidate_state) = build_index_state(&candidate).unwrap();
    let (_, baseline_state) = build_index_state(&baseline).unwrap();
    let outcome = Baseline::new(baseline_state).check(&candidate_state);
    let digest = canonical_digest(&outcome.violations);

    let existing_meta = BaselineMeta {
        established_at: Some("t0".to_string()),
        reported_digest: Some(digest),
        reported_at: Some("t1".to_string()),
    };
    let decision = evaluate_gate(&TrustPolicy::Warn, &candidate, Some(&baseline), &existing_meta, 4_000, "u").unwrap();
    assert!(!decision.advance);
    assert!(decision.new_meta.is_none(), "recurring digest must not rewrite .meta");
}

#[test]
fn warn_new_mutation_after_recurring_reports_new_digest() {
    let baseline = index_text(ID1);
    let stale_candidate = index_text(ID2);
    let (_, stale_state) = build_index_state(&stale_candidate).unwrap();
    let (_, baseline_state) = build_index_state(&baseline).unwrap();
    let stale_digest = canonical_digest(&Baseline::new(baseline_state).check(&stale_state).violations);

    let existing_meta = BaselineMeta {
        established_at: Some("t0".to_string()),
        reported_digest: Some(stale_digest),
        reported_at: Some("t1".to_string()),
    };
    // A second, DIFFERENT mutation — must be treated as new, not recurring.
    let new_candidate = index_text(ID3);
    let decision = evaluate_gate(&TrustPolicy::Warn, &new_candidate, Some(&baseline), &existing_meta, 5_000, "u").unwrap();
    assert!(!decision.advance);
    let meta = decision.new_meta.expect("a genuinely new digest must rewrite .meta");
    assert_ne!(meta.reported_digest, existing_meta.reported_digest);
}

#[test]
fn strict_dirty_diff_hard_fails_with_primary_slug() {
    let baseline = index_text(ID1);
    let candidate = index_text(ID2);
    let existing_meta = BaselineMeta::default();
    let err = evaluate_gate(&TrustPolicy::Strict, &candidate, Some(&baseline), &existing_meta, 6_000, "u").unwrap_err();
    assert_eq!(err.code(), "TNG-ENTRY-MUTATED");
}

#[test]
fn strict_rollback_hard_fails_with_rollback_slug() {
    let baseline = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\" {{\n content_hash \"{ID1}\"\n }}\n\
         \x20   version \"2.0.0\" {{\n content_hash \"{ID2}\"\n }}\n\
         }}\n"
    );
    let candidate = index_text(ID1); // 2.0.0 disappeared
    let existing_meta = BaselineMeta::default();
    let err = evaluate_gate(&TrustPolicy::Strict, &candidate, Some(&baseline), &existing_meta, 7_000, "u").unwrap_err();
    assert_eq!(err.code(), "TNG-INDEX-ROLLBACK");
}

#[test]
fn baseline_corrupt_maps_to_baseline_corrupt_slug_under_warn_and_strict() {
    let candidate = index_text(ID1);
    let existing_meta = BaselineMeta::default();
    for policy in [TrustPolicy::Warn, TrustPolicy::Strict] {
        let err = evaluate_gate(&policy, &candidate, Some("not kdl {{{"), &existing_meta, 8_000, "u").unwrap_err();
        assert_eq!(err.code(), "TNG-INDEX-BASELINE-CORRUPT");
    }
}

#[test]
fn candidate_parse_failure_never_touches_baseline_state() {
    let existing_meta = BaselineMeta::default();
    let err = evaluate_gate(&TrustPolicy::Warn, "not kdl {{{", None, &existing_meta, 9_000, "u").unwrap_err();
    assert_ne!(err.code(), "TNG-INDEX-BASELINE-CORRUPT");
}

#[test]
fn baseline_meta_render_round_trips() {
    let meta = BaselineMeta {
        established_at: Some("2026-01-01T00:00:00+00:00".to_string()),
        reported_digest: Some("deadbeef".to_string()),
        reported_at: Some("2026-01-02T00:00:00+00:00".to_string()),
    };
    let text = meta.render();
    let reparsed = parse_baseline_meta(&text);
    assert_eq!(reparsed, meta);
}

#[test]
fn baseline_meta_empty_renders_empty_string() {
    assert_eq!(BaselineMeta::default().render(), "");
}

#[test]
fn baseline_meta_corrupt_self_heals_to_default() {
    let reparsed = parse_baseline_meta("not kdl {{{");
    assert_eq!(reparsed, BaselineMeta::default());
}

#[test]
fn iso_timestamp_matches_known_instant() {
    // 2026-01-01T00:00:00+00:00 in unix seconds.
    let ts = crate::registry::parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
    assert_eq!(iso_timestamp(ts.unix_seconds), "2026-01-01T00:00:00+00:00");
}
