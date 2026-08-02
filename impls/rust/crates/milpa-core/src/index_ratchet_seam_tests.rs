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
fn empty_string_established_at_self_heals_like_absent() {
    // A hand-corrupted (or pre-fix) `.baseline.meta` with `established_at:
    // Some("")` must regenerate on the next clean diff, the same as a
    // wholly-absent `established_at` — mirrors Python's `existing_meta.
    // established_at or iso_timestamp(now_unix)` self-healing semantics
    // (`index_ratchet_seam.py`).
    let baseline = index_text(ID1);
    let candidate = index_text(ID1); // identical -> clean diff
    let existing_meta = BaselineMeta { established_at: Some(String::new()), ..Default::default() };
    let decision = evaluate_gate(&TrustPolicy::Warn, &candidate, Some(&baseline), &existing_meta, 2_500, "u").unwrap();
    let meta = decision.new_meta.unwrap();
    assert!(meta.established_at.as_deref().is_some_and(|s| !s.is_empty()));
}

// ---------------------------------------------------------------------------
// CR8: evaluate_gate's warn diagnostic is pure data on GateDecision — not a
// direct print. index_cache.rs's apply_ratchet_writes is the sole caller-
// side print site, AFTER the ordinary warn-path writes complete.
// ---------------------------------------------------------------------------

#[test]
fn warn_dirty_diff_populates_warn_message() {
    let baseline = index_text(ID1);
    let candidate = index_text(ID2); // content_hash mutated
    let existing_meta = BaselineMeta::default();
    let decision = evaluate_gate(&TrustPolicy::Warn, &candidate, Some(&baseline), &existing_meta, 3_100, "u").unwrap();
    let msg = decision.warn_message.expect("warn-dirty outcome must populate warn_message");
    assert!(msg.contains("TNG-ENTRY-MUTATED"));
}

#[test]
fn recurring_warn_message_still_populated_though_meta_unwritten() {
    // warn_message is set on EVERY warn-dirty outcome, including the
    // recurring case where new_meta is None (nothing new to persist) — the
    // caller must still print it.
    let baseline = index_text(ID1);
    let candidate = index_text(ID2);
    let (_, candidate_state) = build_index_state(&candidate).unwrap();
    let (_, baseline_state) = build_index_state(&baseline).unwrap();
    let outcome = Baseline::new(baseline_state).check(&candidate_state);
    let digest = canonical_digest(&outcome.violations);

    let existing_meta = BaselineMeta { reported_digest: Some(digest), ..Default::default() };
    let decision = evaluate_gate(&TrustPolicy::Warn, &candidate, Some(&baseline), &existing_meta, 3_200, "u").unwrap();
    assert!(decision.new_meta.is_none(), "recurring digest must not rewrite .meta");
    assert!(decision.warn_message.is_some(), "but warn_message must still be populated");
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
fn strict_hard_fail_carries_structured_digest() {
    // §3.5.3 NORMATIVE (canonical violation digest): the strict path must
    // expose the digest as STRUCTURED data (mirrors Python's
    // `MilpaError.context["digest"]`), not only embedded in message text —
    // the conformance differential asserts cross-impl digest equality via
    // this accessor, not by scraping `err.message()` (this module's error
    // model asserts on codes/structured fields, never message text).
    let baseline = index_text(ID1);
    let candidate = index_text(ID2);
    let (_, baseline_state) = build_index_state(&baseline).unwrap();
    let (_, candidate_state) = build_index_state(&candidate).unwrap();
    let outcome = Baseline::new(baseline_state).check(&candidate_state);
    let expected_digest = canonical_digest(&outcome.violations);

    let existing_meta = BaselineMeta::default();
    let err = evaluate_gate(&TrustPolicy::Strict, &candidate, Some(&baseline), &existing_meta, 6_500, "u").unwrap_err();
    assert_eq!(err.ratchet_digest(), Some(expected_digest.as_str()));
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

// ---------------------------------------------------------------------------
// Provenance-multiset canonical digest rendering (A4b MUST-RESOLVE, flagged
// at A3: the raw-fallback rendering of a provenance-removed violation's
// candidate_value was impl-specific — Rust's Debug-derive fallback for
// what is now `FieldValue::ProvenanceList` (then `FieldValue::StrList`) vs
// Python's dataclass-tuple `str()` fallback. Fixed
// at the root in `provenance_canonical_raw` (registry-protocol §3.5.3
// NORMATIVE (canonical rendering for non-scalar candidate values)). The
// expected hex is ported VERBATIM from
// `test_index_history_ratchet.py::TestProvenanceCanonicalDigest` — byte
// equality proves both implementations render the identical candidate text
// identically, not merely that each is internally consistent.
// ---------------------------------------------------------------------------

fn provenance_index_text(commit_sha: &str) -> String {
    format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   namespace \"acme\"\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"sha256:{}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://example.com/bar.git\"\n\
         \x20           ref \"v1.0.0\"\n\
         \x20           commit_sha \"{commit_sha}\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n",
        "a".repeat(64)
    )
}

#[test]
fn provenance_in_place_mutation_hand_computed_digest_vector() {
    let baseline = provenance_index_text("cafef00dcafef00dcafef00dcafef00dcafef00d");
    let candidate = provenance_index_text("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    let (_, baseline_state) = build_index_state(&baseline).unwrap();
    let (_, candidate_state) = build_index_state(&candidate).unwrap();
    let outcome = Baseline::new(baseline_state).check(&candidate_state);

    assert_eq!(outcome.violations.len(), 1);
    let v = &outcome.violations[0];
    assert_eq!(v.class, "TNG-ENTRY-MUTATED");
    assert_eq!(v.field, "provenances");
    assert_eq!(v.kind, "provenance-removed");

    let expected_candidate_value =
        "git\u{1f}https://example.com/bar.git\u{1f}v1.0.0\u{1f}deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    assert_eq!(v.candidate_value, expected_candidate_value);

    // baseline_value: the same §3.5.3 closed-field-set rendering applied to
    // the BASELINE side's single-element provenance multiset, by hand from
    // `provenance_index_text`'s literal `commit_sha` argument above (never
    // copied from implementation output). Excluded from the digest itself
    // (§3.5.3: baseline is frozen while violations persist, so it adds no
    // discriminating information) but still carried on the payload for
    // human display — a shared misrendering of THIS field across both
    // impls would not be caught by the opaque digest differential alone.
    let expected_baseline_value =
        "git\u{1f}https://example.com/bar.git\u{1f}v1.0.0\u{1f}cafef00dcafef00dcafef00dcafef00dcafef00d";
    assert_eq!(v.baseline_value, expected_baseline_value);

    let digest = canonical_digest(&outcome.violations);
    assert_eq!(
        digest,
        "2d659ca5067920f2faea49046c99caf525fc8c8ce85726554193f340d3ab3c78"
    );
}

// registry-protocol §3.5.3's closed KNOWN GAP: an `oci` provenance mutation
// that differs ONLY in the optional `source` field used to render identical
// `candidate_value` bytes to one that never had a `source` at all — the
// exact digest-collision blind spot the NORMATIVE canonical-rendering
// subsection exists to close for every other field (mirrors the `git`
// instantiation's `commit_sha` coverage above). Fixed by appending
// `\x1f<source-or-empty>` to the `oci` encoding in `provenance_canonical_raw`.
// The expected hex is ported VERBATIM from
// `test_index_history_ratchet.py::TestProvenanceCanonicalDigest::test_oci_source_field_included_in_digest`
// — byte equality proves both implementations render the identical
// candidate text identically. Same hex is pinned again in conformance
// fixture 453 (mirroring fixture 386).
#[test]
fn provenance_oci_source_field_included_in_digest() {
    let baseline = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   namespace \"acme\"\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"sha256:{}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"oci\"\n\
         \x20           registry \"ghcr.io\"\n\
         \x20           repository \"acme/bar\"\n\
         \x20           digest \"sha256:{}\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n",
        "a".repeat(64),
        "b".repeat(64)
    );
    let candidate = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   namespace \"acme\"\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"sha256:{}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"oci\"\n\
         \x20           registry \"ghcr.io\"\n\
         \x20           repository \"acme/bar\"\n\
         \x20           digest \"sha256:{}\"\n\
         \x20           source \"https://example.com/bar.git\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n",
        "a".repeat(64),
        "b".repeat(64)
    );
    let (_, baseline_state) = build_index_state(&baseline).unwrap();
    let (_, candidate_state) = build_index_state(&candidate).unwrap();
    let outcome = Baseline::new(baseline_state).check(&candidate_state);

    assert_eq!(outcome.violations.len(), 1);
    let v = &outcome.violations[0];
    assert_eq!(v.class, "TNG-ENTRY-MUTATED");
    assert_eq!(v.field, "provenances");
    assert_eq!(v.kind, "provenance-removed");

    let expected_candidate_value = format!(
        "oci\u{1f}ghcr.io\u{1f}acme/bar\u{1f}sha256:{}\u{1f}https://example.com/bar.git",
        "b".repeat(64)
    );
    assert_eq!(v.candidate_value, expected_candidate_value);

    // baseline_value: absent `source` renders as the empty string (trailing
    // `\x1f`) — a new canonical form, not a compat-preserving one (no
    // committed fixture pins the pre-`source` oci digest bytes).
    let expected_baseline_value =
        format!("oci\u{1f}ghcr.io\u{1f}acme/bar\u{1f}sha256:{}\u{1f}", "b".repeat(64));
    assert_eq!(v.baseline_value, expected_baseline_value);

    let digest = canonical_digest(&outcome.violations);
    assert_eq!(
        digest,
        "50dd2402807e46c2645f6ef4eebf3e75b67321aacda2aa758fed9224041f31ee"
    );
}

#[test]
fn provenance_append_only_no_violation() {
    let baseline = provenance_index_text("cafef00dcafef00dcafef00dcafef00dcafef00d");
    let mut candidate = provenance_index_text("cafef00dcafef00dcafef00dcafef00dcafef00d");
    // Append a second (oci) provenance record before the closing braces.
    let insertion = format!(
        "\x20       provenance {{\n\
         \x20           kind \"oci\"\n\
         \x20           registry \"ghcr.io\"\n\
         \x20           repository \"acme/bar\"\n\
         \x20           digest \"sha256:{}\"\n\
         \x20       }}\n\
         \x20   }}\n}}\n",
        "b".repeat(64)
    );
    candidate = candidate.replacen("\x20   }\n}\n", &insertion, 1);

    let (_, baseline_state) = build_index_state(&baseline).unwrap();
    let (_, candidate_state) = build_index_state(&candidate).unwrap();
    let outcome = Baseline::new(baseline_state).check(&candidate_state);
    assert!(outcome.violations.is_empty());
    assert!(outcome.advanced);
}

// ---------------------------------------------------------------------------
// Attestation canonical digest rendering (A6): the attestation record's
// canonical-rendering instantiation (registry-protocol §3.5.3 NORMATIVE
// (canonical rendering for non-scalar candidate values)), live now that the
// attestation-monotone row enforces. The expected hex is ported VERBATIM
// from `test_index_history_ratchet.py::TestAttestationCanonicalDigest` —
// byte equality proves both implementations render the identical candidate
// text identically, not merely that each is internally consistent. The same
// hex is pinned in conformance fixture 406's expected/digest.
// ---------------------------------------------------------------------------

fn attestation_index_text(bundle_pin: &str) -> String {
    format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   namespace \"acme\"\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"sha256:{}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://example.com/bar.git\"\n\
         \x20           ref \"v1.0.0\"\n\
         \x20       }}\n\
         \x20       attestation \"author-signed\"\n\
         \x20       signed_by \"alice\"\n\
         \x20       bundle sha256=\"{bundle_pin}\"\n\
         \x20   }}\n\
         }}\n",
        "a".repeat(64)
    )
}

#[test]
fn attestation_repin_hand_computed_digest_vector() {
    let baseline = attestation_index_text(&"1".repeat(64));
    let candidate = attestation_index_text(&"2".repeat(64));
    let (_, baseline_state) = build_index_state(&baseline).unwrap();
    let (_, candidate_state) = build_index_state(&candidate).unwrap();
    let outcome = Baseline::new(baseline_state).check(&candidate_state);

    assert_eq!(outcome.violations.len(), 1);
    let v = &outcome.violations[0];
    assert_eq!(v.class, "TNG-ENTRY-MUTATED");
    assert_eq!(v.field, "attestation");
    assert_eq!(v.kind, "monotone-repinned");

    let expected_candidate_value = format!("author-signed\u{1f}alice\u{1f}{}", "2".repeat(64));
    assert_eq!(v.candidate_value, expected_candidate_value);

    // baseline_value: the same closed-field-set rendering
    // (<kind>\u{1f}<signer>\u{1f}<bundle_pin>, §3.5.3 NORMATIVE (canonical
    // rendering for non-scalar candidate values), the "attestation"
    // instantiation) applied to the BASELINE side, by hand from
    // `attestation_index_text`'s literal `bundle_pin` argument above.
    // Excluded from the digest (§3.5.3) but still carried on the payload
    // for human display — pinning it here closes the same differential
    // blind spot the candidate_value pin closes.
    let expected_baseline_value = format!("author-signed\u{1f}alice\u{1f}{}", "1".repeat(64));
    assert_eq!(v.baseline_value, expected_baseline_value);

    let digest = canonical_digest(&outcome.violations);
    assert_eq!(
        digest,
        "2c02fbe94260c81db0006a77d8572a54feb58d36d1071bf7191d790087a63323"
    );
}

// ---------------------------------------------------------------------------
// rekor canonical digest rendering (A6) + CR1 structured-comparison
// regression lock: `rekor` is now stored as `FieldValue::Rekor(RekorRef)`
// (structured, compared field-by-field) rather than a pre-joined delimiter
// string, but the DIGEST rendering (`rekor_canonical_raw`) is unchanged —
// this hand-computed vector proves the digest bytes are byte-identical to
// before the CR1 fix. Same index shape and digest as conformance fixture
// 408 (`fixture-408-index-history-rekor-frozen-changed-strict`).
// ---------------------------------------------------------------------------

fn rekor_index_text(uuid: &str) -> String {
    format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   namespace \"acme\"\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"sha256:{}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://example.com/bar.git\"\n\
         \x20           ref \"v1.0.0\"\n\
         \x20       }}\n\
         \x20       attestation \"milpa-vendored\"\n\
         \x20       rekor {{\n\
         \x20           uuid \"{uuid}\"\n\
         \x20           log_index \"10\"\n\
         \x20           integrated_time \"1000000000\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n",
        "a".repeat(64)
    )
}

#[test]
fn rekor_mutation_hand_computed_digest_vector() {
    let baseline = rekor_index_text(&"a".repeat(64));
    let candidate = rekor_index_text(&"b".repeat(64));
    let (_, baseline_state) = build_index_state(&baseline).unwrap();
    let (_, candidate_state) = build_index_state(&candidate).unwrap();
    let outcome = Baseline::new(baseline_state).check(&candidate_state);

    assert_eq!(outcome.violations.len(), 1);
    let v = &outcome.violations[0];
    assert_eq!(v.class, "TNG-ENTRY-MUTATED");
    assert_eq!(v.field, "rekor");
    assert_eq!(v.kind, "frozen-changed");

    let expected_candidate_value = format!("{}\u{1f}10\u{1f}1000000000", "b".repeat(64));
    assert_eq!(v.candidate_value, expected_candidate_value);

    // Guards the CR1 invariant: switching the COMPARISON value from a
    // joined `Str` to a structured `Rekor(RekorRef)` must not change the
    // DIGEST-rendering `raw` value at all — same hex as conformance
    // fixture 408's `expected/digest`.
    let digest = canonical_digest(&outcome.violations);
    assert_eq!(
        digest,
        "44b632a79531fc5562f23b8eb6685bff2154156289a5dad5a8fdfbd14ddd06ce"
    );
}

#[test]
fn attestation_strip_is_absent_candidate_value() {
    let baseline = "schema_version 1\n\
         package \"bar\" {\n\
         \x20   namespace \"acme\"\n\
         \x20   version \"1.0.0\" {\n\
         \x20       content_hash \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
         \x20       provenance {\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://example.com/bar.git\"\n\
         \x20           ref \"v1.0.0\"\n\
         \x20       }\n\
         \x20       attestation \"milpa-vendored\"\n\
         \x20   }\n\
         }\n";
    let candidate = baseline.replace("\x20       attestation \"milpa-vendored\"\n", "");

    let (_, baseline_state) = build_index_state(baseline).unwrap();
    let (_, candidate_state) = build_index_state(&candidate).unwrap();
    let outcome = Baseline::new(baseline_state).check(&candidate_state);
    assert_eq!(outcome.violations.len(), 1);
    let v = &outcome.violations[0];
    assert_eq!(v.kind, "monotone-stripped");
    assert_eq!(v.candidate_value, "");
}

// CR15: `attestation-epoch` is a document-root free-text field `Index`
// itself never surfaces (it lives outside every `package` node) —
// `raw_attestation_epoch` is the ONLY site that ever extracts it, and it
// feeds the root pseudo-entry's canonical violation digest (§3.5.3) as a
// raw, unescaped scalar. A `\u{9}` KDL escape decoding to a literal TAB —
// the digest's field-join delimiter — must be rejected at this
// parse-at-gate seam, exactly like every other free-text registry field.

#[test]
fn attestation_epoch_control_char_via_kdl_escape_is_rejected() {
    let text = "schema_version 1\n\
         attestation-epoch \"evil\\u{9}epoch\"\n\
         package \"bar\" {\n\
         \x20   version \"1.0.0\" {\n\
         \x20       content_hash \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
         \x20       provenance {\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://example.com/bar.git\"\n\
         \x20           ref \"v1.0.0\"\n\
         \x20       }\n\
         \x20   }\n\
         }\n";
    let err = build_index_state(text).unwrap_err();
    assert_eq!(err.code(), "TNG-UNSAFE-CONTROL-CHAR");
}

#[test]
fn safe_attestation_epoch_passes() {
    let text = "schema_version 1\n\
         attestation-epoch \"E1\"\n\
         package \"bar\" {\n\
         \x20   version \"1.0.0\" {\n\
         \x20       content_hash \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
         \x20       provenance {\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://example.com/bar.git\"\n\
         \x20           ref \"v1.0.0\"\n\
         \x20       }\n\
         \x20   }\n\
         }\n";
    build_index_state(text).unwrap();
}
