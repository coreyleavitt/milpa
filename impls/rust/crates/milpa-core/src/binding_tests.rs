//! Unit tests for `binding.rs` (rfc-origin-as-identity.md S2).
//!
//! Mirrors Python's `test_binding.py` example-based coverage. Property-based
//! coverage (idempotence, order-independence of DUPLICATE detection) is
//! Python-only (`source_id_tests.rs`'s own note: Rust proptest is
//! deliberately not wired up yet) — this file covers the same laws with a
//! handful of representative examples instead.

use super::*;
use milpa_types::{DepKey, FetchableOrigin, SourceId};

fn git(url: &str) -> SourceId {
    SourceId::Fetchable(FetchableOrigin::Git { git_ref: None, url: url.to_string(), subpath: None })
}

fn registry(reg: &str, ns: Option<&str>, name: &str) -> SourceId {
    SourceId::Fetchable(FetchableOrigin::Registry {
        registry: reg.to_string(),
        namespace: ns.map(|s| s.to_string()),
        name: name.to_string(),
    })
}

fn nimz3() -> SourceId {
    git("https://github.com/coreyleavitt/nim-z3")
}

fn zevv_z3() -> SourceId {
    git("https://github.com/zevv/nimz3")
}

fn reg_chronos() -> SourceId {
    registry("tianguis", None, "chronos")
}

fn reg_chronos_fork() -> SourceId {
    registry("tianguis", Some("acme"), "chronos-fork")
}

fn claim(name: &str, sid: SourceId, is_root: bool, claimant: &str) -> Claim {
    Claim { name: name.to_string(), source_id: sid, is_root, claimant: claimant.to_string() }
}

// ---------------------------------------------------------------------------
// new() — root/override binding
// ---------------------------------------------------------------------------

#[test]
fn root_claim_is_bound_at_construction() {
    let resolver = BindingResolver::new(&[claim("foo", nimz3(), true, "root")]);
    assert_eq!(resolver.source_id_for(&DepKey::bare("foo")), Some(&nimz3()));
}

#[test]
fn empty_root_claims_binds_nothing() {
    let resolver = BindingResolver::new(&[]);
    assert_eq!(resolver.source_id_for(&DepKey::bare("foo")), None);
}

#[test]
fn source_id_for_unknown_key_returns_none() {
    let resolver = BindingResolver::new(&[claim("foo", nimz3(), true, "root")]);
    assert_eq!(resolver.source_id_for(&DepKey::bare("bar")), None);
}

#[test]
#[should_panic]
fn non_root_claim_in_new_panics() {
    let _ = BindingResolver::new(&[claim("foo", nimz3(), false, "root@1.0.0")]);
}

#[test]
fn matching_duplicate_root_claims_are_fine() {
    // Two root claims that AGREE (e.g. an override reasserting the same
    // target as a placeholder dep decl) are not a conflict.
    let resolver = BindingResolver::new(&[
        claim("foo", nimz3(), true, "root"),
        claim("foo", nimz3(), true, "override:foo"),
    ]);
    assert_eq!(resolver.source_id_for(&DepKey::bare("foo")), Some(&nimz3()));
}

#[test]
#[should_panic]
fn disagreeing_root_claims_is_internal_invariant_violation() {
    // Two root claims for one name with DIFFERENT sources is unreachable by
    // construction — a panic, never RES-BINDING-CONFLICT.
    let _ = BindingResolver::new(&[
        claim("foo", nimz3(), true, "root"),
        claim("foo", zevv_z3(), true, "override:foo"),
    ]);
}

// ---------------------------------------------------------------------------
// submit() — arbitration
// ---------------------------------------------------------------------------

#[test]
#[should_panic]
fn root_claim_in_submit_panics() {
    let mut resolver = BindingResolver::new(&[]);
    let _ = resolver.submit(&claim("foo", nimz3(), true, "root"));
}

#[test]
fn first_transitive_claim_is_new() {
    let mut resolver = BindingResolver::new(&[]);
    let decision = resolver.submit(&claim("foo", nimz3(), false, "parent@1.0.0")).unwrap();
    assert_eq!(decision.outcome, BindOutcome::New);
    assert_eq!(decision.accepted, nimz3());
    assert_eq!(resolver.source_id_for(&DepKey::bare("foo")), Some(&nimz3()));
}

#[test]
fn matching_transitive_claim_is_duplicate() {
    let mut resolver = BindingResolver::new(&[]);
    resolver.submit(&claim("foo", nimz3(), false, "a@1.0.0")).unwrap();
    let decision = resolver.submit(&claim("foo", nimz3(), false, "b@2.0.0")).unwrap();
    assert_eq!(decision.outcome, BindOutcome::Duplicate);
    assert_eq!(decision.accepted, nimz3());
}

#[test]
fn transitive_disagrees_with_root_loses_silently() {
    let mut resolver = BindingResolver::new(&[claim("foo", nimz3(), true, "root")]);
    let decision = resolver.submit(&claim("foo", zevv_z3(), false, "a@1.0.0")).unwrap();
    assert_eq!(decision.outcome, BindOutcome::LostToRoot);
    assert_eq!(decision.accepted, nimz3());
    assert_eq!(resolver.source_id_for(&DepKey::bare("foo")), Some(&nimz3()));
}

#[test]
fn two_disagreeing_transitives_with_no_root_conflict() {
    let mut resolver = BindingResolver::new(&[]);
    resolver.submit(&claim("foo", nimz3(), false, "a@1.0.0")).unwrap();
    let err = resolver.submit(&claim("foo", zevv_z3(), false, "b@1.0.0")).unwrap_err();
    assert_eq!(err.code(), "RES-BINDING-CONFLICT");
}

#[test]
fn conflict_message_names_both_sources_and_remedy() {
    let mut resolver = BindingResolver::new(&[]);
    resolver.submit(&claim("foo", nimz3(), false, "a@1.0.0")).unwrap();
    let err = resolver.submit(&claim("foo", zevv_z3(), false, "b@1.0.0")).unwrap_err();
    let message = err.message();
    assert!(message.contains("nim-z3"));
    assert!(message.contains("zevv/nimz3"));
    assert!(message.contains("overrides {}"));
}

#[test]
fn conflict_does_not_mutate_existing_binding() {
    let mut resolver = BindingResolver::new(&[]);
    resolver.submit(&claim("foo", nimz3(), false, "a@1.0.0")).unwrap();
    let _ = resolver.submit(&claim("foo", zevv_z3(), false, "b@1.0.0"));
    assert_eq!(resolver.source_id_for(&DepKey::bare("foo")), Some(&nimz3()));
}

// ---------------------------------------------------------------------------
// Namespace non-crossing — first-class RED test (RFC §4.3 B1/G1, the literal
// #193 root cause: a bare-name store lets ns1::foo and ns2::foo cross-bind).
// ---------------------------------------------------------------------------

#[test]
fn ns1_foo_and_ns2_foo_never_cross_bind_via_submit() {
    let mut resolver = BindingResolver::new(&[]);
    let d1 = resolver.submit(&claim("ns1::foo", nimz3(), false, "a@1.0.0")).unwrap();
    let d2 = resolver.submit(&claim("ns2::foo", zevv_z3(), false, "b@1.0.0")).unwrap();
    assert_eq!(d1.outcome, BindOutcome::New);
    assert_eq!(d2.outcome, BindOutcome::New);
    assert_eq!(
        resolver.source_id_for(&DepKey { name: "foo".into(), namespace: Some("ns1".into()) }),
        Some(&nimz3())
    );
    assert_eq!(
        resolver.source_id_for(&DepKey { name: "foo".into(), namespace: Some("ns2".into()) }),
        Some(&zevv_z3())
    );
    assert_eq!(resolver.source_id_for(&DepKey::bare("foo")), None);
}

#[test]
fn ns1_foo_and_ns2_foo_never_cross_bind_via_root() {
    // Different DepKeys — this must NOT panic, even though both claims are
    // is_root=true and would collide if keyed by bare name.
    let resolver = BindingResolver::new(&[
        claim("ns1::foo", nimz3(), true, "root"),
        claim("ns2::foo", zevv_z3(), true, "root"),
    ]);
    assert_eq!(
        resolver.source_id_for(&DepKey { name: "foo".into(), namespace: Some("ns1".into()) }),
        Some(&nimz3())
    );
    assert_eq!(
        resolver.source_id_for(&DepKey { name: "foo".into(), namespace: Some("ns2".into()) }),
        Some(&zevv_z3())
    );
}

#[test]
fn ns_qualified_transitive_vs_unqualified_root_do_not_interact() {
    let mut resolver = BindingResolver::new(&[claim("foo", nimz3(), true, "root")]);
    // A namespaced transitive claim for "ns1::foo" is a DIFFERENT DepKey
    // from the unqualified root's "foo" — it must be NEW, not LOST_TO_ROOT.
    let decision = resolver.submit(&claim("ns1::foo", zevv_z3(), false, "a@1.0.0")).unwrap();
    assert_eq!(decision.outcome, BindOutcome::New);
    assert_eq!(resolver.source_id_for(&DepKey::bare("foo")), Some(&nimz3()));
    assert_eq!(
        resolver.source_id_for(&DepKey { name: "foo".into(), namespace: Some("ns1".into()) }),
        Some(&zevv_z3())
    );
}

// ---------------------------------------------------------------------------
// Override to a different coordinate (RFC §5 row) — grouping key stays the
// OVERRIDDEN name, not the accepted SourceId's own namespace/name.
// ---------------------------------------------------------------------------

#[test]
fn grouping_key_is_overridden_name_not_target_coordinate() {
    let resolver =
        BindingResolver::new(&[claim("chronos", reg_chronos_fork(), true, "override:chronos")]);
    assert_eq!(resolver.source_id_for(&DepKey::bare("chronos")), Some(&reg_chronos_fork()));
    assert_eq!(
        resolver.source_id_for(&DepKey { name: "chronos-fork".into(), namespace: Some("acme".into()) }),
        None
    );
}

#[test]
fn transitive_matching_override_target_is_duplicate() {
    let mut resolver =
        BindingResolver::new(&[claim("chronos", reg_chronos_fork(), true, "override:chronos")]);
    let decision =
        resolver.submit(&claim("chronos", reg_chronos_fork(), false, "a@1.0.0")).unwrap();
    assert_eq!(decision.outcome, BindOutcome::Duplicate);
}

#[test]
fn transitive_disagreeing_with_override_loses_to_root() {
    let mut resolver =
        BindingResolver::new(&[claim("chronos", reg_chronos_fork(), true, "override:chronos")]);
    let decision = resolver.submit(&claim("chronos", reg_chronos(), false, "a@1.0.0")).unwrap();
    assert_eq!(decision.outcome, BindOutcome::LostToRoot);
    assert_eq!(decision.accepted, reg_chronos_fork());
}

// ---------------------------------------------------------------------------
// Idempotence / order-independence — a handful of representative examples
// standing in for Python's Hypothesis coverage (see module doc comment).
// ---------------------------------------------------------------------------

#[test]
fn resubmitting_a_matching_claim_is_always_duplicate() {
    let mut resolver = BindingResolver::new(&[]);
    let first = resolver.submit(&claim("foo", nimz3(), false, "a@1.0.0")).unwrap();
    assert_eq!(first.outcome, BindOutcome::New);
    for i in 0..5 {
        let decision =
            resolver.submit(&claim("foo", nimz3(), false, &format!("b{i}@1.0.0"))).unwrap();
        assert_eq!(decision.outcome, BindOutcome::Duplicate);
        assert_eq!(decision.accepted, nimz3());
    }
}

#[test]
fn interleaving_two_distinct_names_does_not_disturb_duplicate_detection() {
    let mut resolver = BindingResolver::new(&[]);
    let d1 = resolver.submit(&claim("x", nimz3(), false, "a@1.0.0")).unwrap();
    let d2 = resolver.submit(&claim("y", zevv_z3(), false, "a@1.0.0")).unwrap();
    assert_eq!(d1.outcome, BindOutcome::New);
    assert_eq!(d2.outcome, BindOutcome::New);

    let d3 = resolver.submit(&claim("x", nimz3(), false, "b@1.0.0")).unwrap();
    let d4 = resolver.submit(&claim("y", zevv_z3(), false, "b@1.0.0")).unwrap();
    assert_eq!(d3.outcome, BindOutcome::Duplicate);
    assert_eq!(d3.accepted, nimz3());
    assert_eq!(d4.outcome, BindOutcome::Duplicate);
    assert_eq!(d4.accepted, zevv_z3());
}

// ---------------------------------------------------------------------------
// S5-rekey (RFC §4.4 deliverable #1) — canonical_for / depkey_for_canonical /
// canonical_key_for_requirement. Landed, tested building blocks for the
// solver re-key; NOT YET wired into resolve()/resolve_workspace() (`Term`/
// `SolverDep::new` and the provider's `candidates`/`stubs` maps are still
// name-keyed) — mirrors Python's equivalent `test_binding.py` additions.
// ---------------------------------------------------------------------------

#[test]
fn canonical_for_bound_key_returns_canonical_string() {
    let resolver = BindingResolver::new(&[claim("foo", nimz3(), true, "root")]);
    assert_eq!(resolver.canonical_for(&DepKey::bare("foo")).unwrap(), canonical(&nimz3()));
}

#[test]
fn canonical_for_unbound_key_is_milpa_internal() {
    let resolver = BindingResolver::new(&[]);
    let err = resolver.canonical_for(&DepKey::bare("never-bound")).unwrap_err();
    assert_eq!(err.code(), "MILPA-INTERNAL");
}

#[test]
fn display_for_returns_none_when_nothing_bound() {
    let resolver = BindingResolver::new(&[]);
    assert_eq!(resolver.display_for("git+https://example.com/x"), None);
}

#[test]
fn solver_key_display_is_the_bound_depkey() {
    let resolver = BindingResolver::new(&[claim("foo", nimz3(), true, "root")]);
    let sk = resolver.canonical_for(&DepKey::bare("foo")).unwrap();
    // A SolverKey IS its canonical origin string …
    assert_eq!(sk, canonical(&nimz3()));
    // … and carries its display DepKey inline.
    assert_eq!(sk.display(), &DepKey::bare("foo"));
}

#[test]
fn solver_key_two_labels_one_source_collapse_to_the_first_bound_depkey() {
    // The headline regression: two DIFFERENT root claims ("foo", "bar") that
    // both target the SAME source-id collapse to ONE origin — its SolverKey
    // `.display()` is whichever DepKey was bound FIRST (BFS-first, mirroring
    // Phase B's alias-selection convention), never the second, regardless of
    // which label is used to look it up.
    let resolver = BindingResolver::new(&[
        claim("foo", nimz3(), true, "root"),
        claim("bar", nimz3(), true, "root"),
    ]);
    assert_eq!(resolver.canonical_for(&DepKey::bare("foo")).unwrap().display(), &DepKey::bare("foo"));
    assert_eq!(resolver.canonical_for(&DepKey::bare("bar")).unwrap().display(), &DepKey::bare("foo"));
}

#[test]
fn solver_key_transitive_claim_extends_the_index() {
    let mut resolver = BindingResolver::new(&[]);
    resolver.submit(&claim("foo", nimz3(), false, "a@1.0.0")).unwrap();
    assert_eq!(resolver.canonical_for(&DepKey::bare("foo")).unwrap().display(), &DepKey::bare("foo"));
}

#[test]
fn canonical_key_for_requirement_url_matches_git_source_id_canonical() {
    let index = Index { packages: vec![] };
    let key = canonical_key_for_requirement(
        "foo",
        None,
        Some("https://github.com/coreyleavitt/nim-z3"),
        None,
        &std::collections::BTreeMap::new(),
        &index,
        None,
        None,
    )
    .unwrap();
    assert_eq!(key, canonical(&nimz3()));
}

#[test]
fn canonical_key_for_requirement_named_matches_registry_source_id_canonical() {
    let index = Index { packages: vec![] };
    let key = canonical_key_for_requirement(
        "chronos",
        None,
        None,
        None,
        &std::collections::BTreeMap::new(),
        &index,
        None,
        None,
    )
    .unwrap();
    assert_eq!(key, canonical(&reg_chronos()));
}

#[test]
fn canonical_key_for_requirement_override_wins_over_own_declared_source() {
    use milpa_manifest::{Override, OverrideTarget};

    let index = Index { packages: vec![] };
    let mut overrides = std::collections::BTreeMap::new();
    overrides.insert(
        "chronos".to_string(),
        Override {
            name: "chronos".to_string(),
            target: OverrideTarget::Git {
                url: "https://github.com/zevv/nimz3".to_string(),
                git_ref: "main".to_string(),
                subpath: None,
            },
            version: None,
        },
    );
    let key = canonical_key_for_requirement("chronos", None, None, None, &overrides, &index, None, None).unwrap();
    // DE2-ref: the override pins git_ref="main", so it is part of the source pin.
    assert_eq!(
        key,
        canonical(&SourceId::Fetchable(FetchableOrigin::Git {
            url: "https://github.com/zevv/nimz3".to_string(),
            git_ref: Some("main".to_string()),
            subpath: None,
        }))
    );
}

#[test]
fn canonical_key_for_requirement_two_labels_same_url_produce_the_same_canonical_key() {
    // The pre-fetch collapse precondition: independent of WHICH label a
    // requirement is declared under, the SAME (url, no-override) always
    // yields the SAME canonical key — this is what lets `candidates`/
    // `SolverDep::new` naturally collapse two labels for one origin.
    let index = Index { packages: vec![] };
    let empty = std::collections::BTreeMap::new();
    let url = "https://github.com/coreyleavitt/nim-z3";
    let key_foo = canonical_key_for_requirement("foo", None, Some(url), None, &empty, &index, None, None).unwrap();
    let key_bar = canonical_key_for_requirement("bar", None, Some(url), None, &empty, &index, None, None).unwrap();
    assert_eq!(key_foo, key_bar);
}
