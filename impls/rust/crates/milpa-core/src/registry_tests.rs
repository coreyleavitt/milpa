//! Unit tests for the tianguis index reader (S8). Each TNG validator + the
//! resolve-time policy is exercised here; the conformance corpus drives the same
//! codes end-to-end through the resolver (fixtures 087–098).

use super::*;
use milpa_solver::VersionSet;

const ID1: &str = "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001";

fn full() -> VersionSet {
    VersionSet::full()
}

fn gte(s: &str) -> VersionSet {
    VersionSet::from_constraint(Some(s)).unwrap()
}

/// Build an index.kdl with one git-vendored version, parameterizing the fields a
/// validator inspects. Multi-line children (the on-disk fixture form).
fn git_index(url: &str, git_ref: &str, commit_sha: Option<&str>) -> String {
    let commit = commit_sha
        .map(|s| format!("\n            commit_sha \"{s}\""))
        .unwrap_or_default();
    format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"{url}\"\n\
         \x20           ref \"{git_ref}\"{commit}\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    )
}

#[test]
fn parses_a_git_package_with_versions_sorted_newest_first() {
    let text = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   namespace \"acme\"\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://e/bar.git\"\n\
         \x20           ref \"v1.0.0\"\n\
         \x20       }}\n\
         \x20   }}\n\
         \x20   version \"2.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://e/bar.git\"\n\
         \x20           ref \"v2.0.0\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    );
    let idx = Index::parse(&text).unwrap();
    assert_eq!(idx.packages.len(), 1);
    let pkg = &idx.packages[0];
    assert_eq!(pkg.name, "bar");
    assert_eq!(pkg.namespace, "acme");
    // newest-first
    assert_eq!(pkg.versions[0].version, "2.0.0");
    assert_eq!(pkg.versions[1].version, "1.0.0");
    assert_eq!(pkg.versions[0].content_hash, ID1);
    assert!(matches!(
        pkg.versions[0].provenances[0],
        Provenance::Git { .. }
    ));
}

#[test]
fn higher_schema_version_is_refused() {
    let err = Index::parse("schema_version 99\n").unwrap_err();
    assert_eq!(err.code(), "TNG-SCHEMA-UNKNOWN");
}

#[test]
fn missing_schema_version_is_tolerated() {
    // Legacy/minimal index: no schema_version node parses fine.
    let idx = Index::parse("package \"bar\" {\n    version \"1.0.0\"\n}\n").unwrap();
    assert_eq!(idx.packages.len(), 1);
}

#[test]
fn unsafe_package_name_is_rejected_at_parse() {
    let text = "schema_version 1\npackage \"../evil\" {\n    version \"1.0.0\"\n}\n";
    assert_eq!(Index::parse(text).unwrap_err().code(), "TNG-UNSAFE-NAME");
}

#[test]
fn bad_commit_sha_is_rejected() {
    let text = git_index("https://e/bar.git", "v1", Some("nope"));
    assert_eq!(
        Index::parse(&text).unwrap_err().code(),
        "TNG-BAD-COMMIT-SHA"
    );
}

#[test]
fn good_commit_sha_is_accepted() {
    let sha = "cafef00dcafef00dcafef00dcafef00dcafef00d";
    let idx = Index::parse(&git_index("https://e/bar.git", "v1", Some(sha))).unwrap();
    match &idx.packages[0].versions[0].provenances[0] {
        Provenance::Git { commit_sha, .. } => assert_eq!(commit_sha.as_deref(), Some(sha)),
        other => panic!("expected git, got {other:?}"),
    }
}

#[test]
fn bad_oci_digest_is_rejected() {
    let text = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"oci\"\n\
         \x20           registry \"ghcr.io\"\n\
         \x20           repository \"e/bar\"\n\
         \x20           digest \"nope\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    );
    assert_eq!(
        Index::parse(&text).unwrap_err().code(),
        "TNG-BAD-OCI-DIGEST"
    );
}

#[test]
fn leading_dash_url_and_ref_are_rejected() {
    assert_eq!(
        Index::parse(&git_index("--upload-pack=evil", "v1", None))
            .unwrap_err()
            .code(),
        "TNG-UNSAFE-URL"
    );
    assert_eq!(
        Index::parse(&git_index("https://e/bar.git", "--upload-pack=rce", None))
            .unwrap_err()
            .code(),
        "TNG-UNSAFE-REF"
    );
}

#[test]
fn leading_dash_oci_field_is_rejected() {
    let text = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"oci\"\n\
         \x20           registry \"-bad\"\n\
         \x20           repository \"e/bar\"\n\
         \x20           digest \"{ID1}\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    );
    assert_eq!(
        Index::parse(&text).unwrap_err().code(),
        "TNG-UNSAFE-OCI-FIELD"
    );
}

#[test]
fn unknown_provenance_kind_is_skipped() {
    let text = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"ipfs\"\n\
         \x20           cid \"Qm123\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    );
    let idx = Index::parse(&text).unwrap();
    assert!(idx.packages[0].versions[0].provenances.is_empty());
}

#[test]
fn duplicate_version_keeps_the_first() {
    let text = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20   }}\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"dag-sha256:{}\"\n\
         \x20   }}\n\
         }}\n",
        "2".repeat(64)
    );
    let idx = Index::parse(&text).unwrap();
    assert_eq!(idx.packages[0].versions.len(), 1);
    assert_eq!(idx.packages[0].versions[0].content_hash, ID1);
}

// --- resolve-time policy (in-memory Index) ---

fn pkg(name: &str, namespace: &str, versions: Vec<IndexVersion>) -> Package {
    Package {
        name: name.into(),
        namespace: namespace.into(),
        versions,
    }
}

fn ver(v: &str, hash: &str, provs: Vec<Provenance>) -> IndexVersion {
    IndexVersion {
        version: v.into(),
        content_hash: hash.into(),
        provenances: provs,
        dep_decl: None,
        dep_decl_schema_version: None,
        attestation: None,
        namespace: String::new(),
        published_at: None,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        published_at_raw: None,
    }
}

fn git() -> Provenance {
    Provenance::Git {
        url: "https://e/bar.git".into(),
        ref_spec: "v1".into(),
        commit_sha: None,
    }
}

#[test]
fn resolve_not_found_is_tng_not_found() {
    let idx = Index::default();
    let err = idx.resolve_named_all("missing", &full(), None).unwrap_err();
    assert_eq!(err.code(), "TNG-NOT-FOUND");
}

#[test]
fn resolve_bare_collision_is_ambiguous() {
    let idx = Index {
        packages: vec![
            pkg("bar", "ns1", vec![ver("1.0.0", ID1, vec![git()])]),
            pkg("bar", "ns2", vec![ver("1.0.0", ID1, vec![git()])]),
        ],
    };
    assert_eq!(
        idx.resolve_named_all("bar", &full(), None)
            .unwrap_err()
            .code(),
        "TNG-AMBIGUOUS-NAME"
    );
}

#[test]
fn resolve_no_satisfying_version() {
    let idx = Index {
        packages: vec![pkg("bar", "", vec![ver("1.0.0", ID1, vec![git()])])],
    };
    let err = idx
        .resolve_named_all("bar", &gte(">= 2.0.0"), Some(">= 2.0.0"))
        .unwrap_err();
    assert_eq!(err.code(), "TNG-NO-SATISFYING-VERSION");
}

#[test]
fn resolve_all_provenance_less_is_no_provenance() {
    let idx = Index {
        packages: vec![pkg("bar", "", vec![ver("1.0.0", ID1, vec![])])],
    };
    let err = idx.resolve_named_all("bar", &full(), None).unwrap_err();
    assert_eq!(err.code(), "TNG-NO-PROVENANCE");
}

#[test]
fn resolve_returns_satisfying_newest_first() {
    let idx = Index {
        packages: vec![pkg(
            "bar",
            "",
            vec![
                ver("2.0.0", ID1, vec![git()]),
                ver("1.0.0", ID1, vec![git()]),
            ],
        )],
    };
    let got = idx.resolve_named_all("bar", &full(), None).unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].version, "2.0.0");
}

// ---------------------------------------------------------------------------
// A5 — yank selection semantics (registry-protocol §5.2 NORMATIVE yank
// clause), both named-lookup entry points. Mirrors
// impls/python/tests/test_registry.py::TestYankSelection.
// ---------------------------------------------------------------------------

fn yanked_ver(v: &str, hash: &str, provs: Vec<Provenance>, reason: Option<&str>) -> IndexVersion {
    IndexVersion {
        yanked: true,
        yanked_reason: reason.map(String::from),
        ..ver(v, hash, provs)
    }
}

#[test]
fn bare_yanked_version_excluded_from_enumeration() {
    let idx = Index {
        packages: vec![pkg(
            "bar",
            "",
            vec![
                yanked_ver("2.0.0", ID1, vec![git()], Some("ships a vulnerable bearssl pin")),
                ver("1.0.0", ID1, vec![git()]),
            ],
        )],
    };
    let got = idx.resolve_named_all("bar", &full(), None).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].version, "1.0.0");
}

#[test]
fn bare_all_yanked_raises_no_satisfying_version() {
    let idx = Index {
        packages: vec![pkg(
            "bar",
            "",
            vec![
                yanked_ver("2.0.0", ID1, vec![git()], Some("ships a vulnerable bearssl pin")),
                yanked_ver("1.0.0", ID1, vec![git()], None),
            ],
        )],
    };
    let err = idx.resolve_named_all("bar", &full(), None).unwrap_err();
    assert_eq!(err.code(), "TNG-NO-SATISFYING-VERSION");
}

#[test]
fn bare_no_satisfying_version_names_yanked_candidates() {
    let idx = Index {
        packages: vec![pkg(
            "bar",
            "",
            vec![yanked_ver(
                "2.0.0",
                ID1,
                vec![git()],
                Some("ships a vulnerable bearssl pin"),
            )],
        )],
    };
    let err = idx.resolve_named_all("bar", &full(), None).unwrap_err();
    assert_eq!(err.code(), "TNG-NO-SATISFYING-VERSION");
    assert!(err.message().contains("excluded as yanked"));
    assert!(err.message().contains("2.0.0"));
    assert!(err.message().contains("ships a vulnerable bearssl pin"));
}

#[test]
fn bare_no_yank_no_yanked_excluded_segment() {
    let idx = Index {
        packages: vec![pkg("bar", "", vec![ver("1.0.0", ID1, vec![git()])])],
    };
    let err = idx
        .resolve_named_all("bar", &gte(">= 2.0.0"), Some(">= 2.0.0"))
        .unwrap_err();
    assert_eq!(err.code(), "TNG-NO-SATISFYING-VERSION");
    assert!(!err.message().contains("excluded as yanked"));
}

#[test]
fn yanked_version_excluded_even_when_only_match_for_constraint() {
    // No --allow-yanked escape hatch (§3.2): a yanked version that is the
    // ONLY constraint-satisfying candidate is still excluded.
    let idx = Index {
        packages: vec![pkg(
            "bar",
            "",
            vec![
                yanked_ver("2.0.0", ID1, vec![git()], None),
                ver("1.0.0", ID1, vec![git()]),
            ],
        )],
    };
    let err = idx
        .resolve_named_all("bar", &gte("== 2.0.0"), Some("== 2.0.0"))
        .unwrap_err();
    assert_eq!(err.code(), "TNG-NO-SATISFYING-VERSION");
}

// -- qualified lookup path (resolve_named_all_qualified, S5b) — named
// explicitly in registry-protocol §5.2: "the qualified path is exactly
// where a parallel-logic miss has happened before."

#[test]
fn qualified_yanked_version_excluded_from_enumeration() {
    let idx = Index {
        packages: vec![pkg(
            "bar",
            "core",
            vec![
                yanked_ver("2.0.0", ID1, vec![git()], Some("ships a vulnerable bearssl pin")),
                ver("1.0.0", ID1, vec![git()]),
            ],
        )],
    };
    let got = idx
        .resolve_named_all_qualified("core", "bar", &full(), None)
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].version, "1.0.0");
}

#[test]
fn qualified_all_yanked_raises_no_satisfying_version() {
    let idx = Index {
        packages: vec![pkg(
            "bar",
            "core",
            vec![
                yanked_ver("2.0.0", ID1, vec![git()], Some("ships a vulnerable bearssl pin")),
                yanked_ver("1.0.0", ID1, vec![git()], None),
            ],
        )],
    };
    let err = idx
        .resolve_named_all_qualified("core", "bar", &full(), None)
        .unwrap_err();
    assert_eq!(err.code(), "TNG-NO-SATISFYING-VERSION");
}

#[test]
fn qualified_no_satisfying_version_names_yanked_candidates() {
    let idx = Index {
        packages: vec![pkg(
            "bar",
            "core",
            vec![yanked_ver(
                "2.0.0",
                ID1,
                vec![git()],
                Some("ships a vulnerable bearssl pin"),
            )],
        )],
    };
    let err = idx
        .resolve_named_all_qualified("core", "bar", &full(), None)
        .unwrap_err();
    assert_eq!(err.code(), "TNG-NO-SATISFYING-VERSION");
    assert!(err.message().contains("excluded as yanked"));
    assert!(err.message().contains("ships a vulnerable bearssl pin"));
}

// ---------------------------------------------------------------------------
// S2 — dep_decl + dep_decl_schema_version on IndexVersion
// ---------------------------------------------------------------------------

const DEP_DECL_HASH: &str =
    "sha256:7f3c7f3c7f3c7f3c7f3c7f3c7f3c7f3c7f3c7f3c7f3c7f3c7f3c7f3c7f3c7f3c";

fn index_with_dep_decl() -> String {
    format!(
        "schema_version 1\n\
         package \"nkdl\" {{\n\
         \x20   namespace \"coreyleavitt\"\n\
         \x20   version \"0.2.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       dep_decl \"{DEP_DECL_HASH}\"\n\
         \x20       dep_decl_schema_version 0\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://github.com/coreyleavitt/nkdl\"\n\
         \x20           ref \"v0.2.0\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    )
}

fn index_without_dep_decl() -> String {
    format!(
        "schema_version 1\n\
         package \"nkdl\" {{\n\
         \x20   namespace \"coreyleavitt\"\n\
         \x20   version \"0.2.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://github.com/coreyleavitt/nkdl\"\n\
         \x20           ref \"v0.2.0\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    )
}

#[test]
fn s2_dep_decl_present_is_surfaced() {
    let idx = Index::parse(&index_with_dep_decl()).unwrap();
    let iv = &idx.packages[0].versions[0];
    assert_eq!(iv.dep_decl.as_deref(), Some(DEP_DECL_HASH));
}

#[test]
fn s2_dep_decl_schema_version_present_is_surfaced() {
    let idx = Index::parse(&index_with_dep_decl()).unwrap();
    let iv = &idx.packages[0].versions[0];
    assert_eq!(iv.dep_decl_schema_version, Some(0));
}

#[test]
fn s2_dep_decl_absent_yields_none() {
    let idx = Index::parse(&index_without_dep_decl()).unwrap();
    let iv = &idx.packages[0].versions[0];
    assert!(iv.dep_decl.is_none());
}

#[test]
fn s2_dep_decl_schema_version_absent_yields_none() {
    let idx = Index::parse(&index_without_dep_decl()).unwrap();
    let iv = &idx.packages[0].versions[0];
    assert!(iv.dep_decl_schema_version.is_none());
}

// ---------------------------------------------------------------------------
// RFC per-entry-attestation.md P2 — EntryAttestation parse (registry-protocol §3.2)
// ---------------------------------------------------------------------------

fn index_author_signed_with_rekor() -> String {
    format!(
        "schema_version 1\n\
         package \"nimkdl\" {{\n\
         \x20   namespace \"coreyleavitt\"\n\
         \x20   version \"0.1.4\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://github.com/coreyleavitt/nimkdl\"\n\
         \x20           ref \"v0.1.4\"\n\
         \x20       }}\n\
         \x20       attestation \"author-signed\"\n\
         \x20       signed_by \"https://github.com/coreyleavitt/tianguis/.github/workflows/publish.yaml\"\n\
         \x20       rekor {{\n\
         \x20           uuid \"108e9186e8c5677abce5a62d285437741218f878474a02d9a4dac01dc12e39b979336e712890d636\"\n\
         \x20           log_index \"1753541583\"\n\
         \x20           integrated_time \"1780881469\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    )
}

#[test]
fn test_rekor_block_folds_into_attestation() {
    // Inverts the prior tolerate-and-ignore behavior: registry-protocol.md
    // §3.2 now parses `attestation`/`signed_by`/`rekor` into a typed
    // `EntryAttestation` record instead of discarding them (RFC
    // per-entry-attestation.md P2 slice).
    let idx = Index::parse(&index_author_signed_with_rekor()).unwrap();
    let iv = &idx.packages[0].versions[0];
    let att = iv.attestation.as_ref().expect("must be attested");
    match &att.kind {
        AttestationKind::AuthorSigned { signer } => {
            assert_eq!(
                signer,
                "https://github.com/coreyleavitt/tianguis/.github/workflows/publish.yaml"
            );
        }
        AttestationKind::MilpaVendored => panic!("expected AuthorSigned"),
    }
    let rekor = att.rekor.as_ref().expect("rekor must be present");
    assert_eq!(
        rekor.uuid,
        "108e9186e8c5677abce5a62d285437741218f878474a02d9a4dac01dc12e39b979336e712890d636"
    );
    assert_eq!(rekor.log_index, "1753541583");
    assert_eq!(rekor.integrated_time, "1780881469");
    assert!(att.bundle_pin.is_none());
}

#[test]
fn test_rekor_without_attestation_is_tolerated_and_ignored() {
    // A lone `rekor` block with no `attestation` kind is still forward-compat
    // ignored — there is no kind to tag it with (registry-protocol §3.2 NORMATIVE).
    let text = format!(
        "schema_version 1\n\
         package \"foo\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://example.com/foo.git\"\n\
         \x20           ref \"main\"\n\
         \x20       }}\n\
         \x20       rekor {{\n\
         \x20           uuid \"abc\"\n\
         \x20           log_index \"1\"\n\
         \x20           integrated_time \"2\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    );
    let idx = Index::parse(&text).unwrap();
    let iv = &idx.packages[0].versions[0];
    assert!(iv.attestation.is_none());
}

#[test]
fn test_milpa_vendored_has_no_signer() {
    let text = format!(
        "schema_version 1\n\
         package \"chronos\" {{\n\
         \x20   namespace \"status-im\"\n\
         \x20   version \"4.0.3\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://github.com/status-im/nim-chronos\"\n\
         \x20           ref \"HEAD\"\n\
         \x20       }}\n\
         \x20       attestation \"milpa-vendored\"\n\
         \x20   }}\n\
         }}\n"
    );
    let idx = Index::parse(&text).unwrap();
    let iv = &idx.packages[0].versions[0];
    let att = iv.attestation.as_ref().expect("must be attested");
    assert!(matches!(att.kind, AttestationKind::MilpaVendored));
    assert!(att.rekor.is_none());
    assert!(att.bundle_pin.is_none());
}

/// A minimal single-version `version` KdlNode for exercising `parse_version_node`
/// directly (diagnostics-vector assertions — this test module is a submodule of
/// `registry` via `super::*`, so private items are reachable).
fn one_version_node(inner: &str) -> kdl::KdlDocument {
    let text = format!(
        "package \"foo\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://example.com/foo.git\"\n\
         \x20           ref \"main\"\n\
         \x20       }}\n\
         {inner}\
         \x20   }}\n\
         }}\n"
    );
    kdl::KdlDocument::parse(&text).unwrap()
}

fn version_child(doc: &kdl::KdlDocument) -> kdl::KdlNode {
    let pkg = doc.nodes().iter().find(|n| n.name().value() == "package").unwrap();
    pkg.children()
        .unwrap()
        .nodes()
        .iter()
        .find(|n| n.name().value() == "version")
        .unwrap()
        .clone()
}

#[test]
fn test_unrecognized_attestation_kind_collapses_to_unattested() {
    // Closed kind set (registry-protocol §3.2 NORMATIVE): an unrecognized
    // `attestation` value MUST collapse to None with an observable diagnostic.
    let doc = one_version_node("        attestation \"bogus-kind\"\n");
    let node = version_child(&doc);
    let (iv, diagnostics) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert!(iv.attestation.is_none());
    assert!(
        diagnostics.iter().any(|m| m.contains("bogus-kind") && m.contains("foo")),
        "diagnostics: {diagnostics:?}"
    );
}

#[test]
fn test_author_signed_missing_signed_by_collapses_to_unattested() {
    // `author-signed` with no sibling `signed_by` is structurally invalid —
    // MUST collapse to None with an observable diagnostic (registry-protocol §3.2).
    let doc = one_version_node("        attestation \"author-signed\"\n");
    let node = version_child(&doc);
    let (iv, diagnostics) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert!(iv.attestation.is_none());
    assert!(
        diagnostics.iter().any(|m| m.contains("author-signed") && m.contains("foo")),
        "diagnostics: {diagnostics:?}"
    );
}

#[test]
fn test_bundle_pin_captured_when_valid() {
    let hex64 = "a".repeat(64);
    let doc = one_version_node(&format!(
        "        attestation \"author-signed\"\n\
         \x20       signed_by \"https://example.com/workflow.yaml\"\n\
         \x20       bundle sha256=\"{hex64}\"\n"
    ));
    let node = version_child(&doc);
    let (iv, diagnostics) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    let att = iv.attestation.expect("must be attested");
    assert_eq!(att.bundle_pin.as_deref(), Some(hex64.as_str()));
    assert!(diagnostics.is_empty());
}

#[test]
fn test_malformed_bundle_pin_drops_pin_without_collapsing_kind() {
    // A malformed `bundle sha256=` value normalizes ONLY bundle_pin to None
    // — it MUST NOT collapse an otherwise well-formed kind/signer pairing
    // (registry-protocol §3.2 NORMATIVE).
    let doc = one_version_node(
        "        attestation \"author-signed\"\n\
         \x20       signed_by \"https://example.com/workflow.yaml\"\n\
         \x20       bundle sha256=\"not-valid-hex\"\n",
    );
    let node = version_child(&doc);
    let (iv, diagnostics) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    let att = iv.attestation.expect("kind/signer must survive");
    assert!(matches!(att.kind, AttestationKind::AuthorSigned { .. }));
    assert!(att.bundle_pin.is_none());
    assert!(
        diagnostics.iter().any(|m| m.contains("bundle") && m.contains("not-valid-hex")),
        "diagnostics: {diagnostics:?}"
    );
}

#[test]
fn test_no_attestation_node_is_unattested() {
    // A legacy entry with none of the four sibling nodes parses as unattested,
    // with no diagnostic (absence is not a collapse — registry-protocol §3.2).
    let doc = one_version_node("");
    let node = version_child(&doc);
    let (iv, diagnostics) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert!(iv.attestation.is_none());
    assert!(diagnostics.is_empty());
}

// ---------------------------------------------------------------------------
// A2a — published_at + yank triple parse-to-typed extension
// (registry-protocol §3.2 "published_at" / "Yank triple"; mirrors
// impls/python/tests/test_registry.py::TestA2aPublishedAtAndYankTriple)
// ---------------------------------------------------------------------------

#[test]
fn a2a_published_at_parsed_to_timestamp() {
    let doc = one_version_node("        published_at \"2026-06-01T00:00:00Z\"\n");
    let node = version_child(&doc);
    let (iv, _) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert_eq!(
        iv.published_at,
        parse_iso8601_timestamp("2026-06-01T00:00:00Z")
    );
    assert_eq!(iv.published_at_raw.as_deref(), Some("2026-06-01T00:00:00Z"));
}

#[test]
fn a2a_published_at_absent_yields_none() {
    let doc = one_version_node("");
    let node = version_child(&doc);
    let (iv, _) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert!(iv.published_at.is_none());
    assert!(iv.published_at_raw.is_none());
}

#[test]
fn a2a_malformed_published_at_yields_none_no_diagnostic() {
    let doc = one_version_node("        published_at \"not-a-timestamp\"\n");
    let node = version_child(&doc);
    let (iv, diagnostics) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert!(iv.published_at.is_none());
    // Raw text is still captured (digest needs "exactly as served" even when
    // malformed) but the typed value is absent, and no diagnostic fires.
    assert_eq!(iv.published_at_raw.as_deref(), Some("not-a-timestamp"));
    assert!(diagnostics.is_empty());
}

#[test]
fn a2a_yanked_true_parsed() {
    let doc = one_version_node("        yanked #true\n");
    let node = version_child(&doc);
    let (iv, _) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert!(iv.yanked);
}

#[test]
fn a2a_yanked_at_parsed_to_timestamp() {
    let doc = one_version_node("        yanked_at \"2026-07-01T12:00:00Z\"\n");
    let node = version_child(&doc);
    let (iv, _) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert_eq!(
        iv.yanked_at,
        parse_iso8601_timestamp("2026-07-01T12:00:00Z")
    );
}

#[test]
fn a2a_yanked_reason_parsed() {
    let doc = one_version_node("        yanked_reason \"ships a vulnerable bearssl pin\"\n");
    let node = version_child(&doc);
    let (iv, _) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert_eq!(iv.yanked_reason.as_deref(), Some("ships a vulnerable bearssl pin"));
}

#[test]
fn a2a_yanked_absent_defaults_false() {
    let doc = one_version_node("");
    let node = version_child(&doc);
    let (iv, _) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert!(!iv.yanked);
}

#[test]
fn a2a_yanked_at_absent_yields_none() {
    let doc = one_version_node("");
    let node = version_child(&doc);
    let (iv, _) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert!(iv.yanked_at.is_none());
}

#[test]
fn a2a_yanked_reason_absent_yields_none() {
    let doc = one_version_node("");
    let node = version_child(&doc);
    let (iv, _) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert!(iv.yanked_reason.is_none());
}

#[test]
fn a2a_malformed_yanked_defaults_false_no_diagnostic() {
    let doc = one_version_node("        yanked \"not-a-bool\"\n");
    let node = version_child(&doc);
    let (iv, diagnostics) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert!(!iv.yanked);
    assert!(diagnostics.is_empty());
}

#[test]
fn a2a_malformed_yanked_at_yields_none_no_diagnostic() {
    let doc = one_version_node("        yanked_at \"also-not-a-timestamp\"\n");
    let node = version_child(&doc);
    let (iv, diagnostics) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert!(iv.yanked_at.is_none());
    assert!(diagnostics.is_empty());
}

// ---------------------------------------------------------------------------
// ISO-8601 timestamp parser — malformed/edge cases (registry.rs's hand-rolled
// parser; no external date crate — see registry.rs module docs).
// ---------------------------------------------------------------------------

#[test]
fn iso8601_parses_z_suffixed() {
    let t = parse_iso8601_timestamp("2026-05-26T04:49:44Z").unwrap();
    // 2026-05-26T04:49:44Z: sanity-check against an independently computed
    // Unix timestamp (via `date -u -d ... +%s`-equivalent reasoning is not
    // available offline here, so this pins internal consistency: re-parsing
    // the same string is idempotent and two different instants differ).
    let t2 = parse_iso8601_timestamp("2026-05-26T04:49:44Z").unwrap();
    assert_eq!(t, t2);
    let t3 = parse_iso8601_timestamp("2026-05-26T04:49:45Z").unwrap();
    assert_ne!(t, t3);
    assert_eq!(t3.unix_seconds, t.unix_seconds + 1);
}

#[test]
fn iso8601_offset_and_z_agree_on_same_instant() {
    let z = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
    let offset = parse_iso8601_timestamp("2026-01-01T01:00:00+01:00").unwrap();
    assert_eq!(z, offset);
}

#[test]
fn iso8601_rejects_garbage() {
    assert!(parse_iso8601_timestamp("not-a-timestamp").is_none());
    assert!(parse_iso8601_timestamp("").is_none());
    assert!(parse_iso8601_timestamp("2026-13-01T00:00:00Z").is_none()); // month 13
    assert!(parse_iso8601_timestamp("2026-01-01T00:00:00+99:99").is_none());
}
