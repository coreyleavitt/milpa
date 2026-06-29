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
