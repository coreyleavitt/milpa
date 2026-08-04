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

// --- registry-protocol §3.3: the optional oci provenance `source` field ----
// (the git repository an OCI artifact was packed and published from) -------

#[test]
fn oci_provenance_source_url_absent_by_default() {
    // No `source` child on the oci provenance — an older (pre-this-field)
    // index entry — so source_url parses to None, not an empty string or a
    // hard error (registry-protocol §3.3 — optional, purely additive).
    // Mirrors Python's `test_oci_provenance_source_url_absent_by_default`.
    let text = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"oci\"\n\
         \x20           registry \"ghcr.io\"\n\
         \x20           repository \"e/bar\"\n\
         \x20           digest \"sha256:{}\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n",
        "b".repeat(64)
    );
    let idx = Index::parse(&text).unwrap();
    match &idx.packages[0].versions[0].provenances[0] {
        Provenance::Oci { source_url, .. } => assert_eq!(*source_url, None),
        other => panic!("expected oci, got {other:?}"),
    }
}

#[test]
fn oci_provenance_source_url_parsed_url_annotated() {
    // `source (url)"…"` — the milpa KDL url convention — parses into
    // `Provenance::Oci::source_url` as a plain string (registry-protocol
    // §3.3), mirroring how `git`'s own `url` field already accepts the
    // annotation. Mirrors Python's
    // `test_oci_provenance_source_url_parsed_url_annotated`.
    let text = format!(
        "schema_version 1\n\
         package \"z3\" {{\n\
         \x20   namespace \"coreyleavitt\"\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"oci\"\n\
         \x20           registry \"ghcr.io\"\n\
         \x20           repository \"coreyleavitt/z3\"\n\
         \x20           digest \"sha256:{}\"\n\
         \x20           source (url)\"https://github.com/coreyleavitt/z3\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n",
        "b".repeat(64)
    );
    let idx = Index::parse(&text).unwrap();
    match &idx.packages[0].versions[0].provenances[0] {
        Provenance::Oci { source_url, .. } => {
            assert_eq!(source_url.as_deref(), Some("https://github.com/coreyleavitt/z3"))
        }
        other => panic!("expected oci, got {other:?}"),
    }
}

#[test]
fn oci_provenance_source_url_parsed_plain_string() {
    // `source` also accepts a plain (non-annotated) string, per the milpa
    // url convention's back-compat acceptance. Mirrors Python's
    // `test_oci_provenance_source_url_parsed_plain_string`.
    let text = format!(
        "schema_version 1\n\
         package \"z3\" {{\n\
         \x20   namespace \"coreyleavitt\"\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"oci\"\n\
         \x20           registry \"ghcr.io\"\n\
         \x20           repository \"coreyleavitt/z3\"\n\
         \x20           digest \"sha256:{}\"\n\
         \x20           source \"https://github.com/coreyleavitt/z3\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n",
        "b".repeat(64)
    );
    let idx = Index::parse(&text).unwrap();
    match &idx.packages[0].versions[0].provenances[0] {
        Provenance::Oci { source_url, .. } => {
            assert_eq!(source_url.as_deref(), Some("https://github.com/coreyleavitt/z3"))
        }
        other => panic!("expected oci, got {other:?}"),
    }
}

// --- TNG-UNSAFE-CONTROL-CHAR (CR2 — canonical-digest delimiter injection) ---
//
// index.kdl is attacker-controlled network input. KDL 2.0's `\u{XXXX}`
// escape syntax delivers a literal ASCII control character through an
// otherwise well-formed string literal. TAB and LF are exactly the
// delimiters registry-protocol §3.5.3's canonical violation digest uses;
// `\x1f`/`\x1e` are the non-scalar-rendering delimiters. Left unvalidated, a
// crafted namespace/version/provenance/rekor field lets two semantically
// different violation sets serialize to identical digest bytes, defeating
// the warn-mode habituation defense. Mirrors Python's test_registry.py
// TestValidators control-char suite — same fields, same slug.

#[test]
fn namespace_control_char_via_kdl_escape_is_rejected() {
    let text = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   namespace \"evil\\u{{9}}namespace\"\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://e/bar.git\"\n\
         \x20           ref \"v1\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    );
    assert_eq!(
        Index::parse(&text).unwrap_err().code(),
        "TNG-UNSAFE-CONTROL-CHAR"
    );
}

#[test]
fn version_string_control_char_via_kdl_escape_is_rejected() {
    // `\u{1f}` — ASCII unit separator, the provenance-record encoding
    // delimiter (§3.5.3).
    let text = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\\u{{1f}}evil\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://e/bar.git\"\n\
         \x20           ref \"v1\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    );
    assert_eq!(
        Index::parse(&text).unwrap_err().code(),
        "TNG-UNSAFE-CONTROL-CHAR"
    );
}

#[test]
fn git_url_and_ref_control_char_via_kdl_escape_are_rejected() {
    assert_eq!(
        Index::parse(&git_index("https://e/foo\\u{a}.git", "v1", None))
            .unwrap_err()
            .code(),
        "TNG-UNSAFE-CONTROL-CHAR"
    );
    assert_eq!(
        Index::parse(&git_index("https://e/bar.git", "ma\\u{9}in", None))
            .unwrap_err()
            .code(),
        "TNG-UNSAFE-CONTROL-CHAR"
    );
}

#[test]
fn oci_registry_and_repository_control_char_via_kdl_escape_are_rejected() {
    let registry_text = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"oci\"\n\
         \x20           registry \"ghcr\\u{{9}}.io\"\n\
         \x20           repository \"e/bar\"\n\
         \x20           digest \"{ID1}\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    );
    assert_eq!(
        Index::parse(&registry_text).unwrap_err().code(),
        "TNG-UNSAFE-CONTROL-CHAR"
    );

    let repository_text = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"oci\"\n\
         \x20           registry \"ghcr.io\"\n\
         \x20           repository \"e\\u{{9}}/bar\"\n\
         \x20           digest \"{ID1}\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    );
    assert_eq!(
        Index::parse(&repository_text).unwrap_err().code(),
        "TNG-UNSAFE-CONTROL-CHAR"
    );
}

#[test]
fn oci_provenance_source_control_char_via_kdl_escape_is_rejected() {
    // The optional oci provenance `source` field gets the same control-
    // character rejection as every other registry free-text field
    // (registry-protocol §3.3 NORMATIVE — control-character rejection).
    // Mirrors Python's `test_control_char_in_oci_source_via_kdl_escape`.
    let text = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"oci\"\n\
         \x20           registry \"ghcr.io\"\n\
         \x20           repository \"e/bar\"\n\
         \x20           digest \"{ID1}\"\n\
         \x20           source \"https://example.com/foo\\u{{9}}.git\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    );
    assert_eq!(
        Index::parse(&text).unwrap_err().code(),
        "TNG-UNSAFE-CONTROL-CHAR"
    );
}

#[test]
fn rekor_fields_control_char_via_kdl_escape_are_rejected() {
    // TAB is the canonical violation digest's field-join delimiter
    // (§3.5.3) — an unvalidated rekor field could shift the digest's
    // 7-tuple boundaries.
    fn rekor_index(uuid: &str, log_index: &str, integrated_time: &str) -> String {
        format!(
            "schema_version 1\n\
             package \"bar\" {{\n\
             \x20   version \"1.0.0\" {{\n\
             \x20       content_hash \"{ID1}\"\n\
             \x20       provenance {{\n\
             \x20           kind \"git\"\n\
             \x20           url \"https://e/bar.git\"\n\
             \x20           ref \"v1\"\n\
             \x20       }}\n\
             \x20       attestation \"milpa-vendored\"\n\
             \x20       rekor {{\n\
             \x20           uuid \"{uuid}\"\n\
             \x20           log_index \"{log_index}\"\n\
             \x20           integrated_time \"{integrated_time}\"\n\
             \x20       }}\n\
             \x20   }}\n\
             }}\n"
        )
    }

    assert_eq!(
        Index::parse(&rekor_index("abc\\u{9}def", "1", "2"))
            .unwrap_err()
            .code(),
        "TNG-UNSAFE-CONTROL-CHAR"
    );
    assert_eq!(
        Index::parse(&rekor_index("abc", "1\\u{9}", "2"))
            .unwrap_err()
            .code(),
        "TNG-UNSAFE-CONTROL-CHAR"
    );
    assert_eq!(
        Index::parse(&rekor_index("abc", "1", "2\\u{9}"))
            .unwrap_err()
            .code(),
        "TNG-UNSAFE-CONTROL-CHAR"
    );
}

#[test]
fn attestation_signed_by_control_char_via_kdl_escape_is_rejected() {
    // `signed_by` is rendered raw into the attestation canonical digest
    // (`attestation_canonical_raw`, §3.5.3) — the same injection exposure
    // CR2 closed for `rekor`'s fields (registry-protocol §3.3).
    let text = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://e/bar.git\"\n\
         \x20           ref \"v1\"\n\
         \x20       }}\n\
         \x20       attestation \"author-signed\"\n\
         \x20       signed_by \"alice\\u{{9}}evil\"\n\
         \x20   }}\n\
         }}\n"
    );
    assert_eq!(Index::parse(&text).unwrap_err().code(), "TNG-UNSAFE-CONTROL-CHAR");
}

// fixture-411-tng-unsafe-control-char is exercised end-to-end (both impls,
// differentially) by the generic conformance corpus runner
// (milpa-conformance/tests/corpus.rs `discover()` + this crate's Python
// counterpart tests/test_conformance.py) — no hand-rolled fixture-reading
// unit test needed here; the targeted-field coverage above is direct-call.

// CR15: the original CR2 field enumeration was hand-built and missed fields
// that provably reach the same digest / diagnostic output — `content_hash`
// (a SetOnce ratchet field the §3.5.3 digest renders directly), `name` (the
// 3rd element of EVERY digest 7-tuple; only `is_safe_name`'s path-traversal
// blacklist ran on it, which does NOT reject control chars), and
// `yanked_reason` (unvalidated free text rendered raw into the
// TNG-NO-SATISFYING-VERSION message and the yank-transition stderr notice).
// fixture-412/413 (content_hash / name) are exercised end-to-end by the
// generic conformance corpus runner; the targeted-field coverage below is
// direct-call, mirroring Python's test_registry.py CR15 suite.

#[test]
fn content_hash_control_char_via_kdl_escape_is_rejected() {
    let text = "schema_version 1\n\
         package \"bar\" {\n\
         \x20   version \"1.0.0\" {\n\
         \x20       content_hash \"sha256:tainted\\u{9}\\u{a}injected\"\n\
         \x20       provenance {\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://e/bar.git\"\n\
         \x20           ref \"v1\"\n\
         \x20       }\n\
         \x20   }\n\
         }\n";
    assert_eq!(
        Index::parse(text).unwrap_err().code(),
        "TNG-UNSAFE-CONTROL-CHAR"
    );
}

#[test]
fn package_name_control_char_via_kdl_escape_is_rejected() {
    let text = format!(
        "schema_version 1\n\
         package \"pkg\\u{{9}}name\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://e/bar.git\"\n\
         \x20           ref \"v1\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    );
    assert_eq!(
        Index::parse(&text).unwrap_err().code(),
        "TNG-UNSAFE-CONTROL-CHAR"
    );
}

#[test]
fn package_name_path_traversal_still_rejected_alongside_control_char_guard() {
    // Regression guard: adding the control-char check to `name` MUST NOT
    // displace the pre-existing path-traversal (`TNG-UNSAFE-NAME`) check —
    // a `..`-name with no control chars still raises `TNG-UNSAFE-NAME`, not
    // `TNG-UNSAFE-CONTROL-CHAR`.
    let text = format!(
        "schema_version 1\n\
         package \"../evil\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://e/bar.git\"\n\
         \x20           ref \"v1\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    );
    assert_eq!(Index::parse(&text).unwrap_err().code(), "TNG-UNSAFE-NAME");
}

#[test]
fn yanked_reason_control_char_via_kdl_escape_is_rejected() {
    let text = format!(
        "schema_version 1\n\
         package \"bar\" {{\n\
         \x20   version \"1.0.0\" {{\n\
         \x20       content_hash \"{ID1}\"\n\
         \x20       provenance {{\n\
         \x20           kind \"git\"\n\
         \x20           url \"https://e/bar.git\"\n\
         \x20           ref \"v1\"\n\
         \x20       }}\n\
         \x20       yanked #true\n\
         \x20       yanked_reason \"evil\\u{{9}}injected\"\n\
         \x20   }}\n\
         }}\n"
    );
    assert_eq!(
        Index::parse(&text).unwrap_err().code(),
        "TNG-UNSAFE-CONTROL-CHAR"
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
        ], ..Default::default()
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
        packages: vec![pkg("bar", "", vec![ver("1.0.0", ID1, vec![git()])])], ..Default::default()
    };
    let err = idx
        .resolve_named_all("bar", &gte(">= 2.0.0"), Some(">= 2.0.0"))
        .unwrap_err();
    assert_eq!(err.code(), "TNG-NO-SATISFYING-VERSION");
}

#[test]
fn resolve_all_provenance_less_is_no_provenance() {
    let idx = Index {
        packages: vec![pkg("bar", "", vec![ver("1.0.0", ID1, vec![])])], ..Default::default()
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
        )], ..Default::default()
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
        )], ..Default::default()
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
        )], ..Default::default()
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
        )], ..Default::default()
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
        packages: vec![pkg("bar", "", vec![ver("1.0.0", ID1, vec![git()])])], ..Default::default()
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
        )], ..Default::default()
    };
    let err = idx
        .resolve_named_all("bar", &gte("== 2.0.0"), Some("== 2.0.0"))
        .unwrap_err();
    assert_eq!(err.code(), "TNG-NO-SATISFYING-VERSION");
}

#[test]
fn bare_yanked_excluded_diagnostic_scoped_to_satisfying_versions() {
    // CR13/5: the "(excluded as yanked: …)" diagnostic must list only
    // yanked versions that WOULD have satisfied the constraint if not
    // yanked — a yanked 1.0.0 must not be listed for a ^2.0.0 failure,
    // even though selection still excludes it (unconditionally, before
    // matching). Mirrors
    // impls/python/tests/test_registry.py::test_bare_yanked_excluded_diagnostic_scoped_to_satisfying_versions.
    let idx = Index {
        packages: vec![pkg(
            "bar",
            "",
            vec![
                yanked_ver("2.5.0", ID1, vec![git()], Some("ships a vulnerable bearssl pin")),
                yanked_ver("1.0.0", ID1, vec![git()], None),
            ],
        )], ..Default::default()
    };
    let err = idx
        .resolve_named_all("bar", &gte("^2.0.0"), Some("^2.0.0"))
        .unwrap_err();
    assert_eq!(err.code(), "TNG-NO-SATISFYING-VERSION");
    let message = err.message();
    let yanked_segment = message.split_once("(excluded as yanked:").unwrap().1;
    assert!(yanked_segment.contains("2.5.0"));
    assert!(!yanked_segment.contains("1.0.0"));
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
        )], ..Default::default()
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
        )], ..Default::default()
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
        )], ..Default::default()
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

#[test]
fn test_lone_malformed_bundle_sibling_with_no_attestation_node_is_silent() {
    // CR13/6: a malformed `bundle sha256=` sibling with NO `attestation` node
    // at all must produce NO diagnostic — no EntryAttestation is ever
    // constructed in this shape, so the "bundle pin ... dropped" diagnostic
    // is spurious noise (registry-protocol §3.2). Mirrors
    // impls/python/tests/test_registry.py::test_lone_malformed_bundle_sibling_with_no_attestation_node_is_silent.
    let doc = one_version_node("        bundle sha256=\"not-valid-hex\"\n");
    let node = version_child(&doc);
    let (iv, diagnostics) = parse_version_node("", "foo", "1.0.0", &node).unwrap();
    assert!(iv.attestation.is_none());
    assert!(diagnostics.is_empty(), "diagnostics: {diagnostics:?}");
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

// Pure ISO-8601 timestamp parser unit tests (`iso8601_*`) moved to
// `milpa-types` alongside `Timestamp`/`parse_iso8601_timestamp` themselves
// (D0, rfc-resolution-semantics.md Axis D prerequisite) — they exercise the
// parser directly, not `registry.rs`'s own IndexVersion-parsing logic. The
// `a2a_*` tests above stay here: they exercise registry.rs's parse-to-typed
// wiring (`IndexVersion.published_at`/`yanked_at`), merely using the
// (re-exported) parser to construct the expected value.

// ---------------------------------------------------------------------------
// D3 (resolution-semantics RFC §3 Axis D / §4 stage 2): the exclude-newer
// hard cut at the enumeration layer — pure-function unit tests, isolated
// from index parsing / the resolver / the solver (mirrors
// impls/python/tests/test_registry.py::TestFilterByExcludeNewer).
// ---------------------------------------------------------------------------

fn ver_at(v: &str, published_at: Option<Timestamp>) -> IndexVersion {
    IndexVersion {
        published_at,
        ..ver(v, "sha256:x", vec![git()])
    }
}

#[test]
fn d3_no_bound_is_a_no_op() {
    let versions = vec![
        ver_at("1.0.0", None),
        ver_at("2.0.0", parse_iso8601_timestamp("2026-01-01T00:00:00Z")),
    ];
    let (kept, dropped) = filter_by_exclude_newer(&versions, None);
    assert_eq!(kept, versions);
    assert_eq!(dropped, 0);
}

#[test]
fn d3_keeps_versions_at_or_before_the_bound() {
    let ts = parse_iso8601_timestamp("2026-06-01T00:00:00Z").unwrap();
    let older = ver_at("1.0.0", parse_iso8601_timestamp("2026-01-01T00:00:00Z"));
    let exact = ver_at("1.5.0", Some(ts));
    let newer = ver_at("2.0.0", parse_iso8601_timestamp("2026-12-01T00:00:00Z"));
    let (kept, dropped) =
        filter_by_exclude_newer(&[older.clone(), exact.clone(), newer], Some(ts));
    assert_eq!(kept, vec![older, exact]);
    assert_eq!(dropped, 1);
}

#[test]
fn d3_fail_closed_excludes_unprovable_published_at() {
    let ts = parse_iso8601_timestamp("2026-06-01T00:00:00Z").unwrap();
    let unprovable = ver_at("1.0.0", None);
    let (kept, dropped) = filter_by_exclude_newer(&[unprovable], Some(ts));
    assert!(kept.is_empty());
    assert_eq!(dropped, 1);
}

#[test]
fn d3_empties_the_set_reports_full_dropped_count() {
    let ts = parse_iso8601_timestamp("2020-01-01T00:00:00Z").unwrap();
    let versions = vec![
        ver_at("1.0.0", parse_iso8601_timestamp("2026-01-01T00:00:00Z")),
        ver_at("2.0.0", None),
    ];
    let (kept, dropped) = filter_by_exclude_newer(&versions, Some(ts));
    assert!(kept.is_empty());
    assert_eq!(dropped, 2);
}
