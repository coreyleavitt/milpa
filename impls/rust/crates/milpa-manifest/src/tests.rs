//! S3 unit tests: the manifest grammar, ported from the reference parser's
//! behavior (`milpa/manifest.py`) and the conformance fixtures
//! (`conformance/spec-v1/fixture-0NN-man-*`). The conformance corpus is
//! the language-agnostic SSOT; these add fast in-crate coverage and pin the
//! success-shape of the parsed model.

use super::*;

/// Assert that parsing `text` as a document fails with exactly `code`.
fn doc_err(text: &str) -> &'static str {
    parse_document(text)
        .expect_err("expected a ManifestError")
        .code
}

fn pkg(text: &str) -> Manifest {
    match parse_document(text).expect("expected a package manifest") {
        ManifestDoc::Package(m) => m,
        ManifestDoc::Workspace(_) => panic!("expected package, got workspace"),
    }
}

fn ws(text: &str) -> Workspace {
    match parse_document(text).expect("expected a workspace") {
        ManifestDoc::Workspace(w) => w,
        ManifestDoc::Package(_) => panic!("expected workspace, got package"),
    }
}

// --------------------------------------------------------------- error codes

#[test]
fn error_codes_match_fixtures() {
    // (input, expected MAN-* code) — one row per fixture-0NN-man-* this slice
    // greens. Mirrors conformance/spec-v1.
    let cases: &[(&str, &str)] = &[
        ("name \"x\" {\n", "MAN-KDL-SYNTAX"),
        ("kind \"library\"\n", "MAN-NAME-MISSING"),
        ("name \"a\"\nname \"b\"\nkind \"library\"\n", "MAN-NAME-DUPLICATE"),
        ("name 42\nkind \"library\"\n", "MAN-NAME-TYPE"),
        ("name \"x\"\nsrc_dir 42\n", "MAN-SRC-DIR-TYPE"),
        ("name \"x\"\ncas {\n  notdir \"y\"\n}\n", "MAN-CAS-DIR-MISSING"),
        ("name \"x\"\ncas {\n  dir 42\n}\n", "MAN-CAS-DIR-TYPE"),
        ("name \"x\"\nbogus \"y\"\nkind \"library\"\n", "MAN-UNKNOWN-TOP-LEVEL"),
        ("name \"x\"\nkind \"library\" \"extra\"\n", "MAN-KIND-ARITY"),
        ("name \"x\"\nkind \"frobnicate\"\n", "MAN-KIND-INVALID"),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\"\n  foo git=(url)\"https://a/f.git\" ref=\"m\"\n}\n",
            "MAN-DEP-DUPLICATE",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" bogus=\"y\"\n}\n",
            "MAN-DEP-UNKNOWN-PROPS",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\"\n}\n",
            "MAN-DEP-REF-MISSING",
        ),
        ("name \"x\"\ndeps {\n  foo local=\"\"\n}\n", "MAN-DEP-LOCAL-PATH"),
        ("name \"x\"\ndeps {\n  foo tarball=\"\"\n}\n", "MAN-URL-ARG-TYPE"),
        (
            "name \"x\"\ndeps {\n  foo tarball=(url)\"https://x/t.tgz\" sha256=42\n}\n",
            "MAN-DEP-TARBALL-SHA",
        ),
        (
            "name \"x\"\ndeps {\n  foo tarball=(url)\"https://x/t.tgz\" strip_components=-1\n}\n",
            "MAN-DEP-TARBALL-STRIP",
        ),
        (
            "name \"x\"\ndeps {\n  member \"a\" extra=\"y\"\n}\n",
            "MAN-DEP-MEMBER-PROPS",
        ),
        ("name \"x\"\ndeps {\n  member \"a\" \"b\"\n}\n", "MAN-DEP-MEMBER-ARITY"),
        (
            "name \"x\"\ndeps {\n  foo bar=\"y\"\n}\n",
            "MAN-DEP-NAMED-PROPS",
        ),
        ("name \"x\"\ndeps {\n  foo 42\n}\n", "MAN-DEP-NAMED-CONSTRAINT"),
        ("name \"x\"\ndeps {\n  foo \"a\" \"b\"\n}\n", "MAN-DEP-NAMED-ARITY"),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" {\n    mirror\n  }\n}\n",
            "MAN-DEP-MIRROR-ARITY",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" {\n    flag\n  }\n}\n",
            "MAN-DEP-FLAG-NAME-MISSING",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" {\n    flag \"a\" #true #false\n  }\n}\n",
            "MAN-DEP-FLAG-TOO-MANY-ARGS",
        ),
        (
            "name \"x\"\nflags {\n  a\n}\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" {\n    flag \"a\" \"nope\"\n  }\n}\n",
            "MAN-DEP-FLAG-BOOL",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" {\n    bogus \"y\"\n  }\n}\n",
            "MAN-DEP-UNKNOWN-CHILD",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=\"no-scheme\" ref=\"m\"\n}\n",
            "MAN-URL-ARG-TYPE",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=\"ftp://a/f.git\" ref=\"m\"\n}\n",
            "MAN-URL-ARG-TYPE",
        ),
        (
            "name \"x\"\noverrides {\n  notpkg \"a\"\n}\n",
            "MAN-OVERRIDE-KIND",
        ),
        ("name \"x\"\noverrides {\n  pkg\n}\n", "MAN-OVERRIDE-ARITY"),
        (
            "name \"x\"\noverrides {\n  pkg \"a\" git=(url)\"https://a/f.git\" ref=\"m\" bogus=\"y\"\n}\n",
            "MAN-OVERRIDE-UNKNOWN-PROPS",
        ),
        (
            "name \"x\"\noverrides {\n  pkg \"a\" ref=\"m\"\n}\n",
            // S8: `ref=` alone is zero-form → MAN-OVERRIDE-TARGET-AMBIGUOUS
            // (the old MAN-OVERRIDE-GIT-MISSING is superseded for the zero-form case)
            "MAN-OVERRIDE-TARGET-AMBIGUOUS",
        ),
        (
            "name \"x\"\noverrides {\n  pkg \"a\" git=(url)\"https://a/f.git\"\n}\n",
            "MAN-OVERRIDE-REF-MISSING",
        ),
        (
            "name \"x\"\noverrides {\n  pkg \"a\" git=(url)\"https://a/f.git\" ref=\"m\"\n  pkg \"a\" git=(url)\"https://a/f.git\" ref=\"m\"\n}\n",
            "MAN-OVERRIDE-DUPLICATE",
        ),
        (
            // D5 (Python↔Rust divergence fix): the SECOND `pkg "foo"` override
            // also carries a malformed `version=`. The duplicate-name check
            // must win over the version-validation error on the duplicate
            // entry — converges Rust's ordering onto Python's (which already
            // checks duplicate-name before parsing `version=`).
            "name \"x\"\noverrides {\n  pkg \"foo\" local=\"a\"\n  pkg \"foo\" local=\"b\" version=\"not-a-semver\"\n}\n",
            "MAN-OVERRIDE-DUPLICATE",
        ),
        (
            "name \"x\"\nflags {\n  a\n  a\n}\n",
            "MAN-FLAG-DUPLICATE",
        ),
        ("name \"x\"\nflags {\n  a \"pos\"\n}\n", "MAN-FLAG-POS-ARGS"),
        ("name \"x\"\nflags {\n  a bogus=#true\n}\n", "MAN-FLAG-UNKNOWN-PROPS"),
        ("name \"x\"\nflags {\n  a default=\"no\"\n}\n", "MAN-FLAG-DEFAULT-TYPE"),
        (
            "name \"x\"\nflags {\n  a description=42\n}\n",
            "MAN-FLAG-DESCRIPTION-TYPE",
        ),
        (
            "name \"x\"\nflags {\n  a {\n    bogus \"y\"\n  }\n}\n",
            "MAN-FLAG-UNKNOWN-CHILD",
        ),
        (
            "name \"x\"\nflags {\n  a {\n    defines 42\n  }\n}\n",
            "MAN-FLAG-DEFINES-ARG-TYPE",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" flag=\"undeclared\"\n}\n",
            "MAN-FLAG-UNDECLARED-REFERENCE",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" bogus_pred=\"y\"\n}\n",
            // bogus_pred is not in URL_DEP_PROPS → unknown prop, not a predicate.
            "MAN-DEP-UNKNOWN-PROPS",
        ),
        (
            "name \"x\"\ndeps {\n  when bogus=\"y\" {\n    foo git=(url)\"https://a/f.git\" ref=\"m\"\n  }\n}\n",
            "MAN-PREDICATE-UNKNOWN",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" platform=42\n}\n",
            "MAN-PREDICATE-VALUE-TYPE",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" platform=(weird)\"linux\"\n}\n",
            "MAN-PREDICATE-UNSUPPORTED-ANNOTATION",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" {\n    platform\n  }\n}\n",
            "MAN-PREDICATE-CHILD-NO-ARGS",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" {\n    platform 42\n  }\n}\n",
            "MAN-PREDICATE-CHILD-ARG-TYPE",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" {\n    platform \"linux\" (not)\"windows\"\n  }\n}\n",
            "MAN-PREDICATE-MIXED-NEGATION",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" platform=\"linux\" {\n    platform \"windows\"\n  }\n}\n",
            "MAN-PREDICATE-FORM-CONFLICT",
        ),
        ("name \"x\"\nmirrors {\n  bogus \"y\"\n}\n", "MAN-MIRRORS-UNKNOWN-CHILD"),
        ("name \"x\"\nmirrors {\n  mirror \"a\" \"b\"\n}\n", "MAN-MIRRORS-ARITY"),
        ("name \"x\"\nmirrors {\n  mirror 42\n}\n", "MAN-URL-ARG-TYPE"),
        ("name \"x\"\nspec-version \"one\"\n", "MAN-SPEC-VERSION-TYPE"),
        ("name \"x\"\nspec-version 99\n", "MAN-SPEC-VERSION-UNSUPPORTED"),
        // A1 (rfc-resolution-semantics.md §3 Axis A / §5): top-level package
        // `version` — malformed value is a hard error (milpa.kdl is milpa's
        // own strict manifest format, unlike the `.nimble` compat adapter).
        ("name \"x\"\nversion \"not-a-version\"\n", "MAN-PACKAGE-VERSION-INVALID"),
        ("name \"x\"\nversion \"1.2\"\n", "MAN-PACKAGE-VERSION-INVALID"),
        ("name \"x\"\nversion 123\n", "MAN-PACKAGE-VERSION-INVALID"),
        // A3b (rfc-resolution-semantics.md §3 Axis A (b) step 4): dep-level
        // `version=` annotation — same strict-format rationale as the
        // top-level `version` field, on git/local/tarball deps and on
        // `overrides { pkg … version= }` rules.
        (
            "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" version=\"nope\"\n}\n",
            "MAN-DEP-VERSION-INVALID",
        ),
        (
            "name \"x\"\ndeps {\n  foo local=\"../f\" version=\"nope\"\n}\n",
            "MAN-DEP-VERSION-INVALID",
        ),
        (
            "name \"x\"\ndeps {\n  foo tarball=(url)\"https://a/f.tar.gz\" version=\"nope\"\n}\n",
            "MAN-DEP-VERSION-INVALID",
        ),
        (
            "name \"x\"\noverrides {\n  pkg \"foo\" git=(url)\"https://a/f.git\" ref=\"m\" version=\"nope\"\n}\n",
            "MAN-DEP-VERSION-INVALID",
        ),
        // C3 (rfc-resolution-semantics.md §3 Axis C / §5): resolution {
        // strategy } block — unknown/duplicate child vs. malformed value.
        (
            "name \"x\"\nresolution {\n  bogus \"y\"\n}\n",
            "MAN-RESOLUTION-BLOCK-INVALID",
        ),
        (
            "name \"x\"\nresolution {\n  strategy \"maxver\"\n  strategy \"minver\"\n}\n",
            "MAN-RESOLUTION-BLOCK-INVALID",
        ),
        (
            "name \"x\"\nresolution {\n  strategy\n}\n",
            "MAN-RESOLUTION-STRATEGY-INVALID",
        ),
        (
            "name \"x\"\nresolution {\n  strategy \"bogus\"\n}\n",
            "MAN-RESOLUTION-STRATEGY-INVALID",
        ),
        // D1 (rfc-resolution-semantics.md §3 Axis D): resolution {
        // exclude-newer } — unknown/duplicate child vs. malformed value.
        (
            "name \"x\"\nresolution {\n  exclude-newer\n}\n",
            "MAN-RESOLUTION-EXCLUDE-NEWER-INVALID",
        ),
        (
            "name \"x\"\nresolution {\n  exclude-newer \"not-a-timestamp\"\n}\n",
            "MAN-RESOLUTION-EXCLUDE-NEWER-INVALID",
        ),
        (
            "name \"x\"\nresolution {\n  exclude-newer \"2026-01-01T00:00:00Z\"\n  exclude-newer \"2026-02-01T00:00:00Z\"\n}\n",
            "MAN-RESOLUTION-BLOCK-INVALID",
        ),
        // Workspace role.
        (
            "workspace {\n  member \"a\"\n}\nkind \"library\"\n",
            "MAN-WORKSPACE-HAS-DEPS-OR-KIND",
        ),
        ("workspace {\n  bogus \"y\"\n}\n", "MAN-WORKSPACE-UNKNOWN-NODE"),
        ("workspace {\n  member \"a\" \"b\"\n}\n", "MAN-WORKSPACE-MEMBER-ARITY"),
        (
            "workspace {\n  member \"a\"\n  member \"a\"\n}\n",
            "MAN-WORKSPACE-MEMBER-DUPLICATE",
        ),
        (
            "workspace {\n  member \"a\"\n}\nbogus \"y\"\n",
            "MAN-WORKSPACE-UNKNOWN-TOP-LEVEL",
        ),
    ];
    for (input, want) in cases {
        let got = doc_err(input);
        assert_eq!(got, *want, "input:\n{input}\nwanted {want}, got {got}");
    }
}

#[test]
fn workspace_in_package_only_path() {
    // parse_manifest (package-only) rejects a workspace block; parse_document
    // would instead route it to the workspace path (different code).
    let e = parse_manifest("workspace {\n  member \"a\"\n}\n").unwrap_err();
    assert_eq!(e.code, "MAN-WORKSPACE-IN-PACKAGE");
}

// ------------------------------------------------------------- success shapes

#[test]
fn single_url_dep() {
    let m = pkg(
        "name \"myapp\"\nkind \"application\"\ndeps {\n  foo git=(url)\"https://github.com/example/foo.git\" ref=\"main\"\n}\n",
    );
    assert_eq!(m.name.as_deref(), Some("myapp"));
    assert_eq!(m.kind, "application");
    assert_eq!(m.deps.len(), 1);
    match &m.deps[0] {
        Dep::Url(u) => {
            assert_eq!(u.name, "foo");
            assert_eq!(u.git, "https://github.com/example/foo.git");
            assert_eq!(u.git_ref, "main");
        }
        other => panic!("expected UrlDep, got {other:?}"),
    }
}

#[test]
fn named_dep_with_constraint() {
    let m = pkg("name \"a\"\ndeps {\n  bar \">= 2.0.0\"\n}\n");
    match &m.deps[0] {
        Dep::Named(n) => {
            assert_eq!(n.name, "bar");
            assert_eq!(n.constraint.as_deref(), Some(">= 2.0.0"));
            // Parse-boundary: parsed_constraint is pre-populated and valid.
            assert!(
                n.parsed_constraint.is_some(),
                "NamedDep with a constraint string must carry a pre-parsed VersionSet"
            );
        }
        other => panic!("expected NamedDep, got {other:?}"),
    }
}

/// A malformed version-constraint string in a milpa.kdl NamedDep must be
/// rejected at the manifest-parse boundary with MAN-DEP-NAMED-CONSTRAINT
/// (not at resolve time with MAN-NIMBLE-CONSTRAINT).
#[test]
fn named_dep_malformed_constraint_raises_at_parse_boundary() {
    // "@@@bad" is not a valid version constraint (no leading operator, no version)
    let code = doc_err("name \"a\"\ndeps {\n  z \"@@@bad\"\n}\n");
    assert_eq!(
        code, "MAN-DEP-NAMED-CONSTRAINT",
        "malformed named-dep constraint must yield MAN-DEP-NAMED-CONSTRAINT at parse time"
    );
}

/// A named dep with no constraint parses successfully; parsed_constraint is None.
#[test]
fn named_dep_without_constraint_has_no_parsed_constraint() {
    let m = pkg("name \"a\"\ndeps {\n  results\n}\n");
    match &m.deps[0] {
        Dep::Named(n) => {
            assert_eq!(n.name, "results");
            assert!(n.constraint.is_none());
            assert!(
                n.parsed_constraint.is_none(),
                "NamedDep with no constraint string must have no parsed_constraint"
            );
        }
        other => panic!("expected NamedDep, got {other:?}"),
    }
}

#[test]
fn kind_defaults_to_library() {
    let m = pkg("name \"a\"\n");
    assert_eq!(m.kind, "library");
    assert!(m.deps.is_empty());
}

#[test]
fn local_member_tarball_deps() {
    let m = pkg(
        "name \"a\"\ndeps {\n  loc local=\"../loc\"\n  member \"mem\"\n  tb tarball=(url)\"https://x/t.tgz\" sha256=\"abc\" strip_components=1\n}\n",
    );
    assert!(matches!(&m.deps[0], Dep::Local(l) if l.path == "../loc"));
    assert!(matches!(&m.deps[1], Dep::Member(mm) if mm.name == "mem"));
    match &m.deps[2] {
        Dep::Tarball(t) => {
            assert_eq!(t.url, "https://x/t.tgz");
            assert_eq!(t.sha256.as_deref(), Some("abc"));
            assert_eq!(t.strip_components, 1);
        }
        other => panic!("expected TarballDep, got {other:?}"),
    }
}

#[test]
fn when_block_distributes_and_merges_predicates() {
    // `when` predicate (platform) AND the dep's own child predicate (arch).
    // Inherited (`when`) predicates come first, then the dep's own (the dep's
    // own set is internally sorted by `merge_predicates`); the two are
    // concatenated, not re-sorted — mirroring the reference `inherited + own`.
    let m = pkg(
        "name \"a\"\ndeps {\n  when platform=\"linux\" {\n    foo git=(url)\"https://a/f.git\" ref=\"m\" {\n      arch \"amd64\" \"arm64\"\n    }\n  }\n}\n",
    );
    let Dep::Url(u) = &m.deps[0] else {
        panic!("expected UrlDep")
    };
    assert_eq!(u.predicates.len(), 2);
    assert_eq!(u.predicates[0].name, "platform");
    assert_eq!(u.predicates[0].values, vec!["linux"]);
    assert_eq!(u.predicates[1].name, "arch");
    assert_eq!(u.predicates[1].values, vec!["amd64", "arm64"]);
}

#[test]
fn negated_inline_predicate() {
    let m = pkg(
        "name \"a\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" platform=(not)\"windows\"\n}\n",
    );
    let Dep::Url(u) = &m.deps[0] else {
        panic!("expected UrlDep")
    };
    assert!(u.predicates[0].negated);
    assert_eq!(u.predicates[0].values, vec!["windows"]);
}

#[test]
fn spec_version_present_and_default() {
    let explicit = pkg("name \"a\"\nspec-version 1\n");
    assert_eq!(explicit.spec_version, 1);
    assert!(explicit.spec_version_explicit);

    let absent = pkg("name \"a\"\n");
    assert_eq!(absent.spec_version, 1);
    assert!(!absent.spec_version_explicit);
}

/// A1 (rfc-resolution-semantics.md §3 Axis A (b) step 1): the top-level
/// package `version` field — sibling of `spec-version` (schema epoch),
/// distinct concept (the package's own declared release version).
#[test]
fn package_version_present_and_absent() {
    let m = pkg("name \"x\"\nversion \"1.2.3\"\n");
    assert_eq!(m.version, Some(milpa_types::Version::release(1, 2, 3)));

    let absent = pkg("name \"x\"\n");
    assert!(absent.version.is_none());
}

/// C3 (rfc-resolution-semantics.md §3 Axis C / §5): the manifest
/// `resolution { strategy }` block — present iff declared, extensible
/// (only `strategy` recognized today; Axis D adds `exclude-newer` later).
#[test]
fn resolution_block_present_and_absent() {
    let m = pkg("name \"x\"\nresolution {\n  strategy \"lowest-direct\"\n}\n");
    assert_eq!(
        m.resolution.and_then(|r| r.strategy),
        Some(milpa_solver::Strategy::LowestDirect)
    );

    let absent = pkg("name \"x\"\n");
    assert!(absent.resolution.is_none());

    // A declared-but-empty block is a distinct Some(Resolution{strategy:None})
    // from a genuinely absent node — both behave identically at the
    // effective-strategy precedence point, but the parse itself must not
    // collapse "empty block" into "absent block".
    let empty = pkg("name \"x\"\nresolution {\n}\n");
    assert_eq!(
        empty.resolution,
        Some(Resolution {
            strategy: None,
            exclude_newer: None,
        })
    );
}

/// C3 (Axis W): a workspace root may declare `resolution { strategy }` too
/// (root-only — one shared lock, one resolution policy).
#[test]
fn workspace_resolution_block_present_and_absent() {
    let w = ws("workspace {\n  member \"a\"\n}\nresolution {\n  strategy \"semver\"\n}\n");
    assert_eq!(
        w.resolution.and_then(|r| r.strategy),
        Some(milpa_solver::Strategy::Semver)
    );

    let absent = ws("workspace {\n  member \"a\"\n}\n");
    assert!(absent.resolution.is_none());
}

/// D1 (rfc-resolution-semantics.md §3 Axis D): the manifest
/// `resolution { exclude-newer }` block — present iff declared, and
/// composes cleanly with C3's `strategy` sibling.
#[test]
fn resolution_exclude_newer_present_and_absent() {
    let m = pkg("name \"x\"\nresolution {\n  exclude-newer \"2026-01-01T00:00:00Z\"\n}\n");
    assert_eq!(
        m.resolution.and_then(|r| r.exclude_newer),
        milpa_types::parse_iso8601_timestamp("2026-01-01T00:00:00Z")
    );

    let absent = pkg("name \"x\"\n");
    assert!(absent.resolution.is_none());
}

/// D1: a `resolution { }` block declaring BOTH `strategy` and
/// `exclude-newer` parses both fields together (they are independent
/// siblings, not a mutually-exclusive choice).
#[test]
fn resolution_strategy_and_exclude_newer_both_parse() {
    let m = pkg(
        "name \"x\"\nresolution {\n  strategy \"minver\"\n  exclude-newer \"2026-01-01T00:00:00Z\"\n}\n",
    );
    let r = m.resolution.unwrap();
    assert_eq!(r.strategy, Some(milpa_solver::Strategy::Minver));
    assert_eq!(
        r.exclude_newer,
        milpa_types::parse_iso8601_timestamp("2026-01-01T00:00:00Z")
    );
}

/// D1: an unknown child still raises `MAN-RESOLUTION-BLOCK-INVALID` even
/// when both recognized children (`strategy`, `exclude-newer`) are also
/// present in the same block.
#[test]
fn resolution_unknown_child_still_invalid_with_known_children_present() {
    let code = doc_err(
        "name \"x\"\nresolution {\n  strategy \"minver\"\n  exclude-newer \"2026-01-01T00:00:00Z\"\n  bogus \"y\"\n}\n",
    );
    assert_eq!(code, "MAN-RESOLUTION-BLOCK-INVALID");
}

/// D1 (Axis W): a workspace root may declare `resolution { exclude-newer }`
/// too (root-only — one shared lock, one resolution policy).
#[test]
fn workspace_resolution_exclude_newer_present_and_absent() {
    let w = ws("workspace {\n  member \"a\"\n}\nresolution {\n  exclude-newer \"2026-01-01T00:00:00Z\"\n}\n");
    assert_eq!(
        w.resolution.and_then(|r| r.exclude_newer),
        milpa_types::parse_iso8601_timestamp("2026-01-01T00:00:00Z")
    );
}

/// A3b (rfc-resolution-semantics.md §3 Axis A (b) step 4): the dep-level
/// `version=` annotation on git/local/tarball deps — present iff declared,
/// distinct from an override (which redirects the source, D-A3).
#[test]
fn dep_version_annotation_present_and_absent() {
    let with_version = pkg(
        "name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\" version=\"1.2.3\"\n}\n",
    );
    let Dep::Url(u) = &with_version.deps[0] else {
        panic!("expected UrlDep")
    };
    assert_eq!(u.version, Some(milpa_types::Version::release(1, 2, 3)));

    let without_version = pkg("name \"x\"\ndeps {\n  foo git=(url)\"https://a/f.git\" ref=\"m\"\n}\n");
    let Dep::Url(u2) = &without_version.deps[0] else {
        panic!("expected UrlDep")
    };
    assert!(u2.version.is_none());
}

#[test]
fn local_dep_version_annotation() {
    let m = pkg("name \"x\"\ndeps {\n  foo local=\"../foo\" version=\"0.3.0\"\n}\n");
    let Dep::Local(l) = &m.deps[0] else {
        panic!("expected LocalDep")
    };
    assert_eq!(l.version, Some(milpa_types::Version::release(0, 3, 0)));
}

#[test]
fn tarball_dep_version_annotation() {
    let m = pkg(
        "name \"x\"\ndeps {\n  foo tarball=(url)\"https://a/f.tar.gz\" version=\"2.0.0\"\n}\n",
    );
    let Dep::Tarball(t) = &m.deps[0] else {
        panic!("expected TarballDep")
    };
    assert_eq!(t.version, Some(milpa_types::Version::release(2, 0, 0)));
}

/// A3b/D-A3: `version=` on an override rule — orthogonal to `target` (label
/// vs redirect), valid regardless of which target form is selected.
#[test]
fn override_version_annotation_all_forms() {
    let git_form = pkg(
        "name \"x\"\noverrides {\n  pkg \"foo\" git=(url)\"https://a/f.git\" ref=\"m\" version=\"1.0.0\"\n}\n",
    );
    assert_eq!(
        git_form.overrides[0].version,
        Some(milpa_types::Version::release(1, 0, 0))
    );

    let local_form = pkg(
        "name \"x\"\noverrides {\n  pkg \"foo\" local=\"../foo\" version=\"2.1.0\"\n}\n",
    );
    assert_eq!(
        local_form.overrides[0].version,
        Some(milpa_types::Version::release(2, 1, 0))
    );

    let member_form = pkg(
        "name \"x\"\noverrides {\n  pkg \"foo\" version=\"0.9.0\" {\n    member \"foo\"\n  }\n}\n",
    );
    assert_eq!(
        member_form.overrides[0].version,
        Some(milpa_types::Version::release(0, 9, 0))
    );

    let absent = pkg(
        "name \"x\"\noverrides {\n  pkg \"foo\" git=(url)\"https://a/f.git\" ref=\"m\"\n}\n",
    );
    assert!(absent.overrides[0].version.is_none());
}

#[test]
fn cas_and_mirrors_and_overrides() {
    let m = pkg(
        "name \"a\"\ncas {\n  dir \".store\"\n}\nmirrors {\n  mirror (url)\"https://m/a.git\"\n}\noverrides {\n  pkg \"x\" git=(url)\"https://o/x.git\" ref=\"v1\"\n}\n",
    );
    assert_eq!(m.cas_dir, ".store");
    assert_eq!(m.self_mirrors, vec!["https://m/a.git"]);
    assert_eq!(m.overrides.len(), 1);
    assert_eq!(m.overrides[0].name, "x");
    match &m.overrides[0].target {
        crate::OverrideTarget::Git { git_ref, .. } => assert_eq!(git_ref, "v1"),
        other => panic!("expected GitTarget, got {:?}", other),
    }
}

#[test]
fn dev_deps_independent_namespace() {
    // Same name in deps and dev-deps is valid (independent namespaces, §3.3).
    let m = pkg("name \"a\"\ndeps {\n  foo\n}\ndev-deps {\n  foo\n}\n");
    assert_eq!(m.deps.len(), 1);
    assert_eq!(m.dev_deps.len(), 1);
}

#[test]
fn workspace_members_parse() {
    let w = ws("name \"root\"\nworkspace {\n  member \"a\"\n  member \"b\"\n}\n");
    assert_eq!(w.members, vec!["a", "b"]);
}

#[test]
fn flag_declaration_with_defines() {
    let m = pkg(
        "name \"a\"\nflags {\n  ssl default=#true description=\"use ssl\" {\n    defines \"a_ssl\" \"b_ssl\"\n  }\n}\n",
    );
    assert_eq!(m.flags.len(), 1);
    let f = &m.flags[0];
    assert_eq!(f.name, "ssl");
    assert!(f.default);
    assert_eq!(f.description, "use ssl");
    assert_eq!(f.defines, vec!["a_ssl", "b_ssl"]);
}

#[test]
fn all_codes_are_real_spec_slugs_and_nonempty() {
    // Guards against typos in MAN_CODES; the conformance parity test checks
    // the full subset against errors.md.
    assert!(!ManifestError::all_codes().is_empty());
    for c in ManifestError::all_codes() {
        assert!(c.starts_with("MAN-"), "unexpected non-MAN code {c}");
    }
}

// --------------------------------------------------------- KDL 2.0 (#123)

/// KDL 2.0 booleans use `#true`/`#false`. A manifest using `#true` for a
/// flag default must parse correctly — `KdlValue::Bool` still fires for the
/// v2 keyword form.
#[test]
fn kdl2_hash_true_flag_default_parses() {
    let m = pkg("name \"a\"\nflags {\n  ssl default=#true\n}\n");
    assert_eq!(m.flags.len(), 1);
    assert!(m.flags[0].default, "expected default=true from #true");
}

/// KDL 2.0: bare `true` (without `#`) is reserved and must be rejected as a
/// KDL syntax error — milpa surfaces it as MAN-KDL-SYNTAX.
#[test]
fn kdl2_bare_true_is_syntax_error() {
    assert_eq!(
        doc_err("name \"a\"\nflags {\n  ssl default=true\n}\n"),
        "MAN-KDL-SYNTAX",
        "bare `true` must be rejected by KDL 2.0 parser"
    );
}

/// Empirical #122/#123 check: KDL 2.0 behaviour for `¼` (U+00BC VULGAR FRACTION
/// ONE QUARTER) as a top-level node name.
///
/// kdl-rs 6.7.1 in v2 mode accepts `¼` as a valid identifier (KDL 2.0 allows
/// Unicode letters and numbers in identifiers, and U+00BC is category No =
/// Other_Number — which KDL 2.0 does allow in identifiers). The Rust impl
/// therefore surfaces it as MAN-UNKNOWN-TOP-LEVEL (the node name is not a
/// recognised milpa top-level keyword), which is the CONFORMANT result.
///
/// This confirms #123 resolves the #122 divergence: under v2, Rust is now
/// conformant (MAN-UNKNOWN-TOP-LEVEL); the divergence was caused by the v1 parser
/// via kdl-rs's legacy shim (which used `char::is_numeric()` = Nd+Nl+No, but
/// the shim incorrectly rejected No-category chars as initial chars).
#[test]
fn kdl2_quarter_fraction_is_unknown_top_level() {
    // `¼` = U+00BC, KDL-2.0-valid identifier (No category)
    assert_eq!(
        doc_err("\u{00BC} \"x\"\n"),
        "MAN-UNKNOWN-TOP-LEVEL",
        "¼ should be a valid KDL 2.0 ident, rejected as unknown top-level by milpa"
    );
}

// ---------------------------------------------------------------------------
// S2 — `milpa_manifest::Predicate` is a re-export of `milpa_types::Predicate`
// (RFC rfc-conditional-requires.md §3.3 / Part A).
// ---------------------------------------------------------------------------

/// Verify that `crate::Predicate` (the milpa-manifest re-export) and
/// `milpa_types::Predicate` (the SSOT) are the same type.  A function that
/// accepts `crate::Predicate` must also accept a `milpa_types::Predicate`
/// value without any cast — re-export identity holds.  If these were separate
/// types this function would not compile.
#[test]
fn manifest_predicate_is_types_predicate_reexport() {
    fn accepts(p: crate::Predicate) -> String {
        p.name
    }
    let p: milpa_types::Predicate = milpa_types::Predicate {
        name: "platform".into(),
        values: vec!["linux".into()],
        negated: false,
    };
    // Compiles iff `crate::Predicate` == `milpa_types::Predicate`.
    let name = accepts(p);
    assert_eq!(name, "platform");
}

// ---------------------------------------------------------------------------
// S2 (RFC #23 §7 + §3.1.2) — same-package `enables` closure unit tests.
//
// Conformance note: S2's pure closure is NOT observable through the
// conformance runner's `resolve` command because active_flags in the lockfile
// are only populated when S3/S4a wire cross-package flag activation through
// the resolver.  These tests mirror the Python tests/test_flag_closure.py
// exactly so both impls assert identical closure results on identical inputs.
// ---------------------------------------------------------------------------

/// Build a simple `FlagDecl` with a name and same-pkg enables list.
fn flag_decl(name: &str, enables: &[&str]) -> FlagDecl {
    FlagDecl {
        name: name.to_string(),
        default: false,
        description: String::new(),
        defines: vec![],
        enables_same_pkg: enables.iter().map(|s| s.to_string()).collect(),
        enables_cross_pkg: vec![],
        conflicts: vec![],
    }
}

fn set(names: &[&str]) -> std::collections::HashSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

// --- Property 1: Seed inclusion ---

#[test]
fn s2_empty_seed_returns_empty() {
    let flags = vec![flag_decl("tls", &[]), flag_decl("http", &[])];
    let result = flag_enables_closure(&flags, &set(&[]));
    assert!(result.is_empty());
}

#[test]
fn s2_seed_with_no_enables() {
    let flags = vec![flag_decl("tls", &[]), flag_decl("http", &[])];
    let result = flag_enables_closure(&flags, &set(&["tls"]));
    assert!(result.contains("tls"));
}

#[test]
fn s2_full_seed_preserved() {
    let flags = vec![flag_decl("tls", &[]), flag_decl("http", &[])];
    let seed = set(&["tls", "http"]);
    let result = flag_enables_closure(&flags, &seed);
    assert!(result.contains("tls") && result.contains("http"));
}

// --- Property 2: One-hop enable ---

#[test]
fn s2_one_hop() {
    // seed {full} where full enables "tls" "http" → result ⊇ {full, tls, http}
    let flags = vec![
        flag_decl("tls", &[]),
        flag_decl("http", &[]),
        flag_decl("full", &["tls", "http"]),
    ];
    let result = flag_enables_closure(&flags, &set(&["full"]));
    assert_eq!(result, set(&["full", "tls", "http"]));
}

#[test]
fn s2_inactive_flag_does_not_propagate() {
    let flags = vec![flag_decl("tls", &[]), flag_decl("full", &["tls"])];
    // seed does NOT include "full"
    let result = flag_enables_closure(&flags, &set(&["tls"]));
    assert_eq!(result, set(&["tls"]));
}

#[test]
fn s2_enables_multiple_targets() {
    let flags = vec![
        flag_decl("a", &[]),
        flag_decl("b", &[]),
        flag_decl("c", &[]),
        flag_decl("meta", &["a", "b", "c"]),
    ];
    let result = flag_enables_closure(&flags, &set(&["meta"]));
    assert_eq!(result, set(&["meta", "a", "b", "c"]));
}

// --- Property 3: Transitive (multi-hop) ---

#[test]
fn s2_two_hop() {
    // a enables b, b enables c, seed {a} → {a, b, c}
    let flags = vec![
        flag_decl("c", &[]),
        flag_decl("b", &["c"]),
        flag_decl("a", &["b"]),
    ];
    let result = flag_enables_closure(&flags, &set(&["a"]));
    assert_eq!(result, set(&["a", "b", "c"]));
}

#[test]
fn s2_three_hop() {
    // a→b→c→d chain from seed {a}
    let flags = vec![
        flag_decl("d", &[]),
        flag_decl("c", &["d"]),
        flag_decl("b", &["c"]),
        flag_decl("a", &["b"]),
    ];
    let result = flag_enables_closure(&flags, &set(&["a"]));
    assert_eq!(result, set(&["a", "b", "c", "d"]));
}

#[test]
fn s2_diamond() {
    // Diamond: a→{b,c}, b→d, c→d. result is {a,b,c,d}
    let flags = vec![
        flag_decl("d", &[]),
        flag_decl("b", &["d"]),
        flag_decl("c", &["d"]),
        flag_decl("a", &["b", "c"]),
    ];
    let result = flag_enables_closure(&flags, &set(&["a"]));
    assert_eq!(result, set(&["a", "b", "c", "d"]));
}

// --- Property 4: Idempotence ---

#[test]
fn s2_closure_is_idempotent() {
    let flags = vec![
        flag_decl("c", &[]),
        flag_decl("b", &["c"]),
        flag_decl("a", &["b"]),
    ];
    let seed = set(&["a"]);
    let first = flag_enables_closure(&flags, &seed);
    let second = flag_enables_closure(&flags, &first);
    assert_eq!(first, second);
}

#[test]
fn s2_idempotent_no_enables() {
    let flags = vec![flag_decl("x", &[]), flag_decl("y", &[])];
    let seed = set(&["x", "y"]);
    let first = flag_enables_closure(&flags, &seed);
    let second = flag_enables_closure(&flags, &first);
    assert_eq!(first, second);
}

// --- Property 5: Cycle termination ---

#[test]
fn s2_two_cycle() {
    // a enables b, b enables a, seed {a} → {a, b}; function terminates
    let flags = vec![flag_decl("b", &["a"]), flag_decl("a", &["b"])];
    let result = flag_enables_closure(&flags, &set(&["a"]));
    assert_eq!(result, set(&["a", "b"]));
}

#[test]
fn s2_self_enable() {
    // A flag that enables itself is a trivial cycle; still terminates
    let flags = vec![flag_decl("a", &["a"])];
    let result = flag_enables_closure(&flags, &set(&["a"]));
    assert_eq!(result, set(&["a"]));
}

#[test]
fn s2_three_cycle() {
    // a→b→c→a cycle; seed {a} → {a, b, c}
    let flags = vec![
        flag_decl("c", &["a"]),
        flag_decl("b", &["c"]),
        flag_decl("a", &["b"]),
    ];
    let result = flag_enables_closure(&flags, &set(&["a"]));
    assert_eq!(result, set(&["a", "b", "c"]));
}

#[test]
fn s2_cycle_plus_tail() {
    // a→b→a cycle, a also enables d; seed {a} → {a, b, d}
    let flags = vec![
        flag_decl("d", &[]),
        flag_decl("b", &["a"]),
        flag_decl("a", &["b", "d"]),
    ];
    let result = flag_enables_closure(&flags, &set(&["a"]));
    assert_eq!(result, set(&["a", "b", "d"]));
}

// --- Property 6: Order-independence ---

#[test]
fn s2_flag_table_order_does_not_affect_result() {
    let seed = set(&["meta"]);
    // Order A: meta last
    let flags_a = vec![
        flag_decl("a", &[]),
        flag_decl("b", &[]),
        flag_decl("meta", &["a", "b"]),
    ];
    // Order B: meta first
    let flags_b = vec![
        flag_decl("meta", &["a", "b"]),
        flag_decl("b", &[]),
        flag_decl("a", &[]),
    ];
    assert_eq!(
        flag_enables_closure(&flags_a, &seed),
        flag_enables_closure(&flags_b, &seed)
    );
}

#[test]
fn s2_union_is_commutative() {
    let flags = vec![
        flag_decl("x", &[]),
        flag_decl("y", &[]),
        flag_decl("fa", &["x"]),
        flag_decl("fb", &["y"]),
    ];
    let r1 = flag_enables_closure(&flags, &set(&["fa", "fb"]));
    let r2 = flag_enables_closure(&flags, &set(&["fb", "fa"]));
    assert_eq!(r1, r2);
    assert_eq!(r1, set(&["fa", "fb", "x", "y"]));
}

// --- Property 7: Cross-package entries are ignored ---

#[test]
fn s2_cross_pkg_entries_not_followed() {
    // cross-package enables are ignored in S2 (resolve-time concern, S3/S4a)
    let flags = vec![
        flag_decl("tls", &[]),
        FlagDecl {
            name: "full".to_string(),
            default: false,
            description: String::new(),
            defines: vec![],
            enables_same_pkg: vec!["tls".to_string()],
            enables_cross_pkg: vec![CrossPkgEnable {
                dep: "chronos".to_string(),
                flag_requests: vec![FlagRequest {
                    name: "tls".to_string(),
                    enabled: true,
                }],
            }],
            conflicts: vec![],
        },
    ];
    let result = flag_enables_closure(&flags, &set(&["full"]));
    assert!(result.contains("tls"), "'tls' (same-pkg) must be reached");
    assert!(!result.contains("chronos"), "'chronos' is cross-pkg, not a flag");
}

// --- Unknown targets graceful ---

#[test]
fn s2_closure_skips_unknown_enables_targets() {
    // enables targets not in the flag table are silently ignored
    let flags = vec![flag_decl("a", &["nonexistent"])];
    let result = flag_enables_closure(&flags, &set(&["a"]));
    assert!(result.contains("a"));
    assert!(!result.contains("nonexistent"));
}

// --- Default-seeding is caller's responsibility ---

#[test]
fn s2_default_seeding_is_callers_responsibility() {
    let flags = vec![
        FlagDecl {
            name: "ssl".to_string(),
            default: true,
            description: String::new(),
            defines: vec![],
            enables_same_pkg: vec![],
            enables_cross_pkg: vec![],
            conflicts: vec![],
        },
        flag_decl("debug", &[]),
        FlagDecl {
            name: "net".to_string(),
            default: true,
            description: String::new(),
            defines: vec![],
            enables_same_pkg: vec!["ssl".to_string()],
            enables_cross_pkg: vec![],
            conflicts: vec![],
        },
    ];
    // Caller seeds from default-true flags
    let defaults_seed: std::collections::HashSet<String> = flags
        .iter()
        .filter(|f| f.default)
        .map(|f| f.name.clone())
        .collect();
    assert_eq!(defaults_seed, set(&["ssl", "net"]));
    let result = flag_enables_closure(&flags, &defaults_seed);
    assert!(result.contains("ssl"));
    assert!(result.contains("net"));
    assert!(!result.contains("debug"));
}

// ---------------------------------------------------------------------------
// S5b: namespace-qualified named dep grammar
// ---------------------------------------------------------------------------

/// Helper: extract the single NamedDep from a manifest text.
fn single_named(text: &str) -> NamedDep {
    let m = pkg(text);
    assert_eq!(m.deps.len(), 1, "expected exactly one dep");
    match m.deps.into_iter().next().unwrap() {
        Dep::Named(n) => n,
        other => panic!("expected Named dep, got {other:?}"),
    }
}

fn s5b_manifest(dep_line: &str) -> String {
    format!("name \"app\"\nkind \"library\"\ndeps {{\n  {dep_line}\n}}\n")
}

#[test]
fn s5b_named_dep_namespace_attr_parsed() {
    // Canonical form: `pkg namespace="core" ">= 1.0.0"`.
    let n = single_named(&s5b_manifest(r#"pkg namespace="core" ">= 1.0.0""#));
    assert_eq!(n.name, "pkg");
    assert_eq!(n.namespace, Some("core".to_string()));
    assert_eq!(n.constraint.as_deref(), Some(">= 1.0.0"));
}

#[test]
fn s5b_named_dep_namespace_attr_no_constraint() {
    let n = single_named(&s5b_manifest(r#"pkg namespace="core""#));
    assert_eq!(n.name, "pkg");
    assert_eq!(n.namespace, Some("core".to_string()));
    assert!(n.constraint.is_none());
}

#[test]
fn s5b_slash_shorthand_desugars_to_namespace_attr() {
    // Slash shorthand: `"core/pkg" ">= 1.0.0"` desugars to namespace="core", name="pkg".
    let n = single_named(&s5b_manifest(r#""core/pkg" ">= 1.0.0""#));
    assert_eq!(n.name, "pkg");
    assert_eq!(n.namespace, Some("core".to_string()));
    assert_eq!(n.constraint.as_deref(), Some(">= 1.0.0"));
}

#[test]
fn s5b_slash_shorthand_no_constraint() {
    let n = single_named(&s5b_manifest(r#""core/pkg""#));
    assert_eq!(n.name, "pkg");
    assert_eq!(n.namespace, Some("core".to_string()));
    assert!(n.constraint.is_none());
}

#[test]
fn s5b_slash_two_slashes_invalid() {
    let err = doc_err(&s5b_manifest(r#""a/b/c""#));
    assert_eq!(err, "MAN-DEP-NAME-INVALID");
}

#[test]
fn s5b_slash_empty_namespace_invalid() {
    let err = doc_err(&s5b_manifest(r#""/pkg""#));
    assert_eq!(err, "MAN-DEP-NAME-INVALID");
}

#[test]
fn s5b_slash_empty_name_part_invalid() {
    let err = doc_err(&s5b_manifest(r#""core/""#));
    assert_eq!(err, "MAN-DEP-NAME-INVALID");
}

#[test]
fn s5b_namespace_attr_non_string_invalid() {
    let err = doc_err(&s5b_manifest("pkg namespace=123"));
    assert_eq!(err, "MAN-DEP-NAMED-PROPS");
}

#[test]
fn s5b_namespace_attr_invalid_charset() {
    let err = doc_err(&s5b_manifest("pkg namespace=\"core!\""));
    assert_eq!(err, "MAN-DEP-NAME-INVALID");
}

#[test]
fn s5b_both_forms_produce_identical_named_dep() {
    // canonical attr and slash shorthand must produce identical NamedDep.
    let attr = single_named(&s5b_manifest(r#"pkg namespace="core" ">= 1.0.0""#));
    let slash = single_named(&s5b_manifest(r#""core/pkg" ">= 1.0.0""#));
    assert_eq!(attr, slash);
}

#[test]
fn s5b_no_namespace_gives_none() {
    let n = single_named(&s5b_manifest(r#"pkg ">= 1.0.0""#));
    assert!(n.namespace.is_none());
}

#[test]
fn s5b_two_qualified_deps_different_namespaces_not_duplicates() {
    // Two deps with same bare name but different namespaces are allowed.
    let text = "name \"app\"\nkind \"library\"\ndeps {\n  \"ns1/alpha\" \">= 1.0.0\"\n  \"ns2/alpha\" \">= 2.0.0\"\n}\n";
    let m = pkg(text);
    assert_eq!(m.deps.len(), 2);
}

#[test]
fn s5b_two_same_namespace_same_name_is_duplicate() {
    // Same (namespace, name) pair is a duplicate.
    let text = "name \"app\"\nkind \"library\"\ndeps {\n  \"core/pkg\" \">= 1.0.0\"\n  \"core/pkg\" \">= 2.0.0\"\n}\n";
    let err = doc_err(text);
    assert_eq!(err, "MAN-DEP-DUPLICATE");
}

#[test]
fn s5b_format_namespace_canonical_attr_form() {
    // Round-trip: format emits namespace= attr, NOT slash form.
    let m = pkg(&s5b_manifest(r#""core/pkg" ">= 1.0.0""#));
    let text = crate::format::format_manifest(&m);
    // Must contain canonical attr form.
    assert!(text.contains("namespace=\"core\""), "expected namespace attr in:\n{text}");
    // Must NOT re-emit the slash shorthand.
    assert!(!text.contains("core/pkg"), "slash form must not appear in output:\n{text}");
}

#[test]
fn s5b_format_namespace_round_trip() {
    // parse → format → parse must yield equal manifest.
    let input = s5b_manifest(r#""core/pkg" ">= 1.0.0""#);
    let m = pkg(&input);
    let text = crate::format::format_manifest(&m);
    let m2 = pkg(&text);
    assert_eq!(m.deps, m2.deps);
}

// --- RFC §3.1.1 example ---

#[test]
fn s2_rfc_full_flag_example() {
    // RFC §3.1.1: tls, http, full enables {tls, http}; cross-pkg (chronos) ignored.
    let flags = vec![
        flag_decl("tls", &[]),
        flag_decl("http", &[]),
        FlagDecl {
            name: "full".to_string(),
            default: false,
            description: String::new(),
            defines: vec![],
            enables_same_pkg: vec!["tls".to_string(), "http".to_string()],
            enables_cross_pkg: vec![CrossPkgEnable {
                dep: "chronos".to_string(),
                flag_requests: vec![FlagRequest {
                    name: "tls".to_string(),
                    enabled: true,
                }],
            }],
            conflicts: vec![],
        },
    ];
    let result = flag_enables_closure(&flags, &set(&["full"]));
    assert_eq!(result, set(&["full", "tls", "http"]));
}

// ---------------------------------------------------------------------------
// S8 — subpath grammar (rfc-origin-as-identity.md §4.1/§10 item 14). Mirrors
// Python's test_subpath_grammar.py `TestSubpathParse`. (The `SourceId`-level
// injectivity/escape-guard coverage — `TestSubpathDistinctOrigins`/
// `TestSubpathEscapeGuard` — already exists in `source_id_tests.rs`, landed
// with S1; only the GRAMMAR layer is new here.)
// ---------------------------------------------------------------------------

#[test]
fn s8_git_dep_subpath_parses() {
    let m = pkg(
        "name \"x\"\ndeps {\n  react-dom git=(url)\"https://github.com/facebook/react.git\" \
         ref=\"main\" subpath=\"packages/react-dom\"\n}\n",
    );
    let Dep::Url(u) = &m.deps[0] else { panic!("expected UrlDep") };
    assert_eq!(u.subpath.as_deref(), Some("packages/react-dom"));
}

#[test]
fn s8_git_dep_no_subpath_is_none() {
    let m = pkg("name \"x\"\ndeps {\n  foo git=(url)\"https://example.com/foo.git\" ref=\"main\"\n}\n");
    let Dep::Url(u) = &m.deps[0] else { panic!("expected UrlDep") };
    assert_eq!(u.subpath, None);
}

#[test]
fn s8_tarball_dep_subpath_parses() {
    let m = pkg(
        "name \"x\"\ndeps {\n  foo tarball=(url)\"https://example.com/pkg.tar.gz\" subpath=\"pkg/foo\"\n}\n",
    );
    let Dep::Tarball(t) = &m.deps[0] else { panic!("expected TarballDep") };
    assert_eq!(t.subpath.as_deref(), Some("pkg/foo"));
}

#[test]
fn s8_tarball_dep_no_subpath_is_none() {
    let m = pkg("name \"x\"\ndeps {\n  foo tarball=(url)\"https://example.com/pkg.tar.gz\"\n}\n");
    let Dep::Tarball(t) = &m.deps[0] else { panic!("expected TarballDep") };
    assert_eq!(t.subpath, None);
}

#[test]
fn s8_git_dep_subpath_wrong_type_raises() {
    assert_eq!(
        doc_err(
            "name \"x\"\ndeps {\n  foo git=(url)\"https://example.com/foo.git\" ref=\"main\" \
             subpath=#true\n}\n"
        ),
        "MAN-DEP-UNKNOWN-PROPS"
    );
}

#[test]
fn s8_git_dep_subpath_round_trips() {
    let m = pkg(
        "name \"x\"\ndeps {\n  react-dom git=(url)\"https://github.com/facebook/react.git\" \
         ref=\"main\" subpath=\"packages/react-dom\"\n}\n",
    );
    let out = crate::format::format_manifest(&m);
    assert!(out.contains("subpath=\"packages/react-dom\""), "missing subpath in:\n{out}");
    let m2 = pkg(&out);
    let Dep::Url(u2) = &m2.deps[0] else { panic!("expected UrlDep") };
    assert_eq!(u2.subpath.as_deref(), Some("packages/react-dom"));
}

#[test]
fn s8_tarball_dep_subpath_round_trips() {
    let m = pkg(
        "name \"x\"\ndeps {\n  foo tarball=(url)\"https://example.com/pkg.tar.gz\" subpath=\"pkg/foo\"\n}\n",
    );
    let out = crate::format::format_manifest(&m);
    assert!(out.contains("subpath=\"pkg/foo\""), "missing subpath in:\n{out}");
    let m2 = pkg(&out);
    let Dep::Tarball(t2) = &m2.deps[0] else { panic!("expected TarballDep") };
    assert_eq!(t2.subpath.as_deref(), Some("pkg/foo"));
}

#[test]
fn s8_manifest_parse_accepts_traversing_subpath_string() {
    // The parser itself does NOT validate subpath — `source_id::normalize_source`
    // is the SOLE validation boundary; a traversing string parses fine at the
    // manifest layer (mirrors Python's identically-named test).
    let m = pkg(
        "name \"x\"\ndeps {\n  foo git=(url)\"https://example.com/foo.git\" ref=\"main\" \
         subpath=\"../escape\"\n}\n",
    );
    let Dep::Url(u) = &m.deps[0] else { panic!("expected UrlDep") };
    assert_eq!(u.subpath.as_deref(), Some("../escape"));
}

// ---------------------------------------------------------------------------
// S8b — COMPLETE overrides grammar (rfc-origin-as-identity.md §7 B5 / §10
// item 14): `OciTarget`/`TarballTarget`/`RegistryTarget` (Rust:
// `OverrideTarget::{Oci,Tarball,Registry}`) + version-scoped overrides.
// Mirrors Python's test_override_targets_extended.py grammar classes.
// ---------------------------------------------------------------------------

#[test]
fn s8b_oci_target_parses() {
    let m = pkg(&format!(
        "name \"x\"\noverrides {{\n  pkg \"foo\" oci=\"ghcr.io/acme/foo\" digest=\"sha256:{}\"\n}}\n",
        "a".repeat(64)
    ));
    let ov = &m.overrides[0];
    assert_eq!(ov.name, "foo");
    let OverrideTarget::Oci { registry, repository, digest, subpath } = &ov.target else {
        panic!("expected OverrideTarget::Oci")
    };
    assert_eq!(registry, "ghcr.io");
    assert_eq!(repository, "acme/foo");
    assert_eq!(digest, &format!("sha256:{}", "a".repeat(64)));
    assert_eq!(*subpath, None);
}

#[test]
fn s8b_oci_target_subpath_parses() {
    let m = pkg(&format!(
        "name \"x\"\noverrides {{\n  pkg \"foo\" oci=\"ghcr.io/acme/foo\" digest=\"sha256:{}\" \
         subpath=\"pkg/foo\"\n}}\n",
        "a".repeat(64)
    ));
    let OverrideTarget::Oci { subpath, .. } = &m.overrides[0].target else {
        panic!("expected OverrideTarget::Oci")
    };
    assert_eq!(subpath.as_deref(), Some("pkg/foo"));
}

#[test]
fn s8b_oci_target_missing_digest_raises() {
    assert_eq!(
        doc_err("name \"x\"\noverrides {\n  pkg \"foo\" oci=\"ghcr.io/acme/foo\"\n}\n"),
        "MAN-OVERRIDE-DIGEST-MISSING"
    );
}

#[test]
fn s8b_oci_target_malformed_coordinate_no_slash_raises() {
    assert_eq!(
        doc_err(&format!(
            "name \"x\"\noverrides {{\n  pkg \"foo\" oci=\"ghcronly\" digest=\"sha256:{}\"\n}}\n",
            "a".repeat(64)
        )),
        "MAN-OVERRIDE-OCI-MALFORMED"
    );
}

#[test]
fn s8b_oci_target_round_trips() {
    let m = pkg(&format!(
        "name \"x\"\noverrides {{\n  pkg \"foo\" oci=\"ghcr.io/acme/foo\" digest=\"sha256:{}\"\n}}\n",
        "b".repeat(64)
    ));
    let out = crate::format::format_manifest(&m);
    let m2 = pkg(&out);
    assert_eq!(m.overrides, m2.overrides);
}

#[test]
fn s8b_tarball_target_parses() {
    let m = pkg(
        "name \"x\"\noverrides {\n  pkg \"foo\" tarball=(url)\"https://example.com/foo.tar.gz\" \
         sha256=\"deadbeef\" strip_components=1\n}\n",
    );
    let OverrideTarget::Tarball { url, sha256, strip_components, subpath } = &m.overrides[0].target
    else {
        panic!("expected OverrideTarget::Tarball")
    };
    assert_eq!(url, "https://example.com/foo.tar.gz");
    assert_eq!(sha256.as_deref(), Some("deadbeef"));
    assert_eq!(*strip_components, 1);
    assert_eq!(*subpath, None);
}

#[test]
fn s8b_tarball_target_subpath_parses() {
    let m = pkg(
        "name \"x\"\noverrides {\n  pkg \"foo\" tarball=(url)\"https://example.com/foo.tar.gz\" \
         subpath=\"pkg/foo\"\n}\n",
    );
    let OverrideTarget::Tarball { subpath, .. } = &m.overrides[0].target else {
        panic!("expected OverrideTarget::Tarball")
    };
    assert_eq!(subpath.as_deref(), Some("pkg/foo"));
}

#[test]
fn s8b_tarball_target_round_trips() {
    let m = pkg(
        "name \"x\"\noverrides {\n  pkg \"foo\" tarball=(url)\"https://example.com/foo.tar.gz\" \
         sha256=\"deadbeef\" strip_components=1 subpath=\"pkg/foo\"\n}\n",
    );
    let out = crate::format::format_manifest(&m);
    let m2 = pkg(&out);
    assert_eq!(m.overrides, m2.overrides);
}

#[test]
fn s8b_registry_target_parses() {
    let m = pkg("name \"x\"\noverrides {\n  pkg \"old-fork\" named=\"widget\" namespace=\"acme\"\n}\n");
    let ov = &m.overrides[0];
    assert_eq!(ov.name, "old-fork");
    let OverrideTarget::Registry { name, namespace } = &ov.target else {
        panic!("expected OverrideTarget::Registry")
    };
    assert_eq!(name, "widget");
    assert_eq!(namespace.as_deref(), Some("acme"));
}

#[test]
fn s8b_registry_target_namespace_optional() {
    let m = pkg("name \"x\"\noverrides {\n  pkg \"old-fork\" named=\"widget\"\n}\n");
    let OverrideTarget::Registry { namespace, .. } = &m.overrides[0].target else {
        panic!("expected OverrideTarget::Registry")
    };
    assert_eq!(*namespace, None);
}

#[test]
fn s8b_registry_target_missing_named_raises() {
    // No target form present at all -> ambiguous (namespace= alone never
    // selects the registry form; `named=` is the discriminator).
    assert_eq!(
        doc_err("name \"x\"\noverrides {\n  pkg \"old-fork\" namespace=\"acme\"\n}\n"),
        "MAN-OVERRIDE-TARGET-AMBIGUOUS"
    );
}

#[test]
fn s8b_registry_target_version_scoped() {
    let m = pkg(
        "name \"x\"\noverrides {\n  pkg \"old-fork\" named=\"widget\" namespace=\"acme\" \
         version=\"1.0.0\"\n}\n",
    );
    assert_eq!(m.overrides[0].version, Some(milpa_types::Version::release(1, 0, 0)));
}

#[test]
fn s8b_registry_target_round_trips() {
    let m = pkg(
        "name \"x\"\noverrides {\n  pkg \"old-fork\" named=\"widget\" namespace=\"acme\" \
         version=\"1.0.0\"\n}\n",
    );
    let out = crate::format::format_manifest(&m);
    let m2 = pkg(&out);
    assert_eq!(m.overrides, m2.overrides);
}

#[test]
fn s8b_target_ambiguity_two_new_forms_mixed_raises() {
    assert_eq!(
        doc_err(&format!(
            "name \"x\"\noverrides {{\n  pkg \"foo\" oci=\"ghcr.io/a/b\" digest=\"sha256:{}\" \
             tarball=(url)\"https://example.com/x.tar.gz\"\n}}\n",
            "a".repeat(64)
        )),
        "MAN-OVERRIDE-TARGET-AMBIGUOUS"
    );
}

#[test]
fn s8b_target_ambiguity_old_and_new_form_mixed_raises() {
    assert_eq!(
        doc_err(
            "name \"x\"\noverrides {\n  pkg \"foo\" git=(url)\"https://example.com/foo.git\" \
             ref=\"main\" named=\"foo\"\n}\n"
        ),
        "MAN-OVERRIDE-TARGET-AMBIGUOUS"
    );
}
