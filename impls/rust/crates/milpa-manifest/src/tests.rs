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
        ("name \"x\"\ndeps {\n  foo tarball=\"\"\n}\n", "MAN-DEP-TARBALL-URL"),
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
            "MAN-GIT-URL-NO-SCHEME",
        ),
        (
            "name \"x\"\ndeps {\n  foo git=\"ftp://a/f.git\" ref=\"m\"\n}\n",
            "MAN-GIT-URL-BAD-SCHEME",
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
            "MAN-OVERRIDE-GIT-MISSING",
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

#[test]
fn cas_and_mirrors_and_overrides() {
    let m = pkg(
        "name \"a\"\ncas {\n  dir \".store\"\n}\nmirrors {\n  mirror (url)\"https://m/a.git\"\n}\noverrides {\n  pkg \"x\" git=(url)\"https://o/x.git\" ref=\"v1\"\n}\n",
    );
    assert_eq!(m.cas_dir, ".store");
    assert_eq!(m.self_mirrors, vec!["https://m/a.git"]);
    assert_eq!(m.overrides.len(), 1);
    assert_eq!(m.overrides[0].name, "x");
    assert_eq!(m.overrides[0].git_ref, "v1");
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
