//! Unit tests for manifest discovery (S13). The discovery `MAN-*` codes are not
//! fixture-expressible (the corpus reads manifest text directly), so they are
//! covered here.

use super::*;

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn prefers_milpa_kdl() {
    let d = tmp();
    std::fs::write(
        d.path().join("milpa.kdl"),
        "name \"pkg\"\nkind \"library\"\n",
    )
    .unwrap();
    std::fs::write(d.path().join("pkg.nimble"), "requires \"foo\"\n").unwrap();
    let doc = discover_manifest(d.path()).unwrap();
    match doc {
        ManifestDoc::Package(m) => {
            assert_eq!(m.name.as_deref(), Some("pkg"));
            assert!(m.deps.is_empty(), "milpa.kdl wins; .nimble ignored");
        }
        other => panic!("expected package, got {other:?}"),
    }
}

#[test]
fn no_manifest_is_man_no_manifest() {
    let d = tmp();
    assert_eq!(
        discover_manifest(d.path()).unwrap_err().code(),
        "MAN-NO-MANIFEST"
    );
}

#[test]
fn nimble_by_dir_name_promotes_to_manifest() {
    let d = tmp();
    let name = d.path().file_name().unwrap().to_string_lossy().into_owned();
    std::fs::write(
        d.path().join(format!("{name}.nimble")),
        "requires \"https://e/foo.git#v1\"\nrequires \"bar >= 1.0.0\"\nrequires \"nim >= 2.0.0\"\n",
    )
    .unwrap();
    let doc = discover_manifest(d.path()).unwrap();
    match doc {
        ManifestDoc::Package(m) => {
            assert_eq!(m.name.as_deref(), Some(name.as_str()));
            assert_eq!(m.kind, "library");
            // foo (url) + bar (named); nim dropped.
            assert_eq!(m.deps.len(), 2);
            assert!(matches!(&m.deps[0], Dep::Url(u) if u.name == "foo" && u.git_ref == "v1"));
            assert!(matches!(&m.deps[1], Dep::Named(n) if n.name == "bar"));
        }
        other => panic!("expected package, got {other:?}"),
    }
}

#[test]
fn single_other_nimble_is_fallback() {
    let d = tmp();
    std::fs::write(d.path().join("whatever.nimble"), "requires \"foo\"\n").unwrap();
    let doc = discover_manifest(d.path()).unwrap();
    assert!(matches!(doc, ManifestDoc::Package(m) if m.name.as_deref() == Some("whatever")));
}

#[test]
fn multiple_nimbles_is_ambiguous() {
    let d = tmp();
    std::fs::write(d.path().join("a.nimble"), "").unwrap();
    std::fs::write(d.path().join("b.nimble"), "").unwrap();
    assert_eq!(
        discover_manifest(d.path()).unwrap_err().code(),
        "MAN-NIMBLE-AMBIGUOUS"
    );
}

#[test]
fn load_manifest_explicit_missing_path_is_not_found() {
    let d = tmp();
    let missing = d.path().join("milpa.kdl");
    assert_eq!(
        load_manifest(&missing).unwrap_err().code(),
        "MAN-FILE-NOT-FOUND"
    );
}

#[test]
fn load_manifest_surfaces_man_parse_codes() {
    let d = tmp();
    let p = d.path().join("milpa.kdl");
    std::fs::write(&p, "kind \"library\"\n").unwrap(); // no name
    assert_eq!(load_manifest(&p).unwrap_err().code(), "MAN-NAME-MISSING");
}
