//! Unit tests for manifest mutation (S13). The MAN-MUTATE-* codes are not
//! fixture-expressible (the corpus never invokes the mutating verbs), so they
//! are covered here.

use super::*;

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn identity(m: Manifest) -> Manifest {
    m
}

#[test]
fn missing_file_is_man_mutate_file_not_found() {
    let d = tmp();
    let err = mutate_manifest_file(&d.path().join("milpa.kdl"), identity).unwrap_err();
    assert_eq!(err.code(), "MAN-MUTATE-FILE-NOT-FOUND");
}

#[test]
fn nimble_is_refused() {
    let d = tmp();
    let p = d.path().join("foo.nimble");
    std::fs::write(&p, "requires \"x\"\n").unwrap();
    assert_eq!(
        mutate_manifest_file(&p, identity).unwrap_err().code(),
        "MAN-MUTATE-NIMBLE-REFUSED"
    );
}

#[test]
fn workspace_is_refused() {
    let d = tmp();
    let p = d.path().join("milpa.kdl");
    std::fs::write(&p, "workspace {\n    member \"a\"\n}\n").unwrap();
    assert_eq!(
        mutate_manifest_file(&p, identity).unwrap_err().code(),
        "MAN-MUTATE-WORKSPACE-REFUSED"
    );
}

#[test]
fn add_dep_rewrites_canonically_and_reports_comment_loss() {
    let d = tmp();
    let p = d.path().join("milpa.kdl");
    // Two hand-written comments; the canonical render keeps only its 1 header.
    std::fs::write(
        &p,
        "// my project\nname \"app\"\nkind \"application\"\n// end\n",
    )
    .unwrap();

    let res = mutate_manifest_file(&p, |mut m| {
        m.deps
            .push(milpa_manifest::Dep::Named(milpa_manifest::NamedDep {
                name: "newdep".into(),
                constraint: None,
            }));
        m
    })
    .unwrap();

    assert_eq!(
        res.comments_lost, 1,
        "2 source comments → 1 header retained"
    );
    let written = std::fs::read_to_string(&p).unwrap();
    assert!(written.contains("deps {"));
    assert!(written.contains("\"newdep\""));
    // Re-parse confirms the rewrite is valid + the dep landed.
    match milpa_manifest::parse_document(&written).unwrap() {
        milpa_manifest::ManifestDoc::Package(m) => {
            assert!(m.deps.iter().any(|dep| dep.name() == "newdep"));
        }
        other => panic!("expected package, got {other:?}"),
    }
}

#[test]
fn malformed_package_surfaces_its_parse_code() {
    let d = tmp();
    let p = d.path().join("milpa.kdl");
    std::fs::write(&p, "kind \"library\"\n").unwrap(); // no name
    assert_eq!(
        mutate_manifest_file(&p, identity).unwrap_err().code(),
        "MAN-NAME-MISSING"
    );
}
