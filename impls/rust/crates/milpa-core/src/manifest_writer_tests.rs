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
                parsed_constraint: None,
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

// ---------------------------------------------------------------------------
// add_mirror (D-add slice) — pure manifest mutation, no fetch/verify/lockfile
// ---------------------------------------------------------------------------

const CANON_URL: &str = "https://example.com/foo.git";
const MIRROR_URL: &str = "https://mirror.example.com/foo.git";

/// Write a minimal milpa.kdl with a URL dep named `dep_name`.
fn write_url_dep_manifest(dir: &std::path::Path, dep_name: &str, git_url: &str) {
    std::fs::write(
        dir.join("milpa.kdl"),
        format!(
            "name \"app\"\nkind \"application\"\ndeps {{\n    {dep_name} git=(url)\"{git_url}\" ref=\"main\"\n}}\n"
        ),
    )
    .unwrap();
}

#[test]
fn add_mirror_appends_to_kdl_no_lockfile_needed() {
    // D-add: pure manifest mutation — no milpa.lock required.
    let d = tmp();
    let proj = d.path();
    write_url_dep_manifest(proj, "foo", CANON_URL);
    // No milpa.lock written.

    add_mirror(proj, "foo", MIRROR_URL).unwrap();

    let written = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
    assert!(written.contains(&format!("mirror (url)\"{MIRROR_URL}\"")));
    // milpa.lock must NOT exist.
    assert!(!proj.join("milpa.lock").exists());
}

#[test]
fn add_mirror_round_trip_parser() {
    // Written milpa.kdl re-parses with the mirror present on the dep.
    let d = tmp();
    let proj = d.path();
    write_url_dep_manifest(proj, "foo", CANON_URL);

    add_mirror(proj, "foo", MIRROR_URL).unwrap();

    let written = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
    let manifest = match milpa_manifest::parse_document(&written).unwrap() {
        milpa_manifest::ManifestDoc::Package(m) => m,
        other => panic!("expected package, got {other:?}"),
    };
    let foo = manifest
        .deps
        .iter()
        .find(|d| d.name() == "foo")
        .expect("foo dep must exist");
    match foo {
        milpa_manifest::Dep::Url(u) => {
            assert!(u.mirrors.contains(&MIRROR_URL.to_string()));
        }
        other => panic!("expected UrlDep, got {other:?}"),
    }
}

#[test]
fn add_mirror_idempotent() {
    // Running add_mirror twice: second call returns Ok(()), no duplicate mirror.
    let d = tmp();
    let proj = d.path();
    write_url_dep_manifest(proj, "foo", CANON_URL);

    add_mirror(proj, "foo", MIRROR_URL).unwrap();
    add_mirror(proj, "foo", MIRROR_URL).unwrap(); // second — must not error

    let written = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
    let count = written.matches(MIRROR_URL).count();
    assert_eq!(count, 1, "mirror URL must appear exactly once");
}

#[test]
fn add_mirror_dep_not_declared_is_error() {
    // `dep_name` absent from milpa.kdl → MAN-MIRROR-EDITABLE-PROVENANCE.
    let d = tmp();
    let proj = d.path();
    write_url_dep_manifest(proj, "foo", CANON_URL);

    let err = add_mirror(proj, "nosuchdep", MIRROR_URL).unwrap_err();
    assert_eq!(err.code(), "MAN-MIRROR-EDITABLE-PROVENANCE");
    // milpa.kdl must be unmodified.
    let kdl = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
    assert!(!kdl.contains(MIRROR_URL));
}

#[test]
fn add_mirror_local_dep_rejected() {
    // A local dep cannot carry mirrors → MAN-MIRROR-EDITABLE-PROVENANCE.
    let d = tmp();
    let proj = d.path();
    let local_dir = d.path().join("local_pkg");
    std::fs::create_dir_all(&local_dir).unwrap();
    std::fs::write(
        proj.join("milpa.kdl"),
        format!(
            "name \"app\"\nkind \"application\"\ndeps {{\n    localpkg local=\"{}\"\n}}\n",
            local_dir.display()
        ),
    )
    .unwrap();

    let err = add_mirror(proj, "localpkg", MIRROR_URL).unwrap_err();
    assert_eq!(err.code(), "MAN-MIRROR-EDITABLE-PROVENANCE");
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
