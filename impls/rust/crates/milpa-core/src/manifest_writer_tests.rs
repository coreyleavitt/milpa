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
                flag_requests: Vec::new(),
                optional: false,
                predicates: Vec::new(),
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

// ---------------------------------------------------------------------------
// S9a — format_workspace_manifest + mutate_workspace_manifest_file tests
// ---------------------------------------------------------------------------

#[test]
fn format_workspace_manifest_minimal_two_members() {
    let ws = milpa_manifest::Workspace {
        members: vec!["member-a".into(), "member-b".into()],
        overrides: Vec::new(),
        flags: Vec::new(),
        name: None,
    };
    let out = milpa_manifest::format_workspace_manifest(&ws);
    assert!(out.contains("member \"member-a\""), "output:\n{out}");
    assert!(out.contains("member \"member-b\""), "output:\n{out}");
    assert!(out.ends_with('\n'));
}

#[test]
fn format_workspace_manifest_name_emitted_when_some() {
    let ws = milpa_manifest::Workspace {
        members: vec!["pkg".into()],
        overrides: Vec::new(),
        flags: Vec::new(),
        name: Some("my-workspace".into()),
    };
    let out = milpa_manifest::format_workspace_manifest(&ws);
    assert!(out.contains("name \"my-workspace\""), "output:\n{out}");
}

#[test]
fn format_workspace_manifest_name_absent_when_none() {
    let ws = milpa_manifest::Workspace {
        members: vec!["pkg".into()],
        overrides: Vec::new(),
        flags: Vec::new(),
        name: None,
    };
    let out = milpa_manifest::format_workspace_manifest(&ws);
    // No standalone name= line (only the header comment)
    let name_lines: Vec<_> = out.lines().filter(|l| l.starts_with("name ")).collect();
    assert!(name_lines.is_empty(), "unexpected name line: {name_lines:?}");
}

#[test]
fn format_workspace_manifest_url_annotation_on_git_override() {
    let ws = milpa_manifest::Workspace {
        members: vec!["pkg".into()],
        overrides: vec![milpa_manifest::Override {
            name: "dep-x".into(),
            target: milpa_manifest::OverrideTarget::Git {
                url: "https://github.com/example/dep-x.git".into(),
                git_ref: "main".into(),
            },
        }],
        flags: Vec::new(),
        name: None,
    };
    let out = milpa_manifest::format_workspace_manifest(&ws);
    assert!(out.contains("git=(url)\"https://github.com/example/dep-x.git\""), "output:\n{out}");
}

#[test]
fn format_workspace_manifest_idempotent() {
    // format(parse(format(ws))) == format(ws): byte-stable canonical serializer.
    let ws = milpa_manifest::Workspace {
        members: vec!["member-a".into(), "member-b".into()],
        overrides: vec![milpa_manifest::Override {
            name: "dep-x".into(),
            target: milpa_manifest::OverrideTarget::Git {
                url: "https://github.com/example/dep-x.git".into(),
                git_ref: "main".into(),
            },
        }],
        flags: vec![milpa_manifest::FlagDecl {
            name: "extras".into(),
            default: false,
            description: String::new(),
            defines: Vec::new(),
            enables_same_pkg: Vec::new(),
            enables_cross_pkg: Vec::new(),
            conflicts: Vec::new(),
        }],
        name: Some("root".into()),
    };
    let first = milpa_manifest::format_workspace_manifest(&ws);
    let reparsed = match milpa_manifest::parse_document(&first).unwrap() {
        milpa_manifest::ManifestDoc::Workspace(w) => w,
        other => panic!("expected Workspace, got {other:?}"),
    };
    let second = milpa_manifest::format_workspace_manifest(&reparsed);
    assert_eq!(first, second, "idempotence violated");
}

#[test]
fn mutate_workspace_manifest_file_identity() {
    let d = tmp();
    let p = d.path().join("milpa.kdl");
    std::fs::write(&p, "workspace {\n    member \"member-a\"\n}\n").unwrap();
    let result = mutate_workspace_manifest_file(&p, |ws| ws).unwrap();
    assert_eq!(result.path, p);
    let text = std::fs::read_to_string(&p).unwrap();
    assert!(text.contains("member \"member-a\""), "output:\n{text}");
}

#[test]
fn mutate_workspace_manifest_file_refused_on_package() {
    let d = tmp();
    let p = d.path().join("milpa.kdl");
    std::fs::write(&p, "name \"mypkg\"\nkind \"library\"\n").unwrap();
    assert_eq!(
        mutate_workspace_manifest_file(&p, |ws| ws).unwrap_err().code(),
        "MAN-MUTATE-WORKSPACE-REFUSED"
    );
}

#[test]
fn mutate_workspace_manifest_file_not_found() {
    let d = tmp();
    let p = d.path().join("no-such.kdl");
    assert_eq!(
        mutate_workspace_manifest_file(&p, |ws| ws).unwrap_err().code(),
        "MAN-MUTATE-FILE-NOT-FOUND"
    );
}

// ---------------------------------------------------------------------------
// S9b — apply_workspace_manifest_change tests
// ---------------------------------------------------------------------------

/// Write a minimal workspace milpa.kdl with the given member paths.
fn write_workspace(root: &std::path::Path, members: &[&str]) {
    let members_block: String = members
        .iter()
        .map(|m| format!("    member \"{m}\"\n"))
        .collect();
    std::fs::write(
        root.join("milpa.kdl"),
        format!("workspace {{\n{members_block}}}\n"),
    )
    .unwrap();
}

/// Write a minimal member milpa.kdl (no deps) in `member_dir`.
fn write_member(member_dir: &std::path::Path, name: &str) {
    std::fs::create_dir_all(member_dir).unwrap();
    std::fs::write(
        member_dir.join("milpa.kdl"),
        format!("name \"{name}\"\nkind \"library\"\n"),
    )
    .unwrap();
}

/// Build a trivial empty MockedFetcher + CaStore pair for tests that resolve a
/// workspace with no external deps.
fn empty_registry_and_store(
    tmp: &tempfile::TempDir,
) -> (crate::fetchers::MockedFetcher, crate::store::CaStore) {
    let mocked_dir = tmp.path().join("mocked-fetches");
    std::fs::create_dir_all(&mocked_dir).unwrap();
    let registry = crate::fetchers::MockedFetcher::new(&mocked_dir);
    let store = crate::store::CaStore::new(tmp.path().join(".cas"));
    (registry, store)
}

#[test]
fn s9b_atomicity_resolution_failure_leaves_manifest_unchanged() {
    // Atomicity guarantee: if loading the proposed workspace fails (member dir
    // doesn't exist → WS-MEMBER-DIR-MISSING), milpa.kdl is untouched.
    let d = tmp();
    let root = d.path();

    let member_a = root.join("member-a");
    write_member(&member_a, "member-a");
    write_workspace(root, &["member-a"]);

    let original_kdl = std::fs::read_to_string(root.join("milpa.kdl")).unwrap();

    let (registry, store) = empty_registry_and_store(&d);
    let err = apply_workspace_manifest_change(
        root,
        None, // no index
        &registry,
        None,  // no profile
        None,  // no prior lock
        milpa_solver::Strategy::default(),
        &store,
        false,
        |mut ws| {
            // Add a member whose directory does NOT exist — should fail.
            ws.members.push("ghost-does-not-exist".to_string());
            ws
        },
    )
    .unwrap_err();

    // The error code must be a WS-* topology error (not a resolution error).
    assert_eq!(err.code(), "WS-MEMBER-DIR-MISSING");

    // milpa.kdl must be byte-identical to what we started with.
    let after_kdl = std::fs::read_to_string(root.join("milpa.kdl")).unwrap();
    assert_eq!(
        after_kdl, original_kdl,
        "milpa.kdl was modified despite failure; atomicity ordering violated"
    );

    // No lock must have been written.
    assert!(
        !root.join("milpa.lock").exists(),
        "milpa.lock was written despite failure"
    );
}

#[test]
fn s9b_atomicity_existing_lock_unchanged_on_failure() {
    // An existing milpa.lock must NOT be overwritten when the mutation fails.
    let d = tmp();
    let root = d.path();

    let member_a = root.join("member-a");
    write_member(&member_a, "member-a");
    write_workspace(root, &["member-a"]);

    let prior_lock_text = "strategy maxver\n";
    std::fs::write(root.join("milpa.lock"), prior_lock_text).unwrap();

    let (registry, store) = empty_registry_and_store(&d);
    let _ = apply_workspace_manifest_change(
        root,
        None,
        &registry,
        None,
        None,
        milpa_solver::Strategy::default(),
        &store,
        false,
        |mut ws| {
            ws.members.push("ghost".to_string());
            ws
        },
    )
    .unwrap_err();

    let after_lock = std::fs::read_to_string(root.join("milpa.lock")).unwrap();
    assert_eq!(
        after_lock, prior_lock_text,
        "milpa.lock was overwritten despite failure"
    );
}

#[test]
fn s9b_happy_path_writes_manifest_and_lock() {
    // A valid mutation (adding an existing member) writes both milpa.kdl and milpa.lock.
    let d = tmp();
    let root = d.path();

    let member_a = root.join("member-a");
    let member_b = root.join("member-b");
    write_member(&member_a, "member-a");
    write_member(&member_b, "member-b");
    // Start with member-a only.
    write_workspace(root, &["member-a"]);

    let (registry, store) = empty_registry_and_store(&d);
    let (graph, wr) = apply_workspace_manifest_change(
        root,
        None,
        &registry,
        None,
        None,
        milpa_solver::Strategy::default(),
        &store,
        false,
        |mut ws| {
            ws.members.push("member-b".to_string());
            ws
        },
    )
    .unwrap();

    // WriteResult points at the manifest path.
    assert_eq!(wr.path, root.join("milpa.kdl"));

    // milpa.kdl now contains member-b.
    let kdl_text = std::fs::read_to_string(root.join("milpa.kdl")).unwrap();
    assert!(
        kdl_text.contains("\"member-b\""),
        "member-b missing from milpa.kdl: {kdl_text}"
    );

    // milpa.lock exists.
    assert!(
        root.join("milpa.lock").exists(),
        "milpa.lock must be written on success"
    );

    // graph has deps (member graph — no external deps but the call succeeded).
    let _ = graph;
}

#[test]
fn s9b_package_mutate_still_refuses_workspace() {
    // mutate_manifest_file (plain package path) still refuses a workspace doc.
    let d = tmp();
    let p = d.path().join("milpa.kdl");
    std::fs::write(&p, "workspace {\n    member \"pkg\"\n}\n").unwrap();
    assert_eq!(
        mutate_manifest_file(&p, identity).unwrap_err().code(),
        "MAN-MUTATE-WORKSPACE-REFUSED"
    );
}

#[test]
fn s9b_workspace_typed_path_not_refused() {
    // apply_workspace_manifest_change must NOT raise MAN-MUTATE-WORKSPACE-REFUSED.
    let d = tmp();
    let root = d.path();

    let member_a = root.join("member-a");
    write_member(&member_a, "member-a");
    write_workspace(root, &["member-a"]);

    let (registry, store) = empty_registry_and_store(&d);
    let result = apply_workspace_manifest_change(
        root,
        None,
        &registry,
        None,
        None,
        milpa_solver::Strategy::default(),
        &store,
        false,
        |ws| ws, // identity
    );
    match &result {
        Err(e) if e.code() == "MAN-MUTATE-WORKSPACE-REFUSED" => {
            panic!(
                "apply_workspace_manifest_change raised MAN-MUTATE-WORKSPACE-REFUSED; \
                 the workspace-typed path must be allowed to mutate workspace docs"
            );
        }
        _ => {} // Ok or any other error (unlikely given valid setup) is fine here.
    }
    result.unwrap(); // must succeed on a valid workspace.
}

#[test]
fn format_workspace_manifest_byte_identical_to_python_fixture() {
    // Byte-identity gate: the canonical serializer must emit the same bytes as
    // the Python impl produced for fixture-264. Read the fixture's expected output
    // and compare byte-for-byte.
    let fixture_expected = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../conformance/spec-v1/fixture-264-s9a-workspace-manifest-roundtrip/expected/milpa.kdl");
    let expected = match std::fs::read_to_string(&fixture_expected) {
        Ok(t) => t,
        Err(e) => panic!("cannot read fixture-264 expected/milpa.kdl: {e}"),
    };
    let fixture_input = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../conformance/spec-v1/fixture-264-s9a-workspace-manifest-roundtrip/milpa.kdl");
    let input = std::fs::read_to_string(&fixture_input).unwrap();
    let ws = match milpa_manifest::parse_document(&input).unwrap() {
        milpa_manifest::ManifestDoc::Workspace(w) => w,
        other => panic!("expected Workspace, got {other:?}"),
    };
    let produced = milpa_manifest::format_workspace_manifest(&ws);
    assert_eq!(
        produced, expected,
        "Rust serializer output differs from Python fixture-264 expected/milpa.kdl"
    );
}
