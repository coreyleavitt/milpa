//! Unit tests for the workspace member loader (S11a). The conformance corpus
//! drives the same WS-* codes end-to-end (fixtures 104/107/108/109/110/111).

use super::*;

/// Lay out a workspace at a fresh tempdir: root `milpa.kdl` text + a list of
/// `(relative_path, milpa_kdl_text_or_none)` members (None ⇒ create the dir but
/// no manifest; an absent entry ⇒ don't create the dir at all).
fn workspace_dir(root_kdl: &str, members: &[(&str, Option<&str>)]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("milpa.kdl"), root_kdl).unwrap();
    for (path, kdl) in members {
        let dir = tmp.path().join(path);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(text) = kdl {
            std::fs::write(dir.join("milpa.kdl"), text).unwrap();
        }
    }
    tmp
}

fn code(tmp: &tempfile::TempDir) -> &'static str {
    load_workspace(tmp.path()).unwrap_err().code()
}

#[test]
fn not_a_workspace_is_ws_not_a_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("milpa.kdl"),
        "name \"pkg\"\nkind \"library\"\n",
    )
    .unwrap();
    assert_eq!(code(&tmp), "WS-NOT-A-WORKSPACE");
}

#[test]
fn no_root_manifest_is_ws_no_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(code(&tmp), "WS-NO-MANIFEST");
}

#[test]
fn member_dot_is_rejected() {
    let tmp = workspace_dir("workspace {\n    member \".\"\n}\n", &[]);
    assert_eq!(code(&tmp), "WS-MEMBER-DOT");
}

#[test]
fn member_dir_missing() {
    // member "a" declared but no `a/` directory created.
    let tmp = workspace_dir("workspace {\n    member \"a\"\n}\n", &[]);
    assert_eq!(code(&tmp), "WS-MEMBER-DIR-MISSING");
}

#[test]
fn member_no_manifest() {
    let tmp = workspace_dir("workspace {\n    member \"a\"\n}\n", &[("a", None)]);
    assert_eq!(code(&tmp), "WS-MEMBER-NO-MANIFEST");
}

#[test]
fn member_is_workspace() {
    let tmp = workspace_dir(
        "workspace {\n    member \"a\"\n}\n",
        &[("a", Some("workspace {\n    member \"b\"\n}\n"))],
    );
    assert_eq!(code(&tmp), "WS-MEMBER-IS-WORKSPACE");
}

#[test]
fn member_has_overrides() {
    let tmp = workspace_dir(
        "workspace {\n    member \"a\"\n}\n",
        &[(
            "a",
            Some(
                "name \"liba\"\nkind \"library\"\noverrides {\n    \
                 pkg \"bar\" git=(url)\"https://e/bar.git\" ref=\"main\"\n}\n",
            ),
        )],
    );
    assert_eq!(code(&tmp), "WS-MEMBER-HAS-OVERRIDES");
}

#[test]
fn member_duplicate_name() {
    let tmp = workspace_dir(
        "workspace {\n    member \"a\"\n    member \"b\"\n}\n",
        &[
            ("a", Some("name \"dup\"\nkind \"library\"\n")),
            ("b", Some("name \"dup\"\nkind \"library\"\n")),
        ],
    );
    assert_eq!(code(&tmp), "WS-MEMBER-DUPLICATE-NAME");
}

#[test]
fn loads_a_valid_two_member_workspace() {
    let tmp = workspace_dir(
        "workspace {\n    member \"member-a\"\n    member \"member-b\"\n}\n",
        &[
            ("member-a", Some("name \"liba\"\nkind \"library\"\nsrc_dir \"src\"\n")),
            (
                "member-b",
                Some("name \"libb\"\nkind \"library\"\nsrc_dir \"src\"\ndeps {\n    member \"liba\"\n}\n"),
            ),
        ],
    );
    let w = load_workspace(tmp.path()).unwrap();
    assert_eq!(w.members.len(), 2);
    assert_eq!(w.members[0].name, "liba");
    assert_eq!(w.members[0].path, "member-a");
    assert_eq!(w.members[1].name, "libb");
    assert!(w.members[1].directory.ends_with("member-b"));
}
