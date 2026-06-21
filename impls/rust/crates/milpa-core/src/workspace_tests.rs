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

/// F18: Rust must also reject "./" with WS-MEMBER-DOT (not WS-MEMBER-PATH-ESCAPE).
#[test]
fn member_dot_slash_is_rejected_with_dot_code() {
    let tmp = workspace_dir("workspace {\n    member \"./\"\n}\n", &[]);
    assert_eq!(code(&tmp), "WS-MEMBER-DOT");
}

/// F16: A path traversal escaping the workspace root raises WS-MEMBER-PATH-ESCAPE.
#[test]
fn member_path_escape_is_rejected() {
    let tmp = workspace_dir("workspace {\n    member \"../../escape\"\n}\n", &[]);
    assert_eq!(code(&tmp), "WS-MEMBER-PATH-ESCAPE");
}

/// F16: The dot-check runs before the escape check: "." yields WS-MEMBER-DOT,
/// not WS-MEMBER-PATH-ESCAPE.
#[test]
fn dot_before_escape_check_ordering() {
    let tmp = workspace_dir("workspace {\n    member \".\"\n}\n", &[]);
    assert_eq!(code(&tmp), "WS-MEMBER-DOT");
}

/// R2-2: A member path "pkg/.." resolves lexically to the workspace root.
/// The inclusive containment check must NOT treat this as PATH-ESCAPE; it must
/// fall through to WS-MEMBER-IS-WORKSPACE (because root/milpa.kdl is a workspace).
///
/// Previously the old `is_under_root` returned false for equal-to-root (strict
/// `!=` guard), producing WS-MEMBER-PATH-ESCAPE.  After the fix it returns true
/// (inclusive `starts_with`), matching Python behavior.
#[test]
fn member_resolves_to_root_yields_is_workspace() {
    // "pkg/.." — lexically reduces to root; "pkg" dir may or may not exist.
    let tmp = workspace_dir("workspace {\n    member \"pkg/..\"\n}\n", &[]);
    assert_eq!(code(&tmp), "WS-MEMBER-IS-WORKSPACE");
}

/// R2-1: A member that is an existing symlink whose real target escapes the
/// workspace root raises WS-MEMBER-PATH-ESCAPE.
///
/// This requires filesystem support for symlinks.  Uses std::os::unix::fs::symlink.
#[test]
#[cfg(unix)]
fn member_symlink_escaping_root_yields_path_escape() {
    use std::os::unix::fs::symlink;

    // Layout:
    //   <tmp>/
    //     workspace-root/
    //       milpa.kdl      (workspace declaring member "symlink-member")
    //       symlink-member -> ../outside-root  (symlink)
    //     outside-root/    (real directory outside workspace-root)
    let outer = tempfile::tempdir().unwrap();
    let ws_root = outer.path().join("workspace-root");
    let outside = outer.path().join("outside-root");
    std::fs::create_dir_all(&ws_root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(
        outside.join("milpa.kdl"),
        "name \"escaped\"\nkind \"library\"\n",
    ).unwrap();
    std::fs::write(
        ws_root.join("milpa.kdl"),
        "workspace {\n    member \"symlink-member\"\n}\n",
    ).unwrap();
    // Create symlink: workspace-root/symlink-member -> ../outside-root
    symlink("../outside-root", ws_root.join("symlink-member")).unwrap();

    let result = load_workspace(&ws_root).unwrap_err();
    assert_eq!(result.code(), "WS-MEMBER-PATH-ESCAPE");
}

/// Dangling-symlink OUTSIDE root → WS-MEMBER-PATH-ESCAPE.
///
/// A member dir that is a symlink pointing to a nonexistent path OUTSIDE the
/// workspace root must yield WS-MEMBER-PATH-ESCAPE, not WS-MEMBER-DIR-MISSING.
/// Python's `resolve(strict=False)` follows the dangling link and resolves to
/// the (nonexistent) outside target; `is_relative_to(root)` is False →
/// WS-MEMBER-PATH-ESCAPE.  Rust must match: before this fix, `candidate.exists()`
/// returned false (stat follows the dead link) → fell to `normalize_lexically` →
/// treated the symlink as a plain dir → starts_with(root) true → WRONG slug.
#[test]
#[cfg(unix)]
fn dangling_symlink_outside_root_yields_path_escape() {
    use std::os::unix::fs::symlink;

    // Layout:
    //   <tmp>/
    //     workspace-root/
    //       milpa.kdl      (workspace declaring member "dangle-out")
    //       dangle-out -> ../../outside-nonexistent  (dangling: target absent)
    let outer = tempfile::tempdir().unwrap();
    let ws_root = outer.path().join("workspace-root");
    std::fs::create_dir_all(&ws_root).unwrap();
    std::fs::write(
        ws_root.join("milpa.kdl"),
        "workspace {\n    member \"dangle-out\"\n}\n",
    ).unwrap();
    // Create dangling symlink: target does NOT exist.
    symlink("../../outside-nonexistent", ws_root.join("dangle-out")).unwrap();
    // Confirm the target really is missing (so candidate.exists() returns false).
    assert!(!ws_root.join("dangle-out").exists(), "target must be absent for this test to be meaningful");

    let result = load_workspace(&ws_root).unwrap_err();
    assert_eq!(result.code(), "WS-MEMBER-PATH-ESCAPE");
}

/// Dangling-symlink INSIDE root → WS-MEMBER-DIR-MISSING (not PATH-ESCAPE).
///
/// When the dangling symlink's target resolves lexically to a path INSIDE the
/// workspace root (e.g. `link -> nonexistent-subdir`), the containment check
/// passes (not an escape) and the caller proceeds to the dir-existence check,
/// which sees a missing directory and raises WS-MEMBER-DIR-MISSING.
#[test]
#[cfg(unix)]
fn dangling_symlink_inside_root_yields_dir_missing() {
    use std::os::unix::fs::symlink;

    // Layout:
    //   <tmp>/
    //     workspace-root/
    //       milpa.kdl    (workspace declaring member "dangle-in")
    //       dangle-in -> nonexistent-inside  (dangling: target absent but INSIDE root)
    let outer = tempfile::tempdir().unwrap();
    let ws_root = outer.path().join("workspace-root");
    std::fs::create_dir_all(&ws_root).unwrap();
    std::fs::write(
        ws_root.join("milpa.kdl"),
        "workspace {\n    member \"dangle-in\"\n}\n",
    ).unwrap();
    symlink("nonexistent-inside", ws_root.join("dangle-in")).unwrap();
    assert!(!ws_root.join("dangle-in").exists(), "target must be absent");

    let result = load_workspace(&ws_root).unwrap_err();
    assert_eq!(result.code(), "WS-MEMBER-DIR-MISSING");
}

/// Mid-path dangling symlink: member "danglink/pkg" where "danglink" is a
/// dangling symlink pointing outside the workspace root.
///
/// Python: `(root / "danglink/pkg").resolve(strict=False)` reads danglink's
/// target, resolves it relative to root → outside path →
/// `is_relative_to(root)` False → WS-MEMBER-PATH-ESCAPE.
///
/// Rust before the fix: `symlink_metadata("danglink/pkg")` fails (parent
/// dangling) → ancestor-walk finds `danglink` → `ancestor.canonicalize()`
/// fails (dangling) → `normalize_lexically("root/danglink")` (does NOT follow
/// link) → `root/danglink/pkg` starts_with(root) True → WS-MEMBER-DIR-MISSING.
/// WRONG slug — divergence from Python.
///
/// After the fix: ancestor-walk finds `danglink` → `best_effort_resolve(danglink)`
/// → dangling branch → reads link target `../../outside-nonexistent` → resolves
/// outside root → `outside/pkg` starts_with(root) False → WS-MEMBER-PATH-ESCAPE.
/// CORRECT — parity with Python.
#[test]
#[cfg(unix)]
fn mid_path_dangling_symlink_outside_root_yields_path_escape() {
    use std::os::unix::fs::symlink;

    // Layout:
    //   <outer>/
    //     workspace-root/
    //       milpa.kdl      (workspace declaring member "danglink/pkg")
    //       danglink -> ../../outside-nonexistent  (dangling: target absent)
    //   (no "outside-nonexistent" directory — the link is dangling)
    let outer = tempfile::tempdir().unwrap();
    let ws_root = outer.path().join("workspace-root");
    std::fs::create_dir_all(&ws_root).unwrap();
    std::fs::write(
        ws_root.join("milpa.kdl"),
        "workspace {\n    member \"danglink/pkg\"\n}\n",
    ).unwrap();
    // Create dangling symlink at ws_root/danglink → ../../outside-nonexistent
    // The target does NOT exist; danglink/pkg is a mid-path dangling case.
    symlink("../../outside-nonexistent", ws_root.join("danglink")).unwrap();
    // Confirm the member path is truly unreachable (stat fails on danglink/pkg).
    assert!(!ws_root.join("danglink").exists(), "danglink target must be absent");
    assert!(!ws_root.join("danglink/pkg").exists(), "mid-path must be unreachable");

    let result = load_workspace(&ws_root).unwrap_err();
    assert_eq!(
        result.code(),
        "WS-MEMBER-PATH-ESCAPE",
        "mid-path dangling symlink pointing outside root must yield \
         WS-MEMBER-PATH-ESCAPE (not WS-MEMBER-DIR-MISSING) — got {:?}",
        result.code()
    );
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

/// Symlinked workspace root: member "pkg/.." resolves to root → WS-MEMBER-IS-WORKSPACE.
///
/// Scenario: the workspace root is accessed via a symlink path (like macOS /tmp → /private/tmp,
/// or any dev setup using symlinked project directories).  With the old branch-(c) path,
/// `is_under_root` would:
///   - canonicalize root → <realroot>   (follows symlink)
///   - normalize_lexically(link/pkg/..) → <link>   (does NOT follow symlink)
///   - <link>.starts_with(<realroot>) → false → WS-MEMBER-PATH-ESCAPE  (WRONG)
///
/// After the fix (best_effort_resolve), the non-existent "pkg/.." suffix is appended
/// to the canonicalized link parent → <realroot>/pkg/.. → normalize lexically → <realroot>
/// → starts_with(<realroot>) → true → WS-MEMBER-IS-WORKSPACE  (CORRECT).
#[test]
#[cfg(unix)]
fn member_resolves_to_root_via_symlinked_ws_root_yields_is_workspace() {
    use std::os::unix::fs::symlink;

    // Layout:
    //   <outer>/
    //     realroot/
    //       milpa.kdl    (workspace declaring member "pkg/..")
    //     link -> realroot   (symlink)
    let outer = tempfile::tempdir().unwrap();
    let realroot = outer.path().join("realroot");
    std::fs::create_dir_all(&realroot).unwrap();
    std::fs::write(
        realroot.join("milpa.kdl"),
        "workspace {\n    member \"pkg/..\"\n}\n",
    ).unwrap();
    let link = outer.path().join("link");
    symlink("realroot", &link).unwrap();

    // Load workspace via the SYMLINK path, not the real path.
    // "pkg/.." lexically resolves to the workspace root.
    // Python: (link / "pkg/..").resolve() → realroot  (follows symlink through link)
    // Rust after fix: best_effort_resolve(link/pkg/..) → canonicalize(link) + normalize(..)
    //                                                   = realroot
    // Result must be WS-MEMBER-IS-WORKSPACE (not WS-MEMBER-PATH-ESCAPE).
    let result = load_workspace(&link).unwrap_err();
    assert_eq!(result.code(), "WS-MEMBER-IS-WORKSPACE",
        "loading workspace via symlinked root with member 'pkg/..' should yield \
         WS-MEMBER-IS-WORKSPACE, not PATH-ESCAPE — got code {:?}", result.code());
}

/// Symlinked workspace root, via load_workspace_from_manifest: member "pkg/.." → WS-MEMBER-IS-WORKSPACE.
///
/// Mirrors the existing `member_resolves_to_root_via_symlinked_ws_root_yields_is_workspace`
/// test above, but exercises `load_workspace_from_manifest` instead of `load_workspace`.
/// Python already tests both paths (test_ws_security_parity.py:
/// `test_member_resolves_to_root_via_symlinked_ws_root_from_manifest`); this closes the
/// corresponding Rust gap.
#[test]
#[cfg(unix)]
fn member_resolves_to_root_via_symlinked_ws_root_from_manifest_yields_is_workspace() {
    use std::os::unix::fs::symlink;

    // Layout:
    //   <outer>/
    //     realroot/
    //       milpa.kdl    (workspace declaring member "pkg/..")
    //     link -> realroot   (symlink)
    let outer = tempfile::tempdir().unwrap();
    let realroot = outer.path().join("realroot");
    std::fs::create_dir_all(&realroot).unwrap();
    std::fs::write(
        realroot.join("milpa.kdl"),
        "workspace {\n    member \"pkg/..\"\n}\n",
    ).unwrap();
    let link = outer.path().join("link");
    symlink("realroot", &link).unwrap();

    // Construct the Workspace struct directly (bypassing manifest file read).
    let parsed = milpa_manifest::Workspace {
        members: vec!["pkg/..".to_string()],
        overrides: vec![],
        flags: vec![],
        name: None,
    };

    // Load workspace from the SYMLINK path with a pre-parsed manifest.
    // "pkg/.." lexically resolves to the workspace root — should be WS-MEMBER-IS-WORKSPACE.
    let result = load_workspace_from_manifest(&link, &parsed).unwrap_err();
    assert_eq!(
        result.code(),
        "WS-MEMBER-IS-WORKSPACE",
        "load_workspace_from_manifest via symlinked root with member 'pkg/..' \
         should yield WS-MEMBER-IS-WORKSPACE, not PATH-ESCAPE — got {:?}",
        result.code()
    );
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
