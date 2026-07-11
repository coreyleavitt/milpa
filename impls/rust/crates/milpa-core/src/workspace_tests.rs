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

/// Dangling-symlink OUTSIDE root → WS-MEMBER-DIR-MISSING (spec §11.0, S4, #168).
///
/// A member dir that is a dangling symlink (target nonexistent, outside the root)
/// yields WS-MEMBER-DIR-MISSING — NOT WS-MEMBER-PATH-ESCAPE.
/// spec §11.0: `metadata()` (stat) is used to determine existence; stat fails for
/// a dangling symlink, so the longest stat-existing prefix is the parent directory.
/// The resolved candidate is `canonical_root/dangle-out` → inside root → no escape
/// → dir-existence check fails → WS-MEMBER-DIR-MISSING.
/// Conformance corpus: fixture-310-ws-member-dangling-symlink.
#[test]
#[cfg(unix)]
fn dangling_symlink_outside_root_yields_dir_missing() {
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
    assert!(!ws_root.join("dangle-out").exists(), "target must be absent for this test to be meaningful");

    let result = load_workspace(&ws_root).unwrap_err();
    assert_eq!(result.code(), "WS-MEMBER-DIR-MISSING");
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

/// Mid-path dangling symlink → WS-MEMBER-DIR-MISSING (spec §11.0, S4, #168).
///
/// Member "danglink/pkg" where "danglink" is a dangling symlink outside the root.
/// spec §11.0: `metadata()` (stat) fails for "danglink" → not in the stat-existing
/// prefix → longest prefix is `workspace-root` → result is
/// `canonical_root/danglink/pkg` → inside root → no escape → WS-MEMBER-DIR-MISSING.
///
/// (Before S4 the ancestor-walk used `symlink_metadata` (lstat) which found
/// "danglink" as the longest existing prefix → `best_effort_resolve(danglink)` →
/// dangling branch → followed the link target outside the root → PATH-ESCAPE.
/// The new stat-based walk skips dangling symlinks entirely.)
#[test]
#[cfg(unix)]
fn mid_path_dangling_symlink_outside_root_yields_dir_missing() {
    use std::os::unix::fs::symlink;

    // Layout:
    //   <outer>/
    //     workspace-root/
    //       milpa.kdl      (workspace declaring member "danglink/pkg")
    //       danglink -> ../../outside-nonexistent  (dangling: target absent)
    let outer = tempfile::tempdir().unwrap();
    let ws_root = outer.path().join("workspace-root");
    std::fs::create_dir_all(&ws_root).unwrap();
    std::fs::write(
        ws_root.join("milpa.kdl"),
        "workspace {\n    member \"danglink/pkg\"\n}\n",
    ).unwrap();
    symlink("../../outside-nonexistent", ws_root.join("danglink")).unwrap();
    assert!(!ws_root.join("danglink").exists(), "danglink target must be absent");
    assert!(!ws_root.join("danglink/pkg").exists(), "mid-path must be unreachable");

    let result = load_workspace(&ws_root).unwrap_err();
    assert_eq!(
        result.code(),
        "WS-MEMBER-DIR-MISSING",
        "mid-path dangling symlink treated as non-existent (spec §11.0) — got {:?}",
        result.code()
    );
}

/// Cyclic (self-referential) symlink member → WS-MEMBER-DIR-MISSING (spec §11.0, S4, #168).
///
/// A member that is a self-referential symlink (`link-self → link-self`) causes stat
/// to fail with ELOOP.  spec §11.0: stat-based ancestor walk → longest stat-existing
/// prefix = workspace-root → result is inside root → no escape → WS-MEMBER-DIR-MISSING.
/// Conformance corpus: fixture-309-ws-member-cyclic-symlink.
#[test]
#[cfg(unix)]
fn cyclic_symlink_member_yields_dir_missing() {
    use std::os::unix::fs::symlink;

    let outer = tempfile::tempdir().unwrap();
    let ws_root = outer.path().join("workspace-root");
    std::fs::create_dir_all(&ws_root).unwrap();
    std::fs::write(
        ws_root.join("milpa.kdl"),
        "workspace {\n    member \"link-self\"\n}\n",
    ).unwrap();
    // Self-referential symlink: link-self → link-self
    symlink("link-self", ws_root.join("link-self")).unwrap();
    assert!(!ws_root.join("link-self").exists(), "cyclic symlink must not stat-exist");

    let result = load_workspace(&ws_root).unwrap_err();
    assert_eq!(
        result.code(),
        "WS-MEMBER-DIR-MISSING",
        "cyclic symlink member must yield WS-MEMBER-DIR-MISSING (spec §11.0) — got {:?}",
        result.code()
    );
}

/// Two-hop cyclic symlink (a→b, b→a) member → WS-MEMBER-DIR-MISSING (spec §11.0).
///
/// Exercises the ELOOP stat failure path for multi-hop cycles.
#[test]
#[cfg(unix)]
fn two_hop_cyclic_symlink_member_yields_dir_missing() {
    use std::os::unix::fs::symlink;

    let outer = tempfile::tempdir().unwrap();
    let ws_root = outer.path().join("workspace-root");
    std::fs::create_dir_all(&ws_root).unwrap();
    std::fs::write(
        ws_root.join("milpa.kdl"),
        "workspace {\n    member \"link-a\"\n}\n",
    ).unwrap();
    symlink("link-b", ws_root.join("link-a")).unwrap();
    symlink("link-a", ws_root.join("link-b")).unwrap();
    assert!(!ws_root.join("link-a").exists(), "cyclic symlink must not stat-exist");

    let result = load_workspace(&ws_root).unwrap_err();
    assert_eq!(result.code(), "WS-MEMBER-DIR-MISSING");
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
        ..Default::default()
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

// ---------------------------------------------------------------------------
// S8: workspace index-trust root-authority tests
// (RFC registry-trust-federation §6.4a, spec/registry-protocol.md §3.4.7)
//
// Replaces the deleted max-merge + conflicting-signers matrix: index-trust
// is now declared ONLY on the workspace ROOT (a single value, no merge). A
// member declaring any of index-trust / index-trust-signer /
// index-trust-bundle is a hard error (WS-INDEX-TRUST-ON-MEMBER), raised at
// workspace-load time before any index fetch.
// ---------------------------------------------------------------------------

use milpa_manifest::TrustPolicy;

/// No index-trust anywhere (root or member) → the workspace's effective
/// policy defaults to Warn, same as the package-manifest field default.
#[test]
fn workspace_no_index_trust_anywhere_defaults_to_warn() {
    let tmp = workspace_dir(
        "workspace {\n    member \"sub\"\n}\n",
        &[("sub", Some("name \"sub\"\n"))],
    );
    let ws = load_workspace(tmp.path()).unwrap();
    assert_eq!(ws.index_trust_policy, TrustPolicy::Warn);
    assert_eq!(ws.index_trust_signer, None);
    assert_eq!(ws.index_trust_bundle, None);
}

/// The workspace ROOT declaring `index-trust "strict"` alongside the
/// `workspace { }` block IS the effective policy — no merge, member is plain.
#[test]
fn workspace_root_declares_index_trust_strict_is_effective_policy() {
    let tmp = workspace_dir(
        "index-trust \"strict\"\nworkspace {\n    member \"sub\"\n}\n",
        &[("sub", Some("name \"sub\"\nkind \"library\"\n"))],
    );
    let ws = load_workspace(tmp.path()).unwrap();
    assert_eq!(ws.index_trust_policy, TrustPolicy::Strict);
}

/// The workspace ROOT can declare `index-trust "off"` — a manifest-level path
/// to an effective `off` for the whole workspace, structurally unreachable
/// under the old max-merge design (spec §3.4.7).
#[test]
fn workspace_root_declares_index_trust_off_is_effective_policy() {
    let tmp = workspace_dir(
        "index-trust \"off\"\nworkspace {\n    member \"sub\"\n}\n",
        &[("sub", Some("name \"sub\"\nkind \"library\"\n"))],
    );
    let ws = load_workspace(tmp.path()).unwrap();
    assert_eq!(ws.index_trust_policy, TrustPolicy::Off);
}

/// The workspace ROOT's `index-trust-signer` / `index-trust-bundle` flow
/// straight through to the LoadedWorkspace — no merge, no member scan.
#[test]
fn workspace_root_index_trust_signer_and_bundle_flow_through() {
    let signer = "https://github.com/org/repo/.github/workflows/pub.yaml@refs/heads/main";
    let tmp = workspace_dir(
        &format!(
            "index-trust-signer \"{signer}\"\nindex-trust-bundle \"/path/to/bundle.json\"\n\
             workspace {{\n    member \"sub\"\n}}\n"
        ),
        &[("sub", Some("name \"sub\"\nkind \"library\"\n"))],
    );
    let ws = load_workspace(tmp.path()).unwrap();
    assert_eq!(ws.index_trust_signer.as_deref(), Some(signer));
    assert_eq!(ws.index_trust_bundle.as_deref(), Some("/path/to/bundle.json"));
}

/// A member declaring `index-trust "strict"` is a hard error — WS-INDEX-TRUST-ON-MEMBER
/// — raised BEFORE any index fetch, even when the root declares nothing.
#[test]
fn member_declaring_index_trust_is_ws_index_trust_on_member() {
    let tmp = workspace_dir(
        "workspace {\n    member \"sub\"\n}\n",
        &[("sub", Some("name \"sub\"\nkind \"library\"\nindex-trust \"strict\"\n"))],
    );
    let result = load_workspace(tmp.path()).unwrap_err();
    assert_eq!(result.code(), "WS-INDEX-TRUST-ON-MEMBER");
}

/// A member declaring `index-trust "warn"` — the SAME as the default value —
/// still errors: the rule is about WHERE the field is declared, not what
/// value it holds (spec §3.4.7 member-declaration-error clause).
#[test]
fn member_declaring_index_trust_warn_default_value_is_still_ws_index_trust_on_member() {
    let tmp = workspace_dir(
        "workspace {\n    member \"sub\"\n}\n",
        &[("sub", Some("name \"sub\"\nkind \"library\"\nindex-trust \"warn\"\n"))],
    );
    let result = load_workspace(tmp.path()).unwrap_err();
    assert_eq!(result.code(), "WS-INDEX-TRUST-ON-MEMBER");
}

/// A member declaring `index-trust-signer` (without `index-trust` itself) is
/// also a hard error — all three fields are root-only.
#[test]
fn member_declaring_index_trust_signer_is_ws_index_trust_on_member() {
    let tmp = workspace_dir(
        "workspace {\n    member \"sub\"\n}\n",
        &[(
            "sub",
            Some(
                "name \"sub\"\nkind \"library\"\n\
                 index-trust-signer \"https://github.com/org/repo/.github/workflows/publish.yaml@refs/heads/main\"\n",
            ),
        )],
    );
    let result = load_workspace(tmp.path()).unwrap_err();
    assert_eq!(result.code(), "WS-INDEX-TRUST-ON-MEMBER");
}

/// A member declaring `index-trust-bundle` is also a hard error.
#[test]
fn member_declaring_index_trust_bundle_is_ws_index_trust_on_member() {
    let tmp = workspace_dir(
        "workspace {\n    member \"sub\"\n}\n",
        &[(
            "sub",
            Some("name \"sub\"\nkind \"library\"\nindex-trust-bundle \"/path/to/bundle.json\"\n"),
        )],
    );
    let result = load_workspace(tmp.path()).unwrap_err();
    assert_eq!(result.code(), "WS-INDEX-TRUST-ON-MEMBER");
}

// ---------------------------------------------------------------------------
// P3a (rfc-per-entry-attestation.md §4): entry-trust root-authority
// validation — mirrors the index-trust tests above. Like index-history,
// entry-trust has no signer/bundle sub-fields (it gates per-entry
// attestation checking, not a Sigstore verification identity), so this
// axis is a single-node mirror.
// ---------------------------------------------------------------------------

/// A member declaring `entry-trust "strict"` is a hard error —
/// WS-ENTRY-TRUST-ON-MEMBER — raised BEFORE any resolve, even when the root
/// declares nothing.
#[test]
fn member_declaring_entry_trust_is_ws_entry_trust_on_member() {
    let tmp = workspace_dir(
        "workspace {\n    member \"sub\"\n}\n",
        &[("sub", Some("name \"sub\"\nkind \"library\"\nentry-trust \"strict\"\n"))],
    );
    let result = load_workspace(tmp.path()).unwrap_err();
    assert_eq!(result.code(), "WS-ENTRY-TRUST-ON-MEMBER");
}

/// A member declaring `entry-trust "warn"` — the SAME as the default
/// value — still errors: the rule is about WHERE the field is declared,
/// not what value it holds.
#[test]
fn member_declaring_entry_trust_warn_default_value_is_still_ws_entry_trust_on_member() {
    let tmp = workspace_dir(
        "workspace {\n    member \"sub\"\n}\n",
        &[("sub", Some("name \"sub\"\nkind \"library\"\nentry-trust \"warn\"\n"))],
    );
    let result = load_workspace(tmp.path()).unwrap_err();
    assert_eq!(result.code(), "WS-ENTRY-TRUST-ON-MEMBER");
}

// ---------------------------------------------------------------------------
// A3 (rfc-registry-append-only.md §2): index-history root-authority
// validation — mirrors the index-trust / entry-trust tests above.
// ---------------------------------------------------------------------------

/// The workspace root MAY declare `index-history`; it becomes the effective
/// policy for the whole workspace invocation.
#[test]
fn workspace_root_index_history_flows_through() {
    let tmp = workspace_dir(
        "index-history \"strict\"\nworkspace {\n    member \"sub\"\n}\n",
        &[("sub", Some("name \"sub\"\nkind \"library\"\n"))],
    );
    let ws = load_workspace(tmp.path()).unwrap();
    assert_eq!(ws.index_history_policy, milpa_manifest::TrustPolicy::Strict);
}

/// A member declaring `index-history "strict"` is a hard error —
/// WS-INDEX-HISTORY-ON-MEMBER — raised BEFORE any index fetch, even when
/// the root declares nothing.
#[test]
fn member_declaring_index_history_is_ws_index_history_on_member() {
    let tmp = workspace_dir(
        "workspace {\n    member \"sub\"\n}\n",
        &[("sub", Some("name \"sub\"\nkind \"library\"\nindex-history \"strict\"\n"))],
    );
    let result = load_workspace(tmp.path()).unwrap_err();
    assert_eq!(result.code(), "WS-INDEX-HISTORY-ON-MEMBER");
}

/// A member declaring `index-history "warn"` — the SAME as the default
/// value — still errors: the rule is about WHERE the field is declared,
/// not what value it holds.
#[test]
fn member_declaring_index_history_warn_default_value_is_still_ws_index_history_on_member() {
    let tmp = workspace_dir(
        "workspace {\n    member \"sub\"\n}\n",
        &[("sub", Some("name \"sub\"\nkind \"library\"\nindex-history \"warn\"\n"))],
    );
    let result = load_workspace(tmp.path()).unwrap_err();
    assert_eq!(result.code(), "WS-INDEX-HISTORY-ON-MEMBER");
}

/// Two members, one declaring index-trust — still errors (fires on the first
/// offending member encountered; two members previously "agreeing" is no
/// longer a legal escape hatch under the root-authority model).
#[test]
fn two_members_one_declaring_index_trust_is_ws_index_trust_on_member() {
    let tmp = workspace_dir(
        "workspace {\n    member \"a\"\n    member \"b\"\n}\n",
        &[
            ("a", Some("name \"a\"\nkind \"library\"\n")),
            ("b", Some("name \"b\"\nkind \"library\"\nindex-trust \"strict\"\n")),
        ],
    );
    let result = load_workspace(tmp.path()).unwrap_err();
    assert_eq!(result.code(), "WS-INDEX-TRUST-ON-MEMBER");
}

/// load_workspace_from_manifest (the in-memory mutation path) enforces the
/// same member-declaration check as load_workspace.
#[test]
fn load_workspace_from_manifest_also_raises_ws_index_trust_on_member() {
    let tmp = tempfile::tempdir().unwrap();
    let sub_dir = tmp.path().join("sub");
    std::fs::create_dir_all(&sub_dir).unwrap();
    std::fs::write(
        sub_dir.join("milpa.kdl"),
        "name \"sub\"\nkind \"library\"\nindex-trust \"strict\"\n",
    )
    .unwrap();
    let parsed = milpa_manifest::Workspace {
        members: vec!["sub".to_string()],
        overrides: vec![],
        flags: vec![],
        name: None,
        ..Default::default()
    };
    let result = load_workspace_from_manifest(tmp.path(), &parsed).unwrap_err();
    assert_eq!(result.code(), "WS-INDEX-TRUST-ON-MEMBER");
}

// ---------------------------------------------------------------------------
// RD-H2: load_workspace_with_member_override must re-validate the FULL
// (post-substitution) member list, not just the substituted member.
// ---------------------------------------------------------------------------

/// `LoadedWorkspace`'s fields are public, so it is technically possible for a
/// caller to hand-assemble (or hold a stale/tampered copy of) one that never
/// went through `load_workspace`'s validation. `load_workspace_with_member_override`
/// must not trust its input: even when the member being overridden is
/// perfectly legal, if ANOTHER member in the list already (illegally) carries
/// an index-trust declaration, the override must still raise
/// `WS-INDEX-TRUST-ON-MEMBER` rather than silently constructing an invalid
/// `LoadedWorkspace`.
#[test]
fn override_revalidates_other_members_not_just_the_substituted_one() {
    let tmp = workspace_dir(
        "workspace {\n    member \"a\"\n    member \"b\"\n}\n",
        &[
            ("a", Some("name \"a\"\nkind \"library\"\n")),
            ("b", Some("name \"b\"\nkind \"library\"\n")),
        ],
    );
    let ws = load_workspace(tmp.path()).unwrap(); // legal at load time

    // Simulate a member that is (illegally) carrying an index-trust
    // declaration in memory — e.g. a caller that built/held a LoadedWorkspace
    // without going through load_workspace's validation.
    let mut tampered = ws.clone();
    tampered.members[0].manifest.index_trust_policy_explicit = true;

    // Propose a harmless, unrelated change to member "b" — the member being
    // overridden is NOT the illegal one.
    let proposed_b = match milpa_manifest::parse_document("name \"b\"\nkind \"library\"\n").unwrap() {
        milpa_manifest::ManifestDoc::Package(m) => m,
        other => panic!("expected package, got {other:?}"),
    };

    let member_b_dir = tampered.members[1].directory.clone();
    let result =
        load_workspace_with_member_override(&tampered, &member_b_dir, proposed_b).unwrap_err();
    assert_eq!(result.code(), "WS-INDEX-TRUST-ON-MEMBER");
}

/// The happy path: overriding a member with a legal proposed manifest, in an
/// otherwise-legal workspace, succeeds and the substitution takes effect.
#[test]
fn override_succeeds_when_all_members_legal() {
    let tmp = workspace_dir(
        "workspace {\n    member \"a\"\n    member \"b\"\n}\n",
        &[
            ("a", Some("name \"a\"\nkind \"library\"\n")),
            ("b", Some("name \"b\"\nkind \"library\"\n")),
        ],
    );
    let ws = load_workspace(tmp.path()).unwrap();
    let proposed_b = match milpa_manifest::parse_document("name \"b\"\nkind \"application\"\n").unwrap()
    {
        milpa_manifest::ManifestDoc::Package(m) => m,
        other => panic!("expected package, got {other:?}"),
    };
    let member_b_dir = ws.members[1].directory.clone();
    let result = load_workspace_with_member_override(&ws, &member_b_dir, proposed_b).unwrap();
    assert_eq!(result.members[1].manifest.kind, "application");
    assert_eq!(result.members[0].manifest.kind, "library");
}

/// A `member_dir` that matches none of the workspace's declared members
/// raises `WS-MEMBER-DIR-MISSING` rather than silently no-op'ing.
#[test]
fn override_unknown_member_dir_raises_member_dir_missing() {
    let tmp = workspace_dir(
        "workspace {\n    member \"a\"\n}\n",
        &[("a", Some("name \"a\"\nkind \"library\"\n"))],
    );
    let ws = load_workspace(tmp.path()).unwrap();
    let nonmember = tmp.path().join("not-a-member");
    let proposed = match milpa_manifest::parse_document("name \"x\"\nkind \"library\"\n").unwrap() {
        milpa_manifest::ManifestDoc::Package(m) => m,
        other => panic!("expected package, got {other:?}"),
    };
    let result = load_workspace_with_member_override(&ws, &nonmember, proposed).unwrap_err();
    assert_eq!(result.code(), "WS-MEMBER-DIR-MISSING");
}
