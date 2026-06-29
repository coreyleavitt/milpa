//! Unit tests for the single-package frozen path (S10). Each FROZEN-* code is
//! exercised here; the conformance corpus drives the same codes end-to-end via
//! the harness `cmd=frozen` (fixtures 078–083, 106, 114).

use super::*;
use milpa_manifest::{Dep, Manifest, NamedDep};
use milpa_types::{LockedDep, Lockfile, ProvenanceRecord, LOCKFILE_SCHEMA_VERSION};

fn manifest(deps: Vec<Dep>) -> Manifest {
    Manifest {
        name: Some("myapp".into()),
        kind: "application".into(),
        src_dir: String::new(),
        deps,
        dev_deps: Vec::new(),
        overrides: Vec::new(),
        flags: Vec::new(),
        self_mirrors: Vec::new(),
        cas_dir: String::new(),
        spec_version: 1,
        spec_version_explicit: false,
        attestation_policy: milpa_manifest::AttestationPolicy::Permissive,
        optional_auto_flags: std::collections::BTreeSet::new(),
    }
}

fn named(name: &str, constraint: Option<&str>) -> Dep {
    Dep::Named(NamedDep {
        name: name.into(),
        namespace: None,
        constraint: constraint.map(str::to_string),
        parsed_constraint: constraint.map(|c| {
            milpa_solver::VersionSet::from_constraint(Some(c))
                .expect("test constraint must be valid")
        }),
        flag_requests: Vec::new(),
        optional: false,
        predicates: Vec::new(),
    })
}

fn lock(strategy: &str, deps: Vec<LockedDep>) -> Lockfile {
    Lockfile {
        version: LOCKFILE_SCHEMA_VERSION,
        strategy: strategy.into(),
        deps,
    }
}

fn locked(name: &str, version: &str, identity: Option<&str>, prov: ProvenanceRecord) -> LockedDep {
    LockedDep {
        name: name.into(),
        namespace: None,
        identity: identity.map(str::to_string),
        version: version.into(),
        src_dir: "src".into(),
        requires: vec![],
        provenances: vec![prov],
        active_flags: vec![],
        dep_decl: None,
        cond_requires: vec![],
        aliases: vec![],
    }
}

fn git_rec() -> ProvenanceRecord {
    ProvenanceRecord::Git {
        url: "https://e/foo.git".into(),
        ref_spec: Some("main".into()),
        commit_sha: Some("abcdef1234567890abcdef1234567890abcdef12".into()),
        origin: "observed".into(),
        submodule_shas: vec![],
    }
}

/// A fresh store + the identity of a small admitted tree, so `link_external`
/// succeeds for the dep named `foo`.
fn store_with_foo(root: &std::path::Path) -> (CaStore, String) {
    let store = CaStore::new(root.join(".cas"));
    let src = root.join("seed");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("foo.nim"), b"# foo").unwrap();
    let identity = crate::compute_content_hash(&src).unwrap();
    store.admit(&src, &identity).unwrap();
    (store, identity)
}

fn deps_dir(tmp: &tempfile::TempDir) -> std::path::PathBuf {
    tmp.path().join("_deps")
}

#[test]
fn strategy_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let store = CaStore::new(tmp.path().join(".cas"));
    // default request is maxver; lockfile says minver.
    let err = resolve_frozen(
        &manifest(vec![]),
        &lock("minver", vec![]),
        &store,
        &deps_dir(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "FROZEN-STRATEGY-MISMATCH");
}

#[test]
fn manifest_dep_not_in_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let store = CaStore::new(tmp.path().join(".cas"));
    let err = resolve_frozen(
        &manifest(vec![named("foo", None)]),
        &lock("maxver", vec![]),
        &store,
        &deps_dir(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "FROZEN-MANIFEST-DEP-NOT-IN-LOCK");
}

#[test]
fn constraint_unsatisfied() {
    let tmp = tempfile::tempdir().unwrap();
    let store = CaStore::new(tmp.path().join(".cas"));
    let lf = lock(
        "maxver",
        vec![locked("foo", "1.0.0", Some("dag-sha256:00"), git_rec())],
    );
    let err = resolve_frozen(
        &manifest(vec![named("foo", Some(">= 2.0.0"))]),
        &lf,
        &store,
        &deps_dir(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "FROZEN-CONSTRAINT-UNSATISFIED");
}

#[test]
fn locked_version_unparseable() {
    let tmp = tempfile::tempdir().unwrap();
    let store = CaStore::new(tmp.path().join(".cas"));
    let lf = lock(
        "maxver",
        vec![locked("foo", "not-a-version", Some("dag-sha256:00"), git_rec())],
    );
    let err = resolve_frozen(
        &manifest(vec![named("foo", Some(">= 1.0.0"))]),
        &lf,
        &store,
        &deps_dir(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "FROZEN-LOCKED-VERSION-UNPARSEABLE");
}

#[test]
fn member_dep_bails() {
    let tmp = tempfile::tempdir().unwrap();
    let store = CaStore::new(tmp.path().join(".cas"));
    let lf = lock(
        "maxver",
        vec![locked(
            "liba",
            "0.0.1",
            Some("dag-sha256:00"),
            ProvenanceRecord::Member {
                name: "liba".into(),
                origin: "observed".into(),
            },
        )],
    );
    let err = resolve_frozen(&manifest(vec![]), &lf, &store, &deps_dir(&tmp)).unwrap_err();
    assert_eq!(err.code(), "FROZEN-MEMBER-DEP");
}

#[test]
fn local_dep_bails() {
    let tmp = tempfile::tempdir().unwrap();
    let store = CaStore::new(tmp.path().join(".cas"));
    let lf = lock(
        "maxver",
        vec![locked(
            "foo",
            "0.0.1",
            Some("dag-sha256:00"),
            ProvenanceRecord::Local {
                path: "../foo".into(),
                origin: "observed".into(),
            },
        )],
    );
    let err = resolve_frozen(&manifest(vec![]), &lf, &store, &deps_dir(&tmp)).unwrap_err();
    assert_eq!(err.code(), "FROZEN-LOCAL-DEP");
}

#[test]
fn identity_not_in_store() {
    let tmp = tempfile::tempdir().unwrap();
    let store = CaStore::new(tmp.path().join(".cas"));
    let lf = lock(
        "maxver",
        vec![locked(
            "foo",
            "0.0.1",
            Some("dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"),
            git_rec(),
        )],
    );
    let err = resolve_frozen(&manifest(vec![]), &lf, &store, &deps_dir(&tmp)).unwrap_err();
    assert_eq!(err.code(), "FROZEN-IDENTITY-NOT-IN-STORE");
}

// ---------------------------------------------------------------------------
// Workspace frozen path tests (fixtures 085, 086)
// ---------------------------------------------------------------------------

/// Build a minimal workspace on disk: root milpa.kdl with one member, and the
/// member directory with its own milpa.kdl. Returns (tmp, loaded_workspace).
fn make_workspace_with_member(
    member_name: &str,
    member_kdl: &str,
) -> (tempfile::TempDir, crate::workspace::LoadedWorkspace) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(
        root.join("milpa.kdl"),
        format!("workspace {{\n    member \"{member_name}\"\n}}\n"),
    )
    .unwrap();
    let member_dir = root.join(member_name);
    std::fs::create_dir_all(&member_dir).unwrap();
    std::fs::write(member_dir.join("milpa.kdl"), member_kdl).unwrap();
    let ws = crate::workspace::load_workspace(root).unwrap();
    (tmp, ws)
}

#[test]
fn workspace_frozen_member_not_in_workspace() {
    // Lockfile references "libfoo" (member provenance), but the workspace only
    // declares "libbar". → FROZEN-MEMBER-NOT-IN-WORKSPACE (fixture 085 analog).
    let (tmp, ws) = make_workspace_with_member("libbar", "name \"libbar\"\nkind \"library\"\n");
    let store = CaStore::new(tmp.path().join(".cas"));
    let lf = lock(
        "maxver",
        vec![
            // "libbar" IS in the workspace; its pin must match the member's
            // epoch-2 on-disk identity so the drift check passes and the
            // not-in-workspace error (for libfoo) is what fires.
            locked(
                "libbar",
                "0.0.1",
                Some("dag-sha256:49845efa0775928552ad4327409411c871582b1c717b53e97a4f11acc6ab0eb3"),
                ProvenanceRecord::Member {
                    name: "libbar".into(),
                    origin: "observed".into(),
                },
            ),
            // "libfoo" is NOT in the workspace — this triggers the error.
            locked(
                "libfoo",
                "0.0.1",
                Some("dag-sha256:0000000000000000000000000000000000000000000000000000000000000002"),
                ProvenanceRecord::Member {
                    name: "libfoo".into(),
                    origin: "observed".into(),
                },
            ),
        ],
    );
    let err = crate::frozen::resolve_workspace_frozen(
        &ws,
        &lf,
        &store,
        &tmp.path().join("_deps"),
    )
    .unwrap_err();
    assert_eq!(err.code(), "FROZEN-MEMBER-NOT-IN-WORKSPACE");
}

#[test]
fn workspace_frozen_member_identity_drift() {
    // Lockfile records an identity for "libfoo" that does NOT match the real
    // on-disk content hash. → FROZEN-MEMBER-IDENTITY-DRIFT (fixture 086 analog).
    let (tmp, ws) = make_workspace_with_member("libfoo", "name \"libfoo\"\nkind \"library\"\n");
    let store = CaStore::new(tmp.path().join(".cas"));
    // Use a deliberately wrong identity (all-99 bytes).
    let lf = lock(
        "maxver",
        vec![locked(
            "libfoo",
            "0.0.1",
            Some("dag-sha256:0000000000000000000000000000000000000000000000000000000000000099"),
            ProvenanceRecord::Member {
                name: "libfoo".into(),
                origin: "observed".into(),
            },
        )],
    );
    let err = crate::frozen::resolve_workspace_frozen(
        &ws,
        &lf,
        &store,
        &tmp.path().join("_deps"),
    )
    .unwrap_err();
    assert_eq!(err.code(), "FROZEN-MEMBER-IDENTITY-DRIFT");
}

#[test]
fn success_links_and_rebuilds_graph() {
    let tmp = tempfile::tempdir().unwrap();
    let (store, identity) = store_with_foo(tmp.path());
    let lf = lock(
        "maxver",
        vec![locked("foo", "0.0.1", Some(&identity), git_rec())],
    );
    let dd = deps_dir(&tmp);
    let graph = resolve_frozen(&manifest(vec![named("foo", None)]), &lf, &store, &dd).unwrap();
    assert_eq!(graph.deps.len(), 1);
    assert_eq!(graph.deps[0].name, "foo");
    assert_eq!(graph.deps[0].identity, identity);
    // _deps/foo is a CAS symlink.
    assert!(std::fs::symlink_metadata(dd.join("foo"))
        .unwrap()
        .file_type()
        .is_symlink());
}

// ---------------------------------------------------------------------------
// D-frozen slice: aliases + provenances carried through frozen reconstruction
// ---------------------------------------------------------------------------

/// Tracer: a lockfile dep with aliases carries the aliases onto the ResolvedDep.
/// Rust already carried aliases in resolved_from_locked; this test pins the
/// invariant so any future regression is caught. (Python had the bug — aliases
/// were dropped; this test proves Rust did not have the same defect.)
#[test]
fn frozen_carries_aliases_from_locked_dep() {
    let tmp = tempfile::tempdir().unwrap();
    let (store, identity) = store_with_foo(tmp.path());
    let mut locked_dep = locked("foo", "0.0.1", Some(&identity), git_rec());
    locked_dep.aliases = vec!["bar".to_string()];
    let lf = lock("maxver", vec![locked_dep]);
    let dd = deps_dir(&tmp);
    // Manifest declares only "foo" (canonical); "bar" is a lockfile alias.
    let graph = resolve_frozen(&manifest(vec![named("foo", None)]), &lf, &store, &dd).unwrap();
    assert_eq!(graph.deps.len(), 1);
    let dep = &graph.deps[0];
    assert_eq!(dep.name, "foo");
    // D-frozen: aliases must be carried through resolved_from_locked.
    assert_eq!(dep.aliases, vec!["bar".to_string()],
        "frozen reconstruction must carry aliases from LockedDep");
}

/// Alias symlink materializes in _deps/ after resolve_frozen on a deduped dep.
#[test]
fn frozen_alias_symlink_created_in_deps() {
    let tmp = tempfile::tempdir().unwrap();
    let (store, identity) = store_with_foo(tmp.path());
    let mut locked_dep = locked("foo", "0.0.1", Some(&identity), git_rec());
    locked_dep.aliases = vec!["bar".to_string()];
    let lf = lock("maxver", vec![locked_dep]);
    let dd = deps_dir(&tmp);
    std::fs::create_dir_all(&dd).unwrap();

    resolve_frozen(&manifest(vec![named("foo", None)]), &lf, &store, &dd).unwrap();

    // Canonical symlink must exist.
    let canonical = dd.join("foo");
    assert!(std::fs::symlink_metadata(&canonical).unwrap().file_type().is_symlink(),
        "_deps/foo must be a symlink");

    // Alias symlink must exist and resolve to the same store entry.
    let alias_link = dd.join("bar");
    assert!(std::fs::symlink_metadata(&alias_link).unwrap().file_type().is_symlink(),
        "_deps/bar alias symlink must be created by rebuild_deps_view");
    assert!(alias_link.exists(), "_deps/bar alias symlink must not be dangling");

    // Both resolve to the same canonical CAS path.
    let canonical_real = std::fs::canonicalize(&canonical).unwrap();
    let alias_real = std::fs::canonicalize(&alias_link).unwrap();
    assert_eq!(canonical_real, alias_real,
        "_deps/bar and _deps/foo must resolve to the same CAS entry");
}

/// Multiple aliases on one dep — all three must appear on the ResolvedDep.
#[test]
fn frozen_carries_multiple_aliases() {
    let tmp = tempfile::tempdir().unwrap();
    let (store, identity) = store_with_foo(tmp.path());
    let mut locked_dep = locked("foo", "0.0.1", Some(&identity), git_rec());
    locked_dep.aliases = vec!["aaa".to_string(), "bar".to_string(), "zzz".to_string()];
    let lf = lock("maxver", vec![locked_dep]);
    let dd = deps_dir(&tmp);

    let graph = resolve_frozen(&manifest(vec![named("foo", None)]), &lf, &store, &dd).unwrap();

    let dep = &graph.deps[0];
    assert_eq!(dep.aliases, vec!["aaa".to_string(), "bar".to_string(), "zzz".to_string()],
        "all three aliases must be carried through frozen reconstruction");
}

/// Frozen carries ALL provenances (observed + declared) — not just the first.
#[test]
fn frozen_carries_all_provenances() {
    let tmp = tempfile::tempdir().unwrap();
    let (store, identity) = store_with_foo(tmp.path());
    let observed = ProvenanceRecord::Git {
        url: "https://example.com/foo.git".into(),
        ref_spec: Some("main".into()),
        commit_sha: Some("obs123".into()),
        origin: "observed".into(),
        submodule_shas: vec![],
    };
    let declared = ProvenanceRecord::Git {
        url: "https://mirror.example.com/foo.git".into(),
        ref_spec: None,
        commit_sha: None,
        origin: "declared".into(),
        submodule_shas: vec![],
    };
    let locked_dep = LockedDep {
        name: "foo".into(),
        namespace: None,
        identity: Some(identity),
        version: "0.0.1".into(),
        src_dir: "src".into(),
        requires: vec![],
        provenances: vec![declared, observed],
        active_flags: vec![],
        dep_decl: None,
        cond_requires: vec![],
        aliases: vec![],
    };
    let lf = lock("maxver", vec![locked_dep]);
    let dd = deps_dir(&tmp);

    let graph = resolve_frozen(&manifest(vec![named("foo", None)]), &lf, &store, &dd).unwrap();

    let dep = &graph.deps[0];
    assert_eq!(dep.provenances.len(), 2,
        "both provenances must be carried; got {:?}", dep.provenances);
    let origins: Vec<_> = dep.provenances.iter().map(|p| match p {
        ProvenanceRecord::Git { origin, .. } => origin.as_str(),
        _ => "?",
    }).collect();
    assert!(origins.contains(&"observed"), "observed provenance must be carried");
    assert!(origins.contains(&"declared"), "declared provenance must be carried");
}

// ---------------------------------------------------------------------------
// R9: rebuild_deps_view must not sweep local dep symlinks as stale
// ---------------------------------------------------------------------------
//
// Local deps (ProvenanceRecord::Local) have no CAS identity so they are NOT
// in the `expected` map.  Before the fix, `local_names` was absent and
// rebuild_deps_view would delete them during Step 2's stale-entry sweep.
// These tests pin the corrected behaviour by calling rebuild_deps_view directly.

/// Helper: a minimal ResolvedDep with a Local provenance and no identity.
fn local_dep(name: &str, path: &str) -> milpa_types::ResolvedDep {
    milpa_types::ResolvedDep {
        name: name.into(),
        namespace: None,
        identity: String::new(),
        version: milpa_types::Version::release(0, 0, 1),
        src_dir: "src".into(),
        requires: vec![],
        provenances: vec![milpa_types::ProvenanceRecord::Local {
            path: path.into(),
            origin: "observed".into(),
        }],
        dep_decl: None,
        cond_requires: vec![],
        aliases: vec![],
        active_flags: vec![],
    }
}

#[test]
fn rebuild_deps_view_preserves_local_symlink_and_removes_stale() {
    // R9 REGRESSION: rebuild_deps_view must NOT sweep local dep symlinks.
    //
    // Setup:
    //   _deps/mylib  → symlink to <local_src>  (created as LocalFetcher would)
    //   _deps/stale  → a dir from a prior run (genuinely stale)
    //
    // Graph contains only the local dep (no CAS deps).
    //
    // Expected after rebuild_deps_view:
    //   _deps/mylib  → still a symlink, still points to <local_src>
    //   _deps/stale  → removed
    let tmp = tempfile::tempdir().unwrap();
    let store = CaStore::new(tmp.path().join(".cas"));

    let local_src = tmp.path().join("mylib-src");
    std::fs::create_dir_all(&local_src).unwrap();
    std::fs::write(local_src.join("mylib.nim"), b"# mylib").unwrap();

    let deps_dir = tmp.path().join("_deps");
    std::fs::create_dir_all(&deps_dir).unwrap();

    // Pre-create the local symlink (as LocalFetcher would).
    let local_link = deps_dir.join("mylib");
    std::os::unix::fs::symlink(local_src.canonicalize().unwrap(), &local_link).unwrap();

    // Pre-create a stale entry.
    let stale = deps_dir.join("stale-dep");
    std::fs::create_dir_all(&stale).unwrap();

    let graph = milpa_types::ResolvedGraph {
        deps: vec![local_dep("mylib", &local_src.to_string_lossy())],
    };

    crate::frozen::rebuild_deps_view(&graph, &deps_dir, &store);

    // Local symlink must survive.
    let meta = std::fs::symlink_metadata(&local_link).unwrap();
    assert!(
        meta.file_type().is_symlink(),
        "_deps/mylib (local dep symlink) must NOT be swept by rebuild_deps_view"
    );
    assert_eq!(
        std::fs::read_link(&local_link).unwrap().canonicalize().unwrap(),
        local_src.canonicalize().unwrap(),
        "_deps/mylib must still point to the local source dir"
    );

    // Stale entry must be removed.
    assert!(
        !stale.exists(),
        "_deps/stale-dep must be removed as a stale entry"
    );
}

#[test]
fn rebuild_deps_view_preserves_local_symlink_alongside_cas_dep() {
    // R9 REGRESSION variant: local symlink preserved when CAS dep entries also exist.
    //
    // Graph: local dep "locallib" + CAS git dep "foo".
    // _deps/locallib → local symlink (must survive)
    // _deps/old-dep  → stale dir (must be removed)
    // _deps/foo      → must be created as CAS symlink
    let tmp = tempfile::tempdir().unwrap();
    let (store, identity) = store_with_foo(tmp.path());

    let local_src = tmp.path().join("local-src");
    std::fs::create_dir_all(&local_src).unwrap();
    std::fs::write(local_src.join("l.nim"), b"# local").unwrap();

    let deps_dir = tmp.path().join("_deps");
    std::fs::create_dir_all(&deps_dir).unwrap();

    // Pre-create the local dep symlink (as LocalFetcher would).
    let local_link = deps_dir.join("locallib");
    std::os::unix::fs::symlink(local_src.canonicalize().unwrap(), &local_link).unwrap();

    // Pre-create a stale entry.
    let stale = deps_dir.join("old-dep");
    std::fs::create_dir_all(&stale).unwrap();

    let local = local_dep("locallib", &local_src.to_string_lossy());
    let git = milpa_types::ResolvedDep {
        name: "foo".into(),
        namespace: None,
        identity: identity.clone(),
        version: milpa_types::Version::release(0, 0, 1),
        src_dir: "src".into(),
        requires: vec![],
        provenances: vec![milpa_types::ProvenanceRecord::Git {
            url: "https://e/foo.git".into(),
            ref_spec: Some("main".into()),
            commit_sha: None,
            origin: "observed".into(),
            submodule_shas: vec![],
        }],
        dep_decl: None,
        cond_requires: vec![],
        aliases: vec![],
        active_flags: vec![],
    };
    let graph = milpa_types::ResolvedGraph { deps: vec![local, git] };

    crate::frozen::rebuild_deps_view(&graph, &deps_dir, &store);

    // Local symlink preserved.
    let local_meta = std::fs::symlink_metadata(&local_link).unwrap();
    assert!(
        local_meta.file_type().is_symlink(),
        "_deps/locallib local symlink must survive rebuild_deps_view"
    );

    // CAS symlink created.
    let foo_meta = std::fs::symlink_metadata(deps_dir.join("foo")).unwrap();
    assert!(
        foo_meta.file_type().is_symlink(),
        "_deps/foo CAS symlink must be created"
    );

    // Stale removed.
    assert!(!stale.exists(), "_deps/old-dep must be removed as stale");
}

/// Regression: plain (non-deduped, single-provenance) dep still works after D-frozen changes.
#[test]
fn frozen_plain_dep_no_aliases_regression() {
    let tmp = tempfile::tempdir().unwrap();
    let (store, identity) = store_with_foo(tmp.path());
    let lf = lock(
        "maxver",
        vec![locked("foo", "0.0.1", Some(&identity), git_rec())],
    );
    let dd = deps_dir(&tmp);
    let graph = resolve_frozen(&manifest(vec![named("foo", None)]), &lf, &store, &dd).unwrap();
    assert_eq!(graph.deps.len(), 1);
    let dep = &graph.deps[0];
    assert_eq!(dep.name, "foo");
    assert!(dep.aliases.is_empty(), "plain dep must have empty aliases; got {:?}", dep.aliases);
    assert_eq!(dep.provenances.len(), 1);
    assert!(dd.join("foo").is_symlink());
}
