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
    }
}

fn named(name: &str, constraint: Option<&str>) -> Dep {
    Dep::Named(NamedDep {
        name: name.into(),
        constraint: constraint.map(str::to_string),
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
        identity: identity.map(str::to_string),
        version: version.into(),
        src_dir: "src".into(),
        requires: vec![],
        provenances: vec![prov],
        active_flags: vec![],
        self_mirrors: vec![],
    }
}

fn git_rec() -> ProvenanceRecord {
    ProvenanceRecord::Git {
        url: "https://e/foo.git".into(),
        ref_spec: Some("main".into()),
        commit_sha: Some("abcdef1234567890abcdef1234567890abcdef12".into()),
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
        vec![locked("foo", "1.0.0", Some("sha256:00"), git_rec())],
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
        vec![locked("foo", "not-a-version", Some("sha256:00"), git_rec())],
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
            Some("sha256:00"),
            ProvenanceRecord::Member {
                name: "liba".into(),
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
            Some("sha256:00"),
            ProvenanceRecord::Local {
                path: "../foo".into(),
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
            Some("sha256:0000000000000000000000000000000000000000000000000000000000000001"),
            git_rec(),
        )],
    );
    let err = resolve_frozen(&manifest(vec![]), &lf, &store, &deps_dir(&tmp)).unwrap_err();
    assert_eq!(err.code(), "FROZEN-IDENTITY-NOT-IN-STORE");
}

#[test]
fn legacy_registry_provenance() {
    let tmp = tempfile::tempdir().unwrap();
    let (store, identity) = store_with_foo(tmp.path());
    let lf = lock(
        "maxver",
        vec![locked(
            "foo",
            "1.0.0",
            Some(&identity),
            ProvenanceRecord::Registry {
                name: "foo".into(),
                tag: Some("v1.0.0".into()),
                commit_sha: None,
            },
        )],
    );
    // Identity IS in the store, so it gets past link_external and fails when
    // rebuilding the resolved dep from the legacy record.
    let err = resolve_frozen(&manifest(vec![]), &lf, &store, &deps_dir(&tmp)).unwrap_err();
    assert_eq!(err.code(), "FROZEN-LEGACY-REGISTRY-PROVENANCE");
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
