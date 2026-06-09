//! Resolver orchestration tests (ported from `tests/test_resolver.py`).
//!
//! Each test injects a fake [`FetcherRegistry`] mapping `(url, ref)` → fetched
//! bytes, so the integration runs without network or git. Identity is computed
//! by the resolver from the materialized tree — the fake never reports it.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

use milpa_manifest::{Dep, LocalDep, Manifest, NamedDep, Override, Predicate, Profile, UrlDep};
use milpa_solver::Strategy;
use milpa_types::{
    LockedDep, Lockfile, Provenance, ProvenanceRecord, Version, LOCKFILE_SCHEMA_VERSION,
};

use crate::fetch::{FetchError, FetcherRegistry, Receipt};
use crate::identity::compute_content_hash;
use crate::registry::{Index, IndexEntry};
use crate::resolver::resolve;

// --- fake fetcher ----------------------------------------------------------

/// What a `(url, ref)` fetch materializes: a returned SHA plus either a
/// `<name>.nimble` body or a full `milpa.kdl`.
#[derive(Clone, Default)]
struct Mock {
    sha: String,
    nimble: Option<String>,
    milpa_kdl: Option<String>,
}

#[derive(Default)]
struct FakeReg {
    /// `(url, ref)` → mock for git fetches; also reused for tarball URLs (ref "").
    by_url_ref: BTreeMap<(String, String), Mock>,
    calls: RefCell<Vec<(String, String, String)>>,
}

impl FakeReg {
    fn git(mocks: &[(&str, &str, Mock)]) -> Self {
        let mut by_url_ref = BTreeMap::new();
        for (url, refp, m) in mocks {
            by_url_ref.insert((url.to_string(), refp.to_string()), m.clone());
        }
        FakeReg {
            by_url_ref,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<(String, String, String)> {
        self.calls.borrow().clone()
    }

    fn materialize(&self, name: &str, m: &Mock, dest: &Path) -> Result<(), FetchError> {
        std::fs::create_dir_all(dest).map_err(|e| FetchError::Failed(format!("mkdir: {e}")))?;
        if let Some(kdl) = &m.milpa_kdl {
            std::fs::write(dest.join("milpa.kdl"), kdl)
                .map_err(|e| FetchError::Failed(format!("write: {e}")))?;
        } else if let Some(nim) = &m.nimble {
            std::fs::write(dest.join(format!("{name}.nimble")), nim)
                .map_err(|e| FetchError::Failed(format!("write: {e}")))?;
        }
        Ok(())
    }
}

impl FetcherRegistry for FakeReg {
    fn fetch(&self, name: &str, p: &Provenance, dest: &Path) -> Result<Receipt, FetchError> {
        match p {
            Provenance::Git { url, ref_spec, .. } => {
                self.calls
                    .borrow_mut()
                    .push((name.to_string(), url.clone(), ref_spec.clone()));
                let m = self
                    .by_url_ref
                    .get(&(url.clone(), ref_spec.clone()))
                    .ok_or_else(|| {
                        FetchError::Failed(format!("no mock for {url:?} @ {ref_spec:?}"))
                    })?
                    .clone();
                self.materialize(name, &m, dest)?;
                Ok(Receipt {
                    resolved_ref: Some(m.sha),
                })
            }
            Provenance::Tarball { url, .. } => {
                self.calls
                    .borrow_mut()
                    .push((name.to_string(), url.clone(), String::new()));
                let m = self
                    .by_url_ref
                    .get(&(url.clone(), String::new()))
                    .ok_or_else(|| FetchError::Failed(format!("no tarball mock for {url:?}")))?
                    .clone();
                self.materialize(name, &m, dest)?;
                Ok(Receipt { resolved_ref: None })
            }
            Provenance::Local { path } => {
                self.calls
                    .borrow_mut()
                    .push((name.to_string(), path.clone(), String::new()));
                copy_tree(Path::new(path), dest)
                    .map_err(|e| FetchError::Failed(format!("local copy: {e}")))?;
                Ok(Receipt { resolved_ref: None })
            }
            other => Err(FetchError::Failed(format!("unmocked: {other:?}"))),
        }
    }
}

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

// --- builders --------------------------------------------------------------

fn nimble(sha: &str, body: &str) -> Mock {
    Mock {
        sha: sha.to_string(),
        nimble: Some(body.to_string()),
        milpa_kdl: None,
    }
}

fn milpa_kdl(sha: &str, body: &str) -> Mock {
    Mock {
        sha: sha.to_string(),
        nimble: None,
        milpa_kdl: Some(body.to_string()),
    }
}

fn url_dep(name: &str, git: &str, refp: &str) -> Dep {
    Dep::Url(UrlDep {
        name: name.to_string(),
        git: git.to_string(),
        git_ref: refp.to_string(),
        mirrors: Vec::new(),
        predicates: Vec::new(),
        flag_requests: Vec::new(),
    })
}

fn named_dep(name: &str, constraint: Option<&str>) -> Dep {
    Dep::Named(NamedDep {
        name: name.to_string(),
        constraint: constraint.map(str::to_string),
    })
}

fn manifest(deps: Vec<Dep>) -> Manifest {
    manifest_full(deps, Vec::new(), Vec::new())
}

fn manifest_full(deps: Vec<Dep>, dev_deps: Vec<Dep>, overrides: Vec<Override>) -> Manifest {
    Manifest {
        name: Some("root".to_string()),
        kind: "library".to_string(),
        src_dir: String::new(),
        deps,
        dev_deps,
        overrides,
        flags: Vec::new(),
        self_mirrors: Vec::new(),
        cas_dir: String::new(),
        spec_version: 1,
        spec_version_explicit: false,
    }
}

fn deps_dir(tmp: &tempfile::TempDir) -> std::path::PathBuf {
    tmp.path().join("_deps")
}

/// Real content hash of a tree containing only `<name>.nimble = body` — used so
/// an index entry's `content_hash` matches what the resolver computes (the
/// identity gate then passes).
fn hash_of_nimble(name: &str, body: &str) -> String {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(format!("{name}.nimble")), body).unwrap();
    compute_content_hash(tmp.path()).unwrap()
}

fn v(major: u64, minor: u64, patch: u64) -> Version {
    Version::release(major, minor, patch)
}

// --- tests -----------------------------------------------------------------

#[test]
fn resolve_single_url_dep_no_transitive() {
    let reg = FakeReg::git(&[(
        "https://example.com/foo.git",
        "main",
        nimble("aaa111", "srcDir = \"src\"\n"),
    )]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("foo", "https://example.com/foo.git", "main")]);

    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap();

    assert_eq!(graph.deps.len(), 1);
    let foo = &graph.deps[0];
    assert_eq!(foo.name, "foo");
    assert_eq!(foo.src_dir, "src");
    assert!(foo.identity.starts_with("sha256:"));
    assert_eq!(foo.identity.len(), "sha256:".len() + 64);
    match &foo.provenance {
        Provenance::Git {
            url,
            ref_spec,
            commit_sha,
        } => {
            assert_eq!(url, "https://example.com/foo.git");
            assert_eq!(ref_spec, "main");
            assert_eq!(commit_sha.as_deref(), Some("aaa111"));
        }
        other => panic!("expected git provenance, got {other:?}"),
    }
}

#[test]
fn resolve_url_dep_with_transitive_url() {
    let reg = FakeReg::git(&[
        (
            "https://example.com/foo.git",
            "main",
            nimble(
                "aaa111",
                "srcDir = \"src\"\nrequires \"https://example.com/bar.git#v1\"\n",
            ),
        ),
        (
            "https://example.com/bar.git",
            "v1",
            nimble("bbb222", "srcDir = \"src\"\n"),
        ),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("foo", "https://example.com/foo.git", "main")]);

    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap();
    let names: Vec<&str> = graph.deps.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"foo"));
    assert!(names.contains(&"bar"));
    // Transitive comes before its dependent (topological order).
    let foo_pos = names.iter().position(|n| *n == "foo").unwrap();
    let bar_pos = names.iter().position(|n| *n == "bar").unwrap();
    assert!(bar_pos < foo_pos);
}

#[test]
fn resolve_dedup_same_url_ref_fetches_once() {
    let reg = FakeReg::git(&[
        (
            "https://example.com/foo.git",
            "main",
            nimble("aaa", "requires \"https://example.com/shared.git#v1\"\n"),
        ),
        (
            "https://example.com/bar.git",
            "main",
            nimble("bbb", "requires \"https://example.com/shared.git#v1\"\n"),
        ),
        (
            "https://example.com/shared.git",
            "v1",
            nimble("ccc", "srcDir = \"src\"\n"),
        ),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![
        url_dep("foo", "https://example.com/foo.git", "main"),
        url_dep("bar", "https://example.com/bar.git", "main"),
    ]);

    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap();
    let shared: Vec<_> = graph.deps.iter().filter(|d| d.name == "shared").collect();
    assert_eq!(shared.len(), 1);
    let shared_calls: Vec<_> = reg
        .calls()
        .into_iter()
        .filter(|c| c.0 == "shared")
        .collect();
    assert_eq!(shared_calls.len(), 1, "shared fetched exactly once");
}

#[test]
fn resolve_named_dep_strategy_selects_version() {
    // foo published at 0.4.0 / 0.5.0 / 1.0.0; maxver→1.0.0, minver→0.4.0. The
    // index content_hash gates identity; the fake mocks only the selected
    // version's fetch, proving lazy (two-phase) materialization.
    let body = "srcDir = \"src\"\n";
    let index = Index {
        packages: vec![(
            "foo".to_string(),
            vec![
                IndexEntry {
                    version: "0.4.0".into(),
                    content_hash: hash_of_nimble("foo", body),
                    provenance: Provenance::Git {
                        url: "https://example.com/foo.git".into(),
                        ref_spec: "v0.4.0".into(),
                        commit_sha: None,
                    },
                },
                IndexEntry {
                    version: "0.5.0".into(),
                    content_hash: hash_of_nimble("foo", body),
                    provenance: Provenance::Git {
                        url: "https://example.com/foo.git".into(),
                        ref_spec: "v0.5.0".into(),
                        commit_sha: None,
                    },
                },
                IndexEntry {
                    version: "1.0.0".into(),
                    content_hash: hash_of_nimble("foo", body),
                    provenance: Provenance::Git {
                        url: "https://example.com/foo.git".into(),
                        ref_spec: "v1.0.0".into(),
                        commit_sha: None,
                    },
                },
            ],
        )],
    };
    let m = manifest(vec![named_dep("foo", Some(">= 0.4.0"))]);

    let reg_max = FakeReg::git(&[("https://example.com/foo.git", "v1.0.0", nimble("s1", body))]);
    let tmp_max = tempfile::tempdir().unwrap();
    let g_max = resolve(
        &m,
        Some(&index),
        &reg_max,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp_max),
    )
    .unwrap();
    let foo_max = g_max.deps.iter().find(|d| d.name == "foo").unwrap();
    assert_eq!(foo_max.version, v(1, 0, 0));

    let reg_min = FakeReg::git(&[("https://example.com/foo.git", "v0.4.0", nimble("s0", body))]);
    let tmp_min = tempfile::tempdir().unwrap();
    let g_min = resolve(
        &m,
        Some(&index),
        &reg_min,
        None,
        None,
        Strategy::Minver,
        &deps_dir(&tmp_min),
    )
    .unwrap();
    let foo_min = g_min.deps.iter().find(|d| d.name == "foo").unwrap();
    assert_eq!(foo_min.version, v(0, 4, 0));
}

#[test]
fn resolve_named_dep_without_index_errors() {
    let reg = FakeReg::default();
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![named_dep("foo", Some(">= 0.4.0"))]);
    let err = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-NO-INDEX");
}

#[test]
fn resolve_url_dep_with_override_fetches_override() {
    let reg = FakeReg::git(&[(
        "https://fork.example.com/foo.git",
        "patched",
        nimble("ovr", "srcDir = \"src\"\n"),
    )]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest_full(
        vec![url_dep("foo", "https://example.com/foo.git", "main")],
        Vec::new(),
        vec![Override {
            name: "foo".into(),
            git: "https://fork.example.com/foo.git".into(),
            git_ref: "patched".into(),
        }],
    );
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap();
    let foo = graph.deps.iter().find(|d| d.name == "foo").unwrap();
    match &foo.provenance {
        Provenance::Git { url, ref_spec, .. } => {
            assert_eq!(url, "https://fork.example.com/foo.git");
            assert_eq!(ref_spec, "patched");
        }
        other => panic!("expected git, got {other:?}"),
    }
    // Original URL was never fetched.
    assert!(reg
        .calls()
        .iter()
        .all(|c| c.1 != "https://example.com/foo.git"));
}

#[test]
fn resolve_root_override_precedence_suppresses_transitive_provenance() {
    // §10.1: root declares `shared` from the fork; a transitive (translib)
    // declares `shared` from upstream → upstream is suppressed, never fetched.
    let reg = FakeReg::git(&[
        (
            "https://example.com/translib.git",
            "main",
            nimble(
                "tl",
                "requires \"https://upstream.example.com/shared.git#main\"\n",
            ),
        ),
        (
            "https://fork.example.com/shared.git",
            "main",
            nimble("fk", "srcDir = \"src\"\n"),
        ),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![
        url_dep("translib", "https://example.com/translib.git", "main"),
        url_dep("shared", "https://fork.example.com/shared.git", "main"),
    ]);
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap();
    let shared: Vec<_> = graph.deps.iter().filter(|d| d.name == "shared").collect();
    assert_eq!(shared.len(), 1);
    match &shared[0].provenance {
        Provenance::Git { url, .. } => assert_eq!(url, "https://fork.example.com/shared.git"),
        other => panic!("expected git, got {other:?}"),
    }
    assert!(
        reg.calls()
            .iter()
            .all(|c| c.1 != "https://upstream.example.com/shared.git"),
        "upstream shared must not be fetched"
    );
}

#[test]
fn resolve_non_root_provenance_disagreement_conflicts() {
    // §10.3: two transitive deps declare `shared` from different URLs and the
    // root has no authority over `shared` → RES-PROVENANCE-CONFLICT.
    let reg = FakeReg::git(&[
        (
            "https://example.com/a.git",
            "main",
            nimble("a", "requires \"https://x.example.com/shared.git#main\"\n"),
        ),
        (
            "https://example.com/b.git",
            "main",
            nimble("b", "requires \"https://y.example.com/shared.git#main\"\n"),
        ),
        (
            "https://x.example.com/shared.git",
            "main",
            nimble("sx", "srcDir = \"src\"\n"),
        ),
        (
            "https://y.example.com/shared.git",
            "main",
            nimble("sy", "srcDir = \"src\"\n"),
        ),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![
        url_dep("a", "https://example.com/a.git", "main"),
        url_dep("b", "https://example.com/b.git", "main"),
    ]);
    let err = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-PROVENANCE-CONFLICT");
}

#[test]
fn resolve_dev_deps_root_enrolls_transitive_excludes() {
    // §9: root dev-dep `d` is enrolled; transitive dep `a`'s OWN dev-dep `e`
    // (declared in a's milpa.kdl) is excluded from the graph.
    let a_kdl = "name \"a\"\nkind \"library\"\nsrc_dir \"src\"\n\
                 dev-deps {\n  e git=\"https://example.com/e.git\" ref=\"main\"\n}\n";
    let reg = FakeReg::git(&[
        ("https://example.com/a.git", "main", milpa_kdl("a", a_kdl)),
        (
            "https://example.com/d.git",
            "main",
            nimble("d", "srcDir = \"src\"\n"),
        ),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest_full(
        vec![url_dep("a", "https://example.com/a.git", "main")],
        vec![url_dep("d", "https://example.com/d.git", "main")],
        Vec::new(),
    );
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap();
    let names: Vec<&str> = graph.deps.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"a"));
    assert!(names.contains(&"d"), "root dev-dep enrolled");
    assert!(!names.contains(&"e"), "transitive dev-dep excluded");
    assert!(
        reg.calls().iter().all(|c| c.0 != "e"),
        "transitive dev-dep never fetched"
    );
}

#[test]
fn resolve_local_dep_copies_and_parses() {
    let tmp = tempfile::tempdir().unwrap();
    // A local source tree under the project root.
    let src = tmp.path().join("liblocal");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("liblocal.nimble"), "srcDir = \"src\"\n").unwrap();

    let reg = FakeReg::default();
    let m = manifest(vec![Dep::Local(LocalDep {
        name: "liblocal".into(),
        path: "liblocal".into(),
    })]);
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap();
    let dep = graph.deps.iter().find(|d| d.name == "liblocal").unwrap();
    assert_eq!(dep.src_dir, "src");
    match &dep.provenance {
        // The recorded path is the declared relative path, not the absolute copy.
        Provenance::Local { path } => assert_eq!(path, "liblocal"),
        other => panic!("expected local, got {other:?}"),
    }
}

#[test]
fn resolve_fetch_failure_surfaces() {
    // No mock for foo → the URL fetch fails → FETCH-ALL-FAILED.
    let reg = FakeReg::default();
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("foo", "https://example.com/foo.git", "main")]);
    let err = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "FETCH-ALL-FAILED");
}

#[test]
fn resolve_malformed_nimble_constraint_is_manifest_error() {
    // A transitive .nimble with a malformed version constraint → MAN-NIMBLE-CONSTRAINT.
    let reg = FakeReg::git(&[(
        "https://example.com/foo.git",
        "main",
        nimble("f", "requires \"bar >= not.a.version\"\n"),
    )]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("foo", "https://example.com/foo.git", "main")]);
    let err = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "MAN-NIMBLE-CONSTRAINT");
}

#[test]
fn resolve_prior_lockfile_pin_rejects_hostile_bytes() {
    // §8: the prior lockfile pins an identity that does NOT match the bytes the
    // fetch delivers → every candidate fails the identity gate → FETCH-ALL-FAILED.
    let reg = FakeReg::git(&[(
        "https://example.com/foo.git",
        "main",
        nimble("f", "srcDir = \"src\"\n"),
    )]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("foo", "https://example.com/foo.git", "main")]);
    let prior = Lockfile {
        version: LOCKFILE_SCHEMA_VERSION,
        strategy: "maxver".into(),
        deps: vec![LockedDep {
            name: "foo".into(),
            identity: Some(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            version: "0.0.1".into(),
            src_dir: "src".into(),
            requires: Vec::new(),
            provenances: vec![ProvenanceRecord::Git {
                url: "https://example.com/foo.git".into(),
                ref_spec: Some("main".into()),
                commit_sha: None,
            }],
            active_flags: Vec::new(),
            self_mirrors: Vec::new(),
        }],
    };
    let err = resolve(
        &m,
        None,
        &reg,
        None,
        Some(&prior),
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "FETCH-ALL-FAILED");
}

#[test]
fn resolve_prior_lockfile_pin_accepts_matching_bytes() {
    // §8: a pin whose identity matches the delivered bytes resolves cleanly.
    let body = "srcDir = \"src\"\n";
    let identity = hash_of_nimble("foo", body);
    let reg = FakeReg::git(&[("https://example.com/foo.git", "main", nimble("f", body))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("foo", "https://example.com/foo.git", "main")]);
    let prior = Lockfile {
        version: LOCKFILE_SCHEMA_VERSION,
        strategy: "maxver".into(),
        deps: vec![LockedDep {
            name: "foo".into(),
            identity: Some(identity.clone()),
            version: "0.0.1".into(),
            src_dir: "src".into(),
            requires: Vec::new(),
            provenances: vec![ProvenanceRecord::Git {
                url: "https://example.com/foo.git".into(),
                ref_spec: Some("main".into()),
                commit_sha: None,
            }],
            active_flags: Vec::new(),
            self_mirrors: Vec::new(),
        }],
    };
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        Some(&prior),
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap();
    let foo = graph.deps.iter().find(|d| d.name == "foo").unwrap();
    assert_eq!(foo.identity, identity);
}

#[test]
fn resolve_mirror_fallback_uses_second_candidate() {
    // §8a: the primary URL has no mock (fetch fails); the dep-block mirror does
    // → the resolver falls through to the mirror.
    let reg = FakeReg::git(&[(
        "https://mirror.example.com/foo.git",
        "main",
        nimble("m", "srcDir = \"src\"\n"),
    )]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![Dep::Url(UrlDep {
        name: "foo".into(),
        git: "https://primary.example.com/foo.git".into(),
        git_ref: "main".into(),
        mirrors: vec!["https://mirror.example.com/foo.git".into()],
        predicates: Vec::new(),
        flag_requests: Vec::new(),
    })]);
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap();
    assert_eq!(graph.deps.len(), 1);
    assert_eq!(graph.deps[0].name, "foo");
}

#[test]
fn resolve_content_hash_dedup_aliases_to_lex_min_name() {
    // Two URL deps deliver byte-identical trees (same single file) → they
    // collapse to the lexicographically-smallest name ("bar").
    let identical = milpa_kdl("x", "name \"shared\"\nkind \"library\"\nsrc_dir \"src\"\n");
    let reg = FakeReg::git(&[
        ("https://example.com/foo.git", "main", identical.clone()),
        ("https://example.com/bar.git", "main", identical),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![
        url_dep("foo", "https://example.com/foo.git", "main"),
        url_dep("bar", "https://example.com/bar.git", "main"),
    ]);
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap();
    let names: Vec<&str> = graph.deps.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, vec!["bar"], "deduped to lex-min canonical");
}

#[test]
fn resolve_profile_filters_conditional_dep() {
    // §6: a dep gated by `when nim=">= 2.0.0"` is dropped when the profile's nim
    // version does not satisfy it — and never fetched.
    let reg = FakeReg::default();
    let tmp = tempfile::tempdir().unwrap();
    let dep = Dep::Url(UrlDep {
        name: "foo".into(),
        git: "https://example.com/foo.git".into(),
        git_ref: "main".into(),
        mirrors: Vec::new(),
        predicates: vec![Predicate {
            name: "nim".into(),
            values: vec![">= 2.0.0".into()],
            negated: false,
        }],
        flag_requests: Vec::new(),
    });
    let m = manifest(vec![dep]);
    let profile = Profile {
        nim_version: Some(v(1, 9, 0)),
        flags: Vec::new(),
    };
    let graph = resolve(
        &m,
        None,
        &reg,
        Some(&profile),
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap();
    assert!(graph.deps.is_empty());
    assert!(reg.calls().is_empty(), "filtered dep never fetched");
}

#[test]
fn resolve_absent_profile_includes_conditional_dep() {
    // §6: an absent profile disables filtering — the gated dep is included.
    let reg = FakeReg::git(&[(
        "https://example.com/foo.git",
        "main",
        nimble("f", "srcDir = \"src\"\n"),
    )]);
    let tmp = tempfile::tempdir().unwrap();
    let dep = Dep::Url(UrlDep {
        name: "foo".into(),
        git: "https://example.com/foo.git".into(),
        git_ref: "main".into(),
        mirrors: Vec::new(),
        predicates: vec![Predicate {
            name: "nim".into(),
            values: vec![">= 2.0.0".into()],
            negated: false,
        }],
        flag_requests: Vec::new(),
    });
    let m = manifest(vec![dep]);
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
    )
    .unwrap();
    assert_eq!(graph.deps.len(), 1);
}
