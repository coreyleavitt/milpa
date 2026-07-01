//! Resolver orchestration tests (ported from `tests/test_resolver.py`).
//!
//! Each test injects a fake [`FetcherRegistry`] mapping `(url, ref)` → fetched
//! bytes, so the integration runs without network or git. Identity is computed
//! by the resolver from the materialized tree — the fake never reports it.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

use milpa_manifest::{
    Dep, LocalDep, Manifest, NamedDep, Override, OverrideTarget, Predicate, Profile, TarballDep,
    UrlDep,
};
use milpa_solver::Strategy;
use milpa_types::{
    LockedDep, Lockfile, Provenance, ProvenanceRecord, Version, LOCKFILE_SCHEMA_VERSION,
};

use crate::error::MilpaError;
use crate::fetch::{FetchError, FetcherRegistry, Receipt};
use crate::identity::compute_content_hash;
use crate::registry::{Index, IndexVersion, Package};
use crate::resolver::resolve;
use crate::store::CaStore;

// --- fake fetcher ----------------------------------------------------------

/// What a `(url, ref)` fetch materializes: a returned SHA plus either a
/// `<name>.nimble` body or a full `milpa.kdl`.
#[derive(Clone, Default)]
struct Mock {
    sha: String,
    nimble: Option<String>,
    milpa_kdl: Option<String>,
    /// For tarball mocks: the sha256 the transport reports for the downloaded
    /// archive bytes. Modelled like the real `fetch_tarball`: an `expected_sha256`
    /// pin is checked against this value, and it is returned in the receipt.
    archive_sha: Option<String>,
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
                    ..Default::default()
                })
            }
            Provenance::Tarball {
                url,
                expected_sha256,
                ..
            } => {
                self.calls
                    .borrow_mut()
                    .push((name.to_string(), url.clone(), String::new()));
                let m = self
                    .by_url_ref
                    .get(&(url.clone(), String::new()))
                    .ok_or_else(|| FetchError::Failed(format!("no tarball mock for {url:?}")))?
                    .clone();
                let archive_sha = m.archive_sha.clone();
                // Model the real `fetch_tarball`: gate an existing pin against the
                // archive's actual sha before materializing.
                if let (Some(exp), Some(actual)) = (expected_sha256.as_deref(), &archive_sha) {
                    let want = exp.strip_prefix("sha256:").unwrap_or(exp);
                    if want != actual {
                        return Err(FetchError::Transport(
                            "FETCH-SHA256-MISMATCH",
                            format!("archive sha256 mismatch — expected {exp}, got {actual}"),
                        ));
                    }
                }
                self.materialize(name, &m, dest)?;
                Ok(Receipt {
                    archive_sha256: archive_sha,
                    ..Default::default()
                })
            }
            Provenance::Local { path } => {
                self.calls
                    .borrow_mut()
                    .push((name.to_string(), path.clone(), String::new()));
                copy_tree(Path::new(path), dest)
                    .map_err(|e| FetchError::Failed(format!("local copy: {e}")))?;
                Ok(Receipt::default())
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
        ..Mock::default()
    }
}

fn milpa_kdl(sha: &str, body: &str) -> Mock {
    Mock {
        sha: sha.to_string(),
        milpa_kdl: Some(body.to_string()),
        ..Mock::default()
    }
}

/// A tarball mock: serves `<name>.nimble = body` and reports `archive_sha` as the
/// downloaded archive's sha256 (the transport receipt the resolver records/pins).
fn tarball_mock(archive_sha: &str, body: &str) -> Mock {
    Mock {
        nimble: Some(body.to_string()),
        archive_sha: Some(archive_sha.to_string()),
        ..Mock::default()
    }
}

fn tarball_dep(name: &str, url: &str, sha256: Option<&str>) -> Dep {
    Dep::Tarball(TarballDep {
        name: name.to_string(),
        url: url.to_string(),
        sha256: sha256.map(str::to_string),
        strip_components: 0,
        predicates: vec![],
    })
}

/// Build a `FakeReg` from tarball mocks keyed by URL (ref slot is empty for
/// tarballs, matching the `Provenance::Tarball` dispatch arm).
fn tarball_reg(mocks: &[(&str, Mock)]) -> FakeReg {
    let mut by_url_ref = BTreeMap::new();
    for (url, m) in mocks {
        by_url_ref.insert((url.to_string(), String::new()), m.clone());
    }
    FakeReg {
        by_url_ref,
        calls: RefCell::new(Vec::new()),
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
        optional: false,
    })
}

fn named_dep(name: &str, constraint: Option<&str>) -> Dep {
    Dep::Named(NamedDep {
        name: name.to_string(),
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
        attestation_policy: milpa_manifest::TrustPolicy::Warn,
        index_trust_policy: milpa_manifest::TrustPolicy::Warn,
        index_trust_signer: None,
        index_trust_bundle: None,
        optional_auto_flags: std::collections::BTreeSet::new(),
    }
}

fn deps_dir(tmp: &tempfile::TempDir) -> std::path::PathBuf {
    tmp.path().join("_deps")
}

/// A no-op CaStore for resolver tests: points to a temp dir inside `tmp`
/// so `rebuild_deps_view`'s `store.link()` calls are valid (it just won't
/// find real CAS entries, which is fine — the fake fetcher never admits into
/// a CAS and the resolver's own _deps/ already has the materialized dirs).
fn cas_store(tmp: &tempfile::TempDir) -> CaStore {
    CaStore::new(tmp.path().join("cas"))
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
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();

    assert_eq!(graph.deps.len(), 1);
    let foo = &graph.deps[0];
    assert_eq!(foo.name, "foo");
    assert_eq!(foo.src_dir, "src");
    assert!(foo.identity.starts_with("dag-sha256:"));
    assert_eq!(foo.identity.len(), "dag-sha256:".len() + 64);
    match foo.provenances.first().expect("at least one provenance") {
        ProvenanceRecord::Git {
            url,
            ref_spec,
            commit_sha,
            ..
        } => {
            assert_eq!(url, "https://example.com/foo.git");
            assert_eq!(ref_spec.as_deref(), Some("main"));
            assert_eq!(commit_sha.as_deref(), Some("aaa111"));
        }
        other => panic!("expected git provenance, got {other:?}"),
    }
    // D-lifecycle: no mirrors declared → single observed provenance.
    assert_eq!(foo.provenances.len(), 1);
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
        None,
        false,
        &cas_store(&tmp),
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
        None,
        false,
        &cas_store(&tmp),
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
    let idx_ver = |ver: &str| IndexVersion {
        version: ver.into(),
        content_hash: hash_of_nimble("foo", body),
        provenances: vec![Provenance::Git {
            url: "https://example.com/foo.git".into(),
            ref_spec: format!("v{ver}"),
            commit_sha: None,
        }],
        dep_decl: None,
        dep_decl_schema_version: None,
    };
    let index = Index {
        packages: vec![Package {
            name: "foo".to_string(),
            namespace: String::new(),
            versions: vec![idx_ver("0.4.0"), idx_ver("0.5.0"), idx_ver("1.0.0")],
        }],
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
        None,
        false,
        &cas_store(&tmp_max),
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
        None,
        false,
        &cas_store(&tmp_min),
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
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-NO-INDEX");
}

/// S5b spike — §3.B error-slug divergence diagnostic (workspace-completion RFC).
///
/// Constructs the §3.B error-path case: dep requires `foo >= 2.0.0`, index has
/// only `foo` 1.x.  Records the observed error slug and **passes** — proving
/// the current behaviour without breaking the loop's green gate.
///
/// Expected (pre-S6): Rust emits `TNG-NO-SATISFYING-VERSION` because
/// `process_named` passes the constraint to `resolve_named_all` at Phase A,
/// and the index rejects it eagerly before the solver sees it.
///
/// After S6 this assertion flips to `SOLVE-CONFLICT` (enumerate-all normative,
/// solver owns satisfiability).  At that point the spike test is superseded by
/// the corpus fixture; update or remove accordingly.
#[test]
fn s5b_phase_a_error_slug_divergence_spike() {
    // Index: foo exists, but only at 1.0.0.
    let index = Index {
        packages: vec![Package {
            name: "foo".to_string(),
            namespace: String::new(),
            versions: vec![IndexVersion {
                version: "1.0.0".to_string(),
                content_hash: "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"
                    .to_string(),
                provenances: vec![Provenance::Git {
                    url: "https://example.com/foo.git".into(),
                    ref_spec: "v1.0.0".into(),
                    commit_sha: None,
                }],
                dep_decl: None,
                dep_decl_schema_version: None,
            }],
        }],
    };
    // Manifest: requires foo >= 2.0.0 — unsatisfiable given the index.
    let m = manifest(vec![named_dep("foo", Some(">= 2.0.0"))]);
    let reg = FakeReg::default(); // no fetch mocks needed; Phase A errors before fetch
    let tmp = tempfile::tempdir().unwrap();

    let err = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap_err();

    // S6 (enumerate-all normative, resolver-semantics §2.1): both impls now emit
    // SOLVE-CONFLICT.  The solver owns satisfiability; the enumerator no longer
    // pre-filters by constraint.  See corpus fixture-261 for the canonical assertion.
    assert_eq!(
        err.code(),
        "SOLVE-CONFLICT",
        "S6: enumerate-all normative — SOLVE-CONFLICT is the canonical slug \
         when the index has versions but none satisfy the declared constraint"
    );
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
            target: OverrideTarget::Git {
                url: "https://fork.example.com/foo.git".into(),
                git_ref: "patched".into(),
            },
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
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = graph.deps.iter().find(|d| d.name == "foo").unwrap();
    match foo.provenances.first().expect("provenance") {
        ProvenanceRecord::Git { url, ref_spec, .. } => {
            assert_eq!(url, "https://fork.example.com/foo.git");
            assert_eq!(ref_spec.as_deref(), Some("patched"));
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
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let shared: Vec<_> = graph.deps.iter().filter(|d| d.name == "shared").collect();
    assert_eq!(shared.len(), 1);
    match shared[0].provenances.first().expect("provenance") {
        ProvenanceRecord::Git { url, .. } => assert_eq!(url, "https://fork.example.com/shared.git"),
        other => panic!("expected git, got {other:?}"),
    }
    assert!(
        reg.calls()
            .iter()
            .all(|c| c.1 != "https://upstream.example.com/shared.git"),
        "upstream shared must not be fetched"
    );
}

// ---------------------------------------------------------------------------
// S2a (#131) characterization tests — regression net for the SSOT refactor
// that routes extract_requires through edge_sources::resolve_edges.
// These tests pin behaviors that must be preserved after the refactor.
// ---------------------------------------------------------------------------

#[test]
fn s2a_transitive_milpa_kdl_flag_inactive_dep_excluded() {
    // Characterization test for S2a: a transitive dep that has a milpa.kdl with
    // a flag-gated sub-dep (default=#false) must NOT appear in the resolved graph.
    // After the S2a refactor, this behavior flows through resolve_edges (which
    // uses the flag-aware MilpaKdlEdgeSource), not the inline clause-d block.
    let extra_url = "https://example.com/s2a-extra.git";
    let parent_url = "https://example.com/s2a-parent.git";
    let parent_kdl = r#"name "s2aparent"
kind "library"
flags {
    feature_x default=#false
}
deps {
    when flag="feature_x" {
        s2aextra git=(url)"https://example.com/s2a-extra.git" ref="main"
    }
}"#;
    let reg = FakeReg::git(&[
        (parent_url, "main", milpa_kdl("s2achar01s2achar01s2achar01s2achar01s2achar01", parent_kdl)),
        (extra_url, "main", nimble("s2achar02s2achar02s2achar02s2achar02s2achar02", "")),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("s2aparent", parent_url, "main")]);
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
    assert!(
        graph.deps.iter().all(|d| d.name != "s2aextra"),
        "s2aextra must be excluded: flag feature_x is default=#false"
    );
    assert!(
        reg.calls().iter().all(|c| c.1 != extra_url),
        "s2aextra must never be fetched"
    );
}

#[test]
fn s2a_transitive_milpa_kdl_flag_active_via_default_dep_included() {
    // Complement of the above: with default=#true, the flag-gated sub-dep IS included.
    // URL tail is "s2aextray" so the resolver assigns dep name "s2aextray".
    let extra_url = "https://example.com/s2aextray.git";
    let parent_url = "https://example.com/s2aparenton.git";
    let parent_kdl = r#"name "s2aparenton"
kind "library"
flags {
    feature_y default=#true
}
deps {
    when flag="feature_y" {
        s2aextray git=(url)"https://example.com/s2aextray.git" ref="main"
    }
}"#;
    let reg = FakeReg::git(&[
        (parent_url, "main", milpa_kdl("s2achar03s2achar03s2achar03s2achar03s2achar03", parent_kdl)),
        (extra_url, "main", nimble("s2achar04s2achar04s2achar04s2achar04s2achar04", "")),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("s2aparenton", parent_url, "main")]);
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
    assert!(
        graph.deps.iter().any(|d| d.name == "s2aextray"),
        "s2aextray must be included: flag feature_y is default=#true"
    );
    assert!(
        reg.calls().iter().any(|c| c.1 == extra_url),
        "s2aextray must be fetched"
    );
}

#[test]
fn s2a_override_routes_transitive_named_dep_in_milpa_kdl_to_fork() {
    // Characterization test: a transitive NAMED dep declared in a milpa.kdl
    // that has a root-level override must enter the solver as eq_sentinel
    // (via overrides_by_name in edgeset_to_extracted), and the override must
    // route the fetch to the fork URL.
    // After the S2a refactor this same path flows through resolve_edges.
    //
    // translib's milpa.kdl declares "s2ashared" as a named dep (no URL).
    // Root override: s2ashared → fork. The named dep in translib's EdgeSet must
    // be recognized as overridden and enqueued as Item::Named{ eq_sentinel }.
    let translib_url = "https://example.com/s2atranslib.git";
    let fork_url = "https://fork.example.com/s2ashared.git";
    let translib_kdl = r#"name "s2atranslib"
kind "library"
deps {
    s2ashared ">= 1.0.0"
}"#;
    let reg = FakeReg::git(&[
        (translib_url, "main", milpa_kdl("s2achar05s2achar05s2achar05s2achar05s2achar05", translib_kdl)),
        (fork_url, "main", nimble("s2achar06s2achar06s2achar06s2achar06s2achar06", "")),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    // Root has no s2ashared dep directly — only an override routing it to fork.
    let m = manifest_full(
        vec![url_dep("s2atranslib", translib_url, "main")],
        Vec::new(),
        vec![Override {
            name: "s2ashared".into(),
            target: OverrideTarget::Git {
                url: fork_url.into(),
                git_ref: "main".into(),
            },
        }],
    );
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
    let shared: Vec<_> = graph.deps.iter().filter(|d| d.name == "s2ashared").collect();
    assert_eq!(shared.len(), 1, "s2ashared must appear exactly once");
    match shared[0].provenances.first().expect("provenance") {
        ProvenanceRecord::Git { url, .. } => {
            assert_eq!(url, fork_url, "s2ashared must come from the fork (override)");
        }
        other => panic!("expected git provenance, got {other:?}"),
    }
    assert!(
        reg.calls().iter().any(|c| c.1 == fork_url),
        "fork must be fetched"
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
        None,
        false,
        &cas_store(&tmp),
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
        None,
        false,
        &cas_store(&tmp),
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
        predicates: vec![],
    })]);
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let dep = graph.deps.iter().find(|d| d.name == "liblocal").unwrap();
    assert_eq!(dep.src_dir, "src");
    match dep.provenances.first().expect("provenance") {
        // The recorded path is the declared relative path, not the absolute copy.
        ProvenanceRecord::Local { path, .. } => assert_eq!(path, "liblocal"),
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
        None,
        false,
        &cas_store(&tmp),
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
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "MAN-NIMBLE-CONSTRAINT");
}

#[test]
fn resolve_prior_lockfile_pin_rejects_hostile_bytes() {
    // §8 / Phase D item 3: the prior lockfile pins an identity that does NOT
    // match the bytes the fetch delivers → supply-chain signal →
    // FETCH-PROVENANCE-DIVERGENCE (raised immediately, not folded into FETCH-ALL-FAILED).
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
            namespace: None,
            identity: Some(
                "dag-sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            version: "0.0.1".into(),
            src_dir: "src".into(),
            requires: Vec::new(),
            provenances: vec![ProvenanceRecord::Git {
                url: "https://example.com/foo.git".into(),
                ref_spec: Some("main".into()),
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            }],
            active_flags: Vec::new(),
            dep_decl: None,
            cond_requires: Vec::new(),
            aliases: Vec::new(),
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
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "FETCH-PROVENANCE-DIVERGENCE");
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
            namespace: None,
            identity: Some(identity.clone()),
            version: "0.0.1".into(),
            src_dir: "src".into(),
            requires: Vec::new(),
            provenances: vec![ProvenanceRecord::Git {
                url: "https://example.com/foo.git".into(),
                ref_spec: Some("main".into()),
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            }],
            active_flags: Vec::new(),
            dep_decl: None,
            cond_requires: Vec::new(),
            aliases: Vec::new(),
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
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = graph.deps.iter().find(|d| d.name == "foo").unwrap();
    assert_eq!(foo.identity, identity);
}

// ---------------------------------------------------------------------------
// D-fallback tests (RFC Phase D item 3): transport-failure vs identity-divergence
// ---------------------------------------------------------------------------

fn url_dep_with_mirrors(name: &str, git: &str, refp: &str, mirrors: Vec<&str>) -> Dep {
    Dep::Url(UrlDep {
        name: name.to_string(),
        git: git.to_string(),
        git_ref: refp.to_string(),
        mirrors: mirrors.iter().map(|s| s.to_string()).collect(),
        predicates: Vec::new(),
        flag_requests: Vec::new(),
        optional: false,
    })
}

fn prior_with_zero_identity(dep_name: &str, url: &str) -> Lockfile {
    Lockfile {
        version: LOCKFILE_SCHEMA_VERSION,
        strategy: "maxver".into(),
        deps: vec![LockedDep {
            name: dep_name.into(),
            namespace: None,
            identity: Some(
                "dag-sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            version: "0.0.1".into(),
            src_dir: "src".into(),
            requires: Vec::new(),
            provenances: vec![ProvenanceRecord::Git {
                url: url.into(),
                ref_spec: Some("main".into()),
                commit_sha: None,
                origin: "observed".into(),
                submodule_shas: vec![],
            }],
            active_flags: Vec::new(),
            dep_decl: None,
            cond_requires: Vec::new(),
            aliases: Vec::new(),
        }],
    }
}

/// DF-1: primary transport-fails, mirror succeeds → mirror becomes observed.
#[test]
fn resolve_df1_transport_fail_falls_through_to_mirror() {
    // Primary has no mock (transport fail); mirror has a mock (succeeds).
    let primary = "https://primary.example.com/foo.git";
    let mirror = "https://mirror.example.com/foo.git";
    let reg = FakeReg::git(&[(mirror, "main", nimble("m", "srcDir = \"src\"\n"))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep_with_mirrors("foo", primary, "main", vec![mirror])]);
    let graph = resolve(
        &m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap();
    assert_eq!(graph.deps.len(), 1);
    // Mirror becomes observed.
    let foo = &graph.deps[0];
    let observed: Vec<_> = foo.provenances.iter().filter(|p| {
        matches!(p, ProvenanceRecord::Git { origin, .. } if origin == "observed")
    }).collect();
    assert_eq!(observed.len(), 1);
    if let ProvenanceRecord::Git { url, .. } = observed[0] {
        assert_eq!(url, mirror, "mirror must be the observed provenance");
    }
    // Primary was also contacted (transport-fail) and is now declared.
    let called = reg.calls();
    assert!(called.iter().any(|(_, u, _)| u == primary), "primary must have been tried");
    assert!(called.iter().any(|(_, u, _)| u == mirror), "mirror must have been tried");
}

/// DF-2a: primary fetch SUCCEEDS but returns WRONG identity → FETCH-PROVENANCE-DIVERGENCE.
#[test]
fn resolve_df2_identity_divergence_raises_immediately() {
    // Primary has a mock (succeeds) but the prior pin is an all-zeros identity
    // that will never match → supply-chain signal → FETCH-PROVENANCE-DIVERGENCE.
    let primary = "https://example.com/foo.git";
    let reg = FakeReg::git(&[(primary, "main", nimble("f", "srcDir = \"src\"\n"))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("foo", primary, "main")]);
    let prior = prior_with_zero_identity("foo", primary);
    let err = resolve(
        &m, None, &reg, None, Some(&prior), Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(
        err.code(), "FETCH-PROVENANCE-DIVERGENCE",
        "identity mismatch must raise FETCH-PROVENANCE-DIVERGENCE, not be swallowed"
    );
}

/// DF-2b: divergence must NOT fall through to the mirror — mirror is never contacted.
#[test]
fn resolve_df2_divergence_does_not_try_mirror() {
    let primary = "https://primary.example.com/foo.git";
    let mirror = "https://mirror.example.com/foo.git";
    // Both primary and mirror have mocks so if mirror were contacted it would succeed.
    // The prior pins an all-zeros identity that won't match → divergence on primary.
    let reg = FakeReg::git(&[
        (primary, "main", nimble("p", "srcDir = \"src\"\n")),
        (mirror, "main", nimble("m", "srcDir = \"src\"\n")),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep_with_mirrors("foo", primary, "main", vec![mirror])]);
    let prior = prior_with_zero_identity("foo", primary);
    let err = resolve(
        &m, None, &reg, None, Some(&prior), Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "FETCH-PROVENANCE-DIVERGENCE");
    // Mirror must NOT have been contacted.
    let called = reg.calls();
    assert!(
        !called.iter().any(|(_, u, _)| u == mirror),
        "mirror must NOT be contacted after primary diverged; calls: {called:?}"
    );
}

/// DF-3: ALL candidates transport-fail → FETCH-ALL-FAILED (preserved behavior).
#[test]
fn resolve_df3_all_transport_fail_raises_fetch_all_failed() {
    // Neither primary nor mirror has a mock → all transport-fail.
    let primary = "https://primary.example.com/foo.git";
    let mirror = "https://mirror.example.com/foo.git";
    let reg = FakeReg::default(); // no mocks
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep_with_mirrors("foo", primary, "main", vec![mirror])]);
    let err = resolve(
        &m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "FETCH-ALL-FAILED");
    // Both candidates must have been tried.
    let called = reg.calls();
    assert!(called.iter().any(|(_, u, _)| u == primary), "primary must be tried");
    assert!(called.iter().any(|(_, u, _)| u == mirror), "mirror must be tried");
}

/// DF-4: fresh resolve, no prior pin → no identity gate, first candidate adopted.
#[test]
fn resolve_df4_fresh_resolve_no_prior_no_divergence_check() {
    let primary = "https://example.com/foo.git";
    let reg = FakeReg::git(&[(primary, "main", nimble("f", "srcDir = \"src\"\n"))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("foo", primary, "main")]);
    // No prior lockfile → no expected_identity → no gate.
    let graph = resolve(
        &m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap();
    assert_eq!(graph.deps.len(), 1);
    let foo = &graph.deps[0];
    let observed: Vec<_> = foo.provenances.iter().filter(|p| {
        matches!(p, ProvenanceRecord::Git { origin, .. } if origin == "observed")
    }).collect();
    assert_eq!(observed.len(), 1);
    if let ProvenanceRecord::Git { url, .. } = observed[0] {
        assert_eq!(url, primary);
    }
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
        optional: false,
    })]);
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    assert_eq!(graph.deps.len(), 1);
    assert_eq!(graph.deps[0].name, "foo");
}

/// Phase B tracer bullet: two URL deps, identical content → one node.
/// Canonical = BFS-insertion order (first DECLARED), not lex-min.
/// `foo` is declared first → canonical is "foo"; alias is "bar".
#[test]
fn resolve_content_hash_dedup_bfs_first_wins() {
    let identical = milpa_kdl("x", "name \"shared\"\nkind \"library\"\nsrc_dir \"src\"\n");
    let reg = FakeReg::git(&[
        ("https://example.com/foo.git", "main", identical.clone()),
        ("https://example.com/bar.git", "main", identical),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    // Declared order: foo first, bar second → BFS canonical = foo.
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
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    assert_eq!(graph.deps.len(), 1, "deduped to one node");
    assert_eq!(graph.deps[0].name, "foo", "BFS-first declared wins (not lex-min)");
    assert_eq!(
        graph.deps[0].aliases,
        vec!["bar".to_string()],
        "alias should be 'bar'"
    );
}

/// Phase B BFS-beats-lex: root-declared 'zlib' + root-declared 'aaa-zlib' (lex-earlier)
/// with identical content → canonical must be 'zlib' (BFS-first), not 'aaa-zlib' (lex-min).
#[test]
fn resolve_content_hash_dedup_bfs_order_beats_lex_min() {
    let identical = milpa_kdl("x", "name \"shared\"\nkind \"library\"\nsrc_dir \"src\"\n");
    let reg = FakeReg::git(&[
        ("https://example.com/zlib.git", "main", identical.clone()),
        ("https://example.com/aaa-zlib.git", "main", identical),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    // Declared order: zlib first, aaa-zlib second.
    // Lex-min would be 'aaa-zlib'. BFS-first is 'zlib'. BFS must win.
    let m = manifest(vec![
        url_dep("zlib", "https://example.com/zlib.git", "main"),
        url_dep("aaa-zlib", "https://example.com/aaa-zlib.git", "main"),
    ]);
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    assert_eq!(graph.deps.len(), 1, "deduped to one node");
    assert_eq!(
        graph.deps[0].name, "zlib",
        "BFS-first canonical should be 'zlib', not lex-min 'aaa-zlib'"
    );
    assert_eq!(
        graph.deps[0].aliases,
        vec!["aaa-zlib".to_string()],
        "alias should be 'aaa-zlib'"
    );
}

/// Phase B: a dep that `requires` an aliased name has its requires rewritten to canonical.
/// baz requires bar; bar is an alias of foo (same content) → baz.requires = [foo].
#[test]
fn resolve_dedup_requires_rewritten_to_canonical() {
    let shared = milpa_kdl("x", "name \"shared\"\nkind \"library\"\nsrc_dir \"src\"\n");
    // baz declares 'bar' as a dep
    let baz_kdl_body = concat!(
        "name \"baz\"\nkind \"library\"\nsrc_dir \"src\"\n",
        "deps {\n    bar git=(url)\"https://example.com/bar.git\" ref=\"main\"\n}\n"
    );
    let baz_mock = milpa_kdl("x", baz_kdl_body);
    let reg = FakeReg::git(&[
        ("https://example.com/foo.git", "main", shared.clone()),
        ("https://example.com/bar.git", "main", shared),
        ("https://example.com/baz.git", "main", baz_mock),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![
        url_dep("foo", "https://example.com/foo.git", "main"),
        url_dep("bar", "https://example.com/bar.git", "main"),
        url_dep("baz", "https://example.com/baz.git", "main"),
    ]);
    let graph = resolve(
        &m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false,
        &cas_store(&tmp),
    )
    .unwrap();
    let names: Vec<&str> = graph.deps.iter().map(|d| d.name.as_str()).collect();
    assert!(!names.contains(&"bar"), "'bar' must be deduped away: {names:?}");
    assert!(names.contains(&"foo"), "'foo' must be canonical: {names:?}");
    assert!(names.contains(&"baz"), "'baz' must survive: {names:?}");

    let baz_dep = graph.deps.iter().find(|d| d.name == "baz").unwrap();
    assert!(
        baz_dep.requires.contains(&"foo".to_string()),
        "baz.requires must contain 'foo' after rewrite: {:?}",
        baz_dep.requires
    );
    assert!(
        !baz_dep.requires.contains(&"bar".to_string()),
        "baz.requires must NOT contain 'bar' after rewrite: {:?}",
        baz_dep.requires
    );
}

/// Phase B: two deps with DIFFERENT content must NOT be merged.
#[test]
fn resolve_dedup_different_content_not_merged() {
    let alpha = milpa_kdl("x", "name \"alpha\"\nkind \"library\"\nsrc_dir \"src\"\n");
    let beta = milpa_kdl("x", "name \"beta\"\nkind \"library\"\nsrc_dir \"lib\"\n");
    let reg = FakeReg::git(&[
        ("https://example.com/alpha.git", "main", alpha),
        ("https://example.com/beta.git", "main", beta),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![
        url_dep("alpha", "https://example.com/alpha.git", "main"),
        url_dep("beta", "https://example.com/beta.git", "main"),
    ]);
    let graph = resolve(
        &m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false,
        &cas_store(&tmp),
    )
    .unwrap();
    assert_eq!(graph.deps.len(), 2, "different-content deps must not be merged");
    let names: Vec<&str> = graph.deps.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"alpha") && names.contains(&"beta"), "both must survive: {names:?}");
    for dep in &graph.deps {
        assert!(dep.aliases.is_empty(), "no aliases for non-deduped dep {:?}", dep.name);
    }
}

/// Phase B: three deps with identical content → one canonical + two lex-sorted aliases.
#[test]
fn resolve_dedup_three_way_one_canonical_two_aliases() {
    let shared = milpa_kdl("x", "name \"shared\"\nkind \"library\"\nsrc_dir \"src\"\n");
    let reg = FakeReg::git(&[
        ("https://example.com/foo.git", "main", shared.clone()),
        ("https://example.com/bar.git", "main", shared.clone()),
        ("https://example.com/baz.git", "main", shared),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    // Declared: foo, bar, baz → BFS canonical = foo (declared first).
    let m = manifest(vec![
        url_dep("foo", "https://example.com/foo.git", "main"),
        url_dep("bar", "https://example.com/bar.git", "main"),
        url_dep("baz", "https://example.com/baz.git", "main"),
    ]);
    let graph = resolve(
        &m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false,
        &cas_store(&tmp),
    )
    .unwrap();
    assert_eq!(graph.deps.len(), 1, "three-way dedup → one node");
    assert_eq!(graph.deps[0].name, "foo", "BFS-first canonical");
    assert_eq!(
        graph.deps[0].aliases,
        vec!["bar".to_string(), "baz".to_string()],
        "aliases must be lex-sorted"
    );
}

/// Regression: fixture-115 — dep with `platform "windows"` child-node predicate
/// is excluded when `MILPA_TARGET_PLATFORM=linux` (§6.2 + §6.6).
#[test]
fn resolve_profile_excludes_platform_mismatch() {
    let reg = FakeReg::default(); // no mocks needed — dep must not be fetched
    let tmp = tempfile::tempdir().unwrap();
    let dep = Dep::Url(UrlDep {
        name: "winonly".into(),
        git: "https://github.com/example/winonly.git".into(),
        git_ref: "main".into(),
        mirrors: Vec::new(),
        predicates: vec![Predicate {
            name: "platform".into(),
            values: vec!["windows".into()],
            negated: false,
        }],
        flag_requests: Vec::new(),
        optional: false,
    });
    let m = manifest(vec![dep]);
    let profile = Profile {
        platform: Some("linux".into()),
        arch: Some("amd64".into()),
        nim_version: Some(v(2, 0, 0)),
        ..Profile::default()
    };
    let graph = resolve(
        &m,
        None,
        &reg,
        Some(&profile),
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    assert!(graph.deps.is_empty(), "windows-gated dep excluded on linux");
    assert!(reg.calls().is_empty(), "excluded dep must never be fetched");
}

/// Dep with matching platform predicate IS included when the profile matches.
#[test]
fn resolve_profile_includes_platform_match() {
    let reg = FakeReg::git(&[(
        "https://github.com/example/linuxonly.git",
        "main",
        nimble("abc", "srcDir = \"src\"\n"),
    )]);
    let tmp = tempfile::tempdir().unwrap();
    let dep = Dep::Url(UrlDep {
        name: "linuxonly".into(),
        git: "https://github.com/example/linuxonly.git".into(),
        git_ref: "main".into(),
        mirrors: Vec::new(),
        predicates: vec![Predicate {
            name: "platform".into(),
            values: vec!["linux".into()],
            negated: false,
        }],
        flag_requests: Vec::new(),
        optional: false,
    });
    let m = manifest(vec![dep]);
    let profile = Profile {
        platform: Some("linux".into()),
        ..Profile::default()
    };
    let graph = resolve(
        &m,
        None,
        &reg,
        Some(&profile),
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    assert_eq!(graph.deps.len(), 1, "linux-gated dep included on linux");
    assert_eq!(graph.deps[0].name, "linuxonly");
}

/// S4 / §3.C — a NEGATED predicate over an ABSENT axis must EXCLUDE the dep.
///
/// `when arch != "arm64"` with `arch=None` is indeterminate ⇒ false, NOT true.
/// Before the fix, `any_match=false` for absent axis, then `!false = true` ⟹ dep included.
/// After the fix, absent axis short-circuits to `false` regardless of `negated`.
#[test]
fn resolve_partial_profile_negated_absent_axis_excludes() {
    let reg = FakeReg::default(); // dep must not be fetched
    let tmp = tempfile::tempdir().unwrap();
    let dep = Dep::Url(UrlDep {
        name: "archlib".into(),
        git: "https://github.com/example/archlib.git".into(),
        git_ref: "main".into(),
        mirrors: Vec::new(),
        predicates: vec![Predicate {
            name: "arch".into(),
            values: vec!["arm64".into()],
            negated: true, // `when arch != "arm64"` — true on amd64, but arch is absent
        }],
        flag_requests: Vec::new(),
        optional: false,
    });
    let m = manifest(vec![dep]);
    // Partial profile: platform known, arch absent.
    let profile = Profile {
        platform: Some("linux".into()),
        arch: None, // absent axis
        nim_version: None,
        milpa_version: None,
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
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    // Absent axis ⇒ indeterminate ⇒ excluded regardless of negation (§3.C / §6).
    assert!(
        graph.deps.is_empty(),
        "negated predicate over absent axis must EXCLUDE the dep, not include it"
    );
    assert!(reg.calls().is_empty(), "excluded dep must never be fetched");
}

/// S4 / §3.C — a POSITIVE predicate over an ABSENT axis also EXCLUDES the dep.
/// (This already worked before S4; verifying it stays correct after the fix.)
#[test]
fn resolve_partial_profile_positive_absent_axis_excludes() {
    let reg = FakeReg::default();
    let tmp = tempfile::tempdir().unwrap();
    let dep = Dep::Url(UrlDep {
        name: "amdlib".into(),
        git: "https://github.com/example/amdlib.git".into(),
        git_ref: "main".into(),
        mirrors: Vec::new(),
        predicates: vec![Predicate {
            name: "arch".into(),
            values: vec!["amd64".into()],
            negated: false, // `when arch == "amd64"` — arch is absent
        }],
        flag_requests: Vec::new(),
        optional: false,
    });
    let m = manifest(vec![dep]);
    let profile = Profile {
        platform: Some("linux".into()),
        arch: None,
        nim_version: None,
        milpa_version: None,
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
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    assert!(
        graph.deps.is_empty(),
        "positive predicate over absent axis must EXCLUDE the dep"
    );
    assert!(reg.calls().is_empty());
}

/// Absent profile includes deps regardless of predicates (§6 absent-profile rule).
#[test]
fn resolve_absent_profile_includes_platform_gated_dep() {
    let reg = FakeReg::git(&[(
        "https://github.com/example/winonly.git",
        "main",
        nimble("abc", "srcDir = \"src\"\n"),
    )]);
    let tmp = tempfile::tempdir().unwrap();
    let dep = Dep::Url(UrlDep {
        name: "winonly".into(),
        git: "https://github.com/example/winonly.git".into(),
        git_ref: "main".into(),
        mirrors: Vec::new(),
        predicates: vec![Predicate {
            name: "platform".into(),
            values: vec!["windows".into()],
            negated: false,
        }],
        flag_requests: Vec::new(),
        optional: false,
    });
    let m = manifest(vec![dep]);
    let graph = resolve(
        &m,
        None,
        &reg,
        None, // absent profile
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    assert_eq!(graph.deps.len(), 1, "absent profile includes all deps");
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
        optional: false,
    });
    let m = manifest(vec![dep]);
    let profile = Profile {
        nim_version: Some(v(1, 9, 0)),
        ..Profile::default()
    };
    let graph = resolve(
        &m,
        None,
        &reg,
        Some(&profile),
        None,
        Strategy::Maxver,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
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
        optional: false,
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
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    assert_eq!(graph.deps.len(), 1);
}

// --- seed_root flag-gate characterization (§6 + S7, #179 migration guard) ---
//
// These two tests pin the flag-gate behavior of the `seed_root` path — i.e.
// the filtering that `resolve_with_features` applies to the root manifest
// when a profile is present (`Some(p)` arm, line ~228).  They must pass GREEN
// BEFORE and AFTER the migration from `filter_manifest_by_profile` to the
// unified `FilterCtx` + `filter_manifest` path.  If the two implementations
// are NOT semantically equivalent these tests catch the divergence.

#[test]
fn seed_root_flag_gate_default_flag_includes_dep() {
    // §6 / S7: a root dep gated by `when flag="feat"` is INCLUDED when the
    // manifest declares `flags { feat default=#true }` and a profile is present.
    // `filter_manifest_by_profile` computes the flag closure over manifest
    // defaults and enriches `profile.flags`; the closure includes "feat".
    // After migration: `FilterCtx::build(manifest, Some(p), None)` computes
    // the same `active_flags` set → identical result.
    let reg = FakeReg::git(&[(
        "https://example.com/optlib.git",
        "main",
        nimble("optlib", "srcDir = \"src\"\n"),
    )]);
    let tmp = tempfile::tempdir().unwrap();
    let dep = Dep::Url(UrlDep {
        name: "optlib".into(),
        git: "https://example.com/optlib.git".into(),
        git_ref: "main".into(),
        mirrors: Vec::new(),
        predicates: vec![Predicate {
            name: "flag".into(),
            values: vec!["feat".into()],
            negated: false,
        }],
        flag_requests: Vec::new(),
        optional: false,
    });
    let mut m = manifest(vec![dep]);
    m.flags.push(milpa_manifest::FlagDecl {
        name: "feat".into(),
        default: true,
        description: String::new(),
        defines: Vec::new(),
        enables_same_pkg: Vec::new(),
        enables_cross_pkg: Vec::new(),
        conflicts: Vec::new(),
    });
    let profile = Profile { platform: Some("linux".into()), ..Profile::default() };
    let graph = resolve(
        &m, None, &reg, Some(&profile), None, Strategy::Maxver,
        &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap();
    assert_eq!(graph.deps.len(), 1, "default-active flag → dep included via seed_root");
    assert_eq!(graph.deps[0].name, "optlib");
}

#[test]
fn seed_root_flag_gate_inactive_flag_excludes_dep() {
    // §6 / S7: a root dep gated by `when flag="nodef"` is EXCLUDED when the
    // manifest declares `flags { nodef default=#false }` and a profile is present.
    // The flag is not in the closure of default-true flags → enriched
    // `profile.flags` does NOT contain "nodef" → dep filtered out.
    // After migration: `FilterCtx::build` active_flags also omits "nodef" →
    // dep_passes_flag_predicates returns false → same exclusion.
    let reg = FakeReg::default(); // dep must never be fetched
    let tmp = tempfile::tempdir().unwrap();
    let dep = Dep::Url(UrlDep {
        name: "optlib2".into(),
        git: "https://example.com/optlib2.git".into(),
        git_ref: "main".into(),
        mirrors: Vec::new(),
        predicates: vec![Predicate {
            name: "flag".into(),
            values: vec!["nodef".into()],
            negated: false,
        }],
        flag_requests: Vec::new(),
        optional: false,
    });
    let mut m = manifest(vec![dep]);
    m.flags.push(milpa_manifest::FlagDecl {
        name: "nodef".into(),
        default: false,
        description: String::new(),
        defines: Vec::new(),
        enables_same_pkg: Vec::new(),
        enables_cross_pkg: Vec::new(),
        conflicts: Vec::new(),
    });
    let profile = Profile { platform: Some("linux".into()), ..Profile::default() };
    let graph = resolve(
        &m, None, &reg, Some(&profile), None, Strategy::Maxver,
        &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap();
    assert!(graph.deps.is_empty(), "inactive flag → dep excluded via seed_root");
    assert!(reg.calls().is_empty(), "excluded dep must never be fetched");
}

// --- tarball TOFU pinning (lockfile-schema.md §5, issue #116) ---------------

#[test]
fn resolve_tarball_first_fetch_records_archive_sha256() {
    // §5: a tarball dep declared without a manifest `sha256=` undergoes first-use
    // pinning — the downloaded archive's sha256 is recorded in the lockfile's
    // tarball provenance. (RED before the fix: the record drops it to `None`.)
    let url = "https://example.com/foo.tar.gz";
    let body = "srcDir = \"src\"\n";
    let reg = tarball_reg(&[(url, tarball_mock("archivesha_aaaa", body))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![tarball_dep("foo", url, None)]);
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
    let foo = graph.deps.iter().find(|d| d.name == "foo").unwrap();
    assert_eq!(
        foo.provenances.first().cloned(),
        Some(ProvenanceRecord::Tarball {
            url: url.into(),
            sha256: Some("archivesha_aaaa".into()),
            origin: "observed".into(),
        })
    );
    // D-lifecycle: tarball deps have no mirrors → single observed provenance.
    assert_eq!(foo.provenances.len(), 1);
}

/// Build a prior lockfile pinning `name` to `identity` with a tarball provenance
/// recording `sha256` (the TOFU pin).
fn tarball_prior(name: &str, url: &str, identity: &str, sha256: &str) -> Lockfile {
    Lockfile {
        version: LOCKFILE_SCHEMA_VERSION,
        strategy: "maxver".into(),
        deps: vec![LockedDep {
            name: name.into(),
            namespace: None,
            identity: Some(identity.into()),
            version: "0.0.1".into(),
            src_dir: "src".into(),
            requires: Vec::new(),
            provenances: vec![ProvenanceRecord::Tarball {
                url: url.into(),
                sha256: Some(sha256.into()),
                origin: "observed".into(),
            }],
            active_flags: Vec::new(),
            dep_decl: None,
            cond_requires: Vec::new(),
            aliases: Vec::new(),
        }],
    }
}

#[test]
fn resolve_tarball_refetch_rejects_substituted_archive() {
    // §5: on refetch of a TOFU-pinned tarball, the resolver MUST supply the locked
    // sha256 as the expected archive hash. Here the remote archive has been
    // substituted (different bytes → different archive sha) but extracts to the
    // SAME tree, so the identity gate alone would pass — only the archive-level
    // pin catches it. RED before the fix: expected_sha256 is None → accepted.
    let url = "https://example.com/foo.tar.gz";
    let body = "srcDir = \"src\"\n";
    let identity = hash_of_nimble("foo", body);
    // Substituted archive: same body (identity matches) but a different sha.
    let reg = tarball_reg(&[(url, tarball_mock("archivesha_BBBB", body))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![tarball_dep("foo", url, None)]);
    let prior = tarball_prior("foo", url, &identity, "archivesha_AAAA");
    let err = resolve(
        &m,
        None,
        &reg,
        None,
        Some(&prior),
        Strategy::Maxver,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "FETCH-ALL-FAILED");
    let MilpaError::Fetch(FetchError::AllFailed(msg)) = &err else {
        panic!("expected AllFailed, got {err:?}");
    };
    assert!(
        msg.contains("FETCH-SHA256-MISMATCH"),
        "substituted archive must be rejected at the archive boundary, got: {msg}"
    );
}

#[test]
fn resolve_tarball_refetch_preserves_pin() {
    // §5: a matching refetch rewrites the lockfile with the TOFU pin intact —
    // the archive sha256 must not silently drop to None. RED before the fix: the
    // record used the (absent) manifest sha256.
    let url = "https://example.com/foo.tar.gz";
    let body = "srcDir = \"src\"\n";
    let identity = hash_of_nimble("foo", body);
    let reg = tarball_reg(&[(url, tarball_mock("archivesha_AAAA", body))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![tarball_dep("foo", url, None)]);
    let prior = tarball_prior("foo", url, &identity, "archivesha_AAAA");
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        Some(&prior),
        Strategy::Maxver,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = graph.deps.iter().find(|d| d.name == "foo").unwrap();
    assert_eq!(
        foo.provenances.first().cloned(),
        Some(ProvenanceRecord::Tarball {
            url: url.into(),
            sha256: Some("archivesha_AAAA".into()),
            origin: "observed".into(),
        })
    );
}

#[test]
fn resolve_tarball_manifest_sha256_mismatch_rejected_on_first_fetch() {
    // §5: a manifest-declared `sha256=` is an explicit pin enforced from the very
    // first fetch — a non-matching archive is rejected at the archive boundary
    // even with no prior lockfile.
    let url = "https://example.com/foo.tar.gz";
    let body = "srcDir = \"src\"\n";
    let reg = tarball_reg(&[(url, tarball_mock("archivesha_actual", body))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![tarball_dep("foo", url, Some("archivesha_declared"))]);
    let err = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap_err();
    assert_eq!(err.code(), "FETCH-ALL-FAILED");
    let MilpaError::Fetch(FetchError::AllFailed(msg)) = &err else {
        panic!("expected AllFailed, got {err:?}");
    };
    assert!(msg.contains("FETCH-SHA256-MISMATCH"), "got: {msg}");
}

// ---------------------------------------------------------------------------
// S4c (RFC #23 §3.1.4): exclusion (conflicts) + RESOLVE-FLAG-CONFLICT
// ---------------------------------------------------------------------------

/// Build a UrlDep with flag requests for use in S4c tests.
fn url_dep_with_flags(name: &str, git: &str, refp: &str, flag_reqs: Vec<milpa_manifest::FlagRequest>) -> Dep {
    Dep::Url(UrlDep {
        name: name.to_string(),
        git: git.to_string(),
        git_ref: refp.to_string(),
        mirrors: Vec::new(),
        predicates: Vec::new(),
        flag_requests: flag_reqs,
        optional: false,
    })
}

/// Helper: parse manifest KDL and extract the error code (mirrors manifest test doc_err).
fn manifest_parse_err(text: &str) -> &'static str {
    match milpa_manifest::parse_manifest(text) {
        Err(e) => e.code,
        Ok(_) => panic!("expected ManifestError"),
    }
}

/// Helper: parse manifest KDL and return the package Manifest.
fn parse_pkg(text: &str) -> milpa_manifest::Manifest {
    milpa_manifest::parse_manifest(text).expect("expected a package manifest")
}

#[test]
fn s4c_man_flag_conflicts_undeclared_parse_error() {
    // MAN-FLAG-CONFLICTS-UNDECLARED: conflicts references undeclared flag.
    // Mirrors test_s4c_conflicts.py::TestManFlagConflictsUndeclared::test_undeclared_conflicts_target_raises.
    let code = manifest_parse_err(
        r#"name "mylib"
kind "library"
flags {
    openssl default=#false {
        conflicts "bearssl"
    }
}"#,
    );
    assert_eq!(code, "MAN-FLAG-CONFLICTS-UNDECLARED");
}

#[test]
fn s4c_man_flag_conflicts_declared_accepted() {
    // conflicts referencing a declared flag → no error.
    let m = parse_pkg(
        r#"name "mylib"
kind "library"
flags {
    openssl default=#false {
        conflicts "bearssl"
    }
    bearssl default=#false
}"#,
    );
    let openssl = m.flags.iter().find(|f| f.name == "openssl").expect("openssl");
    assert!(openssl.conflicts.iter().any(|s| s == "bearssl"));
}

#[test]
fn s4c_man_flag_conflicts_forward_reference_accepted() {
    // forward reference in conflicts (target declared later) is legal (post-parse).
    let m = parse_pkg(
        r#"name "mylib"
kind "library"
flags {
    openssl default=#false {
        conflicts "bearssl"
    }
    bearssl default=#false
}"#,
    );
    // The post-parse pass validates after the full table is built; forward ref OK.
    let openssl = m.flags.iter().find(|f| f.name == "openssl").expect("openssl");
    assert_eq!(openssl.conflicts, vec!["bearssl"]);
}

#[test]
fn s4c_resolve_flag_conflict_both_defaults_true() {
    // Both openssl and bearssl default=#true, openssl conflicts bearssl.
    // Post-fixpoint validation must raise RESOLVE-FLAG-CONFLICT.
    // Payload: dep="lib-tls", flag_a="bearssl", flag_b="openssl" (lex order),
    //          sources_a=["default"], sources_b=["default"].
    let url = "https://example.com/lib-tls.git";
    let dep_kdl = r#"name "lib-tls"
kind "library"
flags {
    openssl default=#true {
        conflicts "bearssl"
    }
    bearssl default=#true
}"#;
    let reg = FakeReg::git(&[(url, "main", milpa_kdl("abcd0000abcd0000abcd0000abcd0000abcd0000", dep_kdl))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("lib-tls", url, "main")]);
    let err = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap_err();
    assert_eq!(err.code(), "RESOLVE-FLAG-CONFLICT");
}

#[test]
fn s4c_resolve_flag_conflict_payload_byte_identity() {
    // Normative payload (RFC #23 §3.1.4 + §5 risk #3):
    //   dep      — "lib-tls"
    //   flag_a   — "bearssl" (lexicographically smaller)
    //   flag_b   — "openssl" (lexicographically larger)
    //   sources_a — ["default"] (bearssl activated by DEFAULT)
    //   sources_b — ["default"] (openssl activated by DEFAULT)
    // Mirrors test_s4c_conflicts.py::TestS4cResolveIntegration::test_conflict_payload_byte_identity.
    let url = "https://example.com/lib-tls.git";
    let dep_kdl = r#"name "lib-tls"
kind "library"
flags {
    openssl default=#true {
        conflicts "bearssl"
    }
    bearssl default=#true
}"#;
    let reg = FakeReg::git(&[(url, "main", milpa_kdl("abcd1111abcd1111abcd1111abcd1111abcd1111", dep_kdl))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("lib-tls", url, "main")]);
    let err = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap_err();
    assert_eq!(err.code(), "RESOLVE-FLAG-CONFLICT");

    // Extract the structured payload from CoreError::FlagConflict.
    let crate::error::MilpaError::Core(crate::error::CoreError::FlagConflict {
        dep, flag_a, flag_b, sources_a, sources_b
    }) = &err else {
        panic!("expected CoreError::FlagConflict, got {err:?}");
    };

    // Payload fields — must be byte-identical to Python impl.
    assert_eq!(dep, "lib-tls");
    assert_eq!(flag_a, "bearssl");   // lex order: "bearssl" < "openssl"
    assert_eq!(flag_b, "openssl");
    assert_eq!(sources_a, &vec!["default".to_string()]); // bearssl: DEFAULT source
    assert_eq!(sources_b, &vec!["default".to_string()]); // openssl: DEFAULT source
}

#[test]
fn s4c_resolve_flag_conflict_only_one_active_no_error() {
    // openssl default=#true, bearssl default=#false → only openssl active → no conflict.
    // No false positive.
    let url = "https://example.com/lib-tls.git";
    let dep_kdl = r#"name "lib-tls"
kind "library"
flags {
    openssl default=#true {
        conflicts "bearssl"
    }
    bearssl default=#false
}"#;
    let reg = FakeReg::git(&[(url, "main", milpa_kdl("abcd2222abcd2222abcd2222abcd2222abcd2222", dep_kdl))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("lib-tls", url, "main")]);
    // Should succeed (no conflict).
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
    let dep_names: Vec<&str> = graph.deps.iter().map(|d| d.name.as_str()).collect();
    assert!(dep_names.contains(&"lib-tls"), "lib-tls should be in resolved graph");
}

#[test]
fn s4c_resolve_flag_conflict_symmetry_one_side_declared() {
    // Conflict declared on ONE flag only (openssl conflicts bearssl, but bearssl
    // does NOT declare conflicts "openssl") — still detected.
    // RFC §3.1.4: "Symmetric: declare once."  The check on openssl's conflicts list
    // fires when both are active.
    let url = "https://example.com/lib-tls.git";
    let dep_kdl = r#"name "lib-tls"
kind "library"
flags {
    openssl default=#true {
        conflicts "bearssl"
    }
    bearssl default=#true
}"#;
    let reg = FakeReg::git(&[(url, "main", milpa_kdl("abcd3333abcd3333abcd3333abcd3333abcd3333", dep_kdl))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("lib-tls", url, "main")]);
    let err = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap_err();
    assert_eq!(err.code(), "RESOLVE-FLAG-CONFLICT");
}

#[test]
fn s4c_resolve_flag_conflict_via_edge_request_sources_payload() {
    // openssl default=#true, bearssl default=#false.
    // Consumer requests bearssl (flag "bearssl") on lib-tls.
    // → openssl=DEFAULT, bearssl=EDGE_REQUEST → conflict.
    // Payload: flag_a="bearssl" (sources_a=["edge_request"]),
    //          flag_b="openssl" (sources_b=["default"]).
    // Mirrors test_s4c_conflicts.py::test_conflict_via_edge_request_sources_payload.
    let url = "https://example.com/lib-tls.git";
    let dep_kdl = r#"name "lib-tls"
kind "library"
flags {
    openssl default=#true {
        conflicts "bearssl"
    }
    bearssl default=#false
}"#;
    let reg = FakeReg::git(&[(url, "main", milpa_kdl("abcd4444abcd4444abcd4444abcd4444abcd4444", dep_kdl))]);
    let tmp = tempfile::tempdir().unwrap();

    let dep = url_dep_with_flags(
        "lib-tls", url, "main",
        vec![milpa_manifest::FlagRequest { name: "bearssl".to_string(), enabled: true }],
    );
    let m = manifest(vec![dep]);
    let err = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap_err();
    assert_eq!(err.code(), "RESOLVE-FLAG-CONFLICT");

    let crate::error::MilpaError::Core(crate::error::CoreError::FlagConflict {
        dep, flag_a, flag_b, sources_a, sources_b
    }) = &err else {
        panic!("expected CoreError::FlagConflict, got {err:?}");
    };

    assert_eq!(dep, "lib-tls");
    assert_eq!(flag_a, "bearssl");          // lex order
    assert_eq!(flag_b, "openssl");
    assert_eq!(sources_a, &vec!["edge_request".to_string()]); // bearssl: EDGE_REQUEST
    assert_eq!(sources_b, &vec!["default".to_string()]);      // openssl: DEFAULT
}

// ---------------------------------------------------------------------------
// S5: active_flags lockfile authority
// ---------------------------------------------------------------------------

#[test]
fn s5_single_active_flag_in_resolved_dep() {
    // Dep with openssl default=#true → ResolvedDep.active_flags = ["openssl"].
    let url = "https://example.com/lib-tls.git";
    let dep_kdl = r#"name "lib-tls"
kind "library"
flags {
    openssl default=#true {
        defines "ssl" "useOpenSSL"
    }
}"#;
    let reg = FakeReg::git(&[(url, "main", milpa_kdl("s5110000s5110000s5110000s5110000s5110000", dep_kdl))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("lib-tls", url, "main")]);
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
    let lib_tls = graph.deps.iter().find(|d| d.name == "lib-tls").expect("lib-tls in graph");
    assert_eq!(lib_tls.active_flags, vec!["openssl"]);
}

#[test]
fn s5_multiple_active_flags_lexicographically_sorted() {
    // Dep with zstd, aarch64, mbedtls all default=#true → lex order: aarch64 < mbedtls < zstd.
    let url = "https://example.com/lib-multi.git";
    let dep_kdl = r#"name "lib-multi"
kind "library"
flags {
    zstd default=#true
    aarch64 default=#true
    mbedtls default=#true
}"#;
    let reg = FakeReg::git(&[(url, "main", milpa_kdl("s5220000s5220000s5220000s5220000s5220000", dep_kdl))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("lib-multi", url, "main")]);
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
    let dep = graph.deps.iter().find(|d| d.name == "lib-multi").expect("lib-multi in graph");
    // Must be lexicographically sorted: aarch64 < mbedtls < zstd
    assert_eq!(dep.active_flags, vec!["aarch64", "mbedtls", "zstd"]);
}

#[test]
fn s5_no_active_flags_empty() {
    // Dep with all flags default=#false → active_flags empty.
    let url = "https://example.com/lib-none.git";
    let dep_kdl = r#"name "lib-none"
kind "library"
flags {
    openssl default=#false
    bearssl default=#false
}"#;
    let reg = FakeReg::git(&[(url, "main", milpa_kdl("s5330000s5330000s5330000s5330000s5330000", dep_kdl))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("lib-none", url, "main")]);
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
    let dep = graph.deps.iter().find(|d| d.name == "lib-none").expect("lib-none in graph");
    assert!(dep.active_flags.is_empty(), "expected empty active_flags, got {:?}", dep.active_flags);
}

#[test]
fn s5_active_flags_via_edge_request() {
    // Consumer requests openssl (default=#false) → active_flags = ["openssl"].
    let url = "https://example.com/lib-req.git";
    let dep_kdl = r#"name "lib-req"
kind "library"
flags {
    openssl default=#false
}"#;
    let reg = FakeReg::git(&[(url, "main", milpa_kdl("s5440000s5440000s5440000s5440000s5440000", dep_kdl))]);
    let tmp = tempfile::tempdir().unwrap();
    let dep = url_dep_with_flags(
        "lib-req", url, "main",
        vec![milpa_manifest::FlagRequest { name: "openssl".to_string(), enabled: true }],
    );
    let m = manifest(vec![dep]);
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
    let d = graph.deps.iter().find(|d| d.name == "lib-req").expect("lib-req in graph");
    assert_eq!(d.active_flags, vec!["openssl"]);
}

#[test]
fn s5_active_flags_in_lockfile_emission() {
    // active_flags on ResolvedDep propagate into the lockfile via locked_from_resolved.
    let url = "https://example.com/lib-lock.git";
    let dep_kdl = r#"name "lib-lock"
kind "library"
flags {
    alpha default=#true
    beta default=#true
    gamma default=#false
}"#;
    let reg = FakeReg::git(&[(url, "main", milpa_kdl("s5550000s5550000s5550000s5550000s5550000", dep_kdl))]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("lib-lock", url, "main")]);
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
    let lockfile = crate::lockfile::from_graph(&graph, "maxver");
    let locked = lockfile.deps.iter().find(|d| d.name == "lib-lock").expect("lib-lock in lockfile");
    // alpha and beta are active (default=#true); gamma is not.
    // Lexicographically sorted: alpha < beta.
    assert_eq!(locked.active_flags, vec!["alpha", "beta"]);
}

// ---------------------------------------------------------------------------
// C1b-completion: CLI-selected root flags participate in conflict detection
// ---------------------------------------------------------------------------

/// Helper: build a Manifest with no deps but with the given flag declarations.
fn manifest_with_flags(name: &str, flags: Vec<milpa_manifest::FlagDecl>) -> milpa_manifest::Manifest {
    milpa_manifest::Manifest {
        name: Some(name.to_string()),
        kind: "application".to_string(),
        src_dir: String::new(),
        deps: Vec::new(),
        dev_deps: Vec::new(),
        overrides: Vec::new(),
        flags,
        self_mirrors: Vec::new(),
        cas_dir: String::new(),
        spec_version: 1,
        spec_version_explicit: false,
        attestation_policy: milpa_manifest::TrustPolicy::Warn,
        index_trust_policy: milpa_manifest::TrustPolicy::Warn,
        index_trust_signer: None,
        index_trust_bundle: None,
        optional_auto_flags: std::collections::BTreeSet::new(),
    }
}

#[test]
fn c1b_cli_features_conflict_on_root_raises() {
    // Root manifest: flags { x conflicts=["y"]; y }.
    // --features x,y → RESOLVE-FLAG-CONFLICT (both have source "cli").
    // Mirrors test_s4c_conflicts.py::TestC1bCliRootFlagConflicts::test_cli_features_conflict_on_root_raises.

    let flags = vec![
        milpa_manifest::FlagDecl {
            name: "x".to_string(), default: false,
            description: String::new(), defines: Vec::new(),
            enables_same_pkg: Vec::new(), enables_cross_pkg: Vec::new(),
            conflicts: vec!["y".to_string()],
        },
        milpa_manifest::FlagDecl {
            name: "y".to_string(), default: false,
            description: String::new(), defines: Vec::new(),
            enables_same_pkg: Vec::new(), enables_cross_pkg: Vec::new(),
            conflicts: Vec::new(),
        },
    ];
    let m = manifest_with_flags("myapp", flags);
    let reg = FakeReg::default();
    let tmp = tempfile::tempdir().unwrap();

    let features: std::collections::BTreeSet<String> = ["x".to_string(), "y".to_string()].into_iter().collect();
    let err = crate::resolver::resolve_with_features(
        &m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp),
        None, false, &cas_store(&tmp),
        &features, false, false,
    ).unwrap_err();

    assert_eq!(err.code(), "RESOLVE-FLAG-CONFLICT");
}

#[test]
fn c1b_cli_features_conflict_payload_includes_cli_source() {
    // Payload must have dep="myapp", flag_a="x", flag_b="y", sources ["cli"] each.
    // Mirrors test_s4c_conflicts.py::TestC1bCliRootFlagConflicts::test_cli_features_conflict_payload_includes_cli_source.
    let flags = vec![
        milpa_manifest::FlagDecl {
            name: "x".to_string(), default: false,
            description: String::new(), defines: Vec::new(),
            enables_same_pkg: Vec::new(), enables_cross_pkg: Vec::new(),
            conflicts: vec!["y".to_string()],
        },
        milpa_manifest::FlagDecl {
            name: "y".to_string(), default: false,
            description: String::new(), defines: Vec::new(),
            enables_same_pkg: Vec::new(), enables_cross_pkg: Vec::new(),
            conflicts: Vec::new(),
        },
    ];
    let m = manifest_with_flags("myapp", flags);
    let reg = FakeReg::default();
    let tmp = tempfile::tempdir().unwrap();

    let features: std::collections::BTreeSet<String> = ["x".to_string(), "y".to_string()].into_iter().collect();
    let err = crate::resolver::resolve_with_features(
        &m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp),
        None, false, &cas_store(&tmp),
        &features, false, false,
    ).unwrap_err();

    assert_eq!(err.code(), "RESOLVE-FLAG-CONFLICT");

    let crate::error::MilpaError::Core(crate::error::CoreError::FlagConflict {
        dep, flag_a, flag_b, sources_a, sources_b
    }) = &err else {
        panic!("expected CoreError::FlagConflict, got {err:?}");
    };

    // "x" < "y" lex → flag_a="x", flag_b="y"
    assert_eq!(dep, "myapp");
    assert_eq!(flag_a, "x");
    assert_eq!(flag_b, "y");
    // Both activated by CLI
    assert_eq!(sources_a, &vec!["cli".to_string()]);
    assert_eq!(sources_b, &vec!["cli".to_string()]);
}

#[test]
fn c1b_cli_features_no_conflict_no_error() {
    // --features x only (not y) → no conflict.

    let flags = vec![
        milpa_manifest::FlagDecl {
            name: "x".to_string(), default: false,
            description: String::new(), defines: Vec::new(),
            enables_same_pkg: Vec::new(), enables_cross_pkg: Vec::new(),
            conflicts: vec!["y".to_string()],
        },
        milpa_manifest::FlagDecl {
            name: "y".to_string(), default: false,
            description: String::new(), defines: Vec::new(),
            enables_same_pkg: Vec::new(), enables_cross_pkg: Vec::new(),
            conflicts: Vec::new(),
        },
    ];
    let m = manifest_with_flags("myapp", flags);
    let reg = FakeReg::default();
    let tmp = tempfile::tempdir().unwrap();

    let features: std::collections::BTreeSet<String> = ["x".to_string()].into_iter().collect();
    // Should succeed (no conflict between x alone)
    crate::resolver::resolve_with_features(
        &m, None, &reg, None, None, Strategy::Maxver, &deps_dir(&tmp),
        None, false, &cas_store(&tmp),
        &features, false, false,
    ).unwrap();
}

/// C1b: ActivationSource::Cli serializes as "cli" — byte-identical to Python.
///
/// `_ACTIVATION_SOURCE_NAMES[ActivationSource.CLI] == "cli"` (Python).
/// `serialize_sources({Cli}) == ["cli"]` (Rust, check_s4c_flag_conflicts inner fn).
///
/// This is a unit test for the serializer only; the C1b code path that records
/// CLI as a source (via `--features` → dep_active_flags) is a future concern
/// (root-level flag identity not yet tracked).
#[test]
fn activation_source_cli_serializes_as_cli() {
    use milpa_types::ActivationSource;
    use std::collections::BTreeSet;

    // Replicate the serialize_sources function from check_s4c_flag_conflicts.
    fn serialize_sources(s: &BTreeSet<ActivationSource>) -> Vec<String> {
        s.iter()
            .map(|src| match src {
                ActivationSource::Default => "default",
                ActivationSource::EdgeRequest => "edge_request",
                ActivationSource::EnablesRule => "enables_rule",
                ActivationSource::Cli => "cli",
            })
            .map(String::from)
            .collect()
    }

    // Single CLI source → "cli"
    let cli_only: BTreeSet<ActivationSource> = [ActivationSource::Cli].into_iter().collect();
    assert_eq!(serialize_sources(&cli_only), vec!["cli"]);

    // All four sources → canonical declaration order:
    // Default < EdgeRequest < EnablesRule < Cli
    let all: BTreeSet<ActivationSource> = [
        ActivationSource::Cli,
        ActivationSource::Default,
        ActivationSource::EdgeRequest,
        ActivationSource::EnablesRule,
    ]
    .into_iter()
    .collect();
    assert_eq!(
        serialize_sources(&all),
        vec!["default", "edge_request", "enables_rule", "cli"]
    );
}

// ---------------------------------------------------------------------------
// F5: check_workspace_frozen_active_flags_mismatch — member default-seed
// ---------------------------------------------------------------------------

/// Helper: build a LoadedWorkspace on disk with one member whose milpa.kdl is
/// `member_kdl`.  Returns (TempDir, LoadedWorkspace).
fn ws_with_one_member(
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

/// F5 regression: when no workspace-root CLI seed is supplied, the per-member
/// loop must use the MEMBER's own default-true flags as seed (mirrors
/// FilterCtx::build).  A member with `flags { extra default=#true }` and a dep
/// `{ flag "extra" }` should be detected as mismatching when the lockfile omits
/// that dep.
///
/// Previously the loop fell through to `HashSet::new()` (empty active set),
/// meaning the dep was treated as not-admitted → no mismatch detected even
/// though the default-true flag activates it.
#[test]
fn f5_workspace_frozen_member_default_seed_detected() {
    // Member manifest: flag "extra" default=#true, dep "optfoo" gated by `when flag="extra"`.
    // The correct KDL syntax for flag-gated deps is the `when` block form
    // (§6.3 NORMATIVE); `flag "extra"` as a child node on a dep is a FlagRequest,
    // not a predicate gate.
    let member_kdl = r#"name "memb"
kind "library"
flags {
    extra default=#true
}
deps {
    when flag="extra" {
        optfoo git=(url)"https://example.com/optfoo.git" ref="main"
    }
}
"#;
    let (_tmp, ws) = ws_with_one_member("memb", member_kdl);

    // Lockfile does NOT include "optfoo" — mismatches the default-true activation.
    let lock = Lockfile {
        version: milpa_types::LOCKFILE_SCHEMA_VERSION,
        strategy: "maxver".into(),
        deps: vec![], // optfoo absent
    };

    let features = std::collections::BTreeSet::new();
    let err = crate::resolver::check_workspace_frozen_active_flags_mismatch(
        &ws, &lock, &features, false, false,
    )
    .unwrap_err();

    assert_eq!(
        err.code(),
        "FROZEN-ACTIVE-FLAGS-MISMATCH",
        "F5: member default-seed mismatch must be detected when ws CLI seed is absent"
    );
}

/// F5 inverse: when the lockfile INCLUDES the flag-gated dep (consistent with
/// member's default-true activation), no mismatch should be raised.
#[test]
fn f5_workspace_frozen_member_default_seed_consistent() {
    let member_kdl = r#"name "memb"
kind "library"
flags {
    extra default=#true
}
deps {
    when flag="extra" {
        optfoo git=(url)"https://example.com/optfoo.git" ref="main"
    }
}
"#;
    let (_tmp, ws) = ws_with_one_member("memb", member_kdl);

    // Lockfile INCLUDES "optfoo" — consistent with default-true activation.
    let lock = Lockfile {
        version: milpa_types::LOCKFILE_SCHEMA_VERSION,
        strategy: "maxver".into(),
        deps: vec![
            milpa_types::LockedDep {
                name: "optfoo".into(),
                namespace: None,
                identity: None,
                version: "0.1.0".into(),
                src_dir: "src".into(),
                requires: vec![],
                provenances: vec![milpa_types::ProvenanceRecord::Git {
                    url: "https://example.com/optfoo.git".into(),
                    ref_spec: Some("main".into()),
                    commit_sha: Some("abc123".into()),
                    origin: "observed".into(),
                    submodule_shas: vec![],
                }],
                active_flags: vec![],
                dep_decl: None,
                cond_requires: vec![],
                aliases: vec![],
            },
        ],
    };

    let features = std::collections::BTreeSet::new();
    crate::resolver::check_workspace_frozen_active_flags_mismatch(
        &ws, &lock, &features, false, false,
    )
    .expect("F5: consistent lock must pass frozen check");
}
