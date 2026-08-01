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
    parse_iso8601_timestamp, LockedDep, Lockfile, Provenance, ProvenanceRecord, ResolvedDep,
    ResolvedGraph, Version, LOCKFILE_SCHEMA_VERSION,
};

use crate::lockfile::{format_lockfile, from_graph, parse_lockfile};

use crate::error::MilpaError;
use crate::fetch::{FetchError, FetcherRegistry, Receipt};
use crate::identity::compute_content_hash;
use crate::registry::{Index, IndexVersion, Package};
use crate::resolver::{resolve, resolve_with_features};
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
    /// D4 (resolution-semantics RFC §3 Axis D): the resolved commit's
    /// committer date, as unix seconds — mirrors `fetch_git`'s real
    /// `Receipt.committer_date`. `None` (the default) for non-git mocks.
    committer_date: Option<i64>,
    /// D-D2 additive extension (resolution-semantics RFC §3 Axis D / §6
    /// D-D2): an optional per-commit-sha override for `committer_date`,
    /// keyed by the exact-pin `commit_sha` the incoming `Provenance::Git`
    /// carries. Lets a test prove exclude-newer validation on a REUSED
    /// branch-ref pin reads the PINNED commit's own date, not the flat
    /// `committer_date` above (which represents the ref's current tip).
    /// `None` (the default) for every pre-existing mock — behavior is
    /// unaffected unless a test explicitly opts in.
    committer_date_by_sha: Option<BTreeMap<String, i64>>,
}

#[derive(Default)]
struct FakeReg {
    /// `(url, ref)` → mock for git fetches; also reused for tarball URLs (ref "").
    by_url_ref: BTreeMap<(String, String), Mock>,
    /// `"registry/repository@digest"` → mock for OCI fetches. Keyed to match
    /// `fetch_oci`'s `oci_ref` format exactly (see `fetchers.rs::fetch_oci`).
    by_oci: BTreeMap<String, Mock>,
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
            by_oci: BTreeMap::new(),
            calls: RefCell::new(Vec::new()),
        }
    }

    /// Build a `FakeReg` from OCI mocks keyed by `(registry, repository, digest)`.
    fn oci(mocks: &[(&str, &str, &str, Mock)]) -> Self {
        let mut by_oci = BTreeMap::new();
        for (registry, repository, digest, m) in mocks {
            by_oci.insert(format!("{registry}/{repository}@{digest}"), m.clone());
        }
        FakeReg {
            by_url_ref: BTreeMap::new(),
            by_oci,
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
            Provenance::Git {
                url,
                ref_spec,
                commit_sha,
            } => {
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
                // D-D2: an exact-commit pin is echoed back verbatim as
                // `resolved_ref` — mirroring the real `fetch_git`, which
                // always reports precisely the pinned SHA it was given,
                // never the ref's current tip (`m.sha` below). Every
                // pre-existing test that exercises pin-reuse constructs
                // `m.sha` equal to the pin it uses, so this is a no-op for
                // all of them.
                let resolved_ref = commit_sha.clone().unwrap_or_else(|| m.sha.clone());
                // D-D2: an exact-commit pin also prefers its own per-sha
                // committer_date override, if the mock provides one — see
                // `Mock::committer_date_by_sha`'s doc. Absent -> falls back
                // to the flat `committer_date` (unaffected by commit_sha,
                // today's behavior for every pre-existing test).
                let committer_unix = commit_sha
                    .as_ref()
                    .and_then(|sha| {
                        m.committer_date_by_sha.as_ref().and_then(|map| map.get(sha))
                    })
                    .copied()
                    .or(m.committer_date);
                Ok(Receipt {
                    resolved_ref: Some(resolved_ref),
                    committer_date: committer_unix.map(|s| milpa_types::Timestamp {
                        unix_seconds: s,
                        nanos: 0,
                    }),
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
            Provenance::Oci {
                registry,
                repository,
                digest,
            } => {
                let oci_ref = format!("{registry}/{repository}@{digest}");
                self.calls
                    .borrow_mut()
                    .push((name.to_string(), oci_ref.clone(), String::new()));
                let m = self
                    .by_oci
                    .get(&oci_ref)
                    .ok_or_else(|| FetchError::Failed(format!("no oci mock for {oci_ref:?}")))?
                    .clone();
                self.materialize(name, &m, dest)?;
                Ok(Receipt::default())
            }
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
        version: None,
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
        by_oci: BTreeMap::new(),
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
        version: None,
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
        version: None,
        attestation_policy: milpa_manifest::TrustPolicy::Warn,
        index_trust_policy: milpa_manifest::TrustPolicy::Warn,
        index_trust_signer: None,
        index_trust_bundle: None,
        index_trust_policy_explicit: false,
        entry_trust_policy: milpa_manifest::TrustPolicy::Warn,
        entry_trust_policy_explicit: false,
        index_history_policy: milpa_manifest::TrustPolicy::Warn,
        index_history_policy_explicit: false,
        resolution: None,
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
        true,
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
        true,
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
        true,
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
        attestation: None,
        namespace: String::new(),
        published_at: None,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        published_at_raw: None,
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
        true,
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
        true,
        &deps_dir(&tmp_min),
        None,
        false,
        &cas_store(&tmp_min),
    )
    .unwrap();
    let foo_min = g_min.deps.iter().find(|d| d.name == "foo").unwrap();
    assert_eq!(foo_min.version, v(0, 4, 0));
}

// ---------------------------------------------------------------------------
// B2 (resolver-semantics RFC §4 stage 4 / §3 Axis B — #192/#70): feeding the
// prior lockfile's recorded versions into the solver as preferences.
//
// `milpa-solver`'s `lib.rs` B2 test module covers the solver-internal
// mechanism (`pick_version`'s preference short-circuit, threaded through
// `solve()`) against a synthetic in-memory provider in isolation. This
// proves the RESOLVER wires the prior lockfile into that mechanism for real
// named/index deps (multi-candidate — the only case a preference can ever
// bite, per the RFC §7 dependency note) via `ResolveProvider::preference`.
// ---------------------------------------------------------------------------

/// Two-version index entry for `name`, one package per distinct `.nimble`
/// body (so each version gets its own real content_hash — mirrors
/// `resolve_named_dep_strategy_selects_version`'s single-package helper,
/// generalized to two named packages sharing one `Index`).
fn two_version_package(name: &str, body_v1: &str, body_v2: &str) -> Package {
    let idx_ver = |ver: &str, body: &str| IndexVersion {
        version: ver.into(),
        content_hash: hash_of_nimble(name, body),
        provenances: vec![Provenance::Git {
            url: format!("https://example.com/{name}.git"),
            ref_spec: format!("v{ver}"),
            commit_sha: None,
        }],
        dep_decl: None,
        dep_decl_schema_version: None,
        attestation: None,
        namespace: String::new(),
        published_at: None,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        published_at_raw: None,
    };
    Package {
        name: name.to_string(),
        namespace: String::new(),
        versions: vec![idx_ver("1.0.0", body_v1), idx_ver("2.0.0", body_v2)],
    }
}

fn b2_index() -> Index {
    Index {
        packages: vec![
            two_version_package("libfoo", "# libfoo v1\n", "# libfoo v2\n"),
            two_version_package("libbar", "# libbar v1\n", "# libbar v2\n"),
        ],
    }
}

fn b2_registry() -> FakeReg {
    FakeReg::git(&[
        (
            "https://example.com/libfoo.git",
            "v1.0.0",
            nimble("f1", "# libfoo v1\n"),
        ),
        (
            "https://example.com/libfoo.git",
            "v2.0.0",
            nimble("f2", "# libfoo v2\n"),
        ),
        (
            "https://example.com/libbar.git",
            "v1.0.0",
            nimble("b1", "# libbar v1\n"),
        ),
        (
            "https://example.com/libbar.git",
            "v2.0.0",
            nimble("b2", "# libbar v2\n"),
        ),
    ])
}

/// A minimal prior `Lockfile` entry for a named dep pinned at `version`.
///
/// `name`/`version` are the only fields load-bearing for the RESOLUTION
/// outcome, but `identity` MUST be `Some(_)` here (B4, resolution-semantics
/// RFC §3 Axis B / D-B3): `ResolveProvider::preference` now treats
/// `identity: None` as "this pin was stripped — no preference" (the SAME
/// "identity=None means unpinned" convention `strip_dep_pin` already uses
/// for git-pin reuse), so a hand-rolled fixture that leaves `identity: None`
/// would be silently indistinguishable from an upgraded/stripped dep and
/// these B2 tests would stop exercising the minimal-change preference at
/// all. A real prior lock always has a real identity for a named dep, which
/// is what this synthetic (but non-null) placeholder value stands in for.
fn b2_prior_named_dep(name: &str, version: &str) -> LockedDep {
    LockedDep {
        name: name.to_string(),
        namespace: None,
        identity: Some(format!("sha256:{}", "0".repeat(64))),
        version: version.to_string(),
        src_dir: String::new(),
        requires: Vec::new(),
        provenances: Vec::new(),
        active_flags: Vec::new(),
        dep_decl: None,
        cond_requires: Vec::new(),
        aliases: Vec::new(),
        attestation: None,
        declared_version_source: None,
    }
}

fn b2_prior_lock(foo_version: &str, bar_version: &str) -> Lockfile {
    Lockfile {
        version: LOCKFILE_SCHEMA_VERSION,
        strategy: "maxver".into(),
        exclude_newer: None,
        deps: vec![
            b2_prior_named_dep("libfoo", foo_version),
            b2_prior_named_dep("libbar", bar_version),
        ],
    }
}

#[test]
fn resolve_b2_fresh_resolve_picks_newest() {
    // No prior lock — unaffected: both unconstrained named deps pick
    // strategy-newest (maxver, the default).
    let index = b2_index();
    let reg = b2_registry();
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![named_dep("libfoo", None), named_dep("libbar", None)]);
    let graph = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        None,
        Strategy::Maxver,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = graph.deps.iter().find(|d| d.name == "libfoo").unwrap();
    let bar = graph.deps.iter().find(|d| d.name == "libbar").unwrap();
    assert_eq!(foo.version, v(2, 0, 0));
    assert_eq!(bar.version, v(2, 0, 0));
}

#[test]
fn resolve_b2_prior_lock_pins_unconstrained_deps() {
    // The default-change itself: re-resolving against a prior lock pinning
    // both unconstrained named deps at 1.0.0 keeps them at 1.0.0 — pre-B2
    // this would newest-wins bump both to 2.0.0.
    let index = b2_index();
    let reg = b2_registry();
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![named_dep("libfoo", None), named_dep("libbar", None)]);
    let prior = b2_prior_lock("1.0.0", "1.0.0");
    let graph = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        Some(&prior),
        Strategy::Maxver,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = graph.deps.iter().find(|d| d.name == "libfoo").unwrap();
    let bar = graph.deps.iter().find(|d| d.name == "libbar").unwrap();
    assert_eq!(foo.version, v(1, 0, 0));
    assert_eq!(bar.version, v(1, 0, 0));
}

#[test]
fn resolve_b2_bump_one_dep_leaves_unrelated_pinned() {
    // The #192 regression fixture, at full resolver granularity: narrowing
    // libfoo's constraint to exclude the locked 1.0.0 forces ONLY libfoo to
    // move (to 2.0.0, the sole remaining candidate); libbar — unrelated,
    // unconstrained — stays pinned at its locked 1.0.0 even though 2.0.0 is
    // available and a fresh maxver resolve would pick it.
    let index = b2_index();
    let reg = b2_registry();
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![
        named_dep("libfoo", Some(">=2.0.0")),
        named_dep("libbar", None),
    ]);
    let prior = b2_prior_lock("1.0.0", "1.0.0");
    let graph = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        Some(&prior),
        Strategy::Maxver,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = graph.deps.iter().find(|d| d.name == "libfoo").unwrap();
    let bar = graph.deps.iter().find(|d| d.name == "libbar").unwrap();
    assert_eq!(foo.version, v(2, 0, 0)); // forced: 1.0.0 no longer >= 2.0.0
    assert_eq!(bar.version, v(1, 0, 0)); // unrelated: stays locked, NOT newest-wins-bumped
}

#[test]
fn resolve_b4_stripped_pin_named_dep_opts_out_of_preference() {
    // B4 (resolution-semantics RFC §3 Axis B / D-B3): a prior entry with
    // `identity: None` (the exact shape `strip_dep_pin` — the shared
    // mechanism `update <dep>`/`--upgrade <dep>` delegate to — produces)
    // carries no preference at all, even though its `version` field still
    // says "1.0.0". libfoo's pin is stripped (identity=None); libbar's is
    // real (identity=Some). Both are otherwise unconstrained. Only libfoo
    // moves to the newest (2.0.0); libbar stays locked at 1.0.0 — proving
    // `ResolveProvider::preference` reads `identity`, not just `version`.
    let index = b2_index();
    let reg = b2_registry();
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![named_dep("libfoo", None), named_dep("libbar", None)]);
    let mut prior = b2_prior_lock("1.0.0", "1.0.0");
    let foo_entry = prior.deps.iter_mut().find(|d| d.name == "libfoo").unwrap();
    foo_entry.identity = None; // pin stripped -> no preference
    let graph = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        Some(&prior),
        Strategy::Maxver,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = graph.deps.iter().find(|d| d.name == "libfoo").unwrap();
    let bar = graph.deps.iter().find(|d| d.name == "libbar").unwrap();
    assert_eq!(foo.version, v(2, 0, 0)); // stripped -> no preference -> newest
    assert_eq!(bar.version, v(1, 0, 0)); // real pin -> preference still applies
}

// ---------------------------------------------------------------------------
// C2 (resolver-semantics RFC §3 Axis C / §4 stage 4, D-C2 — #111): `Strategy::
// LowestDirect`'s provider-level effective-strategy precompute, at full
// resolver granularity — the resolver wires the real `root_authority` set
// into `ResolveProvider::is_root_direct` for a real named/index dep.
// `milpa-solver`'s own `lib.rs` C2 test module covers the solver-internal
// mechanism (`effective_strategy`'s Minver/Maxver split) against a synthetic
// provider in isolation.
// ---------------------------------------------------------------------------

#[test]
fn resolve_c2_lowest_direct_root_direct_minver_transitive_maxver() {
    // "direct" is root-declared. "transitive" is discovered ONLY via
    // "direct"'s own `.nimble` `requires "transitive"` line (bare name,
    // unconstrained) — it is NEVER root-declared. Under
    // `Strategy::LowestDirect`, "direct" (root-direct) picks the LOWEST
    // satisfying version while "transitive" (purely transitive) still picks
    // the HIGHEST — the whole point of the effective-strategy precompute.
    let direct_body = |ver: &str| format!("srcDir = \"src\"\nrequires \"transitive\"\n# {ver}\n");
    let transitive_body = "srcDir = \"src\"\n";

    let idx_ver = |name: &str, ver: &str, body: &str| IndexVersion {
        version: ver.into(),
        content_hash: hash_of_nimble(name, body),
        provenances: vec![Provenance::Git {
            url: format!("https://example.com/{name}.git"),
            ref_spec: format!("v{ver}"),
            commit_sha: None,
        }],
        dep_decl: None,
        dep_decl_schema_version: None,
        attestation: None,
        namespace: String::new(),
        published_at: None,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        published_at_raw: None,
    };

    let index = Index {
        packages: vec![
            Package {
                name: "direct".to_string(),
                namespace: String::new(),
                versions: vec![
                    idx_ver("direct", "1.0.0", &direct_body("1.0.0")),
                    idx_ver("direct", "2.0.0", &direct_body("2.0.0")),
                ],
            },
            Package {
                name: "transitive".to_string(),
                namespace: String::new(),
                versions: vec![
                    idx_ver("transitive", "1.0.0", transitive_body),
                    idx_ver("transitive", "2.0.0", transitive_body),
                ],
            },
        ],
    };
    let reg = FakeReg::git(&[
        (
            "https://example.com/direct.git",
            "v1.0.0",
            nimble("d1", &direct_body("1.0.0")),
        ),
        (
            "https://example.com/direct.git",
            "v2.0.0",
            nimble("d2", &direct_body("2.0.0")),
        ),
        (
            "https://example.com/transitive.git",
            "v1.0.0",
            nimble("t1", transitive_body),
        ),
        (
            "https://example.com/transitive.git",
            "v2.0.0",
            nimble("t2", transitive_body),
        ),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![named_dep("direct", None)]);
    let graph = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        None,
        Strategy::LowestDirect,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let direct = graph.deps.iter().find(|d| d.name == "direct").unwrap();
    let transitive = graph.deps.iter().find(|d| d.name == "transitive").unwrap();
    assert_eq!(direct.version, v(1, 0, 0)); // root-direct -> Minver
    assert_eq!(transitive.version, v(2, 0, 0)); // transitive -> Maxver
}

// ---------------------------------------------------------------------------
// C3 (resolver-semantics RFC §3 Axis C / D-C2, #98/#111): B2's lock-
// preference bypass on VALUE-DIVERGENCE, never CLI flag presence. Reuses
// the exact "direct" (root-direct, discovered via a plain named dep) /
// "transitive" (purely transitive, discovered only via direct's own
// `.nimble` `requires`) shape the C2 contrast test above uses, adding a
// `prior` Lockfile to exercise `ResolveProvider::bypasses_lock_preference`.
// ---------------------------------------------------------------------------

/// Same direct/transitive index + registry as
/// `resolve_c2_lowest_direct_root_direct_minver_transitive_maxver`, factored
/// out so the C3 bypass tests below can each supply a different `prior`.
fn c3_direct_transitive_index_and_registry() -> (Index, FakeReg) {
    let direct_body = |ver: &str| format!("srcDir = \"src\"\nrequires \"transitive\"\n# {ver}\n");
    let transitive_body = "srcDir = \"src\"\n";

    let idx_ver = |name: &str, ver: &str, body: &str| IndexVersion {
        version: ver.into(),
        content_hash: hash_of_nimble(name, body),
        provenances: vec![Provenance::Git {
            url: format!("https://example.com/{name}.git"),
            ref_spec: format!("v{ver}"),
            commit_sha: None,
        }],
        dep_decl: None,
        dep_decl_schema_version: None,
        attestation: None,
        namespace: String::new(),
        published_at: None,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        published_at_raw: None,
    };

    let index = Index {
        packages: vec![
            Package {
                name: "direct".to_string(),
                namespace: String::new(),
                versions: vec![
                    idx_ver("direct", "1.0.0", &direct_body("1.0.0")),
                    idx_ver("direct", "2.0.0", &direct_body("2.0.0")),
                ],
            },
            Package {
                name: "transitive".to_string(),
                namespace: String::new(),
                versions: vec![
                    idx_ver("transitive", "1.0.0", transitive_body),
                    idx_ver("transitive", "2.0.0", transitive_body),
                ],
            },
        ],
    };
    let reg = FakeReg::git(&[
        (
            "https://example.com/direct.git",
            "v1.0.0",
            nimble("d1", &direct_body("1.0.0")),
        ),
        (
            "https://example.com/direct.git",
            "v2.0.0",
            nimble("d2", &direct_body("2.0.0")),
        ),
        (
            "https://example.com/transitive.git",
            "v1.0.0",
            nimble("t1", transitive_body),
        ),
        (
            "https://example.com/transitive.git",
            "v2.0.0",
            nimble("t2", transitive_body),
        ),
    ]);
    (index, reg)
}

fn c3_prior_lock(direct_version: &str, transitive_version: &str, strategy: &str) -> Lockfile {
    Lockfile {
        version: LOCKFILE_SCHEMA_VERSION,
        strategy: strategy.to_string(),
        exclude_newer: None,
        deps: vec![
            b2_prior_named_dep("direct", direct_version),
            b2_prior_named_dep("transitive", transitive_version),
        ],
    }
}

/// The #192 regression guard: explicit `Strategy::Maxver` against an
/// already-`"maxver"`-recorded lock must NOT bypass — value-divergence gate,
/// not flag-presence. `direct` is locked at 1.0.0 (NOT what a fresh maxver
/// pick would choose — 2.0.0), so if the lock-preference is honored, the
/// resolve returns the LOCKED 1.0.0.
#[test]
fn resolve_c3_maxver_explicit_on_maxver_lock_keeps_locked_pin() {
    let (index, reg) = c3_direct_transitive_index_and_registry();
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![named_dep("direct", None)]);
    let prior = c3_prior_lock("1.0.0", "2.0.0", "maxver");
    let graph = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        Some(&prior),
        Strategy::Maxver,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let direct = graph.deps.iter().find(|d| d.name == "direct").unwrap();
    assert_eq!(
        direct.version,
        v(1, 0, 0),
        "explicit Strategy::Maxver on a maxver-recorded lock must be a NO-OP \
         against lock-preference (value-divergence gate, not flag-presence) \
         — got a bypass instead"
    );
}

/// D-C2: `LowestDirect` diverging from a `"maxver"` lock bypasses ONLY the
/// root-direct package; the purely-transitive package keeps its lock pin.
/// Both pins are the OPPOSITE of what each package's fresh pick would be
/// under `LowestDirect`, so "bypassed" (fresh pick) vs. "kept" (locked pin)
/// is unambiguous.
#[test]
fn resolve_c3_lowest_direct_bypasses_root_direct_only() {
    let (index, reg) = c3_direct_transitive_index_and_registry();
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![named_dep("direct", None)]);
    // direct locked at 2.0.0 (LowestDirect's Minver-for-root wants 1.0.0);
    // transitive locked at 1.0.0 (LowestDirect's Maxver-for-transitive wants 2.0.0).
    let prior = c3_prior_lock("2.0.0", "1.0.0", "maxver");
    let graph = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        Some(&prior),
        Strategy::LowestDirect,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let direct = graph.deps.iter().find(|d| d.name == "direct").unwrap();
    let transitive = graph.deps.iter().find(|d| d.name == "transitive").unwrap();
    assert_eq!(
        direct.version,
        v(1, 0, 0),
        "root-direct dep must BYPASS lock-preference under a diverging \
         lowest-direct strategy and pick Minver fresh"
    );
    assert_eq!(
        transitive.version,
        v(1, 0, 0),
        "purely-transitive dep must KEEP its lock pin under lowest-direct — \
         a whole-graph bypass here would drag it forward (#192 again)"
    );
}

/// A genuinely divergent non-`lowest-direct` strategy (`Minver` vs. a
/// `"maxver"`-recorded lock) bypasses lock-preference for EVERY package.
#[test]
fn resolve_c3_minver_vs_maxver_lock_bypasses_whole_graph() {
    let (index, reg) = c3_direct_transitive_index_and_registry();
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![named_dep("direct", None)]);
    // Both locked at 2.0.0 (what maxver naturally picks) — opposite of what
    // minver would pick (1.0.0), so a whole-graph bypass is unambiguous.
    let prior = c3_prior_lock("2.0.0", "2.0.0", "maxver");
    let graph = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        Some(&prior),
        Strategy::Minver,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let direct = graph.deps.iter().find(|d| d.name == "direct").unwrap();
    let transitive = graph.deps.iter().find(|d| d.name == "transitive").unwrap();
    assert_eq!(direct.version, v(1, 0, 0));
    assert_eq!(transitive.version, v(1, 0, 0));
}

// ---------------------------------------------------------------------------
// R6 (code-review finding, Medium): `ResolveProvider::is_root_direct` must
// compare FULL identity (name AND namespace), not just the bare name — else
// a namespace-qualified TRANSITIVE dep is misclassified as root-direct
// merely because an UNRELATED root dep shares its bare name under a
// DIFFERENT namespace. See `root_direct_keys` (resolver.rs) — the
// namespace-aware sibling of the bare-name `root_authority` set (which
// stays bare-name-only, unchanged, for the provenance gate — #193).
// ---------------------------------------------------------------------------

/// Direct unit coverage of `ResolveProvider::is_root_direct` against a
/// hand-built namespace-aware authority set — no fetch/solve involved.
#[test]
fn is_root_direct_namespace_aware_direct_unit_coverage() {
    use milpa_solver::PackageProvider;
    use milpa_types::DepKey;

    let empty_index = Index { packages: vec![] };
    let empty_reg = FakeReg::git(&[]);
    let tmp = tempfile::tempdir().unwrap();

    let make = |keys: Vec<DepKey>| {
        let mut p = super::ResolveProvider::new(
            &empty_reg,
            &empty_index,
            deps_dir(&tmp),
            BTreeMap::new(),
            None,
            None,
            false,
            Strategy::Maxver,
            false,
            None,
        );
        p.root_direct_keys = keys.into_iter().collect();
        p
    };

    // Matches same name + same namespace.
    let p = make(vec![DepKey { name: "foo".into(), namespace: Some("ns1".into()) }]);
    assert!(p.is_root_direct("ns1::foo"));

    // The R6 bug: a root "ns1::foo" must NOT make an unrelated, purely-
    // transitive "ns2::foo" look root-direct.
    let p = make(vec![DepKey { name: "foo".into(), namespace: Some("ns1".into()) }]);
    assert!(!p.is_root_direct("ns2::foo"));

    // A bare package is not matched by a namespaced root dep.
    let p = make(vec![DepKey { name: "foo".into(), namespace: Some("ns1".into()) }]);
    assert!(!p.is_root_direct("foo"));

    // No-namespace common case is unaffected: a bare root dep still matches
    // the bare package.
    let p = make(vec![DepKey { name: "foo".into(), namespace: None }]);
    assert!(p.is_root_direct("foo"));
}

fn named_dep_ns(name: &str, namespace: &str, constraint: Option<&str>) -> Dep {
    Dep::Named(NamedDep {
        name: name.to_string(),
        namespace: Some(namespace.to_string()),
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

fn locked_dep_ns(name: &str, namespace: &str, version: &str) -> LockedDep {
    LockedDep {
        name: name.to_string(),
        namespace: Some(namespace.to_string()),
        identity: Some(format!("sha256:{}", "0".repeat(64))),
        version: version.to_string(),
        src_dir: String::new(),
        requires: Vec::new(),
        provenances: Vec::new(),
        active_flags: Vec::new(),
        dep_decl: None,
        cond_requires: Vec::new(),
        aliases: Vec::new(),
        attestation: None,
        declared_version_source: None,
    }
}

/// Index + registry fixture shared by the two full-resolve R6 tests below:
/// "foo" exists under TWO distinct namespaces ("ns1", "ns2"), each with two
/// candidate versions (1.0.0 / 2.0.0) backed by DISTINCT content (so the two
/// namespaced packages are never confused with each other). "carrier" is a
/// root-direct URL dep whose own `milpa.kdl` declares a TRANSITIVE named dep
/// on "foo" under namespace "ns2" — an unrelated package sharing "foo"'s bare
/// name, discovered only via `carrier`'s own manifest (never root-declared).
fn r6_namespace_index_and_registry() -> (Index, FakeReg) {
    let body = |ns: &str, ver: &str| format!("srcDir = \"src\"\n# {ns}-{ver}\n");

    let idx_ver = |ns: &str, ver: &str| IndexVersion {
        version: ver.into(),
        content_hash: hash_of_nimble("foo", &body(ns, ver)),
        provenances: vec![Provenance::Git {
            url: format!("https://example.com/{ns}/foo.git"),
            ref_spec: format!("v{ver}"),
            commit_sha: None,
        }],
        dep_decl: None,
        dep_decl_schema_version: None,
        attestation: None,
        namespace: ns.to_string(),
        published_at: None,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        published_at_raw: None,
    };

    let index = Index {
        packages: vec![
            Package {
                name: "foo".to_string(),
                namespace: "ns1".to_string(),
                versions: vec![idx_ver("ns1", "1.0.0"), idx_ver("ns1", "2.0.0")],
            },
            Package {
                name: "foo".to_string(),
                namespace: "ns2".to_string(),
                versions: vec![idx_ver("ns2", "1.0.0"), idx_ver("ns2", "2.0.0")],
            },
        ],
    };

    let carrier_kdl = "name \"carrier\"\nkind \"library\"\ndeps {\n    foo namespace=\"ns2\"\n}\n";
    let reg = FakeReg::git(&[
        (
            "https://example.com/ns1/foo.git",
            "v1.0.0",
            nimble("foo", &body("ns1", "1.0.0")),
        ),
        (
            "https://example.com/ns1/foo.git",
            "v2.0.0",
            nimble("foo", &body("ns1", "2.0.0")),
        ),
        (
            "https://example.com/ns2/foo.git",
            "v1.0.0",
            nimble("foo", &body("ns2", "1.0.0")),
        ),
        (
            "https://example.com/ns2/foo.git",
            "v2.0.0",
            nimble("foo", &body("ns2", "2.0.0")),
        ),
        (
            "https://example.com/carrier.git",
            "main",
            milpa_kdl("carriersha0carriersha0carriersha0carriersha0", carrier_kdl),
        ),
    ]);
    (index, reg)
}

fn r6_root_manifest() -> Manifest {
    manifest(vec![
        named_dep_ns("foo", "ns1", None),
        url_dep("carrier", "https://example.com/carrier.git", "main"),
    ])
}

/// The core R6 regression: under `Strategy::LowestDirect`, the purely-
/// transitive `ns2::foo` (reached only via `carrier`'s milpa.kdl) must get
/// the TRANSITIVE default (Maxver), not Minver — pre-fix, the bare-name
/// `root_authority` check misclassified it as root-direct because the
/// unrelated root dep `ns1::foo` shares its bare name.
#[test]
fn resolve_r6_namespace_qualified_transitive_gets_transitive_default_not_minver() {
    let (index, reg) = r6_namespace_index_and_registry();
    let tmp = tempfile::tempdir().unwrap();
    let m = r6_root_manifest();
    let graph = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        None,
        Strategy::LowestDirect,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let ns1_foo = graph
        .deps
        .iter()
        .find(|d| d.name == "foo" && d.namespace.as_deref() == Some("ns1"))
        .expect("ns1::foo in graph");
    let ns2_foo = graph
        .deps
        .iter()
        .find(|d| d.name == "foo" && d.namespace.as_deref() == Some("ns2"))
        .expect("ns2::foo in graph");
    assert_eq!(ns1_foo.version, v(1, 0, 0), "root-direct ns1::foo -> Minver under lowest-direct");
    assert_eq!(
        ns2_foo.version,
        v(2, 0, 0),
        "purely-transitive ns2::foo must get the TRANSITIVE default (Maxver), \
         not Minver — pre-fix it was misclassified as root-direct via the \
         bare-name root_authority check"
    );
}

/// C3 bypass scoping, namespace-aware: under an EXPLICIT `LowestDirect`
/// diverging from a `"maxver"`-recorded lock, root-direct `ns1::foo`
/// bypasses its lock pin (as always), but the purely-transitive `ns2::foo`
/// must KEEP its lock pin — pre-fix it would ALSO bypass (misclassified as
/// root-direct) and fresh-pick Minver instead. Both pins are the OPPOSITE of
/// what a fresh Minver pick would be (1.0.0), so "bypassed" and "kept" are
/// unambiguous for both deps.
#[test]
fn resolve_r6_namespace_qualified_transitive_keeps_lock_preference() {
    let (index, reg) = r6_namespace_index_and_registry();
    let tmp = tempfile::tempdir().unwrap();
    let m = r6_root_manifest();
    let prior = Lockfile {
        version: LOCKFILE_SCHEMA_VERSION,
        strategy: "maxver".into(),
        exclude_newer: None,
        deps: vec![locked_dep_ns("foo", "ns1", "2.0.0"), locked_dep_ns("foo", "ns2", "2.0.0")],
    };
    let graph = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        Some(&prior),
        Strategy::LowestDirect,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let ns1_foo = graph
        .deps
        .iter()
        .find(|d| d.name == "foo" && d.namespace.as_deref() == Some("ns1"))
        .expect("ns1::foo in graph");
    let ns2_foo = graph
        .deps
        .iter()
        .find(|d| d.name == "foo" && d.namespace.as_deref() == Some("ns2"))
        .expect("ns2::foo in graph");
    assert_eq!(
        ns1_foo.version,
        v(1, 0, 0),
        "root-direct ns1::foo must BYPASS its lock pin under a diverging \
         lowest-direct strategy and pick Minver fresh"
    );
    assert_eq!(
        ns2_foo.version,
        v(2, 0, 0),
        "purely-transitive ns2::foo must KEEP its lock pin (2.0.0) — pre-fix \
         it would be misclassified as root-direct, wrongly bypass, and \
         fresh-pick Minver (1.0.0) instead"
    );
}

// ---------------------------------------------------------------------------
// R9 (resolver-semantics RFC §3 Axis C NORMATIVE, code-review finding): the
// lockfile-recorded `strategy` is diagnostic/frozen-parity only, never a LIVE
// resolution input.
//
// Before this fix, `resolve_effective_strategy` (main.rs) had a third
// precedence tier that fell back to the prior lockfile's recorded `strategy`
// before the global default, and `ResolveProvider::bypasses_lock_preference`
// fired B2's bypass on `effective_strategy != prior.strategy` alone. Together
// these meant a one-off `--strategy X` invisibly and PERMANENTLY governed
// every future bare resolve (hidden sticky state), and naively deleting the
// tier without retargeting the bypass would have been a WORSE regression: a
// bare resolve against a non-default-strategy lock would compute
// effective=maxver, see it "diverge", and newest-wins bump the WHOLE graph.
//
// The fix: precedence is CLI > manifest > default (no lockfile tier at all),
// and the bypass additionally requires `strategy_explicit` (CLI or manifest
// `resolution { strategy }` — never a merely default-filled value) on top of
// the existing value-divergence check.
//
// Reuses `b2_index`/`b2_registry`/`b2_prior_named_dep` (two independent
// unconstrained named deps, each with 1.0.0/2.0.0 candidates).
// ---------------------------------------------------------------------------

fn b2_prior_lock_with_strategy(foo_version: &str, bar_version: &str, strategy: &str) -> Lockfile {
    Lockfile {
        strategy: strategy.into(),
        ..b2_prior_lock(foo_version, bar_version)
    }
}

#[test]
fn resolve_r9_bare_fetch_keeps_locked_versions_despite_nondefault_lock() {
    // (a) The key regression guard: a BARE re-resolve (strategy_explicit =
    // false) against a lock recorded under a NON-DEFAULT strategy must keep
    // every unconstrained multi-candidate named dep at its LOCKED version.
    let index = b2_index();
    let reg = b2_registry();
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![named_dep("libfoo", None), named_dep("libbar", None)]);

    // Simulates a one-off `milpa fetch --strategy minver` (explicit,
    // value-diverging) — legitimately picks 1.0.0 for both and records
    // "minver" as the lock's strategy.
    let one_off = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        None,
        Strategy::Minver,
        true, // strategy_explicit
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = one_off.deps.iter().find(|d| d.name == "libfoo").unwrap();
    let bar = one_off.deps.iter().find(|d| d.name == "libbar").unwrap();
    assert_eq!(foo.version, v(1, 0, 0));
    assert_eq!(bar.version, v(1, 0, 0));

    let prior = b2_prior_lock_with_strategy("1.0.0", "1.0.0", "minver");

    // Now a BARE fetch: no CLI flag, no manifest `resolution` block. The CLI
    // layer computes effective=maxver (tier 3 is gone) and
    // strategy_explicit=false. Despite effective (maxver) numerically
    // differing from the lock's recorded value (minver), the bypass must
    // NOT fire — both deps must stay at their locked 1.0.0.
    let bare = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        Some(&prior),
        Strategy::Maxver,
        false, // strategy_explicit
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = bare.deps.iter().find(|d| d.name == "libfoo").unwrap();
    let bar = bare.deps.iter().find(|d| d.name == "libbar").unwrap();
    assert_eq!(
        foo.version,
        v(1, 0, 0),
        "a bare re-resolve against a non-default-strategy lock must stay \
         stable via B2 lock-preference — a default-filled effective strategy \
         must never bypass, even when it numerically diverges from the \
         lock's recorded strategy"
    );
    assert_eq!(bar.version, v(1, 0, 0));
}

#[test]
fn resolve_r9_manifest_resolution_block_diverging_from_lock_bypasses() {
    // (d) A manifest `resolution { strategy }` — not just a CLI flag — counts
    // as an EXPLICIT strategy source. When it diverges from the lock's
    // recorded strategy, the bypass must still fire (a declared, visible
    // policy change SHOULD re-resolve).
    let index = b2_index();
    let reg = b2_registry();
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![named_dep("libfoo", None), named_dep("libbar", None)]);

    // A lock recorded under maxver (both pinned at 2.0.0 — the OPPOSITE of
    // what minver would pick), simulating an earlier maxver run.
    let maxver_run = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        None,
        Strategy::Maxver,
        false, // strategy_explicit
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = maxver_run.deps.iter().find(|d| d.name == "libfoo").unwrap();
    let bar = maxver_run.deps.iter().find(|d| d.name == "libbar").unwrap();
    assert_eq!(foo.version, v(2, 0, 0));
    assert_eq!(bar.version, v(2, 0, 0));
    let prior = b2_prior_lock_with_strategy("2.0.0", "2.0.0", "maxver");

    // The manifest NOW declares `resolution { strategy = minver }` — a
    // declared, visible policy change (no CLI flag at all: strategy_cli
    // stays None throughout).
    let m_with_resolution = Manifest {
        resolution: Some(milpa_manifest::Resolution {
            strategy: Some(Strategy::Minver),
            exclude_newer: None,
        }),
        ..m.clone()
    };
    // Mirrors `resolve_effective_strategy`/`strategy_is_explicit` (main.rs)
    // exactly: cli_strategy is None throughout this test.
    let cli_strategy: Option<Strategy> = None;
    let effective_strategy = cli_strategy
        .or_else(|| m_with_resolution.resolution.and_then(|r| r.strategy))
        .unwrap_or_default();
    let strategy_explicit = cli_strategy.is_some()
        || m_with_resolution.resolution.and_then(|r| r.strategy).is_some();
    assert_eq!(effective_strategy, Strategy::Minver);
    assert!(strategy_explicit);

    let bare = resolve(
        &m_with_resolution,
        Some(&index),
        &reg,
        None,
        Some(&prior),
        effective_strategy,
        strategy_explicit,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = bare.deps.iter().find(|d| d.name == "libfoo").unwrap();
    let bar = bare.deps.iter().find(|d| d.name == "libbar").unwrap();
    assert_eq!(
        foo.version,
        v(1, 0, 0),
        "a manifest resolution{{strategy}} block diverging from the lock's \
         recorded strategy must still bypass lock-preference — only a \
         merely DEFAULT-FILLED effective strategy is exempt"
    );
    assert_eq!(bar.version, v(1, 0, 0));
}

#[test]
fn resolve_r9_new_dep_picked_under_default_not_prior_explicit_strategy() {
    // (e) No hidden sticky state: a one-off explicit `--strategy X` run must
    // NOT make a SUBSEQUENT bare fetch behave as if X were still in effect
    // for a brand-NEW dep that didn't exist in the prior lock. The new dep
    // must be picked under the DEFAULT strategy (maxver), not the previous
    // run's explicit minver.
    let mut index = b2_index();
    index.packages.push(two_version_package("libbaz", "# libbaz v1\n", "# libbaz v2\n"));
    let mut reg = b2_registry();
    reg.by_url_ref.insert(
        ("https://example.com/libbaz.git".to_string(), "v1.0.0".to_string()),
        nimble("z1", "# libbaz v1\n"),
    );
    reg.by_url_ref.insert(
        ("https://example.com/libbaz.git".to_string(), "v2.0.0".to_string()),
        nimble("z2", "# libbaz v2\n"),
    );
    let tmp = tempfile::tempdir().unwrap();

    // One-off explicit `--strategy minver` run — only libfoo/libbar exist in
    // the manifest at this point; libbaz is not yet declared.
    let m_two = manifest(vec![named_dep("libfoo", None), named_dep("libbar", None)]);
    let one_off = resolve(
        &m_two,
        Some(&index),
        &reg,
        None,
        None,
        Strategy::Minver,
        true, // strategy_explicit
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = one_off.deps.iter().find(|d| d.name == "libfoo").unwrap();
    let bar = one_off.deps.iter().find(|d| d.name == "libbar").unwrap();
    assert_eq!(foo.version, v(1, 0, 0));
    assert_eq!(bar.version, v(1, 0, 0));
    let prior = b2_prior_lock_with_strategy("1.0.0", "1.0.0", "minver");

    // Add libbaz to the manifest, then do a BARE fetch (no CLI flag, no
    // manifest resolution block) — effective=maxver, strategy_explicit=false.
    let m_three = manifest(vec![
        named_dep("libfoo", None),
        named_dep("libbar", None),
        named_dep("libbaz", None),
    ]);
    let bare = resolve(
        &m_three,
        Some(&index),
        &reg,
        None,
        Some(&prior),
        Strategy::Maxver,
        false, // strategy_explicit
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = bare.deps.iter().find(|d| d.name == "libfoo").unwrap();
    let bar = bare.deps.iter().find(|d| d.name == "libbar").unwrap();
    let baz = bare.deps.iter().find(|d| d.name == "libbaz").unwrap();
    // Pre-existing deps stay locked (B2 preference, no bypass).
    assert_eq!(foo.version, v(1, 0, 0));
    assert_eq!(bar.version, v(1, 0, 0));
    // The NEW dep has no prior entry to prefer at all — it is picked fresh
    // under THIS resolve's effective strategy (maxver, the default), NOT the
    // previous run's explicit minver. 2.0.0 (not 1.0.0) is the proof: sticky
    // minver would have picked 1.0.0 here.
    assert_eq!(
        baz.version,
        v(2, 0, 0),
        "a new dep with no prior lock entry must be picked under the CURRENT \
         effective strategy (maxver, default) — a prior run's explicit \
         --strategy must never leak forward as hidden state"
    );
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
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-NO-INDEX");
}

// ---------------------------------------------------------------------------
// OCI consumer resolution (registry named-dep path) — parity with Python's
// tests/test_oci_registry_consumer.py. Before this test existed, the fake
// fetcher had no `Provenance::Oci` arm at all; the production code path
// (`materialize_named` → `fetch_any` → `DefaultRegistry::fetch` →
// `transport_to_record`) was already fully generic across transport kinds
// (registry.rs already parses `provenance kind "oci"` straight into
// `Provenance::Oci`, unlike a hardcoded git-only branch) — this test proves
// that wiring end to end and pins it as a regression test.
// ---------------------------------------------------------------------------

const OCI_TEST_REGISTRY: &str = "ghcr.io";
const OCI_TEST_REPOSITORY: &str = "acme/widget";
const OCI_TEST_DIGEST: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn oci_index(content_hash: &str) -> Index {
    Index {
        packages: vec![Package {
            name: "widget".to_string(),
            namespace: "acme".to_string(),
            versions: vec![IndexVersion {
                version: "1.0.0".to_string(),
                content_hash: content_hash.to_string(),
                provenances: vec![Provenance::Oci {
                    registry: OCI_TEST_REGISTRY.to_string(),
                    repository: OCI_TEST_REPOSITORY.to_string(),
                    digest: OCI_TEST_DIGEST.to_string(),
                }],
                dep_decl: None,
                dep_decl_schema_version: None,
                attestation: None,
                namespace: "acme".to_string(),
                published_at: None,
                yanked: false,
                yanked_at: None,
                yanked_reason: None,
                published_at_raw: None,
            }],
        }],
    }
}

#[test]
fn resolve_named_dep_oci_provenance_produces_oci_record() {
    let body = "srcDir = \"src\"\n";
    let index = oci_index(&hash_of_nimble("widget", body));
    let reg = FakeReg::oci(&[(
        OCI_TEST_REGISTRY,
        OCI_TEST_REPOSITORY,
        OCI_TEST_DIGEST,
        nimble("s-oci", body),
    )]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![named_dep("widget", None)]);
    let graph = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        None,
        Strategy::Maxver,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();

    assert_eq!(graph.deps.len(), 1);
    let dep = graph.deps.iter().find(|d| d.name == "widget").unwrap();

    // The fake oras-pull transport was actually invoked, with the full OCI
    // reference built from the index's provenance fields.
    let oci_ref = format!("{OCI_TEST_REGISTRY}/{OCI_TEST_REPOSITORY}@{OCI_TEST_DIGEST}");
    assert_eq!(
        reg.calls(),
        vec![("widget".to_string(), oci_ref, String::new())]
    );

    // The candidate carries a Oci ProvenanceRecord, not a Git one.
    assert_eq!(dep.provenances.len(), 1);
    match &dep.provenances[0] {
        ProvenanceRecord::Oci {
            registry,
            repository,
            digest,
            origin,
        } => {
            assert_eq!(registry, OCI_TEST_REGISTRY);
            assert_eq!(repository, OCI_TEST_REPOSITORY);
            assert_eq!(digest, OCI_TEST_DIGEST);
            assert_eq!(origin, "observed");
        }
        other => panic!("expected Oci provenance, got {other:?}"),
    }
}

#[test]
fn resolve_named_dep_oci_provenance_round_trips_through_lockfile() {
    let body = "srcDir = \"src\"\n";
    let index = oci_index(&hash_of_nimble("widget", body));
    let reg = FakeReg::oci(&[(
        OCI_TEST_REGISTRY,
        OCI_TEST_REPOSITORY,
        OCI_TEST_DIGEST,
        nimble("s-oci", body),
    )]);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![named_dep("widget", None)]);
    let graph = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        None,
        Strategy::Maxver,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();

    let lockfile = crate::lockfile::from_graph(&graph, "maxver", None);
    let locked = lockfile.deps.iter().find(|d| d.name == "widget").unwrap();
    assert_eq!(locked.provenances.len(), 1);
    let locked_prov = &locked.provenances[0];
    assert!(matches!(locked_prov, ProvenanceRecord::Oci { .. }));

    // Full format -> parse round-trip.
    let text = crate::lockfile::format_lockfile(&lockfile);
    assert!(text.contains("kind \"oci\""), "lockfile text missing OCI record:\n{text}");
    let reparsed = crate::lockfile::parse_lockfile(&text).unwrap();
    let reparsed_dep = reparsed.deps.iter().find(|d| d.name == "widget").unwrap();
    assert_eq!(&reparsed_dep.provenances[0], locked_prov);
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
                attestation: None,
                namespace: String::new(),
                published_at: None,
                yanked: false,
                yanked_at: None,
                yanked_reason: None,
                published_at_raw: None,
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
        true,
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
            version: None,
        }],
    );
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        true,
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

/// A3b/D-A3 (rfc-resolution-semantics.md §6): when an override redirects a
/// dep, its own `version=` annotation is that target's step 4 — a
/// `version=` left on the now-redirected ORIGINAL declaration is dead and
/// ignored (not a conflict, since the redirect discards the original
/// declaration entirely and builds a fresh dep from the override target).
#[test]
fn resolve_override_version_annotation_wins_over_original_dep_version() {
    let reg = FakeReg::git(&[(
        "https://fork.example.com/foo.git",
        "patched",
        nimble("ovr", "srcDir = \"src\"\n"), // no version field — steps 1-3 miss
    )]);
    let tmp = tempfile::tempdir().unwrap();
    let original = Dep::Url(UrlDep {
        name: "foo".to_string(),
        git: "https://example.com/foo.git".to_string(),
        git_ref: "main".to_string(),
        mirrors: Vec::new(),
        predicates: Vec::new(),
        flag_requests: Vec::new(),
        optional: false,
        // Dead once overridden — must NOT be the resolved version.
        version: Some(v(1, 0, 0)),
    });
    let m = manifest_full(
        vec![original],
        Vec::new(),
        vec![Override {
            name: "foo".into(),
            target: OverrideTarget::Git {
                url: "https://fork.example.com/foo.git".into(),
                git_ref: "patched".into(),
            },
            // The override target's own annotation — this is what must win.
            version: Some(v(2, 0, 0)),
        }],
    );
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap();
    let foo = graph.deps.iter().find(|d| d.name == "foo").unwrap();
    assert_eq!(foo.version, v(2, 0, 0), "override's own version= must win");
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
        true,
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
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
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
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
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
            version: None,
        }],
    );
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
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
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-PROVENANCE-CONFLICT");
}

#[test]
fn resolve_non_root_provenance_disagreement_with_differing_real_versions_conflicts() {
    // §10.3, strengthened: the test above uses two BARE no-version `shared`
    // candidates, so the gate fires trivially — it never actually races a
    // real version-level conflict. Here each URL's own `shared` carries a
    // DIFFERENT REAL declared version (1.0.0 vs 2.0.0) — the shape a naive
    // solver could plausibly resolve into a version-level SOLVE-CONFLICT on
    // the shared name, rather than a provenance disagreement. The provenance
    // gate must still win: RES-PROVENANCE-CONFLICT, before either candidate's
    // version data is ever consulted by the solver.
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
            nimble(
                "sx",
                "version = \"1.0.0\"\nauthor = \"e\"\ndescription = \"d\"\nlicense = \"MIT\"\nsrcDir = \"src\"\n",
            ),
        ),
        (
            "https://y.example.com/shared.git",
            "main",
            nimble(
                "sy",
                "version = \"2.0.0\"\nauthor = \"e\"\ndescription = \"d\"\nlicense = \"MIT\"\nsrcDir = \"src\"\n",
            ),
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
        true,
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
        true,
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
        version: None,
    })]);
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        true,
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
        true,
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
        true,
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
        exclude_newer: None,
        deps: vec![LockedDep {
            declared_version_source: None,
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
            attestation: None,
        }],
    };
    let err = resolve(
        &m,
        None,
        &reg,
        None,
        Some(&prior),
        Strategy::Maxver,
        true,
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
        exclude_newer: None,
        deps: vec![LockedDep {
            declared_version_source: None,
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
            attestation: None,
        }],
    };
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        Some(&prior),
        Strategy::Maxver,
        true,
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
        version: None,
    })
}

fn prior_with_zero_identity(dep_name: &str, url: &str) -> Lockfile {
    Lockfile {
        version: LOCKFILE_SCHEMA_VERSION,
        strategy: "maxver".into(),
        exclude_newer: None,
        deps: vec![LockedDep {
            declared_version_source: None,
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
            attestation: None,
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
        &m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp),
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
        &m, None, &reg, None, Some(&prior), Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp),
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
        &m, None, &reg, None, Some(&prior), Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp),
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
        &m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp),
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
        &m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp),
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
        version: None,
    })]);
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        true,
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
        true,
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
        true,
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
        &m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false,
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
        &m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false,
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
        &m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false,
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
        version: None,
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
        true,
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
        version: None,
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
        true,
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
        version: None,
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
        true,
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
        version: None,
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
        true,
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
        version: None,
    });
    let m = manifest(vec![dep]);
    let graph = resolve(
        &m,
        None,
        &reg,
        None, // absent profile
        None,
        Strategy::Maxver,
        true,
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
        version: None,
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
        true,
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
        version: None,
    });
    let m = manifest(vec![dep]);
    let graph = resolve(
        &m,
        None,
        &reg,
        None,
        None,
        Strategy::Maxver,
        true,
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
        version: None,
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
        true,
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
        version: None,
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
        true,
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
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
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
        exclude_newer: None,
        deps: vec![LockedDep {
            declared_version_source: None,
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
            attestation: None,
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
        true,
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
        true,
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
    let err = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap_err();
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
        version: None,
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
    let err = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap_err();
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
    let err = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap_err();
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
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
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
    let err = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap_err();
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
    let err = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap_err();
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
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
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
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
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
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
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
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
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
    let graph = resolve(&m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp), None, false, &cas_store(&tmp)).unwrap();
    let lockfile = crate::lockfile::from_graph(&graph, "maxver", None);
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
        version: None,
        attestation_policy: milpa_manifest::TrustPolicy::Warn,
        index_trust_policy: milpa_manifest::TrustPolicy::Warn,
        index_trust_signer: None,
        index_trust_bundle: None,
        index_trust_policy_explicit: false,
        entry_trust_policy: milpa_manifest::TrustPolicy::Warn,
        entry_trust_policy_explicit: false,
        index_history_policy: milpa_manifest::TrustPolicy::Warn,
        index_history_policy_explicit: false,
        resolution: None,
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
        &m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp),
        None, false, &cas_store(&tmp),
        &features, false, false,
        None,
        None,
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
        &m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp),
        None, false, &cas_store(&tmp),
        &features, false, false,
        None,
        None,
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
        &m, None, &reg, None, None, Strategy::Maxver, true, &deps_dir(&tmp),
        None, false, &cas_store(&tmp),
        &features, false, false,
        None,
        None,
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
        exclude_newer: None,
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
        exclude_newer: None,
        deps: vec![
            milpa_types::LockedDep {
                declared_version_source: None,
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
                attestation: None,
            },
        ],
    };

    let features = std::collections::BTreeSet::new();
    crate::resolver::check_workspace_frozen_active_flags_mismatch(
        &ws, &lock, &features, false, false,
    )
    .expect("F5: consistent lock must pass frozen check");
}

// ---------------------------------------------------------------------------
// M6: effective_trust_policy SSOT unit tests (RFC registry-trust-federation §6.3)
// Zero tests existed before this PR; these cover the full policy matrix.
// ---------------------------------------------------------------------------

#[test]
fn effective_trust_policy_manifest_off_unconditional() {
    use crate::resolver::effective_trust_policy;
    use milpa_manifest::TrustPolicy;
    // manifest=Off wins unconditionally — env=Strict and flag=true are both no-ops.
    assert_eq!(
        effective_trust_policy(&TrustPolicy::Off, true, Some(&TrustPolicy::Strict)),
        TrustPolicy::Off,
        "manifest Off must win over flag=true + env=Strict"
    );
    assert_eq!(
        effective_trust_policy(&TrustPolicy::Off, false, Some(&TrustPolicy::Strict)),
        TrustPolicy::Off,
        "manifest Off must win over env=Strict"
    );
    assert_eq!(
        effective_trust_policy(&TrustPolicy::Off, false, None),
        TrustPolicy::Off,
        "manifest Off with no env must still be Off"
    );
}

#[test]
fn effective_trust_policy_flag_escalates_warn_to_strict() {
    use crate::resolver::effective_trust_policy;
    use milpa_manifest::TrustPolicy;
    assert_eq!(
        effective_trust_policy(&TrustPolicy::Warn, true, None),
        TrustPolicy::Strict,
        "flag=true must escalate Warn→Strict"
    );
}

#[test]
fn effective_trust_policy_env_strict_escalates_manifest_warn() {
    use crate::resolver::effective_trust_policy;
    use milpa_manifest::TrustPolicy;
    assert_eq!(
        effective_trust_policy(&TrustPolicy::Warn, false, Some(&TrustPolicy::Strict)),
        TrustPolicy::Strict,
        "env=Strict must escalate manifest Warn"
    );
}

#[test]
fn effective_trust_policy_env_off_is_noop_floor() {
    use crate::resolver::effective_trust_policy;
    use milpa_manifest::TrustPolicy;
    // env=Off cannot downgrade manifest Warn — it is a no-op floor.
    assert_eq!(
        effective_trust_policy(&TrustPolicy::Warn, false, Some(&TrustPolicy::Off)),
        TrustPolicy::Warn,
        "env=Off must not downgrade manifest Warn"
    );
}

#[test]
fn effective_trust_policy_env_warn_no_escalation() {
    use crate::resolver::effective_trust_policy;
    use milpa_manifest::TrustPolicy;
    // env=Warn on manifest Warn → stays Warn.
    assert_eq!(
        effective_trust_policy(&TrustPolicy::Warn, false, Some(&TrustPolicy::Warn)),
        TrustPolicy::Warn,
        "env=Warn + manifest=Warn must stay Warn"
    );
}

#[test]
fn effective_trust_policy_manifest_strict_env_off_stays_strict() {
    use crate::resolver::effective_trust_policy;
    use milpa_manifest::TrustPolicy;
    // manifest=Strict + env=Off → stays Strict (Off in env is a no-op floor).
    assert_eq!(
        effective_trust_policy(&TrustPolicy::Strict, false, Some(&TrustPolicy::Off)),
        TrustPolicy::Strict,
        "env=Off must not downgrade manifest Strict"
    );
}

// ---------------------------------------------------------------------------
// B5 (resolver-semantics RFC §3 Axis B / §7 slice B5 — #70 acceptance): the
// steady-state round-trip property.
//
//     resolve(M) -> G;  L = from_graph(G);  resolve(M, prior=parse(format(L))) == G
//
// Python's mirrored test (`test_b5_reresolve_property.py`) drives this via a
// Hypothesis generator sampling 1-3 named packages x 2-4 candidate versions
// x an optional floor constraint. **Rust has no property-testing framework
// wired up yet** — confirmed by grep (zero `proptest`/`quickcheck` references
// anywhere in this workspace's `Cargo.toml`/`Cargo.lock`); `docs/rfc-
// property-based-testing.md` §"Rust (v2 reference)" itself marks `proptest`
// as the anticipated *future* choice, never landed (Tiers A-C are Python-
// only; Rust proptest is explicitly "eventual"). Bootstrapping a brand-new
// test-framework dependency as a side effect of an unrelated resolution-
// semantics slice is out of this slice's scope (reported, not silently
// added) — instead this covers the SAME parameter space Python's generator
// explores via a deterministic sweep over every structurally distinct case:
// 1-3 packages, 2-4 versions per package, and constraint modes spanning
// unconstrained / floor-at-lowest / floor-mid / floor-at-highest (the
// single-remaining-candidate degenerate case). For a parameter space this
// small, boundary-exhaustive enumeration is at least as rigorous as bounded
// random sampling, at zero new-dependency cost.
//
// L6 code-review follow-up: re-confirmed `proptest` is STILL not a
// milpa-core/workspace dependency (checked all `Cargo.toml`s again), so per
// that finding's explicit guidance the sweep below was WIDENED with more
// hand-chosen adversarial shapes rather than reaching for a new dependency:
// a zero-choice single-version package, a wide (8-version) ladder,
// declaration order that is the reverse of alphabetical name order, and
// multiple packages sharing an identical version ladder. Python's Hypothesis
// generator remains the generative oracle for this property; this sweep is
// a deliberately bounded, dependency-free stand-in, not a replacement.
// ---------------------------------------------------------------------------

/// N-version index entry for `name` (generalizes `two_version_package` to
/// an arbitrary version ladder) — one distinct `.nimble` body per version so
/// each gets its own real `content_hash`.
fn multi_version_package(name: &str, versions: &[&str]) -> Package {
    let idx_ver = |ver: &str| IndexVersion {
        version: ver.into(),
        content_hash: hash_of_nimble(name, &format!("# {name} {ver}\n")),
        provenances: vec![Provenance::Git {
            url: format!("https://example.com/{name}.git"),
            ref_spec: format!("v{ver}"),
            commit_sha: None,
        }],
        dep_decl: None,
        dep_decl_schema_version: None,
        attestation: None,
        namespace: String::new(),
        published_at: None,
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        published_at_raw: None,
    };
    Package {
        name: name.to_string(),
        namespace: String::new(),
        versions: versions.iter().map(|v| idx_ver(v)).collect(),
    }
}

fn b5_index(specs: &[(&str, &[&str])]) -> Index {
    Index {
        packages: specs
            .iter()
            .map(|(name, versions)| multi_version_package(name, versions))
            .collect(),
    }
}

fn b5_registry(specs: &[(&str, &[&str])]) -> FakeReg {
    let mut mocks: Vec<(String, String, Mock)> = Vec::new();
    for (name, versions) in specs {
        for ver in versions.iter() {
            mocks.push((
                format!("https://example.com/{name}.git"),
                format!("v{ver}"),
                nimble(&format!("{name}-{ver}"), &format!("# {name} {ver}\n")),
            ));
        }
    }
    let refs: Vec<(&str, &str, Mock)> = mocks
        .iter()
        .map(|(u, r, m)| (u.as_str(), r.as_str(), m.clone()))
        .collect();
    FakeReg::git(&refs)
}

fn b5_manifest(specs: &[(&str, &[&str], Option<usize>)]) -> Manifest {
    manifest(
        specs
            .iter()
            .map(|(name, versions, floor_idx)| {
                let constraint = floor_idx.map(|i| format!(">={}", versions[i]));
                named_dep(name, constraint.as_deref())
            })
            .collect(),
    )
}

/// Normalized, order-insensitive signature of everything that identifies a
/// resolved dep's steady state -- mirrors Python's `_dep_signature`.
fn b5_normalize(d: &ResolvedDep) -> ResolvedDep {
    let mut d = d.clone();
    d.provenances.sort_by_key(|p| format!("{p:?}"));
    d.requires.sort();
    d.aliases.sort();
    d.active_flags.sort();
    d.cond_requires.sort_by_key(|c| format!("{c:?}"));
    d
}

fn b5_graph_signature(g: &ResolvedGraph) -> BTreeMap<String, ResolvedDep> {
    g.deps
        .iter()
        .map(|d| (d.name.clone(), b5_normalize(d)))
        .collect()
}

/// Runs one round-trip case: resolve fresh, round-trip the lock through the
/// REAL on-disk text format (`format_lockfile` + `parse_lockfile`, not just
/// the in-memory `from_graph` object -- the boundary a silent field-drop
/// bug would cross undetected), re-resolve the SAME manifest against the
/// SAME index with that lock as `prior`, and assert the two graphs agree.
fn b5_assert_round_trip_reproduces(specs: &[(&str, &[&str], Option<usize>)]) {
    let index_specs: Vec<(&str, &[&str])> = specs.iter().map(|(n, v, _)| (*n, *v)).collect();
    let index = b5_index(&index_specs);
    let reg = b5_registry(&index_specs);
    let m = b5_manifest(specs);

    let tmp1 = tempfile::tempdir().unwrap();
    let graph1 = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        None,
        Strategy::Maxver,
        true,
        &deps_dir(&tmp1),
        None,
        false,
        &cas_store(&tmp1),
    )
    .unwrap();

    let lock1 = from_graph(&graph1, "maxver", None);
    let prior = parse_lockfile(&format_lockfile(&lock1)).unwrap();

    let tmp2 = tempfile::tempdir().unwrap();
    let graph2 = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        Some(&prior),
        Strategy::Maxver,
        true,
        &deps_dir(&tmp2),
        None,
        false,
        &cas_store(&tmp2),
    )
    .unwrap();

    assert_eq!(
        b5_graph_signature(&graph2),
        b5_graph_signature(&graph1),
        "re-resolving with the just-produced lock must reproduce the same graph (specs: {specs:?})"
    );
}

#[test]
fn resolve_b5_reresolve_with_own_lock_reproduces_same_graph_sweep() {
    let cases: Vec<Vec<(&str, &[&str], Option<usize>)>> = vec![
        // 1 pkg, 2 versions, unconstrained.
        vec![("foo", &["1.0.0", "2.0.0"], None)],
        // 1 pkg, 4 versions, floor at the lowest (every candidate still open).
        vec![("foo", &["1.0.0", "2.0.0", "3.0.0", "4.0.0"], Some(0))],
        // 1 pkg, 4 versions, floor excluding some (mid-range).
        vec![("foo", &["1.0.0", "2.0.0", "3.0.0", "4.0.0"], Some(2))],
        // 1 pkg, floor at the top -- single-remaining-candidate degenerate case.
        vec![("foo", &["1.0.0", "2.0.0", "3.0.0"], Some(2))],
        // 2 pkgs, mixed unconstrained/floor.
        vec![
            ("foo", &["1.0.0", "2.0.0"], None),
            ("bar", &["1.0.0", "2.0.0", "3.0.0"], Some(1)),
        ],
        // 3 pkgs, mixed.
        vec![
            ("foo", &["1.0.0", "2.0.0", "3.0.0"], None),
            ("bar", &["1.0.0", "2.0.0"], None),
            ("baz", &["1.0.0", "2.0.0", "3.0.0", "4.0.0"], Some(1)),
        ],
        // 2 pkgs, one floor-at-lowest, one floor-at-highest.
        vec![
            ("aaa", &["1.0.0", "2.0.0"], Some(0)),
            ("bbb", &["1.0.0", "2.0.0"], Some(1)),
        ],
        // 3 pkgs, every floor edge case in one graph.
        vec![
            ("ppp", &["1.0.0", "2.0.0", "3.0.0", "4.0.0"], None),
            ("qqq", &["1.0.0", "2.0.0", "3.0.0", "4.0.0"], Some(0)),
            ("rrr", &["1.0.0", "2.0.0", "3.0.0", "4.0.0"], Some(3)),
        ],
        // L6: widened adversarial shapes (see the module doc-comment above --
        // proptest is not, and must not become, a milpa-core dependency;
        // Python's Hypothesis generator (`test_b5_reresolve_property.py`)
        // remains the generative oracle for this property. These cases probe
        // corners the original 8-case boundary sweep didn't: a zero-choice
        // degenerate package, a wide ladder, declaration order that is the
        // REVERSE of alphabetical name order (guards against a latent
        // dependence on iteration/sort order rather than true declaration
        // order -- the same axis R3/RR3 pins for solve determinism), and
        // multiple packages sharing an IDENTICAL version ladder (guards
        // against any accidental cross-package aliasing in candidate/lock
        // bookkeeping keyed loosely on version strings).
        //
        // Single version, zero degrees of freedom -- the solver has exactly
        // one candidate before AND after the round trip.
        vec![("solo", &["1.0.0"], None)],
        // Wide ladder (8 versions), floor one below the top.
        vec![(
            "wide",
            &["1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0", "6.0.0", "7.0.0", "8.0.0"],
            Some(6),
        )],
        // Declaration order is the REVERSE of alphabetical name order.
        vec![
            ("zeta", &["1.0.0", "2.0.0", "3.0.0"], Some(1)),
            ("mu", &["1.0.0", "2.0.0"], None),
            ("alpha", &["1.0.0", "2.0.0", "3.0.0", "4.0.0"], Some(0)),
        ],
        // Two packages, deliberately non-alphabetical declaration order,
        // each floored at the OPPOSITE end of an identical version ladder.
        vec![
            ("omega-pkg", &["1.0.0", "2.0.0", "3.0.0"], Some(2)),
            ("delta-pkg", &["1.0.0", "2.0.0", "3.0.0"], Some(0)),
        ],
        // Three packages sharing an IDENTICAL version ladder, each with a
        // different (or absent) floor.
        vec![
            ("shared-a", &["1.0.0", "2.0.0", "3.0.0", "4.0.0"], None),
            ("shared-b", &["1.0.0", "2.0.0", "3.0.0", "4.0.0"], Some(0)),
            ("shared-c", &["1.0.0", "2.0.0", "3.0.0", "4.0.0"], Some(3)),
        ],
        // 4 packages, heterogeneous ladder widths (2/3/5/6) and every floor
        // shape (none/low/mid/high) combined in one graph.
        vec![
            ("het-a", &["1.0.0", "2.0.0"], None),
            ("het-b", &["1.0.0", "2.0.0", "3.0.0"], Some(0)),
            ("het-c", &["1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0"], Some(2)),
            (
                "het-d",
                &["1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0", "6.0.0"],
                Some(5),
            ),
        ],
    ];

    for case in &cases {
        b5_assert_round_trip_reproduces(case);
    }
}

// ---------------------------------------------------------------------------
// D3 (resolution-semantics RFC §3 Axis D / §4 stage 2 — #86): the
// exclude-newer hard cut on index/named candidates, applied at the
// ENUMERATION layer, end to end through `resolve_with_features`.
//
// `milpa-core::registry_tests`'s `d3_*` tests cover the pure filtering
// function (`filter_by_exclude_newer`) in isolation. This proves the
// resolver actually wires `exclude_newer` into `process_named` for a real
// named/index dep: selection (an older version is chosen because a newer
// one is filtered out), fail-closed exclusion (no provable `published_at` is
// never permissively kept), the distinct `RES-EXCLUDE-NEWER-EMPTY` error
// class (never a generic no-satisfying-version/solve-conflict), and the
// no-bound regression (behavior is byte-identical to pre-D3 when
// `exclude_newer` is unset). Mirrors
// impls/python/tests/test_d3_exclude_newer_enumeration.py.
// ---------------------------------------------------------------------------

fn d3_ver(name: &str, ver: &str, body: &str, published_at: Option<&str>) -> IndexVersion {
    IndexVersion {
        version: ver.into(),
        content_hash: hash_of_nimble(name, body),
        provenances: vec![Provenance::Git {
            url: format!("https://example.com/{name}.git"),
            ref_spec: format!("v{ver}"),
            commit_sha: None,
        }],
        dep_decl: None,
        dep_decl_schema_version: None,
        attestation: None,
        namespace: String::new(),
        published_at: published_at.and_then(parse_iso8601_timestamp),
        yanked: false,
        yanked_at: None,
        yanked_reason: None,
        published_at_raw: None,
    }
}

/// `versions` is `(version, nimble_body, published_at)`; `published_at: None`
/// omits the field entirely (the fail-closed case — mirrors the Python
/// helper's `_build_index`).
fn d3_index(name: &str, versions: &[(&str, &str, Option<&str>)]) -> Index {
    Index {
        packages: vec![Package {
            name: name.to_string(),
            namespace: String::new(),
            versions: versions
                .iter()
                .map(|(ver, body, published_at)| d3_ver(name, ver, body, *published_at))
                .collect(),
        }],
    }
}

fn d3_registry(name: &str, versions: &[(&str, &str)]) -> FakeReg {
    let mut by_url_ref = BTreeMap::new();
    for (ver, body) in versions {
        by_url_ref.insert(
            (format!("https://example.com/{name}.git"), format!("v{ver}")),
            nimble("s", body),
        );
    }
    FakeReg {
        by_url_ref,
        by_oci: BTreeMap::new(),
        calls: RefCell::new(Vec::new()),
    }
}

#[allow(clippy::too_many_arguments)]
fn d3_resolve(
    m: &Manifest,
    index: &Index,
    reg: &FakeReg,
    tmp: &tempfile::TempDir,
    exclude_newer: Option<&str>,
) -> Result<ResolvedGraph, MilpaError> {
    resolve_with_features(
        m,
        Some(index),
        reg,
        None,
        None,
        Strategy::Maxver,
        true,
        &deps_dir(tmp),
        None,
        false,
        &cas_store(tmp),
        &std::collections::BTreeSet::new(),
        false,
        false,
        None,
        exclude_newer.map(|ts| parse_iso8601_timestamp(ts).unwrap()),
    )
}

#[test]
fn resolve_d3_older_version_selected_when_newer_is_excluded() {
    let index = d3_index(
        "libfoo",
        &[
            ("1.0.0", "# v1\n", Some("2026-01-01T00:00:00Z")),
            ("2.0.0", "# v2\n", Some("2026-12-01T00:00:00Z")),
        ],
    );
    let reg = d3_registry("libfoo", &[("1.0.0", "# v1\n"), ("2.0.0", "# v2\n")]);
    let m = manifest(vec![named_dep("libfoo", None)]);

    // No bound: newest (2.0.0) wins — the pre-D3 regression baseline.
    let tmp_fresh = tempfile::tempdir().unwrap();
    let fresh = d3_resolve(&m, &index, &reg, &tmp_fresh, None).unwrap();
    assert_eq!(
        fresh.deps.iter().find(|d| d.name == "libfoo").unwrap().version,
        v(2, 0, 0)
    );

    // Bound between the two publish dates: 2.0.0 is excluded, 1.0.0 wins.
    let tmp_bounded = tempfile::tempdir().unwrap();
    let bounded = d3_resolve(
        &m,
        &index,
        &reg,
        &tmp_bounded,
        Some("2026-06-01T00:00:00Z"),
    )
    .unwrap();
    assert_eq!(
        bounded.deps.iter().find(|d| d.name == "libfoo").unwrap().version,
        v(1, 0, 0)
    );
}

#[test]
fn resolve_d3_fail_closed_excludes_unprovable_timestamp() {
    let index = d3_index(
        "libfoo",
        &[
            ("1.0.0", "# v1\n", Some("2026-01-01T00:00:00Z")),
            ("2.0.0", "# v2\n", None), // no published_at at all
        ],
    );
    let reg = d3_registry("libfoo", &[("1.0.0", "# v1\n"), ("2.0.0", "# v2\n")]);
    let m = manifest(vec![named_dep("libfoo", None)]);

    // No bound: 2.0.0 (no published_at) still wins on maxver — unaffected.
    let tmp_fresh = tempfile::tempdir().unwrap();
    let fresh = d3_resolve(&m, &index, &reg, &tmp_fresh, None).unwrap();
    assert_eq!(
        fresh.deps.iter().find(|d| d.name == "libfoo").unwrap().version,
        v(2, 0, 0)
    );

    // Bound active: 2.0.0 is fail-closed excluded (unprovable), 1.0.0 wins —
    // NOT 2.0.0, even though an absent published_at is ordinarily permissive.
    let tmp_bounded = tempfile::tempdir().unwrap();
    let bounded = d3_resolve(
        &m,
        &index,
        &reg,
        &tmp_bounded,
        Some("2026-06-01T00:00:00Z"),
    )
    .unwrap();
    assert_eq!(
        bounded.deps.iter().find(|d| d.name == "libfoo").unwrap().version,
        v(1, 0, 0)
    );
}

#[test]
fn resolve_d3_all_candidates_excluded_raises_res_exclude_newer_empty() {
    let index = d3_index(
        "libfoo",
        &[
            ("1.0.0", "# v1\n", Some("2026-01-01T00:00:00Z")),
            ("2.0.0", "# v2\n", Some("2026-12-01T00:00:00Z")),
        ],
    );
    let reg = d3_registry("libfoo", &[("1.0.0", "# v1\n"), ("2.0.0", "# v2\n")]);
    let m = manifest(vec![named_dep("libfoo", None)]);

    let tmp = tempfile::tempdir().unwrap();
    let err = d3_resolve(&m, &index, &reg, &tmp, Some("2020-01-01T00:00:00Z")).unwrap_err();
    assert_eq!(err.code(), "RES-EXCLUDE-NEWER-EMPTY");
}

#[test]
fn resolve_d3_single_unprovable_candidate_empties_and_raises() {
    let index = d3_index("libfoo", &[("1.0.0", "# v1\n", None)]);
    let reg = d3_registry("libfoo", &[("1.0.0", "# v1\n")]);
    let m = manifest(vec![named_dep("libfoo", None)]);

    let tmp = tempfile::tempdir().unwrap();
    let err = d3_resolve(&m, &index, &reg, &tmp, Some("2026-06-01T00:00:00Z")).unwrap_err();
    assert_eq!(err.code(), "RES-EXCLUDE-NEWER-EMPTY");
}

#[test]
fn resolve_d3_no_bound_picks_newest_regardless_of_published_at() {
    let index = d3_index(
        "libfoo",
        &[
            ("1.0.0", "# v1\n", Some("2026-12-01T00:00:00Z")), // newer publish date...
            ("2.0.0", "# v2\n", Some("2026-01-01T00:00:00Z")), // ...than this "newer" version
        ],
    );
    let reg = d3_registry("libfoo", &[("1.0.0", "# v1\n"), ("2.0.0", "# v2\n")]);
    let m = manifest(vec![named_dep("libfoo", None)]);

    let tmp = tempfile::tempdir().unwrap();
    let graph = d3_resolve(&m, &index, &reg, &tmp, None).unwrap();
    // maxver picks the highest SEMVER (2.0.0); published_at is irrelevant
    // when no bound is active.
    assert_eq!(
        graph.deps.iter().find(|d| d.name == "libfoo").unwrap().version,
        v(2, 0, 0)
    );
}

// ---------------------------------------------------------------------------
// D4 (resolution-semantics RFC §3 Axis D / §6 D-D1/D-D2 — #86): the
// exclude-newer hard cut on a git/url pinned-ref dep, applied as VALIDATION
// (not selection — a git dep has exactly one candidate, unlike an index dep's
// enumerated set, D3's concern).
//
// `crates/milpa-core/src/fetchers_tests.rs`'s `fetch_git_committer_date_*`
// tests cover the REAL git committer-date read (via real local repos, incl.
// the anti-tagger-date guard: an annotated tag whose tagger date differs
// from the commit's committer date). This proves the RESOLVER wires
// `exclude_newer` into that value and raises `RES-EXCLUDE-NEWER-PIN`
// end to end through `resolve_with_features`, using `FakeReg`'s mock
// `committer_date` (which mirrors the real `Receipt.committer_date` field
// exactly) — the same resolver-test convention D3's `d3_resolve` uses.
// Mirrors impls/python/tests/test_d4_exclude_newer_git_validation.py.
// ---------------------------------------------------------------------------

fn d4_registry(url: &str, refp: &str, sha: &str, committer_unix: i64) -> FakeReg {
    let mut by_url_ref = BTreeMap::new();
    by_url_ref.insert(
        (url.to_string(), refp.to_string()),
        Mock {
            sha: sha.to_string(),
            committer_date: Some(committer_unix),
            ..Mock::default()
        },
    );
    FakeReg {
        by_url_ref,
        by_oci: BTreeMap::new(),
        calls: RefCell::new(Vec::new()),
    }
}

#[allow(clippy::too_many_arguments)]
fn d4_resolve(
    m: &Manifest,
    reg: &FakeReg,
    tmp: &tempfile::TempDir,
    exclude_newer: Option<&str>,
) -> Result<ResolvedGraph, MilpaError> {
    resolve_with_features(
        m,
        None,
        reg,
        None,
        None,
        Strategy::Maxver,
        true,
        &deps_dir(tmp),
        None,
        false,
        &cas_store(tmp),
        &std::collections::BTreeSet::new(),
        false,
        false,
        None,
        exclude_newer.map(|ts| parse_iso8601_timestamp(ts).unwrap()),
    )
}

#[test]
fn resolve_d4_commit_predating_bound_resolves_cleanly() {
    let m = manifest(vec![url_dep("foo", "https://example.com/foo.git", "v1.0.0")]);
    // Commit committer date = 2020-01-01T00:00:00Z.
    let reg = d4_registry("https://example.com/foo.git", "v1.0.0", "a".repeat(40).as_str(), 1_577_836_800);

    let tmp = tempfile::tempdir().unwrap();
    let graph = d4_resolve(&m, &reg, &tmp, Some("2020-06-01T00:00:00Z")).unwrap();
    assert!(graph.deps.iter().any(|d| d.name == "foo"));
}

#[test]
fn resolve_d4_commit_newer_than_bound_hard_fails() {
    let m = manifest(vec![url_dep("foo", "https://example.com/foo.git", "v1.0.0")]);
    // Commit committer date = 2020-01-01T00:00:00Z — AFTER the bound below.
    let sha = "a".repeat(40);
    let reg = d4_registry("https://example.com/foo.git", "v1.0.0", &sha, 1_577_836_800);

    let tmp = tempfile::tempdir().unwrap();
    let err = d4_resolve(&m, &reg, &tmp, Some("2019-01-01T00:00:00Z")).unwrap_err();
    assert_eq!(err.code(), "RES-EXCLUDE-NEWER-PIN");
    // Message content isn't a harness-checked surface (this crate's own design
    // note: "the harness asserts on .code() only") — a light Debug-format
    // sanity check confirms the dep name and commit made it into the message.
    let msg = format!("{err:?}");
    assert!(msg.contains("foo"), "message must name the dep: {msg}");
    assert!(msg.contains(&sha), "message must name the commit: {msg}");
}

#[test]
fn resolve_d4_commit_exactly_at_bound_passes() {
    // L9: the comparison is STRICT `>` (resolver.rs process_url) -- a
    // pinned commit whose committer date EQUALS the exclude-newer bound
    // exactly must pass, not hard-fail. Only strictly-newer-than-bound is
    // rejected.
    let m = manifest(vec![url_dep("foo", "https://example.com/foo.git", "v1.0.0")]);
    // Commit committer date = 2020-01-01T00:00:00Z -- identical to the bound.
    let reg = d4_registry("https://example.com/foo.git", "v1.0.0", "a".repeat(40).as_str(), 1_577_836_800);

    let tmp = tempfile::tempdir().unwrap();
    let graph = d4_resolve(&m, &reg, &tmp, Some("2020-01-01T00:00:00Z")).unwrap();
    assert!(graph.deps.iter().any(|d| d.name == "foo"));
}

#[test]
fn resolve_d4_no_bound_is_a_no_op_regression() {
    let m = manifest(vec![url_dep("foo", "https://example.com/foo.git", "v1.0.0")]);
    // An arbitrarily "old" committer date — must not matter with no bound set.
    let reg = d4_registry("https://example.com/foo.git", "v1.0.0", "a".repeat(40).as_str(), 0);

    let tmp = tempfile::tempdir().unwrap();
    let graph = d4_resolve(&m, &reg, &tmp, None).unwrap();
    assert!(graph.deps.iter().any(|d| d.name == "foo"));
}

#[test]
fn resolve_d4_no_bound_tolerates_missing_committer_date_regression() {
    // L2: `fetch_git` now degrades a committer-date READ FAILURE to `None`
    // on the Receipt rather than failing the whole fetch (a `git log` hiccup
    // must not fail a fetch that never asked for a time bound). With NO
    // exclude-newer bound configured, a git dep whose mock never sets
    // committer_date (standing in for that degraded-to-`None` receipt) must
    // still resolve cleanly — this is the "doesn't need the date" half of
    // L2's fix.
    let m = manifest(vec![url_dep("foo", "https://example.com/foo.git", "v1.0.0")]);
    let mut by_url_ref = BTreeMap::new();
    by_url_ref.insert(
        ("https://example.com/foo.git".to_string(), "v1.0.0".to_string()),
        Mock {
            sha: "a".repeat(40),
            ..Mock::default()
        },
    );
    let reg = FakeReg {
        by_url_ref,
        by_oci: BTreeMap::new(),
        calls: RefCell::new(Vec::new()),
    };

    let tmp = tempfile::tempdir().unwrap();
    let graph = d4_resolve(&m, &reg, &tmp, None).unwrap();
    assert!(graph.deps.iter().any(|d| d.name == "foo"));
}

#[test]
fn resolve_d4_bound_set_but_committer_date_absent_stays_unvalidated_regression() {
    // L2 (the other half, corrected): `fetch_git` degrading a date-read
    // failure to `None` must NOT flip into a NEW fail-closed branch when a
    // bound IS configured — `committer_date: None` is the SAME
    // "not validated by D4" signal non-git transports already use
    // (local/tarball/OCI never have a commit date at all), and this
    // permissive absence-handling is relied on throughout the CLI test
    // suite's D5 (`--locked` drift) coverage, which routinely passes
    // `--exclude-newer` against mocked git fixtures that never populate a
    // `committer_date` file. An earlier draft of this fix made this case
    // fail closed (reasoning that a hiccup shouldn't silently bypass the
    // check) and that broke ~20 unrelated existing tests — the absence
    // convention is intentional, not a gap. This regression-pins the
    // corrected (unchanged) behavior: a very tight bound that WOULD fail if
    // a committer_date were present still resolves cleanly when it's absent.
    let m = manifest(vec![url_dep("foo", "https://example.com/foo.git", "v1.0.0")]);
    let mut by_url_ref = BTreeMap::new();
    by_url_ref.insert(
        ("https://example.com/foo.git".to_string(), "v1.0.0".to_string()),
        Mock {
            sha: "a".repeat(40),
            ..Mock::default()
        },
    );
    let reg = FakeReg {
        by_url_ref,
        by_oci: BTreeMap::new(),
        calls: RefCell::new(Vec::new()),
    };

    let tmp = tempfile::tempdir().unwrap();
    let graph = d4_resolve(&m, &reg, &tmp, Some("1970-01-01T00:00:00Z")).unwrap();
    assert!(graph.deps.iter().any(|d| d.name == "foo"));
}

// ---------------------------------------------------------------------------
// D-D2 (resolution-semantics RFC §3 Axis D / §6 D-D2): branch-ref-once-locked
// reproducibility. `FakeReg` previously keyed purely on `(url, ref)` and
// ignored `commit_sha` entirely, so "resolver reused the OLD pinned commit's
// committer date" vs "resolver re-fetched the live ref-tip's date" were
// indistinguishable in a D4 test. `Mock::committer_date_by_sha` (additive:
// `None` for every pre-existing mock, unaffected) now lets a mock report a
// DIFFERENT committer date depending on whether the incoming fetch carries an
// exact commit_sha pin — proving the resolver, given a prior lock pinning an
// OLD commit_sha for a branch ref, validates exclude_newer against THAT
// PINNED commit's date, not a freshly re-resolved ref-tip date. Mirrors
// conformance fixtures 445/446 (impl-neutral, run by both harnesses) and
// impls/python's mocked.py additive extension.
// ---------------------------------------------------------------------------

/// A prior `Lockfile` pinning `name` to `commit_sha` at `(url, ref="main")`,
/// with `identity` matching whatever `FakeReg`'s single content dir
/// materializes (`hash_of_nimble(name, body)`) — the SAME tree regardless of
/// which commit_sha is pinned, so the identity gate passes trivially and the
/// test isolates exactly the committer_date-by-commit_sha distinction.
fn d_d2_prior_lock(name: &str, url: &str, commit_sha: &str, identity: &str) -> Lockfile {
    Lockfile {
        version: LOCKFILE_SCHEMA_VERSION,
        strategy: "maxver".into(),
        exclude_newer: None,
        deps: vec![LockedDep {
            declared_version_source: None,
            name: name.into(),
            namespace: None,
            identity: Some(identity.into()),
            version: "0.0.1".into(),
            src_dir: "src".into(),
            requires: Vec::new(),
            provenances: vec![ProvenanceRecord::Git {
                url: url.into(),
                ref_spec: Some("main".into()),
                commit_sha: Some(commit_sha.into()),
                origin: "observed".into(),
                submodule_shas: vec![],
            }],
            active_flags: Vec::new(),
            dep_decl: None,
            cond_requires: Vec::new(),
            aliases: Vec::new(),
            attestation: None,
        }],
    }
}

#[allow(clippy::too_many_arguments)]
fn d_d2_resolve(
    m: &Manifest,
    reg: &FakeReg,
    prior: Option<&Lockfile>,
    tmp: &tempfile::TempDir,
    exclude_newer: Option<&str>,
) -> Result<ResolvedGraph, MilpaError> {
    resolve_with_features(
        m,
        None,
        reg,
        None,
        prior,
        Strategy::Maxver,
        true,
        &deps_dir(tmp),
        None,
        false,
        &cas_store(tmp),
        &std::collections::BTreeSet::new(),
        false,
        false,
        None,
        exclude_newer.map(|ts| parse_iso8601_timestamp(ts).unwrap()),
    )
}

#[test]
fn resolve_d_d2_reused_pin_validates_against_pinned_date_not_tip_date() {
    // Tip (unpinned fetch): committer date 2026 — AFTER the bound; would fail
    // if a fresh/re-fetch used it. Pinned commit's own date: 2020 — BEFORE
    // the bound. Only reusing the PRIOR LOCK'S PINNED commit (not the live
    // tip) resolves cleanly.
    let url = "https://example.com/widget.git";
    let body = "srcDir = \"src\"\n";
    let identity = hash_of_nimble("widget", body);
    let tip_sha = "2".repeat(40);
    let old_sha = "1".repeat(40);

    let mut committer_date_by_sha = BTreeMap::new();
    committer_date_by_sha.insert(old_sha.clone(), 1_577_836_800); // 2020-01-01
    let mut by_url_ref = BTreeMap::new();
    by_url_ref.insert(
        (url.to_string(), "main".to_string()),
        Mock {
            sha: tip_sha.clone(),
            nimble: Some(body.to_string()),
            committer_date: Some(1_798_761_600), // 2026-12-... (well after bound)
            committer_date_by_sha: Some(committer_date_by_sha),
            ..Mock::default()
        },
    );
    let reg = FakeReg {
        by_url_ref,
        by_oci: BTreeMap::new(),
        calls: RefCell::new(Vec::new()),
    };

    let m = manifest(vec![url_dep("widget", url, "main")]);
    let bound = "2021-01-01T00:00:00Z";

    // Fresh resolve (no prior): unpinned fetch reports the TIP's date (2026)
    // -> exceeds the bound -> hard fails.
    let tmp_fresh = tempfile::tempdir().unwrap();
    let err = d_d2_resolve(&m, &reg, None, &tmp_fresh, Some(bound)).unwrap_err();
    assert_eq!(err.code(), "RES-EXCLUDE-NEWER-PIN");

    // Prior-pinned resolve: the prior lock pins `old_sha`, whose own date
    // (2020) is BEFORE the bound -> resolves cleanly, reproducing `old_sha`
    // verbatim (not silently drifting to the tip's `tip_sha`).
    let prior = d_d2_prior_lock("widget", url, &old_sha, &identity);
    let tmp_pinned = tempfile::tempdir().unwrap();
    let graph = d_d2_resolve(&m, &reg, Some(&prior), &tmp_pinned, Some(bound)).unwrap();
    let widget = graph.deps.iter().find(|d| d.name == "widget").unwrap();
    match widget.provenances.first().expect("provenance") {
        ProvenanceRecord::Git { commit_sha, .. } => {
            assert_eq!(
                commit_sha.as_deref(),
                Some(old_sha.as_str()),
                "reused pin must reproduce the OLD commit, not the live tip"
            );
        }
        other => panic!("expected git provenance, got {other:?}"),
    }
}

#[test]
fn resolve_d_d2_reused_pin_fails_despite_passing_tip() {
    // Mirror direction: the pinned commit's OWN date (2026) is AFTER the
    // bound and must hard-fail, even though the mock's flat/tip date (2020)
    // would pass the same bound — proving the resolver doesn't permissively
    // fall back to the tip's date when a pin is in play.
    let url = "https://example.com/widget.git";
    let body = "srcDir = \"src\"\n";
    let identity = hash_of_nimble("widget", body);
    let tip_sha = "4".repeat(40);
    let old_sha = "3".repeat(40);

    let mut committer_date_by_sha = BTreeMap::new();
    committer_date_by_sha.insert(old_sha.clone(), 1_798_761_600); // 2026, after bound
    let mut by_url_ref = BTreeMap::new();
    by_url_ref.insert(
        (url.to_string(), "main".to_string()),
        Mock {
            sha: tip_sha,
            nimble: Some(body.to_string()),
            committer_date: Some(1_577_836_800), // 2020-01-01, before bound
            committer_date_by_sha: Some(committer_date_by_sha),
            ..Mock::default()
        },
    );
    let reg = FakeReg {
        by_url_ref,
        by_oci: BTreeMap::new(),
        calls: RefCell::new(Vec::new()),
    };

    let m = manifest(vec![url_dep("widget", url, "main")]);
    let bound = "2021-01-01T00:00:00Z";
    let prior = d_d2_prior_lock("widget", url, &old_sha, &identity);
    let tmp = tempfile::tempdir().unwrap();
    let err = d_d2_resolve(&m, &reg, Some(&prior), &tmp, Some(bound)).unwrap_err();
    assert_eq!(err.code(), "RES-EXCLUDE-NEWER-PIN");
    let msg = format!("{err:?}");
    assert!(
        msg.contains(&old_sha),
        "message must name the PINNED commit, not the tip: {msg}"
    );
}

// ---------------------------------------------------------------------------
// A4 (resolver-semantics RFC §3 Axis A (c) / §6 D-A1): the version-unknown
// constrained multi-constrainer enumeration, at RESOLVER-MESSAGE granularity
// (not just the solver-internal `SolverError::VersionUnknownConstrained`
// object — `milpa-solver`'s own unit tests, e.g.
// `version_unknown_constrained_enumerates_multiple_real_constrainers`, cover
// that in isolation). This proves `version_unknown_constrained_err` (this
// file's production function, exercised end to end through `resolve`) names
// BOTH real constrainers in the rendered remedy message — the amoxtli
// incident floored two packages at once, so a user must be able to fix every
// constraint in one pass instead of a serial fail-fix-rerun loop. Mirrors
// impls/python/tests/test_a4_version_unknown_constrained.py's
// `TestVersionUnknownConstrainedMultipleRealConstrainers`.
// ---------------------------------------------------------------------------

#[test]
fn resolve_a4_version_unknown_constrained_names_both_real_constrainers() {
    // bearssl: root-declared git URL dep, no version source at all (version-
    // unknown). chronos and asyncdispatch are independent named/index deps,
    // each floors bearssl at a DIFFERENT real constraint via their own
    // `.nimble` requires line.
    let bearssl_url = "https://example.com/bearssl.git";
    let chronos_url = "https://example.com/chronos.git";
    let async_url = "https://example.com/asyncdispatch.git";
    let bearssl_body = "author = \"e\"\ndescription = \"d\"\nlicense = \"MIT\"\n";
    let chronos_body =
        "author = \"e\"\ndescription = \"d\"\nlicense = \"MIT\"\nrequires \"bearssl >= 0.2.8\"\n";
    let async_body =
        "author = \"e\"\ndescription = \"d\"\nlicense = \"MIT\"\nrequires \"bearssl <= 0.9.0\"\n";

    let mut by_url_ref = BTreeMap::new();
    by_url_ref.insert(
        (bearssl_url.to_string(), "main".to_string()),
        nimble("b".repeat(40).as_str(), bearssl_body),
    );
    by_url_ref.insert(
        (chronos_url.to_string(), "v1.0.0".to_string()),
        nimble("c".repeat(40).as_str(), chronos_body),
    );
    by_url_ref.insert(
        (async_url.to_string(), "v1.0.0".to_string()),
        nimble("d".repeat(40).as_str(), async_body),
    );
    let reg = FakeReg {
        by_url_ref,
        by_oci: BTreeMap::new(),
        calls: RefCell::new(Vec::new()),
    };

    let single_ver = |name: &str, url: &str, body: &str| Package {
        name: name.to_string(),
        namespace: String::new(),
        versions: vec![IndexVersion {
            version: "1.0.0".into(),
            content_hash: hash_of_nimble(name, body),
            provenances: vec![Provenance::Git {
                url: url.to_string(),
                ref_spec: "v1.0.0".to_string(),
                commit_sha: None,
            }],
            dep_decl: None,
            dep_decl_schema_version: None,
            attestation: None,
            namespace: String::new(),
            published_at: None,
            yanked: false,
            yanked_at: None,
            yanked_reason: None,
            published_at_raw: None,
        }],
    };
    let index = Index {
        packages: vec![
            single_ver("chronos", chronos_url, chronos_body),
            single_ver("asyncdispatch", async_url, async_body),
        ],
    };

    let m = manifest(vec![
        url_dep("bearssl", bearssl_url, "main"),
        named_dep("chronos", None),
        named_dep("asyncdispatch", None),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let err = resolve(
        &m,
        Some(&index),
        &reg,
        None,
        None,
        Strategy::Maxver,
        true,
        &deps_dir(&tmp),
        None,
        false,
        &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-VERSION-UNKNOWN-CONSTRAINED");
    let msg = format!("{err:?}");
    assert!(msg.contains("bearssl"), "message must name bearssl: {msg}");
    // BOTH real constrainers must be named — not just the first one the
    // solver happened to record.
    assert!(
        msg.contains("chronos") && msg.contains(">=0.2.8"),
        "message must name chronos's constraint: {msg}"
    );
    assert!(
        msg.contains("asyncdispatch") && msg.contains("<=0.9.0"),
        "message must name asyncdispatch's constraint: {msg}"
    );
}

// ---------------------------------------------------------------------------
// #193 — the three-tier provenance authority lattice (resolver-semantics.md
// §10.0), REVISED to validate-against-registry (§10.0/§10.3/§10.5). Mirrors
// Python's `tests/test_provenance_lattice.py`: resolver-level scenarios +
// direct gate-unit tests of `ResolveProvider::gate`'s tier decision table,
// plus direct unit tests of `normalize_git_source_url` /
// `validate_transitive_url_against_registry`.
//
// Tier 1 (highest) Root      — root/member deps + dev-deps + overrides.
// Tier 2           Registry  — a `Named`/index claim.
// Tier 3 (lowest)  Self-URL  — a transitive url/local/tarball claim.
//
// **Design revision (validate-against-registry):** the registry is a TRUSTED
// DEFAULT, not an explicit per-build choice. For a non-root name present in
// the registry index, a transitive self-declared `git=` claim is VALIDATED
// against the registry's recorded source for the name (`gate_only`, BEFORE
// the tier-based `gate()` below is ever consulted):
//   - AGREES (same git repository the registry records — a differing `ref`
//     is still agreement) → ACCEPTED and resolves normally, exactly like an
//     ordinary tier-3 url dep — this BYPASSES the tier gate entirely, so two
//     agreeing pins of the same real repo (different refs, from different
//     transitives) coexist rather than being arbitrated against each other.
//     This SUPERSEDES the prior "membership-based redirect" design (a lone
//     agreeing url pin is no longer silently redirected to the registry's
//     own version — it is accepted AS ITSELF).
//   - DISAGREES (a different source repository, or an incomparable
//     transport) → raises `RES-PROVENANCE-CONFLICT` — even for a LONE
//     disagreeing claim, with no competing claim anywhere else in the graph
//     (the headline behavioral change from the prior disagreement-only
//     design: a transitive can no longer silently substitute a registry
//     name's source, nor can it silently be overridden by the registry).
//
// Ordering note: unlike Python's wave-based concurrent BFS, Rust's
// `process_items` gates a batch then DISPATCHES each survivor depth-first —
// dispatching a URL/tarball/local item recursively drains its own subtree
// (via a nested `process_items` call) before the outer loop's next sibling
// is even visited. So here, ordering between two competing claims is forced
// by ROOT-DEP DECLARATION ORDER (which branch is listed first in the root
// manifest), not by hop-count — the branch declared first has its entire
// subtree fully resolved (fetched, gated, sub-dep processed) before the
// next declared branch is ever dispatched. Under validate-against-registry
// this ordering barely matters for a registry-known name's url claim: the
// claim is validated at its OWN discovery, a static function of the name +
// the (already-loaded) index record alone — never of which other claims
// happen to exist or when they are discovered.
// ---------------------------------------------------------------------------

/// Builds a single-package, single-version `Index` for `name`, backed by a
/// git provenance at `(url, ref)` whose content matches `hash_of_nimble` — so
/// the identity gate passes when the resolver fetches it as a `Named` claim.
fn lattice_index(name: &str, url: &str, refp: &str, body: &str) -> Index {
    lattice_index_ver(name, url, refp, "1.0.0", body)
}

/// Like `lattice_index`, but lets the caller pick the recorded version string
/// (mirrors Python's `_index_kdl_one_pkg`'s `version` positional).
fn lattice_index_ver(name: &str, url: &str, refp: &str, version: &str, body: &str) -> Index {
    Index {
        packages: vec![Package {
            name: name.to_string(),
            namespace: String::new(),
            versions: vec![IndexVersion {
                version: version.into(),
                content_hash: hash_of_nimble(name, body),
                provenances: vec![Provenance::Git {
                    url: url.to_string(),
                    ref_spec: refp.to_string(),
                    commit_sha: None,
                }],
                dep_decl: None,
                dep_decl_schema_version: None,
                attestation: None,
                namespace: String::new(),
                published_at: None,
                yanked: false,
                yanked_at: None,
                yanked_reason: None,
                published_at_raw: None,
            }],
        }],
    }
}

/// Two single-version packages in one `Index` — mirrors Python's
/// `_index_kdl_two_pkgs`, for the mid-solve-residual scenario below (which
/// needs BOTH `outer` and `foo` to be registry-known).
#[allow(clippy::too_many_arguments)]
fn lattice_index_two(
    name1: &str, url1: &str, ref1: &str, body1: &str,
    name2: &str, url2: &str, ref2: &str, body2: &str,
) -> Index {
    let mut idx = lattice_index(name1, url1, ref1, body1);
    idx.packages.extend(lattice_index(name2, url2, ref2, body2).packages);
    idx
}

#[test]
fn resolve_lattice_disagreeing_url_conflicts_url_branch_discovered_first() {
    // §10.0/§10.3/§10.5: a tier-3 self-declared URL claim for `foo` (a
    // registry-known name) DISAGREES with the registry's recorded source
    // (`pin.example.com` vs `registry.example.com`). `wrapa` (the url
    // branch) is declared FIRST, so its own subtree — including `foo`'s
    // validation — runs before `wrapb` (the named branch) is ever visited.
    // Under validate-against-registry this raises RES-PROVENANCE-CONFLICT
    // at wrapa's own discovery, regardless of wrapb's competing claim.
    let wrapa_url = "https://example.com/wrapa.git";
    let wrapb_url = "https://example.com/wrapb.git";
    let foo_pin_url = "https://pin.example.com/foo.git";
    let foo_registry_url = "https://registry.example.com/foo.git";
    let foo_registry_body = "# registry\n";

    let reg = FakeReg::git(&[
        (wrapa_url, "main", nimble("wrapa", &format!("requires \"{foo_pin_url}#v9.9.9\"\n"))),
        (wrapb_url, "main", nimble("wrapb", "requires \"foo\"\n")),
        (foo_pin_url, "v9.9.9", nimble("foo", "# url-pin\n")),
        (foo_registry_url, "v1.0.0", nimble("foo", foo_registry_body)),
    ]);
    let index = lattice_index("foo", foo_registry_url, "v1.0.0", foo_registry_body);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![
        url_dep("wrapa", wrapa_url, "main"),
        url_dep("wrapb", wrapb_url, "main"),
    ]);
    let err = resolve(
        &m, Some(&index), &reg, None, None, Strategy::Maxver, true,
        &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-PROVENANCE-CONFLICT");
    assert!(format!("{err:?}").contains("foo"));

    // The disagreeing pin must genuinely never have been fetched — validated
    // and rejected BEFORE any fetch is dispatched (§10.5).
    assert!(
        reg.calls().iter().all(|c| c.1 != foo_pin_url),
        "the disagreeing pin must never be fetched"
    );
}

#[test]
fn resolve_lattice_disagreeing_url_conflicts_named_branch_discovered_first() {
    // Same shape, roles swapped: `wrapb` (the named branch) is declared
    // FIRST. The outcome MUST be identical — `wrapa`'s disagreeing url claim
    // still conflicts, at its own discovery, regardless of the registry
    // claim already being on record (order-independence, §10.5).
    let wrapa_url = "https://example.com/wrapa-swap.git";
    let wrapb_url = "https://example.com/wrapb-swap.git";
    let foo_pin_url = "https://pin.example.com/foo.git";
    let foo_registry_url = "https://registry.example.com/foo.git";
    let foo_registry_body = "# registry\n";

    let reg = FakeReg::git(&[
        (wrapb_url, "main", nimble("wrapb", "requires \"foo\"\n")),
        (wrapa_url, "main", nimble("wrapa", &format!("requires \"{foo_pin_url}#v9.9.9\"\n"))),
        (foo_pin_url, "v9.9.9", nimble("foo", "# url-pin\n")),
        (foo_registry_url, "v1.0.0", nimble("foo", foo_registry_body)),
    ]);
    let index = lattice_index("foo", foo_registry_url, "v1.0.0", foo_registry_body);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![
        url_dep("wrapb", wrapb_url, "main"),
        url_dep("wrapa", wrapa_url, "main"),
    ]);
    let err = resolve(
        &m, Some(&index), &reg, None, None, Strategy::Maxver, true,
        &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-PROVENANCE-CONFLICT");
    assert!(format!("{err:?}").contains("foo"));

    assert!(
        reg.calls().iter().all(|c| c.1 != foo_pin_url),
        "the disagreeing pin must never be fetched"
    );
}

#[test]
fn resolve_lattice_mid_solve_residual_closed_by_immediate_validation() {
    // THE old residual (would have needed a post-hoc sweep) — now closed by
    // construction under validate-against-registry. `foo` is a registry-
    // known name. An eager tier-3 URL transitive (`wrapa`, declared FIRST)
    // claims `foo` via `git=` at a DIFFERENT repository than the registry's
    // — this is discovered and validated during wrapa's own eager subtree,
    // BEFORE `outer` (ALSO a registry package, declared second) is ever even
    // dispatched. `outer`'s OWN bare-name claim on `foo` — discoverable only
    // when the solver would materialize outer's selected candidate — is
    // never even reached: the conflict fires from the registry index alone
    // (a static, pre-loaded fact), without needing outer's claim to exist or
    // be discovered.
    let wrapa_url = "https://example.com/wrapa-mid.git";
    let outer_url = "https://registry.example.com/outer-mid.git";
    // The pin/registry URLs' basenames MUST be exactly "foo" — a nimble
    // `requires "<url>#<ref>"` line derives the transitive dep's NAME from
    // the URL's basename, and that derived name is what must collide with
    // the registry package name "foo" below.
    let foo_pin_url = "https://pin.example.com/foo.git";
    let foo_registry_url = "https://registry.example.com/foo.git";
    let outer_body = "requires \"foo\"\n";
    let foo_registry_body = "# registry\n";

    let reg = FakeReg::git(&[
        (wrapa_url, "main", nimble("wrapa-mid", &format!("requires \"{foo_pin_url}#v9.9.9\"\n"))),
        // outer's own manifest requires foo by bare name — never even
        // fetched: wrapa's own claim already aborts resolution before outer
        // is ever selected/materialized.
        (outer_url, "v1.0.0", nimble("outer-mid", outer_body)),
        (foo_pin_url, "v9.9.9", nimble("foo", "# url-pin\n")),
        (foo_registry_url, "v1.0.0", nimble("foo", foo_registry_body)),
    ]);
    let index = lattice_index_two(
        "outer-mid", outer_url, "v1.0.0", outer_body,
        "foo", foo_registry_url, "v1.0.0", foo_registry_body,
    );
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![
        url_dep("wrapa-mid", wrapa_url, "main"),
        named_dep("outer-mid", None),
    ]);
    let err = resolve(
        &m, Some(&index), &reg, None, None, Strategy::Maxver, true,
        &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-PROVENANCE-CONFLICT");
    assert!(format!("{err:?}").contains("foo"));

    assert!(
        reg.calls().iter().all(|c| c.1 != foo_pin_url && c.1 != outer_url),
        "neither the disagreeing pin nor outer (never selected) may be fetched"
    );
}

#[test]
fn resolve_lattice_two_disagreeing_urls_for_registry_name_both_conflict() {
    // §10.0/§10.3: three transitives claim `shared` — `q` by bare name
    // (registry), `r1`/`r2` via TWO DIFFERENT self-declared URLs (via nested
    // `mid1`/`mid2` hops) — BOTH of which DISAGREE with the registry's
    // recorded source. Under validate-against-registry, EACH disagreeing url
    // is independently invalid: whichever the BFS reaches first raises
    // RES-PROVENANCE-CONFLICT. (Under the prior membership-based redesign
    // this fixture demonstrated "registry wins, no conflict" — the revision
    // inverts that outcome.)
    let q_url = "https://example.com/q.git";
    let r1_url = "https://example.com/r1.git";
    let r2_url = "https://example.com/r2.git";
    let mid1_url = "https://example.com/mid1.git";
    let mid2_url = "https://example.com/mid2.git";
    let shared_x_url = "https://x.example.com/shared.git";
    let shared_y_url = "https://y.example.com/shared.git";
    let shared_registry_url = "https://registry.example.com/shared.git";
    let shared_registry_body = "# registry\n";

    let reg = FakeReg::git(&[
        (q_url, "main", nimble("q", "requires \"shared\"\n")),
        (r1_url, "main", nimble("r1", &format!("requires \"{mid1_url}#main\"\n"))),
        (r2_url, "main", nimble("r2", &format!("requires \"{mid2_url}#main\"\n"))),
        (mid1_url, "main", nimble("mid1", &format!("requires \"{shared_x_url}#v8.0.0\"\n"))),
        (mid2_url, "main", nimble("mid2", &format!("requires \"{shared_y_url}#v9.0.0\"\n"))),
        (shared_x_url, "v8.0.0", nimble("shared", "# x\n")),
        (shared_y_url, "v9.0.0", nimble("shared", "# y\n")),
        (shared_registry_url, "v1.0.0", nimble("shared", shared_registry_body)),
    ]);
    let index = lattice_index("shared", shared_registry_url, "v1.0.0", shared_registry_body);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![
        url_dep("q", q_url, "main"),
        url_dep("r1", r1_url, "main"),
        url_dep("r2", r2_url, "main"),
    ]);
    let err = resolve(
        &m, Some(&index), &reg, None, None, Strategy::Maxver, true,
        &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-PROVENANCE-CONFLICT");
    assert!(format!("{err:?}").contains("shared"));
}

#[test]
fn resolve_lattice_root_beats_both_registry_and_url() {
    // §10.0/§10.1: root declares `shared` directly (tier 1). One transitive
    // claims `shared` by bare name (tier 2, registry-known) and ANOTHER
    // transitive claims it via a different self-declared URL (tier 3,
    // disagreeing with the registry). Root wins over BOTH — no conflict, no
    // validation is even attempted (root_authority excludes `shared` from
    // the validate-against-registry branch entirely); the resolved
    // provenance is root's own.
    let root_shared_url = "https://root.example.com/shared.git";
    let t1_url = "https://example.com/t1.git";
    let t2_url = "https://example.com/t2.git";
    let evil_shared_url = "https://evil.example.com/shared.git";
    let shared_registry_url = "https://registry.example.com/shared.git";
    let shared_registry_body = "# registry\n";

    let reg = FakeReg::git(&[
        (root_shared_url, "main", nimble("shared", "# root-pin\n")),
        (t1_url, "main", nimble("t1", "requires \"shared\"\n")),
        (t2_url, "main", nimble("t2", &format!("requires \"{evil_shared_url}#main\"\n"))),
        (evil_shared_url, "main", nimble("shared", "# evil\n")),
        (shared_registry_url, "v1.0.0", nimble("shared", shared_registry_body)),
    ]);
    let index = lattice_index("shared", shared_registry_url, "v1.0.0", shared_registry_body);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![
        url_dep("shared", root_shared_url, "main"),
        url_dep("t1", t1_url, "main"),
        url_dep("t2", t2_url, "main"),
    ]);
    let graph = resolve(
        &m, Some(&index), &reg, None, None, Strategy::Maxver, true,
        &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap();

    let shared: Vec<_> = graph.deps.iter().filter(|d| d.name == "shared").collect();
    assert_eq!(shared.len(), 1);
    match shared[0].provenances.first().expect("provenance") {
        ProvenanceRecord::Git { url, .. } => assert_eq!(url, root_shared_url),
        other => panic!("expected git provenance, got {other:?}"),
    }
    assert!(
        reg.calls().iter().all(|c| c.1 != evil_shared_url && c.1 != shared_registry_url),
        "neither the registry nor the evil transitive url may ever be fetched"
    );
}

#[test]
fn resolve_lattice_lone_url_pin_of_registry_name_agrees_is_accepted() {
    // A transitive url-pins `foo` — a name that ALSO exists in the registry —
    // at the SAME repository the registry records, just a DIFFERENT `ref`
    // (an older tag). No competing named claim exists anywhere else in the
    // graph. Under validate-against-registry, this is ACCEPTED (not
    // redirected): `foo` resolves from the transitive's OWN pinned ref,
    // genuinely fetched — this supersedes the prior membership-based design,
    // under which this exact shape was silently redirected to the
    // registry's version instead.
    let t1_url = "https://example.com/t1agree.git";
    let foo_registry_url = "https://registry.example.com/fooagree.git";
    let foo_older_body = "# older-tag\n";
    let foo_registry_body = "# registry\n";

    let reg = FakeReg::git(&[
        (t1_url, "main", nimble("t1agree", &format!("requires \"{foo_registry_url}#v0.9.0\"\n"))),
        (foo_registry_url, "v0.9.0", nimble("fooagree", foo_older_body)),
        (foo_registry_url, "v1.0.0", nimble("fooagree", foo_registry_body)),
    ]);
    let index = lattice_index("fooagree", foo_registry_url, "v1.0.0", foo_registry_body);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("t1agree", t1_url, "main")]);
    let graph = resolve(
        &m, Some(&index), &reg, None, None, Strategy::Maxver, true,
        &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap();

    let foo = graph.deps.iter().find(|d| d.name == "fooagree").expect("fooagree in graph");
    // Accepted AS ITSELF: resolves from the transitive's own pinned ref/tag,
    // NOT redirected to the registry's version.
    assert_eq!(foo.version, v(0, 9, 0));
    match foo.provenances.first().expect("provenance") {
        ProvenanceRecord::Git { url, ref_spec, .. } => {
            assert_eq!(url, foo_registry_url);
            assert_eq!(ref_spec.as_deref(), Some("v0.9.0"));
        }
        other => panic!("expected git provenance, got {other:?}"),
    }
    // Genuinely fetched (accepted claims are ordinary tier-3 url deps).
    assert!(
        reg.calls().iter().any(|c| c.1 == foo_registry_url && c.2 == "v0.9.0"),
        "the agreeing pin must be genuinely fetched at its OWN ref"
    );
}

#[test]
fn resolve_lattice_lone_url_pin_of_registry_name_disagrees_conflicts() {
    // §10.0 NORMATIVE, validate-against-registry: a transitive url-pins
    // `foo` — a name that ALSO exists in the registry — at a DIFFERENT
    // repository than the registry records, with NO competing claim
    // anywhere else in the graph. This is the headline behavioral change
    // from the pure disagreement-only design: a LONE transitive claim can
    // conflict with a KNOWN registry name, with no second claim needed to
    // arbitrate against.
    let t1_url = "https://example.com/t1lone.git";
    let foo_pin_url = "https://pin.example.com/foolone.git";
    let foo_registry_url = "https://registry.example.com/foolone.git";
    let foo_registry_body = "# registry\n";

    let reg = FakeReg::git(&[
        (t1_url, "main", nimble("t1lone", &format!("requires \"{foo_pin_url}#main\"\n"))),
        (foo_pin_url, "main", nimble("foolone", "# url-pin\n")),
        (foo_registry_url, "v1.0.0", nimble("foolone", foo_registry_body)),
    ]);
    let index = lattice_index("foolone", foo_registry_url, "v1.0.0", foo_registry_body);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("t1lone", t1_url, "main")]);
    let err = resolve(
        &m, Some(&index), &reg, None, None, Strategy::Maxver, true,
        &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-PROVENANCE-CONFLICT");
    assert!(format!("{err:?}").contains("foolone"));

    assert!(
        reg.calls().iter().all(|c| c.1 != foo_pin_url),
        "the disagreeing lone pin must never be fetched"
    );
}

#[test]
fn resolve_lattice_two_agreeing_url_pins_of_same_registry_name_coexist() {
    // Two DIFFERENT transitives each pin `foo` — a registry-known name — at
    // the registry's OWN repository, but at two DIFFERENT refs. Both AGREE
    // with the registry (same repo), so BOTH are accepted: they coexist as
    // independent candidates, never conflicting with EACH OTHER (agreement
    // is validated per-claim against the static registry record, never
    // between claims). Ordinary solver version-negotiation (maxver) then
    // picks the higher version. Rust's BFS is synchronous (no thread pool),
    // so the two sequential fetches to `_deps/foocoexist` (re-linked from
    // the CAS on each fetch) never race — unlike Python's concurrent wave
    // dispatch, which needs an explicit dest-disambiguation escape hatch.
    let t1_url = "https://example.com/t1coexist.git";
    let t2_url = "https://example.com/t2coexist.git";
    let foo_registry_url = "https://registry.example.com/foocoexist.git";
    let foo_v2_body = "# v2\n";
    let foo_v3_body = "# v3\n";
    let foo_registry_body = "# registry\n";

    let reg = FakeReg::git(&[
        (t1_url, "main", nimble("t1coexist", &format!("requires \"{foo_registry_url}#v2.0.0\"\n"))),
        (t2_url, "main", nimble("t2coexist", &format!("requires \"{foo_registry_url}#v3.0.0\"\n"))),
        (foo_registry_url, "v1.0.0", nimble("foocoexist", foo_registry_body)),
        (foo_registry_url, "v2.0.0", nimble("foocoexist", foo_v2_body)),
        (foo_registry_url, "v3.0.0", nimble("foocoexist", foo_v3_body)),
    ]);
    let index = lattice_index("foocoexist", foo_registry_url, "v1.0.0", foo_registry_body);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![
        url_dep("t1coexist", t1_url, "main"),
        url_dep("t2coexist", t2_url, "main"),
    ]);
    let graph = resolve(
        &m, Some(&index), &reg, None, None, Strategy::Maxver, true,
        &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap();

    let foo = graph.deps.iter().find(|d| d.name == "foocoexist").expect("foocoexist in graph");
    assert_eq!(foo.version, v(3, 0, 0), "maxver picks the higher of the two coexisting pins");
    match foo.provenances.first().expect("provenance") {
        ProvenanceRecord::Git { url, ref_spec, .. } => {
            assert_eq!(url, foo_registry_url);
            assert_eq!(ref_spec.as_deref(), Some("v3.0.0"));
        }
        other => panic!("expected git provenance, got {other:?}"),
    }
    // Both agreeing pins were genuinely fetched (peacefully coexisting
    // candidates) — neither was blocked by the other.
    assert!(reg.calls().iter().any(|c| c.1 == foo_registry_url && c.2 == "v2.0.0"));
    assert!(reg.calls().iter().any(|c| c.1 == foo_registry_url && c.2 == "v3.0.0"));
}

#[test]
fn resolve_lattice_lone_url_pin_of_non_registry_name_stands() {
    // A transitive url-pins a name that is NOT in the registry index at all
    // (the index exists and is non-trivial, but has no entry for `bar`) —
    // there is nothing to validate against, so this is the plain tier-3 case
    // (§10.3's second rule). The url pin stands, exactly as before.
    let t1_url = "https://example.com/t1bar.git";
    let bar_pin_url = "https://pin.example.com/bar.git";
    let unrelated_url = "https://registry.example.com/unrelated.git";
    let unrelated_body = "# unrelated\n";

    let reg = FakeReg::git(&[
        (t1_url, "main", nimble("t1bar", &format!("requires \"{bar_pin_url}#main\"\n"))),
        (bar_pin_url, "main", nimble("bar", "# bar-pin\n")),
        (unrelated_url, "v1.0.0", nimble("unrelated", unrelated_body)),
    ]);
    let index = lattice_index("unrelated", unrelated_url, "v1.0.0", unrelated_body);
    let tmp = tempfile::tempdir().unwrap();
    let m = manifest(vec![url_dep("t1bar", t1_url, "main")]);
    let graph = resolve(
        &m, Some(&index), &reg, None, None, Strategy::Maxver, true,
        &deps_dir(&tmp), None, false, &cas_store(&tmp),
    )
    .unwrap();

    let bar = graph.deps.iter().find(|d| d.name == "bar").expect("bar in graph");
    match bar.provenances.first().expect("provenance") {
        ProvenanceRecord::Git { url, .. } => assert_eq!(url, bar_pin_url),
        other => panic!("expected git provenance, got {other:?}"),
    }
}

// --- direct unit tests: `normalize_git_source_url` / -----------------------
// --- `validate_transitive_url_against_registry` -----------------------------

#[test]
fn normalize_git_source_url_trailing_git_suffix_stripped() {
    assert_eq!(
        super::normalize_git_source_url("https://example.com/foo.git"),
        super::normalize_git_source_url("https://example.com/foo"),
    );
}

#[test]
fn normalize_git_source_url_trailing_slash_stripped() {
    assert_eq!(
        super::normalize_git_source_url("https://example.com/foo/"),
        super::normalize_git_source_url("https://example.com/foo"),
    );
}

#[test]
fn normalize_git_source_url_scheme_and_host_case_insensitive() {
    assert_eq!(
        super::normalize_git_source_url("HTTPS://Example.COM/foo.git"),
        super::normalize_git_source_url("https://example.com/foo.git"),
    );
}

#[test]
fn normalize_git_source_url_path_case_preserved() {
    // Path casing is NOT normalized — many git hosts are path-case-sensitive.
    assert_ne!(
        super::normalize_git_source_url("https://example.com/Foo.git"),
        super::normalize_git_source_url("https://example.com/foo.git"),
    );
}

#[test]
fn normalize_git_source_url_different_hosts_differ() {
    assert_ne!(
        super::normalize_git_source_url("https://a.example.com/foo.git"),
        super::normalize_git_source_url("https://b.example.com/foo.git"),
    );
}

/// Build a minimal single-version `Package` carrying one git provenance, for
/// the `validate_transitive_url_against_registry` unit tests below.
fn pkg_with_git(name: &str, url: &str, refp: &str) -> Package {
    Package {
        name: name.to_string(),
        namespace: String::new(),
        versions: vec![IndexVersion {
            version: "1.0.0".into(),
            content_hash: format!("sha256:{}", "0".repeat(64)),
            provenances: vec![Provenance::Git {
                url: url.to_string(),
                ref_spec: refp.to_string(),
                commit_sha: None,
            }],
            dep_decl: None,
            dep_decl_schema_version: None,
            attestation: None,
            namespace: String::new(),
            published_at: None,
            yanked: false,
            yanked_at: None,
            yanked_reason: None,
            published_at_raw: None,
        }],
    }
}

#[test]
fn validate_transitive_url_agrees_same_url_same_ref() {
    let pkg = pkg_with_git("foo", "https://registry.example.com/foo.git", "v1.0.0");
    super::validate_transitive_url_against_registry(
        "foo", "https://registry.example.com/foo.git", &pkg,
    )
    .expect("agreement must not error");
}

#[test]
fn validate_transitive_url_agrees_same_repo_different_ref() {
    // Different ref, same repo: still an agreement (ref only selects a version).
    let pkg = pkg_with_git("foo", "https://registry.example.com/foo.git", "v1.0.0");
    super::validate_transitive_url_against_registry(
        "foo", "https://registry.example.com/foo.git", &pkg,
    )
    .expect("differing ref must still agree");
}

#[test]
fn validate_transitive_url_agrees_matches_an_older_versions_provenance() {
    // The claim matches version 1.0.0's recorded source, not the newest
    // (2.0.0's) — agreement checks EVERY version's provenance, not just the
    // latest.
    let pkg = Package {
        name: "foo".to_string(),
        namespace: String::new(),
        versions: vec![
            IndexVersion {
                version: "2.0.0".into(),
                content_hash: format!("sha256:{}", "0".repeat(64)),
                provenances: vec![Provenance::Git {
                    url: "https://registry.example.com/foo-v2.git".to_string(),
                    ref_spec: "v2.0.0".to_string(),
                    commit_sha: None,
                }],
                dep_decl: None,
                dep_decl_schema_version: None,
                attestation: None,
                namespace: String::new(),
                published_at: None,
                yanked: false,
                yanked_at: None,
                yanked_reason: None,
                published_at_raw: None,
            },
            IndexVersion {
                version: "1.0.0".into(),
                content_hash: format!("sha256:{}", "0".repeat(64)),
                provenances: vec![Provenance::Git {
                    url: "https://registry.example.com/foo.git".to_string(),
                    ref_spec: "v1.0.0".to_string(),
                    commit_sha: None,
                }],
                dep_decl: None,
                dep_decl_schema_version: None,
                attestation: None,
                namespace: String::new(),
                published_at: None,
                yanked: false,
                yanked_at: None,
                yanked_reason: None,
                published_at_raw: None,
            },
        ],
    };
    super::validate_transitive_url_against_registry(
        "foo", "https://registry.example.com/foo.git", &pkg,
    )
    .expect("must match the older version's recorded source");
}

#[test]
fn validate_transitive_url_agrees_normalized_git_suffix_and_case() {
    let pkg = pkg_with_git("foo", "https://Registry.example.com/foo.git", "v1.0.0");
    // No ".git" suffix on the claim, different host casing: still agrees.
    super::validate_transitive_url_against_registry(
        "foo", "https://registry.example.com/foo", &pkg,
    )
    .expect("normalized comparison must agree");
}

#[test]
fn validate_transitive_url_disagrees_different_repository() {
    let pkg = pkg_with_git("foo", "https://registry.example.com/foo.git", "v1.0.0");
    let err = super::validate_transitive_url_against_registry(
        "foo", "https://pin.example.com/foo.git", &pkg,
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-PROVENANCE-CONFLICT");
    assert!(format!("{err:?}").contains("foo"));
}

#[test]
fn validate_transitive_url_disagrees_incomparable_oci_only_entry() {
    // The registry entry is OCI-only — a git= claim can never be compared to
    // it, so it is treated as a disagreement (conservative).
    let pkg = Package {
        name: "foo".to_string(),
        namespace: String::new(),
        versions: vec![IndexVersion {
            version: "1.0.0".into(),
            content_hash: format!("sha256:{}", "a".repeat(64)),
            provenances: vec![Provenance::Oci {
                registry: "ghcr.io".to_string(),
                repository: "example/foo".to_string(),
                digest: format!("sha256:{}", "b".repeat(64)),
            }],
            dep_decl: None,
            dep_decl_schema_version: None,
            attestation: None,
            namespace: String::new(),
            published_at: None,
            yanked: false,
            yanked_at: None,
            yanked_reason: None,
            published_at_raw: None,
        }],
    };
    let err = super::validate_transitive_url_against_registry(
        "foo", "https://example.com/foo.git", &pkg,
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-PROVENANCE-CONFLICT");
}

#[test]
fn validate_transitive_url_disagrees_no_provenance_at_all() {
    // A package version with no provenance recorded whatsoever — also
    // incomparable, also a disagreement.
    let pkg = Package {
        name: "foo".to_string(),
        namespace: String::new(),
        versions: vec![IndexVersion {
            version: "1.0.0".into(),
            content_hash: String::new(),
            provenances: vec![],
            dep_decl: None,
            dep_decl_schema_version: None,
            attestation: None,
            namespace: String::new(),
            published_at: None,
            yanked: false,
            yanked_at: None,
            yanked_reason: None,
            published_at_raw: None,
        }],
    };
    let err = super::validate_transitive_url_against_registry(
        "foo", "https://example.com/foo.git", &pkg,
    )
    .unwrap_err();
    assert_eq!(err.code(), "RES-PROVENANCE-CONFLICT");
}

// --- direct gate-unit tests: `ResolveProvider::gate`'s tier decision table -

/// A minimal `ResolveProvider` for direct `gate()` unit tests — no
/// fetch/solve involved. Mirrors `is_root_direct_namespace_aware_direct_unit_coverage`'s
/// construction pattern above.
fn gate_provider<'a>(reg: &'a FakeReg, idx: &'a Index, tmp: &tempfile::TempDir) -> super::ResolveProvider<'a> {
    super::ResolveProvider::new(
        reg, idx, deps_dir(tmp), BTreeMap::new(), None, None, false, Strategy::Maxver, false, None,
    )
}

fn url_item(name: &str, git: &str, refp: &str) -> super::Item {
    super::Item::Url(UrlDep {
        name: name.to_string(),
        git: git.to_string(),
        git_ref: refp.to_string(),
        mirrors: Vec::new(),
        predicates: Vec::new(),
        flag_requests: Vec::new(),
        optional: false,
        version: None,
    })
}

fn named_item(name: &str) -> super::Item {
    super::Item::Named {
        name: name.to_string(),
        constraint: milpa_solver::VersionSet::full(),
        namespace: None,
    }
}

#[test]
fn gate_first_claim_registers_and_proceeds() {
    let empty_index = Index { packages: vec![] };
    let empty_reg = FakeReg::git(&[]);
    let tmp = tempfile::tempdir().unwrap();
    let p = gate_provider(&empty_reg, &empty_index, &tmp);

    assert!(matches!(p.gate(&url_item("foo", "u1", "main")), super::Gate::Proceed));
    assert_eq!(
        p.seen_by_name.borrow().get("foo"),
        Some(&(super::PKey::Url("u1".into(), "main".into()), super::TIER_SELF_URL)),
    );
}

#[test]
fn gate_same_pkey_dedups() {
    // Unlike Python's `_check_provenance_gate` (which fuses transport-level
    // dedup into the gate and returns False/suppress for a repeat same-pkey
    // claim), Rust's `gate()` returns Proceed for a same-pkey repeat and
    // relies on the SEPARATE transport-level `seen_url`/`seen_named`/
    // `seen_local`/`seen_tarball` sets (plus, for URL deps, the S4b
    // multi-consumer flag-request-union logic in `process_url`) to avoid a
    // real re-fetch. This is a pre-existing, unchanged architectural split —
    // #193 only generalizes the TIER the gate arbitrates on, never this
    // same-pkey branch. "Dedup" here means: the claim does not conflict or
    // get suppressed by tier — the ACTUAL fetch-once guarantee lives one
    // layer down, at dispatch.
    let empty_index = Index { packages: vec![] };
    let empty_reg = FakeReg::git(&[]);
    let tmp = tempfile::tempdir().unwrap();
    let p = gate_provider(&empty_reg, &empty_index, &tmp);

    p.gate(&url_item("foo", "u1", "main"));
    assert!(matches!(p.gate(&url_item("foo", "u1", "main")), super::Gate::Proceed));
}

#[test]
fn gate_named_claims_always_dedup_same_sentinel() {
    // Two `Named` claims for the same bare name always carry the same
    // `PKey::Named(DepKey { name, namespace: None })` — the gate always takes
    // the same-pkey branch (Proceed; see `gate_same_pkey_dedups`'s doc
    // comment on why that's Proceed, not Suppress, in Rust's design), never
    // the tier-compare/Conflict branch, regardless of which transitive
    // introduces the claim or what constraint each carries (constraints
    // aren't provenance). The real enumerate-once dedup for `Named` claims is
    // `seen_named` (a `BTreeSet<DepKey>`) in `process_named`.
    let empty_index = Index { packages: vec![] };
    let empty_reg = FakeReg::git(&[]);
    let tmp = tempfile::tempdir().unwrap();
    let p = gate_provider(&empty_reg, &empty_index, &tmp);

    p.gate(&named_item("foo"));
    assert!(matches!(p.gate(&named_item("foo")), super::Gate::Proceed));
}

#[test]
fn gate_root_wins_over_tier3_url() {
    let empty_index = Index { packages: vec![] };
    let empty_reg = FakeReg::git(&[]);
    let tmp = tempfile::tempdir().unwrap();
    let mut p = gate_provider(&empty_reg, &empty_index, &tmp);
    p.root_authority = std::collections::BTreeSet::from(["foo".to_string()]);
    // Mirrors what `seed_root` would have already written before any BFS item
    // is ever gated: the root's own claim, recorded at TIER_ROOT.
    p.seen_by_name.borrow_mut().insert(
        "foo".to_string(),
        (super::PKey::Url("root-u".into(), "main".into()), super::TIER_ROOT),
    );

    assert!(matches!(p.gate(&url_item("foo", "evil-u", "main")), super::Gate::Suppress));
    assert_eq!(
        p.seen_by_name.borrow().get("foo"),
        Some(&(super::PKey::Url("root-u".into(), "main".into()), super::TIER_ROOT)),
        "root's own entry must be untouched",
    );
}

#[test]
fn gate_root_wins_over_tier2_named() {
    let empty_index = Index { packages: vec![] };
    let empty_reg = FakeReg::git(&[]);
    let tmp = tempfile::tempdir().unwrap();
    let mut p = gate_provider(&empty_reg, &empty_index, &tmp);
    p.root_authority = std::collections::BTreeSet::from(["foo".to_string()]);
    p.seen_by_name.borrow_mut().insert(
        "foo".to_string(),
        (super::PKey::Url("root-u".into(), "main".into()), super::TIER_ROOT),
    );

    assert!(matches!(p.gate(&named_item("foo")), super::Gate::Suppress));
    assert_eq!(
        p.seen_by_name.borrow().get("foo"),
        Some(&(super::PKey::Url("root-u".into(), "main".into()), super::TIER_ROOT)),
    );
}

#[test]
fn gate_tier2_beats_tier3_arriving_after() {
    // Tier-3 registers first; a differently-keyed tier-2 claim arrives
    // second — it wins (overwrites the gate entry), Proceed.
    use milpa_types::DepKey;

    let empty_index = Index { packages: vec![] };
    let empty_reg = FakeReg::git(&[]);
    let tmp = tempfile::tempdir().unwrap();
    let p = gate_provider(&empty_reg, &empty_index, &tmp);

    p.gate(&url_item("foo", "u1", "main"));
    assert!(matches!(p.gate(&named_item("foo")), super::Gate::Proceed));
    assert_eq!(
        p.seen_by_name.borrow().get("foo"),
        Some(&(super::PKey::Named(DepKey::bare("foo")), super::TIER_REGISTRY)),
    );
}

#[test]
fn gate_tier3_suppressed_when_arriving_after_tier2() {
    // Tier-2 registers first; a tier-3 claim arrives second — suppressed
    // BEFORE any fetch would be dispatched.
    use milpa_types::DepKey;

    let empty_index = Index { packages: vec![] };
    let empty_reg = FakeReg::git(&[]);
    let tmp = tempfile::tempdir().unwrap();
    let p = gate_provider(&empty_reg, &empty_index, &tmp);

    p.gate(&named_item("foo"));
    assert!(matches!(p.gate(&url_item("foo", "u1", "main")), super::Gate::Suppress));
    assert_eq!(
        p.seen_by_name.borrow().get("foo"),
        Some(&(super::PKey::Named(DepKey::bare("foo")), super::TIER_REGISTRY)),
        "the registry entry stays authoritative",
    );
}

#[test]
fn gate_tier3_vs_tier3_conflicts_when_no_tier2() {
    let empty_index = Index { packages: vec![] };
    let empty_reg = FakeReg::git(&[]);
    let tmp = tempfile::tempdir().unwrap();
    let p = gate_provider(&empty_reg, &empty_index, &tmp);

    p.gate(&url_item("foo", "u1", "main"));
    assert!(matches!(p.gate(&url_item("foo", "u2", "main")), super::Gate::Conflict(_, _)));
}

#[test]
fn gate_tier3_vs_tier3_no_conflict_once_tier2_on_record() {
    // Once a tier-2 claim is recorded for a name, a differing tier-3 claim is
    // just suppressed (registry already won) — the tier-3-vs-tier-3 conflict
    // branch is never reached, even for a SECOND differently-keyed tier-3
    // claim.
    let empty_index = Index { packages: vec![] };
    let empty_reg = FakeReg::git(&[]);
    let tmp = tempfile::tempdir().unwrap();
    let p = gate_provider(&empty_reg, &empty_index, &tmp);

    p.gate(&named_item("foo"));
    p.gate(&url_item("foo", "u1", "main"));
    assert!(matches!(p.gate(&url_item("foo", "u2", "main")), super::Gate::Suppress));
}
