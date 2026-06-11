//! The diff/normalization engine (conformance-fixtures.md §5) and the
//! implementation-under-test seam ([`Target`]).
//!
//! [`run_fixture`] is the whole contract in one place: build a scratch project,
//! ask the [`Target`] to produce outputs (or an error code), then either assert
//! the error slug (`expected/error`) or byte-diff `milpa.lock` / `nim.cfg` /
//! `_deps_structure.txt` against `expected/`. It is `Target`-generic so the same
//! engine is proven by the synthetic stub (S2) and applied to the real
//! [`MilpaTarget`] over the corpus.

use std::path::{Path, PathBuf};

use crate::fixture::{Cmd, Expected, Fixture};

/// A per-fixture scratch project: a sandbox `_deps/` and content-addressed store
/// the `Target` materializes into. The caller supplies the root (tests use a
/// `tempfile::TempDir`); this lays out the standard subdirectories.
pub struct Scratch {
    pub root: PathBuf,
    pub deps_dir: PathBuf,
    pub cas_root: PathBuf,
}

impl Scratch {
    /// Lay out `_deps/` and `.cas/` under `root`.
    pub fn new(root: &Path) -> std::io::Result<Self> {
        let deps_dir = root.join("_deps");
        let cas_root = root.join(".cas");
        std::fs::create_dir_all(&deps_dir)?;
        std::fs::create_dir_all(&cas_root)?;
        Ok(Scratch {
            root: root.to_path_buf(),
            deps_dir,
            cas_root,
        })
    }
}

/// The byte-diffable outputs of a success run. `_deps_structure.txt` is *not*
/// here — the harness reads it from the materialized `_deps/` on disk so it
/// exercises the real symlink-resolution + `<CAS_ROOT>` normalization (§2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outputs {
    pub lock_text: String,
    pub nimcfg_text: String,
}

/// What a `Target` produced for a non-error run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Produced {
    /// A success run with byte-diffable outputs (the single-package
    /// `resolve`/`frozen` path).
    Outputs(Outputs),
    /// A workspace success run: a shared `milpa.lock` + one `nim.cfg` per member
    /// (keyed by the member's workspace-relative path). There is no root
    /// `nim.cfg` (lockfile §7.6 / P1).
    WorkspaceOutputs {
        lock_text: String,
        member_nimcfgs: Vec<(String, String)>,
    },
    /// A `cmd=parse-lockfile` run that did not error. The spec defines no
    /// success variant for `parse-lockfile` (§2.7), so a fixture reaching this
    /// is an authoring error, surfaced as a failure by `run_fixture`.
    NoByteDiff,
}

/// The implementation under test. The `Err` payload is the error **code**
/// (`spec/errors.md` slug) — the only thing the harness compares for error
/// fixtures (§3.1); message text is never checked.
pub trait Target {
    fn execute(&self, fx: &Fixture, scratch: &Scratch) -> Result<Produced, String>;
}

/// The outcome of running one fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail(String),
    /// Not assertable by the in-process library Target (a CLI-only verb fixture
    /// — §2.7.1/§2.7.2). Driven by the black-box CLI harness instead.
    Skip(String),
}

impl Verdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass)
    }
}

/// Run one fixture against `target` in `scratch` and return the verdict.
pub fn run_fixture(fx: &Fixture, target: &dyn Target, scratch: &Scratch) -> Verdict {
    // CLI-only fixtures (mutation/liveness verbs) are not modeled by the
    // in-process library Target; they are covered by the black-box CLI harness.
    if fx.cmd == Cmd::CliOnly {
        return Verdict::Skip(
            "CLI-only verb fixture (add/remove/update/show/--version); \
             covered by the black-box CLI harness, not the in-process runner"
                .to_string(),
        );
    }

    let produced = target.execute(fx, scratch);

    match (&fx.expected, produced) {
        // Error fixture: the raised code must equal the expected slug.
        (Expected::Error(slug), Err(code)) => {
            if &code == slug {
                Verdict::Pass
            } else {
                Verdict::Fail(format!("expected error {slug:?}, got {code:?}"))
            }
        }
        (Expected::Error(slug), Ok(_)) => {
            Verdict::Fail(format!("expected error {slug:?} but the run succeeded"))
        }

        // Success fixture: byte-diff the three outputs.
        (Expected::Success, Err(code)) => {
            Verdict::Fail(format!("expected success but errored with {code:?}"))
        }
        (Expected::Success, Ok(Produced::NoByteDiff)) => Verdict::Fail(
            "success fixture produced no byte-diff outputs (parse-lockfile has no success variant)"
                .to_string(),
        ),
        (Expected::Success, Ok(Produced::Outputs(out))) => diff_success(fx, scratch, &out),
        (
            Expected::Success,
            Ok(Produced::WorkspaceOutputs {
                lock_text,
                member_nimcfgs,
            }),
        ) => diff_workspace_success(fx, scratch, &lock_text, &member_nimcfgs),
    }
}

/// Byte-diff a workspace success: the shared `milpa.lock`, each member's
/// `expected/<path>/nim.cfg`, and `_deps_structure.txt` (members are not
/// symlinked into `_deps/`, so it reflects only external deps).
fn diff_workspace_success(
    fx: &Fixture,
    scratch: &Scratch,
    lock_text: &str,
    member_nimcfgs: &[(String, String)],
) -> Verdict {
    let expected = fx.dir.join("expected");
    if let Some(fail) = diff_file(&expected.join("milpa.lock"), lock_text, "milpa.lock") {
        return fail;
    }
    for (path, text) in member_nimcfgs {
        let label = format!("{path}/nim.cfg");
        if let Some(fail) = diff_file(&expected.join(path).join("nim.cfg"), text, &label) {
            return fail;
        }
    }
    let got_structure = match read_deps_structure(&scratch.deps_dir, &scratch.cas_root) {
        Ok(s) => s,
        Err(e) => return Verdict::Fail(format!("reading _deps structure: {e}")),
    };
    if let Some(fail) = diff_file(
        &expected.join("_deps_structure.txt"),
        &got_structure,
        "_deps_structure.txt",
    ) {
        return fail;
    }
    Verdict::Pass
}

/// Byte-diff the three success outputs against `expected/`.
fn diff_success(fx: &Fixture, scratch: &Scratch, out: &Outputs) -> Verdict {
    let expected = fx.dir.join("expected");

    if let Some(fail) = diff_file(&expected.join("milpa.lock"), &out.lock_text, "milpa.lock") {
        return fail;
    }
    if let Some(fail) = diff_file(&expected.join("nim.cfg"), &out.nimcfg_text, "nim.cfg") {
        return fail;
    }

    let got_structure = match read_deps_structure(&scratch.deps_dir, &scratch.cas_root) {
        Ok(s) => s,
        Err(e) => return Verdict::Fail(format!("reading _deps structure: {e}")),
    };
    if let Some(fail) = diff_file(
        &expected.join("_deps_structure.txt"),
        &got_structure,
        "_deps_structure.txt",
    ) {
        return fail;
    }

    Verdict::Pass
}

/// Compare `got` against the bytes of `expected_path`; `None` on match.
fn diff_file(expected_path: &Path, got: &str, label: &str) -> Option<Verdict> {
    match std::fs::read_to_string(expected_path) {
        Ok(want) if want == got => None,
        Ok(want) => Some(Verdict::Fail(format!(
            "{label} mismatch:\n--- expected ---\n{want}\n--- actual ---\n{got}"
        ))),
        Err(e) => Some(Verdict::Fail(format!("missing expected/{label}: {e}"))),
    }
}

/// Build the `_deps_structure.txt` body from the materialized `_deps/`
/// (conformance-fixtures.md §2.6). Each `_deps/<name>` symlink is **resolved**
/// (`canonicalize`, not `read_link` — RFC §4.4 TRAP: the on-disk link stays
/// relative, but the structure file records the resolved CAS target), then the
/// canonical CAS-root prefix is replaced with `<CAS_ROOT>`. Lines are sorted by
/// name and the body ends with a trailing newline (empty string if no deps).
pub fn read_deps_structure(deps_dir: &Path, cas_root: &Path) -> std::io::Result<String> {
    if !deps_dir.is_dir() {
        return Ok(String::new());
    }

    // Canonical CAS-root prefix, no trailing separator (§2.6 clause).
    let cas_prefix = std::fs::canonicalize(cas_root)
        .unwrap_or_else(|_| cas_root.to_path_buf())
        .to_string_lossy()
        .into_owned();

    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(deps_dir)? {
        let entry = entry?;
        let path = entry.path();
        if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
            let name = entry.file_name().to_string_lossy().into_owned();
            entries.push((name, path));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut lines = String::new();
    for (name, link) in entries {
        let resolved = std::fs::canonicalize(&link)?;
        let resolved_str = resolved.to_string_lossy();
        let normalized = resolved_str.replace(&cas_prefix, "<CAS_ROOT>");
        lines.push_str(&format!("{name} -> {normalized}/\n"));
    }
    Ok(lines)
}

/// The real implementation under test: delegates to `milpa-core`. Wired
/// **incrementally** — at S2 every path returned a not-wired sentinel; by S11b
/// all three `cmd` paths (parse-lockfile / resolve / frozen, single-package and
/// workspace) delegate to real `milpa-core` calls.
pub struct MilpaTarget;

impl Target for MilpaTarget {
    fn execute(&self, fx: &Fixture, scratch: &Scratch) -> Result<Produced, String> {
        use milpa_core::{FrozenResolver, ManifestDoc, Resolver};

        match fx.cmd {
            // S5a: parse the fixture's `milpa.lock` and surface any LOCK-* code.
            // A clean parse yields no byte-diff outputs (`parse-lockfile` has no
            // success variant, §2.7), so `run_fixture` flags a non-erroring
            // success fixture as an authoring error.
            Cmd::ParseLockfile => {
                let text = std::fs::read_to_string(fx.dir.join("milpa.lock"))
                    .map_err(|e| format!("E2E-LOCKFILE-UNREADABLE: {e}"))?;
                match milpa_core::parse_lockfile(&text) {
                    Ok(_lock) => Ok(Produced::NoByteDiff),
                    Err(e) => Err(e.code().to_string()),
                }
            }
            // The resolve path: parse `milpa.kdl` (MAN-* on malformed), parse the
            // optional `index.kdl` (TNG-* parse validators), then resolve against
            // the `mocked-fetches/` fake. A *valid* resolve falls through to the
            // not-yet-wired tail (S9 nim.cfg + lock emission produce the byte-diff
            // outputs), so success fixtures stay parked until S9; resolve-time
            // error fixtures (TNG-*/RES-*/SOLVE-*) green here.
            Cmd::Resolve => {
                let text = std::fs::read_to_string(fx.dir.join("milpa.kdl"))
                    .map_err(|e| format!("E2E-MANIFEST-UNREADABLE: {e}"))?;
                // Optional tianguis index for named-dep resolution. The parser
                // surfaces TNG-* trust-boundary errors (schema/unsafe/bad-*).
                let index = {
                    let p = fx.dir.join("index.kdl");
                    if p.is_file() {
                        let itext = std::fs::read_to_string(&p)
                            .map_err(|e| format!("E2E-INDEX-UNREADABLE: {e}"))?;
                        match milpa_core::Index::parse(&itext) {
                            Ok(i) => Some(i),
                            Err(e) => return Err(e.code().to_string()),
                        }
                    } else {
                        None
                    }
                };

                // Optional `MILPA_TARGET_*` profile (from the fixture's `env`
                // file) for conditional-dep predicate filtering (§6).
                let profile = fixture_profile(&fx.dir);

                let manifest = match milpa_core::parse_document(&text) {
                    // Workspace: load (WS-* topology) → multi-member union resolve
                    // (RES-WS-*) → shared milpa.lock + per-member nim.cfg.
                    Ok(ManifestDoc::Workspace(_)) => {
                        let loaded = match milpa_core::load_workspace(&fx.dir) {
                            Ok(w) => w,
                            Err(e) => return Err(e.code().to_string()),
                        };
                        let fetcher = crate::fake_fetcher::FakeFetcher::new(
                            fx.dir.join("mocked-fetches"),
                            scratch.cas_root.clone(),
                        );
                        return match milpa_core::resolve_workspace(
                            &loaded,
                            index.as_ref(),
                            &fetcher,
                            profile.as_ref(),
                            None,
                            milpa_core::Strategy::default(),
                            &scratch.deps_dir,
                        ) {
                            Ok(graph) => Ok(Produced::WorkspaceOutputs {
                                lock_text: milpa_core::format_lockfile(&milpa_core::from_graph(
                                    &graph, "maxver",
                                )),
                                member_nimcfgs: milpa_core::format_workspace_nimcfgs(
                                    &loaded, &graph,
                                ),
                            }),
                            Err(e) => Err(e.code().to_string()),
                        };
                    }
                    Ok(ManifestDoc::Package(m)) => m,
                    Err(e) => return Err(e.code().to_string()),
                };

                // The fake fetcher also admits into the scratch CAS and symlinks
                // `_deps/<name>` → the store (the shape `_deps_structure.txt`
                // records), since the resolve trait carries no store parameter.
                let fetcher = crate::fake_fetcher::FakeFetcher::new(
                    fx.dir.join("mocked-fetches"),
                    scratch.cas_root.clone(),
                );
                match milpa_core::Milpa.resolve(
                    &manifest,
                    index.as_ref(),
                    &fetcher,
                    profile.as_ref(),
                    None,
                    &scratch.deps_dir,
                ) {
                    // S9: emit the byte-diff outputs. `_deps_structure.txt` is read
                    // by the harness from the materialized (symlinked) `_deps/`.
                    Ok(graph) => {
                        let lock_text =
                            milpa_core::format_lockfile(&milpa_core::from_graph(&graph, "maxver"));
                        let nimcfg_text =
                            milpa_core::format_nimcfg(&graph, "_deps", &manifest.src_dir);
                        Ok(Produced::Outputs(Outputs {
                            lock_text,
                            nimcfg_text,
                        }))
                    }
                    Err(e) => Err(e.code().to_string()),
                }
            }
            // The frozen path: parse milpa.kdl + milpa.lock, seed the CAS from
            // `cas-seed/`, then reconstruct the graph from the lockfile (no
            // fetch/solve). Surfaces FROZEN-* disqualifications. Workspace-frozen
            // (per-member identity checks) is S11.
            Cmd::Frozen => {
                let mtext = std::fs::read_to_string(fx.dir.join("milpa.kdl"))
                    .map_err(|e| format!("E2E-MANIFEST-UNREADABLE: {e}"))?;
                let doc = match milpa_core::parse_document(&mtext) {
                    Ok(d) => d,
                    Err(e) => return Err(e.code().to_string()),
                };
                let ltext = std::fs::read_to_string(fx.dir.join("milpa.lock"))
                    .map_err(|e| format!("E2E-LOCKFILE-UNREADABLE: {e}"))?;
                let lock = match milpa_core::parse_lockfile(&ltext) {
                    Ok(l) => l,
                    Err(e) => return Err(e.code().to_string()),
                };

                // Seed the CAS from `cas-seed/` (the S2-deferred copy-then-admit):
                // each `cas-seed/<name>/` tree is admitted under its content hash,
                // standing in for what a prior `milpa fetch` would have populated.
                let store = milpa_core::CaStore::new(scratch.cas_root.clone());
                seed_cas(&fx.dir.join("cas-seed"), &store, &scratch.root)?;

                // Workspace-frozen: members are verified by on-disk identity (no
                // `_deps` symlink), externals come from the CAS.
                if matches!(doc, ManifestDoc::Workspace(_)) {
                    let loaded = match milpa_core::load_workspace(&fx.dir) {
                        Ok(w) => w,
                        Err(e) => return Err(e.code().to_string()),
                    };
                    return match milpa_core::resolve_workspace_frozen(
                        &loaded,
                        &lock,
                        &store,
                        &scratch.deps_dir,
                    ) {
                        Ok(graph) => Ok(Produced::WorkspaceOutputs {
                            lock_text: milpa_core::format_lockfile(&milpa_core::from_graph(
                                &graph, "maxver",
                            )),
                            member_nimcfgs: milpa_core::format_workspace_nimcfgs(&loaded, &graph),
                        }),
                        Err(e) => Err(e.code().to_string()),
                    };
                }
                let manifest = match doc {
                    ManifestDoc::Package(m) => m,
                    ManifestDoc::Workspace(_) => unreachable!("handled above"),
                };

                match milpa_core::Milpa.resolve_frozen(&manifest, &lock, &store, &scratch.deps_dir)
                {
                    Ok(graph) => {
                        let lock_text =
                            milpa_core::format_lockfile(&milpa_core::from_graph(&graph, "maxver"));
                        let nimcfg_text =
                            milpa_core::format_nimcfg(&graph, "_deps", &manifest.src_dir);
                        Ok(Produced::Outputs(Outputs {
                            lock_text,
                            nimcfg_text,
                        }))
                    }
                    Err(e) => Err(e.code().to_string()),
                }
            }
            // CLI-only verbs are skipped by `run_fixture` before reaching the
            // Target; this arm exists only for match exhaustiveness.
            Cmd::CliOnly => Err(
                "E2E-CLI-ONLY: mutation/liveness verb fixtures are driven by the \
                 black-box CLI harness, not the in-process Target"
                    .to_string(),
            ),
        }
    }
}

/// Build a [`Profile`] from a fixture's optional `env` file (KEY=VALUE per line,
/// the `MILPA_TARGET_*` axes — conformance-fixtures §2). Returns `None` when the
/// file is absent (no predicate filtering — the common case). Mirrors the Python
/// harness's `_fixture_profile`.
fn fixture_profile(dir: &Path) -> Option<milpa_core::Profile> {
    let text = std::fs::read_to_string(dir.join("env")).ok()?;
    let mut env: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            env.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Some(milpa_core::Profile {
        platform: env.get("MILPA_TARGET_PLATFORM").cloned(),
        arch: env.get("MILPA_TARGET_ARCH").cloned(),
        nim_version: env
            .get("MILPA_TARGET_NIM")
            .and_then(|s| milpa_core::parse_version(s)),
        milpa_version: env
            .get("MILPA_TARGET_MILPA")
            .and_then(|s| milpa_core::parse_version(s)),
        flags: Vec::new(),
    })
}

/// Admit every `cas-seed/<name>/` tree into `store` under its content hash,
/// standing in for a prior `milpa fetch`. `admit` moves its source, so each tree
/// is copied to a staging dir (on the same filesystem as the CAS) first. A no-op
/// when `cas-seed/` is absent.
fn seed_cas(
    seed_root: &Path,
    store: &milpa_core::CaStore,
    scratch_root: &Path,
) -> Result<(), String> {
    if !seed_root.is_dir() {
        return Ok(());
    }
    let staging_root = scratch_root.join(".cas-seed-staging");
    for entry in std::fs::read_dir(seed_root).map_err(|e| format!("E2E-CAS-SEED: {e}"))? {
        let entry = entry.map_err(|e| format!("E2E-CAS-SEED: {e}"))?;
        if !entry
            .file_type()
            .map_err(|e| format!("E2E-CAS-SEED: {e}"))?
            .is_dir()
        {
            continue;
        }
        let name = entry.file_name();
        let staged = staging_root.join(&name);
        let _ = std::fs::remove_dir_all(&staged);
        copy_tree(&entry.path(), &staged).map_err(|e| format!("E2E-CAS-SEED: {e}"))?;
        let identity = milpa_core::compute_content_hash(&staged)
            .map_err(|e| format!("E2E-CAS-SEED: {}", e.message()))?;
        if !store.contains(&identity).unwrap_or(false) {
            store
                .admit(&staged, &identity)
                .map_err(|e| format!("E2E-CAS-SEED: {}", e.message()))?;
        }
        let _ = std::fs::remove_dir_all(&staged);
    }
    Ok(())
}

/// Recursively copy `src`'s contents into `dst` (mirrors the fake-fetcher copy).
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deps_structure_resolves_symlinks_and_normalizes_cas_root() {
        let tmp = tempfile::tempdir().unwrap();
        let scratch = Scratch::new(tmp.path()).unwrap();

        // Materialize a CAS entry and a relative `_deps/foo` symlink to it, the
        // way the real admit/link step does (relative on-disk link, identity.md
        // §3.4). canonicalize must follow it AND resolve the cas-root prefix.
        let hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let entry = scratch.cas_root.join("sha256").join(hex);
        std::fs::create_dir_all(&entry).unwrap();
        std::os::unix::fs::symlink(
            format!("../.cas/sha256/{hex}"),
            scratch.deps_dir.join("foo"),
        )
        .unwrap();

        let structure = read_deps_structure(&scratch.deps_dir, &scratch.cas_root).unwrap();
        assert_eq!(structure, format!("foo -> <CAS_ROOT>/sha256/{hex}/\n"));
    }

    #[test]
    fn empty_deps_dir_yields_empty_structure() {
        let tmp = tempfile::tempdir().unwrap();
        let scratch = Scratch::new(tmp.path()).unwrap();
        assert_eq!(
            read_deps_structure(&scratch.deps_dir, &scratch.cas_root).unwrap(),
            ""
        );
    }

    #[test]
    fn milpa_target_resolve_emits_outputs_for_a_dependency_free_manifest() {
        // S9: a *valid* no-dep manifest resolves to an empty graph and emits the
        // byte-diff outputs (an empty-deps lockfile + header-only nim.cfg).
        let tmp = tempfile::tempdir().unwrap();
        let scratch = Scratch::new(tmp.path()).unwrap();
        std::fs::write(
            tmp.path().join("milpa.kdl"),
            "name \"probe\"\nkind \"library\"\n",
        )
        .unwrap();
        let fx = Fixture {
            id: "synthetic/probe".into(),
            dir: tmp.path().to_path_buf(),
            cmd: Cmd::Resolve,
            expected: Expected::Success,
        };
        match MilpaTarget.execute(&fx, &scratch) {
            Ok(Produced::Outputs(out)) => {
                assert!(out.lock_text.contains("strategy \"maxver\""));
                assert!(out.nimcfg_text.contains("# generated by milpa"));
            }
            other => panic!("expected Outputs, got {other:?}"),
        }
    }

    #[test]
    fn milpa_target_resolve_surfaces_manifest_error_code() {
        // A malformed manifest surfaces its MAN-* code (the S3 greening path).
        let tmp = tempfile::tempdir().unwrap();
        let scratch = Scratch::new(tmp.path()).unwrap();
        std::fs::write(tmp.path().join("milpa.kdl"), "kind \"library\"\n").unwrap();
        let fx = Fixture {
            id: "synthetic/probe".into(),
            dir: tmp.path().to_path_buf(),
            cmd: Cmd::Resolve,
            expected: Expected::Error("MAN-NAME-MISSING".into()),
        };
        assert_eq!(
            MilpaTarget.execute(&fx, &scratch),
            Err("MAN-NAME-MISSING".into())
        );
    }

    #[test]
    fn milpa_target_frozen_emits_outputs_for_a_dependency_free_lockfile() {
        // S10: a no-dep manifest + matching empty maxver lockfile resolves frozen
        // (no fetch/solve) and emits outputs.
        let tmp = tempfile::tempdir().unwrap();
        let scratch = Scratch::new(tmp.path()).unwrap();
        std::fs::write(
            tmp.path().join("milpa.kdl"),
            "name \"probe\"\nkind \"library\"\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("milpa.lock"),
            "version 1\nstrategy \"maxver\"\n",
        )
        .unwrap();
        let fx = Fixture {
            id: "synthetic/probe".into(),
            dir: tmp.path().to_path_buf(),
            cmd: Cmd::Frozen,
            expected: Expected::Success,
        };
        match MilpaTarget.execute(&fx, &scratch) {
            Ok(Produced::Outputs(out)) => assert!(out.lock_text.contains("strategy \"maxver\"")),
            other => panic!("expected Outputs, got {other:?}"),
        }
    }

    #[test]
    fn milpa_target_frozen_surfaces_strategy_mismatch() {
        // A minver lockfile against the default maxver request → FROZEN-*.
        let tmp = tempfile::tempdir().unwrap();
        let scratch = Scratch::new(tmp.path()).unwrap();
        std::fs::write(
            tmp.path().join("milpa.kdl"),
            "name \"probe\"\nkind \"library\"\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("milpa.lock"),
            "version 1\nstrategy \"minver\"\n",
        )
        .unwrap();
        let fx = Fixture {
            id: "synthetic/probe".into(),
            dir: tmp.path().to_path_buf(),
            cmd: Cmd::Frozen,
            expected: Expected::Error("FROZEN-STRATEGY-MISMATCH".into()),
        };
        assert_eq!(
            MilpaTarget.execute(&fx, &scratch),
            Err("FROZEN-STRATEGY-MISMATCH".into())
        );
    }
}
