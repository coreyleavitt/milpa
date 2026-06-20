//! Fixture *I/O*: discovery, `cmd` dispatch, and `expected/` reading
//! (conformance-fixtures.md §1.2, §2.7, §3.1). Deliberately free of any milpa
//! input parsing — a [`Fixture`] exposes its directory and the harness contract
//! (which `cmd`, success-or-error, the expected error slug), and the
//! implementation-under-test ([`crate::runner::Target`]) reads and parses the
//! raw inputs itself. That keeps this layer a true black box.

use std::path::{Path, PathBuf};

/// Which entry point a fixture exercises (conformance-fixtures.md §2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    /// `resolve` (default): parse `milpa.kdl` (+ optional `index.kdl`) and
    /// resolve against `mocked-fetches/`.
    Resolve,
    /// `parse-lockfile`: parse the fixture's `milpa.lock` input only. Always an
    /// error fixture (no success variant).
    ParseLockfile,
    /// `lock-roundtrip`: parse `milpa.lock`, re-emit via `format_lockfile`, and
    /// byte-compare against `expected/milpa.lock`. Tests parse+format without
    /// the resolver pipeline (e.g. Phase B `aliases` field).
    LockRoundtrip,
    /// `frozen`: no-network frozen path against `milpa.kdl` + `milpa.lock`,
    /// optionally CAS-seeded from `cas-seed/`.
    Frozen,
    /// `verify`: frozen-fetch to populate `_deps/`, then run `cmd_verify`.
    /// S6 dep_decl edge-drift fixtures (§3.7.2).
    Verify,
    /// `workspace-manifest-roundtrip` (S9a): parse `milpa.kdl` as a workspace
    /// manifest, re-emit via `format_workspace_manifest`, and byte-compare
    /// against `expected/milpa.kdl`. Proves the canonical serializer is
    /// byte-stable across both impls (Depth-F6).
    WorkspaceManifestRoundtrip,
    /// A CLI-only verb fixture (§2.7.1 mutation `add`/`remove`/`update` or
    /// §2.7.2 liveness `show`/`--version`). These exercise the CLI binary and
    /// its argv/output contract, which the in-process library [`Target`] does
    /// not model — they are driven exclusively by the black-box CLI harness
    /// (`harness/`). The in-process corpus runner SKIPS them (not a failure).
    CliOnly,
}

impl Cmd {
    fn from_dir(dir: &Path) -> Self {
        match std::fs::read_to_string(dir.join("cmd")) {
            Ok(text) => {
                // The first whitespace token is the selector (§2.7).
                let head = text.trim().split_whitespace().next().unwrap_or("");
                match head {
                    "parse-lockfile" => Cmd::ParseLockfile,
                    "lock-roundtrip" => Cmd::LockRoundtrip,
                    "workspace-manifest-roundtrip" => Cmd::WorkspaceManifestRoundtrip,
                    "frozen" => Cmd::Frozen,
                    "verify" => Cmd::Verify,
                    "resolve" | "" => Cmd::Resolve,
                    // Mutation (§2.7.1) + liveness (§2.7.2) selectors: CLI-only.
                    // check-certificate (§2.7.3): also CLI-only (--certificate flag).
                    "add" | "remove" | "update" | "show" | "--version"
                    | "check-certificate" => Cmd::CliOnly,
                    // Unknown selector defaults to resolve (back-compat).
                    _ => Cmd::Resolve,
                }
            }
            // Absent `cmd` ⇒ resolve (§2.7).
            Err(_) => Cmd::Resolve,
        }
    }
}

/// The harness contract a fixture asserts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expected {
    /// Byte-diff `expected/{milpa.lock,nim.cfg,_deps_structure.txt}`.
    Success,
    /// Assert the raised error's `.code()` equals this spec slug
    /// (`expected/error`, §3.1).
    Error(String),
}

/// A discovered fixture: its identity, directory, selected `cmd`, and contract.
#[derive(Debug, Clone)]
pub struct Fixture {
    /// Stable id, e.g. `spec-v1/fixture-003-single-url-dep`. Used in
    /// `known_failing.txt` and test output.
    pub id: String,
    /// The fixture directory (inputs + `expected/`).
    pub dir: PathBuf,
    pub cmd: Cmd,
    /// `--no-index` global flag present in the `cmd` (cli-contract §2.6): the
    /// in-process `Target` must resolve with NO index, overriding any
    /// `index.kdl`, so a named dep raises `RES-NO-INDEX`.
    pub no_index: bool,
    pub expected: Expected,
}

impl Fixture {
    /// Load a single fixture directory into its harness contract. Reads `cmd`
    /// and `expected/` only — inputs are left on disk for the `Target`.
    pub fn load(id: impl Into<String>, dir: &Path) -> Self {
        let error_file = dir.join("expected").join("error");
        let expected = match std::fs::read_to_string(&error_file) {
            Ok(slug) => Expected::Error(slug.trim().to_string()),
            Err(_) => Expected::Success,
        };
        let no_index = std::fs::read_to_string(dir.join("cmd"))
            .map(|t| t.split_whitespace().any(|w| w == "--no-index"))
            .unwrap_or(false);
        Fixture {
            id: id.into(),
            dir: dir.to_path_buf(),
            cmd: Cmd::from_dir(dir),
            no_index,
            expected,
        }
    }
}

/// Discover every `spec-v<N>/fixture-*` directory under `root`, sorted by id for
/// deterministic ordering. `root` may be the shared corpus ([`crate::CORPUS_REL`]
/// resolved against `CARGO_MANIFEST_DIR`) or the synthetic self-test corpus.
///
/// The walk mirrors the Python adapter's two-level scan: `spec-v*` group dirs,
/// then `fixture-*` dirs within each. Non-matching entries are ignored.
pub fn discover(root: &Path) -> Vec<Fixture> {
    let mut fixtures = Vec::new();
    let Ok(groups) = std::fs::read_dir(root) else {
        return fixtures;
    };
    let mut group_dirs: Vec<PathBuf> = groups
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("spec-v"))
        })
        .collect();
    group_dirs.sort();

    for group in group_dirs {
        let group_name = group.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let Ok(entries) = std::fs::read_dir(&group) else {
            continue;
        };
        let mut fixture_dirs: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("fixture-"))
            })
            .collect();
        fixture_dirs.sort();

        for fixture_dir in fixture_dirs {
            let name = fixture_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            let id = format!("{group_name}/{name}");
            fixtures.push(Fixture::load(id, &fixture_dir));
        }
    }
    fixtures
}
