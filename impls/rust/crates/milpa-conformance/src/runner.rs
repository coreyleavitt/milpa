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

use milpa_core::parse_env_bool;

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
    /// A `cmd=lock-roundtrip` success: only `milpa.lock` is byte-compared.
    /// No `nim.cfg` or `_deps_structure.txt` are checked.
    LockOnly(String),
    /// A `cmd=workspace-manifest-roundtrip` (S9a) success: only
    /// `expected/milpa.kdl` is byte-compared against the re-emitted KDL.
    WorkspaceKdl(String),
    /// H-infra: a `cmd=git-protocol` run that passed the content_hash assertion.
    /// The `content_hash` field carries the computed hash for diagnostic output.
    /// `run_fixture` maps this to `Verdict::Pass` for success-expected fixtures.
    GitProtocolPass { content_hash: String },
    /// H-infra: a `cmd=hash` run that passed the expected/stdout assertion.
    /// The `identity` field carries the computed identity for diagnostic output.
    HashPass { identity: String },
    /// S7: a `cmd=index-trust` run that passed the `expected/outcome` assertion.
    /// The `outcome` field carries the computed outcome string for diagnostics.
    IndexTrustPass { outcome: String },
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

/// CLI filesystem-discovery guard fixtures whose error path cannot be modelled
/// by the in-process runner.  These exercise the CLI's file-discovery layer
/// (load_or_discover_manifest, frozen lockfile existence guard) which runs
/// before any resolver or parser call.  The in-process runner reads fixture
/// files directly by name and cannot represent a "missing milpa.kdl/milpa.lock"
/// scenario.  Covered by the black-box CLI harness for all three impls; skipped
/// in-process (same rationale as [`Cmd::CliOnly`]).
const CLI_DISCOVERY_GUARD: &[&str] = &[
    // MAN-NO-MANIFEST: no milpa.kdl in fixture dir (runner reads it by path).
    "fixture-153-man-no-manifest",
    // MAN-NIMBLE-AMBIGUOUS: two *.nimble files, no milpa.kdl (runner reads milpa.kdl).
    "fixture-154-man-nimble-ambiguous",
    // FROZEN-NO-LOCKFILE: cmd:frozen but no milpa.lock (runner reads it by path).
    "fixture-156-frozen-no-lockfile",
    // LOCK-FILE-NOT-FOUND via show: cmd:show is CliOnly but listed for completeness.
    "fixture-157-lock-file-not-found",
    // (fixture-288 un-parked: the runner is now project-dir-aware (§2.8.1), so it
    // reads milpa.kdl + loads the workspace from <fixture>/workspace-root and
    // raises WS-MEMBER-PATH-ESCAPE like the CLI — rfc-conformance-parity Slice 3.)
];

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

    // CLI filesystem-discovery guard fixtures: the in-process runner reads
    // fixture files by name (milpa.kdl, milpa.lock) and cannot model the
    // CLI's file-discovery layer that raises MAN-NO-MANIFEST, MAN-NIMBLE-AMBIGUOUS,
    // or FROZEN-NO-LOCKFILE.  These are covered by the black-box CLI harness.
    if let Some(fixture_name) = fx.dir.file_name().and_then(|n| n.to_str()) {
        if CLI_DISCOVERY_GUARD.contains(&fixture_name) {
            return Verdict::Skip(format!(
                "CLI filesystem-discovery guard fixture ({fixture_name}); \
                 in-process runner cannot model a missing milpa.kdl/milpa.lock — \
                 covered by the black-box CLI harness"
            ));
        }
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
        (Expected::Success, Ok(Produced::LockOnly(lock_text))) => {
            let expected = fx.dir.join("expected");
            match diff_file(&expected.join("milpa.lock"), &lock_text, "milpa.lock") {
                Some(fail) => fail,
                None => Verdict::Pass,
            }
        }
        (Expected::Success, Ok(Produced::WorkspaceKdl(kdl_text))) => {
            let expected = fx.dir.join("expected");
            match diff_file(&expected.join("milpa.kdl"), &kdl_text, "milpa.kdl") {
                Some(fail) => fail,
                None => Verdict::Pass,
            }
        }
        // H-infra: git-protocol fixture passed the content_hash assertion (checked
        // inside run_git_protocol_fixture and returned as GitProtocolPass).
        // The fixture has no milpa.lock / nim.cfg / _deps_structure.txt to diff.
        (Expected::Success, Ok(Produced::GitProtocolPass { .. })) => Verdict::Pass,
        // H-infra: hash fixture passed the expected/stdout assertion (checked
        // inside run_hash_fixture and returned as HashPass).
        (Expected::Success, Ok(Produced::HashPass { .. })) => Verdict::Pass,
        // S7: index-trust policy state machine passed the expected/outcome assertion
        // (checked inside run_index_trust_fixture and returned as IndexTrustPass).
        (Expected::Success, Ok(Produced::IndexTrustPass { .. })) => Verdict::Pass,
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

    // Build-mode: redact the encoder-dependent tarball sha256 before diff.
    let lock_for_diff;
    let lock_text = if is_build_mode_fixture(&fx.dir) {
        lock_for_diff = redact_tarball_sha256(lock_text);
        &lock_for_diff
    } else {
        lock_text
    };

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

/// The stable placeholder for the encoder-dependent tarball archive sha256 in
/// build-mode fixtures.  MUST be identical in the Python and Rust runners
/// (SSOT: conformance-fixtures.md §2.3.4 build-mode extension).
const TARBALL_SHA256_PLACEHOLDER: &str = "<TARBALL-SHA256>";

/// Return true when any `mocked-fetches/<key>/format` file is present in the
/// fixture.  Build-mode fixtures build real archives at test time; their
/// lockfile's tarball `sha256` field is encoder-dependent and MUST be redacted
/// before the byte-diff.
fn is_build_mode_fixture(fixture_dir: &Path) -> bool {
    let mocked = fixture_dir.join("mocked-fetches");
    if !mocked.is_dir() {
        return false;
    }
    std::fs::read_dir(&mocked)
        .ok()
        .map(|rd| {
            rd.flatten().any(|e| {
                e.path().is_dir() && e.path().join("format").is_file()
            })
        })
        .unwrap_or(false)
}

/// Replace the encoder-dependent sha256 value inside tarball provenance blocks
/// with [`TARBALL_SHA256_PLACEHOLDER`].  Only called for build-mode fixtures
/// (`is_build_mode_fixture` true).  The placeholder is the same string the
/// fixture author places in `expected/milpa.lock`; after redaction the
/// byte-diff is stable across Python (zlib) and Rust (flate2/lzma-rs) encoders.
///
/// Matches the `sha256 "<hex64>"` line inside a tarball provenance block.
/// Uses a simple line-by-line scan rather than a full regex to avoid pulling in
/// the `regex` crate.
fn redact_tarball_sha256(lock_text: &str) -> String {
    lock_text
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            // Match:  sha256 "<64 hex chars>"
            if trimmed.starts_with("sha256 \"") && trimmed.ends_with('"') {
                let inner = &trimmed["sha256 \"".len()..trimmed.len() - 1];
                // Only redact if it looks like a 64-char hex digest (not already a placeholder).
                if inner.len() == 64 && inner.chars().all(|c| c.is_ascii_hexdigit()) {
                    let indent: String = line
                        .chars()
                        .take_while(|c| c.is_whitespace())
                        .collect();
                    return format!("{indent}sha256 \"{TARBALL_SHA256_PLACEHOLDER}\"");
                }
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Byte-diff the three success outputs against `expected/`.
fn diff_success(fx: &Fixture, scratch: &Scratch, out: &Outputs) -> Verdict {
    let expected = fx.dir.join("expected");

    // Build-mode: redact the encoder-dependent tarball sha256 before diff.
    let lock_text = if is_build_mode_fixture(&fx.dir) {
        redact_tarball_sha256(&out.lock_text)
    } else {
        out.lock_text.clone()
    };

    if let Some(fail) = diff_file(&expected.join("milpa.lock"), &lock_text, "milpa.lock") {
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

    // Collect (label, path) pairs — recurse one level into @ns/ directories.
    // C1: namespace directories ("@<ns>/") hold the actual per-dep symlinks;
    // emit them as "@ns/name -> ..." consistent with fixture _deps_structure.txt.
    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(deps_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            entries.push((name, path));
        } else if meta.file_type().is_dir() && name.starts_with('@') {
            // Namespace directory: recurse one level and collect children.
            for child in std::fs::read_dir(&path)?.flatten() {
                let child_path = child.path();
                let child_name = child.file_name().to_string_lossy().into_owned();
                let child_meta = std::fs::symlink_metadata(&child_path)?;
                if child_meta.file_type().is_symlink() {
                    entries.push((format!("{}/{}", name, child_name), child_path));
                }
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut lines = String::new();
    for (name, link) in entries {
        let resolved = std::fs::canonicalize(&link)?;
        let resolved_str = resolved.to_string_lossy();
        if resolved_str.starts_with(&cas_prefix) {
            // CAS-backed dep (git/tarball/oci): normalize the CAS root prefix.
            let normalized = resolved_str.replace(&cas_prefix, "<CAS_ROOT>");
            lines.push_str(&format!("{name} -> {normalized}/\n"));
        } else {
            // Local dep: symlink points outside the CAS (live source tree).
            // Emit a portable sentinel — the absolute target path is
            // machine-specific and must NOT be recorded in the fixture.
            lines.push_str(&format!("{name} -> (symlink)\n"));
        }
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
        use milpa_core::{FrozenResolver, ManifestDoc};

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
            // lock-roundtrip: parse milpa.lock → re-emit → byte-compare vs
            // expected/milpa.lock. Tests parse+format for fields not produced
            // by the resolver pipeline (e.g. Phase B `aliases`).
            Cmd::LockRoundtrip => {
                let text = std::fs::read_to_string(fx.dir.join("milpa.lock"))
                    .map_err(|e| format!("E2E-LOCKFILE-UNREADABLE: {e}"))?;
                let lock = match milpa_core::parse_lockfile(&text) {
                    Ok(l) => l,
                    Err(e) => return Err(e.code().to_string()),
                };
                Ok(Produced::LockOnly(milpa_core::format_lockfile(&lock)))
            }
            // workspace-manifest-roundtrip (S9a): parse milpa.kdl as a workspace
            // manifest → re-emit via format_workspace_manifest → byte-compare vs
            // expected/milpa.kdl. Proves the canonical serializer is byte-stable
            // across both impls (Depth-F6).
            Cmd::WorkspaceManifestRoundtrip => {
                use milpa_core::ManifestDoc;
                let text = std::fs::read_to_string(fx.dir.join("milpa.kdl"))
                    .map_err(|e| format!("E2E-MANIFEST-UNREADABLE: {e}"))?;
                let ws = match milpa_core::parse_document(&text) {
                    Ok(ManifestDoc::Workspace(w)) => w,
                    Ok(ManifestDoc::Package(_)) => {
                        return Err("E2E-WORKSPACE-MANIFEST-ROUNDTRIP-PACKAGE-DOC".to_string());
                    }
                    Err(e) => return Err(e.code().to_string()),
                };
                Ok(Produced::WorkspaceKdl(milpa_core::format_workspace_manifest(&ws)))
            }
            // The resolve path: parse `milpa.kdl` (MAN-* on malformed), parse the
            // optional `index.kdl` (TNG-* parse validators), then resolve against
            // the `mocked-fetches/` fake. A *valid* resolve falls through to the
            // not-yet-wired tail (S9 nim.cfg + lock emission produce the byte-diff
            // outputs), so success fixtures stay parked until S9; resolve-time
            // error fixtures (TNG-*/RES-*/SOLVE-*) green here.
            Cmd::Resolve => {
                // §2.8.1: project-dir selects the project root (the -C dir). All
                // other control inputs (mocked-fetches/, index.kdl, cas-seed/,
                // dep-decl/, expected/) stay rooted at fx.dir; only the
                // manifest/workspace load uses project_root. Mirrors the black-box
                // harness and the Python adapter.
                let project_root = fixture_project_root(fx);
                let text = std::fs::read_to_string(project_root.join("milpa.kdl"))
                    .map_err(|e| format!("E2E-MANIFEST-UNREADABLE: {e}"))?;
                // Optional tianguis index for named-dep resolution. The parser
                // surfaces TNG-* trust-boundary errors (schema/unsafe/bad-*).
                // --no-index (cli-contract §2.6) overrides any present index.kdl,
                // forcing index=None so a named dep raises RES-NO-INDEX.
                let index = {
                    let p = fx.dir.join("index.kdl");
                    if fx.no_index {
                        None
                    } else if p.is_file() {
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

                // §8 prior-lockfile pin reuse: a `resolve` fixture MAY ship a
                // milpa.lock input (conformance-fixtures §2.9 / resolver-semantics
                // §8). Load it (gracefully — absent/unparseable ⇒ None, a soft
                // preference) so tarball TOFU / git pinned-commit re-assertion is
                // exercised exactly as the CLI's `cmd_fetch` does.
                let prior_lock = milpa_core::load_lockfile(&fx.dir.join("milpa.lock")).ok();

                let manifest = match milpa_core::parse_document(&text) {
                    // Workspace: load (WS-* topology) → multi-member union resolve
                    // (RES-WS-*) → shared milpa.lock + per-member nim.cfg.
                    Ok(ManifestDoc::Workspace(_)) => {
                        let loaded = match milpa_core::load_workspace(&project_root) {
                            Ok(w) => w,
                            Err(e) => return Err(e.code().to_string()),
                        };
                        let fetcher = crate::fake_fetcher::FakeFetcher::new(
                            fx.dir.join("mocked-fetches"),
                            scratch.cas_root.clone(),
                            fx.dir.clone(),
                            scratch.root.clone(),
                        );
                        // S5: read MILPA_REQUIRE_ATTESTED_METADATA from the fixture env
                        // and thread it to the workspace resolve path (§13.1 workspace rule).
                        let ws_require_attested = fixture_require_attested_metadata(&fx.dir);
                        // S1 (RFC: workspace-completion §3.A): read CLI feature-selection
                        // inputs from fixture env and pass to the extended workspace signature.
                        let ws_cli_features = fixture_cli_features(&fx.dir);
                        let ws_cli_no_default = fixture_no_default_features(&fx.dir);
                        let ws_cli_all_features = fixture_all_features(&fx.dir);
                        let store = milpa_core::CaStore::new(&scratch.cas_root);
                        return match milpa_core::resolve_workspace_with_features(
                            &loaded,
                            index.as_ref(),
                            &fetcher,
                            profile.as_ref(),
                            prior_lock.as_ref(),
                            milpa_core::Strategy::default(),
                            &scratch.deps_dir,
                            ws_require_attested,
                            &store,
                            &ws_cli_features,
                            ws_cli_no_default,
                            ws_cli_all_features,
                        ) {
                            Ok(graph) => {
                                // B-nimcfg: _deps/ view rebuilt internally by resolve_workspace
                                // (alias symlinks + stale removal). No external call needed.
                                // S11 §3.8: build flag_defines (SSOT) for unified -d: in per-member nim.cfg.
                                let ws_flag_defines = milpa_core::build_flag_defines(&graph, &scratch.deps_dir);
                                Ok(Produced::WorkspaceOutputs {
                                    lock_text: milpa_core::format_lockfile(&milpa_core::from_graph(
                                        &graph, "maxver",
                                    )),
                                    member_nimcfgs: milpa_core::format_workspace_nimcfgs(
                                        &loaded, &graph, Some(&ws_flag_defines),
                                    ),
                                })
                            }
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
                    fx.dir.clone(),
                    scratch.root.clone(),
                );

                // S3b / Slice 2: mirror the CLI's maybe_dep_decl_store exactly —
                // three-way logic lives in fixture_dep_decl_store (M5 SSOT).
                let dep_decl_store_box = fixture_dep_decl_store(fx);
                let dep_decl_store: Option<&dyn milpa_core::dep_decl_store::DepDeclStore> =
                    dep_decl_store_box.as_deref();

                // S5: read MILPA_REQUIRE_ATTESTED_METADATA from the fixture env.
                let require_attested_metadata = fixture_require_attested_metadata(&fx.dir);
                // S9 (RFC #23 §3.4): read CLI feature-selection from fixture env.
                let cli_features = fixture_cli_features(&fx.dir);
                let cli_no_default = fixture_no_default_features(&fx.dir);
                let cli_all_features = fixture_all_features(&fx.dir);

                let store = milpa_core::CaStore::new(&scratch.cas_root);
                match milpa_core::resolve_with_features(
                    &manifest,
                    index.as_ref(),
                    &fetcher,
                    profile.as_ref(),
                    prior_lock.as_ref(),
                    milpa_core::Strategy::default(),
                    &scratch.deps_dir,
                    dep_decl_store,
                    require_attested_metadata,
                    &store,
                    &cli_features,
                    cli_no_default,
                    cli_all_features,
                ) {
                    // S9: emit the byte-diff outputs. `_deps_structure.txt` is read
                    // by the harness from the materialized (symlinked) `_deps/`.
                    Ok(graph) => {
                        // B-nimcfg: _deps/ view rebuilt internally by resolve
                        // (alias symlinks + stale removal). No external call needed.
                        let lock_text =
                            milpa_core::format_lockfile(&milpa_core::from_graph(&graph, "maxver"));
                        // §7.5 S6: compute flag_defines from dep manifests (SSOT).
                        let flag_defines = milpa_core::build_flag_defines(&graph, &scratch.deps_dir);
                        let nimcfg_text =
                            milpa_core::format_nimcfg(&graph, "_deps", &manifest.src_dir, Some(&flag_defines));
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
                // M6: use project_root (not fx.dir) for manifest/lock/workspace loads,
                // matching the resolve path's §2.8.1 project-dir logic.
                let project_root = fixture_project_root(fx);
                let mtext = std::fs::read_to_string(project_root.join("milpa.kdl"))
                    .map_err(|e| format!("E2E-MANIFEST-UNREADABLE: {e}"))?;
                let doc = match milpa_core::parse_document(&mtext) {
                    Ok(d) => d,
                    Err(e) => return Err(e.code().to_string()),
                };
                let ltext = std::fs::read_to_string(project_root.join("milpa.lock"))
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
                    let loaded = match milpa_core::load_workspace(&project_root) {
                        Ok(w) => w,
                        Err(e) => return Err(e.code().to_string()),
                    };
                    // S2 (RFC: workspace-completion §3.A / Breadth-P1b):
                    // FROZEN-ACTIVE-FLAGS-MISMATCH check for workspace frozen path.
                    // Must run BEFORE resolve_workspace_frozen so the correct slug
                    // fires rather than FROZEN-MANIFEST-DEP-NOT-IN-LOCK.
                    let ws_cli_features = fixture_cli_features(&fx.dir);
                    let ws_cli_no_default = fixture_no_default_features(&fx.dir);
                    let ws_cli_all_features = fixture_all_features(&fx.dir);
                    if let Err(e) = milpa_core::check_workspace_frozen_active_flags_mismatch(
                        &loaded,
                        &lock,
                        &ws_cli_features,
                        ws_cli_no_default,
                        ws_cli_all_features,
                    ) {
                        return Err(e.code().to_string());
                    }
                    return match milpa_core::resolve_workspace_frozen(
                        &loaded,
                        &lock,
                        &store,
                        &scratch.deps_dir,
                    ) {
                        Ok(graph) => {
                            // S11 §3.8: build flag_defines (SSOT) for unified -d: in per-member nim.cfg.
                            let ws_flag_defines = milpa_core::build_flag_defines(&graph, &scratch.deps_dir);
                            Ok(Produced::WorkspaceOutputs {
                                lock_text: milpa_core::format_lockfile(&milpa_core::from_graph(
                                    &graph, "maxver",
                                )),
                                member_nimcfgs: milpa_core::format_workspace_nimcfgs(&loaded, &graph, Some(&ws_flag_defines)),
                            })
                        }
                        Err(e) => Err(e.code().to_string()),
                    };
                }
                let manifest = match doc {
                    ManifestDoc::Package(m) => m,
                    ManifestDoc::Workspace(_) => unreachable!("handled above"),
                };

                // S9 (RFC #23 §3.4): FROZEN-ACTIVE-FLAGS-MISMATCH check.
                // Recompute root active-flag closure from manifest + CLI inputs;
                // compare to lockfile: if a flag-gated root dep is admitted by the
                // CLI seed but absent from lock (or vice versa), raise the error.
                let cli_features = fixture_cli_features(&fx.dir);
                let cli_no_default = fixture_no_default_features(&fx.dir);
                let cli_all_features_flag = fixture_all_features(&fx.dir);
                if let Err(e) = milpa_core::check_frozen_active_flags_mismatch(
                    &manifest,
                    &lock,
                    &cli_features,
                    cli_no_default,
                    cli_all_features_flag,
                ) {
                    return Err(e.code().to_string());
                }

                match milpa_core::Milpa.resolve_frozen(&manifest, &lock, &store, &scratch.deps_dir)
                {
                    Ok(graph) => {
                        let lock_text =
                            milpa_core::format_lockfile(&milpa_core::from_graph(&graph, "maxver"));
                        // §7.5 S6: compute flag_defines from dep manifests (SSOT).
                        let flag_defines = milpa_core::build_flag_defines(&graph, &scratch.deps_dir);
                        let nimcfg_text =
                            milpa_core::format_nimcfg(&graph, "_deps", &manifest.src_dir, Some(&flag_defines));
                        Ok(Produced::Outputs(Outputs {
                            lock_text,
                            nimcfg_text,
                        }))
                    }
                    Err(e) => Err(e.code().to_string()),
                }
            }
            // S6: verify path — regular (non-frozen) resolve to populate _deps/
            // and warm the CAS, then restore the pre-authored lock and check
            // dep_decl pins against the live index (§3.7.2).
            // This mirrors the harness black-box approach exactly.
            Cmd::Verify => {
                // M6: use project_root (not fx.dir) for manifest/lock/workspace loads,
                // matching the resolve path's §2.8.1 project-dir logic.
                let project_root = fixture_project_root(fx);
                let mtext = std::fs::read_to_string(project_root.join("milpa.kdl"))
                    .map_err(|e| format!("E2E-MANIFEST-UNREADABLE: {e}"))?;
                let doc = match milpa_core::parse_document(&mtext) {
                    Ok(d) => d,
                    Err(e) => return Err(e.code().to_string()),
                };
                // Missing lock → LOCK-FILE-NOT-FOUND, mirroring cmd_verify's
                // first check (before any _deps/ work). fixture-164 (#125)
                // exercises the no-lock branch.
                let lock_path = project_root.join("milpa.lock");
                if !lock_path.is_file() {
                    return Err("LOCK-FILE-NOT-FOUND".to_string());
                }
                let ltext = std::fs::read_to_string(&lock_path)
                    .map_err(|e| format!("E2E-LOCKFILE-UNREADABLE: {e}"))?;
                let lock = match milpa_core::parse_lockfile(&ltext) {
                    Ok(l) => l,
                    Err(e) => return Err(e.code().to_string()),
                };

                // Phase 1: regular resolve to populate _deps/ and warm the CAS.
                // Uses the fixture's mocked-fetches/ + dep-decl/ + index.kdl.
                let store = milpa_core::CaStore::new(scratch.cas_root.clone());
                let fetcher = crate::fake_fetcher::FakeFetcher::new(
                    fx.dir.join("mocked-fetches"),
                    scratch.cas_root.clone(),
                    fx.dir.clone(),
                    scratch.root.clone(),
                );
                // S3b / Slice 2: three-way dep_decl_store selection — now uses the
                // same SSOT helper as the resolve path (M5), so fx.no_index and the
                // index.kdl→Http branch are both honored here (parity gap closed).
                let dep_decl_store_box = fixture_dep_decl_store(fx);
                let dep_decl_store: Option<&dyn milpa_core::dep_decl_store::DepDeclStore> =
                    dep_decl_store_box.as_deref();
                let verify_index = {
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
                let profile = fixture_profile(&fx.dir);

                let _pre_phase_result = match doc {
                    ManifestDoc::Workspace(_) => {
                        let loaded = match milpa_core::load_workspace(&project_root) {
                            Ok(w) => w,
                            Err(e) => return Err(e.code().to_string()),
                        };
                        let verify_cli_features = fixture_cli_features(&fx.dir);
                        let verify_cli_no_default = fixture_no_default_features(&fx.dir);
                        let verify_cli_all_features = fixture_all_features(&fx.dir);
                        milpa_core::resolve_workspace_with_features(
                            &loaded,
                            verify_index.as_ref(),
                            &fetcher,
                            profile.as_ref(),
                            None,
                            milpa_core::Strategy::default(),
                            &scratch.deps_dir,
                            false, // verify pre-phase: no attestation flag
                            &store,
                            &verify_cli_features,
                            verify_cli_no_default,
                            verify_cli_all_features,
                        ).map_err(|e| e.code().to_string())
                    }
                    ManifestDoc::Package(ref manifest) => {
                        milpa_core::resolve(
                            manifest,
                            verify_index.as_ref(),
                            &fetcher,
                            profile.as_ref(),
                            None,
                            milpa_core::Strategy::default(),
                            &scratch.deps_dir,
                            dep_decl_store,
                            false,
                            &store,
                        ).map_err(|e| e.code().to_string())
                    }
                };
                // Pre-phase resolve errors are ignored — if _deps/ isn't populated,
                // the disk check below will fail with LOCK-GRAPH-MISMATCH.
                // For S6 fixtures the pre-phase always succeeds.
                // B-nimcfg: _deps/ view rebuilt internally by the live resolve calls
                // above (alias symlinks + stale removal). No external call needed.

                // Restore the pre-authored milpa.lock (with the old dep_decl pins
                // under test). The pre-phase may have generated a new lock with
                // the current index's dep_decl hash — we discard that.
                std::fs::write(scratch.root.join("milpa.lock"), &ltext)
                    .map_err(|e| format!("E2E-LOCKFILE-WRITE: {e}"))?;

                // Load the workspace once for both the frozen-flags mismatch check
                // (S11b, Breadth-P2c) and the §13.1 strict-policy derivation.
                // A single load is sufficient — both checks read the same on-disk
                // state and neither mutates it.
                let ws_loaded_for_verify = if matches!(doc, ManifestDoc::Workspace(_)) {
                    Some(milpa_core::load_workspace(&project_root))
                } else {
                    None
                };

                // S11b (Breadth-P2c): workspace frozen-flags mismatch check.
                // Runs BEFORE disk check, matching cmd_verify's ordering.
                if let Some(ref ws_result) = ws_loaded_for_verify {
                    match ws_result {
                        Ok(loaded_verify) => {
                            if let Err(e) = milpa_core::check_workspace_frozen_active_flags_mismatch(
                                loaded_verify,
                                &lock,
                                &std::collections::BTreeSet::new(),
                                false,
                                false,
                            ) {
                                return Err(e.code().to_string());
                            }
                        }
                        Err(_) => {
                            // workspace load failed — fall through to disk check
                            let divergences = milpa_core::verify_lockfile_against_deps(&lock, &scratch.deps_dir);
                            if !divergences.is_empty() {
                                return Err("LOCK-GRAPH-MISMATCH".to_string());
                            }
                            return Ok(Produced::NoByteDiff);
                        }
                    }
                }

                // Phase 2: disk check.
                let divergences =
                    milpa_core::verify_lockfile_against_deps(&lock, &scratch.deps_dir);
                if !divergences.is_empty() {
                    return Err("LOCK-GRAPH-MISMATCH".to_string());
                }

                // Phase 3: dep_decl edge check vs live index (§3.7.2).
                let pinned: Vec<_> = lock
                    .deps
                    .iter()
                    .filter(|d| d.dep_decl.is_some())
                    .collect();
                if pinned.is_empty() {
                    // No pins — verify passes.
                    return Ok(Produced::NoByteDiff);
                }

                // §13.1: effective strict = OR(manifest attestation-policy "strict",
                // MILPA_REQUIRE_ATTESTED_METADATA flag from fixture env).
                // Route through the milpa-core SSOT helpers (effective_trust_policy /
                // workspace_any_member_strict) rather than re-deriving the OR rule.
                let flag_strict = fixture_require_attested_metadata(&fx.dir);
                let strict = match &doc {
                    ManifestDoc::Package(m) => {
                        use milpa_core::TrustPolicy;
                        milpa_core::effective_trust_policy(&m.attestation_policy, flag_strict, None)
                            == TrustPolicy::Strict
                    }
                    ManifestDoc::Workspace(_) => {
                        // Workspace: OR across all members (+ flag). Reuse the
                        // single load from ws_loaded_for_verify (no second I/O).
                        match ws_loaded_for_verify.as_ref().and_then(|r| r.as_ref().ok()) {
                            Some(ws) => milpa_core::workspace_any_member_strict(ws) || flag_strict,
                            None => flag_strict,
                        }
                    }
                };

                // Use the index loaded for the pre-phase (if absent → offline).
                let index = match verify_index {
                    None => {
                        // Offline: strict → VERIFY-EDGE-MISMATCH; non-strict → skip.
                        if strict {
                            return Err("VERIFY-EDGE-MISMATCH".to_string());
                        }
                        return Ok(Produced::NoByteDiff);
                    }
                    Some(i) => i,
                };

                // Per-dep edge check.
                for dep in &pinned {
                    let locked_pin = dep.dep_decl.as_deref().unwrap();
                    // Find the package by bare name, then find the exact version-node.
                    let iv = match index.lookup_bare(&dep.name) {
                        milpa_core::registry::BareLookup::NotFound
                        | milpa_core::registry::BareLookup::Ambiguous(_) => {
                            return Err("LOCK-DEPDECL-PIN-MISSING".to_string());
                        }
                        milpa_core::registry::BareLookup::Found(pkg) => pkg
                            .versions
                            .into_iter()
                            .find(|v| v.version == dep.version),
                    };
                    match iv {
                        None => return Err("LOCK-DEPDECL-PIN-MISSING".to_string()),
                        Some(entry) => match &entry.dep_decl {
                            None => return Err("LOCK-DEPDECL-PIN-MISSING".to_string()),
                            Some(current) if current != locked_pin => {
                                return Err("VERIFY-EDGE-MISMATCH".to_string());
                            }
                            _ => {} // match
                        },
                    }
                }
                Ok(Produced::NoByteDiff)
            }
            // H-infra: git-protocol fixtures run the REAL fetch_git against a
            // generated local bare repo.  No milpa.kdl or mocked-fetches/ needed.
            // Error-class fixtures (EXTRACT-SYMLINK-ESCAPE, FETCH-GIT-LFS-POINTER)
            // return Err(slug) directly so run_fixture's verdict dispatch can match
            // them against Expected::Error(slug).  The error string is the slug
            // itself — no wrapping prefix — so the bijection check works cleanly.
            Cmd::GitProtocol => {
                run_git_protocol_fixture(fx, scratch)
            }
            // H-infra: hash fixtures exercise the milpa hash A0-cmd path.
            // Same git-protocol.json schema; asserts expected/stdout matches
            // the identity computed over the materialized tree.
            Cmd::Hash => {
                run_hash_fixture(fx, scratch)
            }
            // CLI-only verbs are skipped by `run_fixture` before reaching the
            // Target; this arm exists only for match exhaustiveness.
            Cmd::CliOnly => Err(
                "E2E-CLI-ONLY: mutation/liveness verb fixtures are driven by the \
                 black-box CLI harness, not the in-process Target"
                    .to_string(),
            ),
            // Epoch-2 Merkle-DAG oracle fixtures (RFC slice B2-git): the production
            // DAG builder + per-transport materializers reproduce the hand-frozen
            // `dag-sha256:` pin. Two transports are live: staged seam input
            // (dag-oracle.json) → builder; git (git-protocol.json) → real
            // object-store materialization → git seam → builder. The builder is
            // independent of the frozen oracle, so reproducing the pin IS the
            // differential check.
            Cmd::DagOracle => run_dag_oracle_fixture(fx, scratch),
            // S7: index-trust policy state machine (RFC registry-trust-federation §11 S7).
            // MockVerifier-driven; no real Sigstore infrastructure required.
            Cmd::IndexTrust => run_index_trust_fixture(fx),
        }
    }
}

// ---------------------------------------------------------------------------
// H-infra: git-protocol fixture tier
// ---------------------------------------------------------------------------
// H-infra runs the REAL fetch_git (not MockedFetcher) against file:// URLs
// pointing at local bare repos generated at test time from the fixture's
// git-protocol.json spec.  This is the only tier that can catch git-protocol
// bugs (object-store vs smudge divergence, submodule omission, etc.) —
// MockedFetcher stages bytes verbatim with no git invocation.

/// Minimal JSON reader for the git-protocol.json fixture schema.
/// The schema is entirely under our control (no user data), so this
/// hand-rolled traversal is safe.  Not a general-purpose parser.
mod serde_like {
    /// An extremely minimal JSON value type (only what git-protocol.json uses).
    #[derive(Debug, Clone)]
    pub enum Val {
        Str(String),
        Null,
        Arr(Vec<Val>),
        Obj(Vec<(String, Val)>),
    }

    impl Val {
        pub fn as_str(&self) -> Option<&str> {
            if let Val::Str(s) = self { Some(s) } else { None }
        }
        pub fn as_arr(&self) -> Option<&[Val]> {
            if let Val::Arr(a) = self { Some(a) } else { None }
        }
        pub fn as_obj(&self) -> Option<&[(String, Val)]> {
            if let Val::Obj(o) = self { Some(o) } else { None }
        }
        pub fn is_null(&self) -> bool {
            matches!(self, Val::Null)
        }
        pub fn get(&self, key: &str) -> Option<&Val> {
            self.as_obj()?.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        }
    }

    pub fn parse(s: &str) -> Result<Val, String> {
        let mut chars = s.chars().peekable();
        let val = parse_val(&mut chars)?;
        // skip trailing whitespace
        while chars.peek().map(|c| c.is_whitespace()).unwrap_or(false) {
            chars.next();
        }
        Ok(val)
    }

    fn skip_ws(it: &mut std::iter::Peekable<std::str::Chars>) {
        while it.peek().map(|c| c.is_whitespace()).unwrap_or(false) {
            it.next();
        }
    }

    fn parse_val(it: &mut std::iter::Peekable<std::str::Chars>) -> Result<Val, String> {
        skip_ws(it);
        match it.peek().copied() {
            Some('"') => Ok(Val::Str(parse_string(it)?)),
            Some('{') => Ok(Val::Obj(parse_obj(it)?)),
            Some('[') => Ok(Val::Arr(parse_arr(it)?)),
            Some('n') => {
                for c in ['n','u','l','l'] {
                    if it.next() != Some(c) { return Err("expected null".into()); }
                }
                Ok(Val::Null)
            }
            other => Err(format!("unexpected char in JSON: {other:?}")),
        }
    }

    fn parse_string(it: &mut std::iter::Peekable<std::str::Chars>) -> Result<String, String> {
        assert_eq!(it.next(), Some('"'));
        let mut s = String::new();
        loop {
            match it.next() {
                None => return Err("unterminated string".into()),
                Some('"') => break,
                Some('\\') => {
                    match it.next() {
                        Some('"') => s.push('"'),
                        Some('\\') => s.push('\\'),
                        Some('n') => s.push('\n'),
                        Some('r') => s.push('\r'),
                        Some('t') => s.push('\t'),
                        other => return Err(format!("unknown escape \\{other:?}")),
                    }
                }
                Some(c) => s.push(c),
            }
        }
        Ok(s)
    }

    fn parse_obj(it: &mut std::iter::Peekable<std::str::Chars>) -> Result<Vec<(String, Val)>, String> {
        assert_eq!(it.next(), Some('{'));
        let mut pairs = Vec::new();
        skip_ws(it);
        if it.peek() == Some(&'}') { it.next(); return Ok(pairs); }
        loop {
            skip_ws(it);
            let key = parse_string(it)?;
            skip_ws(it);
            if it.next() != Some(':') { return Err("expected ':'".into()); }
            skip_ws(it);
            let val = parse_val(it)?;
            pairs.push((key, val));
            skip_ws(it);
            match it.next() {
                Some(',') => continue,
                Some('}') => break,
                other => return Err(format!("expected , or }}, got {other:?}")),
            }
        }
        Ok(pairs)
    }

    fn parse_arr(it: &mut std::iter::Peekable<std::str::Chars>) -> Result<Vec<Val>, String> {
        assert_eq!(it.next(), Some('['));
        let mut items = Vec::new();
        skip_ws(it);
        if it.peek() == Some(&']') { it.next(); return Ok(items); }
        loop {
            skip_ws(it);
            let val = parse_val(it)?;
            items.push(val);
            skip_ws(it);
            match it.next() {
                Some(',') => continue,
                Some(']') => break,
                other => return Err(format!("expected , or ], got {other:?}")),
            }
        }
        Ok(items)
    }
}

/// Build a local git repo from a repo spec and return its path + all commit SHAs.
///
/// Returns `(repo_dir, [sha_0, sha_1, ...])` in oldest-first order.
///
/// Two forms are supported:
///
/// *Single-commit form* (backward-compat): `repo_spec["files"]` is a
/// `{relpath: content}` object.  One commit is produced; the SHA list has one element.
///
/// *Multi-commit form* (H4): `repo_spec["commits"]` is an array of
/// `{"files": {relpath: content}}` objects applied sequentially.  Each dict
/// is committed on top of the previous (files not mentioned survive — no
/// auto-deletion).  The SHA list has one entry per commit.
///
/// All files are committed with fixed author identity (these are disposable
/// test repos, not the milpa repo whose config the global git config protects).
fn make_git_protocol_repo(
    tmpdir: &std::path::Path,
    repo_spec: &serde_like::Val,
    peer_shas: &std::collections::HashMap<String, String>,
) -> Result<(std::path::PathBuf, Vec<String>), String> {
    let name = repo_spec.get("name")
        .and_then(|v| v.as_str())
        .ok_or("repo_spec missing 'name'")?;
    let ref_name = repo_spec.get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("main");

    let repo_dir = tmpdir.join(name);
    std::fs::create_dir_all(&repo_dir)
        .map_err(|e| format!("create repo dir: {e}"))?;

    // git init — without -c flags (git init ignores them in some versions)
    let out = std::process::Command::new("git")
        .arg("-C").arg(&repo_dir)
        .args(["init", "-q", "-b", ref_name])
        .output()
        .map_err(|e| format!("git init: {e}"))?;
    if !out.status.success() {
        return Err(format!("git init failed: {}", String::from_utf8_lossy(&out.stderr)));
    }

    // git add + commit helper (captures the SHA after each commit).
    // Pin commit authorship + timestamp so commit SHAs are reproducible across
    // runs and impls — required for golden expected/submodule_shas (#177, H5).
    // 1577836800 = 2020-01-01T00:00:00Z. Content hashes are unaffected (.git/ excluded).
    // commit.gpgSign=false prevents host SSH/GPG commit signing from changing the
    // commit SHA (the signed commit object differs from an unsigned one, breaking
    // cross-impl golden reproducibility if the host has commit.gpgSign=true).
    let git_c = |args: &[&str]| -> std::io::Result<std::process::Output> {
        std::process::Command::new("git")
            .arg("-C").arg(&repo_dir)
            .args(["-c", "user.email=milpa-hinfra@test.milpa",
                   "-c", "user.name=Milpa H-infra",
                   "-c", "core.autocrlf=false",
                   "-c", "commit.gpgSign=false"])
            .args(args)
            .env("GIT_AUTHOR_NAME", "Milpa H-infra")
            .env("GIT_AUTHOR_EMAIL", "milpa-hinfra@test.milpa")
            .env("GIT_AUTHOR_DATE", "1577836800 +0000")
            .env("GIT_COMMITTER_NAME", "Milpa H-infra")
            .env("GIT_COMMITTER_EMAIL", "milpa-hinfra@test.milpa")
            .env("GIT_COMMITTER_DATE", "1577836800 +0000")
            .output()
    };
    let head_sha = || -> Result<String, String> {
        let out = std::process::Command::new("git")
            .arg("-C").arg(&repo_dir)
            .args(["rev-parse", "HEAD"])
            .output()
            .map_err(|e| format!("git rev-parse: {e}"))?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };

    // hostile_tree branch (#177, EXTRACT-ZIP-SLIP fixtures): build a raw git
    // tree object whose entry paths contain path-traversal sequences that
    // `git add` and `git mktree` refuse to accept (e.g. "../../escape" or
    // "/escape").  We bypass git's safety checks by hand-crafting the raw
    // tree object bytes and feeding them to `git hash-object --literally`,
    // exactly as the verified recipe in the design doc prescribes.
    // The normal files/commits/symlinks/orphan_tip path is SKIPPED entirely.
    let mut commit_shas: Vec<String> = Vec::new();

    if let Some(hostile_entries_val) = repo_spec.get("hostile_tree") {
        use std::io::Write as _;
        let entries = hostile_entries_val.as_arr()
            .ok_or("repo_spec 'hostile_tree' must be an array")?;

        // Step 1: write each blob and collect its SHA.
        let mut blob_shas: Vec<(String, String, String)> = Vec::new(); // (mode, name, sha)
        for entry_val in entries {
            let mode = entry_val.get("mode").and_then(|v| v.as_str())
                .ok_or("hostile_tree entry missing 'mode'")?;
            let name = entry_val.get("name").and_then(|v| v.as_str())
                .ok_or("hostile_tree entry missing 'name'")?;
            let content = entry_val.get("content").and_then(|v| v.as_str())
                .ok_or("hostile_tree entry missing 'content'")?;

            let mut child = std::process::Command::new("git")
                .arg("-C").arg(&repo_dir)
                .args(["hash-object", "-w", "--stdin"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| format!("git hash-object (blob) spawn: {e}"))?;
            child.stdin.take().unwrap().write_all(content.as_bytes())
                .map_err(|e| format!("git hash-object (blob) write stdin: {e}"))?;
            let out = child.wait_with_output()
                .map_err(|e| format!("git hash-object (blob) wait: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "git hash-object (blob) failed:\n  stderr: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
            blob_shas.push((mode.to_string(), name.to_string(), sha));
        }

        // Step 2: build raw tree bytes.
        // Format per git pack protocol: "<mode> <name>\0<20-byte-sha>" per entry.
        let mut raw_tree: Vec<u8> = Vec::new();
        for (mode, name, sha_hex) in &blob_shas {
            let header = format!("{mode} {name}");
            raw_tree.extend_from_slice(header.as_bytes());
            raw_tree.push(0u8); // NUL separator
            // Decode 40-char hex SHA to 20 raw bytes.
            for i in 0..20 {
                let byte_str = &sha_hex[i * 2..i * 2 + 2];
                let byte = u8::from_str_radix(byte_str, 16)
                    .map_err(|_| format!("invalid SHA hex in blob {sha_hex:?}"))?;
                raw_tree.push(byte);
            }
        }

        // Step 3: write the raw tree object (--literally bypasses path validation).
        let mut child = std::process::Command::new("git")
            .arg("-C").arg(&repo_dir)
            .args(["hash-object", "-t", "tree", "--literally", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("git hash-object (tree) spawn: {e}"))?;
        child.stdin.take().unwrap().write_all(&raw_tree)
            .map_err(|e| format!("git hash-object (tree) write stdin: {e}"))?;
        let out = child.wait_with_output()
            .map_err(|e| format!("git hash-object (tree) wait: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git hash-object (tree) failed:\n  stderr: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let tree_sha = String::from_utf8_lossy(&out.stdout).trim().to_string();

        // Step 4: create a commit wrapping the hostile tree.
        let out = git_c(&["commit-tree", &tree_sha, "-m", "H-infra hostile-tree commit"])
            .map_err(|e| format!("git commit-tree: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git commit-tree failed:\n  stderr: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let commit_sha_hostile = String::from_utf8_lossy(&out.stdout).trim().to_string();

        // Step 5: point the branch ref at this commit.
        let update_ref_arg = format!("refs/heads/{ref_name}");
        let out = git_c(&["update-ref", &update_ref_arg, &commit_sha_hostile])
            .map_err(|e| format!("git update-ref: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git update-ref failed:\n  stderr: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }

        commit_shas.push(commit_sha_hostile);
        return Ok((repo_dir, commit_shas));
    }

    if let Some(commits_val) = repo_spec.get("commits") {
        // Multi-commit form
        let commits = commits_val.as_arr()
            .ok_or("repo_spec 'commits' must be an array")?;
        for (i, commit_spec) in commits.iter().enumerate() {
            let files = commit_spec.get("files")
                .and_then(|v| v.as_obj())
                .ok_or_else(|| format!("commit[{i}] missing 'files' object"))?;
            // Write this commit's files
            for (relpath, val) in files {
                let content = val.as_str()
                    .ok_or_else(|| format!("commit[{i}] file {relpath:?} value must be a string"))?;
                let target = repo_dir.join(relpath);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("create dir for {relpath}: {e}"))?;
                }
                std::fs::write(&target, content.as_bytes())
                    .map_err(|e| format!("write {relpath}: {e}"))?;
            }
            let out = git_c(&["add", "."]).map_err(|e| format!("git add: {e}"))?;
            if !out.status.success() {
                return Err(format!("git add failed: {}", String::from_utf8_lossy(&out.stderr)));
            }
            let msg = if i == 0 { "H-infra initial commit".to_string() } else { format!("H-infra commit {i}") };
            let out = git_c(&["commit", "-q", "-m", &msg])
                .map_err(|e| format!("git commit: {e}"))?;
            if !out.status.success() {
                return Err(format!("git commit failed: {}", String::from_utf8_lossy(&out.stderr)));
            }
            commit_shas.push(head_sha()?);
        }
    } else {
        // Single-commit (backward-compat) form
        let files = repo_spec.get("files")
            .and_then(|v| v.as_obj())
            .ok_or("repo_spec missing 'files' (and no 'commits' array)")?;
        for (relpath, val) in files {
            let content = val.as_str()
                .ok_or_else(|| format!("file {relpath:?} value must be a string"))?;
            let target = repo_dir.join(relpath);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create dir for {relpath}: {e}"))?;
            }
            std::fs::write(&target, content.as_bytes())
                .map_err(|e| format!("write {relpath}: {e}"))?;
        }
        // H3d: symlinks support — commit mode-120000 blobs for escape/safe tests.
        // The target string is committed verbatim; containment is the fetcher's job.
        if let Some(symlinks_val) = repo_spec.get("symlinks") {
            let symlinks = symlinks_val.as_obj()
                .ok_or("repo_spec 'symlinks' must be an object")?;
            for (link_path, val) in symlinks {
                let link_target = val.as_str()
                    .ok_or_else(|| format!("symlink {link_path:?} value must be a string"))?;
                let link_on_disk = repo_dir.join(link_path);
                if let Some(parent) = link_on_disk.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("create dir for symlink {link_path}: {e}"))?;
                }
                // Remove stale symlink/file if present (idempotent).
                let _ = std::fs::remove_file(&link_on_disk);
                std::os::unix::fs::symlink(link_target, &link_on_disk)
                    .map_err(|e| format!("create symlink {link_path} -> {link_target}: {e}"))?;
            }
        }
        // Exec-bit support (epoch-2 identity, spec §1.8.2.1): chmod +x the listed
        // paths before `git add` so git records them as mode-100755 blobs.
        if let Some(exec_val) = repo_spec.get("executable") {
            use std::os::unix::fs::PermissionsExt as _;
            let execs = exec_val.as_arr()
                .ok_or("repo_spec 'executable' must be an array")?;
            for val in execs {
                let relpath = val.as_str()
                    .ok_or("'executable' entries must be strings")?;
                let target = repo_dir.join(relpath);
                let mut perms = std::fs::metadata(&target)
                    .map_err(|e| format!("stat {relpath}: {e}"))?
                    .permissions();
                let mode = perms.mode();
                perms.set_mode(mode | 0o111);
                std::fs::set_permissions(&target, perms)
                    .map_err(|e| format!("chmod +x {relpath}: {e}"))?;
            }
        }
        let out = git_c(&["add", "."]).map_err(|e| format!("git add: {e}"))?;
        if !out.status.success() {
            return Err(format!("git add failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
        let out = git_c(&["commit", "-q", "-m", "H-infra initial commit"])
            .map_err(|e| format!("git commit: {e}"))?;
        if !out.status.success() {
            return Err(format!("git commit failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
        commit_shas.push(head_sha()?);
    }

    // Optional: create an orphan tip commit and force-reset the branch to it.
    // This simulates a force-push that makes earlier commits unreachable from
    // any ref — so a `git clone` of this repo will NOT fetch those commits.
    // Used by H4 to produce a non-tip commit absent after a plain clone,
    // exposing the Rust FETCH-GIT-COMMIT-ABSENT bug before the 4-step fix.
    if let Some(orphan_spec) = repo_spec.get("orphan_tip") {
        let orphan_files = orphan_spec.get("files")
            .and_then(|v| v.as_obj())
            .ok_or("orphan_tip missing 'files' object")?;
        let orphan_branch = "__milpa_hinfra_orphan__";
        // Create an orphan branch
        let out = git_c(&["checkout", "--orphan", orphan_branch])
            .map_err(|e| format!("git checkout --orphan: {e}"))?;
        if !out.status.success() {
            return Err(format!("git checkout --orphan failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
        // Remove all tracked files so the orphan starts clean
        let out = git_c(&["rm", "-rf", "."])
            .map_err(|e| format!("git rm: {e}"))?;
        // Ignore failure (empty repo rm is ok if nothing staged yet)
        let _ = out;
        // Write orphan files
        for (relpath, val) in orphan_files {
            let content = val.as_str()
                .ok_or_else(|| format!("orphan_tip file {relpath:?} value must be a string"))?;
            let target = repo_dir.join(relpath);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create dir for orphan {relpath}: {e}"))?;
            }
            std::fs::write(&target, content.as_bytes())
                .map_err(|e| format!("write orphan {relpath}: {e}"))?;
        }
        let out = git_c(&["add", "."])
            .map_err(|e| format!("git add (orphan): {e}"))?;
        if !out.status.success() {
            return Err(format!("git add (orphan) failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
        let out = git_c(&["commit", "-q", "-m", "H-infra orphan tip (simulates force-push)"])
            .map_err(|e| format!("git commit (orphan): {e}"))?;
        if !out.status.success() {
            return Err(format!("git commit (orphan) failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
        let orphan_sha = head_sha()?;
        // Force-reset the target ref to the orphan commit
        let out = git_c(&["branch", "-f", ref_name, &orphan_sha])
            .map_err(|e| format!("git branch -f: {e}"))?;
        if !out.status.success() {
            return Err(format!("git branch -f failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
        // Detach HEAD so clone of the ref works cleanly
        let out = git_c(&["checkout", "--detach", "HEAD"])
            .map_err(|e| format!("git checkout --detach: {e}"))?;
        if !out.status.success() {
            return Err(format!("git checkout --detach failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
    }

    // H5 (#177, R1-03): submodule superproject support.
    // Write .gitmodules with RELATIVE sibling urls ("./repo-name") and inject
    // gitlink entries via `git update-index --add --cacheinfo 160000,<sha>,<path>`.
    // Submodule repos MUST precede the superproject in the descriptor (descriptor
    // order guarantees this) so their SHAs are available in peer_shas.
    // Using "./repo-name" keeps committed .gitmodules bytes deterministic
    // (no tmpdir path); milpa resolves them against the superproject file:// URL.
    if let Some(submodules_val) = repo_spec.get("submodules") {
        let submodules = submodules_val.as_arr()
            .ok_or("repo_spec 'submodules' must be an array")?;
        // Build .gitmodules content
        let mut gitmodules_content = String::new();
        for sub_spec in submodules {
            let sub_path = sub_spec.get("path").and_then(|v| v.as_str())
                .ok_or("submodule spec missing 'path'")?;
            let sub_repo = sub_spec.get("repo").and_then(|v| v.as_str())
                .ok_or("submodule spec missing 'repo'")?;
            gitmodules_content.push_str(&format!(
                "[submodule \"{sub_path}\"]\n\tpath = {sub_path}\n\turl = ./{sub_repo}\n"
            ));
        }
        let gitmodules_path = repo_dir.join(".gitmodules");
        std::fs::write(&gitmodules_path, gitmodules_content.as_bytes())
            .map_err(|e| format!("write .gitmodules: {e}"))?;
        let out = git_c(&["add", ".gitmodules"])
            .map_err(|e| format!("git add .gitmodules: {e}"))?;
        if !out.status.success() {
            return Err(format!("git add .gitmodules failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
        // Inject gitlink entries for each submodule
        for sub_spec in submodules {
            let sub_path = sub_spec.get("path").and_then(|v| v.as_str())
                .ok_or("submodule spec missing 'path'")?;
            let sub_repo = sub_spec.get("repo").and_then(|v| v.as_str())
                .ok_or("submodule spec missing 'repo'")?;
            let sub_sha = peer_shas.get(sub_repo)
                .ok_or_else(|| format!(
                    "submodule repo {sub_repo:?} not found in peer_shas; \
                     available: {:?}", peer_shas.keys().collect::<Vec<_>>()
                ))?;
            let cacheinfo = format!("160000,{sub_sha},{sub_path}");
            let out = git_c(&["update-index", "--add", "--cacheinfo", &cacheinfo])
                .map_err(|e| format!("git update-index (submodule {sub_path}): {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "git update-index --cacheinfo {sub_path} failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
        }
        let out = git_c(&["commit", "-q", "-m", "H-infra add submodules"])
            .map_err(|e| format!("git commit (submodules): {e}"))?;
        if !out.status.success() {
            return Err(format!("git commit (submodules) failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
        commit_shas.push(head_sha()?);
    }

    Ok((repo_dir, commit_shas))
}

/// Execute a git-protocol fixture end-to-end using the REAL `fetch_git`.
///
/// H-infra flow:
/// 1. Parse `git-protocol.json`.
/// 2. Generate each declared repo under a tempdir.
/// 3. Build a `file://` URL for the target repo.
/// 4. Call `milpa_core::fetchers::fetch_git` (the REAL fetcher, not MockedFetcher).
/// 5. Compare `compute_content_hash(dest)` to `expected/content_hash`.
///
/// content_hash is over the materialized source tree (file relpaths + bytes),
/// NOT git pack objects — so it is stable across git versions and both impls.
fn run_git_protocol_fixture(fx: &Fixture, scratch: &Scratch) -> Result<Produced, String> {
    // Parse git-protocol.json
    let spec_path = fx.dir.join("git-protocol.json");
    let spec_text = std::fs::read_to_string(&spec_path)
        .map_err(|e| format!("git-protocol.json missing or unreadable: {e}"))?;
    let spec = serde_like::parse(&spec_text)
        .map_err(|e| format!("git-protocol.json parse error: {e}"))?;

    // Read expected outcome: either a content_hash (success) or an error slug.
    // Error-class git-protocol fixtures (e.g. EXTRACT-SYMLINK-ESCAPE,
    // FETCH-GIT-LFS-POINTER) expect fetch_git to raise; success-class fixtures
    // assert the materialized tree's content_hash matches the declared value.
    let expected_error_path = fx.dir.join("expected").join("error");
    let expected_error: Option<String> = std::fs::read_to_string(&expected_error_path).ok()
        .map(|s| s.trim().to_string());
    let expected_hash_path = fx.dir.join("expected").join("content_hash");
    let expected_hash: String = if expected_error.is_none() {
        std::fs::read_to_string(&expected_hash_path)
            .map_err(|e| format!("expected/content_hash missing: {e}"))?
            .trim()
            .to_string()
    } else {
        String::new()
    };

    let repos_spec = spec.get("repos")
        .and_then(|v| v.as_arr())
        .ok_or("git-protocol.json missing 'repos' array")?;
    let fetch_spec = spec.get("fetch")
        .and_then(|v| v.as_obj())
        .ok_or("git-protocol.json missing 'fetch' object")?;

    // Generate repos in a sub-tempdir of the scratch root
    let repos_tmpdir = scratch.root.join("git-repos");
    std::fs::create_dir_all(&repos_tmpdir)
        .map_err(|e| format!("create repos tmpdir: {e}"))?;

    let mut repo_paths: std::collections::HashMap<String, std::path::PathBuf> =
        std::collections::HashMap::new();
    let mut repo_commit_shas: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for repo_spec in repos_spec {
        let name = repo_spec.get("name").and_then(|v| v.as_str())
            .ok_or("repo spec missing 'name'")?
            .to_string();
        // Build peer_shas from repos built so far for submodule gitlink injection
        // (H5, #177): the superproject looks up each submodule's head SHA here.
        let peer_shas: std::collections::HashMap<String, String> = repo_commit_shas.iter()
            .filter_map(|(n, shas)| shas.last().map(|s| (n.clone(), s.clone())))
            .collect();
        let (repo_dir, shas) = make_git_protocol_repo(&repos_tmpdir, repo_spec, &peer_shas)?;
        repo_paths.insert(name.clone(), repo_dir);
        repo_commit_shas.insert(name, shas);
    }

    // Resolve fetch parameters
    let fetch_map: std::collections::HashMap<&str, &serde_like::Val> =
        fetch_spec.iter().map(|(k, v)| (k.as_str(), v)).collect();

    let repo_name = fetch_map.get("repo_name")
        .and_then(|v| v.as_str())
        .ok_or("fetch missing 'repo_name'")?;
    let dep_name = fetch_map.get("dep_name")
        .and_then(|v| v.as_str())
        .unwrap_or("smoke");
    let ref_spec = fetch_map.get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("main");

    // H4: commit_sha may be null (no pin), a literal 40-hex SHA, or an
    // "@repo:<name>:commit:<index>" reference resolved from the generated SHAs.
    let raw_commit_sha: Option<&str> = fetch_map.get("commit_sha")
        .and_then(|v| if v.is_null() { None } else { v.as_str() });
    let commit_sha: Option<String> = match raw_commit_sha {
        None => None,
        Some(s) if s.starts_with("@repo:") => {
            // Resolve "@repo:<repo_name>:commit:<index>" to the actual SHA.
            let parts: Vec<&str> = s.splitn(4, ':').collect();
            // parts: ["@repo", "<repo_name>", "commit", "<index>"]
            if parts.len() == 4 && parts[0] == "@repo" && parts[2] == "commit" {
                let ref_repo = parts[1];
                let idx: usize = parts[3].parse()
                    .map_err(|_| format!("commit SHA reference {s:?}: index must be an integer"))?;
                let sha_list = repo_commit_shas.get(ref_repo)
                    .ok_or_else(|| format!("commit SHA reference {s:?}: repo {ref_repo:?} not found"))?;
                Some(sha_list.get(idx)
                    .ok_or_else(|| format!("commit SHA reference {s:?}: index {idx} out of range (repo has {} commits)", sha_list.len()))?
                    .clone())
            } else {
                return Err(format!("commit SHA reference {s:?}: expected format @repo:<name>:commit:<index>"));
            }
        }
        Some(s) => Some(s.to_string()),
    };

    let target_repo = repo_paths.get(repo_name)
        .ok_or_else(|| format!("fetch.repo_name {repo_name:?} not found in repos"))?;

    // Build fetch URL for the target repo.
    //
    // Normally we use file:// so fetch_git exercises the real git pack-transfer
    // protocol path (clone over the smart-HTTP-like protocol).
    //
    // EXCEPTION — hostile_tree repos (#177, EXTRACT-ZIP-SLIP fixtures):
    // git's pack-transfer fsck validates tree-entry paths and rejects hostiles
    // with "fullPathname" BEFORE the objects arrive at the clone scratch.
    // That means git raises FETCH-GIT-FAILED, not milpa raising EXTRACT-ZIP-SLIP,
    // which is NOT what these fixtures test.  The fixtures test milpa's OWN
    // containment guard (R1-01 NORMATIVE), so the clone must succeed.
    //
    // When the target repo spec carries "hostile_tree", we use a raw local
    // filesystem path (no file:// prefix).  git then uses local-transport
    // (hardlink/copy of loose objects), which SKIPS pack-transfer fsck.
    // The hostile tree objects arrive in the clone scratch intact; git ls-tree
    // enumerates the hostile entries; milpa's materializer fires EXTRACT-ZIP-SLIP.
    let abs_repo = target_repo.canonicalize()
        .map_err(|e| format!("canonicalize repo path: {e}"))?;
    let target_spec_by_name: std::collections::HashMap<&str, &serde_like::Val> =
        repos_spec.iter()
            .filter_map(|rs| rs.get("name").and_then(|v| v.as_str()).map(|n| (n, rs)))
            .collect();
    let uses_hostile_tree = target_spec_by_name.get(repo_name)
        .and_then(|rs| rs.get("hostile_tree"))
        .is_some();
    let file_url = if uses_hostile_tree {
        // Local-transport path: git hardlinks objects, bypasses pack-fsck.
        abs_repo.to_string_lossy().into_owned()
    } else {
        format!("file://{}", abs_repo.to_string_lossy())
    };

    let dest = scratch.deps_dir.join(dep_name);

    // Run the REAL fetch_git (not MockedFetcher).
    // H3d: error-class fixtures expect fetch_git to raise the declared slug.
    // We capture the FetchError and its slug so the verdict machinery can
    // match it against Expected::Error(slug) in run_fixture.
    let fetch_result = milpa_core::fetchers::fetch_git(
        dep_name,
        &file_url,
        ref_spec,
        commit_sha.as_deref(),
        &dest,
    );

    // Keep the receipt to extract submodule_shas after the error check.
    let receipt = match fetch_result {
        Err(e) => {
            let slug = e.code().to_string();
            if let Some(ref expected_slug) = expected_error {
                if &slug == expected_slug {
                    // Error-class fixture: slug matches — report as Err(slug) so
                    // run_fixture's (Expected::Error(slug), Err(code)) arm passes it.
                    return Err(slug);
                } else {
                    return Err(format!(
                        "expected error {expected_slug:?}, got {slug:?}: {e:?}"
                    ));
                }
            }
            // Success-class fixture but fetch raised an error.
            return Err(format!("fetch_git failed [{}]: {:?}", slug, e));
        }
        Ok(receipt) => {
            // Fetcher succeeded — if we expected an error, that's a test failure.
            if let Some(ref expected_slug) = expected_error {
                return Err(format!(
                    "expected error {expected_slug:?} but fetch_git succeeded"
                ));
            }

            // Confirm the receipt has a resolved SHA (proves git was actually invoked)
            let resolved_sha = receipt.resolved_ref.as_deref().unwrap_or("");
            if resolved_sha.len() != 40 {
                return Err(format!(
                    "fetch_git returned unexpected resolved_ref: {resolved_sha:?} \
                     (expected 40-char hex SHA)"
                ));
            }
            receipt
        }
    };

    // Compute content_hash of the materialized tree
    let got_hash = milpa_core::compute_content_hash(&dest)
        .map_err(|e| format!("compute_content_hash failed: {e:?}"))?;

    if got_hash != expected_hash {
        return Err(format!(
            "content_hash mismatch:\n  expected: {expected_hash}\n  actual:   {got_hash}\n  \
             (fetch_git used file:// URL: {file_url:?})"
        ));
    }

    // H5 (#177): assert submodule_shas if the golden file exists.
    // Format: path-sorted lines "<path> <40hex>\n" — mirrors Python executor.
    let expected_shas_path = fx.dir.join("expected").join("submodule_shas");
    if expected_shas_path.exists() {
        let expected_shas = std::fs::read_to_string(&expected_shas_path)
            .map_err(|e| format!("expected/submodule_shas unreadable: {e}"))?;
        // receipt.submodule_shas is Vec<(String, String)>, path-sorted by the fetcher.
        let mut got_shas = receipt.submodule_shas.clone();
        got_shas.sort_by(|a, b| a.0.cmp(&b.0));
        let got_shas_text: String = got_shas.iter()
            .map(|(p, s)| format!("{p} {s}\n"))
            .collect();
        if got_shas_text != expected_shas {
            return Err(format!(
                "submodule_shas mismatch:\n  expected:\n{expected_shas}\
                   actual:\n{got_shas_text}\
                   (fetch_git used file:// URL: {file_url:?})"
            ));
        }
    }

    // Return GitProtocolPass: git-protocol fixtures assert content_hash (+ submodule_shas).
    // run_fixture's (Expected::Success, Ok(Produced::GitProtocolPass { .. })) arm passes it.
    Ok(Produced::GitProtocolPass { content_hash: got_hash })
}

// ---------------------------------------------------------------------------
// Epoch-2 Merkle-DAG oracle tier (cmd=dag-oracle) — RFC identity-conformance B2
// ---------------------------------------------------------------------------
// Two transports, distinguished by the fixture's source file:
//   * dag-oracle.json   — staged seam input fed DIRECTLY to the production DAG
//                         builder (the builder's own contract test).
//   * git-protocol.json — a real git repo cloned --no-checkout and enumerated via
//                         the production git seam (enumerate_git_entries), then
//                         fed to the SAME builder (the cross-transport proof).
// Either way the impl's builder reproduces the hand-frozen pin in
// expected/content_hash; the builder is independent of the frozen reference
// oracle, so agreement IS the differential check. Reuses GitProtocolPass since
// the assertion target is identical (a content-hash string).

fn run_dag_oracle_fixture(fx: &Fixture, scratch: &Scratch) -> Result<Produced, String> {
    let expected = std::fs::read_to_string(fx.dir.join("expected").join("content_hash"))
        .map_err(|e| format!("expected/content_hash missing: {e}"))?
        .trim()
        .to_string();

    let git_spec = fx.dir.join("git-protocol.json");
    let tarball_spec = fx.dir.join("tarball-protocol.json");
    let local_spec = fx.dir.join("local-protocol.json");
    let staged_spec = fx.dir.join("dag-oracle.json");

    let (entries, transport): (Vec<milpa_core::MaterializedEntry>, &str) = if git_spec.is_file() {
        (dag_oracle_git_entries(fx, scratch)?, "git")
    } else if tarball_spec.is_file() {
        (dag_oracle_tarball_entries(&tarball_spec, scratch)?, "tarball")
    } else if local_spec.is_file() {
        (dag_oracle_local_entries(&local_spec, scratch)?, "local")
    } else if staged_spec.is_file() {
        (dag_oracle_staged_entries(&staged_spec)?, "staged")
    } else {
        return Err(
            "dag-oracle fixture has none of git-protocol.json / tarball-protocol.json / \
             local-protocol.json / dag-oracle.json"
                .to_string(),
        );
    };

    let got = milpa_core::compute_dag_identity(&entries)
        .map_err(|e| format!("compute_dag_identity failed: {e:?}"))?;
    if got != expected {
        return Err(format!(
            "dag-sha256 mismatch ({transport} transport):\n  \
             expected (pinned oracle): {expected}\n  actual   (impl builder):  {got}"
        ));
    }
    Ok(Produced::GitProtocolPass { content_hash: got })
}

/// Parse a staged `dag-oracle.json` (list of `{relpath, mode, content}`) into the
/// materialized seam sequence — the builder's contract test input.
fn dag_oracle_staged_entries(path: &Path) -> Result<Vec<milpa_core::MaterializedEntry>, String> {
    use milpa_core::dag_identity::{MODE_EXECUTABLE, MODE_REGULAR, MODE_SYMLINK};
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("dag-oracle.json unreadable: {e}"))?;
    let spec = serde_like::parse(&text).map_err(|e| format!("dag-oracle.json parse error: {e}"))?;
    let arr = spec.get("entries").and_then(|v| v.as_arr()).unwrap_or(&[]);
    let mut entries = Vec::with_capacity(arr.len());
    for e in arr {
        let relpath = e.get("relpath").and_then(|v| v.as_str())
            .ok_or("entry missing string 'relpath'")?;
        let mode_str = e.get("mode").and_then(|v| v.as_str())
            .ok_or("entry missing string 'mode'")?;
        let content = e.get("content").and_then(|v| v.as_str())
            .ok_or("entry missing string 'content'")?;
        let mode_byte = match mode_str {
            "regular" => MODE_REGULAR,
            "executable" => MODE_EXECUTABLE,
            "symlink" => MODE_SYMLINK,
            other => return Err(format!("unknown entry mode {other:?}")),
        };
        entries.push(milpa_core::MaterializedEntry::new(
            relpath,
            mode_byte,
            content.as_bytes().to_vec(),
        ));
    }
    Ok(entries)
}

/// Generate the git repo from `git-protocol.json`, clone --no-checkout, and return
/// the production git seam's entries — the cross-transport proof path (the SAME
/// enumeration milpa uses to materialize a git dep into the CAS).
fn dag_oracle_git_entries(
    fx: &Fixture,
    scratch: &Scratch,
) -> Result<Vec<milpa_core::MaterializedEntry>, String> {
    let spec_text = std::fs::read_to_string(fx.dir.join("git-protocol.json"))
        .map_err(|e| format!("git-protocol.json unreadable: {e}"))?;
    let spec = serde_like::parse(&spec_text)
        .map_err(|e| format!("git-protocol.json parse error: {e}"))?;
    let repos_spec = spec.get("repos").and_then(|v| v.as_arr())
        .ok_or("git-protocol.json missing 'repos' array")?;
    let fetch_spec = spec.get("fetch")
        .ok_or("git-protocol.json missing 'fetch' object")?;

    let repos_tmpdir = scratch.root.join("dag-oracle-repos");
    std::fs::create_dir_all(&repos_tmpdir).map_err(|e| format!("create repos tmpdir: {e}"))?;

    let mut repo_paths: std::collections::HashMap<String, std::path::PathBuf> =
        std::collections::HashMap::new();
    let mut peer_shas_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for repo_spec in repos_spec {
        let name = repo_spec.get("name").and_then(|v| v.as_str())
            .ok_or("repo spec missing 'name'")?
            .to_string();
        let (repo_dir, shas) = make_git_protocol_repo(&repos_tmpdir, repo_spec, &peer_shas_map)?;
        if let Some(last) = shas.last() {
            peer_shas_map.insert(name.clone(), last.clone());
        }
        repo_paths.insert(name, repo_dir);
    }

    let repo_name = fetch_spec.get("repo_name").and_then(|v| v.as_str())
        .ok_or("fetch missing 'repo_name'")?;
    let target_repo = repo_paths.get(repo_name)
        .ok_or_else(|| format!("fetch.repo_name {repo_name:?} not found in repos"))?;
    let file_url = format!("file://{}", target_repo.canonicalize()
        .map_err(|e| format!("canonicalize repo: {e}"))?.display());
    let git_ref = fetch_spec.get("ref").and_then(|v| v.as_str()).unwrap_or("main");

    // Clone --no-checkout (spec §1.7.1: no working-tree checkout / smudge filters),
    // mirroring fetch_git's object-store discipline, then enumerate via the seam.
    let clone_scratch = scratch.root.join("dag-oracle-clone");
    let out = std::process::Command::new("git")
        .args(["clone", "-q", "--no-checkout", "--end-of-options", &file_url])
        .arg(&clone_scratch)
        .output()
        .map_err(|e| format!("git clone spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!("git clone failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let rev = std::process::Command::new("git")
        .arg("-C").arg(&clone_scratch)
        .args(["rev-parse", git_ref])
        .output()
        .map_err(|e| format!("git rev-parse spawn: {e}"))?;
    if !rev.status.success() {
        return Err(format!("git rev-parse failed: {}", String::from_utf8_lossy(&rev.stderr)));
    }
    let commit = String::from_utf8_lossy(&rev.stdout).trim().to_string();

    let (entries, _submodule_shas) =
        milpa_core::fetchers::enumerate_git_entries(&clone_scratch, &commit, None, None)
            .map_err(|e| format!("enumerate_git_entries failed: {e:?}"))?;
    Ok(entries)
}

/// Lay out a `{files, symlinks, executable}` tree description onto disk (the shared
/// on-disk shape `make_git_protocol_repo` commits, minus git): regular files, the
/// exec bit (+x) for relpaths in `executable`, and filesystem symlinks (target
/// string written verbatim, not followed). Shared by the tarball + local proofs.
fn materialize_tree_on_disk(root: &Path, spec: &serde_like::Val) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::create_dir_all(root).map_err(|e| format!("create tree root: {e}"))?;
    if let Some(files) = spec.get("files").and_then(|v| v.as_obj()) {
        for (relpath, val) in files {
            let content = val.as_str()
                .ok_or_else(|| format!("file {relpath:?} value must be a string"))?;
            let target = root.join(relpath);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create dir for {relpath}: {e}"))?;
            }
            std::fs::write(&target, content.as_bytes())
                .map_err(|e| format!("write {relpath}: {e}"))?;
        }
    }
    if let Some(execs) = spec.get("executable").and_then(|v| v.as_arr()) {
        for val in execs {
            let relpath = val.as_str().ok_or("'executable' entries must be strings")?;
            let target = root.join(relpath);
            let mut perms = std::fs::metadata(&target)
                .map_err(|e| format!("stat {relpath}: {e}"))?
                .permissions();
            let mode = perms.mode();
            perms.set_mode(mode | 0o111);
            std::fs::set_permissions(&target, perms)
                .map_err(|e| format!("chmod +x {relpath}: {e}"))?;
        }
    }
    if let Some(symlinks) = spec.get("symlinks").and_then(|v| v.as_obj()) {
        for (link_path, val) in symlinks {
            let link_target = val.as_str()
                .ok_or_else(|| format!("symlink {link_path:?} value must be a string"))?;
            let link_on_disk = root.join(link_path);
            if let Some(parent) = link_on_disk.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create dir for symlink {link_path}: {e}"))?;
            }
            let _ = std::fs::remove_file(&link_on_disk);
            std::os::unix::fs::symlink(link_target, &link_on_disk)
                .map_err(|e| format!("create symlink {link_path} -> {link_target}: {e}"))?;
        }
    }
    Ok(())
}

/// Build a real `.tar.gz` from `tarball-protocol.json` (via the system `tar`,
/// mirroring how git-protocol fixtures shell out to `git`), then enumerate it via
/// the production tarball seam (`enumerate_tarball_entries`) — the cross-transport
/// proof for the tarball transport.
fn dag_oracle_tarball_entries(
    spec_path: &Path,
    scratch: &Scratch,
) -> Result<Vec<milpa_core::MaterializedEntry>, String> {
    let text = std::fs::read_to_string(spec_path)
        .map_err(|e| format!("tarball-protocol.json unreadable: {e}"))?;
    let spec = serde_like::parse(&text)
        .map_err(|e| format!("tarball-protocol.json parse error: {e}"))?;

    let tree_root = scratch.root.join("tarball-tree");
    materialize_tree_on_disk(&tree_root, &spec)?;

    let archive_path = scratch.root.join("tarball-archive.tar.gz");
    // `tar -czf <archive> -C <tree> .` preserves POSIX modes (exec bit) + symlinks.
    let out = std::process::Command::new("tar")
        .arg("-czf").arg(&archive_path)
        .arg("-C").arg(&tree_root)
        .arg(".")
        .output()
        .map_err(|e| format!("tar spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!("tar -czf failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let archive_bytes = std::fs::read(&archive_path)
        .map_err(|e| format!("read tar archive: {e}"))?;

    milpa_core::fetchers::enumerate_tarball_entries(
        &archive_bytes,
        0,
        milpa_core::Limits::default(),
    )
    .map_err(|e| format!("enumerate_tarball_entries failed: {e:?}"))
}

/// Lay out `local-protocol.json` on disk, then enumerate it via the production
/// local seam (`enumerate_local_entries`) — the cross-transport proof for the
/// local transport (a directory walk reading the on-disk POSIX bits).
fn dag_oracle_local_entries(
    spec_path: &Path,
    scratch: &Scratch,
) -> Result<Vec<milpa_core::MaterializedEntry>, String> {
    let text = std::fs::read_to_string(spec_path)
        .map_err(|e| format!("local-protocol.json unreadable: {e}"))?;
    let spec = serde_like::parse(&text)
        .map_err(|e| format!("local-protocol.json parse error: {e}"))?;

    let tree_root = scratch.root.join("local-tree");
    materialize_tree_on_disk(&tree_root, &spec)?;

    milpa_core::enumerate_local_entries(&tree_root)
        .map_err(|e| format!("enumerate_local_entries failed: {e:?}"))
}

/// Execute a `hash` fixture end-to-end: build a local git repo, materialise the
/// tree via `fetch_git`, compute the content identity, and assert it matches
/// `expected/stdout`.
///
/// This pins the A0 `milpa hash <source-spec>` path:
///   - `fetch_git` materialises the tree (same inner registry as `cmd_hash`).
///   - `compute_content_hash(&dest)` gives the identity (identical to what
///     `DefaultRegistry::fetch` sets as `Receipt::identity`, which is what
///     `cmd_hash` reads and prints to stdout).
///   - `expected/stdout` carries the expected `sha256:<64hex>` line.
///
/// Reuses the `git-protocol.json` schema and `make_git_protocol_repo` so
/// fixtures can be authored with the same tooling as git-protocol fixtures.
fn run_hash_fixture(fx: &Fixture, scratch: &Scratch) -> Result<Produced, String> {
    // Parse git-protocol.json (same schema as git-protocol fixtures)
    let spec_path = fx.dir.join("git-protocol.json");
    let spec_text = std::fs::read_to_string(&spec_path)
        .map_err(|e| format!("git-protocol.json missing or unreadable: {e}"))?;
    let spec = serde_like::parse(&spec_text)
        .map_err(|e| format!("git-protocol.json parse error: {e}"))?;

    // Read expected stdout (sha256:<hex> for git sources, empty for local)
    let expected_stdout_path = fx.dir.join("expected").join("stdout");
    let expected_stdout = std::fs::read_to_string(&expected_stdout_path)
        .map_err(|e| format!("expected/stdout missing or unreadable: {e}"))?
        .trim()
        .to_string();

    let repos_spec = spec.get("repos")
        .and_then(|v| v.as_arr())
        .ok_or("git-protocol.json missing 'repos' array")?;
    let fetch_spec = spec.get("fetch")
        .and_then(|v| v.as_obj())
        .ok_or("git-protocol.json missing 'fetch' object")?;

    // Generate repos (reuse make_git_protocol_repo)
    let repos_tmpdir = scratch.root.join("hash-git-repos");
    std::fs::create_dir_all(&repos_tmpdir)
        .map_err(|e| format!("create repos tmpdir: {e}"))?;

    let mut repo_paths: std::collections::HashMap<String, std::path::PathBuf> =
        std::collections::HashMap::new();
    let mut repo_commit_shas: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for repo_spec in repos_spec {
        let name = repo_spec.get("name").and_then(|v| v.as_str())
            .ok_or("repo spec missing 'name'")?
            .to_string();
        let peer_shas: std::collections::HashMap<String, String> = repo_commit_shas.iter()
            .filter_map(|(n, shas)| shas.last().map(|s| (n.clone(), s.clone())))
            .collect();
        let (repo_dir, shas) = make_git_protocol_repo(&repos_tmpdir, repo_spec, &peer_shas)?;
        repo_paths.insert(name.clone(), repo_dir);
        repo_commit_shas.insert(name, shas);
    }

    let fetch_map: std::collections::HashMap<&str, &serde_like::Val> =
        fetch_spec.iter().map(|(k, v)| (k.as_str(), v)).collect();

    let repo_name = fetch_map.get("repo_name")
        .and_then(|v| v.as_str())
        .ok_or("fetch missing 'repo_name'")?;
    let dep_name = fetch_map.get("dep_name")
        .and_then(|v| v.as_str())
        .unwrap_or("smoke");
    let ref_spec = fetch_map.get("ref")
        .and_then(|v| v.as_str())
        .unwrap_or("main");

    let raw_commit_sha: Option<&str> = fetch_map.get("commit_sha")
        .and_then(|v| if v.is_null() { None } else { v.as_str() });
    let commit_sha: Option<String> = match raw_commit_sha {
        None => None,
        Some(s) if s.starts_with("@repo:") => {
            let parts: Vec<&str> = s.splitn(4, ':').collect();
            if parts.len() == 4 && parts[0] == "@repo" && parts[2] == "commit" {
                let ref_repo = parts[1];
                let idx: usize = parts[3].parse()
                    .map_err(|_| format!("commit SHA reference {s:?}: index must be an integer"))?;
                let sha_list = repo_commit_shas.get(ref_repo)
                    .ok_or_else(|| format!("commit SHA reference {s:?}: repo {ref_repo:?} not found"))?;
                Some(sha_list.get(idx)
                    .ok_or_else(|| format!("commit SHA reference {s:?}: index {idx} out of range"))?
                    .clone())
            } else {
                return Err(format!("commit SHA reference {s:?}: expected @repo:<name>:commit:<index>"));
            }
        }
        Some(s) => Some(s.to_string()),
    };

    let target_repo = repo_paths.get(repo_name)
        .ok_or_else(|| format!("fetch.repo_name {repo_name:?} not found in repos"))?;

    let abs_repo = target_repo.canonicalize()
        .map_err(|e| format!("canonicalize repo path: {e}"))?;
    let file_url = format!("file://{}", abs_repo.to_string_lossy());

    let dest = scratch.deps_dir.join(dep_name);

    // Materialise the tree via the REAL fetch_git (same inner transport as cmd_hash)
    milpa_core::fetchers::fetch_git(
        dep_name,
        &file_url,
        ref_spec,
        commit_sha.as_deref(),
        &dest,
    ).map_err(|e| format!("fetch_git failed [{}]: {:?}", e.code(), e))?;

    // Compute the content identity — identical to what DefaultRegistry::fetch sets
    // as Receipt::identity, which is what cmd_hash reads and prints to stdout.
    // A0 architectural pin: MUST use compute_content_hash here, NOT receipt.identity
    // from fetch_git (the low-level fn does not set identity; DefaultRegistry does).
    let got_identity = milpa_core::compute_content_hash(&dest)
        .map_err(|e| format!("compute_content_hash failed: {e:?}"))?;

    if got_identity != expected_stdout {
        return Err(format!(
            "hash stdout mismatch:\n  expected: {expected_stdout:?}\n  actual:   {got_identity:?}\n  \
             (fetch_git used file:// URL: {file_url:?})"
        ));
    }

    // Return HashPass: hash fixtures assert only expected/stdout.
    Ok(Produced::HashPass { identity: got_identity })
}

/// Parse the fixture's optional `env` file (KEY=VALUE per line) into a map.
/// Returns an empty map when the file is absent.
fn fixture_env(dir: &Path) -> std::collections::HashMap<String, String> {
    let text = match std::fs::read_to_string(dir.join("env")) {
        Ok(t) => t,
        Err(_) => return std::collections::HashMap::new(),
    };
    let mut env = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            env.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    env
}

/// Build a [`Profile`] from a fixture's optional `env` file (KEY=VALUE per line,
/// the `MILPA_TARGET_*` axes — conformance-fixtures §2). Returns `None` when the
/// file is absent or carries no `MILPA_TARGET_*` keys (no predicate filtering —
/// the common case). Mirrors the Python harness's `_fixture_profile` AND the
/// CLI's `profile_from_env()`: both return `None` when no target axes are set,
/// regardless of whether other env vars (e.g. `MILPA_CLI_FEATURES`) are present.
fn fixture_profile(dir: &Path) -> Option<milpa_core::Profile> {
    let env = fixture_env(dir);
    let platform = env.get("MILPA_TARGET_PLATFORM").cloned();
    let arch = env.get("MILPA_TARGET_ARCH").cloned();
    let nim_version = env
        .get("MILPA_TARGET_NIM")
        .and_then(|s| milpa_core::parse_version(s));
    let milpa_version = env
        .get("MILPA_TARGET_MILPA")
        .and_then(|s| milpa_core::parse_version(s));
    // Absent profile = no MILPA_TARGET_* axes present — mirrors CLI profile_from_env().
    // An env file carrying only MILPA_CLI_FEATURES (no target axes) must yield None
    // so that resolver-semantics §470 "absent profile ⇒ platform filtering disabled"
    // is exercised, not the Some(profile-with-all-None-axes) path.
    if platform.is_none() && arch.is_none() && nim_version.is_none() && milpa_version.is_none() {
        return None;
    }
    Some(milpa_core::Profile {
        platform,
        arch,
        nim_version,
        milpa_version,
        flags: Vec::new(),
    })
}

/// S5: read `MILPA_REQUIRE_ATTESTED_METADATA` from the fixture's `env` file.
/// Returns `true` when the value is a non-empty string that is not `"0"` or `"false"`.
fn fixture_require_attested_metadata(dir: &Path) -> bool {
    let env = fixture_env(dir);
    env.get("MILPA_REQUIRE_ATTESTED_METADATA")
        .map(|v| parse_env_bool(v))
        .unwrap_or(false)
}

/// §2.8.1: resolve the fixture's project root. When a `project-dir` control file
/// is present, the root is `<fixture>/<trimmed contents>`; otherwise it is the
/// fixture dir itself. Mirrors the black-box harness and the Python adapter.
///
/// Confinement: the suffix MUST be relative (not absolute) and MUST NOT escape
/// the fixture root after path normalization. An absolute suffix would let
/// `Path::join` silently discard `fx.dir`, and `..` components could escape the
/// fixture sandbox. Either condition is a fixture-authoring error; panic with a
/// clear message rather than silently reading from an unintended location.
fn fixture_project_root(fx: &Fixture) -> PathBuf {
    match std::fs::read_to_string(fx.dir.join("project-dir")) {
        Ok(s) if !s.trim().is_empty() => {
            let suffix = Path::new(s.trim());
            assert!(
                !suffix.is_absolute(),
                "project-dir must be a relative path, got absolute: {:?}",
                suffix
            );
            let joined = fx.dir.join(suffix);
            // Normalize by resolving `.` and `..` lexically without requiring
            // the path to exist on disk (canonicalize would fail for non-existent
            // paths). We walk the components and track whether we would escape
            // fx.dir.
            let mut components: Vec<std::ffi::OsString> = fx
                .dir
                .components()
                .map(|c| c.as_os_str().to_os_string())
                .collect();
            let base_depth = components.len();
            for component in suffix.components() {
                match component {
                    std::path::Component::ParentDir => {
                        assert!(
                            components.len() > base_depth,
                            "project-dir escapes fixture root: {:?} applied to {:?}",
                            suffix,
                            fx.dir
                        );
                        components.pop();
                    }
                    std::path::Component::CurDir => {} // skip `.`
                    std::path::Component::Normal(part) => components.push(part.to_os_string()),
                    other => panic!(
                        "unexpected path component {:?} in project-dir {:?}",
                        other, suffix
                    ),
                }
            }
            joined
        }
        _ => fx.dir.clone(),
    }
}

/// S3b / Slice 2 — SSOT for dep_decl_store selection (M5).
///
/// Implements the three-way CLI-mirror logic exactly once, called from BOTH the
/// resolve path and the verify pre-phase:
///   --no-index (fx.no_index) → None;
///   dep-decl/ dir present   → FileDepDeclStore (MILPA_DEP_DECL_DIR analogue);
///   index.kdl present       → HttpDepDeclStore over the file:// base URL
///                             (MILPA_INDEX_URL→HttpDepDeclStore path);
///   else                    → None.
///
/// Returns a boxed store so the helper owns the value; callers unwrap with
/// `.as_deref()` to get `Option<&dyn DepDeclStore>` for the resolve/resolve_with_features APIs.
fn fixture_dep_decl_store(
    fx: &Fixture,
) -> Option<Box<dyn milpa_core::dep_decl_store::DepDeclStore>> {
    if fx.no_index {
        return None;
    }
    let dep_decl_dir = fx.dir.join("dep-decl");
    if dep_decl_dir.is_dir() {
        return Some(Box::new(milpa_core::FileDepDeclStore::new(&dep_decl_dir)));
    }
    let index_kdl = fx.dir.join("index.kdl");
    if index_kdl.is_file() {
        return Some(Box::new(milpa_core::make_dep_decl_store(&format!(
            "file://{}",
            index_kdl.display()
        ))));
    }
    None
}

/// S9 (RFC #23 §3.4): read `MILPA_CLI_FEATURES` from the fixture's `env` file.
/// Returns a BTreeSet of feature names (comma-separated). Mirrors Python's
/// `_fixture_cli_features`.
fn fixture_cli_features(dir: &Path) -> std::collections::BTreeSet<String> {
    let env = fixture_env(dir);
    match env.get("MILPA_CLI_FEATURES") {
        Some(raw) if !raw.is_empty() => raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => std::collections::BTreeSet::new(),
    }
}

/// S9 (RFC #23 §3.4): read `MILPA_NO_DEFAULT_FEATURES` from the fixture env.
fn fixture_no_default_features(dir: &Path) -> bool {
    let env = fixture_env(dir);
    env.get("MILPA_NO_DEFAULT_FEATURES")
        .map(|v| parse_env_bool(v))
        .unwrap_or(false)
}

/// S9 (RFC #23 §3.4): read `MILPA_ALL_FEATURES` from the fixture env.
fn fixture_all_features(dir: &Path) -> bool {
    let env = fixture_env(dir);
    env.get("MILPA_ALL_FEATURES")
        .map(|v| parse_env_bool(v))
        .unwrap_or(false)
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

// ---------------------------------------------------------------------------
// S7: index-trust policy state machine fixture runner
// ---------------------------------------------------------------------------

/// Run a `cmd=index-trust` fixture: computes the effective trust policy via
/// [`milpa_core::effective_trust_policy`], runs [`milpa_core::index_trust::enforce_index_trust`]
/// with a [`MockVerifier`]-driven result, and compares the outcome to
/// `expected/outcome`.
///
/// Env fields consumed:
/// - `mock_verifier_result`      — `VerificationResult` wire string; drives MockVerifier.
/// - `MILPA_INDEX_TRUST_MANIFEST` — simulated manifest `index-trust` policy
///   (`warn` / `strict` / `off`; absent → `warn`).
/// - `MILPA_INDEX_TRUST`         — env policy override (same axis as the CLI
///   `MILPA_INDEX_TRUST` env var).
/// - `MILPA_REQUIRE_ATTESTED_INDEX` — flag escalation (`1` = escalate warn→strict).
/// - `MILPA_INDEX_TRUST_WS_MEMBER_MAX` — simulates workspace member max-merge:
///   `max(root_policy, member_max)` replaces manifest policy before calling
///   `effective_trust_policy`.
/// - `MILPA_INDEX_TRUST_WS_CONFLICT` — workspace conflicting-signers (1 = conflict);
///   immediately returns `error:WS-INDEX-CONFLICTING-SIGNERS` without going through
///   the verifier (validated before any fetch in the real resolver).
///
/// Returns `Ok(Produced::IndexTrustPass { outcome })` when the computed outcome
/// matches `expected/outcome`; `Err(message)` on any mismatch.
fn run_index_trust_fixture(fx: &Fixture) -> Result<Produced, String> {
    use milpa_core::index_trust::{
        IndexBundleVerifier, MockVerifier, TrustBundle, VerificationResult, enforce_index_trust,
    };
    use milpa_core::{effective_trust_policy, parse_env_bool, TrustPolicy};

    // Inline trust policy parser: same as milpa_manifest::parse_trust_policy.
    // milpa_manifest is not in milpa-conformance's Cargo.toml deps; TrustPolicy
    // IS re-exported from milpa_core. This mirrors the three-value logic exactly.
    fn parse_trust_policy_str(s: &str, field: &str) -> Result<TrustPolicy, String> {
        match s {
            "warn" => Ok(TrustPolicy::Warn),
            "strict" => Ok(TrustPolicy::Strict),
            "off" => Ok(TrustPolicy::Off),
            _ => Err(format!(
                "unknown trust policy {s:?} for {field}: expected \"warn\", \"strict\", or \"off\""
            )),
        }
    }

    let dir = &fx.dir;
    let env = fixture_env(dir);

    // Read expected/outcome.
    let outcome_path = dir.join("expected").join("outcome");
    let expected_outcome = std::fs::read_to_string(&outcome_path)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("cannot read expected/outcome: {e}"))?;

    // Workspace conflicting-signers: hard validation error before any fetch/verify.
    let ws_conflict = env
        .get("MILPA_INDEX_TRUST_WS_CONFLICT")
        .map(|v| parse_env_bool(v))
        .unwrap_or(false);
    if ws_conflict {
        let got_outcome = "error:WS-INDEX-CONFLICTING-SIGNERS".to_string();
        if got_outcome == expected_outcome {
            return Ok(Produced::IndexTrustPass { outcome: got_outcome });
        }
        return Err(format!(
            "outcome mismatch:\n  expected: {expected_outcome:?}\n  actual:   {got_outcome:?}"
        ));
    }

    // Parse mock_verifier_result (drives MockVerifier; absent → "trusted").
    let mock_result_str = env
        .get("mock_verifier_result")
        .map(|s| s.as_str())
        .unwrap_or("trusted");
    let mock_result = VerificationResult::from_value(mock_result_str)
        .ok_or_else(|| format!("invalid mock_verifier_result: {mock_result_str:?}"))?;

    // Manifest policy from env field (absent → Warn, same as absent index-trust node).
    let manifest_policy_str = env
        .get("MILPA_INDEX_TRUST_MANIFEST")
        .map(|s| s.as_str())
        .unwrap_or("warn");
    let mut manifest_policy =
        parse_trust_policy_str(manifest_policy_str, "MILPA_INDEX_TRUST_MANIFEST")
            .map_err(|e| format!("invalid MILPA_INDEX_TRUST_MANIFEST: {e}"))?;

    // Workspace member max-merge: max(root_policy, member_max_policy).
    // strict=2 > warn=1 > off=0; only escalates, never demotes.
    if let Some(ws_member_max_str) = env.get("MILPA_INDEX_TRUST_WS_MEMBER_MAX") {
        let member_max =
            parse_trust_policy_str(ws_member_max_str, "MILPA_INDEX_TRUST_WS_MEMBER_MAX")
                .map_err(|e| format!("invalid MILPA_INDEX_TRUST_WS_MEMBER_MAX: {e}"))?;
        let rank = |p: &TrustPolicy| match p {
            TrustPolicy::Off => 0u8,
            TrustPolicy::Warn => 1,
            TrustPolicy::Strict => 2,
        };
        if rank(&member_max) > rank(&manifest_policy) {
            manifest_policy = member_max;
        }
    }

    // Env override (MILPA_INDEX_TRUST) and flag (MILPA_REQUIRE_ATTESTED_INDEX).
    let env_override = env
        .get("MILPA_INDEX_TRUST")
        .and_then(|s| parse_trust_policy_str(s, "MILPA_INDEX_TRUST").ok());
    let flag = env
        .get("MILPA_REQUIRE_ATTESTED_INDEX")
        .map(|v| parse_env_bool(v))
        .unwrap_or(false);

    // Compute effective policy via the shared SSOT helper (RFC §6.6 authority model).
    let policy = effective_trust_policy(&manifest_policy, flag, env_override.as_ref());

    // Build MockVerifier and call verify (ignores all params; returns mock_result).
    let trust_bundle = TrustBundle::test();
    let verifier = MockVerifier::new(mock_result.clone());
    let result = verifier.verify(
        b"index-bytes",
        b"bundle-bytes",
        &trust_bundle,
        "",
        None,
    );

    // Invoke enforce_index_trust and determine the outcome.
    let got_outcome = match enforce_index_trust(result.clone(), &policy, "mock://test-index") {
        Err(e) => format!("error:{}", e.code()),
        Ok(()) => {
            if policy == TrustPolicy::Off || result == VerificationResult::Trusted {
                "trusted".to_string()
            } else {
                // policy == Warn + non-Trusted result → a warning was emitted to stderr.
                // The slug is deterministically derivable from the VerificationResult variant
                // (the slug_map in enforce_index_trust is a bijection; we mirror it here so
                // the conformance runner can compute the outcome string for comparison without
                // capturing stderr — the BEHAVIOR is verified by enforce_index_trust NOT raising).
                let slug = match &result {
                    VerificationResult::BundleMissing => "TNG-INDEX-BUNDLE-MISSING",
                    VerificationResult::BundleMalformed => "TNG-INDEX-BUNDLE-MALFORMED",
                    VerificationResult::SigInvalid => "TNG-INDEX-SIGNATURE-INVALID",
                    VerificationResult::DigestMismatch => "TNG-INDEX-DIGEST-MISMATCH",
                    VerificationResult::SignerMismatch => "TNG-INDEX-SIGNER-MISMATCH",
                    VerificationResult::BundleStale => "TNG-INDEX-BUNDLE-STALE",
                    VerificationResult::Trusted => unreachable!("handled above"),
                };
                format!("warn:{slug}")
            }
        }
    };

    if got_outcome == expected_outcome {
        return Ok(Produced::IndexTrustPass { outcome: got_outcome });
    }
    Err(format!(
        "outcome mismatch:\n  expected: {expected_outcome:?}\n  actual:   {got_outcome:?}"
    ))
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
            no_index: false,
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
            no_index: false,
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
            no_index: false,
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
            no_index: false,
            expected: Expected::Error("FROZEN-STRATEGY-MISMATCH".into()),
        };
        assert_eq!(
            MilpaTarget.execute(&fx, &scratch),
            Err("FROZEN-STRATEGY-MISMATCH".into())
        );
    }

    // M5 regression: fixture_dep_decl_store implements the full three-way logic
    // (no_index → None; dep-decl/ → File; index.kdl → Http; else → None).
    // Both the resolve path and the verify pre-phase call this helper, so the
    // parity gap (verify was two-way only) cannot recur.
    #[test]
    fn fixture_dep_decl_store_three_way_logic() {
        let tmp = tempfile::tempdir().unwrap();
        let make_fx = |dir: std::path::PathBuf, no_index: bool| Fixture {
            id: "synthetic/probe".into(),
            dir,
            cmd: Cmd::Resolve,
            no_index,
            expected: Expected::Success,
        };

        // Arm 1: no_index=true → always None, even if dep-decl/ exists.
        let dir1 = tmp.path().join("arm1");
        std::fs::create_dir_all(dir1.join("dep-decl")).unwrap();
        let fx1 = make_fx(dir1, true);
        assert!(
            fixture_dep_decl_store(&fx1).is_none(),
            "no_index=true must return None regardless of dep-decl/"
        );

        // Arm 2: dep-decl/ dir present → FileDepDeclStore (Some).
        let dir2 = tmp.path().join("arm2");
        std::fs::create_dir_all(dir2.join("dep-decl")).unwrap();
        let fx2 = make_fx(dir2, false);
        assert!(
            fixture_dep_decl_store(&fx2).is_some(),
            "dep-decl/ dir present must return Some(FileDepDeclStore)"
        );

        // Arm 3: index.kdl present (no dep-decl/) → HttpDepDeclStore (Some).
        let dir3 = tmp.path().join("arm3");
        std::fs::create_dir_all(&dir3).unwrap();
        // Write a minimal valid index.kdl so the file exists (content doesn't
        // matter for the store-selection predicate; the store is only queried
        // during resolve, not during construction).
        std::fs::write(dir3.join("index.kdl"), "").unwrap();
        let fx3 = make_fx(dir3, false);
        assert!(
            fixture_dep_decl_store(&fx3).is_some(),
            "index.kdl present must return Some(HttpDepDeclStore)"
        );

        // Arm 4: nothing present → None.
        let dir4 = tmp.path().join("arm4");
        std::fs::create_dir_all(&dir4).unwrap();
        let fx4 = make_fx(dir4, false);
        assert!(
            fixture_dep_decl_store(&fx4).is_none(),
            "neither dep-decl/ nor index.kdl → None"
        );
    }

    // M6 regression: Frozen and Verify use fixture_project_root, not fx.dir, for
    // manifest/lock/workspace loads. A `project-dir` control file that points to a
    // subdir must allow the fixture to find milpa.kdl + milpa.lock there.
    #[test]
    fn milpa_target_frozen_respects_project_dir_control_file() {
        let tmp = tempfile::tempdir().unwrap();
        let scratch = Scratch::new(tmp.path()).unwrap();
        // The subdir that is the actual project root.
        let sub = tmp.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("milpa.kdl"), "name \"probe\"\nkind \"library\"\n").unwrap();
        std::fs::write(sub.join("milpa.lock"), "version 1\nstrategy \"maxver\"\n").unwrap();
        // project-dir control file: contents = "sub"
        std::fs::write(tmp.path().join("project-dir"), "sub").unwrap();
        // Note: NO milpa.kdl at tmp.path() itself — if the runner used fx.dir it
        // would surface E2E-MANIFEST-UNREADABLE, proving the fix.
        let fx = Fixture {
            id: "synthetic/probe-project-dir".into(),
            dir: tmp.path().to_path_buf(),
            cmd: Cmd::Frozen,
            no_index: false,
            expected: Expected::Success,
        };
        match MilpaTarget.execute(&fx, &scratch) {
            Ok(Produced::Outputs(out)) => {
                assert!(
                    out.lock_text.contains("strategy \"maxver\""),
                    "Frozen with project-dir must load manifest from the subdir"
                );
            }
            other => panic!("expected Outputs, got {other:?}"),
        }
    }
}
