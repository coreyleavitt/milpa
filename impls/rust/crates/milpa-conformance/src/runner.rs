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
                // an in-process adapter that produces a different normative output
                // than its own CLI is a bug (rfc-conformance-parity §3 corollary).
                //   --no-index → None;
                //   dep-decl/ dir present → FileDepDeclStore (MILPA_DEP_DECL_DIR analogue);
                //   else index.kdl present → HttpDepDeclStore over the index base
                //     (the CLI's MILPA_INDEX_URL→HttpDepDeclStore path); a missing
                //     dep-decl/<hash>.kdl then raises TNG-DEPDECL-FETCH-FAILED
                //     (fixture-144), matching the black-box CLI;
                //   else None.
                let dep_decl_dir = fx.dir.join("dep-decl");
                let index_kdl = fx.dir.join("index.kdl");
                let file_store;
                let http_store;
                let dep_decl_store: Option<&dyn milpa_core::dep_decl_store::DepDeclStore> =
                    if fx.no_index {
                        None
                    } else if dep_decl_dir.is_dir() {
                        file_store = milpa_core::FileDepDeclStore::new(&dep_decl_dir);
                        Some(&file_store)
                    } else if index_kdl.is_file() {
                        http_store = milpa_core::make_dep_decl_store(&format!(
                            "file://{}",
                            index_kdl.display()
                        ));
                        Some(&http_store)
                    } else {
                        None
                    };

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
                let mtext = std::fs::read_to_string(fx.dir.join("milpa.kdl"))
                    .map_err(|e| format!("E2E-MANIFEST-UNREADABLE: {e}"))?;
                let doc = match milpa_core::parse_document(&mtext) {
                    Ok(d) => d,
                    Err(e) => return Err(e.code().to_string()),
                };
                // Missing lock → LOCK-FILE-NOT-FOUND, mirroring cmd_verify's
                // first check (before any _deps/ work). fixture-164 (#125)
                // exercises the no-lock branch.
                let lock_path = fx.dir.join("milpa.lock");
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
                let dep_decl_dir = fx.dir.join("dep-decl");
                let file_store;
                let dep_decl_store: Option<&dyn milpa_core::dep_decl_store::DepDeclStore> =
                    if dep_decl_dir.is_dir() {
                        file_store = milpa_core::FileDepDeclStore::new(&dep_decl_dir);
                        Some(&file_store)
                    } else {
                        None
                    };
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
                        let loaded = match milpa_core::load_workspace(&fx.dir) {
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

                // S11b (Breadth-P2c): workspace frozen-flags mismatch check.
                // Runs BEFORE disk check, matching cmd_verify's ordering.
                if let ManifestDoc::Workspace(_) = doc {
                    let loaded_verify = match milpa_core::load_workspace(&fx.dir) {
                        Ok(w) => w,
                        Err(_) => {
                            // workspace load failed — fall through to disk check
                            let divergences = milpa_core::verify_lockfile_against_deps(&lock, &scratch.deps_dir);
                            if !divergences.is_empty() {
                                return Err("LOCK-GRAPH-MISMATCH".to_string());
                            }
                            return Ok(Produced::NoByteDiff);
                        }
                    };
                    if let Err(e) = milpa_core::check_workspace_frozen_active_flags_mismatch(
                        &loaded_verify,
                        &lock,
                        &std::collections::BTreeSet::new(),
                        false,
                        false,
                    ) {
                        return Err(e.code().to_string());
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
                // Route through the milpa-core SSOT helpers (effective_strict_policy /
                // workspace_any_member_strict) rather than re-deriving the OR rule.
                let flag_strict = fixture_require_attested_metadata(&fx.dir);
                let strict = match &doc {
                    ManifestDoc::Package(m) => {
                        milpa_core::effective_strict_policy(&m.attestation_policy, flag_strict)
                    }
                    ManifestDoc::Workspace(_) => {
                        // Workspace: OR across all members (+ flag).
                        match milpa_core::load_workspace(&fx.dir) {
                            Ok(ws) => milpa_core::workspace_any_member_strict(&ws) || flag_strict,
                            Err(_) => flag_strict,
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
fn fixture_project_root(fx: &Fixture) -> PathBuf {
    match std::fs::read_to_string(fx.dir.join("project-dir")) {
        Ok(s) if !s.trim().is_empty() => fx.dir.join(s.trim()),
        _ => fx.dir.clone(),
    }
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
}
