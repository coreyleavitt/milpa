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
    /// A success run with byte-diffable outputs (the `resolve`/`frozen` path).
    Outputs(Outputs),
    /// A `cmd=parse-lockfile` run that did not error. The spec defines no
    /// success variant for `parse-lockfile` (§2.7), so a fixture reaching this
    /// is an authoring error, surfaced as a failure by `run_fixture`.
    NoByteDiff,
}

/// The implementation under test. The `Err` payload is the error **code**
/// (`docs/spec/errors.md` slug) — the only thing the harness compares for error
/// fixtures (§3.1); message text is never checked.
pub trait Target {
    fn execute(&self, fx: &Fixture, scratch: &Scratch) -> Result<Produced, String>;
}

/// The outcome of running one fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail(String),
}

impl Verdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass)
    }
}

/// Run one fixture against `target` in `scratch` and return the verdict.
pub fn run_fixture(fx: &Fixture, target: &dyn Target, scratch: &Scratch) -> Verdict {
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
    }
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
/// **incrementally** — at S2 every path returns the not-wired sentinel, so the
/// whole real corpus fails (all entries live in `known_failing.txt`). Each
/// later slice replaces one arm with the real `milpa-core` call, at which point
/// its fixtures green and leave the known-failing list.
pub struct MilpaTarget;

/// Sentinel returned by not-yet-wired `MilpaTarget` arms. Not a `docs/spec`
/// slug (the parity check only enumerates real domain-enum codes), so it can
/// never accidentally satisfy an `expected/error` fixture.
const NOT_WIRED: &str = "E2E-NOT-WIRED";

impl Target for MilpaTarget {
    fn execute(&self, fx: &Fixture, scratch: &Scratch) -> Result<Produced, String> {
        use milpa_core::{ManifestDoc, Resolver};

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
                let manifest = match milpa_core::parse_document(&text) {
                    // Workspace resolution (multi-member) is S11; leave parked.
                    Ok(ManifestDoc::Workspace(_)) => return Err(NOT_WIRED.to_string()),
                    Ok(ManifestDoc::Package(m)) => m,
                    Err(e) => return Err(e.code().to_string()),
                };

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
                    None,
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
            // S10 wires the frozen path.
            Cmd::Frozen => Err(NOT_WIRED.to_string()),
        }
    }
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
    fn milpa_target_frozen_not_wired_yet() {
        let tmp = tempfile::tempdir().unwrap();
        let scratch = Scratch::new(tmp.path()).unwrap();
        let fx = Fixture {
            id: "synthetic/probe".into(),
            dir: tmp.path().to_path_buf(),
            cmd: Cmd::Frozen,
            expected: Expected::Success,
        };
        assert_eq!(MilpaTarget.execute(&fx, &scratch), Err(NOT_WIRED.into()));
    }
}
