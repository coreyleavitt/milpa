//! S2 done-criterion (RFC §6 S2): the harness engine, proven against two
//! hand-authored synthetic fixtures driven through a **stub** `Target` with zero
//! domain logic. This exercises discovery, `cmd` dispatch, the success byte-diff
//! (incl. `<CAS_ROOT>` normalization of a real `_deps/` symlink), the
//! `expected/error` path, and — crucially — that the diff actually *fails* on a
//! wrong output (so a green run means matching, not a no-op).

use std::path::{Path, PathBuf};

use milpa_conformance::{
    discover, run_fixture, Fixture, Outputs, Produced, Scratch, Target, Verdict,
};

// Canned outputs the stub produces. These MUST stay byte-identical to the
// synthetic fixture's `expected/` files (the two-copy nature is intrinsic: the
// stub cannot read the expected files without making every diff trivially pass).
const STUB_LOCK: &str = "version 1\nstrategy \"maxver\"\n";
const STUB_NIMCFG: &str = "--path:\"src\"\n--path:\"_deps/foo/src\"\n";
const STUB_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn synthetic_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("synthetic")
}

fn find(id_suffix: &str) -> Fixture {
    discover(&synthetic_root())
        .into_iter()
        .find(|f| f.id.ends_with(id_suffix))
        .unwrap_or_else(|| panic!("synthetic fixture {id_suffix} not discovered"))
}

/// Materialize the canned `_deps/foo` → CAS symlink the way the real admit/link
/// step does (a *relative* on-disk link into the store), so the harness's
/// `canonicalize`-based `_deps_structure.txt` builder is genuinely exercised.
fn materialize_foo(scratch: &Scratch) {
    let entry = scratch.cas_root.join("sha256").join(STUB_HEX);
    std::fs::create_dir_all(&entry).unwrap();
    std::os::unix::fs::symlink(
        format!("../.cas/sha256/{STUB_HEX}"),
        scratch.deps_dir.join("foo"),
    )
    .unwrap();
}

/// Stub implementation under test: canned, fixture-id-keyed, no milpa logic.
struct StubTarget;

impl Target for StubTarget {
    fn execute(&self, fx: &Fixture, scratch: &Scratch) -> Result<Produced, String> {
        if fx.id.ends_with("fixture-001-stub-pass") {
            materialize_foo(scratch);
            Ok(Produced::Outputs(Outputs {
                lock_text: STUB_LOCK.to_string(),
                nimcfg_text: STUB_NIMCFG.to_string(),
            }))
        } else if fx.id.ends_with("fixture-002-stub-error") {
            Err("STUB-ERROR".to_string())
        } else {
            Err("STUB-UNKNOWN-FIXTURE".to_string())
        }
    }
}

/// Same as `StubTarget` but emits a wrong lockfile — used to prove the diff
/// actually compares bytes (a green pass must mean "matched", not "ran").
struct WrongStubTarget;

impl Target for WrongStubTarget {
    fn execute(&self, fx: &Fixture, scratch: &Scratch) -> Result<Produced, String> {
        materialize_foo(scratch);
        let _ = fx;
        Ok(Produced::Outputs(Outputs {
            lock_text: "version 1\nstrategy \"minver\"\n".to_string(), // wrong!
            nimcfg_text: STUB_NIMCFG.to_string(),
        }))
    }
}

fn scratch() -> (tempfile::TempDir, Scratch) {
    let tmp = tempfile::tempdir().unwrap();
    let s = Scratch::new(tmp.path()).unwrap();
    (tmp, s)
}

#[test]
fn discovers_both_synthetic_fixtures() {
    let ids: Vec<String> = discover(&synthetic_root())
        .into_iter()
        .map(|f| f.id)
        .collect();
    assert_eq!(ids.len(), 2, "discovered: {ids:?}");
    assert!(ids.iter().any(|i| i.ends_with("fixture-001-stub-pass")));
    assert!(ids.iter().any(|i| i.ends_with("fixture-002-stub-error")));
}

#[test]
fn stub_pass_fixture_passes() {
    let fx = find("fixture-001-stub-pass");
    let (_tmp, s) = scratch();
    assert_eq!(run_fixture(&fx, &StubTarget, &s), Verdict::Pass);
}

#[test]
fn stub_error_fixture_passes() {
    let fx = find("fixture-002-stub-error");
    let (_tmp, s) = scratch();
    assert_eq!(run_fixture(&fx, &StubTarget, &s), Verdict::Pass);
}

#[test]
fn diff_detects_a_wrong_lockfile() {
    let fx = find("fixture-001-stub-pass");
    let (_tmp, s) = scratch();
    match run_fixture(&fx, &WrongStubTarget, &s) {
        Verdict::Fail(msg) => assert!(msg.contains("milpa.lock mismatch"), "got: {msg}"),
        other => panic!("diff failed to detect a wrong lockfile: {other:?}"),
    }
}
