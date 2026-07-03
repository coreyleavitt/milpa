//! Binary-level regression tests for the "load_workspace error swallowed as
//! absent" bug family (code-review items RD-C1 / RD-H1 / RD-M1, plus
//! `cmd_clean` found via the review's "mirror everywhere" instruction).
//!
//! Root cause (see `find_parent_workspace` / `resolve_index_trust_fields` /
//! `cmd_verify` in `milpa-cli/src/main.rs`, and `workspace.py:find_workspace_root`
//! for the reference behavior): several call sites conflated "`load_workspace`
//! returned `Err`" with "there is no workspace here" via `if let Ok(ws) =
//! load_workspace(...)` / `match load_workspace(...) { Err(_) => <fallback> }`.
//! A workspace MEMBER illegally declaring any index-trust field
//! (`WS-INDEX-TRUST-ON-MEMBER`, raised by `load_workspace` — root-authority
//! model, spec §3.4.7 / RFC registry-trust-federation §6.4a) is a genuine
//! structural error that MUST propagate, not be treated as "not a workspace,
//! fall back to standalone-package / warn / success" behavior.
//!
//! Every scenario below uses a two-member workspace where `member-a`
//! illegally declares `index-trust "strict"` and `member-b` is clean; the
//! command under test is run from `member-b` (or the workspace root for
//! `show`/`verify`). All of them must fail closed with
//! `WS-INDEX-TRUST-ON-MEMBER` — never silently succeed, never fail with an
//! unrelated code (e.g. a fetch-transport error, which would mean the buggy
//! code fell through to standalone-package treatment and only failed later,
//! for the wrong reason).

use std::path::Path;
use std::process::Command;

/// Path to the compiled `milpa` binary (set by Cargo at test-compile time).
const MILPA: &str = env!("CARGO_BIN_EXE_milpa");

const MILPA_ENV_VARS: &[&str] = &[
    "MILPA_INDEX_URL",
    "MILPA_INDEX_BUNDLE_URL",
    "MILPA_INDEX_TRUST",
    "MILPA_INDEX_TRUST_MOCK_VERIFIER",
    "MILPA_INDEX_TRUST_SIGNER",
    "MILPA_INDEX_TRUST_BUNDLE",
    "MILPA_INDEX_MAX_AGE",
    "MILPA_CACHE_DIR",
    "MILPA_MOCKED_FETCHES",
    "MILPA_REQUIRE_ATTESTED_METADATA",
];

/// Lay out a two-member workspace at `root`: `member-a` illegally declares
/// `index-trust "strict"`; `member-b` is a clean package manifest. Returns
/// `(root, member_a_dir, member_b_dir)`.
fn illegal_workspace(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    std::fs::write(
        root.join("milpa.kdl"),
        "workspace {\n    member \"member-a\"\n    member \"member-b\"\n}\n",
    )
    .expect("write workspace root milpa.kdl");

    let member_a = root.join("member-a");
    std::fs::create_dir_all(&member_a).unwrap();
    std::fs::write(
        member_a.join("milpa.kdl"),
        "name \"member-a\"\nkind \"library\"\nindex-trust \"strict\"\n",
    )
    .expect("write member-a milpa.kdl");

    let member_b = root.join("member-b");
    std::fs::create_dir_all(&member_b).unwrap();
    std::fs::write(
        member_b.join("milpa.kdl"),
        "name \"member-b\"\nkind \"library\"\n",
    )
    .expect("write member-b milpa.kdl");

    (member_a, member_b)
}

/// Run `milpa -C <dir> <verb> [args...]` with an isolated cache and a
/// clean MILPA_* env (plus `MILPA_MOCKED_FETCHES` pointed at an empty temp
/// dir, so that IF a fix regresses and the buggy fallthrough is reached, the
/// resulting fetch attempt fails fast and locally — FETCH-MOCK-MISSING / the
/// resolver's aggregate — rather than hitting the real network).
/// Returns `(exit_code, stderr)`.
fn run_milpa(dir: &Path, cache_dir: &Path, verb: &str, args: &[&str]) -> (i32, String) {
    let mocked_fetches = cache_dir.join("mocked-fetches-empty");
    std::fs::create_dir_all(&mocked_fetches).unwrap();

    let mut cmd = Command::new(MILPA);
    for var in MILPA_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.env("XDG_CACHE_HOME", cache_dir);
    cmd.env("MILPA_CACHE_DIR", cache_dir);
    cmd.env("MILPA_MOCKED_FETCHES", &mocked_fetches);
    cmd.env("MILPA_INDEX_URL", ""); // explicitly no index — irrelevant to these scenarios

    cmd.arg("-C").arg(dir);
    cmd.arg(verb);
    cmd.args(args);

    let out = cmd.output().expect("milpa binary must be runnable");
    let code = out.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stderr)
}

fn assert_ws_index_trust_on_member(code: i32, stderr: &str, verb: &str) {
    assert_ne!(code, 0, "{verb}: must fail (nonzero exit)\nstderr:\n{stderr}");
    assert_ne!(code, 101, "{verb}: must not panic (exit 101)\nstderr:\n{stderr}");
    assert!(
        stderr.contains("WS-INDEX-TRUST-ON-MEMBER"),
        "{verb}: must surface WS-INDEX-TRUST-ON-MEMBER (the trust-check failure), \
         not a downstream/unrelated error — got exit {code}\nstderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// RD-C1: find_parent_workspace member-dir delegation (add / update / remove)
// ---------------------------------------------------------------------------

/// `milpa add` from a clean member dir, in a workspace where a DIFFERENT
/// member illegally declares index-trust, must fail with
/// WS-INDEX-TRUST-ON-MEMBER — BEFORE any fetch (a fake, unreachable git URL
/// is used; if the buggy fallthrough to standalone-package treatment were
/// still present, this would instead fail later with a fetch-transport
/// error) — and must not create member-b/milpa.lock or member-b/_deps/.
#[test]
fn add_from_member_dir_propagates_ws_index_trust_on_member() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("ws");
    let cache = tmp.path().join("cache");
    std::fs::create_dir_all(&root).unwrap();
    let (_member_a, member_b) = illegal_workspace(&root);

    let (code, stderr) = run_milpa(
        &member_b,
        &cache,
        "add",
        &[
            "somedep",
            "--git",
            "https://example.invalid/nonexistent/somedep.git",
            "--ref",
            "main",
        ],
    );

    assert_ws_index_trust_on_member(code, &stderr, "add");
    assert!(
        !member_b.join("milpa.lock").exists(),
        "add must not write member-b/milpa.lock when the workspace is trust-invalid"
    );
    assert!(
        !member_b.join("_deps").exists(),
        "add must not create member-b/_deps/ when the workspace is trust-invalid"
    );
    // The member's own manifest must also be untouched.
    let member_b_manifest = std::fs::read_to_string(member_b.join("milpa.kdl")).unwrap();
    assert!(
        !member_b_manifest.contains("somedep"),
        "add must not mutate member-b/milpa.kdl when the workspace is trust-invalid"
    );
}

/// `milpa remove` from a clean member dir mirrors `add`: propagate, don't
/// fall through to standalone treatment.
#[test]
fn remove_from_member_dir_propagates_ws_index_trust_on_member() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("ws");
    let cache = tmp.path().join("cache");
    std::fs::create_dir_all(&root).unwrap();
    let (_member_a, member_b) = illegal_workspace(&root);

    let (code, stderr) = run_milpa(&member_b, &cache, "remove", &["somedep"]);

    assert_ws_index_trust_on_member(code, &stderr, "remove");
    assert!(!member_b.join("milpa.lock").exists());
    assert!(!member_b.join("_deps").exists());
}

/// `milpa update` (no args — the whole-workspace re-resolve path) from a
/// clean member dir mirrors `add`/`remove`.
#[test]
fn update_from_member_dir_propagates_ws_index_trust_on_member() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("ws");
    let cache = tmp.path().join("cache");
    std::fs::create_dir_all(&root).unwrap();
    let (_member_a, member_b) = illegal_workspace(&root);

    let (code, stderr) = run_milpa(&member_b, &cache, "update", &[]);

    assert_ws_index_trust_on_member(code, &stderr, "update");
    assert!(!member_b.join("milpa.lock").exists());
    assert!(!member_b.join("_deps").exists());
}

// ---------------------------------------------------------------------------
// RD-H1: cmd_verify
// ---------------------------------------------------------------------------

/// `milpa verify` at the workspace root, where a member illegally declares
/// index-trust, must fail with WS-INDEX-TRUST-ON-MEMBER — not silently
/// treat the workspace as absent (which would then hit
/// VERIFY-DEPS-DIR-MISSING / LOCK-GRAPH-MISMATCH instead, or — with a
/// present but stale lockfile — report success).
#[test]
fn verify_at_workspace_root_propagates_ws_index_trust_on_member() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("ws");
    let cache = tmp.path().join("cache");
    std::fs::create_dir_all(&root).unwrap();
    illegal_workspace(&root);

    // Rust's cmd_verify loads the lockfile FIRST (before the index-trust
    // field resolution this test targets), so supply a minimal valid
    // lockfile to isolate the swallow specifically — otherwise the earlier
    // LOCK-FILE-NOT-FOUND / LOCK-VERSION-MISSING check would mask it.
    std::fs::write(
        root.join("milpa.lock"),
        "version 1\nstrategy \"maxver\"\n",
    )
    .unwrap();

    let (code, stderr) = run_milpa(&root, &cache, "verify", &[]);
    assert_ws_index_trust_on_member(code, &stderr, "verify");
}

// ---------------------------------------------------------------------------
// RD-M1: cmd_show_index_trust
// ---------------------------------------------------------------------------

/// `milpa show --index-trust` at the workspace root must surface
/// WS-INDEX-TRUST-ON-MEMBER, not print a confident `policy: warn` / exit 0
/// for a workspace that `fetch`/`lock`/`verify` would actually refuse to run
/// against.
#[test]
fn show_index_trust_at_workspace_root_propagates_ws_index_trust_on_member() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("ws");
    let cache = tmp.path().join("cache");
    std::fs::create_dir_all(&root).unwrap();
    illegal_workspace(&root);

    let (code, stderr) = run_milpa(&root, &cache, "show", &["--index-trust"]);
    assert_ws_index_trust_on_member(code, &stderr, "show --index-trust");
}

/// Sanity companion: `show --index-trust` outside any milpa project dir (no
/// manifest at all) MUST remain graceful — exit 0, default `warn` — this is
/// the one case RD-M1 intentionally keeps swallowed (MAN-NO-MANIFEST).
#[test]
fn show_index_trust_outside_project_dir_stays_graceful() {
    let tmp = tempfile::TempDir::new().unwrap();
    let empty = tmp.path().join("not-a-project");
    let cache = tmp.path().join("cache");
    std::fs::create_dir_all(&empty).unwrap();

    let (code, stderr) = run_milpa(&empty, &cache, "show", &["--index-trust"]);
    assert_eq!(code, 0, "no-manifest case must stay graceful\nstderr:\n{stderr}");
}

// ---------------------------------------------------------------------------
// Bonus (found via the "mirror everywhere" instruction, not individually
// enumerated): cmd_clean had the identical `if let Ok(ws) = load_workspace(dir)
// { .. } else { .. }` swallow. Python's `cmd_clean` calls the unguarded
// `find_workspace_root` too, so a trust-invalid workspace must propagate here
// as well, not silently fall back to (harmlessly idempotent, but WRONG —
// masks the real error) single-package cleanup.
// ---------------------------------------------------------------------------

#[test]
fn clean_at_workspace_root_propagates_ws_index_trust_on_member() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("ws");
    let cache = tmp.path().join("cache");
    std::fs::create_dir_all(&root).unwrap();
    illegal_workspace(&root);

    let (code, stderr) = run_milpa(&root, &cache, "clean", &[]);
    assert_ws_index_trust_on_member(code, &stderr, "clean");
}

/// Sanity companion: `clean` on a LEGAL workspace still works (root-cause fix
/// must not regress the happy path).
#[test]
fn clean_at_legal_workspace_root_still_succeeds() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("ws");
    let cache = tmp.path().join("cache");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("milpa.kdl"),
        "workspace {\n    member \"member-a\"\n}\n",
    )
    .unwrap();
    let member_a = root.join("member-a");
    std::fs::create_dir_all(&member_a).unwrap();
    std::fs::write(member_a.join("milpa.kdl"), "name \"member-a\"\nkind \"library\"\n").unwrap();
    std::fs::create_dir_all(root.join("_deps")).unwrap();
    std::fs::write(member_a.join("nim.cfg"), "# stale\n").unwrap();

    let (code, stderr) = run_milpa(&root, &cache, "clean", &[]);
    assert_eq!(code, 0, "clean on a legal workspace must still succeed\nstderr:\n{stderr}");
    assert!(!root.join("_deps").exists());
    assert!(!member_a.join("nim.cfg").exists());
}
