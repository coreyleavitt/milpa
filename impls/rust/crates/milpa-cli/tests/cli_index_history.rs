//! Binary-level CLI regression tests for `milpa index status`/`milpa index
//! accept` (A3 — rfc-registry-append-only.md; cli-contract.md §5.12).
//!
//! Each test spawns the real `milpa` binary via `std::process::Command`,
//! mirroring `crates/milpa-cli/tests/cli_index_trust.rs`'s isolation
//! discipline (fresh `XDG_CACHE_HOME`/`MILPA_CACHE_DIR` per test, MILPA_*
//! env vars cleared before each run). `MILPA_INDEX_TRUST=off` is set in
//! most tests to isolate the index-history axis from index-trust (both are
//! independently gated per registry-protocol §3.4.0).

use std::path::Path;
use std::process::Command;

const MILPA: &str = env!("CARGO_BIN_EXE_milpa");

fn write_manifest(dir: &Path, index_history: Option<&str>) {
    let policy_line = index_history
        .map(|p| format!("\nindex-history \"{p}\""))
        .unwrap_or_default();
    std::fs::write(
        dir.join("milpa.kdl"),
        format!("name \"app\"\nkind \"application\"{policy_line}\n"),
    )
    .expect("write milpa.kdl");
}

fn write_index(dir: &Path, content_hash_suffix: char) -> String {
    let path = dir.join("index.kdl");
    let hash = content_hash_suffix.to_string().repeat(64);
    std::fs::write(
        &path,
        format!(
            "schema_version 1\npackage \"bar\" {{\n    version \"1.0.0\" {{\n        content_hash \"sha256:{hash}\"\n    }}\n}}\n"
        ),
    )
    .expect("write index.kdl");
    format!("file://{}", path.display())
}

struct Harness {
    proj: std::path::PathBuf,
    cache: std::path::PathBuf,
    index_url: String,
    _tmp: tempfile::TempDir,
}

fn setup(index_history: Option<&str>, content_hash_suffix: char) -> Harness {
    let tmp = tempfile::TempDir::new().unwrap();
    let proj = tmp.path().join("proj");
    let cache = tmp.path().join("cache");
    let idx_dir = tmp.path().join("idx");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&idx_dir).unwrap();
    write_manifest(&proj, index_history);
    let index_url = write_index(&idx_dir, content_hash_suffix);
    Harness { proj, cache, index_url, _tmp: tmp }
}

fn run(h: &Harness, verb_args: &[&str], extra_env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(MILPA);
    for var in &[
        "MILPA_INDEX_URL",
        "MILPA_INDEX_BUNDLE_URL",
        "MILPA_INDEX_TRUST",
        "MILPA_INDEX_TRUST_MOCK_VERIFIER",
        "MILPA_INDEX_TRUST_SIGNER",
        "MILPA_INDEX_TRUST_BUNDLE",
        "MILPA_INDEX_MAX_AGE",
        "MILPA_INDEX_HISTORY",
        "MILPA_CACHE_DIR",
        "MILPA_MOCKED_FETCHES",
        "MILPA_REQUIRE_ATTESTED_METADATA",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("XDG_CACHE_HOME", &h.cache);
    cmd.env("MILPA_CACHE_DIR", &h.cache);
    cmd.env("MILPA_INDEX_URL", &h.index_url);
    cmd.env("MILPA_INDEX_TRUST", "off");
    cmd.arg("-C").arg(&h.proj);
    cmd.args(verb_args);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("milpa binary must be runnable");
    let code = out.status.code().unwrap_or(-1);
    (code, String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

// ---------------------------------------------------------------------------
// --no-index hard error
// ---------------------------------------------------------------------------

#[test]
fn no_index_flag_is_hard_error_for_status() {
    let h = setup(None, 'a');
    let mut cmd = Command::new(MILPA);
    cmd.env_remove("MILPA_INDEX_URL");
    cmd.env("XDG_CACHE_HOME", &h.cache);
    cmd.env("MILPA_CACHE_DIR", &h.cache);
    cmd.arg("-C").arg(&h.proj).arg("--no-index").arg("index").arg("status");
    let out = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0));
    assert!(stderr.contains("TNG-INDEX-NOT-CONFIGURED"), "stderr:\n{stderr}");
}

#[test]
fn no_index_flag_is_hard_error_for_accept() {
    let h = setup(None, 'a');
    let mut cmd = Command::new(MILPA);
    cmd.env_remove("MILPA_INDEX_URL");
    cmd.env("XDG_CACHE_HOME", &h.cache);
    cmd.env("MILPA_CACHE_DIR", &h.cache);
    cmd.arg("-C").arg(&h.proj).arg("--no-index").arg("index").arg("accept");
    let out = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0));
    assert!(stderr.contains("TNG-INDEX-NOT-CONFIGURED"), "stderr:\n{stderr}");
}

// ---------------------------------------------------------------------------
// status: read-only, absent baseline
// ---------------------------------------------------------------------------

#[test]
fn status_absent_baseline_exits_zero_reports_absent() {
    let h = setup(None, 'a');
    let (code, stdout, _stderr) = run(&h, &["index", "status"], &[]);
    assert_eq!(code, 0);
    assert!(stdout.contains("baseline:          absent"), "stdout:\n{stdout}");
    assert!(stdout.contains("policy:            warn"), "stdout:\n{stdout}");
    assert!(stdout.contains(&h.index_url), "stdout:\n{stdout}");
}

#[test]
fn status_without_refresh_never_writes_cache() {
    let h = setup(None, 'a');
    run(&h, &["index", "status"], &[]);
    // No cache dir contents at all — status without --refresh must not fetch.
    let index_cache_dir = h.cache.join("milpa").join("index");
    if index_cache_dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(&index_cache_dir).unwrap().collect();
        assert!(entries.is_empty(), "status must not write any cache file: {entries:?}");
    }
}

// ---------------------------------------------------------------------------
// accept: TOFU establishment
// ---------------------------------------------------------------------------

#[test]
fn accept_first_run_establishes_tofu_trust_anchor() {
    let h = setup(None, 'a');
    let (code, stdout, _stderr) = run(&h, &["index", "accept"], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("no prior baseline"), "stdout:\n{stdout}");

    // A subsequent status must now report a present, non-pending baseline.
    let (code2, stdout2, _) = run(&h, &["index", "status"], &[]);
    assert_eq!(code2, 0);
    assert!(stdout2.contains("baseline:          present"), "stdout:\n{stdout2}");
    assert!(stdout2.contains("pending:           no"), "stdout:\n{stdout2}");
}

#[test]
fn accept_idempotent_second_run_reports_nothing_to_accept() {
    let h = setup(None, 'a');
    run(&h, &["index", "accept"], &[]);
    let (code, stdout, _) = run(&h, &["index", "accept"], &[]);
    assert_eq!(code, 0);
    assert!(stdout.contains("nothing to accept"), "stdout:\n{stdout}");
}

// ---------------------------------------------------------------------------
// accept: dirty diff — prints the violation + digest, still swaps the baseline
// ---------------------------------------------------------------------------

#[test]
fn accept_dirty_diff_prints_violation_and_digest_then_swaps_baseline() {
    let h = setup(None, 'a');
    run(&h, &["index", "accept"], &[]);

    // Mutate the served index's content_hash (frozen-field violation).
    let idx_path = h.proj.parent().unwrap().join("idx").join("index.kdl");
    let hash_b = "b".repeat(64);
    std::fs::write(
        &idx_path,
        format!(
            "schema_version 1\npackage \"bar\" {{\n    version \"1.0.0\" {{\n        content_hash \"sha256:{hash_b}\"\n    }}\n}}\n"
        ),
    )
    .unwrap();

    let (code, stdout, _stderr) = run(&h, &["index", "accept"], &[]);
    assert_eq!(code, 0, "accept always exits 0 on success (incl. absorbing a violation)");
    assert!(stdout.contains("violation:"), "stdout:\n{stdout}");
    assert!(stdout.contains("TNG-ENTRY-MUTATED"), "stdout:\n{stdout}");
    assert!(stdout.contains("frozen-changed"), "stdout:\n{stdout}");
    assert!(stdout.contains("digest:"), "stdout:\n{stdout}");

    // The baseline is now the mutated content — a following accept is clean.
    let (code2, stdout2, _) = run(&h, &["index", "accept"], &[]);
    assert_eq!(code2, 0);
    assert!(stdout2.contains("nothing to accept"), "stdout:\n{stdout2}");
}

// ---------------------------------------------------------------------------
// status --refresh: dry-run diff preview, writes nothing
// ---------------------------------------------------------------------------

#[test]
fn status_refresh_previews_diff_without_writing() {
    let h = setup(None, 'a');
    run(&h, &["index", "accept"], &[]);

    let idx_path = h.proj.parent().unwrap().join("idx").join("index.kdl");
    let hash_b = "b".repeat(64);
    std::fs::write(
        &idx_path,
        format!(
            "schema_version 1\npackage \"bar\" {{\n    version \"1.0.0\" {{\n        content_hash \"sha256:{hash_b}\"\n    }}\n}}\n"
        ),
    )
    .unwrap();

    let (baseline_bytes_before, _) = {
        let (baseline_path, _) = baseline_sidecar_path(&h);
        (std::fs::read(&baseline_path).unwrap(), ())
    };

    let (code, stdout, _stderr) = run(&h, &["index", "status", "--refresh"], &[]);
    assert_eq!(code, 1, "a nonempty violation set under --refresh exits 1");
    assert!(stdout.contains("violation:"), "stdout:\n{stdout}");

    let (baseline_path, _) = baseline_sidecar_path(&h);
    let baseline_bytes_after = std::fs::read(&baseline_path).unwrap();
    assert_eq!(baseline_bytes_before, baseline_bytes_after, "--refresh must never write the baseline");
}

fn baseline_sidecar_path(h: &Harness) -> (std::path::PathBuf, std::path::PathBuf) {
    // Reuse milpa-core's own naming authority (the ONE function both the CLI
    // and the ordinary ratchet-gated fetch path use) instead of
    // hand-computing the cache key — avoids a second, potentially-drifting
    // implementation of the same derivation in test code.
    let cache_dir = h.cache.join("milpa").join("index");
    milpa_core::baseline_sidecar_paths(&h.index_url, &cache_dir)
}

// ---------------------------------------------------------------------------
// index-history "off": accept still works, warns that the baseline written
// will not be consulted again until re-enabled (cli-contract §5.12 NORMATIVE).
// ---------------------------------------------------------------------------

#[test]
fn accept_under_off_policy_warns_and_still_writes() {
    let h = setup(Some("off"), 'a');
    let (code, _stdout, stderr) = run(&h, &["index", "accept"], &[]);
    assert_eq!(code, 0);
    assert!(stderr.contains("index-history is \"off\""), "stderr:\n{stderr}");
    let (baseline_path, _) = baseline_sidecar_path(&h);
    assert!(baseline_path.exists(), "accept must still write the baseline under off");
}

// ---------------------------------------------------------------------------
// milpa fetch (strict): a dirty refetch hard-fails with no cache mutation.
// ---------------------------------------------------------------------------

#[test]
fn fetch_strict_dirty_refetch_hard_fails() {
    let h = setup(Some("strict"), 'a');
    let (code0, _, stderr0) = run(&h, &["fetch"], &[]);
    assert_eq!(code0, 0, "first fetch (TOFU) must succeed: {stderr0}");

    let idx_path = h.proj.parent().unwrap().join("idx").join("index.kdl");
    let hash_b = "b".repeat(64);
    std::fs::write(
        &idx_path,
        format!(
            "schema_version 1\npackage \"bar\" {{\n    version \"1.0.0\" {{\n        content_hash \"sha256:{hash_b}\"\n    }}\n}}\n"
        ),
    )
    .unwrap();

    let (code, _, stderr) = run(&h, &["--refresh-index", "fetch"], &[]);
    assert_ne!(code, 0, "stderr:\n{stderr}");
    assert!(stderr.contains("TNG-ENTRY-MUTATED"), "stderr:\n{stderr}");
}

#[test]
fn fetch_warn_dirty_refetch_makes_status_pending() {
    let h = setup(Some("warn"), 'a');
    run(&h, &["fetch"], &[]);

    let idx_path = h.proj.parent().unwrap().join("idx").join("index.kdl");
    let hash_b = "b".repeat(64);
    std::fs::write(
        &idx_path,
        format!(
            "schema_version 1\npackage \"bar\" {{\n    version \"1.0.0\" {{\n        content_hash \"sha256:{hash_b}\"\n    }}\n}}\n"
        ),
    )
    .unwrap();

    let (code, _, stderr) = run(&h, &["--refresh-index", "fetch"], &[]);
    assert_eq!(code, 0, "warn must not hard-fail: {stderr}");
    assert!(stderr.contains("index-history violation"), "stderr:\n{stderr}");

    let (status_code, stdout, _) = run(&h, &["index", "status"], &[]);
    assert_eq!(status_code, 1, "a pending violation makes status exit 1");
    assert!(stdout.contains("pending:           yes"), "stdout:\n{stdout}");
}
