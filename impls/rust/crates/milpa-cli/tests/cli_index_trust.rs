//! Binary-level CLI regression tests for index-trust dispatch (ITEM 1 + ITEM 2).
//!
//! Each test spawns the real `milpa` binary (`CARGO_BIN_EXE_milpa`) via
//! `std::process::Command`.  Env vars are set per-Command; no global state is
//! mutated, so the tests are serial-safe and can run in any order.
//!
//! ITEM 1 — five dispatch scenarios (all via the MockVerifier seam):
//!
//!   (1) manifest `index-trust "strict"` + mock sig-invalid
//!       → exit 1, TNG-INDEX-SIGNATURE-INVALID
//!   (2) manifest warn (explicit; S4 default is strict) + mock sig-invalid
//!       → exit 0, warning line with TNG-INDEX-SIGNATURE-INVALID
//!   (3) manifest `index-trust "off"` + MILPA_INDEX_TRUST=strict + mock sig-invalid
//!       → exit 0  (off wins; gate is silent)
//!   (4) MILPA_INDEX_TRUST=off + manifest warn + mock sig-invalid
//!       → exit 0, warning (env=off is a no-op floor, warn still fires)
//!   (5) `--require-attested-index` + manifest warn + mock sig-invalid
//!       → exit 1, TNG-INDEX-SIGNATURE-INVALID
//!       (THE dead-flags regression: flag must be threaded to maybe_index)
//!
//! (The old scenario 6 — strict + no seam → TNG-INDEX-VERIFY-UNSUPPORTED — is gone: S4a
//! removed that stopgap. The real "strict really fails on a bad bundle end-to-end" test
//! lands in S4b once S5 provides a fixture bundle to fail on.)
//!
//! ITEM 2 — bundle-URL override regression:
//!
//!   (7) MILPA_INDEX_BUNDLE_URL=file:///dev/null + mock trusted + strict
//!       → exit 0  (override routes bundle fetch to /dev/null; mock fires cleanly)
//!       A missing bundle sidecar without the override would produce
//!       TNG-INDEX-BUNDLE-MALFORMED under strict, so this proves the override is used.

use std::path::Path;
use std::process::Command;

/// Path to the compiled `milpa` binary (set by Cargo at test-compile time).
const MILPA: &str = env!("CARGO_BIN_EXE_milpa");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a minimal `milpa.kdl` with no deps.
/// `index_trust`: if Some, adds `index-trust "<value>"` to the manifest.
fn write_manifest(dir: &Path, index_trust: Option<&str>) {
    let policy_line = index_trust
        .map(|p| format!("\nindex-trust \"{p}\""))
        .unwrap_or_default();
    std::fs::write(
        dir.join("milpa.kdl"),
        format!("name \"app\"\nkind \"application\"{policy_line}\n"),
    )
    .expect("write milpa.kdl");
}

/// Write a minimal valid `index.kdl` to `dir`; return its `file://` URL.
fn write_index(dir: &Path) -> String {
    let path = dir.join("index.kdl");
    std::fs::write(&path, "schema_version 1\n").expect("write index.kdl");
    format!("file://{}", path.display())
}

/// Run `milpa [global_flags] fetch` in `project_dir`.
///
/// Clears all MILPA_* env vars inherited from the test runner (prevents leakage),
/// then applies `cache_dir` isolation and the caller-supplied `env_vars`.
/// Returns `(exit_code, stderr_string)`.
fn run_fetch(
    project_dir: &Path,
    cache_dir: &Path,
    env_vars: &[(&str, &str)],
    global_flags: &[&str],
) -> (i32, String) {
    let mut cmd = Command::new(MILPA);

    // Clear known MILPA_* env vars so the test environment cannot pollute results.
    for var in &[
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
    ] {
        cmd.env_remove(var);
    }

    // Isolate the index cache (XDG_CACHE_HOME) and the CAS (MILPA_CACHE_DIR).
    cmd.env("XDG_CACHE_HOME", cache_dir);
    cmd.env("MILPA_CACHE_DIR", cache_dir);

    // Build the command: `-C <project> [global_flags] fetch`.
    cmd.arg("-C").arg(project_dir);
    cmd.args(global_flags);
    cmd.arg("fetch");

    // Apply test-specific env vars (may override the defaults above).
    for (k, v) in env_vars {
        cmd.env(k, v);
    }

    let out = cmd.output().expect("milpa binary must be runnable");
    let code = out.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stderr)
}

// ---------------------------------------------------------------------------
// Scenario 1: manifest strict + sig-invalid → exit 1, TNG-INDEX-SIGNATURE-INVALID
// ---------------------------------------------------------------------------

#[test]
fn strict_manifest_sig_invalid_exits_one_with_slug() {
    let tmp = tempfile::TempDir::new().unwrap();
    let proj = tmp.path().join("proj");
    let cache = tmp.path().join("cache");
    let idx_dir = tmp.path().join("idx");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&idx_dir).unwrap();

    write_manifest(&proj, Some("strict"));
    let index_url = write_index(&idx_dir);

    let (code, stderr) = run_fetch(
        &proj,
        &cache,
        &[
            ("MILPA_INDEX_URL", &index_url),
            ("MILPA_INDEX_BUNDLE_URL", "file:///dev/null"),
            ("MILPA_INDEX_TRUST_MOCK_VERIFIER", "sig-invalid"),
        ],
        &[],
    );

    assert_ne!(
        code, 0,
        "strict + sig-invalid must fail; got exit {code}\nstderr:\n{stderr}"
    );
    assert_ne!(
        code, 101,
        "must not be a panic (exit 101); got {code}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("TNG-INDEX-SIGNATURE-INVALID"),
        "stderr must contain TNG-INDEX-SIGNATURE-INVALID\nstderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: manifest warn (explicit) + sig-invalid → exit 0, warning with slug
// ---------------------------------------------------------------------------

#[test]
fn warn_manifest_sig_invalid_exits_zero_with_warning() {
    let tmp = tempfile::TempDir::new().unwrap();
    let proj = tmp.path().join("proj");
    let cache = tmp.path().join("cache");
    let idx_dir = tmp.path().join("idx");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&idx_dir).unwrap();

    write_manifest(&proj, Some("warn")); // explicit warn (S4 flipped the default to strict)
    let index_url = write_index(&idx_dir);

    let (code, stderr) = run_fetch(
        &proj,
        &cache,
        &[
            ("MILPA_INDEX_URL", &index_url),
            ("MILPA_INDEX_BUNDLE_URL", "file:///dev/null"),
            ("MILPA_INDEX_TRUST_MOCK_VERIFIER", "sig-invalid"),
        ],
        &[],
    );

    assert_eq!(
        code, 0,
        "warn + sig-invalid must exit 0 (warning, not error)\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("TNG-INDEX-SIGNATURE-INVALID"),
        "stderr must contain the warning slug TNG-INDEX-SIGNATURE-INVALID\nstderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 3: manifest off + MILPA_INDEX_TRUST=strict → off wins, gate silent
// ---------------------------------------------------------------------------

#[test]
fn manifest_off_wins_over_env_strict() {
    // If the regression fires (off no longer wins), the mock sig-invalid under
    // effective strict policy would produce exit 1 — the assertion catches it.
    let tmp = tempfile::TempDir::new().unwrap();
    let proj = tmp.path().join("proj");
    let cache = tmp.path().join("cache");
    let idx_dir = tmp.path().join("idx");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&idx_dir).unwrap();

    write_manifest(&proj, Some("off"));
    let index_url = write_index(&idx_dir);

    let (code, stderr) = run_fetch(
        &proj,
        &cache,
        &[
            ("MILPA_INDEX_URL", &index_url),
            ("MILPA_INDEX_TRUST", "strict"),
            // With off winning, the mock verifier branch is never reached;
            // these are set to confirm that even with sig-invalid in scope,
            // the off path returns cleanly.
            ("MILPA_INDEX_BUNDLE_URL", "file:///dev/null"),
            ("MILPA_INDEX_TRUST_MOCK_VERIFIER", "sig-invalid"),
        ],
        &[],
    );

    assert_eq!(
        code, 0,
        "manifest off must silence the trust gate even when MILPA_INDEX_TRUST=strict; \
         got exit {code}\nstderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 4: MILPA_INDEX_TRUST=off + manifest warn → warn still fires (no-op floor)
// ---------------------------------------------------------------------------

#[test]
fn env_off_is_noop_floor_manifest_warn_still_fires() {
    // MILPA_INDEX_TRUST=off cannot downgrade a manifest's warn policy.
    // effective_trust_policy(Warn, false, Some(Off)) == Warn.
    let tmp = tempfile::TempDir::new().unwrap();
    let proj = tmp.path().join("proj");
    let cache = tmp.path().join("cache");
    let idx_dir = tmp.path().join("idx");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&idx_dir).unwrap();

    write_manifest(&proj, Some("warn")); // explicit manifest warn (S4 flipped the default to strict)
    let index_url = write_index(&idx_dir);

    let (code, stderr) = run_fetch(
        &proj,
        &cache,
        &[
            ("MILPA_INDEX_URL", &index_url),
            ("MILPA_INDEX_TRUST", "off"), // env=off must NOT suppress manifest warn
            ("MILPA_INDEX_BUNDLE_URL", "file:///dev/null"),
            ("MILPA_INDEX_TRUST_MOCK_VERIFIER", "sig-invalid"),
        ],
        &[],
    );

    assert_eq!(
        code, 0,
        "env=off cannot suppress manifest warn; expect exit 0\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("TNG-INDEX-SIGNATURE-INVALID"),
        "warn must still fire (env=off is a no-op floor)\nstderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 5: --require-attested-index + manifest warn + sig-invalid → exit 1
//   This is the test that would have caught the dead-flags bug.
// ---------------------------------------------------------------------------

#[test]
fn require_attested_index_flag_escalates_warn_to_strict() {
    // --require-attested-index escalates manifest warn → effective strict.
    // Pre-fix bug: the flag was parsed but every maybe_index call site passed
    // literal `false` for require_attested_index, so the flag was a no-op.
    // This test would have turned red immediately if that regression re-appeared.
    let tmp = tempfile::TempDir::new().unwrap();
    let proj = tmp.path().join("proj");
    let cache = tmp.path().join("cache");
    let idx_dir = tmp.path().join("idx");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&idx_dir).unwrap();

    write_manifest(&proj, Some("warn")); // explicit warn; flag must escalate to strict (S4: default is now strict)
    let index_url = write_index(&idx_dir);

    let (code, stderr) = run_fetch(
        &proj,
        &cache,
        &[
            ("MILPA_INDEX_URL", &index_url),
            ("MILPA_INDEX_BUNDLE_URL", "file:///dev/null"),
            ("MILPA_INDEX_TRUST_MOCK_VERIFIER", "sig-invalid"),
        ],
        &["--require-attested-index"], // global flag before verb
    );

    assert_ne!(
        code, 0,
        "--require-attested-index must escalate warn→strict (exit non-zero); \
         got exit 0\nstderr:\n{stderr}"
    );
    assert_ne!(
        code, 101,
        "must not be a panic (exit 101)\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("TNG-INDEX-SIGNATURE-INVALID"),
        "strict escalation must produce TNG-INDEX-SIGNATURE-INVALID\nstderr:\n{stderr}"
    );
}

// Scenario 6 (strict + no seam → TNG-INDEX-VERIFY-UNSUPPORTED) was removed in S4a along
// with the stopgap it asserted. The real end-to-end "strict fails on a bad bundle" test
// lands in S4b, once S5 supplies a fixture bundle to fail on.

// ---------------------------------------------------------------------------
// Scenario 7 (ITEM 2): MILPA_INDEX_BUNDLE_URL override is used by bundle transport
// ---------------------------------------------------------------------------

#[test]
fn bundle_url_override_routes_bundle_fetch_to_override_path() {
    // Proves that MILPA_INDEX_BUNDLE_URL is actually consulted by the bundle
    // transport, not just parsed.
    //
    // Setup: manifest strict + mock=trusted + MILPA_INDEX_URL pointing at a
    // valid index.kdl + MILPA_INDEX_BUNDLE_URL=file:///dev/null.
    //
    // Without the override, the derived bundle URL would be
    // `<index_url>.bundle` — a file that does NOT exist.  Under strict policy,
    // a missing/malformed bundle → TNG-INDEX-BUNDLE-MALFORMED → exit 1.
    //
    // With the override pointing at /dev/null, curl returns empty bytes (OK),
    // MockVerifier=trusted fires → success → exit 0.
    //
    // So: if the override is not consulted, exit ≠ 0; if it is, exit == 0.
    let tmp = tempfile::TempDir::new().unwrap();
    let proj = tmp.path().join("proj");
    let cache = tmp.path().join("cache");
    let idx_dir = tmp.path().join("idx");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&idx_dir).unwrap();

    write_manifest(&proj, Some("strict")); // strict to engage the full gate
    let index_url = write_index(&idx_dir);
    // Deliberately do NOT create index.kdl.bundle — its absence is the discriminator.

    let (code, stderr) = run_fetch(
        &proj,
        &cache,
        &[
            ("MILPA_INDEX_URL", &index_url),
            ("MILPA_INDEX_BUNDLE_URL", "file:///dev/null"), // override to readable file
            ("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted"),
        ],
        &[],
    );

    assert_eq!(
        code, 0,
        "MILPA_INDEX_BUNDLE_URL override must route bundle fetch to /dev/null \
         (trusted mock → success); got exit {code}\nstderr:\n{stderr}"
    );
}
