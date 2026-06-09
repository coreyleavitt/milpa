//! Unit/integration tests for the real fetchers (S14c). Offline: Local is a
//! pure copy; Git drives the `git` CLI against *local* repos (no network). The
//! FETCH-* codes aren't fixture-expressible (the corpus uses the FakeFetcher).

use super::*;

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

// --- Local -----------------------------------------------------------------

#[test]
fn local_copies_a_dir_tree() {
    let d = tmp();
    let src = d.path().join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.nim"), b"a").unwrap();
    std::fs::write(src.join("sub/b.nim"), b"b").unwrap();

    let dest = d.path().join("_deps/x");
    let r = fetch_local("x", &src, &dest).unwrap();
    assert_eq!(r.resolved_ref, None);
    assert_eq!(std::fs::read(dest.join("a.nim")).unwrap(), b"a");
    assert_eq!(std::fs::read(dest.join("sub/b.nim")).unwrap(), b"b");
}

#[test]
fn local_missing_path_is_not_found() {
    let d = tmp();
    let err = fetch_local("x", &d.path().join("nope"), &d.path().join("dest")).unwrap_err();
    assert_eq!(err.code(), "FETCH-LOCAL-PATH-NOT-FOUND");
}

#[test]
fn local_file_path_is_not_a_dir() {
    let d = tmp();
    let f = d.path().join("file");
    std::fs::write(&f, b"x").unwrap();
    let err = fetch_local("x", &f, &d.path().join("dest")).unwrap_err();
    assert_eq!(err.code(), "FETCH-LOCAL-PATH-NOT-DIR");
}

// --- Git (local repos, no network) -----------------------------------------

/// Create a throwaway git repo at `dir` with one commit; return its HEAD sha.
/// Uses `-c user.*` overrides — safe here (a disposable fixture repo, NOT the
/// milpa repo whose history the global config protects).
fn make_repo(dir: &std::path::Path) -> Option<String> {
    std::fs::create_dir_all(dir).ok()?;
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.email=t@t", "-c", "user.name=t"])
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    // `git init` doesn't accept the -c user.* config args cleanly in all
    // versions; run it bare.
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["init", "-q", "-b", "main"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    std::fs::write(dir.join("foo.nim"), b"echo 1").ok()?;
    git(&["add", "."])?;
    git(&["commit", "-q", "-m", "init"])?;
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[test]
fn git_clones_and_checks_out_pinned_commit() {
    let d = tmp();
    let repo = d.path().join("origin");
    let Some(sha) = make_repo(&repo) else {
        eprintln!("skipping: git unavailable");
        return;
    };
    let dest = d.path().join("_deps/dep");
    let r = fetch_git("dep", &repo.to_string_lossy(), "main", Some(&sha), &dest).unwrap();
    assert_eq!(r.resolved_ref.as_deref(), Some(sha.as_str()));
    assert!(dest.join("foo.nim").is_file());
}

#[test]
fn git_clone_of_nonexistent_repo_is_git_failed() {
    let d = tmp();
    let missing = d.path().join("no-such-repo");
    let err = fetch_git(
        "dep",
        &missing.to_string_lossy(),
        "main",
        None,
        &d.path().join("dest"),
    )
    .unwrap_err();
    // Either a clone failure (git present) — both map to FETCH-GIT-FAILED.
    assert_eq!(err.code(), "FETCH-GIT-FAILED");
}

#[test]
fn git_absent_pinned_commit_is_commit_absent() {
    let d = tmp();
    let repo = d.path().join("origin");
    if make_repo(&repo).is_none() {
        eprintln!("skipping: git unavailable");
        return;
    }
    let bogus = "0".repeat(40);
    let dest = d.path().join("_deps/dep");
    let err = fetch_git("dep", &repo.to_string_lossy(), "main", Some(&bogus), &dest).unwrap_err();
    assert_eq!(err.code(), "FETCH-GIT-COMMIT-ABSENT");
}

// --- dispatch --------------------------------------------------------------

#[test]
fn registry_dispatches_local() {
    let d = tmp();
    let src = d.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("x"), b"x").unwrap();
    let prov = Provenance::Local {
        path: src.to_string_lossy().into_owned(),
    };
    let dest = d.path().join("_deps/x");
    let r = DefaultRegistry.fetch("x", &prov, &dest).unwrap();
    assert_eq!(r.resolved_ref, None);
    assert!(dest.join("x").is_file());
}
