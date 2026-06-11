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
    let r = DefaultRegistry::with_curl()
        .fetch("x", &prov, &dest)
        .unwrap();
    assert_eq!(r.resolved_ref, None);
    assert!(dest.join("x").is_file());
}

// --- Tarball (injected http, offline) --------------------------------------

/// A minimal uncompressed USTAR archive containing one regular file.
fn single_file_tar(name: &str, data: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    let nb = name.as_bytes();
    h[..nb.len().min(100)].copy_from_slice(&nb[..nb.len().min(100)]);
    h[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
    h[156] = b'0';
    let mut out = h.to_vec();
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out.extend(std::iter::repeat_n(0u8, 1024)); // end-of-archive
    out
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}

#[test]
fn tarball_extracts_raw_tar() {
    let d = tmp();
    let tar = single_file_tar("foo.nim", b"echo 1");
    let http = move |_: &str| Ok(tar.clone());
    let dest = d.path().join("_deps/foo");
    fetch_tarball("foo", "https://e/foo.tar", None, 0, &dest, &http).unwrap();
    assert_eq!(std::fs::read(dest.join("foo.nim")).unwrap(), b"echo 1");
}

#[test]
fn tarball_extracts_gzip() {
    let d = tmp();
    let tgz = gzip(&single_file_tar("foo.nim", b"gz"));
    let http = move |_: &str| Ok(tgz.clone());
    let dest = d.path().join("_deps/foo");
    fetch_tarball("foo", "https://e/foo.tar.gz", None, 0, &dest, &http).unwrap();
    assert_eq!(std::fs::read(dest.join("foo.nim")).unwrap(), b"gz");
}

#[test]
fn tarball_sha256_mismatch_rejects_before_extraction() {
    let d = tmp();
    let tar = single_file_tar("foo.nim", b"x");
    let http = move |_: &str| Ok(tar.clone());
    let dest = d.path().join("_deps/foo");
    let err = fetch_tarball(
        "foo",
        "https://e/foo.tar",
        Some("sha256:deadbeef"),
        0,
        &dest,
        &http,
    )
    .unwrap_err();
    assert_eq!(err.code(), "FETCH-SHA256-MISMATCH");
    assert!(!dest.exists(), "rejected before extraction");
}

#[test]
fn tarball_sha256_match_accepts() {
    let d = tmp();
    let tar = single_file_tar("foo.nim", b"x");
    let want = super::sha256_hex(&tar);
    let http = move |_: &str| Ok(tar.clone());
    let dest = d.path().join("_deps/foo");
    fetch_tarball("foo", "https://e/foo.tar", Some(&want), 0, &dest, &http).unwrap();
    assert!(dest.join("foo.nim").is_file());
}

#[test]
fn tarball_download_failure_is_download_failed() {
    let d = tmp();
    let http = |_: &str| Err("connection refused".to_string());
    let err = fetch_tarball(
        "foo",
        "https://e/foo.tar",
        None,
        0,
        &d.path().join("dest"),
        &http,
    )
    .unwrap_err();
    assert_eq!(err.code(), "FETCH-DOWNLOAD-FAILED");
}

// --- OCI (oras almost certainly absent in the container → pull-failed) ------

#[test]
fn oci_pull_failure_is_pull_failed() {
    let d = tmp();
    let err = fetch_oci(
        "x",
        "ghcr.io",
        "org/pkg",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        &d.path().join("_deps/x"),
    )
    .unwrap_err();
    // oras absent (or the digest unresolvable) → pull failure.
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
}

// --- CasAdmittingFetcher ---------------------------------------------------

#[test]
fn cas_admitting_fetcher_produces_cas_symlink_at_dest() {
    // The mocked path goes through CasAdmittingFetcher → dest is a symlink,
    // not a real directory (BLOCKER-R1 fix: issue #118).
    let d = tmp();
    let mocked = d.path().join("mocked-fetches");
    let key = super::url_key("https://github.com/example/bar.git", "main");
    let key_dir = mocked.join(&key);
    std::fs::create_dir_all(key_dir.join("content")).unwrap();
    std::fs::write(
        key_dir.join("sha"),
        "abcdef1234567890abcdef1234567890abcdef12\n",
    )
    .unwrap();
    std::fs::write(key_dir.join("content").join("bar.nim"), b"# bar").unwrap();

    let cas_root = d.path().join(".cas");
    let store = crate::store::CaStore::new(&cas_root);
    let fetcher = super::CasAdmittingFetcher::new(
        super::MockedFetcher::new(&mocked),
        store,
        d.path().join("staging"),
    );

    std::fs::create_dir_all(d.path().join("_deps")).unwrap();
    let dest = d.path().join("_deps").join("bar");
    let p = milpa_types::Provenance::Git {
        url: "https://github.com/example/bar.git".into(),
        ref_spec: "main".into(),
        commit_sha: None,
    };
    let receipt = FetcherRegistry::fetch(&fetcher, "bar", &p, &dest).unwrap();

    // Receipt carries the SHA from the mock fixture.
    assert_eq!(
        receipt.resolved_ref.as_deref(),
        Some("abcdef1234567890abcdef1234567890abcdef12")
    );

    // dest MUST be a symlink, not a real directory (the R1 fix).
    let meta = std::fs::symlink_metadata(&dest).unwrap();
    assert!(
        meta.file_type().is_symlink(),
        "_deps/bar must be a CAS symlink, not a real directory"
    );

    // The symlink target is relative (identity.md §3.4).
    let link_target = std::fs::read_link(&dest).unwrap();
    assert!(
        link_target.is_relative(),
        "CAS symlink target must be relative, got {link_target:?}"
    );

    // Content is accessible through the symlink.
    assert_eq!(std::fs::read(dest.join("bar.nim")).unwrap(), b"# bar");

    // The CAS entry lives under <cas_root>/sha256/<hex>/.
    assert!(cas_root.join("sha256").is_dir());
}

// Local provenance through CasAdmittingFetcher must NOT be admitted to CAS.
// spec/plugin-contract.md §4: editable sources declare cas_admissible = false,
// so the registry skips admit+link and materializes a real working dir at dest.
#[test]
fn cas_admitting_fetcher_local_provenance_stays_real_dir() {
    let d = tmp();
    let src = d.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("local.nim"), b"# local").unwrap();

    let cas_root = d.path().join(".cas");
    let store = crate::store::CaStore::new(&cas_root);
    let inner = super::DefaultRegistry::with_curl();
    let fetcher = super::CasAdmittingFetcher::new(inner, store, d.path().join("staging"));

    std::fs::create_dir_all(d.path().join("_deps")).unwrap();
    let dest = d.path().join("_deps").join("local_dep");
    let p = milpa_types::Provenance::Local {
        path: src.to_string_lossy().into_owned(),
    };
    FetcherRegistry::fetch(&fetcher, "local_dep", &p, &dest).unwrap();

    // Must be a real directory, NOT a CAS symlink (plugin-contract §4).
    let meta = std::fs::symlink_metadata(&dest).unwrap();
    assert!(
        meta.file_type().is_dir(),
        "Local provenance through CasAdmittingFetcher must stay a real dir, not a symlink"
    );
    assert!(
        !meta.file_type().is_symlink(),
        "Local provenance must not be admitted to CAS (would freeze user edits)"
    );

    // CAS must NOT have been populated (no sha256/ subdir created).
    assert!(
        !cas_root.join("sha256").is_dir(),
        "CAS must not be populated for Local provenance"
    );

    // Content is readable from the real dir.
    assert_eq!(std::fs::read(dest.join("local.nim")).unwrap(), b"# local");
}

// --- url_key (§2.3.1) -------------------------------------------------------

#[test]
fn url_key_encodes_the_spec_example() {
    assert_eq!(
        super::url_key("https://github.com/example/foo.git", "main"),
        "https___github.com_example_foo.git@main"
    );
}

#[test]
fn url_key_separator_at_is_literal_but_ref_at_is_substituted() {
    assert_eq!(
        super::url_key("https://x.example/r.git", "v1@beta"),
        "https___x.example_r.git@v1_beta"
    );
}

#[test]
fn url_key_preserves_allowed_class() {
    assert_eq!(super::url_key("a.b_c-d", "1.2.3-rc.4"), "a.b_c-d@1.2.3-rc.4");
}

// --- MockedFetcher ----------------------------------------------------------

#[test]
fn mocked_fetcher_copies_content_and_returns_sha() {
    let d = tmp();
    let mocked = d.path().join("mocked-fetches");
    let key = super::url_key("https://github.com/example/foo.git", "main");
    let key_dir = mocked.join(&key);
    std::fs::create_dir_all(key_dir.join("content")).unwrap();
    std::fs::write(
        key_dir.join("sha"),
        "abcdef1234567890abcdef1234567890abcdef12\n",
    )
    .unwrap();
    std::fs::write(key_dir.join("content").join("foo.nim"), b"# src").unwrap();
    std::fs::write(key_dir.join("foo.nimble"), b"version = \"1.0.0\"").unwrap();

    let fetcher = super::MockedFetcher::new(&mocked);
    let dest = d.path().join("_deps").join("foo");
    std::fs::create_dir_all(d.path().join("_deps")).unwrap();
    let p = milpa_types::Provenance::Git {
        url: "https://github.com/example/foo.git".into(),
        ref_spec: "main".into(),
        commit_sha: None,
    };
    let receipt = FetcherRegistry::fetch(&fetcher, "foo", &p, &dest).unwrap();

    assert_eq!(
        receipt.resolved_ref.as_deref(),
        Some("abcdef1234567890abcdef1234567890abcdef12")
    );
    assert_eq!(std::fs::read(dest.join("foo.nim")).unwrap(), b"# src");
    assert!(dest.join("foo.nimble").is_file());
}

// --- mocked ref-resolution (conformance-fixtures §2.3.3) --------------------

#[test]
fn mocked_default_branch_resolves_ref_from_mock_entry_without_network() {
    let d = tmp();
    let mocked = d.path().join("mocked-fetches");
    // One entry keyed url@main; mocked_default_branch should return "main".
    let key = super::url_key("https://github.com/example/foo.git", "main");
    let key_dir = mocked.join(&key);
    std::fs::create_dir_all(key_dir.join("content")).unwrap();
    std::fs::write(
        key_dir.join("sha"),
        "abcdef1234567890abcdef1234567890abcdef12\n",
    )
    .unwrap();

    let r =
        super::mocked_default_branch(&mocked, "https://github.com/example/foo.git").unwrap();
    assert_eq!(r, "main");
}

#[test]
fn mocked_default_branch_uses_same_entry_as_fetch_sha_ssot() {
    // The ref discovered by mocked_default_branch must point at the very same
    // entry resolve_mock_key reads for its sha — single source of truth.
    let d = tmp();
    let mocked = d.path().join("mocked-fetches");
    let url = "https://github.com/example/bar.git";
    let key = super::url_key(url, "trunk");
    let key_dir = mocked.join(&key);
    std::fs::create_dir_all(key_dir.join("content")).unwrap();
    std::fs::write(key_dir.join("sha"), "0123456789012345678901234567890123456789\n")
        .unwrap();

    let discovered = super::mocked_default_branch(&mocked, url).unwrap();
    assert_eq!(discovered, "trunk");
    let (sha, _) = super::resolve_mock_key(&mocked, url, &discovered).unwrap();
    assert_eq!(sha, "0123456789012345678901234567890123456789");
}

#[test]
fn mocked_default_branch_no_entry_is_error() {
    let d = tmp();
    let mocked = d.path().join("mocked-fetches");
    std::fs::create_dir_all(&mocked).unwrap();
    let err = super::mocked_default_branch(&mocked, "https://example.com/none.git")
        .unwrap_err();
    // Non-catalog Failed — surfaced by the caller as a discovery failure.
    match err {
        super::FetchError::Failed(m) => assert!(m.contains("no mocked-fetches entry"), "{m}"),
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn mocked_fetcher_missing_key_is_fetch_mock_missing() {
    let d = tmp();
    let fetcher = super::MockedFetcher::new(d.path().join("mocked-fetches"));
    let p = milpa_types::Provenance::Git {
        url: "https://example.com/x.git".into(),
        ref_spec: "main".into(),
        commit_sha: None,
    };
    let err =
        FetcherRegistry::fetch(&fetcher, "x", &p, &d.path().join("dest")).unwrap_err();
    assert_eq!(err.code(), "FETCH-MOCK-MISSING");
}
