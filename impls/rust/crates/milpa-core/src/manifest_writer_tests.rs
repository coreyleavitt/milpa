//! Unit tests for manifest mutation (S13). The MAN-MUTATE-* codes are not
//! fixture-expressible (the corpus never invokes the mutating verbs), so they
//! are covered here.

use super::*;

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn identity(m: Manifest) -> Manifest {
    m
}

#[test]
fn missing_file_is_man_mutate_file_not_found() {
    let d = tmp();
    let err = mutate_manifest_file(&d.path().join("milpa.kdl"), identity).unwrap_err();
    assert_eq!(err.code(), "MAN-MUTATE-FILE-NOT-FOUND");
}

#[test]
fn nimble_is_refused() {
    let d = tmp();
    let p = d.path().join("foo.nimble");
    std::fs::write(&p, "requires \"x\"\n").unwrap();
    assert_eq!(
        mutate_manifest_file(&p, identity).unwrap_err().code(),
        "MAN-MUTATE-NIMBLE-REFUSED"
    );
}

#[test]
fn workspace_is_refused() {
    let d = tmp();
    let p = d.path().join("milpa.kdl");
    std::fs::write(&p, "workspace {\n    member \"a\"\n}\n").unwrap();
    assert_eq!(
        mutate_manifest_file(&p, identity).unwrap_err().code(),
        "MAN-MUTATE-WORKSPACE-REFUSED"
    );
}

#[test]
fn add_dep_rewrites_canonically_and_reports_comment_loss() {
    let d = tmp();
    let p = d.path().join("milpa.kdl");
    // Two hand-written comments; the canonical render keeps only its 1 header.
    std::fs::write(
        &p,
        "// my project\nname \"app\"\nkind \"application\"\n// end\n",
    )
    .unwrap();

    let res = mutate_manifest_file(&p, |mut m| {
        m.deps
            .push(milpa_manifest::Dep::Named(milpa_manifest::NamedDep {
                name: "newdep".into(),
                constraint: None,
                parsed_constraint: None,
            }));
        m
    })
    .unwrap();

    assert_eq!(
        res.comments_lost, 1,
        "2 source comments → 1 header retained"
    );
    let written = std::fs::read_to_string(&p).unwrap();
    assert!(written.contains("deps {"));
    assert!(written.contains("\"newdep\""));
    // Re-parse confirms the rewrite is valid + the dep landed.
    match milpa_manifest::parse_document(&written).unwrap() {
        milpa_manifest::ManifestDoc::Package(m) => {
            assert!(m.deps.iter().any(|dep| dep.name() == "newdep"));
        }
        other => panic!("expected package, got {other:?}"),
    }
}

/// Make a throwaway git repo at `dir` containing `files` (name→bytes); return
/// HEAD sha. `-c user.*` is safe here (disposable fixture, not the milpa repo).
fn make_repo(dir: &std::path::Path, files: &[(&str, &[u8])]) -> Option<String> {
    std::fs::create_dir_all(dir).ok()?;
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["init", "-q", "-b", "main"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    for (name, data) in files {
        std::fs::write(dir.join(name), data).ok()?;
    }
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
    git(&["add", "."])?;
    git(&["commit", "-q", "-m", "c"])?;
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Build a project (milpa.kdl with a url dep + a milpa.lock pinning its identity
/// to `identity`) so `add_mirror` has something to validate against.
fn project_with_dep(dir: &std::path::Path, canonical_url: &str, identity: &str) {
    std::fs::write(
        dir.join("milpa.kdl"),
        format!(
            "name \"app\"\nkind \"application\"\ndeps {{\n    foo git=(url)\"{canonical_url}\" ref=\"main\"\n}}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("milpa.lock"),
        format!(
            "version 1\nstrategy \"maxver\"\ndep \"foo\" {{\n    identity \"{identity}\"\n    version \"0.0.1\"\n    \
             provenance {{\n        kind \"git\"\n        url \"{canonical_url}\"\n        ref \"main\"\n    }}\n}}\n"
        ),
    )
    .unwrap();
}

// The manifest's *canonical* URL only needs to parse (a valid scheme); add_mirror
// fetches the MIRROR URL, where a `file://` local repo is fine for git clone.
const CANON_URL: &str = "https://example.com/foo.git";

#[test]
fn add_mirror_accepts_identical_content_and_records_it() {
    let d = tmp();
    let mirror = d.path().join("mirror");
    if make_repo(&mirror, &[("foo.nim", b"echo 1")]).is_none() {
        eprintln!("skipping: git unavailable");
        return;
    }
    // Lock the dep at the mirror's own content hash → the fetch must match.
    let identity = crate::compute_content_hash(&mirror).unwrap();
    let proj = d.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    project_with_dep(&proj, CANON_URL, &identity);

    let mirror_url = format!("file://{}", mirror.display());
    add_mirror(&proj, "foo", &mirror_url).unwrap();
    let written = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
    assert!(written.contains(&format!("mirror (url)\"{mirror_url}\"")));
}

#[test]
fn add_mirror_rejects_divergent_content() {
    let d = tmp();
    let mirror = d.path().join("mirror");
    if make_repo(&mirror, &[("foo.nim", b"echo 1")]).is_none() {
        eprintln!("skipping: git unavailable");
        return;
    }
    // Lock the dep at a DIFFERENT identity → the mirror's content won't match.
    let bogus = format!("sha256:{}", "0".repeat(64));
    let proj = d.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    project_with_dep(&proj, CANON_URL, &bogus);

    let err = add_mirror(&proj, "foo", &format!("file://{}", mirror.display())).unwrap_err();
    assert_eq!(err.code(), "MAN-ADD-MIRROR-IDENTITY-MISMATCH");
}

#[test]
fn malformed_package_surfaces_its_parse_code() {
    let d = tmp();
    let p = d.path().join("milpa.kdl");
    std::fs::write(&p, "kind \"library\"\n").unwrap(); // no name
    assert_eq!(
        mutate_manifest_file(&p, identity).unwrap_err().code(),
        "MAN-NAME-MISSING"
    );
}
