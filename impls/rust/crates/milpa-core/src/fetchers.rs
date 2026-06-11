//! Real transport fetchers + the dispatching registry (RFC §6 S14c; mirrors
//! `milpa/fetchers/{local,git,...}.py` + the `FetcherRegistry` dispatch).
//!
//! [`DefaultRegistry`] matches the closed [`Provenance`] enum and routes to a
//! per-transport fetch. Identity is **never** reported by a fetcher — the caller
//! (resolver / CAS) computes it from the materialized bytes, so a fetcher can't
//! lie about content (RFC §4.6).
//!
//! **This sub-slice wires Local + Git** (both offline-testable: Local is a pure
//! directory copy; Git drives the `git` CLI, exercised against *local* repos in
//! tests — no network). Tarball (http + gzip + safe_extract) and OCI (oras) land
//! in the next sub-slice; their dispatch arms return a clearly-marked
//! non-catalog placeholder until then.

use std::io::Read;
use std::path::Path;
use std::process::Command;

use flate2::read::GzDecoder;
use milpa_types::Provenance;
use sha2::{Digest, Sha256};

use crate::fetch::{FetchError, FetcherRegistry, Receipt};
use crate::safe_extract::{extract_tar, Limits};

fn transport(code: &'static str, message: impl Into<String>) -> FetchError {
    FetchError::Transport(code, message.into())
}

/// A byte-fetching transport (an injected seam, like the index cache's): maps a
/// URL to its bytes, or an error string. `DefaultRegistry::with_curl` uses the
/// `curl` CLI; tests inject a closure.
pub type HttpGet = Box<dyn Fn(&str) -> Result<Vec<u8>, String>>;

/// The reference [`FetcherRegistry`]: dispatch the closed `Provenance` enum to a
/// per-transport fetch. Carries an [`HttpGet`] for the tarball transport.
pub struct DefaultRegistry {
    http_get: HttpGet,
}

impl DefaultRegistry {
    /// A registry whose tarball downloads use a custom byte transport.
    pub fn new(http_get: impl Fn(&str) -> Result<Vec<u8>, String> + 'static) -> Self {
        DefaultRegistry {
            http_get: Box::new(http_get),
        }
    }

    /// The production registry: tarball downloads shell out to `curl -fsSL`.
    pub fn with_curl() -> Self {
        DefaultRegistry::new(|url| {
            let out = Command::new("curl")
                .args(["-fsSL", url])
                .output()
                .map_err(|e| format!("cannot run curl: {e}"))?;
            if out.status.success() {
                Ok(out.stdout)
            } else {
                Err(format!(
                    "curl failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ))
            }
        })
    }
}

impl FetcherRegistry for DefaultRegistry {
    fn fetch(&self, name: &str, p: &Provenance, dest: &Path) -> Result<Receipt, FetchError> {
        match p {
            Provenance::Local { path } => fetch_local(name, Path::new(path), dest),
            Provenance::Git {
                url,
                ref_spec,
                commit_sha,
            } => fetch_git(name, url, ref_spec, commit_sha.as_deref(), dest),
            Provenance::Tarball {
                url,
                expected_sha256,
                strip_components,
            } => fetch_tarball(
                name,
                url,
                expected_sha256.as_deref(),
                *strip_components,
                dest,
                self.http_get.as_ref(),
            ),
            Provenance::Oci {
                registry,
                repository,
                digest,
            } => fetch_oci(name, registry, repository, digest, dest),
        }
    }
}

/// Copy a local source tree into `dest` (mirrors `LocalFetcher`).
/// `FETCH-LOCAL-PATH-NOT-FOUND` / `FETCH-LOCAL-PATH-NOT-DIR` on a bad source.
pub fn fetch_local(name: &str, src: &Path, dest: &Path) -> Result<Receipt, FetchError> {
    if !src.exists() {
        return Err(transport(
            "FETCH-LOCAL-PATH-NOT-FOUND",
            format!(
                "fetching {name:?}: local source path does not exist: {}",
                src.display()
            ),
        ));
    }
    if !src.is_dir() {
        return Err(transport(
            "FETCH-LOCAL-PATH-NOT-DIR",
            format!(
                "fetching {name:?}: local source path is not a directory: {}",
                src.display()
            ),
        ));
    }
    clear_dest(dest).map_err(|e| transport("FETCH-LOCAL-PATH-NOT-DIR", e))?;
    copy_tree(src, dest)
        .map_err(|e| transport("FETCH-LOCAL-PATH-NOT-DIR", format!("copying {name:?}: {e}")))?;
    // A local copy carries no resolved ref; its provenance evidence is the
    // declared path, recorded by the resolver.
    Ok(Receipt {
        resolved_ref: None,
        archive_sha256: None,
    })
}

/// Clone `url` into `dest` and check out the pinned commit (or `ref_spec`).
/// `FETCH-GIT-FAILED` on a clone/checkout failure; `FETCH-GIT-COMMIT-ABSENT` if
/// the pinned commit isn't present after cloning. Mirrors `GitFetcher`.
pub fn fetch_git(
    name: &str,
    url: &str,
    ref_spec: &str,
    commit_sha: Option<&str>,
    dest: &Path,
) -> Result<Receipt, FetchError> {
    clear_dest(dest).map_err(|e| transport("FETCH-GIT-FAILED", e))?;
    run_git(name, &["clone", "-q", url, &dest.to_string_lossy()])?;

    match commit_sha {
        Some(sha) => {
            // Exact-commit pin (Invariant 2): verify the commit is present
            // before checkout, so an absent pin is a clear coded error.
            if !commit_present(dest, sha) {
                let _ = std::fs::remove_dir_all(dest);
                return Err(transport(
                    "FETCH-GIT-COMMIT-ABSENT",
                    format!("fetching {name:?}: pinned commit {sha} not present in {url}"),
                ));
            }
            run_git_in(name, dest, &["checkout", "-q", sha])?;
        }
        None => {
            run_git_in(name, dest, &["checkout", "-q", ref_spec])?;
        }
    }

    Ok(Receipt {
        resolved_ref: git_head_sha(dest),
        archive_sha256: None,
    })
}

fn run_git(name: &str, args: &[&str]) -> Result<(), FetchError> {
    git_status(name, Command::new("git").args(args))
}

fn run_git_in(name: &str, dir: &Path, args: &[&str]) -> Result<(), FetchError> {
    git_status(name, Command::new("git").arg("-C").arg(dir).args(args))
}

fn git_status(name: &str, cmd: &mut Command) -> Result<(), FetchError> {
    let out = cmd.output().map_err(|e| {
        transport(
            "FETCH-GIT-FAILED",
            format!("fetching {name:?}: cannot run git: {e}"),
        )
    })?;
    if out.status.success() {
        Ok(())
    } else {
        Err(transport(
            "FETCH-GIT-FAILED",
            format!(
                "fetching {name:?}: git failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ))
    }
}

/// `git cat-file -e <sha>^{commit}` — true iff the commit object exists.
fn commit_present(dir: &Path, sha: &str) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["cat-file", "-e", &format!("{sha}^{{commit}}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn git_head_sha(dir: &Path) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

/// Download a tarball, verify its sha256 (before extraction), gunzip if needed,
/// and safe-extract into `dest` (mirrors `TarballFetcher`). `FETCH-DOWNLOAD-FAILED`
/// on transport error; `FETCH-SHA256-MISMATCH` if the declared hash differs (the
/// archive is rejected BEFORE any extraction); `FETCH-EXTRACT-FAILED` wrapping any
/// `safe_extract` violation.
pub fn fetch_tarball(
    name: &str,
    url: &str,
    expected_sha256: Option<&str>,
    strip_components: u32,
    dest: &Path,
    http_get: &dyn Fn(&str) -> Result<Vec<u8>, String>,
) -> Result<Receipt, FetchError> {
    let bytes = http_get(url).map_err(|e| {
        transport(
            "FETCH-DOWNLOAD-FAILED",
            format!("fetching {name:?} from {url}: {e}"),
        )
    })?;

    // Compute the archive digest once: it gates an existing pin (below) AND is
    // returned as the TOFU receipt so the resolver can record/preserve it
    // (`lockfile-schema.md §5`).
    let actual_sha = sha256_hex(&bytes);

    if let Some(expected) = expected_sha256 {
        // Accept a bare hex digest or a `sha256:`-prefixed one.
        let want = expected.strip_prefix("sha256:").unwrap_or(expected);
        if actual_sha != want {
            return Err(transport(
                "FETCH-SHA256-MISMATCH",
                format!(
                    "fetching {name:?}: archive sha256 mismatch — expected {expected}, got {actual_sha} \
                     (URL {url}); rejected before extraction"
                ),
            ));
        }
    }

    // gzip magic (1f 8b) → decompress; else treat the bytes as a raw tar.
    let tar_bytes = if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        let mut out = Vec::new();
        GzDecoder::new(&bytes[..])
            .read_to_end(&mut out)
            .map_err(|e| {
                transport(
                    "FETCH-EXTRACT-FAILED",
                    format!("fetching {name:?}: gunzip: {e}"),
                )
            })?;
        out
    } else {
        bytes
    };

    clear_dest(dest).map_err(|e| transport("FETCH-EXTRACT-FAILED", e))?;
    extract_tar(&tar_bytes, dest, strip_components, Limits::default()).map_err(|e| {
        let _ = std::fs::remove_dir_all(dest);
        // Re-key any EXTRACT-* (or other) failure as the tarball-transport code.
        transport(
            "FETCH-EXTRACT-FAILED",
            format!("fetching {name:?}: safe extraction failed ({})", e.code()),
        )
    })?;
    Ok(Receipt {
        resolved_ref: None,
        archive_sha256: Some(actual_sha),
    })
}

/// Pull an OCI artifact via `oras` and safe-extract its single source tarball
/// (mirrors `OciFetcher`). `FETCH-OCI-PULL-FAILED` (incl. `oras` absent);
/// `FETCH-OCI-NO-TARBALL` / `FETCH-OCI-AMBIGUOUS-TARBALL` on 0 / >1 `*.tar.gz`.
pub fn fetch_oci(
    name: &str,
    registry: &str,
    repository: &str,
    digest: &str,
    dest: &Path,
) -> Result<Receipt, FetchError> {
    let oci_ref = format!("{registry}/{repository}@{digest}");
    let scratch = dest
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".{name}.oci-pull"));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch)
        .map_err(|e| transport("FETCH-OCI-PULL-FAILED", format!("oci scratch: {e}")))?;

    let pull = Command::new("oras")
        .args(["pull", &oci_ref, "--output"])
        .arg(&scratch)
        .output();
    let ok = matches!(&pull, Ok(o) if o.status.success());
    if !ok {
        let detail = match &pull {
            Ok(o) => String::from_utf8_lossy(&o.stderr).trim().to_string(),
            Err(e) => format!("cannot run oras: {e}"),
        };
        let _ = std::fs::remove_dir_all(&scratch);
        return Err(transport(
            "FETCH-OCI-PULL-FAILED",
            format!("oras pull failed for {name:?} ({oci_ref}): {detail}"),
        ));
    }

    let mut tarballs: Vec<std::path::PathBuf> = std::fs::read_dir(&scratch)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.to_string_lossy().ends_with(".tar.gz"))
                .collect()
        })
        .unwrap_or_default();
    tarballs.sort();

    let result = match tarballs.as_slice() {
        [] => Err(transport(
            "FETCH-OCI-NO-TARBALL",
            format!("OCI artifact {oci_ref} contained no *.tar.gz"),
        )),
        [one] => {
            let bytes = std::fs::read(one).map_err(|e| {
                transport(
                    "FETCH-OCI-PULL-FAILED",
                    format!("reading pulled tarball: {e}"),
                )
            })?;
            let mut tar = Vec::new();
            GzDecoder::new(&bytes[..])
                .read_to_end(&mut tar)
                .map_err(|e| transport("FETCH-EXTRACT-FAILED", format!("gunzip: {e}")))?;
            clear_dest(dest).map_err(|e| transport("FETCH-EXTRACT-FAILED", e))?;
            extract_tar(&tar, dest, 0, Limits::default())
                .map(|_| Receipt {
                    resolved_ref: None,
                    archive_sha256: None,
                })
                .map_err(|e| transport("FETCH-EXTRACT-FAILED", e.code().to_string()))
        }
        many => Err(transport(
            "FETCH-OCI-AMBIGUOUS-TARBALL",
            format!(
                "OCI artifact {oci_ref} has {} *.tar.gz files; ambiguous",
                many.len()
            ),
        )),
    };
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

// ---------------------------------------------------------------------------
// CAS-admitting fetcher wrapper (issue #2 / differential-conformance-harness RFC)
// ---------------------------------------------------------------------------

/// A [`FetcherRegistry`] wrapper that admits every fetched tree into a
/// [`CaStore`] and replaces `dest` with a relative CAS symlink.
///
/// The inner registry materializes content into a staging directory; the
/// wrapper then:
///   1. Computes the content hash of the staged tree.
///   2. Admits the staging tree into `store` (move-via-rename, duplicate is no-op).
///   3. Removes any stale `dest` and creates a relative symlink at `dest` →
///      the store entry.
///
/// This is the CAS layer used by the CLI when `MILPA_MOCKED_FETCHES` is set,
/// producing the same `_deps/<name>` → CAS symlink structure that the
/// conformance harness's `FakeFetcher` produces (single source of truth for
/// the CAS logic lives in `store.rs`; this wrapper just orchestrates).
pub struct CasAdmittingFetcher<R> {
    inner: R,
    store: crate::store::CaStore,
    staging_root: std::path::PathBuf,
}

impl<R: FetcherRegistry> CasAdmittingFetcher<R> {
    /// Wrap `inner` so every successful fetch is admitted into `store`.
    /// `staging_root` is a directory on the same filesystem as the CAS root;
    /// staging sub-dirs are created there so `rename(2)` into the store is atomic.
    pub fn new(
        inner: R,
        store: crate::store::CaStore,
        staging_root: impl Into<std::path::PathBuf>,
    ) -> Self {
        CasAdmittingFetcher {
            inner,
            store,
            staging_root: staging_root.into(),
        }
    }
}

impl<R: FetcherRegistry> FetcherRegistry for CasAdmittingFetcher<R> {
    fn fetch(&self, name: &str, p: &milpa_types::Provenance, dest: &Path) -> Result<Receipt, FetchError> {
        if p.cas_admissible() {
            // Immutable source (Git / Tarball / OCI): fetch into a staging directory
            // on the same filesystem as the CAS (for atomic rename(2) during admit),
            // then admit + create a relative CAS symlink at `dest`.
            // spec/plugin-contract.md §4; spec/identity.md §3.5.
            let staging = self.staging_root.join(".milpa-cas-stage").join(name);
            let _ = std::fs::remove_dir_all(&staging);
            std::fs::create_dir_all(&staging).map_err(|e| {
                FetchError::Failed(format!("CasAdmittingFetcher: cannot create staging dir: {e}"))
            })?;

            let receipt = self.inner.fetch(name, p, &staging)?;

            // Compute the identity and admit to the CAS.
            use crate::identity::compute_content_hash;
            let identity = compute_content_hash(&staging).map_err(|e| {
                FetchError::Failed(format!("CasAdmittingFetcher: hash staged tree: {}", e.message()))
            })?;
            self.store.admit(&staging, &identity).map_err(|e| {
                FetchError::Failed(format!("CasAdmittingFetcher: admit to CAS: {}", e.message()))
            })?;
            // `admit` moves staging on success; clean up defensively.
            let _ = std::fs::remove_dir_all(&staging);

            // Create the relative CAS symlink at dest.
            self.store.link(&identity, dest).map_err(|e| {
                FetchError::Failed(format!("CasAdmittingFetcher: link _deps entry: {}", e.message()))
            })?;

            Ok(receipt)
        } else {
            // Editable / Local provenance: do NOT admit to CAS — the dep must stay
            // as a real working directory so the user's in-progress edits remain live.
            // spec/plugin-contract.md §4: "editable sources MUST declare
            // cas_admissible = False … Admitting would silently freeze user edits."
            self.inner.fetch(name, p, dest)
        }
    }
}

// ---------------------------------------------------------------------------
// Mocked transport (issue #2 / differential-conformance-harness RFC)
// ---------------------------------------------------------------------------

/// Encode a `(url, ref_spec)` pair to its `mocked-fetches/` subdirectory name
/// (conformance-fixtures.md §2.3.1). Every character outside `[A-Za-z0-9._-]`
/// is replaced with `_`; a literal `@` separates the encoded URL from the
/// encoded ref.
///
/// This is the **production single source of truth** — `milpa-conformance`
/// re-exports this function rather than maintaining a parallel copy.
pub fn url_key(url: &str, ref_spec: &str) -> String {
    fn sanitize(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }
    format!("{}@{}", sanitize(url), sanitize(ref_spec))
}

/// A [`FetcherRegistry`] backed by a `mocked-fetches/` fixture tree.
///
/// When `MILPA_MOCKED_FETCHES=<dir>` is set, `milpa-cli` wraps the resolution
/// with this registry instead of [`DefaultRegistry`]. Every fetch is satisfied
/// offline from `<dir>/<url_key(url, ref)>/`:
///
/// 1. Read `<key>/sha` — the commit SHA to return in the receipt.
/// 2. Copy `<key>/content/` verbatim into `dest` (if the sub-directory exists).
/// 3. Copy `<key>/<name>.nimble` into `dest` if present.
/// 4. Return a `Receipt` with `resolved_ref = Some(sha)`.
///
/// If the key directory is missing, returns `FETCH-MOCK-MISSING`.
/// Only `Provenance::Git` is supported; any other provenance yields a clear
/// (non-catalog) error.
///
/// `milpa-conformance`'s `FakeFetcher` also delegates to [`stage_mock`] for
/// the core logic, then additionally admits the staged tree into the CAS and
/// symlinks `dest` → the store entry.
pub struct MockedFetcher {
    mocked_fetches_dir: std::path::PathBuf,
}

impl MockedFetcher {
    pub fn new(mocked_fetches_dir: impl Into<std::path::PathBuf>) -> Self {
        MockedFetcher {
            mocked_fetches_dir: mocked_fetches_dir.into(),
        }
    }
}

impl FetcherRegistry for MockedFetcher {
    fn fetch(&self, name: &str, p: &Provenance, dest: &Path) -> Result<Receipt, FetchError> {
        // Resolve the mock key dir and the receipt fields per transport. Git keys
        // on (url, ref) and returns a commit SHA; tarball keys on (url, "") and
        // returns the recorded archive sha256 (gating an existing pin first,
        // exactly like the real `fetch_tarball` — conformance-fixtures.md §2.3.4).
        let (key_dir, receipt) = match p {
            Provenance::Git { url, ref_spec, .. } => {
                let (sha, key_dir) = resolve_mock_key(&self.mocked_fetches_dir, url, ref_spec)?;
                (
                    key_dir,
                    Receipt {
                        resolved_ref: Some(sha),
                        archive_sha256: None,
                    },
                )
            }
            Provenance::Tarball {
                url,
                expected_sha256,
                ..
            } => {
                let (archive_sha, key_dir) =
                    resolve_tarball_mock_key(&self.mocked_fetches_dir, url)?;
                if let Some(expected) = expected_sha256 {
                    let want = expected.strip_prefix("sha256:").unwrap_or(expected);
                    if want != archive_sha {
                        return Err(FetchError::Transport(
                            "FETCH-SHA256-MISMATCH",
                            format!(
                                "mocked fetch {name:?}: archive sha256 mismatch — \
                                 expected {expected}, got {archive_sha} (URL {url})"
                            ),
                        ));
                    }
                }
                (
                    key_dir,
                    Receipt {
                        resolved_ref: None,
                        archive_sha256: Some(archive_sha),
                    },
                )
            }
            other => {
                return Err(FetchError::Failed(format!(
                    "MockedFetcher: unsupported provenance kind: {other:?}; \
                     only Git and Tarball provenance are mocked"
                )));
            }
        };
        clear_dest(dest).map_err(|e| FetchError::Failed(e))?;
        std::fs::create_dir_all(dest)
            .map_err(|e| FetchError::Failed(format!("MockedFetcher: cannot create dest: {e}")))?;
        stage_mock_content(name, &key_dir, dest)?;
        Ok(receipt)
    }
}

/// Resolve the `(url, ref_spec)` pair to its `mocked-fetches/<key>/` directory
/// and read its `sha` file. Returns `(sha, key_dir)`.
///
/// `FETCH-MOCK-MISSING` if the key directory does not exist.
pub fn resolve_mock_key(
    mocked_fetches_dir: &Path,
    url: &str,
    ref_spec: &str,
) -> Result<(String, std::path::PathBuf), FetchError> {
    let key_dir = mocked_fetches_dir.join(url_key(url, ref_spec));
    if !key_dir.is_dir() {
        return Err(FetchError::Transport(
            "FETCH-MOCK-MISSING",
            format!(
                "mocked fetch: no fixture for {url:?} @ {ref_spec:?} \
                 (expected dir: {})",
                key_dir.display()
            ),
        ));
    }
    let sha = std::fs::read_to_string(key_dir.join("sha"))
        .map_err(|e| {
            FetchError::Failed(format!(
                "mock fixture: cannot read {}/sha: {e}",
                key_dir.display()
            ))
        })?
        .trim()
        .to_string();
    Ok((sha, key_dir))
}

/// Resolve a tarball URL to its `mocked-fetches/<url_key(url, "")>/` directory
/// and read its `archive_sha256` file (the sha256 the transport reports for the
/// downloaded archive — conformance-fixtures.md §2.3.4). Returns
/// `(archive_sha256, key_dir)`. Tarballs have no ref, so the key's ref slot is
/// empty (`<san(url)>@`), matching [`mocked_default_branch`]'s URL-prefix match.
///
/// `FETCH-MOCK-MISSING` if the key directory does not exist.
pub fn resolve_tarball_mock_key(
    mocked_fetches_dir: &Path,
    url: &str,
) -> Result<(String, std::path::PathBuf), FetchError> {
    let key_dir = mocked_fetches_dir.join(url_key(url, ""));
    if !key_dir.is_dir() {
        return Err(FetchError::Transport(
            "FETCH-MOCK-MISSING",
            format!(
                "mocked fetch: no tarball fixture for {url:?} \
                 (expected dir: {})",
                key_dir.display()
            ),
        ));
    }
    let archive_sha = std::fs::read_to_string(key_dir.join("archive_sha256"))
        .map_err(|e| {
            FetchError::Failed(format!(
                "mock fixture: cannot read {}/archive_sha256: {e}",
                key_dir.display()
            ))
        })?
        .trim()
        .to_string();
    Ok((archive_sha, key_dir))
}

/// Stage the mocked bytes from `key_dir` into `dest`: copy `content/` verbatim,
/// then copy `<name>.nimble` if present. `dest` must already exist.
///
/// Used by both [`MockedFetcher`] (copy-to-dest path) and `milpa-conformance`'s
/// `FakeFetcher` (stage-then-CAS-admit path) — the single source of truth for
/// the byte-staging step.
pub fn stage_mock_content(name: &str, key_dir: &Path, dest: &Path) -> Result<(), FetchError> {
    let content = key_dir.join("content");
    if content.is_dir() {
        copy_tree(&content, dest)
            .map_err(|e| FetchError::Failed(format!("mock fixture: copy content: {e}")))?;
    }
    let nimble_src = key_dir.join(format!("{name}.nimble"));
    if nimble_src.is_file() {
        std::fs::copy(&nimble_src, dest.join(format!("{name}.nimble")))
            .map_err(|e| FetchError::Failed(format!("mock fixture: copy nimble: {e}")))?;
    }
    Ok(())
}

/// Mocked default-branch (ref) discovery (conformance-fixtures.md §2.3.3,
/// cli-contract.md §8.4). When `MILPA_MOCKED_FETCHES` is set, `add --git`
/// answers `git ls-remote --symref HEAD` from the mock tree with no network:
/// it finds the unique `mocked-fetches/<key>/` entry whose encoded URL matches
/// `url` and returns that entry's ref (the ref component of the §2.3.1 URL-key).
///
/// SSOT: the very same `mocked-fetches/<key>/` entry is then read at fetch time
/// for its `sha` — there is no separate ref→SHA table. Returns the ref string.
///
/// Errors (non-catalog `Failed`) if no entry, or more than one entry, matches
/// `url` — the caller surfaces this as a default-branch-discovery failure
/// (cli-contract §5.6: exit 1), exactly as a network discovery failure would.
pub fn mocked_default_branch(mocked_fetches_dir: &Path, url: &str) -> Result<String, FetchError> {
    // url_key encodes (url, ref) as "<san(url)>@<san(ref)>"; the URL portion is
    // everything before the LAST '@'. Match on the sanitized URL so this stays
    // the single source of truth with url_key (no parallel decode).
    let want_url = url_key(url, "");
    // want_url == "<san(url)>@" — strip the trailing '@' to get the URL prefix.
    let want_prefix = want_url.trim_end_matches('@').to_string();

    let read = std::fs::read_dir(mocked_fetches_dir).map_err(|e| {
        FetchError::Failed(format!(
            "mocked ref-resolution: cannot read {}: {e}",
            mocked_fetches_dir.display()
        ))
    })?;

    let mut matches: Vec<String> = Vec::new();
    for entry in read.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        // Split on the LAST '@': the separator url_key inserts between url+ref.
        if let Some(at) = name.rfind('@') {
            let (enc_url, enc_ref) = (&name[..at], &name[at + 1..]);
            if enc_url == want_prefix {
                matches.push(enc_ref.to_string());
            }
        }
    }

    match matches.len() {
        1 => Ok(matches.pop().unwrap()),
        0 => Err(FetchError::Failed(format!(
            "mocked ref-resolution: no mocked-fetches entry for url {url:?} \
             (looked under {})",
            mocked_fetches_dir.display()
        ))),
        n => Err(FetchError::Failed(format!(
            "mocked ref-resolution: {n} mocked-fetches entries match url {url:?}; \
             pass --ref explicitly to disambiguate"
        ))),
    }
}

/// Lowercase hex sha256 of `bytes` (no `sha256:` prefix).
fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Remove `dest` if present (symlink-safe), leaving the parent intact.
fn clear_dest(dest: &Path) -> Result<(), String> {
    let Ok(meta) = std::fs::symlink_metadata(dest) else {
        return Ok(());
    };
    let ft = meta.file_type();
    let res = if ft.is_symlink() || ft.is_file() {
        std::fs::remove_file(dest)
    } else {
        std::fs::remove_dir_all(dest)
    };
    res.map_err(|e| format!("cannot clear {}: {e}", dest.display()))
}

/// Recursively copy `src`'s contents into `dst`, preserving symlinks.
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            let target = std::fs::read_link(&from)?;
            let _ = std::fs::remove_file(&to);
            std::os::unix::fs::symlink(target, &to)?;
        } else if ft.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "fetchers_tests.rs"]
mod fetchers_tests;
