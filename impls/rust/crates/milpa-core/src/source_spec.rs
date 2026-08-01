//! `parse_source_spec` — turn CLI tokens into a [`Provenance`] for `milpa hash`.
//!
//! This is the parser half of the `milpa hash <source>` sub-command (slice A0-parse).
//! The CLI wrapper (A0-cmd) lives in `milpa-cli::main` and is a separate concern;
//! this module has no CLI dependency.
//!
//! # Accepted forms
//!
//! - `git=<url> ref=<value>` → `Provenance::Git { url, ref_spec, commit_sha: None }`
//! - `local=<path>` → `Provenance::Local { path: <absolute path> }`
//! - `oci=<registry>/<repository>@sha256:<64hex>` → `Provenance::Oci { registry, repository, digest }`
//!
//! `ref` may be any string (branch, tag, or full commit SHA). Enforcing that
//! `ref` is a pinned SHA is the caller's responsibility — this parser does NOT
//! reject symbolic refs. `commit_sha` is always `None`; the fetcher resolves it.
//!
//! For `local=`, relative paths are resolved against `base_dir` (defaults to the
//! current directory when `None`). Path existence is NOT checked — that is the
//! fetcher's job.
//!
//! For `oci=`, the value is split on the single `@`: left part is
//! `registry/repository` (split on the first `/`), right part is the digest kept
//! verbatim (`sha256:<64-hex>` form). Digest format is validated inline
//! (mirrors `validate_oci_digest` / `TNG-BAD-OCI-DIGEST` semantics), and
//! registry/repository are checked for leading `-` (mirrors `validate_oci_field` /
//! `TNG-UNSAFE-OCI-FIELD`). All violations are translated to `CLI-SOURCE-SPEC-INVALID`.
//!
//! All parse failures return [`MilpaError::Core`] with the `CLI-SOURCE-SPEC-INVALID`
//! slug (spec/errors.md §CLI; spec/cli-contract.md §5.11).

use std::path::{Path, PathBuf};

use milpa_types::Provenance;

use crate::error::{CoreError, MilpaError};

fn invalid(msg: impl Into<String>) -> MilpaError {
    MilpaError::Core(CoreError::Resolver("CLI-SOURCE-SPEC-INVALID", msg.into()))
}

/// Parse CLI source-spec tokens into a [`Provenance`] for `milpa hash`.
///
/// # Parameters
/// - `tokens`: slice of `key=value` strings from the CLI
///   (e.g. `["git=https://...", "ref=main"]`).
/// - `base_dir`: base directory for resolving relative `local=` paths.
///   When `None`, the current working directory is used.
///
/// # Returns
/// A [`Provenance::Git`] or [`Provenance::Local`] instance.
///
/// # Errors
/// Returns `MilpaError` with slug `CLI-SOURCE-SPEC-INVALID` on any parse error:
/// unknown key, token without `=`, missing required key, mixing `git=`+`local=`,
/// empty token list, or duplicate keys.
pub fn parse_source_spec<S: AsRef<str>>(
    tokens: &[S],
    base_dir: Option<&Path>,
) -> Result<Provenance, MilpaError> {
    if tokens.is_empty() {
        return Err(invalid(
            "source spec requires at least one token (e.g. git=<url> ref=<ref> or local=<path>)",
        ));
    }

    let mut resolved: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for token in tokens {
        let token = token.as_ref();
        let Some(eq_pos) = token.find('=') else {
            return Err(invalid(format!(
                "malformed token {token:?}: expected key=value"
            )));
        };
        let key = &token[..eq_pos];
        let value = &token[eq_pos + 1..];

        match key {
            "git" | "ref" | "local" | "oci" => {}
            _ => {
                return Err(invalid(format!(
                    "unknown source-spec key {key:?}: expected one of git, ref, local, oci"
                )));
            }
        }

        if resolved.contains_key(key) {
            return Err(invalid(format!("duplicate key {key:?} in source spec")));
        }
        resolved.insert(key.to_string(), value.to_string());
    }

    let has_git_keys = resolved.contains_key("git") || resolved.contains_key("ref");
    let has_local_keys = resolved.contains_key("local");
    let has_oci_keys = resolved.contains_key("oci");

    let form_count =
        usize::from(has_git_keys) + usize::from(has_local_keys) + usize::from(has_oci_keys);
    if form_count > 1 {
        let mut keys: Vec<String> = resolved.keys().cloned().collect();
        keys.sort();
        return Err(invalid(format!(
            "cannot mix source spec forms (git, local, oci) in a single spec (keys: {keys:?})"
        )));
    }

    if has_git_keys {
        let mut missing: Vec<&str> = Vec::new();
        if !resolved.contains_key("git") {
            missing.push("git");
        }
        if !resolved.contains_key("ref") {
            missing.push("ref");
        }
        missing.sort();
        if !missing.is_empty() {
            return Err(invalid(format!(
                "git source spec requires both git= and ref=; missing: {missing:?}"
            )));
        }
        return Ok(Provenance::Git {
            url: resolved.remove("git").unwrap(),
            ref_spec: resolved.remove("ref").unwrap(),
            commit_sha: None,
        });
    }

    if has_oci_keys {
        let raw_oci = resolved.remove("oci").unwrap();
        // Split on '@': there MUST be exactly one '@'.
        if raw_oci.matches('@').count() != 1 {
            return Err(invalid(format!(
                "oci= value must contain exactly one '@'; got {raw_oci:?}"
            )));
        }
        let (ref_part, digest) = raw_oci.split_once('@').unwrap();
        if digest.is_empty() {
            return Err(invalid(format!(
                "oci= value has empty digest (nothing after '@'); got {raw_oci:?}"
            )));
        }
        // Split registry/repository on the first '/'.
        let Some(slash_pos) = ref_part.find('/') else {
            return Err(invalid(format!(
                "oci= registry/repository reference must contain '/'; got {ref_part:?}"
            )));
        };
        let registry = &ref_part[..slash_pos];
        let repository = &ref_part[slash_pos + 1..];
        // Validate registry and repository: must not begin with '-' (TNG-UNSAFE-OCI-FIELD).
        for (field_name, field_val) in [("registry", registry), ("repository", repository)] {
            if field_val.starts_with('-') {
                return Err(invalid(format!(
                    "oci= {field_name} {field_val:?} must not begin with '-'"
                )));
            }
        }
        // Validate digest format: sha256:<64 lowercase hex> (TNG-BAD-OCI-DIGEST).
        let digest_ok = digest
            .strip_prefix("sha256:")
            .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        if !digest_ok {
            return Err(invalid(format!(
                "oci= digest {digest:?} is not in `sha256:<64 lowercase hex>` form"
            )));
        }
        return Ok(Provenance::Oci {
            registry: registry.to_string(),
            repository: repository.to_string(),
            digest: digest.to_string(),
            // Manifest `oci=` dep declarations have no `source` concept
            // (registry-protocol §3.3's manifest-grammar carve-out) — always
            // `None` here.
            source_url: None,
        });
    }

    // local form
    let raw_path = resolved.remove("local").unwrap();
    let path = Path::new(&raw_path);
    let abs_path: PathBuf = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let base = match base_dir {
            Some(b) => b.to_path_buf(),
            None => std::env::current_dir().map_err(|e| {
                invalid(format!(
                    "local= path is relative but current_dir() failed: {e}"
                ))
            })?,
        };
        base.join(path)
    };

    Ok(Provenance::Local {
        path: abs_path.to_string_lossy().into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // -----------------------------------------------------------------------
    // Test 1: git form with full commit SHA → GitProvenance
    // -----------------------------------------------------------------------

    #[test]
    fn git_form_commit_sha() {
        let sha = "a".repeat(40);
        let result = parse_source_spec(
            &["git=https://example.com/r.git", &format!("ref={sha}")],
            None,
        )
        .unwrap();
        assert!(
            matches!(
                &result,
                Provenance::Git { url, ref_spec, commit_sha: None }
                if url == "https://example.com/r.git" && ref_spec == &sha
            ),
            "expected GitProvenance, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2: local form with absolute path → LocalProvenance
    // -----------------------------------------------------------------------

    #[test]
    fn local_form_absolute_path() {
        let result = parse_source_spec(&["local=/abs/path/to/pkg"], None).unwrap();
        assert!(
            matches!(&result, Provenance::Local { path } if path == "/abs/path/to/pkg"),
            "expected Local with abs path, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3: local form with relative path → resolved against base_dir
    // -----------------------------------------------------------------------

    #[test]
    fn local_form_relative_path_resolved_against_base_dir() {
        let base = PathBuf::from("/workspace/root");
        let result = parse_source_spec(&["local=mypkg"], Some(&base)).unwrap();
        assert!(
            matches!(&result, Provenance::Local { path } if path == "/workspace/root/mypkg"),
            "expected Local with resolved path, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 4: unknown key → MilpaError
    // -----------------------------------------------------------------------

    #[test]
    fn unknown_key_raises() {
        let err = parse_source_spec(&["foo=bar"], None).unwrap_err();
        assert_eq!(err.code(), "CLI-SOURCE-SPEC-INVALID");
    }

    // -----------------------------------------------------------------------
    // Test 5: token without = → MilpaError
    // -----------------------------------------------------------------------

    #[test]
    fn token_without_equals_raises() {
        let err = parse_source_spec(&["notakeyvalue"], None).unwrap_err();
        assert_eq!(err.code(), "CLI-SOURCE-SPEC-INVALID");
    }

    // -----------------------------------------------------------------------
    // Test 6: git= without ref= → MilpaError
    // -----------------------------------------------------------------------

    #[test]
    fn git_missing_ref_raises() {
        let err = parse_source_spec(&["git=https://example.com/r.git"], None).unwrap_err();
        assert_eq!(err.code(), "CLI-SOURCE-SPEC-INVALID");
    }

    // -----------------------------------------------------------------------
    // Test 7: mixing git= and local= → MilpaError
    // -----------------------------------------------------------------------

    #[test]
    fn mixing_git_and_local_raises() {
        let err = parse_source_spec(
            &["git=https://example.com/r.git", "ref=main", "local=/some/path"],
            None,
        )
        .unwrap_err();
        assert_eq!(err.code(), "CLI-SOURCE-SPEC-INVALID");
    }

    // -----------------------------------------------------------------------
    // Test 8: empty token list → MilpaError
    // -----------------------------------------------------------------------

    #[test]
    fn empty_tokens_raises() {
        let tokens: &[&str] = &[];
        let err = parse_source_spec(tokens, None).unwrap_err();
        assert_eq!(err.code(), "CLI-SOURCE-SPEC-INVALID");
    }

    // -----------------------------------------------------------------------
    // Test 9: duplicate key → MilpaError
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_key_raises() {
        let err = parse_source_spec(
            &[
                "git=https://a.com/r.git",
                "git=https://b.com/r.git",
                "ref=main",
            ],
            None,
        )
        .unwrap_err();
        assert_eq!(err.code(), "CLI-SOURCE-SPEC-INVALID");
    }

    // -----------------------------------------------------------------------
    // Test 10: symbolic ref is accepted (no over-rejection)
    // -----------------------------------------------------------------------

    #[test]
    fn symbolic_ref_accepted() {
        let result =
            parse_source_spec(&["git=https://example.com/r.git", "ref=main"], None).unwrap();
        assert!(
            matches!(&result, Provenance::Git { ref_spec, commit_sha: None, .. } if ref_spec == "main"),
            "symbolic ref should be accepted: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // OCI form tests (oci=<registry>/<repository>@<digest>)
    // -----------------------------------------------------------------------

    fn valid_digest() -> String {
        format!("sha256:{}", "a".repeat(64))
    }

    // Test 11: basic oci= form → Provenance::Oci
    #[test]
    fn oci_form_basic() {
        let digest = valid_digest();
        let token = format!("oci=ghcr.io/org/pkg@{digest}");
        let result = parse_source_spec(&[token.as_str()], None).unwrap();
        assert!(
            matches!(
                &result,
                Provenance::Oci { registry, repository, digest: d, .. }
                if registry == "ghcr.io" && repository == "org/pkg" && d == &digest
            ),
            "expected OCI provenance, got {result:?}"
        );
    }

    // Test 12: repository with multiple slashes → registry=first segment, repository=rest
    #[test]
    fn oci_form_multi_slash_repository() {
        let digest = valid_digest();
        let token = format!("oci=reg.io/a/b/c@{digest}");
        let result = parse_source_spec(&[token.as_str()], None).unwrap();
        assert!(
            matches!(
                &result,
                Provenance::Oci { registry, repository, .. }
                if registry == "reg.io" && repository == "a/b/c"
            ),
            "expected registry=reg.io, repository=a/b/c, got {result:?}"
        );
    }

    // Test 13: missing '@' → CLI-SOURCE-SPEC-INVALID
    #[test]
    fn oci_missing_at_raises() {
        let err = parse_source_spec(&["oci=ghcr.io/org/pkg"], None).unwrap_err();
        assert_eq!(err.code(), "CLI-SOURCE-SPEC-INVALID");
    }

    // Test 14: two '@' → CLI-SOURCE-SPEC-INVALID
    #[test]
    fn oci_two_at_raises() {
        let digest = valid_digest();
        let token = format!("oci=ghcr.io/org/pkg@{digest}@extra");
        let err = parse_source_spec(&[token.as_str()], None).unwrap_err();
        assert_eq!(err.code(), "CLI-SOURCE-SPEC-INVALID");
    }

    // Test 15: no '/' before '@' → CLI-SOURCE-SPEC-INVALID
    #[test]
    fn oci_no_slash_before_at_raises() {
        let digest = valid_digest();
        let token = format!("oci=ghcr.io@{digest}");
        let err = parse_source_spec(&[token.as_str()], None).unwrap_err();
        assert_eq!(err.code(), "CLI-SOURCE-SPEC-INVALID");
    }

    // Test 16: invalid digest → CLI-SOURCE-SPEC-INVALID
    #[test]
    fn oci_invalid_digest_raises() {
        let err = parse_source_spec(&["oci=ghcr.io/org/pkg@notadigest"], None).unwrap_err();
        assert_eq!(err.code(), "CLI-SOURCE-SPEC-INVALID");
    }

    // Test 17: mixing oci= with git= → CLI-SOURCE-SPEC-INVALID
    #[test]
    fn oci_mixed_with_git_raises() {
        let digest = valid_digest();
        let oci_token = format!("oci=ghcr.io/org/pkg@{digest}");
        let err = parse_source_spec(
            &[oci_token.as_str(), "git=https://example.com/r.git", "ref=main"],
            None,
        )
        .unwrap_err();
        assert_eq!(err.code(), "CLI-SOURCE-SPEC-INVALID");
    }
}
