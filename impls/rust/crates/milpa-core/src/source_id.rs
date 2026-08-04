//! `SourceId` — the version-independent origin, per
//! `docs/rfc-origin-as-identity.md` §4.1/§4.2 (S1; revised round-2.5,
//! [[provenance_source_selection]]). Mirrors Python's `milpa/source_id.py`
//! function-for-function (§9 cross-impl discipline).
//!
//! The value SHAPE (`milpa_types::SourceId` / `FetchableOrigin`) is a
//! zero-logic enum in `milpa-types` (that crate's own "data only, logic
//! lives elsewhere" rule). This module is the LOGIC half: `canonical()`
//! (infallible, the ONE-WAY wire-format serializer — never parsed back),
//! `normalize_source()` (the heuristic git-normalize rule, and now ALSO the
//! sole validation boundary), and `format_source_id()` (infallible, the
//! shared diagnostic formatter, B6).
//!
//! **Nothing calls this module yet.** S1 is a pure value-type slice — the
//! binding/resolver wiring lands in S2+.
//!
//! **Round-2.5 representation correction — there is NO `parse()`.** The
//! authoritative representation is the frozen enum value itself (structural
//! eq/hash IS the identity — cargo/uv model, not a flat string parsed back
//! into typed fields). On disk (a later slice, S5) each kind serializes
//! STRUCTURED, never as a flat key. `canonical()` survives ONLY as a
//! **one-way** injective string — the in-memory solver key and the
//! human/diagnostic display form. Nothing ever reconstructs a `SourceId` by
//! parsing a flat string, so the `#subdirectory=`/percent-escaping
//! round-trip machinery an earlier draft needed only to make a flat string
//! round-trippable is gone along with `parse()` itself.
//!
//! **The injectivity law** (the only law left):
//!
//! ```text
//! canonical(a) == canonical(b)  iff  a == b        # one-way; NEVER parsed back
//! ```
//!
//! Injectivity holds over well-formed `SourceId` values without any
//! escaping — see the Python module's docstring for the full argument
//! (variable-arity name-last `pkg+`, the OCI registry segment-boundary
//! guard, the `#subdirectory=` delimiter-collision guard). Rust proptest is
//! not wired up (`source_id_tests.rs`'s own note); the injectivity law is
//! property-tested in Python only (`test_source_id_properties.py`) per
//! `rfc-property-based-testing.md`.
//!
//! **Validation boundary moved to `normalize_source` (round-2.5
//! correction).** The six variants still do NOT self-validate on
//! construction. Previously `parse()` was "the only place UNTRUSTED strings
//! become a `SourceId`," so it owned validation. With `parse()` gone,
//! `normalize_source` is now that boundary: it both normalizes AND enforces
//! the field invariants below, returning `Err(MilpaError)` (slug
//! `SRC-ID-MALFORMED`) on violation. `canonical()` itself remains pure
//! formatting — it does not validate.
//!
//! Well-formedness invariants (enforced by `normalize_source`):
//!
//!   - Any `subpath` field: `None` means "no subpath" — when NOT `None`, it
//!     MUST be non-empty, MUST NOT start with `/` (absolute), and MUST NOT
//!     contain a `..` segment (mirrors `safe_extract.rs`'s zip-slip
//!     discipline). Use `None`, never `""`, for "no subpath."
//!   - `Git.url` / `Tarball.url` / the OCI `"{registry}/{repository}"` base:
//!     MUST NOT contain a literal `#subdirectory=` substring (the
//!     injectivity guard above).
//!   - `Oci.registry`: MUST NOT contain `/` (the segment-boundary guard
//!     above).
//!   - `Registry.registry` (the configured alias) and `.name`: each matches
//!     the manifest package-name alphabet `[A-Za-z0-9_-]+` (`valid_flag_name`)
//!     — never `/`.
//!   - `Registry.namespace`, when not `None`: a `/`-separated path; EACH
//!     segment (not the whole string) MUST be non-empty, MUST NOT be `..`,
//!     and MUST NOT contain an unsafe character (below). Segments are NOT
//!     fenced to `valid_flag_name`'s stricter charset — real tianguis
//!     namespaces are host-qualified domain names (`codeberg.org`,
//!     `bitbucket.org/<user>`) which contain `.`, a character
//!     `valid_flag_name` rejects. `/` is the segment *separator*, always
//!     allowed between segments.
//!   - **Control-char / Unicode-line-separator guard (code-review S2).**
//!     `Git.url` (post-normalize), `Tarball.url`, `Oci.registry`/
//!     `.repository`, `Local.path`, and each `Registry.namespace` segment
//!     MUST NOT contain a character `milpa_manifest::contains_unsafe_char`
//!     (the single source of truth — ASCII C0/C1 controls + U+2028/U+2029)
//!     flags. Without this guard a crafted, network-fetched `milpa.kdl`
//!     could smuggle a terminal-escape sequence through a free-text origin
//!     field into a diagnostic sink.
//!   - **Git URL fragment guard (code-review D1).** A raw `#fragment` in a
//!     declared `Git.url` is REJECTED, never silently stripped — it collides
//!     with milpa's own reserved `#subdirectory=` one-way-key delimiter. A
//!     `?query` IS silently stripped (transport/auth noise, not
//!     identity-bearing) — see `normalize_git_url`'s doc comment for the
//!     full Python/Rust convergence rationale.

use milpa_manifest::{contains_unsafe_char, valid_flag_name};
use milpa_types::{FetchableOrigin, SourceId};

use crate::error::{CoreError, MilpaError};

// ---------------------------------------------------------------------------
// Formal half — canonical()
// ---------------------------------------------------------------------------

const GIT_PREFIX: &str = "git+";
const OCI_PREFIX: &str = "oci+";
const TAR_PREFIX: &str = "tar+";
const PKG_PREFIX: &str = "pkg+";
const FILE_PREFIX: &str = "file+";
const MEMBER_PREFIX: &str = "member+";

/// The uniform subpath delimiter (RFC §4.1) shared by Git/Tarball/Oci.
const SUBDIR_DELIM: &str = "#subdirectory=";
// DE2-ref pin delimiters — one-way, injective (url/repo/ref/digest carry no
// '#', enforced by normalize_source), placed BEFORE the subpath suffix.
const REF_DELIM: &str = "#ref=";
const DIGEST_DELIM: &str = "#digest=";

fn malformed(msg: impl Into<String>) -> MilpaError {
    MilpaError::Core(CoreError::SourceId("SRC-ID-MALFORMED", msg.into()))
}

fn subdir_suffix(subpath: Option<&str>) -> String {
    match subpath {
        None => String::new(),
        Some(sp) => format!("{SUBDIR_DELIM}{sp}"),
    }
}

fn ref_suffix(git_ref: Option<&str>) -> String {
    match git_ref {
        None => String::new(),
        Some(r) => format!("{REF_DELIM}{r}"),
    }
}

fn digest_suffix(digest: Option<&str>) -> String {
    match digest {
        None => String::new(),
        Some(d) => format!("{DIGEST_DELIM}{d}"),
    }
}

/// Serialize `sid` to its canonical wire-format string (RFC §4.1).
///
/// ONE-WAY: this is the solver-variable value and the in-memory/display
/// key — it is NEVER parsed back (the on-disk lockfile form is structured,
/// a later slice). Injective over well-formed `SourceId` values (i.e.
/// values that have passed through `normalize_source`) — see the module
/// docstring. `canonical()` itself performs no validation.
pub fn canonical(sid: &SourceId) -> String {
    match sid {
        SourceId::Fetchable(FetchableOrigin::Git { url, git_ref, subpath }) => {
            format!(
                "{GIT_PREFIX}{url}{}{}",
                ref_suffix(git_ref.as_deref()),
                subdir_suffix(subpath.as_deref())
            )
        }
        SourceId::Fetchable(FetchableOrigin::Tarball { url, subpath }) => {
            format!("{TAR_PREFIX}{url}{}", subdir_suffix(subpath.as_deref()))
        }
        SourceId::Fetchable(FetchableOrigin::Oci { registry, repository, digest, subpath }) => {
            format!(
                "{OCI_PREFIX}{registry}/{repository}{}{}",
                digest_suffix(digest.as_deref()),
                subdir_suffix(subpath.as_deref())
            )
        }
        SourceId::Fetchable(FetchableOrigin::Local { path }) => format!("{FILE_PREFIX}{path}"),
        SourceId::Fetchable(FetchableOrigin::Registry { registry, namespace, name }) => {
            match namespace {
                None => format!("{PKG_PREFIX}{registry}/{name}"),
                Some(ns) => format!("{PKG_PREFIX}{registry}/{ns}/{name}"),
            }
        }
        SourceId::Member { member_name } => format!("{MEMBER_PREFIX}{member_name}"),
    }
}

/// The single diagnostic formatter for a `SourceId` (RFC §10 S1, B6).
///
/// Every later slug that needs to name a source-id in a human message —
/// `RES-BINDING-CONFLICT` (S2), `RES-IMPORT-COLLISION` (S6),
/// `FROZEN-SOURCE-ID-MISMATCH` (S5) — reuses this, defined once here.
pub fn format_source_id(sid: &SourceId) -> String {
    let label = match sid {
        SourceId::Fetchable(FetchableOrigin::Git { .. }) => "git dependency",
        SourceId::Fetchable(FetchableOrigin::Oci { .. }) => "OCI dependency",
        SourceId::Fetchable(FetchableOrigin::Tarball { .. }) => "tarball dependency",
        SourceId::Fetchable(FetchableOrigin::Local { .. }) => "local dependency",
        SourceId::Fetchable(FetchableOrigin::Registry { .. }) => "registry package",
        SourceId::Member { .. } => "workspace member",
    };
    format!("{label} {:?}", canonical(sid))
}

// ---------------------------------------------------------------------------
// Heuristic half — normalize_source (also the sole validation boundary)
// ---------------------------------------------------------------------------

/// Default port per git URL scheme (RFC §4.2 "Added by this RFC"): stripping
/// these closes a real missed-unification (`ssh://user@host:22/org/repo`
/// and `ssh://host/org/repo` are the same repo).
fn git_default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "https" => Some(443),
        "http" => Some(80),
        "ssh" => Some(22),
        "git" => Some(9418),
        _ => None,
    }
}

/// Subpath escape guard (RFC §4.1 normative) — mirrors `safe_extract.rs`'s
/// zip-slip discipline: reject an empty, absolute, or `..`-traversing subpath.
fn validate_subpath(subpath: &str, context: &str) -> Result<(), MilpaError> {
    if subpath.is_empty() {
        return Err(malformed(format!(
            "{context} has an empty subdirectory subpath (use `subpath: None` \
             to mean the repo root)"
        )));
    }
    if subpath.starts_with('/') {
        return Err(malformed(format!(
            "{context} has an absolute subpath {subpath:?} (subpath must be relative)"
        )));
    }
    if subpath.split('/').any(|seg| seg == "..") {
        return Err(malformed(format!(
            "{context} has a path-traversal subpath {subpath:?} (a `..` segment is not allowed)"
        )));
    }
    Ok(())
}

/// Injectivity guard (RFC §4.1 "Subpath in the one-way key"): a base URL (or
/// OCI `registry/repository`) that itself contains a literal
/// `#subdirectory=` substring would let `canonical()` collide between
/// `SourceId { url: format!("{b}#subdirectory={s}"), subpath: None }` and
/// `SourceId { url: b, subpath: Some(s) }` — two DIFFERENT values, one
/// string. Such a base is pathological; reject it here rather than escape it.
fn validate_no_delim_collision(base: &str, context: &str) -> Result<(), MilpaError> {
    if base.contains(SUBDIR_DELIM) {
        return Err(malformed(format!(
            "{context} contains a literal {SUBDIR_DELIM:?} fragment, which would \
             collide with the subpath delimiter in the canonical source-id key"
        )));
    }
    Ok(())
}

/// `alias`/`name` fence (RFC §4.1): both MUST be `/`-free and match the
/// manifest package-name alphabet — the injectivity anchors that make the
/// `pkg+` variable-arity form's boundaries unambiguous.
fn validate_registry_component(value: &str, label: &str) -> Result<(), MilpaError> {
    if !valid_flag_name(value) {
        return Err(malformed(format!(
            "registry {label} {value:?} must match the package-name alphabet [A-Za-z0-9_-]+"
        )));
    }
    Ok(())
}

/// Reject ASCII control characters (0x00-0x1F, 0x7F) and Unicode line
/// separators (U+2028/U+2029) in a free-text origin field (code-review S2 —
/// control-char injection). Reuses `milpa_manifest::contains_unsafe_char`
/// (the single source of truth for this predicate, mirroring Python's
/// `manifest.contains_unsafe_char` import) rather than a fourth duplicate
/// check. Without this guard a crafted, network-fetched `milpa.kdl` could
/// smuggle a terminal-escape sequence through an origin field into a
/// diagnostic sink.
fn validate_no_unsafe_char(value: &str, context: &str) -> Result<(), MilpaError> {
    if contains_unsafe_char(value) {
        return Err(malformed(format!(
            "{context} contains a control character or Unicode line separator \
             (U+2028/U+2029), which is not allowed in a source origin field"
        )));
    }
    Ok(())
}

/// Per-`/`-segment namespace validation (RFC §4.1 round-2.5 correction;
/// broadened by code-review S2 to the full `contains_unsafe_char` charset —
/// ASCII controls AND Unicode line separators, not ASCII controls alone):
/// each segment must be non-empty, not `..`, and free of unsafe characters.
/// NOT fenced to `valid_flag_name`'s charset — real namespaces are
/// host-qualified (`codeberg.org`) and contain `.`. `/` is the segment
/// separator, always allowed between segments.
fn validate_namespace(namespace: &str) -> Result<(), MilpaError> {
    for seg in namespace.split('/') {
        if seg.is_empty() {
            return Err(malformed(format!(
                "registry namespace {namespace:?} has an empty '/'-segment"
            )));
        }
        if seg == ".." {
            return Err(malformed(format!(
                "registry namespace {namespace:?} has a path-traversal segment {seg:?}"
            )));
        }
        validate_no_unsafe_char(seg, &format!("registry namespace {namespace:?} segment {seg:?}"))?;
    }
    Ok(())
}

/// The git-source equality definition (RFC §4.2), in three explicit tiers:
///
/// - **Kept** (promoted from `resolver.rs`'s `normalize_git_source_url`):
///   lowercase scheme+host, strip a trailing `/` and a trailing `.git`
///   suffix; path case is PRESERVED.
/// - **Added by this RFC**: strip userinfo/credentials and strip the
///   scheme's DEFAULT port only.
/// - **Added by code-review D1 (cross-impl convergence)**: strip a `?query`
///   suffix — transport/auth noise, not identity-bearing. A raw `#fragment`
///   is NOT stripped here (this function stays total); `normalize_source`
///   rejects it outright before ever calling this function (a fragment
///   collides with milpa's own reserved `#subdirectory=` one-way-key
///   delimiter). Before this fix, Rust preserved BOTH query and fragment
///   verbatim (its own hand-parse never dropped them) while Python's
///   `urlsplit`/`urlunsplit` mirror silently dropped both — a real
///   Python/Rust source-id divergence for `git=(url)"…?ref=main"` and an
///   inconsistent accept/reject for `git=(url)"…#subdirectory=evil"`. Both
///   impls now converge: strip query, reject fragment.
/// - **NOT attempted**: ssh<->https unification, SCP-style desugaring —
///   both undecidable/unreachable (RFC §4.2); `overrides {}` is the escape
///   hatch.
///
/// Total: never panics. A URL with no recognizable `scheme://authority`
/// falls back to a lowercased whole string.
///
/// `pub(crate)`: reused by `binding::check_registry_shadow` (RFC
/// origin-as-identity.md §6.1, S3c) — the SAME git-source equality
/// definition `normalize_source` itself uses, deliberately NOT
/// `resolver.rs`'s narrower `normalize_git_source_url` (which skips
/// userinfo/default-port stripping; mirrors Python's `check_registry_shadow`
/// importing `source_id._normalize_git_url`, never `resolver.py`'s own
/// `_normalize_git_source_url`).
pub(crate) fn normalize_git_url(url: &str) -> String {
    let mut s = url.trim().to_string();
    if let Some(stripped) = s.strip_suffix('/') {
        s = stripped.to_string();
    }
    if let Some(stripped) = s.strip_suffix(".git") {
        s = stripped.to_string();
    }
    let Some(idx) = s.find("://") else {
        return s.to_lowercase();
    };
    let scheme = s[..idx].to_lowercase();
    let mut rest = &s[idx + 3..];
    // Strip query (code-review D1): drop everything from the first '?'
    // onward, BEFORE splitting authority/path, so it is stripped whether it
    // is attached directly to the authority (no path) or to the path.
    if let Some(q) = rest.find('?') {
        rest = &rest[..q];
    }
    let (authority, path) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash..]),
        None => (rest, ""),
    };
    // Strip userinfo: everything up to and including the LAST '@' in the
    // authority component (mirrors URL syntax: userinfo can itself contain
    // ':' for user:pass, so split on the last '@', never the first).
    let host_and_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    // Split host:port, being careful of bracketed IPv6 literals ('[::1]:22').
    let (host, port): (&str, Option<&str>) = if let Some(rest) = host_and_port.strip_prefix('[') {
        match rest.find(']') {
            Some(end) => {
                let after = &rest[end + 1..];
                let port = after.strip_prefix(':');
                (&host_and_port[..end + 2], port)
            }
            None => (host_and_port, None),
        }
    } else {
        match host_and_port.rfind(':') {
            Some(colon) => (&host_and_port[..colon], Some(&host_and_port[colon + 1..])),
            None => (host_and_port, None),
        }
    };
    let host_lower = host.to_lowercase();
    let default_port = git_default_port(&scheme);
    let port_num: Option<u16> = port.and_then(|p| p.parse().ok());
    let netloc = match port_num {
        Some(p) if Some(p) != default_port => format!("{host_lower}:{p}"),
        _ => host_lower,
    };
    format!("{scheme}://{netloc}{path}")
}

/// Normalize `raw` to its equality-defining `SourceId` form (RFC §4.2) —
/// and, since `parse()` no longer exists to own it, the sole VALIDATION
/// boundary (module docstring): returns `Err(MilpaError)` (slug
/// `SRC-ID-MALFORMED`) on any well-formedness violation.
///
/// Kind-dispatched; only the git case has non-trivial NORMALIZATION (see
/// `normalize_git_url`) — two genuinely different remotes serving identical
/// bytes are NOT unified here (undecidable; that is `content_hash`'s job,
/// post-fetch — RFC §3.3).
pub fn normalize_source(raw: &SourceId) -> Result<SourceId, MilpaError> {
    match raw {
        SourceId::Fetchable(FetchableOrigin::Git { url, git_ref, subpath }) => {
            // D1 (code-review): a raw '#' fragment in the DECLARED url is
            // rejected outright, never silently stripped — checked here (on
            // the untrusted input) rather than inside `normalize_git_url`,
            // which stays a total, never-panic string transform. See that
            // function's doc comment for the full Python/Rust convergence
            // rationale.
            if url.contains('#') {
                return Err(malformed(format!(
                    "git source url {url:?} contains a '#' fragment, which collides \
                     with milpa's reserved subpath delimiter ({SUBDIR_DELIM:?}) — use \
                     the manifest `subpath` property instead of a URL fragment"
                )));
            }
            let normalized = normalize_git_url(url);
            validate_no_unsafe_char(&normalized, &format!("git+ source url {normalized:?}"))?;
            // Vestigial for Git specifically (a normalized url can never
            // contain '#' given the reject above), kept for structural
            // symmetry with the Tarball/Oci arms below, which still rely on
            // this guard.
            validate_no_delim_collision(&normalized, &format!("git+ source url {normalized:?}"))?;
            if let Some(sp) = subpath {
                validate_subpath(sp, "git dependency")?;
            }
            // DE2-ref: the pinned ref joins the source-id. Reject '#'
            // (guarantees canonical() injectivity against #ref=/#subdirectory=)
            // and any terminal-unsafe char (same sink as the url).
            if let Some(r) = git_ref {
                if r.contains('#') {
                    return Err(malformed(format!(
                        "git ref {r:?} contains a '#', which collides with milpa's \
                         reserved source-id delimiters"
                    )));
                }
                validate_no_unsafe_char(r, &format!("git ref {r:?}"))?;
            }
            Ok(SourceId::Fetchable(FetchableOrigin::Git {
                url: normalized,
                git_ref: git_ref.clone(),
                subpath: subpath.clone(),
            }))
        }
        SourceId::Fetchable(FetchableOrigin::Oci { registry, repository, digest, subpath }) => {
            if registry.contains('/') {
                return Err(malformed(format!(
                    "OCI registry {registry:?} must not contain '/' (per the OCI \
                     distribution spec a registry is host[:port] only)"
                )));
            }
            validate_no_unsafe_char(registry, &format!("OCI registry {registry:?}"))?;
            validate_no_unsafe_char(repository, &format!("OCI repository {repository:?}"))?;
            let base = format!("{registry}/{repository}");
            validate_no_delim_collision(&base, &format!("oci+ source {base:?}"))?;
            if let Some(sp) = subpath {
                validate_subpath(sp, "OCI dependency")?;
            }
            // DE2-ref: the pinned digest joins the source-id (reject '#' for
            // canonical() injectivity; digest format is validated at the fetch
            // boundary — TNG-BAD-OCI-DIGEST).
            if let Some(d) = digest {
                if d.contains('#') {
                    return Err(malformed(format!(
                        "OCI digest {d:?} contains a '#', which collides with milpa's \
                         reserved source-id delimiters"
                    )));
                }
            }
            Ok(SourceId::Fetchable(FetchableOrigin::Oci {
                registry: registry.clone(),
                repository: repository.clone(),
                digest: digest.clone(),
                subpath: subpath.clone(),
            }))
        }
        SourceId::Fetchable(FetchableOrigin::Tarball { url, subpath }) => {
            validate_no_unsafe_char(url, &format!("tar+ source url {url:?}"))?;
            validate_no_delim_collision(url, &format!("tar+ source url {url:?}"))?;
            if let Some(sp) = subpath {
                validate_subpath(sp, "tarball dependency")?;
            }
            Ok(SourceId::Fetchable(FetchableOrigin::Tarball { url: url.clone(), subpath: subpath.clone() }))
        }
        SourceId::Fetchable(FetchableOrigin::Local { path }) => {
            validate_no_unsafe_char(path, &format!("local source path {path:?}"))?;
            Ok(SourceId::Fetchable(FetchableOrigin::Local { path: path.clone() }))
        }
        SourceId::Fetchable(FetchableOrigin::Registry { registry, namespace, name }) => {
            validate_registry_component(registry, "alias")?;
            if let Some(ns) = namespace {
                validate_namespace(ns)?;
            }
            validate_registry_component(name, "name")?;
            Ok(SourceId::Fetchable(FetchableOrigin::Registry {
                registry: registry.clone(),
                namespace: namespace.clone(),
                name: name.clone(),
            }))
        }
        SourceId::Member { member_name } => Ok(SourceId::Member { member_name: member_name.clone() }),
    }
}

#[cfg(test)]
#[path = "source_id_tests.rs"]
mod source_id_tests;
