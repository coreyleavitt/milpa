//! Manifest discovery + loading (RFC §6 S13; `milpa/manifest.py`).
//!
//! The CLI's first step: find a project's manifest. Prefers `milpa.kdl`; falls
//! back to a `.nimble` file (Nim convention — `<name>.nimble`, then any single
//! `*.nimble`). Emits the discovery `MAN-*` codes. Mirrors `manifest.py`'s
//! `load_manifest` / `discover_manifest` / `manifest_from_nimble`.
//!
//! **Exempt by construction:** the Rust `.nimble` line-form parser
//! ([`milpa_manifest::nimble::parse_nimble`]) is *total* — a heuristic scan that
//! never raises — so `MAN-NIMBLE-PARSE` is unreachable, and a `.nimble` file-read
//! failure surfaces as `MAN-FILE-UNREADABLE` (the same generic code a `milpa.kdl`
//! read failure uses), so the standalone `NIMBLE-FILE-*` codes are never emitted
//! (the Python `load_nimble` that raises them is dead outside its own tests —
//! P2). Both are documented in the bijection lint's EXEMPT set.

use std::path::Path;

use milpa_manifest::nimble::{parse_nimble, NimbleManifest, NimbleRequirement};
use milpa_manifest::{Dep, Manifest, ManifestDoc, NamedDep, UrlDep};

use crate::error::MilpaError;

fn man(code: &'static str, message: impl Into<String>) -> MilpaError {
    MilpaError::Manifest(milpa_manifest::ManifestError::new(code, message.into()))
}

/// Read + parse a `milpa.kdl` at an explicit `path` (`MAN-FILE-NOT-FOUND` if
/// absent, `MAN-FILE-UNREADABLE` on other I/O error, else the parser's `MAN-*`).
pub fn load_manifest(path: &Path) -> Result<ManifestDoc, MilpaError> {
    let text = read_manifest_file(path)?;
    Ok(milpa_manifest::parse_document(&text)?)
}

/// Discover and load a project's manifest from `project_dir` (mirrors
/// `manifest.py:discover_manifest`):
///   1. `milpa.kdl` (preferred — the declarative manifest);
///   2. `<dir-name>.nimble` (Nim convention);
///   3. a single `*.nimble` (fallback); multiple → `MAN-NIMBLE-AMBIGUOUS`;
///   4. none → `MAN-NO-MANIFEST`.
pub fn discover_manifest(project_dir: &Path) -> Result<ManifestDoc, MilpaError> {
    let milpa_kdl = project_dir.join("milpa.kdl");
    if milpa_kdl.is_file() {
        return load_manifest(&milpa_kdl);
    }

    let project_name = project_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let primary = project_dir.join(format!("{project_name}.nimble"));
    if primary.is_file() {
        return load_from_nimble(&primary, &project_name);
    }

    let mut nimbles: Vec<std::path::PathBuf> = match std::fs::read_dir(project_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "nimble"))
            .collect(),
        Err(_) => Vec::new(),
    };
    nimbles.sort();
    match nimbles.as_slice() {
        [one] => {
            let stem = one
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            load_from_nimble(one, &stem)
        }
        [] => Err(man(
            "MAN-NO-MANIFEST",
            format!(
                "no manifest found in {} — looked for milpa.kdl, {project_name}.nimble, \
                 and any *.nimble",
                project_dir.display()
            ),
        )),
        many => {
            let names: Vec<String> = many
                .iter()
                .map(|p| {
                    p.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            Err(man(
                "MAN-NIMBLE-AMBIGUOUS",
                format!(
                    "multiple .nimble files in {} ({}); rename one to {project_name}.nimble \
                     or add a milpa.kdl",
                    project_dir.display(),
                    names.join(", ")
                ),
            ))
        }
    }
}

/// Read a manifest file, mapping I/O failure to the discovery codes.
fn read_manifest_file(path: &Path) -> Result<String, MilpaError> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(man(
            "MAN-FILE-NOT-FOUND",
            format!("manifest file not found: {}", path.display()),
        )),
        Err(e) => Err(man(
            "MAN-FILE-UNREADABLE",
            format!("cannot read manifest {}: {e}", path.display()),
        )),
    }
}

/// Read a `.nimble` and promote it to a package [`ManifestDoc`]. A file-read
/// failure is `MAN-FILE-UNREADABLE` (the heuristic parser is total, so there is
/// no parse-error path → `MAN-NIMBLE-PARSE`/`NIMBLE-FILE-*` are unreachable).
fn load_from_nimble(path: &Path, name: &str) -> Result<ManifestDoc, MilpaError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        man(
            "MAN-FILE-UNREADABLE",
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    let nm = parse_nimble(&text);
    Ok(ManifestDoc::Package(manifest_from_nimble(&nm, name)))
}

/// Convert a parsed `.nimble` into a milpa [`Manifest`] (mirrors
/// `manifest.py:manifest_from_nimble`): URL requirements → `UrlDep`, named →
/// `NamedDep` (constraint preserved), `nim` dropped, `kind` defaults to library.
pub fn manifest_from_nimble(nm: &NimbleManifest, name: &str) -> Manifest {
    let mut deps: Vec<Dep> = Vec::new();
    for req in &nm.requires {
        match req {
            NimbleRequirement::Url { url, ref_spec, .. } => {
                deps.push(Dep::Url(UrlDep {
                    name: name_from_url(url),
                    git: url.clone(),
                    // §7.2 normative: bare URL with no `#ref` defaults to HEAD
                    // (the remote's default branch), matching nimble's behavior.
                    git_ref: ref_spec.clone().unwrap_or_else(|| "HEAD".to_string()),
                    mirrors: Vec::new(),
                    predicates: Vec::new(),
                    flag_requests: Vec::new(),
                    optional: false,
                }));
            }
            NimbleRequirement::Named {
                name: dep_name,
                constraint,
                ..
            } => {
                if dep_name == "nim" {
                    continue;
                }
                // Nimble-derived deps: constraint is validated lazily at
                // resolve time by build_from_nimble → from_nimble_constraint
                // (MAN-NIMBLE-CONSTRAINT). parsed_constraint stays None here.
                deps.push(Dep::Named(NamedDep {
                    name: dep_name.clone(),
                    constraint: constraint.clone(),
                    parsed_constraint: None,
                    flag_requests: Vec::new(),
                    optional: false,
                    predicates: Vec::new(),
                    namespace: None, // Nimble-derived deps have no namespace.
                }));
            }
        }
    }
    Manifest {
        name: Some(name.to_string()),
        kind: "library".to_string(),
        src_dir: nm.src_dir.clone().unwrap_or_default(),
        deps,
        dev_deps: Vec::new(),
        overrides: Vec::new(),
        flags: Vec::new(),
        self_mirrors: Vec::new(),
        cas_dir: String::new(),
        spec_version: 1,
        spec_version_explicit: false,
        attestation_policy: milpa_manifest::AttestationPolicy::Permissive,
        optional_auto_flags: std::collections::BTreeSet::new(),
    }
}

/// Derive a package name from a git URL's last path segment (`…/foo.git` → `foo`).
fn name_from_url(url: &str) -> String {
    let tail = url.trim_end_matches('/').rsplit('/').next().unwrap_or(url);
    tail.strip_suffix(".git").unwrap_or(tail).to_string()
}

#[cfg(test)]
#[path = "discovery_tests.rs"]
mod discovery_tests;
