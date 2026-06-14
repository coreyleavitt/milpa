//! `milpa` CLI binary (RFC §6 S13; `spec/cli-contract.md`; mirrors
//! `milpa/cli.py`). A thin argparse-equivalent over the feature-complete
//! `milpa-core` library: the 8 conformance verbs (`fetch`/`lock`/`show`/`verify`/
//! `clean` + `add`/`remove`/`update`), the global flags (`-C`/`-j`/`-s`/
//! `--frozen`/`--version`), and the exit-code + stdout/stderr discipline.
//!
//! Exit codes (cli-contract §3): `0` on success, `1` on any failure, with a
//! single `CODE: message` diagnostic line on stderr (§4 — diagnostics to stderr,
//! the verb's data to stdout). No other codes. `publish` is out of scope for
//! spec v1.0 (§10).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use milpa_core::{
    add_mirror, dep_decl_store::DepDeclStore, discover_manifest, effective_strict_policy,
    fetch::{FetchError, FetcherRegistry}, format_nimcfg, format_workspace_nimcfgs, from_graph,
    load_index, load_lockfile, load_manifest, load_workspace,
    make_dep_decl_store, mutate_manifest_file, parse_env_bool, parse_lockfile, parse_version,
    resolve, resolve_with_cert, resolve_workspace, resolve_workspace_frozen,
    verify_lockfile_against_deps, workspace_any_member_strict, write_lockfile, CaStore,
    CasAdmittingFetcher, CoreError, DefaultRegistry, FailureCert, FileDepDeclStore,
    FrozenResolver, Index, ManifestDoc, Milpa, MilpaError, MockedFetcher, Profile, Resolver,
    Strategy, SuccessCert, DEFAULT_INDEX_URL, DEFAULT_TTL_SECONDS,
};
use milpa_manifest::{Dep, Manifest, UrlDep};

const VERSION: &str = "0.1.0";

const USAGE: &str = "usage: milpa [-C <dir>] [-j <N>] [-s <mode>] [--frozen] \
[--certificate <path>] <fetch|lock|show|verify|clean|add|remove|update> [args]";

fn main() {
    // Gap-1 R4: catch any Rust panic, emit a human line + the machine-readable
    // slug, then exit 1. An unhandled panic exiting 101 is a crash verdict.
    std::panic::set_hook(Box::new(|info| {
        eprintln!("{info}");
        eprintln!("milpa-error: INTERNAL-PANIC");
    }));

    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(match run(&args) {
        Ok(code) => code,
        // Gap-1 R1/R2: on a typed Err, emit the human line then the terminal
        // machine-readable slug. The human line is first for readability (R2
        // says position-independent, but slug-last is the SHOULD).
        Err(e) => {
            eprintln!("{}: {}", e.code(), message_of(&e));
            eprintln!("milpa-error: {}", e.code());
            1
        }
    });
}

/// Parsed global flags + the verb and its tail.
struct Cli {
    directory: PathBuf,
    strategy: Strategy,
    frozen: bool,
    /// Path for the §5 result certificate (cli-contract §2.5). `None` when
    /// `--certificate` is absent; `Some(path)` when present. Only used by
    /// `fetch` and `lock`; other verbs silently ignore it.
    certificate: Option<PathBuf>,
    /// S5: `--require-attested-metadata` flag (cli-contract §8.4).
    /// When set, the effective attestation policy is strict (OR with
    /// manifest `attestation-policy "strict"`). The flag CANNOT weaken a
    /// manifest-declared strict policy.
    require_attested_metadata: bool,
    verb: String,
    rest: Vec<String>,
}

fn run(args: &[String]) -> Result<i32, MilpaError> {
    if args.iter().any(|a| a == "--version") {
        println!("milpa {VERSION}");
        return Ok(0);
    }
    let Some(cli) = parse_args(args) else {
        eprintln!("{USAGE}");
        // Gap-1 R4/§3: argument-parse failures exit 2 (NO milpa-error: line).
        // Empty args → print help and exit 0 (NORMATIVE: §1, "no verb → exit 0").
        return Ok(if args.is_empty() { 0 } else { 2 });
    };

    let dir = &cli.directory;
    let cert_path = cli.certificate.as_deref();
    match cli.verb.as_str() {
        "show" => cmd_show(dir),
        "verify" => cmd_verify(dir, cli.require_attested_metadata),
        "clean" => cmd_clean(dir),
        "fetch" => cmd_fetch(dir, cli.strategy, cli.frozen, true, cert_path, cli.require_attested_metadata),
        "lock" => cmd_fetch(dir, cli.strategy, cli.frozen, false, cert_path, cli.require_attested_metadata),
        "update" => cmd_update(dir, cli.strategy, &cli.rest),
        "add" => cmd_add(dir, &cli.rest),
        "remove" => cmd_remove(dir, &cli.rest),
        other => {
            // Gap-1 §3: unknown verb is a usage error → exit 2 (no milpa-error: line).
            eprintln!("milpa: unknown command {other:?}\n{USAGE}");
            Ok(2)
        }
    }
}

/// Hand-rolled arg parse: global flags (some take a value), then the verb + tail.
fn parse_args(args: &[String]) -> Option<Cli> {
    let mut directory = PathBuf::from(".");
    let mut strategy = Strategy::default();
    let mut frozen = false;
    let mut certificate: Option<PathBuf> = None;
    // S5: `MILPA_REQUIRE_ATTESTED_METADATA` env var also activates strict policy
    // (cli-contract §8.4). The flag OR the env var; same OR semantics as manifest.
    let mut require_attested_metadata = std::env::var("MILPA_REQUIRE_ATTESTED_METADATA")
        .map(|v| parse_env_bool(&v))
        .unwrap_or(false);
    let mut i = 0;
    let verb;
    loop {
        let a = args.get(i)?;
        match a.as_str() {
            "-C" | "--directory" => {
                directory = PathBuf::from(args.get(i + 1)?);
                i += 2;
            }
            "-j" | "--parallel" => {
                args.get(i + 1)?; // accepted; the serial reference ignores -j (§4.4)
                i += 2;
            }
            "-s" | "--strategy" => {
                strategy = parse_strategy(args.get(i + 1)?)?;
                i += 2;
            }
            "--frozen" => {
                frozen = true;
                i += 1;
            }
            "--certificate" => {
                certificate = Some(PathBuf::from(args.get(i + 1)?));
                i += 2;
            }
            "--require-attested-metadata" => {
                require_attested_metadata = true;
                i += 1;
            }
            v if !v.starts_with('-') => {
                verb = v.to_string();
                i += 1;
                break;
            }
            _ => return None,
        }
    }
    Some(Cli {
        directory,
        strategy,
        frozen,
        certificate,
        require_attested_metadata,
        verb,
        rest: args[i..].to_vec(),
    })
}

fn parse_strategy(s: &str) -> Option<Strategy> {
    match s {
        "maxver" => Some(Strategy::Maxver),
        "minver" => Some(Strategy::Minver),
        "semver" => Some(Strategy::Semver),
        _ => None,
    }
}

// --- verbs -----------------------------------------------------------------

/// `milpa show` — print the locked dep graph (stdout).
fn cmd_show(dir: &Path) -> Result<i32, MilpaError> {
    let text = std::fs::read_to_string(dir.join("milpa.lock")).map_err(|_| {
        MilpaError::Core(CoreError::Lockfile(
            "LOCK-FILE-NOT-FOUND",
            "no milpa.lock — run `milpa fetch` first".into(),
        ))
    })?;
    let lock = parse_lockfile(&text)?;
    for dep in &lock.deps {
        println!("{:20} {}", dep.name, dep.version);
        if let Some(id) = &dep.identity {
            println!("  identity    {}", &id[..id.len().min(23)]);
        }
        if !dep.requires.is_empty() {
            println!("  requires    {}", dep.requires.join(", "));
        }
    }
    Ok(0)
}

/// `milpa verify` — confirm `_deps/` matches the lockfile (stderr report).
///
/// `require_attested_metadata` is the parsed CLI flag (already ORed with the
/// `MILPA_REQUIRE_ATTESTED_METADATA` env var by `parse_args` — the env parse
/// lives there and only there, per Finding 1 SSOT).
fn cmd_verify(dir: &Path, require_attested_metadata: bool) -> Result<i32, MilpaError> {
    // Gap-1 D: load_lockfile's `?` surfaces LOCK-FILE-NOT-FOUND via the Err path
    // in main (which now emits the milpa-error: slug automatically). No inline
    // slug needed for the missing-lockfile case.
    let lock = load_lockfile(&dir.join("milpa.lock"))?;
    let deps_dir = dir.join("_deps");
    // Gap-1 D: VERIFY-DEPS-DIR-MISSING — emitted inline (Ok(1) path).
    if !deps_dir.exists() {
        eprintln!("verify: _deps/ directory not found — run `milpa fetch` first");
        eprintln!("milpa-error: VERIFY-DEPS-DIR-MISSING");
        return Ok(1);
    }
    let divergences = verify_lockfile_against_deps(&lock, &deps_dir);
    if !divergences.is_empty() {
        eprintln!("verification failed — {} divergence(s):", divergences.len());
        for d in &divergences {
            eprintln!("  {d}");
        }
        // Gap-1 D: LOCK-GRAPH-MISMATCH — emitted inline (Ok(1) path).
        eprintln!("milpa-error: LOCK-GRAPH-MISMATCH");
        return Ok(1);
    }

    // S6: dep_decl edge check — compare locked pins against the live index (§3.7.2).
    let pinned: Vec<_> = lock.deps.iter().filter(|d| d.dep_decl.is_some()).collect();
    if !pinned.is_empty() {
        // §13.1: effective strict = OR(manifest/workspace-member attestation-policy "strict",
        // require_attested_metadata).  Use the SSOT helpers (Finding 1 + Finding 2):
        //   - Single-package: effective_strict_policy(manifest.attestation_policy, flag)
        //   - Workspace:      workspace_any_member_strict(ws) || flag
        // The env-var parse lives in parse_args (the one SSOT); `require_attested_metadata`
        // already incorporates it — no inline re-read here.
        let strict = match discover_manifest(dir) {
            Ok(milpa_manifest::ManifestDoc::Package(m)) => {
                effective_strict_policy(&m.attestation_policy, require_attested_metadata)
            }
            Ok(milpa_manifest::ManifestDoc::Workspace(_)) => {
                // Finding 2: load the workspace and consult member policies.
                match load_workspace(dir) {
                    Ok(ws) => workspace_any_member_strict(&ws) || require_attested_metadata,
                    Err(_) => require_attested_metadata,
                }
            }
            Err(_) => require_attested_metadata,
        };

        // Determine online state: MILPA_INDEX_URL must be set.
        // maybe_index() returns None when offline/unreachable (treats as absent).
        let index_opt = maybe_index()?;
        if index_opt.is_none() {
            // Offline / unreachable.
            if strict {
                eprintln!(
                    "dep_decl edge check requires live index — offline (strict mode)"
                );
                eprintln!("milpa-error: VERIFY-EDGE-MISMATCH");
                return Ok(1);
            }
            eprintln!(
                "dep_decl edge check SKIPPED for {} dep(s) — offline (network required)",
                pinned.len()
            );
        } else if let Some(index) = index_opt {
            // Online: check each pin against the live index.
            for dep in &pinned {
                let locked_pin = dep.dep_decl.as_deref().unwrap();
                let iv = match index.lookup_bare(&dep.name) {
                    milpa_core::registry::BareLookup::NotFound
                    | milpa_core::registry::BareLookup::Ambiguous(_) => None,
                    milpa_core::registry::BareLookup::Found(pkg) => {
                        pkg.versions.into_iter().find(|v| v.version == dep.version)
                    }
                };
                match iv {
                    None => {
                        eprintln!(
                            "dep '{}@{}': dep_decl pin present in lock but \
                             package/version not in index",
                            dep.name, dep.version
                        );
                        eprintln!("milpa-error: LOCK-DEPDECL-PIN-MISSING");
                        return Ok(1);
                    }
                    Some(entry) => match &entry.dep_decl {
                        None => {
                            eprintln!(
                                "dep '{}@{}': dep_decl pin present in lock but \
                                 index version-node lacks dep_decl (retracted?)",
                                dep.name, dep.version
                            );
                            eprintln!("milpa-error: LOCK-DEPDECL-PIN-MISSING");
                            return Ok(1);
                        }
                        Some(current) if current != locked_pin => {
                            eprintln!(
                                "dep '{}@{}': locked dep_decl {} != index dep_decl {} \
                                 — dependency graph has drifted",
                                dep.name, dep.version, locked_pin, current
                            );
                            eprintln!("milpa-error: VERIFY-EDGE-MISMATCH");
                            return Ok(1);
                        }
                        _ => {} // match
                    },
                }
            }
        }
    }

    eprintln!("verified {} deps", lock.deps.len());
    Ok(0)
}

/// `milpa clean` — remove `_deps/` + `nim.cfg`, keep `milpa.lock`.
fn cmd_clean(dir: &Path) -> Result<i32, MilpaError> {
    let _ = std::fs::remove_dir_all(dir.join("_deps"));
    let _ = std::fs::remove_file(dir.join("nim.cfg"));
    Ok(0)
}

// ---------------------------------------------------------------------------
// Certificate JSON serialisation (cli-contract §2.5 + resolver-semantics §5)
// ---------------------------------------------------------------------------

/// Serialise a success certificate to the §2.5.1 JSON schema and write it
/// atomically to `path` (tmp + rename). On any I/O or serialisation error the
/// file at `path` is left absent or unchanged.
fn write_success_cert(path: &Path, cert: &SuccessCert) -> std::io::Result<()> {
    let json = success_cert_to_json(cert);
    write_cert_atomic(path, &json)
}

/// Serialise a failure certificate to the §2.5.2 JSON schema and write it
/// atomically to `path` (tmp + rename).
fn write_failure_cert(path: &Path, cert: &FailureCert) -> std::io::Result<()> {
    let json = failure_cert_to_json(cert);
    write_cert_atomic(path, &json)
}

/// Build the §2.5.1 JSON string for a success certificate.
fn success_cert_to_json(cert: &SuccessCert) -> String {
    let resolved: Vec<String> = cert
        .resolved
        .iter()
        .map(|(pkg, ver)| {
            format!(r#"    {{"package": {pkg_j}, "version": {ver_j}}}"#,
                pkg_j = json_str(pkg),
                ver_j = json_str(ver))
        })
        .collect();
    let witness: Vec<String> = cert
        .witness
        .iter()
        .map(|w| {
            format!(
                r#"    {{"package": {p}, "version": {v}, "constraint": {c}, "satisfied_by": {s}}}"#,
                p = json_str(&w.package),
                v = json_str(&w.version),
                c = json_str(&w.constraint),
                s = json_str(&w.satisfied_by),
            )
        })
        .collect();
    format!(
        "{{\n  \"kind\": \"success\",\n  \"resolved\": [\n{}\n  ],\n  \"witness\": [\n{}\n  ]\n}}",
        resolved.join(",\n"),
        witness.join(",\n"),
    )
}

/// Build the §2.5.2 JSON string for a failure certificate.
fn failure_cert_to_json(cert: &FailureCert) -> String {
    // message: null when empty (Python impl convention; not byte-normative).
    let message_val = if cert.message.is_empty() {
        "null".to_string()
    } else {
        json_str(&cert.message)
    };
    let refutation: Vec<String> = cert
        .refutation
        .iter()
        .map(|r| {
            format!(
                r#"    {{"package": {p}, "constraint": {c}}}"#,
                p = json_str(&r.package),
                c = json_str(&r.constraint),
            )
        })
        .collect();
    format!(
        "{{\n  \"kind\": \"failure\",\n  \"message\": {message_val},\n  \"refutation\": [\n{}\n  ]\n}}",
        refutation.join(",\n"),
    )
}

/// Minimal JSON string escaping (only what spec values contain: printable ASCII
/// without control chars; no need for full Unicode escape).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Atomic write: write to a sibling tmp file, then rename into place.
fn write_cert_atomic(path: &Path, json: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// `milpa fetch` / `lock` / `update` — resolve, write `milpa.lock` (+ `nim.cfg`
/// for fetch). `--frozen` reconstructs from the lockfile + CAS (no network).
/// `MILPA_MOCKED_FETCHES` if set+non-empty (the conformance fetch transport,
/// cli-contract §8.4). `None` selects the real network transports.
fn mocked_fetches_dir() -> Option<PathBuf> {
    std::env::var("MILPA_MOCKED_FETCHES")
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Build the fetcher registry used by every resolve path (fetch / lock / add /
/// remove / update). All fetches go through `CasAdmittingFetcher` so
/// `_deps/<name>` is always a relative CAS symlink. The inner fetcher is the
/// `MockedFetcher` when `MILPA_MOCKED_FETCHES` is set (offline, conformance),
/// else `DefaultRegistry` (real network). Single source of truth for the
/// stage→hash→admit→link orchestration lives in `CasAdmittingFetcher`.
fn build_registry() -> Box<dyn FetcherRegistry> {
    let store = CaStore::new(cas_root());
    // staging_root on the same filesystem as the CAS so rename(2) is atomic.
    let staging_root = cas_root();
    match mocked_fetches_dir() {
        Some(mocked_dir) => Box::new(CasAdmittingFetcher::new(
            MockedFetcher::new(mocked_dir),
            store,
            staging_root,
        )),
        None => Box::new(CasAdmittingFetcher::new(
            DefaultRegistry::with_curl(),
            store,
            staging_root,
        )),
    }
}

fn cmd_fetch(
    dir: &Path,
    strategy: Strategy,
    frozen: bool,
    emit_nimcfg: bool,
    cert_path: Option<&Path>,
    require_attested_metadata: bool,
) -> Result<i32, MilpaError> {
    let deps_dir = dir.join("_deps");
    let doc = discover_manifest(dir)?;

    // All fetches go through CasAdmittingFetcher so that _deps/<name> is
    // always a relative CAS symlink (matching Python's registry layer and the
    // conformance harness's FakeFetcher). The inner fetcher is selected by
    // MILPA_MOCKED_FETCHES: set+non-empty → MockedFetcher (offline, for
    // conformance / testing); unset/empty → DefaultRegistry (real network).
    // Single source of truth for stage→hash→admit→link lives in
    // CasAdmittingFetcher (fetchers.rs) — no parallel orchestration elsewhere.
    let registry = build_registry();

    if let ManifestDoc::Workspace(_) = doc {
        let ws = load_workspace(dir)?;
        let graph = if frozen {
            // Workspace frozen path: reconstruct from lockfile + CAS, check
            // FROZEN-MEMBER-NOT-IN-WORKSPACE and FROZEN-MEMBER-IDENTITY-DRIFT.
            let lock_path = dir.join("milpa.lock");
            if !lock_path.exists() {
                return Err(MilpaError::Core(CoreError::Frozen(
                    "FROZEN-NO-LOCKFILE",
                    "frozen: no milpa.lock — run `milpa fetch` first".into(),
                )));
            }
            let lock = load_lockfile(&lock_path)?;
            resolve_workspace_frozen(&ws, &lock, &CaStore::new(cas_root()), &deps_dir)?
        } else {
            let index = maybe_index()?;
            let profile = profile_from_env();
            // §8: reuse existing pins (idempotent repeated fetch — see single-pkg path).
            let prior = maybe_prior_lockfile(&dir.join("milpa.lock"));
            resolve_workspace(
                &ws,
                index.as_ref(),
                registry.as_ref(),
                profile.as_ref(),
                prior.as_ref(),
                strategy,
                &deps_dir,
                require_attested_metadata,
            )?
        };
        write_lockfile(
            &from_graph(&graph, strategy.as_str()),
            &dir.join("milpa.lock"),
        )?;
        if emit_nimcfg {
            for (path, text) in format_workspace_nimcfgs(&ws, &graph) {
                let target = dir.join(&path).join("nim.cfg");
                if let Some(p) = target.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                let _ = std::fs::write(target, text);
            }
        }
        eprintln!(
            "resolved {} deps across {} members{}",
            graph.deps.len(),
            ws.members.len(),
            if frozen { " (frozen)" } else { "" }
        );
        return Ok(0);
    }

    let ManifestDoc::Package(manifest) = doc else {
        unreachable!("workspace handled above");
    };

    let graph = if frozen {
        // Gap-1 E (partial): FROZEN-NO-LOCKFILE — distinguish "no lockfile"
        // from other lockfile errors when --frozen is active. Without --frozen,
        // a missing lockfile falls through to full resolution (not an error).
        let lock_path = dir.join("milpa.lock");
        if !lock_path.exists() {
            return Err(MilpaError::Core(CoreError::Frozen(
                "FROZEN-NO-LOCKFILE",
                "frozen: no milpa.lock — run `milpa fetch` first".into(),
            )));
        }
        // FROZEN-NO-CAS: the Rust impl always constructs a CaStore (never None),
        // so this condition is unrepresentable — left as a known cross-impl
        // divergence (the differential harness will catch it later).
        let lock = load_lockfile(&lock_path)?;
        Milpa.resolve_frozen(&manifest, &lock, &CaStore::new(cas_root()), &deps_dir)?
    } else {
        let index = maybe_index()?;
        let profile = profile_from_env();
        // §8: reuse the existing lockfile's pins so repeated `fetch`/`lock` runs
        // are idempotent and a silently-moved ref / substituted archive is caught.
        let prior = maybe_prior_lockfile(&dir.join("milpa.lock"));

        // S3b: wire dep_decl_store from environment (MILPA_DEP_DECL_DIR or MILPA_INDEX_URL).
        // Built before the cert branch so both paths share the same store — single
        // source of truth for DepDecl wiring (fixes Finding-High-2).
        let dep_decl_store_owned = maybe_dep_decl_store();
        let dep_decl_store: Option<&dyn DepDeclStore> =
            dep_decl_store_owned.as_deref();

        if let Some(cert_dest) = cert_path {
            // §2.5: resolve with certificate — emit JSON regardless of success/failure,
            // then propagate the normal exit/slug outcome.
            // Thread dep_decl_store and require_attested_metadata so the cert path is
            // IDENTICAL to the non-cert path modulo certificate emission (fixes
            // Finding-High-1: strict attestation; Finding-High-2: DepDecl wiring).
            return cmd_fetch_with_cert(
                dir, &manifest, &deps_dir, index.as_ref(), registry.as_ref(),
                profile.as_ref(), prior.as_ref(), strategy, emit_nimcfg, cert_dest,
                dep_decl_store, require_attested_metadata,
            );
        }

        resolve(
            &manifest,
            index.as_ref(),
            registry.as_ref(),
            profile.as_ref(),
            prior.as_ref(),
            strategy,
            &deps_dir,
            dep_decl_store,
            require_attested_metadata,
        )?
    };

    write_lockfile(
        &from_graph(&graph, strategy.as_str()),
        &dir.join("milpa.lock"),
    )?;
    if emit_nimcfg {
        let _ = std::fs::write(
            dir.join("nim.cfg"),
            format_nimcfg(&graph, "_deps", &manifest.src_dir),
        );
    }
    eprintln!(
        "resolved {} deps{}",
        graph.deps.len(),
        if frozen { " (frozen)" } else { "" }
    );
    Ok(0)
}

/// The `--certificate` sub-path for `cmd_fetch`/`cmd_lock` (single-package,
/// non-frozen). Runs `resolve_with_cert`, writes the certificate, then applies
/// the normal exit/slug discipline (§2.5).
///
/// Mirrors the non-cert path in `cmd_fetch` exactly: `dep_decl_store` and
/// `require_attested_metadata` are threaded through to `resolve_with_cert` so
/// that DepDecl wiring and strict-attestation enforcement are identical to the
/// non-cert resolve path (spec §2.5, §13.1; fixes Finding-High-1 + Finding-High-2).
#[allow(clippy::too_many_arguments)]
fn cmd_fetch_with_cert(
    dir: &Path,
    manifest: &Manifest,
    deps_dir: &Path,
    index: Option<&Index>,
    registry: &dyn FetcherRegistry,
    profile: Option<&Profile>,
    prior: Option<&milpa_core::Lockfile>,
    strategy: Strategy,
    emit_nimcfg: bool,
    cert_dest: &Path,
    dep_decl_store: Option<&dyn DepDeclStore>,
    require_attested_metadata: bool,
) -> Result<i32, MilpaError> {
    match resolve_with_cert(manifest, index, registry, profile, prior, strategy, deps_dir, dep_decl_store, require_attested_metadata) {
        Ok((graph, cert)) => {
            // Write the success certificate (best-effort; a cert write failure
            // does NOT abort the command — the lock/nim.cfg still land).
            let _ = write_success_cert(cert_dest, &cert);
            write_lockfile(&from_graph(&graph, strategy.as_str()), &dir.join("milpa.lock"))?;
            if emit_nimcfg {
                let _ = std::fs::write(
                    dir.join("nim.cfg"),
                    format_nimcfg(&graph, "_deps", &manifest.src_dir),
                );
            }
            eprintln!("resolved {} deps", graph.deps.len());
            Ok(0)
        }
        Err((err, failure_cert)) => {
            // Write the failure certificate, then surface the error normally.
            // The normal error path (main's Err arm) emits the slug + exits 1.
            let _ = write_failure_cert(cert_dest, &failure_cert);
            Err(err)
        }
    }
}

/// `milpa update [<dep>]` — re-resolve and refresh `milpa.lock`, optionally
/// scoped to a single dep (cli-contract §5.8). Never mutates `milpa.kdl`; never
/// emits `nim.cfg` (only `milpa.lock` and `_deps/` change).
///
/// - No `<dep>`: drop ALL pins (`prior = None`) → full re-resolve from scratch.
/// - `update <dep>`: reject if `<dep>` is not in the lockfile (LOCK-DEP-NOT-FOUND);
///   drop ONLY that pin; pass all other pins to the resolver as `prior` so they
///   stay stable; re-resolve; write the new lockfile.
fn cmd_update(dir: &Path, strategy: Strategy, rest: &[String]) -> Result<i32, MilpaError> {
    let name = rest.first().cloned();
    let lock_path = dir.join("milpa.lock");

    // Scoped update: load the lockfile and build the prior (all pins minus the
    // named dep). Reject if the named dep is not pinned.
    let prior: Option<milpa_core::Lockfile> = match &name {
        None => None,
        Some(name) => {
            // §5.8: with a <dep> arg but no lockfile, exit 1 (no prior pins to
            // drop selectively — `milpa fetch` is the correct action).
            if !lock_path.exists() {
                return Err(MilpaError::Core(CoreError::Lockfile(
                    "LOCK-FILE-NOT-FOUND",
                    "update: no milpa.lock — run `milpa fetch` first".into(),
                )));
            }
            let full = load_lockfile(&lock_path)?;
            if !full.deps.iter().any(|d| &d.name == name) {
                let mut known: Vec<&str> = full.deps.iter().map(|d| d.name.as_str()).collect();
                known.sort_unstable();
                eprintln!(
                    "update: no dep {name:?} in lockfile (known: {})",
                    if known.is_empty() {
                        "<none>".to_string()
                    } else {
                        known.join(", ")
                    }
                );
                eprintln!("milpa-error: LOCK-DEP-NOT-FOUND");
                return Ok(1);
            }
            // Drop only the named pin; everything else is retained as prior.
            let mut prior = full;
            prior.deps.retain(|d| &d.name != name);
            Some(prior)
        }
    };

    let doc = discover_manifest(dir)?;
    let deps_dir = dir.join("_deps");
    let registry = build_registry();

    if let ManifestDoc::Workspace(_) = doc {
        let ws = load_workspace(dir)?;
        let index = maybe_index()?;
        let profile = profile_from_env();
        let graph = resolve_workspace(
            &ws,
            index.as_ref(),
            registry.as_ref(),
            profile.as_ref(),
            prior.as_ref(),
            strategy,
            &deps_dir,
            false, // cmd_update does not accept --require-attested-metadata (fetch/lock only)
        )?;
        write_lockfile(&from_graph(&graph, strategy.as_str()), &lock_path)?;
        eprintln!(
            "updated {} across {} members",
            name.as_deref().unwrap_or("all deps"),
            ws.members.len()
        );
        return Ok(0);
    }

    let ManifestDoc::Package(manifest) = doc else {
        unreachable!("workspace handled above");
    };
    let index = maybe_index()?;
    let profile = profile_from_env();
    let dep_decl_store_owned = maybe_dep_decl_store();
    let dep_decl_store: Option<&dyn DepDeclStore> = dep_decl_store_owned.as_deref();
    let graph = resolve(
        &manifest,
        index.as_ref(),
        registry.as_ref(),
        profile.as_ref(),
        prior.as_ref(),
        strategy,
        &deps_dir,
        dep_decl_store,
        false, // require_attested_metadata: not surfaced by `update` verb
    )?;
    write_lockfile(&from_graph(&graph, strategy.as_str()), &lock_path)?;
    eprintln!("updated {}", name.as_deref().unwrap_or("all deps"));
    Ok(0)
}

/// `milpa add <name> --git <url> [--ref <r>]` / `add <name> --mirror <url>`.
fn cmd_add(dir: &Path, rest: &[String]) -> Result<i32, MilpaError> {
    let Some(name) = rest.first().cloned().filter(|n| !n.starts_with('-')) else {
        // Gap-1 C: no-name → usage error → exit 2 (no milpa-error: line).
        eprintln!("add: usage: milpa add <name> --git <url> [--ref <r>] | --mirror <url>");
        return Ok(2);
    };
    if let Some(url) = flag_value(rest, "--mirror") {
        add_mirror(dir, &name, &url)?;
        eprintln!("added mirror for {name}");
        return Ok(0);
    }
    let Some(url) = flag_value(rest, "--git") else {
        // Gap-1 C: no --git/--mirror → usage error → exit 2 (no milpa-error: line).
        eprintln!("add: requires --git <url> (new dep) or --mirror <url> (existing dep)");
        return Ok(2);
    };

    // Gap-1 D: MAN-ADD-DEP-EXISTS — pre-check by loading the manifest before
    // mutating. `load_manifest` returns Err(MAN-*) on parse failures, which
    // propagate via `?`. On success we check for the duplicate and return
    // MAN-ADD-DEP-EXISTS via Err (which main's Err path will slug-print).
    let existing_doc = load_manifest(&dir.join("milpa.kdl"))?;
    let ManifestDoc::Package(existing) = existing_doc else {
        return Err(MilpaError::Manifest(milpa_manifest::ManifestError::new(
            "MAN-ADD-DEP-EXISTS",
            "add: cannot add a dep to a workspace root manifest".to_string(),
        )));
    };
    if existing.deps.iter().any(|d| d.name() == name) {
        return Err(MilpaError::Manifest(milpa_manifest::ManifestError::new(
            "MAN-ADD-DEP-EXISTS",
            format!("dep {name:?} is already declared in milpa.kdl"),
        )));
    }

    // Ref discovery (cli-contract §5.6): if --ref is omitted, discover the
    // default branch. Under MILPA_MOCKED_FETCHES this is answered from the mock
    // tree (no network, conformance-fixtures §2.3.3); otherwise via
    // `git ls-remote --symref HEAD`. Discovery failure → FETCH-REF-DISCOVERY-FAILED.
    let git_ref = match flag_value(rest, "--ref") {
        Some(r) => r,
        None => match discover_default_branch(&url) {
            Ok(r) => r,
            Err(msg) => {
                return Err(MilpaError::Fetch(FetchError::Transport(
                    "FETCH-REF-DISCOVERY-FAILED",
                    format!("could not discover default branch for {url}: {msg}; pass --ref explicitly"),
                )));
            }
        },
    };

    // Build the proposed manifest (existing + the new url dep) and run a full
    // resolve (cli-contract §5.6). Only on success do we write milpa.kdl +
    // milpa.lock atomically; on any failure both files are left unmodified.
    let mut proposed = existing.clone();
    proposed.deps.push(Dep::Url(UrlDep {
        name: name.clone(),
        git: url.clone(),
        git_ref: git_ref.clone(),
        mirrors: Vec::new(),
        predicates: Vec::new(),
        flag_requests: Vec::new(),
    }));

    let deps_dir = dir.join("_deps");
    let registry = build_registry();
    let index = maybe_index()?;
    let profile = profile_from_env();
    let graph = Milpa.resolve(
        &proposed,
        index.as_ref(),
        registry.as_ref(),
        profile.as_ref(),
        None,
        &deps_dir,
    )?;

    // Resolution succeeded → commit both outputs.
    mutate_manifest_file(&dir.join("milpa.kdl"), move |mut m| {
        m.deps.push(Dep::Url(UrlDep {
            name: name.clone(),
            git: url.clone(),
            git_ref: git_ref.clone(),
            mirrors: Vec::new(),
            predicates: Vec::new(),
            flag_requests: Vec::new(),
        }));
        m
    })?;
    write_lockfile(&from_graph(&graph, "maxver"), &dir.join("milpa.lock"))?;
    eprintln!("added dep");
    Ok(0)
}

/// Discover a remote's default branch. Under `MILPA_MOCKED_FETCHES` this is the
/// mocked ref-resolution path (conformance-fixtures §2.3.3) — no network.
/// Otherwise it runs `git ls-remote --symref HEAD`. Returns the branch name or
/// a human-readable error string (the caller maps it to FETCH-REF-DISCOVERY-FAILED,
/// cli-contract §5.6).
fn discover_default_branch(url: &str) -> Result<String, String> {
    if let Some(mocked) = mocked_fetches_dir() {
        return match milpa_core::mocked_default_branch(&mocked, url) {
            Ok(r) => Ok(r),
            Err(e) => Err(format!("{e:?}")),
        };
    }
    let out = std::process::Command::new("git")
        .args(["ls-remote", "--symref", url, "HEAD"])
        .output()
        .map_err(|e| format!("git ls-remote: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // First line: "ref: refs/heads/<branch>\tHEAD".
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("ref: refs/heads/") {
            if let Some(branch) = rest.split_whitespace().next() {
                return Ok(branch.to_string());
            }
        }
    }
    Err("could not parse default branch from ls-remote output".to_string())
}

/// `milpa remove <name>` — drop a dep from `milpa.kdl` and regenerate the
/// lockfile (cli-contract §5.7). Mirrors `cmd_add`'s structure: load the
/// manifest, reject an undeclared dep, build the proposed manifest (minus the
/// dep), run a FULL resolve, and only on success atomically write BOTH
/// `milpa.kdl` and `milpa.lock`. On any failure both files are left unmodified.
fn cmd_remove(dir: &Path, rest: &[String]) -> Result<i32, MilpaError> {
    let Some(name) = rest.first().cloned() else {
        // Gap-1 C: no-name → usage error → exit 2 (no milpa-error: line).
        eprintln!("remove: usage: milpa remove <name>");
        return Ok(2);
    };

    // Load the current manifest. Parse failures propagate via `?` (MAN-* slug).
    let existing_doc = load_manifest(&dir.join("milpa.kdl"))?;
    let ManifestDoc::Package(existing) = existing_doc else {
        return Err(MilpaError::Manifest(milpa_manifest::ManifestError::new(
            "MAN-REMOVE-DEP-ABSENT",
            "remove: cannot remove a dep from a workspace root manifest".to_string(),
        )));
    };

    // §5.7: reject if <dep> is not declared in milpa.kdl.
    if !existing.deps.iter().any(|d| d.name() == name) {
        eprintln!("remove: no dep {name:?} in milpa.kdl");
        eprintln!("milpa-error: MAN-REMOVE-DEP-ABSENT");
        return Ok(1);
    }

    // Build the proposed manifest (manifest minus <dep>) and run a full resolve
    // (§5.7). Only on success do we commit both outputs; on any failure both
    // files are left unmodified (resolve runs before any write).
    let mut proposed = existing.clone();
    proposed.deps.retain(|d| d.name() != name);

    let deps_dir = dir.join("_deps");
    let registry = build_registry();
    let index = maybe_index()?;
    let profile = profile_from_env();
    let graph = Milpa.resolve(
        &proposed,
        index.as_ref(),
        registry.as_ref(),
        profile.as_ref(),
        None,
        &deps_dir,
    )?;

    // Resolution succeeded → commit both outputs.
    {
        let name = name.clone();
        mutate_manifest_file(&dir.join("milpa.kdl"), move |mut m| {
            m.deps.retain(|d| d.name() != name);
            m
        })?;
    }
    write_lockfile(&from_graph(&graph, "maxver"), &dir.join("milpa.lock"))?;
    eprintln!("removed {name}");
    Ok(0)
}

// --- helpers ---------------------------------------------------------------

/// Load the tianguis index from the cache (real network via `curl`).
///
/// Three-way `MILPA_INDEX_URL` semantics (cli-contract.md §8.1 NORMATIVE):
/// - **absent** from env → load from `DEFAULT_INDEX_URL` (live tianguis).
/// - **present but empty** (`""`) → explicitly NO index; return `Ok(None)`
///   without any network attempt. The harness sets this for air-gapped fixtures.
/// - **present and non-empty** → load from that URL.
///
/// Returns:
/// - `Ok(Some(index))` — index loaded and parsed successfully.
/// - `Ok(None)` — no index (explicitly-empty env var, or genuinely unreachable).
///   The resolver surfaces `RES-NO-INDEX` only if a named dep actually needs it.
/// - `Err(e)` — index was fetched but `Index::parse` raised a `TNG-*` (or
///   other catalog) error; this MUST propagate so the correct slug is emitted.
///
/// The two non-catalog sentinels (`MILPA-INDEX-UNREACHABLE`, `MILPA-INTERNAL-IO`)
/// are infrastructure failures (no network / cache I/O error) — treated as
/// "absent" rather than a validation error so the resolver decides whether the
/// absence is fatal.
fn maybe_index() -> Result<Option<Index>, MilpaError> {
    // Three-way semantics: distinguish absent (→ DEFAULT_INDEX_URL) from
    // present-but-empty (→ explicitly no index, no network).
    let raw = std::env::var("MILPA_INDEX_URL");
    let url = match &raw {
        Err(_) => DEFAULT_INDEX_URL.to_string(), // absent → production default
        Ok(s) if s.trim().is_empty() => return Ok(None), // empty → no index
        Ok(s) => s.clone(), // non-empty → that URL
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let http = |url: &str| -> Result<String, String> {
        let out = std::process::Command::new("curl")
            .args(["-fsSL", url])
            .output()
            .map_err(|e| format!("curl: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    };
    match load_index(
        &url,
        &index_cache_dir(),
        &http,
        DEFAULT_TTL_SECONDS,
        now,
    ) {
        Ok(index) => Ok(Some(index)),
        // Non-catalog sentinels: index is unreachable or cache I/O failed.
        // Treat as absent — the resolver will raise RES-NO-INDEX only if a
        // named dep actually needs the index.
        Err(e) if matches!(e.code(), "MILPA-INDEX-UNREACHABLE" | "MILPA-INTERNAL-IO") => {
            Ok(None)
        }
        // Catalog errors (TNG-*, etc.): the index was fetched but failed
        // parse/validation. Propagate so the correct slug reaches the user.
        Err(e) => Err(e),
    }
}

/// `$MILPA_CACHE_DIR` else `$XDG_CACHE_HOME/milpa` else `~/.cache/milpa` — the CAS
/// root (cli-contract §8.2). Never evicted by `milpa clean`.
fn cas_root() -> PathBuf {
    std::env::var("MILPA_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| cache_home().join("milpa"))
}

fn index_cache_dir() -> PathBuf {
    cache_home().join("milpa").join("index")
}

fn cache_home() -> PathBuf {
    std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".cache"))
                .unwrap_or_else(|_| PathBuf::from(".cache"))
        })
}

/// Build a [`Profile`] from the `MILPA_TARGET_*` environment variables
/// (cli-contract §8, manifest-grammar §6.6). Returns `None` when none of the
/// four variables are set (the common case — no conditional filtering).
fn profile_from_env() -> Option<Profile> {
    let platform = std::env::var("MILPA_TARGET_PLATFORM")
        .ok()
        .filter(|s| !s.is_empty());
    let arch = std::env::var("MILPA_TARGET_ARCH")
        .ok()
        .filter(|s| !s.is_empty());
    let nim_version = std::env::var("MILPA_TARGET_NIM")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| parse_version(&s));
    let milpa_version = std::env::var("MILPA_TARGET_MILPA")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| parse_version(&s));

    if platform.is_none() && arch.is_none() && nim_version.is_none() && milpa_version.is_none() {
        return None;
    }
    Some(Profile {
        platform,
        arch,
        nim_version,
        milpa_version,
        flags: Vec::new(),
    })
}

/// Build a `DepDeclStore` from the environment (S3b, cli-contract §8.2).
///
/// Priority:
/// 1. `MILPA_DEP_DECL_DIR` set → `FileDepDeclStore` (conformance / air-gapped).
/// 2. Three-way `MILPA_INDEX_URL` semantics (cli-contract §8.1):
///    - **absent** → `HttpDepDeclStore` from `DEFAULT_INDEX_URL` (production default).
///    - **present but empty** → `None` (explicitly no index; DepDecl unreachable).
///    - **present and non-empty** → `HttpDepDeclStore` from that URL.
///
/// Returns `None` when DepDecl is not configured (the common case for URL-dep-only
/// projects); the resolver's clause (c) is structurally present but falls through
/// to MilpaKdl/Nimble.
fn maybe_dep_decl_store() -> Option<Box<dyn DepDeclStore>> {
    let dep_decl_dir = std::env::var("MILPA_DEP_DECL_DIR").unwrap_or_default();
    if !dep_decl_dir.is_empty() {
        return Some(Box::new(FileDepDeclStore::new(PathBuf::from(dep_decl_dir))));
    }
    // Three-way semantics: absent → default URL, empty → no index, non-empty → that URL.
    let raw = std::env::var("MILPA_INDEX_URL");
    let index_url = match &raw {
        Err(_) => DEFAULT_INDEX_URL.to_string(), // absent → production default
        Ok(s) if s.trim().is_empty() => return None, // empty → no index
        Ok(s) => s.clone(), // non-empty → that URL
    };
    Some(Box::new(make_dep_decl_store(&index_url)))
}

/// Load an existing `milpa.lock` as the §8 prior for pin reuse (resolver-
/// semantics §8: the named stability guarantee that makes repeated `milpa fetch`
/// runs idempotent for an unchanged manifest). Returns `None` when the lockfile
/// is absent or unparseable: §8 pin reuse is a *soft preference*, so a
/// missing/corrupt prior degrades to a fresh resolve rather than blocking
/// `fetch`/`lock` — contrast `--frozen`, which errors on a bad lock.
fn maybe_prior_lockfile(path: &Path) -> Option<milpa_core::Lockfile> {
    if !path.exists() {
        return None;
    }
    load_lockfile(path).ok()
}

/// The value following `flag` in `args` (e.g. `--git <url>`), if present.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

/// Best-effort human message for the stderr diagnostic line.
fn message_of(e: &MilpaError) -> String {
    match e {
        MilpaError::Core(c) => c.message().to_string(),
        MilpaError::Manifest(m) => m.message.clone(),
        MilpaError::Solver(_) | MilpaError::Fetch(_) => e.code().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_global_flags_then_verb() {
        let cli = parse_args(&[
            "-C".into(),
            "/tmp/p".into(),
            "-s".into(),
            "minver".into(),
            "--frozen".into(),
            "fetch".into(),
        ])
        .unwrap();
        assert_eq!(cli.directory, PathBuf::from("/tmp/p"));
        assert!(matches!(cli.strategy, Strategy::Minver));
        assert!(cli.frozen);
        assert_eq!(cli.verb, "fetch");
    }

    #[test]
    fn add_args_split_name_and_flags() {
        let cli = parse_args(&[
            "add".into(),
            "foo".into(),
            "--git".into(),
            "https://e/foo.git".into(),
        ])
        .unwrap();
        assert_eq!(cli.verb, "add");
        assert_eq!(cli.rest, vec!["foo", "--git", "https://e/foo.git"]);
        assert_eq!(
            flag_value(&cli.rest, "--git").as_deref(),
            Some("https://e/foo.git")
        );
    }

    #[test]
    fn clean_run_offline() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // clean on an empty project is a no-op success.
        assert_eq!(cmd_clean(dir).unwrap(), 0);
    }

    /// `remove` rejects an undeclared dep WITHOUT resolving or writing anything
    /// (cli-contract §5.7 — reject if <dep> not in milpa.kdl, exit 1; both files
    /// left unmodified). No mocked transport needed: the reject path is hit
    /// before any resolve.
    #[test]
    fn remove_rejects_undeclared_dep_and_leaves_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let manifest = "name \"app\"\nkind \"application\"\ndeps {\n  foo git=\"https://e/foo.git\" ref=\"main\"\n}\n";
        std::fs::write(dir.join("milpa.kdl"), manifest).unwrap();
        // remove of an absent dep → exit 1 (MAN-REMOVE-DEP-ABSENT).
        assert_eq!(cmd_remove(dir, &["ghost".into()]).unwrap(), 1);
        // manifest is unmodified; no lockfile was written.
        assert_eq!(std::fs::read_to_string(dir.join("milpa.kdl")).unwrap(), manifest);
        assert!(!dir.join("milpa.lock").exists());
    }

    /// `remove <dep>` now conforms to cli-contract §5.7: it runs a FULL resolve
    /// over the manifest-minus-dep and writes BOTH milpa.kdl and milpa.lock.
    /// Removing the only dep → empty graph → empty/header-only lockfile.
    /// Exercised offline via the mocked transport.
    #[test]
    fn remove_resolves_and_writes_both_files_via_mock() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let url = "https://example.com/foo.git";
        let mocked = make_mocked_fetches(
            tmp.path(),
            url,
            "main",
            &"b".repeat(40),
            &[("foo.nim", b"# foo")],
        );
        std::fs::write(
            proj.join("milpa.kdl"),
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=\"{url}\" ref=\"main\"\n}}\n"),
        )
        .unwrap();

        // SAFETY: serialized by ENV_MUTEX.
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let r = cmd_remove(&proj, &["foo".into()]);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(r.unwrap(), 0, "remove should resolve + write both files");
        let after = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        assert!(!after.contains("\"foo\""), "foo must be gone from milpa.kdl");
        // milpa.lock MUST be (re)written — the empty graph yields a header-only lock.
        let lock = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();
        assert!(!lock.contains("\"foo\""), "lockfile must not contain foo");
        assert!(lock.contains("version 1"), "lockfile must have the header");
    }

    /// Scoped `update <dep>` (cli-contract §5.8): drops ONLY the named pin,
    /// retains all other pins as `prior`, re-resolves, writes the new lockfile,
    /// and leaves milpa.kdl untouched. Exercised offline via the mocked transport.
    #[test]
    fn update_scoped_drops_one_pin_retains_others_via_mock() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let foo = "https://example.com/foo.git";
        let bar = "https://example.com/bar.git";
        let _ = make_mocked_fetches(tmp.path(), foo, "main", &"a".repeat(40), &[("foo.nim", b"# foo")]);
        let mocked = make_mocked_fetches(tmp.path(), bar, "main", &"b".repeat(40), &[("bar.nim", b"# bar")]);

        let manifest = format!(
            "name \"app\"\nkind \"application\"\ndeps {{\n  foo git=\"{foo}\" ref=\"main\"\n  bar git=\"{bar}\" ref=\"main\"\n}}\n"
        );
        std::fs::write(proj.join("milpa.kdl"), &manifest).unwrap();

        // First, fetch to produce a baseline lockfile with both pins.
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        assert_eq!(cmd_fetch(&proj, Strategy::default(), false, true, None, false).unwrap(), 0);
        let baseline = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();
        assert!(baseline.contains("\"foo\"") && baseline.contains("\"bar\""));

        // Scoped update of foo: succeeds, writes the lockfile, leaves kdl intact.
        let r = cmd_update(&proj, Strategy::default(), &["foo".into()]);
        let after_kdl = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        let after_lock = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(r.unwrap(), 0, "scoped update should succeed");
        assert_eq!(after_kdl, manifest, "update MUST NOT mutate milpa.kdl");
        // Both deps still present (bar retained via prior, foo re-resolved).
        assert!(after_lock.contains("\"foo\"") && after_lock.contains("\"bar\""));
    }

    /// Scoped `update <dep>` rejects a dep not in the lockfile (LOCK-DEP-NOT-FOUND,
    /// exit 1) and rejects when no lockfile exists (LOCK-FILE-NOT-FOUND).
    #[test]
    fn update_scoped_rejects_dep_not_in_lock() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        )
        .unwrap();

        // No lockfile yet → scoped update fails with LOCK-FILE-NOT-FOUND.
        let no_lock = cmd_update(&proj, Strategy::default(), &["ghost".into()]);
        assert!(no_lock.is_err());
        assert_eq!(no_lock.unwrap_err().code(), "LOCK-FILE-NOT-FOUND");

        // Write an empty lockfile; scoped update of an absent dep → exit 1.
        std::fs::write(
            proj.join("milpa.lock"),
            "// generated by milpa; reproducible build snapshot\nversion 1\nstrategy \"maxver\"\n",
        )
        .unwrap();
        let r = cmd_update(&proj, Strategy::default(), &["ghost".into()]);
        assert_eq!(r.unwrap(), 1, "dep-not-in-lock → exit 1");
    }

    /// `add --git` now conforms to cli-contract §5.6: it runs a full resolve and
    /// writes BOTH milpa.kdl and milpa.lock. Exercised offline via the mocked
    /// transport. Covers explicit --ref, mocked default-branch discovery (no
    /// --ref), and the MAN-ADD-DEP-EXISTS duplicate guard.
    #[test]
    fn add_git_resolves_and_writes_lockfile_via_mock() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let sha = "b".repeat(40);
        let url = "https://example.com/foo.git";
        let mocked = make_mocked_fetches(tmp.path(), url, "main", &sha, &[("foo.nim", b"# foo")]);
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        )
        .unwrap();

        // SAFETY: serialized by ENV_MUTEX.
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };

        // (1) add with explicit --ref → resolve + write both files.
        let r = cmd_add(
            &proj,
            &["foo".into(), "--git".into(), url.into(), "--ref".into(), "main".into()],
        );
        let after_add = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        let lock = std::fs::read_to_string(proj.join("milpa.lock")).unwrap_or_default();

        // (2) duplicate guard.
        let dup = cmd_add(
            &proj,
            &["foo".into(), "--git".into(), url.into(), "--ref".into(), "main".into()],
        );

        // (3) add a second dep with NO --ref → mocked default-branch discovery.
        let url2 = "https://example.com/bar.git";
        let _ = make_mocked_fetches(tmp.path(), url2, "trunk", &"c".repeat(40), &[("bar.nim", b"# bar")]);
        let r2 = cmd_add(&proj, &["bar".into(), "--git".into(), url2.into()]);
        let after_add2 = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();

        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(r.unwrap(), 0, "add --git --ref should succeed");
        assert!(after_add.contains("\"foo\""), "manifest should contain foo");
        assert!(lock.contains("\"foo\""), "lockfile should contain foo");

        assert!(dup.is_err());
        assert_eq!(dup.unwrap_err().code(), "MAN-ADD-DEP-EXISTS");

        assert_eq!(r2.unwrap(), 0, "add --git (no --ref) should resolve via mock");
        // Discovered ref "trunk" must land in the manifest.
        assert!(after_add2.contains("\"bar\""), "manifest should contain bar");
        assert!(after_add2.contains("trunk"), "discovered ref should be trunk");
    }

    #[test]
    fn parse_failure_returns_exit_2() {
        // An invalid strategy value makes parse_args return None → exit 2.
        let args: Vec<String> = vec!["-s".into(), "bogus".into(), "fetch".into()];
        assert_eq!(run(&args).unwrap(), 2);
    }

    #[test]
    fn unknown_verb_returns_exit_2() {
        assert_eq!(run(&["notaverb".to_string()]).unwrap(), 2);
    }

    #[test]
    fn usage_subcmds_return_exit_2() {
        // remove with no name → exit 2.
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(cmd_remove(tmp.path(), &[]).unwrap(), 2);
        // add with no name → exit 2.
        assert_eq!(cmd_add(tmp.path(), &[]).unwrap(), 2);
        // add with no --git/--mirror → exit 2.
        assert_eq!(cmd_add(tmp.path(), &["foo".into()]).unwrap(), 2);
    }

    // --- MILPA_MOCKED_FETCHES integration -----------------------------------
    //
    // These tests verify that `cmd_fetch` selects `MockedFetcher` when the env
    // var is set. Because `std::env::set_var` is shared state, the two env-var
    // tests are serialized with a static Mutex; all other tests never touch
    // `MILPA_MOCKED_FETCHES` and run freely in parallel.

    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Build a minimal `mocked-fetches/<url_key>/` fixture tree and return its
    /// root dir (inside `base`).
    fn make_mocked_fetches(
        base: &std::path::Path,
        url: &str,
        ref_spec: &str,
        sha: &str,
        src_files: &[(&str, &[u8])],
    ) -> std::path::PathBuf {
        let mocked = base.join("mocked-fetches");
        let key_dir = mocked.join(milpa_core::url_key(url, ref_spec));
        std::fs::create_dir_all(key_dir.join("content")).unwrap();
        std::fs::write(key_dir.join("sha"), format!("{sha}\n")).unwrap();
        for (name, data) in src_files {
            std::fs::write(key_dir.join("content").join(name), data).unwrap();
        }
        mocked
    }

    #[test]
    fn mocked_fetches_env_resolves_offline_and_writes_lockfile() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let sha = "a".repeat(40);
        let mocked = make_mocked_fetches(
            tmp.path(),
            "https://example.com/foo.git",
            "main",
            &sha,
            &[("foo.nim", b"# foo")],
        );
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\ndeps {\n  foo git=\"https://example.com/foo.git\" ref=\"main\"\n}\n",
        )
        .unwrap();

        // SAFETY: serialized by ENV_MUTEX; unique env var name; cleaned up after.
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let result = cmd_fetch(&proj, Strategy::default(), false, true, None, false);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert!(result.is_ok(), "expected Ok, got {result:?}");
        assert_eq!(result.unwrap(), 0);
        let lock = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();
        assert!(lock.contains("\"foo\""), "lockfile should contain dep name");

        // BLOCKER-R1 fix (#118): _deps/<name> must be a CAS symlink, not a
        // real directory. The CasAdmittingFetcher wrapper is what produces
        // this — verify the symlink is present.
        let foo_meta = std::fs::symlink_metadata(proj.join("_deps").join("foo")).unwrap();
        assert!(
            foo_meta.file_type().is_symlink(),
            "_deps/foo must be a CAS symlink after mocked fetch (BLOCKER-R1)"
        );
    }

    #[test]
    fn mocked_fetches_missing_key_errors_with_fetch_all_failed() {
        // The resolver wraps a per-candidate FETCH-MOCK-MISSING in FETCH-ALL-FAILED
        // (mirror-fallback §8a): all 1 candidate(s) failed. The CLI sees
        // FETCH-ALL-FAILED; the inner cause text carries the slug for human
        // diagnostics. This is the correct, spec-conformant behaviour.
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        // An empty mocked-fetches dir — no key for the dep below.
        let mocked = tmp.path().join("mocked-fetches");
        std::fs::create_dir_all(&mocked).unwrap();

        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\ndeps {\n  foo git=\"https://example.com/foo.git\" ref=\"main\"\n}\n",
        )
        .unwrap();

        // SAFETY: serialized by ENV_MUTEX.
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let result = cmd_fetch(&proj, Strategy::default(), false, true, None, false);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert!(result.is_err(), "expected Err, got {result:?}");
        // Resolver wraps per-candidate failures into FETCH-ALL-FAILED (§8a).
        assert_eq!(result.unwrap_err().code(), "FETCH-ALL-FAILED");
    }

    // --- maybe_index propagation (BLOCKER-R2) ---------------------------------
    //
    // These tests verify that maybe_index() propagates TNG-* parse errors instead
    // of swallowing them via .ok(). They set MILPA_INDEX_URL and MILPA_CACHE_DIR
    // so are serialized behind ENV_MUTEX like the other env-var tests above.

    #[test]
    fn maybe_index_propagates_tng_error_for_malformed_index() {
        // BLOCKER-R2 fix (#118): a fetched index that fails Index::parse with a
        // TNG-* error (e.g. schema_version too high → TNG-SCHEMA-UNKNOWN) must
        // surface as Err(TNG-*), NOT be swallowed into Ok(None).
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();

        // Write an index.kdl with schema_version 99 — raises TNG-SCHEMA-UNKNOWN.
        let index_path = tmp.path().join("index.kdl");
        std::fs::write(
            &index_path,
            "schema_version 99\npackage \"foo\" {\n  version \"1.0.0\" {\n    content_hash \"sha256:0000000000000000000000000000000000000000000000000000000000000001\"\n    provenance {\n      kind \"git\"\n      url \"https://github.com/example/foo.git\"\n      ref \"v1.0.0\"\n    }\n  }\n}\n",
        )
        .unwrap();

        // Point MILPA_INDEX_URL at the file; isolate the index cache via
        // XDG_CACHE_HOME (index_cache_dir uses XDG_CACHE_HOME/milpa/index).
        let url = format!("file://{}", index_path.display());
        unsafe { std::env::set_var("MILPA_INDEX_URL", &url) };
        unsafe { std::env::set_var("XDG_CACHE_HOME", tmp.path()) };

        let result = maybe_index();

        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };

        // Must propagate TNG-SCHEMA-UNKNOWN, not return Ok(None).
        assert!(
            result.is_err(),
            "expected Err(TNG-SCHEMA-UNKNOWN), got Ok({result:?})"
        );
        assert_eq!(
            result.unwrap_err().code(),
            "TNG-SCHEMA-UNKNOWN",
            "wrong error code: expected TNG-SCHEMA-UNKNOWN"
        );
    }

    #[test]
    fn maybe_index_returns_none_when_index_unreachable() {
        // When the index URL is unreachable (no cache, curl fails), maybe_index()
        // returns Ok(None) — the resolver decides whether RES-NO-INDEX applies.
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();

        // A file:// URL that doesn't exist → curl will fail; no cache exists.
        unsafe {
            std::env::set_var(
                "MILPA_INDEX_URL",
                "file:///nonexistent-milpa-test-index-12345.kdl",
            )
        };
        unsafe { std::env::set_var("XDG_CACHE_HOME", tmp.path()) };

        let result = maybe_index();

        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };

        // Unreachable → Ok(None), not an error.
        assert_eq!(
            result,
            Ok(None),
            "expected Ok(None) for unreachable index, got {result:?}"
        );
    }
}
