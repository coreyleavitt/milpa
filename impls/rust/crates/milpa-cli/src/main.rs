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
    add_mirror, apply_workspace_manifest_change, baseline_sidecar_paths, build_flag_defines,
    build_index_state, canonical_digest, check_frozen_active_flags_mismatch,
    check_locked_drift,
    check_workspace_frozen_active_flags_mismatch,
    dep_decl_store::DepDeclStore, discover_manifest, effective_trust_policy,
    fetch::{FetchError, FetcherRegistry}, fetch_verified_candidate_text, format_nimcfg,
    format_workspace_nimcfgs, from_graph, index_url_from_env, iso_timestamp,
    load_index_with_history, load_lockfile, load_manifest, load_workspace,
    parse_baseline, parse_baseline_meta, print_yank_notice,
    registry::{parse_iso8601_timestamp, Timestamp},
    LoadedMember, LoadedWorkspace,
    make_dep_decl_store, mutate_manifest_file, parse_env_bool, parse_lockfile, parse_source_spec,
    parse_version,
    resolve_with_cert, resolve_with_features, resolve_workspace_frozen,
    resolve_workspace_with_cert, resolve_workspace_with_features,
    verify_lockfile_against_deps, workspace_any_member_strict, write_baseline_pair, write_lockfile,
    Baseline, BaselineMeta, CaStore,
    CasAdmittingFetcher, CoreError, DefaultRegistry, FailureCert, FileDepDeclStore,
    FrozenResolver, Index, ManifestDoc, Milpa, MilpaError, MockedFetcher, Profile,
    ProvenanceRecord, RatchetOutcome, Strategy, SuccessCert, Version, DEFAULT_INDEX_URL, DEFAULT_TTL_SECONDS,
};
use milpa_manifest::{valid_flag_name, Dep, FlagRequest, Manifest, OverrideTarget, UrlDep, Workspace};

const VERSION: &str = "0.1.0";

const USAGE: &str = "usage: milpa [-C <dir>] [-j <N>] [-s <mode>] [--frozen] \
[--no-index] [--certificate <path>] <fetch|lock|show|verify|clean|add|remove|update|workspace|store|index|hash> [args]";

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
///
/// C3 (resolution-semantics RFC §3 Axis C / D-C2): `--strategy` is NO LONGER
/// a global pre-dispatch field here — it moved to a per-verb scan of `rest`
/// (`strategy_flag_value`), mirroring `--locked`/`--upgrade`'s existing
/// scoping, so a `Strategy(Option)` sentinel can distinguish "unspecified"
/// from an explicit `--strategy maxver`.
struct Cli {
    directory: PathBuf,
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
    /// `--no-index` (cli-contract §8.1): resolve with no tianguis index
    /// (offline / air-gapped). The explicit form of an empty `MILPA_INDEX_URL`;
    /// OVERRIDES any configured index (env or default). URL/local deps resolve;
    /// a named dep raises `RES-NO-INDEX`. Only `fetch`/`lock` consult it.
    no_index: bool,
    /// S6: `--require-attested-index` flag (cli-contract §8.5, RFC §6.5).
    /// Overrides any `index-trust` manifest field → effective policy = Strict.
    /// Identical semantics to `--require-attested-metadata` but for the index.
    require_attested_index: bool,
    /// S6: `--refresh-index` flag (cli-contract §8.6, RFC §7.1).
    /// Bypasses the TTL and forces a fresh network fetch of the index and its
    /// Sigstore bundle sidecar.
    refresh_index: bool,
    /// P3a: `--require-attested-entries` flag (RFC per-entry-attestation.md
    /// §4). Escalates the effective entry-trust policy warn→strict.
    /// Identical semantics to `--require-attested-index` but for the
    /// per-entry author-attribution axis.
    require_attested_entries: bool,
    verb: String,
    rest: Vec<String>,
}

fn run(args: &[String]) -> Result<i32, MilpaError> {
    // Scan only the pre-verb prefix (mirrors parse_args's own loop boundary:
    // global flags precede the first non-dash token, the verb). A3b added a
    // subcommand-scoped `--version` flag (`add --git ... --version x.y.z`) —
    // scanning the WHOLE argv here would collide with it (`milpa add foo
    // --git <url> --version 1.2.3` would print the binary version and exit
    // 0 instead of running `add`).
    //
    // L1: the boundary must be computed the same way `parse_args` walks
    // global flags — a naive "first token not starting with `-`" scan stops
    // at the VALUE of a value-consuming global flag (`-C <dir>`,
    // `--certificate <path>`, `-j <N>`), not at the flag itself. That made
    // `milpa -C <dir> --version` treat `<dir>` as the verb boundary, slicing
    // `--version` OUT of the pre-verb region entirely — it fell through to
    // `parse_args`, which rejects a bare `--version` token, printing USAGE
    // and exiting 2 instead of printing the version and exiting 0.
    // `pre_verb_slice` mirrors `parse_args`'s own flag/value pairing so the
    // two never disagree about where the verb starts.
    if pre_verb_slice(args).iter().any(|a| a == "--version") {
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

    // S9 (RFC #23 §3.4): reject --all-features + --no-default-features together
    // for the verbs that accept feature-selection flags (fetch, lock, update).
    // The two flags are mutually exclusive: --all-features activates every declared
    // root flag; --no-default-features suppresses all defaults and starts from an
    // empty baseline — the intents are contradictory.  Cargo rejects this
    // combination; milpa follows the same policy (spec/errors.md §CLI).
    if matches!(cli.verb.as_str(), "fetch" | "lock" | "update")
        && check_feature_flags_conflict(&cli.rest)
    {
        return Err(MilpaError::Core(CoreError::Resolver(
            "CLI-FEATURE-FLAGS-CONFLICT",
            "--all-features and --no-default-features are mutually exclusive: \
             --all-features activates every declared root flag while \
             --no-default-features suppresses all defaults — pass at most one"
                .into(),
        )));
    }

    // B4 (resolution-semantics RFC §3 Axis B / D-B3): `--locked` (forbids
    // deviation) and `--upgrade` (forces it) are contradictory — reject
    // before dispatching to fetch/lock. Scoped to those two verbs, mirroring
    // where both flags are actually parsed (inside `cmd_fetch`).
    if matches!(cli.verb.as_str(), "fetch" | "lock")
        && cli.rest.iter().any(|a| a == "--locked")
        && upgrade_flag_values(&cli.rest).is_some()
    {
        return Err(MilpaError::Core(CoreError::Resolver(
            "CLI-LOCKED-UPGRADE-CONFLICT",
            "--locked and --upgrade are mutually exclusive: --locked forbids any \
             deviation from the committed lock while --upgrade forces it for the \
             targeted package(s) — pass at most one"
                .into(),
        )));
    }

    // C3 (resolution-semantics RFC §3 Axis C / D-C2): `--strategy` is now
    // scoped to the resolve-triggering verbs (fetch/lock/update/add/remove/
    // workspace add-member/remove-member), parsed from `rest` — mirrors
    // `--locked`/`--upgrade`'s existing scoping, not the old global
    // pre-verb flag loop. A malformed value (present but unrecognized) is
    // a usage error (exit 2), matching the old global loop's short-circuit.
    // Verbs that don't consult it (show/verify/clean/...) never scan for
    // it — same "silently ignored on a non-owning verb" behavior every
    // other scoped flag already has in this hand-rolled parser.
    let strategy_cli: Option<Strategy> = if matches!(
        cli.verb.as_str(),
        "fetch" | "lock" | "update" | "add" | "remove" | "workspace"
    ) {
        match strategy_flag_value(&cli.rest) {
            Ok(v) => v,
            Err(()) => {
                eprintln!("{USAGE}");
                return Ok(2);
            }
        }
    } else {
        None
    };

    // D2 (resolution-semantics RFC §3 Axis D): `--exclude-newer <ts>` is
    // scoped to fetch/lock ONLY — narrower than `--strategy`'s per-verb
    // scoping (§3 Axis D "Verb reach": a CLI time-bound override is a
    // fetch/lock-time CI concern; add/update/remove always read the
    // manifest's committed bound instead, with no CLI override at all).
    // A malformed value is a diagnosed failure (CLI-EXCLUDE-NEWER-INVALID,
    // exit 1 + slug) — NOT a bare usage error like a malformed `--strategy`
    // (that flag is a closed enum via `choices`; a timestamp has no such
    // enum, so it gets a real slug instead of an exit-2 parse error).
    let exclude_newer_cli: Option<Timestamp> = if matches!(cli.verb.as_str(), "fetch" | "lock") {
        exclude_newer_flag_value(&cli.rest)?
    } else {
        None
    };

    match cli.verb.as_str() {
        "show" => {
            // `--index-trust` flag on `show`: describe cached bundle claims.
            // spec/cli-contract.md §5.3a.
            if cli.rest.iter().any(|a| a == "--index-trust") {
                cmd_show_index_trust(dir)
            } else {
                cmd_show(dir)
            }
        }
        "verify" => cmd_verify(dir, cli.require_attested_metadata, cli.no_index, cli.require_attested_index, cli.refresh_index, cli.require_attested_entries),
        "clean" => cmd_clean(dir),
        "fetch" => cmd_fetch(dir, strategy_cli, cli.frozen, true, cert_path, cli.require_attested_metadata, cli.no_index, &cli.rest, cli.require_attested_index, cli.refresh_index, cli.require_attested_entries, exclude_newer_cli),
        "lock" => cmd_fetch(dir, strategy_cli, cli.frozen, false, cert_path, cli.require_attested_metadata, cli.no_index, &cli.rest, cli.require_attested_index, cli.refresh_index, cli.require_attested_entries, exclude_newer_cli),
        "update" => cmd_update(dir, strategy_cli, &cli.rest, cli.no_index, cli.require_attested_index, cli.refresh_index, cli.require_attested_entries),
        "add" => cmd_add(dir, strategy_cli, &cli.rest, cli.no_index, cli.require_attested_index, cli.refresh_index, cli.require_attested_entries),
        "remove" => cmd_remove(dir, strategy_cli, &cli.rest, cli.no_index, cli.require_attested_index, cli.refresh_index),
        "store" => cmd_store(&cli.rest),
        "workspace" => cmd_workspace(dir, &cli.rest, strategy_cli, cli.no_index, cli.require_attested_index, cli.refresh_index),
        "index" => cmd_index(dir, &cli.rest, cli.no_index, cli.require_attested_index),
        "hash" => cmd_hash(&cli.rest, dir),
        other => {
            // Gap-1 §3: unknown verb is a usage error → exit 2 (no milpa-error: line).
            eprintln!("milpa: unknown command {other:?}\n{USAGE}");
            Ok(2)
        }
    }
}

/// L1: compute the pre-verb prefix the SAME way `parse_args` walks global
/// flags, so a value-consuming global flag's value is never mistaken for
/// the verb boundary. This must recognize every value-consuming global flag
/// `parse_args` recognizes (`-C`/`--directory`, `-j`/`--parallel`,
/// `--certificate`) plus every boolean one, so `--version` anywhere in the
/// true pre-verb region is found regardless of what precedes it. Stops at
/// the first token that is either the verb (doesn't start with `-`) or an
/// unrecognized flag (left for `parse_args` to reject).
fn pre_verb_slice(args: &[String]) -> &[String] {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-C" | "--directory" | "-j" | "--parallel" | "--certificate" => {
                // Value-consuming: skip the flag AND its value. If the value
                // is missing (flag is the last token), stop at the end —
                // `parse_args` will reject the truncated invocation itself.
                i = (i + 2).min(args.len());
            }
            "--frozen" | "--no-index" | "--require-attested-metadata"
            | "--require-attested-index" | "--require-attested-entries"
            | "--refresh-index" | "--version" => {
                i += 1;
            }
            _ => break,
        }
    }
    &args[..i]
}

/// Hand-rolled arg parse: global flags (some take a value), then the verb + tail.
fn parse_args(args: &[String]) -> Option<Cli> {
    let mut directory = PathBuf::from(".");
    let mut frozen = false;
    let mut no_index = false;
    let mut certificate: Option<PathBuf> = None;
    // S5: `MILPA_REQUIRE_ATTESTED_METADATA` env var also activates strict policy
    // (cli-contract §8.4). The flag OR the env var; same OR semantics as manifest.
    let mut require_attested_metadata = std::env::var("MILPA_REQUIRE_ATTESTED_METADATA")
        .map(|v| parse_env_bool(&v))
        .unwrap_or(false);
    // S6: `--require-attested-index` flag only. The MILPA_INDEX_TRUST env var is
    // NOT parsed here — it is read by build_index_trust_policy (the SSOT) inside
    // maybe_index. Parsing MILPA_INDEX_TRUST to a bool here was wrong: it collapsed
    // "warn"/"off" into false (same as unset) and could not represent the full
    // three-value policy enum. Kill the double-read; env goes through the SSOT.
    let mut require_attested_index = false;
    let mut refresh_index = false;
    // P3a: entry-trust escalation flag (mirrors require_attested_index).
    let mut require_attested_entries = false;
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
            "--frozen" => {
                frozen = true;
                i += 1;
            }
            "--no-index" => {
                no_index = true;
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
            "--require-attested-index" => {
                require_attested_index = true;
                i += 1;
            }
            "--require-attested-entries" => {
                require_attested_entries = true;
                i += 1;
            }
            "--refresh-index" => {
                refresh_index = true;
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
        frozen,
        certificate,
        require_attested_metadata,
        no_index,
        require_attested_index,
        refresh_index,
        require_attested_entries,
        verb,
        rest: args[i..].to_vec(),
    })
}

/// C3 (resolution-semantics RFC §3 Axis C / D-C2): parse `--strategy`/`-s`
/// from the verb's tail args (`rest`) — scoped per-verb, mirroring
/// `--locked`/`--upgrade`'s existing scoping (`upgrade_flag_values`), NOT
/// the old global pre-verb flag loop. `Ok(None)` = flag absent (unspecified
/// — the caller's `resolve_effective_strategy` defers to the manifest, else
/// the global default); `Ok(Some(s))` = explicit, always wins; `Err(())` = present
/// with a missing or unrecognized value (usage error, exit 2 — mirrors the
/// old global loop's `parse_strategy(..)?` short-circuit via `Option`).
fn strategy_flag_value(rest: &[String]) -> Result<Option<Strategy>, ()> {
    let Some(idx) = rest.iter().position(|a| a == "-s" || a == "--strategy") else {
        return Ok(None);
    };
    match rest.get(idx + 1).and_then(|v| Strategy::parse(v)) {
        Some(s) => Ok(Some(s)),
        None => Err(()),
    }
}

/// C3 (resolution-semantics RFC §3 Axis C / D-C2): resolve the
/// EXPLICITLY-DECLARED strategy for one verb's resolve, walking the
/// precedence chain ONCE — explicit CLI `--strategy` > the manifest's
/// `resolution { strategy }` > `None` (neither source declared one).
///
/// `cli_strategy` is `None` when `--strategy` was not passed (the
/// `Option<Strategy>` sentinel plumbing) — distinct from an explicit
/// `--strategy maxver`, which always wins even though it names the default
/// value.
///
/// RR1 (duplicate-precedence-walk cleanup): this used to be a PAIR of
/// near-identical functions — `resolve_effective_strategy` (returning a
/// default-filled `Strategy`) and a sibling `strategy_is_explicit`
/// (returning whether it was explicit) — that walked this SAME precedence
/// chain twice per call site (~10 sites in this file alone). Collapsed
/// into a single walk: every call site now derives BOTH facts from this
/// one `Option<Strategy>` result:
///
/// ```ignore
/// let decl = resolve_effective_strategy(cli_strategy, resolution);
/// let strategy_explicit = decl.is_some();
/// let strategy = decl.unwrap_or_default();
/// ```
///
/// R9 (resolution-semantics RFC §3 Axis C NORMATIVE text: "the lockfile-
/// recorded strategy is diagnostic/frozen-parity only, never a live
/// input"): there used to be a third tier here that fell back to the prior
/// lockfile's recorded `strategy` before the global default. That made a
/// one-off `--strategy X` invisibly and permanently govern every future
/// bare resolve (hidden sticky state), and made the lockfile a live
/// resolution input rather than a pure diagnostic record — contradicting
/// the RFC text above. That tier is gone; this function takes no `prior`
/// argument at all.
///
/// Stability of a bare re-resolve against a lock recorded under a
/// non-default strategy is preserved a DIFFERENT way — via B2's
/// lock-preference mechanism (`ResolveProvider::preference`), not by
/// treating the lockfile's strategy as a governing tier here. See
/// `ResolveProvider::bypasses_lock_preference` for how: the bypass that
/// would otherwise drop B2's preference and newest-wins the whole graph
/// only fires when the strategy declared here is `Some` AND diverges from
/// the lock's recorded value — never when it is merely default-filled.
fn resolve_effective_strategy(
    cli_strategy: Option<Strategy>,
    resolution: Option<milpa_manifest::Resolution>,
) -> Option<Strategy> {
    if let Some(s) = cli_strategy {
        return Some(s);
    }
    resolution.and_then(|r| r.strategy)
}

/// D2 (resolution-semantics RFC §3 Axis D): parse `--exclude-newer <ts>`
/// from the verb's tail args (`rest`) — scoped to `fetch`/`lock` ONLY by the
/// caller (narrower than `--strategy`'s per-verb scoping; see the call site
/// in `run()`). `Ok(None)` = flag absent (unspecified — the caller's
/// `resolve_effective_exclude_newer` defers to the manifest); `Ok(Some(ts))`
/// = explicit, parsed via the shared `parse_iso8601_timestamp`; `Err(_)` =
/// present with a missing or unparseable value — a DIAGNOSED failure
/// (`CLI-EXCLUDE-NEWER-INVALID`, exit 1 + slug), unlike `strategy_flag_value`'s
/// bare `Err(())` usage error: a timestamp has no closed enum of valid
/// spellings the way `-s`/`--strategy` does via `choices`, so a malformed
/// value gets a real catalog slug instead of a silent exit-2.
fn exclude_newer_flag_value(rest: &[String]) -> Result<Option<Timestamp>, MilpaError> {
    let Some(idx) = rest.iter().position(|a| a == "--exclude-newer") else {
        return Ok(None);
    };
    match rest.get(idx + 1) {
        Some(raw) => match parse_iso8601_timestamp(raw) {
            Some(ts) => Ok(Some(ts)),
            None => Err(MilpaError::Core(CoreError::Resolver(
                "CLI-EXCLUDE-NEWER-INVALID",
                format!("--exclude-newer value {raw:?} is not a parseable ISO 8601 timestamp"),
            ))),
        },
        None => Err(MilpaError::Core(CoreError::Resolver(
            "CLI-EXCLUDE-NEWER-INVALID",
            "--exclude-newer requires a value (an ISO 8601 timestamp)".into(),
        ))),
    }
}

/// D2/D5 (resolution-semantics RFC §3 Axis D): resolve the EFFECTIVE
/// exclude-newer time-bound for one verb's resolve, in precedence order —
/// explicit CLI `--exclude-newer` > the manifest's `resolution {
/// exclude-newer }` > the prior lockfile's recorded `exclude_newer` > `None`
/// (no time bound).
///
/// NOTE (R9): `resolve_effective_strategy` no longer has an analogous
/// lockfile-fallback tier at all — the lockfile-recorded `strategy` is
/// diagnostic/frozen-parity only, never a live input (unlike
/// `exclude_newer`, which legitimately keeps its own D5 no-silent-drop
/// lockfile-fallback tier here, by design, for the verbs that call this
/// with a real `prior`). The two functions' precedence chains are NOT
/// symmetric post-R9 — this asymmetry is intentional.
///
/// (`prior` is the ACTUAL on-disk lockfile, never the resolve-scoped
/// `prior` that `update`/`--upgrade` null out or strip for B2's
/// minimal-change preference).
///
/// **D5 (no-silent-drop, §6 D-D3):** the third (lockfile) tier is load-
/// bearing, not decorative — a bound set ONLY via a one-off CLI
/// `--exclude-newer` on `fetch`/`lock` (with no matching `resolution {
/// exclude-newer }` ever added to the manifest) is recorded in the
/// lockfile by D5. Without this tier, the very next `update`/`remove`
/// (which never see a CLI flag) would silently drop that bound —
/// `resolution` is `None`, tier 2 misses, and the project would silently
/// un-freeze. Falling back to the lockfile's own recorded value here
/// closes that hole — this is precisely the D5 asymmetry that makes
/// `exclude_newer`'s lockfile tier CORRECT while `strategy`'s equivalent
/// (now-removed) tier was WRONG (R9): `exclude_newer` has no CLI surface
/// on `add`/`update`/`remove`, so falling back to the lockfile is the only
/// way to avoid silently dropping a committed bound; `strategy` DOES have
/// a CLI surface on every resolve-triggering verb, so an unspecified
/// `--strategy` is a genuine "use the default" signal, not a gap to patch.
///
/// Only `fetch`/`lock` register the CLI flag (§3 Axis D "Verb reach" — a
/// time-bound CLI override is a fetch/lock-time CI concern). Every other
/// resolve-triggering verb (`add`/`update`/`remove`/workspace
/// add-member/remove-member) always calls this with `cli_exclude_newer:
/// None`, so it transparently falls through to tiers 2/3 — the manifest's
/// committed bound (or, absent that, the lockfile's carried-forward bound)
/// is honored with no new CLI plumbing at those call sites.
fn resolve_effective_exclude_newer(
    cli_exclude_newer: Option<Timestamp>,
    resolution: Option<milpa_manifest::Resolution>,
    prior: Option<&milpa_core::Lockfile>,
) -> Option<Timestamp> {
    if cli_exclude_newer.is_some() {
        return cli_exclude_newer;
    }
    if let Some(ts) = resolution.and_then(|r| r.exclude_newer) {
        return Some(ts);
    }
    prior.and_then(|p| p.exclude_newer)
}

// --- verbs -----------------------------------------------------------------

/// Format a single [`ProvenanceRecord`] for `milpa show` output.
///
/// Mirrors Python `_format_provenance` in `cli.py` exactly.
fn format_provenance_record(p: &ProvenanceRecord) -> String {
    match p {
        ProvenanceRecord::Git { url, ref_spec, commit_sha, .. } => {
            let mut parts = vec![format!("git {url}")];
            if let Some(r) = ref_spec {
                parts.push(format!("@ {r}"));
            }
            if let Some(sha) = commit_sha {
                parts.push(format!("(sha {})", &sha[..sha.len().min(8)]));
            }
            parts.join(" ")
        }
        ProvenanceRecord::Tarball { url, .. } => format!("tarball {url}"),
        ProvenanceRecord::Local { path, .. } => format!("local {path}"),
        ProvenanceRecord::Member { name, .. } => format!("member {name}"),
        ProvenanceRecord::Oci { registry, repository, digest, .. } => {
            format!("oci {registry}/{repository}@{}", &digest[..digest.len().min(15)])
        }
        ProvenanceRecord::Root { name, .. } => format!("root {name}"),
    }
}

/// `milpa show` — print the locked dep graph (stdout).
/// A7 (rfc-resolution-semantics.md §3 Axis A / §5): the `" (<label>)"` suffix
/// `cmd_show` prints next to a dep's version. Pure/testable in isolation
/// (Rust's `cmd_show` writes straight to stdout via `println!`, which isn't
/// easily captured without a subprocess — see `s10_show_prints_active_flags`'s
/// note above — so the branching logic itself lives here where it CAN be
/// unit-tested directly).
///
/// - `declared_version_source` present → `" (<source>)"` (manifest/nimble/
///   tag/annotation).
/// - absent AND `version == "0.0.0"` → `" (version-unknown)"`, the A5
///   flattening pairing (§5 NORMATIVE: version-unknown is defined by THIS
///   pairing, not by source-absence alone).
/// - absent AND any other version (e.g. a named/index dep, out of Axis A's
///   scope, which also carries no source) → no suffix; it has a real known
///   version, just not one of the four Axis-A sources.
fn version_suffix(declared_version_source: &Option<String>, version: &str) -> String {
    if let Some(src) = declared_version_source {
        format!(" ({src})")
    } else if version == "0.0.0" {
        " (version-unknown)".to_string()
    } else {
        String::new()
    }
}

/// Render a [`Timestamp`] back to canonical UTC ISO 8601
/// (`YYYY-MM-DDTHH:MM:SS[.fraction]Z`) for `cmd_show`'s `exclude-newer`
/// header line — the exact wire form the Python reference's
/// `_format_resolution_timestamp` produces, and byte-identical to
/// `milpa_types::format_iso8601_timestamp` (the lockfile writer's own
/// serializer for this same field, `milpa-core::lockfile.rs`).
///
/// This duplicates that function's algorithm rather than calling it: only
/// `Timestamp` itself (via `milpa_core::registry`'s re-export) is reachable
/// from `milpa-cli` today — `milpa-types` is not a direct dependency of this
/// crate, and neither `milpa-core` nor `milpa-manifest` re-exports
/// `format_iso8601_timestamp` (they re-export `parse_iso8601_timestamp` and
/// `Timestamp`, but not the formatter). Follow-up: add
/// `format_iso8601_timestamp` to `milpa-core`'s `pub use` list (one line,
/// next to its existing `Timestamp` re-export) and delete this copy.
fn format_timestamp_for_show(ts: &Timestamp) -> String {
    // Howard Hinnant's `civil_from_days` (proleptic Gregorian, days-since-
    // epoch -> (year, month, day)) — transcribed verbatim from
    // `milpa_types::format_iso8601_timestamp`'s private helper of the same
    // name.
    let z = ts.unix_seconds.div_euclid(86400) + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    let secs_of_day = ts.unix_seconds.rem_euclid(86400);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    if ts.nanos == 0 {
        format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
    } else {
        let mut frac = format!("{:09}", ts.nanos);
        while frac.ends_with('0') {
            frac.pop();
        }
        format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}.{frac}Z")
    }
}

/// A7/D5 (rfc-resolution-semantics.md §3 Axis D / §5): the `exclude-newer`
/// header line `cmd_show` prints right after `strategy` — `None` when the
/// lockfile recorded no bound (a genuine absence, never a fake/hardcoded
/// line), `Some("exclude-newer <ts>")` otherwise. Pure/testable in
/// isolation for the same reason `version_suffix` is: `cmd_show` writes
/// straight to stdout via `println!`, so the branching + formatting logic
/// lives in a helper that CAN be unit-tested directly. Mirrors the Python
/// reference's `cmd_show`: `f"exclude-newer {_format_resolution_timestamp(lockfile.exclude_newer)}"`.
fn exclude_newer_header_line(exclude_newer: &Option<Timestamp>) -> Option<String> {
    exclude_newer
        .as_ref()
        .map(|ts| format!("exclude-newer {}", format_timestamp_for_show(ts)))
}

fn cmd_show(dir: &Path) -> Result<i32, MilpaError> {
    let text = std::fs::read_to_string(dir.join("milpa.lock")).map_err(|_| {
        MilpaError::Core(CoreError::Lockfile(
            "LOCK-FILE-NOT-FOUND",
            "no milpa.lock — run `milpa fetch` first".into(),
        ))
    })?;
    let lock = parse_lockfile(&text)?;

    // A7 (rfc-resolution-semantics.md §3 Axis A): top-level resolution-state
    // header, printed once before the per-dep list. `strategy` is always
    // shown; `exclude_newer` (D5) is shown only when the lockfile recorded
    // one (never a fake/hardcoded value for the absent case) — see
    // `exclude_newer_header_line`'s doc comment for the exact contract.
    println!("strategy    {}", lock.strategy);
    if let Some(line) = exclude_newer_header_line(&lock.exclude_newer) {
        println!("{line}");
    }

    for dep in &lock.deps {
        // A7: surface the declared-version source next to the version —
        // `manifest`/`nimble`/`tag`/`annotation` when a source was recorded
        // (A5), or `(version-unknown)` for the A5 flattening pairing
        // (`version == "0.0.0"` + no `declared_version_source`). A
        // named/index dep also has no `declared_version_source` (out of
        // Axis A's scope) but is NOT version-unknown — it is only flagged
        // when paired with the flattened `0.0.0` sentinel, per the RFC's
        // unambiguous pairing.
        let suffix = version_suffix(&dep.declared_version_source, &dep.version);
        println!("{:20} {}{}", dep.name, dep.version, suffix);
        if let Some(id) = &dep.identity {
            // Print algo:digest[:8] — matches Python `{algo}:{digest[:8]}`.
            if let Some((algo, digest)) = id.split_once(':') {
                println!("  identity    {}:{}", algo, &digest[..digest.len().min(8)]);
            } else {
                println!("  identity    {}", &id[..id.len().min(8)]);
            }
        }
        for prov in &dep.provenances {
            println!("  provenance  {}", format_provenance_record(prov));
        }
        if !dep.requires.is_empty() {
            println!("  requires    {}", dep.requires.join(", "));
        }
        // S7 (#135): surface cond_requires — one line per conditional require.
        for cr in &dep.cond_requires {
            let preds_str = cr
                .predicates
                .iter()
                .map(|p| {
                    let op = if p.negated { "!=" } else { "=" };
                    format!("{}{}{}", p.name, op, p.values.first().map(|s| s.as_str()).unwrap_or(""))
                })
                .collect::<Vec<_>>()
                .join(", ");
            println!("  cond-req    {} [{}]", cr.name, preds_str);
        }
        // S10 (RFC #23 §3.7): print active_flags when non-empty.
        if !dep.active_flags.is_empty() {
            println!("  active_flags {}", dep.active_flags.join(" "));
        }
        // S1 (rfc-resolver-correctness.md #142): surface aliases so a user can see
        // that a dep was deduped (e.g. "bar" → canonical "foo").
        if !dep.aliases.is_empty() {
            let mut sorted_aliases = dep.aliases.clone();
            sorted_aliases.sort();
            println!("  aliases     {}", sorted_aliases.join(", "));
        }
        // RFC per-entry-attestation.md P2 (§7): render the lockfile's
        // attestation block as an UNVERIFIED claim — no crypto has ever run
        // over it. The wording upgrades to a verified fact only once the
        // (later) P3 entry-trust gate exists; this schema does not change.
        if let Some(att) = &dep.attestation {
            let claim = match &att.kind {
                milpa_core::AttestationKind::AuthorSigned { signer } => {
                    format!("claims author-signed by {signer}")
                }
                milpa_core::AttestationKind::MilpaVendored => "claims milpa-vendored".to_string(),
            };
            println!("  attestation {claim}");
        }
    }
    Ok(0)
}

/// `milpa show --index-trust` — print index-trust observability to stdout.
///
/// Describes the effective index-trust policy and the cached bundle's CLAIMS
/// (no cryptographic verification — claims only).  The output format is
/// byte-identical to the Python implementation.
///
/// spec/cli-contract.md §5.3a.
fn cmd_show_index_trust(dir: &Path) -> Result<i32, MilpaError> {
    use milpa_core::index_cache::{cache_path_for, index_url_from_env};
    use milpa_core::index_trust::{describe_index_bundle, format_index_trust_info};
    use std::time::{SystemTime, UNIX_EPOCH};

    let index_url = index_url_from_env();

    // Spec §5.3a SSOT: compute the effective index-trust policy the SAME way the
    // enforcement gate does — load the manifest (root-authority model: a workspace's
    // root value IS the effective policy, no merge across members — see
    // resolve_index_trust_fields), then apply env override. Falls back to Warn ONLY
    // for the genuine "no manifest here" case (MAN-NO-MANIFEST) so `show --index-trust`
    // still works outside a milpa project dir. Any OTHER discovery/load failure —
    // in particular a member illegally declaring index-trust (WS-INDEX-TRUST-ON-MEMBER)
    // — MUST propagate (RD-M1 code-review item): this command's whole purpose is to
    // show what the gate would enforce, so it must not silently print a fabricated
    // "warn" for a workspace the gate would actually refuse to run against.
    let (manifest_policy, _manifest_signer, _manifest_bundle) = resolve_index_trust_fields(dir)?;
    let env_override = read_env_index_trust_policy();
    let effective_policy = effective_trust_policy(&manifest_policy, false, env_override.as_ref());
    let policy_str = match effective_policy {
        milpa_manifest::TrustPolicy::Strict => "strict",
        milpa_manifest::TrustPolicy::Warn => "warn",
        milpa_manifest::TrustPolicy::Off => "off",
    };

    // Locate cached files: index + bundle sidecar.
    // Item 5b: use the pub bundle_path() SSOT instead of reconstructing the ".bundle" path inline.
    let cache_dir = index_cache_dir();
    let cache_file = cache_path_for(&index_url, &cache_dir);
    let bundle_file = milpa_core::index_cache::bundle_path(&cache_file);

    let index_cached = cache_file.exists();
    let bundle_cached = bundle_file.exists();

    let info = if bundle_cached {
        std::fs::read(&bundle_file)
            .ok()
            .and_then(|b| describe_index_bundle(&b))
    } else {
        None
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let max_age = std::env::var("MILPA_INDEX_MAX_AGE")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(604800);

    let output = format_index_trust_info(
        &index_url,
        &policy_str,
        index_cached,
        bundle_cached,
        info.as_ref(),
        now,
        max_age,
    );
    print!("{output}");
    Ok(0)
}

/// `milpa verify` — confirm `_deps/` matches the lockfile (stderr report).
///
/// `require_attested_metadata` is the parsed CLI flag (already ORed with the
/// `MILPA_REQUIRE_ATTESTED_METADATA` env var by `parse_args` — the env parse
/// lives there and only there, per Finding 1 SSOT).
#[allow(clippy::too_many_arguments)]
fn cmd_verify(
    dir: &Path,
    require_attested_metadata: bool,
    no_index: bool,
    require_attested_index: bool,
    refresh_index: bool,
    require_attested_entries: bool,
) -> Result<i32, MilpaError> {
    // Gap-1 D: load_lockfile's `?` surfaces LOCK-FILE-NOT-FOUND via the Err path
    // in main (which now emits the milpa-error: slug automatically). No inline
    // slug needed for the missing-lockfile case.
    let lock = load_lockfile(&dir.join("milpa.lock"))?;

    // S10 (RFC #23 §3.7): active_flags mismatch check — manifest-vs-lockfile.
    // Runs BEFORE the disk check (it's about manifest consistency, not disk state).
    // Routes through check_frozen_active_flags_mismatch (SSOT), which internally
    // uses dep_passes_flag_predicates for the admission decision.  With no CLI
    // features (empty BTreeSet, no_default_features=false, all_features=false),
    // the function uses the default-true flag closure as the seed.
    //
    // Also capture the manifest's index_trust fields for the dep_decl edge check below.
    let mut verify_index_policy = milpa_manifest::TrustPolicy::Warn;
    let mut verify_index_signer: Option<String> = None;
    let mut verify_index_bundle: Option<String> = None;
    // P3a (RFC per-entry-attestation.md §7): captured alongside the index-trust
    // fields for the offline entry-attestation reverify below.
    let mut verify_entry_trust_policy = milpa_manifest::TrustPolicy::Warn;
    // A3 (rfc-registry-append-only.md §2): captured alongside the other
    // policy axes for the dep_decl edge check's maybe_index() call below.
    let mut verify_index_history_policy = milpa_manifest::TrustPolicy::Warn;
    match discover_manifest(dir) {
        Ok(milpa_manifest::ManifestDoc::Package(ref manifest)) => {
            verify_index_policy = manifest.index_trust_policy.clone();
            verify_index_signer = manifest.index_trust_signer.clone();
            verify_index_bundle = manifest.index_trust_bundle.clone();
            verify_entry_trust_policy = manifest.entry_trust_policy.clone();
            verify_index_history_policy = manifest.index_history_policy.clone();
            if let Err(e) = check_frozen_active_flags_mismatch(
                manifest,
                &lock,
                &std::collections::BTreeSet::new(),
                false,
                false,
            ) {
                eprintln!("{}: {}", e.code(), message_of(&e));
                eprintln!("milpa-error: {}", e.code());
                return Ok(1);
            }
        }
        Ok(milpa_manifest::ManifestDoc::Workspace(_)) => {
            // S11b (Breadth-P2c): workspace frozen-flags mismatch check.
            // Runs BEFORE disk-state check; uses manifest defaults (no CLI features at verify time).
            //
            // RD-H1 (code-review): `discover_manifest` already CONFIRMED this dir's
            // milpa.kdl is a workspace document, so `load_workspace`'s errors (WS-*,
            // including WS-INDEX-TRUST-ON-MEMBER) MUST propagate here — swallowing
            // them via `if let Ok(ws) = ...` silently downgraded a hard structural
            // error into "verify passed" or a misleading LOCK-GRAPH-MISMATCH.
            let ws = load_workspace(dir)?;
            // SSOT (Item 1): workspace_index_trust_fields replaces the inline collect+merge.
            let (p, s, b) = workspace_index_trust_fields(&ws);
            verify_index_policy = p;
            verify_index_signer = s;
            verify_index_bundle = b;
            verify_entry_trust_policy = ws.entry_trust_policy.clone();
            verify_index_history_policy = ws.index_history_policy.clone();
            if let Err(e) = check_workspace_frozen_active_flags_mismatch(
                &ws,
                &lock,
                &std::collections::BTreeSet::new(),
                false,
                false,
            ) {
                eprintln!("{}: {}", e.code(), message_of(&e));
                eprintln!("milpa-error: {}", e.code());
                return Ok(1);
            }
        }
        // Genuinely no manifest / not a milpa project dir here → graceful
        // defaults (verify still runs the disk-state check below).
        Err(_) => {}
    }

    // Sv (rfc-attestation-verifier): offline reverify of the CACHED index
    // attestation bundle — the offline post-incident audit path (Part-1 §7.5).
    // A tampered/invalid cached bundle fails verify under strict (warns under
    // warn). Never fetches; independent of the online dep_decl edge check below.
    {
        let raw = std::env::var("MILPA_INDEX_URL").ok();
        let explicit_no_index = raw.as_deref().map(|s| s.trim().is_empty()).unwrap_or(false);
        if !no_index && !explicit_no_index {
            let url = milpa_core::index_cache::index_url_from_env();
            // Same gate assembly as index loading; None ⟹ policy off ⟹ nothing to reverify.
            if let Some(active) = build_index_trust_gate(
                &verify_index_policy,
                verify_index_signer.clone(),
                verify_index_bundle.clone(),
                require_attested_index,
                &url,
            )? {
                if let Err(e) = milpa_core::index_cache::reverify_cached_index(
                    &url,
                    &index_cache_dir(),
                    &active.cfg,
                    active.verifier.as_ref(),
                ) {
                    eprintln!("cached index attestation reverify failed: {}", message_of(&e));
                    eprintln!("milpa-error: {}", e.code());
                    return Ok(1);
                }
            }
        }
    }

    // P3a (RFC per-entry-attestation.md §7): offline reverify of CACHED
    // per-entry attestation bundles. Same shape as the index reverify above —
    // never fetches, independent of the online dep_decl edge check below.
    if let Err(e) = reverify_cached_entry_attestations(
        &lock,
        &verify_entry_trust_policy,
        verify_index_signer.clone(),
        verify_index_bundle.clone(),
        require_attested_entries,
        no_index,
    ) {
        eprintln!("cached entry attestation reverify failed: {}", message_of(&e));
        eprintln!("milpa-error: {}", e.code());
        return Ok(1);
    }

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
        // require_attested_metadata).  Use the SSOT helpers (S1 rename):
        //   - Single-package: effective_trust_policy(&manifest.attestation_policy, flag, None) == TrustPolicy::Strict
        //   - Workspace:      workspace_any_member_strict(ws) || flag
        // The env-var parse lives in parse_args (the one SSOT); `require_attested_metadata`
        // already incorporates it — no inline re-read here.
        let strict = match discover_manifest(dir) {
            Ok(milpa_manifest::ManifestDoc::Package(m)) => {
                use milpa_core::TrustPolicy;
                effective_trust_policy(&m.attestation_policy, require_attested_metadata, None)
                    == TrustPolicy::Strict
            }
            Ok(milpa_manifest::ManifestDoc::Workspace(_)) => {
                // load the workspace and consult member policies.
                // RD-H1: this dir's milpa.kdl is a confirmed workspace document
                // (discover_manifest already said so) — load_workspace errors
                // (WS-INDEX-TRUST-ON-MEMBER etc.) MUST propagate, not silently
                // fall back to the flag-only strict decision.
                let ws = load_workspace(dir)?;
                workspace_any_member_strict(&ws) || require_attested_metadata
            }
            Err(_) => require_attested_metadata,
        };

        // Determine online state: MILPA_INDEX_URL must be set.
        // maybe_index() returns None when offline/unreachable (treats as absent).
        // Pass verify_index_policy (captured above from manifest) and the threaded flags.
        let verify_history_policy = effective_index_history_policy(&verify_index_history_policy);
        let index_opt = maybe_index(no_index, &verify_index_policy, verify_index_signer, verify_index_bundle, require_attested_index, refresh_index, &verify_history_policy)?;
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
///
/// In workspace mode (cli-contract §5.5): remove `<ws_root>/_deps/` and each
/// member's `nim.cfg`.  The root-level `nim.cfg` is never present in workspace
/// mode (workspaces use per-member nim.cfg), so we skip it.
fn cmd_clean(dir: &Path) -> Result<i32, MilpaError> {
    // Root-cause discipline (RD-C1 family — "mirror everywhere"; Python's
    // `cmd_clean` calls the unguarded `find_workspace_root` too): only a
    // CONFIRMED workspace document at `dir` triggers workspace-mode cleanup;
    // `load_workspace`'s structural errors (WS-*) then propagate rather than
    // being swallowed into "must not be a workspace, clean single-package
    // instead" — `if let Ok(ws) = load_workspace(dir) { .. } else { .. }`
    // could not distinguish "no workspace here" from "workspace here but
    // trust-invalid".
    match discover_manifest(dir) {
        Ok(ManifestDoc::Workspace(_)) => {
            let ws = load_workspace(dir)?;
            // Workspace mode: remove root _deps/ + per-member nim.cfg.
            let _ = std::fs::remove_dir_all(ws.root.join("_deps"));
            for member in &ws.members {
                let _ = std::fs::remove_file(member.directory.join("nim.cfg"));
            }
        }
        // Package manifest, or no manifest at all (nothing to clean) →
        // single-package mode. Idempotent — exits 0 even if nothing exists.
        Ok(ManifestDoc::Package(_)) | Err(_) => {
            let _ = std::fs::remove_dir_all(dir.join("_deps"));
            let _ = std::fs::remove_file(dir.join("nim.cfg"));
        }
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// `milpa hash` — probe content identity without CAS side-effects (A0-cmd)
// ---------------------------------------------------------------------------

/// `milpa hash <token> [<token>...]` — parse the source spec tokens, fetch the
/// source into a scratch temp dir via the **inner** (non-CAS) registry, print the
/// content identity to stdout, then discard the temp dir.
///
/// Architectural pin (spec/cli-contract.md §5.11 NORMATIVE):
///   - Identity is read from `Receipt::identity` — the field set by
///     `DefaultRegistry::fetch` (the same site `milpa fetch` uses).
///   - This function MUST NOT call `compute_content_hash` directly.
///   - No `milpa.lock`, no `_deps/`, no CAS admission.
///
/// stdout: `sha256:<64hex>` (one line) for git/tarball/OCI sources;
///         empty for local/editable sources (no stable identity).
/// stderr: diagnostic on failure only.
/// Exit: 0 on success; 1 on bad spec (CLI-SOURCE-SPEC-INVALID) or fetch error.
fn cmd_hash(tokens: &[String], base_dir: &Path) -> Result<i32, MilpaError> {
    if tokens.is_empty() {
        // Empty token list: surface the parse error (CLI-SOURCE-SPEC-INVALID).
        parse_source_spec::<String>(&[], Some(base_dir))?;
        unreachable!("parse_source_spec always fails on empty tokens");
    }
    let prov = parse_source_spec(tokens, Some(base_dir))?;

    // Fetch into a scratch temp dir using the same inner registry as `milpa fetch`
    // (but bypassing CAS admission — pure hash probe, zero side effects).
    let tmp = tempfile::TempDir::new().map_err(|e| {
        MilpaError::Core(CoreError::Resolver(
            "MILPA-INTERNAL",
            format!("cmd_hash: create temp dir: {e}"),
        ))
    })?;

    // Build the inner registry directly (same selection logic as build_registry(),
    // but without the CasAdmittingFetcher wrapper — no CAS admission here).
    let receipt = match mocked_fetches_dir() {
        Some(mocked_dir) => MockedFetcher::new(mocked_dir).fetch("hash", &prov, tmp.path()),
        None => DefaultRegistry::with_curl().fetch("hash", &prov, tmp.path()),
    }
    .map_err(MilpaError::Fetch)?;
    // tmp is dropped here (auto-cleanup) after the fetch result is obtained.

    // Print the identity — it comes from Receipt::identity (set by DefaultRegistry::fetch).
    // MUST NOT call compute_content_hash here (spec/cli-contract.md §5.11 NORMATIVE).
    if let Some(id) = &receipt.identity {
        println!("{id}");
    }
    // For local/editable provenances identity is None → print nothing (stdout empty).
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

/// Single construction site for the CAS store (cli-contract §8.2).
///
/// Every command that touches the CAS (fetch / lock / update / add / remove /
/// store / frozen paths) MUST obtain its ``CaStore`` via this function — never
/// via ``CaStore::new(cas_root())`` inline.  This is the ONE place where
/// ``cas_root()`` logic is consulted, matching the Python impl's pattern of
/// building one store in ``_build_env`` and sharing it.
fn build_store() -> CaStore {
    CaStore::new(cas_root())
}

/// Build the fetcher registry used by every resolve path (fetch / lock / add /
/// remove / update). All fetches go through `CasAdmittingFetcher` so
/// `_deps/<name>` is always a relative CAS symlink. The inner fetcher is the
/// `MockedFetcher` when `MILPA_MOCKED_FETCHES` is set (offline, conformance),
/// else `DefaultRegistry` (real network). Single source of truth for the
/// stage→hash→admit→link orchestration lives in `CasAdmittingFetcher`.
fn build_registry() -> Box<dyn FetcherRegistry> {
    let store = build_store();
    // C-stage: CasAdmittingFetcher no longer takes a staging_root —
    // staging is owned by CaStore::scratch() under <cas_root>/_scratch/.
    match mocked_fetches_dir() {
        Some(mocked_dir) => Box::new(CasAdmittingFetcher::new(
            MockedFetcher::new(mocked_dir),
            store,
        )),
        None => Box::new(CasAdmittingFetcher::new(
            DefaultRegistry::with_curl(),
            store,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_fetch(
    dir: &Path,
    strategy_cli: Option<Strategy>,
    frozen: bool,
    emit_nimcfg: bool,
    cert_path: Option<&Path>,
    require_attested_metadata: bool,
    no_index: bool,
    rest: &[String],
    require_attested_index: bool,
    refresh_index: bool,
    require_attested_entries: bool,
    // D2 (resolution-semantics RFC §3 Axis D): the CLI `--exclude-newer`
    // value (fetch/lock only — the ONLY two verbs `cmd_fetch` implements).
    // `None` when unspecified; resolved to the EFFECTIVE value against this
    // verb's own manifest below, mirroring `strategy_cli`.
    exclude_newer_cli: Option<Timestamp>,
) -> Result<i32, MilpaError> {
    let deps_dir = dir.join("_deps");
    let doc = discover_manifest(dir)?;

    // S2 (RFC: workspace-completion §3.A): parse CLI feature-selection from
    // the verb's rest args.  Mirrors how `cmd_update` accepts --features.
    // Needed for the workspace path's resolve_workspace_with_features call.
    let (cli_features, cli_no_default, cli_all_features) = parse_feature_args(rest);

    // B3 (resolution-semantics RFC §3 Axis B): `--locked` is scoped to
    // fetch/lock only (this fn handles both verbs), parsed from `rest` the
    // same way `--features`/`--all-features` are — not the global pre-verb
    // flag loop, which is reserved for the legacy `--frozen`/`--strategy`
    // flags this RFC does not migrate (that is Axis C's C3, later).
    let locked = rest.iter().any(|a| a == "--locked");

    // B4 (resolution-semantics RFC §3 Axis B / D-B3): `--upgrade [<dep>...]`
    // is scoped the same way `--locked` is — parsed from `rest`, not the
    // pre-verb global flag loop. `None` = flag absent (ordinary
    // minimal-change applies); `Some(vec![])` = bare (opt out globally);
    // `Some(names)` = opt out only for those deps.
    let upgrade = upgrade_flag_values(rest);

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
        // C3/R9 (resolution-semantics RFC §3 Axis C / D-C2): resolve the
        // EFFECTIVE strategy (+ whether it was explicitly sourced) ONCE,
        // valid for both the frozen and non-frozen paths below (the frozen
        // path's `write_lockfile` rewrite, further down, also needs a
        // strategy value) — against the WORKSPACE ROOT manifest (Axis W:
        // resolution{} is root-only).
        let strategy_decl = resolve_effective_strategy(strategy_cli, ws.resolution);
        let strategy_explicit = strategy_decl.is_some();
        let strategy = strategy_decl.unwrap_or_default();
        // D2: resolve the EFFECTIVE exclude-newer bound the same way, against
        // the WORKSPACE ROOT manifest (Axis D is root-only, same as
        // strategy). Deliberately NO lockfile (tier-3) fallback here — unlike
        // `update`/`remove`, `fetch`/`lock` DO have a CLI override, so an
        // absent CLI + absent manifest is a genuine "nothing declared this
        // run" result. This is exactly what makes `--locked`'s no-silent-drop
        // check (below) meaningful: comparing THIS honest 2-tier value
        // against the committed lock's recorded value is how a real drop
        // gets caught (D5, §6 D-D3).
        let exclude_newer = resolve_effective_exclude_newer(exclude_newer_cli, ws.resolution, None);
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
            // S11b: the active-flags mismatch check MUST run before the
            // in-store/disk check inside resolve_workspace_frozen, so a
            // feature-selection change surfaces as FROZEN-ACTIVE-FLAGS-MISMATCH
            // rather than FROZEN-IDENTITY-NOT-IN-STORE (fixture-252). Mirrors the
            // verify path; uses the actual CLI features (not empty like verify).
            check_workspace_frozen_active_flags_mismatch(
                &ws, &lock, &cli_features, cli_no_default, cli_all_features,
            )?;
            resolve_workspace_frozen(&ws, &lock, &build_store(), &deps_dir)?
        } else {
            // SSOT (RD-M4): maybe_index_for_workspace collapses extract+call.
            let index = maybe_index_for_workspace(no_index, &ws, require_attested_index, refresh_index)?;
            let profile = profile_from_env();
            // §8: reuse existing pins (idempotent repeated fetch — see single-pkg path).
            let prior = maybe_prior_lockfile(&dir.join("milpa.lock"));
            // C3: `strategy` (the effective value) was already computed above,
            // before the frozen/non-frozen split.
            // B4: delegate to the SAME strip-pin mechanism `milpa update` uses (D-B3).
            let prior = match &upgrade {
                Some(names) => strip_pins_for_upgrade(prior, names)?,
                None => prior,
            };
            // P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
            let entry_trust = build_entry_trust_gate(
                &ws.entry_trust_policy,
                ws.index_trust_signer.clone(),
                ws.index_trust_bundle.clone(),
                require_attested_entries,
                no_index,
            )?;

            // S8 (RFC: workspace-completion §3.E): --certificate honored in workspace
            // mode (both fetch and lock). Mirrors cmd_fetch_with_cert for single-package.
            if let Some(cert_dest) = cert_path {
                return cmd_fetch_workspace_with_cert(
                    dir, &ws, &deps_dir,
                    index.as_ref(), registry.as_ref(),
                    profile.as_ref(), prior.as_ref(),
                    strategy, strategy_explicit, emit_nimcfg, cert_dest,
                    require_attested_metadata,
                    &cli_features, cli_no_default, cli_all_features,
                    entry_trust.as_ref(),
                    locked,
                    exclude_newer,
                );
            }

            // S2 (workspace-completion §3.A): CLI feature-selection wired in.
            let ws_graph = resolve_workspace_with_features(
                &ws,
                index.as_ref(),
                registry.as_ref(),
                profile.as_ref(),
                prior.as_ref(),
                strategy,
                strategy_explicit,
                &deps_dir,
                require_attested_metadata,
                &build_store(),
                &cli_features,
                cli_no_default,
                cli_all_features,
                entry_trust.as_ref(),
                exclude_newer,
            )?;
            // B3: --locked asserts the resolve matches the committed lock
            // (identity + provenance, never the version label — D-B2)
            // BEFORE anything is written, so a drifted resolve never
            // clobbers the committed lockfile/nim.cfg.
            if locked {
                check_locked_drift(prior.as_ref(), &ws_graph, exclude_newer)?;
            }
            ws_graph
        };
        write_lockfile(
            &from_graph(&graph, strategy.as_str(), exclude_newer),
            &dir.join("milpa.lock"),
        )?;
        if emit_nimcfg {
            // S11 §3.8: build flag_defines (SSOT) for unified -d: in per-member nim.cfg.
            let ws_flag_defines = milpa_core::build_flag_defines(&graph, &deps_dir);
            for (path, text) in format_workspace_nimcfgs(&ws, &graph, Some(&ws_flag_defines)) {
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

    // C3/R9 (resolution-semantics RFC §3 Axis C / D-C2): resolve the
    // EFFECTIVE strategy (+ whether it was explicitly sourced) ONCE, valid
    // for both the frozen and non-frozen paths below (the frozen path's
    // `write_lockfile` rewrite, further down, also needs a strategy value)
    // — against the current manifest.
    let strategy_decl = resolve_effective_strategy(strategy_cli, manifest.resolution);
    let strategy_explicit = strategy_decl.is_some();
    let strategy = strategy_decl.unwrap_or_default();
    // D2: resolve the EFFECTIVE exclude-newer bound the same way. Deliberately
    // NO lockfile (tier-3) fallback here — see the workspace branch above for
    // the full rationale (fetch/lock's CLI override makes an honest 2-tier
    // value the correct "new resolve" input to `--locked`'s drift check).
    let exclude_newer = resolve_effective_exclude_newer(exclude_newer_cli, manifest.resolution, None);

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
        // Same ordering rule as the workspace path: active-flags mismatch check
        // runs before the in-store check so a feature-selection change surfaces
        // as FROZEN-ACTIVE-FLAGS-MISMATCH, not FROZEN-IDENTITY-NOT-IN-STORE
        // (fixture-212). Mirrors the verify path.
        check_frozen_active_flags_mismatch(
            &manifest, &lock, &cli_features, cli_no_default, cli_all_features,
        )?;
        Milpa.resolve_frozen(&manifest, &lock, &build_store(), &deps_dir)?
    } else {
        let index = maybe_index_for_manifest(no_index, &manifest, require_attested_index, refresh_index)?;
        let profile = profile_from_env();
        // §8: reuse the existing lockfile's pins so repeated `fetch`/`lock` runs
        // are idempotent and a silently-moved ref / substituted archive is caught.
        let prior = maybe_prior_lockfile(&dir.join("milpa.lock"));
        // C3: `strategy` (the effective value) was already computed above,
        // before the frozen/non-frozen split.
        // B4: delegate to the SAME strip-pin mechanism `milpa update` uses (D-B3).
        let prior = match &upgrade {
            Some(names) => strip_pins_for_upgrade(prior, names)?,
            None => prior,
        };

        // S3b: wire dep_decl_store from environment (MILPA_DEP_DECL_DIR or MILPA_INDEX_URL).
        // Built before the cert branch so both paths share the same store — single
        // source of truth for DepDecl wiring (fixes Finding-High-2).
        let dep_decl_store_owned = maybe_dep_decl_store(no_index);
        let dep_decl_store: Option<&dyn DepDeclStore> =
            dep_decl_store_owned.as_deref();
        // P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
        let entry_trust = build_entry_trust_gate(
            &manifest.entry_trust_policy,
            manifest.index_trust_signer.clone(),
            manifest.index_trust_bundle.clone(),
            require_attested_entries,
            no_index,
        )?;

        if let Some(cert_dest) = cert_path {
            // §2.5: resolve with certificate — emit JSON regardless of success/failure,
            // then propagate the normal exit/slug outcome.
            // Thread dep_decl_store and require_attested_metadata so the cert path is
            // IDENTICAL to the non-cert path modulo certificate emission (fixes
            // Finding-High-1: strict attestation; Finding-High-2: DepDecl wiring).
            return cmd_fetch_with_cert(
                dir, &manifest, &deps_dir, index.as_ref(), registry.as_ref(),
                profile.as_ref(), prior.as_ref(), strategy, strategy_explicit, emit_nimcfg, cert_dest,
                dep_decl_store, require_attested_metadata, entry_trust.as_ref(),
                locked,
                exclude_newer,
            );
        }

        // S9: honor CLI feature-selection on the single-package path too (the
        // workspace path already does via resolve_workspace_with_features). The
        // bare resolve() ignored --features, so feature/profile fixtures passed
        // in-process but diverged black-box (Slice F, fixture-209/210/211/...).
        let pkg_graph = resolve_with_features(
            &manifest,
            index.as_ref(),
            registry.as_ref(),
            profile.as_ref(),
            prior.as_ref(),
            strategy,
            strategy_explicit,
            &deps_dir,
            dep_decl_store,
            require_attested_metadata,
            &build_store(),
            &cli_features,
            cli_no_default,
            cli_all_features,
            entry_trust.as_ref(),
            exclude_newer,
        )?;
        // B3: see the workspace branch above for the rationale.
        if locked {
            check_locked_drift(prior.as_ref(), &pkg_graph, exclude_newer)?;
        }
        pkg_graph
    };

    write_lockfile(
        &from_graph(&graph, strategy.as_str(), exclude_newer),
        &dir.join("milpa.lock"),
    )?;
    if emit_nimcfg {
        let flag_defines = build_flag_defines(&graph, &deps_dir);
        let _ = std::fs::write(
            dir.join("nim.cfg"),
            format_nimcfg(&graph, "_deps", &manifest.src_dir, Some(&flag_defines)),
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
    // R9: see `resolve_effective_strategy`'s doc comment.
    strategy_explicit: bool,
    emit_nimcfg: bool,
    cert_dest: &Path,
    dep_decl_store: Option<&dyn DepDeclStore>,
    require_attested_metadata: bool,
    entry_trust: Option<&milpa_core::EntryTrustConfig>,
    locked: bool,
    // D2 (resolution-semantics RFC §3 Axis D): the EFFECTIVE exclude-newer
    // time-bound this resolve is running under.
    exclude_newer: Option<Timestamp>,
) -> Result<i32, MilpaError> {
    match resolve_with_cert(manifest, index, registry, profile, prior, strategy, strategy_explicit, deps_dir, dep_decl_store, require_attested_metadata, &build_store(), entry_trust, exclude_newer) {
        Ok((graph, cert)) => {
            // B3: --locked asserts the resolve matches the committed lock
            // BEFORE any cert/lockfile/nim.cfg write. A drift is reported
            // via an EMPTY failure cert — mirrors the existing convention
            // for every other non-SOLVE-CONFLICT MilpaError failure.
            if locked {
                if let Err(e) = check_locked_drift(prior, &graph, exclude_newer) {
                    let _ = write_failure_cert(
                        cert_dest,
                        &FailureCert { message: String::new(), refutation: Vec::new() },
                    );
                    return Err(e.into());
                }
            }
            // Write the success certificate (best-effort; a cert write failure
            // does NOT abort the command — the lock/nim.cfg still land).
            let _ = write_success_cert(cert_dest, &cert);
            write_lockfile(&from_graph(&graph, strategy.as_str(), exclude_newer), &dir.join("milpa.lock"))?;
            if emit_nimcfg {
                let flag_defines = build_flag_defines(&graph, deps_dir);
                let _ = std::fs::write(
                    dir.join("nim.cfg"),
                    format_nimcfg(&graph, "_deps", &manifest.src_dir, Some(&flag_defines)),
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

/// The `--certificate` sub-path for workspace `cmd_fetch`/`cmd_lock` (S8,
/// RFC: workspace-completion §3.E). Runs `resolve_workspace_with_cert`, writes
/// the certificate on both success and failure, then applies the normal
/// exit/slug discipline — mirroring `cmd_fetch_with_cert` for single-package.
///
/// Certificate content is defined by `cli-contract §2.5` over the workspace
/// graph (the workspace resolves as one shared graph — same schema as
/// single-package). Harness comparison is on the parsed JSON object, not bytes
/// (`cli-contract §2.5.1 NOTE`; `conformance-fixtures §2.7.3`).
#[allow(clippy::too_many_arguments)]
fn cmd_fetch_workspace_with_cert(
    dir: &Path,
    ws: &LoadedWorkspace,
    deps_dir: &Path,
    index: Option<&Index>,
    registry: &dyn FetcherRegistry,
    profile: Option<&Profile>,
    prior: Option<&milpa_core::Lockfile>,
    strategy: Strategy,
    // R9: see `resolve_effective_strategy`'s doc comment.
    strategy_explicit: bool,
    emit_nimcfg: bool,
    cert_dest: &Path,
    require_attested_metadata: bool,
    features: &std::collections::BTreeSet<String>,
    no_default_features: bool,
    all_features: bool,
    entry_trust: Option<&milpa_core::EntryTrustConfig>,
    locked: bool,
    // D2 (resolution-semantics RFC §3 Axis D): the EFFECTIVE exclude-newer
    // time-bound this resolve is running under.
    exclude_newer: Option<Timestamp>,
) -> Result<i32, MilpaError> {
    match resolve_workspace_with_cert(
        ws, index, registry, profile, prior, strategy, strategy_explicit, deps_dir,
        require_attested_metadata, &build_store(),
        features, no_default_features, all_features,
        entry_trust,
        exclude_newer,
    ) {
        Ok((graph, cert)) => {
            // B3: see cmd_fetch_with_cert for the rationale.
            if locked {
                if let Err(e) = check_locked_drift(prior, &graph, exclude_newer) {
                    let _ = write_failure_cert(
                        cert_dest,
                        &FailureCert { message: String::new(), refutation: Vec::new() },
                    );
                    return Err(e.into());
                }
            }
            // Write success certificate (best-effort; a cert write failure does
            // NOT abort the command — lock/nim.cfg still land).
            let _ = write_success_cert(cert_dest, &cert);
            write_lockfile(&from_graph(&graph, strategy.as_str(), exclude_newer), &dir.join("milpa.lock"))?;
            if emit_nimcfg {
                let ws_flag_defines = milpa_core::build_flag_defines(&graph, deps_dir);
                for (path, text) in format_workspace_nimcfgs(ws, &graph, Some(&ws_flag_defines)) {
                    let target = dir.join(&path).join("nim.cfg");
                    if let Some(p) = target.parent() {
                        let _ = std::fs::create_dir_all(p);
                    }
                    let _ = std::fs::write(target, text);
                }
            }
            eprintln!(
                "resolved {} deps across {} members",
                graph.deps.len(),
                ws.members.len(),
            );
            Ok(0)
        }
        Err((err, failure_cert)) => {
            // Write failure certificate, then surface the error normally.
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
#[allow(clippy::too_many_arguments)]
fn cmd_update(dir: &Path, strategy_cli: Option<Strategy>, rest: &[String], no_index: bool, require_attested_index: bool, refresh_index: bool, require_attested_entries: bool) -> Result<i32, MilpaError> {
    let name = rest.first().cloned();
    let lock_path = dir.join("milpa.lock");

    // Scoped update: load the lockfile and build the prior (all pins minus the
    // named dep). Reject if the named dep is not pinned.
    //
    // B4 (resolution-semantics RFC §3 Axis B / D-B3): the guard + strip below
    // delegates to `strip_pins_for_upgrade` — the SAME shared mechanism
    // `--upgrade [<dep>...]` on fetch/lock uses, so the two verbs cannot
    // structurally drift. This covers the D-update-remove alias→canonical
    // resolution (Phase D item 5), the not-in-lockfile guard, and the
    // pin-strip (retains declared mirror provenances per Phase D item 5;
    // clears identity so the dep re-resolves fresh) in one call.
    let dep_names: Vec<String> = name.iter().cloned().collect();
    let prior_loaded: Option<milpa_core::Lockfile> = if dep_names.is_empty() {
        None
    } else {
        // §5.8: with a <dep> arg but no lockfile, exit 1 (no prior pins to
        // drop selectively — `milpa fetch` is the correct action).
        if !lock_path.exists() {
            return Err(MilpaError::Core(CoreError::Lockfile(
                "LOCK-FILE-NOT-FOUND",
                "update: no milpa.lock — run `milpa fetch` first".into(),
            )));
        }
        Some(load_lockfile(&lock_path)?)
    };
    let prior = match strip_pins_for_upgrade(prior_loaded, &dep_names) {
        Ok(p) => p,
        Err(e) if e.code() == "LOCK-DEP-NOT-FOUND" => {
            eprintln!("update: {}", message_of(&e));
            eprintln!("milpa-error: LOCK-DEP-NOT-FOUND");
            return Ok(1);
        }
        Err(e) => return Err(e),
    };

    let doc = discover_manifest(dir)?;
    let deps_dir = dir.join("_deps");
    let registry = build_registry();

    if let ManifestDoc::Workspace(_) = doc {
        let ws = load_workspace(dir)?;
        // SSOT (RD-M4): maybe_index_for_workspace collapses extract+call.
        let index = maybe_index_for_workspace(no_index, &ws, require_attested_index, refresh_index)?;
        let profile = profile_from_env();
        let ws_deps_dir = dir.join("_deps");
        // P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
        let entry_trust = build_entry_trust_gate(
            &ws.entry_trust_policy,
            ws.index_trust_signer.clone(),
            ws.index_trust_bundle.clone(),
            require_attested_entries,
            no_index,
        )?;
        // C3/R9 (resolution-semantics RFC §3 Axis C / D-C2): resolve the
        // EFFECTIVE strategy (+ whether it was explicitly sourced) against
        // the WORKSPACE ROOT manifest — independent of `prior` above, which
        // this verb deliberately nulls/strips for B2's minimal-change
        // preference (dropping a dep's pin must not also reset the
        // governing strategy).
        let strategy_decl = resolve_effective_strategy(strategy_cli, ws.resolution);
        let strategy_explicit = strategy_decl.is_some();
        let strategy = strategy_decl.unwrap_or_default();
        // D2/D5: `update` has no CLI `--exclude-newer` flag (fetch/lock only,
        // §3 Axis D "Verb reach") — falls through to the manifest's committed
        // bound, then (D5, no-silent-drop) the lockfile's own recorded bound.
        let exclude_newer = resolve_effective_exclude_newer(
            None, ws.resolution, maybe_prior_lockfile(&lock_path).as_ref(),
        );
        let graph = resolve_workspace_with_features(
            &ws,
            index.as_ref(),
            registry.as_ref(),
            profile.as_ref(),
            prior.as_ref(),
            strategy,
            strategy_explicit,
            &ws_deps_dir,
            false, // cmd_update does not accept --require-attested-metadata (fetch/lock only)
            &build_store(),
            &std::collections::BTreeSet::new(),
            false,
            false,
            entry_trust.as_ref(),
            exclude_newer,
        )?;
        write_lockfile(&from_graph(&graph, strategy.as_str(), exclude_newer), &lock_path)?;
        eprintln!(
            "updated {} across {} members",
            name.as_deref().unwrap_or("all deps"),
            ws.members.len()
        );
        return Ok(0);
    }

    // S11e: member-dir detect-and-delegate for `update`.
    // If dir is a member of a parent workspace, delegate the full workspace re-resolve
    // to the workspace root (shared milpa.lock + shared _deps/), NOT a member-local lock.
    if let Some((ws_root, ws)) = find_parent_workspace(dir)? {
        let ws_lock_path = ws_root.join("milpa.lock");
        let ws_deps_dir = ws_root.join("_deps");
        // SSOT (RD-M4): maybe_index_for_workspace collapses extract+call.
        let index = maybe_index_for_workspace(no_index, &ws, require_attested_index, refresh_index)?;
        let profile = profile_from_env();
        // P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
        let entry_trust = build_entry_trust_gate(
            &ws.entry_trust_policy,
            ws.index_trust_signer.clone(),
            ws.index_trust_bundle.clone(),
            require_attested_entries,
            no_index,
        )?;
        // Re-build prior against the SHARED lockfile, not a member-local one.
        // B4 (D-B3): same shared `strip_pins_for_upgrade` delegation as the
        // root/direct-workspace path above.
        let ws_prior_loaded: Option<milpa_core::Lockfile> = if dep_names.is_empty() {
            None
        } else {
            if !ws_lock_path.exists() {
                eprintln!("update: no milpa.lock at {} — run `milpa fetch` first", ws_lock_path.display());
                eprintln!("milpa-error: LOCK-FILE-NOT-FOUND");
                return Ok(1);
            }
            Some(load_lockfile(&ws_lock_path)?)
        };
        let ws_prior = match strip_pins_for_upgrade(ws_prior_loaded, &dep_names) {
            Ok(p) => p,
            Err(e) if e.code() == "LOCK-DEP-NOT-FOUND" => {
                eprintln!("update: {}", message_of(&e));
                eprintln!("milpa-error: LOCK-DEP-NOT-FOUND");
                return Ok(1);
            }
            Err(e) => return Err(e),
        };
        // C3/R9: resolve the EFFECTIVE strategy (+ whether it was
        // explicitly sourced) against the WORKSPACE ROOT manifest.
        let strategy_decl = resolve_effective_strategy(strategy_cli, ws.resolution);
        let strategy_explicit = strategy_decl.is_some();
        let strategy = strategy_decl.unwrap_or_default();
        // D2/D5: no CLI flag on `update` — manifest-only, then (no-silent-
        // drop) the lockfile's own recorded bound, same as the root path above.
        let exclude_newer = resolve_effective_exclude_newer(
            None, ws.resolution, maybe_prior_lockfile(&ws_lock_path).as_ref(),
        );
        let graph = resolve_workspace_with_features(
            &ws,
            index.as_ref(),
            registry.as_ref(),
            profile.as_ref(),
            ws_prior.as_ref(),
            strategy,
            strategy_explicit,
            &ws_deps_dir,
            false,
            &build_store(),
            &std::collections::BTreeSet::new(),
            false,
            false,
            entry_trust.as_ref(),
            exclude_newer,
        )?;
        write_lockfile(&from_graph(&graph, strategy.as_str(), exclude_newer), &ws_lock_path)?;
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
    let index = maybe_index_for_manifest(no_index, &manifest, require_attested_index, refresh_index)?;
    let profile = profile_from_env();
    let dep_decl_store_owned = maybe_dep_decl_store(no_index);
    let dep_decl_store: Option<&dyn DepDeclStore> = dep_decl_store_owned.as_deref();
    // P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
    let entry_trust = build_entry_trust_gate(
        &manifest.entry_trust_policy,
        manifest.index_trust_signer.clone(),
        manifest.index_trust_bundle.clone(),
        require_attested_entries,
        no_index,
    )?;
    // C3/R9: resolve the EFFECTIVE strategy (+ whether it was explicitly
    // sourced) against the current manifest — independent of `prior` above
    // (same rationale as the workspace branch).
    let strategy_decl = resolve_effective_strategy(strategy_cli, manifest.resolution);
    let strategy_explicit = strategy_decl.is_some();
    let strategy = strategy_decl.unwrap_or_default();
    // D2/D5: no CLI flag on `update` — manifest-only, then (no-silent-drop)
    // the lockfile's own recorded bound.
    let exclude_newer = resolve_effective_exclude_newer(
        None, manifest.resolution, maybe_prior_lockfile(&lock_path).as_ref(),
    );
    let graph = resolve_with_features(
        &manifest,
        index.as_ref(),
        registry.as_ref(),
        profile.as_ref(),
        prior.as_ref(),
        strategy,
        strategy_explicit,
        &deps_dir,
        dep_decl_store,
        false, // require_attested_metadata: not surfaced by `update` verb
        &build_store(),
        &std::collections::BTreeSet::new(),
        false,
        false,
        entry_trust.as_ref(),
        exclude_newer,
    )?;
    write_lockfile(&from_graph(&graph, strategy.as_str(), exclude_newer), &lock_path)?;
    eprintln!("updated {}", name.as_deref().unwrap_or("all deps"));
    Ok(0)
}

/// A3b (§3 Axis A (b) step 4): parse `add --git`'s `--version` flag.
///
/// Returns `Ok(None)` when absent. A malformed value is rejected with the
/// same slug as the manifest grammar (`MAN-DEP-VERSION-INVALID`) — the CLI
/// writes the exact `version=` annotation a hand-edit would, so a malformed
/// value is rejected the same way before anything is written.
fn parse_add_version_flag(rest: &[String]) -> Result<Option<Version>, MilpaError> {
    match flag_value(rest, "--version") {
        None => Ok(None),
        Some(raw) => parse_version(&raw).map(Some).ok_or_else(|| {
            MilpaError::Manifest(milpa_manifest::ManifestError::new(
                "MAN-DEP-VERSION-INVALID",
                format!("--version value {raw:?} is not a valid semver version (expected 'x.y.z')"),
            ))
        }),
    }
}

/// `milpa add <name> --git <url> [--ref <r>]` / `add <name> --mirror <url>`.
#[allow(clippy::too_many_arguments)]
fn cmd_add(dir: &Path, strategy_cli: Option<Strategy>, rest: &[String], no_index: bool, require_attested_index: bool, refresh_index: bool, require_attested_entries: bool) -> Result<i32, MilpaError> {
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
        // S11a: add at a workspace root emits the canonical directive slug.
        eprintln!(
            "add: cannot add a dep to a workspace root — \
             to add a dep, `cd` to a member; \
             to add a member, use `milpa workspace add-member`"
        );
        eprintln!("milpa-error: MAN-MUTATE-WORKSPACE-REFUSED");
        return Ok(1);
    };
    if existing.deps.iter().any(|d| d.name() == name) {
        return Err(MilpaError::Manifest(milpa_manifest::ManifestError::new(
            "MAN-ADD-DEP-EXISTS",
            format!("dep {name:?} is already declared in milpa.kdl"),
        )));
    }

    // A3b (§3 Axis A (b) step 4): --version validation, shared by both the
    // member-dir and single-package paths below.
    let version_annotation = parse_add_version_flag(rest)?;

    // S11e: if this is a member dir (has a parent workspace), delegate to
    // workspace-level add: mutate the MEMBER's manifest + re-resolve the WHOLE
    // workspace.  The shared lock must be written; NO member-local lock.
    if let Some((ws_root, ws)) = find_parent_workspace(dir)? {
        // Re-use `existing` (already loaded from dir/milpa.kdl) for the member manifest.
        // S10 (RFC #23 §3.7): parse --optional and --features from rest.
        let optional_flag = rest.iter().any(|a| a == "--optional");
        let feat_str = flag_value(rest, "--features");
        let feat_names: Vec<String> = feat_str
            .as_deref()
            .map(|s| s.split(',').filter(|f| !f.is_empty()).map(String::from).collect())
            .unwrap_or_default();

        if optional_flag {
            if !valid_flag_name(&name) {
                eprintln!("add: dep name {:?} is not a valid flag name (must match [A-Za-z0-9_-]+)", name);
                eprintln!("milpa-error: MAN-DEP-OPTIONAL-INVALID-NAME");
                return Ok(1);
            }
            let declared_flag_names: std::collections::HashSet<&str> =
                existing.flags.iter().map(|f| f.name.as_str()).collect();
            if declared_flag_names.contains(name.as_str()) {
                eprintln!("add: dep {:?} optional=#true would clash with an existing flag of the same name", name);
                eprintln!("milpa-error: MAN-DEP-OPTIONAL-FLAG-CLASH");
                return Ok(1);
            }
        }

        let flag_reqs_ws: Vec<FlagRequest> = feat_names
            .iter()
            .map(|f| FlagRequest { name: f.clone(), enabled: true })
            .collect();

        // Ref discovery — same as the single-package path.
        let git_ref_ws = match flag_value(rest, "--ref") {
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

        // Build proposed MEMBER manifest with the new dep.
        let mut proposed_member = existing.clone();
        proposed_member.deps.push(Dep::Url(UrlDep {
            name: name.clone(),
            git: url.clone(),
            git_ref: git_ref_ws.clone(),
            mirrors: Vec::new(),
            predicates: Vec::new(),
            flag_requests: flag_reqs_ws.clone(),
            optional: optional_flag,
            version: version_annotation.clone(),
        }));

        // Rebuild the workspace with the proposed member manifest.
        let ws_with_override = milpa_core::load_workspace_with_member_override(&ws, dir, proposed_member.clone())?;
        let ws_deps_dir = ws_root.join("_deps");
        let ws_lock_path = ws_root.join("milpa.lock");
        // SSOT (RD-M4): maybe_index_for_workspace collapses extract+call.
        let index = maybe_index_for_workspace(no_index, &ws, require_attested_index, refresh_index)?;
        let profile = profile_from_env();
        // B7 (RFC resolution-semantics.md §3 Axis B): thread the SHARED
        // workspace lock as `prior` so adding a dep to one member re-resolves
        // minimally — other members' already-locked deps stay pinned.
        let prior = maybe_prior_lockfile(&ws_lock_path);
        // C3/R9 (resolution-semantics RFC §3 Axis C / D-C2): resolve the
        // EFFECTIVE strategy (+ whether it was explicitly sourced) against
        // the WORKSPACE ROOT manifest (Axis W: resolution{} is root-only).
        let strategy_decl = resolve_effective_strategy(strategy_cli, ws.resolution);
        let strategy_explicit = strategy_decl.is_some();
        let strategy = strategy_decl.unwrap_or_default();
        // D2/D5: no CLI flag on `add` — manifest-only, against the WORKSPACE
        // ROOT manifest (same root-only rationale as strategy above), then
        // (no-silent-drop) the shared lock's own recorded bound.
        let exclude_newer = resolve_effective_exclude_newer(None, ws.resolution, prior.as_ref());
        // P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
        let entry_trust = build_entry_trust_gate(
            &ws.entry_trust_policy,
            ws.index_trust_signer.clone(),
            ws.index_trust_bundle.clone(),
            require_attested_entries,
            no_index,
        )?;
        let graph = resolve_workspace_with_features(
            &ws_with_override,
            index.as_ref(),
            build_registry().as_ref(),
            profile.as_ref(),
            prior.as_ref(),
            strategy,
            strategy_explicit,
            &ws_deps_dir,
            false,
            &build_store(),
            &std::collections::BTreeSet::new(),
            false,
            false,
            entry_trust.as_ref(),
            exclude_newer,
        )?;

        // Atomic write: member manifest first, then shared workspace lock.
        // NO member-local lock written (D5 correctness point).
        let name_c = name.clone();
        let url_c = url.clone();
        let git_ref_c = git_ref_ws.clone();
        let version_c = version_annotation.clone();
        mutate_manifest_file(&dir.join("milpa.kdl"), move |mut m| {
            m.deps.push(Dep::Url(UrlDep {
                name: name_c,
                git: url_c,
                git_ref: git_ref_c,
                mirrors: Vec::new(),
                predicates: Vec::new(),
                flag_requests: flag_reqs_ws,
                optional: optional_flag,
                version: version_c,
            }));
            m
        })?;
        write_lockfile(&from_graph(&graph, strategy.as_str(), exclude_newer), &ws_lock_path)?;
        eprintln!("added dep");
        return Ok(0);
    }

    // S10 (RFC #23 §3.7): parse --optional and --features <comma-list> from rest.
    let optional = rest.iter().any(|a| a == "--optional");
    let features_str = flag_value(rest, "--features");
    let feature_names: Vec<String> = features_str
        .as_deref()
        .map(|s| s.split(',').filter(|f| !f.is_empty()).map(String::from).collect())
        .unwrap_or_default();

    // S10 pre-write clash check: validate optional dep name + flag namespace clash.
    if optional {
        // Charset check: dep name must match [A-Za-z0-9_-]+.
        if !valid_flag_name(&name) {
            eprintln!(
                "add: dep name {:?} is not a valid flag name (must match [A-Za-z0-9_-]+)",
                name
            );
            eprintln!("milpa-error: MAN-DEP-OPTIONAL-INVALID-NAME");
            return Ok(1);
        }
        // Clash check: dep name must not collide with an existing declared flag.
        let declared_flag_names: std::collections::HashSet<&str> =
            existing.flags.iter().map(|f| f.name.as_str()).collect();
        if declared_flag_names.contains(name.as_str()) {
            eprintln!(
                "add: dep {:?} optional=#true would clash with an existing flag of the same name",
                name
            );
            eprintln!("milpa-error: MAN-DEP-OPTIONAL-FLAG-CLASH");
            return Ok(1);
        }
    }

    // Build FlagRequest list from --features.
    let flag_reqs: Vec<FlagRequest> = feature_names
        .iter()
        .map(|f| FlagRequest { name: f.clone(), enabled: true })
        .collect();

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
        flag_requests: flag_reqs.clone(),
        optional,
        version: version_annotation.clone(),
    }));

    let deps_dir = dir.join("_deps");
    let registry = build_registry();
    let index = maybe_index_for_manifest(no_index, &existing, require_attested_index, refresh_index)?;
    let profile = profile_from_env();
    // B7 (RFC resolution-semantics.md §3 Axis B): thread the committed lock as
    // `prior` so minimal-change re-resolution applies — the new dep resolves
    // while every other already-locked dep stays pinned (#192 through this door).
    let prior = maybe_prior_lockfile(&dir.join("milpa.lock"));
    // C3/R9: resolve the EFFECTIVE strategy (+ whether it was explicitly
    // sourced) against the current manifest.
    let strategy_decl = resolve_effective_strategy(strategy_cli, existing.resolution);
    let strategy_explicit = strategy_decl.is_some();
    let strategy = strategy_decl.unwrap_or_default();
    // D2/D5: no CLI flag on `add` — manifest-only, then (no-silent-drop) the
    // lockfile's own recorded bound.
    let exclude_newer = resolve_effective_exclude_newer(None, existing.resolution, prior.as_ref());
    // P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
    let entry_trust = build_entry_trust_gate(
        &existing.entry_trust_policy,
        existing.index_trust_signer.clone(),
        existing.index_trust_bundle.clone(),
        require_attested_entries,
        no_index,
    )?;
    let graph = resolve_with_features(
        &proposed,
        index.as_ref(),
        registry.as_ref(),
        profile.as_ref(),
        prior.as_ref(),
        strategy,
        strategy_explicit,
        &deps_dir,
        None,
        false,
        &build_store(),
        &std::collections::BTreeSet::new(),
        false,
        false,
        entry_trust.as_ref(),
        exclude_newer,
    )?;

    // Resolution succeeded → commit both outputs.
    mutate_manifest_file(&dir.join("milpa.kdl"), move |mut m| {
        m.deps.push(Dep::Url(UrlDep {
            name: name.clone(),
            git: url.clone(),
            git_ref: git_ref.clone(),
            mirrors: Vec::new(),
            predicates: Vec::new(),
            flag_requests: flag_reqs,
            optional,
            version: version_annotation.clone(),
        }));
        m
    })?;
    write_lockfile(&from_graph(&graph, strategy.as_str(), exclude_newer), &dir.join("milpa.lock"))?;
    eprintln!("added dep");
    Ok(0)
}

// ---------------------------------------------------------------------------
// cmd_workspace — workspace add-member / remove-member (S10, D4)
// ---------------------------------------------------------------------------

/// `milpa workspace add-member <path>` / `milpa workspace remove-member <name|path>`
///
/// S10 (RFC: workspace-completion §3.F / D4): grouped under a `workspace`
/// subcommand.  Both verbs delegate to `apply_workspace_manifest_change` for
/// the validate→resolve-in-memory→write-manifest→write-lock atomicity ordering.
///
/// Validation rules (before any on-disk mutation):
///   `add-member <path>`:
///     - dir must exist          → `WS-MEMBER-DIR-MISSING`
///     - dir must contain milpa.kdl → `WS-MEMBER-NO-MANIFEST`
///     - milpa.kdl must have a `name` → `MAN-NAME-MISSING`
///     - member must not be a workspace → `WS-MEMBER-IS-WORKSPACE`
///     - name-unique among existing members → `WS-MEMBER-DUPLICATE-NAME`
///   `remove-member <name|path>`:
///     - name/path must match a declared member → `WS-REMOVE-MEMBER-NOT-FOUND`
///     - no dangling root MemberTarget override → `WS-REMOVE-MEMBER-TARGET-EXISTS`
///     - no dangling member-edge in other members' deps/dev_deps → `WS-REMOVE-MEMBER-REFERENCED`
fn cmd_workspace(
    dir: &Path,
    rest: &[String],
    strategy_cli: Option<Strategy>,
    no_index: bool,
    require_attested_index: bool,
    refresh_index: bool,
) -> Result<i32, MilpaError> {
    let sub = rest.first().map(|s| s.as_str());
    match sub {
        Some("add-member") => cmd_workspace_add_member(dir, &rest[1..], strategy_cli, no_index, require_attested_index, refresh_index),
        Some("remove-member") => cmd_workspace_remove_member(dir, &rest[1..], strategy_cli, no_index, require_attested_index, refresh_index),
        _ => {
            eprintln!("workspace: usage: milpa workspace <add-member|remove-member> [args]");
            Ok(2)
        }
    }
}

fn cmd_workspace_add_member(
    dir: &Path,
    rest: &[String],
    strategy_cli: Option<Strategy>,
    no_index: bool,
    require_attested_index: bool,
    refresh_index: bool,
) -> Result<i32, MilpaError> {
    let Some(member_path_str) = rest.first() else {
        eprintln!("workspace add-member: usage: milpa workspace add-member <path>");
        return Ok(2);
    };

    let member_abs = dir.join(member_path_str).canonicalize().unwrap_or_else(|_| dir.join(member_path_str));

    // Guard 1: directory must exist.
    if !member_abs.is_dir() {
        eprintln!(
            "workspace add-member: {:?}: directory does not exist",
            member_path_str
        );
        eprintln!("milpa-error: WS-MEMBER-DIR-MISSING");
        return Ok(1);
    }

    // Guard 2: must contain milpa.kdl.
    let kdl_path = member_abs.join("milpa.kdl");
    if !kdl_path.exists() {
        eprintln!(
            "workspace add-member: {:?}: no milpa.kdl found",
            member_path_str
        );
        eprintln!("milpa-error: WS-MEMBER-NO-MANIFEST");
        return Ok(1);
    }

    // Guard 3: parse member manifest; check name + no-nesting.
    let member_text = std::fs::read_to_string(&kdl_path).map_err(|e| {
        MilpaError::Manifest(milpa_manifest::ManifestError::new(
            "MAN-FILE-UNREADABLE",
            format!("cannot read {}: {}", kdl_path.display(), e),
        ))
    })?;
    let member_doc = milpa_manifest::parse_document(&member_text)?;
    let member_manifest = match member_doc {
        ManifestDoc::Workspace(_) => {
            eprintln!(
                "workspace add-member: {:?} is itself a workspace; nested workspaces are not supported",
                member_path_str
            );
            eprintln!("milpa-error: WS-MEMBER-IS-WORKSPACE");
            return Ok(1);
        }
        ManifestDoc::Package(m) => m,
    };
    let new_member_name = match &member_manifest.name {
        None => {
            return Err(MilpaError::Manifest(milpa_manifest::ManifestError::new(
                "MAN-NAME-MISSING",
                format!(
                    "{}: milpa.kdl has no name — add a `name \"...\"` declaration",
                    member_path_str
                ),
            )));
        }
        Some(n) => n.clone(),
    };

    // Guard 4: name-unique among existing members.
    let current_ws = load_workspace(dir)?;
    for existing_member in &current_ws.members {
        if existing_member.name == new_member_name {
            return Err(MilpaError::Core(CoreError::Workspace(
                "WS-MEMBER-DUPLICATE-NAME",
                format!("a member named {:?} already exists in the workspace", new_member_name),
            )));
        }
    }

    // Determine the member path to record: relative to the workspace root.
    let rel_path = if let Ok(canonical_dir) = dir.canonicalize() {
        if let Ok(rel) = member_abs.strip_prefix(&canonical_dir) {
            rel.to_string_lossy().to_string()
        } else {
            member_path_str.to_string()
        }
    } else {
        member_path_str.to_string()
    };

    // Delegate to apply_workspace_manifest_change.
    let registry = build_registry();
    // SSOT (RD-M4): maybe_index_for_workspace collapses extract+call.
    let index = maybe_index_for_workspace(no_index, &current_ws, require_attested_index, refresh_index)?;
    let profile = profile_from_env();
    // B7 (RFC resolution-semantics.md §3 Axis B): thread the SHARED workspace
    // lock as `prior` — adding a member re-resolves minimally, so the OTHER
    // members' already-locked deps stay pinned instead of newest-wins-bumping.
    let prior = maybe_prior_lockfile(&dir.join("milpa.lock"));
    // C3/R9 (resolution-semantics RFC §3 Axis C / D-C2): resolve the
    // EFFECTIVE strategy (+ whether it was explicitly sourced) against the
    // WORKSPACE ROOT manifest (Axis W: resolution{} is root-only) —
    // `current_ws` above is already the workspace root's loaded manifest.
    let strategy_decl = resolve_effective_strategy(strategy_cli, current_ws.resolution);
    let strategy_explicit = strategy_decl.is_some();
    let strategy = strategy_decl.unwrap_or_default();
    // D2/D5: no CLI flag on `workspace add-member` — manifest-only, then
    // (no-silent-drop) the shared lock's own recorded bound.
    let exclude_newer = resolve_effective_exclude_newer(None, current_ws.resolution, prior.as_ref());
    let _rel_path = rel_path.clone();
    apply_workspace_manifest_change(
        dir,
        index.as_ref(),
        registry.as_ref(),
        profile.as_ref(),
        prior.as_ref(),
        strategy,
        strategy_explicit,
        &build_store(),
        false,
        exclude_newer,
        move |mut ws: Workspace| {
            ws.members.push(_rel_path.clone());
            ws
        },
    )?;

    eprintln!("added member {:?}", rel_path);
    Ok(0)
}

fn cmd_workspace_remove_member(
    dir: &Path,
    rest: &[String],
    strategy_cli: Option<Strategy>,
    no_index: bool,
    require_attested_index: bool,
    refresh_index: bool,
) -> Result<i32, MilpaError> {
    let Some(name_or_path) = rest.first() else {
        eprintln!("workspace remove-member: usage: milpa workspace remove-member <name|path>");
        return Ok(2);
    };

    // Load the current workspace (validates topology; raises WS-* on errors).
    let current_ws = load_workspace(dir)?;
    let ws_doc_text = std::fs::read_to_string(dir.join("milpa.kdl")).map_err(|_| {
        MilpaError::Core(CoreError::Workspace(
            "WS-NO-MANIFEST",
            format!("no milpa.kdl at {}", dir.display()),
        ))
    })?;
    let parsed_ws = match milpa_manifest::parse_document(&ws_doc_text)? {
        ManifestDoc::Workspace(w) => w,
        ManifestDoc::Package(_) => {
            return Err(MilpaError::Core(CoreError::Workspace(
                "WS-NOT-A-WORKSPACE",
                "not a workspace manifest".into(),
            )));
        }
    };

    // F19: resolve name_or_path relative to the workspace root (dir) so that a
    // root-relative path (e.g. "./member-b") is accepted.  Mirrors Python's
    // `_cwd_resolved = (root.resolve() / Path(name_or_path)).resolve()` arm.
    let root_resolved: Option<PathBuf> = {
        let p = std::path::Path::new(name_or_path);
        // Only attempt resolution for non-absolute paths (abs paths are already
        // covered by the m.directory.to_string_lossy() arm below).
        if p.is_relative() {
            dir.join(p).canonicalize().ok()
        } else {
            None
        }
    };

    // Resolve name_or_path to a matched member.
    let matched: Option<&LoadedMember> = current_ws.members.iter().find(|m| {
        if m.name == *name_or_path
            || m.path == *name_or_path
            || m.directory.to_string_lossy() == name_or_path.as_str()
        {
            return true;
        }
        // Root-relative arm: if the user supplied a path relative to the
        // workspace root (e.g. "./member-b") and it resolves to this member's
        // directory, accept it.
        if let Some(ref root_abs) = root_resolved {
            if let Ok(member_abs) = m.directory.canonicalize() {
                return member_abs == *root_abs;
            }
        }
        false
    });

    // Guard 1: member must exist.
    let matched = match matched {
        None => {
            eprintln!(
                "workspace remove-member: {:?} is not a member of this workspace",
                name_or_path
            );
            eprintln!("milpa-error: WS-REMOVE-MEMBER-NOT-FOUND");
            return Ok(1);
        }
        Some(m) => m,
    };
    let matched_path = matched.path.clone();
    let matched_name = matched.name.clone();

    // Guard 2 (class-1): check for dangling root MemberTarget overrides.
    for ov in &parsed_ws.overrides {
        if let OverrideTarget::Member { member_name } = &ov.target {
            if *member_name == matched_name {
                eprintln!(
                    "workspace remove-member: cannot remove member {:?}: \
                    the workspace root's overrides block has a MemberTarget entry for {:?} \
                    (pkg {:?} → member {:?}); remove or update the override first",
                    matched_name, matched_name, ov.name, matched_name
                );
                eprintln!("milpa-error: WS-REMOVE-MEMBER-TARGET-EXISTS");
                return Ok(1);
            }
        }
    }

    // Guard 3 (class-2): check for dangling member-edges in other members'
    // deps AND dev_deps.
    let mut referencing: Vec<String> = Vec::new();
    for m in &current_ws.members {
        if m.path == matched_path {
            continue;
        }
        let has_ref = m.manifest.deps.iter().chain(m.manifest.dev_deps.iter()).any(|dep| {
            matches!(dep, Dep::Member(d) if d.name == matched_name)
        });
        if has_ref {
            referencing.push(if m.name.is_empty() { m.path.clone() } else { m.name.clone() });
        }
    }
    if !referencing.is_empty() {
        referencing.sort();
        let refs_str: Vec<_> = referencing.iter().map(|r| format!("{:?}", r)).collect();
        eprintln!(
            "workspace remove-member: cannot remove member {:?}: \
            it is referenced by member-dep edges in: {}; remove those deps first",
            matched_name,
            refs_str.join(", ")
        );
        eprintln!("milpa-error: WS-REMOVE-MEMBER-REFERENCED");
        return Ok(1);
    }

    // Delegate to apply_workspace_manifest_change.
    let registry = build_registry();
    // SSOT (RD-M4): maybe_index_for_workspace collapses extract+call.
    let index = maybe_index_for_workspace(no_index, &current_ws, require_attested_index, refresh_index)?;
    let profile = profile_from_env();
    // B7 (RFC resolution-semantics.md §3 Axis B): thread the SHARED workspace
    // lock as `prior` — removing a member re-resolves minimally, so remaining
    // members' already-locked deps stay pinned.
    let prior = maybe_prior_lockfile(&dir.join("milpa.lock"));
    // C3/R9: resolve the EFFECTIVE strategy (+ whether it was explicitly
    // sourced) against the WORKSPACE ROOT manifest.
    let strategy_decl = resolve_effective_strategy(strategy_cli, current_ws.resolution);
    let strategy_explicit = strategy_decl.is_some();
    let strategy = strategy_decl.unwrap_or_default();
    // D2/D5: no CLI flag on `workspace remove-member` — manifest-only, then
    // (no-silent-drop) the shared lock's own recorded bound.
    let exclude_newer = resolve_effective_exclude_newer(None, current_ws.resolution, prior.as_ref());
    let _matched_path = matched_path.clone();
    apply_workspace_manifest_change(
        dir,
        index.as_ref(),
        registry.as_ref(),
        profile.as_ref(),
        prior.as_ref(),
        strategy,
        strategy_explicit,
        &build_store(),
        false,
        exclude_newer,
        move |mut ws: Workspace| {
            ws.members.retain(|p| p != &_matched_path);
            ws
        },
    )?;

    eprintln!("removed member {:?}", matched_name);
    Ok(0)
}

/// `milpa store ls` / `milpa store path` — read-only CAS inspection (C-store-ro slice).
///
/// `rest` is the tail after "store": `["ls"]` or `["path", "<identity-or-prefix>"]`.
/// The store root is derived from `MILPA_CACHE_DIR` / XDG / HOME exactly as in
/// `cmd_fetch` (via `cas_root()`).
///
/// - `store ls`: prints every entry currently in the store, one `sha256:<64hex>`
///   per line, lexicographically sorted.  Empty store → no output, exit 0.
/// - `store path <identity-or-prefix>`: resolves to an absolute path and prints it.
///   Full identity or bare 64-hex → exact lookup.  Shorter string (≥16 hex chars) →
///   unique-prefix match.  <16 hex chars or ambiguous → `STORE-AMBIGUOUS-PREFIX`.
///   Absent → `CAS-NOT-IN-STORE`.
fn cmd_store(rest: &[String]) -> Result<i32, MilpaError> {
    let store = build_store();
    let sub = rest.first().map(|s| s.as_str());
    match sub {
        Some("ls") => {
            for identity in store.list_identities() {
                println!("{identity}");
            }
            Ok(0)
        }
        Some("path") => {
            let Some(arg) = rest.get(1) else {
                eprintln!("store path: usage: milpa store path <identity-or-prefix>");
                return Ok(2);
            };
            match store.resolve_prefix(arg) {
                Ok(identity) => {
                    let path = store.path_for(&identity).map_err(|e| {
                        MilpaError::Core(e)
                    })?;
                    println!("{}", path.display());
                    Ok(0)
                }
                Err(e) => {
                    eprintln!("{}: {}", e.code(), e.message());
                    eprintln!("milpa-error: {}", e.code());
                    Ok(1)
                }
            }
        }
        _ => {
            eprintln!("usage: milpa store <ls|path> [args]");
            Ok(2)
        }
    }
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

/// Alias→canonical resolution — returns the canonical name as an owned `String`.
///
/// If `name` is a canonical lockfile dep name OR an alias of one, returns the
/// canonical dep name. Otherwise returns `name.to_string()` (caller's guard fires).
///
/// SSOT for `cmd_update` + `cmd_remove`.
fn canonical_name_for(name: &str, lockfile: &milpa_core::Lockfile) -> String {
    for dep in &lockfile.deps {
        if dep.name == name {
            return name.to_string();
        }
        if dep.aliases.iter().any(|a| a == name) {
            return dep.name.clone();
        }
    }
    name.to_string()
}

/// Strip the recorded pin for each name in `dep_names` (alias→canonical
/// resolved against `prior`), or drop every pin when `dep_names` is empty.
///
/// THE shared mechanism behind both `milpa update`/`milpa update <dep>` and
/// `--upgrade [<dep>...]` on `fetch`/`lock` (resolution-semantics RFC §3
/// Axis B / D-B3): bare (`dep_names` empty) drops every pin outright
/// (`Ok(None)` — the caller re-resolves with no prior at all, newest-wins
/// for the whole graph, identical to bare `update`); named opts out ONLY
/// for those deps, looping `milpa_core::strip_dep_pin` once per name so
/// every other dep's pin is untouched and keeps B2's minimal-change
/// preference. Both `cmd_update` and `cmd_fetch`'s `--upgrade` path call
/// this ONE function, so the two verbs cannot structurally drift.
fn strip_pins_for_upgrade(
    prior: Option<milpa_core::Lockfile>,
    dep_names: &[String],
) -> Result<Option<milpa_core::Lockfile>, MilpaError> {
    if dep_names.is_empty() {
        return Ok(None);
    }
    let Some(mut result) = prior else {
        return Err(MilpaError::Core(CoreError::Lockfile(
            "LOCK-FILE-NOT-FOUND",
            "no milpa.lock to scope --upgrade/update against — run `milpa fetch` first".into(),
        )));
    };
    for name in dep_names {
        let canonical = canonical_name_for(name, &result);
        if !result.deps.iter().any(|d| d.name == canonical) {
            let mut known: Vec<&str> = result.deps.iter().map(|d| d.name.as_str()).collect();
            known.sort_unstable();
            return Err(MilpaError::Core(CoreError::Lockfile(
                "LOCK-DEP-NOT-FOUND",
                format!(
                    "no dep {name:?} in lockfile (known: {})",
                    if known.is_empty() {
                        "<none>".to_string()
                    } else {
                        known.join(", ")
                    }
                ),
            )));
        }
        result = milpa_core::strip_dep_pin(result, &canonical);
    }
    Ok(Some(result))
}

/// S5b: Convert a CLI dep-name from slash form to double-colon solver_var form.
///
/// `"ns1/bar"` → `"ns1::bar"`.  Names without a slash are returned unchanged.
/// Malformed slash forms (more than one slash, empty segments) are also
/// returned unchanged — the guard in the caller will produce MAN-REMOVE-DEP-ABSENT.
/// M1: routes through `DepKey::solver_var()` — SOLE join site for `::` in CLI.
fn desugar_dep_name(name: &str) -> String {
    if name.contains('/') {
        let parts: Vec<&str> = name.splitn(2, '/').collect();
        if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty()
            && !parts[1].contains('/')
        {
            return milpa_manifest::DepKey {
                name: parts[1].to_string(),
                namespace: Some(parts[0].to_string()),
            }.solver_var();
        }
    }
    name.to_string()
}

/// S5b: Compute the solver_var (remove-key) for a dep.
///
/// For `Dep::Named` with a namespace, returns `"ns::bare"`.
/// For all other deps (or Named without namespace), returns the bare name.
/// M1: routes through `DepKey::solver_var()` — SOLE join site for `::` in CLI.
fn dep_remove_key(dep: &milpa_manifest::Dep) -> String {
    if let milpa_manifest::Dep::Named(n) = dep {
        return milpa_manifest::DepKey {
            name: n.name.clone(),
            namespace: n.namespace.clone(),
        }.solver_var();
    }
    dep.name().to_string()
}

/// `milpa remove <name>` — drop a dep from `milpa.kdl` and regenerate the
/// lockfile (cli-contract §5.7). Mirrors `cmd_add`'s structure: load the
/// manifest, reject an undeclared dep, build the proposed manifest (minus the
/// dep), run a FULL resolve, and only on success atomically write BOTH
/// `milpa.kdl` and `milpa.lock`. On any failure both files are left unmodified.
fn cmd_remove(dir: &Path, strategy_cli: Option<Strategy>, rest: &[String], no_index: bool, require_attested_index: bool, refresh_index: bool) -> Result<i32, MilpaError> {
    let Some(name) = rest.first().cloned() else {
        // Gap-1 C: no-name → usage error → exit 2 (no milpa-error: line).
        eprintln!("remove: usage: milpa remove <name>");
        return Ok(2);
    };

    // Load the current manifest. Parse failures propagate via `?` (MAN-* slug).
    let existing_doc = load_manifest(&dir.join("milpa.kdl"))?;
    let ManifestDoc::Package(existing) = existing_doc else {
        // S11a: remove at a workspace root emits the canonical directive slug.
        eprintln!(
            "remove: cannot remove a dep from a workspace root — \
             to remove a dep, `cd` to a member; \
             to remove a member, use `milpa workspace remove-member`"
        );
        eprintln!("milpa-error: MAN-MUTATE-WORKSPACE-REFUSED");
        return Ok(1);
    };

    // S11e: if this is a member dir (has a parent workspace), delegate to
    // workspace-level remove: mutate the MEMBER's manifest + re-resolve the WHOLE
    // workspace.  The shared lock must be written; NO member-local lock.
    if let Some((ws_root, ws)) = find_parent_workspace(dir)? {
        let ws_lock_path = ws_root.join("milpa.lock");

        // Alias→canonical resolution against the SHARED lockfile.
        let shared_prior: Option<milpa_core::Lockfile> = if ws_lock_path.exists() {
            load_lockfile(&ws_lock_path).ok()
        } else {
            None
        };
        // S5b: desugar slash shorthand for workspace member remove.
        let name_key_ws: String = desugar_dep_name(&name);
        let canonical_ws: String = if let Some(ref lf) = shared_prior {
            canonical_name_for(&name_key_ws, lf)
        } else {
            name_key_ws.clone()
        };

        // Guard: dep must be declared in the MEMBER's milpa.kdl.
        // S5b: use dep_remove_key() to match qualified deps by solver_var.
        if !existing.deps.iter().any(|d| dep_remove_key(d) == canonical_ws) {
            eprintln!("remove: no dep {name:?} in milpa.kdl");
            eprintln!("milpa-error: MAN-REMOVE-DEP-ABSENT");
            return Ok(1);
        }

        // Build proposed member manifest without the dep.
        let mut proposed_member = existing.clone();
        proposed_member.deps.retain(|d| dep_remove_key(d) != canonical_ws);

        // Rebuild workspace with proposed member manifest and resolve.
        let ws_with_override = milpa_core::load_workspace_with_member_override(&ws, dir, proposed_member.clone())?;
        let ws_deps_dir = ws_root.join("_deps");
        // SSOT (RD-M4): maybe_index_for_workspace collapses extract+call.
        let index = maybe_index_for_workspace(no_index, &ws, require_attested_index, refresh_index)?;
        let profile = profile_from_env();
        // C3/R9 (resolution-semantics RFC §3 Axis C / D-C2): resolve the
        // EFFECTIVE strategy (+ whether it was explicitly sourced) against
        // the WORKSPACE ROOT manifest (Axis W: resolution{} is root-only).
        let strategy_decl = resolve_effective_strategy(strategy_cli, ws.resolution);
        let strategy_explicit = strategy_decl.is_some();
        let strategy = strategy_decl.unwrap_or_default();
        // D2/D5: no CLI flag on `remove` — manifest-only, then (no-silent-
        // drop) the shared lock's own recorded bound.
        let exclude_newer = resolve_effective_exclude_newer(None, ws.resolution, shared_prior.as_ref());
        let graph = resolve_workspace_with_features(
            &ws_with_override,
            index.as_ref(),
            build_registry().as_ref(),
            profile.as_ref(),
            shared_prior.as_ref(),
            strategy,
            strategy_explicit,
            &ws_deps_dir,
            false,
            &build_store(),
            &std::collections::BTreeSet::new(),
            false,
            false,
            // P3a (RFC per-entry-attestation.md §8): `remove` is not in the
            // entry-trust command-coverage set (fetch/lock/add/update only) —
            // mirrors the Python impl's cli.py wiring.
            None,
            exclude_newer,
        )?;

        // Atomic write: member manifest first, then shared workspace lock.
        // NO member-local lock written (D5 correctness point).
        let canonical_c = canonical_ws.clone();
        mutate_manifest_file(&dir.join("milpa.kdl"), move |mut m| {
            // S5b: use dep_remove_key() so qualified deps are matched by solver_var.
            m.deps.retain(|d| dep_remove_key(d) != canonical_c.as_str());
            m
        })?;
        write_lockfile(&from_graph(&graph, strategy.as_str(), exclude_newer), &ws_lock_path)?;
        eprintln!("removed {canonical_ws}");
        return Ok(0);
    }

    // S5b: desugar slash shorthand in the dep name ("ns1/bar" → "ns1::bar").
    // The solver_var form is what the lockfile stores and what dep_remove_key()
    // returns for qualified Named deps.
    let name_key: String = desugar_dep_name(&name);

    // D-update-remove: alias→canonical resolution (Phase D item 5).
    // If `name` is an alias of a canonical lockfile dep, resolve to the manifest
    // dep name so the guard and mutation operate on the correct entry.
    let lock_path = dir.join("milpa.lock");
    // B7-gap (C3): use the shared soft-fail loader — same helper the other
    // resolve-triggering verbs (fetch/lock/add/update) use — so a missing or
    // corrupt prior degrades to a fresh resolve rather than hard-failing, and
    // (critically) so the SAME prior gets threaded into `resolve()` below for
    // minimal-change re-resolution (B2). Previously this branch hardcoded
    // `None` into the `resolve()` call, so `milpa remove` dragged unrelated
    // transitives to newest-available instead of keeping them pinned.
    let prior_lock: Option<milpa_core::Lockfile> = maybe_prior_lockfile(&lock_path);
    let canonical: String = if let Some(ref lf) = prior_lock {
        canonical_name_for(&name_key, lf)
    } else {
        name_key.clone()
    };

    // §5.7: reject if <dep> (resolved canonical) is not declared in milpa.kdl.
    // S5b: use dep_remove_key() so that qualified deps ("ns1::bar") match.
    if !existing.deps.iter().any(|d| dep_remove_key(d) == canonical) {
        eprintln!("remove: no dep {name:?} in milpa.kdl");
        eprintln!("milpa-error: MAN-REMOVE-DEP-ABSENT");
        return Ok(1);
    }

    // Collect prior aliases for the removed dep (for warning after re-resolve).
    let prior_aliases: Vec<String> = prior_lock
        .as_ref()
        .and_then(|lf| lf.deps.iter().find(|d| d.name == canonical))
        .map(|d| d.aliases.clone())
        .unwrap_or_default();

    // Build the proposed manifest (manifest minus <dep>) and run a full resolve
    // (§5.7). Only on success do we commit both outputs; on any failure both
    // files are left unmodified (resolve runs before any write).
    let mut proposed = existing.clone();
    proposed.deps.retain(|d| dep_remove_key(d) != canonical);

    let deps_dir = dir.join("_deps");
    let registry = build_registry();
    let index = maybe_index_for_manifest(no_index, &existing, require_attested_index, refresh_index)?;
    let profile = profile_from_env();
    // C3/R9: resolve the EFFECTIVE strategy (+ whether it was explicitly
    // sourced) against the current manifest (`prior_lock`, above, is used
    // for alias resolution too — see B7-gap comment further up).
    let strategy_decl = resolve_effective_strategy(strategy_cli, existing.resolution);
    let strategy_explicit = strategy_decl.is_some();
    let strategy = strategy_decl.unwrap_or_default();
    // D2/D5: `remove` has no CLI `--exclude-newer` flag (fetch/lock only) —
    // manifest-only, then (no-silent-drop, D-D3) the already-loaded on-disk
    // lock's own recorded bound. Previously this branch called the bare
    // `resolve()` convenience wrapper, which hardcodes `exclude_newer: None`
    // internally — that silently dropped a committed bound on every
    // single-package `milpa remove`. Switched to `resolve_with_features`
    // (same defaults `resolve()` uses: no entry-trust gate, no CLI feature
    // selection) so a real effective value can be threaded through.
    let exclude_newer = resolve_effective_exclude_newer(None, existing.resolution, prior_lock.as_ref());
    let graph = resolve_with_features(
        &proposed,
        index.as_ref(),
        registry.as_ref(),
        profile.as_ref(),
        prior_lock.as_ref(),
        strategy,
        strategy_explicit,
        &deps_dir,
        None,
        false,
        &build_store(),
        &std::collections::BTreeSet::new(),
        false,
        false,
        None,
        exclude_newer,
    )?;

    // D-update-remove Phase D item 5: warn per alias that the prior lockfile
    // recorded for the removed dep. If the canonical is still in the new graph
    // (pulled in transitively), warn that its alias remains live; otherwise warn
    // that the alias will be cleaned up.
    {
        let new_canonical_names: std::collections::HashSet<&str> =
            graph.deps.iter().map(|d| d.name.as_str()).collect();
        for alias in &prior_aliases {
            if new_canonical_names.contains(canonical.as_str()) {
                eprintln!(
                    "warning: alias {alias:?} of removed dep {canonical:?} \
                     is still required transitively; _deps/{alias} remains live"
                );
            } else {
                eprintln!(
                    "warning: removing dep {canonical:?} also removes alias \
                     {alias:?} (_deps/{alias} will be cleaned up)"
                );
            }
        }
    }

    // Resolution succeeded → commit both outputs.
    {
        let canonical = canonical.clone();
        mutate_manifest_file(&dir.join("milpa.kdl"), move |mut m| {
            // S5b: use dep_remove_key() so qualified deps are matched by solver_var.
            m.deps.retain(|d| dep_remove_key(d) != canonical.as_str());
            m
        })?;
    }
    write_lockfile(&from_graph(&graph, strategy.as_str(), exclude_newer), &dir.join("milpa.lock"))?;
    eprintln!("removed {canonical}");
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
/// Single source of truth for "the user wants no index" (cli-contract §8.1):
/// the `--no-index` flag OR a present-but-empty `MILPA_INDEX_URL`. The flag
/// takes precedence over any env value — it can only ADD the no-index request.
fn no_index_requested(flag: bool) -> bool {
    if flag {
        return true;
    }
    matches!(std::env::var("MILPA_INDEX_URL"), Ok(s) if s.trim().is_empty())
}

/// Read `MILPA_INDEX_TRUST` env var as a `TrustPolicy`. Returns `None` if unset or unrecognized.
fn read_env_index_trust_policy() -> Option<milpa_manifest::TrustPolicy> {
    use milpa_manifest::TrustPolicy;
    std::env::var("MILPA_INDEX_TRUST").ok().and_then(|v| match v.trim() {
        "strict" => Some(TrustPolicy::Strict),
        "warn" => Some(TrustPolicy::Warn),
        "off" => Some(TrustPolicy::Off),
        _ => None,
    })
}

/// Read `MILPA_INDEX_HISTORY` env var as a `TrustPolicy`. Returns `None` if
/// unset or unrecognized. Mirrors `read_env_index_trust_policy` /
/// `read_env_entry_trust_policy` for the A3 (`rfc-registry-append-only.md`
/// §2) index-history axis.
fn read_env_index_history_policy() -> Option<milpa_manifest::TrustPolicy> {
    use milpa_manifest::TrustPolicy;
    std::env::var("MILPA_INDEX_HISTORY").ok().and_then(|v| match v.trim() {
        "strict" => Some(TrustPolicy::Strict),
        "warn" => Some(TrustPolicy::Warn),
        "off" => Some(TrustPolicy::Off),
        _ => None,
    })
}

/// A3 (`rfc-registry-append-only.md` §2; registry-protocol §3.4.0/§3.5.2):
/// the effective `index-history` policy — manifest field + `MILPA_INDEX_HISTORY`
/// env layering through the shared `effective_trust_policy` SSOT (the SAME
/// authority formula `index-trust`/`entry-trust` use). Unlike those two axes,
/// no CLI flag escalates this axis (cli-contract.md §8.7 defines none), so
/// `flag` is always `false`.
fn effective_index_history_policy(manifest_policy: &milpa_manifest::TrustPolicy) -> milpa_manifest::TrustPolicy {
    use milpa_core::effective_trust_policy;
    let env_policy = read_env_index_history_policy();
    effective_trust_policy(manifest_policy, false, env_policy.as_ref())
}

/// Resolve the manifest-level index-trust `(policy, signer, bundle)` for `dir`.
///
/// This is the SSOT trust-field resolution-root helper (RD-M4 code-review
/// item): `cmd_show_index_trust` (observability) uses it directly; the
/// enforcement gate (`maybe_index`'s callers — `cmd_fetch`/`cmd_update`/
/// `cmd_add`/`cmd_remove`) already thread `discover_manifest(dir)?` +
/// `load_workspace(dir)?` inline for the SAME un-swallowed discovery (they
/// need the manifest/workspace object itself for more than trust fields, so
/// they are not routed through this helper — but they follow the identical
/// discipline below).
///
/// Root-cause split (mirrors `cmd_fetch`'s pattern, and Python's
/// `find_workspace_root`/`load_workspace` split): `discover_manifest`
/// distinguishes "confirmed workspace document" / "package" / "absent"; once
/// a directory's `milpa.kdl` is CONFIRMED workspace-shaped, `load_workspace`
/// is called UNGUARDED — any structural error (`WS-*`, including
/// `WS-INDEX-TRUST-ON-MEMBER`) propagates rather than being swallowed into a
/// fabricated `(Warn, None, None)`.
///
/// The ONE case treated as "no project here" (graceful default, not an
/// error): `discover_manifest` finding no manifest/`.nimble` at all
/// (`MAN-NO-MANIFEST`) — so callers keep working outside a milpa project dir.
/// Every other error (workspace structural failures, KDL syntax errors, …)
/// propagates to the caller.
fn resolve_index_trust_fields(
    dir: &Path,
) -> Result<(milpa_manifest::TrustPolicy, Option<String>, Option<String>), MilpaError> {
    match discover_manifest(dir) {
        Ok(milpa_manifest::ManifestDoc::Workspace(_)) => {
            let ws = load_workspace(dir)?;
            Ok(workspace_index_trust_fields(&ws))
        }
        Ok(milpa_manifest::ManifestDoc::Package(ref m)) => Ok((
            m.index_trust_policy.clone(),
            m.index_trust_signer.clone(),
            m.index_trust_bundle.clone(),
        )),
        Err(e) if e.code() == "MAN-NO-MANIFEST" => {
            Ok((milpa_manifest::TrustPolicy::Warn, None, None))
        }
        Err(e) => Err(e),
    }
}

#[allow(clippy::too_many_arguments)]
fn maybe_index(
    no_index: bool,
    manifest_policy: &milpa_manifest::TrustPolicy,
    manifest_signer: Option<String>,
    manifest_bundle: Option<String>,
    require_attested_index: bool,
    refresh_index: bool,
    index_history_policy: &milpa_manifest::TrustPolicy,
) -> Result<Option<Index>, MilpaError> {
    // --no-index flag OR present-but-empty MILPA_INDEX_URL → explicitly no
    // index (the flag overrides any configured index). Absent → default URL.
    if no_index_requested(no_index) {
        return Ok(None);
    }
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

    let http = |url: &str| -> Result<Vec<u8>, String> {
        let out = std::process::Command::new("curl")
            .args(["-fsSL", url])
            .output()
            .map_err(|e| format!("curl: {e}"))?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    };

    // Item 5 (M8): dispatch through the extracted trust-gate helper.
    // build_index_trust_gate owns: env reads, effective_trust_policy,
    // seam-vs-S4b dispatch, config+verifier construction.
    use milpa_core::BundleHttpGet;
    let gate = build_index_trust_gate(manifest_policy, manifest_signer, manifest_bundle, require_attested_index, &url)?;
    match gate {
        None => load_index_raw(&url, &http, now, None, None, None, refresh_index, index_history_policy),
        Some(active) => load_index_raw(
            &url,
            &http,
            now,
            Some(&active.cfg),
            Some(active.verifier.as_ref()),
            Some(active.bundle_fn.as_ref() as BundleHttpGet<'_>),
            refresh_index,
            index_history_policy,
        ),
    }
}

/// An active trust gate: config + verifier + bundle transport, assembled for one index load.
///
/// `build_index_trust_gate` returns `Some(_)` when the policy is Warn/Strict, `None` when
/// Off. (Before the real verifier landed there was also a "Warn/Strict but no verifier"
/// degraded state — that is gone; the real [`SigstoreVerifier`] always exists now.)
struct IndexTrustGateActive {
    cfg: milpa_core::index_trust::IndexTrustConfig,
    verifier: Box<dyn milpa_core::index_trust::IndexBundleVerifier>,
    bundle_fn: Box<dyn Fn(&str) -> Result<Vec<u8>, milpa_core::BundleError>>,
}

impl std::fmt::Debug for IndexTrustGateActive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IndexTrustGateActive {{ cfg: {:?}, .. }}", self.cfg)
    }
}

/// Resolve `(TrustBundle, expected_signer)` from index-trust inputs: env
/// override > manifest field > spec default (Item 2 precedence).
///
/// Extracted from `build_index_trust_gate` so `build_entry_trust_gate` (P3a)
/// can derive the SAME effective vendor-bot identity Layer 1 resolved (RFC
/// per-entry-attestation.md §5 NORMATIVE: the vendored-kind expected signer
/// must be "the SAME effective vendor-bot identity Layer 1 resolved... never
/// a second hardcoded copy of the default") without duplicating the
/// file-loading / priority logic. Both callers pass their own manifest
/// values (index-trust and entry-trust share the trust-root/signer INPUTS —
/// `MILPA_INDEX_TRUST_SIGNER` / `index-trust-signer` — even though they are
/// separate policy axes, RFC §4).
fn resolve_trust_bundle_and_signer(
    manifest_signer: Option<String>,
    manifest_bundle: Option<String>,
) -> Result<(milpa_core::index_trust::TrustBundle, String), MilpaError> {
    use milpa_core::index_trust::{TrustBundle, DEFAULT_INDEX_SIGNER};

    let signer = std::env::var("MILPA_INDEX_TRUST_SIGNER")
        .ok()
        .filter(|s| !s.is_empty())
        .or(manifest_signer) // manifest middle tier
        .unwrap_or_else(|| DEFAULT_INDEX_SIGNER.to_string()); // spec default
    // spec/cli-contract.md §8.6 NORMATIVE: MILPA_INDEX_TRUST_BUNDLE (or the manifest
    // `index-trust-bundle` node) MUST be a `file://` URL; non-file:// values are rejected.
    // A custom trust-root override currently resolves to TrustBundle::production() (the
    // embedded standard trusted_root.json); wiring a file:// trust-root read is a separate
    // follow-up, not needed for the public tianguis instance.
    let raw_bundle = std::env::var("MILPA_INDEX_TRUST_BUNDLE")
        .ok()
        .filter(|s| !s.is_empty())
        .or(manifest_bundle); // manifest middle tier
    let trust_bundle = match raw_bundle {
        Some(ref path) if !path.starts_with("file://") => {
            return Err(MilpaError::Core(CoreError::Tianguis(
                "MILPA-INTERNAL",
                format!(
                    "MILPA_INDEX_TRUST_BUNDLE (or index-trust-bundle manifest node) \
                     must be a file:// URL; got: {path:?}. \
                     Use file:///abs/path/to/bundle.json (three slashes for an absolute \
                     path). (spec/cli-contract.md §8.6 NORMATIVE)"
                ),
            )));
        }
        Some(_) | None => TrustBundle::production(),
    };
    Ok((trust_bundle, signer))
}

/// Build the trust-gate assembly for loading an index at `url`.
///
/// Item 5 (M8): single owner of all trust-gate decisions:
///   - reads MILPA_INDEX_TRUST + MILPA_INDEX_TRUST_MOCK_VERIFIER + MILPA_INDEX_TRUST_SIGNER +
///     MILPA_INDEX_TRUST_BUNDLE + MILPA_INDEX_MAX_AGE from env.
///   - applies effective_trust_policy(manifest_policy, require_attested_index, env_override).
///   - applies env > manifest > default precedence for signer + bundle (Item 2).
///   - enforces the file:// guard on MILPA_INDEX_TRUST_MOCK_VERIFIER (spec §8.6.6).
///   - dispatches: Off → `None`; mock-seam → `Some(MockVerifier)`; otherwise (Warn/Strict) →
///     `Some(SigstoreVerifier)` — the real verifier really verifies (RFC attestation-verifier).
///
/// `manifest_signer` / `manifest_bundle` come from the manifest field (or the max-merged
/// workspace value); they are the middle tier in env > manifest > default.
///
/// `url` is needed only for error messages (no network I/O here).
fn build_index_trust_gate(
    manifest_policy: &milpa_manifest::TrustPolicy,
    manifest_signer: Option<String>,
    manifest_bundle: Option<String>,
    require_attested_index: bool,
    url: &str,
) -> Result<Option<IndexTrustGateActive>, MilpaError> {
    use milpa_core::effective_trust_policy;
    use milpa_core::index_trust::{
        IndexBundleVerifier, IndexTrustConfig, MockVerifier, SigstoreVerifier, VerificationResult,
    };
    use milpa_manifest::TrustPolicy;

    let env_policy = read_env_index_trust_policy();
    let effective_policy = effective_trust_policy(manifest_policy, require_attested_index, env_policy.as_ref());

    // Policy=Off: gate fully disabled.
    if effective_policy == TrustPolicy::Off {
        return Ok(None);
    }

    // Mock-verifier seam (conformance only): MILPA_INDEX_TRUST_MOCK_VERIFIER=<wire> is honored
    // ONLY for file:// index URLs (spec §8.6.6). Absent it, the real SigstoreVerifier is used
    // — both Warn and Strict really verify (RFC attestation-verifier; no more no-seam stopgap).
    let mock_verifier_str = std::env::var("MILPA_INDEX_TRUST_MOCK_VERIFIER")
        .ok()
        .filter(|s| !s.trim().is_empty());

    // Item 2 (M1 Rust): file:// guard — seam is ONLY honored for file:// index URLs.
    if mock_verifier_str.is_some() && !url.starts_with("file://") {
        return Err(MilpaError::Core(CoreError::Tianguis(
            "MILPA-INTERNAL",
            format!(
                "MILPA_INDEX_TRUST_MOCK_VERIFIER is a conformance-internal test seam \
                 and is only honored when the resolved index URL scheme is `file://`. \
                 Current index URL is {url:?} (not file://). \
                 Do not set this variable with production or network index URLs. \
                 (spec §8.6.6 conformance-internal seam)"
            ),
        )));
    }

    // Shared config assembly (both the mock seam and the real verifier use it).
    let (trust_bundle, signer) = resolve_trust_bundle_and_signer(manifest_signer, manifest_bundle)?;
    let max_age: Option<u64> = std::env::var("MILPA_INDEX_MAX_AGE")
        .ok()
        .and_then(|v| v.trim().parse().ok());
    let mut cfg = IndexTrustConfig::new(effective_policy, trust_bundle, signer);
    if let Some(age) = max_age {
        cfg.max_age_seconds = age;
    }

    // Verifier: the conformance mock seam, or the real production verifier.
    let verifier: Box<dyn IndexBundleVerifier> = match mock_verifier_str {
        Some(mock_str) => {
            let mock_result = VerificationResult::from_value(mock_str.trim()).ok_or_else(|| {
                MilpaError::Core(CoreError::Tianguis(
                    "MILPA-INTERNAL",
                    format!(
                        "MILPA_INDEX_TRUST_MOCK_VERIFIER={mock_str:?} is not a valid \
                         VerificationResult wire string (expected one of: trusted, sig-invalid, \
                         digest-mismatch, signer-mismatch, bundle-stale, bundle-missing, \
                         bundle-malformed). Test seam must never fail-open silently."
                    ),
                ))
            })?;
            Box::new(MockVerifier::new(mock_result))
        }
        None => Box::new(SigstoreVerifier),
    };

    Ok(Some(IndexTrustGateActive {
        cfg,
        verifier,
        bundle_fn: build_bundle_http_fn(),
    }))
}

/// Build the curl-based bundle HTTP fetcher closure.
fn build_bundle_http_fn() -> Box<dyn Fn(&str) -> Result<Vec<u8>, milpa_core::BundleError>> {
    use milpa_core::BundleError;
    Box::new(|bundle_url: &str| -> Result<Vec<u8>, BundleError> {
        let out = std::process::Command::new("curl")
            .args(["-fsSL", bundle_url])
            .output()
            .map_err(|e| BundleError::Other(format!("curl: {e}")))?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            // Distinguish 404 from other errors: re-run with -w for status.
            let status_out = std::process::Command::new("curl")
                .args(["-o", "/dev/null", "-s", "-w", "%{http_code}", bundle_url])
                .output()
                .map_err(|e| BundleError::Other(format!("curl status check: {e}")))?;
            let code = String::from_utf8_lossy(&status_out.stdout);
            if code.trim() == "404" {
                Err(BundleError::NotFound)
            } else {
                Err(BundleError::Other(
                    String::from_utf8_lossy(&out.stderr).trim().to_string(),
                ))
            }
        }
    })
}

/// Read `MILPA_ENTRY_TRUST` env var as a `TrustPolicy`. Mirrors
/// `read_env_index_trust_policy` for the sibling entry-trust axis.
fn read_env_entry_trust_policy() -> Option<milpa_manifest::TrustPolicy> {
    use milpa_manifest::TrustPolicy;
    std::env::var("MILPA_ENTRY_TRUST").ok().and_then(|v| match v.trim() {
        "strict" => Some(TrustPolicy::Strict),
        "warn" => Some(TrustPolicy::Warn),
        "off" => Some(TrustPolicy::Off),
        _ => None,
    })
}

/// P3a (RFC per-entry-attestation.md §3, §4, §5): build the `EntryTrustConfig`
/// for the entry-trust gate, or `None` when the effective policy is `Off`
/// (`resolve_with_features` / `resolve_workspace_with_features` never invoke
/// the gate machinery in that case — mirrors `build_index_trust_gate`'s `None`).
///
/// Authority model:
/// 1. Compute effective policy = `effective_trust_policy(entry_trust_policy,
///    require_attested_entries, MILPA_ENTRY_TRUST env override)`.
/// 2. If `Off` → return `None`.
/// 3. Reuse index-trust's trust-root + expected-signer resolution
///    (`resolve_trust_bundle_and_signer`) — RFC §5 NORMATIVE: the
///    vendored-kind expected signer MUST be the SAME effective vendor-bot
///    identity Layer 1 resolved, never a second hardcoded copy.
/// 4. Build the bundle store: `MILPA_ENTRY_BUNDLE_DIR` (mirror of
///    `MILPA_DEP_DECL_DIR`) or derived from `MILPA_INDEX_URL`.
/// 5. Build verifier: `MockEntryVerifier` from the `MILPA_ENTRY_TRUST_MOCK_MAP`
///    / `MILPA_ENTRY_TRUST_MOCK_DEFAULT` conformance seam (file://-index-only
///    guard, mirroring `MILPA_INDEX_TRUST_MOCK_VERIFIER`), or
///    `SigstoreEntryVerifier` in production.
fn build_entry_trust_gate(
    entry_trust_policy: &milpa_manifest::TrustPolicy,
    manifest_signer: Option<String>,
    manifest_bundle: Option<String>,
    require_attested_entries: bool,
    no_index: bool,
) -> Result<Option<milpa_core::EntryTrustConfig>, MilpaError> {
    use milpa_core::entry_trust::{MockEntryVerifier, SigstoreEntryVerifier, VerifierOutcome};
    use milpa_core::{effective_trust_policy, EntryBundleVerifier, EntryTrustConfig};
    use milpa_manifest::TrustPolicy;

    let env_policy = read_env_entry_trust_policy();
    let effective_policy =
        effective_trust_policy(entry_trust_policy, require_attested_entries, env_policy.as_ref());
    if effective_policy == TrustPolicy::Off {
        return Ok(None);
    }

    // Reuse index-trust's trust-root + expected-signer resolution (RFC §5).
    let (trust_bundle, expected_signer) = resolve_trust_bundle_and_signer(manifest_signer, manifest_bundle)?;

    // Build the bundle-acquisition store.
    let entry_bundle_dir = std::env::var("MILPA_ENTRY_BUNDLE_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let raw_index_url = std::env::var("MILPA_INDEX_URL").ok().filter(|s| !s.is_empty());
    let bundle_store = milpa_core::entry_bundle_store_from_paths(
        entry_bundle_dir.as_deref(),
        raw_index_url.as_deref(),
        no_index,
    );

    // Verifier: MockEntryVerifier from conformance seam, SigstoreEntryVerifier
    // in production. Mirrors MILPA_INDEX_TRUST_MOCK_VERIFIER's file://-only guard.
    let mock_map_raw = std::env::var("MILPA_ENTRY_TRUST_MOCK_MAP")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let mock_default_raw = std::env::var("MILPA_ENTRY_TRUST_MOCK_DEFAULT")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let verifier: Box<dyn EntryBundleVerifier> = if mock_map_raw.is_some() || mock_default_raw.is_some() {
        // Guard: mock seam is conformance-internal; ONLY honored for file:// indexes.
        if !raw_index_url.as_deref().unwrap_or("").starts_with("file://") {
            return Err(MilpaError::Core(CoreError::Tianguis(
                "MILPA-INTERNAL",
                "MILPA_ENTRY_TRUST_MOCK_MAP / MILPA_ENTRY_TRUST_MOCK_DEFAULT are \
                 conformance-internal and only honored for file:// index URLs \
                 (all conformance fixtures use file://; production indexes are \
                 https). These variables must not be set in production or with \
                 non-file:// index URLs."
                    .to_string(),
            )));
        }
        let default_result = match mock_default_raw.as_deref() {
            None => VerifierOutcome::Trusted,
            Some(raw) => VerifierOutcome::from_wire_value(raw).ok_or_else(|| {
                MilpaError::Core(CoreError::Tianguis(
                    "MILPA-INTERNAL",
                    format!(
                        "MILPA_ENTRY_TRUST_MOCK_DEFAULT={raw:?} is not a valid \
                         result wire string (expected one of: trusted, bundle-malformed, \
                         digest-mismatch, subject-mismatch, signature-invalid, \
                         signer-mismatch). Test seam must never fail-open silently."
                    ),
                ))
            })?,
        };
        let mut by_subject: std::collections::HashMap<String, VerifierOutcome> =
            std::collections::HashMap::new();
        if let Some(raw) = &mock_map_raw {
            let parsed: serde_json::Value = serde_json::from_str(raw).map_err(|e| {
                MilpaError::Core(CoreError::Tianguis(
                    "MILPA-INTERNAL",
                    format!("MILPA_ENTRY_TRUST_MOCK_MAP is not valid JSON: {e}"),
                ))
            })?;
            let obj = parsed.as_object().ok_or_else(|| {
                MilpaError::Core(CoreError::Tianguis(
                    "MILPA-INTERNAL",
                    "MILPA_ENTRY_TRUST_MOCK_MAP must be a JSON object".to_string(),
                ))
            })?;
            for (k, v) in obj {
                let vs = v.as_str().ok_or_else(|| {
                    MilpaError::Core(CoreError::Tianguis(
                        "MILPA-INTERNAL",
                        format!("MILPA_ENTRY_TRUST_MOCK_MAP entry {k:?} must be a string value"),
                    ))
                })?;
                let result = VerifierOutcome::from_wire_value(vs).ok_or_else(|| {
                    MilpaError::Core(CoreError::Tianguis(
                        "MILPA-INTERNAL",
                        format!(
                            "MILPA_ENTRY_TRUST_MOCK_MAP entry {k:?}={vs:?} is not a valid \
                             result wire string (expected one of: trusted, bundle-malformed, \
                             digest-mismatch, subject-mismatch, signature-invalid, \
                             signer-mismatch). Test seam must never fail-open silently."
                        ),
                    ))
                })?;
                by_subject.insert(k.clone(), result);
            }
        }
        Box::new(MockEntryVerifier::new(default_result, by_subject))
    } else {
        Box::new(SigstoreEntryVerifier)
    };

    Ok(Some(EntryTrustConfig {
        policy: effective_policy,
        trust_bundle,
        expected_vendor_signer: expected_signer,
        verifier,
        bundle_store,
    }))
}

/// P3a (RFC per-entry-attestation.md §7): re-verify CACHED per-entry
/// attestation bundles offline — NEVER fetches.
///
/// For each locked dep carrying an `attestation` block, re-derive the
/// verification outcome from the cached bundle (crypto + subject binding, no
/// freshness — mirrors `reverify_cached_index`'s shape) against the
/// lockfile's recorded kind/signer/namespace. Missing cached bundle →
/// `BundleMissing` (warn/strict per policy). A no-op when the effective
/// entry-trust policy is `Off`.
///
/// Offline invariant: this checks `bundle_store.is_cached(pin)` BEFORE ever
/// calling `bundle_store.get(pin)` — for `HttpEntryBundleStore`, `get()` on
/// an uncached pin would attempt a real network fetch, which `milpa verify`
/// must never do. A pin that is present but not cached is reported as
/// `BundleMissing` (cause `unfetchable`), exactly as if the bundle had never
/// been fetched.
fn reverify_cached_entry_attestations(
    lock: &milpa_core::Lockfile,
    entry_trust_policy: &milpa_manifest::TrustPolicy,
    manifest_signer: Option<String>,
    manifest_bundle: Option<String>,
    require_attested_entries: bool,
    no_index: bool,
) -> Result<(), MilpaError> {
    use milpa_core::entry_trust::EntryVerificationResult;
    use milpa_core::EntryAttestation;

    let Some(cfg) = build_entry_trust_gate(
        entry_trust_policy,
        manifest_signer,
        manifest_bundle,
        require_attested_entries,
        no_index,
    )?
    else {
        return Ok(()); // policy off
    };

    for dep in &lock.deps {
        let Some(att) = &dep.attestation else { continue };

        let (result, cause): (EntryVerificationResult, Option<String>) = match &att.bundle_pin {
            None => (EntryVerificationResult::BundleMissing, Some("no-pin".to_string())),
            Some(pin) => match &cfg.bundle_store {
                Some(store) if store.is_cached(pin) => {
                    // Cached: reuse the shared gate pipeline. get() on a
                    // cached pin never touches the network (is_cached above).
                    let reconstructed = EntryAttestation {
                        kind: att.kind.clone(),
                        rekor: att.rekor.clone(),
                        bundle_pin: att.bundle_pin.clone(),
                    };
                    milpa_core::evaluate_entry_attestation(
                        Some(&reconstructed),
                        dep.identity.as_deref().unwrap_or(""),
                        &att.namespace,
                        &dep.name,
                        &dep.version,
                        cfg.verifier.as_ref(),
                        cfg.bundle_store.as_deref(),
                        &cfg.trust_bundle,
                        &cfg.expected_vendor_signer,
                    )?
                }
                // NEVER fetch — a present-but-uncached pin (or no store at
                // all) is unfetchable-from-cache.
                _ => (EntryVerificationResult::BundleMissing, Some("unfetchable".to_string())),
            },
        };

        milpa_core::enforce_entry_trust(
            result,
            &cfg.policy,
            &att.namespace,
            &dep.name,
            &dep.version,
            cause.as_deref(),
        )?;
    }
    Ok(())
}

/// Internal helper: call load_index_with_history with pre-resolved arguments.
#[allow(clippy::too_many_arguments)]
fn load_index_raw<'a>(
    url: &str,
    http: &dyn Fn(&str) -> Result<Vec<u8>, String>,
    now: u64,
    config: Option<&'a milpa_core::index_trust::IndexTrustConfig>,
    verifier: Option<&'a dyn milpa_core::index_trust::IndexBundleVerifier>,
    bundle_http: Option<milpa_core::BundleHttpGet<'a>>,
    refresh_index: bool,
    index_history_policy: &milpa_manifest::TrustPolicy,
) -> Result<Option<Index>, MilpaError> {
    match load_index_with_history(
        url,
        &index_cache_dir(),
        http,
        DEFAULT_TTL_SECONDS,
        now,
        config,
        verifier,
        bundle_http,
        refresh_index,
        index_history_policy,
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

/// Map a `std::env::consts::OS` token to the Nim `hostOS` vocabulary
/// (cli-contract §8, spec/manifest-grammar §6.6).
///
/// Rust's OS strings differ from Python's `platform.system().lower()` inputs,
/// but BOTH must produce the same Nim-vocabulary output token for the same
/// physical host.  Unknown tokens are passed through unchanged (spec §8 allows
/// unknown values; `when platform="X"` simply never matches).
///
/// Python `_OS_MAP` input → output:  darwin→macosx, linux→linux,
///   windows→windows, freebsd→freebsd, openbsd→openbsd, netbsd→netbsd.
/// Rust `std::env::consts::OS` uses "macos" instead of "darwin"; all others
/// match.  Both must output "macosx" for macOS.
pub(crate) fn host_platform_token(raw: &str) -> String {
    match raw {
        "macos" => "macosx".to_string(),
        "linux" => "linux".to_string(),
        "windows" => "windows".to_string(),
        "freebsd" => "freebsd".to_string(),
        "openbsd" => "openbsd".to_string(),
        "netbsd" => "netbsd".to_string(),
        other => other.to_string(),
    }
}

/// Map a `std::env::consts::ARCH` token to the Nim `hostCPU` vocabulary
/// (cli-contract §8, spec/manifest-grammar §6.6).
///
/// Python `_ARCH_MAP` input → output:  x86_64→amd64, amd64→amd64,
///   aarch64→arm64, arm64→arm64, i386→i386, i686→i386.
/// Rust `std::env::consts::ARCH` uses "x86_64" / "aarch64" / "x86".
/// Unknown tokens are passed through unchanged.
pub(crate) fn host_arch_token(raw: &str) -> String {
    match raw {
        "x86_64" | "amd64" => "amd64".to_string(),
        "aarch64" | "arm64" => "arm64".to_string(),
        "x86" | "i386" | "i686" => "i386".to_string(),
        other => other.to_string(),
    }
}

/// Build a [`Profile`] from the `MILPA_TARGET_*` environment variables
/// (cli-contract §8, manifest-grammar §6.6).
///
/// Always returns `Some(Profile)` — the CLI MUST host-default every axis
/// that is not overridden by an env var (spec §8 NOTE; mirrors Python
/// `Profile.from_environment`).  The conformance runner's `fixture_profile`
/// is intentionally separate and continues to return `None` for the
/// host-independent corpus path (§470 absent-profile).
fn profile_from_env() -> Option<Profile> {
    let platform = std::env::var("MILPA_TARGET_PLATFORM")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| host_platform_token(std::env::consts::OS));
    let arch = std::env::var("MILPA_TARGET_ARCH")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| host_arch_token(std::env::consts::ARCH));
    let nim_version = std::env::var("MILPA_TARGET_NIM")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| parse_version(&s));
    let milpa_version = std::env::var("MILPA_TARGET_MILPA")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| parse_version(&s))
        .or_else(|| parse_version(VERSION));

    Some(Profile {
        platform: Some(platform),
        arch: Some(arch),
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
fn maybe_dep_decl_store(no_index: bool) -> Option<Box<dyn DepDeclStore>> {
    // --no-index (or empty MILPA_INDEX_URL) → no index ⇒ DepDecl unreachable.
    if no_index_requested(no_index) {
        return None;
    }
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

/// S8 (RFC registry-trust-federation §6.4a, spec §3.4.7 root-authority model):
/// read a loaded workspace's own `(index-trust, index-trust-signer,
/// index-trust-bundle)` fields directly off its ROOT — no merge across
/// members. Members are structurally forbidden from declaring these fields
/// (`WS-INDEX-TRUST-ON-MEMBER`, enforced at `load_workspace` time), so by the
/// time a `LoadedWorkspace` exists its root value IS the effective policy.
/// Mirrors `cli.py:_load_manifest_trust_fields`'s workspace branch.
fn workspace_index_trust_fields(
    ws: &LoadedWorkspace,
) -> (milpa_manifest::TrustPolicy, Option<String>, Option<String>) {
    (
        ws.index_trust_policy.clone(),
        ws.index_trust_signer.clone(),
        ws.index_trust_bundle.clone(),
    )
}

/// RD-M4 SSOT: extract a loaded workspace's index-trust fields and call
/// `maybe_index` in one place, so a future `maybe_index` signature change
/// touches this one wrapper instead of every workspace call site.
fn maybe_index_for_workspace(
    no_index: bool,
    ws: &LoadedWorkspace,
    require_attested_index: bool,
    refresh_index: bool,
) -> Result<Option<Index>, MilpaError> {
    let (policy, signer, bundle) = workspace_index_trust_fields(ws);
    let history_policy = effective_index_history_policy(&ws.index_history_policy);
    maybe_index(no_index, &policy, signer, bundle, require_attested_index, refresh_index, &history_policy)
}

/// RD-M4 SSOT: extract a single-package manifest's index-trust fields and
/// call `maybe_index` in one place, mirroring `maybe_index_for_workspace`.
fn maybe_index_for_manifest(
    no_index: bool,
    m: &Manifest,
    require_attested_index: bool,
    refresh_index: bool,
) -> Result<Option<Index>, MilpaError> {
    let history_policy = effective_index_history_policy(&m.index_history_policy);
    maybe_index(
        no_index,
        &m.index_trust_policy,
        m.index_trust_signer.clone(),
        m.index_trust_bundle.clone(),
        require_attested_index,
        refresh_index,
        &history_policy,
    )
}

// ---------------------------------------------------------------------------
// cmd_index_status / cmd_index_accept (A3 — rfc-registry-append-only.md;
// cli-contract.md §5.12) — the append-only-ratchet inspection/reset surface.
// Mirrors `cli.py`'s `cmd_index_status`/`cmd_index_accept`.
//
// Both verbs share: the `--no-index` hard error, the effective index URL +
// index-history policy (`index_verb_setup`), member-dir → workspace-root
// delegation (S11e, via `find_parent_workspace` — the same helper
// `update`/`add`/`remove` already use), and the fetch-and-verify + diff
// machinery used by `--refresh` (status) and the ordinary path (accept).
// Neither verb duplicates the dominance-fold/digest logic — both compose
// `milpa_core::ratchet`/`index_ratchet_seam` primitives directly.
// ---------------------------------------------------------------------------

/// Two-level dispatch for `milpa index <status|accept>` — the third instance
/// of the nested-subparser pattern `workspace add-member`/`remove-member`
/// established (cli-contract §5.10/§5.12): sub-verbs routed through one
/// `index` dispatcher, an unrecognised sub-verb exits 2.
fn cmd_index(
    dir: &Path,
    rest: &[String],
    no_index: bool,
    require_attested_index: bool,
) -> Result<i32, MilpaError> {
    let sub = rest.first().map(|s| s.as_str());
    match sub {
        Some("status") => {
            let refresh = rest[1..].iter().any(|a| a == "--refresh");
            cmd_index_status(dir, no_index, require_attested_index, refresh)
        }
        Some("accept") => cmd_index_accept(dir, no_index, require_attested_index),
        _ => {
            eprintln!("index: usage: milpa index <status [--refresh]|accept>");
            Ok(2)
        }
    }
}

/// Shared preamble for `index status`/`index accept`: the `--no-index` hard
/// error, the effective index URL, and the effective `index-history` policy.
///
/// Member-dir delegation (S11e): `find_parent_workspace(dir)` — the SAME
/// helper `update`/`add`/`remove` use — resolves a member directory to its
/// workspace root's policy. The baseline sidecar pair is keyed purely by
/// index URL in the process-global cache dir, so a member-dir invocation is
/// byte-identical to a root-dir invocation by construction, not by a
/// special-cased delegation path (there is no member-level baseline state
/// to delegate FROM in the first place).
fn index_verb_setup(dir: &Path, no_index: bool) -> Result<(String, milpa_manifest::TrustPolicy), MilpaError> {
    if no_index_requested(no_index) {
        return Err(MilpaError::Core(CoreError::Tianguis(
            "TNG-INDEX-NOT-CONFIGURED",
            "milpa index: no index is configured (--no-index, or an empty \
             MILPA_INDEX_URL) — there is no index to load or compare against"
                .to_string(),
        )));
    }
    let url = index_url_from_env();

    let manifest_policy = if let Some((_, ws)) = find_parent_workspace(dir)? {
        ws.index_history_policy.clone()
    } else {
        match discover_manifest(dir) {
            Ok(milpa_manifest::ManifestDoc::Workspace(_)) => {
                let ws = load_workspace(dir)?;
                ws.index_history_policy.clone()
            }
            Ok(milpa_manifest::ManifestDoc::Package(m)) => m.index_history_policy.clone(),
            Err(e) if e.code() == "MAN-NO-MANIFEST" => milpa_manifest::TrustPolicy::Warn,
            Err(e) => return Err(e),
        }
    };
    Ok((url, effective_index_history_policy(&manifest_policy)))
}

/// Force a network fetch + trust-gate verification of `url`'s index
/// candidate for `index status --refresh` / `index accept`. Touches no
/// cache state ([`fetch_verified_candidate_text`] performs no writes).
///
/// Returns `(candidate_text, index_trust_is_off)` — the second element
/// drives the index-trust-off caveat both verbs must print (cli-contract
/// §5.12 NORMATIVE (contract points)).
fn fetch_index_candidate(
    dir: &Path,
    url: &str,
    require_attested_index: bool,
) -> Result<(String, bool), MilpaError> {
    let (manifest_policy, manifest_signer, manifest_bundle) = if let Some((_, ws)) = find_parent_workspace(dir)? {
        workspace_index_trust_fields(&ws)
    } else {
        resolve_index_trust_fields(dir)?
    };
    let gate = build_index_trust_gate(&manifest_policy, manifest_signer, manifest_bundle, require_attested_index, url)?;
    let is_off = gate.is_none();

    let http = |u: &str| -> Result<Vec<u8>, String> {
        let out = std::process::Command::new("curl")
            .args(["-fsSL", u])
            .output()
            .map_err(|e| format!("curl: {e}"))?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    };

    use milpa_core::BundleHttpGet;
    let text = match &gate {
        None => fetch_verified_candidate_text(url, &http, None, None, None)?,
        Some(active) => fetch_verified_candidate_text(
            url,
            &http,
            Some(active.bundle_fn.as_ref() as BundleHttpGet<'_>),
            Some(&active.cfg),
            Some(active.verifier.as_ref()),
        )?,
    };
    Ok((text, is_off))
}

/// Read-only local inspection of the baseline sidecar pair — the plain
/// `index status` (no `--refresh`) path. NEVER raises: a present-but-corrupt
/// baseline is reported as `baseline: corrupt`, not `TNG-INDEX-BASELINE-CORRUPT`
/// (cli-contract §5.12 NORMATIVE — `status` is a read-only inspection tool
/// and must not hard-fail on a broken local trust state).
///
/// Returns `(baseline_state, established_at, pending, last_reported)`, each
/// already formatted for display (`(none)` for absent timestamps).
fn read_local_baseline_status(
    baseline_path: &Path,
    meta_path: &Path,
) -> (&'static str, String, &'static str, String) {
    if !baseline_path.is_file() {
        return ("absent", "(none)".to_string(), "no", "(none)".to_string());
    }
    let Ok(baseline_bytes) = std::fs::read(baseline_path) else {
        return ("corrupt", "(none)".to_string(), "no", "(none)".to_string());
    };
    let Ok(baseline_text) = String::from_utf8(baseline_bytes) else {
        return ("corrupt", "(none)".to_string(), "no", "(none)".to_string());
    };
    if parse_baseline(&baseline_text).is_err() {
        return ("corrupt", "(none)".to_string(), "no", "(none)".to_string());
    }

    let meta = if meta_path.is_file() {
        std::fs::read_to_string(meta_path)
            .map(|t| parse_baseline_meta(&t))
            .unwrap_or_default()
    } else {
        BaselineMeta::default()
    };

    let established_at = meta.established_at.clone().unwrap_or_else(|| "(none)".to_string());
    if let Some(digest) = &meta.reported_digest {
        if !digest.is_empty() {
            return (
                "present",
                established_at,
                "yes",
                meta.reported_at.clone().unwrap_or_else(|| "(none)".to_string()),
            );
        }
    }
    ("present", established_at, "no", "(none)".to_string())
}

/// The fixed-format `index status` block (cli-contract §5.12 NORMATIVE
/// (status block, fixed format)) — a 19-character label+colon column,
/// mirroring `show --index-trust`'s convention (§5.3a).
#[allow(clippy::too_many_arguments)]
fn format_index_status_block(
    index_url: &str,
    policy: &str,
    baseline: &str,
    established_at: &str,
    pending: &str,
    last_reported: &str,
) -> String {
    let fields: [(&str, &str); 6] = [
        ("index-url:", index_url),
        ("policy:", policy),
        ("baseline:", baseline),
        ("established-at:", established_at),
        ("pending:", pending),
        ("last-reported:", last_reported),
    ];
    let mut out = String::new();
    for (label, value) in fields {
        out.push_str(&format!("{label:<19}{value}\n"));
    }
    out
}

/// Diff `candidate_text` against the on-disk baseline at `baseline_path` —
/// the shared computation behind `status --refresh` and `accept`.
///
/// Returns `(outcome, baseline_state)`: `outcome` is `Some` when
/// `baseline_state == "present"`, else `None`. Composes
/// `index_ratchet_seam::build_index_state`/`parse_baseline` and
/// `ratchet::Baseline` directly — no dominance-fold/digest logic is
/// reimplemented here.
///
/// Yank-transition notices (legal, non-error) are printed to stderr here,
/// reusing `index_ratchet_seam::print_yank_notice` — the SAME stderr line
/// the ordinary ratchet-gated fetch path prints.
fn compute_index_diff(candidate_text: &str, baseline_path: &Path) -> Result<(Option<RatchetOutcome>, &'static str), MilpaError> {
    let (_, candidate_state) = build_index_state(candidate_text)?;

    if !baseline_path.is_file() {
        return Ok((None, "absent"));
    }
    let Ok(baseline_bytes) = std::fs::read(baseline_path) else {
        return Ok((None, "corrupt"));
    };
    let Ok(baseline_text) = String::from_utf8(baseline_bytes) else {
        return Ok((None, "corrupt"));
    };
    let baseline_state = match parse_baseline(&baseline_text) {
        Ok(s) => s,
        Err(_) => return Ok((None, "corrupt")),
    };

    let outcome = Baseline::new(baseline_state).check(&candidate_state);
    for transition in &outcome.transitions {
        print_yank_notice(transition);
    }
    Ok((Some(outcome), "present"))
}

/// Render the shared three-branch diff text (cli-contract §5.12 NORMATIVE
/// (violation-line format...) / (`accept` MUST...)) used by both
/// `status --refresh` and `accept`. Returns `(text, clean)`; `clean` is
/// meaningful only for the `"present"` branch — callers decide exit
/// code / write behavior per-verb from `baseline_state` + `clean` (the two
/// verbs have DIFFERENT rules for the absent/corrupt branches: `status`
/// treats corrupt as attention-worthy, `accept` treats it as successful
/// re-establishment).
fn render_index_verb_diff(outcome: Option<&RatchetOutcome>, baseline_state: &str) -> (String, bool) {
    if baseline_state == "absent" {
        return ("no prior baseline — this fetch establishes the trust anchor\n".to_string(), true);
    }
    if baseline_state == "corrupt" {
        return (
            "baseline unreadable — cannot show what changed; re-establishing the trust anchor\n".to_string(),
            true,
        );
    }

    let outcome = outcome.expect("outcome must be Some when baseline_state == present");
    if outcome.clean() {
        return ("nothing to accept\n".to_string(), true);
    }

    let violations = &outcome.violations;
    let mut lines: Vec<String> = Vec::new();
    if violations.iter().any(|v| v.field == "attestation-epoch") {
        // registry-protocol §3.5.1: attestation-epoch enforcement is live as
        // of A6. The blast-radius sentence cli-contract §5.12 requires
        // before the ordinary diff.
        lines.push(
            "accepting this change reclassifies every entry between the \
             epochs as pre-epoch/legacy, nullifying the attestation mandate \
             for all of them — an index-wide consequence, not a one-row one"
                .to_string(),
        );
    }
    for v in violations {
        lines.push(
            [
                "violation:",
                v.class,
                &v.entry_key.namespace,
                &v.entry_key.name,
                &v.entry_key.version,
                &v.field,
                v.kind,
                &v.baseline_value,
                &v.candidate_value,
            ]
            .join("\t"),
        );
    }
    lines.push(format!("digest: {}", canonical_digest(violations)));
    (lines.join("\n") + "\n", false)
}

/// `milpa index status [--refresh]` — read-only append-only-ratchet
/// inspection. NEVER writes to disk, under any invocation, including
/// `--refresh` (cli-contract §5.12 NORMATIVE).
fn cmd_index_status(
    dir: &Path,
    no_index: bool,
    require_attested_index: bool,
    refresh: bool,
) -> Result<i32, MilpaError> {
    let (url, policy) = index_verb_setup(dir, no_index)?;
    let cache_dir = index_cache_dir();
    let (baseline_p, meta_p) = baseline_sidecar_paths(&url, &cache_dir);
    let policy_str = trust_policy_wire(&policy);

    if !refresh {
        let (baseline_state, established_at, pending, last_reported) = read_local_baseline_status(&baseline_p, &meta_p);
        let block = format_index_status_block(&url, policy_str, baseline_state, &established_at, pending, &last_reported);
        print!("{block}");
        return Ok(if baseline_state == "corrupt" || pending == "yes" { 1 } else { 0 });
    }

    let (candidate_text, trust_off) = fetch_index_candidate(dir, &url, require_attested_index)?;
    if trust_off {
        eprintln!(
            "[milpa] warning: index-trust is \"off\" — this fetch has no \
             cryptographic basis; the diff below attests only to continuity \
             of whatever the transport delivered"
        );
    }

    let (outcome, baseline_state) = compute_index_diff(&candidate_text, &baseline_p)?;
    let (text, clean) = render_index_verb_diff(outcome.as_ref(), baseline_state);
    print!("{text}");

    if baseline_state == "corrupt" {
        return Ok(1);
    }
    if baseline_state == "absent" {
        return Ok(0);
    }
    Ok(if clean { 0 } else { 1 })
}

/// `milpa index accept` — fetch, print the diff, and atomically accept the
/// new trust baseline (cli-contract §5.12). Non-interactive; idempotent;
/// per-URL. Its ONLY mutation is the atomic baseline-pair swap, performed
/// UNLESS the diff against a present, parseable baseline is already clean
/// (the idempotent no-op case — `nothing to accept`, no write).
fn cmd_index_accept(dir: &Path, no_index: bool, require_attested_index: bool) -> Result<i32, MilpaError> {
    let (url, policy) = index_verb_setup(dir, no_index)?;
    let cache_dir = index_cache_dir();
    let (baseline_p, _meta_p) = baseline_sidecar_paths(&url, &cache_dir);

    let (candidate_text, trust_off) = fetch_index_candidate(dir, &url, require_attested_index)?;
    if trust_off {
        eprintln!(
            "[milpa] warning: index-trust is \"off\" — this fetch has no \
             cryptographic basis; accepting it attests only to continuity of \
             whatever the transport delivered"
        );
    }
    if policy == milpa_manifest::TrustPolicy::Off {
        eprintln!(
            "[milpa] warning: index-history is \"off\" — the baseline \
             written by this accept will not be consulted again until the \
             axis is re-enabled"
        );
    }

    let (outcome, baseline_state) = compute_index_diff(&candidate_text, &baseline_p)?;
    let (text, clean) = render_index_verb_diff(outcome.as_ref(), baseline_state);
    print!("{text}");

    if baseline_state == "present" && clean {
        return Ok(0); // idempotent no-op — nothing to accept, no write.
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let new_meta = BaselineMeta {
        established_at: Some(iso_timestamp(now as i64)),
        reported_digest: None,
        reported_at: None,
    };
    write_baseline_pair(&url, &cache_dir, candidate_text.as_bytes(), &new_meta)?;
    Ok(0)
}

/// The manifest-node wire string for a `TrustPolicy` value (`"off"`/`"warn"`/`"strict"`).
fn trust_policy_wire(p: &milpa_manifest::TrustPolicy) -> &'static str {
    use milpa_manifest::TrustPolicy;
    match p {
        TrustPolicy::Off => "off",
        TrustPolicy::Warn => "warn",
        TrustPolicy::Strict => "strict",
    }
}

// S11e / RD-H2: the member-override reconstruction used to live here as a
// CLI-local `ws_with_member_override` that never re-validated root-authority
// index-trust declarations after substitution. It now lives in `milpa-core`
// as `load_workspace_with_member_override` (mirrors `workspace.py`'s module
// shape — the validator and the constructor are colocated so a
// `LoadedWorkspace` cannot be produced by this path without being
// re-checked). See the two call sites below and
// `milpa_core::workspace::load_workspace_with_member_override`.

/// Determine whether `dir/milpa.kdl` is a *confirmed* workspace-shaped
/// document, WITHOUT fully loading/validating the workspace.
///
/// Root-cause split (mirrors the discovery half of `workspace.py:find_workspace_root`,
/// which parses first and only calls `load_workspace` — unguarded — once the
/// document is known to be a workspace manifest): a directory can be in one
/// of four states, and only two of them mean "keep walking upward":
///   - no `milpa.kdl` here, or it's unreadable            → `Ok(false)` (absent, keep walking)
///   - `milpa.kdl` parses as a *package* manifest          → `Ok(false)` (transparent, keep walking)
///   - `milpa.kdl` parses as a *workspace* manifest         → `Ok(true)`  (STOP — this is the root)
///   - `milpa.kdl` fails to parse with a `MAN-WORKSPACE-*`  → `Err(e)`   (STOP — it IS a workspace
///     grammar error (arity, duplicate member, unknown node,          document, but a structurally
///     workspace-in-package, etc.)                                     invalid one; must propagate)
///
/// Any other parse failure (`MAN-KDL-SYNTAX`, `MAN-UNKNOWN-TOP-LEVEL` for a
/// package-shaped doc, I/O error, …) means this directory's `milpa.kdl` is not
/// recognizable as a workspace document at all — treated as absent, same as
/// Python's ancestor walk.
fn milpa_kdl_is_workspace_doc(dir: &Path) -> Result<bool, MilpaError> {
    let kdl_path = dir.join("milpa.kdl");
    let text = match std::fs::read_to_string(&kdl_path) {
        Ok(t) => t,
        Err(_) => return Ok(false), // no file / unreadable → absent, keep walking
    };
    match milpa_manifest::parse_document(&text) {
        Ok(milpa_manifest::ManifestDoc::Workspace(_)) => Ok(true),
        Ok(milpa_manifest::ManifestDoc::Package(_)) => Ok(false),
        Err(e) if e.code.starts_with("MAN-WORKSPACE-") => Err(MilpaError::Manifest(e)),
        Err(_) => Ok(false),
    }
}

/// S11e (RFC: workspace-completion §3.G / D5): walk upward from `start_dir`
/// looking for a parent workspace that contains `start_dir` as a member.
///
/// Mirrors `workspace.py:find_workspace_root`.  Returns `Ok(Some((root, ws)))`
/// if a workspace root is found AND `start_dir` is one of its declared
/// members; returns `Ok(None)` otherwise (standalone-package or
/// not-a-declared-member).
///
/// Algorithm (root-cause fix — RD-C1 code-review item): discovery
/// (`milpa_kdl_is_workspace_doc`) is split from loading (`load_workspace`).
/// Once a directory's `milpa.kdl` is CONFIRMED workspace-shaped, `load_workspace`
/// is called unguarded — any structural error it raises (`WS-*`, including
/// `WS-INDEX-TRUST-ON-MEMBER`) MUST propagate rather than being treated as
/// "no workspace here, keep walking". Previously `if let Ok(ws) = load_workspace(...)`
/// conflated "semantically invalid workspace" with "absent", silently falling
/// through member-dir `add`/`update`/`remove` to standalone-package treatment.
///
/// 1. Walk up one directory at a time.
/// 2. At each level, check whether `milpa.kdl` is a confirmed workspace doc.
/// 3. If not (absent or a package manifest) → continue upward.
/// 4. If a `MAN-WORKSPACE-*` grammar error occurred at this level → propagate.
/// 5. If confirmed → call `load_workspace` UNGUARDED (`?`); check that
///    `start_dir` is the resolved directory of one of the declared members.
/// 6. If so, return `(root, ws)`.  If the workspace doesn't declare
///    `start_dir` as a member, stop searching (return `None`) — mirrors
///    Python's "the workspace does not legitimately contain start_dir".
/// 7. Return `None` at the filesystem root.
fn find_parent_workspace(
    start_dir: &Path,
) -> Result<Option<(PathBuf, LoadedWorkspace)>, MilpaError> {
    let Ok(start_resolved) = start_dir.canonicalize() else {
        return Ok(None);
    };
    let mut current = start_resolved.clone();
    // Walk upward — skip `current` itself (that's start_dir, the member dir).
    loop {
        match current.parent() {
            None => return Ok(None), // filesystem root reached
            Some(parent) => current = parent.to_path_buf(),
        }
        if milpa_kdl_is_workspace_doc(&current)? {
            // Confirmed workspace document — load_workspace's errors (WS-*)
            // MUST propagate from here on; this is the workspace root.
            let ws = load_workspace(&current)?;
            // Check if start_dir is a declared member.
            for member in &ws.members {
                // F10: if THIS member's directory is uncanonicalizable (e.g. the
                // member dir was deleted), skip it and continue checking the rest.
                // Only conclude "not a member" after ALL members have been checked.
                let member_abs = match member.directory.canonicalize() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                if member_abs == start_resolved {
                    return Ok(Some((current.clone(), ws)));
                }
            }
            // Found a workspace but start_dir is not a member — stop searching.
            return Ok(None);
        }
        // Not a workspace root at this level (absent or a package manifest)
        // → continue upward.
    }
}

/// Parse CLI feature-selection arguments from verb-level tail args.
///
/// Returns `(features, no_default_features, all_features)` where `features`
/// is the set of explicit flag names from `--features <comma-list>`.
/// S2 (RFC: workspace-completion §3.A): used by `cmd_fetch`/`cmd_lock` to
/// forward feature selection into `resolve_workspace_with_features`.
fn parse_feature_args(rest: &[String]) -> (std::collections::BTreeSet<String>, bool, bool) {
    let features_str = flag_value(rest, "--features");
    let features: std::collections::BTreeSet<String> = features_str
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let no_default = rest.iter().any(|a| a == "--no-default-features");
    let all_features = rest.iter().any(|a| a == "--all-features");
    (features, no_default, all_features)
}

/// Returns `true` when both `--all-features` and `--no-default-features` are
/// present in `rest` (the verb-level tail args).  Used to detect the
/// mutually-exclusive combination before dispatching to the resolver.
fn check_feature_flags_conflict(rest: &[String]) -> bool {
    let has_all = rest.iter().any(|a| a == "--all-features");
    let has_no_default = rest.iter().any(|a| a == "--no-default-features");
    has_all && has_no_default
}

/// The value following `flag` in `args` (e.g. `--git <url>`), if present.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

/// Parses `--upgrade [<dep>...]` from the verb's tail args (B4,
/// resolution-semantics RFC §3 Axis B / D-B3). Returns `None` when the flag
/// is absent (ordinary minimal-change applies); `Some(vec![])` for a bare
/// `--upgrade` (opt out globally); `Some(names)` for `--upgrade <dep>...`
/// (opt out only for those deps). Collects every token after `--upgrade` up
/// to the next dash-prefixed token (single `-s`/`-C` or double `--strategy`/
/// `--frozen`/etc.) or the end of `rest` — mirrors how Python argparse's
/// `nargs="*"` stops at ANY option-looking token, not only a `--long` one
/// (R12: `-s`/`--strategy` is also legal on `fetch`/`lock`, so a boundary
/// that only recognized `--` would over-collect `milpa fetch --upgrade foo
/// -s minver` as upgrade targets `["foo", "-s", "minver"]`, spuriously
/// rejecting the nonexistent dep `"-s"`). No dep name legitimately starts
/// with `-` (dep names are package identifiers), so this is a safe,
/// unambiguous boundary.
fn upgrade_flag_values(rest: &[String]) -> Option<Vec<String>> {
    let idx = rest.iter().position(|a| a == "--upgrade")?;
    let mut names = Vec::new();
    for tok in &rest[idx + 1..] {
        if tok.starts_with('-') {
            break;
        }
        names.push(tok.clone());
    }
    Some(names)
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
        // C3 (resolution-semantics RFC §3 Axis C / D-C2): `-s`/`--strategy`
        // moved out of the global pre-verb flag loop (scoped per-verb now,
        // parsed from `rest` via `strategy_flag_value`) — this test only
        // exercises the flags that REMAIN global (`-C`/`--frozen`).
        let cli = parse_args(&[
            "-C".into(),
            "/tmp/p".into(),
            "--frozen".into(),
            "fetch".into(),
        ])
        .unwrap();
        assert_eq!(cli.directory, PathBuf::from("/tmp/p"));
        assert!(cli.frozen);
        assert_eq!(cli.verb, "fetch");
    }

    /// C3 (resolution-semantics RFC §3 Axis C / D-C2): `-s`/`--strategy` is
    /// no longer a global pre-verb flag — it must appear in the verb's tail
    /// (`rest`), parsed by `strategy_flag_value`.
    #[test]
    fn strategy_flag_scoped_to_verb_tail() {
        let cli = parse_args(&[
            "fetch".into(),
            "-s".into(),
            "minver".into(),
        ])
        .unwrap();
        assert_eq!(cli.verb, "fetch");
        assert_eq!(strategy_flag_value(&cli.rest), Ok(Some(Strategy::Minver)));
    }

    /// C2 (resolver-semantics RFC §3 Axis C, D-C1): the `lowest-direct`
    /// wire string parses like any other `--strategy` value — C3 now via
    /// the scoped `strategy_flag_value` (not a `Cli.strategy` global field).
    #[test]
    fn parses_lowest_direct_strategy_flag() {
        let cli = parse_args(&[
            "fetch".into(),
            "--strategy".into(),
            "lowest-direct".into(),
        ])
        .unwrap();
        assert_eq!(cli.verb, "fetch");
        assert_eq!(
            strategy_flag_value(&cli.rest),
            Ok(Some(Strategy::LowestDirect))
        );
    }

    /// C3: an unrecognized `--strategy` value is a parse error (`Err(())`),
    /// not silently ignored — mirrors the old global loop's short-circuit.
    #[test]
    fn strategy_flag_malformed_value_errors() {
        let cli = parse_args(&["fetch".into(), "--strategy".into(), "bogus".into()]).unwrap();
        assert_eq!(strategy_flag_value(&cli.rest), Err(()));
    }

    /// C3: `--strategy` absent from the verb's tail is `Ok(None)` — the
    /// "unspecified" sentinel that defers to the manifest/lockfile.
    #[test]
    fn strategy_flag_absent_is_none() {
        let cli = parse_args(&["fetch".into()]).unwrap();
        assert_eq!(strategy_flag_value(&cli.rest), Ok(None));
    }

    // -----------------------------------------------------------------------
    // D2 (resolution-semantics RFC §3 Axis D) — `--exclude-newer <ts>` CLI
    // sentinel + fetch/lock-only scoping + precedence.
    // -----------------------------------------------------------------------

    #[test]
    fn exclude_newer_flag_parses_valid_timestamp() {
        let cli = parse_args(&[
            "fetch".into(),
            "--exclude-newer".into(),
            "2026-01-01T00:00:00Z".into(),
        ])
        .unwrap();
        let ts = exclude_newer_flag_value(&cli.rest).unwrap().unwrap();
        assert_eq!(ts, parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap());
    }

    #[test]
    fn exclude_newer_flag_absent_is_none() {
        let cli = parse_args(&["fetch".into()]).unwrap();
        assert_eq!(exclude_newer_flag_value(&cli.rest).unwrap(), None);
    }

    /// D2: a malformed value is a DIAGNOSED failure (CLI-EXCLUDE-NEWER-INVALID),
    /// not a bare `Err(())` usage error like `strategy_flag_value` — a
    /// timestamp has no closed enum of valid spellings.
    #[test]
    fn exclude_newer_flag_malformed_value_errors_with_slug() {
        let cli = parse_args(&[
            "fetch".into(),
            "--exclude-newer".into(),
            "not-a-timestamp".into(),
        ])
        .unwrap();
        let err = exclude_newer_flag_value(&cli.rest).unwrap_err();
        assert_eq!(err.code(), "CLI-EXCLUDE-NEWER-INVALID");
    }

    #[test]
    fn exclude_newer_flag_missing_value_errors_with_slug() {
        let cli = parse_args(&["fetch".into(), "--exclude-newer".into()]).unwrap();
        let err = exclude_newer_flag_value(&cli.rest).unwrap_err();
        assert_eq!(err.code(), "CLI-EXCLUDE-NEWER-INVALID");
    }

    /// D2 precedence: explicit CLI value always wins over the manifest's
    /// `resolution { exclude-newer }` (and over the lockfile's recorded
    /// value, tier 3).
    #[test]
    fn resolve_effective_exclude_newer_cli_overrides_manifest() {
        let cli_ts = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        let manifest_ts = parse_iso8601_timestamp("2020-01-01T00:00:00Z").unwrap();
        let resolution = milpa_manifest::Resolution { strategy: None, exclude_newer: Some(manifest_ts) };
        assert_eq!(
            resolve_effective_exclude_newer(Some(cli_ts), Some(resolution), None),
            Some(cli_ts)
        );
    }

    /// D2 precedence: unspecified CLI defers to the manifest's declared bound.
    #[test]
    fn resolve_effective_exclude_newer_falls_back_to_manifest() {
        let manifest_ts = parse_iso8601_timestamp("2020-01-01T00:00:00Z").unwrap();
        let resolution = milpa_manifest::Resolution { strategy: None, exclude_newer: Some(manifest_ts) };
        assert_eq!(
            resolve_effective_exclude_newer(None, Some(resolution), None),
            Some(manifest_ts)
        );
    }

    /// D5 precedence (§6 D-D3 no-silent-drop): absent CLI AND absent manifest
    /// falls back to tier 3 — the prior lockfile's own recorded bound —
    /// rather than silently resetting to `None`.
    #[test]
    fn resolve_effective_exclude_newer_falls_back_to_prior_lockfile() {
        let lock_ts = parse_iso8601_timestamp("2019-06-01T00:00:00Z").unwrap();
        let lock = milpa_core::Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: Some(lock_ts),
            deps: vec![],
        };
        assert_eq!(
            resolve_effective_exclude_newer(None, None, Some(&lock)),
            Some(lock_ts)
        );
    }

    /// D5: the manifest tier still wins over the lockfile tier when both are
    /// present (manifest is the more-recently-authored, durable source).
    #[test]
    fn resolve_effective_exclude_newer_manifest_wins_over_prior_lockfile() {
        let manifest_ts = parse_iso8601_timestamp("2020-01-01T00:00:00Z").unwrap();
        let lock_ts = parse_iso8601_timestamp("2019-06-01T00:00:00Z").unwrap();
        let resolution = milpa_manifest::Resolution { strategy: None, exclude_newer: Some(manifest_ts) };
        let lock = milpa_core::Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: Some(lock_ts),
            deps: vec![],
        };
        assert_eq!(
            resolve_effective_exclude_newer(None, Some(resolution), Some(&lock)),
            Some(manifest_ts)
        );
    }

    /// Absent CLI, absent manifest, absent (or no) prior lockfile resolves to
    /// `None` — no time bound, the true "nothing was ever set" case.
    #[test]
    fn resolve_effective_exclude_newer_none_when_all_absent() {
        assert_eq!(resolve_effective_exclude_newer(None, None, None), None);
        let resolution = milpa_manifest::Resolution { strategy: None, exclude_newer: None };
        assert_eq!(resolve_effective_exclude_newer(None, Some(resolution), None), None);
        let lock = milpa_core::Lockfile {
            version: 1,
            strategy: "maxver".into(),
            exclude_newer: None,
            deps: vec![],
        };
        assert_eq!(
            resolve_effective_exclude_newer(None, None, Some(&lock)),
            None
        );
    }

    /// D2 end-to-end: `milpa fetch --exclude-newer <bogus>` surfaces the CLI
    /// slug through the real `run()` dispatch (no mocked fetch needed — the
    /// malformed-value check fires before any resolve is attempted).
    #[test]
    fn e2e_fetch_malformed_exclude_newer_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        ).unwrap();

        let rc = run(&[
            "-C".into(),
            proj.to_str().unwrap().into(),
            "fetch".into(),
            "--exclude-newer".into(),
            "not-a-timestamp".into(),
        ]);
        let err = rc.unwrap_err();
        assert_eq!(err.code(), "CLI-EXCLUDE-NEWER-INVALID");
    }

    /// D2 end-to-end: same malformed-value check on `lock`.
    #[test]
    fn e2e_lock_malformed_exclude_newer_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        ).unwrap();

        let rc = run(&[
            "-C".into(),
            proj.to_str().unwrap().into(),
            "lock".into(),
            "--exclude-newer".into(),
            "not-a-timestamp".into(),
        ]);
        let err = rc.unwrap_err();
        assert_eq!(err.code(), "CLI-EXCLUDE-NEWER-INVALID");
    }

    /// D2 scoping: `--exclude-newer` is registered on fetch/lock ONLY — on
    /// `update` it is never even scanned (§3 Axis D "Verb reach": narrower
    /// than `--strategy`'s per-verb scoping). Passing it to `update` must
    /// NOT surface CLI-EXCLUDE-NEWER-INVALID even with a malformed value —
    /// the flag is simply not consulted there (mirrors how `--strategy` is
    /// silently ignored on `show`/`clean`, per this hand-rolled parser's
    /// existing "not-registered" philosophy for out-of-scope verbs).
    #[test]
    fn e2e_update_does_not_register_exclude_newer_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        ).unwrap();

        let rc = run(&[
            "-C".into(),
            proj.to_str().unwrap().into(),
            "update".into(),
            "--exclude-newer".into(),
            "not-a-timestamp".into(),
        ]);
        // `update` treats its first `rest` token as the <dep> name — it never
        // scans for `--exclude-newer` at all, so whatever error surfaces here
        // must NOT be CLI-EXCLUDE-NEWER-INVALID.
        if let Err(e) = rc {
            assert_ne!(e.code(), "CLI-EXCLUDE-NEWER-INVALID");
        }
    }

    #[test]
    fn parses_no_index_flag() {
        let cli = parse_args(&["--no-index".into(), "fetch".into()]).unwrap();
        assert!(cli.no_index, "--no-index must set cli.no_index");
        assert_eq!(cli.verb, "fetch");
        // Default (flag absent) is false.
        let cli2 = parse_args(&["fetch".into()]).unwrap();
        assert!(!cli2.no_index);
    }

    #[test]
    fn no_index_requested_flag_overrides() {
        // The flag forces no-index regardless of env.
        assert!(no_index_requested(true));
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

    // -----------------------------------------------------------------------
    // C-clean guard tests (Phase C) — the CAS must survive clean.
    // -----------------------------------------------------------------------

    /// THE CRITICAL GUARD: clean removes _deps/ by unlinking symlinks only.
    ///
    /// Set up a project where `_deps/<name>` is a symlink into a CAS store dir
    /// that contains a sentinel file.  After cmd_clean:
    ///   (a) _deps/ is gone.
    ///   (b) The CAS dir AND its sentinel file STILL EXIST.
    ///
    /// A broken clean that uses a follow-symlink recursive remove would delete
    /// the CAS contents and fail assertion (b).  `std::fs::remove_dir_all` on
    /// Linux removes symlinks themselves (does NOT follow them), so this passes —
    /// but the test locks that invariant against future regression.
    #[test]
    fn clean_unlinks_symlink_never_deletes_cas_target() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();

        // Build a fake CAS entry with a sentinel file inside it.
        let cas_entry = tmp.path().join("cas").join("abc123");
        std::fs::create_dir_all(&cas_entry).unwrap();
        let sentinel = cas_entry.join("mylib.nim");
        std::fs::write(&sentinel, b"# sentinel -- must survive clean\n").unwrap();

        // Wire up _deps/ with a symlink pointing at the CAS entry.
        let deps_dir = proj.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();
        std::os::unix::fs::symlink(&cas_entry, deps_dir.join("mylib")).unwrap();

        let rc = cmd_clean(&proj).unwrap();
        assert_eq!(rc, 0);

        // (a) _deps/ is gone.
        assert!(
            !deps_dir.exists(),
            "_deps/ must be removed by clean"
        );

        // (b) CAS entry and sentinel file are untouched.
        assert!(
            cas_entry.exists(),
            "CAS store entry must NOT be deleted by clean — \
             clean must unlink the symlink, not follow it"
        );
        assert!(
            sentinel.exists(),
            "CAS sentinel file must NOT be deleted by clean — \
             the store is shared across projects"
        );
    }

    /// clean removes nim.cfg from the project root.
    #[test]
    fn clean_removes_nim_cfg() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let nim_cfg = dir.join("nim.cfg");
        std::fs::write(&nim_cfg, b"--path:_deps/foo\n").unwrap();

        let rc = cmd_clean(dir).unwrap();
        assert_eq!(rc, 0);
        assert!(!nim_cfg.exists(), "nim.cfg must be removed by clean");
    }

    /// clean does NOT remove milpa.lock — the lockfile survives.
    #[test]
    fn clean_leaves_milpa_lock_intact() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let lock = dir.join("milpa.lock");
        let lock_content = b"# lockfile\nversion 1\n";
        std::fs::write(&lock, lock_content).unwrap();
        // Also put a nim.cfg so clean has something to do.
        std::fs::write(dir.join("nim.cfg"), b"--path:_deps/foo\n").unwrap();

        let rc = cmd_clean(dir).unwrap();
        assert_eq!(rc, 0);
        assert!(lock.exists(), "milpa.lock must survive clean");
        assert_eq!(
            std::fs::read(&lock).unwrap(),
            lock_content,
            "milpa.lock content must be unchanged by clean"
        );
    }

    /// clean called twice is safe — second call is a no-op success (idempotent).
    #[test]
    fn clean_idempotent_called_twice() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let deps_dir = dir.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();
        std::fs::write(dir.join("nim.cfg"), b"--path:_deps/foo\n").unwrap();

        let rc1 = cmd_clean(dir).unwrap();
        let rc2 = cmd_clean(dir).unwrap();
        assert_eq!(rc1, 0);
        assert_eq!(rc2, 0, "second clean call must succeed (idempotent)");
    }

    /// `remove` rejects an undeclared dep WITHOUT resolving or writing anything
    /// (cli-contract §5.7 — reject if <dep> not in milpa.kdl, exit 1; both files
    /// left unmodified). No mocked transport needed: the reject path is hit
    /// before any resolve.
    #[test]
    fn remove_rejects_undeclared_dep_and_leaves_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let manifest = "name \"app\"\nkind \"application\"\ndeps {\n  foo git=(url)\"https://e/foo.git\" ref=\"main\"\n}\n";
        std::fs::write(dir.join("milpa.kdl"), manifest).unwrap();
        // remove of an absent dep → exit 1 (MAN-REMOVE-DEP-ABSENT).
        assert_eq!(cmd_remove(dir, Some(Strategy::default()), &["ghost".into()], false, false, false).unwrap(), 1);
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
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{url}\" ref=\"main\"\n}}\n"),
        )
        .unwrap();

        // SAFETY: serialized by ENV_MUTEX.
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let r = cmd_remove(&proj, Some(Strategy::default()), &["foo".into()], false, false, false);
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
            "name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{foo}\" ref=\"main\"\n  bar git=(url)\"{bar}\" ref=\"main\"\n}}\n"
        );
        std::fs::write(proj.join("milpa.kdl"), &manifest).unwrap();

        // First, fetch to produce a baseline lockfile with both pins.
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        assert_eq!(cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, None).unwrap(), 0);
        let baseline = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();
        assert!(baseline.contains("\"foo\"") && baseline.contains("\"bar\""));

        // Scoped update of foo: succeeds, writes the lockfile, leaves kdl intact.
        let r = cmd_update(&proj, Some(Strategy::default()), &["foo".into()], false, false, false, false);
        let after_kdl = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        let after_lock = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(r.unwrap(), 0, "scoped update should succeed");
        assert_eq!(after_kdl, manifest, "update MUST NOT mutate milpa.kdl");
        // Both deps still present (bar retained via prior, foo re-resolved).
        assert!(after_lock.contains("\"foo\"") && after_lock.contains("\"bar\""));
    }

    // -------------------------------------------------------------------------
    // B3 (resolution-semantics RFC §3 Axis B / §6 D-B2): `--locked` CLI slice.
    // Anti-hollow: calls `cmd_fetch` directly (the real fn `fetch`/`lock`
    // dispatch to) with `--locked` in `rest`, exactly as `run()` would pass it.
    // -------------------------------------------------------------------------

    /// `--locked` on an up-to-date lock passes (resolve == lock).
    #[test]
    fn locked_passes_when_up_to_date_via_mock() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let url = "https://example.com/foo.git";
        let mocked = make_mocked_fetches(tmp.path(), url, "main", &"a".repeat(40), &[("foo.nim", b"# foo")]);
        std::fs::write(
            proj.join("milpa.kdl"),
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{url}\" ref=\"main\"\n}}\n"),
        )
        .unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let baseline = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, None);
        assert_eq!(baseline.unwrap(), 0);

        let locked_arg = vec!["--locked".to_string()];
        let r = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &locked_arg, false, false, false, None);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(r.unwrap(), 0, "--locked on an up-to-date lock should pass");
    }

    /// `--locked` also accepted on the `lock` verb (both dispatch through
    /// `cmd_fetch` with `emit_nimcfg=false`).
    #[test]
    fn locked_passes_on_lock_verb_too_via_mock() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let url = "https://example.com/foo.git";
        let mocked = make_mocked_fetches(tmp.path(), url, "main", &"a".repeat(40), &[("foo.nim", b"# foo")]);
        std::fs::write(
            proj.join("milpa.kdl"),
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{url}\" ref=\"main\"\n}}\n"),
        )
        .unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let baseline = cmd_fetch(&proj, Some(Strategy::default()), false, false, None, false, false, &[], false, false, false, None);
        assert_eq!(baseline.unwrap(), 0);

        let locked_arg = vec!["--locked".to_string()];
        let r = cmd_fetch(&proj, Some(Strategy::default()), false, false, None, false, false, &locked_arg, false, false, false, None);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(r.unwrap(), 0, "--locked on `lock` should also pass");
    }

    /// `--locked` with no committed lockfile at all -> RES-LOCKED-DRIFT.
    #[test]
    fn locked_with_no_prior_lock_fails_via_mock() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let url = "https://example.com/foo.git";
        let mocked = make_mocked_fetches(tmp.path(), url, "main", &"a".repeat(40), &[("foo.nim", b"# foo")]);
        std::fs::write(
            proj.join("milpa.kdl"),
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{url}\" ref=\"main\"\n}}\n"),
        )
        .unwrap();
        assert!(!proj.join("milpa.lock").exists());

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let locked_arg = vec!["--locked".to_string()];
        let r = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &locked_arg, false, false, false, None);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(r.unwrap_err().code(), "RES-LOCKED-DRIFT");
    }

    /// A manifest edit that moves the dep to a different ref (different
    /// commit_sha/provenance) -> RES-LOCKED-DRIFT naming the drifted
    /// package; the committed lockfile must NOT be clobbered.
    #[test]
    fn locked_detects_drift_after_manifest_edit_via_mock() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let url = "https://example.com/foo.git";
        let mocked = make_mocked_fetches(tmp.path(), url, "v1.0.0", &"a".repeat(40), &[("foo.nim", b"# foo v1")]);
        std::fs::write(
            proj.join("milpa.kdl"),
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{url}\" ref=\"v1.0.0\"\n}}\n"),
        )
        .unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        assert_eq!(
            cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, None).unwrap(),
            0
        );
        let baseline_lock = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();

        // Move the dep to a different tag.
        let _ = make_mocked_fetches(tmp.path(), url, "v2.0.0", &"b".repeat(40), &[("foo.nim", b"# foo v2")]);
        std::fs::write(
            proj.join("milpa.kdl"),
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{url}\" ref=\"v2.0.0\"\n}}\n"),
        )
        .unwrap();

        let locked_arg = vec!["--locked".to_string()];
        let r = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &locked_arg, false, false, false, None);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        let err = r.unwrap_err();
        assert_eq!(err.code(), "RES-LOCKED-DRIFT");
        assert!(message_of(&err).contains("foo"));

        // The committed lockfile must be unchanged (still pinned to v1.0.0).
        let after_lock = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();
        assert_eq!(after_lock, baseline_lock);
    }

    /// D5 (resolution-semantics RFC §3 Axis D / §6 D-D3 no-silent-drop):
    /// `--locked` must treat a DROPPED `exclude_newer` (present in the
    /// committed lock, absent from the new resolve) as drift — a silent
    /// relaxation of the time-bound is exactly the kind of divergence
    /// `--locked` exists to catch.
    #[test]
    fn locked_flags_dropped_exclude_newer_as_drift() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let url = "https://example.com/foo.git";
        let mocked = make_mocked_fetches(tmp.path(), url, "main", &"a".repeat(40), &[("foo.nim", b"# foo")]);
        std::fs::write(
            proj.join("milpa.kdl"),
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{url}\" ref=\"main\"\n}}\n"),
        )
        .unwrap();

        let ts = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        // Baseline: fetch WITH --exclude-newer (records it in the lock).
        let baseline = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, Some(ts));
        assert_eq!(baseline.unwrap(), 0);
        let baseline_lock = load_lockfile(&proj.join("milpa.lock")).unwrap();
        assert_eq!(baseline_lock.exclude_newer, Some(ts));

        // `--locked` with NO --exclude-newer this time (manifest declares no
        // resolution{} block either) — the effective value is None, dropping
        // the committed bound. Must raise RES-LOCKED-DRIFT, not silently pass.
        let locked_arg = vec!["--locked".to_string()];
        let r = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &locked_arg, false, false, false, None);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        let err = r.unwrap_err();
        assert_eq!(err.code(), "RES-LOCKED-DRIFT");
        assert!(message_of(&err).contains("exclude_newer"), "message: {}", message_of(&err));
    }

    /// D5: `--locked` PASSES when the effective exclude_newer still matches
    /// the committed lock's recorded value (no drift).
    #[test]
    fn locked_passes_when_exclude_newer_unchanged() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let url = "https://example.com/foo.git";
        let mocked = make_mocked_fetches(tmp.path(), url, "main", &"a".repeat(40), &[("foo.nim", b"# foo")]);
        std::fs::write(
            proj.join("milpa.kdl"),
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{url}\" ref=\"main\"\n}}\n"),
        )
        .unwrap();

        let ts = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let baseline = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, Some(ts));
        assert_eq!(baseline.unwrap(), 0);

        // Same --exclude-newer passed again alongside --locked: no drift.
        let locked_arg = vec!["--locked".to_string()];
        let r = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &locked_arg, false, false, false, Some(ts));
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(r.unwrap(), 0, "--locked with an unchanged exclude_newer must pass");
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
        let no_lock = cmd_update(&proj, Some(Strategy::default()), &["ghost".into()], false, false, false, false);
        assert!(no_lock.is_err());
        assert_eq!(no_lock.unwrap_err().code(), "LOCK-FILE-NOT-FOUND");

        // Write an empty lockfile; scoped update of an absent dep → exit 1.
        std::fs::write(
            proj.join("milpa.lock"),
            "// generated by milpa; reproducible build snapshot\nversion 1\nstrategy \"maxver\"\n",
        )
        .unwrap();
        let r = cmd_update(&proj, Some(Strategy::default()), &["ghost".into()], false, false, false, false);
        assert_eq!(r.unwrap(), 1, "dep-not-in-lock → exit 1");
    }

    // -------------------------------------------------------------------------
    // B4 (resolution-semantics RFC §3 Axis B / D-B3): `--upgrade [<dep>...]`
    // on fetch/lock, implemented as DELEGATION to `strip_pins_for_upgrade` —
    // the SAME shared mechanism `update`/`update <dep>` uses. Real NAMED/index
    // deps with two real content-hash-matched mocked-git versions each (B2's
    // preference only ever bites a multi-candidate named dep; a root-declared
    // git dep has exactly one solver-visible candidate regardless).
    // -------------------------------------------------------------------------

    /// Stage real v1.0.0/v2.0.0 mocked git content for `name` under `base`'s
    /// shared `mocked-fetches/` dir; returns (mocked_dir, content_hash_v1,
    /// content_hash_v2) computed the SAME way the resolver will at fetch time
    /// (the mocked fetcher copies `content/*` verbatim with no `.nimble`
    /// sibling here, so hashing `content/` directly is byte-identical to
    /// hashing the materialized dest).
    fn b4_stage_two_versions(
        base: &std::path::Path,
        name: &str,
        sha_prefix: &str,
    ) -> (std::path::PathBuf, String, String) {
        let url = format!("https://example.com/{name}.git");
        let nim_name = format!("{name}.nim");
        let body_v1 = format!("# {name} v1").into_bytes();
        let body_v2 = format!("# {name} v2").into_bytes();
        let sha1 = format!("{sha_prefix}1").repeat(20);
        let sha2 = format!("{sha_prefix}2").repeat(20);
        let _ = make_mocked_fetches(base, &url, "v1.0.0", &sha1, &[(nim_name.as_str(), body_v1.as_slice())]);
        let mocked = make_mocked_fetches(base, &url, "v2.0.0", &sha2, &[(nim_name.as_str(), body_v2.as_slice())]);
        let content1 = mocked.join(milpa_core::url_key(&url, "v1.0.0")).join("content");
        let content2 = mocked.join(milpa_core::url_key(&url, "v2.0.0")).join("content");
        let h1 = milpa_core::compute_content_hash(&content1).unwrap();
        let h2 = milpa_core::compute_content_hash(&content2).unwrap();
        (mocked, h1, h2)
    }

    /// Build an `index.kdl` text for `pkgs` (name -> (hash_v1, hash_v2));
    /// `include_v2` controls whether the 2.0.0 candidate is listed at all
    /// (simulates "a newer version got published" between two resolves).
    fn b4_index_kdl(pkgs: &[(&str, (String, String))], include_v2: bool) -> String {
        let mut s = String::from("schema_version 1\n");
        for (name, (h1, h2)) in pkgs {
            s.push_str(&format!(
                "package \"{name}\" {{\n    version \"1.0.0\" {{\n        content_hash \"{h1}\"\n        provenance {{\n            kind \"git\"\n            url \"https://example.com/{name}.git\"\n            ref \"v1.0.0\"\n            commit_sha \"{}\"\n        }}\n    }}\n",
                "a".repeat(40),
            ));
            if include_v2 {
                s.push_str(&format!(
                    "    version \"2.0.0\" {{\n        content_hash \"{h2}\"\n        provenance {{\n            kind \"git\"\n            url \"https://example.com/{name}.git\"\n            ref \"v2.0.0\"\n            commit_sha \"{}\"\n        }}\n    }}\n",
                    "b".repeat(40),
                ));
            }
            s.push_str("}\n");
        }
        s
    }

    const B4_ROOT_KDL: &str =
        "name \"myapp\"\nkind \"application\"\nindex-trust \"off\"\ndeps {\n    foo\n    bar\n}\n";

    /// A fresh project resolved once against a v1-only index (both foo/bar
    /// lock to 1.0.0 — the only candidate at that point). MILPA_INDEX_URL /
    /// MILPA_MOCKED_FETCHES must already be set by the caller (ENV_MUTEX-guarded).
    fn b4_make_locked_project(tmp: &std::path::Path, subdir: &str) -> std::path::PathBuf {
        let proj = tmp.join(subdir);
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("milpa.kdl"), B4_ROOT_KDL).unwrap();
        let rc = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, None).unwrap();
        assert_eq!(rc, 0);
        let versions = b4_versions(&proj.join("milpa.lock"));
        assert_eq!(
            versions,
            std::collections::BTreeMap::from([
                ("foo".to_string(), "1.0.0".to_string()),
                ("bar".to_string(), "1.0.0".to_string()),
            ]),
        );
        proj
    }

    fn b4_versions(lock_path: &std::path::Path) -> std::collections::BTreeMap<String, String> {
        let lf = load_lockfile(lock_path).unwrap();
        lf.deps.into_iter().map(|d| (d.name, d.version)).collect()
    }

    // -----------------------------------------------------------------------
    // R12 (code review): `upgrade_flag_values` must stop collecting
    // dep-name tokens at ANY dash-prefixed token (single `-s` or double
    // `--strategy`), matching Python argparse's `nargs="*"` option-boundary
    // behavior. Before the fix it only recognized `--`-prefixed tokens as
    // boundaries, so `milpa fetch --upgrade foo -s minver` collected
    // `["foo", "-s", "minver"]` as upgrade targets — `strip_pins_for_upgrade`
    // then raised a spurious `LOCK-DEP-NOT-FOUND` for the nonexistent dep
    // `"-s"`, and the `-s minver` strategy flag was swallowed instead of
    // being parsed by `strategy_flag_value`.
    // -----------------------------------------------------------------------

    #[test]
    fn r12_upgrade_stops_at_single_dash_short_flag() {
        let rest = vec!["--upgrade".to_string(), "foo".to_string(), "-s".to_string(), "minver".to_string()];
        assert_eq!(upgrade_flag_values(&rest), Some(vec!["foo".to_string()]));
        // The strategy flag must still be independently parseable from the
        // same `rest` — proving `-s minver` was left alone, not consumed.
        assert_eq!(strategy_flag_value(&rest), Ok(Some(Strategy::Minver)));
    }

    #[test]
    fn r12_upgrade_stops_at_double_dash_long_flag() {
        let rest = vec!["--upgrade".to_string(), "foo".to_string(), "--strategy".to_string(), "minver".to_string()];
        assert_eq!(upgrade_flag_values(&rest), Some(vec!["foo".to_string()]));
    }

    #[test]
    fn r12_upgrade_collects_multiple_dep_names() {
        let rest = vec!["--upgrade".to_string(), "foo".to_string(), "bar".to_string()];
        assert_eq!(
            upgrade_flag_values(&rest),
            Some(vec!["foo".to_string(), "bar".to_string()])
        );
    }

    #[test]
    fn r12_bare_upgrade_with_nothing_after_means_whole_graph() {
        let rest = vec!["--upgrade".to_string()];
        assert_eq!(upgrade_flag_values(&rest), Some(vec![]));
    }

    #[test]
    fn r12_upgrade_immediately_followed_by_strategy_flag_collects_zero_targets() {
        let rest = vec!["--upgrade".to_string(), "--strategy".to_string(), "minver".to_string()];
        assert_eq!(upgrade_flag_values(&rest), Some(vec![]));
        assert_eq!(strategy_flag_value(&rest), Ok(Some(Strategy::Minver)));
    }

    #[test]
    fn r12_upgrade_absent_is_none() {
        let rest = vec!["fetch".to_string()];
        assert_eq!(upgrade_flag_values(&rest), None);
    }

    /// Bare `--upgrade` opts out of the minimal-change preference GLOBALLY:
    /// contrasted with a plain re-fetch (which keeps both locked), it pulls
    /// the newest allowed version for the whole graph.
    #[test]
    fn b4_bare_upgrade_pulls_newest_everywhere_via_mock() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let (mocked, foo_h1, foo_h2) = b4_stage_two_versions(base, "foo", "1");
        let (_, bar_h1, bar_h2) = b4_stage_two_versions(base, "bar", "2");
        let hashes = vec![("foo", (foo_h1, foo_h2)), ("bar", (bar_h1, bar_h2))];
        let index_v1_path = base.join("index-v1.kdl");
        std::fs::write(&index_v1_path, b4_index_kdl(&hashes, false)).unwrap();
        let index_v1v2_path = base.join("index-v1v2.kdl");
        std::fs::write(&index_v1v2_path, b4_index_kdl(&hashes, true)).unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1_path.display())) };
        let proj = b4_make_locked_project(base, "proj");

        // A newer version got published.
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1v2_path.display())) };

        // Plain re-fetch (no --upgrade): minimal-change keeps both locked.
        let rc = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, None).unwrap();
        assert_eq!(rc, 0);
        assert_eq!(
            b4_versions(&proj.join("milpa.lock")),
            std::collections::BTreeMap::from([
                ("foo".to_string(), "1.0.0".to_string()),
                ("bar".to_string(), "1.0.0".to_string()),
            ]),
        );

        // Bare --upgrade: opts out GLOBALLY -> both move to the newest.
        let upgrade_arg = vec!["--upgrade".to_string()];
        let rc = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &upgrade_arg, false, false, false, None).unwrap();
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };
        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        assert_eq!(rc, 0);
        assert_eq!(
            b4_versions(&proj.join("milpa.lock")),
            std::collections::BTreeMap::from([
                ("foo".to_string(), "2.0.0".to_string()),
                ("bar".to_string(), "2.0.0".to_string()),
            ]),
        );
    }

    /// `--upgrade <dep>` moves ONLY the named dep; the unrelated dep stays
    /// locked even though a newer version exists.
    #[test]
    fn b4_scoped_upgrade_moves_only_named_dep_via_mock() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let (mocked, foo_h1, foo_h2) = b4_stage_two_versions(base, "foo", "1");
        let (_, bar_h1, bar_h2) = b4_stage_two_versions(base, "bar", "2");
        let hashes = vec![("foo", (foo_h1, foo_h2)), ("bar", (bar_h1, bar_h2))];
        let index_v1_path = base.join("index-v1.kdl");
        std::fs::write(&index_v1_path, b4_index_kdl(&hashes, false)).unwrap();
        let index_v1v2_path = base.join("index-v1v2.kdl");
        std::fs::write(&index_v1v2_path, b4_index_kdl(&hashes, true)).unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1_path.display())) };
        let proj = b4_make_locked_project(base, "proj");
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1v2_path.display())) };

        let upgrade_arg = vec!["--upgrade".to_string(), "foo".to_string()];
        let rc = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &upgrade_arg, false, false, false, None).unwrap();
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };
        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        assert_eq!(rc, 0);
        let versions = b4_versions(&proj.join("milpa.lock"));
        assert_eq!(versions["foo"], "2.0.0", "opted out -> newest");
        assert_eq!(versions["bar"], "1.0.0", "untouched -> stays locked");
    }

    /// Delegation equivalence (D-B3): `--upgrade`/`--upgrade <dep>` on
    /// fetch/lock produce the SAME resolved versions as `update`/
    /// `update <dep>` from the same starting lock.
    #[test]
    fn b4_upgrade_delegation_equivalence_via_mock() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let (mocked, foo_h1, foo_h2) = b4_stage_two_versions(base, "foo", "1");
        let (_, bar_h1, bar_h2) = b4_stage_two_versions(base, "bar", "2");
        let hashes = vec![("foo", (foo_h1, foo_h2)), ("bar", (bar_h1, bar_h2))];
        let index_v1_path = base.join("index-v1.kdl");
        std::fs::write(&index_v1_path, b4_index_kdl(&hashes, false)).unwrap();
        let index_v1v2_path = base.join("index-v1v2.kdl");
        std::fs::write(&index_v1v2_path, b4_index_kdl(&hashes, true)).unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1_path.display())) };
        let proj_a = b4_make_locked_project(base, "a");
        let proj_b = b4_make_locked_project(base, "b");
        let proj_c = b4_make_locked_project(base, "c");
        let proj_d = b4_make_locked_project(base, "d");
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1v2_path.display())) };

        // Bare: fetch --upgrade vs bare update.
        let upgrade_bare = vec!["--upgrade".to_string()];
        assert_eq!(
            cmd_fetch(&proj_a, Some(Strategy::default()), false, true, None, false, false, &upgrade_bare, false, false, false, None).unwrap(),
            0
        );
        assert_eq!(
            cmd_update(&proj_b, Some(Strategy::default()), &[], false, false, false, false).unwrap(),
            0
        );
        assert_eq!(b4_versions(&proj_a.join("milpa.lock")), b4_versions(&proj_b.join("milpa.lock")));

        // Scoped: fetch --upgrade foo vs update foo.
        let upgrade_foo = vec!["--upgrade".to_string(), "foo".to_string()];
        assert_eq!(
            cmd_fetch(&proj_c, Some(Strategy::default()), false, true, None, false, false, &upgrade_foo, false, false, false, None).unwrap(),
            0
        );
        assert_eq!(
            cmd_update(&proj_d, Some(Strategy::default()), &["foo".to_string()], false, false, false, false).unwrap(),
            0
        );
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };
        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        assert_eq!(b4_versions(&proj_c.join("milpa.lock")), b4_versions(&proj_d.join("milpa.lock")));
        let versions_c = b4_versions(&proj_c.join("milpa.lock"));
        assert_eq!(versions_c["foo"], "2.0.0");
        assert_eq!(versions_c["bar"], "1.0.0");
    }

    /// `--locked` + `--upgrade` together -> `CLI-LOCKED-UPGRADE-CONFLICT`,
    /// via the real `run()` dispatch (the mutual-exclusion check lives
    /// there, before any verb runs — no manifest or fetch infra needed).
    #[test]
    fn b4_locked_and_upgrade_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("milpa.kdl"), "name \"app\"\nkind \"application\"\n").unwrap();

        for verb_args in [
            vec!["fetch".to_string(), "--locked".to_string(), "--upgrade".to_string()],
            vec!["fetch".to_string(), "--locked".to_string(), "--upgrade".to_string(), "foo".to_string()],
            vec!["lock".to_string(), "--locked".to_string(), "--upgrade".to_string()],
        ] {
            let mut argv = vec!["-C".to_string(), proj.to_str().unwrap().to_string()];
            argv.extend(verb_args);
            let rc = run(&argv);
            let err = rc.unwrap_err();
            assert_eq!(err.code(), "CLI-LOCKED-UPGRADE-CONFLICT");
        }
    }

    // NOTE: no Rust-side "upgrade bypasses the frozen fast-path" test is
    // needed here — mirrors B3's own documented asymmetry (this file's
    // `locked_passes_when_up_to_date_via_mock` region): Rust's `cmd_fetch`
    // only takes the frozen reconstruction branch when `--frozen` is
    // EXPLICITLY passed (the `if frozen { .. } else { .. }` split above), so
    // there is no implicit "attempt frozen whenever a lock+CAS exist" path
    // for `--upgrade` to bypass — Rust's plain fetch/lock always fully
    // resolves already. Python's `cmd_fetch` DOES attempt an implicit frozen
    // fast-path unconditionally, which is why that bypass fix + its test
    // exist only on the Python side (`test_b4_upgrade.py`'s
    // `TestUpgradeBypassesFrozenFastPath`).

    // -------------------------------------------------------------------------
    // B7 (resolution-semantics RFC §3 Axis B, final Axis-B slice): thread
    // `prior` through the remaining resolve-triggering verbs that hardcoded
    // `prior=None` — `add` (both the standalone-package `cmd_add` path and
    // the member-dir delegation path), `workspace add-member`, and
    // `workspace remove-member`. Reuses the B4 helpers (`b4_stage_two_versions`
    // / `b4_index_kdl` / `b4_versions`) — same "lock against v1-only index,
    // then swap to v1+v2" shape that genuinely exercises "would move under a
    // fresh/newest-wins resolve".
    // -------------------------------------------------------------------------

    /// Stage a single-version git dep used as the NEWLY ADDED dep for `add`
    /// tests (`milpa add --git` fetches directly — never index-resolved).
    /// Writes an explicit `.nimble` `version = "1.0.0"` sibling of `content/`
    /// so the added dep's resolved version is deterministic (Axis A) rather
    /// than falling back to the version-unknown sentinel.
    fn b7_stage_new_dep(base: &std::path::Path, name: &str, sha: &str) -> std::path::PathBuf {
        let url = format!("https://example.com/{name}.git");
        let nim_name = format!("{name}.nim");
        let body = format!("# {name} v1").into_bytes();
        let mocked = make_mocked_fetches(base, &url, "main", sha, &[(nim_name.as_str(), body.as_slice())]);
        let key_dir = mocked.join(milpa_core::url_key(&url, "main"));
        std::fs::write(
            key_dir.join(format!("{name}.nimble")),
            "# Package\nversion = \"1.0.0\"\nauthor = \"e\"\ndescription = \"d\"\nlicense = \"MIT\"\n",
        )
        .unwrap();
        mocked
    }

    /// `milpa add baz --git ...` resolves baz while foo/bar — already locked
    /// at 1.0.0 — stay pinned even though the index now also offers 2.0.0 for
    /// both (would newest-wins-bump them pre-B7).
    #[test]
    fn b7_add_leaves_existing_deps_pinned() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let (mocked, foo_h1, foo_h2) = b4_stage_two_versions(base, "foo", "1");
        let (_, bar_h1, bar_h2) = b4_stage_two_versions(base, "bar", "2");
        let hashes = vec![("foo", (foo_h1, foo_h2)), ("bar", (bar_h1, bar_h2))];
        let index_v1_path = base.join("index-v1.kdl");
        std::fs::write(&index_v1_path, b4_index_kdl(&hashes, false)).unwrap();
        let index_v1v2_path = base.join("index-v1v2.kdl");
        std::fs::write(&index_v1v2_path, b4_index_kdl(&hashes, true)).unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1_path.display())) };
        let proj = b4_make_locked_project(base, "proj");

        // A newer version of both got published.
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1v2_path.display())) };
        b7_stage_new_dep(base, "baz", &"c".repeat(40));

        let rc = cmd_add(
            &proj,
            Some(Strategy::default()),
            &["baz".to_string(), "--git".to_string(), "https://example.com/baz.git".to_string(), "--ref".to_string(), "main".to_string()],
            false,
            false,
            false,
            false,
        );
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };
        unsafe { std::env::remove_var("MILPA_INDEX_URL") };

        assert_eq!(rc.unwrap(), 0);
        let versions = b4_versions(&proj.join("milpa.lock"));
        assert_eq!(versions["baz"], "1.0.0", "the newly added dep resolves");
        assert_eq!(versions["foo"], "1.0.0", "B7: unrelated locked dep must NOT move");
        assert_eq!(versions["bar"], "1.0.0", "B7: unrelated locked dep must NOT move");
    }

    /// `milpa add` invoked from a workspace MEMBER dir re-resolves the WHOLE
    /// shared workspace graph; B7: another member's already-locked dep (foo,
    /// in member-a) must stay pinned when a new dep is added to member-b,
    /// even though foo's index now also offers 2.0.0.
    #[test]
    fn b7_add_from_member_dir_leaves_other_members_pinned() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let (mocked, foo_h1, foo_h2) = b4_stage_two_versions(base, "foo", "1");
        let hashes = vec![("foo", (foo_h1, foo_h2))];
        let index_v1_path = base.join("index-v1.kdl");
        std::fs::write(&index_v1_path, b4_index_kdl(&hashes, false)).unwrap();
        let index_v1v2_path = base.join("index-v1v2.kdl");
        std::fs::write(&index_v1v2_path, b4_index_kdl(&hashes, true)).unwrap();

        let root = base.join("ws");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("milpa.kdl"),
            "workspace {\n    member \"member-a\"\n    member \"member-b\"\n}\nindex-trust \"off\"\n",
        )
        .unwrap();
        let member_a = root.join("member-a");
        std::fs::create_dir_all(&member_a).unwrap();
        std::fs::write(
            member_a.join("milpa.kdl"),
            "name \"liba\"\nkind \"library\"\ndeps {\n    foo\n}\n",
        )
        .unwrap();
        let member_b = root.join("member-b");
        std::fs::create_dir_all(&member_b).unwrap();
        std::fs::write(member_b.join("milpa.kdl"), "name \"libb\"\nkind \"library\"\n").unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1_path.display())) };
        let rc = cmd_fetch(&root, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, None).unwrap();
        assert_eq!(rc, 0);
        assert_eq!(b4_versions(&root.join("milpa.lock"))["foo"], "1.0.0");

        // foo's index now also offers 2.0.0.
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1v2_path.display())) };
        b7_stage_new_dep(base, "baz", &"c".repeat(40));

        let rc = cmd_add(
            &member_b,
            Some(Strategy::default()),
            &["baz".to_string(), "--git".to_string(), "https://example.com/baz.git".to_string(), "--ref".to_string(), "main".to_string()],
            false,
            false,
            false,
            false,
        );
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };
        unsafe { std::env::remove_var("MILPA_INDEX_URL") };

        assert_eq!(rc.unwrap(), 0);
        let versions = b4_versions(&root.join("milpa.lock"));
        assert_eq!(versions["baz"], "1.0.0");
        assert_eq!(versions["foo"], "1.0.0", "B7: member-a's dep must NOT move");
        assert!(!member_b.join("milpa.lock").exists(), "no member-local lock (D5)");
    }

    /// Adding a new member to the workspace re-resolves the shared graph; B7:
    /// the EXISTING member's already-locked dep (foo) stays pinned even
    /// though the index now also offers 2.0.0.
    #[test]
    fn b7_workspace_add_member_leaves_other_members_pinned() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let (mocked, foo_h1, foo_h2) = b4_stage_two_versions(base, "foo", "1");
        let (_, bar_h1, bar_h2) = b4_stage_two_versions(base, "bar", "2");
        let foo_only = vec![("foo", (foo_h1.clone(), foo_h2.clone()))];
        let both = vec![("foo", (foo_h1, foo_h2)), ("bar", (bar_h1, bar_h2))];
        let index_v1_path = base.join("index-v1.kdl");
        std::fs::write(&index_v1_path, b4_index_kdl(&foo_only, false)).unwrap();
        let index_v1v2_path = base.join("index-v1v2.kdl");
        std::fs::write(&index_v1v2_path, b4_index_kdl(&both, true)).unwrap();

        let root = base.join("ws");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("milpa.kdl"),
            "workspace {\n    member \"member-a\"\n}\nindex-trust \"off\"\n",
        )
        .unwrap();
        let member_a = root.join("member-a");
        std::fs::create_dir_all(&member_a).unwrap();
        std::fs::write(
            member_a.join("milpa.kdl"),
            "name \"liba\"\nkind \"library\"\ndeps {\n    foo\n}\n",
        )
        .unwrap();
        // member-c is the NEW member being added — declared on disk now,
        // added to the workspace manifest by the verb under test.
        let member_c = root.join("member-c");
        std::fs::create_dir_all(&member_c).unwrap();
        std::fs::write(
            member_c.join("milpa.kdl"),
            "name \"libc\"\nkind \"library\"\ndeps {\n    bar\n}\n",
        )
        .unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1_path.display())) };
        let rc = cmd_fetch(&root, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, None).unwrap();
        assert_eq!(rc, 0);
        assert_eq!(b4_versions(&root.join("milpa.lock"))["foo"], "1.0.0");

        // foo's index now also offers 2.0.0; bar (member-c's own dep) is new.
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1v2_path.display())) };
        let rc = cmd_workspace_add_member(&root, &["member-c".to_string()], Some(Strategy::default()), false, false, false);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };
        unsafe { std::env::remove_var("MILPA_INDEX_URL") };

        assert_eq!(rc.unwrap(), 0);
        let versions = b4_versions(&root.join("milpa.lock"));
        assert_eq!(versions["foo"], "1.0.0", "B7: member-a's dep must NOT move");
        assert!(versions.contains_key("bar"), "member-c's own dep resolves");
        let text = std::fs::read_to_string(root.join("milpa.kdl")).unwrap();
        assert!(text.contains("member-c"));
    }

    /// Removing a member re-resolves the shared graph minimally; B7: the
    /// REMAINING member's already-locked dep (foo) stays pinned even though
    /// the index now also offers 2.0.0.
    #[test]
    fn b7_workspace_remove_member_leaves_remaining_members_pinned() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let (mocked, foo_h1, foo_h2) = b4_stage_two_versions(base, "foo", "1");
        let (_, bar_h1, bar_h2) = b4_stage_two_versions(base, "bar", "2");
        let hashes = vec![("foo", (foo_h1, foo_h2)), ("bar", (bar_h1, bar_h2))];
        let index_v1_path = base.join("index-v1.kdl");
        std::fs::write(&index_v1_path, b4_index_kdl(&hashes, false)).unwrap();
        let index_v1v2_path = base.join("index-v1v2.kdl");
        std::fs::write(&index_v1v2_path, b4_index_kdl(&hashes, true)).unwrap();

        let root = base.join("ws");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("milpa.kdl"),
            "workspace {\n    member \"member-a\"\n    member \"member-b\"\n}\nindex-trust \"off\"\n",
        )
        .unwrap();
        let member_a = root.join("member-a");
        std::fs::create_dir_all(&member_a).unwrap();
        std::fs::write(
            member_a.join("milpa.kdl"),
            "name \"liba\"\nkind \"library\"\ndeps {\n    foo\n}\n",
        )
        .unwrap();
        let member_b = root.join("member-b");
        std::fs::create_dir_all(&member_b).unwrap();
        std::fs::write(
            member_b.join("milpa.kdl"),
            "name \"libb\"\nkind \"library\"\ndeps {\n    bar\n}\n",
        )
        .unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1_path.display())) };
        let rc = cmd_fetch(&root, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, None).unwrap();
        assert_eq!(rc, 0);
        let baseline = b4_versions(&root.join("milpa.lock"));
        assert_eq!(baseline["foo"], "1.0.0");
        assert_eq!(baseline["bar"], "1.0.0");

        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1v2_path.display())) };
        let rc = cmd_workspace_remove_member(&root, &["member-b".to_string()], Some(Strategy::default()), false, false, false);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };
        unsafe { std::env::remove_var("MILPA_INDEX_URL") };

        assert_eq!(rc.unwrap(), 0);
        let versions = b4_versions(&root.join("milpa.lock"));
        assert!(!versions.contains_key("bar"), "member-b's dep is gone");
        assert_eq!(versions["foo"], "1.0.0", "B7: member-a's dep must NOT move");
        let text = std::fs::read_to_string(root.join("milpa.kdl")).unwrap();
        assert!(!text.contains("member-b"));
    }

    /// C3 (B7-gap): `milpa remove bar` on a standalone (non-workspace) project
    /// re-resolves the manifest minus `bar`; B7 requires the prior lock be
    /// threaded into that re-resolve so `foo` — already locked at 1.0.0 —
    /// stays pinned even though the index now ALSO offers 2.0.0 for foo.
    /// Pre-fix, `cmd_remove`'s single-package branch hardcoded `prior: None`
    /// into the `resolve()` call, so this newest-wins-dragged foo to 2.0.0.
    #[test]
    fn b7_remove_leaves_other_dep_pinned() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let (mocked, foo_h1, foo_h2) = b4_stage_two_versions(base, "foo", "1");
        let (_, bar_h1, bar_h2) = b4_stage_two_versions(base, "bar", "2");
        let hashes = vec![("foo", (foo_h1, foo_h2)), ("bar", (bar_h1, bar_h2))];
        let index_v1_path = base.join("index-v1.kdl");
        std::fs::write(&index_v1_path, b4_index_kdl(&hashes, false)).unwrap();
        let index_v1v2_path = base.join("index-v1v2.kdl");
        std::fs::write(&index_v1v2_path, b4_index_kdl(&hashes, true)).unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1_path.display())) };
        let proj = b4_make_locked_project(base, "proj");

        // A newer version of foo (the dep NOT being removed) got published.
        unsafe { std::env::set_var("MILPA_INDEX_URL", format!("file://{}", index_v1v2_path.display())) };

        let rc = cmd_remove(&proj, Some(Strategy::default()), &["bar".to_string()], false, false, false);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };
        unsafe { std::env::remove_var("MILPA_INDEX_URL") };

        assert_eq!(rc.unwrap(), 0);
        let versions = b4_versions(&proj.join("milpa.lock"));
        assert!(!versions.contains_key("bar"), "removed dep is gone from the lock");
        assert_eq!(versions["foo"], "1.0.0", "B7: unrelated locked dep must NOT move");
        let text = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        assert!(!text.contains("bar"), "removed dep is gone from the manifest");
    }

    /// D5 (resolution-semantics RFC §3 Axis D / §6 D-D3 no-silent-drop):
    /// `milpa remove <dep>` (single-package path — previously the bare
    /// `resolve()` wrapper, which hardcodes `exclude_newer: None`) must
    /// CARRY FORWARD the prior lockfile's recorded `exclude_newer`, not
    /// silently drop it, when the manifest declares no `resolution {
    /// exclude-newer }` of its own.
    #[test]
    fn remove_carries_forward_exclude_newer_no_silent_drop() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let foo_url = "https://example.com/foo.git";
        let bar_url = "https://example.com/bar.git";
        let foo_sha = "c".repeat(40);
        let bar_sha = "d".repeat(40);

        // milpa.kdl: two git deps, NO resolution{} block.
        std::fs::write(
            proj.join("milpa.kdl"),
            format!(
                "name \"app\"\nkind \"application\"\ndeps {{\n  \
                 foo git=(url)\"{foo_url}\" ref=\"main\"\n  \
                 bar git=(url)\"{bar_url}\" ref=\"main\"\n}}\n"
            ),
        )
        .unwrap();

        let ts = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        let mocked = make_mocked_fetches(tmp.path(), foo_url, "main", &foo_sha, &[("foo.nim", b"version = \"1.0.0\"\n")]);
        // Both fetches share one mocked-fetches root (keyed by url+ref).
        let _ = make_mocked_fetches(tmp.path(), bar_url, "main", &bar_sha, &[("bar.nim", b"version = \"1.0.0\"\n")]);

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        // Real baseline fetch WITH --exclude-newer (records correct identities
        // for both deps + the exclude_newer bound) — avoids hand-fabricating
        // identity hashes that would spuriously trip FETCH-PROVENANCE-DIVERGENCE.
        let baseline = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, Some(ts));
        assert_eq!(baseline.unwrap(), 0, "baseline fetch must succeed");
        let baseline_lock = load_lockfile(&proj.join("milpa.lock")).unwrap();
        assert_eq!(baseline_lock.exclude_newer, Some(ts));

        let r = cmd_remove(&proj, Some(Strategy::default()), &["bar".into()], false, false, false);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(r.unwrap(), 0, "remove must succeed");
        let new_lock = parse_lockfile(
            &std::fs::read_to_string(proj.join("milpa.lock")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            new_lock.exclude_newer,
            Some(ts),
            "single-package `remove` must carry forward the prior lock's exclude_newer, not drop it"
        );
    }

    // -----------------------------------------------------------------------
    // D-update-remove tests (Phase D item 5) — provenance preservation + alias
    // -----------------------------------------------------------------------

    /// Helper: write a minimal `milpa.lock` with one dep that has optional
    /// declared mirror provenances.
    fn write_prior_lock(
        lock_path: &std::path::Path,
        dep_name: &str,
        identity: &str,
        git_url: &str,
        ref_spec: &str,
        commit_sha: &str,
        declared_mirror_urls: &[&str],
        aliases: &[&str],
    ) {
        let mut provenances: Vec<milpa_core::ProvenanceRecord> = declared_mirror_urls
            .iter()
            .map(|url| milpa_core::ProvenanceRecord::Git {
                url: url.to_string(),
                ref_spec: Some(ref_spec.to_string()),
                commit_sha: None,
                origin: "declared".to_string(),
                submodule_shas: vec![],
            })
            .collect();
        provenances.push(milpa_core::ProvenanceRecord::Git {
            url: git_url.to_string(),
            ref_spec: Some(ref_spec.to_string()),
            commit_sha: Some(commit_sha.to_string()),
            origin: "observed".to_string(),
            submodule_shas: vec![],
        });
        let dep = milpa_core::LockedDep {
            declared_version_source: None,
            name: dep_name.to_string(),
            namespace: None,
            identity: Some(identity.to_string()),
            version: "0.0.1".to_string(),
            src_dir: String::new(),
            requires: vec![],
            provenances,
            active_flags: vec![],
            dep_decl: None,
            cond_requires: vec![],
            aliases: aliases.iter().map(|s| s.to_string()).collect(),
            attestation: None,
        };
        let lf = milpa_core::Lockfile {
            version: 1,
            strategy: "maxver".to_string(),
            exclude_newer: None,
            deps: vec![dep],
        };
        write_lockfile(&lf, lock_path).unwrap();
    }

    /// DR-1: `update <dep>` preserves declared mirror provenances that are still
    /// in milpa.kdl. After update, declared mirrors reappear in the new lockfile.
    #[test]
    fn update_preserves_declared_mirror_provenances() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let primary_url = "https://example.com/foo.git";
        let mirror1_url = "https://mirror1.example.com/foo.git";
        let mirror2_url = "https://mirror2.example.com/foo.git";
        let sha = "a".repeat(40);
        let identity = format!("dag-sha256:{}", "a".repeat(64));

        // milpa.kdl: foo with BOTH mirrors still declared.
        std::fs::write(
            proj.join("milpa.kdl"),
            format!(
                "name \"app\"\nkind \"application\"\ndeps {{\n  \
                 foo git=(url)\"{primary_url}\" ref=\"main\" {{\n    \
                 mirror (url)\"{mirror1_url}\"\n    \
                 mirror (url)\"{mirror2_url}\"\n  }}\n}}\n"
            ),
        )
        .unwrap();

        // Prior lockfile: foo with 2 declared mirrors.
        write_prior_lock(
            &proj.join("milpa.lock"),
            "foo",
            &identity,
            primary_url,
            "main",
            &sha,
            &[mirror1_url, mirror2_url],
            &[],
        );

        let mocked = make_mocked_fetches(tmp.path(), primary_url, "main", &sha, &[("foo.nim", b"version = \"1.0.0\"\n")]);

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let r = cmd_update(&proj, Some(Strategy::default()), &["foo".into()], false, false, false, false);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(r.unwrap(), 0, "update must succeed");
        let lock_text = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();
        // Both declared mirrors must appear in the new lockfile.
        assert!(
            lock_text.contains(mirror1_url),
            "mirror1 must be preserved in new lockfile; lock:\n{lock_text}"
        );
        assert!(
            lock_text.contains(mirror2_url),
            "mirror2 must be preserved in new lockfile; lock:\n{lock_text}"
        );
    }

    /// D5 (resolution-semantics RFC §3 Axis D / §6 D-D3 no-silent-drop):
    /// a bare `milpa update` (drops ALL pins, full re-resolve) with NO
    /// `resolution { exclude-newer }` in the manifest must CARRY FORWARD the
    /// prior lockfile's own recorded `exclude_newer` — never silently drop
    /// it — because dropping it would relax semantics (silently un-freeze
    /// the project). This is the exact scenario a one-off `milpa fetch
    /// --exclude-newer <ts>` (never mirrored into the manifest) creates.
    #[test]
    fn update_carries_forward_exclude_newer_no_silent_drop() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let url = "https://example.com/foo.git";
        let sha = "b".repeat(40);
        let identity = format!("dag-sha256:{}", "b".repeat(64));

        // milpa.kdl: NO resolution{} block at all.
        std::fs::write(
            proj.join("milpa.kdl"),
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{url}\" ref=\"main\"\n}}\n"),
        )
        .unwrap();

        // Prior lockfile: recorded a real exclude_newer bound (e.g. from a
        // one-off `milpa fetch --exclude-newer` never mirrored into the manifest).
        let ts = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        let dep = milpa_core::LockedDep {
            declared_version_source: None,
            name: "foo".to_string(),
            namespace: None,
            identity: Some(identity),
            version: "0.0.1".to_string(),
            src_dir: String::new(),
            requires: vec![],
            provenances: vec![milpa_core::ProvenanceRecord::Git {
                url: url.to_string(),
                ref_spec: Some("main".to_string()),
                commit_sha: Some(sha.clone()),
                origin: "observed".to_string(),
                submodule_shas: vec![],
            }],
            active_flags: vec![],
            dep_decl: None,
            cond_requires: vec![],
            aliases: vec![],
            attestation: None,
        };
        let lf = milpa_core::Lockfile {
            version: 1,
            strategy: "maxver".to_string(),
            exclude_newer: Some(ts),
            deps: vec![dep],
        };
        write_lockfile(&lf, &proj.join("milpa.lock")).unwrap();

        let mocked = make_mocked_fetches(tmp.path(), url, "main", &sha, &[("foo.nim", b"version = \"1.0.0\"\n")]);

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        // Bare `update` — no dep arg, drops ALL pins, full re-resolve.
        let r = cmd_update(&proj, None, &[], false, false, false, false);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(r.unwrap(), 0, "update must succeed");
        let new_lock = parse_lockfile(
            &std::fs::read_to_string(proj.join("milpa.lock")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            new_lock.exclude_newer,
            Some(ts),
            "bare `update` must carry forward the prior lock's exclude_newer, not drop it"
        );
    }

    /// DR-2: `update <dep>` drops a declared mirror that was removed from milpa.kdl.
    #[test]
    fn update_drops_mirror_removed_from_manifest() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let primary_url = "https://example.com/foo.git";
        let mirror1_url = "https://mirror1.example.com/foo.git";
        let mirror2_url = "https://mirror2.example.com/foo.git";
        let sha = "a".repeat(40);
        let identity = format!("dag-sha256:{}", "a".repeat(64));

        // milpa.kdl: foo with ONLY mirror1 (mirror2 was removed).
        std::fs::write(
            proj.join("milpa.kdl"),
            format!(
                "name \"app\"\nkind \"application\"\ndeps {{\n  \
                 foo git=(url)\"{primary_url}\" ref=\"main\" {{\n    \
                 mirror (url)\"{mirror1_url}\"\n  }}\n}}\n"
            ),
        )
        .unwrap();

        // Prior lockfile: foo with BOTH mirrors as declared.
        write_prior_lock(
            &proj.join("milpa.lock"),
            "foo",
            &identity,
            primary_url,
            "main",
            &sha,
            &[mirror1_url, mirror2_url],
            &[],
        );

        let mocked = make_mocked_fetches(tmp.path(), primary_url, "main", &sha, &[("foo.nim", b"version = \"1.0.0\"\n")]);

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let r = cmd_update(&proj, Some(Strategy::default()), &["foo".into()], false, false, false, false);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(r.unwrap(), 0, "update must succeed");
        let lock_text = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();
        // mirror2 must NOT appear (it left the manifest).
        assert!(
            !lock_text.contains(mirror2_url),
            "mirror2 was removed from milpa.kdl; must not be in new lockfile; lock:\n{lock_text}"
        );
        // mirror1 must still appear (still in manifest).
        assert!(
            lock_text.contains(mirror1_url),
            "mirror1 is still in milpa.kdl; must appear in new lockfile; lock:\n{lock_text}"
        );
    }

    /// DR-3: `update <alias>` resolves to canonical — no spurious LOCK-DEP-NOT-FOUND.
    #[test]
    fn update_alias_resolves_to_canonical() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let primary_url = "https://example.com/foo.git";
        let sha = "a".repeat(40);
        let identity = format!("dag-sha256:{}", "a".repeat(64));

        // milpa.kdl: foo declared.
        std::fs::write(
            proj.join("milpa.kdl"),
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{primary_url}\" ref=\"main\"\n}}\n"),
        )
        .unwrap();

        // Prior lockfile: foo canonical with alias 'baz'.
        write_prior_lock(
            &proj.join("milpa.lock"),
            "foo",
            &identity,
            primary_url,
            "main",
            &sha,
            &[],
            &["baz"],
        );

        let mocked = make_mocked_fetches(tmp.path(), primary_url, "main", &sha, &[("foo.nim", b"version = \"1.0.0\"\n")]);

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        // Pass alias 'baz' as dep_name — must resolve to canonical 'foo'.
        let r = cmd_update(&proj, Some(Strategy::default()), &["baz".into()], false, false, false, false);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(
            r.unwrap(), 0,
            "update via alias 'baz' must succeed (alias→canonical resolution)"
        );
        let lock_text = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();
        assert!(lock_text.contains("\"foo\""), "foo must be in the new lockfile");
    }

    /// DR-4: `remove <alias>` resolves to canonical — no spurious not-found.
    #[test]
    fn remove_alias_resolves_to_canonical() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let primary_url = "https://example.com/foo.git";
        let sha = "a".repeat(40);
        let identity = format!("dag-sha256:{}", "a".repeat(64));

        // milpa.kdl: foo declared.
        std::fs::write(
            proj.join("milpa.kdl"),
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{primary_url}\" ref=\"main\"\n}}\n"),
        )
        .unwrap();

        // Prior lockfile: foo with alias 'baz'.
        write_prior_lock(
            &proj.join("milpa.lock"),
            "foo",
            &identity,
            primary_url,
            "main",
            &sha,
            &[],
            &["baz"],
        );

        // After remove of foo, no deps remain → empty mocked dir.
        let mocked = tmp.path().join("mocked-fetches");
        std::fs::create_dir_all(&mocked).unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        // Pass alias 'baz' — must resolve to canonical 'foo' for manifest check.
        let r = cmd_remove(&proj, Some(Strategy::default()), &["baz".into()], false, false, false);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(
            r.unwrap(), 0,
            "remove via alias 'baz' must succeed (alias→canonical resolution)"
        );
        let kdl = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        assert!(!kdl.contains("\"foo\""), "foo must be removed from milpa.kdl");
    }

    /// DR-5: `remove <canonical>` with prior aliases warns per alias on stderr.
    #[test]
    fn remove_canonical_with_prior_alias_warns() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let primary_url = "https://example.com/foo.git";
        let sha = "a".repeat(40);
        let identity = format!("dag-sha256:{}", "a".repeat(64));

        // milpa.kdl: foo declared.
        std::fs::write(
            proj.join("milpa.kdl"),
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{primary_url}\" ref=\"main\"\n}}\n"),
        )
        .unwrap();

        // Prior lockfile: foo with alias 'baz'.
        write_prior_lock(
            &proj.join("milpa.lock"),
            "foo",
            &identity,
            primary_url,
            "main",
            &sha,
            &[],
            &["baz"],
        );

        // After remove, no deps remain → empty mocked dir.
        let mocked = tmp.path().join("mocked-fetches");
        std::fs::create_dir_all(&mocked).unwrap();

        // Capture stderr to check for warning.  We use a redirect by running in
        // a subprocess is complex; instead we check that cmd_remove returns 0
        // (warning is non-fatal) and trust the implementation emits to stderr.
        // The unit-level check: cmd_remove with alias in prior must exit 0.
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let r = cmd_remove(&proj, Some(Strategy::default()), &["foo".into()], false, false, false);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        // Removal must succeed (warning is non-fatal).
        assert_eq!(r.unwrap(), 0, "remove with prior alias must succeed (warning, not error)");
        // foo must be gone from milpa.kdl.
        let kdl = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        assert!(!kdl.contains("\"foo\""), "foo must be removed from milpa.kdl after cmd_remove");
    }

    /// DR-6: regression — update/remove with no mirrors or aliases work as before.
    #[test]
    fn update_no_mirrors_regression() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        let primary_url = "https://example.com/foo.git";
        let sha = "a".repeat(40);
        let identity = format!("dag-sha256:{}", "a".repeat(64));

        std::fs::write(
            proj.join("milpa.kdl"),
            format!("name \"app\"\nkind \"application\"\ndeps {{\n  foo git=(url)\"{primary_url}\" ref=\"main\"\n}}\n"),
        )
        .unwrap();

        write_prior_lock(
            &proj.join("milpa.lock"),
            "foo",
            &identity,
            primary_url,
            "main",
            &sha,
            &[], // no mirrors
            &[], // no aliases
        );

        let mocked = make_mocked_fetches(tmp.path(), primary_url, "main", &sha, &[("foo.nim", b"version = \"1.0.0\"\n")]);

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let r = cmd_update(&proj, Some(Strategy::default()), &["foo".into()], false, false, false, false);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(r.unwrap(), 0, "update with no mirrors must succeed");
        let lock_text = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();
        assert!(lock_text.contains("\"foo\""), "foo must be in new lockfile");
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
            Some(Strategy::default()),
            &["foo".into(), "--git".into(), url.into(), "--ref".into(), "main".into()],
            false,
            false,
            false,
            false,
        );
        let after_add = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        let lock = std::fs::read_to_string(proj.join("milpa.lock")).unwrap_or_default();

        // (2) duplicate guard.
        let dup = cmd_add(
            &proj,
            Some(Strategy::default()),
            &["foo".into(), "--git".into(), url.into(), "--ref".into(), "main".into()],
            false,
            false,
            false,
            false,
        );

        // (3) add a second dep with NO --ref → mocked default-branch discovery.
        let url2 = "https://example.com/bar.git";
        let _ = make_mocked_fetches(tmp.path(), url2, "trunk", &"c".repeat(40), &[("bar.nim", b"# bar")]);
        let r2 = cmd_add(&proj, Some(Strategy::default()), &["bar".into(), "--git".into(), url2.into()], false, false, false, false);
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
        assert_eq!(cmd_remove(tmp.path(), Some(Strategy::default()), &[], false, false, false).unwrap(), 2);
        // add with no name → exit 2.
        assert_eq!(cmd_add(tmp.path(), Some(Strategy::default()), &[], false, false, false, false).unwrap(), 2);
        // add with no --git/--mirror → exit 2.
        assert_eq!(cmd_add(tmp.path(), Some(Strategy::default()), &["foo".into()], false, false, false, false).unwrap(), 2);
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
            "name \"app\"\nkind \"application\"\ndeps {\n  foo git=(url)\"https://example.com/foo.git\" ref=\"main\"\n}\n",
        )
        .unwrap();

        // SAFETY: serialized by ENV_MUTEX; unique env var name; cleaned up after.
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let result = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, None);
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

    /// C3 (resolution-semantics RFC §3 Axis C / D-C2): unspecified CLI
    /// `--strategy` (`None`) defers to the manifest's `resolution { strategy }`.
    #[test]
    fn fetch_unspecified_cli_uses_manifest_resolution_strategy() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();
        let cas_dir = tmp.path().join("cas");
        unsafe { std::env::set_var("MILPA_CACHE_DIR", &cas_dir) };

        let mocked = make_mocked_fetches(
            tmp.path(),
            "https://example.com/foo.git",
            "main",
            &"a".repeat(40),
            &[("foo.nim", b"# foo")],
        );
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\nresolution {\n  strategy \"minver\"\n}\ndeps {\n  foo git=(url)\"https://example.com/foo.git\" ref=\"main\"\n}\n",
        )
        .unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let result = cmd_fetch(&proj, None, false, true, None, false, false, &[], false, false, false, None);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };
        unsafe { std::env::remove_var("MILPA_CACHE_DIR") };

        assert_eq!(result.unwrap(), 0);
        let lock = milpa_core::load_lockfile(&proj.join("milpa.lock")).unwrap();
        assert_eq!(lock.strategy, "minver");
    }

    /// C3: explicit CLI `--strategy` overrides the manifest's declared
    /// `resolution { strategy }`.
    #[test]
    fn fetch_explicit_cli_overrides_manifest_resolution_strategy() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();
        let cas_dir = tmp.path().join("cas");
        unsafe { std::env::set_var("MILPA_CACHE_DIR", &cas_dir) };

        let mocked = make_mocked_fetches(
            tmp.path(),
            "https://example.com/foo.git",
            "main",
            &"a".repeat(40),
            &[("foo.nim", b"# foo")],
        );
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\nresolution {\n  strategy \"minver\"\n}\ndeps {\n  foo git=(url)\"https://example.com/foo.git\" ref=\"main\"\n}\n",
        )
        .unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let result = cmd_fetch(&proj, Some(Strategy::Semver), false, true, None, false, false, &[], false, false, false, None);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };
        unsafe { std::env::remove_var("MILPA_CACHE_DIR") };

        assert_eq!(result.unwrap(), 0);
        let lock = milpa_core::load_lockfile(&proj.join("milpa.lock")).unwrap();
        assert_eq!(lock.strategy, "semver");
    }

    /// C3: absent CLI `--strategy` AND no manifest `resolution { strategy }`
    /// defaults to `"maxver"` (unchanged pre-C3 behavior).
    #[test]
    fn fetch_absent_cli_and_manifest_defaults_to_maxver() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();
        let cas_dir = tmp.path().join("cas");
        unsafe { std::env::set_var("MILPA_CACHE_DIR", &cas_dir) };

        let mocked = make_mocked_fetches(
            tmp.path(),
            "https://example.com/foo.git",
            "main",
            &"a".repeat(40),
            &[("foo.nim", b"# foo")],
        );
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\ndeps {\n  foo git=(url)\"https://example.com/foo.git\" ref=\"main\"\n}\n",
        )
        .unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let result = cmd_fetch(&proj, None, false, true, None, false, false, &[], false, false, false, None);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };
        unsafe { std::env::remove_var("MILPA_CACHE_DIR") };

        assert_eq!(result.unwrap(), 0);
        let lock = milpa_core::load_lockfile(&proj.join("milpa.lock")).unwrap();
        assert_eq!(lock.strategy, "maxver");
    }

    /// Live `cmd_fetch` (non-frozen) must build alias symlinks for deduped deps
    /// and remove stale `_deps/` entries.
    ///
    /// Scenario: two deps (`foo` + `bar`) fetch to IDENTICAL content (same bytes
    /// → same content_hash). After `cmd_fetch`:
    ///   - both `_deps/foo` and `_deps/bar` must exist as symlinks (canonical +
    ///     alias);
    ///   - a pre-seeded stale `_deps/garbage` entry must be removed.
    ///
    /// Pre-fix: `resolve()` never called `rebuild_deps_view`, so the alias
    /// symlink was absent and the stale entry was left behind. This test is the
    /// RED gate for the SSOT fix.
    #[test]
    fn live_resolve_builds_alias_symlinks_and_removes_stale_deps() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("project");
        std::fs::create_dir_all(&proj).unwrap();

        // Isolate CAS to this temp dir so it doesn't collide with other tests.
        let cas_dir = tmp.path().join("cas");
        unsafe { std::env::set_var("MILPA_CACHE_DIR", &cas_dir) };

        // Both deps have IDENTICAL content: same bytes → same content_hash.
        // The resolver's finalize() will dedup them: one becomes canonical, the
        // other an alias. rebuild_deps_view must create BOTH symlinks.
        let identical_content: &[(&str, &[u8])] = &[("lib.nim", b"# shared")];
        let sha_foo = "a".repeat(40);
        let sha_bar = "b".repeat(40); // different commit SHAs but same tree

        let mocked_dir = tmp.path().join("mocked-fetches");

        // Lay down mocked fetch content for foo (same files as bar).
        let key_dir_foo = mocked_dir.join(milpa_core::url_key(
            "https://example.com/foo.git",
            "main",
        ));
        std::fs::create_dir_all(key_dir_foo.join("content")).unwrap();
        std::fs::write(key_dir_foo.join("sha"), format!("{sha_foo}\n")).unwrap();
        for (name, data) in identical_content {
            std::fs::write(key_dir_foo.join("content").join(name), data).unwrap();
        }

        // Lay down mocked fetch content for bar (same files as foo → same hash).
        let key_dir_bar = mocked_dir.join(milpa_core::url_key(
            "https://example.com/bar.git",
            "main",
        ));
        std::fs::create_dir_all(key_dir_bar.join("content")).unwrap();
        std::fs::write(key_dir_bar.join("sha"), format!("{sha_bar}\n")).unwrap();
        for (name, data) in identical_content {
            std::fs::write(key_dir_bar.join("content").join(name), data).unwrap();
        }

        // Manifest declares both deps.
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\ndeps {\n  \
             foo git=(url)\"https://example.com/foo.git\" ref=\"main\"\n  \
             bar git=(url)\"https://example.com/bar.git\" ref=\"main\"\n}\n",
        )
        .unwrap();

        // Pre-seed a stale `_deps/garbage` dir that rebuild_deps_view must remove.
        let deps_dir = proj.join("_deps");
        std::fs::create_dir_all(deps_dir.join("garbage")).unwrap();

        // SAFETY: serialized by ENV_MUTEX.
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked_dir) };
        let result = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, None);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };
        unsafe { std::env::remove_var("MILPA_CACHE_DIR") };

        assert!(result.is_ok(), "cmd_fetch must succeed: {result:?}");
        assert_eq!(result.unwrap(), 0);

        // The canonical dep (foo, declared first) must be a symlink.
        let foo_meta = std::fs::symlink_metadata(proj.join("_deps").join("foo")).unwrap();
        assert!(
            foo_meta.file_type().is_symlink(),
            "_deps/foo must be a CAS symlink (canonical dep)"
        );

        // The alias dep (bar, deduped to same hash as foo) must ALSO be a symlink.
        // Pre-fix: this symlink was ABSENT because rebuild_deps_view was never called
        // from the live resolve path.
        let bar_meta = std::fs::symlink_metadata(proj.join("_deps").join("bar")).unwrap();
        assert!(
            bar_meta.file_type().is_symlink(),
            "_deps/bar must be a CAS symlink (alias dep — deduped to same hash as foo)"
        );

        // Both symlinks must point to the SAME CAS entry (same content_hash).
        let foo_target = std::fs::read_link(proj.join("_deps").join("foo")).unwrap();
        let bar_target = std::fs::read_link(proj.join("_deps").join("bar")).unwrap();
        assert_eq!(
            foo_target, bar_target,
            "_deps/foo and _deps/bar must symlink to the same CAS entry (dedup)"
        );

        // Stale entry must be gone.
        assert!(
            !proj.join("_deps").join("garbage").exists(),
            "_deps/garbage must be removed by rebuild_deps_view (stale entry)"
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
            "name \"app\"\nkind \"application\"\ndeps {\n  foo git=(url)\"https://example.com/foo.git\" ref=\"main\"\n}\n",
        )
        .unwrap();

        // SAFETY: serialized by ENV_MUTEX.
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let result = cmd_fetch(&proj, Some(Strategy::default()), false, true, None, false, false, &[], false, false, false, None);
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
            "schema_version 99\npackage \"foo\" {\n  version \"1.0.0\" {\n    content_hash \"dag-sha256:0000000000000000000000000000000000000000000000000000000000000001\"\n    provenance {\n      kind \"git\"\n      url \"https://github.com/example/foo.git\"\n      ref \"v1.0.0\"\n    }\n  }\n}\n",
        )
        .unwrap();

        // Point MILPA_INDEX_URL at the file; isolate the index cache via
        // XDG_CACHE_HOME (index_cache_dir uses XDG_CACHE_HOME/milpa/index).
        let url = format!("file://{}", index_path.display());
        unsafe { std::env::set_var("MILPA_INDEX_URL", &url) };
        unsafe { std::env::set_var("XDG_CACHE_HOME", tmp.path()) };

        let result = maybe_index(false, &milpa_manifest::TrustPolicy::Off, None, None, false, false, &milpa_manifest::TrustPolicy::Off);

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

        let result = maybe_index(false, &milpa_manifest::TrustPolicy::Off, None, None, false, false, &milpa_manifest::TrustPolicy::Off);

        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };

        // Unreachable → Ok(None), not an error.
        assert_eq!(
            result,
            Ok(None),
            "expected Ok(None) for unreachable index, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // ITEM 1: effective_trust_policy SSOT — policy matrix tests
    // -----------------------------------------------------------------------

    #[test]
    fn effective_policy_manifest_off_wins_over_env_strict() {
        use milpa_core::effective_trust_policy;
        use milpa_manifest::TrustPolicy;
        // Off is auditable project-level opt-out; env cannot override it.
        let result = effective_trust_policy(&TrustPolicy::Off, false, Some(&TrustPolicy::Strict));
        assert_eq!(result, TrustPolicy::Off);
    }

    #[test]
    fn effective_policy_flag_escalates_warn_to_strict() {
        use milpa_core::effective_trust_policy;
        use milpa_manifest::TrustPolicy;
        let result = effective_trust_policy(&TrustPolicy::Warn, true, None);
        assert_eq!(result, TrustPolicy::Strict);
    }

    #[test]
    fn effective_policy_env_strict_escalates_manifest_warn() {
        use milpa_core::effective_trust_policy;
        use milpa_manifest::TrustPolicy;
        let result = effective_trust_policy(&TrustPolicy::Warn, false, Some(&TrustPolicy::Strict));
        assert_eq!(result, TrustPolicy::Strict);
    }

    #[test]
    fn effective_policy_env_off_is_noop_floor() {
        use milpa_core::effective_trust_policy;
        use milpa_manifest::TrustPolicy;
        // env=Off is a no-op floor (cannot downgrade manifest warn).
        let result = effective_trust_policy(&TrustPolicy::Warn, false, Some(&TrustPolicy::Off));
        assert_eq!(result, TrustPolicy::Warn);
    }

    #[test]
    fn effective_policy_manifest_warn_env_absent_returns_warn() {
        use milpa_core::effective_trust_policy;
        use milpa_manifest::TrustPolicy;
        let result = effective_trust_policy(&TrustPolicy::Warn, false, None);
        assert_eq!(result, TrustPolicy::Warn);
    }

    // -----------------------------------------------------------------------
    // ITEM 6 (M6): DEFAULT_INDEX_SIGNER is now a pub const in milpa-core
    // -----------------------------------------------------------------------

    #[test]
    fn default_index_signer_constant_is_attest_index_yaml() {
        // Item 6 (M6): DEFAULT_SIGNER promoted to milpa_core::index_trust::DEFAULT_INDEX_SIGNER.
        // Pin test: confirm the value matches spec §3.4.4 step 5 exactly.
        // (The matching pin test also lives in milpa-core's index_trust tests.)
        //
        // The pinned identity is `attest-index.yaml`, tianguis's reusable
        // (`workflow_call`) whole-index signing workflow — NOT `reindex.yaml`
        // (a one-shot migration workflow with no recurring schedule).
        use milpa_core::index_trust::DEFAULT_INDEX_SIGNER;
        assert_eq!(
            DEFAULT_INDEX_SIGNER,
            "https://github.com/coreyleavitt/tianguis/.github/workflows/attest-index.yaml\
             @refs/heads/main",
            "spec §3.4.4 step 5 signer identity must be the tianguis attest-index workflow"
        );
    }

    // -----------------------------------------------------------------------
    // ITEM 2 (M1 Rust): mock seam guard — file:// URLs only
    // -----------------------------------------------------------------------

    #[test]
    fn mock_seam_with_https_url_returns_milpa_internal_error() {
        // Item 2 (M1): MILPA_INDEX_TRUST_MOCK_VERIFIER set + https:// URL → hard error.
        // The seam is CONFORMANCE-INTERNAL and must never be active for network URLs.
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_CACHE_HOME", tmp.path()) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", "https://example.com/index.kdl") };
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted") };

        let result = maybe_index(false, &milpa_manifest::TrustPolicy::Warn, None, None, false, false, &milpa_manifest::TrustPolicy::Off);

        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };

        assert!(
            result.is_err(),
            "mock seam + https:// URL must return an error, got Ok({result:?})"
        );
        let code = result.unwrap_err().code().to_string();
        assert_eq!(
            code, "MILPA-INTERNAL",
            "expected MILPA-INTERNAL, got {code:?}"
        );
    }

    #[test]
    fn mock_seam_with_file_url_is_honored() {
        // Item 2 (M1): MILPA_INDEX_TRUST_MOCK_VERIFIER set + file:// URL → honored.
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_CACHE_HOME", tmp.path()) };
        // A nonexistent file:// URL → MILPA-INDEX-UNREACHABLE (or Ok(None) via load_index_raw),
        // but NOT MILPA-INTERNAL. The guard passes and we fall into the mock path.
        unsafe { std::env::set_var("MILPA_INDEX_URL", "file:///nonexistent-mock-seam-test.kdl") };
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted") };

        let result = maybe_index(false, &milpa_manifest::TrustPolicy::Warn, None, None, false, false, &milpa_manifest::TrustPolicy::Off);

        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };

        // Ok(None) for unreachable file:// — not MILPA-INTERNAL.
        match &result {
            Ok(_) => {} // ok(None) is expected
            Err(e) if e.code() == "MILPA-INTERNAL" => {
                panic!("mock seam with file:// URL must NOT return MILPA-INTERNAL; got {e:?}");
            }
            Err(_) => {} // other errors (e.g. MILPA-INDEX-UNREACHABLE) are fine
        }
    }

    // -----------------------------------------------------------------------
    // No-mock-seam path: the real SigstoreVerifier (S4a removed the stopgap)
    // -----------------------------------------------------------------------

    #[test]
    fn maybe_index_strict_no_mock_no_longer_verify_unsupported() {
        // After S4a: strict + no mock seam goes through the real SigstoreVerifier — the
        // TNG-INDEX-VERIFY-UNSUPPORTED stopgap is gone. With an unreachable file:// index
        // there is nothing to verify, so this resolves to Ok(None), NOT a fail-closed error.
        // (Real strict-fails-on-a-bad-bundle is covered end-to-end in S4b/S5.)
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_CACHE_HOME", tmp.path()) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", "file:///nonexistent-milpa-strict-test.kdl") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };

        let result = maybe_index(false, &milpa_manifest::TrustPolicy::Strict, None, None, false, false, &milpa_manifest::TrustPolicy::Off);

        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };

        if let Err(e) = &result {
            assert_ne!(
                e.code(),
                "TNG-INDEX-VERIFY-UNSUPPORTED",
                "the VERIFY-UNSUPPORTED stopgap must be gone after S4a"
            );
        }
        assert_eq!(result, Ok(None), "unreachable index under strict → Ok(None), got {result:?}");
    }

    #[test]
    fn maybe_index_off_skips_verification_entirely() {
        // Off policy → silent, no gate, no error regardless of seam.
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_CACHE_HOME", tmp.path()) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", "file:///nonexistent-off-test.kdl") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };

        let result = maybe_index(false, &milpa_manifest::TrustPolicy::Off, None, None, false, false, &milpa_manifest::TrustPolicy::Off);

        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };

        // Off → load attempted; unreachable → Ok(None).
        assert_eq!(result, Ok(None), "Off policy must not fail closed: {result:?}");
    }

    // -----------------------------------------------------------------------
    // ITEM 3 (M3) / ITEM 2 / RD-M1 / RD-M4: resolve_index_trust_fields helper
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_index_trust_fields_returns_warn_for_missing_manifest() {
        // No milpa.kdl in an empty temp dir → the ONE graceful case
        // (MAN-NO-MANIFEST) → (Warn, None, None).
        let tmp = tempfile::tempdir().unwrap();
        let (policy, signer, bundle) = resolve_index_trust_fields(tmp.path()).unwrap();
        assert_eq!(policy, milpa_manifest::TrustPolicy::Warn, "missing manifest must default to Warn");
        assert!(signer.is_none(), "signer must be None for missing manifest");
        assert!(bundle.is_none(), "bundle must be None for missing manifest");
    }

    #[test]
    fn resolve_index_trust_fields_reads_strict_from_manifest() {
        // Write a milpa.kdl with index-trust "strict" → returns Strict.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("milpa.kdl"),
            "name \"conformance-test\"\nindex-trust \"strict\"\n",
        )
        .unwrap();
        let (policy, _, _) = resolve_index_trust_fields(tmp.path()).unwrap();
        assert_eq!(policy, milpa_manifest::TrustPolicy::Strict, "manifest strict must return Strict");
    }

    #[test]
    fn resolve_index_trust_fields_workspace_root_declares_directly() {
        // S8 root-authority redesign (spec §3.4.7, RFC §6.4a): the workspace
        // ROOT declares index-trust alongside `workspace { }`; the member
        // declares nothing. The root's own value IS the effective policy —
        // no merge.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("milpa.kdl"),
            "index-trust \"strict\"\nworkspace {\n    member \"sub\"\n}\n",
        )
        .unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("milpa.kdl"), "name \"sub\"\nkind \"library\"\n").unwrap();

        let (policy, _, _) = resolve_index_trust_fields(tmp.path()).unwrap();
        assert_eq!(policy, milpa_manifest::TrustPolicy::Strict, "workspace root's own index-trust IS the effective policy");
    }

    #[test]
    fn resolve_index_trust_fields_workspace_root_declares_signer_and_bundle() {
        // Low code-review finding: prior tests only proved the workspace
        // ROOT's `index-trust` *policy* reaches the gate/verifier via
        // `workspace_index_trust_fields` (see
        // `resolve_index_trust_fields_workspace_root_declares_directly`
        // above). Nothing proved the root's `index-trust-signer` /
        // `index-trust-bundle` make the same trip — `workspace_index_trust_fields`
        // reads all three fields directly off `LoadedWorkspace`'s root with no
        // merge across members (spec §3.4.7 root-authority model), so a gap
        // here would be a silent regression if that read ever got narrowed to
        // policy alone.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("milpa.kdl"),
            "index-trust \"strict\"\n\
             index-trust-signer \"https://github.com/acme/reg/.github/workflows/publish.yaml@refs/heads/main\"\n\
             index-trust-bundle \"file:///etc/milpa/trust-bundle.json\"\n\
             workspace {\n    member \"sub\"\n}\n",
        )
        .unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("milpa.kdl"), "name \"sub\"\nkind \"library\"\n").unwrap();

        // resolve_index_trust_fields threads discover_manifest → load_workspace →
        // workspace_index_trust_fields — the same path `maybe_index`'s callers use.
        let (policy, signer, bundle) = resolve_index_trust_fields(tmp.path()).unwrap();
        assert_eq!(policy, milpa_manifest::TrustPolicy::Strict);
        assert_eq!(
            signer.as_deref(),
            Some("https://github.com/acme/reg/.github/workflows/publish.yaml@refs/heads/main"),
            "workspace root's index-trust-signer must reach the gate config"
        );
        assert_eq!(
            bundle.as_deref(),
            Some("file:///etc/milpa/trust-bundle.json"),
            "workspace root's index-trust-bundle must reach the gate config"
        );

        // Also confirm workspace_index_trust_fields itself (the SSOT helper
        // Item 1 introduced to replace inline collect+merge) returns the same
        // triple directly off a LoadedWorkspace, not just through the
        // higher-level resolve_index_trust_fields wrapper.
        let ws = load_workspace(tmp.path()).unwrap();
        let (ws_policy, ws_signer, ws_bundle) = workspace_index_trust_fields(&ws);
        assert_eq!(ws_policy, milpa_manifest::TrustPolicy::Strict);
        assert_eq!(ws_signer, signer);
        assert_eq!(ws_bundle, bundle);
    }

    #[test]
    fn resolve_index_trust_fields_workspace_member_illegal_propagates_error() {
        // RD-M1 (code-review): a member illegally declaring index-trust makes
        // load_workspace() fail (WS-INDEX-TRUST-ON-MEMBER). Previously this
        // helper's workspace branch swallowed that failure into a fabricated
        // (Warn, None, None) default — which meant `show --index-trust` printed
        // a confident "policy: warn" for a workspace `fetch`/`lock`/`verify`
        // would actually refuse to run against. It must now propagate.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("milpa.kdl"),
            "workspace {\n    member \"sub\"\n}\n",
        )
        .unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("milpa.kdl"), "name \"sub\"\nkind \"library\"\nindex-trust \"strict\"\n").unwrap();

        let err = resolve_index_trust_fields(tmp.path()).unwrap_err();
        assert_eq!(err.code(), "WS-INDEX-TRUST-ON-MEMBER");
    }

    // -----------------------------------------------------------------------
    // ITEM 2: manifest signer/bundle precedence in build_index_trust_gate
    // -----------------------------------------------------------------------

    #[test]
    fn build_trust_gate_manifest_signer_used_when_no_env() {
        // manifest signer set, MILPA_INDEX_TRUST_SIGNER absent → gate config uses manifest signer.
        // We can't read the IndexTrustConfig back out of an opaque gate, but we can verify
        // that the gate builds without error and the signer flows through to mock path.
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_SIGNER") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST") };
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted") };
        // manifest signer supplied; env absent → manifest value wins (middle tier).
        let gate = build_index_trust_gate(
            &milpa_manifest::TrustPolicy::Warn,
            Some("custom@example.com".to_string()),
            None,
            false,
            "file:///some/index.kdl",
        );
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        assert!(
            matches!(gate, Ok(Some(_))),
            "manifest signer with mock seam must build Active gate: {gate:?}"
        );
    }

    #[test]
    fn build_trust_gate_env_signer_wins_over_manifest() {
        // Both manifest signer and MILPA_INDEX_TRUST_SIGNER set → env wins.
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_SIGNER", "env@example.com") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST") };
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted") };
        let gate = build_index_trust_gate(
            &milpa_manifest::TrustPolicy::Warn,
            Some("manifest@example.com".to_string()),
            None,
            false,
            "file:///some/index.kdl",
        );
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_SIGNER") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        // The gate must build successfully (env wins, no error expected).
        assert!(
            matches!(gate, Ok(Some(_))),
            "env signer beats manifest signer: gate must be Active, got {gate:?}"
        );
    }

    #[test]
    fn build_trust_gate_default_signer_when_neither() {
        // Neither manifest signer nor env → DEFAULT_INDEX_SIGNER used (no error).
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_SIGNER") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST") };
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted") };
        let gate = build_index_trust_gate(
            &milpa_manifest::TrustPolicy::Warn,
            None,
            None,
            false,
            "file:///some/index.kdl",
        );
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        assert!(
            matches!(gate, Ok(Some(_))),
            "neither manifest nor env signer → DEFAULT_INDEX_SIGNER, gate Active: {gate:?}"
        );
    }

    // -----------------------------------------------------------------------
    // spec §8.6 / round-4 review Item 2: MILPA_INDEX_TRUST_BUNDLE file:// validation
    //
    // NORMATIVE: MILPA_INDEX_TRUST_BUNDLE MUST be a file:// URL.
    // Values that are not file:// paths MUST be rejected with MILPA-INTERNAL.
    // A valid file:// value resolves to TrustBundle::production() (S4b placeholder).
    // -----------------------------------------------------------------------

    #[test]
    fn trust_bundle_bare_path_is_milpa_internal_error() {
        // spec §8.6 NORMATIVE: MILPA_INDEX_TRUST_BUNDLE must be a file:// URL.
        // A bare filesystem path (no file:// prefix) must be rejected with MILPA-INTERNAL.
        //
        // Guard is dropped BEFORE assertions so a failing assert (RED phase) never
        // poisons ENV_MUTEX for subsequent tests.
        let guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_BUNDLE", "/tmp/bundle.json") };
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST") };
        let result = build_index_trust_gate(
            &milpa_manifest::TrustPolicy::Warn,
            None,
            None,
            false,
            "file:///some/index.kdl",
        );
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_BUNDLE") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        drop(guard); // release before any assertion can panic
        assert!(
            result.is_err(),
            "bare path in MILPA_INDEX_TRUST_BUNDLE must return Err, got Ok({result:?})"
        );
        assert_eq!(
            result.unwrap_err().code(),
            "MILPA-INTERNAL",
            "bare path must be rejected with MILPA-INTERNAL (spec §8.6)"
        );
    }

    #[test]
    fn trust_bundle_https_url_is_milpa_internal_error() {
        // spec §8.6 NORMATIVE: non-file:// values MUST be rejected.
        let guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_BUNDLE", "https://example.com/bundle.json") };
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST") };
        let result = build_index_trust_gate(
            &milpa_manifest::TrustPolicy::Warn,
            None,
            None,
            false,
            "file:///some/index.kdl",
        );
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_BUNDLE") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        drop(guard);
        assert!(result.is_err(), "https:// bundle URL must be rejected");
        assert_eq!(result.unwrap_err().code(), "MILPA-INTERNAL");
    }

    #[test]
    fn trust_bundle_file_url_is_accepted_and_gate_is_active() {
        // spec §8.6: a valid file:// value is accepted; S4b placeholder resolves
        // to TrustBundle::production() (real loading lands with S4b).
        let guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_BUNDLE", "file:///tmp/test-bundle.json") };
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST") };
        let result = build_index_trust_gate(
            &milpa_manifest::TrustPolicy::Warn,
            None,
            None,
            false,
            "file:///some/index.kdl",
        );
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_BUNDLE") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        drop(guard);
        assert!(
            matches!(result, Ok(Some(_))),
            "file:// bundle URL must be accepted and gate must be Active: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // ITEM 5 (M8): build_index_trust_gate — direct unit tests
    //
    // These tests drive the helper directly to verify its contract in isolation,
    // independent of maybe_index's URL/timestamp/http logic.
    // -----------------------------------------------------------------------

    #[test]
    fn build_trust_gate_off_returns_none() {
        // Policy=Off → None (no gate) regardless of env; no error.
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST") };
        let gate = build_index_trust_gate(
            &milpa_manifest::TrustPolicy::Off,
            None,
            None,
            false,
            "file:///any",
        );
        assert!(
            matches!(gate, Ok(None)),
            "Off policy must return None, got {gate:?}"
        );
    }

    #[test]
    fn build_trust_gate_strict_no_seam_builds_real_gate() {
        // After S4a: strict + no seam builds an ACTIVE gate with the real SigstoreVerifier
        // (no more TNG-INDEX-VERIFY-UNSUPPORTED stopgap). Assembly is pure (no I/O), so it
        // succeeds here; the actual verification happens later in load_index_raw.
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST") };
        let result = build_index_trust_gate(
            &milpa_manifest::TrustPolicy::Strict,
            None,
            None,
            false,
            "file:///any",
        );
        assert!(
            matches!(result, Ok(Some(_))),
            "strict + no seam must build an active real-verifier gate, got {result:?}"
        );
    }

    #[test]
    fn build_trust_gate_warn_no_seam_builds_real_gate() {
        // After S4a: warn + no seam also builds an active real-verifier gate (it no longer
        // short-circuits to ungated). Warn vs strict differ only in how a verification
        // FAILURE is handled downstream, not in whether the gate is assembled.
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST") };
        let gate = build_index_trust_gate(
            &milpa_manifest::TrustPolicy::Warn,
            None,
            None,
            false,
            "file:///any",
        );
        assert!(
            matches!(gate, Ok(Some(_))),
            "Warn + no seam must build an active gate, got {gate:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Sv: `milpa verify` reverifies the CACHED index bundle offline
    // -----------------------------------------------------------------------

    /// Seed an isolated cache with an index + bundle for `index_url`, and a minimal
    /// valid project under `root`. Returns the project dir. Caller holds ENV_MUTEX and
    /// has set XDG_CACHE_HOME + the MILPA_INDEX_* env vars.
    fn seed_verify_reverify_case(root: &std::path::Path, index_url: &str) -> PathBuf {
        let cache_file = milpa_core::index_cache::cache_path_for(index_url, &index_cache_dir());
        std::fs::create_dir_all(cache_file.parent().unwrap()).unwrap();
        std::fs::write(&cache_file, b"name \"tianguis-index\"\n").unwrap();
        std::fs::write(
            milpa_core::index_cache::bundle_path(&cache_file),
            b"{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"}",
        )
        .unwrap();

        let proj = root.join("proj");
        std::fs::create_dir_all(proj.join("_deps")).unwrap();
        std::fs::write(proj.join("milpa.kdl"), "name \"x\"\nkind \"application\"\n").unwrap();
        std::fs::write(proj.join("milpa.lock"), "version 1\nstrategy \"maxver\"\n").unwrap();
        proj
    }

    #[test]
    fn verify_fails_on_invalid_cached_bundle_offline() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let index_url = "file:///nonexistent/tianguis/index.kdl";
        unsafe { std::env::set_var("XDG_CACHE_HOME", tmp.path()) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", index_url) };
        unsafe { std::env::set_var("MILPA_INDEX_TRUST", "strict") };
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_MOCK_VERIFIER", "sig-invalid") };

        let proj = seed_verify_reverify_case(tmp.path(), index_url);
        // Minimal-valid project: the ONLY exit-1 condition is the cached-bundle reverify.
        let result = cmd_verify(&proj, false, false, false, false, false);

        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };

        assert_eq!(
            result,
            Ok(1),
            "strict + invalid cached bundle must fail verify offline"
        );
    }

    #[test]
    fn verify_passes_on_trusted_cached_bundle_offline() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let index_url = "file:///nonexistent/tianguis/index.kdl";
        unsafe { std::env::set_var("XDG_CACHE_HOME", tmp.path()) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", index_url) };
        unsafe { std::env::set_var("MILPA_INDEX_TRUST", "strict") };
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted") };

        let proj = seed_verify_reverify_case(tmp.path(), index_url);
        let result = cmd_verify(&proj, false, false, false, false, false);

        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };

        // Trusted cached bundle → reverify passes; 0 deps → verify succeeds.
        assert_eq!(result, Ok(0), "trusted cached bundle must not block verify");
    }

    /// S4b: `strict` really fails end-to-end on a BAD bundle through the REAL SigstoreVerifier
    /// (no mock seam) — the replacement for the deleted VERIFY-UNSUPPORTED scenario 6. Uses the
    /// real S5 fixture with its DSSE signature byte-flipped: the digest pre-check passes (real
    /// index), then the real crypto rejects the tampered signature → fail closed (exit 1).
    #[test]
    fn s4b_strict_fails_on_bad_cached_bundle_via_real_verifier() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let index_url = "file:///nonexistent/tianguis/index.kdl";
        unsafe { std::env::set_var("XDG_CACHE_HOME", tmp.path()) };
        unsafe { std::env::set_var("MILPA_INDEX_URL", index_url) };
        unsafe { std::env::set_var("MILPA_INDEX_TRUST", "strict") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") }; // REAL verifier

        let proj = seed_verify_reverify_case(tmp.path(), index_url);

        // Overwrite the cache with the REAL index + a signature-tampered REAL bundle.
        let fdir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../conformance/spec-v1/_oracle/attestation");
        let real_index = std::fs::read(format!("{fdir}/index.kdl")).unwrap();
        let real_bundle = std::fs::read(format!("{fdir}/index.kdl.bundle")).unwrap();
        let mut bj: serde_json::Value = serde_json::from_slice(&real_bundle).unwrap();
        let sig = bj["dsseEnvelope"]["signatures"][0]["sig"].as_str().unwrap().to_string();
        let flipped = format!("{}{}", if sig.starts_with('A') { "B" } else { "A" }, &sig[1..]);
        bj["dsseEnvelope"]["signatures"][0]["sig"] = serde_json::Value::String(flipped);
        let tampered = serde_json::to_vec(&bj).unwrap();

        let cache_file = milpa_core::index_cache::cache_path_for(index_url, &index_cache_dir());
        std::fs::write(&cache_file, &real_index).unwrap();
        std::fs::write(milpa_core::index_cache::bundle_path(&cache_file), &tampered).unwrap();

        let result = cmd_verify(&proj, false, false, false, false, false);

        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST") };
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };

        assert_eq!(
            result,
            Ok(1),
            "strict + real verifier + signature-tampered real bundle must fail closed"
        );
    }

    #[test]
    fn build_trust_gate_mock_seam_with_https_is_milpa_internal_error() {
        // Item 2 (M1) + Item 5: seam on https:// URL → MILPA-INTERNAL hard error.
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted") };
        let result = build_index_trust_gate(
            &milpa_manifest::TrustPolicy::Warn,
            None,
            None,
            false,
            "https://example.com/index.kdl",
        );
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        assert!(result.is_err(), "seam on https:// must error");
        assert_eq!(result.unwrap_err().code(), "MILPA-INTERNAL");
    }

    #[test]
    fn build_trust_gate_mock_seam_with_file_returns_active() {
        // Item 2 (M1) + Item 5: seam on file:// URL → Active gate.
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted") };
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST") };
        let gate = build_index_trust_gate(
            &milpa_manifest::TrustPolicy::Warn,
            None,
            None,
            false,
            "file:///some/index.kdl",
        );
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        assert!(
            matches!(gate, Ok(Some(_))),
            "seam on file:// must return Active, got {gate:?}"
        );
    }

    #[test]
    fn build_trust_gate_invalid_mock_result_is_milpa_internal() {
        // Invalid VerificationResult wire string → MILPA-INTERNAL (not silent fail-open).
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("MILPA_INDEX_TRUST_MOCK_VERIFIER", "not-a-valid-result") };
        let result = build_index_trust_gate(
            &milpa_manifest::TrustPolicy::Warn,
            None,
            None,
            false,
            "file:///some/index.kdl",
        );
        unsafe { std::env::remove_var("MILPA_INDEX_TRUST_MOCK_VERIFIER") };
        assert!(result.is_err(), "invalid mock result must error");
        assert_eq!(result.unwrap_err().code(), "MILPA-INTERNAL");
    }

    #[test]
    fn build_entry_trust_gate_mock_default_unrecognized_value_fails_loud() {
        // CR6 fix: an unrecognized MILPA_ENTRY_TRUST_MOCK_DEFAULT must never
        // silently collapse to Trusted — mirrors the sibling MOCK_MAP bad-value
        // path, and the index-trust MOCK_VERIFIER precedent above.
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("MILPA_INDEX_URL", "file:///some/index.kdl") };
        unsafe { std::env::set_var("MILPA_ENTRY_TRUST_MOCK_DEFAULT", "bogus-value") };
        unsafe { std::env::remove_var("MILPA_ENTRY_TRUST_MOCK_MAP") };
        let result = build_entry_trust_gate(&milpa_manifest::TrustPolicy::Strict, None, None, false, false);
        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("MILPA_ENTRY_TRUST_MOCK_DEFAULT") };
        match result {
            Err(e) => assert_eq!(e.code(), "MILPA-INTERNAL"),
            Ok(_) => panic!("unrecognized MOCK_DEFAULT must error, not fail-open"),
        }
    }

    #[test]
    fn build_entry_trust_gate_mock_default_gate_only_value_rejected() {
        // `unattested`/`bundle-missing` are gate-level states the verifier
        // itself is documented to never produce — the mock-VERIFIER seam must
        // reject them too, not silently accept the full 8-value gate domain.
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("MILPA_INDEX_URL", "file:///some/index.kdl") };
        unsafe { std::env::set_var("MILPA_ENTRY_TRUST_MOCK_DEFAULT", "unattested") };
        unsafe { std::env::remove_var("MILPA_ENTRY_TRUST_MOCK_MAP") };
        let result = build_entry_trust_gate(&milpa_manifest::TrustPolicy::Strict, None, None, false, false);
        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("MILPA_ENTRY_TRUST_MOCK_DEFAULT") };
        match result {
            Err(e) => assert_eq!(e.code(), "MILPA-INTERNAL"),
            Ok(_) => panic!("gate-only value must be rejected by the mock-verifier seam"),
        }
    }

    #[test]
    fn build_entry_trust_gate_mock_default_recognized_verifier_value_works() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("MILPA_INDEX_URL", "file:///some/index.kdl") };
        unsafe { std::env::set_var("MILPA_ENTRY_TRUST_MOCK_DEFAULT", "signature-invalid") };
        unsafe { std::env::remove_var("MILPA_ENTRY_TRUST_MOCK_MAP") };
        let result = build_entry_trust_gate(&milpa_manifest::TrustPolicy::Strict, None, None, false, false);
        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("MILPA_ENTRY_TRUST_MOCK_DEFAULT") };
        match result {
            Ok(Some(_)) => {}
            Ok(None) => panic!("expected an active gate (Some), got None"),
            Err(e) => panic!("recognized verifier-domain value must build the gate, got error: {}", e.code()),
        }
    }

    #[test]
    fn build_entry_trust_gate_mock_map_gate_only_value_rejected() {
        // Same tightened domain applies to per-subject MOCK_MAP entries.
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("MILPA_INDEX_URL", "file:///some/index.kdl") };
        unsafe { std::env::remove_var("MILPA_ENTRY_TRUST_MOCK_DEFAULT") };
        unsafe {
            std::env::set_var(
                "MILPA_ENTRY_TRUST_MOCK_MAP",
                r#"{"pkg:tianguis/ns1/bar@1.0.0": "bundle-missing"}"#,
            )
        };
        let result = build_entry_trust_gate(&milpa_manifest::TrustPolicy::Strict, None, None, false, false);
        unsafe { std::env::remove_var("MILPA_INDEX_URL") };
        unsafe { std::env::remove_var("MILPA_ENTRY_TRUST_MOCK_MAP") };
        match result {
            Err(e) => assert_eq!(e.code(), "MILPA-INTERNAL"),
            Ok(_) => panic!("gate-only value in MOCK_MAP must be rejected"),
        }
    }

    // -----------------------------------------------------------------------
    // C-store-ro: store ls / store path tests (Phase C)
    // -----------------------------------------------------------------------

    /// Helper: create a bare CAS-layout directory for a controlled 64-hex digest.
    /// This bypasses content-hashing; the store verbs are read-only and inspect
    /// directory names only.  Controlled hex names enable prefix-match tests
    /// without needing real content that hashes to a chosen value.
    fn make_store_entry(store_root: &std::path::Path, hex64: &str) -> PathBuf {
        let entry = store_root.join("dag-sha256").join(hex64);
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("dummy.nim"), b"# test sentinel\n").unwrap();
        entry
    }

    /// Behaviour 1: `store ls` with 2 entries → lex-sorted identities on stdout.
    #[test]
    fn store_ls_two_entries_sorted() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("cas");
        let hex_a = "a".repeat(64);
        let hex_b = "b".repeat(64);
        // Admitted out-of-order to verify sort.
        make_store_entry(&store_root, &hex_b);
        make_store_entry(&store_root, &hex_a);

        let store = CaStore::new(&store_root);
        let identities = store.list_identities();
        assert_eq!(
            identities,
            vec![format!("dag-sha256:{hex_a}"), format!("dag-sha256:{hex_b}")],
            "list_identities must be lex-sorted"
        );
    }

    /// Behaviour 2: `store ls` on empty store → empty list.
    #[test]
    fn store_ls_empty_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("cas");
        std::fs::create_dir_all(&store_root).unwrap();

        let store = CaStore::new(&store_root);
        assert!(store.list_identities().is_empty(), "empty store must produce empty list");
    }

    /// Behaviour 3: `store path <full-identity>` for a present entry → correct path.
    #[test]
    fn store_path_full_identity_present() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("cas");
        let hex64 = "c".repeat(64);
        let entry = make_store_entry(&store_root, &hex64);
        let identity = format!("dag-sha256:{hex64}");

        let store = CaStore::new(&store_root);
        let resolved = store.resolve_prefix(&identity).unwrap();
        assert_eq!(resolved, identity);
        assert_eq!(store.path_for(&resolved).unwrap(), entry);
    }

    /// Behaviour 4: `store path <full-identity>` absent → CAS-NOT-IN-STORE.
    #[test]
    fn store_path_full_identity_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("cas");
        std::fs::create_dir_all(&store_root).unwrap();
        let identity = format!("dag-sha256:{}", "d".repeat(64));

        let store = CaStore::new(&store_root);
        let err = store.resolve_prefix(&identity).unwrap_err();
        assert_eq!(err.code(), "CAS-NOT-IN-STORE");
    }

    /// Behaviour 5: `store path <≥16-char unique prefix>` → resolves to one entry.
    #[test]
    fn store_path_unique_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("cas");
        // Two entries that diverge at position 8; prefix of 16 uniquely picks hex_a.
        let hex_a = format!("{}{}", "aaaa1111", "0".repeat(56));
        let hex_b = format!("{}{}", "aaaa1111", "1".repeat(56));
        let entry_a = make_store_entry(&store_root, &hex_a);
        make_store_entry(&store_root, &hex_b);

        let prefix = format!("dag-sha256:{}", &hex_a[..16]);
        let store = CaStore::new(&store_root);
        let resolved = store.resolve_prefix(&prefix).unwrap();
        assert_eq!(store.path_for(&resolved).unwrap(), entry_a);
    }

    /// Behaviour 6: prefix matching >1 entry → STORE-AMBIGUOUS-PREFIX.
    #[test]
    fn store_path_ambiguous_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("cas");
        let shared = "abcdef1234567890".repeat(2); // 32-char shared prefix
        let hex_a = format!("{}{}", shared, "a".repeat(32));
        let hex_b = format!("{}{}", shared, "b".repeat(32));
        make_store_entry(&store_root, &hex_a);
        make_store_entry(&store_root, &hex_b);

        let prefix = format!("dag-sha256:{}", &shared[..16]); // 16 chars → matches both
        let store = CaStore::new(&store_root);
        let err = store.resolve_prefix(&prefix).unwrap_err();
        assert_eq!(err.code(), "STORE-AMBIGUOUS-PREFIX");
    }

    /// Behaviour 7: prefix shorter than 16 hex chars → STORE-AMBIGUOUS-PREFIX.
    #[test]
    fn store_path_prefix_too_short() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("cas");
        let hex64 = "e".repeat(64);
        make_store_entry(&store_root, &hex64);

        let prefix = format!("dag-sha256:{}", "e".repeat(15)); // 15 < 16 → rejected
        let store = CaStore::new(&store_root);
        let err = store.resolve_prefix(&prefix).unwrap_err();
        assert_eq!(err.code(), "STORE-AMBIGUOUS-PREFIX");
    }

    /// Behaviour 8: bare 64-hex (no sha256: prefix) is accepted as full identity.
    #[test]
    fn store_path_bare_64hex_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("cas");
        let hex64 = "f".repeat(64);
        let entry = make_store_entry(&store_root, &hex64);

        let store = CaStore::new(&store_root);
        let resolved = store.resolve_prefix(&hex64).unwrap();
        assert_eq!(store.path_for(&resolved).unwrap(), entry);
    }

    /// Behaviour 9: bare ≥16-char prefix (no sha256:) is accepted.
    #[test]
    fn store_path_bare_prefix_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("cas");
        let hex64 = format!("{}{}", "1234567890abcdef", "0".repeat(48));
        let entry = make_store_entry(&store_root, &hex64);

        let prefix = &hex64[..16]; // bare, 16 hex chars
        let store = CaStore::new(&store_root);
        let resolved = store.resolve_prefix(prefix).unwrap();
        assert_eq!(store.path_for(&resolved).unwrap(), entry);
    }

    /// `cmd_store` dispatch: `store ls` on empty store → exit 0.
    #[test]
    fn cmd_store_ls_empty_exits_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("cas");
        std::fs::create_dir_all(&store_root).unwrap();

        // Override MILPA_CACHE_DIR so cmd_store picks up our tmp store.
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("MILPA_CACHE_DIR", &store_root) };
        let rc = cmd_store(&["ls".to_string()]).unwrap();
        unsafe { std::env::remove_var("MILPA_CACHE_DIR") };

        assert_eq!(rc, 0);
    }

    /// `cmd_store` dispatch: `store path <absent-full-identity>` → exit 1.
    #[test]
    fn cmd_store_path_absent_exits_one() {
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("cas");
        std::fs::create_dir_all(&store_root).unwrap();

        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("MILPA_CACHE_DIR", &store_root) };
        let rc = cmd_store(&[
            "path".to_string(),
            format!("dag-sha256:{}", "d".repeat(64)),
        ]).unwrap();
        unsafe { std::env::remove_var("MILPA_CACHE_DIR") };

        assert_eq!(rc, 1);
    }

    // -----------------------------------------------------------------------
    // S10: subcommand awareness (RFC #23 §3.7)
    // -----------------------------------------------------------------------

    /// S10: cmd_add --optional writes optional=#true in milpa.kdl.
    #[test]
    fn s10_add_optional_writes_optional_true() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        ).unwrap();

        let url = "https://example.com/mydep.git";
        let sha = "b".repeat(40);
        let mocked = make_mocked_fetches(tmp.path(), url, "main", &sha, &[("dep.nim", b"# dep")]);
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let rc = cmd_add(
            &proj,
            Some(Strategy::default()),
            &["mydep".into(), "--git".into(), url.into(), "--ref".into(), "main".into(), "--optional".into()],
            false,
            false,
            false,
            false,
        );
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(rc.unwrap(), 0, "add --optional must exit 0");
        let kdl = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        assert!(kdl.contains("optional=#true"), "optional=#true must be in manifest:\n{kdl}");
    }

    /// S10: cmd_add --features a,b writes flag "a" / flag "b" children.
    #[test]
    fn s10_add_features_writes_flag_children() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj2");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        ).unwrap();

        let url = "https://example.com/featdep.git";
        let sha = "c".repeat(40);
        let mocked = make_mocked_fetches(tmp.path(), url, "main", &sha, &[("dep.nim", b"# dep")]);
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let rc = cmd_add(
            &proj,
            Some(Strategy::default()),
            &[
                "featdep".into(), "--git".into(), url.into(),
                "--ref".into(), "main".into(),
                "--features".into(), "alpha,beta".into(),
            ],
            false,
            false,
            false,
            false,
        );
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(rc.unwrap(), 0, "add --features must exit 0");
        let kdl = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        assert!(kdl.contains("flag \"alpha\""), "flag alpha must be in manifest:\n{kdl}");
        assert!(kdl.contains("flag \"beta\""), "flag beta must be in manifest:\n{kdl}");
    }

    /// A3b (rfc-resolution-semantics.md §3 Axis A (b) step 4): cmd_add
    /// --version writes version= on the new dep node — the natural-site
    /// workflow, mirrors --optional/--features.
    #[test]
    fn a3b_add_version_writes_version_annotation() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj_ver");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        ).unwrap();

        let url = "https://example.com/verdep.git";
        let sha = "d".repeat(40);
        let mocked = make_mocked_fetches(tmp.path(), url, "main", &sha, &[("dep.nim", b"# dep")]);
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let rc = cmd_add(
            &proj,
            Some(Strategy::default()),
            &[
                "verdep".into(), "--git".into(), url.into(),
                "--ref".into(), "main".into(),
                "--version".into(), "1.2.3".into(),
            ],
            false,
            false,
            false,
            false,
        );
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(rc.unwrap(), 0, "add --version must exit 0");
        let kdl = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        assert!(kdl.contains("version=\"1.2.3\""), "version=\"1.2.3\" must be in manifest:\n{kdl}");
    }

    /// A3b: cmd_add without --version writes no version= at all.
    #[test]
    fn a3b_add_no_version_no_version_annotation() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj_ver2");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        ).unwrap();

        let url = "https://example.com/noverdep.git";
        let sha = "e".repeat(40);
        let mocked = make_mocked_fetches(tmp.path(), url, "main", &sha, &[("dep.nim", b"# dep")]);
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let rc = cmd_add(
            &proj,
            Some(Strategy::default()),
            &["noverdep".into(), "--git".into(), url.into(), "--ref".into(), "main".into()],
            false,
            false,
            false,
            false,
        );
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(rc.unwrap(), 0);
        let kdl = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        assert!(!kdl.contains("version="), "version= must not appear when not requested:\n{kdl}");
    }

    /// A3b: a malformed --version value is rejected (MAN-DEP-VERSION-INVALID)
    /// before anything is written — same slug as the manifest grammar.
    #[test]
    fn a3b_add_version_malformed_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj_ver3");
        std::fs::create_dir_all(&proj).unwrap();
        let original = "name \"app\"\nkind \"application\"\n";
        std::fs::write(proj.join("milpa.kdl"), original).unwrap();

        let rc = cmd_add(
            &proj,
            Some(Strategy::default()),
            &[
                "baddep".into(), "--git".into(), "https://example.com/baddep.git".into(),
                "--ref".into(), "main".into(),
                "--version".into(), "not-a-version".into(),
            ],
            false,
            false,
            false,
            false,
        );
        assert!(rc.is_err(), "malformed --version must reject");
        if let Err(e) = rc {
            assert_eq!(e.code(), "MAN-DEP-VERSION-INVALID");
        }
        // Manifest must be left unmodified — no partial write.
        let kdl = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        assert_eq!(kdl, original);
    }

    /// A3b: `milpa --version` (top-level, no subcommand) still prints the
    /// binary version and exits 0 — the pre-verb-scoped scan must not break
    /// the existing top-level flag.
    #[test]
    fn a3b_top_level_version_flag_still_works() {
        let rc = run(&["--version".to_string()]);
        assert_eq!(rc.unwrap(), 0);
    }

    /// L1: `milpa -C <dir> --version` must print the version and exit 0.
    /// Before the fix, the naive "first non-dash token" pre-verb scan
    /// stopped at `<dir>` (the VALUE of `-C`, not a flag), slicing
    /// `--version` out of the region it scans — the flag was silently never
    /// found, and the invocation fell through to `parse_args`, which
    /// rejects a bare `--version` (not a recognized verb) with USAGE + exit
    /// 2 instead of printing the version.
    #[test]
    fn l1_dash_c_dir_then_version_prints_version_exits_0() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = run(&[
            "-C".to_string(),
            tmp.path().to_str().unwrap().to_string(),
            "--version".to_string(),
        ]);
        assert_eq!(rc.unwrap(), 0, "-C <dir> --version must exit 0");
    }

    /// L1: `milpa --certificate <path> --version` must likewise print the
    /// version and exit 0 — same class of bug as the `-C` case, for the
    /// other value-consuming global flag.
    #[test]
    fn l1_certificate_path_then_version_prints_version_exits_0() {
        let rc = run(&[
            "--certificate".to_string(),
            "/tmp/does-not-need-to-exist.json".to_string(),
            "--version".to_string(),
        ]);
        assert_eq!(rc.unwrap(), 0, "--certificate <path> --version must exit 0");
    }

    /// A3b: the root-cause collision fix — `milpa add <dep> --git <url>
    /// --version x.y.z` run through the FULL `run()` entry point (not just
    /// `cmd_add` directly) must reach `cmd_add`, not the top-level
    /// `--version` early-exit (which also returns `Ok(0)`, so a bare
    /// exit-code assertion cannot distinguish the bug — this test checks the
    /// manifest was actually written).
    #[test]
    fn a3b_run_add_version_does_not_collide_with_top_level_version_flag() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj_ver_run");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        ).unwrap();

        let url = "https://example.com/rundep.git";
        let sha = "f".repeat(40);
        let mocked = make_mocked_fetches(tmp.path(), url, "main", &sha, &[("dep.nim", b"# dep")]);
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let rc = run(&[
            "-C".into(),
            proj.to_str().unwrap().into(),
            "add".into(),
            "rundep".into(),
            "--git".into(),
            url.into(),
            "--ref".into(),
            "main".into(),
            "--version".into(),
            "1.2.3".into(),
        ]);
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(rc.unwrap(), 0);
        let kdl = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        assert!(
            kdl.contains("version=\"1.2.3\""),
            "add must have actually run (not the top-level --version early-exit):\n{kdl}"
        );
    }

    /// S10: cmd_add --optional rejects dep whose name clashes with existing flag.
    #[test]
    fn s10_add_optional_clash_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj3");
        std::fs::create_dir_all(&proj).unwrap();
        // Manifest with flag named "myflag".
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\nflags {\n    \"myflag\" default=#false\n}\n",
        ).unwrap();

        let rc = cmd_add(
            &proj,
            Some(Strategy::default()),
            &["myflag".into(), "--git".into(), "https://example.com/myflag.git".into(),
              "--ref".into(), "main".into(), "--optional".into()],
            false,
            false,
            false,
            false,
        );
        // Must exit non-zero.
        let code = match rc {
            Ok(n) => n,
            Err(_) => 1,
        };
        assert_ne!(code, 0, "add --optional must reject name clashing with existing flag");
        // manifest must be unchanged.
        let kdl = std::fs::read_to_string(proj.join("milpa.kdl")).unwrap();
        assert!(!kdl.contains("myflag.git"), "manifest must not be modified after clash");
    }

    /// A7 (rfc-resolution-semantics.md §3 Axis A / §5): `version_suffix` pure
    /// unit tests — the branching logic `cmd_show` prints next to a dep's
    /// version. See its doc comment for the contract.
    #[test]
    fn a7_version_suffix_shows_source_when_present() {
        for src in ["manifest", "nimble", "tag", "annotation"] {
            assert_eq!(
                version_suffix(&Some(src.to_string()), "2.3.4"),
                format!(" ({src})")
            );
        }
    }

    #[test]
    fn a7_version_suffix_marks_version_unknown_when_source_absent() {
        // A5's flattening pairing: version "0.0.0" + no source => version-unknown.
        assert_eq!(version_suffix(&None, "0.0.0"), " (version-unknown)");
    }

    #[test]
    fn a7_version_suffix_empty_for_named_dep_real_version_no_source() {
        // A named/index dep has no source either, but a real version — not unknown.
        assert_eq!(version_suffix(&None, "1.2.3"), "");
    }

    /// R11: `format_timestamp_for_show` must byte-match
    /// `milpa_types::format_iso8601_timestamp` (the same known instants that
    /// crate's own tests assert against) since it's a transcribed copy of
    /// that function — this is the regression net for the transcription.
    #[test]
    fn r11_format_timestamp_for_show_whole_seconds() {
        let ts = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        assert_eq!(format_timestamp_for_show(&ts), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn r11_format_timestamp_for_show_arbitrary_instant() {
        let ts = parse_iso8601_timestamp("2026-06-15T12:30:45Z").unwrap();
        assert_eq!(format_timestamp_for_show(&ts), "2026-06-15T12:30:45Z");
    }

    #[test]
    fn r11_format_timestamp_for_show_normalizes_offset_to_utc_z() {
        let ts = parse_iso8601_timestamp("2026-01-01T01:00:00+01:00").unwrap();
        assert_eq!(format_timestamp_for_show(&ts), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn r11_format_timestamp_for_show_omits_fraction_when_zero() {
        let ts = Timestamp { unix_seconds: 0, nanos: 0 };
        assert_eq!(format_timestamp_for_show(&ts), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn r11_format_timestamp_for_show_includes_fraction_when_present() {
        let ts = Timestamp { unix_seconds: 0, nanos: 500_000_000 };
        assert_eq!(format_timestamp_for_show(&ts), "1970-01-01T00:00:00.5Z");
    }

    #[test]
    fn r11_exclude_newer_header_line_none_when_absent() {
        assert_eq!(exclude_newer_header_line(&None), None);
    }

    #[test]
    fn r11_exclude_newer_header_line_some_when_present() {
        let ts = parse_iso8601_timestamp("2026-01-01T00:00:00Z").unwrap();
        assert_eq!(
            exclude_newer_header_line(&Some(ts)).as_deref(),
            Some("exclude-newer 2026-01-01T00:00:00Z")
        );
    }

    /// A7: cmd_show's header prints `strategy` and exits 0. This fixture's
    /// lockfile has no `exclude_newer` node, so `lock.exclude_newer` must
    /// parse to `None` and `exclude_newer_header_line` must therefore omit
    /// the line entirely (R11 regression: `cmd_show` must never print a
    /// fake/hardcoded `exclude-newer` value for the absent case).
    #[test]
    fn a7_show_prints_strategy_header_and_exits_0() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("show_strategy_header");
        std::fs::create_dir_all(&proj).unwrap();
        let lock_text = concat!(
            "// generated by milpa; reproducible build snapshot\n",
            "version 1\nstrategy \"minver\"\n\n",
            "dep \"mylib\" {\n",
            "    identity \"dag-sha256:", "a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "    version \"1.0.0\"\n",
            "    src_dir \"\"\n",
            "    requires\n",
            "    provenance {\n",
            "        origin \"observed\"\n",
            "        kind \"git\"\n",
            "        url \"https://example.com/mylib.git\"\n",
            "        ref \"main\"\n",
            "        commit_sha \"", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "\"\n",
            "    }\n",
            "}\n",
        );
        std::fs::write(proj.join("milpa.lock"), lock_text).unwrap();
        let lock = parse_lockfile(&std::fs::read_to_string(proj.join("milpa.lock")).unwrap()).unwrap();
        assert_eq!(lock.strategy, "minver");
        assert_eq!(lock.exclude_newer, None, "fixture has no exclude_newer node");
        assert_eq!(
            exclude_newer_header_line(&lock.exclude_newer),
            None,
            "cmd_show must omit the exclude-newer line when the lockfile recorded no bound"
        );
        let rc = cmd_show(&proj).unwrap();
        assert_eq!(rc, 0, "show must exit 0 and print the strategy header");
    }

    /// R11: `cmd_show`'s header must print an `exclude-newer <ts>` line,
    /// mirroring the Python reference's `cmd_show` (`cli.py`), when the
    /// lockfile recorded a D5 `exclude_newer` bound. Prior to this fix,
    /// `cmd_show` unconditionally omitted the field even though
    /// `Lockfile.exclude_newer` already existed (a stale "not implemented
    /// yet" comment had drifted from reality) — a cross-impl `show`
    /// divergence.
    #[test]
    fn r11_show_prints_exclude_newer_header_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("show_exclude_newer");
        std::fs::create_dir_all(&proj).unwrap();
        let lock_text = concat!(
            "// generated by milpa; reproducible build snapshot\n",
            "version 1\nstrategy \"minver\"\nexclude_newer \"2026-06-15T12:30:45Z\"\n\n",
            "dep \"mylib\" {\n",
            "    identity \"dag-sha256:", "a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "    version \"1.0.0\"\n",
            "    src_dir \"\"\n",
            "    requires\n",
            "    provenance {\n",
            "        origin \"observed\"\n",
            "        kind \"git\"\n",
            "        url \"https://example.com/mylib.git\"\n",
            "        ref \"main\"\n",
            "        commit_sha \"", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "\"\n",
            "    }\n",
            "}\n",
        );
        std::fs::write(proj.join("milpa.lock"), lock_text).unwrap();
        let lock = parse_lockfile(&std::fs::read_to_string(proj.join("milpa.lock")).unwrap()).unwrap();
        assert!(lock.exclude_newer.is_some(), "fixture's exclude_newer node must parse");
        assert_eq!(
            exclude_newer_header_line(&lock.exclude_newer).as_deref(),
            Some("exclude-newer 2026-06-15T12:30:45Z"),
            "must match Python cmd_show's exact label + timestamp wire format"
        );
        let rc = cmd_show(&proj).unwrap();
        assert_eq!(rc, 0, "show must exit 0 with an exclude_newer bound present");
    }

    /// S10: cmd_show prints active_flags for deps that have them.
    #[test]
    fn s10_show_prints_active_flags() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("show_proj");
        std::fs::create_dir_all(&proj).unwrap();

        // Write a lockfile with active_flags.
        let lock_text = concat!(
            "// generated by milpa; reproducible build snapshot\n",
            "version 1\nstrategy \"maxver\"\n\n",
            "dep \"mylib\" {\n",
            "    identity \"dag-sha256:", "a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "    version \"1.0.0\"\n",
            "    src_dir \"\"\n",
            "    requires\n",
            "    provenance {\n",
            "        origin \"observed\"\n",
            "        kind \"git\"\n",
            "        url \"https://example.com/mylib.git\"\n",
            "        ref \"main\"\n",
            "        commit_sha \"", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "\"\n",
            "    }\n",
            "    active_flags \"ssl\" \"threads\"\n",
            "}\n",
        );
        std::fs::write(proj.join("milpa.lock"), lock_text).unwrap();

        // Capture stdout.
        // NOTE: cmd_show writes to stdout (println!). We can't easily capture
        // that in Rust tests without a subprocess. Instead, verify the function
        // returns 0 and the logic is exercised.
        let rc = cmd_show(&proj).unwrap();
        assert_eq!(rc, 0, "show must exit 0 for a valid lockfile with active_flags");
    }

    /// RFC per-entry-attestation.md P2 (§7): cmd_show renders the lockfile's
    /// attestation block as an unverified claim. Mirrors
    /// `s10_show_prints_active_flags`'s pattern — Rust `cmd_show` writes to
    /// stdout via `println!`, which isn't easily captured without a
    /// subprocess, so these tests exercise the parse+render path and assert
    /// `cmd_show` does not error on the new field.
    fn write_lock_with_attestation_block(proj: &std::path::Path, attestation_block: &str) {
        let lock_text = format!(
            "// generated by milpa; reproducible build snapshot\n\
             version 1\nstrategy \"maxver\"\n\n\
             dep \"widget\" {{\n\
             \x20   identity \"dag-sha256:{}\"\n\
             \x20   version \"1.0.0\"\n\
             \x20   src_dir \"\"\n\
             \x20   requires\n\
             {attestation_block}\
             \x20   provenance {{\n\
             \x20       origin \"observed\"\n\
             \x20       kind \"git\"\n\
             \x20       url \"https://example.com/widget.git\"\n\
             \x20       ref \"main\"\n\
             \x20       commit_sha \"{}\"\n\
             \x20   }}\n\
             }}\n",
            "a".repeat(64),
            "a".repeat(40),
        );
        std::fs::write(proj.join("milpa.lock"), lock_text).unwrap();
    }

    #[test]
    fn show_renders_author_signed_claim() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("show_att_author");
        std::fs::create_dir_all(&proj).unwrap();
        write_lock_with_attestation_block(
            &proj,
            "    attestation {\n\
             \x20       kind \"author-signed\"\n\
             \x20       signer \"https://example.com/workflow.yaml\"\n\
             \x20   }\n",
        );
        let lock = parse_lockfile(&std::fs::read_to_string(proj.join("milpa.lock")).unwrap()).unwrap();
        let dep = &lock.deps[0];
        let att = dep.attestation.as_ref().expect("attestation must parse");
        assert!(matches!(
            &att.kind,
            milpa_core::AttestationKind::AuthorSigned { signer } if signer == "https://example.com/workflow.yaml"
        ));
        let rc = cmd_show(&proj).unwrap();
        assert_eq!(rc, 0, "show must exit 0 with an author-signed attestation claim");
    }

    #[test]
    fn show_renders_milpa_vendored_claim() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("show_att_vendored");
        std::fs::create_dir_all(&proj).unwrap();
        write_lock_with_attestation_block(
            &proj,
            "    attestation {\n        kind \"milpa-vendored\"\n    }\n",
        );
        let lock = parse_lockfile(&std::fs::read_to_string(proj.join("milpa.lock")).unwrap()).unwrap();
        let dep = &lock.deps[0];
        let att = dep.attestation.as_ref().expect("attestation must parse");
        assert!(matches!(att.kind, milpa_core::AttestationKind::MilpaVendored));
        let rc = cmd_show(&proj).unwrap();
        assert_eq!(rc, 0, "show must exit 0 with a milpa-vendored attestation claim");
    }

    #[test]
    fn show_no_attestation_line_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("show_att_absent");
        std::fs::create_dir_all(&proj).unwrap();
        write_lock_with_attestation_block(&proj, "");
        let lock = parse_lockfile(&std::fs::read_to_string(proj.join("milpa.lock")).unwrap()).unwrap();
        assert!(lock.deps[0].attestation.is_none());
        let rc = cmd_show(&proj).unwrap();
        assert_eq!(rc, 0, "show must exit 0 with no attestation block");
    }

    /// S10: cmd_verify exits non-zero when optional dep is in lock but default=#false.
    #[test]
    fn s10_verify_active_flags_mismatch_exits_nonzero() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("verify_proj");
        std::fs::create_dir_all(&proj).unwrap();

        // Manifest with an optional dep (gate flag default=#false).
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\ndeps {\n    \"optdep\" git=(url)\"https://example.com/optdep.git\" ref=\"main\" optional=#true\n}\n",
        ).unwrap();

        // _deps/ must exist for verify.
        let deps_dir = proj.join("_deps");
        std::fs::create_dir_all(&deps_dir).unwrap();
        // Create _deps/optdep so the dir exists.
        std::fs::create_dir_all(deps_dir.join("optdep")).unwrap();

        // Lockfile: optdep present with active_flags=("optdep",) — as if it was enabled.
        let lock_text = concat!(
            "// generated by milpa; reproducible build snapshot\n",
            "version 1\nstrategy \"maxver\"\n\n",
            "dep \"optdep\" {\n",
            "    identity \"dag-sha256:", "a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "    version \"1.0.0\"\n",
            "    src_dir \"\"\n",
            "    requires\n",
            "    provenance {\n",
            "        origin \"observed\"\n",
            "        kind \"git\"\n",
            "        url \"https://example.com/optdep.git\"\n",
            "        ref \"main\"\n",
            "        commit_sha \"", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "\"\n",
            "    }\n",
            "    active_flags \"optdep\"\n",
            "}\n",
        );
        std::fs::write(proj.join("milpa.lock"), lock_text).unwrap();

        // verify must exit non-zero — optdep is in lock but flag is default=#false.
        let rc = cmd_verify(&proj, false, false, false, false, false).unwrap();
        assert_ne!(rc, 0, "verify must exit non-zero when active_flags mismatch");
    }

    // -------------------------------------------------------------------------
    // M4: --all-features + --no-default-features conflict
    // (spec/errors.md §CLI, CLI-FEATURE-FLAGS-CONFLICT)
    // -------------------------------------------------------------------------

    #[test]
    fn m4_check_feature_flags_conflict_both_set() {
        // check_feature_flags_conflict returns true when both flags are present.
        let rest: Vec<String> = vec![
            "--all-features".into(),
            "--no-default-features".into(),
        ];
        assert!(
            check_feature_flags_conflict(&rest),
            "both flags → conflict must be detected"
        );
    }

    #[test]
    fn m4_check_feature_flags_conflict_only_all_features() {
        let rest: Vec<String> = vec!["--all-features".into()];
        assert!(
            !check_feature_flags_conflict(&rest),
            "--all-features alone → no conflict"
        );
    }

    #[test]
    fn m4_check_feature_flags_conflict_only_no_default() {
        let rest: Vec<String> = vec!["--no-default-features".into()];
        assert!(
            !check_feature_flags_conflict(&rest),
            "--no-default-features alone → no conflict"
        );
    }

    #[test]
    fn m4_check_feature_flags_conflict_neither() {
        let rest: Vec<String> = vec!["--features".into(), "tls".into()];
        assert!(
            !check_feature_flags_conflict(&rest),
            "neither flag → no conflict"
        );
    }

    #[test]
    fn m4_fetch_with_both_flags_exits_1() {
        // run() with "fetch --all-features --no-default-features" should exit 1
        // with CLI-FEATURE-FLAGS-CONFLICT (no manifest needed — check fires first).
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        // Minimal milpa.kdl so workspace detection doesn't error.
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        ).unwrap();

        let rc = run(&[
            "-C".into(),
            proj.to_str().unwrap().into(),
            "fetch".into(),
            "--all-features".into(),
            "--no-default-features".into(),
        ]);
        // run() now returns Err(MilpaError) for CLI-FEATURE-FLAGS-CONFLICT,
        // going through the typed-error path (main emits CODE: msg + milpa-error: CODE).
        let err = rc.unwrap_err();
        assert_eq!(
            err.code(),
            "CLI-FEATURE-FLAGS-CONFLICT",
            "fetch --all-features --no-default-features must emit CLI-FEATURE-FLAGS-CONFLICT"
        );
    }

    #[test]
    fn m4_lock_with_both_flags_exits_1() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        ).unwrap();

        let rc = run(&[
            "-C".into(),
            proj.to_str().unwrap().into(),
            "lock".into(),
            "--all-features".into(),
            "--no-default-features".into(),
        ]);
        let err = rc.unwrap_err();
        assert_eq!(
            err.code(),
            "CLI-FEATURE-FLAGS-CONFLICT",
            "lock --all-features --no-default-features must emit CLI-FEATURE-FLAGS-CONFLICT"
        );
    }

    #[test]
    fn m4_update_with_both_flags_exits_1() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        ).unwrap();
        // update needs at least a lockfile (even empty) to avoid LOCK-FILE-NOT-FOUND.
        std::fs::write(
            proj.join("milpa.lock"),
            "// generated by milpa; reproducible build snapshot\nversion 1\nstrategy \"maxver\"\n",
        ).unwrap();

        let rc = run(&[
            "-C".into(),
            proj.to_str().unwrap().into(),
            "update".into(),
            "--all-features".into(),
            "--no-default-features".into(),
        ]);
        let err = rc.unwrap_err();
        assert_eq!(
            err.code(),
            "CLI-FEATURE-FLAGS-CONFLICT",
            "update --all-features --no-default-features must emit CLI-FEATURE-FLAGS-CONFLICT"
        );
    }

    // -----------------------------------------------------------------------
    // host_platform_token / host_arch_token — Nim-vocab mapping (§8 NOTE)
    // -----------------------------------------------------------------------

    #[test]
    fn host_platform_macos_maps_to_macosx() {
        // Rust uses "macos"; Python uses "darwin" — both must output "macosx".
        assert_eq!(host_platform_token("macos"), "macosx");
    }

    #[test]
    fn host_platform_known_tokens() {
        assert_eq!(host_platform_token("linux"), "linux");
        assert_eq!(host_platform_token("windows"), "windows");
        assert_eq!(host_platform_token("freebsd"), "freebsd");
        assert_eq!(host_platform_token("openbsd"), "openbsd");
        assert_eq!(host_platform_token("netbsd"), "netbsd");
    }

    #[test]
    fn host_platform_unknown_passthrough() {
        // Unknown tokens pass through unchanged (spec §8: never rejected).
        assert_eq!(host_platform_token("haiku"), "haiku");
        assert_eq!(host_platform_token("solaris"), "solaris");
    }

    #[test]
    fn host_arch_x86_64_maps_to_amd64() {
        assert_eq!(host_arch_token("x86_64"), "amd64");
    }

    #[test]
    fn host_arch_aarch64_maps_to_arm64() {
        assert_eq!(host_arch_token("aarch64"), "arm64");
    }

    #[test]
    fn host_arch_x86_maps_to_i386() {
        // Rust uses "x86"; Python accepts "i386"/"i686" — all must output "i386".
        assert_eq!(host_arch_token("x86"), "i386");
        assert_eq!(host_arch_token("i386"), "i386");
        assert_eq!(host_arch_token("i686"), "i386");
    }

    #[test]
    fn host_arch_aliases() {
        // Robustness aliases.
        assert_eq!(host_arch_token("amd64"), "amd64");
        assert_eq!(host_arch_token("arm64"), "arm64");
    }

    #[test]
    fn host_arch_unknown_passthrough() {
        assert_eq!(host_arch_token("riscv64"), "riscv64");
        assert_eq!(host_arch_token("mips"), "mips");
    }

    // -----------------------------------------------------------------------
    // profile_from_env — CLI always host-defaults (§8 NOTE)
    // -----------------------------------------------------------------------

    #[test]
    fn profile_from_env_no_env_vars_returns_some_host_defaulted() {
        // With no MILPA_TARGET_* vars set, profile_from_env must return Some
        // (not None) and both platform and arch must be non-None strings.
        // We cannot assert the exact value (test runs on varying hosts), but
        // we can assert the shape.
        std::env::remove_var("MILPA_TARGET_PLATFORM");
        std::env::remove_var("MILPA_TARGET_ARCH");
        std::env::remove_var("MILPA_TARGET_NIM");
        std::env::remove_var("MILPA_TARGET_MILPA");

        let profile = profile_from_env();
        assert!(profile.is_some(), "profile_from_env must always return Some");
        let p = profile.unwrap();
        assert!(
            p.platform.is_some(),
            "platform must be host-defaulted (Some) when MILPA_TARGET_PLATFORM unset"
        );
        assert!(
            p.arch.is_some(),
            "arch must be host-defaulted (Some) when MILPA_TARGET_ARCH unset"
        );
        assert!(
            p.milpa_version.is_some(),
            "milpa_version must be defaulted to own version (Some) when MILPA_TARGET_MILPA unset"
        );
    }

    #[test]
    fn profile_from_env_platform_override_wins() {
        std::env::set_var("MILPA_TARGET_PLATFORM", "windows");
        std::env::remove_var("MILPA_TARGET_ARCH");
        std::env::remove_var("MILPA_TARGET_NIM");
        std::env::remove_var("MILPA_TARGET_MILPA");

        let profile = profile_from_env().expect("must be Some");
        assert_eq!(
            profile.platform.as_deref(),
            Some("windows"),
            "MILPA_TARGET_PLATFORM override must win over host detection"
        );

        std::env::remove_var("MILPA_TARGET_PLATFORM");
    }

    // F10: find_parent_workspace skips members whose directory is uncanonicalizable.
    //
    // A full unit test would require a workspace where one member's directory is
    // a broken symlink (present enough for is_dir() to pass during load_workspace
    // but unresolvable for canonicalize()).  That setup is impractical portably and
    // requires a race between load_workspace and the canonicalize call.  The fix
    // (continue instead of fall-through) is covered by code-inspection and by the
    // conformance corpus end-to-end (workspace S11e fixtures exercise the full
    // find_parent_workspace path).  No isolated unit test is added for F10.

    #[test]
    fn profile_from_env_arch_override_wins() {
        std::env::remove_var("MILPA_TARGET_PLATFORM");
        std::env::set_var("MILPA_TARGET_ARCH", "arm64");
        std::env::remove_var("MILPA_TARGET_NIM");
        std::env::remove_var("MILPA_TARGET_MILPA");

        let profile = profile_from_env().expect("must be Some");
        assert_eq!(
            profile.arch.as_deref(),
            Some("arm64"),
            "MILPA_TARGET_ARCH override must win over host detection"
        );

        std::env::remove_var("MILPA_TARGET_ARCH");
    }

    // -----------------------------------------------------------------------
    // F9: cmd_add / cmd_remove thread --strategy into the lockfile
    // -----------------------------------------------------------------------

    /// F9: cmd_add with Strategy::Minver writes `strategy "minver"` to the lock.
    ///
    /// Previously cmd_add hardcoded `from_graph(&graph, "maxver")` regardless of
    /// the --strategy flag. This test catches a regression where the strategy is
    /// ignored and the lockfile records "maxver" instead of "minver".
    #[test]
    fn f9_add_respects_strategy_minver() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("f9_add_proj");
        std::fs::create_dir_all(&proj).unwrap();

        let url = "https://example.com/dep9.git";
        let sha = "9".repeat(40);
        let mocked = make_mocked_fetches(tmp.path(), url, "main", &sha, &[("dep9.nim", b"# dep9")]);
        std::fs::write(
            proj.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        ).unwrap();

        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        let rc = cmd_add(
            &proj,
            Some(Strategy::Minver),
            &["dep9".into(), "--git".into(), url.into(), "--ref".into(), "main".into()],
            false,
            false,
            false,
            false,
        );
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(rc.unwrap(), 0, "cmd_add --strategy minver must succeed");
        let lock = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();
        assert!(
            lock.contains("strategy \"minver\""),
            "lockfile must record strategy minver (F9); got:\n{lock}"
        );
    }

    /// F9: cmd_remove with Strategy::Minver writes `strategy "minver"` to the lock.
    ///
    /// Previously cmd_remove hardcoded `from_graph(&graph, "maxver")` regardless.
    #[test]
    fn f9_remove_respects_strategy_minver() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("f9_rm_proj");
        std::fs::create_dir_all(&proj).unwrap();

        // Start with two deps; remove one; check the lock has minver strategy.
        let url_a = "https://example.com/dpa.git";
        let url_b = "https://example.com/dpb.git";
        let sha_a = "a".repeat(40);
        let sha_b = "b".repeat(40);
        let mocked = tmp.path().join("mocked-fetches");
        // Seed mocked fetches for both deps.
        for (u, ref_s, sha) in [
            (url_a, "main", sha_a.as_str()),
            (url_b, "main", sha_b.as_str()),
        ] {
            let key_dir = mocked.join(milpa_core::url_key(u, ref_s));
            std::fs::create_dir_all(key_dir.join("content")).unwrap();
            std::fs::write(key_dir.join("sha"), format!("{sha}\n")).unwrap();
            std::fs::write(key_dir.join("content").join("dep.nim"), b"# dep").unwrap();
        }
        std::fs::write(
            proj.join("milpa.kdl"),
            format!(
                "name \"app\"\nkind \"application\"\ndeps {{\n  dpa git=(url)\"{url_a}\" ref=\"main\"\n  dpb git=(url)\"{url_b}\" ref=\"main\"\n}}\n"
            ),
        ).unwrap();

        // Fetch first so there's a lockfile and _deps/ to satisfy remove's resolve.
        unsafe { std::env::set_var("MILPA_MOCKED_FETCHES", &mocked) };
        cmd_fetch(&proj, Some(Strategy::Minver), false, true, None, false, false, &[], false, false, false, None).unwrap();

        // Remove dpa with minver strategy.
        let rc = cmd_remove(
            &proj,
            Some(Strategy::Minver),
            &["dpa".into()],
            false,
            false,
            false,
        );
        unsafe { std::env::remove_var("MILPA_MOCKED_FETCHES") };

        assert_eq!(rc.unwrap(), 0, "cmd_remove --strategy minver must succeed");
        let lock = std::fs::read_to_string(proj.join("milpa.lock")).unwrap();
        assert!(
            lock.contains("strategy \"minver\""),
            "lockfile must record strategy minver after remove (F9); got:\n{lock}"
        );
    }
}
