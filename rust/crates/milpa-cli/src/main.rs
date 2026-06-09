//! `milpa` CLI binary (RFC §6 S13; `docs/spec/cli-contract.md`; mirrors
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
    add_mirror, discover_manifest, format_nimcfg, format_workspace_nimcfgs, from_graph,
    index_url_from_env, load_index, load_lockfile, load_workspace, mutate_manifest_file,
    parse_lockfile, resolve_workspace, verify_lockfile_against_deps, write_lockfile, CaStore,
    CoreError, DefaultRegistry, FrozenResolver, Index, ManifestDoc, Milpa, MilpaError, Resolver,
    Strategy, DEFAULT_TTL_SECONDS,
};
use milpa_manifest::{Dep, UrlDep};

const VERSION: &str = "0.1.0";

const USAGE: &str = "usage: milpa [-C <dir>] [-j <N>] [-s <mode>] [--frozen] \
<fetch|lock|show|verify|clean|add|remove|update> [args]";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(match run(&args) {
        Ok(code) => code,
        // The single normative diagnostic line: `CODE: message` to stderr (§4).
        Err(e) => {
            eprintln!("{}: {}", e.code(), message_of(&e));
            1
        }
    });
}

/// Parsed global flags + the verb and its tail.
struct Cli {
    directory: PathBuf,
    strategy: Strategy,
    frozen: bool,
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
        return Ok(if args.is_empty() { 0 } else { 1 });
    };

    let dir = &cli.directory;
    match cli.verb.as_str() {
        "show" => cmd_show(dir),
        "verify" => cmd_verify(dir),
        "clean" => cmd_clean(dir),
        "fetch" => cmd_fetch(dir, cli.strategy, cli.frozen, true),
        "lock" => cmd_fetch(dir, cli.strategy, cli.frozen, false),
        "update" => cmd_fetch(dir, cli.strategy, false, true),
        "add" => cmd_add(dir, &cli.rest),
        "remove" => cmd_remove(dir, &cli.rest),
        other => {
            eprintln!("milpa: unknown command {other:?}\n{USAGE}");
            Ok(1)
        }
    }
}

/// Hand-rolled arg parse: global flags (some take a value), then the verb + tail.
fn parse_args(args: &[String]) -> Option<Cli> {
    let mut directory = PathBuf::from(".");
    let mut strategy = Strategy::default();
    let mut frozen = false;
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
fn cmd_verify(dir: &Path) -> Result<i32, MilpaError> {
    let lock = load_lockfile(&dir.join("milpa.lock"))?;
    let divergences = verify_lockfile_against_deps(&lock, &dir.join("_deps"));
    if divergences.is_empty() {
        eprintln!("verified {} deps", lock.deps.len());
        Ok(0)
    } else {
        eprintln!("verification failed — {} divergence(s):", divergences.len());
        for d in &divergences {
            eprintln!("  {d}");
        }
        Ok(1)
    }
}

/// `milpa clean` — remove `_deps/` + `nim.cfg`, keep `milpa.lock`.
fn cmd_clean(dir: &Path) -> Result<i32, MilpaError> {
    let _ = std::fs::remove_dir_all(dir.join("_deps"));
    let _ = std::fs::remove_file(dir.join("nim.cfg"));
    Ok(0)
}

/// `milpa fetch` / `lock` / `update` — resolve, write `milpa.lock` (+ `nim.cfg`
/// for fetch). `--frozen` reconstructs from the lockfile + CAS (no network).
fn cmd_fetch(
    dir: &Path,
    strategy: Strategy,
    frozen: bool,
    emit_nimcfg: bool,
) -> Result<i32, MilpaError> {
    let deps_dir = dir.join("_deps");
    let doc = discover_manifest(dir)?;

    if let ManifestDoc::Workspace(_) = doc {
        let ws = load_workspace(dir)?;
        let index = maybe_index();
        let graph = resolve_workspace(
            &ws,
            index.as_ref(),
            &DefaultRegistry::with_curl(),
            None,
            None,
            strategy,
            &deps_dir,
        )?;
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
            "resolved {} deps across {} members",
            graph.deps.len(),
            ws.members.len()
        );
        return Ok(0);
    }

    let ManifestDoc::Package(manifest) = doc else {
        unreachable!("workspace handled above");
    };

    let graph = if frozen {
        let lock = load_lockfile(&dir.join("milpa.lock"))?;
        Milpa.resolve_frozen(&manifest, &lock, &CaStore::new(cas_root()), &deps_dir)?
    } else {
        let index = maybe_index();
        Milpa.resolve(
            &manifest,
            index.as_ref(),
            &DefaultRegistry::with_curl(),
            None,
            None,
            &deps_dir,
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

/// `milpa add <name> --git <url> [--ref <r>]` / `add <name> --mirror <url>`.
fn cmd_add(dir: &Path, rest: &[String]) -> Result<i32, MilpaError> {
    let Some(name) = rest.first().cloned().filter(|n| !n.starts_with('-')) else {
        eprintln!("add: usage: milpa add <name> --git <url> [--ref <r>] | --mirror <url>");
        return Ok(1);
    };
    if let Some(url) = flag_value(rest, "--mirror") {
        add_mirror(dir, &name, &url)?;
        eprintln!("added mirror for {name}");
        return Ok(0);
    }
    let Some(url) = flag_value(rest, "--git") else {
        eprintln!("add: requires --git <url> (new dep) or --mirror <url> (existing dep)");
        return Ok(1);
    };
    let git_ref = flag_value(rest, "--ref").unwrap_or_else(|| "main".to_string());
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
    eprintln!("added dep");
    Ok(0)
}

/// `milpa remove <name>` — drop a dep from the manifest.
fn cmd_remove(dir: &Path, rest: &[String]) -> Result<i32, MilpaError> {
    let Some(name) = rest.first().cloned() else {
        eprintln!("remove: usage: milpa remove <name>");
        return Ok(1);
    };
    let mut removed = false;
    {
        let removed = &mut removed;
        let name = name.clone();
        mutate_manifest_file(&dir.join("milpa.kdl"), move |mut m| {
            let before = m.deps.len();
            m.deps.retain(|d| d.name() != name);
            *removed = m.deps.len() != before;
            m
        })?;
    }
    if removed {
        eprintln!("removed {name}");
        Ok(0)
    } else {
        eprintln!("remove: no dep {name:?} in milpa.kdl");
        Ok(1)
    }
}

// --- helpers ---------------------------------------------------------------

/// Load the tianguis index from the cache (real network via `curl`), or `None`
/// when unreachable — `resolve` only surfaces `RES-NO-INDEX` if a named dep
/// actually needs it.
fn maybe_index() -> Option<Index> {
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
    load_index(
        &index_url_from_env(),
        &index_cache_dir(),
        &http,
        DEFAULT_TTL_SECONDS,
        now,
    )
    .ok()
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
    fn show_clean_remove_run_offline() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // clean on an empty project is a no-op success.
        assert_eq!(cmd_clean(dir).unwrap(), 0);
        // a manifest + add/remove round-trip.
        std::fs::write(
            dir.join("milpa.kdl"),
            "name \"app\"\nkind \"application\"\n",
        )
        .unwrap();
        assert_eq!(
            cmd_add(
                dir,
                &["foo".into(), "--git".into(), "https://e/foo.git".into()]
            )
            .unwrap(),
            0
        );
        let after_add = std::fs::read_to_string(dir.join("milpa.kdl")).unwrap();
        assert!(after_add.contains("\"foo\""));
        assert_eq!(cmd_remove(dir, &["foo".into()]).unwrap(), 0);
        let after_rm = std::fs::read_to_string(dir.join("milpa.kdl")).unwrap();
        assert!(!after_rm.contains("\"foo\""));
        // remove of an absent dep → exit 1.
        assert_eq!(cmd_remove(dir, &["ghost".into()]).unwrap(), 1);
    }
}
