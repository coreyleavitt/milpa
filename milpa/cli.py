"""milpa CLI entry point.

argparse-based dispatch over four v0 subcommands:

  fetch  — resolve manifest, clone deps into _deps/, emit nim.cfg, write
           milpa.lock
  lock   — resolve manifest and write milpa.lock (no nim.cfg)
  show   — read milpa.lock, print the dep tree
  clean  — remove _deps/ and nim.cfg; keep milpa.lock

Commands are exposed as `cmd_*` functions taking `project_dir` plus
dependency-injectable callables (fetcher, list_tags) so tests can
exercise them without subprocess overhead or network access. The
`main(argv)` dispatcher is a thin argparse layer over these.
"""

import argparse
import os
import shutil
import sys
from pathlib import Path
from collections.abc import Callable

from . import __version__
from .cas import CAStore
from .fetchers import FetcherRegistry, default_registry
from .nimcfg import write_workspace_nimcfgs
from .lockfile import (
    format_lockfile, from_graph, load_lockfile,
    verify_lockfile_against_deps, verify_workspace_against_disk,
    write_lockfile,
)
from .frozen import NotFrozen, resolve_frozen, resolve_workspace_frozen
from .profile import Profile
from .manifest import (
    LocalDep, ManifestError, MemberDep, NamedDep, TarballDep, UrlDep,
    load_or_discover_manifest,
)
from .manifest_writer import apply_manifest_change_with_resolve
from .nimcfg import write_nimcfg
from .registry import RegistryEntry, list_remote_tags, load_registry
from .solver import Strategy
from .resolver import ResolvedGraph, resolve, resolve_workspace
from .workspace import workspace_containing


SUBCOMMAND_HELP = {
    "fetch":  "resolve manifest, clone deps, emit nim.cfg, write lockfile",
    "lock":   "resolve manifest and write lockfile (no nim.cfg)",
    "show":   "print the resolved dep tree",
    "verify": "recheck each dep in _deps/ against milpa.lock (no fetch)",
    "clean":  "remove _deps/ and nim.cfg (keeps milpa.lock)",
    "add":    "add a mirror for an existing dep (more verbs to come)",
    "remove": "remove a dep from milpa.kdl and regenerate the lockfile",
    "update": "re-resolve (optionally a single dep) and refresh the lockfile",
    "publish": "pack + push + sign + POST tianguis dispatch (author-side)",
}


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="milpa",
        description="Nim dependency resolver. Reads milpa.kdl, emits nim.cfg.",
    )
    parser.add_argument(
        "--version", action="version", version=f"milpa {__version__}"
    )
    parser.add_argument(
        "-C", "--directory", metavar="<dir>", default=".",
        help="run as if invoked from <dir> instead of the current directory",
    )
    parser.add_argument(
        "-j", "--parallel", metavar="<N>", type=int, default=8,
        help="number of concurrent fetches (default: 8; use 1 for serial)",
    )
    parser.add_argument(
        "-s", "--strategy", metavar="<mode>",
        choices=("maxver", "minver", "semver"),
        default="maxver",
        help=(
            "resolution strategy: maxver (default, highest version), "
            "minver (lowest — good for libraries), or semver (highest "
            "within same major as the constraint's lower bound)"
        ),
    )
    parser.add_argument(
        "--frozen", action="store_true",
        help=(
            "fetch: require the lockfile + CAS to fully resolve the "
            "graph with no network access; exit 1 if anything is "
            "missing or drifted. (CI mode.)"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    for name, help_text in SUBCOMMAND_HELP.items():
        sp = subparsers.add_parser(name, help=help_text)
        if name == "remove":
            sp.add_argument(
                "dep_name", metavar="<dep>",
                help="name of the dep to remove from milpa.kdl",
            )
        elif name == "update":
            sp.add_argument(
                "dep_name", metavar="<dep>", nargs="?", default=None,
                help=(
                    "name of a single dep to refresh; if omitted, "
                    "all pins are dropped and the entire graph re-resolves"
                ),
            )
        elif name == "add":
            sp.add_argument(
                "dep_name", metavar="<dep>",
                help="dep name (new dep with --git, or existing dep with --mirror)",
            )
            mode = sp.add_mutually_exclusive_group()
            mode.add_argument(
                "--git", metavar="<url>",
                help="add as a brand-new git-sourced dep at <url>",
            )
            mode.add_argument(
                "--mirror", metavar="<url>",
                help="add <url> as a mirror provenance for the existing <dep>",
            )
            sp.add_argument(
                "--ref", metavar="<ref>",
                help=(
                    "git ref (branch / tag / sha) when using --git "
                    "(default: discovered from remote HEAD)"
                ),
            )
        elif name == "publish":
            sp.add_argument("--name", required=True, help="package name")
            sp.add_argument("--version", required=True, help="semver tag (e.g. v1.2.3)")
            sp.add_argument("--registry", required=True, metavar="<ref>",
                            help="OCI registry ref (e.g. ghcr.io/owner/repo:v1.2.3)")
            sp.add_argument("--provider", required=True,
                            help="CI provider name (github, gitlab, ...)")
            sp.add_argument("--repo-url", required=True, help="https URL of source repo")
            sp.add_argument("--signed-by", required=True,
                            help="cosign signer identity (workflow URL + ref)")
            sp.add_argument("--dispatch-url", default="https://dispatch.tianguis.dev",
                            help="tianguis dispatch endpoint (default: production)")
            sp.add_argument("--oidc-token-env", default="ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                            help="env var holding the bearer OIDC token")
            sp.add_argument("--dry-run", action="store_true",
                            help="pack + push + sign but skip dispatch POST")
    return parser


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

RegistryLoader = Callable[..., dict[str, RegistryEntry]]


def _default_registry_loader(*, cache_path: Path) -> dict[str, RegistryEntry]:
    return load_registry(cache_path=cache_path)


def cmd_fetch(
    project_dir: Path,
    *,
    fetcher: FetcherRegistry = default_registry,
    list_tags: Callable[[str], list[str]] = list_remote_tags,
    registry_loader: RegistryLoader = _default_registry_loader,
    max_parallel: int = 8,
    strategy: Strategy = Strategy.MAXVER,
    frozen: bool = False,
) -> int:
    """Resolve, fetch, emit nim.cfg + milpa.lock.

    Workspace-aware: if project_dir is inside a workspace (root or any
    member), the workspace is resolved as a unit — shared lockfile at
    <root>/milpa.lock, per-member nim.cfgs at <root>/<member>/nim.cfg.
    Otherwise behaves as a single-project fetch.

    Frozen fast path (#36): if a lockfile is present and the global CAS
    holds every pinned identity, resolution skips fetching entirely —
    just symlinks _deps/ into the CAS. On any precondition failure
    (manifest drift, CAS miss, etc.), falls through to the slow path.
    With `frozen=True`, the fall-through is an error instead.
    """
    ws = workspace_containing(project_dir)
    if ws is not None:
        return _cmd_fetch_workspace(
            ws, fetcher=fetcher, list_tags=list_tags,
            registry_loader=registry_loader, max_parallel=max_parallel,
            strategy=strategy, frozen=frozen,
        )

    # Load manifest once to forward self_src_dir to nim.cfg emission
    # and to honor a project-level CAS override (cas { dir "..." }).
    # Errors propagate via the existing resolve/frozen paths.
    self_src_dir = ""
    try:
        manifest = load_or_discover_manifest(project_dir)
        self_src_dir = manifest.src_dir
        fetcher = _fetcher_for_manifest(
            manifest, project_dir, default=fetcher,
        )
    except ManifestError:
        pass  # frozen / slow path will surface the same error with full context

    frozen_result = _try_frozen(
        project_dir, fetcher=fetcher, strategy=strategy,
    )
    if isinstance(frozen_result, ResolvedGraph):
        write_nimcfg(
            frozen_result, project_root=project_dir,
            self_src_dir=self_src_dir,
        )
        print(
            f"resolved {len(frozen_result.deps)} deps (frozen)",
            file=sys.stderr,
        )
        return 0
    if frozen:
        print(f"frozen: {frozen_result}", file=sys.stderr)
        return 1

    graph = _resolve_or_error(
        project_dir, fetcher=fetcher, list_tags=list_tags,
        registry_loader=registry_loader, max_parallel=max_parallel,
        strategy=strategy,
    )
    if isinstance(graph, int):
        return graph
    lockfile = from_graph(graph, strategy=str(strategy))
    write_lockfile(lockfile, project_dir / "milpa.lock")
    write_nimcfg(
        graph, project_root=project_dir, self_src_dir=self_src_dir,
    )
    print(f"resolved {len(graph.deps)} deps", file=sys.stderr)
    return 0


def _fetcher_for_manifest(
    manifest, project_dir: Path, *, default: FetcherRegistry,
) -> FetcherRegistry:
    """Honor a project-level CAS override (`cas { dir "..." }`).

    Precedence (highest first):
      1. `MILPA_CACHE_DIR` env var — already picked up by default_store(); we
         do nothing here so the passed-in registry's CAS wins.
      2. Manifest `cas { dir "..." }` — construct a fresh FetcherRegistry
         with a CAStore at <project_dir>/<cas_dir>. Relative paths resolve
         against the project root; absolute paths used verbatim.
      3. Default (XDG / ~/.cache) — passed-in registry.
    """
    if os.environ.get("MILPA_CACHE_DIR"):
        return default
    if not manifest.cas_dir:
        return default
    cas_root = Path(manifest.cas_dir)
    if not cas_root.is_absolute():
        cas_root = project_dir / cas_root
    cas_root.mkdir(parents=True, exist_ok=True)
    return default.with_store(CAStore(root=cas_root))


def _try_frozen(
    project_dir: Path,
    *,
    fetcher: FetcherRegistry,
    strategy: Strategy,
):
    """Attempt the frozen fast path. Returns ResolvedGraph on success
    or a NotFrozen reason (str) on failure."""
    lockfile_path = project_dir / "milpa.lock"
    if not lockfile_path.exists():
        return "no lockfile"
    if fetcher.store is None:
        return "no CAS attached to fetcher"
    try:
        manifest = load_or_discover_manifest(project_dir)
    except ManifestError:
        return "manifest could not be loaded"
    try:
        lockfile = load_lockfile(lockfile_path)
    except Exception as e:
        return f"lockfile could not be loaded: {e}"
    try:
        return resolve_frozen(
            manifest, lockfile=lockfile, deps_dir=project_dir / "_deps",
            store=fetcher.store, strategy=strategy,
        )
    except NotFrozen as e:
        return str(e)


def _try_workspace_frozen(
    ws,
    *,
    fetcher: FetcherRegistry,
    strategy: Strategy,
):
    """Workspace analog of _try_frozen. Returns ResolvedGraph on success
    or a NotFrozen reason (str) on failure (#78)."""
    lockfile_path = ws.root / "milpa.lock"
    if not lockfile_path.exists():
        return "no lockfile"
    if fetcher.store is None:
        return "no CAS attached to fetcher"
    try:
        lockfile = load_lockfile(lockfile_path)
    except Exception as e:
        return f"lockfile could not be loaded: {e}"
    try:
        return resolve_workspace_frozen(
            ws, lockfile=lockfile, deps_dir=ws.root / "_deps",
            store=fetcher.store, strategy=strategy,
        )
    except NotFrozen as e:
        return str(e)


def _cmd_fetch_workspace(
    ws,  # Workspace
    *,
    fetcher: FetcherRegistry,
    list_tags: Callable[[str], list[str]],
    registry_loader: RegistryLoader,
    max_parallel: int,
    strategy: Strategy,
    frozen: bool = False,
) -> int:
    deps_dir = ws.root / "_deps"

    # Try workspace frozen fast path before any registry / fetch work (#78).
    frozen_result = _try_workspace_frozen(
        ws, fetcher=fetcher, strategy=strategy,
    )
    if isinstance(frozen_result, ResolvedGraph):
        written = write_workspace_nimcfgs(ws, frozen_result)
        print(
            f"resolved {len(frozen_result.deps)} deps across "
            f"{len(ws.members)} members (frozen); "
            f"emitted {len(written)} nim.cfg(s)",
            file=sys.stderr,
        )
        return 0
    if frozen:
        print(f"frozen: {frozen_result}", file=sys.stderr)
        return 1

    cache_path = deps_dir / ".packages_official.json"
    try:
        registry = registry_loader(cache_path=cache_path)
    except Exception as e:
        print(f"failed to load registry: {e}", file=sys.stderr)
        return 1
    prior_lockfile = _maybe_load_prior_lockfile(ws.root / "milpa.lock")
    profile = Profile.from_environment()
    try:
        graph = resolve_workspace(
            ws, deps_dir=deps_dir,
            registry=registry, fetcher=fetcher,
            list_tags=list_tags, max_parallel=max_parallel,
            strategy=strategy,
            prior_lockfile=prior_lockfile,
            profile=profile,
        )
    except Exception as e:
        print(f"workspace resolution failed: {e}", file=sys.stderr)
        return 1
    lockfile = from_graph(graph, strategy=str(strategy))
    write_lockfile(lockfile, ws.root / "milpa.lock")
    written = write_workspace_nimcfgs(ws, graph)
    print(
        f"resolved {len(graph.deps)} deps across {len(ws.members)} members; "
        f"emitted {len(written)} nim.cfg(s)",
        file=sys.stderr,
    )
    return 0


def cmd_lock(
    project_dir: Path,
    *,
    fetcher: FetcherRegistry = default_registry,
    list_tags: Callable[[str], list[str]] = list_remote_tags,
    registry_loader: RegistryLoader = _default_registry_loader,
    max_parallel: int = 8,
    strategy: Strategy = Strategy.MAXVER,
) -> int:
    """Resolve + write milpa.lock; do not emit nim.cfg."""
    graph = _resolve_or_error(
        project_dir, fetcher=fetcher, list_tags=list_tags,
        registry_loader=registry_loader, max_parallel=max_parallel,
        strategy=strategy,
    )
    if isinstance(graph, int):
        return graph
    lockfile = from_graph(graph, strategy=str(strategy))
    write_lockfile(lockfile, project_dir / "milpa.lock")
    print(f"locked {len(graph.deps)} deps", file=sys.stderr)
    return 0


def cmd_show(project_dir: Path) -> int:
    """Print the resolved dep tree from milpa.lock.

    Each dep is shown as three lanes:
      identity    sha256:<8 hex>   ← content hash (the canonical 'what')
      provenance  <source> @ <ref> (sha <short>) ← where the bytes came from
      requires    <names>          ← direct deps

    The full identity and commit SHA are in milpa.lock — `milpa show`
    truncates for readability. See docs/identity-and-provenance.md for
    why the two are distinct.
    """
    lockfile_path = project_dir / "milpa.lock"
    if not lockfile_path.exists():
        print(
            f"no lockfile found at {lockfile_path} — run `milpa fetch` first",
            file=sys.stderr,
        )
        return 1
    try:
        lockfile = load_lockfile(lockfile_path)
    except Exception as e:  # LockfileError or unexpected
        print(f"failed to read lockfile: {e}", file=sys.stderr)
        return 1
    for dep in lockfile.deps:
        print(f"{dep.name:20s} {dep.version}")
        if dep.identity:
            # identity is multihash-encoded (#34) — `<algo>:<hex>`.
            # Truncate the digest portion for display.
            algo, _, digest = dep.identity.partition(":")
            print(f"  identity    {algo}:{digest[:8]}")
        for prov in dep.provenances:
            print(f"  provenance  {_format_provenance_for_show(prov)}")
        if dep.requires:
            print(f"  requires    {', '.join(dep.requires)}")
    return 0


def _format_provenance_for_show(p) -> str:
    """Render a ProvenanceRecord as a one-line summary for cmd_show."""
    from .lockfile import (
        GitProvenanceRecord,
        TarballProvenanceRecord,
        LocalProvenanceRecord,
        MemberProvenanceRecord,
        RegistryProvenanceRecord,
    )
    if isinstance(p, GitProvenanceRecord):
        parts = [f"git {p.url}"]
        if p.ref:
            parts.append(f"@ {p.ref}")
        if p.commit_sha:
            parts.append(f"(sha {p.commit_sha[:8]})")
        return " ".join(parts)
    if isinstance(p, TarballProvenanceRecord):
        return f"tarball {p.url}"
    if isinstance(p, LocalProvenanceRecord):
        return f"local {p.path}"
    if isinstance(p, MemberProvenanceRecord):
        return f"member {p.name}"
    if isinstance(p, RegistryProvenanceRecord):
        parts = [f"registry {p.name}"]
        if p.tag:
            parts.append(f"@ {p.tag}")
        if p.commit_sha:
            parts.append(f"(sha {p.commit_sha[:8]})")
        return " ".join(parts)
    return str(p)


def cmd_verify(project_dir: Path) -> int:
    """Verify every dep in _deps/ matches its lockfile-recorded identity.

    Exits 0 if every dep's bytes hash to its locked content_hash AND
    no extra (non-locked, non-dotfile) entries exist in _deps/. On any
    divergence, lists every issue on stderr and exits 1.

    This is the canonical integrity check — answers 'are my checked-out
    deps what milpa.lock says they should be?' Useful in CI ('did
    anyone hand-edit _deps/?') and after a checkout to confirm
    reproducibility.
    """
    ws = workspace_containing(project_dir)
    if ws is not None:
        lockfile_path = ws.root / "milpa.lock"
        if not lockfile_path.exists():
            print(
                f"no lockfile found at {lockfile_path} — run `milpa fetch` first",
                file=sys.stderr,
            )
            return 1
        try:
            lockfile = load_lockfile(lockfile_path)
        except Exception as e:
            print(f"failed to read lockfile: {e}", file=sys.stderr)
            return 1
        divergences = verify_workspace_against_disk(ws, lockfile)
        if divergences:
            print(
                f"verification failed — {len(divergences)} divergence(s):",
                file=sys.stderr,
            )
            for msg in divergences:
                print(f"  {msg}", file=sys.stderr)
            return 1
        print(
            f"verified {len(lockfile.deps)} deps across "
            f"{len(ws.members)} workspace members",
            file=sys.stderr,
        )
        return 0

    lockfile_path = project_dir / "milpa.lock"
    deps_dir = project_dir / "_deps"
    if not lockfile_path.exists():
        print(
            f"no lockfile found at {lockfile_path} — run `milpa fetch` first",
            file=sys.stderr,
        )
        return 1
    if not deps_dir.exists():
        print(
            f"no deps directory at {deps_dir} — run `milpa fetch` first",
            file=sys.stderr,
        )
        return 1
    try:
        lockfile = load_lockfile(lockfile_path)
    except Exception as e:
        print(f"failed to read lockfile: {e}", file=sys.stderr)
        return 1
    divergences = verify_lockfile_against_deps(lockfile, deps_dir)
    if divergences:
        print(
            f"verification failed — {len(divergences)} divergence(s):",
            file=sys.stderr,
        )
        for msg in divergences:
            print(f"  {msg}", file=sys.stderr)
        return 1
    for warning in _local_source_drift_warnings(project_dir, lockfile):
        print(f"warning: {warning}", file=sys.stderr)
    print(f"verified {len(lockfile.deps)} deps", file=sys.stderr)
    return 0


def _git_default_branch(url: str) -> str:
    """Discover the remote's default branch via git ls-remote --symref HEAD.

    Returns the branch name (e.g. "main" or "master"). On failure
    raises subprocess.CalledProcessError — the caller surfaces the
    error before any manifest mutation."""
    import re
    import subprocess
    out = subprocess.run(
        ["git", "ls-remote", "--symref", url, "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout
    # First line of output: "ref: refs/heads/<branch>\tHEAD"
    m = re.search(r"refs/heads/(\S+)\s+HEAD", out)
    if not m:
        raise RuntimeError(
            f"could not determine default branch for {url}; "
            f"pass --ref explicitly"
        )
    return m.group(1)


def cmd_add(
    project_dir: Path,
    *,
    name: str,
    git: str,
    ref: str | None = None,
    fetcher: FetcherRegistry = default_registry,
    list_tags: Callable[[str], list[str]] = list_remote_tags,
    registry_loader: "RegistryLoader" = _default_registry_loader,
    strategy: Strategy = Strategy.MAXVER,
    default_branch_discoverer: Callable[[str], str] = _git_default_branch,
) -> int:
    """Add a brand-new UrlDep to milpa.kdl. Validates by running a
    full resolve over the proposed manifest; commits manifest +
    lockfile atomically only if resolution succeeds (#16)."""
    from dataclasses import replace

    manifest_path = project_dir / "milpa.kdl"
    if not manifest_path.exists():
        print(
            f"add: no milpa.kdl at {manifest_path}",
            file=sys.stderr,
        )
        return 1

    try:
        manifest = load_or_discover_manifest(project_dir)
    except ManifestError as e:
        print(f"add: cannot load manifest: {e}", file=sys.stderr)
        return 1

    if any(d.name == name for d in manifest.deps):
        print(
            f"add: dep {name!r} already declared in milpa.kdl — "
            f"use `milpa update` to change refs / mirrors",
            file=sys.stderr,
        )
        return 1

    resolved_ref = ref
    if resolved_ref is None:
        try:
            resolved_ref = default_branch_discoverer(git)
        except Exception as e:
            print(
                f"add: could not discover default branch for {git}: {e}; "
                f"pass --ref explicitly",
                file=sys.stderr,
            )
            return 1

    proposed = replace(
        manifest,
        deps=manifest.deps + (UrlDep(name=name, git=git, ref=resolved_ref),),
    )

    try:
        apply_manifest_change_with_resolve(
            project_dir,
            proposed_manifest=proposed,
            fetcher=fetcher,
            list_tags=list_tags,
            registry_loader=registry_loader,
            strategy=strategy,
        )
    except Exception as e:
        print(f"add: resolution failed: {e}", file=sys.stderr)
        return 1

    print(
        f"added {name} (git={git} ref={resolved_ref})",
        file=sys.stderr,
    )
    return 0


def cmd_update(
    project_dir: Path,
    *,
    name: str | None = None,
    fetcher: FetcherRegistry = default_registry,
    list_tags: Callable[[str], list[str]] = list_remote_tags,
    registry_loader: "RegistryLoader" = _default_registry_loader,
    max_parallel: int = 8,
    strategy: Strategy = Strategy.MAXVER,
) -> int:
    """Re-resolve and refresh the lockfile (#18).

    `name=None`: drop ALL pins; the entire graph re-resolves with
    freedom to pick up new upstream bytes.
    `name=<str>`: drop only that dep's pin; everything else stays
    stable (transitives self-update when their resolved provenance
    changes — see #82's per-dep tag-match logic).

    Does NOT mutate milpa.kdl — manifest text is byte-identical
    after this call. Lockfile + _deps/ change.
    """
    from dataclasses import replace

    manifest_path = project_dir / "milpa.kdl"
    lockfile_path = project_dir / "milpa.lock"

    if not manifest_path.exists():
        print(f"update: no milpa.kdl at {manifest_path}", file=sys.stderr)
        return 1

    try:
        manifest = load_or_discover_manifest(project_dir)
    except ManifestError as e:
        print(f"update: cannot load manifest: {e}", file=sys.stderr)
        return 1

    prior_lockfile = None
    if name is not None:
        # Targeted update: load lockfile, filter out the named entry
        if not lockfile_path.exists():
            print(
                f"update: no lockfile at {lockfile_path} — "
                f"run `milpa fetch` first",
                file=sys.stderr,
            )
            return 1
        try:
            full_lockfile = load_lockfile(lockfile_path)
        except Exception as e:
            print(f"update: cannot load lockfile: {e}", file=sys.stderr)
            return 1
        if not any(d.name == name for d in full_lockfile.deps):
            names = ", ".join(sorted(d.name for d in full_lockfile.deps))
            print(
                f"update: no dep {name!r} in lockfile "
                f"(known: {names or '<none>'})",
                file=sys.stderr,
            )
            return 1
        prior_lockfile = replace(
            full_lockfile,
            deps=tuple(d for d in full_lockfile.deps if d.name != name),
        )

    deps_dir = project_dir / "_deps"
    deps_dir.mkdir(parents=True, exist_ok=True)
    cache_path = deps_dir / ".packages_official.json"
    try:
        registry = registry_loader(cache_path=cache_path)
    except Exception as e:
        print(f"update: failed to load registry: {e}", file=sys.stderr)
        return 1

    try:
        graph = resolve(
            manifest,
            deps_dir=deps_dir,
            registry=registry,
            fetcher=fetcher,
            list_tags=list_tags,
            max_parallel=max_parallel,
            strategy=strategy,
            prior_lockfile=prior_lockfile,
            profile=Profile.from_environment(),
        )
    except Exception as e:
        print(f"update: resolution failed: {e}", file=sys.stderr)
        return 1

    new_lockfile = from_graph(graph, strategy=str(strategy))
    write_lockfile(new_lockfile, lockfile_path)
    target = name if name else "all deps"
    print(f"updated {target}", file=sys.stderr)
    return 0


def cmd_remove(
    project_dir: Path,
    *,
    name: str,
    fetcher: FetcherRegistry = default_registry,
    list_tags: Callable[[str], list[str]] = list_remote_tags,
    registry_loader: "RegistryLoader" = _default_registry_loader,
    strategy: Strategy = Strategy.MAXVER,
) -> int:
    """Drop `name` from milpa.kdl + regenerate the lockfile (#17).

    Orphaned transitives disappear naturally from the new lockfile
    via the full re-resolve. If `name` is still required transitively
    by another dep, it stays in the resolved graph — removing from
    the manifest doesn't force removal from the graph."""
    from dataclasses import replace

    manifest_path = project_dir / "milpa.kdl"
    if not manifest_path.exists():
        print(
            f"remove: no milpa.kdl at {manifest_path}",
            file=sys.stderr,
        )
        return 1

    try:
        manifest = load_or_discover_manifest(project_dir)
    except ManifestError as e:
        print(f"remove: cannot load manifest: {e}", file=sys.stderr)
        return 1

    if not any(d.name == name for d in manifest.deps):
        names = ", ".join(sorted(d.name for d in manifest.deps))
        print(
            f"remove: no dep {name!r} in milpa.kdl "
            f"(known: {names or '<none>'})",
            file=sys.stderr,
        )
        return 1

    proposed = replace(
        manifest,
        deps=tuple(d for d in manifest.deps if d.name != name),
    )

    try:
        apply_manifest_change_with_resolve(
            project_dir,
            proposed_manifest=proposed,
            fetcher=fetcher,
            list_tags=list_tags,
            registry_loader=registry_loader,
            strategy=strategy,
        )
    except Exception as e:
        print(f"remove: resolution failed: {e}", file=sys.stderr)
        return 1

    print(f"removed {name}", file=sys.stderr)
    return 0


def cmd_add_mirror(
    project_dir: Path,
    *,
    url: str,
    dep_name: str,
    fetcher: FetcherRegistry = default_registry,
    list_tags: Callable[[str], list[str]] = list_remote_tags,
    registry_loader: "RegistryLoader" = _default_registry_loader,
    strategy: Strategy = Strategy.MAXVER,
    relock: Callable[[Path], None] | None = None,    # back-compat; ignored
) -> int:
    """Append `url` as a mirror provenance for `dep_name` in the
    manifest (#37).

    Validates by (1) fetching `url` and confirming its bytes hash to
    the locked identity for `dep_name`, then (2) running a full
    resolve over the proposed manifest. On success, atomically
    commits manifest + lockfile. On any failure, neither file is
    modified.
    """
    from dataclasses import replace
    from .fetchers.git import GitProvenance
    from .lockfile import (
        GitProvenanceRecord, LocalProvenanceRecord, MemberProvenanceRecord,
    )

    lockfile_path = project_dir / "milpa.lock"
    manifest_path = project_dir / "milpa.kdl"

    if not lockfile_path.exists():
        print(
            f"add --mirror: no lockfile at {lockfile_path} — "
            f"run `milpa fetch` first",
            file=sys.stderr,
        )
        return 1
    if not manifest_path.exists():
        print(
            f"add --mirror: no milpa.kdl at {manifest_path}",
            file=sys.stderr,
        )
        return 1

    try:
        lockfile = load_lockfile(lockfile_path)
    except Exception as e:
        print(f"add --mirror: cannot load lockfile: {e}", file=sys.stderr)
        return 1

    locked = next((d for d in lockfile.deps if d.name == dep_name), None)
    if locked is None:
        names = ", ".join(sorted(d.name for d in lockfile.deps))
        print(
            f"add --mirror: no dep {dep_name!r} in lockfile "
            f"(known: {names or '<none>'})",
            file=sys.stderr,
        )
        return 1

    if any(isinstance(p, (LocalProvenanceRecord, MemberProvenanceRecord))
           for p in locked.provenances):
        print(
            f"add --mirror: dep {dep_name!r} has a local/member "
            f"provenance — cannot add a mirror to an editable source",
            file=sys.stderr,
        )
        return 1

    try:
        manifest = load_or_discover_manifest(project_dir)
    except ManifestError as e:
        print(f"add --mirror: cannot load manifest: {e}", file=sys.stderr)
        return 1

    # Build the proposed manifest (append mirror to the target UrlDep).
    target_in_manifest = next(
        (d for d in manifest.deps
         if isinstance(d, UrlDep) and d.name == dep_name),
        None,
    )
    if target_in_manifest is None:
        print(
            f"add --mirror: dep {dep_name!r} in lockfile has no "
            f"matching UrlDep in milpa.kdl",
            file=sys.stderr,
        )
        return 1
    if url in target_in_manifest.mirrors:
        # Idempotent: nothing to do
        print(
            f"add --mirror: {url} already a mirror for {dep_name}",
            file=sys.stderr,
        )
        return 0

    new_deps = tuple(
        replace(d, mirrors=d.mirrors + (url,))
        if isinstance(d, UrlDep) and d.name == dep_name
        else d
        for d in manifest.deps
    )
    proposed = replace(manifest, deps=new_deps)

    # pre_resolve_validate: probe the mirror URL specifically and
    # check identity. The subsequent full resolve will use the
    # primary URL (which succeeded last time), so the mirror URL
    # itself would never be touched by resolve alone.
    def pre_validate() -> None:
        # Pick a ref from the existing git provenance, falling back
        # to 'main' if no git provenance is recorded.
        ref = "main"
        for p in locked.provenances:
            if isinstance(p, GitProvenanceRecord) and p.ref:
                ref = p.ref
                break
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / dep_name
            result = fetcher.fetch(
                dep_name, GitProvenance(url=url, ref=ref), dest=scratch,
            )
            if result.identity != locked.identity:
                raise ManifestError(
                    f"add --mirror: bytes at {url} hash to "
                    f"{result.identity[:23]}..., "
                    f"locked identity is "
                    f"{(locked.identity or '<none>')[:23]}... "
                    f"— mirrors must serve identical bytes",
                    code="MAN-ADD-MIRROR-IDENTITY-MISMATCH",
                )

    try:
        apply_manifest_change_with_resolve(
            project_dir,
            proposed_manifest=proposed,
            fetcher=fetcher,
            list_tags=list_tags,
            registry_loader=registry_loader,
            strategy=strategy,
            pre_resolve_validate=pre_validate,
        )
    except Exception as e:
        print(str(e), file=sys.stderr)
        return 1

    print(
        f"added mirror {url} for {dep_name}", file=sys.stderr,
    )
    return 0


def _local_source_drift_warnings(
    project_dir: Path, lockfile,
) -> list[str]:
    """For LocalDeps, check whether the source dir has drifted from the
    snapshot recorded in the lockfile. Returns warning messages; does
    NOT affect the exit code.

    Local provenance is the only transport where source can change
    between fetches without milpa noticing — git/tarball/etc fetch
    immutable refs. This warning hints the user to re-`milpa fetch`
    when the source is ahead of the snapshot.
    """
    from .identity import compute_content_hash
    from .lockfile import LocalProvenanceRecord
    warnings: list[str] = []
    for dep in lockfile.deps:
        # Find the first LocalProvenanceRecord (if any). Multi-
        # provenance: identity is single per dep, so the source-drift
        # check applies once even if multiple provenances are recorded.
        local_prov = next(
            (p for p in dep.provenances if isinstance(p, LocalProvenanceRecord)),
            None,
        )
        if local_prov is None:
            continue
        declared = local_prov.path
        abs_source = (project_dir / declared).resolve()
        if not abs_source.is_dir():
            warnings.append(
                f"{dep.name}: local source {abs_source} is missing or "
                f"no longer a directory"
            )
            continue
        actual = compute_content_hash(abs_source)
        if actual != dep.identity:
            warnings.append(
                f"{dep.name}: local source at {declared!r} has drifted "
                f"from the snapshot in milpa.lock; run `milpa fetch` to refresh"
            )
    return warnings


def cmd_publish(
    project_dir: Path,
    *,
    name: str,
    version: str,
    registry_ref: str,
    provider: str,
    repo_url: str,
    signed_by: str,
    dispatch_url: str,
    oidc_token_env: str,
    dry_run: bool,
) -> int:
    """Glue between argparse and milpa.publish.publish().

    Reads the OIDC bearer from the chosen env var (per-provider name —
    GH's ACTIONS_ID_TOKEN_REQUEST_TOKEN, GitLab's CI_JOB_JWT_V2, etc.)
    so the same publish module works across CIs.
    """
    from .publish import publish

    # Try to fetch a sigstore-audience OIDC token regardless of dry-run
    # mode. dry-run only suppresses the index commit on the dispatch
    # side; the rest of the chain (including the POST) should still
    # exercise. If no token is available, dry-run downgrades to the
    # local-dev path (skip POST entirely); a real publish errors out.
    from .publish import fetch_sigstore_oidc_token

    token = fetch_sigstore_oidc_token(oidc_token_env)
    if not token and not dry_run:
        print(f"publish: no sigstore-audience OIDC token available "
              f"(checked ${oidc_token_env} and GH Actions OIDC API); "
              f"this command must run inside a CI job with OIDC enabled "
              f"(or pass --dry-run for local testing)",
              file=sys.stderr)
        return 1

    try:
        result = publish(
            source_dir=project_dir,
            name=name,
            version=version,
            registry_ref=registry_ref,
            provider=provider,
            repo_url=repo_url,
            signed_by=signed_by,
            oidc_token=token,
            dispatch_url=dispatch_url,
            dry_run=dry_run,
        )
    except RuntimeError as e:
        print(f"publish: {e}", file=sys.stderr)
        return 1

    if dry_run:
        print(f"publish: --dry-run complete (no dispatch POST sent)")
    else:
        print(f"publish: dispatch accepted ({result})")
    return 0


def cmd_clean(project_dir: Path) -> int:
    """Remove _deps/ and nim.cfg; keep milpa.lock.

    Workspace-aware: when invoked inside a workspace, removes
    <root>/_deps/ and each member's nim.cfg. Lockfile preserved.
    """
    ws = workspace_containing(project_dir)
    if ws is not None:
        deps_dir = ws.root / "_deps"
        if deps_dir.exists():
            shutil.rmtree(deps_dir)
        for member in ws.members:
            cfg = member.directory / "nim.cfg"
            if cfg.exists():
                cfg.unlink()
        return 0

    deps_dir = project_dir / "_deps"
    nim_cfg = project_dir / "nim.cfg"
    if deps_dir.exists():
        shutil.rmtree(deps_dir)
    if nim_cfg.exists():
        nim_cfg.unlink()
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _maybe_load_prior_lockfile(path: Path):
    """Load a prior lockfile if present; return None otherwise. Silently
    treat parse errors as 'no prior lockfile' — better to run unprotected
    than to refuse to resolve over a corrupt lockfile."""
    if not path.exists():
        return None
    try:
        return load_lockfile(path)
    except Exception:
        return None


def _resolve_or_error(
    project_dir: Path,
    *,
    fetcher: FetcherRegistry,
    list_tags: Callable[[str], list[str]],
    registry_loader: RegistryLoader,
    max_parallel: int = 8,
    strategy: Strategy = Strategy.MAXVER,
):
    """Load manifest + registry + resolve. Returns ResolvedGraph on
    success, exit code (int) on error."""
    try:
        manifest = load_or_discover_manifest(project_dir)
    except ManifestError as e:
        print(f"error reading manifest: {e}", file=sys.stderr)
        return 1
    deps_dir = project_dir / "_deps"
    deps_dir.mkdir(parents=True, exist_ok=True)
    cache_path = deps_dir / ".packages_official.json"
    try:
        registry = registry_loader(cache_path=cache_path)
    except Exception as e:
        print(f"failed to load registry: {e}", file=sys.stderr)
        return 1
    prior_lockfile = _maybe_load_prior_lockfile(project_dir / "milpa.lock")
    profile = Profile.from_environment()
    try:
        return resolve(
            manifest,
            deps_dir=deps_dir,
            registry=registry,
            fetcher=fetcher,
            list_tags=list_tags,
            max_parallel=max_parallel,
            strategy=strategy,
            prior_lockfile=prior_lockfile,
            profile=profile,
        )
    except Exception as e:
        print(f"resolution failed: {e}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# argparse dispatch
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    project_dir = Path(args.directory).resolve()
    strategy = Strategy(args.strategy)
    match args.command:
        case "fetch":
            return cmd_fetch(
                project_dir, max_parallel=args.parallel, strategy=strategy,
                frozen=args.frozen,
            )
        case "lock":
            return cmd_lock(
                project_dir, max_parallel=args.parallel, strategy=strategy,
            )
        case "show":   return cmd_show(project_dir)
        case "verify": return cmd_verify(project_dir)
        case "clean":  return cmd_clean(project_dir)
        case "remove":
            return cmd_remove(
                project_dir, name=args.dep_name, strategy=strategy,
            )
        case "update":
            return cmd_update(
                project_dir, name=args.dep_name, strategy=strategy,
                max_parallel=args.parallel,
            )
        case "add":
            if args.mirror:
                return cmd_add_mirror(
                    project_dir, url=args.mirror, dep_name=args.dep_name,
                    strategy=strategy,
                )
            if args.git:
                return cmd_add(
                    project_dir,
                    name=args.dep_name,
                    git=args.git,
                    ref=args.ref,
                    strategy=strategy,
                )
            print(
                "add: requires either --git <url> "
                "(brand-new dep) or --mirror <url> "
                "(extra provenance for existing dep)",
                file=sys.stderr,
            )
            return 1
        case "publish":
            return cmd_publish(
                project_dir,
                name=args.name,
                version=args.version,
                registry_ref=args.registry,
                provider=args.provider,
                repo_url=args.repo_url,
                signed_by=args.signed_by,
                dispatch_url=args.dispatch_url,
                oidc_token_env=args.oidc_token_env,
                dry_run=args.dry_run,
            )
        case _:
            print(f"unknown command: {args.command}", file=sys.stderr)
            return 1
