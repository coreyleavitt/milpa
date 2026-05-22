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
import shutil
import sys
from pathlib import Path
from collections.abc import Callable

from . import __version__
from .fetcher import FetchResult, fetch_url_dep
from .lockfile import (
    format_lockfile, from_graph, load_lockfile,
    verify_lockfile_against_deps, write_lockfile,
)
from .manifest import ManifestError, load_or_discover_manifest
from .nimcfg import write_nimcfg
from .registry import RegistryEntry, list_remote_tags, load_registry
from .solver import Strategy
from .resolver import resolve


SUBCOMMAND_HELP = {
    "fetch":  "resolve manifest, clone deps, emit nim.cfg, write lockfile",
    "lock":   "resolve manifest and write lockfile (no nim.cfg)",
    "show":   "print the resolved dep tree",
    "verify": "recheck each dep in _deps/ against milpa.lock (no fetch)",
    "clean":  "remove _deps/ and nim.cfg (keeps milpa.lock)",
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
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    for name, help_text in SUBCOMMAND_HELP.items():
        subparsers.add_parser(name, help=help_text)
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
    fetcher: Callable[..., FetchResult] = fetch_url_dep,
    list_tags: Callable[[str], list[str]] = list_remote_tags,
    registry_loader: RegistryLoader = _default_registry_loader,
    max_parallel: int = 8,
    strategy: Strategy = Strategy.MAXVER,
) -> int:
    """Resolve, fetch, emit nim.cfg + milpa.lock."""
    graph = _resolve_or_error(
        project_dir, fetcher=fetcher, list_tags=list_tags,
        registry_loader=registry_loader, max_parallel=max_parallel,
        strategy=strategy,
    )
    if isinstance(graph, int):
        return graph
    lockfile = from_graph(graph, strategy=str(strategy))
    write_lockfile(lockfile, project_dir / "milpa.lock")
    write_nimcfg(graph, project_root=project_dir)
    print(f"resolved {len(graph.deps)} deps", file=sys.stderr)
    return 0


def cmd_lock(
    project_dir: Path,
    *,
    fetcher: Callable[..., FetchResult] = fetch_url_dep,
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
        if dep.content_hash:
            print(f"  identity    sha256:{dep.content_hash[:8]}")
        provenance = dep.source
        if dep.ref:
            provenance += f" @ {dep.ref}"
        if dep.sha:
            provenance += f" (sha {dep.sha[:8]})"
        print(f"  provenance  {provenance}")
        if dep.requires:
            print(f"  requires    {', '.join(dep.requires)}")
    return 0


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
    print(f"verified {len(lockfile.deps)} deps", file=sys.stderr)
    return 0


def cmd_clean(project_dir: Path) -> int:
    """Remove _deps/ and nim.cfg; keep milpa.lock."""
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

def _resolve_or_error(
    project_dir: Path,
    *,
    fetcher: Callable[..., FetchResult],
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
    try:
        return resolve(
            manifest,
            deps_dir=deps_dir,
            registry=registry,
            fetcher=fetcher,
            list_tags=list_tags,
            max_parallel=max_parallel,
            strategy=strategy,
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
            )
        case "lock":
            return cmd_lock(
                project_dir, max_parallel=args.parallel, strategy=strategy,
            )
        case "show":   return cmd_show(project_dir)
        case "verify": return cmd_verify(project_dir)
        case "clean":  return cmd_clean(project_dir)
        case _:
            print(f"unknown command: {args.command}", file=sys.stderr)
            return 1
