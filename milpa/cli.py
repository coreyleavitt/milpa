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
from .lockfile import format_lockfile, from_graph, load_lockfile, write_lockfile
from .manifest import ManifestError, load_manifest
from .nimcfg import write_nimcfg
from .registry import list_remote_tags
from .resolver import resolve


SUBCOMMAND_HELP = {
    "fetch": "resolve manifest, clone deps, emit nim.cfg, write lockfile",
    "lock":  "resolve manifest and write lockfile (no nim.cfg)",
    "show":  "print the resolved dep tree",
    "clean": "remove _deps/ and nim.cfg (keeps milpa.lock)",
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
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    for name, help_text in SUBCOMMAND_HELP.items():
        subparsers.add_parser(name, help=help_text)
    return parser


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_fetch(
    project_dir: Path,
    *,
    fetcher: Callable[..., FetchResult] = fetch_url_dep,
    list_tags: Callable[[str], list[str]] = list_remote_tags,
) -> int:
    """Resolve, fetch, emit nim.cfg + milpa.lock."""
    graph = _resolve_or_error(project_dir, fetcher=fetcher, list_tags=list_tags)
    if isinstance(graph, int):
        return graph
    lockfile = from_graph(graph)
    write_lockfile(lockfile, project_dir / "milpa.lock")
    write_nimcfg(graph, project_root=project_dir)
    print(f"resolved {len(graph.deps)} deps", file=sys.stderr)
    return 0


def cmd_lock(
    project_dir: Path,
    *,
    fetcher: Callable[..., FetchResult] = fetch_url_dep,
    list_tags: Callable[[str], list[str]] = list_remote_tags,
) -> int:
    """Resolve + write milpa.lock; do not emit nim.cfg."""
    graph = _resolve_or_error(project_dir, fetcher=fetcher, list_tags=list_tags)
    if isinstance(graph, int):
        return graph
    lockfile = from_graph(graph)
    write_lockfile(lockfile, project_dir / "milpa.lock")
    print(f"locked {len(graph.deps)} deps", file=sys.stderr)
    return 0


def cmd_show(project_dir: Path) -> int:
    """Print the resolved dep tree from milpa.lock."""
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
        ref_str = f"@ {dep.ref}" if dep.ref else ""
        print(f"{dep.name:20s} {dep.version:10s} {dep.source} {ref_str}".rstrip())
        if dep.requires:
            print(f"  requires: {', '.join(dep.requires)}")
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
):
    """Load manifest + resolve. Returns ResolvedGraph on success, exit
    code (int) on error."""
    manifest_path = project_dir / "milpa.kdl"
    if not manifest_path.exists():
        print(
            f"no manifest found at {manifest_path}",
            file=sys.stderr,
        )
        return 1
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        print(f"error reading manifest: {e}", file=sys.stderr)
        return 1
    try:
        return resolve(
            manifest,
            deps_dir=project_dir / "_deps",
            registry={},
            fetcher=fetcher,
            list_tags=list_tags,
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
    match args.command:
        case "fetch": return cmd_fetch(project_dir)
        case "lock":  return cmd_lock(project_dir)
        case "show":  return cmd_show(project_dir)
        case "clean": return cmd_clean(project_dir)
        case _:
            print(f"unknown command: {args.command}", file=sys.stderr)
            return 1
