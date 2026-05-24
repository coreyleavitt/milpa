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
from .fetchers import FetcherRegistry, default_registry
from .nimcfg import write_workspace_nimcfgs
from .lockfile import (
    format_lockfile, from_graph, load_lockfile,
    verify_lockfile_against_deps, verify_workspace_against_disk,
    write_lockfile,
)
from .frozen import NotFrozen, resolve_frozen
from .manifest import (
    LocalDep, ManifestError, MemberDep, NamedDep, TarballDep, UrlDep,
    load_or_discover_manifest,
)
from .manifest_writer import apply_manifest_change
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
        if name == "add":
            sp.add_argument(
                "--mirror", metavar="<url>",
                help="add <url> as a mirror provenance for <dep>",
            )
            sp.add_argument(
                "dep_name", metavar="<dep>",
                help="the lockfile-known dep name to attach the mirror to",
            )
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
            strategy=strategy,
        )

    frozen_result = _try_frozen(
        project_dir, fetcher=fetcher, strategy=strategy,
    )
    if isinstance(frozen_result, ResolvedGraph):
        write_nimcfg(frozen_result, project_root=project_dir)
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
    write_nimcfg(graph, project_root=project_dir)
    print(f"resolved {len(graph.deps)} deps", file=sys.stderr)
    return 0


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


def _cmd_fetch_workspace(
    ws,  # Workspace
    *,
    fetcher: FetcherRegistry,
    list_tags: Callable[[str], list[str]],
    registry_loader: RegistryLoader,
    max_parallel: int,
    strategy: Strategy,
) -> int:
    deps_dir = ws.root / "_deps"
    cache_path = deps_dir / ".packages_official.json"
    try:
        registry = registry_loader(cache_path=cache_path)
    except Exception as e:
        print(f"failed to load registry: {e}", file=sys.stderr)
        return 1
    try:
        graph = resolve_workspace(
            ws, deps_dir=deps_dir,
            registry=registry, fetcher=fetcher,
            list_tags=list_tags, max_parallel=max_parallel,
            strategy=strategy,
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


def cmd_add_mirror(
    project_dir: Path,
    *,
    url: str,
    dep_name: str,
    fetcher: FetcherRegistry = default_registry,
    relock: Callable[[Path], None] | None = None,
) -> int:
    """Append `url` as a mirror provenance for `dep_name` in the
    manifest (#37).

    Validates by fetching `url` and confirming its bytes hash to the
    identity locked for `dep_name`. On mismatch, returns 1 without
    mutating. On success, atomically appends `mirror "url"` to the
    UrlDep block and triggers `relock` (defaults to cmd_lock when
    None — see apply_manifest_change).
    """
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

    # Local + member deps don't have a meaningful "mirror" concept —
    # their bytes come from an editable source, not a fetchable one.
    from .lockfile import LocalProvenanceRecord, MemberProvenanceRecord
    if any(isinstance(p, (LocalProvenanceRecord, MemberProvenanceRecord))
           for p in locked.provenances):
        print(
            f"add --mirror: dep {dep_name!r} has a local/member "
            f"provenance — cannot add a mirror to an editable source",
            file=sys.stderr,
        )
        return 1

    # Validate: fetch the URL into a scratch dir and verify identity
    # matches the locked pin. apply_manifest_change runs this in the
    # `validate` phase so any failure aborts before mutation.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        scratch = Path(td) / dep_name

        def validate() -> None:
            from .fetchers.git import GitProvenance
            from .lockfile import GitProvenanceRecord
            # Get a reference ref from the existing git provenance (if any)
            ref = "main"
            for p in locked.provenances:
                if isinstance(p, GitProvenanceRecord) and p.ref:
                    ref = p.ref
                    break
            result = fetcher.fetch(
                dep_name, GitProvenance(url=url, ref=ref), dest=scratch,
            )
            if result.identity != locked.identity:
                raise ManifestError(
                    f"add --mirror: bytes at {url} hash to "
                    f"{result.identity[:23]}..., "
                    f"locked identity is {(locked.identity or '<none>')[:23]}... "
                    f"— mirrors must serve identical bytes"
                )

        def mutate(m: Manifest) -> Manifest:
            from dataclasses import replace
            new_deps = []
            for dep in m.deps:
                if isinstance(dep, UrlDep) and dep.name == dep_name:
                    if url in dep.mirrors:
                        # Idempotent: already present
                        new_deps.append(dep)
                    else:
                        new_deps.append(
                            replace(dep, mirrors=dep.mirrors + (url,)),
                        )
                else:
                    new_deps.append(dep)
            return replace(m, deps=tuple(new_deps))

        try:
            apply_manifest_change(
                project_dir,
                validate=validate, mutate=mutate, relock=relock,
            )
        except ManifestError as e:
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
                frozen=args.frozen,
            )
        case "lock":
            return cmd_lock(
                project_dir, max_parallel=args.parallel, strategy=strategy,
            )
        case "show":   return cmd_show(project_dir)
        case "verify": return cmd_verify(project_dir)
        case "clean":  return cmd_clean(project_dir)
        case "add":
            if not args.mirror:
                print(
                    "add: only --mirror is supported today; "
                    "general `milpa add` lands with #16",
                    file=sys.stderr,
                )
                return 1
            return cmd_add_mirror(
                project_dir, url=args.mirror, dep_name=args.dep_name,
                relock=lambda pd: cmd_lock(
                    pd, max_parallel=args.parallel, strategy=strategy,
                ),
            )
        case _:
            print(f"unknown command: {args.command}", file=sys.stderr)
            return 1
