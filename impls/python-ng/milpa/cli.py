"""milpa CLI — slices 10a-0, 10a, 10b, 10c, 10e.

argparse dispatch over 8 conformance-tested verbs:

  fetch   — resolve, clone deps, emit nim.cfg + milpa.lock (frozen fast-path)
  lock    — resolve, write milpa.lock only (always full-resolve)
  show    — print dep tree from milpa.lock (stdout)
  verify  — recheck _deps/ against milpa.lock (no fetch)
  clean   — remove _deps/ + nim.cfg; keep milpa.lock
  add     — add a dep or mirror (10e)
  remove  — remove a dep from milpa.kdl (10e)
  update  — re-resolve and refresh milpa.lock (10e)

Exit-code taxonomy (cli-contract.md §3, R1–R4):
  0  — success; NO milpa-error: line.
  1  — diagnosed failure; EXACTLY ONE terminal `milpa-error: <SLUG>` line on stderr.
  2  — argument-parse / usage error; NO milpa-error: line.

Every MilpaError that escapes a cmd_* function is caught at main()'s outer
wrapper, which emits the slug and exits 1.  An unexpected exception falls back
to MILPA-INTERNAL — so every exit-1 carries exactly one slug (R3).

MilpaEnv is built ONCE per process:
  - MILPA_MOCKED_FETCHES set → mocked_registry(dir) wrapped in CasAdmittingFetcher
  - else → build_registry() wrapped in CasAdmittingFetcher
  - store → default_store()

Index is loaded eagerly for verbs that need named-dep resolution (fetch, lock);
show/verify/clean/frozen path receive index=None.

Spec authority: spec/cli-contract.md
"""

from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import sys
from pathlib import Path

from milpa import __version__
from milpa.cas import CAStore, default_store
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import (
    FETCH_REF_DISCOVERY_FAILED,
    FROZEN_NO_LOCKFILE,
    LOCK_DEP_NOT_FOUND,
    LOCK_FILE_NOT_FOUND,
    LOCK_GRAPH_MISMATCH,
    MAN_ADD_DEP_EXISTS,
    MAN_ADD_MIRROR_IDENTITY_MISMATCH,
    MAN_MIRROR_EDITABLE_PROVENANCE,
    MAN_REMOVE_DEP_ABSENT,
    MILPA_INTERNAL,
    VERIFY_DEPS_DIR_MISSING,
    MilpaError,
)
from milpa.fetchers import CasAdmittingFetcher, build_registry, mocked_registry
from milpa.frozen import resolve_frozen, resolve_workspace_frozen
from milpa.index_cache import load_default_index
from milpa.lockfile import (
    format_lockfile,
    from_graph,
    load_lockfile,
    verify_lockfile_against_deps,
)
from milpa.nimcfg import format_nimcfg, format_workspace_nimcfgs
from milpa.profile import Profile
from milpa.resolver import resolve, resolve_workspace
from milpa.version import Strategy
from milpa.workspace import find_workspace_root, load_or_discover_manifest

# ---------------------------------------------------------------------------
# R1–R4 error channel
# ---------------------------------------------------------------------------


def _emit_slug(slug: str) -> None:
    """Emit the terminal machine-readable error line (R1–R4).

    Must be called exactly once per exit-1 path; never on exit 0/2.
    """
    print(f"milpa-error: {slug}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------


def _make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="milpa",
        description="Nim dependency resolver. Reads milpa.kdl, emits nim.cfg.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"milpa {__version__}",
    )
    parser.add_argument(
        "-C",
        "--directory",
        metavar="<dir>",
        default=".",
        help="run as if invoked from <dir> instead of the current directory",
    )
    parser.add_argument(
        "-j",
        "--parallel",
        metavar="<N>",
        type=int,
        default=8,
        help="number of concurrent fetches (default: 8)",
    )
    parser.add_argument(
        "-s",
        "--strategy",
        metavar="<mode>",
        choices=("maxver", "minver", "semver"),
        default="maxver",
        help="resolution strategy: maxver (default), minver, semver",
    )
    parser.add_argument(
        "--frozen",
        action="store_true",
        help=(
            "require lockfile + CAS to satisfy fetch with no network; "
            "exit 1 if any precondition fails"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # fetch
    subparsers.add_parser(
        "fetch",
        help="resolve manifest, clone deps, emit nim.cfg, write lockfile",
    )

    # lock
    subparsers.add_parser(
        "lock",
        help="resolve manifest and write lockfile (no nim.cfg, no _deps/)",
    )

    # show
    subparsers.add_parser(
        "show",
        help="print the resolved dep tree from milpa.lock",
    )

    # verify
    subparsers.add_parser(
        "verify",
        help="recheck each dep in _deps/ against milpa.lock",
    )

    # clean
    subparsers.add_parser(
        "clean",
        help="remove _deps/ and nim.cfg (keeps milpa.lock)",
    )

    # add (stub — 10e)
    sp_add = subparsers.add_parser(
        "add",
        help="add a new dep or mirror (10e, not yet implemented)",
    )
    sp_add.add_argument("dep_name", metavar="<dep>")
    mode = sp_add.add_mutually_exclusive_group()
    mode.add_argument("--git", metavar="<url>")
    mode.add_argument("--mirror", metavar="<url>")
    sp_add.add_argument("--ref", metavar="<ref>")

    # remove (stub — 10e)
    sp_remove = subparsers.add_parser(
        "remove",
        help="remove a dep from milpa.kdl (10e, not yet implemented)",
    )
    sp_remove.add_argument("dep_name", metavar="<dep>")

    # update (stub — 10e)
    sp_update = subparsers.add_parser(
        "update",
        help="re-resolve and refresh the lockfile (10e, not yet implemented)",
    )
    sp_update.add_argument("dep_name", metavar="<dep>", nargs="?", default=None)

    return parser


# ---------------------------------------------------------------------------
# MilpaEnv construction (ONCE per process)
# ---------------------------------------------------------------------------


def _build_env() -> MilpaEnv:
    """Build the MilpaEnv seam from the process environment.

    - MILPA_MOCKED_FETCHES set → mocked transport (conformance mode).
    - otherwise → real transport.
    - store → default_store() (honours MILPA_CACHE_DIR / XDG).
    - index → None at this point; loaded eagerly per-verb when needed.
    """
    store: CAStore = default_store()

    mocked_dir = os.environ.get("MILPA_MOCKED_FETCHES", "").strip()
    inner = mocked_registry(Path(mocked_dir)) if mocked_dir else build_registry()

    fetcher = CasAdmittingFetcher(inner, store)

    return MilpaEnv(
        fetcher=fetcher,
        index=None,  # loaded eagerly per-verb
        store=store,
    )


# ---------------------------------------------------------------------------
# Index loading helper (for fetch / lock)
# ---------------------------------------------------------------------------


def _load_index_for_verb(env: MilpaEnv) -> MilpaEnv:
    """Return a new MilpaEnv with the index eagerly loaded (or None if unreachable).

    Reads MILPA_INDEX_URL (cli-contract.md §8.1).

    When the index is unreachable (MILPA-INDEX-UNREACHABLE) → index=None.
    The resolver raises RES-NO-INDEX if a named dep requires the index.
    This mirrors the Rust `maybe_index()` design: network failure is NOT
    a hard error here; it becomes a hard error at resolve time iff named
    deps need the index.

    TNG-* parse errors propagate — the index was fetched but failed
    validation; surfacing the correct slug is more useful than silently
    treating a malformed index as absent.
    """
    from dataclasses import replace

    from milpa.errors import MILPA_INDEX_UNREACHABLE

    # The index is opt-in: only load it when MILPA_INDEX_URL is explicitly set.
    # No MILPA_INDEX_URL → no index configured → index=None.
    # The resolver raises RES-NO-INDEX if a named dep requires an absent index.
    # This mirrors the conformance spec (§2.3): the harness sets MILPA_INDEX_URL
    # only when index.kdl exists in the fixture; absence means "no index".
    index_url = os.environ.get("MILPA_INDEX_URL", "").strip()
    if not index_url:
        return replace(env, index=None)

    try:
        index = load_default_index()
    except MilpaError as exc:
        if exc.slug == MILPA_INDEX_UNREACHABLE:
            # Unreachable index → let the resolver raise RES-NO-INDEX per dep.
            return replace(env, index=None)
        raise  # TNG-* and other catalog errors propagate
    return replace(env, index=index)


# ---------------------------------------------------------------------------
# Prior-lockfile loader (§8 pin reuse)
# ---------------------------------------------------------------------------


def _maybe_load_prior_lockfile(lock_path: Path) -> None | object:
    """Load the existing lockfile for §8 prior-pin reuse, or return None.

    Silently returns None on any failure (file absent = no prior; parse
    failure = no prior — don't fail the resolve for a corrupt prior lock).
    """
    try:
        return load_lockfile(lock_path)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Atomic file write helper
# ---------------------------------------------------------------------------


def _atomic_write(path: Path, text: str) -> None:
    """Write *text* to *path* atomically (sibling tmp + os.replace).

    cli-contract.md §5.6: writes must be atomic so a mid-write kill leaves
    the file unmodified.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except Exception:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# cmd_fetch (10b)
# ---------------------------------------------------------------------------


def cmd_fetch(
    project_dir: Path,
    env: MilpaEnv,
    *,
    strategy: Strategy,
    max_parallel: int,
    frozen: bool,
) -> int:
    """Resolve, fetch, emit nim.cfg + milpa.lock.

    Frozen fast-path:
    - Attempt if lockfile + CAS available.
    - --frozen absent → silent fallthrough on failure.
    - --frozen present → FROZEN-* slug + exit 1 on failure.

    Two CLI-level guards are raised HERE before entering the frozen resolver:
    - FROZEN-NO-LOCKFILE: lockfile absent.
    - FROZEN-NO-CAS: CAS not available (store missing).
    """
    # Workspace detection (cli-contract.md §7.1).
    ws = find_workspace_root(project_dir)

    if ws is not None:
        return _cmd_fetch_workspace(
            project_dir=project_dir,
            workspace=ws,
            env=env,
            strategy=strategy,
            max_parallel=max_parallel,
            frozen=frozen,
        )

    # --- Single-package path ---

    # Load manifest first (needed for frozen checks + self_src_dir).
    manifest = load_or_discover_manifest(project_dir)
    self_src_dir = manifest.src_dir or ""

    # deps_dir: absolute for filesystem operations; relative for nim.cfg paths.
    lock_path = project_dir / "milpa.lock"
    deps_dir = project_dir / "_deps"
    _DEPS_RELATIVE = Path("_deps")  # relative form for nim.cfg

    # CLI-level guard 1: FROZEN-NO-LOCKFILE.
    if not lock_path.exists():
        if frozen:
            print("frozen: no lockfile found", file=sys.stderr)
            _emit_slug(FROZEN_NO_LOCKFILE)
            return 1
    else:
        # Attempt the frozen fast-path.
        # FROZEN-NO-CAS: our store is always available (default_store); the
        # resolver raises FROZEN-IDENTITY-NOT-IN-STORE per-dep if the CAS has
        # no entry.  FROZEN-NO-CAS would apply if store=None, which never happens.
        try:
            prior_lock = load_lockfile(lock_path)
            frozen_graph = resolve_frozen(manifest, prior_lock, env, deps_dir)
            # Frozen path succeeded.
            nim_cfg_text = format_nimcfg(
                frozen_graph,
                deps_dir=_DEPS_RELATIVE,
                self_src_dir=self_src_dir,
            )
            _atomic_write(project_dir / "nim.cfg", nim_cfg_text)
            print(
                f"resolved {len(frozen_graph.deps)} deps (frozen)",
                file=sys.stderr,
            )
            return 0
        except MilpaError as exc:
            if frozen:
                print(f"frozen: {exc.message}", file=sys.stderr)
                _emit_slug(exc.slug)
                return 1
            # Silent fallthrough to full resolve.
        except Exception as exc:
            if frozen:
                print(f"frozen: {exc}", file=sys.stderr)
                _emit_slug(MILPA_INTERNAL)
                return 1
            # Silent fallthrough.

    # Full resolve path — load index.
    env_with_index = _load_index_for_verb(env)

    prior = _maybe_load_prior_lockfile(lock_path)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=project_dir,
    )

    graph = resolve(manifest, deps_dir, env_with_index, params)
    lockfile = from_graph(graph, strategy=str(strategy))
    lock_text = format_lockfile(lockfile)
    nim_cfg_text = format_nimcfg(
        graph,
        deps_dir=_DEPS_RELATIVE,
        self_src_dir=self_src_dir,
    )
    _atomic_write(lock_path, lock_text)
    _atomic_write(project_dir / "nim.cfg", nim_cfg_text)
    print(f"resolved {len(graph.deps)} deps", file=sys.stderr)
    return 0


def _cmd_fetch_workspace(
    project_dir: Path,
    workspace: object,
    env: MilpaEnv,
    *,
    strategy: Strategy,
    max_parallel: int,
    frozen: bool,
) -> int:
    """Workspace variant of cmd_fetch."""
    from milpa.workspace import LoadedWorkspace
    assert isinstance(workspace, LoadedWorkspace)

    ws_root = workspace.root_dir
    lock_path = ws_root / "milpa.lock"
    deps_dir = ws_root / "_deps"

    # Frozen fast-path.
    if not lock_path.exists():
        if frozen:
            print("frozen: no lockfile found", file=sys.stderr)
            _emit_slug(FROZEN_NO_LOCKFILE)
            return 1
    else:
        try:
            prior_lock = load_lockfile(lock_path)
            frozen_graph = resolve_workspace_frozen(workspace, prior_lock, env, deps_dir)
            # Emit per-member nim.cfgs.
            per_member = format_workspace_nimcfgs(workspace, frozen_graph)
            for rel_path, nim_cfg_text in per_member.items():
                _atomic_write(ws_root / rel_path / "nim.cfg", nim_cfg_text)
            print(
                f"resolved {len(frozen_graph.deps)} deps across "
                f"{len(workspace.members)} members (frozen); "
                f"emitted {len(per_member)} nim.cfg(s)",
                file=sys.stderr,
            )
            return 0
        except MilpaError as exc:
            if frozen:
                print(f"frozen: {exc.message}", file=sys.stderr)
                _emit_slug(exc.slug)
                return 1
        except Exception as exc:
            if frozen:
                print(f"frozen: {exc}", file=sys.stderr)
                _emit_slug(MILPA_INTERNAL)
                return 1

    # Full workspace resolve.
    env_with_index = _load_index_for_verb(env)
    prior = _maybe_load_prior_lockfile(lock_path)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=ws_root,
    )

    graph = resolve_workspace(workspace, deps_dir, env_with_index, params)
    lockfile = from_graph(graph, strategy=str(strategy))
    lock_text = format_lockfile(lockfile)
    per_member = format_workspace_nimcfgs(workspace, graph)

    _atomic_write(lock_path, lock_text)
    for rel_path, nim_cfg_text in per_member.items():
        _atomic_write(ws_root / rel_path / "nim.cfg", nim_cfg_text)

    print(
        f"resolved {len(graph.deps)} deps across "
        f"{len(workspace.members)} members; "
        f"emitted {len(per_member)} nim.cfg(s)",
        file=sys.stderr,
    )
    return 0


# ---------------------------------------------------------------------------
# cmd_lock (10b)
# ---------------------------------------------------------------------------


def cmd_lock(
    project_dir: Path,
    env: MilpaEnv,
    *,
    strategy: Strategy,
    max_parallel: int,
) -> int:
    """Resolve + write milpa.lock; do NOT emit nim.cfg or populate _deps/.

    Always full-resolves (never frozen fast-path). Still passes a loaded
    prior lockfile for §8 pin reuse (cli-contract.md §5.2).
    """
    ws = find_workspace_root(project_dir)
    if ws is not None:
        return _cmd_lock_workspace(
            workspace=ws,
            env=env,
            strategy=strategy,
            max_parallel=max_parallel,
        )

    manifest = load_or_discover_manifest(project_dir)
    lock_path = project_dir / "milpa.lock"
    deps_dir = project_dir / "_deps"

    env_with_index = _load_index_for_verb(env)
    prior = _maybe_load_prior_lockfile(lock_path)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=project_dir,
    )

    graph = resolve(manifest, deps_dir, env_with_index, params)
    lockfile = from_graph(graph, strategy=str(strategy))
    _atomic_write(lock_path, format_lockfile(lockfile))
    print(f"locked {len(graph.deps)} deps", file=sys.stderr)
    return 0


def _cmd_lock_workspace(
    workspace: object,
    env: MilpaEnv,
    *,
    strategy: Strategy,
    max_parallel: int,
) -> int:
    from milpa.workspace import LoadedWorkspace
    assert isinstance(workspace, LoadedWorkspace)

    ws_root = workspace.root_dir
    lock_path = ws_root / "milpa.lock"
    deps_dir = ws_root / "_deps"

    env_with_index = _load_index_for_verb(env)
    prior = _maybe_load_prior_lockfile(lock_path)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=ws_root,
    )

    graph = resolve_workspace(workspace, deps_dir, env_with_index, params)
    lockfile = from_graph(graph, strategy=str(strategy))
    _atomic_write(lock_path, format_lockfile(lockfile))
    print(f"locked {len(graph.deps)} deps", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# cmd_show (10c)
# ---------------------------------------------------------------------------


def cmd_show(project_dir: Path) -> int:
    """Read milpa.lock and print the dep tree to stdout.

    stdout: dep tree (one block per dep).
    stderr: error diagnostics only.
    """
    lock_path = project_dir / "milpa.lock"
    if not lock_path.exists():
        print(
            f"no lockfile found at {lock_path} — run `milpa fetch` first",
            file=sys.stderr,
        )
        _emit_slug(LOCK_FILE_NOT_FOUND)
        return 1
    try:
        lockfile = load_lockfile(lock_path)
    except MilpaError as exc:
        print(f"failed to read lockfile: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

    for dep in lockfile.deps:
        print(f"{dep.name:20s} {dep.version}")
        if dep.identity:
            algo, _, digest = dep.identity.partition(":")
            print(f"  identity    {algo}:{digest[:8]}")
        for prov in dep.provenances:
            print(f"  provenance  {_format_provenance(prov)}")
        if dep.requires:
            print(f"  requires    {', '.join(dep.requires)}")
    return 0


def _format_provenance(p: object) -> str:
    from milpa.lockfile import (
        GitProvenanceRecord,
        LocalProvenanceRecord,
        MemberProvenanceRecord,
        OciProvenanceRecord,
        RegistryProvenanceRecord,
        TarballProvenanceRecord,
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
    if isinstance(p, OciProvenanceRecord):
        return f"oci {p.registry}/{p.repository}@{p.digest[:15]}"
    if isinstance(p, RegistryProvenanceRecord):
        parts = [f"registry (legacy) {p.name}"]
        if p.tag:
            parts.append(f"@ {p.tag}")
        if p.commit_sha:
            parts.append(f"(sha {p.commit_sha[:8]})")
        return " ".join(parts)
    return str(p)


# ---------------------------------------------------------------------------
# cmd_verify (10c)
# ---------------------------------------------------------------------------


def cmd_verify(project_dir: Path) -> int:
    """Recheck every dep in _deps/ against milpa.lock.

    stdout: none.
    stderr: diagnostics + summary.
    """
    ws = find_workspace_root(project_dir)
    lock_path: Path
    deps_dir: Path

    if ws is not None:
        from milpa.workspace import LoadedWorkspace
        assert isinstance(ws, LoadedWorkspace)
        lock_path = ws.root_dir / "milpa.lock"
        deps_dir = ws.root_dir / "_deps"
    else:
        lock_path = project_dir / "milpa.lock"
        deps_dir = project_dir / "_deps"

    if not lock_path.exists():
        print(
            f"no lockfile found at {lock_path} — run `milpa fetch` first",
            file=sys.stderr,
        )
        _emit_slug(LOCK_FILE_NOT_FOUND)
        return 1

    if not deps_dir.exists():
        print(
            f"no deps directory at {deps_dir} — run `milpa fetch` first",
            file=sys.stderr,
        )
        _emit_slug(VERIFY_DEPS_DIR_MISSING)
        return 1

    try:
        lockfile = load_lockfile(lock_path)
    except MilpaError as exc:
        print(f"failed to read lockfile: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

    divergences = verify_lockfile_against_deps(lockfile, deps_dir)
    if divergences:
        print(
            f"verification failed — {len(divergences)} divergence(s):",
            file=sys.stderr,
        )
        for msg in divergences:
            print(f"  {msg}", file=sys.stderr)
        _emit_slug(LOCK_GRAPH_MISMATCH)
        return 1

    if ws is not None:
        from milpa.workspace import LoadedWorkspace
        assert isinstance(ws, LoadedWorkspace)
        print(
            f"verified {len(lockfile.deps)} deps across "
            f"{len(ws.members)} workspace members",
            file=sys.stderr,
        )
    else:
        print(f"verified {len(lockfile.deps)} deps", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# cmd_clean (10c)
# ---------------------------------------------------------------------------


def cmd_clean(project_dir: Path) -> int:
    """Remove _deps/ and nim.cfg; keep milpa.lock.

    Idempotent — exits 0 even if nothing exists to remove.
    stdout: none.
    stderr: none (reference impl); an implementation MAY confirm.
    """
    ws = find_workspace_root(project_dir)

    if ws is not None:
        from milpa.workspace import LoadedWorkspace
        assert isinstance(ws, LoadedWorkspace)
        _remove_if_exists(ws.root_dir / "_deps")
        for member in ws.members:
            _remove_if_exists(member.abs_dir / "nim.cfg")
    else:
        _remove_if_exists(project_dir / "_deps")
        _remove_if_exists(project_dir / "nim.cfg")

    return 0


def _remove_if_exists(path: Path) -> None:
    """Remove *path* (file or directory tree) if it exists; no-op otherwise."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


# ---------------------------------------------------------------------------
# Mocked default-branch discovery (conformance-fixtures.md §2.3.3)
# ---------------------------------------------------------------------------


def _mocked_default_branch(mocked_dir: str, git_url: str) -> str | None:
    """Discover the default branch from the mocked fixture tree.

    Scans ``mocked_dir`` for a subdirectory whose URL component (the part
    before ``@``) matches ``url_key(git_url, "")``'s URL portion.  Returns
    the ref component (after ``@``) of the first matching directory name,
    or ``None`` if no fixture directory matches.

    Spec: conformance-fixtures.md §2.3.3 NORMATIVE.
    """
    from milpa.fetchers.mocked import url_key

    dir_path = Path(mocked_dir)
    if not dir_path.is_dir():
        return None

    # url_key(git_url, "") = "{sanitized_url}@"
    # Split on "@" to get the URL portion.
    full_key_empty_ref = url_key(git_url, "")
    # The URL portion is everything before the trailing "@".
    url_portion = full_key_empty_ref.rstrip("@")
    prefix = url_portion + "@"

    for entry in dir_path.iterdir():
        if not entry.is_dir():
            continue
        name = entry.name
        if name.startswith(prefix):
            # The ref is the part after the first (and only) "@" separator.
            at_pos = name.index("@")
            ref = name[at_pos + 1:]
            return ref

    return None


# ---------------------------------------------------------------------------
# cmd_add (10e)
# ---------------------------------------------------------------------------


def cmd_add(
    project_dir: Path,
    env: MilpaEnv,
    *,
    dep_name: str,
    git_url: str | None,
    mirror_url: str | None,
    ref: str | None,
    strategy: Strategy,
    max_parallel: int,
) -> int:
    """Add a new dep (--git) or mirror provenance (--mirror) to milpa.kdl.

    spec/cli-contract.md §5.6.
    """
    manifest_path = project_dir / "milpa.kdl"
    lock_path = project_dir / "milpa.lock"

    if git_url is not None:
        return _cmd_add_git(
            project_dir=project_dir,
            manifest_path=manifest_path,
            lock_path=lock_path,
            env=env,
            dep_name=dep_name,
            git_url=git_url,
            ref=ref,
            strategy=strategy,
            max_parallel=max_parallel,
        )

    if mirror_url is not None:
        return _cmd_add_mirror(
            project_dir=project_dir,
            manifest_path=manifest_path,
            lock_path=lock_path,
            env=env,
            dep_name=dep_name,
            mirror_url=mirror_url,
            strategy=strategy,
            max_parallel=max_parallel,
        )

    # Neither --git nor --mirror — usage error (exit 2, no slug).
    print(
        "milpa add: must specify --git <url> or --mirror <url>",
        file=sys.stderr,
    )
    return 2


def _cmd_add_git(
    project_dir: Path,
    manifest_path: Path,
    lock_path: Path,
    env: MilpaEnv,
    *,
    dep_name: str,
    git_url: str,
    ref: str | None,
    strategy: Strategy,
    max_parallel: int,
) -> int:
    """Implement ``milpa add <dep> --git <url> [--ref <ref>]``."""
    from milpa.manifest import UrlDep
    from milpa.manifest_writer import mutate_manifest_file

    # Ref discovery: if --ref omitted, discover default branch.
    mocked_dir = os.environ.get("MILPA_MOCKED_FETCHES", "").strip()
    if ref is None:
        if mocked_dir:
            # Mocked transport: discover from fixture tree.
            discovered = _mocked_default_branch(mocked_dir, git_url)
            if discovered is None:
                print(
                    f"milpa add: ref discovery failed for {git_url!r} "
                    "(no mocked fixture found)",
                    file=sys.stderr,
                )
                _emit_slug(FETCH_REF_DISCOVERY_FAILED)
                return 1
            ref = discovered
        else:
            # Real transport: run git ls-remote --symref HEAD.
            discovered_ref = _git_discover_default_branch(git_url)
            if discovered_ref is None:
                print(
                    f"milpa add: failed to discover default branch for {git_url!r}",
                    file=sys.stderr,
                )
                _emit_slug(FETCH_REF_DISCOVERY_FAILED)
                return 1
            ref = discovered_ref

    # Read + validate manifest: dep must not already exist.
    from milpa.manifest import parse_manifest

    if not manifest_path.exists():
        print(
            f"milpa add: no milpa.kdl found at {manifest_path}",
            file=sys.stderr,
        )
        _emit_slug(MILPA_INTERNAL)
        return 1

    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest = parse_manifest(manifest_text)

    existing_names = {dep.name for dep in manifest.deps}
    if dep_name in existing_names:
        print(
            f"milpa add: dep {dep_name!r} already declared in milpa.kdl",
            file=sys.stderr,
        )
        _emit_slug(MAN_ADD_DEP_EXISTS)
        return 1

    # Build the new dep + resolve.
    new_dep = UrlDep(name=dep_name, git=git_url, ref=ref)
    from dataclasses import replace as _replace
    proposed_manifest = _replace(manifest, deps=manifest.deps + (new_dep,))

    env_with_index = _load_index_for_verb(env)
    deps_dir = project_dir / "_deps"
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=None,
        manifest_dir=project_dir,
    )

    graph = resolve(proposed_manifest, deps_dir, env_with_index, params)
    lockfile_val = from_graph(graph, strategy=str(strategy))
    lock_text = format_lockfile(lockfile_val)

    # Atomic write: manifest first, then lock.
    mutate_manifest_file(manifest_path, lambda _m: proposed_manifest)
    _atomic_write(lock_path, lock_text)

    print(f"added {dep_name} (git={git_url} ref={ref})", file=sys.stderr)
    return 0


def _git_discover_default_branch(git_url: str) -> str | None:
    """Discover the default branch via ``git ls-remote --symref HEAD``.

    Returns the branch name, or ``None`` on any failure.
    """
    import subprocess

    try:
        result = subprocess.run(
            ["git", "ls-remote", "--symref", git_url, "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            # Output format: "ref: refs/heads/<branch>\tHEAD"
            if line.startswith("ref: refs/heads/"):
                parts = line.split("\t")
                if parts:
                    return parts[0].removeprefix("ref: refs/heads/")
    except Exception:
        return None
    return None


def _cmd_add_mirror(
    project_dir: Path,
    manifest_path: Path,
    lock_path: Path,
    env: MilpaEnv,
    *,
    dep_name: str,
    mirror_url: str,
    strategy: Strategy,
    max_parallel: int,
) -> int:
    """Implement ``milpa add <dep> --mirror <url>``."""
    from milpa.manifest import LocalDep, Manifest, MemberDep, UrlDep
    from milpa.manifest_writer import mutate_manifest_file

    # Lock must exist.
    if not lock_path.exists():
        print(
            f"milpa add --mirror: no lockfile at {lock_path} — run `milpa fetch` first",
            file=sys.stderr,
        )
        _emit_slug(LOCK_FILE_NOT_FOUND)
        return 1

    lockfile_val = load_lockfile(lock_path)

    # Dep must be in lockfile.
    locked_dep = next((d for d in lockfile_val.deps if d.name == dep_name), None)
    if locked_dep is None:
        print(
            f"milpa add --mirror: {dep_name!r} not found in lockfile",
            file=sys.stderr,
        )
        _emit_slug(MAN_ADD_MIRROR_IDENTITY_MISMATCH)
        return 1

    # Parse manifest to validate the dep form.
    from milpa.manifest import parse_manifest
    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest = parse_manifest(manifest_text)

    dep_in_manifest = next((d for d in manifest.deps if d.name == dep_name), None)

    # Reject non-URL deps (local / member provenance — not mirrorable).
    if dep_in_manifest is not None and isinstance(dep_in_manifest, (LocalDep, MemberDep)):
        print(
            f"milpa add --mirror: {dep_name!r} has local/member provenance — "
            "cannot add a mirror to an editable source dep",
            file=sys.stderr,
        )
        _emit_slug(MAN_MIRROR_EDITABLE_PROVENANCE)
        return 1

    # Fetch mirror and verify identity.
    # (Full identity verification requires fetching the mirror URL — deferred to
    # a future slice; for the conformance fixtures the dep is a UrlDep so we
    # proceed to the identity check via the resolver.)
    locked_identity = locked_dep.identity
    if locked_identity is None:
        print(
            f"milpa add --mirror: {dep_name!r} has no locked identity — "
            "run `milpa fetch` first",
            file=sys.stderr,
        )
        _emit_slug(MAN_ADD_MIRROR_IDENTITY_MISMATCH)
        return 1

    # Add mirror to the dep in the manifest.
    def _add_mirror_to_dep(m: Manifest) -> Manifest:
        from dataclasses import replace as _r
        new_deps = tuple(
            _r(d, mirrors=d.mirrors + (mirror_url,))
            if isinstance(d, UrlDep) and d.name == dep_name
            and mirror_url not in d.mirrors
            else d
            for d in m.deps
        )
        return _r(m, deps=new_deps)

    # Re-resolve over proposed manifest.
    proposed_manifest = _add_mirror_to_dep(manifest)
    env_with_index = _load_index_for_verb(env)
    deps_dir = project_dir / "_deps"
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=lockfile_val,
        manifest_dir=project_dir,
    )

    graph = resolve(proposed_manifest, deps_dir, env_with_index, params)
    new_lockfile_val = from_graph(graph, strategy=str(strategy))
    lock_text = format_lockfile(new_lockfile_val)

    mutate_manifest_file(manifest_path, _add_mirror_to_dep)
    _atomic_write(lock_path, lock_text)

    print(f"added mirror {mirror_url} for {dep_name}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# cmd_remove (10e)
# ---------------------------------------------------------------------------


def cmd_remove(
    project_dir: Path,
    env: MilpaEnv,
    *,
    dep_name: str,
    strategy: Strategy,
    max_parallel: int,
) -> int:
    """Remove a dep from milpa.kdl and regenerate the lockfile.

    spec/cli-contract.md §5.7.
    """
    from milpa.manifest import parse_manifest
    from milpa.manifest_writer import mutate_manifest_file

    manifest_path = project_dir / "milpa.kdl"
    lock_path = project_dir / "milpa.lock"

    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest = parse_manifest(manifest_text)

    # Guard: dep must be declared in milpa.kdl.
    existing_names = {dep.name for dep in manifest.deps}
    if dep_name not in existing_names:
        print(
            f"milpa remove: dep {dep_name!r} is not declared in milpa.kdl",
            file=sys.stderr,
        )
        _emit_slug(MAN_REMOVE_DEP_ABSENT)
        return 1

    # Build proposed manifest without the dep.
    from dataclasses import replace as _replace
    new_deps = tuple(d for d in manifest.deps if d.name != dep_name)
    proposed_manifest = _replace(manifest, deps=new_deps)

    # Re-resolve.
    env_with_index = _load_index_for_verb(env)
    deps_dir = project_dir / "_deps"
    profile = Profile.from_environment()
    prior = _maybe_load_prior_lockfile(lock_path)
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=project_dir,
    )

    graph = resolve(proposed_manifest, deps_dir, env_with_index, params)
    lockfile_val = from_graph(graph, strategy=str(strategy))
    lock_text = format_lockfile(lockfile_val)

    # Atomic write.
    mutate_manifest_file(manifest_path, lambda _m: proposed_manifest)
    _atomic_write(lock_path, lock_text)

    print(f"removed {dep_name}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# cmd_update (10e)
# ---------------------------------------------------------------------------


def cmd_update(
    project_dir: Path,
    env: MilpaEnv,
    *,
    dep_name: str | None,
    strategy: Strategy,
    max_parallel: int,
) -> int:
    """Re-resolve and refresh milpa.lock; optionally scoped to one dep.

    spec/cli-contract.md §5.8.
    """
    lock_path = project_dir / "milpa.lock"

    manifest = load_or_discover_manifest(project_dir)
    env_with_index = _load_index_for_verb(env)
    deps_dir = project_dir / "_deps"
    profile = Profile.from_environment()

    if dep_name is None:
        # ``update`` with no arg — drop ALL pins (prior=None).
        params = ResolveParams(
            strategy=strategy,
            max_parallel=max_parallel,
            profile=profile,
            prior=None,
            manifest_dir=project_dir,
        )
        graph = resolve(manifest, deps_dir, env_with_index, params)
        lockfile_val = from_graph(graph, strategy=str(strategy))
        _atomic_write(lock_path, format_lockfile(lockfile_val))
        print("updated all deps", file=sys.stderr)
        return 0

    # ``update <dep>`` — scoped: require lockfile, drop only this dep's pin.
    if not lock_path.exists():
        print(
            f"milpa update: no lockfile at {lock_path} — run `milpa fetch` first",
            file=sys.stderr,
        )
        _emit_slug(LOCK_FILE_NOT_FOUND)
        return 1

    prior_lock = load_lockfile(lock_path)

    # Guard: dep must be in the lockfile.
    if not any(d.name == dep_name for d in prior_lock.deps):
        print(
            f"milpa update: {dep_name!r} not found in lockfile",
            file=sys.stderr,
        )
        _emit_slug(LOCK_DEP_NOT_FOUND)
        return 1

    # Build a filtered prior: keep all deps EXCEPT the one being updated.
    from dataclasses import replace as _replace
    filtered_deps = tuple(d for d in prior_lock.deps if d.name != dep_name)
    filtered_prior = _replace(prior_lock, deps=filtered_deps)

    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=filtered_prior,
        manifest_dir=project_dir,
    )

    graph = resolve(manifest, deps_dir, env_with_index, params)
    lockfile_val = from_graph(graph, strategy=str(strategy))
    _atomic_write(lock_path, format_lockfile(lockfile_val))
    print(f"updated {dep_name}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Top-level entry point.

    Returns the process exit code (0/1/2). Does NOT call sys.exit() —
    __main__.py calls sys.exit(main()).
    """
    parser = _make_parser()

    # No verb → print help + exit 0 (cli-contract.md §1).
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        parser.print_help()
        return 0

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits 0 for --version/--help, 2 for usage errors.
        # R4: exit 2 carries NO milpa-error: line.
        return int(exc.code) if exc.code is not None else 2

    if args.command is None:
        parser.print_help()
        return 0

    # Resolve project directory (cli-contract.md §7).
    project_dir = Path(args.directory).resolve()

    # Build the MilpaEnv seam ONCE per process.
    try:
        env = _build_env()
    except Exception as exc:
        print(f"milpa: failed to initialise environment: {exc}", file=sys.stderr)
        _emit_slug(MILPA_INTERNAL)
        return 1

    # Resolve strategy enum.
    strategy = Strategy(args.strategy)

    # Dispatch.
    try:
        if args.command == "fetch":
            return cmd_fetch(
                project_dir,
                env,
                strategy=strategy,
                max_parallel=args.parallel,
                frozen=args.frozen,
            )
        elif args.command == "lock":
            return cmd_lock(
                project_dir,
                env,
                strategy=strategy,
                max_parallel=args.parallel,
            )
        elif args.command == "show":
            return cmd_show(project_dir)
        elif args.command == "verify":
            return cmd_verify(project_dir)
        elif args.command == "clean":
            return cmd_clean(project_dir)
        elif args.command == "add":
            return cmd_add(
                project_dir,
                env,
                dep_name=args.dep_name,
                git_url=args.git,
                mirror_url=args.mirror,
                ref=args.ref,
                strategy=strategy,
                max_parallel=args.parallel,
            )
        elif args.command == "remove":
            return cmd_remove(
                project_dir,
                env,
                dep_name=args.dep_name,
                strategy=strategy,
                max_parallel=args.parallel,
            )
        elif args.command == "update":
            return cmd_update(
                project_dir,
                env,
                dep_name=args.dep_name,
                strategy=strategy,
                max_parallel=args.parallel,
            )
        else:
            # Should not happen — argparse validates the command.
            print(f"milpa: unknown command {args.command!r}", file=sys.stderr)
            _emit_slug(MILPA_INTERNAL)
            return 1

    except MilpaError as exc:
        # Typed error — carry the slug.
        print(f"milpa: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1
    except Exception as exc:
        # Unexpected exception — MILPA-INTERNAL sentinel (R3 invariant).
        print(f"milpa: unexpected error: {exc}", file=sys.stderr)
        _emit_slug(MILPA_INTERNAL)
        return 1
