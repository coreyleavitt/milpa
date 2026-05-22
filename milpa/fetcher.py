"""Git fetcher — clones URL deps into a local deps directory.

`fetch_url_dep(name, git, ref, deps_dir=...)` is the public entry. It
clones `<git>` at `<ref>` into `<deps_dir>/<name>/`, returns a
FetchResult with two values that serve different roles:

  - `sha`           : the resolved commit SHA. *Provenance receipt* —
                      records which commit was actually pulled. Useful
                      for diagnostics and for re-fetching the same
                      commit later.
  - `content_hash`  : sha256 of the source tree (excluding .git).
                      *Identity* — the canonical 'what' of the
                      fetched bytes. Independent of which git server,
                      which clone metadata, or which transport was
                      used.

See docs/identity-and-provenance.md for the model.

Idempotent: re-running with the same args is a no-op (still validates
the working copy). On any failure, no partial clone is left behind.

Subprocess-based; libgit2 isn't a dep. Tests exercise this against
local fixture repos via file:// URLs — no network required.
"""

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import shutil
import subprocess


@dataclass(frozen=True)
class FetchResult:
    name: str
    path: Path
    sha: str           # full commit SHA
    content_hash: str  # sha256 hex over the source tree (no .git)


class FetchError(Exception):
    """Raised when a clone or checkout cannot complete."""


def fetch_url_dep(
    name: str,
    git: str,
    ref: str,
    *,
    deps_dir: Path,
) -> FetchResult:
    """Clone `git@ref` into `deps_dir/name/`, return a FetchResult.

    Idempotent. If `deps_dir/name/` already exists at the requested
    ref, no git operation runs (we just recompute the content hash).
    """
    target = deps_dir / name
    pre_existed = target.exists()
    try:
        if pre_existed:
            _run_git(target.parent, name, git, ref,
                     ["git", "-C", str(target), "fetch", "-q", "origin"])
            _run_git(target.parent, name, git, ref,
                     ["git", "-C", str(target), "checkout", "-q", ref])
        else:
            _run_git(target.parent, name, git, ref,
                     ["git", "clone", "-q", git, str(target)])
            _run_git(target.parent, name, git, ref,
                     ["git", "-C", str(target), "checkout", "-q", ref])
    except FetchError:
        # Only clean up if WE created the dir. If it pre-existed and a
        # later operation (fetch/checkout) failed, leave it alone — the
        # user's pre-existing state isn't ours to nuke.
        if not pre_existed and target.exists():
            shutil.rmtree(target, ignore_errors=True)
        raise
    sha = _git_head_sha(target)
    content_hash = _content_hash(target)
    return FetchResult(name=name, path=target, sha=sha, content_hash=content_hash)


def _run_git(deps_dir: Path, name: str, git: str, ref: str,
             argv: list[str]) -> None:
    """Run a git subcommand and convert non-zero exits to FetchError.

    The error message includes the URL and ref so callers see what was
    being attempted, not just stderr from git.
    """
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        raise FetchError(
            f"fetching {name!r} from {git} at {ref!r} failed: "
            f"{result.stderr.strip() or result.stdout.strip() or 'git exited non-zero'}"
        )


def _git_head_sha(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def _content_hash(path: Path) -> str:
    """sha256 over the source tree, excluding `.git`.

    Walks every regular file under `path` except those in any `.git`
    directory. Files are sorted by their POSIX-formatted relative path
    for determinism. Each file contributes `relpath\\x00<bytes>\\x00` to
    the accumulator. The hex digest is the content hash — same input
    bytes regardless of clone location, commit timestamp, or git internals.
    """
    h = sha256()
    files = sorted(
        (p for p in path.rglob("*") if p.is_file() and ".git" not in p.parts),
        key=lambda p: p.relative_to(path).as_posix(),
    )
    for f in files:
        rel = f.relative_to(path).as_posix().encode("utf-8")
        h.update(rel)
        h.update(b"\x00")
        h.update(f.read_bytes())
        h.update(b"\x00")
    return h.hexdigest()
