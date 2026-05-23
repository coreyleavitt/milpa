"""GitFetcher — clone-based source tree delivery via git subprocess.

Handles `GitProvenance(url, ref)`. URL can be any scheme git understands
(https://, ssh://, git://, file://). Returns a GitReceipt with the
resolved commit SHA.

Idempotent: re-fetching the same provenance at the same dest is a
no-op beyond a `git fetch` + `git checkout`. On failure, leaves no
partial clone behind (only if WE created the dest dir — if it
pre-existed, the user's state is theirs).

Subprocess-based; libgit2 isn't a dep. Tests exercise this against
local fixture repos via file:// URLs.
"""

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess

from .types import FetchError, Provenance, ProvenanceReceipt


@dataclass(frozen=True)
class GitProvenance(Provenance):
    url: str
    ref: str


@dataclass(frozen=True)
class GitReceipt(ProvenanceReceipt):
    commit_sha: str


class GitFetcher:
    """Fetcher for GitProvenance — clones the URL at the ref into dest."""

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, GitProvenance)

    def fetch(
        self,
        name: str,
        p: Provenance,
        *,
        dest: Path,
    ) -> GitReceipt:
        assert isinstance(p, GitProvenance)
        pre_existed = dest.exists()
        try:
            if pre_existed:
                _run_git(name, p,
                         ["git", "-C", str(dest), "fetch", "-q", "origin"])
                _run_git(name, p,
                         ["git", "-C", str(dest), "checkout", "-q", p.ref])
            else:
                _run_git(name, p,
                         ["git", "clone", "-q", p.url, str(dest)])
                _run_git(name, p,
                         ["git", "-C", str(dest), "checkout", "-q", p.ref])
        except FetchError:
            if not pre_existed and dest.exists():
                shutil.rmtree(dest, ignore_errors=True)
            raise
        return GitReceipt(commit_sha=_git_head_sha(dest))


def _run_git(name: str, p: GitProvenance, argv: list[str]) -> None:
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        raise FetchError(
            f"fetching {name!r} from {p.url} at {p.ref!r} failed: "
            f"{result.stderr.strip() or result.stdout.strip() or 'git exited non-zero'}"
        )


def _git_head_sha(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
