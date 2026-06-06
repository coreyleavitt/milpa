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
    # Immutable commit pin (milpa#97). When set, GitFetcher checks out
    # this exact commit rather than the (mutable) `ref` tip — `ref` is
    # retained for provenance/debuggability. None preserves the legacy
    # tip-checkout behavior for every existing caller (additive default).
    commit_sha: str | None = None


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
            if not pre_existed:
                _run_git(name, p,
                         ["git", "clone", "-q", p.url, str(dest)])
            if p.commit_sha:
                # Exact-commit pin (Invariant 2): the index records an
                # immutable commit_sha which may NOT be the branch tip.
                # Ensure it's present (a plain clone of a small repo
                # usually has it), then check out that exact commit —
                # `ref` is recorded for provenance but never determines
                # the working tree here.
                _ensure_commit_present(name, p, dest)
                _run_git(name, p,
                         ["git", "-C", str(dest), "checkout", "-q",
                          p.commit_sha])
            else:
                # Legacy tip behavior: fetch latest then check out the ref.
                if pre_existed:
                    _run_git(name, p,
                             ["git", "-C", str(dest), "fetch", "-q", "origin"])
                _run_git(name, p,
                         ["git", "-C", str(dest), "checkout", "-q", p.ref])
        except FetchError:
            if not pre_existed and dest.exists():
                shutil.rmtree(dest, ignore_errors=True)
            raise
        return GitReceipt(commit_sha=_git_head_sha(dest))


def _ensure_commit_present(name: str, p: GitProvenance, dest: Path) -> None:
    """Make `p.commit_sha` available in `dest` so it can be checked out.

    A plain clone of a small repo usually already has every commit, so the
    cheap `cat-file -e` check short-circuits the common case. Otherwise try
    a targeted `git fetch origin <sha>` (needs the server's
    `uploadpack.allowReachableSHA1InWant`; GitHub/GitLab enable it). If the
    server rejects bare-SHA requests or the clone was shallow, fall back to
    a full history fetch (`--unshallow` when shallow, else a plain fetch).
    """
    have = subprocess.run(
        ["git", "-C", str(dest), "cat-file", "-e",
         f"{p.commit_sha}^{{commit}}"],
        capture_output=True, text=True,
    )
    if have.returncode == 0:
        return
    targeted = subprocess.run(
        ["git", "-C", str(dest), "fetch", "-q", "origin", p.commit_sha],
        capture_output=True, text=True,
    )
    if targeted.returncode == 0:
        return
    # Fallback: deepen/complete history. --unshallow errors on a complete
    # clone, so ignore its result and follow with a plain full fetch.
    subprocess.run(
        ["git", "-C", str(dest), "fetch", "-q", "--unshallow", "origin"],
        capture_output=True, text=True,
    )
    _run_git(name, p, ["git", "-C", str(dest), "fetch", "-q", "origin"])
    # L10: re-check after the full history fetch. If the commit is still
    # absent, raise a clear error rather than letting `git checkout` fail
    # with an opaque "fatal: unable to read tree" message.
    recheck = subprocess.run(
        ["git", "-C", str(dest), "cat-file", "-e",
         f"{p.commit_sha}^{{commit}}"],
        capture_output=True, text=True,
    )
    if recheck.returncode != 0:
        raise FetchError(
            f"commit {p.commit_sha!r} not found in {p.url!r} even after "
            f"full history fetch — the index pin may be stale or the commit "
            f"was force-pushed away"
        )


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
