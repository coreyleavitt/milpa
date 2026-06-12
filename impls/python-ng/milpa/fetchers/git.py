"""GitFetcher — subprocess git clone transport (slice 7d-1).

Handles ``GitProvenance(url, ref, commit_sha=None)``.

URL can be any scheme git understands (https://, ssh://, git://, file://,
or a bare filesystem path that git accepts directly).

On success the source tree is materialized under ``dest/`` and a
``GitReceipt`` carrying the resolved commit SHA is returned.  The receipt
records the transport artifact's own identifier (commit SHA) — never the
source-tree identity hash (forbidden per plugin-contract.md §3.1).

Error mapping:
  - git exits non-zero (clone/checkout/fetch)  → MilpaError(FETCH_GIT_FAILED)
  - commit_sha not found after exhaustive fetch → MilpaError(FETCH_GIT_COMMIT_ABSENT)

``cas_admissible = True`` (inherited default): all git provenances are
CAS-admissible; safety comes from the post-fetch identity gate in the
registry, not from restricting which git refs may be admitted
(plugin-contract.md §4 NORMATIVE rationale).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from milpa.errors import FETCH_GIT_COMMIT_ABSENT, FETCH_GIT_FAILED, MilpaError
from milpa.fetchers.types import Fetcher, Provenance, ProvenanceReceipt

# ---------------------------------------------------------------------------
# GitProvenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GitProvenance(Provenance):
    """Provenance descriptor for a git-backed source tree.

    ``url``        — any URL scheme git understands (https, ssh, git, file,
                     or bare filesystem path).
    ``ref``        — branch, tag, or HEAD; always recorded for provenance
                     and human debuggability.
    ``commit_sha`` — optional exact-commit pin.  When set the fetcher checks
                     out this SHA instead of the mutable ref tip; the ref is
                     kept for display/lockfile provenance only.

    ``cas_admissible = True`` (inherited from ``Provenance`` base):
    CAS admission safety is guaranteed by the post-fetch identity gate in the
    registry, not by restricting which refs may be admitted (§4 NORMATIVE).
    """

    url: str
    ref: str
    commit_sha: str | None = None


# ---------------------------------------------------------------------------
# GitReceipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GitReceipt(ProvenanceReceipt):
    """Transport receipt for a successful git fetch.

    ``commit_sha`` — the SHA of HEAD after clone/checkout.  This identifies
    the git object that was materialized, NOT the source-tree identity hash
    (plugin-contract.md §3.1 NORMATIVE: tree hashes are forbidden in receipts).
    """

    commit_sha: str

    def transport_fields(self) -> dict[str, str]:
        return {"commit_sha": self.commit_sha}


# ---------------------------------------------------------------------------
# GitFetcher
# ---------------------------------------------------------------------------


class GitFetcher(Fetcher):
    """Clone a git repository into ``dest/`` and return the commit SHA.

    Satisfies the three plugin-contract obligations (§1):
      1. Claim: ``can_handle`` returns ``True`` for ``GitProvenance`` only.
      2. Materialize: ``fetch`` runs ``git clone`` (+ optional ``git checkout``
         to pin an exact commit) and populates ``dest/``.
      3. Receipt: returns ``GitReceipt(commit_sha=<HEAD SHA>)``; the SHA
         identifies the transport artifact, not the materialized tree.

    Failure is signalled by raising ``MilpaError`` with a coded slug
    (plugin-contract.md §2 NORMATIVE).  Cleanup of ``dest`` is the
    registry's responsibility.
    """

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

        # --- clone --------------------------------------------------------
        _run_git(
            name,
            p,
            ["git", "clone", "-q", p.url, str(dest)],
        )

        # --- checkout / pin -----------------------------------------------
        if p.commit_sha is not None:
            # Exact-commit pin: ensure the commit is present then check it out.
            _ensure_commit_present(name, p, dest)
            _run_git(
                name,
                p,
                ["git", "-C", str(dest), "checkout", "-q", p.commit_sha],
            )
        else:
            # Mutable-ref tip: check out the declared ref.
            _run_git(
                name,
                p,
                ["git", "-C", str(dest), "checkout", "-q", p.ref],
            )

        return GitReceipt(commit_sha=_git_head_sha(dest))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run_git(name: str, p: GitProvenance, argv: list[str]) -> None:
    """Run a git subprocess; raise ``MilpaError(FETCH_GIT_FAILED)`` on non-zero exit."""
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        detail = stderr or stdout or "git exited non-zero"
        raise MilpaError(
            FETCH_GIT_FAILED,
            f"fetching {name!r} from {p.url!r} at {p.ref!r} failed: {detail}",
            dep=name,
            url=p.url,
            ref=p.ref,
        )


def _git_head_sha(dest: Path) -> str:
    """Return the current HEAD commit SHA in the repository at ``dest``."""
    return subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _ensure_commit_present(name: str, p: GitProvenance, dest: Path) -> None:
    """Ensure ``p.commit_sha`` is reachable in ``dest``.

    Strategy (mirrors the frozen impl's _ensure_commit_present):
      1. ``git cat-file -e <sha>^{commit}`` — cheap local check.
      2. Targeted ``git fetch origin <sha>`` — works when the server
         supports ``uploadpack.allowReachableSHA1InWant`` (GitHub / GitLab).
      3. Full history fetch (``--unshallow`` for shallow clones, then plain
         ``fetch``).
      4. Re-check; if still absent raise ``FETCH-GIT-COMMIT-ABSENT``.
    """
    assert p.commit_sha is not None

    # Step 1: cheap local presence check.
    have = subprocess.run(
        ["git", "-C", str(dest), "cat-file", "-e", f"{p.commit_sha}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    if have.returncode == 0:
        return

    # Step 2: targeted fetch (server-side reachable SHA support).
    targeted = subprocess.run(
        ["git", "-C", str(dest), "fetch", "-q", "origin", p.commit_sha],
        capture_output=True,
        text=True,
    )
    if targeted.returncode == 0:
        return

    # Step 3: full history fetch (handles shallow clones).
    subprocess.run(
        ["git", "-C", str(dest), "fetch", "-q", "--unshallow", "origin"],
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "-C", str(dest), "fetch", "-q", "origin"],
        capture_output=True,
        text=True,
    )

    # Step 4: re-check after full history fetch.
    recheck = subprocess.run(
        ["git", "-C", str(dest), "cat-file", "-e", f"{p.commit_sha}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    if recheck.returncode != 0:
        raise MilpaError(
            FETCH_GIT_COMMIT_ABSENT,
            f"commit {p.commit_sha!r} not found in {p.url!r} even after "
            f"full history fetch — the pin may be stale or the commit was "
            f"force-pushed away",
            dep=name,
            url=p.url,
            commit_sha=p.commit_sha,
        )
