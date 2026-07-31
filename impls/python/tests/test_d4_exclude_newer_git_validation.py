"""D4 (resolution-semantics RFC §3 Axis D / §6 D-D1/D-D2 — #86): the
exclude-newer hard cut on git/url pinned-ref deps, applied as VALIDATION
(not selection — a git dep has exactly one candidate).

Two layers, both against a REAL local git repository (no mocking — the
resolver-semantics RFC's own H-infra convention, per ``test_conformance.py``'s
git-protocol tier and ``test_git_fetcher.py``):

  - Fetcher level (``TestGitReceiptCommitterDate``): proves
    ``GitFetcher.fetch`` reads the resolved commit's own COMMITTER date, never
    an annotated tag's TAGGER date, by building a repo where the two
    genuinely differ.
  - Resolver level (the rest): proves ``resolve()`` wires
    ``params.exclude_newer`` into that read and raises the new
    ``RES-EXCLUDE-NEWER-PIN`` slug exactly when the committer date exceeds the
    bound — including the anti-tagger-date guard end to end, the branch-ref
    case (D-D2: reproducible once fetched, since the resolver reuses the
    fetched commit), and the no-bound regression.
"""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import MilpaError, RES_EXCLUDE_NEWER_PIN
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.git import GitFetcher, GitProvenance
from milpa.fetchers.types import FetcherRegistry
from milpa.manifest import Manifest, UrlDep
from milpa.resolver import resolve

# ---------------------------------------------------------------------------
# Local git repo factory — a commit with a pinned committer date, plus an
# annotated tag on it whose TAGGER date is deliberately different (the
# anti-tagger-date guard fixture).
# ---------------------------------------------------------------------------

_COMMIT_DATE = datetime(2020, 1, 1, tzinfo=timezone.utc)
_TAG_DATE = datetime(2025, 6, 1, tzinfo=timezone.utc)  # far LATER than the commit


def _env_for(dt: datetime) -> dict:
    ts = f"{int(dt.timestamp())} +0000"
    return {
        **os.environ,
        "GIT_AUTHOR_NAME": "Milpa D4 Test",
        "GIT_AUTHOR_EMAIL": "milpa-d4@test.milpa",
        "GIT_AUTHOR_DATE": ts,
        "GIT_COMMITTER_NAME": "Milpa D4 Test",
        "GIT_COMMITTER_EMAIL": "milpa-d4@test.milpa",
        "GIT_COMMITTER_DATE": ts,
    }


def _make_repo_with_annotated_tag(tmp_path: Path, *, tag_name: str = "v1.0.0") -> tuple[Path, str]:
    """One commit dated ``_COMMIT_DATE``, tagged ``tag_name`` (annotated) with
    a TAGGER date of ``_TAG_DATE`` — the two are deliberately far apart so a
    test can distinguish "validated against the commit's date" from
    "validated against the tag's date" (the bug this slice guards against).

    Returns ``(repo_dir, commit_sha)``.
    """
    repo = tmp_path / "source_repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    (repo / "hello.txt").write_text("hello milpa\n")
    subprocess.run(["git", "-C", str(repo), "add", "hello.txt"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgSign=false", "commit", "-m", "initial commit"],
        check=True,
        capture_output=True,
        env=_env_for(_COMMIT_DATE),
    )
    sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    # Annotated tag, created with a DIFFERENT (later) env date — this becomes
    # the tag object's own "tagger" timestamp, distinct from the commit's
    # committer date above.
    subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgSign=false", "-c", "tag.gpgSign=false",
         "tag", "-a", tag_name, "-m", "release"],
        check=True,
        capture_output=True,
        env=_env_for(_TAG_DATE),
    )
    return repo, sha


def _file_url(repo: Path) -> str:
    return f"file://{repo.resolve()}"


def _real_env(tmp_path: Path) -> MilpaEnv:
    registry = FetcherRegistry()
    registry.register(GitFetcher())
    store = CAStore(tmp_path / "cas")
    return MilpaEnv(fetcher=CasAdmittingFetcher(registry, store), index=None, store=store)


def _root_manifest(url: str, ref: str) -> Manifest:
    # Built directly (not via parse_manifest/KDL text): the manifest-level
    # git-URL scheme guard (`_validate_git_url`, milpa/manifest.py) rejects
    # file:// at PARSE time (only https/http/ssh/git are declarable) — a
    # manifest-declaration concern orthogonal to what this slice tests (the
    # RESOLVER's exclude-newer validation). Constructing the parsed `UrlDep`
    # directly is the same bypass the shared git-protocol conformance tier
    # uses (it calls the fetcher registry directly, skipping manifest parse
    # entirely) — here we still want the real end-to-end `resolve()` pipeline,
    # just fed a file:// URL the way an already-parsed manifest object would
    # carry one.
    return Manifest(
        name="myapp",
        kind="application",
        deps=(UrlDep(name="foo", git=url, ref=ref),),
    )


def _resolve(root: Manifest, env: MilpaEnv, tmp_path: Path, *, exclude_newer=None):
    deps_dir = tmp_path / "_deps"
    deps_dir.mkdir(exist_ok=True)
    return resolve(root, deps_dir, env, ResolveParams(exclude_newer=exclude_newer))


# ---------------------------------------------------------------------------
# Fetcher level — GitReceipt.committer_date
# ---------------------------------------------------------------------------


class TestGitReceiptCommitterDate:
    def test_committer_date_is_the_commits_own_date_via_tag_ref(self, tmp_path: Path) -> None:
        """Fetching via an annotated TAG ref must still report the COMMIT's
        committer date, never the tag's own (later) tagger date."""
        repo, sha = _make_repo_with_annotated_tag(tmp_path)
        receipt = GitFetcher().fetch(
            "foo", GitProvenance(url=str(repo), ref="v1.0.0"), dest=tmp_path / "dest"
        )
        assert receipt.commit_sha == sha
        assert receipt.committer_date == _COMMIT_DATE
        assert receipt.committer_date != _TAG_DATE

    def test_committer_date_via_branch_ref(self, tmp_path: Path) -> None:
        repo, sha = _make_repo_with_annotated_tag(tmp_path)
        receipt = GitFetcher().fetch(
            "foo", GitProvenance(url=str(repo), ref="main"), dest=tmp_path / "dest"
        )
        assert receipt.commit_sha == sha
        assert receipt.committer_date == _COMMIT_DATE

    def test_committer_date_via_exact_commit_pin(self, tmp_path: Path) -> None:
        repo, sha = _make_repo_with_annotated_tag(tmp_path)
        receipt = GitFetcher().fetch(
            "foo",
            GitProvenance(url=str(repo), ref="main", commit_sha=sha),
            dest=tmp_path / "dest",
        )
        assert receipt.committer_date == _COMMIT_DATE


# ---------------------------------------------------------------------------
# Resolver level — RES-EXCLUDE-NEWER-PIN
# ---------------------------------------------------------------------------


class TestExcludeNewerGitValidation:
    def test_commit_predating_bound_via_tag_ref_resolves_cleanly(self, tmp_path: Path) -> None:
        repo, _sha = _make_repo_with_annotated_tag(tmp_path)
        env = _real_env(tmp_path)
        # Between the commit's date (2020-01-01) and the tag's tagger date
        # (2025-06-01) — passes ONLY if validation uses the commit's date.
        bound = datetime(2020, 6, 1, tzinfo=timezone.utc)
        graph = _resolve(
            _root_manifest(_file_url(repo), "v1.0.0"), env, tmp_path, exclude_newer=bound
        )
        assert graph.deps[0].name == "foo"

    def test_commit_predating_bound_via_branch_ref_resolves_cleanly(self, tmp_path: Path) -> None:
        repo, _sha = _make_repo_with_annotated_tag(tmp_path)
        env = _real_env(tmp_path)
        bound = datetime(2020, 6, 1, tzinfo=timezone.utc)
        graph = _resolve(
            _root_manifest(_file_url(repo), "main"), env, tmp_path, exclude_newer=bound
        )
        assert graph.deps[0].name == "foo"

    def test_tag_ref_with_tighter_bound_uses_commit_date_not_tagger_date(
        self, tmp_path: Path
    ) -> None:
        """THE anti-tagger-date guard, end to end: if validation incorrectly
        consulted the tag's tagger date (2025-06-01), this bound (2020-06-01,
        which predates the tagger date but postdates the commit's committer
        date of 2020-01-01) would be misjudged as satisfied. It must instead
        correctly report the commit's date and pass."""
        repo, _sha = _make_repo_with_annotated_tag(tmp_path)
        env = _real_env(tmp_path)
        bound = datetime(2020, 6, 1, tzinfo=timezone.utc)
        # Sanity: bound is BEFORE the tag's tagger date and AFTER the commit's
        # committer date — the two dates disagree on whether this should pass.
        assert _COMMIT_DATE < bound < _TAG_DATE
        graph = _resolve(
            _root_manifest(_file_url(repo), "v1.0.0"), env, tmp_path, exclude_newer=bound
        )
        assert graph.deps[0].name == "foo"

    def test_commit_newer_than_bound_via_tag_ref_hard_fails(self, tmp_path: Path) -> None:
        repo, sha = _make_repo_with_annotated_tag(tmp_path)
        env = _real_env(tmp_path)
        bound = datetime(2019, 1, 1, tzinfo=timezone.utc)  # before the commit's date
        with pytest.raises(MilpaError) as exc_info:
            _resolve(_root_manifest(_file_url(repo), "v1.0.0"), env, tmp_path, exclude_newer=bound)
        assert exc_info.value.slug == RES_EXCLUDE_NEWER_PIN
        assert "foo" in exc_info.value.message
        assert sha in exc_info.value.message

    def test_commit_newer_than_bound_via_branch_ref_hard_fails(self, tmp_path: Path) -> None:
        repo, _sha = _make_repo_with_annotated_tag(tmp_path)
        env = _real_env(tmp_path)
        bound = datetime(2019, 1, 1, tzinfo=timezone.utc)
        with pytest.raises(MilpaError) as exc_info:
            _resolve(_root_manifest(_file_url(repo), "main"), env, tmp_path, exclude_newer=bound)
        assert exc_info.value.slug == RES_EXCLUDE_NEWER_PIN
        assert "foo" in exc_info.value.message

    def test_commit_exactly_at_bound_passes_strict_comparison(self, tmp_path: Path) -> None:
        """Exact-boundary case: a pinned commit whose committer date EQUALS
        ``exclude_newer`` exactly must PASS, not raise. The resolver's guard
        (``resolver.py``) is ``committer_date > params.exclude_newer`` — a
        strict greater-than — so an equal timestamp is allowed through, never
        rejected as newer. Pins the off-by-one boundary the strict operator
        establishes."""
        repo, _sha = _make_repo_with_annotated_tag(tmp_path)
        env = _real_env(tmp_path)
        bound = _COMMIT_DATE  # exactly equal to the commit's own committer date
        graph = _resolve(
            _root_manifest(_file_url(repo), "v1.0.0"), env, tmp_path, exclude_newer=bound
        )
        assert graph.deps[0].name == "foo"

    def test_no_exclude_newer_set_is_a_no_op_regression(self, tmp_path: Path) -> None:
        """No exclude_newer at all -> no validation runs, regardless of how
        old/new the commit is (pre-D4 behavior, unchanged)."""
        repo, _sha = _make_repo_with_annotated_tag(tmp_path)
        env = _real_env(tmp_path)
        graph = _resolve(_root_manifest(_file_url(repo), "v1.0.0"), env, tmp_path, exclude_newer=None)
        assert graph.deps[0].name == "foo"
