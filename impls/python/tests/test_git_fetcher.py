"""Tests for milpa.fetchers.git.GitFetcher (slice 7d-1).

All tests use a local temporary git repository (file:// URL or bare path) —
no internet access required.

Coverage:
  - GitProvenance.cas_admissible is True (immutable source per §4 NORMATIVE)
  - GitReceipt.transport_fields returns {"commit_sha": <sha>}
  - GitFetcher.can_handle returns True for GitProvenance, False for others
  - GitFetcher.fetch: successful clone from local repo, receipt has resolved SHA
  - GitFetcher.fetch: receipt commit_sha matches git HEAD
  - GitFetcher.fetch: commit_sha pin — checkout a specific earlier commit
  - GitFetcher.fetch: bad URL → MilpaError with FETCH-GIT-FAILED slug
  - GitFetcher.fetch: bad ref → MilpaError with FETCH-GIT-FAILED slug
  - GitFetcher.fetch: commit_sha absent → MilpaError with FETCH-GIT-COMMIT-ABSENT slug
  - GitFetcher: cas_admissible=True (inherited from Provenance base)
  - GitFetcher does NOT compute identity (tree hash absent from receipt)
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from milpa.errors import (
    FETCH_GIT_COMMIT_ABSENT,
    FETCH_GIT_FAILED,
    MilpaError,
)
from milpa.fetchers.git import GitFetcher, GitProvenance, GitReceipt
from milpa.fetchers.types import FetcherRegistry, Provenance

# ---------------------------------------------------------------------------
# Fixtures — local git repo factory
# ---------------------------------------------------------------------------


def _make_local_repo(tmp_path: Path) -> tuple[Path, str]:
    """Create a local bare-ish git repo with one commit.

    Returns (repo_dir, commit_sha).
    repo_dir is a normal (non-bare) git repository we can clone from via
    the filesystem path.
    """
    repo = tmp_path / "source_repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@milpa.test"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Milpa Test"],
        check=True, capture_output=True,
    )
    (repo / "hello.txt").write_text("hello milpa\n")
    subprocess.run(
        ["git", "-C", str(repo), "add", "hello.txt"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "initial commit"],
        check=True, capture_output=True,
    )
    sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    return repo, sha


def _add_commit(repo: Path) -> str:
    """Add a second commit to repo; return its SHA."""
    (repo / "second.txt").write_text("second file\n")
    subprocess.run(
        ["git", "-C", str(repo), "add", "second.txt"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "second commit"],
        check=True, capture_output=True,
    )
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


# ---------------------------------------------------------------------------
# GitProvenance
# ---------------------------------------------------------------------------


class TestGitProvenance:
    def test_cas_admissible_true(self) -> None:
        """All git provenances are CAS-admissible (plugin-contract.md §4 NORMATIVE)."""
        assert GitProvenance.cas_admissible is True

    def test_frozen_dataclass(self) -> None:
        p = GitProvenance(url="https://example.com/repo.git", ref="main")
        with pytest.raises((AttributeError, TypeError)):
            p.url = "changed"  # type: ignore[misc]

    def test_commit_sha_defaults_none(self) -> None:
        p = GitProvenance(url="https://example.com/repo.git", ref="main")
        assert p.commit_sha is None

    def test_commit_sha_set(self) -> None:
        sha = "a" * 40
        p = GitProvenance(url="u", ref="main", commit_sha=sha)
        assert p.commit_sha == sha


# ---------------------------------------------------------------------------
# GitReceipt
# ---------------------------------------------------------------------------


class TestGitReceipt:
    def test_transport_fields_returns_commit_sha(self) -> None:
        sha = "b" * 40
        r = GitReceipt(commit_sha=sha)
        assert r.transport_fields() == {"commit_sha": sha}

    def test_transport_fields_nonempty(self) -> None:
        r = GitReceipt(commit_sha="c" * 40)
        assert r.transport_fields()  # truthy

    def test_no_identity_field(self) -> None:
        """Receipt MUST NOT contain an identity (tree hash) field (§3.1 NORMATIVE)."""
        r = GitReceipt(commit_sha="d" * 40)
        fields = r.transport_fields()
        for key in fields:
            assert "identity" not in key
            assert "content_hash" not in key
            assert "tree" not in key


# ---------------------------------------------------------------------------
# GitFetcher.can_handle
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _OtherProvenance(Provenance):
    pass


class TestGitFetcherCanHandle:
    def test_claims_git_provenance(self) -> None:
        f = GitFetcher()
        assert f.can_handle(GitProvenance(url="x", ref="main")) is True

    def test_rejects_other_provenance(self) -> None:
        f = GitFetcher()
        assert f.can_handle(_OtherProvenance()) is False

    def test_rejects_base_provenance(self) -> None:
        f = GitFetcher()
        assert f.can_handle(Provenance()) is False


# ---------------------------------------------------------------------------
# GitFetcher.fetch — happy path
# ---------------------------------------------------------------------------


class TestGitFetcherHappyPath:
    def test_clone_materializes_tree(self, tmp_path: Path) -> None:
        repo, _ = _make_local_repo(tmp_path)
        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        receipt = fetcher.fetch("mylib", GitProvenance(url=str(repo), ref="main"), dest=dest)
        assert dest.is_dir()
        assert (dest / "hello.txt").read_text() == "hello milpa\n"
        assert isinstance(receipt, GitReceipt)

    def test_receipt_commit_sha_matches_head(self, tmp_path: Path) -> None:
        repo, expected_sha = _make_local_repo(tmp_path)
        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        receipt = fetcher.fetch("mylib", GitProvenance(url=str(repo), ref="main"), dest=dest)
        # The receipt SHA must be the actual HEAD commit.
        actual = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        assert receipt.commit_sha == actual
        assert receipt.commit_sha == expected_sha

    def test_commit_sha_is_40_hex_chars(self, tmp_path: Path) -> None:
        repo, _ = _make_local_repo(tmp_path)
        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        receipt = fetcher.fetch("mylib", GitProvenance(url=str(repo), ref="main"), dest=dest)
        sha = receipt.commit_sha
        assert len(sha) == 40
        assert all(c in "0123456789abcdef" for c in sha)

    def test_registry_computes_identity_not_fetcher(self, tmp_path: Path) -> None:
        """Identity lives in FetchResult.identity (registry), not receipt fields."""
        repo, _ = _make_local_repo(tmp_path)
        dest = tmp_path / "dest"
        registry = FetcherRegistry()
        registry.register(GitFetcher())
        result = registry.fetch("mylib", GitProvenance(url=str(repo), ref="main"), dest=dest)
        # identity is on result, not in receipt transport_fields
        assert result.identity.startswith("sha256:")
        for v in result.receipt.transport_fields().values():
            assert not v.startswith("sha256:")


# ---------------------------------------------------------------------------
# GitFetcher.fetch — commit_sha pin
# ---------------------------------------------------------------------------


class TestGitFetcherCommitPin:
    def test_pin_to_first_commit(self, tmp_path: Path) -> None:
        """When commit_sha is set, fetcher checks out that exact commit."""
        repo, first_sha = _make_local_repo(tmp_path)
        _add_commit(repo)  # advance the branch
        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        receipt = fetcher.fetch(
            "mylib",
            GitProvenance(url=str(repo), ref="main", commit_sha=first_sha),
            dest=dest,
        )
        assert receipt.commit_sha == first_sha
        # Only first commit's file should be present; second's should not.
        assert (dest / "hello.txt").exists()
        assert not (dest / "second.txt").exists()

    def test_pin_to_second_commit(self, tmp_path: Path) -> None:
        """commit_sha pin to latest commit — both files present."""
        repo, _ = _make_local_repo(tmp_path)
        second_sha = _add_commit(repo)
        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        receipt = fetcher.fetch(
            "mylib",
            GitProvenance(url=str(repo), ref="main", commit_sha=second_sha),
            dest=dest,
        )
        assert receipt.commit_sha == second_sha
        assert (dest / "second.txt").exists()


# ---------------------------------------------------------------------------
# GitFetcher.fetch — error paths
# ---------------------------------------------------------------------------


class TestGitFetcherErrors:
    def test_bad_url_raises_fetch_git_failed(self, tmp_path: Path) -> None:
        """A completely invalid URL raises MilpaError with FETCH-GIT-FAILED."""
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = GitFetcher()
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch(
                "mylib",
                GitProvenance(url="/does/not/exist/repo.git", ref="main"),
                dest=dest,
            )
        assert exc_info.value.slug == FETCH_GIT_FAILED

    def test_bad_ref_raises_fetch_git_failed(self, tmp_path: Path) -> None:
        """A valid repo but non-existent ref raises MilpaError with FETCH-GIT-FAILED."""
        repo, _ = _make_local_repo(tmp_path)
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = GitFetcher()
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch(
                "mylib",
                GitProvenance(url=str(repo), ref="nonexistent-branch-xyz"),
                dest=dest,
            )
        assert exc_info.value.slug == FETCH_GIT_FAILED

    def test_absent_commit_sha_raises_fetch_git_commit_absent(
        self, tmp_path: Path
    ) -> None:
        """commit_sha that doesn't exist raises MilpaError with FETCH-GIT-COMMIT-ABSENT."""
        repo, _ = _make_local_repo(tmp_path)
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = GitFetcher()
        fake_sha = "deadbeef" * 5  # 40-char plausible SHA that doesn't exist
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch(
                "mylib",
                GitProvenance(url=str(repo), ref="main", commit_sha=fake_sha),
                dest=dest,
            )
        assert exc_info.value.slug == FETCH_GIT_COMMIT_ABSENT

    def test_error_slug_is_string(self, tmp_path: Path) -> None:
        """Slug must be a non-empty string, not None (coded error)."""
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = GitFetcher()
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch(
                "mylib",
                GitProvenance(url="/nowhere", ref="main"),
                dest=dest,
            )
        assert exc_info.value.slug  # truthy
        assert isinstance(exc_info.value.slug, str)

    def test_fetch_error_not_fetch_error_type_for_bad_url(
        self, tmp_path: Path
    ) -> None:
        """GitFetcher raises MilpaError (not bare FetchError) for user-facing failures."""
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = GitFetcher()
        # Bad URL is a user-reachable condition → must be MilpaError, not uncoded FetchError.
        with pytest.raises(MilpaError):
            fetcher.fetch(
                "mylib",
                GitProvenance(url="/nowhere", ref="main"),
                dest=dest,
            )


# ---------------------------------------------------------------------------
# GitFetcher uses real git subprocess (no network)
# ---------------------------------------------------------------------------


class TestGitFetcherNoNetwork:
    def test_uses_file_path_not_https(self, tmp_path: Path) -> None:
        """Sanity: our fixture repos use local paths, confirming no network needed."""
        repo, _ = _make_local_repo(tmp_path)
        # Local path URL — no 'https://' anywhere
        url = str(repo)
        assert "https://" not in url
        assert "http://" not in url

    def test_full_round_trip_with_registry(self, tmp_path: Path) -> None:
        """End-to-end through FetcherRegistry: clone → identity computed."""
        repo, sha = _make_local_repo(tmp_path)
        registry = FetcherRegistry()
        registry.register(GitFetcher())
        dest = tmp_path / "pkg"
        result = registry.fetch("pkg", GitProvenance(url=str(repo), ref="main"), dest=dest)
        assert result.name == "pkg"
        assert result.path == dest
        assert result.identity.startswith("sha256:")
        assert result.receipt.transport_fields()["commit_sha"] == sha
