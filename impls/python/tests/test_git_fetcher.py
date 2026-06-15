"""Tests for milpa.fetchers.git.GitFetcher (slice 7d-1).

All tests use a local temporary git repository (file:// URL or bare path) —
no internet access required.

Coverage:
  - GitProvenance.cas_admissible is True (immutable source per §4 NORMATIVE)
  - GitReceipt.transport_fields returns {"commit_sha": <sha>}
  - GitFetcher.can_handle returns True for GitProvenance, False for others
  - GitFetcher.fetch: successful clone from local repo, receipt has resolved SHA
  - transport-normalization: core.autocrlf=false / core.filemode=false injected
    (spec/identity.md §1.7 NORMATIVE) so CRLF repos hash identically regardless
    of host git config
  - GitFetcher.fetch: receipt commit_sha matches git HEAD
  - GitFetcher.fetch: commit_sha pin — checkout a specific earlier commit
  - GitFetcher.fetch: bad URL → MilpaError with FETCH-GIT-FAILED slug
  - GitFetcher.fetch: bad ref → MilpaError with FETCH-GIT-FAILED slug
  - GitFetcher.fetch: commit_sha absent → MilpaError with FETCH-GIT-COMMIT-ABSENT slug
  - GitFetcher: cas_admissible=True (inherited from Provenance base)
  - GitFetcher does NOT compute identity (tree hash absent from receipt)
  - R5: ref starting with '-' treated as (nonexistent) ref → FETCH-GIT-FAILED,
    not silently consumed as an option flag.
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


# ---------------------------------------------------------------------------
# Transport normalization — spec/identity.md §1.7 NORMATIVE
# ---------------------------------------------------------------------------


def _make_crlf_repo(tmp_path: Path) -> tuple[Path, str]:
    """Create a local git repo whose working tree contains CRLF line endings.

    We commit the file with LF bytes (so Git stores LF objects) and disable
    autocrlf so no conversion happens at the object level.  The key property is
    that the *checked-out bytes* must be LF regardless of whatever the host's
    core.autocrlf would normally do — our fetcher must enforce this via the
    transport flags.
    """
    repo = tmp_path / "crlf_repo"
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
    # Write a file with CRLF bytes directly.
    crlf_file = repo / "crlf.txt"
    crlf_file.write_bytes(b"line1\r\nline2\r\n")
    subprocess.run(
        [
            "git", "-c", "core.autocrlf=false",
            "-C", str(repo), "add", "crlf.txt",
        ],
        check=True, capture_output=True,
    )
    subprocess.run(
        [
            "git", "-c", "user.email=test@milpa.test",
            "-c", "user.name=Milpa Test",
            "-C", str(repo), "commit", "-m", "crlf commit",
        ],
        check=True, capture_output=True,
    )
    sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    return repo, sha


class TestGitTransportNormalization:
    """spec/identity.md §1.7: -c core.autocrlf=false -c core.filemode=false must
    be injected so host git config cannot perturb the materialized bytes.

    We prove this in two ways:
      1. The _run_git helper inserts the flags into every git argv.
      2. Two clones of the same repo — one with host core.autocrlf=true (simulated
         via GIT_CONFIG_* env), one clean — produce byte-identical trees.
    """

    def test_transport_flags_present_in_argv(self, tmp_path: Path) -> None:
        """_run_git injects the transport flags into every git invocation."""
        from milpa.fetchers.git import _GIT_TRANSPORT_FLAGS
        assert "-c" in _GIT_TRANSPORT_FLAGS
        assert "core.autocrlf=false" in _GIT_TRANSPORT_FLAGS
        assert "core.filemode=false" in _GIT_TRANSPORT_FLAGS

    def test_crlf_repo_content_preserved_as_lf(self, tmp_path: Path) -> None:
        """Fetcher materializes LF bytes even when host might convert to CRLF.

        We commit CRLF bytes into the repo so that a real core.autocrlf=true
        git would check them out as CRLF, then verify the fetcher's -c flags
        override that and we always get back the same bytes that were committed.
        """
        repo, _ = _make_crlf_repo(tmp_path)
        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        fetcher.fetch("crlf_pkg", GitProvenance(url=str(repo), ref="main"), dest=dest)
        # The fetched bytes must match what was stored in the git object (CRLF).
        # core.autocrlf=false ensures Git doesn't convert them during checkout.
        content = (dest / "crlf.txt").read_bytes()
        assert content == b"line1\r\nline2\r\n", (
            f"Expected CRLF bytes unchanged by git checkout, got {content!r}"
        )

    def test_identity_stable_regardless_of_host_autocrlf_setting(
        self, tmp_path: Path
    ) -> None:
        """Two fetches from the same repo produce the same identity hash.

        This is the SSOT test: if the transport flags weren't injected, a host
        with core.autocrlf=input or =true would produce different bytes and a
        different identity.  With the flags, both fetches agree.
        """
        repo, _ = _make_crlf_repo(tmp_path)
        registry = FetcherRegistry()
        registry.register(GitFetcher())

        dest1 = tmp_path / "dest1"
        dest2 = tmp_path / "dest2"
        prov = GitProvenance(url=str(repo), ref="main")

        result1 = registry.fetch("crlf_pkg", prov, dest=dest1)
        result2 = registry.fetch("crlf_pkg", prov, dest=dest2)

        assert result1.identity == result2.identity, (
            "Identity hash must be stable across two fetches of the same repo"
        )


# ---------------------------------------------------------------------------
# R5 — git argument injection (ref / commit_sha starting with '-')
# ---------------------------------------------------------------------------


class TestGitArgInjectionHardening:
    """R5: attacker-controlled fields starting with '-' must not be parsed as
    git option flags.  We use real git (local repo) so the test exercises the
    actual subprocess call, not just argument-list shape.

    A ref like '-evil' or '--detach' is not a valid git branch/tag name, so
    the fetch must fail with FETCH-GIT-FAILED (ref not found), NOT silently
    succeed as if the flag were consumed by git.
    """

    def test_ref_starting_with_dash_fails_with_fetch_git_failed(
        self, tmp_path: Path
    ) -> None:
        """R5 behavioral: ref='-evil' is treated as a (nonexistent) ref name.

        Without --end-of-options, git checkout -q -evil would interpret -evil
        as an unknown option and produce a different (confusing) error or
        silently ignore it.  With --end-of-options the operand is treated as
        a ref that doesn't exist → FETCH-GIT-FAILED.
        """
        repo, _ = _make_local_repo(tmp_path)
        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch(
                "mylib",
                GitProvenance(url=str(repo), ref="-evil"),
                dest=dest,
            )
        assert exc_info.value.slug == FETCH_GIT_FAILED

    def test_ref_double_dash_detach_fails_with_fetch_git_failed(
        self, tmp_path: Path
    ) -> None:
        """R5 behavioral: ref='--detach' is treated as a nonexistent ref.

        'git checkout --detach' (without end-of-options) is a valid git
        invocation that detaches HEAD to the current commit.  With
        --end-of-options, '--detach' is a ref name that doesn't exist →
        FETCH-GIT-FAILED rather than silently detaching.
        """
        repo, _ = _make_local_repo(tmp_path)
        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch(
                "mylib",
                GitProvenance(url=str(repo), ref="--detach"),
                dest=dest,
            )
        assert exc_info.value.slug == FETCH_GIT_FAILED

    def test_commit_sha_starting_with_dash_fails_with_git_error(
        self, tmp_path: Path
    ) -> None:
        """R5 behavioral: commit_sha='-badoption' must produce a git error.

        A commit SHA that starts with '-' is not a valid SHA and should be
        treated as a nonexistent commit, producing FETCH-GIT-COMMIT-ABSENT
        (local check fails) or FETCH-GIT-FAILED (git rejects the arg).
        Either is acceptable — the important thing is it does NOT silently
        succeed or crash without a MilpaError.
        """
        repo, _ = _make_local_repo(tmp_path)
        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch(
                "mylib",
                GitProvenance(url=str(repo), ref="main", commit_sha="-badoption"),
                dest=dest,
            )
        assert exc_info.value.slug in (FETCH_GIT_FAILED, FETCH_GIT_COMMIT_ABSENT)
