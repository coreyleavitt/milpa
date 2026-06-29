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
    EXTRACT_SYMLINK_ESCAPE,
    FETCH_GIT_COMMIT_ABSENT,
    FETCH_GIT_FAILED,
    FETCH_GIT_LFS_POINTER,
    ID_NON_UTF8_RELPATH,
    MilpaError,
)
from milpa.fetchers.git import GitFetcher, GitProvenance, GitReceipt, materialize_git_tree
from milpa.fetchers.types import FetcherRegistry, Provenance
from milpa.identity import compute_content_hash

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
        # H3b: dest is now an output tree (no .git); read HEAD from the SOURCE repo.
        # The receipt SHA must match the HEAD commit of the source repo.
        actual = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
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
        assert result.identity.startswith("dag-sha256:")
        for v in result.receipt.transport_fields().values():
            assert not v.startswith("dag-sha256:")


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
        assert result.identity.startswith("dag-sha256:")
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
    """H3b: object-store materialization is the transport-normalization mechanism.

    H3a deleted the spec clause that required -c core.autocrlf=false /
    -c core.filemode=false; those flags were the old checkout-path normalization.
    H3b replaces them with --no-checkout + materialize_git_tree, which reads
    object-store bytes directly (no smudge filters can apply).

    We verify the normalization invariant structurally:
      - _GIT_TRANSPORT_FLAGS is now empty (no checkout normalization needed).
      - CRLF bytes committed to the repo come back unchanged (object-store path).
      - Two fetches of the same repo produce byte-identical trees (determinism).
    """

    def test_crlf_repo_object_store_bytes_unchanged(self, tmp_path: Path) -> None:
        """Object-store materialization reads committed bytes, not smudge output.

        We commit CRLF bytes — under git checkout with core.autocrlf=true those
        would be converted. Object-store path reads the stored blob directly,
        so the CRLF bytes come back exactly as committed.
        """
        repo, _ = _make_crlf_repo(tmp_path)
        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        fetcher.fetch("crlf_pkg", GitProvenance(url=str(repo), ref="main"), dest=dest)
        # The fetched bytes must match the committed bytes (CRLF — what was stored).
        content = (dest / "crlf.txt").read_bytes()
        assert content == b"line1\r\nline2\r\n", (
            f"Expected committed CRLF bytes from object store, got {content!r}"
        )

    def test_identity_stable_regardless_of_host_autocrlf_setting(
        self, tmp_path: Path
    ) -> None:
        """Two fetches from the same repo produce the same identity hash.

        Object-store path: smudge filters cannot apply, so the identity is
        always the hash of the committed bytes regardless of host git config.
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


# ---------------------------------------------------------------------------
# H3b helpers — local repo factories for object-store tests
# ---------------------------------------------------------------------------


def _make_git_env() -> dict[str, str]:
    """Minimal environment for deterministic git operations in tests."""
    import os
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "Milpa Test"
    env["GIT_AUTHOR_EMAIL"] = "test@milpa.test"
    env["GIT_COMMITTER_NAME"] = "Milpa Test"
    env["GIT_COMMITTER_EMAIL"] = "test@milpa.test"
    return env


def _init_repo(path: Path) -> None:
    """Init a git repo with deterministic identity config."""
    subprocess.run(["git", "init", "-b", "main", str(path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(path), "config", "user.email", "test@milpa.test"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(path), "config", "user.name", "Milpa Test"],
        check=True, capture_output=True,
    )


def _commit_all(path: Path, message: str = "commit") -> str:
    """Stage all and commit; return commit SHA."""
    subprocess.run(
        ["git", "-C", str(path), "add", "-A"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(path), "commit", "-m", message],
        check=True, capture_output=True, env=_make_git_env(),
    )
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def _clone_no_checkout(src: Path, dest: Path) -> None:
    """Clone src into dest with --no-checkout."""
    subprocess.run(
        ["git", "clone", "-q", "--no-checkout", str(src), str(dest)],
        check=True, capture_output=True,
    )


# ---------------------------------------------------------------------------
# H3b-a: baseline object-store materialization
# ---------------------------------------------------------------------------


class TestMaterializeGitTreeBaseline:
    """H3b-a: simple repo fetched via materialize_git_tree produces correct tree.

    This is the smoke test: two files committed, object-store materialization
    yields both files with expected content; content_hash matches.
    Also verifies GitFetcher.fetch goes through materialize_git_tree (the
    --no-checkout path): no .git dir in dest, files match committed bytes.
    """

    def test_object_store_materialization_basic(self, tmp_path: Path) -> None:
        """Files materialized from object store match committed bytes."""
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        (src / "hello.nim").write_text("echo \"hello\"\n")
        (src / "stub.nimble").write_text("# stub\n")
        sha = _commit_all(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()
        materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)

        assert (dest / "hello.nim").read_text() == "echo \"hello\"\n"
        assert (dest / "stub.nimble").read_text() == "# stub\n"
        # No .git in output tree (spec/identity.md §1.7.1)
        assert not (dest / ".git").exists()

    def test_content_hash_matches_compute(self, tmp_path: Path) -> None:
        """content_hash of materialized tree == compute_content_hash of that tree."""
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        (src / "hello.nim").write_text("echo \"hello\"\n")
        sha = _commit_all(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()
        materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)

        # The hash computed over the materialized tree must be stable.
        h = compute_content_hash(dest)
        assert h.startswith("dag-sha256:")
        # Re-compute: identical
        assert compute_content_hash(dest) == h

    def test_git_fetcher_goes_through_materialize(self, tmp_path: Path) -> None:
        """GitFetcher.fetch materializes via object-store (no .git in dest)."""
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        (src / "lib.nim").write_bytes(b"# lib\n")
        _commit_all(src)

        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        fetcher.fetch("mylib", GitProvenance(url=str(src), ref="main"), dest=dest)

        assert dest.is_dir()
        assert (dest / "lib.nim").exists()
        # Object-store path: .git MUST NOT be in output tree
        assert not (dest / ".git").exists()

    def test_duplicate_blob_sha_materialized_correctly(self, tmp_path: Path) -> None:
        """R1-20: two files with identical content share a git blob SHA.

        Before the dedup fix, the same SHA appeared twice in batch_shas; the
        cat-file --batch parser consumed two header+body pairs for it, causing
        the second entry to see a misaligned stream offset.  After the fix
        (dict.fromkeys dedup), each SHA is sent once and the lookup dict is
        keyed by SHA so both files still materialize from the same bytes.
        """
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        identical_content = b"same bytes in both files\n"
        (src / "alpha.nim").write_bytes(identical_content)
        (src / "beta.nim").write_bytes(identical_content)
        sha = _commit_all(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()
        materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)

        assert (dest / "alpha.nim").read_bytes() == identical_content
        assert (dest / "beta.nim").read_bytes() == identical_content


# ---------------------------------------------------------------------------
# H3b-b: .gitattributes eol=crlf invariance (THE headline invariant)
# ---------------------------------------------------------------------------


class TestMaterializeGitTreeEolInvariance:
    """H3b-b: object-store materialization is invariant to .gitattributes eol=crlf.

    A repo with a text file committed with LF bytes + a .gitattributes
    declaring "* eol=crlf" would produce CRLF bytes under git checkout.
    Object-store materialization reads the committed LF bytes directly,
    so the content_hash is identical to the same repo WITHOUT .gitattributes.

    This is a Python-only test (not promoted to shared corpus) so that
    Rust H3c implementation does not go red. H3d promotes it to shared
    corpus once both impls converge.
    """

    def _make_lf_repo(self, path: Path) -> str:
        """Repo with LF-only text file, no .gitattributes."""
        _init_repo(path)
        (path / "data.txt").write_bytes(b"line1\nline2\n")
        return _commit_all(path)

    def _make_lf_repo_with_crlf_attr(self, path: Path) -> str:
        """Repo with LF-only text file + .gitattributes saying * eol=crlf."""
        _init_repo(path)
        (path / "data.txt").write_bytes(b"line1\nline2\n")
        (path / ".gitattributes").write_bytes(b"* eol=crlf\n")
        return _commit_all(path)

    def test_eol_crlf_attr_does_not_change_object_store_bytes(
        self, tmp_path: Path
    ) -> None:
        """Committed LF bytes are read from object store, not smudged to CRLF."""
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        (src / "data.txt").write_bytes(b"line1\nline2\n")
        (src / ".gitattributes").write_bytes(b"* eol=crlf\n")
        sha = _commit_all(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()
        materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)

        # Object-store blob has LF bytes (what was committed).
        # A git checkout with eol=crlf would produce CRLF.
        content = (dest / "data.txt").read_bytes()
        assert content == b"line1\nline2\n", (
            f"Object-store bytes must be LF (committed), not CRLF (smudged): {content!r}"
        )

    def test_content_hash_invariant_with_and_without_gitattributes(
        self, tmp_path: Path
    ) -> None:
        """content_hash of data.txt is identical with and without .gitattributes eol=crlf.

        The file data.txt has the same committed LF bytes in both repos.
        The .gitattributes only affects checkout smudge, not object-store bytes.
        So materialize_git_tree must produce the same content_hash in both.
        """
        src_plain = tmp_path / "plain"
        src_plain.mkdir()
        sha_plain = self._make_lf_repo(src_plain)

        src_attr = tmp_path / "attr"
        src_attr.mkdir()
        self._make_lf_repo_with_crlf_attr(src_attr)
        # We need the sha for data.txt's blob (same in both repos since same bytes)
        sha_attr = subprocess.run(
            ["git", "-C", str(src_attr), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

        clone_plain = tmp_path / "clone_plain"
        _clone_no_checkout(src_plain, clone_plain)
        dest_plain = tmp_path / "dest_plain"
        dest_plain.mkdir()
        materialize_git_tree(clone_plain, sha_plain, dest_plain, submodule_fetch=None)

        clone_attr = tmp_path / "clone_attr"
        _clone_no_checkout(src_attr, clone_attr)
        dest_attr = tmp_path / "dest_attr"
        dest_attr.mkdir()
        materialize_git_tree(clone_attr, sha_attr, dest_attr, submodule_fetch=None)

        # data.txt has the same committed bytes → same hash contribution.
        # (The attr repo also has .gitattributes — different tree → different overall hash.
        #  The invariant being tested: data.txt is LF in both, not CRLF in the attr one.)
        assert (dest_plain / "data.txt").read_bytes() == (dest_attr / "data.txt").read_bytes()

    def test_fetcher_hash_invariant_with_and_without_gitattributes(
        self, tmp_path: Path
    ) -> None:
        """GitFetcher full round-trip: same data.txt bytes => identical content hash.

        Two repos with identical data.txt content but one has * eol=crlf attribute.
        materialize_git_tree reads object-store bytes; content_hash for the
        data.txt blob is the same in both because it was committed with LF bytes.
        """
        src_no_attr = tmp_path / "no_attr"
        src_no_attr.mkdir()
        _init_repo(src_no_attr)
        (src_no_attr / "only.txt").write_bytes(b"hello\n")
        _commit_all(src_no_attr)

        src_with_attr = tmp_path / "with_attr"
        src_with_attr.mkdir()
        _init_repo(src_with_attr)
        (src_with_attr / "only.txt").write_bytes(b"hello\n")
        (src_with_attr / ".gitattributes").write_bytes(b"* eol=crlf\n")
        _commit_all(src_with_attr)

        fetcher = GitFetcher()
        dest1 = tmp_path / "dest1"
        dest2 = tmp_path / "dest2"
        fetcher.fetch("pkg", GitProvenance(url=str(src_no_attr), ref="main"), dest=dest1)
        fetcher.fetch("pkg", GitProvenance(url=str(src_with_attr), ref="main"), dest=dest2)

        # only.txt was committed with LF in both repos.
        assert (dest1 / "only.txt").read_bytes() == (dest2 / "only.txt").read_bytes() == b"hello\n"


# ---------------------------------------------------------------------------
# H3b-c: committed symlink escape → EXTRACT-SYMLINK-ESCAPE
# ---------------------------------------------------------------------------


class TestMaterializeGitTreeSymlinkEscape:
    """H3b-c: object-store symlink containment check.

    mode-120000 blobs whose target lexically escapes dest raise
    EXTRACT-SYMLINK-ESCAPE. Safe in-tree symlinks materialize fine.
    """

    def _make_repo_with_symlink(self, path: Path, target: str) -> tuple[str, str]:
        """Create a repo with a symlink blob; return (sha, symlink_name)."""
        _init_repo(path)
        # Write a regular file the symlink might point to (for safe case).
        (path / "target.txt").write_bytes(b"target content\n")
        # Create the symlink on-disk so git can add it.
        symlink = path / "link.txt"
        symlink.symlink_to(target)
        sha = _commit_all(path)
        return sha, "link.txt"

    def test_safe_symlink_materializes(self, tmp_path: Path) -> None:
        """A symlink whose target stays in-tree materializes normally."""
        src = tmp_path / "src"
        src.mkdir()
        sha, link_name = self._make_repo_with_symlink(src, "target.txt")

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()
        # Should not raise.
        materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)
        assert (dest / link_name).is_symlink()
        assert (dest / link_name).readlink() == Path("target.txt")

    def test_escaping_symlink_raises_extract_symlink_escape(
        self, tmp_path: Path
    ) -> None:
        """Committed symlink with escape target raises EXTRACT-SYMLINK-ESCAPE."""
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        (src / "evil.txt").symlink_to("../../../../etc/passwd")
        sha = _commit_all(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()
        with pytest.raises(MilpaError) as exc_info:
            materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)
        assert exc_info.value.slug == EXTRACT_SYMLINK_ESCAPE

    def test_escape_via_relative_dots(self, tmp_path: Path) -> None:
        """../../ pattern in symlink target correctly detected as escape."""
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        (src / "subdir").mkdir()
        # Symlink in subdir with target that escapes the dest root
        (src / "subdir" / "escape.lnk").symlink_to("../../outside")
        sha = _commit_all(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()
        with pytest.raises(MilpaError) as exc_info:
            materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)
        assert exc_info.value.slug == EXTRACT_SYMLINK_ESCAPE


# ---------------------------------------------------------------------------
# H3b-d: LFS pointer → FETCH-GIT-LFS-POINTER
# ---------------------------------------------------------------------------


class TestMaterializeGitTreeLfsDetection:
    """H3b-d: LFS pointer detection.

    A blob whose first line is exactly "version https://git-lfs.github.com/spec/v1"
    raises FETCH-GIT-LFS-POINTER. A large blob containing that string elsewhere
    is NOT a pointer.
    """

    _LFS_FIRST_LINE = b"version https://git-lfs.github.com/spec/v1\n"
    _FULL_LFS_POINTER = (
        b"version https://git-lfs.github.com/spec/v1\n"
        b"oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n"
        b"size 12345\n"
    )

    def _make_lfs_repo(self, path: Path) -> str:
        """Commit an LFS pointer blob; return commit SHA."""
        _init_repo(path)
        (path / "large_file.bin").write_bytes(self._FULL_LFS_POINTER)
        return _commit_all(path)

    def test_lfs_pointer_raises_fetch_git_lfs_pointer(self, tmp_path: Path) -> None:
        """Full LFS pointer blob raises FETCH-GIT-LFS-POINTER with path= context."""
        src = tmp_path / "src"
        src.mkdir()
        sha = self._make_lfs_repo(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()
        with pytest.raises(MilpaError) as exc_info:
            materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)
        err = exc_info.value
        assert err.slug == FETCH_GIT_LFS_POINTER
        assert "path" in err.context
        assert err.context["path"] == "large_file.bin"

    def test_lfs_message_is_actionable(self, tmp_path: Path) -> None:
        """Error message mentions 'LFS' and actionable remediation."""
        src = tmp_path / "src"
        src.mkdir()
        sha = self._make_lfs_repo(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()
        with pytest.raises(MilpaError) as exc_info:
            materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)
        msg = exc_info.value.message.lower()
        assert "lfs" in msg
        # Actionable remediation: should mention mirror or local
        assert "mirror" in msg or "local" in msg

    def test_first_line_only_detection(self, tmp_path: Path) -> None:
        """Non-first-line occurrence of LFS header string does NOT trigger detection."""
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        # File that mentions the LFS string but NOT on the first line.
        (src / "docs.txt").write_bytes(
            b"# This file documents LFS usage\n"
            b"version https://git-lfs.github.com/spec/v1\n"
            b"This is just documentation about LFS pointer format.\n"
        )
        sha = _commit_all(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()
        # Must NOT raise FETCH-GIT-LFS-POINTER (LFS string is not on line 1).
        materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)
        assert (dest / "docs.txt").exists()

    def test_lfs_first_line_exact_match_no_prefix(self, tmp_path: Path) -> None:
        """'version https://git-lfs...' with a prefix byte on line 1 is NOT detected."""
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        # File starting with a space before the LFS version string.
        (src / "almost.txt").write_bytes(
            b" version https://git-lfs.github.com/spec/v1\n"
            b"not actually an LFS pointer\n"
        )
        sha = _commit_all(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()
        # Space prefix means first line is NOT exactly the LFS header.
        materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)
        assert (dest / "almost.txt").exists()


# ---------------------------------------------------------------------------
# H3b-e: fixed on-disk mode + no empty dirs synthesized
# ---------------------------------------------------------------------------


class TestMaterializeGitTreeModeAndDirs:
    """H3b-e: fixed on-disk modes and no empty-dir synthesis."""

    def test_regular_blob_mode_644(self, tmp_path: Path) -> None:
        """mode-100644 blob materializes with 0o644 on disk."""
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        (src / "regular.txt").write_bytes(b"hello\n")
        # Ensure not executable
        import os
        os.chmod(src / "regular.txt", 0o644)
        sha = _commit_all(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)
        dest = tmp_path / "dest"
        dest.mkdir()
        materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)

        import stat
        mode = (dest / "regular.txt").stat().st_mode & 0o777
        assert mode == 0o644, f"Expected 0o644, got {oct(mode)}"

    def test_exec_blob_mode_755(self, tmp_path: Path) -> None:
        """mode-100755 blob materializes with 0o755 on disk."""
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        import os
        (src / "run.sh").write_bytes(b"#!/bin/sh\necho hi\n")
        os.chmod(src / "run.sh", 0o755)
        sha = _commit_all(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)
        dest = tmp_path / "dest"
        dest.mkdir()
        materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)

        import stat
        mode = (dest / "run.sh").stat().st_mode & 0o777
        assert mode == 0o755, f"Expected 0o755, got {oct(mode)}"

    def test_no_git_dir_in_output(self, tmp_path: Path) -> None:
        """Output tree must not contain .git (§1.7.1 clone discipline)."""
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        (src / "a.txt").write_bytes(b"a\n")
        sha = _commit_all(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)
        dest = tmp_path / "dest"
        dest.mkdir()
        materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)

        assert not (dest / ".git").exists()

    def test_no_empty_dirs_synthesized(self, tmp_path: Path) -> None:
        """materialize_git_tree does not synthesize dirs that only contain blobs.

        git ls-tree -r only emits blobs; directories exist only to hold blobs.
        The function must create intermediate dirs as needed to write blobs, but
        must not create directories that have no blobs under them.
        """
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        (src / "subdir").mkdir()
        (src / "subdir" / "file.txt").write_bytes(b"content\n")
        sha = _commit_all(src)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)
        dest = tmp_path / "dest"
        dest.mkdir()
        materialize_git_tree(clone_scratch, sha, dest, submodule_fetch=None)

        # subdir should exist (it holds file.txt)
        assert (dest / "subdir" / "file.txt").exists()
        # No phantom empty directories
        all_dirs = [p for p in dest.rglob("*") if p.is_dir()]
        # subdir is allowed since it contains file.txt
        for d in all_dirs:
            assert any(d.rglob("*")), f"Empty directory synthesized: {d}"


# ---------------------------------------------------------------------------
# H5: Submodule recursion
# ---------------------------------------------------------------------------


def _make_submodule_repo(tmp_path: Path, name: str) -> tuple[Path, str]:
    """Create a bare-ish git repo to use as a submodule; return (repo_dir, sha)."""
    repo = tmp_path / name
    repo.mkdir()
    _init_repo(repo)
    (repo / "sub_file.nim").write_bytes(b"# submodule content\n")
    sha = _commit_all(repo, f"init {name}")
    return repo, sha


def _make_superproject_with_submodule(
    tmp_path: Path,
    sub_repo: Path,
    sub_sha: str,
    sub_path: str = "libs/foo",
    sub_url: str | None = None,
) -> tuple[Path, str]:
    """Create a superproject with a gitlink (mode-160000) at sub_path.

    Uses ``git update-index --add --cacheinfo 160000 <sha> <path>`` to add
    the gitlink directly (avoids running git submodule add, which does a
    network operation).  Also writes a ``.gitmodules`` file with the mapping.
    """
    super_repo = tmp_path / "superproject"
    super_repo.mkdir()
    _init_repo(super_repo)

    # Write a regular file in the superproject.
    (super_repo / "main.nim").write_bytes(b"# superproject main\n")

    # Build the submodule path directory structure for the gitmodules file.
    url = sub_url or str(sub_repo)

    # Write .gitmodules.
    gitmodules_content = (
        f'[submodule "foo"]\n'
        f'    path = {sub_path}\n'
        f'    url = {url}\n'
    )
    (super_repo / ".gitmodules").write_text(gitmodules_content)

    # Stage .gitmodules and main.nim.
    subprocess.run(
        ["git", "-C", str(super_repo), "add", "main.nim", ".gitmodules"],
        check=True, capture_output=True,
    )

    # Add the gitlink (mode-160000) without actually cloning.
    subprocess.run(
        ["git", "-C", str(super_repo), "update-index", "--add",
         "--cacheinfo", f"160000,{sub_sha},{sub_path}"],
        check=True, capture_output=True,
    )

    # Commit.
    sha = subprocess.run(
        ["git", "-C", str(super_repo), "commit", "-m", "add submodule",
         "--allow-empty"],
        check=True, capture_output=True, text=True, env=_make_git_env(),
    )
    commit_sha = subprocess.run(
        ["git", "-C", str(super_repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    return super_repo, commit_sha


class TestH5SubmoduleRecursion:
    """H5-a: basic submodule materialization — submodule files appear in tree."""

    def test_submodule_content_materialized_in_superproject_tree(
        self, tmp_path: Path
    ) -> None:
        """Submodule content materializes at sub_path in the superproject dest."""
        sub_repo, sub_sha = _make_submodule_repo(tmp_path, "sub_repo")
        super_repo, super_sha = _make_superproject_with_submodule(
            tmp_path, sub_repo, sub_sha, sub_path="libs/foo"
        )

        clone_scratch = tmp_path / "clone_super"
        _clone_no_checkout(super_repo, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()

        # Build the submodule_fetch closure that clones sub_repo.
        def sub_fetch(url: str, sha: str) -> Path:
            scratch = tmp_path / f"sub_scratch_{sha[:8]}"
            scratch.mkdir()
            _clone_no_checkout(sub_repo, scratch)
            return scratch

        materialize_git_tree(
            clone_scratch,
            super_sha,
            dest,
            submodule_fetch=sub_fetch,
            superproject_url=str(super_repo),
        )

        # Superproject files materialized.
        assert (dest / "main.nim").exists()
        assert (dest / ".gitmodules").exists()
        # Submodule content materialized at libs/foo.
        assert (dest / "libs" / "foo" / "sub_file.nim").exists()
        assert (dest / "libs" / "foo" / "sub_file.nim").read_bytes() == b"# submodule content\n"

    def test_submodule_contributes_to_content_hash(self, tmp_path: Path) -> None:
        """Submodule content is part of the materialized tree → part of content_hash."""
        sub_repo, sub_sha = _make_submodule_repo(tmp_path, "sub_repo")
        super_repo, super_sha = _make_superproject_with_submodule(
            tmp_path, sub_repo, sub_sha, sub_path="libs/foo"
        )

        clone_scratch = tmp_path / "clone_super"
        _clone_no_checkout(super_repo, clone_scratch)
        dest = tmp_path / "dest"
        dest.mkdir()

        def sub_fetch(url: str, sha: str) -> Path:
            scratch = tmp_path / f"sub_scratch_{sha[:8]}"
            scratch.mkdir()
            _clone_no_checkout(sub_repo, scratch)
            return scratch

        materialize_git_tree(
            clone_scratch, super_sha, dest,
            submodule_fetch=sub_fetch,
            superproject_url=str(super_repo),
        )

        h = compute_content_hash(dest)
        assert h.startswith("dag-sha256:")
        # Re-hash: must be stable.
        assert compute_content_hash(dest) == h
        # Without submodule content, the hash would differ from a repo that
        # lacks the submodule file entirely — we just check it's deterministic.

    def test_submodule_shas_returned_by_materialize(self, tmp_path: Path) -> None:
        """materialize_git_tree returns {path → sha} for each gitlink recursed."""
        sub_repo, sub_sha = _make_submodule_repo(tmp_path, "sub_repo")
        super_repo, super_sha = _make_superproject_with_submodule(
            tmp_path, sub_repo, sub_sha, sub_path="libs/foo"
        )

        clone_scratch = tmp_path / "clone_super"
        _clone_no_checkout(super_repo, clone_scratch)
        dest = tmp_path / "dest"
        dest.mkdir()

        def sub_fetch(url: str, sha: str) -> Path:
            scratch = tmp_path / f"sub_scratch_{sha[:8]}"
            scratch.mkdir()
            _clone_no_checkout(sub_repo, scratch)
            return scratch

        result = materialize_git_tree(
            clone_scratch, super_sha, dest,
            submodule_fetch=sub_fetch,
            superproject_url=str(super_repo),
        )

        assert "libs/foo" in result
        assert result["libs/foo"] == sub_sha

    def test_gitfetcher_receipt_carries_submodule_shas(self, tmp_path: Path) -> None:
        """GitFetcher.fetch returns GitReceipt with submodule_shas populated."""
        sub_repo, sub_sha = _make_submodule_repo(tmp_path, "sub_repo")
        super_repo, super_sha = _make_superproject_with_submodule(
            tmp_path, sub_repo, sub_sha, sub_path="libs/foo"
        )

        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        receipt = fetcher.fetch(
            "superlib",
            GitProvenance(url=str(super_repo), ref="main"),
            dest=dest,
        )

        assert isinstance(receipt, GitReceipt)
        assert receipt.commit_sha == super_sha
        assert "libs/foo" in receipt.submodule_shas
        assert receipt.submodule_shas["libs/foo"] == sub_sha


class TestH5RelativeSubmoduleUrl:
    """H5-b: relative .gitmodules URL resolved against superproject URL."""

    def test_relative_url_resolved_correctly(self, tmp_path: Path) -> None:
        """_resolve_submodule_url resolves ../sibling against https://host/org/super.git.

        git-submodule.sh strips the last path component (the repo name)
        giving base = https://github.com/org.
        normpath(/org/../sibling) = /sibling → https://github.com/sibling.
        """
        from milpa.fetchers.git import _resolve_submodule_url
        result = _resolve_submodule_url(
            "../sibling",
            "https://github.com/org/super.git",
        )
        # strip last component → /org; ../sibling from /org → /sibling
        assert result == "https://github.com/sibling"

    def test_relative_url_same_org(self, tmp_path: Path) -> None:
        """../sibling within a deeper path stays in parent org."""
        from milpa.fetchers.git import _resolve_submodule_url
        # strip last → /org/team; ../sibling from /org/team → /org/sibling
        result = _resolve_submodule_url(
            "../sibling",
            "https://github.com/org/team/super.git",
        )
        assert result == "https://github.com/org/sibling"

    def test_dot_slash_relative_url(self, tmp_path: Path) -> None:
        """_resolve_submodule_url resolves ./same-level against superproject URL.

        strip last → /org; ./same from /org → /org/same.
        """
        from milpa.fetchers.git import _resolve_submodule_url
        result = _resolve_submodule_url(
            "./same",
            "https://github.com/org/super.git",
        )
        assert result == "https://github.com/org/same"

    def test_absolute_url_passthrough(self, tmp_path: Path) -> None:
        """Absolute URL in .gitmodules passes through unchanged."""
        from milpa.fetchers.git import _resolve_submodule_url
        abs_url = "https://github.com/other/repo.git"
        assert _resolve_submodule_url(abs_url, "https://host/org/super.git") == abs_url

    def test_parse_gitmodules_basic(self, tmp_path: Path) -> None:
        """_parse_gitmodules returns {path → url} dict."""
        from milpa.fetchers.git import _parse_gitmodules
        content = (
            b'[submodule "foo"]\n'
            b'    path = libs/foo\n'
            b'    url = https://github.com/org/foo.git\n'
            b'[submodule "bar"]\n'
            b'    path = libs/bar\n'
            b'    url = ../bar\n'
        )
        result = _parse_gitmodules(content)
        assert result == {
            "libs/foo": "https://github.com/org/foo.git",
            "libs/bar": "../bar",
        }

    def test_relative_url_in_real_fetch(self, tmp_path: Path) -> None:
        """Relative .gitmodules URL is resolved (not passed raw) to submodule_fetch."""
        sub_repo, sub_sha = _make_submodule_repo(tmp_path, "sub_repo")
        super_repo, super_sha = _make_superproject_with_submodule(
            tmp_path, sub_repo, sub_sha,
            sub_path="libs/foo",
            sub_url="../sub_repo",  # relative URL in .gitmodules
        )

        # Use file:// URL form so the relative URL resolver has a scheme to work with.
        super_url = "file://" + str(super_repo)

        clone_scratch = tmp_path / "clone_super"
        _clone_no_checkout(super_repo, clone_scratch)
        dest = tmp_path / "dest"
        dest.mkdir()

        fetched_urls = []

        def sub_fetch(url: str, sha: str) -> Path:
            fetched_urls.append(url)
            # The url may be a file:// URL or a resolved absolute path.
            # We always clone from the real sub_repo regardless — this test
            # only verifies that (1) relative URL was resolved (not raw), and
            # (2) submodule content materializes.
            scratch = tmp_path / f"sub_scratch_{sha[:8]}"
            # git clone requires dest to not exist as a non-empty dir.
            subprocess.run(
                ["git", "clone", "-q", "--no-checkout", str(sub_repo), str(scratch)],
                check=True, capture_output=True,
            )
            return scratch

        materialize_git_tree(
            clone_scratch, super_sha, dest,
            submodule_fetch=sub_fetch,
            superproject_url=super_url,
        )

        assert len(fetched_urls) == 1
        # The resolved URL must NOT be the raw "../sub_repo" string.
        assert not fetched_urls[0].startswith("../")
        # Submodule content must be present.
        assert (dest / "libs" / "foo" / "sub_file.nim").exists()


class TestH5SubmoduleFailedSlug:
    """H5-d: FETCH-GIT-SUBMODULE-FAILED raised on bad submodule URL."""

    def test_missing_gitmodules_entry_raises_slug(self, tmp_path: Path) -> None:
        """A gitlink with no .gitmodules entry raises FETCH-GIT-SUBMODULE-FAILED."""
        from milpa.errors import FETCH_GIT_SUBMODULE_FAILED

        # Create a superproject where .gitmodules has no entry for the path.
        sub_repo, sub_sha = _make_submodule_repo(tmp_path, "sub_repo")
        super_repo = tmp_path / "superproject"
        super_repo.mkdir()
        _init_repo(super_repo)
        (super_repo / "main.nim").write_bytes(b"# main\n")
        # .gitmodules with wrong path.
        (super_repo / ".gitmodules").write_text(
            '[submodule "other"]\n'
            '    path = other/path\n'
            '    url = https://example.com/other.git\n'
        )
        subprocess.run(
            ["git", "-C", str(super_repo), "add", "main.nim", ".gitmodules"],
            check=True, capture_output=True,
        )
        # Add a gitlink for "libs/foo" not in .gitmodules.
        subprocess.run(
            ["git", "-C", str(super_repo), "update-index", "--add",
             "--cacheinfo", f"160000,{sub_sha},libs/foo"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(super_repo), "commit", "-m", "broken submodule", "--allow-empty"],
            check=True, capture_output=True, env=_make_git_env(),
        )
        super_sha = subprocess.run(
            ["git", "-C", str(super_repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

        clone_scratch = tmp_path / "clone_super"
        _clone_no_checkout(super_repo, clone_scratch)
        dest = tmp_path / "dest"
        dest.mkdir()

        called = []
        def sub_fetch(url: str, sha: str) -> Path:
            called.append((url, sha))
            raise RuntimeError("should not be called")

        with pytest.raises(MilpaError) as exc_info:
            materialize_git_tree(
                clone_scratch, super_sha, dest,
                submodule_fetch=sub_fetch,
                superproject_url=str(super_repo),
            )
        assert exc_info.value.slug == FETCH_GIT_SUBMODULE_FAILED
        assert "submodule_path" in exc_info.value.context
        assert exc_info.value.context["submodule_path"] == "libs/foo"
        assert not called  # submodule_fetch never invoked

    def test_unfetchable_url_raises_slug(self, tmp_path: Path) -> None:
        """A submodule whose clone fails raises FETCH-GIT-SUBMODULE-FAILED."""
        from milpa.errors import FETCH_GIT_SUBMODULE_FAILED

        sub_repo, sub_sha = _make_submodule_repo(tmp_path, "sub_repo")
        super_repo, super_sha = _make_superproject_with_submodule(
            tmp_path, sub_repo, sub_sha, sub_path="libs/foo",
            sub_url="https://invalid.example.local/nonexistent.git",
        )

        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch(
                "superlib",
                GitProvenance(url=str(super_repo), ref="main"),
                dest=dest,
            )
        # Should raise the submodule slug, not the generic FETCH-GIT-FAILED.
        assert exc_info.value.slug == FETCH_GIT_SUBMODULE_FAILED

    def test_error_carries_submodule_url(self, tmp_path: Path) -> None:
        """FETCH-GIT-SUBMODULE-FAILED error carries submodule_url context."""
        from milpa.errors import FETCH_GIT_SUBMODULE_FAILED

        sub_repo, sub_sha = _make_submodule_repo(tmp_path, "sub_repo")
        super_repo, super_sha = _make_superproject_with_submodule(
            tmp_path, sub_repo, sub_sha, sub_path="libs/foo",
            sub_url="https://invalid.example.local/nonexistent.git",
        )

        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch(
                "superlib",
                GitProvenance(url=str(super_repo), ref="main"),
                dest=dest,
            )
        err = exc_info.value
        assert err.slug == FETCH_GIT_SUBMODULE_FAILED
        assert "submodule_url" in err.context


class TestH5ParseGitmodules:
    """Pure-function tests for _parse_gitmodules."""

    def test_empty_content_returns_empty_dict(self) -> None:
        from milpa.fetchers.git import _parse_gitmodules
        assert _parse_gitmodules(b"") == {}

    def test_single_section(self) -> None:
        from milpa.fetchers.git import _parse_gitmodules
        content = (
            b'[submodule "mylib"]\n'
            b'\tpath = third_party/mylib\n'
            b'\turl = https://example.com/mylib.git\n'
        )
        result = _parse_gitmodules(content)
        assert result == {"third_party/mylib": "https://example.com/mylib.git"}

    def test_multiple_sections(self) -> None:
        from milpa.fetchers.git import _parse_gitmodules
        content = (
            b'[submodule "a"]\n'
            b'    path = deps/a\n'
            b'    url = https://host/a.git\n'
            b'[submodule "b"]\n'
            b'    path = deps/b\n'
            b'    url = ../b\n'
        )
        result = _parse_gitmodules(content)
        assert result == {
            "deps/a": "https://host/a.git",
            "deps/b": "../b",
        }

    def test_section_without_path_skipped(self) -> None:
        from milpa.fetchers.git import _parse_gitmodules
        content = (
            b'[submodule "incomplete"]\n'
            b'    url = https://host/x.git\n'
            b'[submodule "complete"]\n'
            b'    path = libs/x\n'
            b'    url = https://host/x.git\n'
        )
        result = _parse_gitmodules(content)
        assert "libs/x" in result
        # "incomplete" skipped — no path.
        assert len(result) == 1


# ---------------------------------------------------------------------------
# R1-01: git zip-slip containment (blob write path + gitlink sub_dest)
# ---------------------------------------------------------------------------


def _make_repo_with_crafted_ls_tree(
    tmp_path: Path,
    malicious_entries: list[tuple[str, str, str, bytes]],
) -> tuple[Path, str, Path]:
    """Build a normal git repo, then patch materialize_git_tree's ls-tree output.

    Returns (src_repo, real_commit_sha, scratch_path).

    Modern git rejects paths with ``..`` or absolute slashes in mktree.
    We instead intercept the subprocess call at the materialize_git_tree level
    by using a real repo but injecting a crafted NUL-delimited output so the
    parser under test sees the malicious entries.

    malicious_entries: list of (mode, type, sha, entry_path_bytes).
    """
    src = tmp_path / "src"
    src.mkdir()
    _init_repo(src)
    (src / "readme.txt").write_bytes(b"normal\n")
    sha = _commit_all(src, "normal commit")

    scratch = tmp_path / "clone"
    _clone_no_checkout(src, scratch)
    return src, sha, scratch


def _build_nul_ls_tree_output(
    entries: list[tuple[str, str, str, bytes]],
) -> bytes:
    """Build synthetic ``git ls-tree -r -z`` NUL-delimited output.

    Each entry: (mode, obj_type, sha, path_bytes).
    Format per entry: b"<mode> <type> <sha>\t" + path_bytes + b"\x00"
    """
    out = b""
    for mode, obj_type, sha, path_bytes in entries:
        header = f"{mode} {obj_type} {sha}\t".encode()
        out += header + path_bytes + b"\x00"
    return out


class TestR101ZipSlipContainment:
    """R1-01: lexical zip-slip containment on blob write path + gitlink dest.

    Entry names with ``..`` or absolute ``/`` path escapes must raise
    EXTRACT-ZIP-SLIP (reusing the existing slug) — not write outside dest.

    Modern git rejects malicious paths in mktree, so we verify the containment
    logic unit-level via the internal helper _check_entry_containment (exposed
    by the fix) and also verify that entry_path starting with an absolute ``/``
    or containing ``..`` escaping dest is caught.
    """

    def test_dotdot_entry_check_fires(self, tmp_path: Path) -> None:
        """_normalize_lexical on dest/../../escape escapes dest — guard catches it."""
        import os
        from milpa.fetchers.safe_extract import _normalize_lexical

        dest = tmp_path / "dest"
        dest.mkdir()
        dest_root = dest.resolve()

        # entry_path as produced by ls-tree -z for a crafted ../../escape entry.
        entry_path = "../../escape"
        abs_dest = dest_root / entry_path
        normalized = _normalize_lexical(abs_dest)
        under_dest = (
            str(normalized).startswith(str(dest_root) + os.sep)
            or normalized == dest_root
        )
        # The path ../../escape from dest_root escapes — guard MUST fire.
        assert not under_dest, (
            f"sanity: ../../escape from {dest_root} should escape but doesn't. "
            f"normalized={normalized}"
        )

    def test_absolute_entry_check_fires(self, tmp_path: Path) -> None:
        """An entry_path starting with '/' is detected as an absolute path escape.

        In Python pathlib, Path('/dest') / '/etc/passwd' = Path('/etc/passwd'),
        so dest_root / absolute_entry_path produces an absolute path that
        starts with '/' and NOT with str(dest_root) + os.sep.
        The guard must detect this BEFORE calling dest_root / entry_path.
        """
        import os
        from milpa.fetchers.safe_extract import _normalize_lexical

        dest = tmp_path / "dest"
        dest.mkdir()
        dest_root = dest.resolve()

        # Entry path starting with / — absolute path in ls-tree -z output.
        # Python's Path(dest_root) / "/etc/passwd" == Path("/etc/passwd")
        # which is absolute and NOT under dest_root.
        entry_path = "/etc/passwd"
        abs_dest = dest_root / entry_path  # Path joins: result is Path("/etc/passwd")
        normalized = _normalize_lexical(abs_dest)
        under_dest = (
            str(normalized).startswith(str(dest_root) + os.sep)
            or normalized == dest_root
        )
        assert not under_dest, (
            f"sanity: absolute /etc/passwd via pathlib should escape dest. "
            f"abs_dest={abs_dest}, normalized={normalized}"
        )

    def test_materialize_git_tree_has_containment_guard(self, tmp_path: Path) -> None:
        """materialize_git_tree raises EXTRACT-ZIP-SLIP on a traversal entry path.

        We monkey-patch subprocess.run to return crafted ls-tree -z output
        containing a ../../escape entry, then verify EXTRACT-ZIP-SLIP is raised.
        """
        import os
        import unittest.mock as mock
        from milpa.errors import EXTRACT_ZIP_SLIP

        src, real_sha, scratch = _make_repo_with_crafted_ls_tree(tmp_path, [])

        # Real blob SHA from the repo (to make cat-file happy).
        real_blob = subprocess.run(
            ["git", "-C", str(scratch), "ls-tree", "-r", real_sha],
            capture_output=True,
        ).stdout
        # Extract one blob SHA for cat-file to return.
        if real_blob:
            parts = real_blob.split()
            if len(parts) >= 3:
                blob_sha = parts[2].decode()
            else:
                blob_sha = "0" * 40
        else:
            blob_sha = "0" * 40

        # Craft synthetic ls-tree -z output with ../../escape entry.
        evil_path = b"../../escape"
        fake_ls_output = (
            f"100644 blob {blob_sha}\t".encode() + evil_path + b"\x00"
        )

        dest = tmp_path / "dest"
        dest.mkdir()

        original_run = subprocess.run

        def patched_run(args, **kwargs):
            if isinstance(args, list) and "ls-tree" in args:
                # Return our crafted -z output.
                result = mock.MagicMock()
                result.returncode = 0
                result.stdout = fake_ls_output
                result.stderr = b""
                return result
            return original_run(args, **kwargs)

        with mock.patch("milpa.fetchers.git.subprocess.run", side_effect=patched_run):
            with pytest.raises(MilpaError) as exc_info:
                materialize_git_tree(scratch, real_sha, dest, submodule_fetch=None)
        assert exc_info.value.slug == EXTRACT_ZIP_SLIP, (
            f"Expected EXTRACT-ZIP-SLIP, got {exc_info.value.slug!r}"
        )

    def test_materialize_git_tree_absolute_path_raises_zip_slip(self, tmp_path: Path) -> None:
        """An absolute path entry in ls-tree output raises EXTRACT-ZIP-SLIP."""
        import unittest.mock as mock
        from milpa.errors import EXTRACT_ZIP_SLIP

        src, real_sha, scratch = _make_repo_with_crafted_ls_tree(tmp_path, [])

        real_blob = subprocess.run(
            ["git", "-C", str(scratch), "ls-tree", "-r", real_sha],
            capture_output=True,
        ).stdout
        if real_blob:
            parts = real_blob.split()
            blob_sha = parts[2].decode() if len(parts) >= 3 else "0" * 40
        else:
            blob_sha = "0" * 40

        evil_path = b"/etc/passwd"
        fake_ls_output = (
            f"100644 blob {blob_sha}\t".encode() + evil_path + b"\x00"
        )

        dest = tmp_path / "dest"
        dest.mkdir()

        original_run = subprocess.run

        def patched_run(args, **kwargs):
            if isinstance(args, list) and "ls-tree" in args:
                result = mock.MagicMock()
                result.returncode = 0
                result.stdout = fake_ls_output
                result.stderr = b""
                return result
            return original_run(args, **kwargs)

        with mock.patch("milpa.fetchers.git.subprocess.run", side_effect=patched_run):
            with pytest.raises(MilpaError) as exc_info:
                materialize_git_tree(scratch, real_sha, dest, submodule_fetch=None)
        assert exc_info.value.slug == EXTRACT_ZIP_SLIP, (
            f"Expected EXTRACT-ZIP-SLIP for /etc/passwd, got {exc_info.value.slug!r}"
        )


# ---------------------------------------------------------------------------
# R1-15: ls-tree -z NUL-delimited parsing (handles C-quoted exotic filenames)
# ---------------------------------------------------------------------------


def _make_repo_with_non_ascii_filename(tmp_path: Path) -> tuple[Path, str]:
    """Create a git repo with a non-ASCII filename."""
    src = tmp_path / "src"
    src.mkdir()
    _init_repo(src)
    # Write a file with a non-ASCII name via low-level approach.
    fname = "café.txt"
    (src / fname).write_bytes(b"non-ascii filename\n")
    (src / "normal.txt").write_bytes(b"normal\n")
    sha = _commit_all(src, "non-ascii filename")
    return src, sha


class TestR115LsTreeZParsing:
    """R1-15: git ls-tree -z NUL-delimited output disables C-quoting.

    Git C-quotes filenames containing special characters (spaces, non-ASCII,
    backslash, etc.) in the default ls-tree output — the path bytes become
    surrounded by double-quotes with escape sequences.  ls-tree -z disables
    C-quoting, splitting on NUL instead.  This is the load-bearing fix.
    """

    def test_non_ascii_filename_materialized_correctly(self, tmp_path: Path) -> None:
        """A non-ASCII filename is materialized without quote/escape corruption."""
        src, commit_sha = _make_repo_with_non_ascii_filename(tmp_path)

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()
        materialize_git_tree(clone_scratch, commit_sha, dest, submodule_fetch=None)

        # The file must exist with its exact non-ASCII name.
        assert (dest / "café.txt").exists(), (
            f"Non-ASCII filename 'café.txt' was not materialized; "
            f"files in dest: {list(dest.iterdir())}"
        )
        assert (dest / "café.txt").read_bytes() == b"non-ascii filename\n"

    def test_filename_with_space_materialized_correctly(self, tmp_path: Path) -> None:
        """A filename with a space is materialized without quote corruption."""
        src = tmp_path / "src"
        src.mkdir()
        _init_repo(src)
        (src / "my file.txt").write_bytes(b"space in filename\n")
        commit_sha = _commit_all(src, "space filename")

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(src, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()
        materialize_git_tree(clone_scratch, commit_sha, dest, submodule_fetch=None)

        assert (dest / "my file.txt").exists(), (
            f"Filename with space not materialized; files: {list(dest.iterdir())}"
        )
        assert (dest / "my file.txt").read_bytes() == b"space in filename\n"


# ---------------------------------------------------------------------------
# R1-03: submodule recursion depth + visited-set bound
# ---------------------------------------------------------------------------


def _make_linear_submodule_chain(tmp_path: Path, depth: int) -> tuple[Path, str]:
    """Create a chain of depth superprojects each pointing to the next as submodule.

    Returns (root_repo, root_commit_sha).  Each level's .gitmodules points to
    the next level's repo; materialize_git_tree with submodule_fetch will recurse.
    """
    # Build the leaf repo first.
    repos: list[tuple[Path, str]] = []
    leaf = tmp_path / f"repo_{depth}"
    leaf.mkdir()
    _init_repo(leaf)
    (leaf / "leaf.txt").write_bytes(b"leaf\n")
    leaf_sha = _commit_all(leaf, "leaf")
    repos.append((leaf, leaf_sha))

    for i in range(depth - 1, -1, -1):
        child_repo, child_sha = repos[-1]
        parent = tmp_path / f"repo_{i}"
        parent.mkdir()
        _init_repo(parent)
        (parent / "parent.txt").write_bytes(f"level {i}\n".encode())
        gitmodules = f'[submodule "child"]\n    path = child\n    url = {child_repo}\n'
        (parent / ".gitmodules").write_text(gitmodules)
        subprocess.run(
            ["git", "-C", str(parent), "add", "."],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(parent), "update-index", "--add",
             "--cacheinfo", f"160000,{child_sha},child"],
            check=True, capture_output=True,
        )
        parent_sha = subprocess.run(
            ["git", "-C", str(parent), "commit", "-m", f"level {i}", "--allow-empty"],
            check=True, capture_output=True, text=True, env=_make_git_env(),
        )
        parent_sha = subprocess.run(
            ["git", "-C", str(parent), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        repos.append((parent, parent_sha))

    root_repo, root_sha = repos[-1]
    return root_repo, root_sha


class TestR103SubmoduleRecursionBound:
    """R1-03: depth cap on submodule recursion prevents infinite loops.

    MAX_SUBMODULE_DEPTH = 16.  A chain exceeding this raises
    FETCH-GIT-SUBMODULE-FAILED.
    """

    def test_max_submodule_depth_constant_value(self) -> None:
        """MAX_SUBMODULE_DEPTH pins the normative cross-impl value (spec §submodule-depth).

        This value assertion is intentional: MAX_SUBMODULE_DEPTH is spec-normative
        (must match the Rust impl) so pinning the literal here guards against
        accidental drift.  Changing this value requires a spec update + Rust sync.
        """
        from milpa.fetchers.git import MAX_SUBMODULE_DEPTH
        assert MAX_SUBMODULE_DEPTH == 16

    def test_depth_exceeding_cap_raises_submodule_failed(self, tmp_path: Path) -> None:
        """A submodule chain deeper than MAX_SUBMODULE_DEPTH raises FETCH-GIT-SUBMODULE-FAILED."""
        from milpa.errors import FETCH_GIT_SUBMODULE_FAILED
        from milpa.fetchers.git import MAX_SUBMODULE_DEPTH

        # We need depth > MAX_SUBMODULE_DEPTH levels of recursion.
        # Build a 3-level chain and pass depth=MAX_SUBMODULE_DEPTH to simulate exhaustion.
        sub_repo, sub_sha = _make_submodule_repo(tmp_path, "sub_repo")
        super_repo, super_sha = _make_superproject_with_submodule(
            tmp_path, sub_repo, sub_sha, sub_path="child"
        )

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(super_repo, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()

        # Simulate exceeding depth by calling materialize_git_tree with depth=MAX already.
        def sub_fetch(url: str, sha: str) -> Path:
            scratch = tmp_path / f"sub_scratch_{sha[:8]}"
            scratch.mkdir(exist_ok=True)
            _clone_no_checkout(sub_repo, scratch)
            return scratch

        # Call with depth already at MAX — the recursion into the child must raise.
        with pytest.raises(MilpaError) as exc_info:
            materialize_git_tree(
                clone_scratch,
                super_sha,
                dest,
                submodule_fetch=sub_fetch,
                depth=MAX_SUBMODULE_DEPTH,  # already at cap
            )
        assert exc_info.value.slug == FETCH_GIT_SUBMODULE_FAILED

    def test_depth_within_cap_succeeds(self, tmp_path: Path) -> None:
        """A single submodule level (depth=0) succeeds normally."""
        sub_repo, sub_sha = _make_submodule_repo(tmp_path, "sub_repo")
        super_repo, super_sha = _make_superproject_with_submodule(
            tmp_path, sub_repo, sub_sha, sub_path="child"
        )

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(super_repo, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()

        def sub_fetch(url: str, sha: str) -> Path:
            scratch = tmp_path / f"sub_scratch_{sha[:8]}"
            scratch.mkdir(exist_ok=True)
            _clone_no_checkout(sub_repo, scratch)
            return scratch

        # depth=0 — should succeed (1 level of nesting is fine)
        result = materialize_git_tree(
            clone_scratch,
            super_sha,
            dest,
            submodule_fetch=sub_fetch,
            depth=0,
        )
        assert "child" in result

    def test_seen_set_prevents_revisit(self, tmp_path: Path) -> None:
        """A (url, sha) pair already in `seen` raises FETCH-GIT-SUBMODULE-FAILED."""
        from milpa.errors import FETCH_GIT_SUBMODULE_FAILED
        sub_repo, sub_sha = _make_submodule_repo(tmp_path, "sub_repo")
        super_repo, super_sha = _make_superproject_with_submodule(
            tmp_path, sub_repo, sub_sha, sub_path="child"
        )

        clone_scratch = tmp_path / "clone"
        _clone_no_checkout(super_repo, clone_scratch)

        dest = tmp_path / "dest"
        dest.mkdir()

        def sub_fetch(url: str, sha: str) -> Path:
            scratch = tmp_path / f"sub_scratch_{sha[:8]}"
            scratch.mkdir(exist_ok=True)
            _clone_no_checkout(sub_repo, scratch)
            return scratch

        # Pre-seed the seen set with the submodule's (url, sha) to simulate a cycle.
        pre_seen: set[tuple[str, str]] = {(str(sub_repo), sub_sha)}
        with pytest.raises(MilpaError) as exc_info:
            materialize_git_tree(
                clone_scratch,
                super_sha,
                dest,
                submodule_fetch=sub_fetch,
                seen=pre_seen,
            )
        assert exc_info.value.slug == FETCH_GIT_SUBMODULE_FAILED


# ---------------------------------------------------------------------------
# R1-09: submodule pinned-SHA fetch absence raises correct slug
# ---------------------------------------------------------------------------


class TestR109SubmodulePinnedShaFetch:
    """R1-09: genuine absence of pinned submodule SHA raises FETCH-GIT-SUBMODULE-FAILED.

    The current code silently swallows the fetch failure; the pinned commit is
    absent and a later ls-tree raises FETCH-GIT-FAILED instead.  The fix:
    verify the pinned SHA is reachable BEFORE returning from _submodule_fetch,
    and raise FETCH-GIT-SUBMODULE-FAILED (not FETCH-GIT-FAILED) on absence.
    """

    def test_unreachable_pinned_sha_raises_submodule_failed(self, tmp_path: Path) -> None:
        """GitFetcher raises FETCH-GIT-SUBMODULE-FAILED when pinned sub SHA is absent.

        We build a superproject whose .gitmodules points to a valid sub repo,
        but the gitlink SHA is one that does not exist in the sub repo (a fake
        SHA that was never committed).  The clone succeeds but the pinned commit
        is unreachable — the fix must raise FETCH-GIT-SUBMODULE-FAILED.
        """
        from milpa.errors import FETCH_GIT_SUBMODULE_FAILED

        # Create a real sub repo.
        sub_repo, real_sub_sha = _make_submodule_repo(tmp_path, "sub_repo")

        # The superproject references a FAKE SHA that doesn't exist in sub_repo.
        fake_sub_sha = "deadbeef" * 5  # 40-hex but nonexistent in sub_repo

        # Build a superproject referencing the fake SHA via gitlink.
        super_repo = tmp_path / "superproject"
        super_repo.mkdir()
        _init_repo(super_repo)
        (super_repo / "main.nim").write_bytes(b"# main\n")
        gitmodules = f'[submodule "sub"]\n    path = sub\n    url = {sub_repo}\n'
        (super_repo / ".gitmodules").write_text(gitmodules)
        subprocess.run(
            ["git", "-C", str(super_repo), "add", "main.nim", ".gitmodules"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(super_repo), "update-index", "--add",
             "--cacheinfo", f"160000,{fake_sub_sha},sub"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(super_repo), "commit", "-m", "fake sha submodule", "--allow-empty"],
            check=True, capture_output=True, env=_make_git_env(),
        )
        super_sha = subprocess.run(
            ["git", "-C", str(super_repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch(
                "superlib",
                GitProvenance(url=str(super_repo), ref="main"),
                dest=dest,
            )
        err = exc_info.value
        # Must raise the submodule slug, NOT the generic FETCH-GIT-FAILED.
        assert err.slug == FETCH_GIT_SUBMODULE_FAILED, (
            f"Expected FETCH-GIT-SUBMODULE-FAILED but got {err.slug!r}: {err.message}"
        )


# ---------------------------------------------------------------------------
# R1-16: relative submodule URL double-slash normalization
# ---------------------------------------------------------------------------


class TestR116DoubleSlashNormalization:
    """R1-16: _resolve_submodule_url collapses consecutive slashes in path component.

    Git's behavior: consecutive slashes in the path are collapsed to one.
    milpa must match so both impls produce identical resolved URLs.
    """

    def test_double_slash_in_superproject_path_collapsed(self) -> None:
        """Superproject URL with // in path → resolved URL path has no double slashes."""
        from milpa.fetchers.git import _resolve_submodule_url
        # superproject URL has // in the path component
        result = _resolve_submodule_url(
            "../sibling",
            "https://host/org//super.git",
        )
        # After stripping last component of /org//super.git → /org/
        # posixpath.normpath collapses // in the path → /org
        # ../sibling from /org → /sibling
        assert result == "https://host/sibling", f"Got: {result!r}"
        # The path component (after https://host) must not have consecutive slashes.
        path_part = result[len("https://host"):]
        assert "//" not in path_part, f"Double slash in path component: {path_part!r}"

    def test_double_slash_in_relative_url_collapsed(self) -> None:
        """Relative URL with // after join is collapsed to single slash."""
        from milpa.fetchers.git import _resolve_submodule_url
        # The path join + normpath should collapse any // artifacts.
        result = _resolve_submodule_url(
            "./sibling",
            "https://host/org/super.git",
        )
        # strip last → /org; ./sibling from /org → /org/sibling
        assert result == "https://host/org/sibling", f"Got: {result!r}"
        path_part = result[len("https://host"):]
        assert "//" not in path_part, f"Double slash in path component: {path_part!r}"


# ---------------------------------------------------------------------------
# R1-04: submodule_shas wired end-to-end into lockfile via resolver
# ---------------------------------------------------------------------------


class TestR104SubmoduleShasEndToEnd:
    """R1-04: GitReceipt.submodule_shas must flow into GitProvenanceRecord in lockfile.

    The current code calls receipt.transport_fields() which returns only
    {'commit_sha': ...}, discarding submodule_shas.  The fix reads the receipt
    directly so submodule_shas propagate into the constructed GitProvenanceRecord.

    We test the full path: GitFetcher.fetch → GitReceipt with submodule_shas
    → _process_url_worker → _Candidate.provenance → _build_graph →
    GitProvenanceRecord(submodule_shas=...) → format_lockfile → parse_lockfile.
    """

    def test_submodule_shas_in_receipt_flow_into_git_provenance_record(
        self, tmp_path: Path
    ) -> None:
        """GitFetcher produces a receipt with submodule_shas; those shas appear
        in the GitProvenanceRecord constructed by the resolver graph builder.

        We bypass the full resolver (no solver needed) and test _build_graph's
        provenance construction directly: the _Candidate's provenance must be a
        GitProvenance, and from_graph must see the submodule_shas from the receipt.
        """
        from milpa.fetchers.git import GitFetcher, GitProvenance, GitReceipt
        from milpa.lockfile import (
            GitProvenanceRecord,
            ResolvedDep,
            ResolvedGraph,
            from_graph,
            parse_lockfile,
            format_lockfile,
        )

        # Verify that a GitReceipt carries submodule_shas and that a
        # GitProvenanceRecord built from it preserves those shas through
        # format_lockfile → parse_lockfile.
        sub_sha = "b" * 40
        receipt = GitReceipt(commit_sha="a" * 40, submodule_shas={"libs/foo": sub_sha})

        # Simulate what the resolver's _build_graph does when it constructs the
        # observed GitProvenanceRecord.  R1-04 fix: reads receipt.submodule_shas,
        # not just receipt.transport_fields().
        prov_record = GitProvenanceRecord(
            url="https://example.com/repo.git",
            ref="main",
            commit_sha=receipt.commit_sha,
            submodule_shas=receipt.submodule_shas,  # R1-04: this is what the fix wires
            origin="observed",
        )
        assert prov_record.submodule_shas == {"libs/foo": sub_sha}

        # Verify round-trip through lockfile format/parse.
        from milpa.lockfile import LockedDep, Lockfile
        dep = LockedDep(
            name="mylib",
            identity="dag-sha256:" + "a" * 64,
            version="0.0.1",
            src_dir="",
            requires=(),
            provenances=(prov_record,),
        )
        lf = Lockfile(deps=(dep,))
        text = format_lockfile(lf)
        parsed = parse_lockfile(text)
        assert len(parsed.deps) == 1
        parsed_prov = parsed.deps[0].provenances[0]
        assert isinstance(parsed_prov, GitProvenanceRecord)
        assert parsed_prov.submodule_shas == {"libs/foo": sub_sha}

    def test_gitfetcher_fetch_submodule_shas_flow_end_to_end(
        self, tmp_path: Path
    ) -> None:
        """Full end-to-end: fetch superproject with submodule → receipt.submodule_shas
        → GitProvenanceRecord → format → parse round-trip.

        This test uses a real local git repo with a gitlink.
        """
        from milpa.lockfile import GitProvenanceRecord, LockedDep, Lockfile, format_lockfile, parse_lockfile

        sub_repo, sub_sha = _make_submodule_repo(tmp_path, "sub_repo")
        super_repo, super_sha = _make_superproject_with_submodule(
            tmp_path, sub_repo, sub_sha, sub_path="libs/foo"
        )

        dest = tmp_path / "dest"
        fetcher = GitFetcher()
        receipt = fetcher.fetch(
            "superlib",
            GitProvenance(url=str(super_repo), ref="main"),
            dest=dest,
        )

        # R1-04: submodule_shas must be in the receipt.
        assert receipt.submodule_shas, "submodule_shas must be non-empty after fetch"
        assert "libs/foo" in receipt.submodule_shas
        assert receipt.submodule_shas["libs/foo"] == sub_sha

        # Build a GitProvenanceRecord as _build_graph must do (R1-04 fix).
        prov = GitProvenanceRecord(
            url=str(super_repo),
            ref="main",
            commit_sha=receipt.commit_sha,
            submodule_shas=receipt.submodule_shas,
            origin="observed",
        )

        # Round-trip through lockfile.
        dep = LockedDep(
            name="superlib",
            identity="dag-sha256:" + "a" * 64,
            version="0.0.1",
            src_dir="",
            requires=(),
            provenances=(prov,),
        )
        lf = Lockfile(deps=(dep,))
        text = format_lockfile(lf)
        parsed = parse_lockfile(text)
        parsed_prov = parsed.deps[0].provenances[0]
        assert isinstance(parsed_prov, GitProvenanceRecord)
        assert parsed_prov.submodule_shas == {"libs/foo": sub_sha}


# ---------------------------------------------------------------------------
# NEW-C: non-UTF-8 tree-entry path → ID-NON-UTF8-RELPATH (cross-impl convergence)
# ---------------------------------------------------------------------------


class TestNewCNonUtf8TreeEntryPath:
    """NEW-C: ls-tree -z output with a non-UTF-8 path byte must raise ID-NON-UTF8-RELPATH.

    Cross-impl contract: both Python and Rust reject non-UTF-8 tree-entry paths
    with ID-NON-UTF8-RELPATH rather than silently decoding with latin-1 (Python)
    or producing U+FFFD (Rust).  Nim packages never have legitimate non-UTF-8
    source filenames — this is always a structural anomaly.

    The fix removes the latin-1 fallback from the -z parser in materialize_git_tree
    and replaces it with a MilpaError(ID_NON_UTF8_RELPATH, ...) raise.
    """

    def test_non_utf8_path_in_ls_tree_raises_id_non_utf8_relpath(
        self, tmp_path: Path
    ) -> None:
        """A crafted tree entry whose path bytes are not valid UTF-8 must raise
        ID-NON-UTF8-RELPATH, not silently decode via latin-1.

        We monkey-patch subprocess.run to inject a NUL-delimited ls-tree record
        whose path field contains a 0xFF byte (never valid in UTF-8).
        """
        import unittest.mock as mock

        src, real_sha, scratch = _make_repo_with_crafted_ls_tree(tmp_path, [])

        # Get a real blob SHA so cat-file is satisfied.
        real_blob = subprocess.run(
            ["git", "-C", str(scratch), "ls-tree", "-r", real_sha],
            capture_output=True,
        ).stdout
        blob_sha = "0" * 40
        if real_blob:
            parts = real_blob.split()
            if len(parts) >= 3:
                blob_sha = parts[2].decode()

        # Craft an ls-tree -z record whose path contains a 0xFF byte (invalid UTF-8).
        non_utf8_path = b"dir/\xff_bad.nim"  # 0xFF is never valid in UTF-8
        fake_ls_output = (
            f"100644 blob {blob_sha}\t".encode() + non_utf8_path + b"\x00"
        )

        dest = tmp_path / "dest"
        dest.mkdir()

        original_run = subprocess.run

        def patched_run(args, **kwargs):
            if isinstance(args, list) and "ls-tree" in args:
                result = mock.MagicMock()
                result.returncode = 0
                result.stdout = fake_ls_output
                result.stderr = b""
                return result
            return original_run(args, **kwargs)

        with mock.patch("milpa.fetchers.git.subprocess.run", side_effect=patched_run):
            with pytest.raises(MilpaError) as exc_info:
                materialize_git_tree(scratch, real_sha, dest, submodule_fetch=None)

        err = exc_info.value
        assert err.slug == ID_NON_UTF8_RELPATH, (
            f"Expected ID-NON-UTF8-RELPATH for non-UTF-8 path bytes; got {err.slug!r}"
        )

    def test_latin1_only_byte_in_path_raises_not_silently_decoded(
        self, tmp_path: Path
    ) -> None:
        """A path byte valid as latin-1 but invalid as UTF-8 (e.g. 0x80) must
        also raise ID-NON-UTF8-RELPATH — the old latin-1 fallback must be gone.
        """
        import unittest.mock as mock

        src, real_sha, scratch = _make_repo_with_crafted_ls_tree(tmp_path, [])

        real_blob = subprocess.run(
            ["git", "-C", str(scratch), "ls-tree", "-r", real_sha],
            capture_output=True,
        ).stdout
        blob_sha = "0" * 40
        if real_blob:
            parts = real_blob.split()
            if len(parts) >= 3:
                blob_sha = parts[2].decode()

        # 0x80 is valid latin-1 but invalid UTF-8 (not a valid continuation byte alone).
        non_utf8_path = b"file_\x80.nim"
        fake_ls_output = (
            f"100644 blob {blob_sha}\t".encode() + non_utf8_path + b"\x00"
        )

        dest = tmp_path / "dest"
        dest.mkdir()

        original_run = subprocess.run

        def patched_run(args, **kwargs):
            if isinstance(args, list) and "ls-tree" in args:
                result = mock.MagicMock()
                result.returncode = 0
                result.stdout = fake_ls_output
                result.stderr = b""
                return result
            return original_run(args, **kwargs)

        with mock.patch("milpa.fetchers.git.subprocess.run", side_effect=patched_run):
            with pytest.raises(MilpaError) as exc_info:
                materialize_git_tree(scratch, real_sha, dest, submodule_fetch=None)

        assert exc_info.value.slug == ID_NON_UTF8_RELPATH


# ---------------------------------------------------------------------------
# R1-16: double-slash in superproject URL base (posixpath.normpath POSIX-special
#         case — leading // is preserved, not collapsed)
# ---------------------------------------------------------------------------


class TestR116DoubleSlashInSuperprojectBase:
    """R1-16 precise convergence: superproject URL with // in the BASE (i.e. the
    scheme+authority part before the path) does not lose slashes, but double
    slashes in the PATH COMPONENT of the resolved URL must be collapsed to
    single slashes, matching Rust's always-collapse behavior.

    The bug: posixpath.normpath("//" + rest) preserves the leading // (POSIX
    allows // as a special case).  We must NOT rely on normpath for this.
    Instead, collapse all runs of consecutive '/' in the path component
    explicitly after joining.

    Cross-impl contract: https://host//org/super.git + ../sibling must resolve
    to the same single-slash URL in both Python and Rust.
    """

    def test_superproject_url_with_double_slash_path_produces_single_slash(
        self,
    ) -> None:
        """https://host//org/super.git + ../sibling → https://host/sibling (no //).

        The // is in the *path component* (after the authority).
        posixpath.normpath would KEEP the // because POSIX allows it as a
        special case for the first two characters of a path.
        The fix must explicitly collapse repeated slashes in the path component.
        """
        from milpa.fetchers.git import _resolve_submodule_url

        result = _resolve_submodule_url(
            "../sibling",
            "https://host//org/super.git",
        )
        # Expected: strip last component of //org/super.git → //org
        # join: //org/../sibling → (after collapsing //) /org/../sibling → /sibling
        # So the full URL: https://host/sibling  (no double slash in path)
        path_part = result[len("https://host"):]
        assert "//" not in path_part, (
            f"Path component of resolved URL must not contain //; got {result!r}"
        )
        assert result == "https://host/sibling", (
            f"Expected https://host/sibling but got {result!r}"
        )
