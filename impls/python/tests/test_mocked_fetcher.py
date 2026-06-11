"""Unit tests for MockedFetcher and url_key (milpa/fetchers/mocked.py).

Covers:
- url_key encoding matches §2.3.1 examples.
- MockedFetcher.fetch reads sha + copies content/ + copies <name>.nimble.
- Missing key → FetchError with code "FETCH-MOCK-MISSING".
"""

import pytest
from pathlib import Path

from milpa.fetchers.git import GitProvenance
from milpa.fetchers.mocked import MockedFetcher, url_key
from milpa.fetchers.types import FetchError


# ---------------------------------------------------------------------------
# url_key encoding
# ---------------------------------------------------------------------------

def test_url_key_encodes_github_https_url():
    """§2.3.1 example: https://github.com/example/foo.git @ main."""
    result = url_key("https://github.com/example/foo.git", "main")
    assert result == "https___github.com_example_foo.git@main"


def test_url_key_encodes_ref_with_slashes():
    """Slashes in ref are encoded like any other non-safe character."""
    result = url_key("https://github.com/org/repo.git", "refs/heads/dev")
    assert result == "https___github.com_org_repo.git@refs_heads_dev"


def test_url_key_leaves_safe_chars_intact():
    """Alphanumeric, '.', '_', '-' pass through unchanged."""
    result = url_key("https://example.org/pkg-1.0.git", "v1.2-stable")
    assert result == "https___example.org_pkg-1.0.git@v1.2-stable"


# ---------------------------------------------------------------------------
# MockedFetcher.fetch — success path
# ---------------------------------------------------------------------------

def _make_mock_dir(root: Path, url: str, ref: str, *, sha: str, files: dict[str, str]) -> Path:
    """Build a mocked-fetches/<key>/ directory tree for testing."""
    key = url_key(url, ref)
    key_dir = root / key
    key_dir.mkdir(parents=True)
    (key_dir / "sha").write_text(sha + "\n")
    content_dir = key_dir / "content"
    content_dir.mkdir()
    for fname, content in files.items():
        (content_dir / fname).write_text(content)
    return key_dir


def test_mocked_fetcher_fetch_returns_correct_commit_sha(tmp_path):
    """fetch() reads sha from the key dir and returns it in the receipt."""
    url = "https://github.com/example/foo.git"
    ref = "main"
    sha = "abcdef1234567890abcdef1234567890abcdef12"
    mocked_dir = tmp_path / "mocked-fetches"
    _make_mock_dir(mocked_dir, url, ref, sha=sha, files={"foo.nim": "# foo\n"})

    fetcher = MockedFetcher(mocked_fetches_dir=mocked_dir)
    dest = tmp_path / "_deps" / "foo"
    receipt = fetcher.fetch("foo", GitProvenance(url=url, ref=ref), dest=dest)

    assert receipt.commit_sha == sha


def test_mocked_fetcher_fetch_copies_content_tree(tmp_path):
    """fetch() copies content/ files into dest."""
    url = "https://github.com/example/foo.git"
    ref = "main"
    mocked_dir = tmp_path / "mocked-fetches"
    _make_mock_dir(
        mocked_dir, url, ref,
        sha="abcdef1234567890abcdef1234567890abcdef12",
        files={"foo.nim": "let x = 1\n", "README.md": "# foo\n"},
    )

    fetcher = MockedFetcher(mocked_fetches_dir=mocked_dir)
    dest = tmp_path / "_deps" / "foo"
    fetcher.fetch("foo", GitProvenance(url=url, ref=ref), dest=dest)

    assert (dest / "foo.nim").read_text() == "let x = 1\n"
    assert (dest / "README.md").read_text() == "# foo\n"


def test_mocked_fetcher_fetch_copies_nimble_if_present(tmp_path):
    """fetch() copies <name>.nimble into dest when it exists in the key dir."""
    url = "https://github.com/example/bar.git"
    ref = "v1.0"
    sha = "1234567890abcdef1234567890abcdef12345678"
    mocked_dir = tmp_path / "mocked-fetches"
    key_dir = _make_mock_dir(mocked_dir, url, ref, sha=sha, files={})
    # nimble file is a sibling of content/, not inside it
    (key_dir / "bar.nimble").write_text('requires "nim >= 1.6"\n')

    fetcher = MockedFetcher(mocked_fetches_dir=mocked_dir)
    dest = tmp_path / "_deps" / "bar"
    fetcher.fetch("bar", GitProvenance(url=url, ref=ref), dest=dest)

    assert (dest / "bar.nimble").read_text() == 'requires "nim >= 1.6"\n'


def test_mocked_fetcher_no_nimble_is_fine(tmp_path):
    """fetch() succeeds even when no <name>.nimble exists in the key dir."""
    url = "https://github.com/example/baz.git"
    ref = "main"
    mocked_dir = tmp_path / "mocked-fetches"
    _make_mock_dir(mocked_dir, url, ref, sha="a" * 40, files={"baz.nim": ""})

    fetcher = MockedFetcher(mocked_fetches_dir=mocked_dir)
    dest = tmp_path / "_deps" / "baz"
    receipt = fetcher.fetch("baz", GitProvenance(url=url, ref=ref), dest=dest)

    assert receipt.commit_sha == "a" * 40
    assert not (dest / "baz.nimble").exists()


# ---------------------------------------------------------------------------
# MockedFetcher.fetch — missing key → FETCH-MOCK-MISSING
# ---------------------------------------------------------------------------

def test_mocked_fetcher_missing_key_raises_fetch_mock_missing(tmp_path):
    """When the key dir is absent, FetchError with code FETCH-MOCK-MISSING is raised."""
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()  # empty — no keys

    fetcher = MockedFetcher(mocked_fetches_dir=mocked_dir)
    dest = tmp_path / "_deps" / "missing"

    with pytest.raises(FetchError) as exc_info:
        fetcher.fetch(
            "missing",
            GitProvenance(url="https://github.com/example/missing.git", ref="main"),
            dest=dest,
        )

    assert exc_info.value.code == "FETCH-MOCK-MISSING"


# ---------------------------------------------------------------------------
# MockedFetcher.can_handle
# ---------------------------------------------------------------------------

def test_mocked_fetcher_can_handle_git_provenance():
    from milpa.fetchers.git import GitProvenance
    f = MockedFetcher(mocked_fetches_dir=Path("/nonexistent"))
    assert f.can_handle(GitProvenance(url="https://x.git", ref="main")) is True


def test_mocked_fetcher_cannot_handle_other_provenance():
    from milpa.fetchers.tarball import TarballProvenance
    f = MockedFetcher(mocked_fetches_dir=Path("/nonexistent"))
    assert f.can_handle(TarballProvenance(url="https://x.tar.gz", expected_sha256="abc")) is False
