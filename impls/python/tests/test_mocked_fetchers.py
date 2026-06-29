"""Tests for milpa.fetchers.mocked — url_key SSOT + per-kind mocked fetchers (slice 7c).

Coverage:
  - url_key encoding: safe chars preserved; unsafe chars → '_'; '@' separator literal;
    tarball empty-ref form; Rust cross-check on two representative URLs.
  - MockedGitFetcher: staged content from fixture dir; commit SHA from 'sha' file.
  - MockedTarballFetcher: staged content; archive_sha256 from fixture; TOFU pin
    re-assertion (FETCH-SHA256-MISMATCH on mismatch); first-fetch (no prior pin) succeeds.
  - MockedOciFetcher: stub raises FETCH-MOCK-MISSING.
  - mocked_registry factory: all four kinds claimed; exclusive dispatch (no
    ambiguity). Local deps use the REAL LocalFetcher (filesystem-native).
  - cas_admissible per kind: Git/Tarball/OCI = True; Local = False.
  - receipt transport_fields non-empty for all concrete receipts.

Spec authority: spec/conformance-fixtures.md §2.3, spec/plugin-contract.md §4.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from milpa.errors import FETCH_EXTRACT_FAILED, FETCH_MOCK_MISSING, FETCH_SHA256_MISMATCH, MilpaError
from milpa.fetchers.mocked import (
    GitProvenance,
    GitReceipt,
    LocalProvenance,
    MockedGitFetcher,
    MockedOciFetcher,
    MockedTarballFetcher,
    OciProvenance,
    TarballProvenance,
    TarballReceipt,
    mocked_registry,
    url_key,
)
from milpa.fetchers.local import LocalFetcher
from milpa.fetchers.types import FetcherRegistry

# ---------------------------------------------------------------------------
# url_key encoding
# ---------------------------------------------------------------------------


class TestUrlKey:
    """§2.3.1 NORMATIVE — every character outside [A-Za-z0-9._-] replaced by '_';
    '@' separator literal; ref portion uses same substitution."""

    def test_safe_chars_preserved(self) -> None:
        # alphanumeric, dot, underscore, dash — all safe
        assert url_key("foo-bar_1.2", "v1.0") == "foo-bar_1.2@v1.0"

    def test_scheme_colons_and_slashes_replaced(self) -> None:
        result = url_key("https://github.com/example/foo.git", "main")
        assert result == "https___github.com_example_foo.git@main"

    def test_at_in_ref_replaced(self) -> None:
        # A '@' within the ref is replaced by '_', not kept as literal.
        result = url_key("https://example.com/pkg.git", "v1@beta")
        assert result == "https___example.com_pkg.git@v1_beta"

    def test_tarball_empty_ref(self) -> None:
        # Tarballs use url_key(url, "") — ref slot is empty → trailing '@'.
        result = url_key("https://example.com/pkg.tar.gz", "")
        assert result == "https___example.com_pkg.tar.gz@"

    def test_local_path_as_url(self) -> None:
        # Local mocked key uses url_key(path, "") per SSOT rule.
        result = url_key("/home/user/mylib", "")
        assert result == "_home_user_mylib@"

    def test_separator_is_literal_at(self) -> None:
        # Exactly one literal '@' separates the encoded url and encoded ref.
        result = url_key("https://a.example.com/b", "main")
        url_part, sep, ref_part = result.partition("@")
        assert sep == "@"
        assert url_part == "https___a.example.com_b"
        assert ref_part == "main"

    def test_rust_cross_check_github_main(self) -> None:
        """Cross-check against the Rust url_key output.

        Rust: url_key("https://github.com/example/foo.git", "main")
              → "https___github.com_example_foo.git@main"

        This is the canonical example from conformance-fixtures.md §2.3.1.
        """
        expected = "https___github.com_example_foo.git@main"
        assert url_key("https://github.com/example/foo.git", "main") == expected

    def test_rust_cross_check_tarball_empty_ref(self) -> None:
        """Cross-check tarball form against Rust.

        Rust: url_key("https://releases.example.com/v1/pkg.tar.gz", "")
              → "https___releases.example.com_v1_pkg.tar.gz@"
        """
        expected = "https___releases.example.com_v1_pkg.tar.gz@"
        assert url_key("https://releases.example.com/v1/pkg.tar.gz", "") == expected


# ---------------------------------------------------------------------------
# Fixture tree builder helper
# ---------------------------------------------------------------------------


def _make_git_fixture(
    mocked_dir: Path,
    url: str,
    ref: str,
    sha: str,
    files: dict[str, bytes] | None = None,
    nimble: str | None = None,
    nimble_name: str | None = None,
) -> Path:
    """Create a git mock fixture directory under mocked_dir."""
    key_dir = mocked_dir / url_key(url, ref)
    key_dir.mkdir(parents=True)
    (key_dir / "sha").write_text(sha + "\n", encoding="utf-8")
    content = key_dir / "content"
    content.mkdir()
    if files:
        for rel, data in files.items():
            fp = content / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(data)
    if nimble is not None:
        name = nimble_name or "pkg"
        (key_dir / f"{name}.nimble").write_text(nimble, encoding="utf-8")
    return key_dir


def _make_tarball_fixture(
    mocked_dir: Path,
    url: str,
    archive_sha256: str,
    files: dict[str, bytes] | None = None,
) -> Path:
    """Create a tarball mock fixture directory under mocked_dir."""
    key_dir = mocked_dir / url_key(url, "")
    key_dir.mkdir(parents=True)
    (key_dir / "archive_sha256").write_text(archive_sha256 + "\n", encoding="utf-8")
    content = key_dir / "content"
    content.mkdir()
    if files:
        for rel, data in files.items():
            fp = content / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(data)
    return key_dir


# ---------------------------------------------------------------------------
# MockedGitFetcher
# ---------------------------------------------------------------------------


class TestMockedGitFetcher:
    URL = "https://github.com/example/foo.git"
    REF = "main"
    SHA = "a" * 40  # 40-char lowercase hex

    def _fetcher(self, mocked_dir: Path) -> MockedGitFetcher:
        return MockedGitFetcher(mocked_dir)

    def test_returns_commit_sha_in_receipt(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_git_fixture(mocked_dir, self.URL, self.REF, self.SHA)
        fetcher = self._fetcher(mocked_dir)
        prov = GitProvenance(url=self.URL, ref=self.REF)
        dest = tmp_path / "_deps" / "foo"

        receipt = fetcher.fetch("foo", prov, dest=dest)

        assert isinstance(receipt, GitReceipt)
        assert receipt.commit_sha == self.SHA

    def test_stages_content_files(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        files = {"src/foo.nim": b"# foo", "README.md": b"readme"}
        _make_git_fixture(mocked_dir, self.URL, self.REF, self.SHA, files=files)
        fetcher = self._fetcher(mocked_dir)
        prov = GitProvenance(url=self.URL, ref=self.REF)
        dest = tmp_path / "_deps" / "foo"

        fetcher.fetch("foo", prov, dest=dest)

        assert (dest / "src" / "foo.nim").read_bytes() == b"# foo"
        assert (dest / "README.md").read_bytes() == b"readme"

    def test_stages_nimble_file(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        nimble_content = 'requires "nim >= 1.0.0"\n'
        _make_git_fixture(
            mocked_dir, self.URL, self.REF, self.SHA,
            nimble=nimble_content, nimble_name="foo",
        )
        fetcher = self._fetcher(mocked_dir)
        prov = GitProvenance(url=self.URL, ref=self.REF)
        dest = tmp_path / "_deps" / "foo"

        fetcher.fetch("foo", prov, dest=dest)

        assert (dest / "foo.nimble").read_text(encoding="utf-8") == nimble_content

    def test_missing_fixture_raises_fetch_mock_missing(
        self, tmp_path: Path
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        fetcher = self._fetcher(mocked_dir)
        prov = GitProvenance(url=self.URL, ref=self.REF)
        dest = tmp_path / "_deps" / "foo"

        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("foo", prov, dest=dest)

        assert exc_info.value.slug == FETCH_MOCK_MISSING

    def test_can_handle_git_provenance(self, tmp_path: Path) -> None:
        fetcher = self._fetcher(tmp_path)
        assert fetcher.can_handle(GitProvenance(url="https://x.com/a.git", ref="main"))

    def test_cannot_handle_tarball_provenance(self, tmp_path: Path) -> None:
        fetcher = self._fetcher(tmp_path)
        assert not fetcher.can_handle(TarballProvenance(url="https://x.com/a.tar.gz"))

    def test_receipt_transport_fields_non_empty(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_git_fixture(mocked_dir, self.URL, self.REF, self.SHA)
        fetcher = self._fetcher(mocked_dir)
        prov = GitProvenance(url=self.URL, ref=self.REF)
        dest = tmp_path / "_deps" / "foo"

        receipt = fetcher.fetch("foo", prov, dest=dest)
        assert receipt.transport_fields()  # must be non-empty

    def test_sha_file_whitespace_stripped(self, tmp_path: Path) -> None:
        """sha file may have trailing newline; SHA is stripped."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        key_dir = mocked_dir / url_key(self.URL, self.REF)
        key_dir.mkdir(parents=True)
        (key_dir / "sha").write_text(f"  {self.SHA}  \n", encoding="utf-8")
        (key_dir / "content").mkdir()
        fetcher = self._fetcher(mocked_dir)
        prov = GitProvenance(url=self.URL, ref=self.REF)
        dest = tmp_path / "_deps" / "foo"

        receipt = fetcher.fetch("foo", prov, dest=dest)
        assert receipt.commit_sha == self.SHA


# ---------------------------------------------------------------------------
# MockedTarballFetcher
# ---------------------------------------------------------------------------


class TestMockedTarballFetcher:
    URL = "https://releases.example.com/v1/pkg.tar.gz"
    ARCHIVE_SHA = "b" * 64  # 64 hex chars = sha256

    def _fetcher(self, mocked_dir: Path) -> MockedTarballFetcher:
        return MockedTarballFetcher(mocked_dir)

    def test_returns_archive_sha256_in_receipt(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_tarball_fixture(mocked_dir, self.URL, self.ARCHIVE_SHA)
        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL)
        dest = tmp_path / "_deps" / "pkg"

        receipt = fetcher.fetch("pkg", prov, dest=dest)

        assert isinstance(receipt, TarballReceipt)
        assert receipt.archive_sha256 == self.ARCHIVE_SHA

    def test_stages_content_files(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        files = {"lib.nim": b"# lib"}
        _make_tarball_fixture(mocked_dir, self.URL, self.ARCHIVE_SHA, files=files)
        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL)
        dest = tmp_path / "_deps" / "pkg"

        fetcher.fetch("pkg", prov, dest=dest)

        assert (dest / "lib.nim").read_bytes() == b"# lib"

    def test_first_fetch_no_pin_succeeds(self, tmp_path: Path) -> None:
        """expected_sha256=None (first fetch, no TOFU pin yet) must succeed."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_tarball_fixture(mocked_dir, self.URL, self.ARCHIVE_SHA)
        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL, expected_sha256=None)
        dest = tmp_path / "_deps" / "pkg"

        receipt = fetcher.fetch("pkg", prov, dest=dest)
        assert receipt.archive_sha256 == self.ARCHIVE_SHA

    def test_pin_matches_archive_sha_succeeds(self, tmp_path: Path) -> None:
        """expected_sha256 pin matching the fixture archive_sha256 must succeed."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_tarball_fixture(mocked_dir, self.URL, self.ARCHIVE_SHA)
        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL, expected_sha256=self.ARCHIVE_SHA)
        dest = tmp_path / "_deps" / "pkg"

        receipt = fetcher.fetch("pkg", prov, dest=dest)
        assert receipt.archive_sha256 == self.ARCHIVE_SHA

    def test_pin_with_sha256_prefix_matches(self, tmp_path: Path) -> None:
        """sha256:<hex> prefix form is accepted (stripped before comparison)."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_tarball_fixture(mocked_dir, self.URL, self.ARCHIVE_SHA)
        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL, expected_sha256=f"sha256:{self.ARCHIVE_SHA}")
        dest = tmp_path / "_deps" / "pkg"

        receipt = fetcher.fetch("pkg", prov, dest=dest)
        assert receipt.archive_sha256 == self.ARCHIVE_SHA

    def test_tofu_pin_mismatch_raises_sha256_mismatch(self, tmp_path: Path) -> None:
        """TOFU refetch with wrong expected_sha256 must raise FETCH-SHA256-MISMATCH (§2.3.4)."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_tarball_fixture(mocked_dir, self.URL, self.ARCHIVE_SHA)
        fetcher = self._fetcher(mocked_dir)
        wrong_sha = "c" * 64
        prov = TarballProvenance(url=self.URL, expected_sha256=wrong_sha)
        dest = tmp_path / "_deps" / "pkg"

        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("pkg", prov, dest=dest)

        assert exc_info.value.slug == FETCH_SHA256_MISMATCH

    def test_tofu_mismatch_no_content_staged(self, tmp_path: Path) -> None:
        """SHA mismatch is detected before staging any content (§2.3.4 NORMATIVE)."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        files = {"sentinel.nim": b"should not appear"}
        _make_tarball_fixture(mocked_dir, self.URL, self.ARCHIVE_SHA, files=files)
        fetcher = self._fetcher(mocked_dir)
        wrong_sha = "d" * 64
        prov = TarballProvenance(url=self.URL, expected_sha256=wrong_sha)
        dest = tmp_path / "_deps" / "pkg"
        dest.mkdir(parents=True)

        with pytest.raises(MilpaError):
            fetcher.fetch("pkg", prov, dest=dest)

        # dest must not contain staged files
        assert not (dest / "sentinel.nim").exists()

    def test_missing_fixture_raises_fetch_mock_missing(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL)
        dest = tmp_path / "_deps" / "pkg"

        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("pkg", prov, dest=dest)

        assert exc_info.value.slug == FETCH_MOCK_MISSING

    def test_can_handle_tarball_provenance(self, tmp_path: Path) -> None:
        fetcher = self._fetcher(tmp_path)
        assert fetcher.can_handle(TarballProvenance(url="https://x.com/a.tar.gz"))

    def test_cannot_handle_git_provenance(self, tmp_path: Path) -> None:
        fetcher = self._fetcher(tmp_path)
        assert not fetcher.can_handle(GitProvenance(url="https://x.com/a.git", ref="main"))

    def test_receipt_transport_fields_non_empty(self, tmp_path: Path) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_tarball_fixture(mocked_dir, self.URL, self.ARCHIVE_SHA)
        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL)
        dest = tmp_path / "_deps" / "pkg"

        receipt = fetcher.fetch("pkg", prov, dest=dest)
        assert receipt.transport_fields()

    def test_tarball_key_uses_empty_ref(self, tmp_path: Path) -> None:
        """Tarball fixture key is url_key(url, "") — empty ref slot (§2.3.4)."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_tarball_fixture(mocked_dir, self.URL, self.ARCHIVE_SHA)
        # The key directory name must end with '@' (empty ref slot).
        key = url_key(self.URL, "")
        assert key.endswith("@"), f"tarball key {key!r} must end with '@'"
        assert (mocked_dir / key).is_dir()

    def test_pin_uppercase_bare_hex_matches(self, tmp_path: Path) -> None:
        """UPPERCASE expected_sha256 must match the lowercase fixture archive_sha256."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_tarball_fixture(mocked_dir, self.URL, self.ARCHIVE_SHA)
        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL, expected_sha256=self.ARCHIVE_SHA.upper())
        dest = tmp_path / "_deps" / "pkg"

        receipt = fetcher.fetch("pkg", prov, dest=dest)
        assert receipt.archive_sha256 == self.ARCHIVE_SHA

    def test_pin_uppercase_prefixed_matches(self, tmp_path: Path) -> None:
        """sha256:<UPPERCASE-HEX> expected form must match the lowercase fixture sha256."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_tarball_fixture(mocked_dir, self.URL, self.ARCHIVE_SHA)
        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(
            url=self.URL,
            expected_sha256=f"sha256:{self.ARCHIVE_SHA.upper()}",
        )
        dest = tmp_path / "_deps" / "pkg"

        receipt = fetcher.fetch("pkg", prov, dest=dest)
        assert receipt.archive_sha256 == self.ARCHIVE_SHA


# ---------------------------------------------------------------------------
# S4a — raw-bytes mode ("archive" file) tests
# ---------------------------------------------------------------------------


def _make_valid_tgz(files: dict[str, bytes]) -> bytes:
    """Build a real .tar.gz in memory from a dict of {name: bytes}."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        inner = io.BytesIO()
        with tarfile.open(fileobj=inner, mode="w") as tf:
            for name, data in files.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        gz.write(inner.getvalue())
    return buf.getvalue()


class TestMockedTarballFetcherRawBytesMode:
    """S4a: raw-bytes mode — ``archive`` file fed through the REAL extractor."""

    URL = "https://releases.example.com/s4a/pkg.tar.gz"

    def _fetcher(self, mocked_dir: Path) -> MockedTarballFetcher:
        return MockedTarballFetcher(mocked_dir)

    def _key_dir(self, mocked_dir: Path) -> Path:
        key_dir = mocked_dir / url_key(self.URL, "")
        key_dir.mkdir(parents=True, exist_ok=True)
        return key_dir

    def test_valid_archive_extracted_via_real_extractor(self, tmp_path: Path) -> None:
        """Test 1 (S4a): valid .tar.gz in ``archive`` → real decompressor runs,
        content is extracted, receipt.archive_sha256 == sha256(raw bytes)."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        key_dir = self._key_dir(mocked_dir)

        archive_bytes = _make_valid_tgz({"lib.nim": b"# s4a raw-bytes test"})
        expected_sha = hashlib.sha256(archive_bytes).hexdigest()
        (key_dir / "archive").write_bytes(archive_bytes)

        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL)
        dest = tmp_path / "_deps" / "pkg"

        receipt = fetcher.fetch("pkg", prov, dest=dest)

        # Content was extracted (real extractor ran, not a verbatim copy).
        assert isinstance(receipt, TarballReceipt)
        assert (dest / "lib.nim").read_bytes() == b"# s4a raw-bytes test"
        # archive_sha256 in receipt == sha256(raw bytes) — same as real fetcher.
        assert receipt.archive_sha256 == expected_sha

    def test_corrupt_archive_raises_fetch_extract_failed(self, tmp_path: Path) -> None:
        """Test 2 (S4a): garbage bytes in ``archive`` → real extractor raises
        FETCH-EXTRACT-FAILED (corruption propagates; mocked fetcher does NOT swallow)."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        key_dir = self._key_dir(mocked_dir)

        # Bytes that start with gzip magic but are corrupt (not a valid gzip stream).
        # The real gzip decompressor fails → FETCH-EXTRACT-FAILED.
        corrupt = b"\x1f\x8b" + b"this is not a valid gzip stream at all"
        (key_dir / "archive").write_bytes(corrupt)

        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL)
        dest = tmp_path / "_deps" / "pkg"

        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("pkg", prov, dest=dest)

        assert exc_info.value.slug == FETCH_EXTRACT_FAILED

    def test_archive_takes_precedence_over_format_and_content(self, tmp_path: Path) -> None:
        """Test 3 (S4a): ``archive`` file wins when both ``archive`` and
        ``format``/``content/`` are present — extracted content matches the archive,
        not the content/ build."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        key_dir = self._key_dir(mocked_dir)

        # archive file: extracts "from_archive.nim"
        archive_bytes = _make_valid_tgz({"from_archive.nim": b"archive-wins"})
        (key_dir / "archive").write_bytes(archive_bytes)

        # format + content/: would extract "from_content.nim" if chosen
        (key_dir / "format").write_text("gz", encoding="utf-8")
        content_dir = key_dir / "content"
        content_dir.mkdir()
        (content_dir / "from_content.nim").write_bytes(b"content-loses")

        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL)
        dest = tmp_path / "_deps" / "pkg"

        fetcher.fetch("pkg", prov, dest=dest)

        # archive wins: from_archive.nim present, from_content.nim absent
        assert (dest / "from_archive.nim").read_bytes() == b"archive-wins"
        assert not (dest / "from_content.nim").exists()


# ---------------------------------------------------------------------------
# MockedOciFetcher (stub)
# ---------------------------------------------------------------------------


class TestMockedOciFetcher:
    def test_always_raises_fetch_mock_missing(self, tmp_path: Path) -> None:
        fetcher = MockedOciFetcher(tmp_path)
        prov = OciProvenance(
            registry="registry.example.com",
            repository="foo/bar",
            digest="sha256:" + "e" * 64,
        )
        dest = tmp_path / "_deps" / "ocipkg"

        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("ocipkg", prov, dest=dest)

        assert exc_info.value.slug == FETCH_MOCK_MISSING

    def test_can_handle_oci_provenance(self, tmp_path: Path) -> None:
        fetcher = MockedOciFetcher(tmp_path)
        prov = OciProvenance(
            registry="registry.example.com",
            repository="foo/bar",
            digest="sha256:" + "e" * 64,
        )
        assert fetcher.can_handle(prov)

    def test_cannot_handle_git_provenance(self, tmp_path: Path) -> None:
        fetcher = MockedOciFetcher(tmp_path)
        assert not fetcher.can_handle(GitProvenance(url="https://x.com/a.git", ref="main"))


# ---------------------------------------------------------------------------
# mocked_registry factory
# ---------------------------------------------------------------------------


class TestMockedRegistry:
    def test_returns_fetcher_registry(self, tmp_path: Path) -> None:
        registry = mocked_registry(tmp_path)
        assert isinstance(registry, FetcherRegistry)

    def test_registers_four_fetchers(self, tmp_path: Path) -> None:
        registry = mocked_registry(tmp_path)
        assert len(registry.fetchers) == 4

    def test_git_dispatch_unique(self, tmp_path: Path) -> None:
        """Exactly one fetcher claims GitProvenance (exclusive dispatch)."""
        registry = mocked_registry(tmp_path)
        prov = GitProvenance(url="https://x.com/a.git", ref="main")
        claims = [f for f in registry.fetchers if f.can_handle(prov)]
        assert len(claims) == 1
        assert isinstance(claims[0], MockedGitFetcher)

    def test_tarball_dispatch_unique(self, tmp_path: Path) -> None:
        registry = mocked_registry(tmp_path)
        prov = TarballProvenance(url="https://x.com/a.tar.gz")
        claims = [f for f in registry.fetchers if f.can_handle(prov)]
        assert len(claims) == 1
        assert isinstance(claims[0], MockedTarballFetcher)

    def test_local_dispatch_unique(self, tmp_path: Path) -> None:
        registry = mocked_registry(tmp_path)
        prov = LocalProvenance(path=Path("/some/path"))
        claims = [f for f in registry.fetchers if f.can_handle(prov)]
        assert len(claims) == 1
        # Local deps are filesystem-native: mocked_registry uses the REAL
        # LocalFetcher (Slice C "205"), matching the in-process adapter.
        assert isinstance(claims[0], LocalFetcher)

    def test_oci_dispatch_unique(self, tmp_path: Path) -> None:
        registry = mocked_registry(tmp_path)
        prov = OciProvenance(
            registry="registry.example.com",
            repository="foo/bar",
            digest="sha256:" + "f" * 64,
        )
        claims = [f for f in registry.fetchers if f.can_handle(prov)]
        assert len(claims) == 1
        assert isinstance(claims[0], MockedOciFetcher)

    def test_git_fetches_from_fixture(self, tmp_path: Path) -> None:
        """End-to-end: mocked_registry dispatches to MockedGitFetcher and returns result."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        url = "https://github.com/example/bar.git"
        ref = "v1.0.0"
        sha = "0" * 40
        _make_git_fixture(mocked_dir, url, ref, sha, files={"bar.nim": b"# bar"})
        registry = mocked_registry(mocked_dir)
        prov = GitProvenance(url=url, ref=ref)
        dest = tmp_path / "_deps" / "bar"

        result = registry.fetch("bar", prov, dest=dest)

        assert isinstance(result.receipt, GitReceipt)
        assert result.receipt.commit_sha == sha
        assert (dest / "bar.nim").read_bytes() == b"# bar"
        assert result.identity.startswith("dag-sha256:")


# ---------------------------------------------------------------------------
# cas_admissible per provenance kind
# ---------------------------------------------------------------------------


class TestCasAdmissiblePerKind:
    def test_git_is_cas_admissible(self) -> None:
        assert GitProvenance.cas_admissible is True

    def test_tarball_is_cas_admissible(self) -> None:
        assert TarballProvenance.cas_admissible is True

    def test_oci_is_cas_admissible(self) -> None:
        assert OciProvenance.cas_admissible is True

    def test_local_is_not_cas_admissible(self) -> None:
        assert LocalProvenance.cas_admissible is False

    def test_git_instance_is_cas_admissible(self) -> None:
        p = GitProvenance(url="https://x.com/a.git", ref="main")
        assert p.cas_admissible is True

    def test_local_instance_is_not_cas_admissible(self) -> None:
        p = LocalProvenance(path=Path("/tmp/x"))
        assert p.cas_admissible is False


# ---------------------------------------------------------------------------
# P2-1 regression — strip_components threaded through raw-bytes and build modes
# ---------------------------------------------------------------------------


def _make_tgz_with_prefix(prefix: str, files: dict[str, bytes]) -> bytes:
    """Build a .tar.gz whose entries have ``prefix/`` prepended to each name.

    For example, ``prefix="pkg-1.0"`` + ``files={"lib.nim": b"..."}`` produces
    an archive entry ``pkg-1.0/lib.nim`` — the canonical top-level-dir form that
    ``strip_components=1`` is designed to handle.
    """
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        inner = io.BytesIO()
        with tarfile.open(fileobj=inner, mode="w") as tf:
            for name, data in files.items():
                arcname = f"{prefix}/{name}"
                info = tarfile.TarInfo(name=arcname)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        gz.write(inner.getvalue())
    return buf.getvalue()


class TestStripComponentsThreaded:
    """Regression for P2-1: strip_components must NOT be silently dropped in
    raw-bytes mode (``archive`` file) or build mode (``format`` file).

    Before the fix, both call sites passed only ``p.url`` to
    ``_run_bytes_through_real_fetcher``, so the dep's declared
    ``strip_components`` was always discarded (defaulted to 0).  That meant
    ``dest/`` received ``prefix/lib.nim`` instead of ``lib.nim`` when
    strip_components=1 was declared.
    """

    URL = "https://releases.example.com/strip/pkg.tar.gz"

    def _fetcher(self, mocked_dir: Path) -> MockedTarballFetcher:
        return MockedTarballFetcher(mocked_dir)

    def _key_dir(self, mocked_dir: Path) -> Path:
        key_dir = mocked_dir / url_key(self.URL, "")
        key_dir.mkdir(parents=True, exist_ok=True)
        return key_dir

    # -- raw-bytes mode (``archive`` file) --

    def test_raw_bytes_strip_components_applied(self, tmp_path: Path) -> None:
        """P2-1 raw-bytes path: strip_components=1 from provenance must be
        forwarded to the real extractor so the leading path component is stripped."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        key_dir = self._key_dir(mocked_dir)

        # Archive has entries like ``pkg-1.0/lib.nim`` — strip_components=1
        # should strip the ``pkg-1.0/`` prefix and place ``lib.nim`` at dest root.
        archive_bytes = _make_tgz_with_prefix("pkg-1.0", {"lib.nim": b"# stripped"})
        (key_dir / "archive").write_bytes(archive_bytes)

        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL, strip_components=1)
        dest = tmp_path / "_deps" / "pkg"

        fetcher.fetch("pkg", prov, dest=dest)

        # With strip_components=1 correctly applied, lib.nim appears at dest root.
        assert (dest / "lib.nim").read_bytes() == b"# stripped"
        # The prefixed path must NOT exist (would appear if strip_components was dropped).
        assert not (dest / "pkg-1.0").exists()

    def test_raw_bytes_strip_components_zero_keeps_prefix(self, tmp_path: Path) -> None:
        """Baseline: strip_components=0 (default) leaves the prefix directory."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        key_dir = self._key_dir(mocked_dir)

        archive_bytes = _make_tgz_with_prefix("pkg-1.0", {"lib.nim": b"# no strip"})
        (key_dir / "archive").write_bytes(archive_bytes)

        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL, strip_components=0)
        dest = tmp_path / "_deps" / "pkg"

        fetcher.fetch("pkg", prov, dest=dest)

        # No stripping: prefix dir is present.
        assert (dest / "pkg-1.0" / "lib.nim").read_bytes() == b"# no strip"

    # -- build mode (``format`` file) --

    def test_build_mode_strip_components_applied(self, tmp_path: Path) -> None:
        """P2-1 build-mode path: strip_components=1 from provenance must be
        forwarded when the archive is built from content/ via the ``format`` file."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        key_dir = self._key_dir(mocked_dir)

        # Build mode: format + content/ — _build_archive_from_content wraps files
        # with NO prefix (arcname = relative path from content/), so we put the
        # prefix directory in the content/ tree itself to simulate the real layout.
        (key_dir / "format").write_text("gz", encoding="utf-8")
        content_dir = key_dir / "content"
        prefix_dir = content_dir / "pkg-1.0"
        prefix_dir.mkdir(parents=True)
        (prefix_dir / "lib.nim").write_bytes(b"# build strip")

        fetcher = self._fetcher(mocked_dir)
        prov = TarballProvenance(url=self.URL, strip_components=1)
        dest = tmp_path / "_deps" / "pkg"

        fetcher.fetch("pkg", prov, dest=dest)

        # strip_components=1 strips ``pkg-1.0/`` → lib.nim at root.
        assert (dest / "lib.nim").read_bytes() == b"# build strip"
        assert not (dest / "pkg-1.0").exists()
