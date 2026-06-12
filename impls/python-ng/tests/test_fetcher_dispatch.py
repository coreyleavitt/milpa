"""Cross-dispatch regression test — SSOT provenance classes route to both real and mocked
fetchers.

Guards the SSOT unification: after deleting the duplicate Provenance/Receipt
definitions from mocked.py, every provenance class is defined exactly once.
This test proves that the *same* class object (no aliasing, no duck-typing
coincidence) is recognized by BOTH a real-fetcher registry (_build_default_registry)
AND a mocked-fetcher registry (mocked_registry).

If the duplication ever returns, isinstance checks in the two registries will
use different classes and the cross-registry dispatch will fail.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.fetchers import (
    GitFetcher,
    GitProvenance,
    GitReceipt,
    TarballFetcher,
    TarballProvenance,
    TarballReceipt,
    _build_default_registry,
)
from milpa.fetchers.mocked import (
    MockedGitFetcher,
    MockedTarballFetcher,
    mocked_registry,
    url_key,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_git_fixture(mocked_dir: Path, url: str, ref: str, sha: str) -> None:
    """Minimal git fixture: just the sha file + empty content dir."""
    key_dir = mocked_dir / url_key(url, ref)
    key_dir.mkdir(parents=True, exist_ok=True)
    (key_dir / "sha").write_text(sha + "\n", encoding="utf-8")
    (key_dir / "content").mkdir(exist_ok=True)
    (key_dir / "content" / "stub.nim").write_bytes(b"# stub")


def _make_tarball_fixture(mocked_dir: Path, url: str, sha: str) -> None:
    """Minimal tarball fixture."""
    key_dir = mocked_dir / url_key(url, "")
    key_dir.mkdir(parents=True, exist_ok=True)
    (key_dir / "archive_sha256").write_text(sha + "\n", encoding="utf-8")
    (key_dir / "content").mkdir(exist_ok=True)
    (key_dir / "content" / "stub.nim").write_bytes(b"# tarball stub")


# ---------------------------------------------------------------------------
# GitProvenance: same class dispatched by both real and mocked registries
# ---------------------------------------------------------------------------


class TestGitProvenanceCrossDispatch:
    """GitProvenance (from milpa.fetchers.git) is the canonical class.

    After the SSOT unification both registries must recognize it via the same
    isinstance check — not two parallel class objects.
    """

    URL = "https://github.com/example/ssot-test.git"
    REF = "main"
    SHA = "a" * 40

    def test_real_registry_claims_git_provenance(self) -> None:
        """_build_default_registry() has exactly one GitFetcher that claims GitProvenance."""
        prov = GitProvenance(url=self.URL, ref=self.REF)
        registry = _build_default_registry()
        claims = [f for f in registry.fetchers if f.can_handle(prov)]
        assert len(claims) == 1, (
            f"expected exactly 1 fetcher to claim GitProvenance; got {len(claims)}: "
            f"{[type(f).__name__ for f in claims]}"
        )
        assert isinstance(claims[0], GitFetcher)

    def test_mocked_registry_claims_git_provenance(self, tmp_path: Path) -> None:
        """mocked_registry() has exactly one MockedGitFetcher that claims GitProvenance."""
        prov = GitProvenance(url=self.URL, ref=self.REF)
        registry = mocked_registry(tmp_path)
        claims = [f for f in registry.fetchers if f.can_handle(prov)]
        assert len(claims) == 1, (
            f"expected exactly 1 mocked fetcher to claim GitProvenance; got {len(claims)}: "
            f"{[type(f).__name__ for f in claims]}"
        )
        assert isinstance(claims[0], MockedGitFetcher)

    def test_same_provenance_instance_dispatches_in_both_registries(
        self, tmp_path: Path
    ) -> None:
        """The EXACT SAME GitProvenance object is claimed by both registries.

        This is the core SSOT regression guard: if the mocked registry used a
        different GitProvenance class (a duplicate definition), can_handle would
        return False here and the test would catch the regression.
        """
        prov = GitProvenance(url=self.URL, ref=self.REF)

        real_reg = _build_default_registry()
        real_claims = [f for f in real_reg.fetchers if f.can_handle(prov)]

        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        mock_reg = mocked_registry(mocked_dir)
        mock_claims = [f for f in mock_reg.fetchers if f.can_handle(prov)]

        assert len(real_claims) == 1, "real registry must claim exactly one fetcher"
        assert len(mock_claims) == 1, "mocked registry must claim exactly one fetcher"
        assert isinstance(real_claims[0], GitFetcher)
        assert isinstance(mock_claims[0], MockedGitFetcher)

    def test_mocked_registry_fetch_produces_git_receipt(self, tmp_path: Path) -> None:
        """End-to-end: mocked_registry.fetch returns a GitReceipt (canonical class)."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_git_fixture(mocked_dir, self.URL, self.REF, self.SHA)

        prov = GitProvenance(url=self.URL, ref=self.REF)
        registry = mocked_registry(mocked_dir)
        dest = tmp_path / "_deps" / "ssot-test"

        result = registry.fetch("ssot-test", prov, dest=dest)

        assert isinstance(result.receipt, GitReceipt), (
            f"expected GitReceipt (from milpa.fetchers.git); "
            f"got {type(result.receipt).__name__}"
        )
        assert result.receipt.commit_sha == self.SHA
        assert result.identity.startswith("sha256:")


# ---------------------------------------------------------------------------
# TarballProvenance: same class dispatched by both real and mocked registries
# ---------------------------------------------------------------------------


class TestTarballProvenanceCrossDispatch:
    """TarballProvenance (from milpa.fetchers.tarball) is the canonical class."""

    URL = "https://releases.example.com/v1/ssot-pkg.tar.gz"
    SHA = "b" * 64

    def test_real_registry_claims_tarball_provenance(self) -> None:
        """_build_default_registry() has exactly one TarballFetcher claiming TarballProvenance."""
        prov = TarballProvenance(url=self.URL)
        registry = _build_default_registry()
        claims = [f for f in registry.fetchers if f.can_handle(prov)]
        assert len(claims) == 1, (
            f"expected exactly 1 fetcher to claim TarballProvenance; got {len(claims)}: "
            f"{[type(f).__name__ for f in claims]}"
        )
        assert isinstance(claims[0], TarballFetcher)

    def test_mocked_registry_claims_tarball_provenance(self, tmp_path: Path) -> None:
        """mocked_registry() has exactly one MockedTarballFetcher that claims TarballProvenance."""
        prov = TarballProvenance(url=self.URL)
        registry = mocked_registry(tmp_path)
        claims = [f for f in registry.fetchers if f.can_handle(prov)]
        assert len(claims) == 1, (
            f"expected exactly 1 mocked fetcher to claim TarballProvenance; got {len(claims)}: "
            f"{[type(f).__name__ for f in claims]}"
        )
        assert isinstance(claims[0], MockedTarballFetcher)

    def test_same_provenance_instance_dispatches_in_both_registries(
        self, tmp_path: Path
    ) -> None:
        """The EXACT SAME TarballProvenance object is claimed by both registries."""
        prov = TarballProvenance(url=self.URL)

        real_reg = _build_default_registry()
        real_claims = [f for f in real_reg.fetchers if f.can_handle(prov)]

        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        mock_reg = mocked_registry(mocked_dir)
        mock_claims = [f for f in mock_reg.fetchers if f.can_handle(prov)]

        assert len(real_claims) == 1, "real registry must claim exactly one fetcher"
        assert len(mock_claims) == 1, "mocked registry must claim exactly one fetcher"
        assert isinstance(real_claims[0], TarballFetcher)
        assert isinstance(mock_claims[0], MockedTarballFetcher)

    def test_mocked_registry_fetch_produces_tarball_receipt(self, tmp_path: Path) -> None:
        """End-to-end: mocked_registry.fetch returns a TarballReceipt (canonical class)."""
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_tarball_fixture(mocked_dir, self.URL, self.SHA)

        prov = TarballProvenance(url=self.URL)
        registry = mocked_registry(mocked_dir)
        dest = tmp_path / "_deps" / "ssot-pkg"

        result = registry.fetch("ssot-pkg", prov, dest=dest)

        assert isinstance(result.receipt, TarballReceipt), (
            f"expected TarballReceipt (from milpa.fetchers.tarball); "
            f"got {type(result.receipt).__name__}"
        )
        assert result.receipt.archive_sha256 == self.SHA
        assert result.identity.startswith("sha256:")

    def test_expected_sha256_field_name_is_canonical(self) -> None:
        """TarballProvenance uses expected_sha256 (canonical field), not sha256."""
        # Constructing with the old 'sha256' kwarg must raise TypeError.
        with pytest.raises(TypeError):
            TarballProvenance(url=self.URL, sha256="abc")  # type: ignore[call-arg]

        # Constructing with the canonical 'expected_sha256' must succeed.
        prov = TarballProvenance(url=self.URL, expected_sha256=self.SHA)
        assert prov.expected_sha256 == self.SHA
