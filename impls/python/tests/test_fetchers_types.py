"""Tests for milpa.fetchers.types (slices 7a + 7e).

Coverage:
  - FetcherConfig v1 shape (§7.1)
  - Provenance.cas_admissible defaults + override
  - ProvenanceReceipt.transport_fields abstractmethod enforcement
  - Fetcher ABC enforcement (can_handle / fetch must be implemented)
  - FetcherRegistry: unique-match dispatch
      - exactly-one-claims → dispatch succeeds
      - ambiguous (two fetchers claim) → uncoded FetchError (code=None)
      - no-handler (zero fetchers claim) → uncoded FetchError (code=None)
  - FetcherRegistry: FETCH-RECEIPT-EMPTY guard (7e)
  - FetcherRegistry: identity computed by registry, not fetcher
  - fetch_any: three-part ordered candidate list (7e §8a)
      - primary fails, mirror succeeds → success
      - all fail → MilpaError(FETCH-ALL-FAILED)
      - identity gate: mismatch skipped, next candidate tried → success
      - identity gate: all mismatch → FETCH-ALL-FAILED
      - no candidates provided → uncoded FetchError (programmer-invariant)
  - FETCH_UNCODED_INVARIANTS catalog exemption set (§5.1)
  - Entry-point discovery: build_registry() finds milpa-fetcher-stub
  - cas_admissible per provenance kind
"""

from __future__ import annotations

import importlib.metadata
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from milpa.errors import FETCH_ALL_FAILED, FETCH_RECEIPT_EMPTY, MilpaError
from milpa.fetchers import (
    FETCH_UNCODED_INVARIANTS,
    Fetcher,
    FetcherConfig,
    FetcherRegistry,
    FetchError,
    Provenance,
    ProvenanceReceipt,
    build_registry,
)

# ---------------------------------------------------------------------------
# Minimal fake helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _AProvenance(Provenance):
    """Kind A — immutable (default cas_admissible=True)."""


@dataclass(frozen=True)
class _BProvenance(Provenance):
    """Kind B — immutable (default cas_admissible=True)."""


@dataclass(frozen=True)
class _EditableProvenance(Provenance):
    """Editable provenance — cas_admissible must be False."""
    cas_admissible: bool = False  # type: ignore[assignment]  # ClassVar override


@dataclass(frozen=True)
class _GoodReceipt(ProvenanceReceipt):
    marker: str

    def transport_fields(self) -> dict[str, str]:
        return {"marker": self.marker}


@dataclass(frozen=True)
class _EmptyReceipt(ProvenanceReceipt):
    def transport_fields(self) -> dict[str, str]:
        return {}


class _AFetcher(Fetcher):
    """Handles _AProvenance only.  Writes a file so identity is non-trivial."""

    def __init__(self, fail: bool = False) -> None:
        self._fail = fail

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, _AProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> _GoodReceipt:
        if self._fail:
            raise MilpaError(FETCH_ALL_FAILED, f"_AFetcher: simulated failure for {name}")
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "a.txt").write_text(f"content-{name}\n")
        return _GoodReceipt(marker="a-ok")


class _BFetcher(Fetcher):
    """Handles _BProvenance only."""

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, _BProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> _GoodReceipt:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "b.txt").write_text(f"b-content-{name}\n")
        return _GoodReceipt(marker="b-ok")


class _GreedyFetcher(Fetcher):
    """Claims both _AProvenance and _BProvenance — triggers ambiguity in tests."""

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, (_AProvenance, _BProvenance))

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> _GoodReceipt:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "g.txt").write_text("greedy\n")
        return _GoodReceipt(marker="greedy")


class _EmptyReceiptFetcher(Fetcher):
    """Returns an empty receipt — should trigger FETCH-RECEIPT-EMPTY."""

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, _AProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> _EmptyReceipt:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "e.txt").write_text("empty\n")
        return _EmptyReceipt()


# ---------------------------------------------------------------------------
# FetcherConfig tests
# ---------------------------------------------------------------------------


class TestFetcherConfig:
    def test_default_mirror_urls_empty(self) -> None:
        cfg = FetcherConfig()
        assert cfg.mirror_urls == []

    def test_frozen_dataclass(self) -> None:
        cfg = FetcherConfig()
        with pytest.raises((AttributeError, TypeError)):
            cfg.mirror_urls = ["https://example.com"]  # type: ignore[misc]

    def test_accepts_mirror_urls(self) -> None:
        cfg = FetcherConfig(mirror_urls=["https://mirror.example.com"])
        assert cfg.mirror_urls == ["https://mirror.example.com"]


# ---------------------------------------------------------------------------
# Provenance.cas_admissible tests
# ---------------------------------------------------------------------------


class TestCasAdmissible:
    def test_base_provenance_cas_admissible_default_true(self) -> None:
        assert Provenance.cas_admissible is True

    def test_a_provenance_inherits_true(self) -> None:
        assert _AProvenance.cas_admissible is True

    def test_editable_provenance_false(self) -> None:
        # Editable sources must declare cas_admissible=False per §4 NORMATIVE.
        p = _EditableProvenance()
        assert p.cas_admissible is False


# ---------------------------------------------------------------------------
# ProvenanceReceipt: abstractmethod enforcement
# ---------------------------------------------------------------------------


class TestProvenanceReceiptABC:
    def test_cannot_instantiate_without_transport_fields(self) -> None:
        class _Bare(ProvenanceReceipt):
            pass  # no transport_fields — ABC incomplete

        with pytest.raises(TypeError, match="transport_fields"):
            _Bare()  # type: ignore[abstract]

    def test_good_receipt_transport_fields_returns_dict(self) -> None:
        r = _GoodReceipt(marker="x")
        assert r.transport_fields() == {"marker": "x"}

    def test_empty_receipt_transport_fields_returns_empty(self) -> None:
        r = _EmptyReceipt()
        assert r.transport_fields() == {}


# ---------------------------------------------------------------------------
# Fetcher ABC enforcement
# ---------------------------------------------------------------------------


class TestFetcherABC:
    def test_cannot_instantiate_without_can_handle_and_fetch(self) -> None:
        class _Incomplete(Fetcher):
            pass

        with pytest.raises(TypeError):
            _Incomplete()  # type: ignore[abstract]

    def test_concrete_fetcher_instantiates(self) -> None:
        f = _AFetcher()
        assert f.can_handle(_AProvenance())
        assert not f.can_handle(_BProvenance())


# ---------------------------------------------------------------------------
# FetcherRegistry: unique-match dispatch
# ---------------------------------------------------------------------------


class TestFetcherRegistryDispatch:
    def _registry_with(self, *fetchers: Fetcher) -> FetcherRegistry:
        r = FetcherRegistry()
        for f in fetchers:
            r.register(f)
        return r

    def test_dispatch_exactly_one_succeeds(self, tmp_path: Path) -> None:
        r = self._registry_with(_AFetcher(), _BFetcher())
        result = r.fetch("pkg", _AProvenance(), dest=tmp_path / "pkg")
        assert result.name == "pkg"
        assert result.path.exists()
        assert result.identity.startswith("sha256:")
        assert result.receipt.transport_fields() == {"marker": "a-ok"}

    def test_dispatch_ambiguity_raises_uncoded_fetch_error(self, tmp_path: Path) -> None:
        # Two fetchers both claim _AProvenance → ambiguity error with code=None.
        r = self._registry_with(_AFetcher(), _GreedyFetcher())
        with pytest.raises(FetchError) as exc_info:
            r.fetch("pkg", _AProvenance(), dest=tmp_path / "pkg")
        err = exc_info.value
        assert err.code is None
        assert "ambiguous" in str(err).lower()

    def test_dispatch_no_handler_raises_uncoded_fetch_error(self, tmp_path: Path) -> None:
        # No fetcher handles _AProvenance → no-handler error with code=None.
        r = self._registry_with(_BFetcher())
        with pytest.raises(FetchError) as exc_info:
            r.fetch("pkg", _AProvenance(), dest=tmp_path / "pkg")
        err = exc_info.value
        assert err.code is None
        assert "no" in str(err).lower()

    def test_dispatch_empty_registry_raises_uncoded(self, tmp_path: Path) -> None:
        r = FetcherRegistry()
        with pytest.raises(FetchError) as exc_info:
            r.fetch("pkg", _AProvenance(), dest=tmp_path / "pkg")
        assert exc_info.value.code is None

    def test_register_order_preserved(self) -> None:
        a, b = _AFetcher(), _BFetcher()
        r = self._registry_with(a, b)
        assert r.fetchers == (a, b)


# ---------------------------------------------------------------------------
# FETCH-RECEIPT-EMPTY guard (7e)
# ---------------------------------------------------------------------------


class TestReceiptEmptyGuard:
    def test_empty_receipt_raises_milpa_error_fetch_receipt_empty(
        self, tmp_path: Path
    ) -> None:
        r = FetcherRegistry()
        r.register(_EmptyReceiptFetcher())
        with pytest.raises(MilpaError) as exc_info:
            r.fetch("pkg", _AProvenance(), dest=tmp_path / "pkg")
        err = exc_info.value
        assert err.slug == FETCH_RECEIPT_EMPTY

    def test_good_receipt_does_not_raise(self, tmp_path: Path) -> None:
        r = FetcherRegistry()
        r.register(_AFetcher())
        result = r.fetch("pkg", _AProvenance(), dest=tmp_path / "pkg")
        # Just check it worked (no exception)
        assert result.receipt.transport_fields()


# ---------------------------------------------------------------------------
# Identity computed by registry (not by fetcher)
# ---------------------------------------------------------------------------


class TestRegistryComputesIdentity:
    def test_identity_is_sha256_prefixed(self, tmp_path: Path) -> None:
        r = FetcherRegistry()
        r.register(_AFetcher())
        result = r.fetch("mypkg", _AProvenance(), dest=tmp_path / "mypkg")
        assert result.identity.startswith("sha256:")

    def test_two_different_deps_different_identity(self, tmp_path: Path) -> None:
        r = FetcherRegistry()
        r.register(_AFetcher())
        r1 = r.fetch("pkg1", _AProvenance(), dest=tmp_path / "pkg1")
        r2 = r.fetch("pkg2", _AProvenance(), dest=tmp_path / "pkg2")
        # Different content (content-pkg1 vs content-pkg2) → different identities.
        assert r1.identity != r2.identity


# ---------------------------------------------------------------------------
# fetch_any: three-part ordered candidate list (7e §8a)
# ---------------------------------------------------------------------------


class _FailFetcher(Fetcher):
    """Handles _AProvenance, always fails."""

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, _AProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> _GoodReceipt:
        raise MilpaError(FETCH_ALL_FAILED, f"FailFetcher: network down for {name}")


class _SucceedOnSecondProvenance(Fetcher):
    """Fails for the first _AProvenance, succeeds for the second.

    Discriminated by a ``tag`` field on the provenance.
    """

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, _TaggedProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> _GoodReceipt:
        assert isinstance(p, _TaggedProvenance)
        if p.fail:
            raise MilpaError(FETCH_ALL_FAILED, f"tagged({p.tag}): fail=True")
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "ok.txt").write_text(f"ok-{p.tag}\n")
        return _GoodReceipt(marker=f"ok-{p.tag}")


@dataclass(frozen=True)
class _TaggedProvenance(Provenance):
    tag: str
    fail: bool = False


class TestFetchAny:
    def _tagged_registry(self) -> FetcherRegistry:
        r = FetcherRegistry()
        r.register(_SucceedOnSecondProvenance())
        return r

    def test_primary_fails_mirror_succeeds(self, tmp_path: Path) -> None:
        r = self._tagged_registry()
        primary = _TaggedProvenance(tag="primary", fail=True)
        mirror = _TaggedProvenance(tag="mirror", fail=False)
        result = r.fetch_any("pkg", [primary, mirror], dest=tmp_path / "pkg")
        assert result.identity.startswith("sha256:")
        assert result.receipt.transport_fields()["marker"] == "ok-mirror"

    def test_all_fail_raises_fetch_all_failed(self, tmp_path: Path) -> None:
        r = self._tagged_registry()
        candidates = [
            _TaggedProvenance(tag="p1", fail=True),
            _TaggedProvenance(tag="p2", fail=True),
        ]
        with pytest.raises(MilpaError) as exc_info:
            r.fetch_any("pkg", candidates, dest=tmp_path / "pkg")
        err = exc_info.value
        assert err.slug == FETCH_ALL_FAILED

    def test_no_candidates_raises_uncoded_fetch_error(self, tmp_path: Path) -> None:
        r = self._tagged_registry()
        with pytest.raises(FetchError) as exc_info:
            r.fetch_any("pkg", [], dest=tmp_path / "pkg")
        assert exc_info.value.code is None  # programmer-invariant, no catalog slug

    def test_primary_only_success(self, tmp_path: Path) -> None:
        r = self._tagged_registry()
        result = r.fetch_any("pkg", [_TaggedProvenance(tag="only")], dest=tmp_path / "pkg")
        assert result.name == "pkg"

    def test_three_candidates_first_success(self, tmp_path: Path) -> None:
        r = self._tagged_registry()
        candidates = [
            _TaggedProvenance(tag="first", fail=False),
            _TaggedProvenance(tag="second", fail=False),
            _TaggedProvenance(tag="third", fail=False),
        ]
        result = r.fetch_any("pkg", candidates, dest=tmp_path / "pkg")
        # First candidate succeeded; marker records which one.
        assert result.receipt.transport_fields()["marker"] == "ok-first"

    def test_three_candidates_only_third_succeeds(self, tmp_path: Path) -> None:
        r = self._tagged_registry()
        candidates = [
            _TaggedProvenance(tag="c1", fail=True),
            _TaggedProvenance(tag="c2", fail=True),
            _TaggedProvenance(tag="c3", fail=False),
        ]
        result = r.fetch_any("pkg", candidates, dest=tmp_path / "pkg")
        assert result.receipt.transport_fields()["marker"] == "ok-c3"


# ---------------------------------------------------------------------------
# Identity gate in fetch_any
# ---------------------------------------------------------------------------


class _IdentityWritingFetcher(Fetcher):
    """Writes a specific content so the identity is deterministic."""

    def __init__(self, content: str) -> None:
        self._content = content

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, _AProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> _GoodReceipt:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "f.txt").write_text(self._content)
        return _GoodReceipt(marker=f"content={self._content[:8]}")


class TestFetchAnyIdentityGate:
    def _compute_expected(self, content: str) -> str:
        """Compute expected identity for a tree containing one file with content."""
        from milpa.identity import compute_content_hash

        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.txt"
            p.write_text(content)
            return compute_content_hash(Path(d))

    def test_identity_match_succeeds(self, tmp_path: Path) -> None:
        content = "exact-content"
        expected = self._compute_expected(content)
        r = FetcherRegistry()
        r.register(_IdentityWritingFetcher(content))
        result = r.fetch_any(
            "pkg",
            [_AProvenance()],
            dest=tmp_path / "pkg",
            expected_identity=expected,
        )
        assert result.identity == expected

    def test_identity_mismatch_primary_then_mismatch_all_fails(
        self, tmp_path: Path
    ) -> None:
        """If all candidates produce wrong identity, FETCH-ALL-FAILED is raised."""
        wrong_identity = "sha256:" + "a" * 64
        r = FetcherRegistry()
        r.register(_IdentityWritingFetcher("wrong"))
        with pytest.raises(MilpaError) as exc_info:
            r.fetch_any(
                "pkg",
                [_AProvenance()],
                dest=tmp_path / "pkg",
                expected_identity=wrong_identity,
            )
        assert exc_info.value.slug == FETCH_ALL_FAILED

    def test_identity_mismatch_primary_correct_mirror(self, tmp_path: Path) -> None:
        """Primary produces wrong identity, mirror produces correct → mirror succeeds."""
        correct_content = "correct-mirror-content"
        expected = self._compute_expected(correct_content)

        @dataclass(frozen=True)
        class _ContentTagged(Provenance):
            use_correct: bool = False

        class _SelectiveFetcher(Fetcher):
            def can_handle(self, p: Provenance) -> bool:
                return isinstance(p, _ContentTagged)

            def fetch(self, name: str, p: Provenance, *, dest: Path) -> _GoodReceipt:
                assert isinstance(p, _ContentTagged)
                dest.mkdir(parents=True, exist_ok=True)
                text = correct_content if p.use_correct else "wrong-content"
                (dest / "f.txt").write_text(text)
                return _GoodReceipt(marker="selective")

        r = FetcherRegistry()
        r.register(_SelectiveFetcher())
        result = r.fetch_any(
            "pkg",
            [_ContentTagged(use_correct=False), _ContentTagged(use_correct=True)],
            dest=tmp_path / "pkg",
            expected_identity=expected,
        )
        assert result.identity == expected


# ---------------------------------------------------------------------------
# FETCH_UNCODED_INVARIANTS catalog exemption
# ---------------------------------------------------------------------------


class TestFetchUncodedInvariants:
    def test_contains_three_conditions(self) -> None:
        assert "ambiguous dispatch" in FETCH_UNCODED_INVARIANTS
        assert "no handler" in FETCH_UNCODED_INVARIANTS
        assert "no candidates" in FETCH_UNCODED_INVARIANTS

    def test_is_frozenset(self) -> None:
        assert isinstance(FETCH_UNCODED_INVARIANTS, frozenset)

    def test_exactly_three_entries(self) -> None:
        assert len(FETCH_UNCODED_INVARIANTS) == 3


# ---------------------------------------------------------------------------
# Entry-point discovery: build_registry() finds milpa-fetcher-stub
# ---------------------------------------------------------------------------


class TestEntryPointDiscovery:
    def test_stub_entry_point_is_installed(self) -> None:
        """milpa-fetcher-stub must appear in importlib.metadata entry points."""
        eps = importlib.metadata.entry_points(group="milpa.fetchers")
        names = [ep.name for ep in eps]
        assert "stub" in names, (
            f"milpa-fetcher-stub entry point not found. "
            f"Installed entry points: {names}. "
            f"Run 'uv sync' to install the fixture package."
        )

    def test_build_registry_registers_stub_fetcher(self, tmp_path: Path) -> None:
        """build_registry() should register the stub fetcher via entry-point discovery."""

        registry = build_registry()
        # The stub fetcher should be present — it handles StubProvenance.
        fetcher_types = [type(f).__name__ for f in registry.fetchers]
        assert "StubFetcher" in fetcher_types, (
            f"StubFetcher not found in registry.  "
            f"Registered fetchers: {fetcher_types}"
        )

    def test_stub_fetcher_can_fetch(self, tmp_path: Path) -> None:
        """Fetcher discovered via entry-point works end-to-end."""
        from milpa_fetcher_stub import StubProvenance

        registry = build_registry()
        dest = tmp_path / "stub-dep"
        result = registry.fetch("stub-dep", StubProvenance(), dest=dest)
        assert (dest / "stub.txt").read_text() == "stub content\n"
        assert result.identity.startswith("sha256:")
        assert result.receipt.transport_fields()["stub_marker"] == "stub-v1"


# ---------------------------------------------------------------------------
# R1b: identity=None must not crash fetch_any identity-gate (latent TypeError fix)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _NonAdmissibleProvenance(Provenance):
    """Non-admissible provenance — cas_admissible=False → identity=None."""
    cas_admissible: bool = False  # type: ignore[assignment]  # ClassVar override


class _NonAdmissibleFetcher(Fetcher):
    """Handles _NonAdmissibleProvenance. Writes a file; identity=None because non-admissible."""

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, _NonAdmissibleProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> _GoodReceipt:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "local.txt").write_text(f"local-{name}\n")
        return _GoodReceipt(marker="local-ok")


class TestFetchAnyIdentityNoneNoCrash:
    """R1b: fetch_any with identity=None on a candidate and expected_identity set
    must NOT raise TypeError — it should record a failure and continue."""

    def test_identity_none_with_expected_identity_does_not_raise_type_error(
        self, tmp_path: Path
    ) -> None:
        """Non-admissible candidate returns FetchResult(identity=None).
        fetch_any must NOT crash with TypeError when slicing None."""
        r = FetcherRegistry()
        r.register(_NonAdmissibleFetcher())
        expected = "sha256:" + "a" * 64  # some expected hash that won't match None

        # Must not raise TypeError; must raise FETCH-ALL-FAILED (identity mismatch
        # counted as a failure, not a crash).
        with pytest.raises(MilpaError) as exc_info:
            r.fetch_any(
                "pkg",
                [_NonAdmissibleProvenance()],
                dest=tmp_path / "pkg",
                expected_identity=expected,
            )
        assert exc_info.value.slug == FETCH_ALL_FAILED

    def test_identity_none_without_expected_identity_succeeds(
        self, tmp_path: Path
    ) -> None:
        """Non-admissible candidate with no expected_identity gate must succeed normally."""
        r = FetcherRegistry()
        r.register(_NonAdmissibleFetcher())
        result = r.fetch_any(
            "pkg",
            [_NonAdmissibleProvenance()],
            dest=tmp_path / "pkg",
        )
        assert result.identity is None
        assert result.name == "pkg"


# ---------------------------------------------------------------------------
# R7: _clear_dest must not follow / destroy a symlink target
# ---------------------------------------------------------------------------


class TestClearDestSymlinkSafety:
    """R7: _clear_dest on a symlink-to-dir must unlink only the symlink,
    leaving the target directory and its contents intact."""

    def test_clear_dest_symlink_removes_only_link(self, tmp_path: Path) -> None:
        from milpa.fetchers.types import _clear_dest

        # Create a target directory with real content.
        target = tmp_path / "real_source"
        target.mkdir()
        (target / "precious.nim").write_text("# do not delete me\n")

        # Create a symlink at dest pointing to the target.
        dest = tmp_path / "link_dest"
        dest.symlink_to(target)
        assert dest.is_symlink()
        assert (dest / "precious.nim").exists()

        # _clear_dest should remove only the symlink.
        _clear_dest(dest)

        # Symlink is gone; dest is now a clean real directory (recreated).
        assert not dest.is_symlink()
        assert dest.is_dir()

        # Target directory and its contents are UNTOUCHED.
        assert target.is_dir()
        assert (target / "precious.nim").exists()
        assert (target / "precious.nim").read_text() == "# do not delete me\n"

    def test_clear_dest_real_dir_still_removed(self, tmp_path: Path) -> None:
        """Sanity: _clear_dest on a real (non-symlink) directory still works."""
        from milpa.fetchers.types import _clear_dest

        dest = tmp_path / "real_dest"
        dest.mkdir()
        (dest / "file.nim").write_text("old content\n")

        _clear_dest(dest)

        assert dest.is_dir()
        assert not (dest / "file.nim").exists()
