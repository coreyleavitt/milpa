"""Tests for S11 — FetcherConfig, ProvenanceReceipt ABC, and entry-point
plugin discovery.

TDD order:
  1. ProvenanceReceipt ABC: concrete subclass must implement transport_fields();
     bare subclass without it is abstract / raises at instantiation.
  2. FetcherConfig: frozen dataclass, mirror_urls default=[], v1 shape.
  3. Built-in receipts (Git/Tarball/Local/OCI) all return non-empty transport_fields().
  4. Empty transport_fields() → FetchError(code='FETCH-RECEIPT-EMPTY') at
     admission time (the fetch path, not at class definition).
  5. Entry-point discovery via real importlib.metadata (fixture plugin installed
     as dev-dep): default_registry contains the plugin fetcher after discovery.
  6. A plugin that claims an existing built-in kind → ambiguity FetchError
     (exclusive dispatch preserved).

The reference-plugin test (5) exercises the REAL importlib.metadata path —
the fixture package `tests/fixtures/milpa_fetcher_stub/` is installed as a
path dev-dependency so its entry point actually populates the metadata.
"""

import importlib.metadata
import sys
from abc import ABC
from dataclasses import dataclass, field, fields
from pathlib import Path

import pytest

from milpa.fetchers import FetchError, FetcherRegistry, Provenance, ProvenanceReceipt
from milpa.fetchers.git import GitReceipt
from milpa.fetchers.local import LocalReceipt
from milpa.fetchers.oci import OciReceipt
from milpa.fetchers.tarball import TarballReceipt
from milpa.fetchers.types import FetcherConfig


# ---------------------------------------------------------------------------
# 1. ProvenanceReceipt is an ABC
# ---------------------------------------------------------------------------


def test_provenance_receipt_is_abstract_base_class():
    """ProvenanceReceipt must be an ABC so concrete subclasses that omit
    transport_fields() cannot be instantiated."""
    assert issubclass(ProvenanceReceipt, ABC)


def test_concrete_receipt_without_transport_fields_cannot_be_instantiated():
    """A frozen dataclass that inherits ProvenanceReceipt but does NOT
    implement transport_fields() must raise TypeError at instantiation
    (abstract method not overridden)."""

    @dataclass(frozen=True)
    class IncompleteReceipt(ProvenanceReceipt):
        some_field: str = "x"
        # transport_fields NOT implemented

    with pytest.raises(TypeError, match="transport_fields"):
        IncompleteReceipt()


def test_concrete_receipt_with_transport_fields_can_be_instantiated():
    """A frozen dataclass that implements transport_fields() is concrete
    and must be instantiable."""

    @dataclass(frozen=True)
    class CompleteReceipt(ProvenanceReceipt):
        pin: str

        def transport_fields(self) -> dict[str, str]:
            return {"pin": self.pin}

    r = CompleteReceipt(pin="abc123")
    assert r.transport_fields() == {"pin": "abc123"}


# ---------------------------------------------------------------------------
# 2. FetcherConfig dataclass — v1 shape
# ---------------------------------------------------------------------------


def test_fetcher_config_exists_and_is_frozen_dataclass():
    """FetcherConfig must be a frozen dataclass (raises FrozenInstanceError
    on mutation)."""
    cfg = FetcherConfig()
    with pytest.raises(Exception):  # FrozenInstanceError is an AttributeError subclass
        cfg.mirror_urls = ["http://example.com"]  # type: ignore[misc]


def test_fetcher_config_has_only_mirror_urls_field():
    """FetcherConfig v1 shape: exactly one field — mirror_urls: list[str]."""
    f_names = {f.name for f in fields(FetcherConfig)}
    assert f_names == {"mirror_urls"}


def test_fetcher_config_default_mirror_urls_is_empty_list():
    cfg = FetcherConfig()
    assert cfg.mirror_urls == []


def test_fetcher_config_accepts_mirror_urls():
    cfg = FetcherConfig(mirror_urls=["https://mirror1.example.com"])
    assert cfg.mirror_urls == ["https://mirror1.example.com"]


def test_fetcher_config_instances_are_independent():
    """Default factory — two default instances must not share the same list."""
    a = FetcherConfig()
    b = FetcherConfig()
    assert a.mirror_urls is not b.mirror_urls


# ---------------------------------------------------------------------------
# 3. Built-in receipts implement transport_fields()
# ---------------------------------------------------------------------------


def test_git_receipt_transport_fields_returns_commit_sha():
    r = GitReceipt(commit_sha="deadbeef" * 5)
    tf = r.transport_fields()
    assert "commit_sha" in tf
    assert tf["commit_sha"] == "deadbeef" * 5
    assert len(tf) >= 1


def test_tarball_receipt_transport_fields_non_empty():
    r = TarballReceipt(
        archive_sha256="a" * 64,
        extracted_bytes=1024,
        extracted_file_count=3,
    )
    tf = r.transport_fields()
    assert "archive_sha256" in tf
    assert len(tf) >= 1


def test_local_receipt_transport_fields_non_empty():
    r = LocalReceipt(source_path=Path("/some/path"))
    tf = r.transport_fields()
    assert "source_path" in tf
    assert len(tf) >= 1


def test_oci_receipt_transport_fields_non_empty():
    r = OciReceipt(oci_digest="sha256:" + "a" * 64)
    tf = r.transport_fields()
    assert "oci_digest" in tf
    assert len(tf) >= 1


# ---------------------------------------------------------------------------
# 4. Admission-time empty-transport_fields check via the fetch path
# ---------------------------------------------------------------------------


def test_fetch_raises_on_empty_transport_fields(tmp_path):
    """A fetcher that returns a receipt with empty transport_fields() must
    trigger FetchError(code='FETCH-RECEIPT-EMPTY') at the registry's
    admission point, not be silently accepted."""

    @dataclass(frozen=True)
    class ToyProvenance(Provenance):
        pass

    @dataclass(frozen=True)
    class EmptyReceipt(ProvenanceReceipt):
        def transport_fields(self) -> dict[str, str]:
            return {}  # contract violation

    class EmptyFieldsFetcher:
        def can_handle(self, p: Provenance) -> bool:
            return isinstance(p, ToyProvenance)

        def fetch(self, name: str, p: Provenance, *, dest: Path) -> EmptyReceipt:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "x.txt").write_text("toy\n")
            return EmptyReceipt()

    registry = FetcherRegistry()
    registry.register(EmptyFieldsFetcher())

    with pytest.raises(FetchError) as exc:
        registry.fetch("toy", ToyProvenance(), dest=tmp_path / "toy")
    assert exc.value.code == "FETCH-RECEIPT-EMPTY"


# ---------------------------------------------------------------------------
# 5. Entry-point discovery via real importlib.metadata
# ---------------------------------------------------------------------------


def _plugin_entry_points_available() -> bool:
    """Return True iff the milpa_fetcher_stub fixture package is installed
    and has an entry point under the 'milpa.fetchers' group."""
    eps = importlib.metadata.entry_points(group="milpa.fetchers")
    return any(ep.name == "stub" for ep in eps)


@pytest.mark.skipif(
    not _plugin_entry_points_available(),
    reason="milpa_fetcher_stub fixture not installed; run `uv sync` to install dev deps",
)
def test_default_registry_includes_stub_plugin_after_discovery():
    """After `uv sync` installs the fixture plugin, importing default_registry
    must include the stub fetcher discovered through the real
    importlib.metadata entry-point path (group='milpa.fetchers')."""
    # Import fresh — the module-level default_registry is built at import
    # time and includes discovered plugins.
    from milpa.fetchers import default_registry
    from milpa.fetchers.types import FetcherConfig

    fetcher_types = [type(f).__name__ for f in default_registry.fetchers]
    assert "StubFetcher" in fetcher_types, (
        f"StubFetcher not found in default_registry.fetchers; got: {fetcher_types}. "
        "Check that milpa_fetcher_stub is installed and that default_registry "
        "runs entry-point discovery."
    )


@pytest.mark.skipif(
    not _plugin_entry_points_available(),
    reason="milpa_fetcher_stub fixture not installed; run `uv sync` to install dev deps",
)
def test_stub_plugin_dispatches_for_its_provenance_kind(tmp_path):
    """The stub plugin's fetcher handles StubProvenance and produces a
    StubReceipt with non-empty transport_fields(). This exercises the full
    fetch path through the discovered plugin."""
    # Import from the stub package directly (it's installed)
    from milpa_fetcher_stub import StubProvenance
    from milpa.fetchers import default_registry

    dest = tmp_path / "stub_dep"
    result = default_registry.fetch("stub_dep", StubProvenance(), dest=dest)

    assert result.name == "stub_dep"
    assert result.path == dest
    assert result.identity.startswith("sha256:")
    # Receipt must carry non-empty transport_fields (ABC enforces it)
    assert result.receipt.transport_fields() != {}


# ---------------------------------------------------------------------------
# 6. Plugin claiming a built-in kind triggers ambiguity error
# ---------------------------------------------------------------------------


def test_plugin_claiming_builtin_kind_triggers_ambiguity_error(tmp_path):
    """A plugin registered in addition to the built-in GitFetcher that also
    claims can_handle(GitProvenance) must trigger the ambiguity FetchError,
    not silently shadow the built-in. Exclusive dispatch is preserved."""
    from milpa.fetchers.git import GitFetcher, GitProvenance

    @dataclass(frozen=True)
    class RogueReceipt(ProvenanceReceipt):
        def transport_fields(self) -> dict[str, str]:
            return {"rogue": "true"}

    class RogueFetcher:
        """Claims GitProvenance — ambiguity conflict with GitFetcher."""
        def can_handle(self, p: Provenance) -> bool:
            return isinstance(p, GitProvenance)

        def fetch(self, name: str, p: Provenance, *, dest: Path) -> RogueReceipt:
            dest.mkdir(parents=True, exist_ok=True)
            return RogueReceipt()

    registry = FetcherRegistry()
    registry.register(GitFetcher())
    registry.register(RogueFetcher())

    with pytest.raises(FetchError, match="ambiguous fetcher dispatch"):
        registry.fetch(
            "x",
            GitProvenance(url="file:///nonexistent", ref="main"),
            dest=tmp_path / "x",
        )
