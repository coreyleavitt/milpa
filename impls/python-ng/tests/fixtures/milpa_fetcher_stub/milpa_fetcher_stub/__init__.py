"""Minimal stub fetcher plugin — used only for S7a entry-point discovery tests.

Declares a new provenance kind (StubProvenance) that does not conflict with
any built-in kind.  The factory signature satisfies plugin-contract.md §7:
one positional ``(config: FetcherConfig) -> Fetcher`` argument.

StubProvenance inherits ``milpa.fetchers.Provenance`` so it carries the
correct ``cas_admissible`` class attribute (inherits ``True`` from base).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from milpa.fetchers.types import Fetcher, FetcherConfig, Provenance, ProvenanceReceipt


@dataclass(frozen=True)
class StubProvenance(Provenance):
    """Toy provenance kind for S7a discovery tests.

    Does not conflict with any built-in kind (git/local/tarball/oci).
    ``cas_admissible = True`` (inherited default).
    """


@dataclass(frozen=True)
class StubReceipt(ProvenanceReceipt):
    """Receipt returned by StubFetcher.  Carries one transport-pinning field."""

    stub_marker: str

    def transport_fields(self) -> dict[str, str]:
        return {"stub_marker": self.stub_marker}


class StubFetcher(Fetcher):
    """Toy fetcher that handles StubProvenance.  Writes a fixed marker file."""

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, StubProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> StubReceipt:
        assert isinstance(p, StubProvenance)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "stub.txt").write_text("stub content\n")
        return StubReceipt(stub_marker="stub-v1")


def stub_factory(config: FetcherConfig) -> StubFetcher:
    """Entry-point factory.  Accepts FetcherConfig, returns a StubFetcher."""
    # config is ignored in v1 (mirror_urls not honored) — spec-conformant.
    return StubFetcher()
