"""Tests for the pluggable-fetcher abstraction (milpa/fetchers/).

These tests exercise the FetcherRegistry + per-transport Fetcher
implementations. Identity computation is the registry's responsibility,
not the fetcher's — that invariant is pinned in
test_registry_computes_identity_externally.

GitFetcher is tested against local file:// fixture repos created in
tmp_path (no network required).
"""

import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from milpa.fetchers import (
    FetcherRegistry,
    FetchError,
    FetchResult,
    Provenance,
    ProvenanceReceipt,
)
from milpa.fetchers.git import GitFetcher, GitProvenance, GitReceipt


def make_repo(path: Path, files: dict[str, str], branch: str = "main") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-q", "-b", branch, str(path)],
        check=True, capture_output=True, text=True,
    )
    for relpath, content in files.items():
        f = path / relpath
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)
    run = lambda *args: subprocess.run(
        ["git", "-C", str(path),
         "-c", "user.email=test@example.com", "-c", "user.name=test",
         *args],
        check=True, capture_output=True, text=True,
    )
    run("add", ".")
    run("commit", "-q", "-m", "initial")
    return path


def test_registry_dispatches_to_git_fetcher_end_to_end(tmp_path):
    """Tracer: register a GitFetcher, fetch a local file:// repo through
    the registry, get back a FetchResult with identity computed by the
    registry and a GitReceipt populated by the fetcher."""
    src = make_repo(tmp_path / "src", {"hello.txt": "hello world\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    registry = FetcherRegistry()
    registry.register(GitFetcher())

    result = registry.fetch(
        "myrepo",
        GitProvenance(url=f"file://{src}", ref="main"),
        dest=deps_dir / "myrepo",
    )

    assert isinstance(result, FetchResult)
    assert result.name == "myrepo"
    assert result.path == deps_dir / "myrepo"
    assert (result.path / "hello.txt").read_text() == "hello world\n"
    # Identity: 64 hex chars (sha256 of source tree)
    # Multihash form: "sha256:" + 64 hex chars
    assert result.identity.startswith("sha256:")
    assert len(result.identity) == len("sha256:") + 64
    assert all(c in "0123456789abcdef" for c in result.identity.split(":", 1)[1])
    # Receipt: transport-specific provenance record
    assert isinstance(result.receipt, GitReceipt)
    assert len(result.receipt.commit_sha) == 40


def test_registry_raises_fetch_error_for_unknown_provenance(tmp_path):
    """When no registered fetcher's can_handle accepts the provenance,
    the registry raises FetchError with a message naming the kind."""

    @dataclass(frozen=True)
    class UnknownProvenance(Provenance):
        marker: str = "x"

    registry = FetcherRegistry()
    registry.register(GitFetcher())  # only handles GitProvenance

    with pytest.raises(FetchError) as exc:
        registry.fetch(
            "anything",
            UnknownProvenance(),
            dest=tmp_path / "dest",
        )
    assert "UnknownProvenance" in str(exc.value)


def test_ambiguous_dispatch_raises_when_multiple_fetchers_match(tmp_path):
    """Registering two fetchers that both claim can_handle for the same
    provenance kind raises FetchError with a clear ambiguity message,
    rather than silently dispatching to the first-registered one.

    This guards against subtle mis-registrations where two fetchers
    overlap on the same provenance type, which would otherwise produce
    non-deterministic or surprising dispatch."""

    @dataclass(frozen=True)
    class MarkerProvenance(Provenance):
        pass

    @dataclass(frozen=True)
    class MarkerReceipt(ProvenanceReceipt):
        who: str

        def transport_fields(self) -> dict[str, str]:
            return {"who": self.who}

    class FetcherA:
        def can_handle(self, p): return isinstance(p, MarkerProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "marker").write_text("A")
            return MarkerReceipt(who="A")

    class FetcherB:
        def can_handle(self, p): return isinstance(p, MarkerProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "marker").write_text("B")
            return MarkerReceipt(who="B")

    registry = FetcherRegistry()
    registry.register(FetcherA())
    registry.register(FetcherB())

    with pytest.raises(FetchError, match="ambiguous fetcher dispatch"):
        registry.fetch("x", MarkerProvenance(), dest=tmp_path / "x")


def test_registry_computes_identity_externally(tmp_path):
    """Load-bearing invariant: identity is computed by the registry
    from the dest tree, not by the fetcher. A fetcher cannot influence
    the content_hash, even if it tries.

    We verify by writing known bytes through a stub fetcher whose
    receipt is unrelated, then asserting the FetchResult.identity
    equals the registry's independent recomputation against the bytes
    actually at dest. Two different fetchers that produce the SAME
    bytes at dest must produce the SAME content_hash, regardless of
    what their receipts say."""
    from milpa.identity import compute_content_hash

    @dataclass(frozen=True)
    class StubProvenance(Provenance):
        payload: str

    @dataclass(frozen=True)
    class StubReceipt(ProvenanceReceipt):
        lie: str

        def transport_fields(self) -> dict[str, str]:
            return {"lie": self.lie}

    class StubFetcher:
        """Writes `payload` bytes to dest. Returns a receipt with
        unrelated metadata — receipt fields must not leak into identity."""
        def __init__(self, lie: str):
            self.lie = lie
        def can_handle(self, p): return isinstance(p, StubProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "file.txt").write_text(p.payload)
            return StubReceipt(lie=self.lie)

    reg_a = FetcherRegistry()
    reg_a.register(StubFetcher(lie="alpha"))
    reg_b = FetcherRegistry()
    reg_b.register(StubFetcher(lie="beta"))

    same_payload = "the actual bytes\n"
    r_a = reg_a.fetch("x", StubProvenance(payload=same_payload), dest=tmp_path / "a")
    r_b = reg_b.fetch("x", StubProvenance(payload=same_payload), dest=tmp_path / "b")

    # Different receipts (the fetchers report different lies)...
    assert r_a.receipt.lie != r_b.receipt.lie
    # ...but identity is purely a function of dest contents.
    assert r_a.identity == r_b.identity
    # And it matches what we'd compute directly against dest, with no
    # registry/fetcher involvement at all.
    assert r_a.identity == compute_content_hash(tmp_path / "a")
