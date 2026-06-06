"""OCI fetcher unit tests — orchestrates `oras pull` + extracts the
resulting tarball into dest. The oras subprocess is injected so unit
tests don't require oras on PATH or a live registry.
"""

import io
import gzip
import tarfile
from pathlib import Path

import pytest

from milpa.fetchers.oci import OciProvenance, OciFetcher


# A real-world OCI artifact published via `milpa publish` contains
# exactly one tar.gz with mediatype application/vnd.tianguis.source.v1.tar+gzip.
# The fake runner below simulates an oras pull by dropping that tarball
# into the requested output directory.
def _make_test_tarball() -> bytes:
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        info = tarfile.TarInfo(name="src/hello.nim")
        body = b'echo "hi"\n'
        info.size = len(body)
        tf.addfile(info, io.BytesIO(body))
        info2 = tarfile.TarInfo(name="README.md")
        body2 = b"# sample\n"
        info2.size = len(body2)
        tf.addfile(info2, io.BytesIO(body2))
    return gzip.compress(tar_buf.getvalue(), mtime=0)


def _fake_oras_runner(tarball_bytes: bytes):
    """Build a runner that simulates `oras pull <ref> --output <dir>`
    by writing `source.tar.gz` into the requested --output directory."""
    def runner(argv, **kw):
        # Parse --output from argv to know where to put the tarball.
        out_dir = None
        for i, a in enumerate(argv):
            if a in ("--output", "-o") and i + 1 < len(argv):
                out_dir = Path(argv[i + 1])
                break
        assert out_dir is not None, f"fake oras: no --output in {argv!r}"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "source.tar.gz").write_bytes(tarball_bytes)
        return (0, f"Downloaded: source.tar.gz\nDigest: sha256:deadbeef\n", "")
    return runner


# ---------------------------------------------------------------------------
# Cycle 9 — OciFetcher pulls an OCI artifact + extracts the tarball into
# dest. Identity (content_hash) is computed by FetcherRegistry, not here.
# ---------------------------------------------------------------------------


def test_oci_fetcher_pulls_and_extracts_into_dest(tmp_path: Path):
    blob = _make_test_tarball()
    fetcher = OciFetcher(runner=_fake_oras_runner(blob))

    dest = tmp_path / "out"
    prov = OciProvenance(
        registry="ghcr.io",
        repository="coreyleavitt/nimkdl",
        digest="sha256:e51aab085ef4f58ed3827742f3314cadb901ac1da36988cae05bb221f3652c24",
    )

    receipt = fetcher.fetch("nimkdl", prov, dest=dest)

    # The tarball was extracted under dest, preserving structure.
    assert (dest / "README.md").read_text() == "# sample\n"
    assert (dest / "src" / "hello.nim").read_text() == 'echo "hi"\n'
    # The .tar.gz itself is NOT left behind in dest (we extract + remove).
    assert not (dest / "source.tar.gz").exists()
    # Receipt records the OCI digest from the provenance.
    assert receipt.oci_digest.startswith("sha256:")


def test_oci_fetcher_can_handle_routes_only_oci_provenance(tmp_path: Path):
    fetcher = OciFetcher(runner=_fake_oras_runner(b""))
    prov = OciProvenance(
        registry="ghcr.io", repository="x/y", digest="sha256:abc",
    )
    assert fetcher.can_handle(prov) is True

    # A non-OCI provenance type — fetcher must decline.
    class FakeProv:
        pass
    assert fetcher.can_handle(FakeProv()) is False  # type: ignore[arg-type]


def test_oci_fetcher_raises_on_oras_failure(tmp_path: Path):
    from milpa.fetchers.types import FetchError

    def failing_runner(argv, **kw):
        return (1, "", "unauthorized: token expired\n")

    fetcher = OciFetcher(runner=failing_runner)
    prov = OciProvenance(
        registry="ghcr.io", repository="x/y", digest="sha256:abc",
    )
    with pytest.raises(FetchError, match="oras pull failed"):
        fetcher.fetch("x", prov, dest=tmp_path / "out")


# ---------------------------------------------------------------------------
# S2 (milpa#97) — the default registry must include OciFetcher so
# provenance-agnostic resolution can route an OciProvenance. Dispatch is
# first-match can_handle on disjoint isinstance types.
# ---------------------------------------------------------------------------


def test_default_registry_routes_oci_to_oci_fetcher():
    from milpa.fetchers import default_registry
    from milpa.fetchers.oci import OciFetcher, OciProvenance

    selected = default_registry._select(
        OciProvenance(registry="ghcr.io", repository="x/y", digest="sha256:abc")
    )
    assert isinstance(selected, OciFetcher)


def test_default_registry_routes_git_to_git_fetcher():
    from milpa.fetchers import default_registry
    from milpa.fetchers.git import GitFetcher, GitProvenance

    selected = default_registry._select(
        GitProvenance(url="https://example.com/x", ref="main")
    )
    assert isinstance(selected, GitFetcher)
