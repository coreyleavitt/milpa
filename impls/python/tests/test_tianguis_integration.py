"""End-to-end integration test against the live tianguis registry.

Gated by MILPA_INTEGRATION_TESTS=1. What's exercised:

  - Real HTTP GET of tianguis index.kdl
  - parse_index against the real document
  - resolve_named('nimkdl') returns the published OCI provenance
  - Real oras pull of the published OCI artifact
  - Real safe-extract into a dest dir
  - The trust-chain invariant: recomputed content_hash == what tianguis recorded

This is the test that proves the registry actually delivers on its
identity-model promise end-to-end.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from milpa.identity import compute_content_hash
from milpa.tianguis_client import load_index, resolve_named
from milpa.fetchers.oci import OciFetcher


pytestmark = pytest.mark.skipif(
    os.environ.get("MILPA_INTEGRATION_TESTS") != "1",
    reason="set MILPA_INTEGRATION_TESTS=1 to run network-based integration tests",
)


# Public raw URL — works while tianguis is public. Stable form even after
# tianguis flips back to private (would just need an auth header).
TIANGUIS_INDEX_URL = (
    "https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl"
)


def _have_oras() -> bool:
    return shutil.which("oras") is not None


def test_e2e_resolve_and_fetch_via_tianguis(tmp_path: Path):
    if not _have_oras():
        pytest.skip("oras binary not on PATH; install from oras.land")

    cache = tmp_path / "tianguis-cache"
    idx = load_index(url=TIANGUIS_INDEX_URL, cache_dir=cache)

    # The canary entry from the R3a acceptance run — pinned for the test
    # to remain stable. If this version goes away, the test breaks loudly.
    resolved = resolve_named(idx, "nimkdl", "== 0.1.4")
    assert resolved.version == "0.1.4"
    assert len(resolved.provenances) == 1
    prov = resolved.provenances[0]
    assert prov.kind == "oci"

    # Real oras pull + extract.
    dest = tmp_path / "fetched"
    fetcher = OciFetcher()
    receipt = fetcher.fetch("nimkdl", prov, dest=dest)
    assert receipt.oci_digest == prov.digest
    assert dest.is_dir() and any(dest.iterdir()), "fetch produced no files"

    # THE invariant — recomputed content_hash matches tianguis's record.
    # If this diverges, the trust chain has a hole.
    recomputed = compute_content_hash(dest)
    assert recomputed == resolved.content_hash, (
        f"content_hash divergence: tianguis recorded {resolved.content_hash!r} "
        f"but the unpacked OCI artifact hashes to {recomputed!r} — "
        f"the trust chain has a hole, this is a serious bug"
    )
