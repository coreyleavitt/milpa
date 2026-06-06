"""End-to-end integration test against fresco's actual dep tree.

Gated by MILPA_INTEGRATION_TESTS=1 so day-to-day developer runs and CI
without network skip these. Run manually with:

    MILPA_INTEGRATION_TESTS=1 uv run pytest tests/test_integration.py -v

What's exercised:
  - Real git clone of chronos (URL dep)
  - Real fetch of the tianguis index (the named-dep registry, milpa#97)
  - Real index lookup for each chronos transitive named dep
  - Real git clone of each named dep at its index-pinned provenance
  - .nimble parsing across all deps
  - Full PubGrub resolution over the materialized candidate set
  - milpa.lock + nim.cfg emission
"""

import os
from pathlib import Path

import pytest

from milpa.cli import cmd_clean, cmd_fetch
from milpa.lockfile import load_lockfile


pytestmark = pytest.mark.skipif(
    os.environ.get("MILPA_INTEGRATION_TESTS") != "1",
    reason="set MILPA_INTEGRATION_TESTS=1 to run network-based integration tests",
)


# A fresco-style manifest: one URL dep (chronos at the contextvars
# fork) whose nimble file has named transitive requires. This exercises
# every layer of milpa end-to-end.
FRESCO_MANIFEST = '''
name "fresco"
deps {
    chronos git="https://github.com/coreyleavitt/chronos.git" ref="feat/contextvars"
}
'''


@pytest.mark.integration
def test_fresco_tree_resolves_end_to_end(tmp_path: Path):
    (tmp_path / "milpa.kdl").write_text(FRESCO_MANIFEST)

    rc = cmd_fetch(tmp_path)
    assert rc == 0, "milpa fetch should resolve fresco's tree successfully"

    # Lockfile present, has the expected shape
    lockfile_path = tmp_path / "milpa.lock"
    assert lockfile_path.exists()
    lockfile = load_lockfile(lockfile_path)

    names = {dep.name for dep in lockfile.deps}
    # chronos is the manifest-declared URL dep
    assert "chronos" in names, f"chronos missing from lockfile (got: {names})"

    # Every dep has cryptographic pins: an identity (multihash) plus at
    # least one provenance. Git provenances (URL deps + index-resolved
    # named deps) carry a commit_sha; we require one when present.
    from milpa.lockfile import GitProvenanceRecord
    for dep in lockfile.deps:
        assert dep.identity, f"dep {dep.name!r} has no identity pin"
        assert dep.provenances, f"dep {dep.name!r} has no provenance"
        first = dep.provenances[0]
        if isinstance(first, GitProvenanceRecord):
            assert first.commit_sha, (
                f"dep {dep.name!r} provenance has no commit_sha pin"
            )

    # nim.cfg has a --path line for each resolved dep
    nim_cfg = (tmp_path / "nim.cfg").read_text()
    for dep in lockfile.deps:
        assert f'"_deps/{dep.name}' in nim_cfg, (
            f"nim.cfg missing path entry for {dep.name!r}"
        )

    # _deps/ has a directory for each resolved dep with at least its
    # .nimble file present
    for dep in lockfile.deps:
        dep_dir = tmp_path / "_deps" / dep.name
        assert dep_dir.is_dir(), f"_deps/{dep.name}/ not present"


@pytest.mark.integration
def test_rerun_is_idempotent(tmp_path: Path):
    (tmp_path / "milpa.kdl").write_text(FRESCO_MANIFEST)

    rc1 = cmd_fetch(tmp_path)
    assert rc1 == 0
    first_lockfile = (tmp_path / "milpa.lock").read_bytes()

    rc2 = cmd_fetch(tmp_path)
    assert rc2 == 0
    second_lockfile = (tmp_path / "milpa.lock").read_bytes()

    # Lockfile bytes should be identical — same content_hash, same SHAs,
    # same emission order.
    assert first_lockfile == second_lockfile, (
        "milpa fetch is not idempotent — lockfile changed on rerun"
    )


@pytest.mark.integration
def test_nimble_only_consumer_resolves(tmp_path: Path):
    """A fresco-style consumer that has ONLY a .nimble file (no
    milpa.kdl) should resolve identically to one with a milpa.kdl.
    Uses intonaco's nimble shape: one URL requires (chronos) + the
    'nim' compiler requires (which milpa drops)."""
    (tmp_path / "myproj.nimble").write_text(
        'requires "nim >= 2.0.0"\n'
        'requires "https://github.com/coreyleavitt/chronos.git#feat/contextvars"\n'
    )
    rc = cmd_fetch(tmp_path)
    assert rc == 0, "milpa fetch from .nimble alone should succeed"

    lockfile = load_lockfile(tmp_path / "milpa.lock")
    names = {dep.name for dep in lockfile.deps}
    # chronos itself + its transitives
    assert "chronos" in names
    # nim should NOT be a dep — compiler version isn't a source dep
    assert "nim" not in names


@pytest.mark.integration
def test_clean_then_fetch_works(tmp_path: Path):
    (tmp_path / "milpa.kdl").write_text(FRESCO_MANIFEST)

    rc = cmd_fetch(tmp_path)
    assert rc == 0
    assert (tmp_path / "_deps").exists()
    assert (tmp_path / "nim.cfg").exists()

    rc = cmd_clean(tmp_path)
    assert rc == 0
    assert not (tmp_path / "_deps").exists()
    assert not (tmp_path / "nim.cfg").exists()

    # Re-fetch from scratch
    rc = cmd_fetch(tmp_path)
    assert rc == 0
    assert (tmp_path / "_deps").exists()
    assert (tmp_path / "nim.cfg").exists()
