"""`milpa add --mirror URL DEPNAME` (#37 Part C).

Adds URL as a mirror provenance for the existing dep DEPNAME. Fetches
URL, verifies its bytes hash to DEPNAME's locked identity, and appends
a `mirror "URL"` line to the manifest atomically via
apply_manifest_change.

Refuses on hash mismatch, unknown dep, local/member sources, missing
manifest, or missing lockfile.
"""

from dataclasses import dataclass

import pytest

from milpa.cas import CAStore
from milpa.cli import cmd_add_mirror
from milpa.fetchers import (
    FetcherRegistry,
    Provenance,
    ProvenanceReceipt,
)
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.identity import compute_content_hash
from milpa.lockfile import (
    GitProvenanceRecord,
    LockedDep,
    Lockfile,
    format_lockfile,
)
from milpa.manifest import Manifest, UrlDep, parse_manifest
from milpa.manifest_writer import write_manifest


def _setup_project(tmp_path, identity, primary_url="https://primary/x.git"):
    """Build a tmp project with manifest + lockfile pinned to identity."""
    write_manifest(
        Manifest(
            kind="library", name="proj",
            deps=(UrlDep(name="x", git=primary_url, ref="main"),),
        ),
        tmp_path / "milpa.kdl",
    )
    (tmp_path / "milpa.lock").write_text(format_lockfile(Lockfile(
        deps=(LockedDep(
            name="x", identity=identity, version="0.0.1",
            src_dir="", requires=(),
            provenances=(GitProvenanceRecord(
                url=primary_url, ref="main", commit_sha="abc",
            ),),
        ),),
    )))


def test_cmd_add_mirror_appends_to_manifest_on_identity_match(tmp_path):
    """Mirror URL serves bytes that hash to the locked identity →
    `mirror "URL"` appended to manifest, exit 0."""
    # Pre-populate CAS with bytes that we'll teach the fake fetcher
    # to serve for the mirror URL.
    store = CAStore(root=tmp_path / "cas")
    scratch = store.root / "_scratch" / "x"
    scratch.mkdir(parents=True)
    (scratch / "x.nimble").write_text('srcDir = "src"\n')
    identity = compute_content_hash(scratch)
    store.admit(scratch, identity)

    _setup_project(tmp_path, identity)

    mirror_url = "https://mirror.example.com/x.git"

    class MirrorFetcher:
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            assert p.url == mirror_url, "fetcher should only see mirror URL"
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "x.nimble").write_text('srcDir = "src"\n')
            return GitReceipt(commit_sha="mirror-sha")

    registry = FetcherRegistry(store=store)
    registry.register(MirrorFetcher())

    rc = cmd_add_mirror(
        tmp_path, url=mirror_url, dep_name="x",
        fetcher=registry, relock=None,
    )

    assert rc == 0
    reparsed = parse_manifest((tmp_path / "milpa.kdl").read_text())
    dep = reparsed.deps[0]
    assert isinstance(dep, UrlDep)
    assert dep.mirrors == (mirror_url,)


def test_cmd_add_mirror_refuses_on_identity_mismatch(tmp_path, capsys):
    """Mirror URL serves bytes hashing to something OTHER than the
    locked identity → exit 1, manifest unchanged."""
    locked_identity = "sha256:" + "a" * 64
    _setup_project(tmp_path, locked_identity)
    original_manifest = (tmp_path / "milpa.kdl").read_text()

    store = CAStore(root=tmp_path / "cas")

    class BadByteFetcher:
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "different.txt").write_text("totally different bytes")
            return GitReceipt(commit_sha="bad-sha")

    registry = FetcherRegistry(store=store)
    registry.register(BadByteFetcher())

    rc = cmd_add_mirror(
        tmp_path,
        url="https://wrong.example.com/x.git",
        dep_name="x",
        fetcher=registry,
        relock=None,
    )

    assert rc == 1
    err = capsys.readouterr().err
    assert "identity" in err.lower() or "hash" in err.lower()
    # Manifest is unchanged
    assert (tmp_path / "milpa.kdl").read_text() == original_manifest


def test_cmd_add_mirror_refuses_when_no_lockfile(tmp_path, capsys):
    """No milpa.lock present → exit 1 with hint to run milpa fetch."""
    write_manifest(
        Manifest(kind="library", name="proj", deps=()),
        tmp_path / "milpa.kdl",
    )
    rc = cmd_add_mirror(
        tmp_path, url="https://x", dep_name="x",
        fetcher=FetcherRegistry(), relock=None,
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "lockfile" in err.lower()


def test_cmd_add_mirror_refuses_unknown_dep_name(tmp_path, capsys):
    """Dep name not in lockfile → exit 1 listing known names."""
    locked_identity = "sha256:" + "a" * 64
    _setup_project(tmp_path, locked_identity)

    rc = cmd_add_mirror(
        tmp_path, url="https://x", dep_name="nonexistent",
        fetcher=FetcherRegistry(), relock=None,
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "nonexistent" in err
    # Lists known dep names
    assert "x" in err


def test_cmd_add_mirror_refuses_on_local_provenance(tmp_path, capsys):
    """Lockfile dep with LocalProvenanceRecord → exit 1; can't mirror
    an editable source."""
    from milpa.lockfile import LocalProvenanceRecord
    identity = "sha256:" + "a" * 64
    write_manifest(
        Manifest(kind="library", name="proj", deps=()),
        tmp_path / "milpa.kdl",
    )
    (tmp_path / "milpa.lock").write_text(format_lockfile(Lockfile(
        deps=(LockedDep(
            name="sibling", identity=identity, version="0.0.1",
            src_dir="", requires=(),
            provenances=(LocalProvenanceRecord(path="../sibling"),),
        ),),
    )))

    rc = cmd_add_mirror(
        tmp_path, url="https://x", dep_name="sibling",
        fetcher=FetcherRegistry(), relock=None,
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "local" in err.lower() or "editable" in err.lower()
