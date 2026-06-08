"""LocalFetcher tests — local-filesystem source trees as a fetch
transport. Copy semantics (symlink mode is deferred).

The fetcher exists to support workspace use cases (intonaco at
`../intonaco`, fresco depending on it without a real git URL). Identity
is computed by the registry from the copied tree, same invariant as
GitFetcher; the LocalReceipt records where we copied from.
"""

from pathlib import Path

import pytest

from milpa.fetchers import FetcherRegistry, FetchError
from milpa.fetchers.local import LocalFetcher, LocalProvenance, LocalReceipt


def _make_source(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for relpath, content in files.items():
        p = root / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


def test_local_fetcher_copies_source_tree_and_returns_receipt(tmp_path):
    """Tracer: register LocalFetcher, fetch a local source dir via
    LocalProvenance, get FetchResult with milpa-computed content_hash
    and a LocalReceipt carrying source_path."""
    src = _make_source(tmp_path / "src", {
        "intonaco.nimble": 'srcDir = "src"\n',
        "src/intonaco.nim": '# stub\n',
    })

    registry = FetcherRegistry()
    registry.register(LocalFetcher())

    dest = tmp_path / "deps" / "intonaco"
    result = registry.fetch(
        "intonaco",
        LocalProvenance(path=src),
        dest=dest,
    )

    # Bytes landed at dest
    assert result.path == dest
    assert (dest / "intonaco.nimble").read_text() == 'srcDir = "src"\n'
    assert (dest / "src" / "intonaco.nim").read_text() == '# stub\n'

    # Identity computed by registry (64-hex sha256)
    # Multihash form: "sha256:" + 64 hex chars
    assert result.identity.startswith("sha256:")
    assert len(result.identity) == len("sha256:") + 64
    assert all(c in "0123456789abcdef" for c in result.identity.split(":", 1)[1])

    # Receipt records where we copied from
    assert isinstance(result.receipt, LocalReceipt)
    assert result.receipt.source_path == src


def test_local_provenance_rejects_relative_path():
    """LocalProvenance is a value type; relative paths are invalid.
    The resolver (which knows project root) is responsible for the
    relative→absolute lift before constructing the provenance."""
    with pytest.raises(ValueError) as exc:
        LocalProvenance(path=Path("../intonaco"))
    assert "absolute" in str(exc.value).lower()


def test_missing_source_raises_fetch_error_with_path_in_message(tmp_path):
    """If the source path doesn't exist, fetch fails fast with the
    path in the error message so the user can locate the issue."""
    registry = FetcherRegistry()
    registry.register(LocalFetcher())

    missing = tmp_path / "nonexistent"

    with pytest.raises(FetchError) as exc:
        registry.fetch(
            "x",
            LocalProvenance(path=missing),
            dest=tmp_path / "dest",
        )
    assert str(missing) in str(exc.value)


def test_source_path_that_is_a_file_raises_fetch_error(tmp_path):
    """LocalFetcher handles source TREES. A file path is invalid input."""
    not_a_dir = tmp_path / "not-a-dir"
    not_a_dir.write_text("just a file\n")

    registry = FetcherRegistry()
    registry.register(LocalFetcher())

    with pytest.raises(FetchError) as exc:
        registry.fetch(
            "x",
            LocalProvenance(path=not_a_dir),
            dest=tmp_path / "dest",
        )
    assert str(not_a_dir) in str(exc.value)
    # error should make clear it's a kind-of-thing problem, not just missing
    assert "director" in str(exc.value).lower()


def test_refetch_reflects_source_changes(tmp_path):
    """If source bytes changed between two fetches, dest must reflect
    the new state and the content_hash must change. No stale snapshot."""
    src = _make_source(tmp_path / "src", {"file.txt": "first\n"})
    dest = tmp_path / "deps" / "x"

    registry = FetcherRegistry()
    registry.register(LocalFetcher())

    r1 = registry.fetch("x", LocalProvenance(path=src), dest=dest)
    assert (dest / "file.txt").read_text() == "first\n"

    # Edit source
    (src / "file.txt").write_text("second\n")

    r2 = registry.fetch("x", LocalProvenance(path=src), dest=dest)
    assert (dest / "file.txt").read_text() == "second\n"
    assert r1.identity != r2.identity


def test_refetch_over_stale_symlink_dest(tmp_path):
    """Regression for #112: dest is a stale symlink (e.g. the dep was a
    CAS-routed url/git dep before the manifest switched it to local=,
    leaving `_deps/<name>` pointing into the CAS). Path.exists() follows
    the link so a naive `if dest.exists(): rmtree(dest)` guard tripped
    OSError('Cannot call rmtree on a symbolic link'); the fetch must
    instead unlink the stale link and copy the source tree fresh —
    without disturbing the link target."""
    src = _make_source(tmp_path / "src", {"file.txt": "real source\n"})

    # Stand in for a CAS entry the stale symlink points at.
    cas_entry = _make_source(tmp_path / "cas", {"file.txt": "cas bytes\n"})
    dest = tmp_path / "deps" / "x"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.symlink_to(cas_entry, target_is_directory=True)
    assert dest.is_symlink()

    registry = FetcherRegistry()
    registry.register(LocalFetcher())

    result = registry.fetch("x", LocalProvenance(path=src), dest=dest)

    # dest is now a real copied tree carrying the source bytes...
    assert not dest.is_symlink()
    assert (dest / "file.txt").read_text() == "real source\n"
    assert result.path == dest
    # ...and the symlink's former target was left untouched.
    assert (cas_entry / "file.txt").read_text() == "cas bytes\n"


def test_symlinks_in_source_preserved_as_symlinks_in_dest(tmp_path):
    """Per the identity model: symlinks within a source tree are data
    (the link target string is part of the hash), not references to
    follow. copytree(symlinks=True) preserves them."""
    src = _make_source(tmp_path / "src", {"target.txt": "linked content\n"})
    # Create a symlink alongside target.txt pointing at it.
    link = src / "link.txt"
    link.symlink_to("target.txt")  # relative symlink within the tree
    assert link.is_symlink()

    registry = FetcherRegistry()
    registry.register(LocalFetcher())

    dest = tmp_path / "deps" / "x"
    registry.fetch("x", LocalProvenance(path=src), dest=dest)

    dest_link = dest / "link.txt"
    assert dest_link.is_symlink(), "symlink in source must remain a symlink in dest"
    import os
    assert os.readlink(dest_link) == "target.txt"


def test_identity_is_path_independent(tmp_path):
    """Two LocalProvenances pointing at different paths but containing
    identical bytes produce the same content_hash. The path is
    provenance; only the bytes are identity. This is the load-bearing
    invariant from F1 (test_registry_computes_identity_externally),
    re-verified for the local transport specifically."""
    files = {"a.txt": "alpha\n", "b/c.txt": "beta\n"}
    s1 = _make_source(tmp_path / "src1", files)
    s2 = _make_source(tmp_path / "completely-different-path", files)

    registry = FetcherRegistry()
    registry.register(LocalFetcher())

    r1 = registry.fetch("x", LocalProvenance(path=s1), dest=tmp_path / "d1")
    r2 = registry.fetch("x", LocalProvenance(path=s2), dest=tmp_path / "d2")

    assert r1.identity == r2.identity
    # Receipts DO record the different paths (that's their job — provenance)
    assert r1.receipt.source_path != r2.receipt.source_path
