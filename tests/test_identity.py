"""Tests for milpa.identity.compute_content_hash.

Identity (sha256 of the source tree) is the canonical 'what' of a
fetched dep. Spec details — what bytes go in, in what order, with
what mode markers — are tested here directly against synthetic trees.

No git involvement. No fetcher integration. End-to-end exercise of
the same hash through `fetch_url_dep` is covered in test_fetcher.py.
"""

import os
import stat
from pathlib import Path

import pytest

from milpa.identity import compute_content_hash


def _write(path: Path, content: str, *, executable: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_executable_bit_changes_content_hash(tmp_path):
    # Two trees with identical file content, different exec bit
    a = tmp_path / "a"
    b = tmp_path / "b"
    _write(a / "script.sh", "#!/bin/sh\necho hi\n", executable=False)
    _write(b / "script.sh", "#!/bin/sh\necho hi\n", executable=True)

    hash_a = compute_content_hash(a)
    hash_b = compute_content_hash(b)
    assert hash_a != hash_b


def test_identical_trees_produce_identical_hashes(tmp_path):
    """Determinism: same bytes + same modes → same hash. Regression
    guard."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    files = {
        "src/main.nim": "import std/strutils\nproc main() = echo \"hi\"\n",
        "README.md": "# project\n",
        "scripts/run.sh": "#!/bin/sh\nexec nim r src/main.nim\n",
    }
    for relpath, content in files.items():
        _write(a / relpath, content, executable=relpath.endswith(".sh"))
        _write(b / relpath, content, executable=relpath.endswith(".sh"))
    assert compute_content_hash(a) == compute_content_hash(b)


def test_dot_git_directory_excluded(tmp_path):
    """`.git/` is provenance, not content — must not affect identity."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    _write(a / "src/main.nim", "echo 'hi'\n")
    _write(b / "src/main.nim", "echo 'hi'\n")
    # b has a fake .git/ directory with random junk
    _write(b / ".git/HEAD", "ref: refs/heads/main\n")
    _write(b / ".git/objects/ab/cd1234", "binary junk")
    assert compute_content_hash(a) == compute_content_hash(b)


def test_symlink_hashed_by_target_not_followed(tmp_path):
    """A symlink is identified by its link target string, not by the
    content of what it points at. (If we followed the link, two trees
    with different symlinks pointing at the same target would have
    the same hash — wrong.)"""
    a = tmp_path / "a"
    a.mkdir()
    target_file = a / "real.txt"
    target_file.write_text("hello\n")
    link = a / "link"
    link.symlink_to("real.txt")

    # b: identical file content but link points elsewhere
    b = tmp_path / "b"
    b.mkdir()
    (b / "real.txt").write_text("hello\n")
    (b / "link").symlink_to("different_target")

    assert compute_content_hash(a) != compute_content_hash(b)


def test_symlink_vs_regular_file_with_same_content_differ(tmp_path):
    """A regular file containing the bytes 'target' and a symlink whose
    target string is 'target' must hash differently — the mode marker
    discriminates."""
    a = tmp_path / "a"
    a.mkdir()
    (a / "entry").write_text("target")   # regular file with content "target"

    b = tmp_path / "b"
    b.mkdir()
    (b / "entry").symlink_to("target")   # symlink whose link string is "target"

    assert compute_content_hash(a) != compute_content_hash(b)


def test_symlink_pointing_outside_tree_does_not_crash(tmp_path):
    """A symlink whose target is outside the tree (or doesn't exist)
    is hashed by its target string. No following, no crash."""
    a = tmp_path / "a"
    a.mkdir()
    (a / "broken").symlink_to("/nonexistent/elsewhere")
    # No crash; produces a valid hash
    h = compute_content_hash(a)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)
