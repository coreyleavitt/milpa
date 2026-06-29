"""Unit tests for the epoch-2 production DAG builder (milpa.dag_identity).

RFC ``rfc-identity-conformance-authority`` slice B2-git; ``spec/identity.md`` §1.8.

These tests pin the **production** builder against the hand-frozen oracle pins
and exercise each load-bearing epoch-2 axis directly. The builder is INDEPENDENT
of the standalone reference oracle
(``conformance/spec-v1/_oracle/dag_sha256_reference.py``) — this file asserts the
builder reproduces the frozen pins, never compares the two code paths, and a
guard test confirms the builder source does not import the oracle.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from milpa.dag_identity import (
    MODE_EXECUTABLE,
    MODE_REGULAR,
    MODE_SYMLINK,
    MaterializedEntry,
    compute_dag_identity,
)
from milpa.errors import ID_NAME_TOO_LONG, MilpaError

_EMPTY_ROOT_PIN = "dag-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_NESTED_PIN = "dag-sha256:e3213019260649b72bb0295aaec004eb20a625dd55fcd4bac9e35df96bce316f"


def _nested_entries() -> list[MaterializedEntry]:
    """The fixture-330 logical tree as a materialized seam sequence."""
    return [
        MaterializedEntry("a.txt", MODE_REGULAR, b"alpha\n"),
        MaterializedEntry("a/b.txt", MODE_REGULAR, b"beta\n"),
        MaterializedEntry("a/run.sh", MODE_EXECUTABLE, b"#!/bin/sh\necho hi\n"),
        MaterializedEntry("link", MODE_SYMLINK, b"a/b.txt"),
    ]


def test_empty_tree_is_pinned_empty_root() -> None:
    assert compute_dag_identity([]) == _EMPTY_ROOT_PIN


def test_nested_tree_reproduces_pinned_oracle_digest() -> None:
    assert compute_dag_identity(_nested_entries()) == _NESTED_PIN


def test_builder_independent_of_materializer_stream_order() -> None:
    # §1.8.3: the builder re-sorts each level by leaf name, so the digest is
    # invariant under the materializer's stream order. A reversed stream (which a
    # naive full-relpath builder would hash differently) yields the same digest.
    assert compute_dag_identity(list(reversed(_nested_entries()))) == _NESTED_PIN


def test_leaf_name_sort_differs_from_full_path_sort() -> None:
    # The anchor case: subdirectory `a` sorts before file `a.txt` by leaf name
    # ("a" is a byte-prefix of "a.txt"), the OPPOSITE of full-relpath order where
    # `a.txt` < `a/b.txt` ('.' 0x2e < '/' 0x2f). The pinned digest only reproduces
    # under leaf-name order; this is the load-bearing divergence guard.
    assert compute_dag_identity(_nested_entries()) == _NESTED_PIN


def test_executable_bit_changes_identity() -> None:
    # Epoch-2 correction: the exec bit (0x01) is part of identity, so toggling it
    # MUST change the digest (epoch 1 dropped it — a correctness hole).
    reg = compute_dag_identity([MaterializedEntry("run.sh", MODE_REGULAR, b"#!/bin/sh\n")])
    exe = compute_dag_identity([MaterializedEntry("run.sh", MODE_EXECUTABLE, b"#!/bin/sh\n")])
    assert reg != exe


def test_symlink_differs_from_regular_with_same_bytes() -> None:
    # A symlink (0x80) whose target string equals a regular file's content must
    # hash differently — the mode-byte domain-separates them (§1.8.2.1).
    reg = compute_dag_identity([MaterializedEntry("x", MODE_REGULAR, b"target")])
    sym = compute_dag_identity([MaterializedEntry("x", MODE_SYMLINK, b"target")])
    assert reg != sym


def test_dot_git_component_excluded_at_any_depth() -> None:
    base = [MaterializedEntry("src/main.nim", MODE_REGULAR, b"echo\n")]
    polluted = base + [
        MaterializedEntry(".git/HEAD", MODE_REGULAR, b"ref: refs/heads/main\n"),
        MaterializedEntry("vendor/x/.git/config", MODE_REGULAR, b"junk\n"),
    ]
    assert compute_dag_identity(base) == compute_dag_identity(polluted)


def test_empty_subdirectory_omitted_does_not_change_identity() -> None:
    # An intermediate directory that becomes empty contributes no entry (§1.8.5).
    # Here a `.git`-only subdir collapses to nothing, leaving the root unchanged.
    base = [MaterializedEntry("a.txt", MODE_REGULAR, b"alpha\n")]
    with_empty = base + [MaterializedEntry("empty/.git/x", MODE_REGULAR, b"junk\n")]
    assert compute_dag_identity(with_empty) == compute_dag_identity(base)


def test_name_too_long_raises_id_name_too_long() -> None:
    too_long = "x" * 4097
    with pytest.raises(MilpaError) as exc:
        compute_dag_identity([MaterializedEntry(too_long, MODE_REGULAR, b"data")])
    assert exc.value.slug == ID_NAME_TOO_LONG


def test_name_at_ceiling_is_accepted() -> None:
    at_ceiling = "x" * 4096
    # Should not raise; produces a valid identity string.
    out = compute_dag_identity([MaterializedEntry(at_ceiling, MODE_REGULAR, b"data")])
    assert out.startswith("dag-sha256:") and len(out) == len("dag-sha256:") + 64


def test_builder_does_not_import_the_oracle() -> None:
    """SSOT/differential discipline: the production builder must not import the
    frozen conformance oracle (sharing code would defeat the differential check).
    """
    src = Path(__file__).resolve().parents[1] / "milpa" / "dag_identity.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    offending: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offending += [a.name for a in node.names if "dag_sha256_reference" in a.name]
        elif isinstance(node, ast.ImportFrom):
            if node.module and "dag_sha256_reference" in node.module:
                offending.append(node.module)
    assert not offending, f"builder must not import the oracle, found: {offending}"
