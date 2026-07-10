"""Unit tests for atomic_cache.py — the shared per-write-unique-temp-name
atomic writer used by index_cache.py, dep_decl_store.py, and
entry_bundle_store.py (registry-protocol §3.5.2 NORMATIVE (concurrency)).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.atomic_cache import atomic_write_bytes, unique_temp_path


class TestUniqueTempPath:
    def test_never_repeats(self) -> None:
        target = Path("/nonexistent/dir/some.artifact")
        names = {unique_temp_path(target) for _ in range(200)}
        assert len(names) == 200, "temp sibling names must be per-write-unique, not fixed"

    def test_two_interleaved_writers_never_tear(self, tmp_path: Path) -> None:
        """Deterministic simulation of the fixed-name race: two writers
        targeting the SAME path must never observe each other's temp file,
        because each gets its own unique sibling name."""
        target = tmp_path / "shared.artifact"
        content_a = b"A" * 5000
        content_b = b"B" * 5000

        tmp_a = unique_temp_path(target)
        tmp_b = unique_temp_path(target)
        assert tmp_a != tmp_b, (
            "the fixed-name hazard: two writers must not share a temp sibling"
        )

        tmp_a.write_bytes(content_a)
        tmp_b.write_bytes(content_b)
        assert tmp_a.read_bytes() == content_a
        assert tmp_b.read_bytes() == content_b

    def test_sibling_of_target(self) -> None:
        target = Path("/some/dir/file.bundle")
        tmp = unique_temp_path(target)
        assert tmp.parent == target.parent
        assert tmp.name.startswith("file.bundle.tmp.")


class TestAtomicWriteBytes:
    def test_write_then_read_round_trips(self, tmp_path: Path) -> None:
        target = tmp_path / "out.bin"
        atomic_write_bytes(target, b"hello world")
        assert target.read_bytes() == b"hello world"

    def test_no_leftover_temp_file_on_success(self, tmp_path: Path) -> None:
        target = tmp_path / "out.bin"
        atomic_write_bytes(target, b"payload")
        leftovers = [p for p in tmp_path.iterdir() if p != target]
        assert leftovers == []

    def test_failure_cleans_up_temp_and_reraises(self, tmp_path: Path) -> None:
        # A target directory that doesn't exist makes the tmp write fail.
        target = tmp_path / "nonexistent-subdir" / "out.bin"
        with pytest.raises(OSError):
            atomic_write_bytes(target, b"payload")
        # No stray temp file left behind (the failed write never created the
        # parent dir, so nothing to clean up, but assert the target itself
        # was never created either).
        assert not target.exists()
