"""Tests for milpa/identity.py — content-hash algorithm + identity string validator.

Covers:
  - parse_identity: each of the 5 ordered checks in identity.md §2.2
  - compute_content_hash: determinism, .git/ exclusion, mode bits (§1.3–1.7)
  - Rust byte-compat oracle (§2.1)
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

import pytest

from milpa.errors import (
    ID_NO_ALGORITHM_PREFIX,
    ID_NON_HEX_DIGEST,
    ID_NON_UTF8_SYMLINK_TARGET,
    ID_NOT_A_STRING,
    ID_UNSUPPORTED_ALGORITHM,
    ID_WRONG_DIGEST_LENGTH,
    MilpaError,
)
from milpa.identity import SUPPORTED_ALGORITHMS, compute_content_hash, parse_identity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_tree(files: dict[str, tuple[str, bool]]) -> Path:
    """Create a temp dir containing the given files.

    ``files`` maps relpath → (content, executable).
    Returns the root Path.
    """
    tmp = Path(tempfile.mkdtemp())
    for relpath, (content, executable) in files.items():
        full = tmp / relpath
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
        if executable:
            full.chmod(full.stat().st_mode | stat.S_IXUSR)
    return tmp


# ---------------------------------------------------------------------------
# SUPPORTED_ALGORITHMS constant
# ---------------------------------------------------------------------------


def test_supported_algorithms_contains_sha256() -> None:
    assert "sha256" in SUPPORTED_ALGORITHMS


# ---------------------------------------------------------------------------
# parse_identity — check 1: must be a string (ID-NOT-A-STRING)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, 42, 3.14, b"sha256:" + b"a" * 64, [], {}])
def test_parse_identity_non_string_raises_not_a_string(value: object) -> None:
    """Check 1: any non-str input → ID-NOT-A-STRING."""
    with pytest.raises(MilpaError) as exc_info:
        parse_identity(value)
    assert exc_info.value.slug == ID_NOT_A_STRING


# ---------------------------------------------------------------------------
# parse_identity — check 2: must contain ':' (ID-NO-ALGORITHM-PREFIX)
# ---------------------------------------------------------------------------


def test_parse_identity_no_colon_raises_no_algorithm_prefix() -> None:
    """Check 2: bare hex string without ':' → ID-NO-ALGORITHM-PREFIX."""
    with pytest.raises(MilpaError) as exc_info:
        parse_identity("a" * 64)
    assert exc_info.value.slug == ID_NO_ALGORITHM_PREFIX


def test_parse_identity_empty_string_raises_no_algorithm_prefix() -> None:
    with pytest.raises(MilpaError) as exc_info:
        parse_identity("")
    assert exc_info.value.slug == ID_NO_ALGORITHM_PREFIX


# ---------------------------------------------------------------------------
# parse_identity — check 3: algorithm must be supported (ID-UNSUPPORTED-ALGORITHM)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algo", ["md5", "sha1", "sha512", "blake2b", "SHA256"])
def test_parse_identity_unsupported_algorithm(algo: str) -> None:
    """Check 3: unknown or wrong-case algorithm → ID-UNSUPPORTED-ALGORITHM."""
    # Use a plausible-length digest so we don't trigger a different error.
    digest = "a" * 64
    with pytest.raises(MilpaError) as exc_info:
        parse_identity(f"{algo}:{digest}")
    assert exc_info.value.slug == ID_UNSUPPORTED_ALGORITHM


# ---------------------------------------------------------------------------
# parse_identity — check 4: digest length must be correct (ID-WRONG-DIGEST-LENGTH)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [0, 1, 32, 63, 65, 128])
def test_parse_identity_wrong_digest_length(length: int) -> None:
    """Check 4: sha256 digest not exactly 64 chars → ID-WRONG-DIGEST-LENGTH."""
    with pytest.raises(MilpaError) as exc_info:
        parse_identity(f"sha256:{'a' * length}")
    assert exc_info.value.slug == ID_WRONG_DIGEST_LENGTH


# ---------------------------------------------------------------------------
# parse_identity — check 5: digest must be lowercase hex (ID-NON-HEX-DIGEST)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "digest",
    [
        "Z" * 64,                         # uppercase non-hex letters
        "A" * 64,                         # uppercase hex letters (uppercase is rejected)
        "g" * 64,                         # lowercase but non-hex
        "a" * 63 + " ",                   # trailing space
        "a" * 63 + "\x00",               # null byte
    ],
)
def test_parse_identity_non_hex_digest(digest: str) -> None:
    """Check 5: non-lowercase-hex chars in digest → ID-NON-HEX-DIGEST."""
    assert len(digest) == 64, "test setup: digest must be exactly 64 chars"
    with pytest.raises(MilpaError) as exc_info:
        parse_identity(f"sha256:{digest}")
    assert exc_info.value.slug == ID_NON_HEX_DIGEST


# ---------------------------------------------------------------------------
# parse_identity — valid identity round-trips unchanged
# ---------------------------------------------------------------------------


def test_parse_identity_valid_lowercase_hex_accepted() -> None:
    """A well-formed sha256 identity is accepted and returned unchanged."""
    valid = "sha256:" + "a" * 64
    assert parse_identity(valid) == valid


def test_parse_identity_valid_uses_full_hex_alphabet() -> None:
    """All of 0-9 + a-f are accepted."""
    digest = ("0123456789abcdef" * 4)[:64]
    valid = f"sha256:{digest}"
    assert parse_identity(valid) == valid


def test_parse_identity_uppercase_f_rejected() -> None:
    """Uppercase hex is explicitly rejected (§2.1: MUST use lowercase)."""
    digest = "F" * 64  # uppercase F — hex but wrong case
    with pytest.raises(MilpaError) as exc_info:
        parse_identity(f"sha256:{digest}")
    assert exc_info.value.slug == ID_NON_HEX_DIGEST


# ---------------------------------------------------------------------------
# compute_content_hash — determinism (identity.md §1.1)
# ---------------------------------------------------------------------------


def test_same_tree_produces_same_hash_determinism() -> None:
    """Two identical trees produce the same hash (determinism, §1.1)."""
    files: dict[str, tuple[str, bool]] = {
        "src/main.nim": ("import std/strutils\nproc main() = echo \"hi\"\n", False),
        "README.md": ("# project\n", False),
        "scripts/run.sh": ("#!/bin/sh\nexec nim r src/main.nim\n", True),
    }
    tree_a = make_tree(files)
    tree_b = make_tree(files)
    assert compute_content_hash(tree_a) == compute_content_hash(tree_b)


def test_different_content_produces_different_hash() -> None:
    """Adding a file changes the hash (basic sanity)."""
    tree_a = make_tree({"a.txt": ("hello\n", False)})
    tree_b = make_tree({"a.txt": ("hello\n", False), "b.txt": ("world\n", False)})
    assert compute_content_hash(tree_a) != compute_content_hash(tree_b)


# ---------------------------------------------------------------------------
# compute_content_hash — .git/ exclusion (identity.md §1.4)
# ---------------------------------------------------------------------------


def test_dot_git_at_root_excluded() -> None:
    """Files under .git/ at the root are excluded from the hash (§1.4)."""
    tree_a = make_tree({"src/main.nim": ("echo 'hi'\n", False)})
    tree_b = make_tree({
        "src/main.nim": ("echo 'hi'\n", False),
        ".git/HEAD": ("ref: refs/heads/main\n", False),
        ".git/objects/ab/cd1234": ("binary junk", False),
    })
    assert compute_content_hash(tree_a) == compute_content_hash(tree_b)


def test_dot_git_at_nested_depth_excluded() -> None:
    """Files under a nested .git/ (e.g. vendor/foo/.git/) are also excluded (§1.4)."""
    tree_a = make_tree({"src/main.nim": ("echo 'hi'\n", False)})
    tree_b = make_tree({
        "src/main.nim": ("echo 'hi'\n", False),
        "vendor/foo/.git/HEAD": ("ref: refs/heads/main\n", False),
    })
    assert compute_content_hash(tree_a) == compute_content_hash(tree_b)


def test_adding_files_under_git_does_not_change_hash() -> None:
    """Adding arbitrary files under .git/ does not affect the hash (§1.4)."""
    base_files: dict[str, tuple[str, bool]] = {"main.nim": ("echo hi\n", False)}
    tree_a = make_tree(base_files)
    tree_b = make_tree({
        **base_files,
        ".git/HEAD": ("ref: refs/heads/main\n", False),
        ".git/config": ("[core]\n\trepositoryformatversion = 0\n", False),
        ".git/objects/pack/pack-abc123.pack": ("binary\x00data", False),
    })
    assert compute_content_hash(tree_a) == compute_content_hash(tree_b)


# ---------------------------------------------------------------------------
# compute_content_hash — mode bits matter (identity.md §1.7)
# ---------------------------------------------------------------------------


def test_executable_bit_changes_hash() -> None:
    """Toggling the owner-execute bit changes the hash (§1.7)."""
    content = "#!/bin/sh\necho hi\n"
    tree_non_exec = make_tree({"script.sh": (content, False)})
    tree_exec = make_tree({"script.sh": (content, True)})
    assert compute_content_hash(tree_non_exec) != compute_content_hash(tree_exec)


def test_only_owner_execute_bit_is_significant() -> None:
    """Group/world execute bits do NOT affect the hash; only S_IXUSR does (§1.7)."""
    tree = make_tree({"f.sh": ("#!/bin/sh\n", False)})
    fpath = tree / "f.sh"

    # Start with no execute bits.
    base_hash = compute_content_hash(tree)

    # Set group-execute only (S_IXGRP = 0o010) — should NOT change the hash.
    fpath.chmod(fpath.stat().st_mode | 0o010)
    assert compute_content_hash(tree) == base_hash

    # Set world-execute only (S_IXOTH = 0o001) — should NOT change the hash.
    fpath.chmod(fpath.stat().st_mode | 0o001)
    assert compute_content_hash(tree) == base_hash

    # Now set owner-execute (S_IXUSR = 0o100) — MUST change the hash.
    fpath.chmod(fpath.stat().st_mode | stat.S_IXUSR)
    assert compute_content_hash(tree) != base_hash


# ---------------------------------------------------------------------------
# compute_content_hash — symlink handling (identity.md §1.5)
# ---------------------------------------------------------------------------


def test_symlink_hashed_by_target_string_not_followed() -> None:
    """Symlinks with different targets produce different hashes (§1.5)."""
    tmp_a = Path(tempfile.mkdtemp())
    tmp_b = Path(tempfile.mkdtemp())
    (tmp_a / "real.txt").write_text("hello\n", encoding="utf-8")
    os.symlink("real.txt", tmp_a / "link")
    (tmp_b / "real.txt").write_text("hello\n", encoding="utf-8")
    os.symlink("different_target", tmp_b / "link")
    assert compute_content_hash(tmp_a) != compute_content_hash(tmp_b)


def test_symlink_vs_regular_file_same_content_differ() -> None:
    """A symlink whose target string equals a file's content still hashes differently
    because the mode marker differs (§1.2)."""
    tmp_a = Path(tempfile.mkdtemp())
    tmp_b = Path(tempfile.mkdtemp())
    (tmp_a / "entry").write_bytes(b"target")  # regular file
    os.symlink("target", tmp_b / "entry")     # symlink with same bytes as target string
    assert compute_content_hash(tmp_a) != compute_content_hash(tmp_b)


def test_broken_symlink_does_not_crash() -> None:
    """A symlink pointing to a non-existent target is hashed by target string (§1.5)."""
    tmp = Path(tempfile.mkdtemp())
    os.symlink("/nonexistent/elsewhere", tmp / "broken")
    result = compute_content_hash(tmp)
    assert result.startswith("sha256:")
    digest = result[len("sha256:"):]
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


# ---------------------------------------------------------------------------
# compute_content_hash — empty tree (§1.2)
# ---------------------------------------------------------------------------


def test_empty_tree_hashes_empty_byte_stream() -> None:
    """An empty tree produces sha256 of the empty byte stream (§1.2)."""
    tmp = Path(tempfile.mkdtemp())
    # sha256("") = e3b0c44...
    assert compute_content_hash(tmp) == (
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


# ---------------------------------------------------------------------------
# compute_content_hash — output format (identity.md §2.1)
# ---------------------------------------------------------------------------


def test_output_has_sha256_prefix() -> None:
    """Output always starts with 'sha256:' (§2.1)."""
    tmp = make_tree({"a.nim": ("echo hi\n", False)})
    result = compute_content_hash(tmp)
    assert result.startswith("sha256:")


def test_output_hex_is_64_lowercase_chars() -> None:
    """The digest part is exactly 64 lowercase hex chars (§2.1)."""
    tmp = make_tree({"a.nim": ("echo hi\n", False)})
    result = compute_content_hash(tmp)
    digest = result[len("sha256:"):]
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_output_is_valid_per_parse_identity() -> None:
    """compute_content_hash output always passes parse_identity (§2.1 / §2.2)."""
    tmp = make_tree({"src/lib.nim": ("proc foo() = discard\n", False)})
    identity = compute_content_hash(tmp)
    assert parse_identity(identity) == identity


# ---------------------------------------------------------------------------
# Rust byte-compat oracle (identity.md §2.1 — byte-exact cross-impl check)
#
# The expected hash below is taken from the Rust reference impl's
# `byte_parity_with_python_oracle` test in identity.rs, which in turn was
# generated from the frozen Python reference implementation.  All three must
# agree.  Regenerate ONLY by re-running the oracle on an identical tree.
# ---------------------------------------------------------------------------

RUST_ORACLE_HASH = (
    "sha256:efa2102677df3bf6ffee86e2503f78e1467ecca8de4ea1a1f79762b2011c60b9"
)


def test_byte_compat_with_rust_reference_oracle() -> None:
    """Byte-exact hash matches the Rust reference impl's oracle (cross-impl parity).

    Tree: README.md (non-exec), src/main.nim (non-exec), run.sh (exec),
          mainlink→src/main.nim (symlink), .git/HEAD (excluded).
    """
    tmp = Path(tempfile.mkdtemp())

    # src/main.nim — non-executable
    src = tmp / "src"
    src.mkdir()
    (src / "main.nim").write_text(
        'import std/strutils\nproc main() = echo "hi"\n', encoding="utf-8"
    )

    # README.md — non-executable
    (tmp / "README.md").write_text("# project\n", encoding="utf-8")

    # run.sh — executable
    run = tmp / "run.sh"
    run.write_text("#!/bin/sh\nexec nim r src/main.nim\n", encoding="utf-8")
    run.chmod(run.stat().st_mode | stat.S_IXUSR)

    # mainlink → src/main.nim (symlink; hashed by target string, not followed)
    os.symlink("src/main.nim", tmp / "mainlink")

    # .git/HEAD — must be excluded
    git_dir = tmp / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("junk\n", encoding="utf-8")

    assert compute_content_hash(tmp) == RUST_ORACLE_HASH


# ---------------------------------------------------------------------------
# compute_content_hash — no line-ending normalisation (identity.md §1.6)
# ---------------------------------------------------------------------------


def test_crlf_and_lf_produce_different_hashes() -> None:
    """CRLF and LF are distinct; no normalisation is applied (§1.6)."""
    tree_lf = make_tree({"file.txt": ("line1\nline2\n", False)})
    tree_crlf = make_tree({"file.txt": ("line1\r\nline2\r\n", False)})
    assert compute_content_hash(tree_lf) != compute_content_hash(tree_crlf)


# ---------------------------------------------------------------------------
# compute_content_hash — ID-NON-UTF8-SYMLINK-TARGET (identity.md §1.5 normative)
# ---------------------------------------------------------------------------


def test_non_utf8_symlink_target_raises_error() -> None:
    """A symlink whose target is non-UTF-8 raises ID-NON-UTF8-SYMLINK-TARGET (§1.5)."""
    tmp = Path(tempfile.mkdtemp())
    # Create a symlink with a raw non-UTF-8 target using os.symlink with bytes.
    raw_target = b"\xff\xfe"  # not valid UTF-8
    os.symlink(raw_target, tmp / "bad_link")
    with pytest.raises(MilpaError) as exc_info:
        compute_content_hash(tmp)
    assert exc_info.value.slug == ID_NON_UTF8_SYMLINK_TARGET
