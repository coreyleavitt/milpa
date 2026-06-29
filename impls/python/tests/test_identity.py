"""Tests for milpa/identity.py — content-hash algorithm + identity string validator.

Covers:
  - parse_identity: each of the 5 ordered checks in identity.md §2.2
  - compute_content_hash: determinism, .git/ exclusion, mode bits (§1.3–1.7)
  - Rust byte-compat oracle (§2.1)
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from milpa.errors import (
    ID_NO_ALGORITHM_PREFIX,
    ID_NON_HEX_DIGEST,
    ID_NON_UTF8_RELPATH,
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


def make_tree(files: dict[str, tuple[str, bool]], root: Path) -> Path:
    """Populate `root` with the given files and return `root`.

    ``files`` maps relpath → (content, executable).
    ``root`` must already exist (caller creates it via tmp_path / "name").
    """
    root.mkdir(parents=True, exist_ok=True)
    for relpath, (content, executable) in files.items():
        full = root / relpath
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
        if executable:
            full.chmod(full.stat().st_mode | stat.S_IXUSR)
    return root


# ---------------------------------------------------------------------------
# SUPPORTED_ALGORITHMS constant
# ---------------------------------------------------------------------------


def test_supported_algorithms_contains_dag_sha256() -> None:
    """A1: canonical scheme is dag-sha256; sha256 is not in the supported set."""
    assert "dag-sha256" in SUPPORTED_ALGORITHMS
    assert "sha256" not in SUPPORTED_ALGORITHMS


def test_sha256_prefix_rejected_as_unsupported_algorithm() -> None:
    """A1: stale sha256: identity string → ID-UNSUPPORTED-ALGORITHM (no legacy tier)."""
    stale = "sha256:" + "a" * 64
    with pytest.raises(MilpaError) as exc_info:
        parse_identity(stale)
    assert exc_info.value.slug == ID_UNSUPPORTED_ALGORITHM


def test_dag_sha256_prefix_accepted() -> None:
    """A1: dag-sha256:<64hex> is the canonical form and must round-trip."""
    valid = "dag-sha256:" + "a" * 64
    assert parse_identity(valid) == valid


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
    """Check 4: dag-sha256 digest not exactly 64 chars → ID-WRONG-DIGEST-LENGTH."""
    with pytest.raises(MilpaError) as exc_info:
        parse_identity(f"dag-sha256:{'a' * length}")
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
        parse_identity(f"dag-sha256:{digest}")
    assert exc_info.value.slug == ID_NON_HEX_DIGEST


# ---------------------------------------------------------------------------
# parse_identity — valid identity round-trips unchanged
# ---------------------------------------------------------------------------


def test_parse_identity_valid_lowercase_hex_accepted() -> None:
    """A well-formed dag-sha256 identity is accepted and returned unchanged."""
    valid = "dag-sha256:" + "a" * 64
    assert parse_identity(valid) == valid


def test_parse_identity_valid_uses_full_hex_alphabet() -> None:
    """All of 0-9 + a-f are accepted."""
    digest = ("0123456789abcdef" * 4)[:64]
    valid = f"dag-sha256:{digest}"
    assert parse_identity(valid) == valid


def test_parse_identity_uppercase_f_rejected() -> None:
    """Uppercase hex is explicitly rejected (§2.1: MUST use lowercase)."""
    digest = "F" * 64  # uppercase F — hex but wrong case
    with pytest.raises(MilpaError) as exc_info:
        parse_identity(f"dag-sha256:{digest}")
    assert exc_info.value.slug == ID_NON_HEX_DIGEST


# ---------------------------------------------------------------------------
# compute_content_hash — determinism (identity.md §1.1)
# ---------------------------------------------------------------------------


def test_same_tree_produces_same_hash_determinism(tmp_path: Path) -> None:
    """Two identical trees produce the same hash (determinism, §1.1)."""
    files: dict[str, tuple[str, bool]] = {
        "src/main.nim": ("import std/strutils\nproc main() = echo \"hi\"\n", False),
        "README.md": ("# project\n", False),
        "scripts/run.sh": ("#!/bin/sh\nexec nim r src/main.nim\n", True),
    }
    tree_a = make_tree(files, tmp_path / "a")
    tree_b = make_tree(files, tmp_path / "b")
    assert compute_content_hash(tree_a) == compute_content_hash(tree_b)


def test_different_content_produces_different_hash(tmp_path: Path) -> None:
    """Adding a file changes the hash (basic sanity)."""
    tree_a = make_tree({"a.txt": ("hello\n", False)}, tmp_path / "a")
    tree_b = make_tree({"a.txt": ("hello\n", False), "b.txt": ("world\n", False)}, tmp_path / "b")
    assert compute_content_hash(tree_a) != compute_content_hash(tree_b)


# ---------------------------------------------------------------------------
# compute_content_hash — .git/ exclusion (identity.md §1.4)
# ---------------------------------------------------------------------------


def test_dot_git_at_root_excluded(tmp_path: Path) -> None:
    """Files under .git/ at the root are excluded from the hash (§1.4)."""
    tree_a = make_tree({"src/main.nim": ("echo 'hi'\n", False)}, tmp_path / "a")
    tree_b = make_tree({
        "src/main.nim": ("echo 'hi'\n", False),
        ".git/HEAD": ("ref: refs/heads/main\n", False),
        ".git/objects/ab/cd1234": ("binary junk", False),
    }, tmp_path / "b")
    assert compute_content_hash(tree_a) == compute_content_hash(tree_b)


def test_dot_git_at_nested_depth_excluded(tmp_path: Path) -> None:
    """Files under a nested .git/ (e.g. vendor/foo/.git/) are also excluded (§1.4)."""
    tree_a = make_tree({"src/main.nim": ("echo 'hi'\n", False)}, tmp_path / "a")
    tree_b = make_tree({
        "src/main.nim": ("echo 'hi'\n", False),
        "vendor/foo/.git/HEAD": ("ref: refs/heads/main\n", False),
    }, tmp_path / "b")
    assert compute_content_hash(tree_a) == compute_content_hash(tree_b)


def test_adding_files_under_git_does_not_change_hash(tmp_path: Path) -> None:
    """Adding arbitrary files under .git/ does not affect the hash (§1.4)."""
    base_files: dict[str, tuple[str, bool]] = {"main.nim": ("echo hi\n", False)}
    tree_a = make_tree(base_files, tmp_path / "a")
    tree_b = make_tree({
        **base_files,
        ".git/HEAD": ("ref: refs/heads/main\n", False),
        ".git/config": ("[core]\n\trepositoryformatversion = 0\n", False),
        ".git/objects/pack/pack-abc123.pack": ("binary\x00data", False),
    }, tmp_path / "b")
    assert compute_content_hash(tree_a) == compute_content_hash(tree_b)


# ---------------------------------------------------------------------------
# compute_content_hash — exec bit IS part of identity (epoch 2, §1.8.2 / §1.8.10)
# ---------------------------------------------------------------------------


def test_executable_bit_changes_hash(tmp_path: Path) -> None:
    """Setting the owner-execute bit DOES change the hash (epoch 2, §1.8.2).

    Epoch 2 uses a four-valued mode-byte: a regular file (0x00) and an executable
    file (0x01) with identical bytes materialize *different* tree nodes, so they
    hash differently — a deliberate correction over the interim epoch-1 stream
    (which excluded the exec bit).
    """
    content = "#!/bin/sh\necho hi\n"
    tree_non_exec = make_tree({"script.sh": (content, False)}, tmp_path / "non_exec")
    tree_exec = make_tree({"script.sh": (content, True)}, tmp_path / "exec")
    assert compute_content_hash(tree_non_exec) != compute_content_hash(tree_exec)


def test_any_execute_bit_affects_hash(tmp_path: Path) -> None:
    """Any of owner/group/world execute bits flips the file to mode-byte 0x01,
    changing identity (epoch 2, §1.8.2.1: ``st_mode & 0o111``)."""
    base = make_tree({"f.sh": ("#!/bin/sh\n", False)}, tmp_path / "t")
    base_hash = compute_content_hash(base)

    # Owner-execute (S_IXUSR = 0o100) → mode-byte 0x01 → different hash.
    owner = make_tree({"f.sh": ("#!/bin/sh\n", False)}, tmp_path / "owner")
    (owner / "f.sh").chmod((owner / "f.sh").stat().st_mode | 0o100)
    assert compute_content_hash(owner) != base_hash

    # Group-execute (S_IXGRP = 0o010) → mode-byte 0x01 → different hash.
    group = make_tree({"f.sh": ("#!/bin/sh\n", False)}, tmp_path / "group")
    (group / "f.sh").chmod((group / "f.sh").stat().st_mode | 0o010)
    assert compute_content_hash(group) != base_hash

    # World-execute (S_IXOTH = 0o001) → mode-byte 0x01 → different hash.
    world = make_tree({"f.sh": ("#!/bin/sh\n", False)}, tmp_path / "world")
    (world / "f.sh").chmod((world / "f.sh").stat().st_mode | 0o001)
    assert compute_content_hash(world) != base_hash


# ---------------------------------------------------------------------------
# compute_content_hash — symlink handling (identity.md §1.5)
# ---------------------------------------------------------------------------


def test_symlink_hashed_by_target_string_not_followed(tmp_path: Path) -> None:
    """Symlinks with different targets produce different hashes (§1.5)."""
    tmp_a = tmp_path / "a"
    tmp_b = tmp_path / "b"
    tmp_a.mkdir()
    tmp_b.mkdir()
    (tmp_a / "real.txt").write_text("hello\n", encoding="utf-8")
    os.symlink("real.txt", tmp_a / "link")
    (tmp_b / "real.txt").write_text("hello\n", encoding="utf-8")
    os.symlink("different_target", tmp_b / "link")
    assert compute_content_hash(tmp_a) != compute_content_hash(tmp_b)


def test_symlink_vs_regular_file_same_content_differ(tmp_path: Path) -> None:
    """A symlink whose target string equals a file's content still hashes differently
    because the mode marker differs (§1.2)."""
    tmp_a = tmp_path / "a"
    tmp_b = tmp_path / "b"
    tmp_a.mkdir()
    tmp_b.mkdir()
    (tmp_a / "entry").write_bytes(b"target")  # regular file
    os.symlink("target", tmp_b / "entry")     # symlink with same bytes as target string
    assert compute_content_hash(tmp_a) != compute_content_hash(tmp_b)


def test_broken_symlink_does_not_crash(tmp_path: Path) -> None:
    """A symlink pointing to a non-existent target is hashed by target string (§1.5)."""
    tmp = tmp_path / "t"
    tmp.mkdir()
    os.symlink("/nonexistent/elsewhere", tmp / "broken")
    result = compute_content_hash(tmp)
    assert result.startswith("dag-sha256:")
    digest = result[len("dag-sha256:"):]
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


# ---------------------------------------------------------------------------
# compute_content_hash — empty tree (§1.2)
# ---------------------------------------------------------------------------


def test_empty_tree_hashes_empty_root(tmp_path: Path) -> None:
    """An empty tree is the zero-entry Merkle-DAG root: sha256(b"") (§1.8.5).

    The empty-root digest is independently pinned (the conformance authority's
    empty-root oracle); under epoch 2 a zero-entry root hashes the empty byte
    string, so the value coincides with sha256("").
    """
    tmp = tmp_path / "empty"
    tmp.mkdir()
    assert compute_content_hash(tmp) == (
        "dag-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


# ---------------------------------------------------------------------------
# compute_content_hash — output format (identity.md §2.1)
# ---------------------------------------------------------------------------


def test_output_has_dag_sha256_prefix(tmp_path: Path) -> None:
    """Output always starts with 'dag-sha256:' (§2.1, A1 epoch)."""
    tmp = make_tree({"a.nim": ("echo hi\n", False)}, tmp_path / "t")
    result = compute_content_hash(tmp)
    assert result.startswith("dag-sha256:")


def test_output_hex_is_64_lowercase_chars(tmp_path: Path) -> None:
    """The digest part is exactly 64 lowercase hex chars (§2.1)."""
    tmp = make_tree({"a.nim": ("echo hi\n", False)}, tmp_path / "t")
    result = compute_content_hash(tmp)
    digest = result[len("dag-sha256:"):]
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_output_is_valid_per_parse_identity(tmp_path: Path) -> None:
    """compute_content_hash output always passes parse_identity (§2.1 / §2.2)."""
    tmp = make_tree({"src/lib.nim": ("proc foo() = discard\n", False)}, tmp_path / "t")
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
    "dag-sha256:10c68c24594e4ab384f0672a67b738eab5190e0837a3e09dd27e89eb1172791a"
)


def test_byte_compat_with_rust_reference_oracle(tmp_path: Path) -> None:
    """Byte-exact hash matches the Rust reference impl's oracle (cross-impl parity).

    Tree: README.md (non-exec), src/main.nim (non-exec), run.sh (exec),
          mainlink→src/main.nim (symlink), .git/HEAD (excluded).
    """
    tmp = tmp_path / "oracle"
    tmp.mkdir()

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


def test_crlf_and_lf_produce_different_hashes(tmp_path: Path) -> None:
    """CRLF and LF are distinct; no normalisation is applied (§1.6)."""
    tree_lf = make_tree({"file.txt": ("line1\nline2\n", False)}, tmp_path / "lf")
    tree_crlf = make_tree({"file.txt": ("line1\r\nline2\r\n", False)}, tmp_path / "crlf")
    assert compute_content_hash(tree_lf) != compute_content_hash(tree_crlf)


# ---------------------------------------------------------------------------
# compute_content_hash — ID-NON-UTF8-SYMLINK-TARGET (identity.md §1.5 normative)
# ---------------------------------------------------------------------------


def test_non_utf8_symlink_target_raises_error(tmp_path: Path) -> None:
    """A symlink whose target is non-UTF-8 raises ID-NON-UTF8-SYMLINK-TARGET (§1.5)."""
    tmp = tmp_path / "t"
    tmp.mkdir()
    # Create a symlink with a raw non-UTF-8 target using os.symlink with bytes.
    raw_target = b"\xff\xfe"  # not valid UTF-8
    os.symlink(raw_target, tmp / "bad_link")
    with pytest.raises(MilpaError) as exc_info:
        compute_content_hash(tmp)
    assert exc_info.value.slug == ID_NON_UTF8_SYMLINK_TARGET


# ---------------------------------------------------------------------------
# compute_content_hash — ID-NON-UTF8-RELPATH (spec/errors.md; distinct from
# ID-NON-UTF8-SYMLINK-TARGET which covers non-UTF-8 symlink *targets*)
# ---------------------------------------------------------------------------


def test_non_utf8_relpath_raises_error(tmp_path: Path) -> None:
    """A file whose name contains non-UTF-8 bytes raises ID-NON-UTF8-RELPATH.

    Mirrors the ID-NON-UTF8-SYMLINK-TARGET test: create a real filesystem entry
    whose *name* (not target) is non-UTF-8, then verify compute_content_hash
    raises the coded MilpaError rather than an uncoded UnicodeEncodeError crash.

    Skipped gracefully if the OS/filesystem rejects the filename.
    """
    tmp = tmp_path / "t"
    tmp.mkdir()
    # Construct a directory whose byte name is non-UTF-8.
    # Use bytes API to create a path component with raw 0xff byte.
    bad_name = b"\xff\xfe"  # not valid UTF-8
    bad_dir_bytes = os.fsencode(tmp) + b"/" + bad_name
    try:
        os.mkdir(bad_dir_bytes)
        # Place a regular file inside the non-UTF-8-named directory so rglob
        # encounters the bad relpath.
        child = bad_dir_bytes + b"/file.txt"
        with open(child, "wb") as f:
            f.write(b"hello")
    except OSError:
        # Some filesystems (vfat, certain WSL mounts) reject non-UTF-8 byte
        # sequences in filenames; skip gracefully.
        pytest.skip("filesystem rejected non-UTF-8 filename bytes")

    with pytest.raises(MilpaError) as exc_info:
        compute_content_hash(tmp)
    assert exc_info.value.slug == ID_NON_UTF8_RELPATH


# ---------------------------------------------------------------------------
# B-cutover STEP-1 invariant: a git-materialized ON-DISK tree hashed through the
# production identity site (compute_content_hash → enumerate_local_entries → DAG)
# equals the git OBJECT-STORE enumeration (enumerate_git_entries → DAG), and both
# equal the independently hand-frozen nested oracle pin.
#
# This is the load-bearing invariant of the clean cutover: because CAS verify
# re-hashes the on-disk stored tree, the production identity MUST be derivable
# from the on-disk tree. The per-transport object-store enumerator then stands as
# the faithfulness PROOF, not a second identity source. If this ever diverges
# (e.g. materialize_git_tree drops the exec bit or a symlink on disk), it is a
# real correctness BLOCKER, not something to paper over.
# ---------------------------------------------------------------------------

#: Independently hand-frozen nested-tree oracle pin (conformance authority).
_NESTED_PIN = "dag-sha256:e3213019260649b72bb0295aaec004eb20a625dd55fcd4bac9e35df96bce316f"


def _git(repo: Path, *args: str) -> None:
    import subprocess

    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t",
         "-c", "core.autocrlf=false", *args],
        check=True, capture_output=True, text=True,
    )


def test_git_materialized_ondisk_equals_object_store_invariant(tmp_path: Path) -> None:
    """on-disk(git-materialized) identity == git object-store identity == nested pin."""
    import subprocess

    from milpa.dag_identity import compute_dag_identity
    from milpa.fetchers.git import enumerate_git_entries, materialize_git_tree
    from milpa.identity import enumerate_local_entries

    # Build the nested oracle tree (a.txt, a/b.txt, a/run.sh +x, link → a/b.txt).
    repo = tmp_path / "nested"
    repo.mkdir()
    (repo / "a.txt").write_text("alpha\n")
    (repo / "a").mkdir()
    (repo / "a/b.txt").write_text("beta\n")
    (repo / "a/run.sh").write_text("#!/bin/sh\necho hi\n")
    os.chmod(repo / "a/run.sh", 0o755)
    os.symlink("a/b.txt", repo / "link")
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "nested")
    commit = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "main"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()

    # Clone --no-checkout: object store only (mirrors GitFetcher discipline).
    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "-q", "--no-checkout", f"file://{repo.resolve()}", str(clone)],
        check=True, capture_output=True, text=True,
    )

    # Object-store enumeration → identity.
    obj_entries, _ = enumerate_git_entries(clone, commit, submodule_fetch=None)
    obj_identity = compute_dag_identity(obj_entries)

    # Materialize to disk via the production disk writer, then the production
    # identity site (compute_content_hash uses the same enumerate_local_entries walk).
    dest = tmp_path / "dest"
    dest.mkdir()
    materialize_git_tree(clone, commit, dest, submodule_fetch=None)
    ondisk_identity = compute_content_hash(dest)
    # Sanity: compute_content_hash IS enumerate_local_entries → compute_dag_identity.
    assert ondisk_identity == compute_dag_identity(enumerate_local_entries(dest))

    assert obj_identity == _NESTED_PIN, "object-store enumeration drifted from the pin"
    assert ondisk_identity == _NESTED_PIN, (
        "git-materialized ON-DISK tree hashed differently from the object-store pin — "
        "materialize_git_tree did not preserve the tree faithfully (exec bit / symlink)"
    )
    assert ondisk_identity == obj_identity
