"""Fetcher tests — exercise real git via subprocess against local fixture repos.

Tests use file:// URLs pointing at bare or non-bare git repos created in
tmp_path. No network access required.
"""

import subprocess
from pathlib import Path

import pytest

from milpa.fetcher import FetchError, fetch_url_dep


def make_repo(path: Path, files: dict[str, str], branch: str = "main") -> Path:
    """Initialize a local git repo at `path` with `files` committed on `branch`.

    Returns `path` for chaining. Uses local user.email/name overrides so
    no global git config is required.
    """
    path.mkdir(parents=True, exist_ok=True)
    run = lambda *args: subprocess.run(
        ["git", "-C", str(path), *args],
        check=True, capture_output=True, text=True,
    )
    subprocess.run(
        ["git", "init", "-q", "-b", branch, str(path)],
        check=True, capture_output=True, text=True,
    )
    for relpath, content in files.items():
        f = path / relpath
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)
    run("add", ".")
    run("-c", "user.email=test@example.com", "-c", "user.name=test",
        "commit", "-q", "-m", "initial")
    return path


def test_clone_local_repo_via_file_url(tmp_path):
    src = make_repo(tmp_path / "src", {"hello.txt": "hello world\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    result = fetch_url_dep(
        "myrepo", f"file://{src}", "main", deps_dir=deps_dir
    )

    assert result.path == deps_dir / "myrepo"
    assert (result.path / "hello.txt").read_text() == "hello world\n"


def test_returned_sha_matches_clone_head(tmp_path):
    src = make_repo(tmp_path / "src", {"a.txt": "alpha\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    result = fetch_url_dep(
        "myrepo", f"file://{src}", "main", deps_dir=deps_dir
    )

    head = subprocess.run(
        ["git", "-C", str(result.path), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert result.sha == head
    # SHA-1 is 40 hex chars
    assert len(result.sha) == 40


def test_content_hash_is_64_hex_chars(tmp_path):
    src = make_repo(tmp_path / "src", {"a.txt": "alpha\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    result = fetch_url_dep(
        "r", f"file://{src}", "main", deps_dir=deps_dir
    )
    assert len(result.content_hash) == 64
    assert all(c in "0123456789abcdef" for c in result.content_hash)


def test_content_hash_is_deterministic(tmp_path):
    # Two repos with identical source content must produce identical
    # content hashes — that's the whole point of content addressing.
    files = {"a.txt": "alpha\n", "b.txt": "beta\n"}
    s1 = make_repo(tmp_path / "src1", files)
    s2 = make_repo(tmp_path / "src2", files)
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    r1 = fetch_url_dep("r1", f"file://{s1}", "main", deps_dir=deps_dir)
    r2 = fetch_url_dep("r2", f"file://{s2}", "main", deps_dir=deps_dir)

    assert r1.content_hash == r2.content_hash


def test_content_hash_differs_on_content_change(tmp_path):
    s1 = make_repo(tmp_path / "src1", {"a.txt": "alpha\n"})
    s2 = make_repo(tmp_path / "src2", {"a.txt": "ALPHA\n"})  # different content
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    r1 = fetch_url_dep("r1", f"file://{s1}", "main", deps_dir=deps_dir)
    r2 = fetch_url_dep("r2", f"file://{s2}", "main", deps_dir=deps_dir)

    assert r1.content_hash != r2.content_hash


def test_idempotent_rerun_returns_same_result(tmp_path):
    src = make_repo(tmp_path / "src", {"a.txt": "alpha\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    r1 = fetch_url_dep("r", f"file://{src}", "main", deps_dir=deps_dir)
    r2 = fetch_url_dep("r", f"file://{src}", "main", deps_dir=deps_dir)

    assert r1 == r2
    assert (deps_dir / "r" / "a.txt").read_text() == "alpha\n"


def test_wrong_ref_existing_dir_updated(tmp_path):
    # Set up a repo with two branches: main (alpha) + dev (beta).
    src = make_repo(tmp_path / "src", {"a.txt": "alpha\n"}, branch="main")
    subprocess.run(
        ["git", "-C", str(src), "checkout", "-q", "-b", "dev"],
        check=True, capture_output=True, text=True,
    )
    (src / "a.txt").write_text("beta\n")
    subprocess.run(
        ["git", "-C", str(src), "-c", "user.email=t@e", "-c", "user.name=t",
         "commit", "-q", "-am", "dev"],
        check=True, capture_output=True, text=True,
    )
    subprocess.run(
        ["git", "-C", str(src), "checkout", "-q", "main"],
        check=True, capture_output=True, text=True,
    )

    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    # First fetch: main → alpha
    r_main = fetch_url_dep("r", f"file://{src}", "main", deps_dir=deps_dir)
    assert (deps_dir / "r" / "a.txt").read_text() == "alpha\n"

    # Second fetch with a different ref: dev → beta. Existing dir gets
    # updated, not blown away or errored on.
    r_dev = fetch_url_dep("r", f"file://{src}", "dev", deps_dir=deps_dir)
    assert (deps_dir / "r" / "a.txt").read_text() == "beta\n"
    assert r_main.sha != r_dev.sha
    assert r_main.content_hash != r_dev.content_hash


def test_bad_url_raises_fetch_error_with_url_in_message(tmp_path):
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()
    bad_url = f"file://{tmp_path}/nonexistent-repo"

    with pytest.raises(FetchError) as exc:
        fetch_url_dep("r", bad_url, "main", deps_dir=deps_dir)
    assert bad_url in str(exc.value)


def test_bad_ref_raises_fetch_error_with_ref_in_message(tmp_path):
    src = make_repo(tmp_path / "src", {"a.txt": "alpha\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    with pytest.raises(FetchError) as exc:
        fetch_url_dep("r", f"file://{src}", "no-such-branch", deps_dir=deps_dir)
    assert "no-such-branch" in str(exc.value)


def test_failure_leaves_no_partial_dir(tmp_path):
    src = make_repo(tmp_path / "src", {"a.txt": "alpha\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    with pytest.raises(FetchError):
        fetch_url_dep("r", f"file://{src}", "no-such-branch", deps_dir=deps_dir)
    # No partial clone left behind for the user to clean up
    assert not (deps_dir / "r").exists()


def test_content_hash_reflects_executable_bit_end_to_end(tmp_path):
    """The content_hash returned by fetch_url_dep flips when a file's
    executable bit changes — verifies the spec lives through git clone
    + checkout + tree-walk, not just the unit-level identity tests."""
    import stat as _stat

    src = tmp_path / "src"
    src.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(src)], check=True)
    script = src / "run.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    run = lambda *a: subprocess.run(
        ["git", "-C", str(src), "-c", "user.email=t@e", "-c", "user.name=t", *a],
        check=True, capture_output=True, text=True,
    )
    run("add", ".")
    run("commit", "-q", "-m", "non-exec")

    deps_dir_a = tmp_path / "deps_a"
    deps_dir_a.mkdir()
    r1 = fetch_url_dep("r", f"file://{src}", "main", deps_dir=deps_dir_a)

    # Flip the exec bit and commit again
    script.chmod(script.stat().st_mode | _stat.S_IXUSR)
    run("update-index", "--chmod=+x", "run.sh")
    run("commit", "-q", "-am", "make exec")

    deps_dir_b = tmp_path / "deps_b"
    deps_dir_b.mkdir()
    r2 = fetch_url_dep("r", f"file://{src}", "main", deps_dir=deps_dir_b)

    # Same file bytes, different exec bit → different content_hash
    assert r1.content_hash != r2.content_hash


def test_content_hash_excludes_dot_git(tmp_path):
    # Two repos with identical SOURCE files but different commit histories
    # (one has an extra empty commit) must have the same content hash —
    # .git is not source content.
    s1 = tmp_path / "src1"
    s1.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(s1)], check=True)
    (s1 / "a.txt").write_text("alpha\n")
    run1 = lambda *a: subprocess.run(
        ["git", "-C", str(s1), "-c", "user.email=test@example.com",
         "-c", "user.name=test", *a],
        check=True, capture_output=True, text=True,
    )
    run1("add", ".")
    run1("commit", "-q", "-m", "first")

    s2 = tmp_path / "src2"
    s2.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(s2)], check=True)
    (s2 / "a.txt").write_text("alpha\n")
    run2 = lambda *a: subprocess.run(
        ["git", "-C", str(s2), "-c", "user.email=test@example.com",
         "-c", "user.name=test", *a],
        check=True, capture_output=True, text=True,
    )
    run2("add", ".")
    run2("commit", "-q", "-m", "first")
    run2("commit", "-q", "--allow-empty", "-m", "extra empty")  # extra history

    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()
    r1 = fetch_url_dep("r1", f"file://{s1}", "main", deps_dir=deps_dir)
    r2 = fetch_url_dep("r2", f"file://{s2}", "main", deps_dir=deps_dir)

    # Different commits, identical source → same content hash.
    assert r1.sha != r2.sha
    assert r1.content_hash == r2.content_hash
