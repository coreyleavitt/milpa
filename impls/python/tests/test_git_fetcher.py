"""GitFetcher tests — exercise real git via subprocess against local
fixture repos. Tests use file:// URLs pointing at local repos created
in tmp_path; no network required.

Identity-level invariants (sha256 of source tree across edge cases)
are tested end-to-end through the registry — that's the surface a
consumer sees.
"""

import subprocess
from pathlib import Path

import pytest

from milpa.fetchers import FetchError, FetcherRegistry
from milpa.fetchers.git import GitFetcher, GitProvenance


def make_repo(path: Path, files: dict[str, str], branch: str = "main") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-q", "-b", branch, str(path)],
        check=True, capture_output=True, text=True,
    )
    for relpath, content in files.items():
        f = path / relpath
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)
    run = lambda *args: subprocess.run(
        ["git", "-C", str(path),
         "-c", "user.email=test@example.com", "-c", "user.name=test",
         *args],
        check=True, capture_output=True, text=True,
    )
    run("add", ".")
    run("commit", "-q", "-m", "initial")
    return path


def make_repo_with_history(
    path: Path, commits: list[dict[str, str]], branch: str = "main",
) -> list[str]:
    """Create a repo with one commit per entry in `commits`. Returns the
    list of commit SHAs in order. Lets a test pin a commit that is NOT the
    branch tip (the single-commit make_repo can't express that)."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-q", "-b", branch, str(path)],
        check=True, capture_output=True, text=True,
    )
    run = lambda *args: subprocess.run(
        ["git", "-C", str(path),
         "-c", "user.email=test@example.com", "-c", "user.name=test",
         *args],
        check=True, capture_output=True, text=True,
    )
    shas: list[str] = []
    for i, files in enumerate(commits):
        for relpath, content in files.items():
            f = path / relpath
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(content)
        run("add", ".")
        run("commit", "-q", "-m", f"commit {i}")
        shas.append(
            run("rev-parse", "HEAD").stdout.strip()
        )
    return shas


@pytest.fixture
def registry():
    r = FetcherRegistry()
    r.register(GitFetcher())
    return r


def fetch(registry, name, src, ref, dest_parent):
    return registry.fetch(
        name,
        GitProvenance(url=f"file://{src}", ref=ref),
        dest=dest_parent / name,
    )


def test_clone_local_repo_via_file_url(tmp_path, registry):
    src = make_repo(tmp_path / "src", {"hello.txt": "hello world\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    result = fetch(registry, "myrepo", src, "main", deps_dir)

    assert result.path == deps_dir / "myrepo"
    assert (result.path / "hello.txt").read_text() == "hello world\n"


def test_receipt_commit_sha_matches_clone_head(tmp_path, registry):
    src = make_repo(tmp_path / "src", {"a.txt": "alpha\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    result = fetch(registry, "myrepo", src, "main", deps_dir)

    head = subprocess.run(
        ["git", "-C", str(result.path), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert result.receipt.commit_sha == head
    assert len(result.receipt.commit_sha) == 40


def test_commit_sha_checks_out_exact_commit_not_tip(tmp_path, registry):
    # S2.5 (milpa#97): the index pins an immutable commit_sha, which may
    # NOT be the branch tip. GitFetcher must check out that exact commit.
    shas = make_repo_with_history(
        tmp_path / "src",
        [
            {"v.txt": "first\n"},
            {"v.txt": "second\n"},
            {"v.txt": "third-tip\n"},
        ],
    )
    first_sha = shas[0]
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    result = registry.fetch(
        "r",
        GitProvenance(
            url=f"file://{tmp_path / 'src'}",
            ref="main",
            commit_sha=first_sha,
        ),
        dest=deps_dir / "r",
    )
    # The working tree is the FIRST commit's content, not the tip's.
    assert (result.path / "v.txt").read_text() == "first\n"
    assert result.receipt.commit_sha == first_sha


def test_no_commit_sha_falls_back_to_ref_tip(tmp_path, registry):
    # commit_sha=None preserves the legacy tip-checkout behavior for every
    # existing caller (url/named-without-pin).
    shas = make_repo_with_history(
        tmp_path / "src",
        [{"v.txt": "first\n"}, {"v.txt": "tip\n"}],
    )
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    result = registry.fetch(
        "r",
        GitProvenance(url=f"file://{tmp_path / 'src'}", ref="main"),
        dest=deps_dir / "r",
    )
    assert (result.path / "v.txt").read_text() == "tip\n"
    assert result.receipt.commit_sha == shas[-1]


def test_content_hash_is_64_hex_chars(tmp_path, registry):
    src = make_repo(tmp_path / "src", {"a.txt": "alpha\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    result = fetch(registry, "r", src, "main", deps_dir)
    # Multihash form: "sha256:" + 64 hex chars
    assert result.identity.startswith("sha256:")
    assert len(result.identity) == len("sha256:") + 64
    assert all(c in "0123456789abcdef" for c in result.identity.split(":", 1)[1])


def test_content_hash_is_deterministic(tmp_path, registry):
    files = {"a.txt": "alpha\n", "b.txt": "beta\n"}
    s1 = make_repo(tmp_path / "src1", files)
    s2 = make_repo(tmp_path / "src2", files)
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    r1 = fetch(registry, "r1", s1, "main", deps_dir)
    r2 = fetch(registry, "r2", s2, "main", deps_dir)

    assert r1.identity == r2.identity


def test_content_hash_differs_on_content_change(tmp_path, registry):
    s1 = make_repo(tmp_path / "src1", {"a.txt": "alpha\n"})
    s2 = make_repo(tmp_path / "src2", {"a.txt": "ALPHA\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    r1 = fetch(registry, "r1", s1, "main", deps_dir)
    r2 = fetch(registry, "r2", s2, "main", deps_dir)

    assert r1.identity != r2.identity


def test_idempotent_rerun_returns_same_result(tmp_path, registry):
    src = make_repo(tmp_path / "src", {"a.txt": "alpha\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    r1 = fetch(registry, "r", src, "main", deps_dir)
    r2 = fetch(registry, "r", src, "main", deps_dir)

    assert r1 == r2
    assert (deps_dir / "r" / "a.txt").read_text() == "alpha\n"


def test_wrong_ref_existing_dir_updated(tmp_path, registry):
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

    r_main = fetch(registry, "r", src, "main", deps_dir)
    assert (deps_dir / "r" / "a.txt").read_text() == "alpha\n"

    r_dev = fetch(registry, "r", src, "dev", deps_dir)
    assert (deps_dir / "r" / "a.txt").read_text() == "beta\n"
    assert r_main.receipt.commit_sha != r_dev.receipt.commit_sha
    assert r_main.identity != r_dev.identity


def test_bad_url_raises_fetch_error_with_url_in_message(tmp_path, registry):
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()
    bad_url = f"file://{tmp_path}/nonexistent-repo"

    with pytest.raises(FetchError) as exc:
        registry.fetch(
            "r",
            GitProvenance(url=bad_url, ref="main"),
            dest=deps_dir / "r",
        )
    assert bad_url in str(exc.value)


def test_bad_ref_raises_fetch_error_with_ref_in_message(tmp_path, registry):
    src = make_repo(tmp_path / "src", {"a.txt": "alpha\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    with pytest.raises(FetchError) as exc:
        fetch(registry, "r", src, "no-such-branch", deps_dir)
    assert "no-such-branch" in str(exc.value)


def test_failure_leaves_no_partial_dir(tmp_path, registry):
    src = make_repo(tmp_path / "src", {"a.txt": "alpha\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    with pytest.raises(FetchError):
        fetch(registry, "r", src, "no-such-branch", deps_dir)
    assert not (deps_dir / "r").exists()


def test_content_hash_reflects_executable_bit_end_to_end(tmp_path, registry):
    """content_hash flips when a file's executable bit changes —
    verifies the spec lives through git clone + checkout + tree-walk,
    end-to-end through the registry."""
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
    r1 = fetch(registry, "r", src, "main", deps_dir_a)

    script.chmod(script.stat().st_mode | _stat.S_IXUSR)
    run("update-index", "--chmod=+x", "run.sh")
    run("commit", "-q", "-am", "make exec")

    deps_dir_b = tmp_path / "deps_b"
    deps_dir_b.mkdir()
    r2 = fetch(registry, "r", src, "main", deps_dir_b)

    assert r1.identity != r2.identity


# ---------------------------------------------------------------------------
# L11 — _ensure_commit_present fallback branches
# ---------------------------------------------------------------------------
# The targeted-fetch (allowReachableSHA1InWant) branch is network-only —
# it requires a server that accepts bare-SHA fetch requests (GitHub/GitLab
# feature) which cannot be reproduced with a plain local file:// repo. That
# branch is noted here as network-only.
#
# The unshallow-then-full-fetch fallback (and the L10 re-check that fires
# when the commit is STILL absent) CAN be exercised with a local fixture:
# a SHA that was never committed to the repo triggers the same code path
# as a stale index pin.
# ---------------------------------------------------------------------------


def test_ensure_commit_present_raises_when_sha_never_existed(tmp_path):
    """L11: when the requested commit_sha does not exist in the repo's
    history at all, _ensure_commit_present exhausts every fallback branch
    (cat-file miss → targeted-fetch ignored for file:// → unshallow →
    full fetch → re-check) and raises a clear FetchError naming the SHA."""
    src = make_repo(tmp_path / "src", {"a.txt": "hello\n"})
    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()

    phantom_sha = "cafebabe" * 5  # 40-hex, never committed

    fetcher = GitFetcher()
    with pytest.raises(FetchError) as exc:
        fetcher.fetch(
            "r",
            GitProvenance(
                url=f"file://{src}",
                ref="main",
                commit_sha=phantom_sha,
            ),
            dest=deps_dir / "r",
        )
    msg = str(exc.value)
    assert phantom_sha in msg, "error must name the missing commit SHA"
    assert "not found" in msg.lower(), "error must say the commit was not found"


def test_content_hash_excludes_dot_git(tmp_path, registry):
    """Different commits (extra empty commit history) but identical
    source tree → same content_hash. .git is provenance, not content."""
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
    run2("commit", "-q", "--allow-empty", "-m", "extra empty")

    deps_dir = tmp_path / "deps"
    deps_dir.mkdir()
    r1 = fetch(registry, "r1", s1, "main", deps_dir)
    r2 = fetch(registry, "r2", s2, "main", deps_dir)

    assert r1.receipt.commit_sha != r2.receipt.commit_sha
    assert r1.identity == r2.identity
