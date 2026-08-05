"""Shared git-protocol repo builder — H-infra fixture infrastructure (SSOT).

Builds a real, local git repository on disk from a ``git-protocol.json``
repo-spec dict (see ``conformance/spec-v1/fixture-*-git-protocol-*/`` and
``conformance/spec-v1/fixture-*-dag-oracle-*/`` for real specs).  This is the
ONE implementation of that repo-generation recipe — both the in-process
conformance adapter (``impls/python/tests/test_conformance.py``) and the
black-box differential runner (``harness/runner.py``) import it rather than
maintaining independent copies (CLAUDE.md audit-for-duplication discipline).

Design constraints (matches the rest of ``harness/``):
- stdlib only; no import milpa.
- Deterministic output: commit authorship + timestamp are pinned so commit
  SHAs are reproducible across runs, hosts, and impls.
"""

from __future__ import annotations

import os as _os
import subprocess
from pathlib import Path


def _make_git_protocol_repo(
    tmpdir: Path,
    repo_spec: dict,  # type: ignore[type-arg]
    peer_shas: "dict[str, str] | None" = None,
) -> tuple[Path, list]:  # type: ignore[type-arg]
    """Build a local git repo from a git-protocol.json repo spec.

    Returns ``(repo_path, [commit_sha_0, commit_sha_1, ...])``.

    Two forms are supported:

    *Single-commit form* (backward-compat): ``repo_spec["files"]`` is a
    ``{relpath: content}`` mapping.  One commit is produced; the returned list
    has one element.

    *Multi-commit form* (H4): ``repo_spec["commits"]`` is a list of
    ``{"files": {relpath: content}}`` dicts applied sequentially.  Each dict
    is committed on top of the previous; files not mentioned in a later commit
    survive (no auto-deletion).  The returned list has one SHA per commit in
    oldest-first order.

    *Symlinks* (H3d): ``repo_spec["symlinks"]`` is a ``{link_path: target}``
    mapping of filesystem symlinks to commit alongside ``files``.  Symlinks are
    created on disk before ``git add`` so git picks them up as mode-120000
    blobs (committed symlinks), exactly as the H3b/H3c invariant tests do.
    The ``target`` value is the raw link-target string (may be relative or
    absolute, safe or escaping — the generator commits whatever the fixture
    declares; containment-checking is the fetcher's job, not the generator's).

    *Submodules* (H5, #177, R1-03): ``repo_spec["submodules"]`` is a list of
    ``{"path": <relpath>, "repo": <name>, "ref": <branch>}`` dicts.  After
    the normal file commits, .gitmodules is written with RELATIVE urls
    (``../<repo-name>``) and gitlink entries are injected via
    ``git update-index --add --cacheinfo 160000,<sha>,<path>``.  The submodule
    repos MUST appear before the superproject in the descriptor (so their SHAs
    are available in ``peer_shas``).

    git user identity and commit timestamp are pinned via env vars so commit
    SHAs are deterministic across runs and both impls — required for golden
    ``expected/submodule_shas`` (#177, H5 cross-impl gap).
    """
    name = repo_spec["name"]
    ref = repo_spec.get("ref", "main")

    repo_dir = tmpdir / name
    repo_dir.mkdir(parents=True, exist_ok=True)

    # Pin commit authorship + timestamp so commit SHAs are reproducible across
    # runs and impls.  Content hashes are unaffected (they exclude .git/).
    # 1577836800 = 2020-01-01T00:00:00Z.
    _hinfra_env = {
        **_os.environ,
        "GIT_AUTHOR_NAME": "Milpa H-infra",
        "GIT_AUTHOR_EMAIL": "milpa-hinfra@test.milpa",
        "GIT_AUTHOR_DATE": "1577836800 +0000",
        "GIT_COMMITTER_NAME": "Milpa H-infra",
        "GIT_COMMITTER_EMAIL": "milpa-hinfra@test.milpa",
        "GIT_COMMITTER_DATE": "1577836800 +0000",
    }

    def _git(args: list) -> None:  # type: ignore[type-arg]
        result = subprocess.run(
            ["git", "-C", str(repo_dir),
             "-c", "user.email=milpa-hinfra@test.milpa",
             "-c", "user.name=Milpa H-infra",
             "-c", "core.autocrlf=false",
             # Disable commit signing so the commit SHA is independent of the
             # host's global git config (e.g. commit.gpgSign=true / ssh signing).
             # Required for cross-impl golden submodule_shas (#177, H5).
             "-c", "commit.gpgSign=false",
             ] + args,
            capture_output=True,
            text=True,
            env=_hinfra_env,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git {args[0]!r} failed in {repo_dir}:\n"
                f"  stdout: {result.stdout.strip()}\n"
                f"  stderr: {result.stderr.strip()}"
            )

    def _head_sha() -> str:
        return subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
            env=_hinfra_env,
        ).stdout.strip()

    # init — without -c user.* (git init ignores them cleanly in some versions)
    subprocess.run(
        ["git", "-C", str(repo_dir), "init", "-b", ref, "-q"],
        capture_output=True, check=True,
    )

    # hostile_tree branch (#177, EXTRACT-ZIP-SLIP fixtures): build a raw git
    # tree object whose entry paths contain path-traversal sequences that
    # `git add` and `git mktree` refuse to accept (e.g. "../../escape" or
    # "/escape").  We bypass git's safety checks by hand-crafting the raw
    # tree object bytes and feeding them directly to `git hash-object
    # --literally`, exactly as the verified recipe in the design doc prescribes.
    # The normal files/commits/symlinks/orphan_tip path is SKIPPED entirely.
    if "hostile_tree" in repo_spec:
        entries = repo_spec["hostile_tree"]  # list of {"mode", "name", "content"}
        # Step 1: write each blob object and collect its SHA.
        blob_shas: list[tuple[str, str, str]] = []  # (mode, name, sha)
        for entry in entries:
            mode = entry["mode"]
            name = entry["name"]
            content_bytes = entry["content"].encode("utf-8")
            result = subprocess.run(
                ["git", "-C", str(repo_dir), "hash-object", "-w", "--stdin"],
                input=content_bytes,           # binary stdin — no text=True
                capture_output=True,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"git hash-object (blob) failed:\n"
                    f"  stdout: {result.stdout.decode(errors='replace').strip()}\n"
                    f"  stderr: {result.stderr.decode(errors='replace').strip()}"
                )
            blob_sha = result.stdout.decode().strip()
            blob_shas.append((mode, name, blob_sha))

        # Step 2: build raw tree bytes.
        # Format per git-pack-protocol: "<mode> <name>\0<20-byte-sha>" per entry.
        raw_tree = b""
        for mode, name, sha_hex in blob_shas:
            raw_tree += f"{mode} {name}".encode("utf-8") + b"\x00"
            raw_tree += bytes.fromhex(sha_hex)

        # Step 3: write the raw tree object (--literally bypasses path validation).
        result = subprocess.run(
            ["git", "-C", str(repo_dir),
             "hash-object", "-t", "tree", "--literally", "-w", "--stdin"],
            input=raw_tree,                    # binary stdin — no text=True
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git hash-object (tree) failed:\n"
                f"  stdout: {result.stdout.decode(errors='replace').strip()}\n"
                f"  stderr: {result.stderr.decode(errors='replace').strip()}"
            )
        tree_sha = result.stdout.decode().strip()

        # Step 4: create a commit wrapping the hostile tree.
        result = subprocess.run(
            ["git", "-C", str(repo_dir),
             "-c", "user.email=milpa-hinfra@test.milpa",
             "-c", "user.name=Milpa H-infra",
             "-c", "core.autocrlf=false",
             "commit-tree", tree_sha, "-m", "H-infra hostile-tree commit"],
            capture_output=True,
            env=_hinfra_env,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git commit-tree failed:\n"
                f"  stdout: {result.stdout.decode(errors='replace').strip()}\n"
                f"  stderr: {result.stderr.decode(errors='replace').strip()}"
            )
        commit_sha_hostile = result.stdout.decode().strip()

        # Step 5: point the branch ref at this commit.
        result = subprocess.run(
            ["git", "-C", str(repo_dir),
             "update-ref", f"refs/heads/{ref}", commit_sha_hostile],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git update-ref failed:\n"
                f"  stdout: {result.stdout.decode(errors='replace').strip()}\n"
                f"  stderr: {result.stderr.decode(errors='replace').strip()}"
            )

        return repo_dir, [commit_sha_hostile]

    # Normalise to a list of commit specs regardless of form.
    if "commits" in repo_spec:
        # Multi-commit form: list of {"files": {...}} dicts.
        commit_specs: list = repo_spec["commits"]
    else:
        # Single-commit (backward-compat): wrap the top-level "files" dict.
        # The top-level "symlinks" map, if present, goes into this single commit.
        commit_specs = [{
            "files": repo_spec.get("files", {}),
            "symlinks": repo_spec.get("symlinks", {}),
            "executable": repo_spec.get("executable", []),
        }]

    commit_shas: list = []
    for i, commit_spec in enumerate(commit_specs):
        files: dict = commit_spec.get("files", {})
        for relpath, content in files.items():
            target = repo_dir / relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        # Exec-bit support (epoch-2 identity, spec §1.8.2.1): relpaths listed in
        # "executable" are chmod +x before `git add` so git records them as
        # mode-100755 blobs (the executable bit is part of the content hash).
        executables: list = commit_spec.get("executable", [])
        for relpath in executables:
            target = repo_dir / relpath
            st_mode = _os.stat(target).st_mode
            _os.chmod(target, st_mode | 0o111)
        # H3d: symlinks support — create on-disk symlinks so git commits them
        # as mode-120000 blobs.  The target string is committed verbatim
        # (escaping or safe — containment is the fetcher's responsibility).
        symlinks: dict = commit_spec.get("symlinks", {})
        for link_path, link_target in symlinks.items():
            link_on_disk = repo_dir / link_path
            link_on_disk.parent.mkdir(parents=True, exist_ok=True)
            # Remove stale symlink/file if present (idempotent re-generation).
            if link_on_disk.exists() or link_on_disk.is_symlink():
                link_on_disk.unlink()
            _os.symlink(link_target, link_on_disk)
        _git(["add", "."])
        msg = f"H-infra commit {i}" if i > 0 else "H-infra initial commit"
        _git(["commit", "-q", "-m", msg])
        commit_shas.append(_head_sha())

    # H5 (#177): submodule superproject support.
    # If "submodules" is declared, write .gitmodules with RELATIVE urls
    # (``../<repo-name>``) and inject gitlink entries via
    # ``git update-index --add --cacheinfo 160000,<sha>,<path>``.
    # The submodule repos MUST be built before this repo (descriptor order
    # guarantees this) so their head SHAs are available in peer_shas.
    # Using relative urls keeps committed .gitmodules bytes deterministic
    # (no tmpdir path) — milpa resolves them against the superproject URL.
    submodule_specs: list = repo_spec.get("submodules", [])
    if submodule_specs:
        if peer_shas is None:
            raise RuntimeError(
                f"repo {name!r} declares submodules but no peer_shas were provided"
            )
        gitmodules_sections = []
        for sub_spec in submodule_specs:
            sub_path = sub_spec["path"]
            sub_repo = sub_spec["repo"]
            # Use "./<repo-name>" (POSIX sibling URL): milpa's _resolve_submodule_url
            # strips the last path component from the superproject URL
            # (e.g. "file:///tmp/git-repos/super" → "file:///tmp/git-repos")
            # then joins the relative URL.  "./<repo>" → "git-repos/<repo>" ✓
            # "../<repo>" would overshoot to the tmpdir's parent. (#177, H5)
            gitmodules_sections.append(
                f'[submodule "{sub_path}"]\n\tpath = {sub_path}\n\turl = ./{sub_repo}'
            )
        gitmodules_content = "\n".join(gitmodules_sections) + "\n"
        (repo_dir / ".gitmodules").write_text(gitmodules_content, encoding="utf-8")
        _git(["add", ".gitmodules"])
        for sub_spec in submodule_specs:
            sub_path = sub_spec["path"]
            sub_repo = sub_spec["repo"]
            sub_sha = peer_shas.get(sub_repo)
            if sub_sha is None:
                raise RuntimeError(
                    f"submodule repo {sub_repo!r} not found in peer_shas; "
                    f"available: {list(peer_shas)}"
                )
            _git(["update-index", "--add", "--cacheinfo",
                  f"160000,{sub_sha},{sub_path}"])
        _git(["commit", "-q", "-m", "H-infra add submodules"])
        commit_shas.append(_head_sha())

    # Optional: create an orphan tip commit and force-reset the branch to it.
    # This simulates a force-push that makes earlier commits unreachable from
    # any ref — so a ``git clone`` of this repo will NOT fetch those commits.
    # Used by H4 to produce a non-tip commit that is absent after a plain clone,
    # exposing the Rust FETCH-GIT-COMMIT-ABSENT bug before the 4-step fix.
    orphan_tip: dict | None = repo_spec.get("orphan_tip")
    if orphan_tip is not None:
        # Create an orphan branch, commit the orphan files, then force-reset
        # the target ref to that orphan commit so it becomes the branch tip.
        orphan_branch = "__milpa_hinfra_orphan__"
        _git(["checkout", "--orphan", orphan_branch])
        _git(["rm", "-rf", "."])
        orphan_files: dict = orphan_tip.get("files", {})
        for relpath, content in orphan_files.items():
            target = repo_dir / relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        _git(["add", "."])
        _git(["commit", "-q", "-m", "H-infra orphan tip (simulates force-push)"])
        orphan_sha = _head_sha()
        # Force-reset the target ref to the orphan commit
        _git(["branch", "-f", ref, orphan_sha])
        # Return to a detached HEAD so `git clone` clones the ref correctly
        _git(["checkout", "--detach", "HEAD"])

    return repo_dir, commit_shas
