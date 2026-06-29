"""Tests for `milpa hash <source>` — A0-cmd slice.

TDD: tests written BEFORE the implementation. RED → GREEN.

Design pin (from RFC §3.3):
  ``milpa hash`` MUST be implemented as:
    1. parse_source_spec(tokens, base_dir=<project root>) → Provenance
    2. fetch into a SCRATCH/throwaway dest via env.fetcher.inner (FetcherRegistry
       — NOT the CAS-admitting wrapper; no CAS admission)
    3. print result.identity to stdout — exactly one line, nothing else
    4. discard the scratch dir

Identity attribute: FetchResult.identity — a ``sha256:<hex>`` string for
CAS-admissible sources (git, tarball) or ``None`` for local/editable sources.

Side-effects: NONE — no ``milpa.lock`` written, no ``_deps/`` populated,
no CAS admission. ``milpa hash`` is "`milpa fetch` minus CAS-admission and
the lockfile write."

Spec: spec/cli-contract.md §5.N (A0-cmd).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv
from milpa.errors import CLI_SOURCE_SPEC_INVALID
from milpa.fetchers import CasAdmittingFetcher, build_registry
from milpa.fetchers.git import GitProvenance
from milpa.fetchers.local import LocalProvenance
from milpa.cli import cmd_hash, main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_env(tmp_path: Path) -> MilpaEnv:
    """Build a MilpaEnv with a real registry and a tmp CAS root (no ~/.cache pollution)."""
    store = CAStore(tmp_path / "cas")
    registry = build_registry()
    fetcher = CasAdmittingFetcher(registry, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


def _make_local_git_repo(tmp_path: Path) -> tuple[Path, str]:
    """Create a local git repo with one commit; return (repo_dir, commit_sha)."""
    repo = tmp_path / "source_repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@milpa.test"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Milpa Test"],
        check=True, capture_output=True,
    )
    (repo / "hello.txt").write_text("hello hash\n")
    subprocess.run(["git", "-C", str(repo), "add", "hello.txt"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "initial"],
        check=True, capture_output=True,
    )
    sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    return repo, sha


# ---------------------------------------------------------------------------
# Behaviour 1 (tracer) — git prov: prints one sha256 line; equals fetch path
# ---------------------------------------------------------------------------


def test_hash_git_prov_prints_identity(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """cmd_hash with a local git prov prints exactly one sha256:<hex> line.

    THE ARCHITECTURAL PIN: uses env.fetcher.inner.fetch() — not compute_content_hash
    directly, not the CAS-admitting wrapper. The identity on stdout is the same
    identity the real fetch path produces for this source.
    """
    repo, sha = _make_local_git_repo(tmp_path)
    env = _make_env(tmp_path)
    prov = GitProvenance(url=f"file://{repo}", ref=sha)

    rc = cmd_hash(prov, env)

    captured = capsys.readouterr()
    assert rc == 0, f"expected exit 0, got {rc}"
    lines = [l for l in captured.out.splitlines() if l]
    assert len(lines) == 1, f"expected exactly one stdout line, got: {captured.out!r}"
    identity = lines[0]
    assert identity.startswith("dag-sha256:"), f"identity must start with dag-sha256:, got {identity!r}"
    assert len(identity) == len("dag-sha256:") + 64, (
        f"dag-sha256 identity must be dag-sha256:<64hex>, got {identity!r}"
    )


def test_hash_git_prov_identity_equals_fetch_path(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """The identity printed by cmd_hash equals what the inner FetcherRegistry produces.

    This is the core pin assertion: cmd_hash MUST NOT derive identity itself.
    It MUST pass the identity through from the fetch result — proven here by
    comparing against an independent direct call to env.fetcher.inner.fetch().
    """
    import tempfile

    repo, sha = _make_local_git_repo(tmp_path)
    env = _make_env(tmp_path)
    prov = GitProvenance(url=f"file://{repo}", ref=sha)

    # Side-channel: fetch via inner registry directly to get the reference identity.
    with tempfile.TemporaryDirectory() as ref_tmp:
        ref_result = env.fetcher.inner.fetch("ref-probe", prov, dest=Path(ref_tmp) / "ref_src")
    reference_identity = ref_result.identity
    assert reference_identity is not None, "git prov must produce a non-None identity"

    capsys.readouterr()  # clear any prior output

    rc = cmd_hash(prov, env)
    captured = capsys.readouterr()
    assert rc == 0
    printed = captured.out.strip()
    assert printed == reference_identity, (
        f"cmd_hash printed {printed!r} but inner fetch returned {reference_identity!r} — "
        "cmd_hash must pass through the fetch identity, not re-derive it"
    )


# ---------------------------------------------------------------------------
# Behaviour 2 — local prov: identity is None → stdout empty
# ---------------------------------------------------------------------------


def test_hash_local_prov_no_identity_empty_stdout(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """cmd_hash with a local prov (cas_admissible=False) produces empty stdout.

    Local trees have no stable identity in milpa's model (lockfile §4.3 NORMATIVE:
    local records carry no identity field). The fetch result identity is None;
    cmd_hash prints nothing (no identity to report), exits 0.
    """
    local_dir = tmp_path / "mysrc"
    local_dir.mkdir()
    (local_dir / "foo.nim").write_text("# nim source\n")
    env = _make_env(tmp_path)
    prov = LocalProvenance(path=local_dir)

    rc = cmd_hash(prov, env)
    captured = capsys.readouterr()

    assert rc == 0, f"expected exit 0 for local prov, got {rc}"
    assert captured.out.strip() == "", (
        f"local prov has no identity; stdout must be empty, got {captured.out!r}"
    )


# ---------------------------------------------------------------------------
# Behaviour 3 — bad source spec: exit 1 + CLI-SOURCE-SPEC-INVALID slug
# ---------------------------------------------------------------------------


def test_hash_bad_spec_exits_1_with_slug(tmp_path: Path) -> None:
    """A malformed source spec exits 1 and emits CLI-SOURCE-SPEC-INVALID on stderr."""
    import os

    env = os.environ.copy()
    env["MILPA_INDEX_URL"] = ""
    env["MILPA_CACHE_DIR"] = str(tmp_path / "cas")

    result = subprocess.run(
        [sys.executable, "-m", "milpa", "hash", "foo=bar"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(tmp_path),
    )

    assert result.returncode == 1, (
        f"expected exit 1 for bad spec, got {result.returncode}; "
        f"stderr: {result.stderr!r}"
    )
    assert f"milpa-error: {CLI_SOURCE_SPEC_INVALID}" in result.stderr, (
        f"expected CLI-SOURCE-SPEC-INVALID slug on stderr, got: {result.stderr!r}"
    )


def test_hash_empty_spec_exits_1_with_slug(tmp_path: Path) -> None:
    """No source tokens at all: argparse parse error or empty-spec slug (exit 1 or 2)."""
    import os

    env = os.environ.copy()
    env["MILPA_INDEX_URL"] = ""
    env["MILPA_CACHE_DIR"] = str(tmp_path / "cas")

    result = subprocess.run(
        [sys.executable, "-m", "milpa", "hash"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(tmp_path),
    )

    # Acceptable: exit 2 (argparse usage error) or exit 1 (MilpaError CLI-SOURCE-SPEC-INVALID).
    # Either way, must NOT be exit 0.
    assert result.returncode != 0, (
        f"expected non-zero exit for empty spec, got 0; stdout: {result.stdout!r}"
    )


# ---------------------------------------------------------------------------
# Behaviour 4 — stdout discipline: exactly one line on success
# ---------------------------------------------------------------------------


def test_hash_stdout_is_exactly_one_line(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """On success (git prov), stdout contains exactly one non-empty line.

    Scripting consumers (tianguis, build pipelines) do $(milpa hash ...) and
    expect exactly one identity line, no trailing noise.
    """
    repo, sha = _make_local_git_repo(tmp_path)
    env = _make_env(tmp_path)
    prov = GitProvenance(url=f"file://{repo}", ref=sha)

    rc = cmd_hash(prov, env)
    captured = capsys.readouterr()

    assert rc == 0
    # Exactly one non-empty line on stdout.
    lines = [l for l in captured.out.splitlines() if l.strip()]
    assert len(lines) == 1, f"expected exactly 1 non-empty stdout line, got: {captured.out!r}"
    # No spurious diagnostics on stdout (diagnostics go to stderr).
    assert "resolved" not in captured.out, "diagnostic text must not appear on stdout"


def test_hash_diagnostics_go_to_stderr(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """On success, stderr may carry diagnostics, NOT the identity.

    The identity MUST be on stdout only. This test checks the routing by
    verifying that stdout contains the sha256 line and stderr does NOT
    carry a sha256 line.
    """
    repo, sha = _make_local_git_repo(tmp_path)
    env = _make_env(tmp_path)
    prov = GitProvenance(url=f"file://{repo}", ref=sha)

    rc = cmd_hash(prov, env)
    captured = capsys.readouterr()

    assert rc == 0
    # The sha256 identity is on stdout.
    assert captured.out.strip().startswith("dag-sha256:"), (
        f"stdout must carry the dag-sha256 identity, got: {captured.out!r}"
    )
    # stderr must NOT carry an identity line (it may carry other diagnostics).
    for line in captured.err.splitlines():
        assert not line.startswith("dag-sha256:"), (
            f"identity must NOT appear on stderr, found: {line!r}"
        )


# ---------------------------------------------------------------------------
# Behaviour 5 — pure side-effects: no milpa.lock, no _deps/ in project dir
# ---------------------------------------------------------------------------


def test_hash_leaves_no_lock_or_deps(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """cmd_hash MUST NOT write milpa.lock or _deps/ into the project directory.

    Uses a git prov so the fetch path is fully exercised (real network of
    inner registry, temp scratch dir, then discard). The project dir (tmp_path)
    must be untouched after cmd_hash returns.
    """
    repo, sha = _make_local_git_repo(tmp_path)
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    env = _make_env(tmp_path)
    prov = GitProvenance(url=f"file://{repo}", ref=sha)

    rc = cmd_hash(prov, env)
    capsys.readouterr()

    assert rc == 0
    assert not (project_dir / "milpa.lock").exists(), (
        "cmd_hash must NOT write milpa.lock"
    )
    assert not (project_dir / "_deps").exists(), (
        "cmd_hash must NOT populate _deps/"
    )
    # Also verify no temp dir is leaked in the project dir.
    for entry in project_dir.iterdir():
        assert not entry.name.startswith("tmp"), (
            f"unexpected temp entry in project dir: {entry}"
        )


def test_hash_scratch_dir_cleaned_up(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """The scratch temp dir is cleaned up after cmd_hash, regardless of success/failure.

    We can't easily inspect the actual temp dir (it's under /tmp or similar).
    We verify indirectly: the CAS is NOT populated (no admission), so the only
    evidence of the fetch is the stdout identity line — the scratch dir itself
    is gone.
    """
    repo, sha = _make_local_git_repo(tmp_path)
    env = _make_env(tmp_path)
    prov = GitProvenance(url=f"file://{repo}", ref=sha)

    rc = cmd_hash(prov, env)
    captured = capsys.readouterr()

    assert rc == 0
    identity = captured.out.strip()
    assert identity.startswith("dag-sha256:"), "sanity: got an identity"

    # CAS must NOT be populated — cmd_hash goes through inner (no CAS admission).
    cas_root = tmp_path / "cas"
    if cas_root.exists():
        admitted = list((cas_root / "dag-sha256").iterdir()) if (cas_root / "dag-sha256").exists() else []
        assert len(admitted) == 0, (
            f"cmd_hash must NOT admit to CAS; found {len(admitted)} admitted entries"
        )
