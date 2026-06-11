"""CLI integration tests for the MILPA_MOCKED_FETCHES transport.

Verifies that:
- MILPA_MOCKED_FETCHES activates the mocked transport end-to-end via the CLI.
- A successful fetch with mocked transport exits 0, writes milpa.lock, and
  emits NO milpa-error: line.
- A missing key under the mocked transport exits 1 with milpa-error: FETCH-MOCK-MISSING.

These drive the CLI through its public entry point main() — the same interface
a language-neutral black-box runner uses (cli-contract.md §3.1).
"""

import re
from pathlib import Path

import pytest

from milpa.cli import main
from milpa.fetchers.mocked import url_key

_SLUG_LINE = re.compile(r"^milpa-error: ([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)$", re.M)


def _slug_lines(stderr: str) -> list[str]:
    return _SLUG_LINE.findall(stderr)


def _write_manifest(path: Path, dep_name: str, url: str, ref: str) -> None:
    (path / "milpa.kdl").write_text(
        f'name "testpkg"\n'
        f'kind "application"\n'
        f'deps {{\n'
        f'    {dep_name} git=(url)"{url}" ref="{ref}"\n'
        f'}}\n'
    )


def _write_mock_entry(
    mocked_root: Path,
    url: str,
    ref: str,
    *,
    sha: str,
    dep_name: str,
    nimble_requires: str = "",
) -> None:
    """Create the mocked-fetches/<key>/ layout for one dep."""
    key = url_key(url, ref)
    key_dir = mocked_root / key
    key_dir.mkdir(parents=True)
    (key_dir / "sha").write_text(sha + "\n")
    content_dir = key_dir / "content"
    content_dir.mkdir()
    (content_dir / f"{dep_name}.nim").write_text(f"# {dep_name} stub\n")
    if nimble_requires:
        (key_dir / f"{dep_name}.nimble").write_text(nimble_requires)


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------

def test_mocked_transport_fetch_succeeds_without_network(
    tmp_path, capsys, monkeypatch
):
    """MILPA_MOCKED_FETCHES set → fetch exits 0, milpa.lock written, no network call."""
    url = "https://github.com/example/foo.git"
    ref = "main"
    sha = "abcdef1234567890abcdef1234567890abcdef12"
    dep_name = "foo"

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    mocked_dir = tmp_path / "mocked-fetches"

    _write_manifest(project_dir, dep_name, url, ref)
    # Minimal nimble: no transitive deps
    _write_mock_entry(
        mocked_dir, url, ref, sha=sha, dep_name=dep_name,
        nimble_requires='requires "nim >= 1.6.0"\n',
    )

    cas_dir = tmp_path / ".cas"
    monkeypatch.setenv("MILPA_MOCKED_FETCHES", str(mocked_dir))
    monkeypatch.setenv("MILPA_CACHE_DIR", str(cas_dir))

    rc = main(["-C", str(project_dir), "fetch"])

    out = capsys.readouterr()
    assert rc == 0, f"expected exit 0, got {rc}; stderr: {out.err}"
    assert _slug_lines(out.err) == [], f"unexpected slug on success: {out.err}"
    assert (project_dir / "milpa.lock").exists(), "milpa.lock not written"
    lock_text = (project_dir / "milpa.lock").read_text()
    assert sha in lock_text, "commit sha not in lockfile"


# ---------------------------------------------------------------------------
# Missing key → FETCH-ALL-FAILED (the CLI fetch path wraps every total
# fetch failure per resolver-semantics §8a; the inner FETCH-MOCK-MISSING
# cause is folded into the human message, but the machine slug is the
# composite. The MockedFetcher itself raises FETCH-MOCK-MISSING directly —
# asserted at the unit level in test_mocked_fetcher.py.)
# ---------------------------------------------------------------------------

def test_mocked_transport_missing_key_exits_1_with_slug(
    tmp_path, capsys, monkeypatch
):
    """MILPA_MOCKED_FETCHES set but key absent → exit 1, milpa-error: FETCH-ALL-FAILED.

    Per resolver-semantics §8a, fetch_any wraps an exhausted candidate list
    (here the single primary, whose mock is missing) as FETCH-ALL-FAILED."""
    url = "https://github.com/example/bar.git"
    ref = "main"

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()  # empty — no keys

    _write_manifest(project_dir, "bar", url, ref)

    cas_dir = tmp_path / ".cas"
    monkeypatch.setenv("MILPA_MOCKED_FETCHES", str(mocked_dir))
    monkeypatch.setenv("MILPA_CACHE_DIR", str(cas_dir))

    rc = main(["-C", str(project_dir), "fetch"])

    err = capsys.readouterr().err
    assert rc == 1, f"expected exit 1, got {rc}; stderr: {err}"
    assert _slug_lines(err) == ["FETCH-ALL-FAILED"], (
        f"expected FETCH-ALL-FAILED slug, got: {_slug_lines(err)!r}\n"
        f"full stderr: {err}"
    )
