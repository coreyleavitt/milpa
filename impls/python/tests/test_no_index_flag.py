"""--no-index global flag (#120 follow-up).

`--no-index` is the discoverable, explicit form of "no index configured" —
an alias of empty MILPA_INDEX_URL (cli-contract §8.1), with the added
guarantee that the flag OVERRIDES any configured index (env or default).
Offline / air-gapped resolution: URL/local deps resolve; a named dep raises
RES-NO-INDEX.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from milpa.cli import _build_env, _load_index_for_verb, main


def _write(p: Path, text: str) -> None:
    p.write_text(text, encoding="utf-8")


def test_flag_overrides_present_index(tmp_path: Path, monkeypatch) -> None:
    """--no-index forces index=None even when MILPA_INDEX_URL points at a
    valid, loadable index (flag precedence over a configured index)."""
    index_kdl = tmp_path / "index.kdl"
    _write(index_kdl, "version 1\n")
    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_kdl.resolve()}")
    monkeypatch.setenv("MILPA_CACHE_DIR", str(tmp_path / "cas"))

    # Sanity: without the flag, the configured index loads (not None).
    env_default = _build_env(no_index=False)
    assert _load_index_for_verb(env_default).index is not None

    # With the flag, the index is suppressed despite being configured.
    env_no_index = _build_env(no_index=True)
    assert env_no_index.no_index is True
    assert _load_index_for_verb(env_no_index).index is None


def test_flag_disables_dep_decl_store(tmp_path: Path, monkeypatch) -> None:
    """--no-index also disables the DepDecl store (the attested-metadata path
    is unreachable with no index), regardless of MILPA_INDEX_URL."""
    index_kdl = tmp_path / "index.kdl"
    _write(index_kdl, "version 1\n")
    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_kdl.resolve()}")
    monkeypatch.setenv("MILPA_CACHE_DIR", str(tmp_path / "cas"))

    assert _build_env(no_index=True).dep_decl_store is None


def test_named_dep_with_no_index_flag_raises(tmp_path: Path, monkeypatch, capsys) -> None:
    """End-to-end: a named dep + --no-index → exit 1 with RES-NO-INDEX,
    even though a valid index is configured."""
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj / "milpa.kdl", 'name "myapp"\nkind "application"\ndeps {\n    results\n}\n')
    index_kdl = tmp_path / "index.kdl"
    _write(index_kdl, "version 1\n")
    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_kdl.resolve()}")
    monkeypatch.setenv("MILPA_CACHE_DIR", str(tmp_path / "cas"))

    rc = main(["--no-index", "-C", str(proj), "fetch"])
    assert rc == 1
    assert "RES-NO-INDEX" in capsys.readouterr().err
