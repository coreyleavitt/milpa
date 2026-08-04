"""CLI-level wiring tests for the S-EpochCommitment index-gate phase
(sub-slice 6: rfc-attestation-v1-normative.md §6, D14-D18).

Mirrors test_cli_index_trust.py's harness pattern: a real `file://` index +
sidecar, driven through `_load_index_for_verb` with the conformance mock
seams (`MILPA_INDEX_TRUST_MOCK_VERIFIER` for Layer-1, the epoch-commitment
phase's own `MILPA_INDEX_EPOCH_MOCK_VERIFIER`), no live crypto.
"""

from __future__ import annotations

import json
import unittest.mock
from pathlib import Path

import pytest

from milpa.epoch_commitment import Armed, ArmingInvalid, PreEpochIdentity, Unarmed, commitment_digest
from milpa.errors import (
    TNG_INDEX_EPOCH_COMMITMENT_INVALID,
    TNG_INDEX_EPOCH_RATCHET_REQUIRED,
    MilpaError,
)
from milpa.index_trust import _reset_warned_urls

_PACKAGE_BLOCK = """\
package "bar" {
    namespace "example"
    version "1.0.0" {
        content_hash "sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "git"
            url "https://example.com/bar.git"
            ref "v1.0.0"
        }
    }
}
"""

_MINIMAL_MILPA_KDL = 'name "testpkg"\n'

_S = [{"namespace": "alice", "name": "leftpad", "version": "1.0.0", "content_hash": "dag-sha256:" + "a" * 64}]
_C = commitment_digest(
    [PreEpochIdentity(namespace=e["namespace"], name=e["name"], version=e["version"], content_hash=e["content_hash"]) for e in _S]
)


def _sidecar_json(integrated_time: int = 1700000000) -> bytes:
    payload = {
        "identities": _S,
        "bundle": {
            "verificationMaterial": {"tlogEntries": [{"integratedTime": integrated_time, "logIndex": 1}]},
            "dsseEnvelope": {"payload": ""},
        },
    }
    return json.dumps(payload).encode("utf-8")


def _write_project(tmp_path: Path, milpa_kdl: str = _MINIMAL_MILPA_KDL) -> Path:
    (tmp_path / "milpa.kdl").write_text(milpa_kdl, encoding="utf-8")
    return tmp_path


def _write_local_index(parent: Path, *, armed: bool, index_history: str | None = None) -> str:
    """Write index + bundle sidecar (Layer-1) + optional epoch-commitment
    sidecar; return the index file:// URL."""
    text = "schema_version 1\n\n"
    if armed:
        text += f'attestation-epoch-commitment "{_C}"\n\n'
    text += _PACKAGE_BLOCK
    idx_file = parent / "index.kdl"
    idx_file.write_text(text, encoding="utf-8")
    (parent / "index.kdl.bundle").write_bytes(b'{"fake": "bundle"}')
    if armed:
        (parent / "index.kdl.epoch-commitment").write_bytes(_sidecar_json())
    return idx_file.as_uri()


def _make_minimal_env() -> "object":
    from milpa.context import MilpaEnv
    return MilpaEnv(
        fetcher=unittest.mock.MagicMock(),
        index=None,
        store=unittest.mock.MagicMock(),
        dep_decl_store=None,
    )


def _base_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, idx_url: str) -> None:
    monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
    monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted")
    monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    _reset_warned_urls()


def test_unarmed_index_computes_unarmed_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "warn"\n')
    idx_url = _write_local_index(tmp_path, armed=False)
    _base_env(monkeypatch, tmp_path, idx_url)

    from milpa.cli import _load_index_for_verb

    env = _make_minimal_env()
    result_env = _load_index_for_verb(env, project_dir)
    assert isinstance(result_env.index.epoch_commitment_status, Unarmed)


def test_armed_valid_computes_armed_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    # S4 (RFC attestation-v1-normative.md D1): entry-trust now defaults to
    # strict, so an armed commitment triggers D18's index-history co-
    # requirement; pin index-history "strict" to isolate the epoch-status
    # computation this test actually exercises (see test_d18_armed_all_strict_is_ok
    # for the co-requirement's own dedicated coverage).
    _write_project(
        project_dir,
        _MINIMAL_MILPA_KDL + 'index-trust "warn"\nindex-history "strict"\n',
    )
    idx_url = _write_local_index(tmp_path, armed=True)
    _base_env(monkeypatch, tmp_path, idx_url)
    monkeypatch.setenv("MILPA_INDEX_EPOCH_MOCK_VERIFIER", "trusted")

    from milpa.cli import _load_index_for_verb

    env = _make_minimal_env()
    result_env = _load_index_for_verb(env, project_dir)
    status = result_env.index.epoch_commitment_status
    assert isinstance(status, Armed)
    assert status.integrated_time == 1700000000


def test_armed_invalid_aborts_before_selection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "warn"\n')
    idx_url = _write_local_index(tmp_path, armed=True)
    _base_env(monkeypatch, tmp_path, idx_url)
    monkeypatch.setenv("MILPA_INDEX_EPOCH_MOCK_VERIFIER", "sig-invalid")

    from milpa.cli import _load_index_for_verb

    env = _make_minimal_env()
    with pytest.raises(MilpaError) as exc_info:
        _load_index_for_verb(env, project_dir)
    assert exc_info.value.slug == TNG_INDEX_EPOCH_COMMITMENT_INVALID


def test_d18_armed_strict_entry_trust_warn_index_history_is_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    _write_project(
        project_dir,
        _MINIMAL_MILPA_KDL
        + 'index-trust "warn"\n'
        + 'entry-trust "strict"\n'
        + 'index-history "warn"\n',
    )
    idx_url = _write_local_index(tmp_path, armed=True)
    _base_env(monkeypatch, tmp_path, idx_url)
    monkeypatch.setenv("MILPA_INDEX_EPOCH_MOCK_VERIFIER", "trusted")

    from milpa.cli import _load_index_for_verb

    env = _make_minimal_env()
    with pytest.raises(MilpaError) as exc_info:
        _load_index_for_verb(env, project_dir)
    assert exc_info.value.slug == TNG_INDEX_EPOCH_RATCHET_REQUIRED


def test_d18_armed_all_strict_is_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    _write_project(
        project_dir,
        _MINIMAL_MILPA_KDL
        + 'index-trust "warn"\n'
        + 'entry-trust "strict"\n'
        + 'index-history "strict"\n',
    )
    idx_url = _write_local_index(tmp_path, armed=True)
    _base_env(monkeypatch, tmp_path, idx_url)
    monkeypatch.setenv("MILPA_INDEX_EPOCH_MOCK_VERIFIER", "trusted")

    from milpa.cli import _load_index_for_verb

    env = _make_minimal_env()
    result_env = _load_index_for_verb(env, project_dir)
    assert isinstance(result_env.index.epoch_commitment_status, Armed)
