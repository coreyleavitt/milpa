"""CLI-level index-history policy-axis wiring tests (A2c, RFC registry-append-only.md §2).

Mirrors ``test_cli_entry_trust.py``'s ``TestBuildEntryTrust`` shape, but at the
``_build_index_history`` level. Unlike ``_build_index_trust`` / ``_build_entry_trust``,
``_build_index_history`` returns the bare ``TrustPolicy`` string (never ``None``) —
``"off"`` is itself a meaningful, load-bearing return value (A2d's ratchet must
still know to *preserve* the baseline under ``"off"``, not treat it as "gate
absent"). This slice is pure policy-axis plumbing: no baseline I/O, no CLI-flag
escalation (spec/cli-contract.md §8.7 defines none for this axis), no ratchet
wiring — those land in A2d.

Covers:
  - manifest ``index-history`` field + ``MILPA_INDEX_HISTORY`` env layering,
    via the shared ``effective_trust_policy`` SSOT (trust.py)
  - ``off`` in the manifest is unconditional — env cannot override it
  - default (no manifest field, no env) resolves to ``"warn"``
  - env ``strict`` escalates a manifest ``warn``
  - env ``off`` cannot weaken a manifest ``warn``/``strict`` (no-op floor)
"""

from __future__ import annotations

import unittest.mock
from pathlib import Path

import pytest


_MINIMAL_MILPA_KDL = 'name "testpkg"\n'


def _write_project(tmp_path: Path, milpa_kdl: str = _MINIMAL_MILPA_KDL) -> Path:
    (tmp_path / "milpa.kdl").write_text(milpa_kdl, encoding="utf-8")
    return tmp_path


def _make_minimal_env(**overrides: object) -> "object":
    from milpa.context import MilpaEnv

    kwargs = dict(
        fetcher=unittest.mock.MagicMock(),
        index=None,
        store=unittest.mock.MagicMock(),
        dep_decl_store=None,
    )
    kwargs.update(overrides)
    return MilpaEnv(**kwargs)


class TestBuildIndexHistory:
    def test_no_manifest_field_and_no_env_defaults_warn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir)
        monkeypatch.delenv("MILPA_INDEX_HISTORY", raising=False)

        from milpa.cli import _build_index_history
        env = _make_minimal_env()
        assert _build_index_history(env, project_dir) == "warn"

    def test_manifest_strict_returns_strict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-history "strict"\n')
        monkeypatch.delenv("MILPA_INDEX_HISTORY", raising=False)

        from milpa.cli import _build_index_history
        env = _make_minimal_env()
        assert _build_index_history(env, project_dir) == "strict"

    def test_manifest_off_returns_off(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``off`` is itself a meaningful return value, not a sentinel for "disabled"."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-history "off"\n')
        monkeypatch.delenv("MILPA_INDEX_HISTORY", raising=False)

        from milpa.cli import _build_index_history
        env = _make_minimal_env()
        assert _build_index_history(env, project_dir) == "off"

    def test_off_wins_over_env_strict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """manifest off is unconditional — env cannot override it (§3.4.0 rule 1)."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-history "off"\n')
        monkeypatch.setenv("MILPA_INDEX_HISTORY", "strict")

        from milpa.cli import _build_index_history
        env = _make_minimal_env()
        assert _build_index_history(env, project_dir) == "off"

    def test_env_strict_escalates_manifest_warn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-history "warn"\n')
        monkeypatch.setenv("MILPA_INDEX_HISTORY", "strict")

        from milpa.cli import _build_index_history
        env = _make_minimal_env()
        assert _build_index_history(env, project_dir) == "strict"

    def test_env_off_cannot_weaken_manifest_strict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """env=off is a no-op floor — it cannot weaken a manifest strict/warn (§3.4.0 rule 2)."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-history "strict"\n')
        monkeypatch.setenv("MILPA_INDEX_HISTORY", "off")

        from milpa.cli import _build_index_history
        env = _make_minimal_env()
        assert _build_index_history(env, project_dir) == "strict"

    def test_workspace_root_policy_is_honored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A workspace project resolves the root manifest's index-history, not
        a member's (members cannot declare it — WS-INDEX-HISTORY-ON-MEMBER)."""
        root = tmp_path / "ws"
        root.mkdir()
        (root / "milpa.kdl").write_text(
            'index-history "strict"\nworkspace {\n    member "sub"\n}\n',
            encoding="utf-8",
        )
        member = root / "sub"
        member.mkdir()
        (member / "milpa.kdl").write_text('name "sub"\nkind "library"\n', encoding="utf-8")
        monkeypatch.delenv("MILPA_INDEX_HISTORY", raising=False)

        from milpa.cli import _build_index_history
        env = _make_minimal_env()
        assert _build_index_history(env, root) == "strict"

    def test_workspace_member_declaring_index_history_propagates_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A member illegally declaring index-history raises WS-INDEX-HISTORY-ON-MEMBER,
        propagated from ``_build_index_history`` rather than swallowed."""
        from milpa.errors import MilpaError, WS_INDEX_HISTORY_ON_MEMBER

        root = tmp_path / "ws"
        root.mkdir()
        (root / "milpa.kdl").write_text('workspace {\n    member "sub"\n}\n', encoding="utf-8")
        member = root / "sub"
        member.mkdir()
        (member / "milpa.kdl").write_text(
            'name "sub"\nkind "library"\nindex-history "warn"\n', encoding="utf-8"
        )
        monkeypatch.delenv("MILPA_INDEX_HISTORY", raising=False)

        from milpa.cli import _build_index_history
        env = _make_minimal_env()
        with pytest.raises(MilpaError) as exc_info:
            _build_index_history(env, root)
        assert exc_info.value.slug == WS_INDEX_HISTORY_ON_MEMBER


# ---------------------------------------------------------------------------
# CR5 — broken manifest must hard-fail, not degrade to warn
# ---------------------------------------------------------------------------


class TestLoadManifestIndexHistoryPolicyManifestErrors:
    """``_load_manifest_index_history_policy``'s degrade-to-warn is scoped to
    a genuinely ABSENT manifest (``MAN-NO-MANIFEST``) — mirrors the identical
    CR5 fix applied to ``_load_manifest_trust_fields`` (index-trust) and
    ``_load_manifest_entry_trust_policy`` (entry-trust) via the shared
    ``_manifest_absent`` predicate.
    """

    def test_broken_manifest_propagates_not_swallowed(self, tmp_path: Path) -> None:
        from milpa.errors import MilpaError

        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "milpa.kdl").write_text("this is not valid { kdl\n", encoding="utf-8")

        from milpa.cli import _load_manifest_index_history_policy
        with pytest.raises(MilpaError) as exc_info:
            _load_manifest_index_history_policy(project_dir)
        assert exc_info.value.slug == "MAN-KDL-SYNTAX"

    def test_genuinely_absent_manifest_still_degrades_to_warn(self, tmp_path: Path) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        from milpa.cli import _load_manifest_index_history_policy
        assert _load_manifest_index_history_policy(project_dir) == "warn"
