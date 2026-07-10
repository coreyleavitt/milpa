"""CLI-level index-trust gate tests.

Covers two review findings:

C1 — trust gate never fires in production CLI
  ``_load_index_for_verb`` called ``load_default_index()`` bare, never passing
  ``config``/``verifier``.  All manifest index-trust policies and env vars were
  silently ignored.  Tests in ``TestTrustGatePlumbing`` demonstrate this: they
  FAIL against the pre-fix code because ``_load_index_for_verb`` does not accept
  a ``project_dir`` argument and ignores the ``MILPA_INDEX_TRUST_MOCK_VERIFIER``
  conformance seam entirely.

M2 — ``cmd_show_index_trust`` phantom import
  ``from milpa.manifest import ManifestDoc, discover_manifest`` raised
  ``ImportError`` (those names do not exist) which was swallowed by the bare
  ``except Exception: pass``, so the policy was always shown as the default
  ``warn`` regardless of the project's ``milpa.kdl``.  Tests in
  ``TestShowIndexTrustManifestPolicy`` demonstrate this: a project declaring
  ``index-trust "strict"`` was shown as ``warn``.

Spec authority: spec/registry-protocol.md §3.4.5, spec/cli-contract.md §2.8/§8.6.
"""

from __future__ import annotations

import unittest.mock
from pathlib import Path

import pytest

from milpa.errors import (
    MilpaError,
    TNG_INDEX_BUNDLE_MISSING,
    TNG_INDEX_SIGNATURE_INVALID,
)
from milpa.index_trust import _reset_warned_urls


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

#: Minimal valid index KDL for local file:// transport.
_VALID_INDEX = """\
schema_version 1

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

#: Minimal milpa.kdl for a standalone package (no deps).
_MINIMAL_MILPA_KDL = 'name "testpkg"\n'


def _write_project(tmp_path: Path, milpa_kdl: str = _MINIMAL_MILPA_KDL) -> Path:
    """Write milpa.kdl to tmp_path and return it."""
    (tmp_path / "milpa.kdl").write_text(milpa_kdl, encoding="utf-8")
    return tmp_path


def _write_local_index(parent: Path) -> str:
    """Write a valid index + fake bundle sidecar; return the index file:// URL.

    The bundle file must be non-empty so ``_cache_bundle_looks_ok`` accepts it
    and the ``MockVerifier`` is invoked (rather than the BundleMissing/crash path).
    The MockVerifier bypasses all crypto, so the bundle content is irrelevant.
    """
    idx_file = parent / "index.kdl"
    idx_file.write_text(_VALID_INDEX, encoding="utf-8")
    # Derived bundle URL: same path with ".bundle" appended (RFC §7.3).
    bundle_file = parent / "index.kdl.bundle"
    bundle_file.write_bytes(b'{"fake": "bundle"}')  # non-empty; MockVerifier ignores content
    return idx_file.as_uri()


def _make_minimal_env() -> "MilpaEnv":
    from milpa.context import MilpaEnv
    return MilpaEnv(
        fetcher=unittest.mock.MagicMock(),
        index=None,
        store=unittest.mock.MagicMock(),
        dep_decl_store=None,
    )


# ---------------------------------------------------------------------------
# TestTrustGatePlumbing — C1
# ---------------------------------------------------------------------------


class TestTrustGatePlumbing:
    """C1: ``_load_index_for_verb`` must wire IndexTrustConfig + verifier.

    All tests FAIL against the pre-fix code because ``_load_index_for_verb``
    does not accept a ``project_dir`` argument (TypeError on call), and even if
    it did, no config/verifier is built or passed to ``load_default_index``.
    """

    def test_strict_policy_sig_invalid_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """manifest index-trust strict + mock sig-invalid → raises TNG-INDEX-SIGNATURE-INVALID."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "strict"\n')
        idx_url = _write_local_index(tmp_path)

        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "sig-invalid")
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        _reset_warned_urls()

        from milpa.cli import _load_index_for_verb
        env = _make_minimal_env()
        with pytest.raises(MilpaError) as exc_info:
            _load_index_for_verb(env, project_dir)
        assert exc_info.value.slug == TNG_INDEX_SIGNATURE_INVALID

    def test_warn_policy_sig_invalid_proceeds_with_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]
    ) -> None:
        """manifest index-trust warn + mock sig-invalid → no raise, warning in stderr."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "warn"\n')
        idx_url = _write_local_index(tmp_path)

        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "sig-invalid")
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        _reset_warned_urls()

        from milpa.cli import _load_index_for_verb
        env = _make_minimal_env()
        result_env = _load_index_for_verb(env, project_dir)
        err = capsys.readouterr().err
        assert TNG_INDEX_SIGNATURE_INVALID in err, (
            "warn policy must emit TNG-INDEX-SIGNATURE-INVALID warning"
        )
        assert result_env.index is not None, "index must be populated despite warning"

    def test_off_in_manifest_wins_over_env_strict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]
    ) -> None:
        """manifest off + env MILPA_INDEX_TRUST=strict → gate silent (off wins per §6.6)."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "off"\n')
        idx_url = _write_local_index(tmp_path)

        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "sig-invalid")
        monkeypatch.setenv("MILPA_INDEX_TRUST", "strict")
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        _reset_warned_urls()

        from milpa.cli import _load_index_for_verb
        env = _make_minimal_env()
        # Must NOT raise — off wins over env strict.
        result_env = _load_index_for_verb(env, project_dir)
        err = capsys.readouterr().err
        assert TNG_INDEX_SIGNATURE_INVALID not in err, "off policy must suppress warnings"
        assert result_env.index is not None

    def test_env_off_does_not_weaken_manifest_warn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]
    ) -> None:
        """env MILPA_INDEX_TRUST=off + manifest warn → warn still fires (env off is no-op floor)."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "warn"\n')
        idx_url = _write_local_index(tmp_path)

        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "sig-invalid")
        monkeypatch.setenv("MILPA_INDEX_TRUST", "off")  # env off cannot weaken manifest warn
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        _reset_warned_urls()

        from milpa.cli import _load_index_for_verb
        env = _make_minimal_env()
        result_env = _load_index_for_verb(env, project_dir)
        err = capsys.readouterr().err
        assert TNG_INDEX_SIGNATURE_INVALID in err, (
            "env off is a no-op floor — manifest warn must still fire"
        )
        assert result_env.index is not None

    def test_require_attested_index_escalates_warn_to_strict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """warn manifest + require_attested_index=True → strict behavior."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "warn"\n')
        idx_url = _write_local_index(tmp_path)

        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "sig-invalid")
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        _reset_warned_urls()

        from milpa.cli import _load_index_for_verb
        from dataclasses import replace
        env = replace(_make_minimal_env(), require_attested_index=True)
        with pytest.raises(MilpaError) as exc_info:
            _load_index_for_verb(env, project_dir)
        assert exc_info.value.slug == TNG_INDEX_SIGNATURE_INVALID

    def test_require_attested_index_does_not_touch_off(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]
    ) -> None:
        """off manifest + require_attested_index=True → still silent (off wins per §6.6)."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "off"\n')
        idx_url = _write_local_index(tmp_path)

        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "sig-invalid")
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        _reset_warned_urls()

        from milpa.cli import _load_index_for_verb
        from dataclasses import replace
        env = replace(_make_minimal_env(), require_attested_index=True)
        # off wins — no raise even with flag.
        result_env = _load_index_for_verb(env, project_dir)
        err = capsys.readouterr().err
        assert TNG_INDEX_SIGNATURE_INVALID not in err
        assert result_env.index is not None

    def test_milpa_index_max_age_reaches_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """MILPA_INDEX_MAX_AGE=100 must propagate to IndexTrustConfig.max_age_seconds."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "warn"\n')
        idx_url = _write_local_index(tmp_path)

        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted")
        monkeypatch.setenv("MILPA_INDEX_MAX_AGE", "100")
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        _reset_warned_urls()

        import milpa.cli as _cli_mod
        captured_configs: list[object] = []
        original_load = _cli_mod.load_default_index

        def capturing_load(**kwargs: object) -> object:
            captured_configs.append(kwargs.get("config"))
            return original_load(**kwargs)

        from milpa.cli import _load_index_for_verb
        with unittest.mock.patch.object(_cli_mod, "load_default_index", capturing_load):
            env = _make_minimal_env()
            _load_index_for_verb(env, project_dir)

        assert len(captured_configs) == 1, "load_default_index must be called exactly once"
        cfg = captured_configs[0]
        assert cfg is not None, (
            "C1: load_default_index must be called WITH a config (trust gate must be wired)"
        )
        assert hasattr(cfg, "max_age_seconds"), "config must have max_age_seconds"
        assert cfg.max_age_seconds == 100, (
            f"MILPA_INDEX_MAX_AGE=100 must reach config.max_age_seconds; "
            f"got {cfg.max_age_seconds!r}"
        )

    def test_bundle_url_override_reaches_transport(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]
    ) -> None:
        """MILPA_INDEX_BUNDLE_URL override must reach the bundle transport call."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "warn"\n')
        idx_url = _write_local_index(tmp_path)

        custom_bundle_url = "https://custom.example.com/custom.bundle"
        received_urls: list[str] = []

        from milpa.index_cache import _BundleNotFound

        def tracking_bundle_get(url: str) -> bytes:
            received_urls.append(url)
            raise _BundleNotFound(f"bundle 404 at {url!r}")

        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted")
        monkeypatch.setenv("MILPA_INDEX_BUNDLE_URL", custom_bundle_url)
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        _reset_warned_urls()

        import milpa.index_cache as _ic_mod
        from milpa.cli import _load_index_for_verb
        with unittest.mock.patch.object(_ic_mod, "urllib_bundle_http_get", tracking_bundle_get):
            env = _make_minimal_env()
            _load_index_for_verb(env, project_dir)

        assert custom_bundle_url in received_urls, (
            f"MILPA_INDEX_BUNDLE_URL must reach the bundle transport; "
            f"transport received: {received_urls!r}"
        )


# ---------------------------------------------------------------------------
# TestShowIndexTrustManifestPolicy — M2
# ---------------------------------------------------------------------------


class TestShowIndexTrustManifestPolicy:
    """M2: ``cmd_show_index_trust`` must read manifest index-trust policy correctly.

    Pre-fix: ``from milpa.manifest import ManifestDoc, discover_manifest`` raised
    ``ImportError`` (those names do not exist in milpa.manifest), which was swallowed
    by the bare ``except Exception: pass``, so the displayed policy was always the
    default ``warn`` regardless of the project's ``milpa.kdl``.
    """

    def test_strict_in_manifest_shown_as_strict(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Project with index-trust "strict" → show --index-trust reports strict.

        M2 regression: reported warn (ImportError swallowed).
        """
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "strict"\n')

        from milpa.cli import cmd_show_index_trust
        ret = cmd_show_index_trust(project_dir)
        assert ret == 0
        out = capsys.readouterr().out
        assert "strict" in out, (
            f"M2: project declares strict; output must say 'strict':\n{out}"
        )
        assert "warn" not in out.split("policy:")[1].split("\n")[0], (
            f"M2: policy line must not say 'warn'; output:\n{out}"
        )

    def test_no_manifest_shows_warn_default(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No manifest in project_dir → show --index-trust reports warn (default)."""
        project_dir = tmp_path / "empty"
        project_dir.mkdir()

        from milpa.cli import cmd_show_index_trust
        ret = cmd_show_index_trust(project_dir)
        assert ret == 0
        out = capsys.readouterr().out
        assert "warn" in out, (
            f"no manifest → default policy must be warn:\n{out}"
        )

    def test_broken_manifest_hard_fails_not_swallowed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """CR5: a syntactically-broken milpa.kdl must hard-fail, not degrade to warn.

        The manifest-absent degrade (``_manifest_absent`` / ``MAN-NO-MANIFEST``)
        is scoped to "no milpa.kdl at all" — a PRESENT-but-broken manifest is a
        genuine error and must propagate as ``MAN-KDL-SYNTAX``, not be swallowed
        into a normal-looking ``policy: warn`` line.
        """
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "milpa.kdl").write_text("this is not valid { kdl\n", encoding="utf-8")

        from milpa.cli import cmd_show_index_trust
        with pytest.raises(MilpaError) as exc_info:
            cmd_show_index_trust(project_dir)
        assert exc_info.value.slug == "MAN-KDL-SYNTAX", (
            f"CR5: broken manifest must hard-fail with MAN-KDL-SYNTAX, not be "
            f"swallowed to warn; got slug={exc_info.value.slug!r}"
        )
        out = capsys.readouterr().out
        assert "policy:" not in out, (
            f"CR5: must not print a normal-looking status block on a broken "
            f"manifest; got:\n{out}"
        )

    def test_off_in_manifest_shown_as_off(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Project with index-trust "off" → show --index-trust reports off."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "off"\n')

        from milpa.cli import cmd_show_index_trust
        ret = cmd_show_index_trust(project_dir)
        assert ret == 0
        out = capsys.readouterr().out
        assert "off" in out, (
            f"M2: project declares off; output must say 'off':\n{out}"
        )


# ---------------------------------------------------------------------------
# TestMockSeamFileOnlyGuard — ITEM M3
# ---------------------------------------------------------------------------


class TestMockSeamFileOnlyGuard:
    """M3: ``MILPA_INDEX_TRUST_MOCK_VERIFIER`` is only honored for file:// index URLs.

    Setting it with a non-file:// URL must raise ``MILPA-INTERNAL`` — fail closed
    and visible.  Spec: cli-contract.md §8.6.6 NORMATIVE (file://-only restriction).
    """

    def test_mock_seam_with_https_index_raises_internal(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Mock seam set + https:// index URL → raises MILPA-INTERNAL immediately."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "warn"\n')

        monkeypatch.setenv("MILPA_INDEX_URL", "https://example.com/index.kdl")
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted")
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        _reset_warned_urls()

        from milpa.cli import _load_index_for_verb
        from milpa.errors import MILPA_INTERNAL
        env = _make_minimal_env()
        with pytest.raises(MilpaError) as exc_info:
            _load_index_for_verb(env, project_dir)
        assert exc_info.value.slug == MILPA_INTERNAL, (
            "mock seam with https:// index must raise MILPA-INTERNAL; "
            f"got slug={exc_info.value.slug!r}"
        )
        assert "conformance-internal" in str(exc_info.value).lower() or \
               "file://" in str(exc_info.value), (
            f"MILPA-INTERNAL message must explain the file://-only restriction; "
            f"got: {exc_info.value!r}"
        )

    def test_mock_seam_with_file_index_uses_mock_verifier(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Mock seam set + file:// index URL → MockVerifier used (no MILPA-INTERNAL)."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "warn"\n')
        idx_url = _write_local_index(tmp_path)

        # Confirm the URL is file://
        assert idx_url.startswith("file://"), f"_write_local_index must return file:// URL; got {idx_url!r}"

        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "sig-invalid")
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        _reset_warned_urls()

        from milpa.cli import _load_index_for_verb
        env = _make_minimal_env()
        # sig-invalid + warn → warning in stderr, no raise
        _load_index_for_verb(env, project_dir)
        err = capsys.readouterr().err
        assert TNG_INDEX_SIGNATURE_INVALID in err, (
            "mock seam with file:// index must use MockVerifier and emit warning"
        )


# ---------------------------------------------------------------------------
# TestShowIndexTrustWorkspacePolicy — ITEM M4
# ---------------------------------------------------------------------------


class TestShowIndexTrustWorkspacePolicy:
    """M4: ``cmd_show_index_trust`` must display the policy the enforcement gate enforces.

    Post S5-redesign (RFC registry-trust-federation §6.4a — root authority):
    index-trust is declared ONLY on the resolution root. For a workspace, that
    is the workspace ROOT manifest (no merge across members). Both
    ``cmd_show_index_trust`` and the enforcement gate call
    ``_load_manifest_trust_fields`` — the SSOT helper — so they display and
    enforce the identical root-declared policy.
    """

    def test_workspace_root_strict_shown_as_strict(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Workspace ROOT declares strict → show reports strict (same as gate enforces)."""
        project_dir = tmp_path / "ws"
        project_dir.mkdir()

        # Workspace root declares strict directly (root authority).
        (project_dir / "milpa.kdl").write_text(
            'index-trust "strict"\nworkspace {\n    member "sub"\n}\n',
            encoding="utf-8",
        )
        # Member declares nothing (legal).
        sub = project_dir / "sub"
        sub.mkdir()
        (sub / "milpa.kdl").write_text(
            'name "sub"\nkind "library"\n',
            encoding="utf-8",
        )

        from milpa.cli import cmd_show_index_trust
        ret = cmd_show_index_trust(project_dir)
        assert ret == 0
        out = capsys.readouterr().out
        assert "strict" in out, (
            f"M4: workspace root declaring strict must show 'strict'; "
            f"output:\n{out}"
        )
        # Make sure it's on the policy line specifically.
        policy_line = next((l for l in out.splitlines() if l.startswith("policy:")), "")
        assert "strict" in policy_line, (
            f"M4: 'strict' must be on the policy: line; policy line={policy_line!r}"
        )

    def test_workspace_root_declares_nothing_shown_as_warn_default(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Workspace root with no index-trust node → show reports 'warn' (default)."""
        project_dir = tmp_path / "ws"
        project_dir.mkdir()
        (project_dir / "milpa.kdl").write_text(
            'workspace {\n    member "sub"\n}\n',
            encoding="utf-8",
        )
        sub = project_dir / "sub"
        sub.mkdir()
        (sub / "milpa.kdl").write_text('name "sub"\nkind "library"\n', encoding="utf-8")

        from milpa.cli import cmd_show_index_trust
        ret = cmd_show_index_trust(project_dir)
        assert ret == 0
        policy_line = next(
            (l for l in capsys.readouterr().out.splitlines() if l.startswith("policy:")),
            "",
        )
        assert "warn" in policy_line

    def test_workspace_root_signer_and_bundle_resolve_from_root(
        self,
        tmp_path: Path,
    ) -> None:
        """Root-declared index-trust-signer/-bundle (not just policy) reach the SSOT
        resolution — the gate reads them straight off the root, no member merge.

        Closes a coverage Low: prior tests exercised only the workspace-root
        *policy*; signer/bundle share the same root-authority read path.
        """
        from milpa.cli import _load_manifest_trust_fields

        project_dir = tmp_path / "ws"
        project_dir.mkdir()
        (project_dir / "milpa.kdl").write_text(
            'index-trust "strict"\n'
            'index-trust-signer "https://example.test/signer@refs/heads/main"\n'
            'index-trust-bundle "file:///tmp/custom-root.json"\n'
            'workspace {\n    member "sub"\n}\n',
            encoding="utf-8",
        )
        sub = project_dir / "sub"
        sub.mkdir()
        (sub / "milpa.kdl").write_text('name "sub"\nkind "library"\n', encoding="utf-8")

        policy, signer, bundle = _load_manifest_trust_fields(project_dir)
        assert policy == "strict"
        assert signer == "https://example.test/signer@refs/heads/main"
        assert bundle == "file:///tmp/custom-root.json"


# ---------------------------------------------------------------------------
# TestShowIndexTrustMemberIllegalDeclaration — RD-M1
# ---------------------------------------------------------------------------


class TestShowIndexTrustMemberIllegalDeclaration:
    """RD-M1: ``show --index-trust`` must NOT swallow ``WS-INDEX-TRUST-ON-MEMBER``.

    Pre-fix: ``_load_manifest_trust_fields`` wrapped its ENTIRE body (including
    ``find_workspace_root``) in a bare ``except (OSError, MilpaError): pass``, so a
    member illegally declaring index-trust fell back to the ``("warn", None, None)``
    default instead of propagating the validation error. That contradicted the
    command's own SSOT claim: "always displays the policy the gate would enforce"
    — the gate (``_build_index_trust`` → ``fetch``/``lock``) raises
    ``WS-INDEX-TRUST-ON-MEMBER`` for this exact workspace, but ``show`` reported
    ``policy: warn`` and exit 0.
    """

    def test_member_illegal_declaration_propagates(
        self,
        tmp_path: Path,
    ) -> None:
        """Member declaring index-trust "warn" → show raises WS-INDEX-TRUST-ON-MEMBER.

        Must NOT silently fall back to policy: warn / exit 0 — that would
        contradict what the enforcement gate (fetch/lock) actually does.
        """
        from milpa.errors import WS_INDEX_TRUST_ON_MEMBER

        project_dir = tmp_path / "ws"
        project_dir.mkdir()
        (project_dir / "milpa.kdl").write_text(
            'workspace {\n    member "sub"\n}\n',
            encoding="utf-8",
        )
        sub = project_dir / "sub"
        sub.mkdir()
        # ILLEGAL: a workspace member declaring index-trust at all.
        (sub / "milpa.kdl").write_text(
            'name "sub"\nkind "library"\nindex-trust "warn"\n',
            encoding="utf-8",
        )

        from milpa.cli import cmd_show_index_trust
        with pytest.raises(MilpaError) as exc_info:
            cmd_show_index_trust(project_dir)
        assert exc_info.value.slug == WS_INDEX_TRUST_ON_MEMBER, (
            "RD-M1: show --index-trust must surface WS-INDEX-TRUST-ON-MEMBER, "
            f"not silently default; got slug={exc_info.value.slug!r}"
        )

    def test_verify_member_illegal_declaration_propagates(
        self,
        tmp_path: Path,
    ) -> None:
        """RD-H1: ``verify`` must surface WS-INDEX-TRUST-ON-MEMBER, not swallow it.

        ``cmd_verify`` resolves the workspace before the lockfile/disk-state
        check, so a member illegally declaring index-trust must hard-fail here
        rather than silently proceeding to a LOCK-GRAPH-MISMATCH / success.
        Mirrors the Rust binary test
        ``verify_at_workspace_root_propagates_ws_index_trust_on_member``.
        """
        from milpa.errors import WS_INDEX_TRUST_ON_MEMBER

        project_dir = tmp_path / "ws"
        project_dir.mkdir()
        (project_dir / "milpa.kdl").write_text(
            'workspace {\n    member "sub"\n}\n',
            encoding="utf-8",
        )
        sub = project_dir / "sub"
        sub.mkdir()
        # ILLEGAL: a workspace member declaring index-trust at all.
        (sub / "milpa.kdl").write_text(
            'name "sub"\nkind "library"\nindex-trust "strict"\n',
            encoding="utf-8",
        )

        from milpa.cli import cmd_verify
        with pytest.raises(MilpaError) as exc_info:
            cmd_verify(project_dir)
        assert exc_info.value.slug == WS_INDEX_TRUST_ON_MEMBER, (
            "RD-H1: verify must surface WS-INDEX-TRUST-ON-MEMBER, not swallow it; "
            f"got slug={exc_info.value.slug!r}"
        )

    def test_standalone_package_no_workspace_still_shows_own_policy(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A standalone (non-workspace) package must still show its own policy fine."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "strict"\n')

        from milpa.cli import cmd_show_index_trust
        ret = cmd_show_index_trust(project_dir)
        assert ret == 0
        policy_line = next(
            (l for l in capsys.readouterr().out.splitlines() if l.startswith("policy:")),
            "",
        )
        assert "strict" in policy_line, (
            f"RD-M1: standalone package must show its declared policy; got {policy_line!r}"
        )

    def test_no_manifest_at_all_degrades_gracefully(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Genuinely no manifest / not in a project → still degrades to warn, no crash."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        from milpa.cli import cmd_show_index_trust
        ret = cmd_show_index_trust(empty_dir)
        assert ret == 0
        policy_line = next(
            (l for l in capsys.readouterr().out.splitlines() if l.startswith("policy:")),
            "",
        )
        assert "warn" in policy_line


# ---------------------------------------------------------------------------
# TestTrustBundleEnvVar — ITEM 2 (spec §8.6: MILPA_INDEX_TRUST_BUNDLE)
# ---------------------------------------------------------------------------


class TestTrustBundleEnvVar:
    """MILPA_INDEX_TRUST_BUNDLE MUST be a file:// URL; bare paths MUST be rejected.

    Spec: cli-contract.md §8.6 NORMATIVE: "The value MUST be a file:// URL ...
    Values that are not file:// paths MUST be rejected."
    """

    def test_bare_path_rejected(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """MILPA_INDEX_TRUST_BUNDLE=/abs/path → raises (must be file:// URL)."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "warn"\n')
        idx_url = _write_local_index(tmp_path)

        # Write a real file so the error is clearly about the URL scheme, not file-not-found.
        bundle_file = tmp_path / "my_bundle.json"
        bundle_file.write_bytes(b'{"fake": "bundle"}')

        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST_BUNDLE", str(bundle_file))  # bare path, no file://
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        _reset_warned_urls()

        from milpa.cli import _load_index_for_verb
        from milpa.errors import MILPA_INTERNAL
        env = _make_minimal_env()
        with pytest.raises(MilpaError) as exc_info:
            _load_index_for_verb(env, project_dir)
        assert exc_info.value.slug == MILPA_INTERNAL, (
            f"bare path MUST be rejected with MILPA-INTERNAL; got slug={exc_info.value.slug!r}"
        )

    def test_file_url_accepted(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """MILPA_INDEX_TRUST_BUNDLE=file:///abs/path → accepted and bundle loaded."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'index-trust "warn"\n')
        idx_url = _write_local_index(tmp_path)

        # Write a minimal fake bundle JSON so the load succeeds.
        bundle_file = tmp_path / "my_bundle.json"
        bundle_file.write_bytes(b'{"fake": "bundle"}')
        bundle_url = bundle_file.as_uri()  # produces file:///abs/path

        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST_BUNDLE", bundle_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted")
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        _reset_warned_urls()

        from milpa.cli import _load_index_for_verb
        env = _make_minimal_env()
        # Must NOT raise — file:// path is accepted.
        result_env = _load_index_for_verb(env, project_dir)
        assert result_env.index is not None, "file:// bundle path must be accepted"


# ---------------------------------------------------------------------------
# Sv — `milpa verify` reverifies the CACHED index bundle offline
# ---------------------------------------------------------------------------


class TestVerifyReverifiesCachedBundle:
    """Sv (rfc-attestation-verifier): `milpa verify` re-verifies the cached
    ``index.kdl.bundle`` offline via the real verifier seam. A failing cached
    bundle fails verify under strict; a trusted one does not block it. No network."""

    @staticmethod
    def _seed_cache_and_project(tmp_path, monkeypatch, mock_result: str) -> Path:
        from milpa.index_cache import _bundle_path, _default_cache_dir, cache_path_for

        cache_home = tmp_path / "cache"
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache_home))
        # Mock seam is honored for file:// index URLs only.
        index_url = "file:///nonexistent/tianguis/index.kdl"
        monkeypatch.setenv("MILPA_INDEX_URL", index_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST", "strict")
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", mock_result)

        # Seed the on-disk cache with an index + bundle. Contents are irrelevant:
        # MockVerifier returns ``mock_result`` regardless — the point is that verify
        # READS the cached files and routes them through the verifier (never fetches).
        cache_file = cache_path_for(index_url, _default_cache_dir())
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_bytes(b'name "tianguis-index"\n')
        _bundle_path(cache_file).write_bytes(b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}')

        # Minimal project: a parseable lockfile + an (empty) _deps dir is enough to
        # reach the reverify step, which runs right after the lockfile loads.
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "milpa.kdl").write_text('name "x"\nkind "application"\n', encoding="utf-8")
        (proj / "milpa.lock").write_text('version 1\nstrategy "maxver"\n', encoding="utf-8")
        (proj / "_deps").mkdir()
        return proj

    def test_verify_fails_on_invalid_cached_bundle_offline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from milpa.cli import cmd_verify

        proj = self._seed_cache_and_project(tmp_path, monkeypatch, "sig-invalid")
        rc = cmd_verify(proj, _make_minimal_env())
        err = capsys.readouterr().err
        assert rc == 1, f"strict + invalid cached bundle must fail verify; stderr:\n{err}"
        assert "TNG-INDEX-SIGNATURE-INVALID" in err, f"expected slug in stderr:\n{err}"

    def test_verify_does_not_block_on_trusted_cached_bundle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from milpa.cli import cmd_verify

        proj = self._seed_cache_and_project(tmp_path, monkeypatch, "trusted")
        rc = cmd_verify(proj, _make_minimal_env())
        err = capsys.readouterr().err
        # Trusted cached bundle → reverify passes; verify proceeds (0 deps → success).
        assert rc == 0, f"trusted cached bundle must not block verify; stderr:\n{err}"
        assert "TNG-INDEX-" not in err, f"no trust slug expected on a trusted bundle:\n{err}"
