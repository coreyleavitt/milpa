"""CLI-level tests for RFC attestation-v1-normative.md §6 slice S5 —
reconciling `milpa verify` + `milpa show` to the strict defaults flipped in
S4.

Covers:
  - verify's own ``BUNDLE-MISSING`` remediation (D6/D12): distinct wording
    from the fetch-path cause/backend split — the concrete migration break
    for a lockfile minted under the old ``warn`` default (no cached bundle).
  - ``verify`` RE-DERIVES ``EpochCommitmentStatus``/``EpochMembership`` from
    the pinned local cache rather than trusting a lock-time claim (round-3
    addition (i)) — the M1 regression: the cached index was replaced by a
    newer fetch between ``lock`` and ``verify``.
  - the no-epoch-armed observability notice (Dsgn-H2), fired from both the
    fetch/lock gate and verify's offline re-derivation.
  - ``show --entry-trust`` minimal observability parity with
    ``show --index-trust``.
"""

from __future__ import annotations

import json
import unittest.mock
from pathlib import Path

import pytest

from milpa.entry_trust import (
    NO_EPOCH_ARMED_NOTICE,
    _reset_no_epoch_armed_notice,
    _reset_warned_entries,
)
from milpa.epoch_commitment import PreEpochIdentity, commitment_digest
from milpa.index_trust import _reset_warned_urls
from milpa.lockfile import AuthorSigned, LockAttestation, Lockfile, LockedDep, write_lockfile

_MINIMAL_MILPA_KDL = 'name "testpkg"\nkind "application"\n'

_CONTENT_HASH = "dag-sha256:" + "a" * 64
_BUNDLE_PIN = "b" * 64


def _make_minimal_env() -> "object":
    from milpa.context import MilpaEnv

    return MilpaEnv(
        fetcher=unittest.mock.MagicMock(),
        index=None,
        store=unittest.mock.MagicMock(),
        dep_decl_store=None,
    )


def _reset_dedup_state() -> None:
    _reset_warned_entries()
    _reset_no_epoch_armed_notice()
    _reset_warned_urls()


def _write_project(tmp_path: Path, extra: str = "") -> Path:
    proj = tmp_path / "project"
    proj.mkdir()
    (proj / "milpa.kdl").write_text(_MINIMAL_MILPA_KDL + extra, encoding="utf-8")
    return proj


def _write_lockfile_with_attestation(
    proj: Path,
    *,
    name: str = "leftpad",
    namespace: str = "alice",
    version: str = "1.0.0",
    content_hash: str = _CONTENT_HASH,
    bundle_pin: "str | None" = _BUNDLE_PIN,
) -> None:
    dep = LockedDep(
        name=name,
        identity=content_hash,
        version=version,
        src_dir="",
        requires=(),
        provenances=(),
        attestation=LockAttestation(
            kind=AuthorSigned(signer="https://example.com/workflow.yaml"),
            rekor=None,
            bundle_pin=bundle_pin,
            namespace=namespace,
        ),
    )
    write_lockfile(Lockfile(deps=(dep,), strategy="maxver"), proj / "milpa.lock")
    (proj / "_deps").mkdir(exist_ok=True)


def _sidecar_json(identities: list[dict], integrated_time: int = 1700000000) -> bytes:
    payload = {
        "identities": identities,
        "bundle": {
            "verificationMaterial": {"tlogEntries": [{"integratedTime": integrated_time, "logIndex": 1}]},
            "dsseEnvelope": {"payload": ""},
        },
    }
    return json.dumps(payload).encode("utf-8")


def _commitment_for(identities: list[dict]) -> str:
    return commitment_digest(
        [
            PreEpochIdentity(
                namespace=e["namespace"], name=e["name"], version=e["version"], content_hash=e["content_hash"]
            )
            for e in identities
        ]
    )


# ---------------------------------------------------------------------------
# verify's own BUNDLE-MISSING remediation (D6/D12) — the pre-flip-lockfile
# migration break.
# ---------------------------------------------------------------------------


class TestVerifyBundleMissingRemediation:
    def test_verify_missing_bundle_names_fetch_then_reverify(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A lockfile minted under the old `warn` default (or any lockfile
        whose bundle was never cached) has nothing for `verify` to
        re-check — `verify` cannot self-heal (it never fetches). The hint
        must name `milpa fetch` + re-verify, not the fetch-path's
        cause/backend split wording."""
        from milpa.cli import cmd_verify

        proj = _write_project(tmp_path, 'entry-trust "strict"\nindex-trust "off"\n')
        _write_lockfile_with_attestation(proj)

        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        monkeypatch.setenv("MILPA_INDEX_URL", "")  # explicitly no index
        monkeypatch.delenv("MILPA_ENTRY_BUNDLE_DIR", raising=False)
        _reset_dedup_state()

        rc = cmd_verify(proj, _make_minimal_env())
        err = capsys.readouterr().err

        assert rc == 1, f"strict + no cached bundle must fail verify; stderr:\n{err}"
        assert "TNG-ENTRY-BUNDLE-MISSING" in err
        assert "milpa verify' never fetches" in err or "milpa verify' only" in err
        assert "run 'milpa fetch'" in err.lower() or "then re-verify" in err.lower(), (
            f"expected verify's own fetch-then-reverify remediation, got:\n{err}"
        )

    def test_verify_missing_bundle_hint_differs_from_fetch_path_hint(self) -> None:
        """The verify-context hint is a DISTINCT function from the fetch
        path's cause/backend-split hint (D6) — not merely the same text
        reused."""
        from milpa.entry_trust import _bundle_missing_hint, _verify_bundle_missing_hint

        fetch_hint = _bundle_missing_hint("unfetchable", None)
        verify_hint = _verify_bundle_missing_hint("unfetchable", None)
        assert fetch_hint != verify_hint
        assert "then re-verify" in verify_hint or "re-run 'milpa verify'" in verify_hint


# ---------------------------------------------------------------------------
# M1 — verify RE-DERIVES EpochMembership from the pinned local cache, not a
# stale lock-time claim (round-3 addition (i)).
# ---------------------------------------------------------------------------


class TestVerifyReDerivesEpochMembership:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        proj = _write_project(
            tmp_path,
            'entry-trust "strict"\nindex-trust "warn"\n',
        )
        _write_lockfile_with_attestation(proj, bundle_pin=_BUNDLE_PIN)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        monkeypatch.setenv("MILPA_INDEX_URL", "file:///nonexistent/tianguis/index.kdl")
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted")
        monkeypatch.setenv("MILPA_INDEX_EPOCH_MOCK_VERIFIER", "trusted")
        monkeypatch.delenv("MILPA_ENTRY_BUNDLE_DIR", raising=False)
        _reset_dedup_state()
        return proj

    def _arm(self, tmp_path: Path, identities: list[dict]) -> None:
        """Overwrite the cached index text + epoch-commitment sidecar to
        simulate a fresh `milpa fetch` re-arming (or first arming) the
        registry between `lock` and `verify`."""
        from milpa.index_cache import (
            _default_cache_dir,
            _default_epoch_commitment_cache_dir,
            _epoch_commitment_cache_path,
            cache_path_for,
        )

        index_url = "file:///nonexistent/tianguis/index.kdl"
        pointer = _commitment_for(identities)
        cache_file = cache_path_for(index_url, _default_cache_dir())
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(
            f'schema_version 1\n\nattestation-epoch-commitment "{pointer}"\n', encoding="utf-8"
        )
        epoch_dir = _default_epoch_commitment_cache_dir()
        epoch_dir.mkdir(parents=True, exist_ok=True)
        _epoch_commitment_cache_path(pointer, epoch_dir).write_bytes(_sidecar_json(identities))

    def _run_offline_reverify(self, proj: Path):
        """Call the two offline reverify functions directly (bypassing
        `cmd_verify`'s disk-vs-lockfile hash check, which is orthogonal to
        what this test exercises) — mirrors `cmd_verify`'s own call
        sequence: index-scoped epoch status first, threaded into the
        entry-trust re-derivation (R4 precedence)."""
        from milpa.cli import _reverify_cached_entry_attestations, _reverify_cached_index_bundle
        from milpa.errors import MilpaError
        from milpa.lockfile import load_lockfile

        env = _make_minimal_env()
        lockfile = load_lockfile(proj / "milpa.lock")
        status = _reverify_cached_index_bundle(env, proj)
        try:
            _reverify_cached_entry_attestations(env, proj, lockfile, epoch_status=status)
            return 0
        except MilpaError as exc:
            return exc

    def test_m1_reflects_current_cache_not_stale_lock_time_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        proj = self._seed(tmp_path, monkeypatch)

        # World at "lock" time: our dep IS in the committed pre-epoch set —
        # PreEpoch caps entry-trust at warn even though the bundle is
        # missing (never cached) here.
        pre_epoch_identities = [
            {"namespace": "alice", "name": "leftpad", "version": "1.0.0", "content_hash": _CONTENT_HASH}
        ]
        self._arm(tmp_path, pre_epoch_identities)
        result_at_lock_time = self._run_offline_reverify(proj)
        assert result_at_lock_time == 0, (
            f"PreEpoch membership must cap entry-trust at warn; got: {result_at_lock_time!r}, "
            f"stderr:\n{capsys.readouterr().err}"
        )
        capsys.readouterr()

        # A newer `milpa fetch` re-arms the registry with a DIFFERENT
        # committed set that no longer includes our dep — same lockfile,
        # same on-disk deps, only the LOCAL CACHE changed.
        post_epoch_identities = [
            {"namespace": "someone-else", "name": "other-pkg", "version": "9.9.9", "content_hash": "dag-sha256:" + "c" * 64}
        ]
        self._arm(tmp_path, post_epoch_identities)
        _reset_dedup_state()
        result_after_rearm = self._run_offline_reverify(proj)
        err = capsys.readouterr().err

        assert result_after_rearm != 0, (
            f"PostEpoch membership must mandate the attestation under strict "
            f"— re-derivation must reflect the CURRENT cache, not the stale "
            f"lock-time PreEpoch classification; stderr:\n{err}"
        )
        assert result_after_rearm.slug == "TNG-ENTRY-BUNDLE-MISSING"
        assert "committed pre-epoch" in result_after_rearm.message or "must carry" in result_after_rearm.message


# ---------------------------------------------------------------------------
# no-epoch-armed observability notice (Dsgn-H2)
# ---------------------------------------------------------------------------


class TestNoEpochArmedNotice:
    def test_verify_emits_notice_once_when_strict_and_unarmed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from milpa.cli import cmd_verify
        from milpa.index_cache import _default_cache_dir, cache_path_for

        proj = _write_project(tmp_path, 'entry-trust "strict"\nindex-trust "warn"\n')
        _write_lockfile_with_attestation(proj, bundle_pin=None)  # no-pin: skip bundle machinery
        index_url = "file:///nonexistent/tianguis/index.kdl"
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        monkeypatch.setenv("MILPA_INDEX_URL", index_url)
        monkeypatch.setenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", "trusted")
        _reset_dedup_state()

        cache_file = cache_path_for(index_url, _default_cache_dir())
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text("schema_version 1\n", encoding="utf-8")  # no commitment field

        rc = cmd_verify(proj, _make_minimal_env())
        err = capsys.readouterr().err
        assert NO_EPOCH_ARMED_NOTICE in err, f"expected the no-epoch-armed notice; stderr:\n{err}"
        assert err.count(NO_EPOCH_ARMED_NOTICE) == 1, "notice must fire at most once per invocation"

    def test_notice_mentions_both_rollout_and_never_adopted_audiences(self) -> None:
        assert "rolling out" in NO_EPOCH_ARMED_NOTICE
        assert "does not attest" in NO_EPOCH_ARMED_NOTICE

    def test_notice_silent_when_warn_policy(self) -> None:
        from milpa.entry_trust import maybe_emit_no_epoch_armed_notice
        from milpa.epoch_commitment import Unarmed
        import io
        import sys

        _reset_no_epoch_armed_notice()
        buf = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = buf
        try:
            maybe_emit_no_epoch_armed_notice("warn", Unarmed())
        finally:
            sys.stderr = old_stderr
        assert buf.getvalue() == ""

    def test_notice_silent_when_armed(self) -> None:
        from milpa.entry_trust import maybe_emit_no_epoch_armed_notice
        from milpa.epoch_commitment import Armed
        import io
        import sys

        _reset_no_epoch_armed_notice()
        buf = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = buf
        try:
            maybe_emit_no_epoch_armed_notice("strict", Armed(identities=frozenset(), integrated_time=0))
        finally:
            sys.stderr = old_stderr
        assert buf.getvalue() == ""


# ---------------------------------------------------------------------------
# `show --entry-trust` minimal observability parity
# ---------------------------------------------------------------------------


class TestShowEntryTrust:
    def test_reports_effective_policy_and_unarmed_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from milpa.cli import cmd_show_entry_trust

        proj = _write_project(tmp_path, 'entry-trust "strict"\n')
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        monkeypatch.delenv("MILPA_INDEX_URL", raising=False)
        monkeypatch.delenv("MILPA_ENTRY_TRUST", raising=False)

        rc = cmd_show_entry_trust(proj)
        out = capsys.readouterr().out
        assert rc == 0
        assert "entry-trust:" in out
        assert "strict" in out
        assert "not armed" in out

    def test_reports_claimed_epoch_commitment_pointer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from milpa.cli import cmd_show_entry_trust
        from milpa.index_cache import _default_cache_dir, cache_path_for

        proj = _write_project(tmp_path, 'entry-trust "strict"\n')
        index_url = "file:///nonexistent/tianguis/index.kdl"
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        monkeypatch.setenv("MILPA_INDEX_URL", index_url)

        pointer = "d" * 64
        cache_file = cache_path_for(index_url, _default_cache_dir())
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(
            f'schema_version 1\n\nattestation-epoch-commitment "{pointer}"\n', encoding="utf-8"
        )

        rc = cmd_show_entry_trust(proj)
        out = capsys.readouterr().out
        assert rc == 0
        assert "claimed" in out
        assert pointer[:12] in out
        assert "not verified" in out  # claims-only discipline, mirrors show --index-trust


# ---------------------------------------------------------------------------
# cold `show` never says "verified" (D12) — regression pin
# ---------------------------------------------------------------------------


class TestColdShowStaysClaims:
    def test_show_always_says_claims_never_verified(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from milpa.cli import cmd_show

        proj = _write_project(tmp_path)
        _write_lockfile_with_attestation(proj)

        rc = cmd_show(proj)
        out = capsys.readouterr().out
        assert rc == 0
        assert "claims author-signed by" in out
        assert "verified" not in out
