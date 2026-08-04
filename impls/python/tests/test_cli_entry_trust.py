"""CLI-level entry-trust gate wiring tests (P3a, RFC per-entry-attestation.md §4).

Mirrors test_cli_index_trust.py's ``TestTrustGatePlumbing`` shape, but at the
``_build_entry_trust`` level (the entry-trust equivalent of
``_build_index_trust``) since the gate itself fires inside ``resolve()``, not
at a single CLI call site — a full ``cmd_fetch`` E2E is covered by the
conformance-fixture matrix instead.

Covers:
  - manifest ``entry-trust`` field + ``MILPA_ENTRY_TRUST`` env layering
  - ``off`` wins over env strict / cannot be escalated by the CLI flag
  - ``--require-attested-entries`` (``require_attested_entries``) escalates warn→strict
  - ``MILPA_ENTRY_TRUST_MOCK_MAP`` / ``MILPA_ENTRY_TRUST_MOCK_DEFAULT`` conformance seam
  - the file://-only guard on the mock seam
  - reuse of index-trust's expected-signer resolution (RFC §5 NORMATIVE)
"""

from __future__ import annotations

import unittest.mock
from pathlib import Path

import pytest

from milpa.errors import MilpaError, MILPA_INTERNAL


_MINIMAL_MILPA_KDL = 'name "testpkg"\n'


def _write_project(tmp_path: Path, milpa_kdl: str = _MINIMAL_MILPA_KDL) -> Path:
    (tmp_path / "milpa.kdl").write_text(milpa_kdl, encoding="utf-8")
    return tmp_path


def _write_local_index(parent: Path) -> str:
    idx_file = parent / "index.kdl"
    idx_file.write_text(
        'schema_version 1\n\n'
        'package "bar" {\n'
        '    namespace "ns1"\n'
        '    version "1.0.0" {\n'
        '        content_hash "dag-sha256:0000000000000000000000000000000000000000000000000000000000000001"\n'
        '    }\n'
        '}\n',
        encoding="utf-8",
    )
    return idx_file.as_uri()


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


class TestBuildEntryTrust:
    def test_off_manifest_disables_gate(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "off"\n')
        monkeypatch.delenv("MILPA_ENTRY_TRUST", raising=False)

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env()
        assert _build_entry_trust(env, project_dir) is None

    def test_no_manifest_field_and_no_env_builds_strict_gate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default (no entry-trust anywhere): effective policy is 'strict', not
        'off' — so the config IS built (S4, RFC attestation-v1-normative.md D1:
        entry-trust defaults to strict, unlike index-history which stays warn);
        this proves the flipped default is live, not silently disabled."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir)
        monkeypatch.delenv("MILPA_ENTRY_TRUST", raising=False)

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env()
        config = _build_entry_trust(env, project_dir)
        assert config is not None
        assert config.policy == "strict"

    def test_manifest_strict_builds_strict_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "strict"\n')
        monkeypatch.delenv("MILPA_ENTRY_TRUST", raising=False)

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env()
        config = _build_entry_trust(env, project_dir)
        assert config is not None
        assert config.policy == "strict"

    def test_off_wins_over_env_strict(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "off"\n')
        monkeypatch.setenv("MILPA_ENTRY_TRUST", "strict")

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env()
        assert _build_entry_trust(env, project_dir) is None

    def test_env_strict_escalates_manifest_warn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "warn"\n')
        monkeypatch.setenv("MILPA_ENTRY_TRUST", "strict")

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env()
        config = _build_entry_trust(env, project_dir)
        assert config is not None
        assert config.policy == "strict"

    def test_require_attested_entries_escalates_warn_to_strict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "warn"\n')
        monkeypatch.delenv("MILPA_ENTRY_TRUST", raising=False)

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env(require_attested_entries=True)
        config = _build_entry_trust(env, project_dir)
        assert config is not None
        assert config.policy == "strict"

    def test_require_attested_entries_does_not_touch_off(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "off"\n')
        monkeypatch.delenv("MILPA_ENTRY_TRUST", raising=False)

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env(require_attested_entries=True)
        assert _build_entry_trust(env, project_dir) is None

    def test_mock_map_seam_requires_file_index(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "strict"\n')
        monkeypatch.setenv("MILPA_INDEX_URL", "https://example.com/index.kdl")
        monkeypatch.setenv("MILPA_ENTRY_TRUST_MOCK_DEFAULT", "trusted")

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env()
        with pytest.raises(MilpaError) as exc_info:
            _build_entry_trust(env, project_dir)
        assert exc_info.value.slug == MILPA_INTERNAL

    def test_mock_map_seam_builds_keyed_verifier(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "strict"\n')
        idx_url = _write_local_index(tmp_path)
        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv(
            "MILPA_ENTRY_TRUST_MOCK_MAP",
            '{"pkg:tianguis/ns1/bar@1.0.0": "signer-mismatch"}',
        )

        from milpa.cli import _build_entry_trust
        from milpa.entry_trust import SignerMismatch, Trusted, build_entry_subject

        env = _make_minimal_env()
        config = _build_entry_trust(env, project_dir)
        assert config is not None
        subj = build_entry_subject("ns1", "bar", "1.0.0", "dag-sha256:" + "a" * 64)
        result = config.verifier.verify(subj, b"", config.trust_bundle, "signer")
        assert result is SignerMismatch

        other_subj = build_entry_subject("ns1", "other", "1.0.0", "dag-sha256:" + "a" * 64)
        assert config.verifier.verify(other_subj, b"", config.trust_bundle, "signer") is Trusted

    def test_mock_default_unrecognized_value_fails_loud(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unrecognized MILPA_ENTRY_TRUST_MOCK_DEFAULT must never silently
        fall back to Trusted — a trust seam fails loud, even in test (mirrors
        the sibling MILPA_ENTRY_TRUST_MOCK_MAP bad-value path)."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "strict"\n')
        idx_url = _write_local_index(tmp_path)
        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_ENTRY_TRUST_MOCK_DEFAULT", "bogus-value")

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env()
        with pytest.raises(MilpaError) as exc_info:
            _build_entry_trust(env, project_dir)
        assert exc_info.value.slug == MILPA_INTERNAL

    def test_mock_default_gate_only_value_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``unattested`` / ``bundle-missing`` are GATE-level states the
        verifier itself is documented to never produce (EntryBundleVerifier.verify
        docstring) — the mock-VERIFIER seam must reject them too, not accept
        the full 8-value gate domain."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "strict"\n')
        idx_url = _write_local_index(tmp_path)
        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_ENTRY_TRUST_MOCK_DEFAULT", "unattested")

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env()
        with pytest.raises(MilpaError) as exc_info:
            _build_entry_trust(env, project_dir)
        assert exc_info.value.slug == MILPA_INTERNAL

    def test_mock_default_recognized_verifier_value_still_works(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "strict"\n')
        idx_url = _write_local_index(tmp_path)
        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv("MILPA_ENTRY_TRUST_MOCK_DEFAULT", "signature-invalid")

        from milpa.cli import _build_entry_trust
        from milpa.entry_trust import SignatureInvalid, build_entry_subject

        env = _make_minimal_env()
        config = _build_entry_trust(env, project_dir)
        assert config is not None
        subj = build_entry_subject("ns1", "bar", "1.0.0", "dag-sha256:" + "a" * 64)
        result = config.verifier.verify(subj, b"", config.trust_bundle, "signer")
        assert result is SignatureInvalid

    def test_mock_map_gate_only_value_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same tightened domain applies to per-subject MOCK_MAP entries."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "strict"\n')
        idx_url = _write_local_index(tmp_path)
        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.setenv(
            "MILPA_ENTRY_TRUST_MOCK_MAP",
            '{"pkg:tianguis/ns1/bar@1.0.0": "bundle-missing"}',
        )

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env()
        with pytest.raises(MilpaError) as exc_info:
            _build_entry_trust(env, project_dir)
        assert exc_info.value.slug == MILPA_INTERNAL

    def test_expected_signer_reuses_index_trust_resolution(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RFC §5 NORMATIVE: vendored expected signer = the SAME effective
        vendor-bot identity Layer 1 resolved — never a second hardcoded copy."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(
            project_dir,
            _MINIMAL_MILPA_KDL + 'entry-trust "strict"\nindex-trust-signer "custom-signer"\n',
        )
        monkeypatch.delenv("MILPA_ENTRY_TRUST", raising=False)
        monkeypatch.delenv("MILPA_INDEX_TRUST_SIGNER", raising=False)

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env()
        config = _build_entry_trust(env, project_dir)
        assert config is not None
        assert config.expected_vendor_signer == "custom-signer"


# ---------------------------------------------------------------------------
# S-Acq — MILPA_INDEX_URL three-way acquisition-wiring fix
# (RFC attestation-v1-normative.md §6 S-Acq). Before the fix,
# ``_build_entry_trust`` collapsed an ABSENT MILPA_INDEX_URL to the same
# ``None`` as a present-but-EMPTY one, so ``entry_bundle_store_from_paths``
# never built a store in the normal (no override) case — every attested
# entry silently resolved BundleMissing/unfetchable with no acquisition
# attempt. These tests pin the corrected three-way semantics directly on
# ``config.bundle_store`` (mirrors ``_build_dep_decl_store``'s already-correct
# three-way, cli.py's ``_resolve_index_url_three_way`` SSOT).
# ---------------------------------------------------------------------------


class TestBundleStoreAcquisitionWiring:
    def test_absent_index_url_builds_store_from_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bug this slice fixes: MILPA_INDEX_URL absent must build a real
        HttpEntryBundleStore from DEFAULT_INDEX_URL, not silently return
        ``None`` (which made acquisition unreachable for the common no-override
        case)."""
        from milpa.entry_bundle_store import HttpEntryBundleStore
        from milpa.index_cache import DEFAULT_INDEX_URL

        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "warn"\n')
        monkeypatch.delenv("MILPA_INDEX_URL", raising=False)
        monkeypatch.delenv("MILPA_ENTRY_BUNDLE_DIR", raising=False)

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env()
        config = _build_entry_trust(env, project_dir)
        assert config is not None
        assert isinstance(config.bundle_store, HttpEntryBundleStore)
        assert config.bundle_store._base_url.startswith(DEFAULT_INDEX_URL.rsplit("/", 1)[0])

    def test_empty_index_url_is_explicitly_no_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "warn"\n')
        monkeypatch.setenv("MILPA_INDEX_URL", "")
        monkeypatch.delenv("MILPA_ENTRY_BUNDLE_DIR", raising=False)

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env()
        config = _build_entry_trust(env, project_dir)
        assert config is not None
        assert config.bundle_store is None

    def test_nonempty_index_url_builds_store_from_that_url(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from milpa.entry_bundle_store import HttpEntryBundleStore

        project_dir = tmp_path / "project"
        project_dir.mkdir()
        _write_project(project_dir, _MINIMAL_MILPA_KDL + 'entry-trust "warn"\n')
        idx_url = _write_local_index(tmp_path)
        monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
        monkeypatch.delenv("MILPA_ENTRY_BUNDLE_DIR", raising=False)

        from milpa.cli import _build_entry_trust
        env = _make_minimal_env()
        config = _build_entry_trust(env, project_dir)
        assert config is not None
        assert isinstance(config.bundle_store, HttpEntryBundleStore)
        assert config.bundle_store._base_url.startswith(idx_url.rsplit("/", 1)[0])


class TestAcquisitionActuallyAttempted:
    """A plain gate run against a REAL served bundle (HttpEntryBundleStore's
    ``file://`` transport, derived purely from ``MILPA_INDEX_URL`` — no
    ``MILPA_ENTRY_BUNDLE_DIR`` involved) must now fetch and verify it, proving
    acquisition is genuinely attempted rather than short-circuited to
    BundleMissing/unfetchable by a ``None`` store."""

    def test_fetch_gate_acquires_bundle_via_index_url_derived_http_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import hashlib
        import shutil

        from milpa.cli import cmd_update
        from milpa.entry_trust import _reset_warned_entries
        from milpa.index_trust import _reset_warned_urls
        from milpa.version import Strategy

        bundle_bytes = b'{"dsseEnvelope": {"payload": "", "signatures": []}}'
        bundle_pin = hashlib.sha256(bundle_bytes).hexdigest()

        index_dir = tmp_path / "registry"
        index_dir.mkdir()
        (index_dir / "attestation").mkdir()
        (index_dir / "attestation" / f"{bundle_pin}.bundle").write_bytes(bundle_bytes)
        idx_file = index_dir / "index.kdl"
        idx_file.write_text(
            "schema_version 1\n"
            'package "bar" {\n'
            '    namespace "ns1"\n'
            '    version "2.0.0" {\n'
            f'        content_hash "{_BAR_CONTENT_HASH}"\n'
            "        provenance {\n"
            '            kind "git"\n'
            '            url "https://github.com/example/bar.git"\n'
            '            ref "v2.0.0"\n'
            '            commit_sha "cafef00dcafef00dcafef00dcafef00dcafef00d"\n'
            "        }\n"
            '        attestation "author-signed"\n'
            '        signed_by "alice"\n'
            f'        bundle sha256="{bundle_pin}"\n'
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "milpa.kdl").write_text(
            'name "myapp"\n'
            'kind "application"\n'
            # S4 (RFC attestation-v1-normative.md D4): index-trust now defaults
            # to strict too, and this synthetic index.kdl ships no whole-index
            # bundle; pin index-trust "warn" to isolate the entry-trust axis
            # this test actually exercises.
            'index-trust "warn"\n'
            'entry-trust "strict"\n'
            "deps {\n"
            '    bar ">= 2.0.0"\n'
            "}\n",
            encoding="utf-8",
        )

        mocked_dir = tmp_path / "mocked-fetches"
        shutil.copytree(_FIXTURE_061_MOCK, mocked_dir / _FIXTURE_061_MOCK.name)

        monkeypatch.setenv("MILPA_INDEX_URL", idx_file.as_uri())
        monkeypatch.setenv("MILPA_ENTRY_TRUST_MOCK_DEFAULT", "trusted")
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        monkeypatch.delenv("MILPA_ENTRY_BUNDLE_DIR", raising=False)
        monkeypatch.delenv("MILPA_ENTRY_TRUST", raising=False)
        monkeypatch.delenv("MILPA_ENTRY_TRUST_MOCK_MAP", raising=False)
        _reset_warned_entries()
        _reset_warned_urls()

        env = _mutation_env(mocked_dir, tmp_path / "cas")
        rc = cmd_update(
            project_dir,
            env,
            dep_name=None,
            strategy=Strategy.MAXVER,
            max_parallel=1,
        )
        # Trusted under strict: no raise, no warning — the bundle was
        # genuinely fetched (via the file:// HttpEntryBundleStore derived
        # from MILPA_INDEX_URL) and hash-verified, not silently skipped.
        assert rc == 0
        assert (project_dir / "milpa.lock").exists()
        err = capsys.readouterr().err
        assert "entry-trust warning" not in err


# ---------------------------------------------------------------------------
# Verb-level behavior: the gate fires through cmd_add / cmd_update
# (RFC per-entry-attestation.md §8 Command Coverage — all four online,
# index-loading verbs run the gate at selection; fetch/lock are covered by
# the conformance entry-* fixture matrix, add/update here).
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parents[3]
_FIXTURE_061_MOCK = (
    _REPO_ROOT
    / "conformance/spec-v1/fixture-061-named-dep/mocked-fetches"
    / "https___github.com_example_bar.git@v2.0.0"
)
_FIXTURE_120_MOCK = (
    _REPO_ROOT
    / "conformance/spec-v1/fixture-120-add-git-dep/mocked-fetches"
    / "https___github.com_example_foo.git@main"
)
_BAR_CONTENT_HASH = "dag-sha256:9497672a6e7b5af95064d5709cd2a7a0b6ccd07a209fd541eb1402dc7a9e0383"


def _write_unattested_index(parent: Path, *, armed: bool = False) -> str:
    """Write an index whose bar@2.0.0 entry has NO attestation record.

    ``armed`` (S-EpochGate, RFC attestation-v1-normative.md §6): when
    ``True``, the index also arms an epoch commitment whose enumerated set
    ``S`` deliberately does NOT include ``bar@2.0.0`` — this candidate is
    then ``PostEpoch``, where the entry-trust mandate applies unchanged.
    Without this, an ``Unarmed`` registry classifies every candidate as
    ``epoch_membership=None``, which S-EpochGate caps at ``warn`` even under
    a ``"strict"`` policy (spec §3.6.3 NORMATIVE) — callers exercising the
    strict-raises path must arm the registry so the mandate is actually live.

    Returns the file:// URL for MILPA_INDEX_URL.
    """
    from milpa.epoch_commitment import PreEpochIdentity, commitment_digest

    idx = parent / "index.kdl"
    text = "schema_version 1\n"
    if armed:
        # A committed set containing an UNRELATED identity — bar@2.0.0 is
        # deliberately absent, so it classifies PostEpoch (mandate applies).
        s = [
            PreEpochIdentity(
                namespace="ns1", name="someone-else", version="9.9.9",
                content_hash="dag-sha256:" + "f" * 64,
            )
        ]
        c = commitment_digest(s)
        text += f'attestation-epoch-commitment "{c}"\n\n'
    text += (
        'package "bar" {\n'
        '    namespace "ns1"\n'
        '    version "2.0.0" {\n'
        f'        content_hash "{_BAR_CONTENT_HASH}"\n'
        "        provenance {\n"
        '            kind "git"\n'
        '            url "https://github.com/example/bar.git"\n'
        '            ref "v2.0.0"\n'
        '            commit_sha "cafef00dcafef00dcafef00dcafef00dcafef00d"\n'
        "        }\n"
        "    }\n"
        "}\n"
    )
    idx.write_text(text, encoding="utf-8")
    if armed:
        import json

        sidecar = {
            "identities": [
                {
                    "namespace": "ns1",
                    "name": "someone-else",
                    "version": "9.9.9",
                    "content_hash": "dag-sha256:" + "f" * 64,
                }
            ],
            "bundle": {
                "verificationMaterial": {"tlogEntries": [{"integratedTime": 1700000000, "logIndex": 1}]},
                "dsseEnvelope": {"payload": ""},
            },
        }
        (parent / "index.kdl.epoch-commitment").write_bytes(json.dumps(sidecar).encode("utf-8"))
    return idx.as_uri()


def _mutation_env(mocked_dir: Path, cas_root: Path) -> "object":
    """Build a MilpaEnv over the mocked transport (mirrors test_cli_mutation)."""
    from milpa.cas import CAStore
    from milpa.context import MilpaEnv
    from milpa.fetchers.cas_admitting import CasAdmittingFetcher
    from milpa.fetchers.mocked import mocked_registry

    store = CAStore(root=cas_root)
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


def _setup_verb_project(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    policy: str,
    include_foo_mock: bool = False,
    armed: bool = False,
) -> "tuple[Path, object]":
    """Common scaffolding for the cmd_add / cmd_update gate tests.

    Creates a project with a NAMED dep ``bar`` (registry-resolved, unattested
    index entry) under the given entry-trust *policy*, a combined mocked-
    fetches dir, and a file:// index in MILPA_INDEX_URL. Returns
    ``(project_dir, env)``.

    ``armed`` (S-EpochGate): passed through to ``_write_unattested_index`` —
    see that function's docstring for why the strict-raises tests need it.
    """
    import shutil

    from milpa.entry_trust import _reset_warned_entries
    from milpa.index_trust import _reset_warned_urls

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    # D18 co-requirement (spec §3.4.8): an Armed commitment + entry-trust
    # "strict" requires index-history "strict" too, else TNG-INDEX-EPOCH-
    # RATCHET-REQUIRED aborts before the entry gate is ever reached.
    index_history_line = 'index-history "strict"\n' if (armed and policy == "strict") else ""
    (project_dir / "milpa.kdl").write_text(
        'name "myapp"\n'
        'kind "application"\n'
        # S4 (RFC attestation-v1-normative.md D4): index-trust now defaults to
        # strict too, and this synthetic index.kdl ships no whole-index
        # bundle; pin index-trust "warn" to isolate the entry-trust axis
        # these tests actually exercise.
        'index-trust "warn"\n'
        f'entry-trust "{policy}"\n'
        f'{index_history_line}'
        "deps {\n"
        '    bar ">= 2.0.0"\n'
        "}\n",
        encoding="utf-8",
    )

    mocked_dir = tmp_path / "mocked-fetches"
    shutil.copytree(_FIXTURE_061_MOCK, mocked_dir / _FIXTURE_061_MOCK.name)
    if include_foo_mock:
        shutil.copytree(_FIXTURE_120_MOCK, mocked_dir / _FIXTURE_120_MOCK.name)

    idx_url = _write_unattested_index(tmp_path, armed=armed)
    monkeypatch.setenv("MILPA_INDEX_URL", idx_url)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("MILPA_ENTRY_TRUST", raising=False)
    monkeypatch.delenv("MILPA_ENTRY_TRUST_MOCK_MAP", raising=False)
    monkeypatch.delenv("MILPA_ENTRY_TRUST_MOCK_DEFAULT", raising=False)
    if armed:
        monkeypatch.setenv("MILPA_INDEX_EPOCH_MOCK_VERIFIER", "trusted")
    else:
        monkeypatch.delenv("MILPA_INDEX_EPOCH_MOCK_VERIFIER", raising=False)
    _reset_warned_entries()
    _reset_warned_urls()

    env = _mutation_env(mocked_dir, tmp_path / "cas")
    return project_dir, env


class TestAddUpdateGateBehavior:
    """Strict violation surfaces through add/update; warn passes (RFC §8)."""

    def test_update_strict_unattested_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from milpa.cli import cmd_update
        from milpa.errors import TNG_ENTRY_UNATTESTED
        from milpa.version import Strategy

        # S-EpochGate (spec §3.6.3): an UNARMED registry classifies every
        # candidate epoch_membership=None, which caps "strict" at "warn" (D11
        # warn-equivalence) — so the mandate this test exercises needs an
        # ARMED registry whose committed set excludes "bar" (PostEpoch).
        project_dir, env = _setup_verb_project(tmp_path, monkeypatch, policy="strict", armed=True)
        with pytest.raises(MilpaError) as exc_info:
            cmd_update(
                project_dir,
                env,
                dep_name=None,
                strategy=Strategy.MAXVER,
                max_parallel=1,
            )
        assert exc_info.value.slug == TNG_ENTRY_UNATTESTED
        # Strict is a hard, late resolve failure: no lockfile is written.
        assert not (project_dir / "milpa.lock").exists()

    def test_update_warn_unattested_passes_with_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from milpa.cli import cmd_update
        from milpa.version import Strategy

        project_dir, env = _setup_verb_project(tmp_path, monkeypatch, policy="warn")
        rc = cmd_update(
            project_dir,
            env,
            dep_name=None,
            strategy=Strategy.MAXVER,
            max_parallel=1,
        )
        assert rc == 0
        assert (project_dir / "milpa.lock").exists()
        err = capsys.readouterr().err
        assert "entry-trust warning" in err
        assert "TNG-ENTRY-UNATTESTED" in err

    def test_add_strict_unattested_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """add --git of a NEW URL dep re-resolves the graph; the existing
        NAMED dep bar hits the gate → strict raises, nothing is written."""
        from milpa.cli import cmd_add
        from milpa.errors import TNG_ENTRY_UNATTESTED
        from milpa.version import Strategy

        # S-EpochGate: see test_update_strict_unattested_raises's comment —
        # the registry must be ARMED (PostEpoch) for "strict" to hard-fail.
        project_dir, env = _setup_verb_project(
            tmp_path, monkeypatch, policy="strict", include_foo_mock=True, armed=True
        )
        with pytest.raises(MilpaError) as exc_info:
            cmd_add(
                project_dir,
                env,
                dep_name="foo",
                git_url="https://github.com/example/foo.git",
                mirror_url=None,
                ref="main",
                strategy=Strategy.MAXVER,
                max_parallel=1,
            )
        assert exc_info.value.slug == TNG_ENTRY_UNATTESTED
        # The failed add must not have mutated the manifest or written a lock.
        assert "foo" not in (project_dir / "milpa.kdl").read_text(encoding="utf-8")
        assert not (project_dir / "milpa.lock").exists()

    def test_add_warn_unattested_passes_with_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from milpa.cli import cmd_add
        from milpa.version import Strategy

        project_dir, env = _setup_verb_project(
            tmp_path, monkeypatch, policy="warn", include_foo_mock=True
        )
        rc = cmd_add(
            project_dir,
            env,
            dep_name="foo",
            git_url="https://github.com/example/foo.git",
            mirror_url=None,
            ref="main",
            strategy=Strategy.MAXVER,
            max_parallel=1,
        )
        assert rc == 0
        assert "foo" in (project_dir / "milpa.kdl").read_text(encoding="utf-8")
        assert (project_dir / "milpa.lock").exists()
        err = capsys.readouterr().err
        assert "entry-trust warning" in err
        assert "TNG-ENTRY-UNATTESTED" in err

    def test_update_strict_unattested_on_unarmed_registry_only_warns(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """S-EpochGate (spec §3.6.3 NORMATIVE): an UNARMED registry (the
        default — no ``attestation-epoch-commitment``) is warn-equivalent for
        EVERY candidate, even under a configured ``"strict"`` policy (D11 —
        the same rule §3.4.0 already states for the whole-registry case).
        This is the CLI-integration counterpart of the direct unit coverage
        in ``tests/test_epoch_gate.py``."""
        from milpa.cli import cmd_update
        from milpa.version import Strategy

        project_dir, env = _setup_verb_project(tmp_path, monkeypatch, policy="strict", armed=False)
        rc = cmd_update(
            project_dir,
            env,
            dep_name=None,
            strategy=Strategy.MAXVER,
            max_parallel=1,
        )
        assert rc == 0
        assert (project_dir / "milpa.lock").exists()
        err = capsys.readouterr().err
        assert "entry-trust warning" in err
        assert "TNG-ENTRY-UNATTESTED" in err


# ---------------------------------------------------------------------------
# CR5 — broken manifest must hard-fail, not degrade to warn
# ---------------------------------------------------------------------------


class TestLoadManifestEntryTrustPolicyManifestErrors:
    """``_load_manifest_entry_trust_policy``'s degrade-to-warn is scoped to a
    genuinely ABSENT manifest (``MAN-NO-MANIFEST``) — mirrors the identical
    CR5 fix applied to ``_load_manifest_trust_fields`` (index-trust) and
    ``_load_manifest_index_history_policy`` (index-history) via the shared
    ``_manifest_absent`` predicate.
    """

    def test_broken_manifest_propagates_not_swallowed(self, tmp_path: Path) -> None:
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "milpa.kdl").write_text("this is not valid { kdl\n", encoding="utf-8")

        from milpa.cli import _load_manifest_entry_trust_policy
        with pytest.raises(MilpaError) as exc_info:
            _load_manifest_entry_trust_policy(project_dir)
        assert exc_info.value.slug == "MAN-KDL-SYNTAX"

    def test_genuinely_absent_manifest_still_degrades_to_strict(self, tmp_path: Path) -> None:
        """S4 (RFC attestation-v1-normative.md D1): a genuinely-absent manifest
        degrades to the flipped 'strict' default, not 'warn'."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        from milpa.cli import _load_manifest_entry_trust_policy
        assert _load_manifest_entry_trust_policy(project_dir) == "strict"
