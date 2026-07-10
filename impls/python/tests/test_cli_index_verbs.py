"""``milpa index status`` / `milpa index accept`` — CLI verb-family tests
(A2e, ``rfc-registry-append-only.md``; cli-contract.md §5.12).

Drives the REAL CLI entry (``milpa.cli.main``), in-process, with ``file://``
index fixtures and an isolated ``XDG_CACHE_HOME`` per test — no network, no
mocked transport. This is deliberately at the same altitude as
``test_cli_index_history.py`` / ``test_s10_subcommand_awareness.py``: real
verb dispatch, real argparse, real sidecar files on disk.

Does NOT re-test the dominance-fold engine (``test_ratchet.py``, A2b) or the
seam's parse/gate primitives (``test_index_history_ratchet.py``, A2d) — this
file is about the VERB layer: read-only ``status``, the three-branch
``accept`` swap, the shared diff renderer, member-dir delegation, and the
``--no-index`` / ``index-history off`` / ``index-trust off`` contract points.
"""

from __future__ import annotations

import os
import stat
import textwrap
from pathlib import Path

import pytest

from milpa.cli import main

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

#: The common case for tests that don't exercise the index-trust axis
#: itself — keeps the fetch-and-verify path trivial (no bundle needed).
_TRUST_OFF = 'index-trust "off"\n'


def _write_manifest(project_dir: Path, *, extra: str = "") -> None:
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "milpa.kdl").write_text(f'name "testpkg"\n{extra}', encoding="utf-8")


def _write_index(index_path: Path, *, content_hash: str = "a" * 64) -> None:
    index_path.write_text(
        textwrap.dedent(
            f"""\
            schema_version 1
            package "foo" {{
                namespace "ns"
                version "1.0.0" {{
                    content_hash "sha256:{content_hash}"
                }}
            }}
            """
        ),
        encoding="utf-8",
    )


def _setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    manifest_extra: str = "",
    history: str = "warn",
) -> tuple[Path, Path]:
    """Returns ``(project_dir, index_path)``. Isolated cache dir per test;
    real ``file://`` index fixture."""
    project_dir = tmp_path / "proj"
    _write_manifest(project_dir, extra=manifest_extra)
    index_path = tmp_path / "index.kdl"
    _write_index(index_path)
    cache_dir = tmp_path / "cache"

    monkeypatch.setenv("XDG_CACHE_HOME", str(cache_dir))
    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_path}")
    monkeypatch.setenv("MILPA_INDEX_HISTORY", history)
    monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
    monkeypatch.delenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", raising=False)
    monkeypatch.delenv("MILPA_MOCKED_FETCHES", raising=False)
    return project_dir, index_path


def _cache_file(tmp_path: Path, index_path: Path) -> Path:
    import hashlib

    digest = hashlib.sha256(f"file://{index_path}".encode()).hexdigest()
    return tmp_path / "cache" / "milpa" / "index" / f"{digest[:16]}.index.kdl"


def _run(project_dir: Path, *args: str) -> int:
    return main(["-C", str(project_dir), "index", *args])


# ---------------------------------------------------------------------------
# status — no baseline
# ---------------------------------------------------------------------------


class TestStatusNoBaseline:
    def test_reports_absent_and_exits_0(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, index_path = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        exit_code = _run(project_dir, "status")
        out = capsys.readouterr()
        assert exit_code == 0
        assert out.err == ""
        assert out.out == (
            f"index-url:         file://{index_path}\n"
            "policy:            warn\n"
            "baseline:          absent\n"
            "established-at:    (none)\n"
            "pending:           no\n"
            "last-reported:     (none)\n"
        )

    def test_never_writes_anything(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, _ = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        _run(project_dir, "status")
        capsys.readouterr()
        cache_root = tmp_path / "cache"
        assert not cache_root.exists()


# ---------------------------------------------------------------------------
# status — clean baseline (after a successful accept)
# ---------------------------------------------------------------------------


class TestStatusClean:
    def test_present_clean_exits_0(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, _ = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        assert _run(project_dir, "accept") == 0
        capsys.readouterr()

        exit_code = _run(project_dir, "status")
        out = capsys.readouterr()
        assert exit_code == 0
        assert "baseline:          present" in out.out
        assert "pending:           no" in out.out
        assert "last-reported:     (none)" in out.out
        assert "established-at:    (none)" not in out.out


# ---------------------------------------------------------------------------
# status — pending violation (a real ordinary-fetch warn-path alarm)
# ---------------------------------------------------------------------------


class TestStatusPending:
    def test_pending_violation_reports_yes_and_exits_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, index_path = _setup(
            tmp_path, monkeypatch, manifest_extra=_TRUST_OFF + 'kind "application"\n'
        )
        assert _run(project_dir, "accept") == 0  # TOFU establish
        capsys.readouterr()

        # Mutate a frozen field (rollback-shaped: content_hash change) and
        # drive an ORDINARY index-consulting verb (`lock`) so the warn-policy
        # ratchet gate at the index-cache seam (A2d) writes .baseline.meta's
        # reported_digest for real — the same mechanism production traffic
        # uses, not a test-only shortcut.
        _write_index(index_path, content_hash="b" * 64)
        lock_exit = main(["-C", str(project_dir), "lock"])
        capsys.readouterr()
        assert lock_exit == 0  # warn policy: violation is a warning, not a failure

        exit_code = _run(project_dir, "status")
        out = capsys.readouterr()
        assert exit_code == 1
        assert "baseline:          present" in out.out
        assert "pending:           yes" in out.out
        assert "last-reported:     (none)" not in out.out


# ---------------------------------------------------------------------------
# status --refresh — dry run, writes NOTHING
# ---------------------------------------------------------------------------


class TestStatusRefreshDryRun:
    def test_refresh_on_clean_candidate_exits_0_and_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, index_path = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        assert _run(project_dir, "accept") == 0
        capsys.readouterr()

        baseline_path = tmp_path / "cache" / "milpa" / "index"
        before = {p: p.read_bytes() for p in baseline_path.iterdir()}

        exit_code = _run(project_dir, "status", "--refresh")
        out = capsys.readouterr()
        assert exit_code == 0
        assert out.out == "nothing to accept\n"

        after = {p: p.read_bytes() for p in baseline_path.iterdir()}
        assert before == after
        assert set(before) == set(after)

    def test_refresh_on_dirty_candidate_exits_1_and_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, index_path = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        assert _run(project_dir, "accept") == 0
        capsys.readouterr()

        cache_index_dir = tmp_path / "cache" / "milpa" / "index"
        before = {p: p.read_bytes() for p in cache_index_dir.iterdir()}

        _write_index(index_path, content_hash="c" * 64)
        exit_code = _run(project_dir, "status", "--refresh")
        out = capsys.readouterr()
        assert exit_code == 1
        assert out.out.startswith("violation:\tTNG-ENTRY-MUTATED\t")
        assert "digest: " in out.out

        after = {p: p.read_bytes() for p in cache_index_dir.iterdir()}
        assert before == after
        assert set(before) == set(after)
        # The ordinary index cache file (distinct from the baseline sidecars)
        # must never have been written by a `status --refresh` dry run.
        assert not _cache_file(tmp_path, index_path).exists()


# ---------------------------------------------------------------------------
# accept — branch 1: baseline present, dirty diff -> print + swap
# ---------------------------------------------------------------------------


class TestAcceptPresentDirty:
    def test_accept_swaps_baseline_and_prints_diff(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, index_path = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        assert _run(project_dir, "accept") == 0
        capsys.readouterr()

        baseline_path = tmp_path / "cache" / "milpa" / "index"
        baseline_file = next(p for p in baseline_path.iterdir() if p.name.endswith(".baseline"))
        bytes_before = baseline_file.read_bytes()

        _write_index(index_path, content_hash="d" * 64)
        exit_code = _run(project_dir, "accept")
        out = capsys.readouterr()
        assert exit_code == 0
        assert out.out.startswith("violation:\tTNG-ENTRY-MUTATED\t")
        assert "digest: " in out.out

        bytes_after = baseline_file.read_bytes()
        assert bytes_after != bytes_before
        assert b"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" in bytes_after

    def test_accept_is_idempotent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, index_path = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        assert _run(project_dir, "accept") == 0
        capsys.readouterr()
        _write_index(index_path, content_hash="e" * 64)
        assert _run(project_dir, "accept") == 0
        capsys.readouterr()

        baseline_path = tmp_path / "cache" / "milpa" / "index"
        before = {p: p.read_bytes() for p in baseline_path.iterdir()}

        exit_code = _run(project_dir, "accept")
        out = capsys.readouterr()
        assert exit_code == 0
        assert out.out == "nothing to accept\n"

        after = {p: p.read_bytes() for p in baseline_path.iterdir()}
        assert before == after


# ---------------------------------------------------------------------------
# accept — branch 2: baseline absent -> TOFU establishment
# ---------------------------------------------------------------------------


class TestAcceptAbsent:
    def test_accept_establishes_trust_anchor(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, index_path = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        exit_code = _run(project_dir, "accept")
        out = capsys.readouterr()
        assert exit_code == 0
        assert out.out == "no prior baseline — this fetch establishes the trust anchor\n"

        baseline_path = tmp_path / "cache" / "milpa" / "index"
        baseline_file = next(p for p in baseline_path.iterdir() if p.name.endswith(".baseline"))
        assert baseline_file.read_bytes() == index_path.read_bytes()


# ---------------------------------------------------------------------------
# accept — branch 3: baseline corrupt -> re-establishment
# ---------------------------------------------------------------------------


class TestAcceptCorrupt:
    def test_accept_reestablishes_over_corrupt_baseline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, index_path = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        assert _run(project_dir, "accept") == 0
        capsys.readouterr()

        baseline_path = tmp_path / "cache" / "milpa" / "index"
        baseline_file = next(p for p in baseline_path.iterdir() if p.name.endswith(".baseline"))
        baseline_file.write_bytes(b"not valid kdl {{{")

        _write_index(index_path, content_hash="f" * 64)
        exit_code = _run(project_dir, "accept")
        out = capsys.readouterr()
        assert exit_code == 0
        assert out.out == (
            "baseline unreadable — cannot show what changed; "
            "re-establishing the trust anchor\n"
        )
        assert baseline_file.read_bytes() == index_path.read_bytes()

    def test_status_reports_corrupt_without_raising(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, index_path = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        assert _run(project_dir, "accept") == 0
        capsys.readouterr()

        baseline_path = tmp_path / "cache" / "milpa" / "index"
        baseline_file = next(p for p in baseline_path.iterdir() if p.name.endswith(".baseline"))
        baseline_file.write_bytes(b"not valid kdl {{{")

        exit_code = _run(project_dir, "status")
        out = capsys.readouterr()
        assert exit_code == 1
        assert "baseline:          corrupt" in out.out
        assert "established-at:    (none)" in out.out
        assert out.err == ""  # no TNG-INDEX-BASELINE-CORRUPT hard-fail, no milpa-error: line


# ---------------------------------------------------------------------------
# epoch-change acceptance -> blast-radius sentence (renderer unit test,
# exercised directly against a hand-built violation set — attestation-epoch
# enforcement is live as of A6; see test_index_history_ratchet.py /
# fixture-404 for the end-to-end live-path coverage).
# ---------------------------------------------------------------------------


class TestEpochChangeBlastRadius:
    def test_renderer_prints_blast_radius_sentence_before_violations(self) -> None:
        from milpa.cli import _render_index_verb_diff
        from milpa.ratchet import ROOT_KEY, RatchetOutcome, Violation

        outcome = RatchetOutcome(
            violations=[
                Violation(
                    class_="TNG-INDEX-ROOT-MUTATED",
                    entry_key=ROOT_KEY,
                    field="attestation-epoch",
                    kind="root-field-changed",
                    baseline_value="E1",
                    candidate_value="E2",
                )
            ],
            advanced=False,
        )
        text, clean = _render_index_verb_diff(outcome, "present")
        assert clean is False
        lines = text.splitlines()
        assert lines[0] == (
            "accepting this change reclassifies every entry between the "
            "epochs as pre-epoch/legacy, nullifying the attestation mandate "
            "for all of them — an index-wide consequence, not a one-row one"
        )
        assert lines[1].startswith("violation:\tTNG-INDEX-ROOT-MUTATED\t")
        assert lines[-1].startswith("digest: ")

    def test_renderer_omits_sentence_when_no_epoch_violation(self) -> None:
        from milpa.cli import _render_index_verb_diff
        from milpa.ratchet import EntryKey, RatchetOutcome, Violation

        outcome = RatchetOutcome(
            violations=[
                Violation(
                    class_="TNG-ENTRY-MUTATED",
                    entry_key=EntryKey(namespace="ns", name="foo", version="1.0.0"),
                    field="content_hash",
                    kind="frozen-changed",
                    baseline_value="sha256:aaa",
                    candidate_value="sha256:bbb",
                )
            ],
            advanced=False,
        )
        text, clean = _render_index_verb_diff(outcome, "present")
        assert clean is False
        assert "blast" not in text
        assert "index-wide consequence" not in text
        assert text.splitlines()[0].startswith("violation:\t")


# ---------------------------------------------------------------------------
# member-dir delegation (S11e symmetry)
# ---------------------------------------------------------------------------


class TestMemberDirDelegation:
    def test_member_dir_status_matches_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = tmp_path / "ws"
        root.mkdir()
        (root / "milpa.kdl").write_text(
            'index-trust "off"\nworkspace {\n    member "sub"\n}\n', encoding="utf-8"
        )
        member = root / "sub"
        member.mkdir()
        (member / "milpa.kdl").write_text('name "sub"\nkind "library"\n', encoding="utf-8")

        index_path = tmp_path / "index.kdl"
        _write_index(index_path)
        cache_dir = tmp_path / "cache"
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache_dir))
        monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_path}")
        monkeypatch.setenv("MILPA_INDEX_HISTORY", "warn")
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)

        exit_root = main(["-C", str(root), "index", "status"])
        out_root = capsys.readouterr()
        exit_member = main(["-C", str(member), "index", "status"])
        out_member = capsys.readouterr()

        assert exit_root == exit_member == 0
        assert out_root.out == out_member.out

    def test_member_declaring_index_history_propagates_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = tmp_path / "ws"
        root.mkdir()
        (root / "milpa.kdl").write_text('workspace {\n    member "sub"\n}\n', encoding="utf-8")
        member = root / "sub"
        member.mkdir()
        (member / "milpa.kdl").write_text(
            'name "sub"\nkind "library"\nindex-history "warn"\n', encoding="utf-8"
        )
        index_path = tmp_path / "index.kdl"
        _write_index(index_path)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_path}")
        monkeypatch.delenv("MILPA_INDEX_HISTORY", raising=False)
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)

        exit_code = main(["-C", str(member), "index", "status"])
        out = capsys.readouterr()
        assert exit_code == 1
        assert "milpa-error: WS-INDEX-HISTORY-ON-MEMBER" in out.err


# ---------------------------------------------------------------------------
# CR5 — a syntactically-broken milpa.kdl must hard-fail, not degrade to warn
# ---------------------------------------------------------------------------


class TestBrokenManifestHardFails:
    """``index status`` / ``index accept`` must propagate a real ``MAN-*``
    manifest error instead of degrading it to ``policy: warn`` and printing a
    normal-looking status block.

    ``_load_manifest_index_history_policy``'s degrade-to-warn is scoped to a
    genuinely ABSENT manifest (``MAN-NO-MANIFEST``, spec/cli-contract.md
    §5.12's soft-fail carve-out is about corrupt LOCAL TRUST STATE — a corrupt
    baseline — not manifest-parse errors). A PRESENT-but-broken ``milpa.kdl``
    (``MAN-KDL-SYNTAX`` here) must hard-fail like every other manifest error
    (§5 NORMATIVE: "On any failure (manifest error, …) … exit 1").
    """

    def _write_broken_manifest(self, project_dir: Path) -> None:
        project_dir.mkdir(parents=True, exist_ok=True)
        (project_dir / "milpa.kdl").write_text("this is not valid { kdl\n", encoding="utf-8")

    def test_status_hard_fails_on_broken_manifest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir = tmp_path / "proj"
        self._write_broken_manifest(project_dir)
        index_path = tmp_path / "index.kdl"
        _write_index(index_path)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_path}")
        monkeypatch.delenv("MILPA_INDEX_HISTORY", raising=False)
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)

        exit_code = _run(project_dir, "status")
        out = capsys.readouterr()
        assert exit_code == 1
        assert "milpa-error: MAN-KDL-SYNTAX" in out.err
        assert "policy:" not in out.out, (
            f"CR5: broken manifest must not be swallowed into a normal status "
            f"block; got:\n{out.out}"
        )

    def test_accept_hard_fails_on_broken_manifest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir = tmp_path / "proj"
        self._write_broken_manifest(project_dir)
        index_path = tmp_path / "index.kdl"
        _write_index(index_path)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_path}")
        monkeypatch.delenv("MILPA_INDEX_HISTORY", raising=False)
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)

        exit_code = _run(project_dir, "accept")
        out = capsys.readouterr()
        assert exit_code == 1
        assert "milpa-error: MAN-KDL-SYNTAX" in out.err
        assert not (tmp_path / "cache").exists(), (
            "CR5: accept must not write a baseline when the manifest is broken"
        )

    def test_status_still_degrades_to_warn_on_genuinely_absent_manifest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Regression guard for the CR5 narrowing: a directory with NO
        milpa.kdl/.nimble at all must still degrade to the documented
        ``warn`` default, not start hard-failing too."""
        project_dir = tmp_path / "proj"
        project_dir.mkdir(parents=True)
        index_path = tmp_path / "index.kdl"
        _write_index(index_path)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_path}")
        monkeypatch.delenv("MILPA_INDEX_HISTORY", raising=False)
        monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)

        exit_code = _run(project_dir, "status")
        out = capsys.readouterr()
        assert exit_code == 0
        assert "policy:            warn" in out.out


# ---------------------------------------------------------------------------
# --no-index -> hard error
# ---------------------------------------------------------------------------


class TestNoIndex:
    def test_status_under_no_index_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, _ = _setup(tmp_path, monkeypatch)
        exit_code = main(["-C", str(project_dir), "--no-index", "index", "status"])
        out = capsys.readouterr()
        assert exit_code == 1
        assert "milpa-error: TNG-INDEX-NOT-CONFIGURED" in out.err
        assert not (tmp_path / "cache").exists()

    def test_accept_under_no_index_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, _ = _setup(tmp_path, monkeypatch)
        exit_code = main(["-C", str(project_dir), "--no-index", "index", "accept"])
        out = capsys.readouterr()
        assert exit_code == 1
        assert "milpa-error: TNG-INDEX-NOT-CONFIGURED" in out.err

    def test_empty_index_url_is_equivalent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, _ = _setup(tmp_path, monkeypatch)
        monkeypatch.setenv("MILPA_INDEX_URL", "")
        exit_code = main(["-C", str(project_dir), "index", "status"])
        out = capsys.readouterr()
        assert exit_code == 1
        assert "milpa-error: TNG-INDEX-NOT-CONFIGURED" in out.err


# ---------------------------------------------------------------------------
# index-history "off" — verbs still work, policy field shows off, accept warns
# ---------------------------------------------------------------------------


class TestIndexHistoryOff:
    def test_status_shows_off_policy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # `index-history` must be declared in the MANIFEST to reach "off":
        # env `off` is a no-op floor that cannot weaken the manifest default
        # ("warn") — §3.4.0 rule 2, same as every other policy axis.
        project_dir, _ = _setup(
            tmp_path,
            monkeypatch,
            manifest_extra=_TRUST_OFF + 'index-history "off"\n',
        )
        exit_code = _run(project_dir, "status")
        out = capsys.readouterr()
        assert exit_code == 0
        assert "policy:            off\n" in out.out

    def test_accept_under_history_off_works_and_warns(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, index_path = _setup(
            tmp_path,
            monkeypatch,
            manifest_extra=_TRUST_OFF + 'index-history "off"\n',
        )
        exit_code = _run(project_dir, "accept")
        out = capsys.readouterr()
        assert exit_code == 0
        assert out.out == "no prior baseline — this fetch establishes the trust anchor\n"
        assert 'index-history is "off"' in out.err
        assert "will not be consulted again until the axis is re-enabled" in out.err

        baseline_path = tmp_path / "cache" / "milpa" / "index"
        baseline_file = next(p for p in baseline_path.iterdir() if p.name.endswith(".baseline"))
        assert baseline_file.read_bytes() == index_path.read_bytes()


# ---------------------------------------------------------------------------
# index-trust "off" — no-cryptographic-basis caveat
# ---------------------------------------------------------------------------


class TestIndexTrustOffCaveat:
    def test_accept_prints_caveat(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, _ = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        _run(project_dir, "accept")
        out = capsys.readouterr()
        assert "index-trust is \"off\"" in out.err
        assert "no cryptographic basis" in out.err

    def test_status_refresh_prints_caveat(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, _ = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        _run(project_dir, "status", "--refresh")
        out = capsys.readouterr()
        assert "index-trust is \"off\"" in out.err
        assert "no cryptographic basis" in out.err

    def test_plain_status_does_not_fetch_or_caveat(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Plain ``status`` (no ``--refresh``) never fetches — nothing to
        caveat about; the local-read-only path stays silent on stderr."""
        project_dir, _ = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        _run(project_dir, "status")
        out = capsys.readouterr()
        assert out.err == ""


# ---------------------------------------------------------------------------
# baseline-write failure — loud, distinct error; previous pair left intact
# ---------------------------------------------------------------------------


class TestBaselineWriteFailure:
    @pytest.mark.skipif(
        os.name != "posix" or os.geteuid() == 0, reason="POSIX perms, non-root only"
    )
    def test_write_failure_is_loud_and_leaves_previous_pair_intact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project_dir, index_path = _setup(tmp_path, monkeypatch, manifest_extra=_TRUST_OFF)
        assert _run(project_dir, "accept") == 0
        capsys.readouterr()

        index_dir = tmp_path / "cache" / "milpa" / "index"
        baseline_file = next(p for p in index_dir.iterdir() if p.name.endswith(".baseline"))
        bytes_before = baseline_file.read_bytes()

        _write_index(index_path, content_hash="9" * 64)
        old_mode = index_dir.stat().st_mode
        index_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)  # r-x: reads OK, no new files
        try:
            exit_code = _run(project_dir, "accept")
            out = capsys.readouterr()
        finally:
            index_dir.chmod(old_mode)

        assert exit_code == 1
        assert "milpa-error: TNG-INDEX-BASELINE-WRITE-FAILED" in out.err
        # The diff WAS printed before the failed write (never a silent no-op).
        assert out.out.startswith("violation:\tTNG-ENTRY-MUTATED\t")
        assert baseline_file.read_bytes() == bytes_before
