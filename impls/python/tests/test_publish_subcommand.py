"""Tests for `milpa publish` — S4 slice (CLI wiring over milpa.publishing).

RFC: docs/rfc-distribution-and-publishing.handoff.md, slice S4.

TDD: each test targets one behavior of the argparse surface + `cmd_publish`
glue. In-process invocation (`cmd_publish` / `main`) is used for logic tests;
ONE black-box subprocess smoke test proves the wired-up argv path end to end.

No mocking of milpa's own code — `push`/`sign` fakes are plain functions
matching the `OrasPush`/`CosignSign` protocol shapes (the accepted E2E gap
for the real `oras`/`cosign` binaries, same house style as
`tests/test_publishing.py`).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from milpa.cli import cmd_publish, main
from milpa.errors import PUBLISH_VERSION_TAG_MISMATCH
from milpa.fetchers.oci import OciProvenance


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_publishable_repo(
    tmp_path: Path,
    *,
    name: str = "widget",
    version: str = "1.2.3",
    tag: bool = True,
) -> Path:
    """A tmp_path git repo that is ALSO a milpa project (milpa.kdl at root),
    with one commit, optionally tagged at ``version`` — the shape
    ``resolve_publish_source`` and ``cmd_publish``'s manifest load both need.

    Adapted from tests/test_publishing.py's ``_make_local_git_repo`` /
    tests/test_hash_subcommand.py's ``_make_local_git_repo`` — same
    fixture-reuse discipline, no new scaffolding beyond adding milpa.kdl.
    """
    repo = tmp_path / "proj"
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
    # Disable tag signing regardless of the invoking user's global git config.
    subprocess.run(
        ["git", "-C", str(repo), "config", "tag.gpgsign", "false"],
        check=True, capture_output=True,
    )
    (repo / "milpa.kdl").write_text(f'name "{name}"\nkind "library"\n')
    (repo / "hello.txt").write_text("hello publish\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "initial"],
        check=True, capture_output=True,
    )
    if tag:
        subprocess.run(
            ["git", "-C", str(repo), "tag", version],
            check=True, capture_output=True,
        )
    return repo


def _fake_digest() -> str:
    return "sha256:" + hashlib.sha256(b"fake-artifact-bytes").hexdigest()


def _make_fake_push():
    calls: list[tuple] = []

    def _push(artifact_path, registry_ref, artifact_type, layer_media_type):
        calls.append((artifact_path, registry_ref, artifact_type, layer_media_type))
        return _fake_digest()

    _push.calls = calls  # type: ignore[attr-defined]
    return _push


def _make_fake_sign():
    calls: list[str] = []

    def _sign(oci_ref):
        calls.append(oci_ref)

    _sign.calls = calls  # type: ignore[attr-defined]
    return _sign


def _make_matching_manifest_fetch(repo: Path):
    """M1: a fake `manifest_fetch` whose returned layer digest matches the
    REAL sha256 of the bytes `execute()` will pack for `repo`'s current HEAD
    — `_fake_digest()` (what the fake `push` returns) is unrelated to the
    real packed bytes, so a fake `manifest_fetch` used alongside it must
    independently compute the real local digest to pass M1's verification.
    """
    from milpa.fetchers.git import enumerate_git_entries
    from milpa.publishing import pack_source

    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    entries, _ = enumerate_git_entries(repo, head, submodule_fetch=None)
    local_digest = "sha256:" + hashlib.sha256(pack_source(entries)).hexdigest()

    calls: list[str] = []

    def _fetch(oci_ref):
        calls.append(oci_ref)
        return {"layers": [{"digest": local_digest}]}

    _fetch.calls = calls  # type: ignore[attr-defined]
    return _fetch


# ---------------------------------------------------------------------------
# Behaviour 1 (tracer) — --dry-run renders the plan + stats to stdout, no network
# ---------------------------------------------------------------------------


def test_dry_run_renders_plan_and_stats_to_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    repo = _make_publishable_repo(tmp_path, version="1.2.3")

    rc = cmd_publish(
        repo,
        version="1.2.3",
        target="ghcr.io/coreyleavitt/widget",
        dry_run=True,
    )

    captured = capsys.readouterr()
    assert rc == 0
    record = json.loads(captured.out)
    assert record["content_hash"].startswith("dag-sha256:")
    assert record["entry_count"] >= 1
    assert "total_bytes" in record
    assert "top_dirs" in record
    assert record["target"]["registry"] == "ghcr.io"
    assert record["target"]["repository"] == "coreyleavitt/widget"


# ---------------------------------------------------------------------------
# Behaviour 2 — --dry-run --output writes the plan render as JSON to a file
# ---------------------------------------------------------------------------


def test_dry_run_output_writes_json_file(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    repo = _make_publishable_repo(tmp_path, version="1.2.3")
    out_path = tmp_path / "plan.json"

    rc = cmd_publish(
        repo,
        version="1.2.3",
        target="ghcr.io/coreyleavitt/widget",
        dry_run=True,
        output_path=out_path,
    )
    capsys.readouterr()

    assert rc == 0
    assert out_path.exists()
    record = json.loads(out_path.read_text())
    assert record["content_hash"].startswith("dag-sha256:")
    assert record["name"] == "widget"
    assert record["version"] == "1.2.3"
    assert record["entry_count"] >= 1


# ---------------------------------------------------------------------------
# Behaviour 3 — --name auto-derives from the manifest; explicit --name overrides
# ---------------------------------------------------------------------------


def test_name_auto_derives_from_manifest(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    repo = _make_publishable_repo(tmp_path, name="widget", version="1.2.3")
    out_path = tmp_path / "plan.json"

    rc = cmd_publish(
        repo,
        version="1.2.3",
        target="ghcr.io/coreyleavitt/widget",
        dry_run=True,
        output_path=out_path,
    )
    capsys.readouterr()

    assert rc == 0
    record = json.loads(out_path.read_text())
    assert record["name"] == "widget"


def test_explicit_name_overrides_manifest(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    repo = _make_publishable_repo(tmp_path, name="widget", version="1.2.3")
    out_path = tmp_path / "plan.json"

    rc = cmd_publish(
        repo,
        version="1.2.3",
        target="ghcr.io/coreyleavitt/widget",
        name="different-name",
        dry_run=True,
        output_path=out_path,
    )
    capsys.readouterr()

    assert rc == 0
    record = json.loads(out_path.read_text())
    assert record["name"] == "different-name"


# ---------------------------------------------------------------------------
# Behaviour 4 — --target splits on the FIRST '/'
# ---------------------------------------------------------------------------


def test_target_splits_on_first_slash(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    repo = _make_publishable_repo(tmp_path, version="1.2.3")

    rc = cmd_publish(
        repo,
        version="1.2.3",
        target="ghcr.io/coreyleavitt/z3",
        dry_run=True,
    )
    captured = capsys.readouterr()

    assert rc == 0
    record = json.loads(captured.out)
    assert record["target"]["registry"] == "ghcr.io"
    assert record["target"]["repository"] == "coreyleavitt/z3"


# ---------------------------------------------------------------------------
# Behaviour 5 — missing --version is an argparse usage error (exit 2)
# ---------------------------------------------------------------------------


def test_missing_version_is_argparse_error(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    repo = _make_publishable_repo(tmp_path, version="1.2.3")

    rc = main(["-C", str(repo), "publish", "--target", "ghcr.io/coreyleavitt/widget"])
    capsys.readouterr()

    assert rc == 2


# ---------------------------------------------------------------------------
# Behaviour 6 — resolve failure surfaces as non-zero exit + slug on stderr;
# --allow-untagged makes the same case succeed (reach the plan).
# ---------------------------------------------------------------------------


def test_untagged_repo_fails_with_version_tag_mismatch_slug(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    repo = _make_publishable_repo(tmp_path, version="1.2.3", tag=False)

    rc = main(
        [
            "-C", str(repo), "publish",
            "--version", "1.2.3",
            "--target", "ghcr.io/coreyleavitt/widget",
            "--dry-run",
        ]
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert f"milpa-error: {PUBLISH_VERSION_TAG_MISMATCH}" in captured.err


def test_allow_untagged_reaches_the_plan(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    repo = _make_publishable_repo(tmp_path, version="1.2.3", tag=False)

    rc = main(
        [
            "-C", str(repo), "publish",
            "--version", "1.2.3",
            "--target", "ghcr.io/coreyleavitt/widget",
            "--allow-untagged",
            "--dry-run",
        ]
    )
    captured = capsys.readouterr()

    assert rc == 0, f"expected exit 0, got {rc}; stderr: {captured.err!r}"
    record = json.loads(captured.out)
    assert record["content_hash"].startswith("dag-sha256:")


# ---------------------------------------------------------------------------
# Behaviour 7 — real (non-dry-run) path with injected fakes (seam 7a)
# ---------------------------------------------------------------------------


def test_real_path_with_injected_push_and_sign_writes_receipt(tmp_path: Path) -> None:
    repo = _make_publishable_repo(tmp_path, name="widget", version="1.2.3")
    out_path = tmp_path / "receipt.json"
    fake_push = _make_fake_push()
    fake_sign = _make_fake_sign()
    fake_manifest_fetch = _make_matching_manifest_fetch(repo)

    rc = cmd_publish(
        repo,
        version="1.2.3",
        target="ghcr.io/coreyleavitt/widget",
        output_path=out_path,
        push=fake_push,
        sign=fake_sign,
        manifest_fetch=fake_manifest_fetch,
    )

    assert rc == 0
    assert len(fake_push.calls) == 1
    assert len(fake_sign.calls) == 1

    record = json.loads(out_path.read_text())
    assert record["name"] == "widget"
    assert record["version"] == "1.2.3"
    assert record["layer_digest"] == _fake_digest()
    expected_ref = OciProvenance(
        "ghcr.io", "coreyleavitt/widget", _fake_digest()
    ).reference
    assert record["oci_ref"] == expected_ref
    # cosign must sign the immutable digest-pinned ref, not the mutable tag.
    assert fake_sign.calls[0] == expected_ref


def test_real_path_defaults_tag_to_version(tmp_path: Path) -> None:
    """--tag omitted → the pushed registry_ref carries the version as the tag."""
    repo = _make_publishable_repo(tmp_path, version="1.2.3")
    fake_push = _make_fake_push()
    fake_sign = _make_fake_sign()
    fake_manifest_fetch = _make_matching_manifest_fetch(repo)

    rc = cmd_publish(
        repo,
        version="1.2.3",
        target="ghcr.io/coreyleavitt/widget",
        push=fake_push,
        sign=fake_sign,
        manifest_fetch=fake_manifest_fetch,
    )

    assert rc == 0
    _artifact_path, registry_ref, _artifact_type, _layer_media_type = fake_push.calls[0]
    assert registry_ref == "ghcr.io/coreyleavitt/widget:1.2.3"


def test_real_path_explicit_tag_overrides_version_default(tmp_path: Path) -> None:
    repo = _make_publishable_repo(tmp_path, version="1.2.3")
    fake_push = _make_fake_push()
    fake_sign = _make_fake_sign()
    fake_manifest_fetch = _make_matching_manifest_fetch(repo)

    rc = cmd_publish(
        repo,
        version="1.2.3",
        target="ghcr.io/coreyleavitt/widget",
        tag="latest",
        push=fake_push,
        sign=fake_sign,
        manifest_fetch=fake_manifest_fetch,
    )

    assert rc == 0
    _artifact_path, registry_ref, _artifact_type, _layer_media_type = fake_push.calls[0]
    assert registry_ref == "ghcr.io/coreyleavitt/widget:latest"


# ---------------------------------------------------------------------------
# Behaviour 8 — black-box smoke: subprocess dry-run exits 0 and prints the plan
# ---------------------------------------------------------------------------


def test_blackbox_subprocess_dry_run_smoke(tmp_path: Path) -> None:
    repo = _make_publishable_repo(tmp_path, version="1.2.3")

    result = subprocess.run(
        [
            sys.executable, "-m", "milpa",
            "-C", str(repo),
            "publish",
            "--version", "1.2.3",
            "--target", "ghcr.io/coreyleavitt/widget",
            "--dry-run",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, (
        f"expected exit 0, got {result.returncode}; stderr: {result.stderr!r}"
    )
    record = json.loads(result.stdout)
    assert record["content_hash"].startswith("dag-sha256:")
    assert record["name"] == "widget"


# ---------------------------------------------------------------------------
# M3-cli — the git tree is enumerated exactly ONCE per invocation
# ---------------------------------------------------------------------------


def test_dry_run_enumerates_git_tree_exactly_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A --dry-run invocation must call enumerate_git_entries exactly once —
    the plan's content hash and the dry-run stats must share ONE
    enumeration, not two independent `ls-tree`/`cat-file` reads of the same
    commit."""
    from milpa.fetchers import git as git_mod

    repo = _make_publishable_repo(tmp_path, version="1.2.3")

    real_enumerate = git_mod.enumerate_git_entries
    calls: list[int] = []

    def counting_enumerate(*args, **kwargs):
        calls.append(1)
        return real_enumerate(*args, **kwargs)

    monkeypatch.setattr(git_mod, "enumerate_git_entries", counting_enumerate)

    rc = cmd_publish(
        repo,
        version="1.2.3",
        target="ghcr.io/coreyleavitt/widget",
        dry_run=True,
    )

    assert rc == 0
    assert len(calls) == 1, f"expected exactly 1 enumeration, got {len(calls)}"


def test_real_run_enumerates_git_tree_exactly_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real (non-dry-run) invocation must also call enumerate_git_entries
    exactly once — cmd_publish reuses its own enumeration for both the plan
    AND execute()'s pack step (via `entries=`), so execute() must never
    re-derive its own."""
    from milpa.fetchers import git as git_mod

    repo = _make_publishable_repo(tmp_path, version="1.2.3")
    fake_push = _make_fake_push()
    fake_sign = _make_fake_sign()
    fake_manifest_fetch = _make_matching_manifest_fetch(repo)

    real_enumerate = git_mod.enumerate_git_entries
    calls: list[int] = []

    def counting_enumerate(*args, **kwargs):
        calls.append(1)
        return real_enumerate(*args, **kwargs)

    monkeypatch.setattr(git_mod, "enumerate_git_entries", counting_enumerate)

    rc = cmd_publish(
        repo,
        version="1.2.3",
        target="ghcr.io/coreyleavitt/widget",
        push=fake_push,
        sign=fake_sign,
        manifest_fetch=fake_manifest_fetch,
    )

    assert rc == 0
    assert len(calls) == 1, f"expected exactly 1 enumeration, got {len(calls)}"


# ---------------------------------------------------------------------------
# M4 — --name is derived from the HEAD tree, not the working directory
# ---------------------------------------------------------------------------


def test_name_auto_derives_from_head_not_working_tree(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """HEAD's milpa.kdl says name "z3"; the WORKING tree is edited afterward
    (uncommitted) to say name "z3-local". The auto-derived --name must be
    "z3" (from HEAD), never "z3-local" (from the working tree) — publish's
    source of truth is the git HEAD tree."""
    repo = _make_publishable_repo(tmp_path, name="z3", version="1.2.3")
    # Edit the working tree's milpa.kdl WITHOUT committing.
    (repo / "milpa.kdl").write_text('name "z3-local"\nkind "library"\n')

    rc = cmd_publish(
        repo,
        version="1.2.3",
        target="ghcr.io/coreyleavitt/z3",
        dry_run=True,
    )
    captured = capsys.readouterr()

    assert rc == 0
    record = json.loads(captured.out)
    assert record["name"] == "z3"


def test_name_auto_derive_raises_when_head_has_no_manifest(tmp_path: Path) -> None:
    """If HEAD's tree has no milpa.kdl (only the working tree has one,
    uncommitted), auto-deriving --name raises MAN-NO-MANIFEST rather than
    silently falling back to the working tree's copy."""
    from milpa.errors import MAN_NO_MANIFEST, MilpaError

    repo = tmp_path / "proj"
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
    subprocess.run(
        ["git", "-C", str(repo), "config", "tag.gpgsign", "false"],
        check=True, capture_output=True,
    )
    (repo / "hello.txt").write_text("hello\n")
    subprocess.run(["git", "-C", str(repo), "add", "hello.txt"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "initial"], check=True, capture_output=True
    )
    subprocess.run(["git", "-C", str(repo), "tag", "1.2.3"], check=True, capture_output=True)
    # Only NOW add milpa.kdl to the working tree (uncommitted) — HEAD has none.
    (repo / "milpa.kdl").write_text('name "ghost"\nkind "library"\n')

    with pytest.raises(MilpaError) as exc_info:
        cmd_publish(
            repo,
            version="1.2.3",
            target="ghcr.io/coreyleavitt/ghost",
            dry_run=True,
        )

    assert exc_info.value.slug == MAN_NO_MANIFEST


# ---------------------------------------------------------------------------
# M6 — the oci_ref of a completed publish must reach the operator even if
# writing --output fails
# ---------------------------------------------------------------------------


def test_output_write_failure_still_surfaces_oci_ref_on_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """If _atomic_write (the --output writer) raises, the publish has
    ALREADY happened (push+sign are irreversible) — the oci_ref must still
    reach the operator on stderr, and the command must still surface the
    failure, not silently succeed with a lost receipt."""
    import milpa.cli as cli_mod

    repo = _make_publishable_repo(tmp_path, name="widget", version="1.2.3")
    out_path = tmp_path / "receipt.json"
    fake_push = _make_fake_push()
    fake_sign = _make_fake_sign()
    fake_manifest_fetch = _make_matching_manifest_fetch(repo)

    def _boom(path, text):
        raise OSError("simulated disk full")

    monkeypatch.setattr(cli_mod, "_atomic_write", _boom)

    with pytest.raises(OSError):
        cmd_publish(
            repo,
            version="1.2.3",
            target="ghcr.io/coreyleavitt/widget",
            output_path=out_path,
            push=fake_push,
            sign=fake_sign,
            manifest_fetch=fake_manifest_fetch,
        )

    captured = capsys.readouterr()
    expected_ref = OciProvenance(
        "ghcr.io", "coreyleavitt/widget", _fake_digest()
    ).reference
    assert expected_ref in captured.err
    assert len(fake_push.calls) == 1
    assert len(fake_sign.calls) == 1
    assert not out_path.exists()


# ---------------------------------------------------------------------------
# M7-code — PublishOutputRecord / PublishDryRunRecord: typed --output wire shape
# ---------------------------------------------------------------------------


def test_publish_output_record_field_set_matches_wire_contract() -> None:
    """PublishOutputRecord's field set is the tianguis composite action's
    cross-repo wire contract for a real-run `--output`. Pin the exact set so
    an addition/removal/rename is caught by a failing test, mirroring
    tests/test_publishing.py's test_publish_receipt_field_set_matches_spec_schema."""
    import dataclasses

    from milpa.cli import PublishOutputRecord

    field_names = {f.name for f in dataclasses.fields(PublishOutputRecord)}
    assert field_names == {
        "name", "version", "content_hash", "oci_ref", "layer_digest", "artifact_type",
    }


def test_publish_dry_run_record_field_set_matches_wire_contract() -> None:
    """PublishDryRunRecord's field set is the --dry-run `--output` wire shape
    — deliberately DIFFERENT from PublishOutputRecord (no oci_ref/
    layer_digest; carries the enumeration-stats guardrail fields instead)."""
    import dataclasses

    from milpa.cli import PublishDryRunRecord

    field_names = {f.name for f in dataclasses.fields(PublishDryRunRecord)}
    assert field_names == {
        "name", "version", "content_hash", "target",
        "entry_count", "total_bytes", "top_dirs",
    }


def test_real_run_output_json_keys_match_publish_output_record(tmp_path: Path) -> None:
    """The ACTUAL --output JSON keys for a real run must be exactly
    PublishOutputRecord's field set — proves cmd_publish builds the record
    via the typed dataclass, not a drifting ad hoc dict literal."""
    import dataclasses

    from milpa.cli import PublishOutputRecord

    repo = _make_publishable_repo(tmp_path, version="1.2.3")
    out_path = tmp_path / "receipt.json"
    fake_push = _make_fake_push()
    fake_sign = _make_fake_sign()
    fake_manifest_fetch = _make_matching_manifest_fetch(repo)

    rc = cmd_publish(
        repo,
        version="1.2.3",
        target="ghcr.io/coreyleavitt/widget",
        output_path=out_path,
        push=fake_push,
        sign=fake_sign,
        manifest_fetch=fake_manifest_fetch,
    )

    assert rc == 0
    record = json.loads(out_path.read_text())
    assert set(record.keys()) == {f.name for f in dataclasses.fields(PublishOutputRecord)}


def test_dry_run_output_json_keys_match_publish_dry_run_record(tmp_path: Path) -> None:
    """The ACTUAL --dry-run --output JSON keys must be exactly
    PublishDryRunRecord's field set."""
    import dataclasses

    from milpa.cli import PublishDryRunRecord

    repo = _make_publishable_repo(tmp_path, version="1.2.3")
    out_path = tmp_path / "plan.json"

    rc = cmd_publish(
        repo,
        version="1.2.3",
        target="ghcr.io/coreyleavitt/widget",
        dry_run=True,
        output_path=out_path,
    )

    assert rc == 0
    record = json.loads(out_path.read_text())
    assert set(record.keys()) == {f.name for f in dataclasses.fields(PublishDryRunRecord)}


# ---------------------------------------------------------------------------
# M8 — split_oci_target rejects an empty registry or repository
# ---------------------------------------------------------------------------


def test_cmd_publish_rejects_trailing_slash_target(tmp_path: Path) -> None:
    """--target "ghcr.io/" (empty repository) must raise a clean CLI-level
    CLI-SOURCE-SPEC-INVALID error, not a garbled ref that only fails
    opaquely inside oras."""
    from milpa.errors import CLI_SOURCE_SPEC_INVALID, MilpaError

    repo = _make_publishable_repo(tmp_path, version="1.2.3")

    with pytest.raises(MilpaError) as exc_info:
        cmd_publish(
            repo,
            version="1.2.3",
            target="ghcr.io/",
            dry_run=True,
        )

    assert exc_info.value.slug == CLI_SOURCE_SPEC_INVALID


def test_main_rejects_trailing_slash_target_with_clean_exit(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """The same case through `main()`'s argv path: non-zero exit + slug on
    stderr, not an oras-level failure."""
    from milpa.errors import CLI_SOURCE_SPEC_INVALID

    repo = _make_publishable_repo(tmp_path, version="1.2.3")

    rc = main(
        [
            "-C", str(repo), "publish",
            "--version", "1.2.3",
            "--target", "ghcr.io/",
            "--dry-run",
        ]
    )
    captured = capsys.readouterr()

    assert rc == 1
    assert f"milpa-error: {CLI_SOURCE_SPEC_INVALID}" in captured.err


# ---------------------------------------------------------------------------
# L5 — --dry-run validates --target too (not only the real push/sign path)
# ---------------------------------------------------------------------------


def test_dry_run_rejects_flag_injection_shaped_target(tmp_path: Path) -> None:
    """A --target whose registry begins with '-' must fail even under
    --dry-run — previously only make_oras_push/make_cosign_sign validated
    via validate_oci_field, so --dry-run (which never reaches those
    closures) passed a flag-injection-shaped target silently."""
    from milpa.errors import MilpaError, TNG_UNSAFE_OCI_FIELD

    repo = _make_publishable_repo(tmp_path, version="1.2.3")

    with pytest.raises(MilpaError) as exc_info:
        cmd_publish(
            repo,
            version="1.2.3",
            target="-evil/x",
            dry_run=True,
        )

    assert exc_info.value.slug == TNG_UNSAFE_OCI_FIELD
