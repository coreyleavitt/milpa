"""Tests for `milpa.publishing` — S2 slice (pure plan/receipt data model).

RFC: docs/rfc-distribution-and-publishing.handoff.md, slice S2.

TDD: each test was written RED-first against a real (throwaway, tmp_path) git
repo — no network, no subprocess beyond the git object-store reads that
`enumerate_git_entries` already performs.
"""

from __future__ import annotations

import dataclasses
import gzip
import hashlib
import io
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

from milpa.dag_identity import (
    MODE_EXECUTABLE,
    MODE_REGULAR,
    MODE_SYMLINK,
    MaterializedEntry,
    compute_dag_identity,
)
from milpa.errors import (
    MILPA_INTERNAL,
    MilpaError,
    PUBLISH_COSIGN_FAILED,
    PUBLISH_DIGEST_MISMATCH,
    PUBLISH_GIT_TREE_READ_FAILED,
    PUBLISH_MANIFEST_FETCH_FAILED,
    PUBLISH_NO_DIGEST_IN_OUTPUT,
    PUBLISH_NON_UTF8_SYMLINK_TARGET,
    PUBLISH_NOT_GIT_REPO,
    PUBLISH_OCI_PUSH_FAILED,
    PUBLISH_SUBMODULE_UNSUPPORTED,
    PUBLISH_UNSAFE_PATH,
    PUBLISH_VERSION_TAG_MISMATCH,
    TNG_UNSAFE_OCI_FIELD,
)
from milpa.fetchers.oci import OciProvenance
from milpa.fetchers.safe_extract import extract_tar
from milpa.identity import compute_content_hash
from milpa.publishing import (
    PublishPlan,
    PublishReceipt,
    PublishSource,
    PublishTarget,
    build_publish_plan,
    execute,
    make_cosign_sign,
    make_oras_manifest_fetch,
    make_oras_push,
    pack_source,
    parse_oras_digest_json,
    resolve_publish_name,
    resolve_publish_source,
    resolve_source_git_url,
)
from milpa.fetchers.git import enumerate_git_entries, parse_ls_tree_z


def _local_artifact_digest(repo: Path, commit: str) -> str:
    """sha256 of the exact bytes `execute()` will pack for (repo, commit) —
    the "local" digest side of M1's push-vs-manifest verification. Shared by
    every execute() test below so a fake `manifest_fetch` can return a
    manifest whose layer digest matches, without duplicating the
    enumerate+pack composition in each test.
    """
    entries, _ = enumerate_git_entries(repo, commit, submodule_fetch=None)
    artifact_bytes = pack_source(entries)
    return "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()


def _make_fake_manifest_fetch(digest: str):
    """A fake `OrasManifestFetch` that always returns a manifest whose single
    layer digest is `digest`, recording every oci_ref it was called with."""
    calls: list[str] = []

    def _fetch(oci_ref: str) -> dict:
        calls.append(oci_ref)
        return {"layers": [{"digest": digest}]}

    _fetch.calls = calls  # type: ignore[attr-defined]
    return _fetch


# ---------------------------------------------------------------------------
# Helpers (adapted from tests/test_hash_subcommand.py:53 _make_local_git_repo —
# thin reuse per the RFC's fixture-reuse discipline, no new scaffolding)
# ---------------------------------------------------------------------------


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
    # Disable tag signing regardless of the invoking user's global git config
    # (tag.gpgsign=true would make a plain `git tag <name>` fail with "no tag
    # message?" since it forces an annotated+signed tag needing a message/key).
    subprocess.run(
        ["git", "-C", str(repo), "config", "tag.gpgsign", "false"],
        check=True, capture_output=True,
    )
    (repo / "hello.txt").write_text("hello publish\n")
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


def _make_target() -> PublishTarget:
    return PublishTarget(
        registry="ghcr.io",
        repository="coreyleavitt/z3",
        tag="v2.0.0",
        artifact_type="application/vnd.milpa.source.v1",
        layer_media_type="application/vnd.milpa.source.v1.tar+gzip",
    )


# ---------------------------------------------------------------------------
# Behaviour 1 (tracer) — plan content_hash equals compute_content_hash(clean tree)
# ---------------------------------------------------------------------------


def test_build_publish_plan_content_hash_matches_compute_content_hash(
    tmp_path: Path,
) -> None:
    """For a clean checkout, git-tree entries == working-dir entries, so the
    plan's identity (over enumerate_git_entries) must equal what
    compute_content_hash (over the working dir) computes for the same tree.
    """
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()

    plan = build_publish_plan(source, target)

    assert plan.content_hash == compute_content_hash(repo)


# ---------------------------------------------------------------------------
# Behaviour 2 — untracked working-tree cruft is excluded from the plan's identity
# ---------------------------------------------------------------------------


def test_build_publish_plan_excludes_untracked_working_tree_cruft(
    tmp_path: Path,
) -> None:
    """Adding an untracked file/dir to the working dir (without committing)
    must NOT change plan.content_hash — proves publish reads the committed
    object-store tree (enumerate_git_entries), not the working directory.
    """
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()

    baseline_plan = build_publish_plan(source, target)

    # Untracked file + untracked dir (mirrors the RFC's _deps/ example) — never
    # `git add`ed, so absent from the committed tree.
    (repo / "untracked.txt").write_text("not committed\n")
    deps_dir = repo / "_deps"
    deps_dir.mkdir()
    (deps_dir / "cruft.nim").write_text("# machine-local cruft\n")

    cruft_plan = build_publish_plan(source, target)

    assert cruft_plan.content_hash == baseline_plan.content_hash


# ---------------------------------------------------------------------------
# Behaviour 3 — plan carries no entry bytes/digest; round-trips its inputs
# ---------------------------------------------------------------------------


def test_build_publish_plan_carries_no_entries_or_digest(tmp_path: Path) -> None:
    """The plan is a footgun-free carrier: no entries/digest attributes, and
    the source/target it was built from round-trip unchanged.
    """
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()

    plan = build_publish_plan(source, target)

    assert not hasattr(plan, "entries")
    assert not hasattr(plan, "digest")
    assert {f.name for f in dataclasses.fields(PublishPlan)} == {
        "source",
        "content_hash",
        "target",
        "source_url",
    }
    assert plan.source == source
    assert plan.target == target


# ---------------------------------------------------------------------------
# Behaviour 3b — resolve_source_git_url / PublishPlan.source_url (data-layer
# mechanism for registry-protocol §3.3's optional oci-provenance `source`
# field — reconciling an OCI-published entry against a transitive git=
# reference to the same upstream repo)
# ---------------------------------------------------------------------------


def test_resolve_source_git_url_returns_none_when_no_origin_remote(tmp_path: Path) -> None:
    """A purely local, never-pushed clone (the fixture repos everywhere else
    in this file) has no `origin` remote configured — this is the ordinary,
    fully-supported case, not an error, so it resolves to None rather than
    raising."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)

    assert resolve_source_git_url(source) is None


def test_resolve_source_git_url_reads_origin_remote(tmp_path: Path) -> None:
    """When `origin` IS configured, its URL is returned verbatim (whatever
    `git remote get-url` reports — no milpa-side reformatting)."""
    repo, commit = _make_local_git_repo(tmp_path)
    subprocess.run(
        ["git", "-C", str(repo), "remote", "add", "origin",
         "https://github.com/coreyleavitt/z3.git"],
        check=True, capture_output=True,
    )
    source = PublishSource(repo=repo, commit=commit)

    assert resolve_source_git_url(source) == "https://github.com/coreyleavitt/z3.git"


def test_build_publish_plan_source_url_none_without_origin_remote(tmp_path: Path) -> None:
    """build_publish_plan's derived source_url mirrors resolve_source_git_url
    exactly: absent for a repo with no origin remote."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()

    plan = build_publish_plan(source, target)

    assert plan.source_url is None


def test_build_publish_plan_source_url_populated_from_origin_remote(tmp_path: Path) -> None:
    """build_publish_plan populates source_url from the repo's origin remote
    — the mechanism a downstream caller (cmd_publish) uses to populate a
    registry entry's optional OCI-provenance `source` field."""
    repo, commit = _make_local_git_repo(tmp_path)
    subprocess.run(
        ["git", "-C", str(repo), "remote", "add", "origin",
         "https://github.com/coreyleavitt/z3.git"],
        check=True, capture_output=True,
    )
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()

    plan = build_publish_plan(source, target)

    assert plan.source_url == "https://github.com/coreyleavitt/z3.git"


# ---------------------------------------------------------------------------
# Behaviour 4 — PublishReceipt.oci_ref derivation matches OciProvenance.reference
# ---------------------------------------------------------------------------


def test_publish_receipt_oci_ref_matches_oci_provenance_reference() -> None:
    """oci_ref is meant to be DERIVED via OciProvenance(...).reference, never a
    hand-rolled f-string — pin that the two stay byte-identical for the same
    (registry, repository, digest) triple.
    """
    registry, repository, digest = (
        "ghcr.io",
        "coreyleavitt/z3",
        "sha256:" + "ab" * 32,
    )
    expected_ref = OciProvenance(registry, repository, digest).reference

    receipt = PublishReceipt(
        content_hash="dag-sha256:" + "cd" * 32,
        oci_ref=expected_ref,
        layer_digest=digest,
        artifact_type="application/vnd.milpa.source.v1",
    )

    assert receipt.oci_ref == expected_ref
    assert receipt.oci_ref == f"{registry}/{repository}@{digest}"


def test_publish_receipt_field_set_matches_spec_schema() -> None:
    """PublishReceipt's field set is a cross-repo contract: spec/cli-contract.md
    §10.2 documents it as EXACTLY {content_hash, oci_ref, layer_digest,
    artifact_type, source_url} — a genuine cross-tool contract consumed by the
    tianguis composite action's submission tooling. Pin the dataclass's field
    set so an addition, removal, or rename here is caught by a failing test
    rather than silently drifting from the spec prose (whichever side changes,
    the other must be updated too — this test is the tripwire, not the source
    of truth).

    RED-first check: this assertion is exact-set equality, not subset/superset
    — it fails just as loudly if a field is ADDED to PublishReceipt as if one
    were removed or renamed, so it can't be satisfied by trivially widening
    the dataclass.
    """
    field_names = {f.name for f in dataclasses.fields(PublishReceipt)}
    assert field_names == {
        "content_hash", "oci_ref", "layer_digest", "artifact_type", "source_url",
    }


# ---------------------------------------------------------------------------
# Behaviour 4b — execute() carries PublishPlan.source_url through to the
# PublishReceipt unchanged (never re-derived at execute() time)
# ---------------------------------------------------------------------------


def test_execute_receipt_carries_source_url_from_plan(tmp_path: Path) -> None:
    """execute()'s PublishReceipt.source_url must come straight from
    plan.source_url (which build_publish_plan already derived via
    resolve_source_git_url) — never re-derived or dropped at execute() time."""
    repo, commit = _make_local_git_repo(tmp_path)
    subprocess.run(
        ["git", "-C", str(repo), "remote", "add", "origin",
         "https://github.com/coreyleavitt/z3.git"],
        check=True, capture_output=True,
    )
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)
    assert plan.source_url == "https://github.com/coreyleavitt/z3.git"

    canned_digest = "sha256:" + "b" * 64

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        return canned_digest

    def fake_sign(oci_ref):
        pass

    fake_manifest_fetch = _make_fake_manifest_fetch(_local_artifact_digest(repo, commit))

    receipt = execute(plan, push=fake_push, sign=fake_sign, manifest_fetch=fake_manifest_fetch)

    assert receipt.source_url == "https://github.com/coreyleavitt/z3.git"


def test_execute_receipt_source_url_none_without_origin_remote(tmp_path: Path) -> None:
    """Mirror of the above for the no-`origin`-remote case: PublishReceipt.source_url
    is None, matching plan.source_url, not some sentinel/empty string."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)
    assert plan.source_url is None

    canned_digest = "sha256:" + "c" * 64

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        return canned_digest

    def fake_sign(oci_ref):
        pass

    fake_manifest_fetch = _make_fake_manifest_fetch(_local_artifact_digest(repo, commit))

    receipt = execute(plan, push=fake_push, sign=fake_sign, manifest_fetch=fake_manifest_fetch)

    assert receipt.source_url is None


# ---------------------------------------------------------------------------
# S3a — resolve_publish_source: git-tree source resolution + preflight guards
# ---------------------------------------------------------------------------


def test_resolve_publish_source_happy_path(tmp_path: Path) -> None:
    """Given a real git repo whose HEAD resolves and is tagged `<version>`,
    resolve_publish_source returns PublishSource(repo, commit=<full HEAD sha>).
    """
    repo, commit = _make_local_git_repo(tmp_path)
    subprocess.run(["git", "-C", str(repo), "tag", "2.0.0"], check=True, capture_output=True)

    source = resolve_publish_source(repo, "2.0.0")

    assert source == PublishSource(repo=repo, commit=commit)
    assert len(source.commit) == 40
    assert all(c in "0123456789abcdef" for c in source.commit)


def test_resolve_publish_source_accepts_v_prefixed_tag(tmp_path: Path) -> None:
    """A `v<version>` tag at HEAD satisfies the version<->tag binding guard,
    same as a bare `<version>` tag.
    """
    repo, commit = _make_local_git_repo(tmp_path)
    subprocess.run(["git", "-C", str(repo), "tag", "v2.0.0"], check=True, capture_output=True)

    source = resolve_publish_source(repo, "2.0.0")

    assert source == PublishSource(repo=repo, commit=commit)


def test_resolve_publish_source_not_a_git_repo(tmp_path: Path) -> None:
    """A plain directory (no .git at all) raises PUBLISH-NOT-GIT-REPO."""
    not_a_repo = tmp_path / "plain_dir"
    not_a_repo.mkdir()

    with pytest.raises(MilpaError) as exc_info:
        resolve_publish_source(not_a_repo, "2.0.0", allow_untagged=True)

    assert exc_info.value.slug == PUBLISH_NOT_GIT_REPO


def test_resolve_publish_source_empty_repo_no_commits(tmp_path: Path) -> None:
    """A git repo with no commits (HEAD unborn) raises PUBLISH-NOT-GIT-REPO."""
    repo = tmp_path / "empty_repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)

    with pytest.raises(MilpaError) as exc_info:
        resolve_publish_source(repo, "2.0.0", allow_untagged=True)

    assert exc_info.value.slug == PUBLISH_NOT_GIT_REPO


def test_resolve_publish_source_version_tag_missing(tmp_path: Path) -> None:
    """Neither `<version>` nor `v<version>` exists as a tag → mismatch, unless
    allow_untagged is set.
    """
    repo, _commit = _make_local_git_repo(tmp_path)

    with pytest.raises(MilpaError) as exc_info:
        resolve_publish_source(repo, "2.0.0")

    assert exc_info.value.slug == PUBLISH_VERSION_TAG_MISMATCH


def test_resolve_publish_source_version_tag_points_elsewhere(tmp_path: Path) -> None:
    """A tag named `<version>` that exists but points at an earlier commit
    (not HEAD) still raises PUBLISH-VERSION-TAG-MISMATCH.
    """
    repo, first_commit = _make_local_git_repo(tmp_path)
    subprocess.run(["git", "-C", str(repo), "tag", "2.0.0"], check=True, capture_output=True)

    # Advance HEAD past the tagged commit.
    (repo / "second.txt").write_text("second commit\n")
    subprocess.run(["git", "-C", str(repo), "add", "second.txt"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "second"], check=True, capture_output=True,
    )

    with pytest.raises(MilpaError) as exc_info:
        resolve_publish_source(repo, "2.0.0")

    assert exc_info.value.slug == PUBLISH_VERSION_TAG_MISMATCH


def test_resolve_publish_source_allow_untagged_skips_guard(tmp_path: Path) -> None:
    """allow_untagged=True is the escape hatch: no tag at all, yet resolution
    succeeds and returns the HEAD commit.
    """
    repo, commit = _make_local_git_repo(tmp_path)

    source = resolve_publish_source(repo, "2.0.0", allow_untagged=True)

    assert source == PublishSource(repo=repo, commit=commit)


def test_resolve_publish_source_refuses_submodule_gitlink(tmp_path: Path) -> None:
    """A HEAD tree containing a mode-160000 gitlink entry raises
    PUBLISH-SUBMODULE-UNSUPPORTED — milpa publish does not vendor submodules.
    """
    repo, _commit = _make_local_git_repo(tmp_path)
    # Inject a gitlink entry directly into the index (lighter than a real
    # submodule checkout) — an arbitrary 40-hex SHA stands in for the
    # submodule's pinned commit; ls-tree surfaces its mode regardless of
    # whether that SHA is reachable.
    fake_submodule_sha = "a" * 40
    subprocess.run(
        ["git", "-C", str(repo), "update-index", "--add", "--cacheinfo",
         f"160000,{fake_submodule_sha},vendor/sub"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "add submodule gitlink"],
        check=True, capture_output=True,
    )

    with pytest.raises(MilpaError) as exc_info:
        resolve_publish_source(repo, "2.0.0", allow_untagged=True)

    assert exc_info.value.slug == PUBLISH_SUBMODULE_UNSUPPORTED


# ---------------------------------------------------------------------------
# M9 — split the overloaded PUBLISH-NOT-GIT-REPO slug: a `git ls-tree`
# subprocess FAILURE on an already-HEAD-resolved commit is a distinct
# failure class ("git tree read failed") from "HEAD does not resolve at
# all", and now raises its own PUBLISH-GIT-TREE-READ-FAILED slug.
# ---------------------------------------------------------------------------


def test_refuse_submodules_ls_tree_subprocess_failure_raises_git_tree_read_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `git ls-tree` subprocess failure on an already-validated (HEAD
    resolves fine) commit must raise PUBLISH-GIT-TREE-READ-FAILED, NOT
    PUBLISH-NOT-GIT-REPO -- that slug is reserved for the genuine
    HEAD-unresolvable case (_resolve_head_commit)."""
    import milpa.publishing as publishing_mod

    repo, _commit = _make_local_git_repo(tmp_path)

    real_run = subprocess.run

    def _failing_ls_tree(argv, **kwargs):
        if len(argv) > 3 and argv[3] == "ls-tree":
            return subprocess.CompletedProcess(
                argv, returncode=128, stdout=b"", stderr=b"fatal: loose object corrupt"
            )
        return real_run(argv, **kwargs)

    monkeypatch.setattr(publishing_mod.subprocess, "run", _failing_ls_tree)

    with pytest.raises(MilpaError) as exc_info:
        resolve_publish_source(repo, "2.0.0", allow_untagged=True)

    assert exc_info.value.slug == PUBLISH_GIT_TREE_READ_FAILED


def test_resolve_publish_source_not_a_git_repo_still_raises_not_git_repo(
    tmp_path: Path,
) -> None:
    """Regression pin: the genuine "not a git repo at all" case (HEAD does
    not resolve) still raises PUBLISH-NOT-GIT-REPO, unaffected by the M9
    slug split -- ls-tree is never even reached in this case."""
    not_a_repo = tmp_path / "plain_dir"
    not_a_repo.mkdir()

    with pytest.raises(MilpaError) as exc_info:
        resolve_publish_source(not_a_repo, "2.0.0", allow_untagged=True)

    assert exc_info.value.slug == PUBLISH_NOT_GIT_REPO


# ---------------------------------------------------------------------------
# R2-M2 — resolve_publish_name: derive --name from the HEAD tree's milpa.kdl
# (relocated from cli.py's _load_head_manifest_name; PublishSource-shaped
# git-object-store read, same family as _resolve_head_commit /
# _check_version_tag_binding / _refuse_submodules)
# ---------------------------------------------------------------------------


def test_resolve_publish_name_reads_head_not_working_tree(tmp_path: Path) -> None:
    """HEAD's milpa.kdl says name "z3"; the WORKING tree is edited afterward
    (uncommitted) to say name "z3-local". resolve_publish_name must return
    "z3" (from HEAD), never "z3-local" -- publish's source of truth is the
    git HEAD tree, not the working directory."""
    repo, commit = _make_local_git_repo(tmp_path)
    (repo / "milpa.kdl").write_text('name "z3"\nkind "library"\n')
    subprocess.run(["git", "-C", str(repo), "add", "milpa.kdl"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "add manifest"],
        check=True, capture_output=True,
    )
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    # Edit the working tree's milpa.kdl WITHOUT committing.
    (repo / "milpa.kdl").write_text('name "z3-local"\nkind "library"\n')

    source = PublishSource(repo=repo, commit=head)

    assert resolve_publish_name(source) == "z3"


def test_resolve_publish_name_raises_man_no_manifest_when_head_has_none(
    tmp_path: Path,
) -> None:
    """If HEAD's tree has no milpa.kdl (only the working tree has one,
    uncommitted), resolve_publish_name raises MAN-NO-MANIFEST rather than
    silently falling back to the working tree's copy."""
    from milpa.errors import MAN_NO_MANIFEST

    repo, commit = _make_local_git_repo(tmp_path)
    # Only NOW add milpa.kdl to the working tree (uncommitted) -- HEAD has none.
    (repo / "milpa.kdl").write_text('name "ghost"\nkind "library"\n')

    source = PublishSource(repo=repo, commit=commit)

    with pytest.raises(MilpaError) as exc_info:
        resolve_publish_name(source)

    assert exc_info.value.slug == MAN_NO_MANIFEST


# ---------------------------------------------------------------------------
# S1a — pack_source: canonical packer skeleton (regular files only)
# ---------------------------------------------------------------------------


def test_pack_source_round_trips_through_extract_and_identity(tmp_path: Path) -> None:
    """pack -> extract_tar -> compute_content_hash must equal the identity of
    the original entries (compute_dag_identity) — the pack<->extract<->identity
    closure invariant for regular files.
    """
    entries = [
        MaterializedEntry("a.txt", MODE_REGULAR, b"hello"),
        MaterializedEntry("dir/b.txt", MODE_REGULAR, b"world"),
    ]

    archive_bytes = pack_source(entries)

    archive_path = tmp_path / "out.tar.gz"
    archive_path.write_bytes(archive_bytes)
    dest = tmp_path / "extracted"
    extract_tar(archive_path, dest)

    assert compute_content_hash(dest) == compute_dag_identity(entries)


def test_pack_source_is_byte_deterministic() -> None:
    """Packing the same entries twice yields identical bytes."""
    entries = [
        MaterializedEntry("a.txt", MODE_REGULAR, b"hello"),
        MaterializedEntry("dir/b.txt", MODE_REGULAR, b"world"),
    ]

    first = pack_source(entries)
    second = pack_source(entries)

    assert first == second


def test_pack_source_is_independent_of_input_order() -> None:
    """Packing the same entries in two different input orders yields
    identical bytes — the canonical sort by relpath makes member order
    independent of enumeration order.
    """
    entries_a = [
        MaterializedEntry("a.txt", MODE_REGULAR, b"hello"),
        MaterializedEntry("dir/b.txt", MODE_REGULAR, b"world"),
        MaterializedEntry("z.txt", MODE_REGULAR, b"last"),
    ]
    entries_b = list(reversed(entries_a))

    assert pack_source(entries_a) == pack_source(entries_b)


def test_pack_source_gzip_mtime_is_zero() -> None:
    """The produced bytes are a valid gzip stream whose header mtime is 0."""
    entries = [MaterializedEntry("a.txt", MODE_REGULAR, b"hello")]

    archive_bytes = pack_source(entries)

    assert archive_bytes[:2] == b"\x1f\x8b", "must be a valid gzip stream (magic bytes)"
    assert archive_bytes[4:8] == b"\x00\x00\x00\x00", "gzip header MTIME field must be zero"
    # Decompression must succeed and yield a valid tar.
    decompressed = gzip.decompress(archive_bytes)
    assert decompressed[:5] == b"a.txt" or b"a.txt" in decompressed[:200]


def test_pack_source_long_path_round_trips(tmp_path: Path) -> None:
    """A path >100 chars (forcing a GNU longname header) round-trips through
    pack -> extract_tar -> hash unchanged.
    """
    long_dir = "d" * 95
    long_relpath = f"{long_dir}/file.txt"
    assert len(long_relpath) > 100
    entries = [MaterializedEntry(long_relpath, MODE_REGULAR, b"deep content")]

    archive_bytes = pack_source(entries)

    archive_path = tmp_path / "out.tar.gz"
    archive_path.write_bytes(archive_bytes)
    dest = tmp_path / "extracted"
    extract_tar(archive_path, dest)

    assert (dest / long_relpath).read_bytes() == b"deep content"
    assert compute_content_hash(dest) == compute_dag_identity(entries)


# ---------------------------------------------------------------------------
# S1b — pack_source: MODE_EXECUTABLE round-trip (exec bit closes end-to-end)
# ---------------------------------------------------------------------------


def test_pack_source_executable_round_trips_through_extract_and_identity(
    tmp_path: Path,
) -> None:
    """pack -> extract_tar -> compute_content_hash must equal the identity of
    the original entries when one entry is MODE_EXECUTABLE — the exec bit
    must survive pack -> extract -> hash, not just MODE_REGULAR (S1a).
    """
    entries = [
        MaterializedEntry("run.sh", MODE_EXECUTABLE, b"#!/bin/sh\necho hi\n"),
        MaterializedEntry("readme.txt", MODE_REGULAR, b"not executable\n"),
    ]

    archive_bytes = pack_source(entries)

    archive_path = tmp_path / "out.tar.gz"
    archive_path.write_bytes(archive_bytes)
    dest = tmp_path / "extracted"
    extract_tar(archive_path, dest)

    assert compute_content_hash(dest) == compute_dag_identity(entries)


def test_pack_source_executable_bit_is_set_on_disk_and_regular_is_not(
    tmp_path: Path,
) -> None:
    """After extraction, the executable entry has 0o111 bits set while a
    sibling regular file does not — guards against a "chmod everything
    0o755" false-green that would uniformly stamp every member executable.
    """
    entries = [
        MaterializedEntry("run.sh", MODE_EXECUTABLE, b"#!/bin/sh\necho hi\n"),
        MaterializedEntry("readme.txt", MODE_REGULAR, b"not executable\n"),
    ]

    archive_bytes = pack_source(entries)
    archive_path = tmp_path / "out.tar.gz"
    archive_path.write_bytes(archive_bytes)
    dest = tmp_path / "extracted"
    extract_tar(archive_path, dest)

    assert (dest / "run.sh").stat().st_mode & 0o111 != 0
    assert (dest / "readme.txt").stat().st_mode & 0o111 == 0


def test_pack_source_with_executable_is_byte_deterministic() -> None:
    """Packing entries that include an executable file is still
    byte-deterministic (pack twice -> identical bytes) — a cheap guard that
    the new MODE_EXECUTABLE branch didn't introduce nondeterminism.
    """
    entries = [
        MaterializedEntry("run.sh", MODE_EXECUTABLE, b"#!/bin/sh\necho hi\n"),
        MaterializedEntry("readme.txt", MODE_REGULAR, b"not executable\n"),
    ]

    first = pack_source(entries)
    second = pack_source(entries)

    assert first == second


# ---------------------------------------------------------------------------
# S1c — pack_source: MODE_SYMLINK round-trip (the genuinely new packer branch)
# ---------------------------------------------------------------------------


def test_pack_source_symlink_round_trips_through_extract_and_identity(
    tmp_path: Path,
) -> None:
    """pack -> extract_tar -> compute_content_hash must equal the identity of
    the original entries when one entry is MODE_SYMLINK — the symlink target
    must survive pack -> extract -> hash, matching enumerate_local_entries'
    UTF-8-decoded-readlink content exactly.
    """
    entries = [
        MaterializedEntry("real.txt", MODE_REGULAR, b"the real file\n"),
        MaterializedEntry("link.txt", MODE_SYMLINK, b"real.txt"),
    ]

    archive_bytes = pack_source(entries)

    archive_path = tmp_path / "out.tar.gz"
    archive_path.write_bytes(archive_bytes)
    dest = tmp_path / "extracted"
    extract_tar(archive_path, dest)

    assert compute_content_hash(dest) == compute_dag_identity(entries)


def test_pack_source_symlink_is_a_real_symlink_on_disk(tmp_path: Path) -> None:
    """After extraction, the symlink entry is an actual on-disk symlink whose
    target matches the original — proves it's emitted as a real tar SYMTYPE
    member, not a regular file containing the target text.
    """
    entries = [
        MaterializedEntry("real.txt", MODE_REGULAR, b"the real file\n"),
        MaterializedEntry("link.txt", MODE_SYMLINK, b"real.txt"),
    ]

    archive_bytes = pack_source(entries)
    archive_path = tmp_path / "out.tar.gz"
    archive_path.write_bytes(archive_bytes)
    dest = tmp_path / "extracted"
    extract_tar(archive_path, dest)

    assert (dest / "link.txt").is_symlink()
    assert os.readlink(dest / "link.txt") == "real.txt"


def test_pack_source_with_symlink_is_byte_deterministic() -> None:
    """Packing entries that include a symlink is still byte-deterministic
    (pack twice -> identical bytes)."""
    entries = [
        MaterializedEntry("real.txt", MODE_REGULAR, b"the real file\n"),
        MaterializedEntry("link.txt", MODE_SYMLINK, b"real.txt"),
    ]

    first = pack_source(entries)
    second = pack_source(entries)

    assert first == second


# ---------------------------------------------------------------------------
# L4 — close remaining round-trip coverage gaps
# ---------------------------------------------------------------------------


def test_pack_source_all_three_modes_together_round_trips_through_extract_and_identity(
    tmp_path: Path,
) -> None:
    """(L4a) A single tree mixing all three modes together (regular +
    executable + symlink) round-trips through pack -> extract_tar -> hash
    matching compute_dag_identity(entries) -- previously only PAIRWISE
    combos were exercised (regular+executable in S1b, regular+symlink in
    S1c); this proves the three branches don't interfere with each other
    when they coexist in one tree.
    """
    entries = [
        MaterializedEntry("readme.txt", MODE_REGULAR, b"just a regular file\n"),
        MaterializedEntry("run.sh", MODE_EXECUTABLE, b"#!/bin/sh\necho hi\n"),
        MaterializedEntry("link.txt", MODE_SYMLINK, b"readme.txt"),
    ]

    archive_bytes = pack_source(entries)

    archive_path = tmp_path / "out.tar.gz"
    archive_path.write_bytes(archive_bytes)
    dest = tmp_path / "extracted"
    extract_tar(archive_path, dest)

    assert compute_content_hash(dest) == compute_dag_identity(entries)
    assert (dest / "run.sh").stat().st_mode & 0o111 != 0
    assert (dest / "readme.txt").stat().st_mode & 0o111 == 0
    assert (dest / "link.txt").is_symlink()
    assert os.readlink(dest / "link.txt") == "readme.txt"


def test_pack_source_empty_file_round_trips_through_extract_and_identity(
    tmp_path: Path,
) -> None:
    """(L4b) A zero-byte (b"") regular-file entry round-trips through
    pack -> extract_tar -> hash unchanged -- the empty-content edge case
    was never exercised (every existing pack_source test uses non-empty
    content).
    """
    entries = [
        MaterializedEntry("empty.txt", MODE_REGULAR, b""),
        MaterializedEntry("nonempty.txt", MODE_REGULAR, b"not empty"),
    ]

    archive_bytes = pack_source(entries)

    archive_path = tmp_path / "out.tar.gz"
    archive_path.write_bytes(archive_bytes)
    dest = tmp_path / "extracted"
    extract_tar(archive_path, dest)

    assert (dest / "empty.txt").read_bytes() == b""
    assert compute_content_hash(dest) == compute_dag_identity(entries)


# ---------------------------------------------------------------------------
# S3b — parse_oras_digest_json + make_oras_push
# ---------------------------------------------------------------------------


def test_parse_oras_digest_json_happy_path_digest_field() -> None:
    """A realistic `oras push --format json` object with a top-level "digest"
    field yields that digest directly."""
    digest = "sha256:" + "a" * 64
    stdout = (
        '{"mediaType":"application/vnd.oci.image.manifest.v1+json",'
        f'"digest":"{digest}","size":1234}}'
    )

    assert parse_oras_digest_json(stdout) == digest


def test_parse_oras_digest_json_happy_path_reference_field_fallback() -> None:
    """When there is no "digest" field, the digest suffix of a "reference"
    field (`registry/repository@sha256:...`) is extracted instead."""
    digest = "sha256:" + "b" * 64
    stdout = f'{{"reference":"ghcr.io/coreyleavitt/z3@{digest}"}}'

    assert parse_oras_digest_json(stdout) == digest


def test_parse_oras_digest_json_malformed_digest_falls_back_to_reference() -> None:
    """(L4c) When "digest" is PRESENT but malformed (not a valid
    sha256:<64-hex> string) alongside a valid "reference" field, the
    reference-suffix fallback still engages -- previously the reference
    fallback was only exercised when "digest" was ABSENT entirely, so a
    present-but-garbled "digest" could in principle have masked a working
    "reference" without any test catching it.
    """
    digest = "sha256:" + "c" * 64
    stdout = (
        '{"digest":"not-a-real-digest",'
        f'"reference":"ghcr.io/coreyleavitt/z3@{digest}"}}'
    )

    assert parse_oras_digest_json(stdout) == digest


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "not json at all",
        '{"mediaType":"application/vnd.oci.image.manifest.v1+json","size":1234}',
        '{"reference":"ghcr.io/coreyleavitt/z3:v1.0.0"}',
        "[]",
    ],
    ids=[
        "empty-string",
        "non-json",
        "valid-json-no-digest-or-reference",
        "reference-without-digest-suffix",
        "valid-json-not-an-object",
    ],
)
def test_parse_oras_digest_json_malformed_raises_no_digest_in_output(stdout: str) -> None:
    """Empty, non-JSON, or digest-less JSON stdout all raise
    PUBLISH-NO-DIGEST-IN-OUTPUT — never a bare exception."""
    with pytest.raises(MilpaError) as exc_info:
        parse_oras_digest_json(stdout)

    assert exc_info.value.slug == PUBLISH_NO_DIGEST_IN_OUTPUT


def test_make_oras_push_validates_registry_ref_before_subprocess() -> None:
    """A registry_ref that `validate_oci_field` rejects (leading '-') raises
    deterministically BEFORE any subprocess is spawned — proven by the fact
    that this test passes with no real `oras` binary required regardless of
    whether one is on PATH."""
    push = make_oras_push()

    with pytest.raises(MilpaError) as exc_info:
        push(Path("/nonexistent/artifact.tar.gz"), "-rf", "application/vnd.milpa.source.v1", "application/vnd.milpa.source.v1.tar+gzip")

    assert exc_info.value.slug == TNG_UNSAFE_OCI_FIELD


def test_make_oras_push_validates_artifact_type_before_subprocess() -> None:
    """Same validation-precedes-subprocess guarantee for `artifact_type`."""
    push = make_oras_push()

    with pytest.raises(MilpaError) as exc_info:
        push(Path("/nonexistent/artifact.tar.gz"), "ghcr.io/coreyleavitt/z3:v1.0.0", "-unsafe", "application/vnd.milpa.source.v1.tar+gzip")

    assert exc_info.value.slug == TNG_UNSAFE_OCI_FIELD


def test_make_oras_push_validates_layer_media_type_before_subprocess() -> None:
    """Same validation-precedes-subprocess guarantee for `layer_media_type`."""
    push = make_oras_push()

    with pytest.raises(MilpaError) as exc_info:
        push(Path("/nonexistent/artifact.tar.gz"), "ghcr.io/coreyleavitt/z3:v1.0.0", "application/vnd.milpa.source.v1", "-unsafe")

    assert exc_info.value.slug == TNG_UNSAFE_OCI_FIELD


# ---------------------------------------------------------------------------
# S3c — make_cosign_sign (keyless signing closure)
# ---------------------------------------------------------------------------


def test_make_cosign_sign_validates_oci_ref_before_subprocess() -> None:
    """An oci_ref that `validate_oci_field` rejects (leading '-') raises
    deterministically BEFORE any subprocess is spawned — proven by the fact
    that this test passes with no real `cosign` binary required regardless of
    whether one is on PATH. Mirrors the push-side validation-precedes-
    subprocess tests above."""
    sign = make_cosign_sign()

    with pytest.raises(MilpaError) as exc_info:
        sign("-rf")

    assert exc_info.value.slug == TNG_UNSAFE_OCI_FIELD


# ---------------------------------------------------------------------------
# S3d — execute(plan, push, sign): the impure orchestration seam
# ---------------------------------------------------------------------------


def test_execute_happy_path_returns_receipt(tmp_path: Path) -> None:
    """execute() packs+pushes+signs via injected fakes and assembles a
    PublishReceipt whose fields are exactly: plan.content_hash unchanged,
    layer_digest == what the fake push returned, oci_ref derived via
    OciProvenance(...).reference over that digest, and artifact_type carried
    from the plan's target.
    """
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)

    canned_digest = "sha256:" + "a" * 64
    push_calls: list[tuple] = []
    sign_calls: list[str] = []

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        push_calls.append((artifact_path, registry_ref, artifact_type, layer_media_type))
        return canned_digest

    def fake_sign(oci_ref):
        sign_calls.append(oci_ref)

    fake_manifest_fetch = _make_fake_manifest_fetch(_local_artifact_digest(repo, commit))

    receipt = execute(plan, push=fake_push, sign=fake_sign, manifest_fetch=fake_manifest_fetch)

    assert receipt == PublishReceipt(
        content_hash=plan.content_hash,
        oci_ref=OciProvenance(target.registry, target.repository, canned_digest).reference,
        layer_digest=canned_digest,
        artifact_type=target.artifact_type,
    )
    assert len(push_calls) == 1
    assert len(sign_calls) == 1
    assert len(fake_manifest_fetch.calls) == 1


def test_execute_signs_the_digest_pinned_ref_not_the_tag(tmp_path: Path) -> None:
    """The ref handed to `sign` must be the immutable `registry/repository@digest`
    form, NOT the mutable `registry/repository:tag` form — proves execute signs
    what was actually pushed, not the (mutable, re-pushable) tag.
    """
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)

    canned_digest = "sha256:" + "b" * 64
    sign_calls: list[str] = []

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        return canned_digest

    def fake_sign(oci_ref):
        sign_calls.append(oci_ref)

    fake_manifest_fetch = _make_fake_manifest_fetch(_local_artifact_digest(repo, commit))

    execute(plan, push=fake_push, sign=fake_sign, manifest_fetch=fake_manifest_fetch)

    assert sign_calls == [f"{target.registry}/{target.repository}@{canned_digest}"]
    assert ":" + target.tag not in sign_calls[0]


def test_execute_pushes_the_canonical_packed_bytes(tmp_path: Path) -> None:
    """The file handed to `push` must exist and contain exactly the bytes
    pack_source(enumerate_git_entries(...)) would produce for the same
    repo/commit — proves execute re-derives entries and packs them via the
    canonical packer, not some ad hoc byte stream.
    """
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)

    entries, _ = enumerate_git_entries(repo, commit, submodule_fetch=None)
    expected_bytes = pack_source(entries)

    captured: dict[str, bytes] = {}

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        assert artifact_path.exists()
        captured["bytes"] = artifact_path.read_bytes()
        return "sha256:" + "c" * 64

    def fake_sign(oci_ref):
        pass

    fake_manifest_fetch = _make_fake_manifest_fetch(_local_artifact_digest(repo, commit))

    execute(plan, push=fake_push, sign=fake_sign, manifest_fetch=fake_manifest_fetch)

    assert captured["bytes"] == expected_bytes


def test_execute_pushes_before_signing(tmp_path: Path) -> None:
    """push must happen before verify (manifest_fetch) must happen before
    sign — you verify the digest before signing what push returned."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)

    order: list[str] = []

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        order.append("push")
        return "sha256:" + "d" * 64

    def fake_sign(oci_ref):
        order.append("sign")

    local_digest = _local_artifact_digest(repo, commit)

    def fake_manifest_fetch(oci_ref):
        order.append("verify")
        return {"layers": [{"digest": local_digest}]}

    execute(plan, push=fake_push, sign=fake_sign, manifest_fetch=fake_manifest_fetch)

    assert order == ["push", "verify", "sign"]


def test_execute_cleans_up_temp_artifact_after_push(tmp_path: Path) -> None:
    """The temp file path handed to push must no longer exist once execute
    returns — proves execute doesn't litter the filesystem with published
    artifacts.
    """
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)

    captured_path: dict[str, Path] = {}

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        assert artifact_path.exists()
        captured_path["path"] = artifact_path
        return "sha256:" + "e" * 64

    def fake_sign(oci_ref):
        pass

    fake_manifest_fetch = _make_fake_manifest_fetch(_local_artifact_digest(repo, commit))

    execute(plan, push=fake_push, sign=fake_sign, manifest_fetch=fake_manifest_fetch)

    assert not captured_path["path"].exists()
    assert not captured_path["path"].parent.exists()


# ---------------------------------------------------------------------------
# H2 — pack_source: tar encoding must be pinned to utf-8 (not locale-dependent)
# ---------------------------------------------------------------------------


def test_pack_source_non_ascii_relpath_round_trips() -> None:
    """A non-ASCII relpath (café/résumé.txt) must pack and round-trip cleanly
    through extract_tar -> compute_content_hash without raising.

    Control (demonstrates the bug class this guards against): opening a tar
    with the SAME GNU format but WITHOUT an explicit encoding="utf-8" -- i.e.
    relying on tarfile's fallback to sys.getfilesystemencoding() -- raises a
    bare UnicodeEncodeError under a forced ascii encoding. pack_source pins
    encoding="utf-8" explicitly, so it must succeed regardless of the
    process's filesystem encoding / locale.
    """
    entries = [
        MaterializedEntry("café/résumé.txt", MODE_REGULAR, b"non-ascii path"),
    ]

    # Control: without an explicit utf-8 encoding, forcing ascii raises.
    control_buf = io.BytesIO()
    with pytest.raises(UnicodeEncodeError):
        with tarfile.open(
            fileobj=control_buf, mode="w", format=tarfile.GNU_FORMAT, encoding="ascii"
        ) as tf:
            info = tarfile.TarInfo(name="café/résumé.txt")
            info.size = len(b"non-ascii path")
            tf.addfile(info, io.BytesIO(b"non-ascii path"))

    # pack_source itself must not raise, and must round-trip.
    archive_bytes = pack_source(entries)

    assert compute_dag_identity(entries) is not None  # sanity: identity computable

    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
        names = tf.getnames()
    assert "café/résumé.txt" in names


def test_pack_source_non_ascii_relpath_extracts_and_hashes_correctly(
    tmp_path: Path,
) -> None:
    """End-to-end: pack -> extract_tar -> compute_content_hash equals the
    identity of the original entries, for a non-ASCII relpath.
    """
    entries = [
        MaterializedEntry("café/résumé.txt", MODE_REGULAR, b"non-ascii path"),
    ]

    archive_bytes = pack_source(entries)
    archive_path = tmp_path / "out.tar.gz"
    archive_path.write_bytes(archive_bytes)
    dest = tmp_path / "extracted"
    extract_tar(archive_path, dest)

    assert compute_content_hash(dest) == compute_dag_identity(entries)


# ---------------------------------------------------------------------------
# M2 — parse_ls_tree_z: the shared ls-tree -z parser (SSOT), reused by both
# enumerate_git_entries (git.py) and _refuse_submodules (publishing.py)
# ---------------------------------------------------------------------------


def test_parse_ls_tree_z_parses_blob_and_gitlink_records() -> None:
    """The shared parser correctly splits NUL-delimited ls-tree -z records
    into (mode, type, sha, path) tuples for both a regular blob and a
    mode-160000 gitlink -- the exact record shapes both
    enumerate_git_entries and _refuse_submodules rely on it for."""
    blob_sha = "a" * 40
    gitlink_sha = "b" * 40
    raw = (
        f"100644 blob {blob_sha}\thello.txt".encode() + b"\x00"
        + f"160000 commit {gitlink_sha}\tvendor/sub".encode() + b"\x00"
    )

    records = parse_ls_tree_z(raw)

    assert records == [
        ("100644", "blob", blob_sha, "hello.txt"),
        ("160000", "commit", gitlink_sha, "vendor/sub"),
    ]


def test_parse_ls_tree_z_used_by_submodule_refusal_guard(tmp_path: Path) -> None:
    """End-to-end regression: resolve_publish_source's submodule-refusal
    guard (_refuse_submodules), now wired through the SHARED parse_ls_tree_z
    helper instead of its own independent parse, still raises
    PUBLISH-SUBMODULE-UNSUPPORTED for a real gitlink entry -- proves the M2
    SSOT refactor didn't change observable behavior."""
    repo, _commit = _make_local_git_repo(tmp_path)
    fake_submodule_sha = "c" * 40
    subprocess.run(
        ["git", "-C", str(repo), "update-index", "--add", "--cacheinfo",
         f"160000,{fake_submodule_sha},vendor/sub"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "add submodule gitlink"],
        check=True, capture_output=True,
    )

    with pytest.raises(MilpaError) as exc_info:
        resolve_publish_source(repo, "2.0.0", allow_untagged=True)

    assert exc_info.value.slug == PUBLISH_SUBMODULE_UNSUPPORTED


# ---------------------------------------------------------------------------
# H1/M5 — _check_entries_safe: producer-side path-containment validation
# ---------------------------------------------------------------------------


def test_pack_source_rejects_dotdot_relpath_entry() -> None:
    """A crafted entries list with a `..`-escaping relpath raises
    PUBLISH-UNSAFE-PATH from pack_source directly (defense-in-depth), not a
    bare tarfile write of an unsafe member name."""
    entries = [MaterializedEntry("../evil.txt", MODE_REGULAR, b"pwn")]

    with pytest.raises(MilpaError) as exc_info:
        pack_source(entries)

    assert exc_info.value.slug == PUBLISH_UNSAFE_PATH


def test_pack_source_rejects_absolute_relpath_entry() -> None:
    """An absolute relpath entry raises PUBLISH-UNSAFE-PATH."""
    entries = [MaterializedEntry("/etc/passwd", MODE_REGULAR, b"pwn")]

    with pytest.raises(MilpaError) as exc_info:
        pack_source(entries)

    assert exc_info.value.slug == PUBLISH_UNSAFE_PATH


def test_pack_source_rejects_absolute_symlink_target() -> None:
    """A MODE_SYMLINK entry whose target is an absolute path raises
    PUBLISH-UNSAFE-PATH."""
    entries = [MaterializedEntry("link.txt", MODE_SYMLINK, b"/etc/passwd")]

    with pytest.raises(MilpaError) as exc_info:
        pack_source(entries)

    assert exc_info.value.slug == PUBLISH_UNSAFE_PATH


def test_pack_source_rejects_symlink_target_escaping_via_dotdot() -> None:
    """A MODE_SYMLINK entry whose relative target resolves outside the tree
    root (via `..`) raises PUBLISH-UNSAFE-PATH."""
    entries = [
        MaterializedEntry("sub/link.txt", MODE_SYMLINK, b"../../../etc/passwd"),
    ]

    with pytest.raises(MilpaError) as exc_info:
        pack_source(entries)

    assert exc_info.value.slug == PUBLISH_UNSAFE_PATH


def test_pack_source_rejects_non_utf8_symlink_target() -> None:
    """A MODE_SYMLINK entry whose content is not valid UTF-8 raises
    PUBLISH-NON-UTF8-SYMLINK-TARGET, not a bare UnicodeDecodeError."""
    entries = [MaterializedEntry("link.txt", MODE_SYMLINK, b"\xff\xfe")]

    with pytest.raises(MilpaError) as exc_info:
        pack_source(entries)

    assert exc_info.value.slug == PUBLISH_NON_UTF8_SYMLINK_TARGET


def test_build_publish_plan_rejects_dotdot_relpath_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A crafted entries list (as a maliciously constructed or corrupted git
    tree could yield) containing a `..`-escaping relpath raises
    PUBLISH-UNSAFE-PATH at PLAN-BUILD time, not only at pack time -- so a
    ``--dry-run`` catches it too.

    Modern git refuses to write a `..`-containing path into a real tree
    (mktree/update-index reject it), so `enumerate_git_entries` is
    monkeypatched to return the crafted entries directly -- the same pattern
    already used in tests/test_git_fetcher.py's TestR101ZipSlipContainment
    for the read-side containment guard.
    """
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()

    evil_entries = [MaterializedEntry("../evil.txt", MODE_REGULAR, b"pwn")]
    monkeypatch.setattr(
        "milpa.publishing.enumerate_git_entries",
        lambda *a, **k: (evil_entries, {}),
    )

    with pytest.raises(MilpaError) as exc_info:
        build_publish_plan(source, target)

    assert exc_info.value.slug == PUBLISH_UNSAFE_PATH


def test_build_publish_plan_rejects_absolute_symlink_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A crafted entries list with an absolute-target symlink raises
    PUBLISH-UNSAFE-PATH at plan-build time."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()

    evil_entries = [MaterializedEntry("link.txt", MODE_SYMLINK, b"/etc/passwd")]
    monkeypatch.setattr(
        "milpa.publishing.enumerate_git_entries",
        lambda *a, **k: (evil_entries, {}),
    )

    with pytest.raises(MilpaError) as exc_info:
        build_publish_plan(source, target)

    assert exc_info.value.slug == PUBLISH_UNSAFE_PATH


def test_build_publish_plan_rejects_non_utf8_symlink_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A crafted entries list with a non-UTF-8 symlink target raises
    PUBLISH-NON-UTF8-SYMLINK-TARGET at plan-build time, not a bare
    UnicodeDecodeError."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()

    evil_entries = [MaterializedEntry("link.txt", MODE_SYMLINK, b"\xff\xfe")]
    monkeypatch.setattr(
        "milpa.publishing.enumerate_git_entries",
        lambda *a, **k: (evil_entries, {}),
    )

    with pytest.raises(MilpaError) as exc_info:
        build_publish_plan(source, target)

    assert exc_info.value.slug == PUBLISH_NON_UTF8_SYMLINK_TARGET


def test_build_publish_plan_still_accepts_safe_entries(tmp_path: Path) -> None:
    """Sanity/regression guard: a normal, safe repo tree still builds a plan
    successfully after the H1/M5 validation was wired in."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()

    plan = build_publish_plan(source, target)

    assert plan.content_hash == compute_content_hash(repo)


# ---------------------------------------------------------------------------
# CR-B1 — build_publish_plan(entries=...): accept a pre-enumerated entries
# list to avoid a second enumeration when a caller (cmd_publish) already
# paid the enumeration cost. Default entries=None re-enumerates exactly as
# before (SSOT fix: this is the ONE plan-builder both build_publish_plan's
# own callers and cmd_publish now share).
# ---------------------------------------------------------------------------


def test_build_publish_plan_accepts_pre_enumerated_entries_and_skips_re_enumeration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When entries= is supplied, build_publish_plan must use those entries
    directly and never call enumerate_git_entries itself -- proven by making
    milpa.publishing.enumerate_git_entries raise if called at all."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()

    preenumerated, _ = enumerate_git_entries(repo, commit, submodule_fetch=None)

    def _must_not_be_called(*args, **kwargs):
        raise AssertionError(
            "build_publish_plan() must not re-enumerate when entries= is given"
        )

    monkeypatch.setattr("milpa.publishing.enumerate_git_entries", _must_not_be_called)

    plan = build_publish_plan(source, target, entries=preenumerated)

    assert plan.content_hash == compute_dag_identity(preenumerated)


def test_build_publish_plan_entries_still_validated_via_check_entries_safe(
    tmp_path: Path,
) -> None:
    """A pre-enumerated entries list handed to build_publish_plan is still
    run through _check_entries_safe -- a caller passing entries= doesn't
    bypass the H1/M5 path-containment guard."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()

    evil_entries = [MaterializedEntry("../evil.txt", MODE_REGULAR, b"pwn")]

    with pytest.raises(MilpaError) as exc_info:
        build_publish_plan(source, target, entries=evil_entries)

    assert exc_info.value.slug == PUBLISH_UNSAFE_PATH


def test_build_publish_plan_default_entries_none_still_re_enumerates(
    tmp_path: Path,
) -> None:
    """Backward-compat sanity: the default entries=None still re-derives
    entries exactly as before -- unchanged happy-path behavior for every
    existing caller that doesn't pass entries=."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()

    plan = build_publish_plan(source, target)

    assert plan.content_hash == compute_content_hash(repo)


# ---------------------------------------------------------------------------
# L2 — pack_source: unsupported mode_byte raises a coded MilpaError, not
# a bare NotImplementedError
# ---------------------------------------------------------------------------


def test_pack_source_unsupported_mode_byte_raises_coded_milpa_internal() -> None:
    """An entry with a mode_byte other than MODE_REGULAR/MODE_EXECUTABLE/
    MODE_SYMLINK must raise MilpaError(MILPA_INTERNAL, ...), not a bare
    NotImplementedError -- pack_source's only non-MilpaError raise before
    this fix."""
    bogus_mode_byte = 0xFF
    entries = [MaterializedEntry("weird", bogus_mode_byte, b"???")]

    with pytest.raises(MilpaError) as exc_info:
        pack_source(entries)

    assert exc_info.value.slug == MILPA_INTERNAL
    assert not isinstance(exc_info.value, NotImplementedError)


# ---------------------------------------------------------------------------
# M3-infra — execute(plan, entries=..., push=..., sign=...): the seam to skip
# re-enumeration when a caller already holds a prior enumeration
# ---------------------------------------------------------------------------


def test_execute_accepts_pre_enumerated_entries_and_skips_re_enumeration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When entries= is supplied, execute() packs exactly those entries and
    never re-derives its own via enumerate_git_entries -- proven by making
    milpa.publishing.enumerate_git_entries raise if called at all."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)

    preenumerated, _ = enumerate_git_entries(repo, commit, submodule_fetch=None)
    expected_bytes = pack_source(preenumerated)

    def _must_not_be_called(*args, **kwargs):
        raise AssertionError(
            "execute() must not re-enumerate when entries= is given"
        )

    monkeypatch.setattr(
        "milpa.publishing.enumerate_git_entries", _must_not_be_called
    )

    captured: dict[str, bytes] = {}

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        captured["bytes"] = artifact_path.read_bytes()
        return "sha256:" + "9" * 64

    def fake_sign(oci_ref):
        pass

    fake_manifest_fetch = _make_fake_manifest_fetch(
        "sha256:" + hashlib.sha256(expected_bytes).hexdigest()
    )

    execute(
        plan,
        entries=preenumerated,
        push=fake_push,
        sign=fake_sign,
        manifest_fetch=fake_manifest_fetch,
    )

    assert captured["bytes"] == expected_bytes


def test_execute_default_entries_none_still_re_enumerates(tmp_path: Path) -> None:
    """Backward-compat sanity: the default entries=None still re-derives
    entries exactly as before -- unchanged happy-path behavior."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)

    entries, _ = enumerate_git_entries(repo, commit, submodule_fetch=None)
    expected_bytes = pack_source(entries)

    captured: dict[str, bytes] = {}

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        captured["bytes"] = artifact_path.read_bytes()
        return "sha256:" + "8" * 64

    def fake_sign(oci_ref):
        pass

    fake_manifest_fetch = _make_fake_manifest_fetch(
        "sha256:" + hashlib.sha256(expected_bytes).hexdigest()
    )

    execute(plan, push=fake_push, sign=fake_sign, manifest_fetch=fake_manifest_fetch)

    assert captured["bytes"] == expected_bytes


# ---------------------------------------------------------------------------
# R2-M1 — manifest_fetch is a REQUIRED keyword-only param of execute(), like
# push/sign (no fallback to a real make_oras_manifest_fetch() by omission)
# ---------------------------------------------------------------------------


def test_execute_requires_manifest_fetch_kwarg(tmp_path: Path) -> None:
    """Omitting manifest_fetch must raise TypeError (missing required
    keyword-only argument), exactly like omitting push or sign -- there is no
    internal fallback to a real make_oras_manifest_fetch() subprocess."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        return "sha256:" + "f" * 64

    def fake_sign(oci_ref):
        pass

    with pytest.raises(TypeError):
        execute(plan, push=fake_push, sign=fake_sign)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# M10 — execute() failure-path coverage: push raises / sign raises
# ---------------------------------------------------------------------------


def test_execute_push_failure_propagates_never_signs_and_cleans_up(
    tmp_path: Path,
) -> None:
    """If the injected push closure raises MilpaError, execute() must:
      - propagate that exact error (no PublishReceipt returned),
      - never call sign,
      - still clean up the temp artifact dir (the `with` block's cleanup
        runs even though push raised inside it).
    """
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)

    captured_path: dict[str, Path] = {}
    sign_calls: list[str] = []

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        assert artifact_path.exists()
        captured_path["path"] = artifact_path
        raise MilpaError(PUBLISH_OCI_PUSH_FAILED, "simulated push failure")

    def fake_sign(oci_ref):
        sign_calls.append(oci_ref)

    def fake_manifest_fetch(oci_ref):
        raise AssertionError(
            "manifest_fetch must never be called when push raises first"
        )

    with pytest.raises(MilpaError) as exc_info:
        execute(
            plan, push=fake_push, sign=fake_sign, manifest_fetch=fake_manifest_fetch
        )

    assert exc_info.value.slug == PUBLISH_OCI_PUSH_FAILED
    assert sign_calls == []
    assert not captured_path["path"].exists()
    assert not captured_path["path"].parent.exists()


def test_execute_sign_failure_propagates_with_temp_already_cleaned(
    tmp_path: Path,
) -> None:
    """If the injected sign closure raises MilpaError, execute() must
    propagate that exact error, and the temp artifact must already be gone
    by the time sign runs (sign is called AFTER the TemporaryDirectory's
    `with` block exits)."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)

    captured_path: dict[str, Path] = {}

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        captured_path["path"] = artifact_path
        return "sha256:" + "f" * 64

    def fake_sign(oci_ref):
        # The temp artifact must already be gone by the time sign() runs.
        assert not captured_path["path"].exists()
        raise MilpaError(PUBLISH_COSIGN_FAILED, "simulated sign failure")

    fake_manifest_fetch = _make_fake_manifest_fetch(_local_artifact_digest(repo, commit))

    with pytest.raises(MilpaError) as exc_info:
        execute(plan, push=fake_push, sign=fake_sign, manifest_fetch=fake_manifest_fetch)

    assert exc_info.value.slug == PUBLISH_COSIGN_FAILED
    assert not captured_path["path"].exists()
    assert not captured_path["path"].parent.exists()


# ---------------------------------------------------------------------------
# M1 — execute() verifies the manifest layer digest before signing
# ---------------------------------------------------------------------------


def test_execute_happy_path_verifies_digest_and_signs(tmp_path: Path) -> None:
    """When manifest_fetch returns a manifest whose layer digest matches the
    local sha256 of the packed bytes, execute() signs and returns normally."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)

    sign_calls: list[str] = []

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        return "sha256:" + "1" * 64

    def fake_sign(oci_ref):
        sign_calls.append(oci_ref)

    fake_manifest_fetch = _make_fake_manifest_fetch(_local_artifact_digest(repo, commit))

    receipt = execute(plan, push=fake_push, sign=fake_sign, manifest_fetch=fake_manifest_fetch)

    assert len(sign_calls) == 1
    assert len(fake_manifest_fetch.calls) == 1
    assert fake_manifest_fetch.calls[0] == receipt.oci_ref


def test_execute_digest_mismatch_raises_and_never_signs(tmp_path: Path) -> None:
    """When the fetched manifest's layer digest does NOT match the local
    sha256 of the packed bytes, execute() raises PUBLISH-DIGEST-MISMATCH and
    never calls sign — cosign must never attest to bytes that disagree with
    what was just packed."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)

    sign_calls: list[str] = []

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        return "sha256:" + "2" * 64

    def fake_sign(oci_ref):
        sign_calls.append(oci_ref)

    wrong_digest = "sha256:" + "0" * 64
    fake_manifest_fetch = _make_fake_manifest_fetch(wrong_digest)

    with pytest.raises(MilpaError) as exc_info:
        execute(plan, push=fake_push, sign=fake_sign, manifest_fetch=fake_manifest_fetch)

    assert exc_info.value.slug == PUBLISH_DIGEST_MISMATCH
    assert sign_calls == []


@pytest.mark.parametrize(
    "manifest",
    [
        {},
        {"layers": []},
        {"layers": "not-a-list"},
        {"layers": [{}]},
        {"layers": [{"digest": 12345}]},
        {"layers": [{"digest": ""}]},
    ],
    ids=[
        "no-layers-key",
        "empty-layers",
        "layers-not-a-list",
        "first-layer-no-digest",
        "digest-not-a-string",
        "digest-empty-string",
    ],
)
def test_execute_malformed_manifest_raises_manifest_fetch_failed(
    tmp_path: Path, manifest: dict
) -> None:
    """A manifest that is missing/empty/malformed-shaped raises
    PUBLISH-MANIFEST-FETCH-FAILED rather than a bare KeyError/IndexError/
    TypeError, and sign() is never called."""
    repo, commit = _make_local_git_repo(tmp_path)
    source = PublishSource(repo=repo, commit=commit)
    target = _make_target()
    plan = build_publish_plan(source, target)

    sign_calls: list[str] = []

    def fake_push(artifact_path, registry_ref, artifact_type, layer_media_type):
        return "sha256:" + "3" * 64

    def fake_sign(oci_ref):
        sign_calls.append(oci_ref)

    def fake_manifest_fetch(oci_ref):
        return manifest

    with pytest.raises(MilpaError) as exc_info:
        execute(plan, push=fake_push, sign=fake_sign, manifest_fetch=fake_manifest_fetch)

    assert exc_info.value.slug == PUBLISH_MANIFEST_FETCH_FAILED
    assert sign_calls == []


def test_make_oras_manifest_fetch_validates_oci_ref_before_subprocess() -> None:
    """An oci_ref that `validate_oci_field` rejects (leading '-') raises
    deterministically BEFORE any subprocess is spawned — proven by the fact
    that this test passes with no real `oras` binary required regardless of
    whether one is on PATH. Mirrors the push/sign validation-precedes-
    subprocess tests above."""
    manifest_fetch = make_oras_manifest_fetch()

    with pytest.raises(MilpaError) as exc_info:
        manifest_fetch("-rf")

    assert exc_info.value.slug == TNG_UNSAFE_OCI_FIELD
