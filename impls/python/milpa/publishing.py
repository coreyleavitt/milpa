"""Author-side publishing — pure plan/receipt data model.

RFC ``docs/rfc-distribution-and-publishing.handoff.md`` (Phase 3, slice S2).

This module is the author-side counterpart to the consumer-side
``milpa.fetchers.oci`` module: where ``fetchers/oci.py`` pulls a published
artifact and raises ``FETCH-OCI-*`` errors, this module (eventually) packs and
pushes one, raising its own ``PUBLISH-*`` error domain. It is intentionally
kept as ONE deep module (mirroring how ``fetchers/oci.py`` bundles descriptor +
receipt + fetcher + closure-factory) — the types are not to be split out.

This slice (S2) lays down only the pure core:

* ``PublishTarget`` / ``PublishSource`` — small typed param objects, mirroring
  the ``ResolveParams``/``MilpaEnv`` param-object cut in ``milpa/context.py``.
* ``build_publish_plan`` — PURE: resolves the git tree at a commit ONCE via
  ``enumerate_git_entries`` (the object-store seam, NOT the working-directory
  walk — see the RFC's "Publish source = the git tree at HEAD" decision) and
  computes the content identity via ``compute_dag_identity``. No network, no
  subprocess beyond the git object-store reads already performed by
  ``enumerate_git_entries``, no arbitrary code execution.
* ``PublishPlan`` — carries the source handle + precomputed ``content_hash`` +
  target metadata ONLY. Deliberately excludes the materialized entries and any
  push digest (a plan holding raw bytes for hundreds of files would be a
  ``--dry-run --output`` JSON-serialization footgun; a later ``execute()``
  re-derives entries cheaply since materialization is ``ls-tree``/``cat-file``,
  not an ``os.walk``). The digest is a product of the push, which doesn't
  exist yet in this slice.
* ``PublishReceipt`` — the eventual output of ``execute()`` (not constructed by
  anything yet in this slice). ``oci_ref`` is meant to be DERIVED via
  ``OciProvenance(registry, repository, digest).reference`` — never a
  hand-rolled f-string. ``layer_digest`` mirrors the pull-side
  ``OciReceipt.layer_digest`` naming (``milpa/fetchers/oci.py``) so the two
  receipts stay consistent.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from milpa.dag_identity import (
    MODE_EXECUTABLE,
    MODE_REGULAR,
    MODE_SYMLINK,
    MaterializedEntry,
    compute_dag_identity,
)
from milpa.errors import (
    MAN_NO_MANIFEST,
    MILPA_INTERNAL,
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
    MilpaError,
)
from milpa.fetchers.git import enumerate_git_entries, parse_ls_tree_z
from milpa.fetchers.oci import OciProvenance, validate_oci_field
from milpa.fetchers.safe_extract import _normalize_lexical
from milpa.manifest import parse_manifest
from milpa.registry import _RE_SHA256_DIGEST


# ---------------------------------------------------------------------------
# Typed param objects (mirrors the ResolveParams/MilpaEnv cut in context.py)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PublishTarget:
    """Where a publish pushes to — registry-agnostic destination metadata.

    Fields
    ------
    registry:
        OCI registry hostname (e.g. ``"ghcr.io"``).
    repository:
        OCI repository path (e.g. ``"coreyleavitt/z3"``).
    tag:
        The OCI tag to push under (e.g. a version string).
    artifact_type:
        The OCI artifact-type media type (milpa-owned, e.g.
        ``"application/vnd.milpa.source.v1"``).
    layer_media_type:
        The media type of the packed source layer (e.g.
        ``"application/vnd.milpa.source.v1.tar+gzip"``).
    """

    registry: str
    repository: str
    tag: str
    artifact_type: str
    layer_media_type: str


@dataclass(frozen=True)
class PublishSource:
    """The git tree being published — repo path + resolved commit.

    Constructed by ``resolve_publish_source`` (S3a), which performs the
    git-repo preflight checks (HEAD resolution, version<->tag binding,
    submodule refusal) before handing a validated instance to
    ``build_publish_plan``.

    Fields
    ------
    repo:
        Path to the git repository (its ``.git`` object store is read from —
        NOT the working directory).
    commit:
        Commit SHA (or any git-resolvable ref) to enumerate the tree at.
    """

    repo: Path
    commit: str


def resolve_publish_source(
    repo: Path, version: str, *, allow_untagged: bool = False
) -> PublishSource:
    """Resolve and preflight-guard a publish source — the git-tree front door.

    Thin and deep: does the git-subprocess preflight and returns the typed
    ``PublishSource``; it does NOT enumerate entries or compute the content
    hash (that's ``build_publish_plan``'s job, S2).

    Guards (in order):

    1. **HEAD must resolve.** ``repo`` must be a git work tree whose HEAD
       resolves to a commit — otherwise ``PUBLISH-NOT-GIT-REPO`` (covers both
       "not a git repo at all" and "git repo with zero commits").
    2. **Version<->HEAD tag binding.** A tag named exactly ``<version>`` or
       ``v<version>`` must resolve to the same commit as HEAD, or
       ``PUBLISH-VERSION-TAG-MISMATCH`` is raised. Skipped entirely when
       ``allow_untagged=True`` (the escape hatch).
    3. **No submodules.** If HEAD's tree contains any gitlink (mode 160000),
       raise ``PUBLISH-SUBMODULE-UNSUPPORTED`` — milpa publish does not
       vendor submodules (see the RFC's D-git rationale: gitlinks vanish
       from ``enumerate_git_entries`` with ``submodule_fetch=None``, which
       would silently ship an incomplete artifact). If the ``git ls-tree``
       subprocess itself fails (a corrupt/incomplete object store, not an
       absent repo — ``commit`` already resolved in guard 1), raise
       ``PUBLISH-GIT-TREE-READ-FAILED`` instead (M9 — distinct failure class
       from guard 1's "HEAD does not resolve at all").

    Args:
        repo:           Path to the git repository to publish from.
        version:        The version being published (checked against tags).
        allow_untagged: Skip the version<->tag binding guard (default False).

    Returns:
        A validated ``PublishSource(repo=repo, commit=<40-hex HEAD sha>)``.

    Raises:
        MilpaError(PUBLISH_NOT_GIT_REPO)
        MilpaError(PUBLISH_VERSION_TAG_MISMATCH)
        MilpaError(PUBLISH_SUBMODULE_UNSUPPORTED)
        MilpaError(PUBLISH_GIT_TREE_READ_FAILED)
    """
    commit = _resolve_head_commit(repo)

    if not allow_untagged:
        _check_version_tag_binding(repo, version, commit)

    _refuse_submodules(repo, commit)

    return PublishSource(repo=repo, commit=commit)


def _resolve_head_commit(repo: Path) -> str:
    """Resolve HEAD to its full 40-hex commit SHA, or raise PUBLISH-NOT-GIT-REPO.

    Covers both failure modes with one subprocess call: a path that is not a
    git work tree, and a git work tree with no commits yet (HEAD unborn).
    """
    result = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet",
         "--end-of-options", "HEAD"],
        capture_output=True,
        text=True,
    )
    commit = result.stdout.strip()
    if result.returncode != 0 or not commit:
        raise MilpaError(
            PUBLISH_NOT_GIT_REPO,
            f"{repo} is not a git repository with a resolvable HEAD: "
            f"{result.stderr.strip() or '(HEAD does not resolve)'}",
            repo=str(repo),
        )
    return commit


def _check_version_tag_binding(repo: Path, version: str, commit: str) -> None:
    """Raise PUBLISH-VERSION-TAG-MISMATCH unless `<version>` or `v<version>`
    tags HEAD.
    """
    for tag_name in (version, f"v{version}"):
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet",
             "--end-of-options", f"{tag_name}^{{commit}}"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip() == commit:
            return

    raise MilpaError(
        PUBLISH_VERSION_TAG_MISMATCH,
        f"no tag {version!r} or {'v' + version!r} points at HEAD ({commit}); "
        f"pass allow_untagged=True to skip this guard",
        repo=str(repo),
        version=version,
        commit=commit,
    )


def _refuse_submodules(repo: Path, commit: str) -> None:
    """Raise PUBLISH-SUBMODULE-UNSUPPORTED if HEAD's tree contains a gitlink.

    Runs its own lightweight ``git ls-tree`` (listing only, no ``cat-file`` —
    this guard runs before ``build_publish_plan``'s heavier full enumeration
    and shouldn't pay for reading every blob just to check for gitlinks), but
    parses the NUL-delimited output via ``parse_ls_tree_z`` (SSOT, shared with
    ``enumerate_git_entries`` in ``fetchers/git.py``) rather than a second,
    independently-maintained copy of the parse (M2 — SSOT discipline).

    M9: a subprocess FAILURE here (this ``commit`` was already validated to
    resolve by ``_resolve_head_commit``) is a distinct failure class from "not
    a git repo" — a corrupt/incomplete object store, not an absent repo/HEAD
    — so it raises ``PUBLISH-GIT-TREE-READ-FAILED`` rather than reusing
    ``PUBLISH-NOT-GIT-REPO`` (which stays scoped to the genuine
    HEAD-unresolvable case in ``_resolve_head_commit``).
    """
    result = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "-z", "--end-of-options", commit],
        capture_output=True,
    )
    if result.returncode != 0:
        raise MilpaError(
            PUBLISH_GIT_TREE_READ_FAILED,
            f"git ls-tree failed for commit {commit!r} in {repo}: "
            f"{result.stderr.decode(errors='replace').strip()}",
            repo=str(repo),
            commit=commit,
        )

    for mode, _obj_type, _sha, path in parse_ls_tree_z(result.stdout):
        if mode == "160000":
            raise MilpaError(
                PUBLISH_SUBMODULE_UNSUPPORTED,
                f"{repo} contains a submodule at {path!r}; milpa publish does "
                f"not vendor submodules (would silently ship an incomplete "
                f"artifact — see enumerate_git_entries submodule_fetch=None)",
                repo=str(repo),
                path=path,
            )


def resolve_publish_name(source: PublishSource) -> str:
    """M4: derive a package's ``--name`` from ``milpa.kdl`` in the HEAD tree,
    NOT the working directory.

    Publish's whole-module invariant is "the source of truth is the git HEAD
    tree" (``resolve_publish_source``/``build_publish_plan`` both read the
    object store, never the working directory). Deriving ``--name`` via
    ``load_or_discover_manifest`` broke that invariant: a locally-edited or
    uncommitted ``milpa.kdl`` in the working tree would put a name in the
    receipt that disagrees with what was actually published.

    Uses ``git show <commit>:milpa.kdl`` (reads the object store directly,
    like ``resolve_publish_source``'s own guards) + the SAME string parser
    (``parse_manifest``) ``load_or_discover_manifest`` uses for the working-
    tree path — no second manifest-parsing implementation.

    Scope note: unlike ``load_or_discover_manifest``, this has no ``.nimble``
    fallback — a HEAD tree with no ``milpa.kdl`` at the project root raises
    ``MAN-NO-MANIFEST`` (pass ``--name`` explicitly instead). No workspace-
    member resolution either; publish itself has no workspace-member concept
    yet (see the RFC handoff).

    Args:
        source: The already-resolved ``PublishSource`` (``repo`` + ``commit``)
            — i.e. whatever ``resolve_publish_source`` returned.

    Raises:
        MilpaError(MAN_NO_MANIFEST): HEAD's tree has no ``milpa.kdl`` at the
            repo root.
    """
    result = subprocess.run(
        ["git", "-C", str(source.repo), "show", f"{source.commit}:milpa.kdl"],
        capture_output=True,
    )
    if result.returncode != 0:
        raise MilpaError(
            MAN_NO_MANIFEST,
            f"no milpa.kdl found at HEAD ({source.commit}) in {source.repo}; "
            f"cannot auto-derive --name from the published tree (pass --name "
            f"explicitly, or commit a milpa.kdl at the repo root): "
            f"{result.stderr.decode(errors='replace').strip()}",
            repo=str(source.repo),
            commit=source.commit,
        )
    text = result.stdout.decode("utf-8")
    return parse_manifest(text).name


# ---------------------------------------------------------------------------
# PublishPlan + build_publish_plan (PURE)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PublishPlan:
    """A pure, side-effect-free description of what a publish would do.

    Deliberately carries NEITHER the materialized entries NOR any push
    digest — only the source handle, the precomputed content identity, and
    the target metadata. See the module docstring for why.
    """

    source: PublishSource
    content_hash: str
    target: PublishTarget


def _entries_or_derive(
    source: PublishSource, entries: list[MaterializedEntry] | None
) -> list[MaterializedEntry]:
    """R2-L2: SSOT for the "use ``entries`` if given, else derive from
    ``source`` via ``enumerate_git_entries``" pattern shared by
    ``build_publish_plan`` and ``execute`` — the object-store seam, not the
    working directory; ``submodule_fetch=None`` means gitlinks contribute
    nothing (matching the "no recursion" default; submodules are refused
    earlier, by ``resolve_publish_source``'s S3a preflight)."""
    if entries is not None:
        return entries
    derived, _submodule_shas = enumerate_git_entries(
        source.repo, source.commit, submodule_fetch=None
    )
    return derived


def build_publish_plan(
    source: PublishSource,
    target: PublishTarget,
    *,
    entries: list[MaterializedEntry] | None = None,
) -> PublishPlan:
    """Build a ``PublishPlan`` — PURE (no network, no subprocess, no push).

    Resolves ``source``'s git tree ONCE via ``enumerate_git_entries`` (the
    object-store seam — reads committed blobs directly from ``.git``, not the
    working directory; untracked/uncommitted cruft is excluded for free) and
    folds it into the canonical content identity via ``compute_dag_identity``.
    Submodules are refused elsewhere (S3a); here ``submodule_fetch=None`` means
    gitlinks contribute nothing (matching the "no recursion" default).

    CR-B1: by default (``entries=None``) entries are derived here via
    ``enumerate_git_entries``, exactly as before. A caller that has ALREADY
    paid the enumeration cost (e.g. ``cmd_publish``, which needs entries for
    both the plan's identity AND the dry-run stats / real-run pack step) MAY
    pass a pre-enumerated ``entries`` list to skip this re-derivation
    entirely — this is the ONE plan-builder both paths share (SSOT: no second
    copy of "validate entries -> compute_dag_identity -> construct
    PublishPlan" living in the CLI).

    Every entry is validated via ``_check_entries_safe`` (H1/M5) BEFORE the
    identity is computed — a crafted or corrupted git tree containing a
    ``..``/absolute-path escape or a non-UTF-8 symlink target is refused here,
    at plan-build time, so a ``--dry-run`` catches it too (not only a real
    ``pack_source`` call). This applies whether ``entries`` was re-derived
    here or supplied by the caller.
    """
    entries = _entries_or_derive(source, entries)
    _check_entries_safe(entries)
    content_hash = compute_dag_identity(entries)
    return PublishPlan(source=source, content_hash=content_hash, target=target)


# ---------------------------------------------------------------------------
# _check_entries_safe (H1/M5) — producer-side path-containment validation
# ---------------------------------------------------------------------------

#: Synthetic root used to run the SAME lexical containment logic the read
#: side already enforces (``fetchers/git.py._check_path_containment``,
#: ``fetchers/safe_extract.py``'s zip-slip/symlink-escape checks — both built
#: on ``_normalize_lexical``, the SSOT helper) against a ``PublishPlan``,
#: which has no real destination directory (it is pure/bytes-free by
#: design — see ``PublishPlan``'s docstring). Never touched on disk.
_SYNTHETIC_ROOT = Path("/__milpa_publish_root__")


def _check_entries_safe(entries: list[MaterializedEntry]) -> None:
    """Validate every materialized entry is safe to pack into a published
    artifact.

    Called at BOTH plan-build time (``build_publish_plan``, so ``--dry-run``
    catches it) and pack time (``pack_source``, as defense-in-depth for any
    caller that hands entries to the packer directly).

    Raises:
        MilpaError(PUBLISH_UNSAFE_PATH): ``entry.relpath`` is absolute, has a
            ``..`` path component, or (for ``MODE_SYMLINK``) the entry's
            decoded target is absolute or escapes the tree root.
        MilpaError(PUBLISH_NON_UTF8_SYMLINK_TARGET): a ``MODE_SYMLINK``
            entry's content is not valid UTF-8 (git allows arbitrary symlink-
            target bytes; a published artifact cannot represent them safely —
            the tar packer decodes them as UTF-8 for ``TarInfo.linkname``).
    """
    for entry in entries:
        _check_relpath_safe(entry.relpath)

        if entry.mode_byte == MODE_SYMLINK:
            try:
                link_target = entry.content.decode("utf-8")
            except UnicodeDecodeError:
                raise MilpaError(
                    PUBLISH_NON_UTF8_SYMLINK_TARGET,
                    f"symlink {entry.relpath!r} has a non-UTF-8 target; cannot "
                    f"safely pack it into a published artifact",
                    entry=entry.relpath,
                )
            _check_symlink_target_safe(entry.relpath, link_target)


def _check_relpath_safe(relpath: str) -> None:
    """Raise PUBLISH-UNSAFE-PATH if ``relpath`` is absolute or escapes the
    (synthetic) tree root via ``..``."""
    if relpath.startswith("/"):
        raise MilpaError(
            PUBLISH_UNSAFE_PATH,
            f"entry {relpath!r} is an absolute path; refusing to pack an "
            f"unsafe artifact",
            entry=relpath,
        )
    candidate = _normalize_lexical(_SYNTHETIC_ROOT / relpath)
    under_root = (
        str(candidate).startswith(str(_SYNTHETIC_ROOT) + os.sep)
        or candidate == _SYNTHETIC_ROOT
    )
    if not under_root:
        raise MilpaError(
            PUBLISH_UNSAFE_PATH,
            f"entry {relpath!r} escapes the tree root via '..'; refusing to "
            f"pack an unsafe artifact",
            entry=relpath,
        )


def _check_symlink_target_safe(relpath: str, link_target: str) -> None:
    """Raise PUBLISH-UNSAFE-PATH if a symlink's decoded target is absolute or
    resolves outside the (synthetic) tree root."""
    if link_target.startswith("/"):
        raise MilpaError(
            PUBLISH_UNSAFE_PATH,
            f"symlink {relpath!r} -> {link_target!r} has an absolute target; "
            f"refusing to pack an unsafe artifact",
            entry=relpath,
            link_target=link_target,
        )
    parent = (_SYNTHETIC_ROOT / relpath).parent
    resolved = _normalize_lexical(parent / link_target)
    under_root = (
        str(resolved).startswith(str(_SYNTHETIC_ROOT) + os.sep)
        or resolved == _SYNTHETIC_ROOT
    )
    if not under_root:
        raise MilpaError(
            PUBLISH_UNSAFE_PATH,
            f"symlink {relpath!r} -> {link_target!r} resolves outside the "
            f"tree root; refusing to pack an unsafe artifact",
            entry=relpath,
            link_target=link_target,
        )


# ---------------------------------------------------------------------------
# PublishReceipt (shape only — nothing constructs one yet in this slice)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PublishReceipt:
    """The output of a (future) ``execute(plan, push, sign)``.

    Fields
    ------
    content_hash:
        The plan's precomputed identity (``dag-sha256:<hex>``) — the subject
        bound into the signed attestation downstream.
    oci_ref:
        The full OCI reference the artifact was pushed to. DERIVED via
        ``OciProvenance(registry, repository, digest).reference`` — never a
        hand-rolled f-string (single-source-of-truth for ref composition).
    layer_digest:
        The OCI content digest of the pushed layer (``sha256:<hex>``). Named
        to mirror the pull-side ``OciReceipt.layer_digest``
        (``milpa/fetchers/oci.py``) so the two receipts are consistent.
    artifact_type:
        The OCI artifact-type media type the artifact was pushed as.
    """

    content_hash: str
    oci_ref: str
    layer_digest: str
    artifact_type: str


# ---------------------------------------------------------------------------
# pack_source (S1a) — canonical packer skeleton, regular files only
# ---------------------------------------------------------------------------


#: mode_byte -> on-disk tar mode for the two regular-file-shaped variants
#: (§1.7.4 disk contract: any POSIX execute bit collapses to 0o755, mirroring
#: ``safe_extract._regular_file_mode`` and ``identity.enumerate_local_entries``'
#: ``st_mode & 0o111`` check on the read side).
_REGULAR_FILE_TAR_MODE: dict[int, int] = {
    MODE_REGULAR: 0o644,
    MODE_EXECUTABLE: 0o755,
}


def _normalized_tarinfo(entry: MaterializedEntry) -> tarfile.TarInfo:
    """Build a ``TarInfo`` for ``entry`` with mtime/uid/gid/uname/gname zeroed.

    Shared by every ``_add_entry`` branch so the normalization (S1a's
    determinism contract) is written once, not duplicated per mode.
    """
    info = tarfile.TarInfo(name=entry.relpath)
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _add_entry(tf: tarfile.TarFile, entry: MaterializedEntry) -> None:
    """Add one ``MaterializedEntry`` to an open ``tarfile.TarFile`` as a
    normalized (mtime/uid/gid/uname/gname all zeroed) member.

    Dispatches on ``entry.mode_byte``. ``MODE_REGULAR`` (S1a) and
    ``MODE_EXECUTABLE`` (S1b) are both packed as a plain tar regular-file
    member, differing only in mode (``0o644`` vs ``0o755``); ``MODE_SYMLINK``
    (S1c) is packed as a ``tarfile.SYMTYPE`` member whose ``linkname`` is the
    entry's ``content`` decoded as UTF-8 (matching ``enumerate_local_entries``'
    ``target.encode("utf-8")`` on the read side — see ``identity.py``). A
    symlink member carries no data section (POSIX ignores symlink permission
    bits, and the tar format stores the target in ``linkname``, not the file
    body) — ``size`` stays 0 and no ``mode`` chmod is applied.
    """
    if entry.mode_byte in _REGULAR_FILE_TAR_MODE:
        info = _normalized_tarinfo(entry)
        info.type = tarfile.REGTYPE
        info.mode = _REGULAR_FILE_TAR_MODE[entry.mode_byte]
        info.size = len(entry.content)
        tf.addfile(info, io.BytesIO(entry.content))
    elif entry.mode_byte == MODE_SYMLINK:
        info = _normalized_tarinfo(entry)
        info.type = tarfile.SYMTYPE
        info.linkname = entry.content.decode("utf-8")
        info.size = 0
        tf.addfile(info)
    else:
        raise MilpaError(
            MILPA_INTERNAL,
            f"pack_source: mode_byte {entry.mode_byte:#x} for {entry.relpath!r} "
            f"is not supported (MODE_REGULAR/MODE_EXECUTABLE/MODE_SYMLINK are "
            f"the only materializable modes; hardlinks are out of scope — "
            f"MaterializedEntry has no inode concept); this is an internal "
            f"milpa bug — please report it",
            relpath=entry.relpath,
            mode_byte=entry.mode_byte,
        )


def pack_source(entries: list[MaterializedEntry]) -> bytes:
    """Pack materialized source entries into a deterministic ``.tar.gz`` (bytes).

    PURE: no filesystem I/O, no network. Given the same ``entries`` (in any
    input order), always returns byte-identical output —

      1. Entries are canonically sorted by ``relpath`` before packing (stable
         member order across calls/processes, independent of input order or
         however the caller enumerated them).
      2. The tar layer is built uncompressed into memory (``tarfile`` GNU
         format, so >100-char paths get a GNU longname extension header), then
         compressed separately with ``gzip.GzipFile(mtime=0)`` — NOT
         ``tarfile.open(mode="w:gz")``, which stamps a nondeterministic gzip
         mtime with no override. No ``filename=`` is passed to ``GzipFile``
         (that would embed a nondeterministic FNAME header).
      3. Every member's ``mtime``/``uid``/``gid``/``uname``/``gname`` are
         zeroed; regular files get mode ``0o644``.

    ``MODE_REGULAR`` (S1a) and ``MODE_EXECUTABLE`` (S1b) entries are packed as
    normalized regular-file tar members; ``MODE_SYMLINK`` (S1c) entries are
    packed as normalized symlink tar members — see ``_add_entry``.

    Every entry is validated via ``_check_entries_safe`` (H1/M5) before
    packing — defense-in-depth for any caller that hands entries to the
    packer directly rather than going through ``build_publish_plan`` (which
    already validates at plan-build time).
    """
    _check_entries_safe(entries)

    tar_buf = io.BytesIO()
    # H2: pin encoding="utf-8" explicitly. Without it, tarfile.open falls back
    # to sys.getfilesystemencoding() (the process locale's fs-encoding), which
    # raises a bare UnicodeEncodeError for a non-ASCII relpath under an
    # ascii-locale CI. Mirrors identity.py/git.py's utf-8-everywhere discipline.
    with tarfile.open(
        fileobj=tar_buf, mode="w", format=tarfile.GNU_FORMAT, encoding="utf-8"
    ) as tf:
        for entry in sorted(entries, key=lambda e: e.relpath):
            _add_entry(tf, entry)
    tar_bytes = tar_buf.getvalue()

    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    return gz_buf.getvalue()


# ---------------------------------------------------------------------------
# parse_oras_digest_json + make_oras_push (S3b) — producer dual of make_oras_pull
# ---------------------------------------------------------------------------


def parse_oras_digest_json(stdout: str) -> str:
    """Extract the pushed manifest digest from ``oras push --format json`` stdout.

    PURE — no I/O, no subprocess. ``oras push --format json`` emits a single
    JSON object describing the pushed root manifest descriptor, with a
    top-level ``"digest"`` field (``"sha256:<64-hex>"``). As a fallback (some
    ``oras`` invocations/versions surface the digest only embedded in a
    top-level ``"reference"`` field, ``"registry/repository@sha256:<64-hex>"``),
    the digest suffix of ``"reference"`` is also accepted. ``"digest"`` wins
    when both are present.

    Reuses ``_RE_SHA256_DIGEST`` (``milpa.registry``) as the single source of
    truth for the digest format — the same regex ``validate_oci_digest``
    checks on the consumer (pull) side; no second digest parser is invented
    here.

    Raises:
        MilpaError(PUBLISH_NO_DIGEST_IN_OUTPUT): ``stdout`` is empty, not
            valid JSON, not a JSON object, or neither ``"digest"`` nor
            ``"reference"`` yields a value matching ``sha256:<64 lowercase hex>``.
    """
    stripped = stdout.strip()
    if not stripped:
        raise MilpaError(
            PUBLISH_NO_DIGEST_IN_OUTPUT,
            "oras push produced no output; expected a --format json object "
            "with a digest",
            stdout=stdout,
        )

    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise MilpaError(
            PUBLISH_NO_DIGEST_IN_OUTPUT,
            f"oras push output is not valid JSON: {exc}",
            stdout=stdout,
        ) from exc

    if not isinstance(data, dict):
        raise MilpaError(
            PUBLISH_NO_DIGEST_IN_OUTPUT,
            f"oras push --format json output was not a JSON object: {stdout!r}",
            stdout=stdout,
        )

    digest = data.get("digest")
    if isinstance(digest, str) and _RE_SHA256_DIGEST.fullmatch(digest):
        return digest

    reference = data.get("reference")
    if isinstance(reference, str) and "@" in reference:
        candidate = reference.rsplit("@", 1)[-1]
        if _RE_SHA256_DIGEST.fullmatch(candidate):
            return candidate

    raise MilpaError(
        PUBLISH_NO_DIGEST_IN_OUTPUT,
        f"no sha256:<64-hex> digest found in oras push output "
        f"(checked 'digest' and 'reference' fields): {stdout!r}",
        stdout=stdout,
    )


#: Injected OCI push transport: given a local artifact path, a full
#: ``registry/repository:tag`` (or ``@digest``) reference, an OCI
#: artifact-type media type, and a layer media type, pushes the artifact and
#: returns the resulting manifest digest (``sha256:<64-hex>``), or raises
#: ``MilpaError(PUBLISH_OCI_PUSH_FAILED, …)``. Producer dual of ``OciPull``
#: (``milpa.fetchers.oci``).
OrasPush = Callable[[Path, str, str, str], str]


def make_oras_push() -> OrasPush:
    """Return a production ``OrasPush`` backed by ``oras push``.

    Mirrors ``make_oras_pull``'s (``milpa.fetchers.oci``) subprocess/error-
    wrapping style exactly, as the producer dual: this pushes rather than
    pulls, and raises the ``PUBLISH-*`` domain rather than ``FETCH-OCI-*``.

    Validation precedes the subprocess (registry-protocol.md §4 discipline):
    every user-supplied token (``registry_ref``, ``artifact_type``,
    ``layer_media_type``) is run through ``validate_oci_field`` BEFORE any
    subprocess is spawned, so a flag-injection attempt (a value starting with
    ``-``) never reaches ``oras`` argv and fails deterministically without
    needing the ``oras`` binary on ``PATH`` at all.

    **Accepted test gap** (mirrors ``make_oras_pull``, which has no argv
    test either): the production subprocess invocation itself is not
    unit-tested under milpa's no-mock house style — real coverage of the
    real ``oras`` binary is the N1/T1 E2E, not a unit test.
    """

    def _push(
        artifact_path: Path,
        registry_ref: str,
        artifact_type: str,
        layer_media_type: str,
    ) -> str:
        validate_oci_field("registry_ref", registry_ref)
        validate_oci_field("artifact_type", artifact_type)
        validate_oci_field("layer_media_type", layer_media_type)

        result = subprocess.run(
            [
                "oras", "push", registry_ref,
                "--artifact-type", artifact_type,
                "--format", "json",
                # oras rejects an absolute file path by default (it would
                # embed the path as the layer's title annotation). The
                # artifact is a milpa-owned temp file with an absolute path,
                # so disable that check — the layer bytes + digest are
                # unaffected.
                "--disable-path-validation",
                f"{artifact_path}:{layer_media_type}",
            ],
            capture_output=True,
        )
        if result.returncode != 0:
            detail = result.stderr.decode(errors="replace").strip()
            raise MilpaError(
                PUBLISH_OCI_PUSH_FAILED,
                f"oras push failed for {registry_ref!r}: {detail}",
                reference=registry_ref,
            )

        stdout = result.stdout.decode(errors="replace")
        return parse_oras_digest_json(stdout)

    return _push


# ---------------------------------------------------------------------------
# make_cosign_sign (S3c) — keyless signing closure, SIGN dual of make_oras_push
# ---------------------------------------------------------------------------


#: Injected keyless-signing transport: given the full ``oci_ref``
#: (``registry/repository@sha256:...``) of a just-pushed artifact, signs it
#: with cosign (keyless — ambient CI OIDC) and returns nothing; success is
#: "did not raise". Raises ``MilpaError(PUBLISH_COSIGN_FAILED, …)`` on
#: failure. The signature lives in the registry/Rekor, not in any milpa
#: type — ``PublishReceipt`` (S2) deliberately has no cosign field.
CosignSign = Callable[[str], None]


def make_cosign_sign() -> CosignSign:
    """Return a production ``CosignSign`` backed by ``cosign sign --yes``.

    Mirrors ``make_oras_push``'s subprocess/error-wrapping style exactly, as
    the SIGN dual of the PUSH closure: this signs the already-pushed OCI
    reference rather than pushing bytes, and raises ``PUBLISH-COSIGN-FAILED``
    rather than ``PUBLISH-OCI-PUSH-FAILED``.

    Validation precedes the subprocess (registry-protocol.md §4 discipline,
    same as ``make_oras_push``): ``oci_ref`` is run through
    ``validate_oci_field`` BEFORE any subprocess is spawned, so a
    flag-injection attempt (a value starting with ``-``) never reaches
    ``cosign`` argv and fails deterministically without needing the
    ``cosign`` binary on ``PATH`` at all.

    Keyless / Fulcio-OIDC: no key material is passed here — ``--yes``
    suppresses the interactive confirmation prompt, and the actual identity
    comes from the ambient CI OIDC token at E2E time (the same mechanism
    tianguis's cosign steps use).

    **Accepted test gap** (mirrors ``make_oras_pull``/``make_oras_push``,
    neither of which has an argv test): the production subprocess invocation
    itself is not unit-tested under milpa's no-mock house style — real
    coverage of the real ``cosign`` binary is the N1/T1 E2E, not a unit test.
    """

    def _sign(oci_ref: str) -> None:
        validate_oci_field("oci_ref", oci_ref)

        result = subprocess.run(
            ["cosign", "sign", "--yes", oci_ref],
            capture_output=True,
        )
        if result.returncode != 0:
            detail = result.stderr.decode(errors="replace").strip()
            raise MilpaError(
                PUBLISH_COSIGN_FAILED,
                f"cosign sign failed for {oci_ref!r}: {detail}",
                reference=oci_ref,
            )

    return _sign


# ---------------------------------------------------------------------------
# make_oras_manifest_fetch (M1) — verify-what-cosign-signs closure
# ---------------------------------------------------------------------------


#: Injected OCI manifest-fetch transport: given the full OCI reference of a
#: just-pushed artifact (``registry/repository@sha256:...`` or
#: ``registry/repository:tag``), fetches and JSON-parses its manifest,
#: returning it as a plain ``dict``. Raises
#: ``MilpaError(PUBLISH_MANIFEST_FETCH_FAILED, ...)`` on any failure to
#: retrieve or parse it. Used by ``execute`` (M1) to verify that the digest
#: about to be signed actually describes the bytes that were pushed — the
#: digest ``oras push`` reports is the OCI *manifest* digest, not
#: ``sha256(artifact_bytes)``, so this closure is the only way to look at
#: what the registry actually stored.
OrasManifestFetch = Callable[[str], dict]


def make_oras_manifest_fetch() -> OrasManifestFetch:
    """Return a production ``OrasManifestFetch`` backed by ``oras manifest fetch``.

    Mirrors ``make_oras_push``'s subprocess/error-wrapping style exactly:
    ``oci_ref`` is validated via ``validate_oci_field`` BEFORE any subprocess
    is spawned (registry-protocol.md §4 discipline), so a flag-injection
    attempt never reaches ``oras`` argv.

    **Accepted test gap** (mirrors ``make_oras_push``/``make_cosign_sign``):
    the production subprocess invocation itself is not unit-tested under
    milpa's no-mock house style — real coverage of the real ``oras`` binary
    is the N1/T1 E2E, not a unit test.
    """

    def _fetch(oci_ref: str) -> dict:
        validate_oci_field("oci_ref", oci_ref)

        result = subprocess.run(
            ["oras", "manifest", "fetch", oci_ref],
            capture_output=True,
        )
        if result.returncode != 0:
            detail = result.stderr.decode(errors="replace").strip()
            raise MilpaError(
                PUBLISH_MANIFEST_FETCH_FAILED,
                f"oras manifest fetch failed for {oci_ref!r}: {detail}",
                reference=oci_ref,
            )

        stdout = result.stdout.decode(errors="replace")
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise MilpaError(
                PUBLISH_MANIFEST_FETCH_FAILED,
                f"oras manifest fetch output is not valid JSON for {oci_ref!r}: {exc}",
                reference=oci_ref,
            ) from exc

        if not isinstance(data, dict):
            raise MilpaError(
                PUBLISH_MANIFEST_FETCH_FAILED,
                f"oras manifest fetch output for {oci_ref!r} was not a JSON object",
                reference=oci_ref,
            )
        return data

    return _fetch


def _extract_layer_digest(manifest: dict, oci_ref: str) -> str:
    """Extract the single layer's ``digest`` field from a fetched manifest.

    Guards defensively against a malformed/unexpected manifest shape (missing
    or empty ``"layers"``, a first layer with no usable ``"digest"``) — every
    failure mode raises ``PUBLISH-MANIFEST-FETCH-FAILED`` rather than a bare
    ``KeyError``/``IndexError``/``TypeError``.
    """
    layers = manifest.get("layers") if isinstance(manifest, dict) else None
    if not isinstance(layers, list) or not layers:
        raise MilpaError(
            PUBLISH_MANIFEST_FETCH_FAILED,
            f"manifest for {oci_ref!r} has no (or an empty) 'layers' array; "
            f"cannot verify the pushed digest",
            reference=oci_ref,
        )

    first_layer = layers[0]
    digest = first_layer.get("digest") if isinstance(first_layer, dict) else None
    if not isinstance(digest, str) or not digest:
        raise MilpaError(
            PUBLISH_MANIFEST_FETCH_FAILED,
            f"manifest for {oci_ref!r}'s first layer has no usable 'digest' field",
            reference=oci_ref,
        )
    return digest


# ---------------------------------------------------------------------------
# execute (S3d) — the impure orchestration seam: pack -> push -> sign -> receipt
# ---------------------------------------------------------------------------


def execute(
    plan: PublishPlan,
    *,
    push: OrasPush,
    sign: CosignSign,
    manifest_fetch: OrasManifestFetch,
    entries: list[MaterializedEntry] | None = None,
) -> PublishReceipt:
    """Execute ``plan``: pack the source tree, push it, verify it, sign it.

    The impure orchestration step — ``build_publish_plan`` stays pure by
    construction, and this is the one place I/O happens. ``push``/``sign``/
    ``manifest_fetch`` are REQUIRED injected closures (``make_oras_push``/
    ``make_cosign_sign``/``make_oras_manifest_fetch`` in production; fakes in
    tests) — none of the three has a default, so a caller can never
    accidentally fall through to a real subprocess by omission. So no real
    ``oras``/``cosign`` subprocess is exercised here.

    Steps:

    1. **Entries**: by default (``entries=None``) re-derive them from
       ``plan.source`` via ``enumerate_git_entries`` — the plan deliberately
       carries neither entries nor bytes (see ``PublishPlan``'s docstring), so
       this recomputes them from the git object store (cheap: ``ls-tree``/
       ``cat-file``, not an ``os.walk``). M3-infra: a caller that already paid
       the enumeration cost (e.g. the CLI, which needs entries for both the
       plan's identity AND the pack step) MAY pass a pre-enumerated ``entries``
       list to skip this re-derivation entirely — it is used as-is (still
       validated by ``pack_source``'s own ``_check_entries_safe`` call).
    2. **Pack** them with the canonical packer (``pack_source``) — the same
       packer proven byte-deterministic and round-trip-safe in S1a/b/c.
    3. **Write** the packed bytes to a throwaway temp file (``oras push`` needs
       a filesystem path) inside a ``tempfile.TemporaryDirectory`` — cleaned up
       unconditionally on the way out of the ``with`` block, even if ``push``
       raises.
    4. **Push** to the mutable ``registry/repository:tag`` reference built
       from ``plan.target`` (the tag form — there is no existing single-source
       helper for this composition, unlike the digest form below;
       ``make_oras_push`` validates every field via ``validate_oci_field``
       before any subprocess runs). Returns the manifest digest.
    5. **Derive** the immutable ``oci_ref`` (``registry/repository@digest``)
       via ``OciProvenance(...).reference`` — never a hand-rolled f-string,
       per the module docstring's single-source-of-truth rule.
    6. **Verify** (M1) — before signing anything: the digest ``push`` returned
       is the OCI *manifest* digest (``sha256(manifest_json)``), which does
       NOT by itself prove the registry stored the bytes just packed. Fetch
       the manifest back via ``manifest_fetch``, extract its (single) layer
       digest, and compare it against a fresh local ``sha256`` of
       ``artifact_bytes``. A mismatch raises ``PUBLISH-DIGEST-MISMATCH``
       *before* ``sign`` is ever called — cosign must never attest to bytes
       that don't match what was just packed.
    7. **Sign** that immutable digest-pinned ref (not the mutable tag), only
       once verified — cosign attests to the exact bytes that were pushed.
    8. **Assemble** the ``PublishReceipt``: ``content_hash`` comes straight
       from the plan (already computed by ``build_publish_plan`` — never
       recomputed here).
    """
    entries = _entries_or_derive(plan.source, entries)
    artifact_bytes = pack_source(entries)

    registry_ref = f"{plan.target.registry}/{plan.target.repository}:{plan.target.tag}"

    with tempfile.TemporaryDirectory(prefix="milpa-publish-") as tmp_dir:
        artifact_path = Path(tmp_dir) / "source.tar.gz"
        artifact_path.write_bytes(artifact_bytes)
        digest = push(
            artifact_path,
            registry_ref,
            plan.target.artifact_type,
            plan.target.layer_media_type,
        )

    oci_ref = OciProvenance(
        plan.target.registry, plan.target.repository, digest
    ).reference

    local_digest = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
    manifest = manifest_fetch(oci_ref)
    remote_digest = _extract_layer_digest(manifest, oci_ref)
    if remote_digest != local_digest:
        raise MilpaError(
            PUBLISH_DIGEST_MISMATCH,
            f"pushed artifact digest mismatch for {oci_ref!r}: local sha256 of "
            f"the packed bytes is {local_digest!r} but the fetched manifest's "
            f"layer digest is {remote_digest!r}; refusing to sign bytes that "
            f"don't match what was just pushed",
            oci_ref=oci_ref,
            local_digest=local_digest,
            remote_digest=remote_digest,
        )

    sign(oci_ref)

    return PublishReceipt(
        content_hash=plan.content_hash,
        oci_ref=oci_ref,
        layer_digest=digest,
        artifact_type=plan.target.artifact_type,
    )
