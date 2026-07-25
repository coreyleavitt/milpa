"""GitFetcher — subprocess git clone transport (slice 7d-1, H3b object-store rewrite).

Handles ``GitProvenance(url, ref, commit_sha=None)``.

URL can be any scheme git understands (https://, ssh://, git://, file://,
or a bare filesystem path that git accepts directly).

On success the source tree is materialized under ``dest/`` via
``materialize_git_tree`` (the single chokepoint) and a ``GitReceipt``
carrying the resolved commit SHA is returned.  The receipt records the
transport artifact's own identifier (commit SHA) — never the source-tree
identity hash (forbidden per plugin-contract.md §3.1).

Materialization mechanism (H3b, spec/identity.md §1.7):
  - Clone is ``--no-checkout``: no working tree, no smudge filters run.
  - ``git ls-tree -r <commit>`` enumerates every blob/symlink/gitlink.
  - ``git cat-file --batch`` reads ALL blobs in ONE subprocess (not N).
  - Fixed on-disk modes: 0o644 (100644), 0o755 (100755), dirs 0o755.
  - mode-120000 (symlink): blob bytes = link-target string; lexical
    containment checked per-symlink; escape → EXTRACT-SYMLINK-ESCAPE.
  - LFS pointer detection: first-line exact match → FETCH-GIT-LFS-POINTER.
  - mode-160000 (gitlink): submodule recursion seam for H5.
  - Output tree never contains .git; empty dirs never synthesized.

Error mapping:
  - git exits non-zero (clone/fetch)      → MilpaError(FETCH_GIT_FAILED)
  - commit_sha not found after exhaustive fetch → MilpaError(FETCH_GIT_COMMIT_ABSENT)
  - symlink target escapes dest           → MilpaError(EXTRACT_SYMLINK_ESCAPE)
  - LFS pointer blob detected             → MilpaError(FETCH_GIT_LFS_POINTER)

``cas_admissible = True`` (inherited default): all git provenances are
CAS-admissible; safety comes from the post-fetch identity gate in the
registry, not from restricting which git refs may be admitted
(plugin-contract.md §4 NORMATIVE rationale).
"""

from __future__ import annotations

import dataclasses
import os
import posixpath
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from milpa.errors import (
    EXTRACT_SYMLINK_ESCAPE,
    EXTRACT_ZIP_SLIP,
    FETCH_GIT_COMMIT_ABSENT,
    FETCH_GIT_FAILED,
    FETCH_GIT_LFS_POINTER,
    FETCH_GIT_SUBMODULE_FAILED,
    ID_NON_UTF8_RELPATH,
    MilpaError,
)
from milpa.dag_identity import (
    MODE_EXECUTABLE,
    MODE_REGULAR,
    MODE_SYMLINK,
    MaterializedEntry,
)
from milpa.fetchers.safe_extract import _normalize_lexical
from milpa.fetchers.types import Fetcher, Provenance, ProvenanceReceipt

# ---------------------------------------------------------------------------
# R1-03: submodule recursion depth cap (NORMATIVE — matches Rust impl)
# ---------------------------------------------------------------------------

#: Maximum allowed depth of submodule recursion.  Exceeding this depth
#: (or re-encountering a (url, sha) pair) raises FETCH-GIT-SUBMODULE-FAILED.
#: Must match the Rust MAX_SUBMODULE_DEPTH constant for cross-impl convergence.
MAX_SUBMODULE_DEPTH: int = 16

# ---------------------------------------------------------------------------
# LFS pointer detection constant (plugin-contract.md §2.3.2)
# ---------------------------------------------------------------------------

#: The exact first line of a Git-LFS pointer file (bytes, without trailing \n
#: stripped so we can match with startswith on raw blob bytes).
_LFS_POINTER_FIRST_LINE: bytes = b"version https://git-lfs.github.com/spec/v1\n"

# ---------------------------------------------------------------------------
# GitProvenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GitProvenance(Provenance):
    """Provenance descriptor for a git-backed source tree.

    ``url``        — any URL scheme git understands (https, ssh, git, file,
                     or bare filesystem path).
    ``ref``        — branch, tag, or HEAD; always recorded for provenance
                     and human debuggability.
    ``commit_sha`` — optional exact-commit pin.  When set the fetcher checks
                     out this SHA instead of the mutable ref tip; the ref is
                     kept for display/lockfile provenance only.

    ``cas_admissible = True`` (inherited from ``Provenance`` base):
    CAS admission safety is guaranteed by the post-fetch identity gate in the
    registry, not by restricting which refs may be admitted (§4 NORMATIVE).
    """

    url: str
    ref: str
    commit_sha: str | None = None


# ---------------------------------------------------------------------------
# GitReceipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GitReceipt(ProvenanceReceipt):
    """Transport receipt for a successful git fetch.

    ``commit_sha`` — the SHA of HEAD after clone.  This identifies
    the git object that was materialized, NOT the source-tree identity hash
    (plugin-contract.md §3.1 NORMATIVE: tree hashes are forbidden in receipts).

    ``submodule_shas`` — provenance map from full submodule path (relative to
    the superproject root, POSIX separators) to the 40-hex gitlink SHA that was
    recursed (H5).  Empty dict when the dep has no submodules.  This is
    PROVENANCE, not identity — recorded alongside ``commit_sha`` in the lockfile
    git provenance block (spec/lockfile-schema.md §4.1).
    """

    commit_sha: str
    submodule_shas: dict[str, str] = dataclasses.field(default_factory=dict)

    def transport_fields(self) -> dict[str, str]:
        return {"commit_sha": self.commit_sha}


# ---------------------------------------------------------------------------
# materialize_git_tree — the single chokepoint (H3b, spec §2.3)
# ---------------------------------------------------------------------------


#: git ls-tree blob mode → epoch-2 mode-byte (spec/identity.md §1.8.2.1).
#: 100644 regular → 0x00, 100755 executable → 0x01, 120000 symlink → 0x80.
#: Any other (unexpected) mode is treated as a regular blob (0x00) — see the
#: permissive branch in ``materialize_git_tree``'s disk writer.
_GIT_MODE_TO_BYTE: dict[str, int] = {
    "100644": MODE_REGULAR,
    "100755": MODE_EXECUTABLE,
    "120000": MODE_SYMLINK,
}


def parse_ls_tree_z(raw_data: bytes) -> list[tuple[str, str, str, str]]:
    """Parse ``git ls-tree -r -z`` NUL-delimited stdout into ``(mode, type, sha,
    path)`` records.

    SSOT for ls-tree -z record parsing (R1-15 NORMATIVE: ``-z`` disables
    C-quoting so exotic/non-ASCII filenames are preserved faithfully). Shared
    by ``enumerate_git_entries`` (this module) and ``milpa.publishing``'s
    submodule-refusal guard (``_refuse_submodules``) so there is exactly ONE
    ls-tree -z parser in the codebase, not two independently-maintained
    copies — the two callers still run their own ``git ls-tree`` subprocess
    (a lightweight listing-only call for the early guard vs. the full
    listing-plus-``cat-file`` enumeration), but parse the identical NUL-
    delimited record format through this one function.

    Args:
        raw_data: The raw ``stdout`` bytes of a ``git ls-tree -r -z <commit>``
            invocation.

    Returns:
        A list of ``(mode, obj_type, sha, entry_path)`` tuples, one per
        tree entry, in ls-tree's own order.

    Raises:
        MilpaError(ID_NON_UTF8_RELPATH): a tree entry path is not valid UTF-8.
    """
    records: list[tuple[str, str, str, str]] = []
    for raw_record in raw_data.split(b"\x00"):
        if not raw_record:
            continue  # skip empty trailing element
        tab_idx = raw_record.index(b"\t")
        meta = raw_record[:tab_idx].decode()
        path_bytes = raw_record[tab_idx + 1:]
        # NEW-C NORMATIVE: non-UTF-8 path bytes are always an error.
        # Both Python and Rust reject identically — latin-1 fallback was removed
        # because it silently produced different on-disk names from Rust's U+FFFD
        # substitution, causing content_hash divergence with no error raised.
        # Nim packages never have legitimate non-UTF-8 source filenames.
        try:
            entry_path = path_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise MilpaError(
                ID_NON_UTF8_RELPATH,
                f"git tree entry path is not valid UTF-8: {path_bytes!r}; "
                f"non-UTF-8 source filenames are not supported in milpa (spec/identity.md §1.5)",
                path=repr(path_bytes),
            )

        parts = meta.split()
        mode, obj_type, sha = parts[0], parts[1], parts[2]
        records.append((mode, obj_type, sha, entry_path))
    return records


def enumerate_git_entries(
    repo: Path,
    commit: str,
    *,
    submodule_fetch: Callable[[str, str], Path] | None,
    superproject_url: str | None = None,
    depth: int = 0,
    seen: set[tuple[str, str]] | None = None,
) -> tuple[list[MaterializedEntry], dict[str, str]]:
    """The git **materialize seam** (RFC slice B2-git): read a commit's tree from
    the object store into a buffered ``list[MaterializedEntry]`` (spec §1.8.4).

    This is the single source of truth for git tree enumeration. Both consumers
    read from here:

      * ``materialize_git_tree`` — writes the entries to ``dest/`` (CAS path).
      * the epoch-2 DAG builder (``milpa.dag_identity.compute_dag_identity``) —
        computes the ``dag-sha256:`` identity over the entries.

    Submodules (mode-160000 gitlinks) are recursed via ``submodule_fetch`` and
    their committed blobs are spliced into the sequence under the gitlink's path
    prefix (spec §1.8.7): the DAG builder then folds them into a subtree whose
    root ``H_tree`` becomes the gitlink's child digest. The submodule URLs and
    pinned SHAs are returned separately as PROVENANCE.

    Args:
        repo:              ``--no-checkout`` clone scratch holding ``.git/`` (the
                           object store read from); NOT an output tree.
        commit:            Commit SHA to enumerate.
        submodule_fetch:   H5 recursion seam: ``(resolved_url, sha) -> clone_scratch``.
                           ``None`` records nothing for gitlinks (no recursion).
        superproject_url:  remote URL of this repo (resolves relative
                           ``url = ../sibling`` in ``.gitmodules``).
        depth:             R1-03 recursion depth (root = 0).
        seen:              R1-03 visited ``(url, sha)`` set on the current path.

    Returns:
        ``(entries, submodule_shas)``:
          * ``entries`` — buffered ``MaterializedEntry`` list (blobs + symlinks,
            committed-tree relpaths, submodule blobs prefixed by gitlink path).
          * ``submodule_shas`` — ``{submodule_path (POSIX): sha}`` PROVENANCE map.

    Raises:
        MilpaError(FETCH_GIT_FAILED)           — git subprocess failed.
        MilpaError(ID_NON_UTF8_RELPATH)        — a tree entry path is not UTF-8.
        MilpaError(FETCH_GIT_SUBMODULE_FAILED)  — submodule URL unresolvable, fetch
                                                  failed, or depth/cycle exceeded.

    Implementation contract (spec/identity.md §1.7, plugin-contract.md §2.3):
      - ``git ls-tree -r -z <commit>`` enumerates blobs/symlinks/gitlinks.
        NUL-delimited (-z) disables C-quoting so exotic / non-ASCII filenames
        are preserved faithfully (R1-15 NORMATIVE).
      - ``git cat-file --batch`` streams ALL blob bytes in ONE subprocess.
      - Empty directories are NOT synthesized.
    """
    # -----------------------------------------------------------------------
    # Step 1: ls-tree -r -z — enumerate (mode, type, sha, path) for every entry
    #
    # R1-15 NORMATIVE: use -z (NUL-delimited) to disable C-quoting.  Without
    # -z, git C-quotes filenames containing non-ASCII, spaces, or backslashes,
    # and the surrounding double-quotes + escape sequences become part of the
    # parsed path.  -z splits on NUL instead, preserving path bytes faithfully.
    # -----------------------------------------------------------------------
    ls_result = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "-z", "--end-of-options", commit],
        capture_output=True,
        check=False,
    )
    if ls_result.returncode != 0:
        raise MilpaError(
            FETCH_GIT_FAILED,
            f"git ls-tree failed for commit {commit!r}: "
            f"{ls_result.stderr.decode(errors='replace').strip()}",
            commit=commit,
        )

    # Parse ls-tree -z output: NUL-terminated records (SSOT: parse_ls_tree_z,
    # shared with milpa.publishing's submodule-refusal guard).
    blobs: list[tuple[str, str, str, str]] = []   # (mode, type, sha, path)
    gitlinks: list[tuple[str, str, str, str]] = []

    for mode, obj_type, sha, entry_path in parse_ls_tree_z(ls_result.stdout):
        if mode == "160000":
            gitlinks.append((mode, obj_type, sha, entry_path))
        else:
            blobs.append((mode, obj_type, sha, entry_path))

    # -----------------------------------------------------------------------
    # Step 2: cat-file --batch — ONE subprocess for ALL blobs
    # -----------------------------------------------------------------------
    # Build the SHA list for --batch (only blobs and symlinks, not gitlinks).
    batch_shas = list(dict.fromkeys(sha for (mode, _, sha, _) in blobs))

    blob_bytes: dict[str, bytes] = {}  # sha → raw blob bytes

    if batch_shas:
        # Write all SHAs to stdin; read headers+content from stdout.
        batch_input = ("\n".join(batch_shas) + "\n").encode()
        cat_result = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "--batch"],
            input=batch_input,
            capture_output=True,
            check=False,
        )
        if cat_result.returncode != 0:
            raise MilpaError(
                FETCH_GIT_FAILED,
                f"git cat-file --batch failed for commit {commit!r}: "
                f"{cat_result.stderr.decode(errors='replace').strip()}",
                commit=commit,
            )

        # Parse the --batch output stream.
        # Each object: "<sha> <type> <size>\n<content>\n"
        data = cat_result.stdout
        pos = 0
        for sha in batch_shas:
            # Read the header line.
            nl = data.index(b"\n", pos)
            header = data[pos:nl].decode()
            pos = nl + 1
            # Header format: "<sha> <type> <size>" or "<sha> missing"
            header_parts = header.split()
            if len(header_parts) == 2 and header_parts[1] == "missing":
                raise MilpaError(
                    FETCH_GIT_FAILED,
                    f"git cat-file --batch: SHA {sha!r} reported missing",
                    commit=commit,
                    sha=sha,
                )
            obj_sha_h, obj_type_h, obj_size_str = header_parts[0], header_parts[1], header_parts[2]
            obj_size = int(obj_size_str)
            # Read exactly obj_size bytes.
            content = data[pos:pos + obj_size]
            pos += obj_size
            # Skip the trailing newline separator between objects.
            if pos < len(data) and data[pos:pos + 1] == b"\n":
                pos += 1
            blob_bytes[sha] = content

    # -----------------------------------------------------------------------
    # Step 3: build the buffered materialized entry sequence
    # -----------------------------------------------------------------------
    # The git mode → mode-byte mapping is the SSOT for the exec/symlink bit that
    # epoch-2 identity depends on (spec §1.8.2.1). LFS detection + on-disk-mode
    # writing + path containment are the DISK consumer's concern
    # (``materialize_git_tree``), not the abstract entry sequence.
    entries: list[MaterializedEntry] = [
        MaterializedEntry(
            relpath=entry_path,
            mode_byte=_GIT_MODE_TO_BYTE.get(mode, MODE_REGULAR),
            content=blob_bytes[sha],
        )
        for (mode, _obj_type, sha, entry_path) in blobs
    ]

    # -----------------------------------------------------------------------
    # Step 4: gitlinks — submodule recursion (H5), spliced into the sequence
    # -----------------------------------------------------------------------
    gitlink_results: dict[str, str] = {}

    if gitlinks and submodule_fetch is not None:
        # R1-03: initialise seen set at the root call (depth=0, seen=None).
        if seen is None:
            seen = set()

        # Parse .gitmodules from the object store (NOT from disk): its bytes were
        # read in Step 2. .gitmodules is committed content, a regular blob at the
        # repo root (relpath ".gitmodules").
        gitmodules_bytes = b""
        for mode, _obj_type, sha, entry_path in blobs:
            if entry_path == ".gitmodules":
                gitmodules_bytes = blob_bytes[sha]
                break
        submodule_url_map = _parse_gitmodules(gitmodules_bytes)

        for mode, obj_type, sha, entry_path in gitlinks:
            # Resolve the submodule URL: look up in .gitmodules by path.
            raw_url = submodule_url_map.get(entry_path)
            if raw_url is None:
                raise MilpaError(
                    FETCH_GIT_SUBMODULE_FAILED,
                    f"submodule at {entry_path!r} has no entry in .gitmodules "
                    f"(or .gitmodules is absent); cannot resolve URL",
                    submodule_path=entry_path,
                    submodule_url="(unknown)",
                )
            resolved_url = _resolve_submodule_url(raw_url, superproject_url)

            # R1-03: depth cap — exceeding MAX_SUBMODULE_DEPTH is the load-bearing guard.
            if depth >= MAX_SUBMODULE_DEPTH:
                raise MilpaError(
                    FETCH_GIT_SUBMODULE_FAILED,
                    f"submodule recursion depth {depth} exceeds cap "
                    f"MAX_SUBMODULE_DEPTH={MAX_SUBMODULE_DEPTH} at {entry_path!r}; "
                    f"possible infinite submodule cycle",
                    submodule_path=entry_path,
                    submodule_url=resolved_url,
                )

            # R1-03: visited-set guard — re-encountering (url, sha) signals a cycle.
            visit_key = (resolved_url, sha)
            if visit_key in seen:
                raise MilpaError(
                    FETCH_GIT_SUBMODULE_FAILED,
                    f"submodule cycle detected: ({resolved_url!r}, {sha!r}) already "
                    f"visited in this recursion (at {entry_path!r})",
                    submodule_path=entry_path,
                    submodule_url=resolved_url,
                )
            # Mark as visiting before recursing (add to child's seen copy).
            child_seen = seen | {visit_key}

            try:
                sub_scratch = submodule_fetch(resolved_url, sha)
            except MilpaError:
                raise
            except Exception as exc:
                raise MilpaError(
                    FETCH_GIT_SUBMODULE_FAILED,
                    f"fetching submodule {entry_path!r} from {resolved_url!r} failed: {exc}",
                    submodule_path=entry_path,
                    submodule_url=resolved_url,
                ) from exc

            # Recurse via the SAME seam: enumerate the submodule's tree, then
            # splice its entries in under the gitlink path prefix (spec §1.8.7).
            sub_entries, sub_results = enumerate_git_entries(
                sub_scratch,
                sha,
                submodule_fetch=submodule_fetch,
                superproject_url=resolved_url,
                depth=depth + 1,
                seen=child_seen,
            )
            for sub_entry in sub_entries:
                entries.append(
                    MaterializedEntry(
                        relpath=entry_path + "/" + sub_entry.relpath,
                        mode_byte=sub_entry.mode_byte,
                        content=sub_entry.content,
                    )
                )
            # Record this gitlink using its POSIX path relative to the root.
            gitlink_results[entry_path] = sha
            # Accumulate nested submodule results with prefixed paths.
            for nested_path, nested_sha in sub_results.items():
                gitlink_results[entry_path + "/" + nested_path] = nested_sha

    return entries, gitlink_results


def materialize_git_tree(
    repo: Path,
    commit: str,
    dest: Path,
    *,
    submodule_fetch: Callable[[str, str], Path] | None,
    superproject_url: str | None = None,
    depth: int = 0,
    seen: set[tuple[str, str]] | None = None,
) -> dict[str, str]:
    """Materialize a git commit's tree from the object store into ``dest/``.

    Thin disk-writing consumer of the ``enumerate_git_entries`` seam (RFC slice
    B2-git): it enumerates once, then writes each buffered entry to ``dest/`` with
    fixed on-disk modes + the path/symlink/LFS safety checks. ``GitFetcher.fetch``
    produces its output tree EXCLUSIVELY via this function (plugin-contract.md §2.4.1).

    Args / Returns / Raises: the seam (``enumerate_git_entries``) plus the disk
    safety checks below. Returns the ``{submodule_path: sha}`` PROVENANCE map.

    Raises:
        MilpaError(EXTRACT_ZIP_SLIP)           — a tree entry path escapes dest (R1-01).
        MilpaError(EXTRACT_SYMLINK_ESCAPE)     — a committed symlink's target escapes dest.
        MilpaError(FETCH_GIT_LFS_POINTER)      — a blob is a Git-LFS pointer.
        MilpaError(FETCH_GIT_FAILED)           — git subprocess failed.
        MilpaError(FETCH_GIT_SUBMODULE_FAILED) — submodule URL unresolvable, fetch failed,
                                                  or recursion depth/cycle exceeded (R1-03).

    Disk contract (spec/identity.md §1.7.4):
      - mode-byte 0x00 (regular) → 0o644, 0x01 (executable) → 0o755.
      - mode-byte 0x80 (symlink): lexical containment check before write.
      - Blob write path: entry path is lexically checked against dest_root
        BEFORE any write — absolute paths and ``..`` escapes raise
        EXTRACT-ZIP-SLIP (R1-01 NORMATIVE).
      - Output tree has no ``.git`` directory; empty directories are NOT synthesized.
    """
    # Canonicalize dest so prefix comparisons are reliable (mirrors SafeExtractor).
    dest_root = dest.resolve()

    entries, gitlink_results = enumerate_git_entries(
        repo,
        commit,
        submodule_fetch=submodule_fetch,
        superproject_url=superproject_url,
        depth=depth,
        seen=seen,
    )

    for entry in entries:
        abs_dest = dest_root / entry.relpath

        # R1-01 NORMATIVE: lexical containment check BEFORE any write.
        # Reuse _normalize_lexical (SSOT from safe_extract) to resolve
        # . and .. without hitting the filesystem.  Reject absolute entry
        # paths (which Python pathlib silently makes absolute when joining)
        # and any .. escape out of dest_root.
        _check_path_containment(entry.relpath, abs_dest, dest_root)

        if entry.mode_byte == MODE_SYMLINK:
            # Symlink: blob bytes are the link-target string.
            _materialize_symlink(entry.relpath, entry.content, abs_dest, dest_root)
        else:
            # Regular or executable blob.
            # LFS first-line detection (plugin-contract.md §2.3.2).
            _check_lfs(entry.relpath, entry.content)
            abs_dest.parent.mkdir(parents=True, exist_ok=True)
            abs_dest.write_bytes(entry.content)
            # Fixed on-disk mode (spec §1.7.4): 0o755 for executable, else 0o644.
            on_disk_mode = 0o755 if entry.mode_byte == MODE_EXECUTABLE else 0o644
            abs_dest.chmod(on_disk_mode)

    return gitlink_results


def _check_path_containment(
    entry_path: str,
    abs_dest: Path,
    dest_root: Path,
) -> None:
    """Raise EXTRACT-ZIP-SLIP if ``abs_dest`` is not strictly under ``dest_root``.

    R1-01 NORMATIVE: called before writing any blob or creating any gitlink
    sub-destination.  Reuses ``_normalize_lexical`` (SSOT from safe_extract)
    to resolve ``.`` and ``..`` without filesystem access.

    Handles two attack classes:
      - ``..`` escape: entry_path = "../../evil" → abs_dest escapes dest_root.
      - Absolute path: entry_path = "/etc/passwd" → Python pathlib replaces
        dest_root entirely (Path(dest_root) / "/etc/passwd" == Path("/etc/passwd")).

    Args:
        entry_path: POSIX relpath from tree root (for error messages).
        abs_dest:   Joined path: ``dest_root / entry_path`` (pre-computed by caller).
        dest_root:  Canonical absolute path of the output tree root (resolved).

    Raises:
        MilpaError(EXTRACT_ZIP_SLIP): if abs_dest escapes dest_root.
    """
    normalized = _normalize_lexical(abs_dest)
    under_dest = (
        str(normalized).startswith(str(dest_root) + os.sep)
        or normalized == dest_root
    )
    if not under_dest:
        raise MilpaError(
            EXTRACT_ZIP_SLIP,
            f"git tree entry {entry_path!r} resolves outside destination: "
            f"{normalized} not under {dest_root}",
            entry=entry_path,
            dest=str(dest_root),
        )


def _parse_gitmodules(content: bytes) -> dict[str, str]:
    """Parse a ``.gitmodules`` blob into a ``{submodule_path: url}`` map.

    ``.gitmodules`` uses a gitconfig-format subset:
    ```
    [submodule "<name>"]
        path = <path>
        url = <url>
    ```
    This is NOT gitconfig eval — pure text parsing, no shell execution.
    Returns a dict mapping each submodule's *path* (not name) to its *url*.
    Entries without both ``path`` and ``url`` are silently skipped.
    """
    result: dict[str, str] = {}
    current_path: str | None = None
    current_url: str | None = None

    text = content.decode("utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[submodule "):
            # Flush previous section if complete.
            if current_path is not None and current_url is not None:
                result[current_path] = current_url
            current_path = None
            current_url = None
        elif "=" in stripped and not stripped.startswith("["):
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip()
            if key == "path":
                current_path = value
            elif key == "url":
                current_url = value

    # Flush final section.
    if current_path is not None and current_url is not None:
        result[current_path] = current_url

    return result


def _resolve_submodule_url(raw_url: str, superproject_url: str | None) -> str:
    """Resolve a submodule URL from ``.gitmodules`` against the superproject URL.

    Git's relative-submodule-URL rule (mirrors git-submodule(1)):
      - Absolute URLs (contain ``://`` or start with ``/`` or ``git@``) pass
        through unchanged.
      - Relative URLs (start with ``./`` or ``../``) are resolved against the
        superproject URL's path component, treating it like a directory path.
        e.g. superproject = ``https://host/org/super.git``
             relative     = ``../sibling``
             → ``https://host/org/sibling``

    This is host-independent (no DNS resolution, no filesystem access) — a
    purely deterministic URL path arithmetic operation.

    Args:
        raw_url:          URL string from ``.gitmodules`` (may be relative).
        superproject_url: The remote clone URL of the enclosing superproject.
                          Required when ``raw_url`` is relative; ``None`` is
                          acceptable only when ``raw_url`` is absolute.

    Returns:
        Resolved absolute URL string.

    Raises:
        ValueError: if ``raw_url`` is relative and ``superproject_url`` is None.
    """
    # Absolute URL heuristic: contains "://" or starts with "/" or is an
    # SCP-style "user@host:path" git URL.
    is_absolute = (
        "://" in raw_url
        or raw_url.startswith("/")
        or (
            not raw_url.startswith("./")
            and not raw_url.startswith("../")
            and "@" in raw_url.split(":")[0]
        )
    )
    if is_absolute:
        return raw_url

    # Relative URL: resolve against superproject_url path component.
    if superproject_url is None:
        raise ValueError(
            f"Cannot resolve relative submodule URL {raw_url!r}: "
            f"superproject_url is None"
        )

    # Strategy: treat the superproject URL as a path and apply POSIX
    # dirname + joinpath logic on the URL's path component.
    # Split off the scheme+host from the path.
    # Supports https://, ssh://, git://, and file:// URL schemes.

    # Git's relative URL rule mirrors git-submodule.sh `resolve_relative_url`:
    #   remoteurl="${remote%/*}"   # strip last path component (after last '/')
    #   ...
    #   url="$remoteurl/$url"      # prepend and normalize
    #
    # Step 1: strip the last path component from superproject_url.
    last_slash = superproject_url.rfind("/")
    if last_slash == -1:
        remoteurl = superproject_url
    else:
        remoteurl = superproject_url[:last_slash]

    # Step 2: split scheme+host from path component (for safe normpath).
    if "://" in remoteurl:
        scheme_end = remoteurl.index("://") + 3
        scheme_host = remoteurl[:scheme_end]      # e.g. "https://"
        after_scheme = remoteurl[scheme_end:]     # e.g. "github.com/org"
        host_slash = after_scheme.find("/")
        if host_slash == -1:
            host_part = after_scheme
            url_path = "/"
        else:
            host_part = after_scheme[:host_slash]
            url_path = after_scheme[host_slash:]
        base = scheme_host + host_part            # e.g. "https://github.com"
    else:
        base = ""
        url_path = remoteurl

    # Step 3: join the path component with the relative URL and normalize.
    # R1-16 NORMATIVE: posixpath.normpath PRESERVES a leading '//' (POSIX allows
    # it as a special case) so we CANNOT rely on normpath to collapse consecutive
    # slashes.  Instead: first normpath (resolves . and ..), then explicitly
    # collapse all runs of consecutive '/' in the result.  This matches Rust's
    # always-collapse behavior so both impls produce byte-identical resolved URLs
    # even when the superproject URL's path component contains //.
    import re as _re
    joined = posixpath.normpath(posixpath.join(url_path, raw_url))
    # Collapse any run of 2+ consecutive '/' to a single '/'.
    resolved_path = _re.sub(r"/{2,}", "/", joined)

    return base + resolved_path


def _check_lfs(entry_path: str, content: bytes) -> None:
    """Raise FETCH_GIT_LFS_POINTER if content is a Git-LFS pointer.

    A blob is a Git-LFS pointer iff its first line is exactly the LFS version
    header (plugin-contract.md §2.3.2 — first-line exact match).
    """
    if content.startswith(_LFS_POINTER_FIRST_LINE):
        raise MilpaError(
            FETCH_GIT_LFS_POINTER,
            f"dep uses Git LFS at path {entry_path!r}: milpa reads the git object "
            f"store directly and cannot fetch LFS blobs — vendor a plain-git mirror "
            f"or use a local= path",
            path=entry_path,
        )


def _materialize_symlink(
    entry_path: str,
    blob_bytes: bytes,
    abs_dest: Path,
    dest_root: Path,
) -> None:
    """Write a mode-120000 symlink blob to disk after lexical containment check.

    plugin-contract.md §2.3.3 — same containment logic as SafeExtractor.

    Args:
        entry_path:  POSIX relpath from tree root (for error messages).
        blob_bytes:  Raw blob bytes = the link-target string (UTF-8).
        abs_dest:    Absolute destination path for the symlink.
        dest_root:   Canonical absolute path of the output tree root.

    Raises:
        MilpaError(EXTRACT_SYMLINK_ESCAPE) — target resolves outside dest_root.
    """
    # Decode target (§1.5: non-UTF-8 → ID-NON-UTF8-SYMLINK-TARGET, but that's
    # raised by compute_content_hash; here we fail with EXTRACT-SYMLINK-ESCAPE
    # to stay consistent with the containment check in SafeExtractor).
    try:
        link_target = blob_bytes.decode("utf-8")
    except UnicodeDecodeError:
        # Non-UTF-8 symlink target — the identity algorithm will fail on it.
        # Raise escape error (it's also a containment concern — we can't safely
        # compute the normalized path with a non-UTF-8 target).
        raise MilpaError(
            EXTRACT_SYMLINK_ESCAPE,
            f"symlink {entry_path!r} has a non-UTF-8 target; cannot check containment",
            entry=entry_path,
            dest=str(dest_root),
        )

    # Lexical containment check (mirrors SafeExtractor._check_and_strip for symlinks).
    # Normalize: parent of abs_dest joined with the link target, all `.` and `..`
    # resolved WITHOUT following filesystem symlinks.
    parent = abs_dest.parent
    resolved_target = _normalize_lexical(parent / link_target)
    under_dest = (
        str(resolved_target).startswith(str(dest_root) + os.sep)
        or resolved_target == dest_root
    )
    if not under_dest:
        raise MilpaError(
            EXTRACT_SYMLINK_ESCAPE,
            f"symlink {entry_path!r} → {link_target!r} resolves outside "
            f"destination: {resolved_target} not under {dest_root}",
            entry=entry_path,
            link_target=link_target,
            dest=str(dest_root),
        )

    # Write the symlink.
    abs_dest.parent.mkdir(parents=True, exist_ok=True)
    if abs_dest.exists() or abs_dest.is_symlink():
        abs_dest.unlink()
    abs_dest.symlink_to(link_target)


# ---------------------------------------------------------------------------
# GitFetcher
# ---------------------------------------------------------------------------


class GitFetcher(Fetcher):
    """Clone a git repository and materialize via object store; return commit SHA.

    Satisfies the three plugin-contract obligations (§1):
      1. Claim: ``can_handle`` returns ``True`` for ``GitProvenance`` only.
      2. Materialize: ``fetch`` runs ``git clone --no-checkout``, ensures the
         commit is present, then calls ``materialize_git_tree`` to populate
         ``dest/`` from the object store (no smudge filters, no CRLF, no LFS).
      3. Receipt: returns ``GitReceipt(commit_sha=<HEAD SHA>)``; the SHA
         identifies the transport artifact, not the materialized tree.

    Failure is signalled by raising ``MilpaError`` with a coded slug
    (plugin-contract.md §2 NORMATIVE).  Cleanup of ``dest`` is the
    registry's responsibility.
    """

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, GitProvenance)

    def fetch(
        self,
        name: str,
        p: Provenance,
        *,
        dest: Path,
    ) -> GitReceipt:
        assert isinstance(p, GitProvenance)

        import tempfile
        import shutil

        # --- clone --no-checkout into a scratch dir -------------------------
        # The scratch dir holds the object store (.git); it is distinct from
        # dest (the output tree).  Cleanup is guaranteed in the finally block.
        # spec/identity.md §1.7.1 NORMATIVE: no working-tree checkout.
        #
        # R5: use --end-of-options before the URL so a URL starting with '-'
        # cannot be misinterpreted as an option flag (git clone >= 2.24).
        clone_scratch_parent = dest.parent / f"_scratch_{dest.name}"
        clone_scratch_parent.mkdir(parents=True, exist_ok=True)
        clone_scratch = Path(tempfile.mkdtemp(dir=clone_scratch_parent))

        try:
            _run_git(
                name,
                p,
                ["git", "clone", "-q", "--no-checkout", "--end-of-options", p.url, str(clone_scratch)],
            )

            # --- resolve commit SHA -----------------------------------------
            if p.commit_sha is not None:
                # Exact-commit pin: ensure the commit is present.
                _ensure_commit_present(name, p, clone_scratch)
                commit = p.commit_sha
            else:
                # Mutable-ref tip: resolve the ref to a commit SHA.
                # The full clone already fetched every branch, tag, and reachable
                # object, so a branch tip, tag, or any commit SHA (full OR short)
                # reachable from history usually resolves locally — no fetch needed.
                # Only fetch explicitly when the ref is not yet present (e.g. a PR
                # ref / hidden namespace the default clone didn't bring down).  This
                # also avoids ``git fetch origin <short-sha>``, which servers reject
                # outright (they accept full SHAs via allowReachableSHA1InWant but
                # not abbreviated ones).
                commit = _try_resolve_ref(clone_scratch, p.ref)
                if commit is None:
                    _run_git(
                        name,
                        p,
                        ["git", "-C", str(clone_scratch), "fetch", "-q", "origin",
                         "--end-of-options", p.ref],
                    )
                    commit = _git_resolve_ref(clone_scratch, p.ref)

            # --- materialize the object-store tree into dest ----------------
            # spec/plugin-contract.md §2.3 + §2.4.1 NORMATIVE: the ONLY path
            # that produces bytes entering the CAS.
            dest.mkdir(parents=True, exist_ok=True)

            # H5: build the submodule_fetch closure.  For each (url, sha) pair,
            # clone the submodule into a scratch dir and return the scratch path.
            # The closure captures clone_scratch_parent so sub-clones land in a
            # predictable location cleaned up by the outer finally block.
            def _submodule_fetch(sub_url: str, sub_sha: str) -> Path:
                sub_scratch = Path(tempfile.mkdtemp(dir=clone_scratch_parent))
                try:
                    result = subprocess.run(
                        ["git", "clone", "-q", "--no-checkout",
                         "--end-of-options", sub_url, str(sub_scratch)],
                        capture_output=True,
                        text=True,
                    )
                    if result.returncode != 0:
                        detail = result.stderr.strip() or result.stdout.strip() or "git clone failed"
                        raise MilpaError(
                            FETCH_GIT_SUBMODULE_FAILED,
                            f"cloning submodule from {sub_url!r}: {detail}",
                            submodule_url=sub_url,
                            submodule_path="(pending)",
                        )
                    # R1-09 NORMATIVE: verify the pinned commit is reachable.
                    # The clone may have fetched only the default branch; the
                    # pinned sub_sha may be on a different branch or commit.
                    # Step 1: cheap local check.
                    have = subprocess.run(
                        ["git", "-C", str(sub_scratch), "cat-file", "-e",
                         "--end-of-options", f"{sub_sha}^{{commit}}"],
                        capture_output=True,
                    )
                    if have.returncode != 0:
                        # Step 2: targeted fetch.
                        fetch_result = subprocess.run(
                            ["git", "-C", str(sub_scratch), "fetch", "-q",
                             "origin", "--end-of-options", sub_sha],
                            capture_output=True,
                        )
                        # Step 3: re-check after fetch.
                        recheck = subprocess.run(
                            ["git", "-C", str(sub_scratch), "cat-file", "-e",
                             "--end-of-options", f"{sub_sha}^{{commit}}"],
                            capture_output=True,
                        )
                        if recheck.returncode != 0:
                            # R1-09: pinned commit genuinely absent — raise
                            # FETCH-GIT-SUBMODULE-FAILED (NOT FETCH-GIT-FAILED).
                            detail = (
                                fetch_result.stderr.decode(errors="replace").strip()
                                if fetch_result.returncode != 0
                                else f"commit {sub_sha!r} absent after fetch"
                            )
                            raise MilpaError(
                                FETCH_GIT_SUBMODULE_FAILED,
                                f"submodule from {sub_url!r}: pinned commit "
                                f"{sub_sha!r} not reachable after clone+fetch: {detail}",
                                submodule_url=sub_url,
                                submodule_path="(pending)",
                            )
                    return sub_scratch
                except MilpaError:
                    raise
                except Exception as exc:
                    raise MilpaError(
                        FETCH_GIT_SUBMODULE_FAILED,
                        f"submodule fetch from {sub_url!r} failed: {exc}",
                        submodule_url=sub_url,
                        submodule_path="(pending)",
                    ) from exc

            submodule_shas = materialize_git_tree(
                clone_scratch,
                commit,
                dest,
                submodule_fetch=_submodule_fetch,
                superproject_url=p.url,
            )

        finally:
            # Clean up the clone scratch regardless of success or failure.
            # spec/identity.md §1.7.1 NORMATIVE: scratch removed after cat-file pass.
            shutil.rmtree(clone_scratch_parent, ignore_errors=True)

        return GitReceipt(commit_sha=commit, submodule_shas=submodule_shas)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


#: Transport flags injected into git clone/fetch invocations.
#: These suppress host-config interference during network operations.
#: The checkout normalization flags (-c core.autocrlf=false, -c core.filemode=false)
#: were removed in H3b: with --no-checkout there is no working-tree checkout,
#: so these flags are structurally irrelevant.  The remaining flags are transport-
#: level (not content-level) and do not affect the materialized bytes.
_GIT_TRANSPORT_FLAGS: list[str] = []


def _run_git(name: str, p: GitProvenance, argv: list[str]) -> None:
    """Run a git subprocess; raise ``MilpaError(FETCH_GIT_FAILED)`` on non-zero exit."""
    patched = [argv[0]] + _GIT_TRANSPORT_FLAGS + argv[1:]
    result = subprocess.run(patched, capture_output=True, text=True)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        detail = stderr or stdout or "git exited non-zero"
        raise MilpaError(
            FETCH_GIT_FAILED,
            f"fetching {name!r} from {p.url!r} at {p.ref!r} failed: {detail}",
            dep=name,
            url=p.url,
            ref=p.ref,
        )


def _git_head_sha(dest: Path) -> str:
    """Return the current HEAD commit SHA in the repository at ``dest``."""
    return subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _try_resolve_ref(repo: Path, ref: str) -> "str | None":
    """Try to resolve *ref* against the object store at *repo* without fetching.

    Does NOT consult FETCH_HEAD — a ``git clone`` leaves a stale FETCH_HEAD
    pointing at the default branch, so consulting it would mis-resolve any
    non-default-branch ref.  (The existing _git_resolve_ref keeps its
    FETCH_HEAD-first logic; it is called only AFTER an explicit fetch.)

    Tries in order:
    1. ``refs/remotes/origin/<ref>^{commit}`` — branch tips fetched by the
       full clone (covers branch names and some tags).
    2. ``<ref>^{commit}``  — resolves annotated/lightweight tags, full SHAs,
       and short SHAs that are already present in the object store (git
       internally expands abbreviated OIDs to the full 40-char SHA).

    Returns the full 40-char SHA on success, or ``None`` when the ref cannot
    be resolved without a targeted ``git fetch``.
    R5: ``--end-of-options`` ensures refs starting with ``-`` are not
    parsed as flags.
    """
    # 1. Remote-tracking branch tip (populated by the full clone).
    result = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet",
         "--end-of-options", f"refs/remotes/origin/{ref}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        sha = result.stdout.strip()
        if sha:
            return sha

    # 2. Direct resolution — covers tags, full SHAs, and short SHAs present
    #    in the object store.
    result2 = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet",
         "--end-of-options", f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    if result2.returncode == 0:
        sha = result2.stdout.strip()
        if sha:
            return sha

    return None


def _git_resolve_ref(repo: Path, ref: str) -> str:
    """Resolve a ref name to a commit SHA in the object store at ``repo``.

    Uses FETCH_HEAD first (populated by the explicit fetch of the ref),
    then falls back to ``refs/remotes/origin/<ref>``.
    R5: --end-of-options ensures ref names starting with '-' are not parsed
    as flags.
    """
    # Try FETCH_HEAD first (written by the preceding git fetch).
    fetch_head = repo / ".git" / "FETCH_HEAD"
    if fetch_head.exists():
        line = fetch_head.read_text().splitlines()[0]
        sha = line.split()[0]
        if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha):
            return sha

    # Fallback: resolve via rev-parse with --end-of-options.
    result = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--end-of-options",
         f"refs/remotes/origin/{ref}"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return result.stdout.strip()

    # Final fallback: try the ref name directly.
    result2 = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--end-of-options", ref],
        capture_output=True,
        text=True,
    )
    if result2.returncode == 0:
        return result2.stdout.strip()

    raise MilpaError(
        FETCH_GIT_FAILED,
        f"could not resolve ref {ref!r} to a commit SHA",
        ref=ref,
    )


def _ensure_commit_present(name: str, p: GitProvenance, dest: Path) -> None:
    """Ensure ``p.commit_sha`` is reachable in ``dest``.

    Strategy (mirrors the frozen impl's _ensure_commit_present):
      1. ``git cat-file -e <sha>^{commit}`` — cheap local check.
      2. Targeted ``git fetch origin <sha>`` — works when the server
         supports ``uploadpack.allowReachableSHA1InWant`` (GitHub / GitLab).
      3. Full history fetch (``--unshallow`` for shallow clones, then plain
         ``fetch``).
      4. Re-check; if still absent raise ``FETCH-GIT-COMMIT-ABSENT``.
    """
    assert p.commit_sha is not None

    # Step 1: cheap local presence check.
    # R5: cat-file -e uses the SHA in an ^{commit} suffix — the object arg is
    # not a bare operand that could be parsed as a flag, but we use
    # --end-of-options for consistency and future-proofing.
    have = subprocess.run(
        ["git", "-C", str(dest), "cat-file", "-e",
         "--end-of-options", f"{p.commit_sha}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    if have.returncode == 0:
        return

    # Step 2: targeted fetch (server-side reachable SHA support).
    # R5: --end-of-options before the SHA refspec.
    targeted = subprocess.run(
        ["git", "-C", str(dest), "fetch", "-q", "origin",
         "--end-of-options", p.commit_sha],
        capture_output=True,
        text=True,
    )
    if targeted.returncode == 0:
        return

    # Step 3a: full history fetch via --unshallow.
    # On a shallow clone this fetches all history; on a full-depth clone git
    # emits "fatal: --unshallow on a complete repository does not make sense"
    # and exits non-zero.  That benign failure is swallowed; any other failure
    # (network error, auth failure) is propagated as FETCH_GIT_FAILED.
    # Precision fix (a) — H4: narrow the soft-fail to the specific "already
    # complete" case; do NOT blanket-swallow arbitrary --unshallow failures.
    unshallow = subprocess.run(
        ["git", "-C", str(dest), "fetch", "-q", "--unshallow", "origin"],
        capture_output=True,
        text=True,
    )
    if unshallow.returncode != 0:
        stderr = unshallow.stderr.strip()
        is_already_complete = (
            "does not make sense" in stderr
            or "complete repository" in stderr
        )
        if not is_already_complete:
            # Real fetch failure — propagate as a coded error.
            raise MilpaError(
                FETCH_GIT_FAILED,
                f"fetching {name!r} from {p.url!r} at {p.ref!r}: "
                f"git fetch --unshallow failed: {stderr or '(no output)'}",
                dep=name,
                url=p.url,
                ref=p.ref,
            )
        # Already complete (non-shallow) — benign; fall through to step 3b.

    # Step 3b: plain fetch to pull any new refs since the clone.
    # Failure is non-fatal (best-effort); step 4 does the definitive check.
    subprocess.run(
        ["git", "-C", str(dest), "fetch", "-q", "origin"],
        capture_output=True,
        text=True,
    )

    # Step 4: re-check after full history fetch.
    recheck = subprocess.run(
        ["git", "-C", str(dest), "cat-file", "-e",
         "--end-of-options", f"{p.commit_sha}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    if recheck.returncode != 0:
        raise MilpaError(
            FETCH_GIT_COMMIT_ABSENT,
            f"commit {p.commit_sha!r} not found in {p.url!r} even after "
            f"full history fetch — the pin may be stale or the commit was "
            f"force-pushed away",
            dep=name,
            url=p.url,
            commit_sha=p.commit_sha,
        )
