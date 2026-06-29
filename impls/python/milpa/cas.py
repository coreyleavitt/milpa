"""Content-addressed store — spec/identity.md §3.

CAStore lays out admitted source trees as:

    <root>/<algorithm>/<hex-digest>/<tree-contents>

The store is concurrency-safe across processes via POSIX rename(2): admit()
commits a scratch tree atomically; duplicate admissions are no-ops.

The 4-tier default_store() precedence (identity.md §3.2):
  1. MILPA_CACHE_DIR env var           — explicit override (tests, sandboxes)
  2. manifest cas { dir "..." }        — NOT this function; applied by CLI/resolver
  3. $XDG_CACHE_HOME/milpa/cas         — XDG standard
  4. ~/.cache/milpa/cas                — fallback

default_store() implements tiers 1, 3, and 4 only.  Tier 2 is applied by the
CLI/resolver (which alone has access to the parsed manifest).
"""

from __future__ import annotations

import os
import shutil
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from milpa.errors import CAS_IDENTITY_MISMATCH, CAS_NOT_IN_STORE, STORE_AMBIGUOUS_PREFIX, MilpaError
from milpa.identity import compute_content_hash, parse_identity

# ---------------------------------------------------------------------------
# _clear_dest — internal helper (mirrors frozen fsutil.clear_dest)
# ---------------------------------------------------------------------------


def _clear_dest(dest: Path) -> None:
    """Remove *dest* if it exists, leaving its parent intact.

    Handles three shapes:
    - symlink (including symlink-to-directory): unlinked, never followed.
    - regular file: unlinked.
    - directory: recursively removed via shutil.rmtree.

    The symlink check comes first because for a symlink-to-directory both
    ``is_symlink()`` and ``is_dir()`` are True; rmtree on a symlink raises on
    CPython ≥ 3.14 and would follow the link into the CAS entry on older
    versions. We must never rmtree through a CAS symlink.

    No-op if *dest* does not exist.
    """
    if dest.is_symlink() or dest.is_file():
        dest.unlink()
    elif dest.is_dir():
        shutil.rmtree(dest)


# ---------------------------------------------------------------------------
# ScratchDir — §3.4 scratch lifecycle
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ScratchDir:
    """Handle for a live scratch subdirectory under ``<root>/_scratch/<uuid>/``.

    Obtained via ``CAStore.scratch()``; never constructed directly.
    """

    path: Path


# ---------------------------------------------------------------------------
# CAStore
# ---------------------------------------------------------------------------


class CAStore:
    """On-disk content-addressed store.

    Layout: ``<root>/<algorithm>/<hex-digest>/<tree-contents>``

    All writes go through ``admit()`` which uses an atomic ``rename(2)`` to
    move a scratch directory into the canonical entry.  The scratch directory
    is always under ``<root>/_scratch/`` — same filesystem mount as the CAS
    entries — so ``rename(2)`` is guaranteed atomic on Linux/macOS POSIX.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def path_for(self, identity: str) -> Path:
        """Canonical path ``<root>/<algorithm>/<hex-digest>/`` for *identity*.

        Validates *identity* via ``parse_identity`` (raises ``MilpaError`` on
        invalid input).  The returned path may or may not exist on disk.
        """
        parse_identity(identity)
        algo, _, hex_digest = identity.partition(":")
        return self.root / algo / hex_digest

    def contains(self, identity: str) -> bool:
        """``True`` iff the store already holds an entry for *identity*."""
        return self.path_for(identity).is_dir()

    def list_identities(self) -> list[str]:
        """Return a lexicographically sorted list of all identities in the store.

        Scans ``<root>/<algorithm>/<hex-digest>/`` directories generically —
        enumerates every algorithm subdir under the CAS root (spec/identity.md §3.1).
        Empty store → empty list.  Entries are returned in canonical
        ``<algorithm>:<64hex>`` form.
        """
        identities: list[str] = []
        if not self.root.is_dir():
            return identities
        for algo_dir in self.root.iterdir():
            # Skip scratch dir and any non-directory entries.
            if algo_dir.name.startswith("_") or not algo_dir.is_dir():
                continue
            for entry in algo_dir.iterdir():
                if entry.is_dir() and not entry.name.startswith("_"):
                    identities.append(f"{algo_dir.name}:{entry.name}")
        identities.sort()
        return identities

    def resolve_prefix(self, prefix: str) -> str:
        """Resolve a hex-digest prefix (with or without an algorithm prefix)
        to a full identity string.

        Generic: strips any ``<algo>:`` prefix to get the bare hex portion;
        does NOT hardcode ``sha256:`` (spec/identity.md §3.1 — store layout is
        algorithm-generic).

        Rules (spec/identity.md §3, C-store-ro slice):
        - A complete identity (``<algo>:<64hex>`` or bare 64-hex) → exact lookup.
          Present → return the full identity.  Absent → raise ``CAS-NOT-IN-STORE``.
        - Else treat as a prefix of the hex digest.  The hex portion of the prefix
          MUST be at least 16 characters; anything shorter is rejected as
          ``STORE-AMBIGUOUS-PREFIX`` (a <16-char prefix is by definition too weak
          to safely pin one entry; we reuse the ambiguous-prefix code rather than
          inventing a separate "too short" code to keep the error catalog minimal).
        - Exactly 1 match → return the full identity.
        - 0 matches → raise ``CAS-NOT-IN-STORE``.
        - >1 match → raise ``STORE-AMBIGUOUS-PREFIX``.

        The caller may then use ``path_for(identity)`` on the returned identity.
        """
        # Strip optional algorithm prefix to get the raw hex portion of the arg.
        if ":" in prefix:
            _, _, hex_part = prefix.partition(":")
            algo_prefix: str | None = prefix[: prefix.index(":")]
        else:
            hex_part = prefix
            algo_prefix = None

        # Exact match: 64-hex digest → direct lookup.
        if len(hex_part) == 64:
            # If a full identity was supplied (algo:hex), validate and look up directly.
            if algo_prefix is not None:
                full_identity = f"{algo_prefix}:{hex_part}"
                if self.contains(full_identity):
                    return full_identity
                raise MilpaError(
                    CAS_NOT_IN_STORE,
                    f"identity not in store: {full_identity!r}",
                    identity=full_identity,
                )
            # Bare 64-hex: search all algorithms for a match.
            matches = [
                identity
                for identity in self.list_identities()
                if identity.partition(":")[2] == hex_part
            ]
            if len(matches) == 1:
                return matches[0]
            if len(matches) == 0:
                raise MilpaError(
                    CAS_NOT_IN_STORE,
                    f"identity not in store: {prefix!r}",
                    identity=prefix,
                )
            raise MilpaError(
                STORE_AMBIGUOUS_PREFIX,
                f"bare hex prefix {prefix!r} matches {len(matches)} store entries "
                f"across multiple algorithms (need an algorithm prefix to disambiguate)",
                prefix=prefix,
                matches=list(matches),
            )

        # Prefix match: enforce the 16-char minimum.
        # A prefix shorter than 16 hex chars is by definition too weak to
        # safely identify a single entry — reject immediately as STORE-AMBIGUOUS-PREFIX
        # rather than introducing a separate "too short" error code (catalog-minimal rule).
        if len(hex_part) < 16:
            raise MilpaError(
                STORE_AMBIGUOUS_PREFIX,
                f"prefix {prefix!r} is shorter than the 16-hex-character minimum "
                f"required to safely identify a single store entry "
                f"(got {len(hex_part)} hex chars)",
                prefix=prefix,
                hex_length=len(hex_part),
            )

        # Scan all identities and collect those whose hex digest starts with the prefix.
        matches = [
            identity
            for identity in self.list_identities()
            if identity.partition(":")[2].startswith(hex_part)
            and (algo_prefix is None or identity.startswith(f"{algo_prefix}:"))
        ]

        if len(matches) == 1:
            return matches[0]
        if len(matches) == 0:
            raise MilpaError(
                CAS_NOT_IN_STORE,
                f"no store entry matches prefix {prefix!r}",
                prefix=prefix,
            )
        # >1 match → ambiguous
        raise MilpaError(
            STORE_AMBIGUOUS_PREFIX,
            f"prefix {prefix!r} matches {len(matches)} store entries "
            f"(need a longer prefix to disambiguate): "
            + ", ".join(m[:20] + "…" for m in matches[:4]),
            prefix=prefix,
            matches=[m for m in matches],
        )

    # ------------------------------------------------------------------
    # §3.3 — admit
    # ------------------------------------------------------------------

    def admit(self, src: Path, identity: str) -> Path:
        """Move *src* into the store under *identity*, returning the canonical path.

        Semantics (identity.md §3.3):
        1. Compute the content hash of *src* and compare to *identity*.
           On mismatch, raise ``CAS-IDENTITY-MISMATCH`` and leave *src* in
           place (store is NOT modified).
        2. **CAS-hit pre-check (idempotency)**: if the canonical entry already
           exists, drop *src* and return the existing path immediately — O(1),
           no rename attempted.  This is the **duplicate-admission = no-op** rule
           (identity.md §3.3 / C-admit-idem).
           We trust identity = content hash: same identity ⟹ same bytes, so
           we never re-copy or compare bytes on a hit.
        3. ``mkdir -p <root>/<algorithm>/`` (the parent of the canonical entry).
        4. Atomic ``rename(2)`` of *src* to the canonical path.
        5. TOCTOU race guard: if the rename raises ``OSError`` because another
           process admitted the same identity between step 2 and step 4, fold
           into the CAS-hit path — remove *src*, return existing canonical.
           If the canonical entry is NOT present after the rename fails, a
           genuine I/O error occurred; re-raise.
        6. Return the canonical path.

        The rename is atomic because *src* MUST reside under
        ``<root>/_scratch/`` (same filesystem mount as the CAS entries).  See
        ``scratch()`` for the scratch lifecycle.
        """
        actual = compute_content_hash(src)
        if actual != identity:
            raise MilpaError(
                CAS_IDENTITY_MISMATCH,
                f"identity mismatch — claimed {identity!r}, computed {actual!r}",
                claimed=identity,
                actual=actual,
            )

        canonical = self.path_for(identity)

        # CAS-hit pre-check (C-admit-idem): if the canonical entry already exists,
        # this is a successful no-op — the store already holds these bytes under
        # this identity.  Drop src and return the existing path.  O(1): no rename
        # attempted.  We trust identity = content hash; no byte comparison needed.
        if canonical.is_dir():
            shutil.rmtree(src, ignore_errors=True)
            return canonical

        canonical.parent.mkdir(parents=True, exist_ok=True)

        try:
            src.rename(canonical)
        except OSError:
            # TOCTOU race: another process admitted the same identity between the
            # pre-check above and this rename.  If canonical is now present, our
            # src is redundant — fold into the CAS-hit path.  If canonical is
            # still absent, a genuine I/O error occurred; re-raise.
            if canonical.is_dir():
                shutil.rmtree(src, ignore_errors=True)
            else:
                raise

        return canonical

    # ------------------------------------------------------------------
    # §3.5 / §3.6 — link
    # ------------------------------------------------------------------

    def link(self, identity: str, target: Path) -> None:
        """Create a **relative** symlink at *target* pointing to the CAS entry.

        Semantics (identity.md §3.5, §3.6):
        - Raises ``CAS-NOT-IN-STORE`` if *identity* has no entry; never creates
          a dangling symlink.
        - Clears a stale *target* (any shape) before creating the new symlink,
          making re-linking idempotent.
        - The symlink target is a path **relative** from *target*'s parent
          directory to the CAS entry.  Relative symlinks remain valid when the
          project tree is bind-mounted at a different absolute path (e.g., host
          ``/home/x/proj`` mounted as ``/work`` in a container).
        """
        canonical = self.path_for(identity)
        if not canonical.is_dir():
            raise MilpaError(
                CAS_NOT_IN_STORE,
                f"cannot link {target} → {identity}: not in store",
                identity=identity,
                target=str(target),
            )
        _clear_dest(target)
        rel = os.path.relpath(canonical, start=target.parent)
        target.symlink_to(rel, target_is_directory=True)

    # ------------------------------------------------------------------
    # §3.4 — scratch lifecycle
    # ------------------------------------------------------------------

    @contextmanager
    def scratch(self) -> Generator[ScratchDir, None, None]:
        """Context manager that allocates and cleans up a unique scratch subdirectory.

        The scratch directory is created under ``<root>/_scratch/<uuid>/``.
        On exit — whether normal, via ``Exception``, or via ``BaseException``
        (``KeyboardInterrupt``, ``SystemExit``) — the directory is removed.
        Only ``SIGKILL`` (which terminates the process without running finally
        blocks) can leave an orphaned entry.

        Usage::

            with store.scratch() as scratch:
                # fetch into scratch.path …
                store.admit(scratch.path / "pkg", identity)
        """
        scratch_root = self.root / "_scratch"
        scratch_root.mkdir(parents=True, exist_ok=True)
        scratch_path = scratch_root / uuid.uuid4().hex
        scratch_path.mkdir()
        sd = ScratchDir(path=scratch_path)
        try:
            yield sd
        except BaseException:
            shutil.rmtree(scratch_path, ignore_errors=True)
            raise
        else:
            shutil.rmtree(scratch_path, ignore_errors=True)


# ---------------------------------------------------------------------------
# §3.2 — default_store (tiers 1, 3, 4)
# ---------------------------------------------------------------------------


def default_store() -> CAStore:
    """Locate the host CAS root using tiers 1, 3, and 4 of the precedence list.

    Tier 2 (manifest ``cas { dir }`` override) is NOT applied here; it is
    applied by the CLI/resolver, which has access to the parsed manifest.

    Precedence (identity.md §3.2):
      Tier 1: ``MILPA_CACHE_DIR`` env var — explicit override (tests, sandboxes).
              Non-empty value used verbatim; empty string is ignored.
      Tier 2: manifest ``cas { dir }`` — NOT this function.
      Tier 3: ``$XDG_CACHE_HOME/milpa/cas`` — XDG standard.
              Non-empty ``XDG_CACHE_HOME`` fires; empty string is ignored.
      Tier 4: ``~/.cache/milpa/cas`` — final fallback.
    """
    override = os.environ.get("MILPA_CACHE_DIR", "")
    if override:
        return CAStore(Path(override))

    xdg = os.environ.get("XDG_CACHE_HOME", "")
    if xdg:
        return CAStore(Path(xdg) / "milpa" / "cas")

    return CAStore(Path.home() / ".cache" / "milpa" / "cas")
