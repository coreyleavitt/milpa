"""LocalFetcher — local filesystem source tree delivery (slice 7d-4).

Handles ``LocalProvenance(path)`` where ``path`` is an absolute filesystem
path to an existing source tree.

Design:
  - ``cas_admissible = False``: local trees are editable; admitting them to
    the CAS would silently freeze user edits (plugin-contract.md §4 NORMATIVE).
    ``CasAdmittingFetcher`` reads this flag and skips CAS admission, keeping
    the dep pointed at the live source directory.
  - **No copy**: the source tree stays in place.  ``dest`` is made to point at
    the source directory via a symlink so the registry can compute identity from
    the materialized path.  Moving or copying would be wrong — the user expects
    to edit the source in-place and have ``milpa fetch`` pick up changes.
  - **No network**: entirely local filesystem I/O.

Receipt:
  ``LocalReceipt.resolved_path`` — the absolute source path used for this
  fetch.  It identifies the transport artifact (the filesystem path), not the
  source-tree hash (plugin-contract.md §3.1 NORMATIVE).

Error mapping:
  - source path does not exist → MilpaError(FETCH_LOCAL_PATH_NOT_FOUND)
  - source path exists but is not a directory → MilpaError(FETCH_LOCAL_PATH_NOT_DIR)
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from milpa.errors import (
    FETCH_LOCAL_PATH_NOT_DIR,
    FETCH_LOCAL_PATH_NOT_FOUND,
    MilpaError,
)
from milpa.fetchers.types import Fetcher, Provenance, ProvenanceReceipt

# ---------------------------------------------------------------------------
# LocalProvenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LocalProvenance(Provenance):
    """Provenance descriptor for a local-filesystem source tree.

    ``path`` must be an absolute path; relative paths are rejected at
    construction — relative-to-project resolution is the caller's
    responsibility (typically the resolver, which knows the project root).

    ``cas_admissible = False`` (NORMATIVE, §4): local trees are editable
    sources.  Admitting them to the CAS would silently freeze user edits;
    the CAS entry would be immutable while the user's source continues to
    change.
    """

    path: Path
    cas_admissible: ClassVar[bool] = False  # noqa: RUF012  # editable source; override default True

    def __post_init__(self) -> None:
        if not self.path.is_absolute():
            raise ValueError(
                f"LocalProvenance.path must be absolute, got {self.path!r}"
            )


# ---------------------------------------------------------------------------
# LocalReceipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LocalReceipt(ProvenanceReceipt):
    """Transport receipt for a successful local-path fetch.

    ``resolved_path`` — the absolute source directory path.  This identifies
    the transport artifact (filesystem path), NOT the source-tree identity hash
    (plugin-contract.md §3.1 NORMATIVE: tree hashes are forbidden in receipts).
    """

    resolved_path: Path

    def transport_fields(self) -> dict[str, str]:
        return {"resolved_path": str(self.resolved_path)}


# ---------------------------------------------------------------------------
# LocalFetcher
# ---------------------------------------------------------------------------


class LocalFetcher(Fetcher):
    """Expose a local filesystem source tree under ``dest/`` without copying it.

    Satisfies the three plugin-contract obligations (§1):
      1. Claim: ``can_handle`` returns ``True`` for ``LocalProvenance`` only.
      2. Materialize: ``fetch`` makes ``dest`` point at the source directory
         (via symlink) so the registry can compute identity on the materialized
         path.  The source directory is NOT moved or copied.
      3. Receipt: returns ``LocalReceipt(resolved_path=<absolute source path>)``
         recording the filesystem path, not a tree hash.

    ``cas_admissible = False`` on ``LocalProvenance`` tells ``CasAdmittingFetcher``
    to skip CAS admission — the dep stays as a live pointer to the source tree.
    """

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, LocalProvenance)

    def fetch(
        self,
        name: str,
        p: Provenance,
        *,
        dest: Path,
    ) -> LocalReceipt:
        assert isinstance(p, LocalProvenance)

        # --- validate source ----------------------------------------------
        if not p.path.exists():
            raise MilpaError(
                FETCH_LOCAL_PATH_NOT_FOUND,
                f"fetching {name!r}: local source path does not exist: {p.path}",
                dep=name,
                path=str(p.path),
            )
        if not p.path.is_dir():
            raise MilpaError(
                FETCH_LOCAL_PATH_NOT_DIR,
                f"fetching {name!r}: local source path is not a directory: {p.path}",
                dep=name,
                path=str(p.path),
            )

        # --- expose source tree under dest --------------------------------
        # Remove dest if it already exists (stale dir / stale symlink from a
        # previous fetch run) so we can create a fresh symlink.
        if dest.exists() or dest.is_symlink():
            if dest.is_symlink():
                dest.unlink()
            else:
                shutil.rmtree(dest)
        dest.symlink_to(p.path.resolve())

        return LocalReceipt(resolved_path=p.path)
