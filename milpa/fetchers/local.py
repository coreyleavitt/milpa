"""LocalFetcher — copies a local-filesystem source tree into dest.

For workspace use cases (e.g. fresco depending on intonaco at
`../intonaco` during development) the manifest declares the dep with
`local="../intonaco"`. The resolver resolves the path against project
root and constructs a LocalProvenance with an absolute Path.

Copy semantics: dest is a snapshot taken at fetch time. Identity is
stable until the next `milpa fetch`. If source drifts between fetches,
re-running `milpa fetch` updates dest (and lockfile); `milpa verify`
flags the mismatch as drift, same as any other transport.

Symlink semantics (live view of source) is deferred — see issue #42
and rfc-pluggable-fetchers.md.
"""

from dataclasses import dataclass
from pathlib import Path
import shutil

from ..fsutil import clear_dest
from .types import FetchError, Provenance, ProvenanceReceipt


@dataclass(frozen=True)
class LocalProvenance(Provenance):
    """Source tree at an absolute filesystem path.

    Relative paths are rejected at construction — relative-to-project
    resolution is the caller's responsibility (typically the resolver,
    which knows the project root). Keeping provenance values
    file-system-truthful prevents transport-time ambiguity about
    'relative to what'.
    """
    path: Path
    cas_admissible = False     # local trees stay editable (#35)

    def __post_init__(self):
        if not self.path.is_absolute():
            raise ValueError(
                f"LocalProvenance.path must be absolute, got {self.path!r}"
            )


@dataclass(frozen=True)
class LocalReceipt(ProvenanceReceipt):
    """What LocalFetcher recorded about a fetch: the absolute source
    path the tree was copied from."""
    source_path: Path

    def transport_fields(self) -> dict[str, str]:
        return {"source_path": str(self.source_path)}


class LocalFetcher:
    """Copies LocalProvenance.path into dest. Identity computed by the
    registry post-copy from the materialized tree."""

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
        if not p.path.exists():
            raise FetchError(
                f"fetching {name!r}: local source path does not exist: {p.path}",
                code="FETCH-LOCAL-PATH-NOT-FOUND",
            )
        if not p.path.is_dir():
            raise FetchError(
                f"fetching {name!r}: local source path is not a directory: {p.path}",
                code="FETCH-LOCAL-PATH-NOT-DIR",
            )
        # dest may be a stale symlink (e.g. proptest was a CAS-routed
        # url/git dep before the manifest switched it to local=, leaving
        # `_deps/proptest` pointing into the CAS). clear_dest unlinks it
        # without following into the CAS, where a plain rmtree would
        # raise on the symlink (#112).
        clear_dest(dest)
        shutil.copytree(p.path, dest, symlinks=True)
        return LocalReceipt(source_path=p.path)
