"""Global content-addressed store (#35).

Bytes are indexed by their content hash and materialized exactly once
per host under <root>/<algorithm>/<hex>/. Projects reference shared
trees by symlink from _deps/<name>/.

See docs/rfc-content-addressed-identity.md Phase C.
"""

import os
import shutil
from pathlib import Path

from .identity import compute_content_hash, parse_identity


class CASError(Exception):
    """Raised on store-integrity violations (identity mismatch, etc.)."""


class CAStore:
    """On-disk content-addressed store.

    Layout: <root>/<algorithm>/<hex>/<tree-contents>

    The store is concurrency-safe across processes via POSIX rename(2):
    admit() commits a scratch tree atomically; duplicate admissions
    are no-ops.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    def path_for(self, identity: str) -> Path:
        """Canonical path for `identity`. May or may not exist."""
        parse_identity(identity)
        algo, _, hex_digest = identity.partition(":")
        return self.root / algo / hex_digest

    def contains(self, identity: str) -> bool:
        """True iff the store already holds an entry for `identity`."""
        return self.path_for(identity).is_dir()

    def admit(self, src: Path, identity: str) -> Path:
        """Move `src` into the store under `identity`, returning the
        canonical path. Verifies src's bytes hash to `identity` before
        admission; raises CASError on mismatch (src is left in place
        for the caller to inspect / clean up).

        Duplicate admissions are no-ops: if the canonical entry already
        exists, src is removed and the existing path is returned.
        """
        actual = compute_content_hash(src)
        if actual != identity:
            raise CASError(
                f"identity mismatch — claimed {identity!r}, "
                f"computed {actual!r}"
            )
        canonical = self.path_for(identity)
        canonical.parent.mkdir(parents=True, exist_ok=True)
        try:
            src.rename(canonical)
        except OSError:
            # Lost the race (or destination pre-existed). Either way the
            # canonical entry is now populated; drop our scratch.
            if canonical.is_dir():
                shutil.rmtree(src, ignore_errors=True)
            else:
                raise
        return canonical

    def link(self, identity: str, target: Path) -> None:
        """Create a symlink at `target` resolving to the CAS entry for
        `identity`. If `target` already exists, it is replaced
        (idempotent re-linking).

        The stored symlink target is **relative** to the symlink's
        directory, not an absolute host path. This keeps `_deps/<name>`
        symlinks valid when the project tree is bind-mounted into a
        container at a different path (e.g., host `/home/x/proj` mounted
        as `/work` inside the container)."""
        canonical = self.path_for(identity)
        if not canonical.is_dir():
            raise CASError(
                f"cannot link {target} → {identity}: not in store"
            )
        if target.is_symlink() or target.exists():
            if target.is_symlink() or target.is_file():
                target.unlink()
            else:
                shutil.rmtree(target)
        rel = os.path.relpath(canonical, start=target.parent)
        target.symlink_to(rel, target_is_directory=True)


def default_store() -> CAStore:
    """Locate the host's CAS root.

    Precedence:
      1. MILPA_CACHE_DIR — explicit override (tests, sandboxes)
      2. XDG_CACHE_HOME/milpa/cas — XDG standard
      3. ~/.cache/milpa/cas — fallback
    """
    override = os.environ.get("MILPA_CACHE_DIR")
    if override:
        return CAStore(root=Path(override))
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return CAStore(root=Path(xdg) / "milpa" / "cas")
    return CAStore(root=Path.home() / ".cache" / "milpa" / "cas")
