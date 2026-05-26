"""OCI artifact fetcher — pulls a tianguis-style source artifact via
oras, extracts the embedded tarball into dest.

Per tianguis #7 (R4). Pairs with `milpa publish` (which pushes the
same tar.gz under media type vnd.tianguis.source.v1.tar+gzip).

Identity is NOT computed here — FetcherRegistry walks dest after fetch
and computes content_hash externally, preserving the invariant that no
fetcher can influence the identity claim (#33).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from .safe_extract import extract_tar
from .types import FetchError, Provenance, ProvenanceReceipt


Runner = Callable[..., tuple[int, str, str]]


def _real_runner(argv: list[str], **kw: Any) -> tuple[int, str, str]:
    proc = subprocess.run(argv, capture_output=True, **kw)
    return (proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


@dataclass(frozen=True)
class OciProvenance(Provenance):
    """OCI artifact pinned by digest. `oci_ref` is the canonical
    `<registry>/<repo>@<digest>` form oras consumes."""
    registry: str = ""
    repository: str = ""
    digest: str = ""

    cas_admissible: ClassVar[bool] = True
    # `kind` is redundant with isinstance() but matches the index.kdl
    # schema where each provenance node carries `kind "oci"`. Lets
    # callers branch on a string without importing the class.
    kind: ClassVar[str] = "oci"

    @property
    def oci_ref(self) -> str:
        return f"{self.registry}/{self.repository}@{self.digest}"


@dataclass(frozen=True)
class OciReceipt(ProvenanceReceipt):
    """Per-fetch receipt for OCI pulls. Records what oras delivered
    (digest pulled from the registry)."""
    oci_digest: str


class OciFetcher:
    """Pulls an OCI artifact via oras + extracts its tarball into dest.

    Assumes the artifact contains exactly one *.tar.gz produced by
    `milpa publish` — that's the only shape tianguis publishes today.
    Future shapes (e.g. raw blobs, multi-layer) extend this fetcher
    rather than introducing new fetchers.
    """

    def __init__(self, runner: Runner = _real_runner) -> None:
        self._runner = runner

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, OciProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> OciReceipt:
        assert isinstance(p, OciProvenance)

        # Pull into a scratch dir; oras writes the artifact's named blobs
        # there. We then locate the source tarball and safe-extract it.
        with tempfile.TemporaryDirectory(prefix="milpa-oci-pull-") as scratch:
            scratch_path = Path(scratch)
            argv = ["oras", "pull", p.oci_ref, "--output", str(scratch_path)]
            code, out, err = self._runner(argv)
            if code != 0:
                raise FetchError(
                    f"oras pull failed for {name!r} ({p.oci_ref}): "
                    f"{err.strip() or out.strip()}"
                )

            tarballs = sorted(scratch_path.glob("*.tar.gz"))
            if not tarballs:
                raise FetchError(
                    f"OCI artifact {p.oci_ref} contained no *.tar.gz "
                    f"(found: {[str(p_) for p_ in scratch_path.iterdir()]})"
                )
            if len(tarballs) > 1:
                raise FetchError(
                    f"OCI artifact {p.oci_ref} contained multiple "
                    f"*.tar.gz files; ambiguous which to extract: "
                    f"{[t.name for t in tarballs]}"
                )

            if dest.exists():
                shutil.rmtree(dest)
            extract_tar(tarballs[0], dest)

        return OciReceipt(oci_digest=p.digest)
