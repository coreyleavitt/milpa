"""TarballFetcher — download an archive, verify integrity, extract
into dest. Used for HTTPS / file:// tarball deps (F2 / #41).

Verification model:
  - If TarballProvenance.expected_sha256 is set: download archive,
    sha256 it, reject (FetchError) if mismatch — BEFORE extraction.
    Pre-fetch integrity check is the whole point of using tarballs
    over git (you can't cryptographically verify a git tag before
    cloning).
  - If expected_sha256 is None (TOFU): download + extract + record
    the computed hash on the TarballReceipt for the lockfile to
    pin. Subsequent fetches with the lockfile's recorded hash
    behave as the pre-declared case.

Identity invariant (F1): TarballFetcher returns only a
TarballReceipt; the registry computes content_hash from the
extracted source tree. The archive sha256 is provenance receipt
(what we downloaded); the source-tree content_hash is identity
(what we have on disk).

Extraction goes through `safe_extract.extract_tar`, which defends
against zip-slip, symlink-escape, decompression bombs, and
excessive file counts.
"""

import hashlib
import shutil
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .safe_extract import ExtractionError, extract_tar
from .types import FetchError, Provenance, ProvenanceReceipt


@dataclass(frozen=True)
class TarballProvenance(Provenance):
    """Tarball at a URL with optional pre-declared integrity hash.

    `expected_sha256`, when set, is verified against the downloaded
    archive BEFORE extraction (rejects tampered bytes without
    creating any files at dest).

    `strip_components` removes leading path components from each
    entry (cf. `tar --strip-components=N`). Default 0; the github-
    tarball idiom of "everything under <repo>-<sha>/" needs 1.
    """
    url: str
    expected_sha256: str | None = None
    strip_components: int = 0


@dataclass(frozen=True)
class TarballReceipt(ProvenanceReceipt):
    """What TarballFetcher recorded about a fetch:
    - archive_sha256: the sha256 of the downloaded archive bytes
      (provenance receipt, NOT identity — milpa hashes the extracted
      source tree separately for identity)
    - extracted_bytes / extracted_file_count: ExtractionResult stats,
      useful for diagnostic + cap-tuning over time
    """
    archive_sha256: str
    extracted_bytes: int
    extracted_file_count: int


class TarballFetcher:
    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, TarballProvenance)

    def fetch(
        self,
        name: str,
        p: Provenance,
        *,
        dest: Path,
    ) -> TarballReceipt:
        assert isinstance(p, TarballProvenance)

        # Download to a temp file. We can't stream-extract because
        # we need to verify the full archive's sha256 before any
        # extraction begins.
        with tempfile.NamedTemporaryFile(
            suffix=".tar.gz", delete=False,
        ) as tmp:
            tmp_path = Path(tmp.name)
        try:
            try:
                _download(p.url, tmp_path)
            except (urllib.error.URLError, FileNotFoundError, OSError) as e:
                raise FetchError(
                    f"fetching {name!r}: cannot download tarball from "
                    f"{p.url}: {e}"
                )

            archive_sha = _sha256_file(tmp_path)
            if p.expected_sha256 is not None and archive_sha != p.expected_sha256:
                raise FetchError(
                    f"fetching {name!r}: archive sha256 mismatch — "
                    f"expected {p.expected_sha256}, got {archive_sha} "
                    f"(URL {p.url}); rejected BEFORE extraction"
                )

            # Extract into dest under safe-extraction caps.
            if dest.exists():
                shutil.rmtree(dest)
            try:
                result = extract_tar(
                    tmp_path, dest,
                    strip_components=p.strip_components,
                )
            except ExtractionError as e:
                # Clean up partial extraction state.
                if dest.exists():
                    shutil.rmtree(dest, ignore_errors=True)
                raise FetchError(
                    f"fetching {name!r}: archive from {p.url} failed "
                    f"safe extraction: {e}"
                )

            return TarballReceipt(
                archive_sha256=archive_sha,
                extracted_bytes=result.total_bytes,
                extracted_file_count=result.file_count,
            )
        finally:
            tmp_path.unlink(missing_ok=True)


def _download(url: str, dest: Path) -> None:
    """Stream a URL to a local file. Handles file://, http://, https://."""
    with urllib.request.urlopen(url) as response, dest.open("wb") as out:
        shutil.copyfileobj(response, out)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()
