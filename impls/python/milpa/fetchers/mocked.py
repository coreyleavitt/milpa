"""MockedFetcher — deterministic fixture transport for conformance testing.

Activated via the `MILPA_MOCKED_FETCHES=<dir>` env var. Every dep fetch is
satisfied from `<dir>/<url@ref-key>/` per spec/conformance-fixtures.md §2.3.

Key encoding rule (§2.3.1):
    re.sub(r'[^A-Za-z0-9._-]', '_', url) + '@' + re.sub(r'[^A-Za-z0-9._-]', '_', ref)

On a missing key, raises FetchError with code "FETCH-MOCK-MISSING" so the CLI
exits 1 with a terminal `milpa-error: FETCH-MOCK-MISSING` line (Gap-1).
No network access is performed.
"""

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from .git import GitProvenance, GitReceipt
from .types import FetchError, Provenance, ProvenanceReceipt


def url_key(url: str, ref: str) -> str:
    """Encode a (url, ref) pair to a mocked-fetches subdirectory name.

    Applies re.sub(r'[^A-Za-z0-9._-]', '_', url) then appends '@' and the
    same encoding of ref (spec/conformance-fixtures.md §2.3.1).
    """
    encoded_url = re.sub(r"[^A-Za-z0-9._-]", "_", url)
    encoded_ref = re.sub(r"[^A-Za-z0-9._-]", "_", ref)
    return f"{encoded_url}@{encoded_ref}"


@dataclass
class MockedFetcher:
    """Fake Fetcher backed by a mocked-fetches/ directory.

    For each fetch call it:
    1. Encodes (url, ref) to a subdirectory key via url_key().
    2. Reads sha from <key>/sha (strip whitespace).
    3. Copies content/ tree into dest.
    4. Copies <name>.nimble into dest if present.
    5. Returns GitReceipt(commit_sha=sha).

    Handles only GitProvenance (what the conformance corpus uses). On an
    unhandled provenance kind, can_handle() returns False so the registry
    will raise the standard "no registered fetcher" error.

    Missing key → FetchError(code="FETCH-MOCK-MISSING").
    """

    mocked_fetches_dir: Path

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, GitProvenance)

    def fetch(
        self,
        name: str,
        p: Provenance,
        *,
        dest: Path,
    ) -> ProvenanceReceipt:
        assert isinstance(p, GitProvenance)
        key = url_key(p.url, p.ref)
        key_dir = self.mocked_fetches_dir / key
        if not key_dir.is_dir():
            raise FetchError(
                f"mocked transport: no entry for {p.url!r} @ {p.ref!r} "
                f"(expected dir: {key_dir})",
                code="FETCH-MOCK-MISSING",
            )
        sha_text = (key_dir / "sha").read_text().strip()
        dest.mkdir(parents=True, exist_ok=True)
        # Copy content/ tree into dest
        content_dir = key_dir / "content"
        if content_dir.is_dir():
            for item in content_dir.iterdir():
                if item.is_file():
                    shutil.copy2(item, dest / item.name)
                elif item.is_dir():
                    shutil.copytree(item, dest / item.name)
        # Copy <name>.nimble if present (sibling of content/, not inside it)
        nimble_src = key_dir / f"{name}.nimble"
        if nimble_src.is_file():
            shutil.copy2(nimble_src, dest / f"{name}.nimble")
        return GitReceipt(commit_sha=sha_text)
