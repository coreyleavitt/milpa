"""Mocked transport fetchers + mocked_registry factory — spec/conformance-fixtures.md §2.3.

Slice 7c per docs/rfc-python-clean-room-rewrite.md.

This module provides:

1. ``url_key(url, ref_spec)`` — the **single source of truth** (SSOT) key encoder
   that maps a ``(url, ref_spec)`` pair to a ``mocked-fetches/`` subdirectory name.
   Matches the Rust ``url_key`` byte-for-byte (conformance-fixtures.md §2.3.1
   NORMATIVE).

2. **Per-kind mocked fetchers**:
   - ``MockedGitFetcher``     — reads sha + content from ``mocked-fetches/<url_key>/``
   - ``MockedTarballFetcher`` — reads archive_sha256 + content (§2.3.4)
   - ``MockedLocalFetcher``   — copies content from ``mocked-fetches/<url_key>/``
   - ``MockedOciFetcher``     — stub (no OCI fixtures defined at v1)

   Each implements ``can_handle`` + ``fetch`` once; the ``FetcherRegistry``'s
   existing unique-match dispatch routes to it.  No ``match`` on provenance kind
   inside a single fat fetcher — that would duplicate the registry's own dispatch
   (rfc-python-clean-room-rewrite.md §4.5).

3. ``mocked_registry(mocked_dir)`` — factory that builds a ``FetcherRegistry``
   with all four fakes pre-registered.  The conformance adapter wraps this in
   ``CasAdmittingFetcher`` for the in-process path.

Concrete Provenance / Receipt subclasses are defined in their canonical
transport modules and re-exported here for convenience:
  - ``GitProvenance`` / ``GitReceipt``         — milpa.fetchers.git
  - ``TarballProvenance`` / ``TarballReceipt`` — milpa.fetchers.tarball
  - ``LocalProvenance`` / ``LocalReceipt``     — milpa.fetchers.local
  - ``OciProvenance`` / ``OciReceipt``         — milpa.fetchers.oci

Spec authority: spec/conformance-fixtures.md §2.3, spec/plugin-contract.md §4.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from milpa.errors import FETCH_MOCK_MISSING, FETCH_SHA256_MISMATCH, MilpaError
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.fetchers.local import LocalProvenance, LocalReceipt
from milpa.fetchers.oci import OciProvenance, OciReceipt
from milpa.fetchers.tarball import TarballProvenance, TarballReceipt
from milpa.fetchers.types import (
    Fetcher,
    FetcherRegistry,
    Provenance,
)

# ---------------------------------------------------------------------------
# url_key — SSOT key encoder (conformance-fixtures.md §2.3.1 NORMATIVE)
# ---------------------------------------------------------------------------

_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]")


def url_key(url: str, ref_spec: str) -> str:
    """Encode ``(url, ref_spec)`` to the ``mocked-fetches/`` subdirectory name.

    Rule (conformance-fixtures.md §2.3.1 NORMATIVE):
      - Apply ``re.sub(r'[^A-Za-z0-9._-]', '_', url)`` to the URL portion.
      - Append the literal ``@`` separator (NOT substituted).
      - Apply the same substitution to ``ref_spec``.

    The ``@`` separator is literal.  A ``@`` *within* the ref is replaced by
    ``_`` like any other unsafe character.  Only the single separator between
    url and ref is the literal ``@``.

    This is the **production SSOT** — all four mocked fetchers and the
    conformance adapter derive the fixture directory name from this function.
    Matches the Rust ``url_key`` output byte-for-byte.

    Examples::

        url_key("https://github.com/example/foo.git", "main")
        →  "https___github.com_example_foo.git@main"

        url_key("https://example.com/pkg.tar.gz", "")
        →  "https___example.com_pkg.tar.gz@"   # tarball: empty ref slot
    """
    return f"{_SAFE_CHARS.sub('_', url)}@{_SAFE_CHARS.sub('_', ref_spec)}"


# ---------------------------------------------------------------------------
# Stage helper — shared by all mocked fetchers
# ---------------------------------------------------------------------------


def _stage_mock_content(name: str, key_dir: Path, dest: Path) -> None:
    """Copy ``content/`` verbatim and ``<name>.nimble`` (if present) into ``dest``.

    Mirrors the Rust ``stage_mock_content`` function (the byte-staging SSOT).

    ``dest`` MUST already exist as a directory.  Files from ``content/`` are
    copied recursively; ``<name>.nimble`` is placed at the root of ``dest``.
    """
    content = key_dir / "content"
    if content.is_dir():
        for src in content.rglob("*"):
            if src.is_file():
                rel = src.relative_to(content)
                tgt = dest / rel
                tgt.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, tgt)

    nimble_src = key_dir / f"{name}.nimble"
    if nimble_src.is_file():
        shutil.copy2(nimble_src, dest / f"{name}.nimble")


# ---------------------------------------------------------------------------
# MockedGitFetcher
# ---------------------------------------------------------------------------


class MockedGitFetcher(Fetcher):
    """Mocked git fetcher — satisfies git fetches offline from the fixture tree.

    Reads ``mocked-fetches/<url_key(url, ref)>/`` per conformance-fixtures.md §2.3.2:
      1. ``sha`` — the commit SHA to return in the receipt.
      2. ``content/`` — source tree staged into ``dest``.
      3. ``<name>.nimble`` (optional) — placed at the root of ``dest``.

    Raises ``FETCH-MOCK-MISSING`` if the key directory does not exist.
    """

    def __init__(self, mocked_dir: Path) -> None:
        self._dir = mocked_dir

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, GitProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> GitReceipt:
        assert isinstance(p, GitProvenance)  # narrowing; can_handle enforces

        key_dir = self._dir / url_key(p.url, p.ref)
        if not key_dir.is_dir():
            raise MilpaError(
                FETCH_MOCK_MISSING,
                f"mocked fetch: no git fixture for {p.url!r} @ {p.ref!r} "
                f"(expected dir: {key_dir})",
                dep=name,
                url=p.url,
                ref=p.ref,
            )

        sha_file = key_dir / "sha"
        if not sha_file.is_file():
            raise MilpaError(
                FETCH_MOCK_MISSING,
                f"mock fixture: cannot read {sha_file}: file not found",
                dep=name,
            )
        commit_sha = sha_file.read_text(encoding="utf-8").strip()

        dest.mkdir(parents=True, exist_ok=True)
        _stage_mock_content(name, key_dir, dest)
        return GitReceipt(commit_sha=commit_sha)


# ---------------------------------------------------------------------------
# MockedTarballFetcher
# ---------------------------------------------------------------------------


class MockedTarballFetcher(Fetcher):
    """Mocked tarball fetcher — satisfies tarball fetches offline (§2.3.4).

    Key is ``url_key(url, "")`` — tarballs have no ref, so the ref slot is
    always empty (``<san(url)>@``).

    Reads ``archive_sha256`` for the mock archive digest.  If the provenance
    carries an ``expected_sha256`` pin (TOFU re-assertion from a prior lockfile),
    the mock compares it against ``archive_sha256`` and raises
    ``FETCH-SHA256-MISMATCH`` on mismatch — before staging any content — exactly
    mirroring the real ``TarballFetcher`` (conformance-fixtures.md §2.3.4).
    """

    def __init__(self, mocked_dir: Path) -> None:
        self._dir = mocked_dir

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, TarballProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> TarballReceipt:
        assert isinstance(p, TarballProvenance)  # narrowing

        key_dir = self._dir / url_key(p.url, "")
        if not key_dir.is_dir():
            raise MilpaError(
                FETCH_MOCK_MISSING,
                f"mocked fetch: no tarball fixture for {p.url!r} "
                f"(expected dir: {key_dir})",
                dep=name,
                url=p.url,
            )

        sha_file = key_dir / "archive_sha256"
        if not sha_file.is_file():
            raise MilpaError(
                FETCH_MOCK_MISSING,
                f"mock fixture: cannot read {sha_file}: file not found",
                dep=name,
            )
        archive_sha = sha_file.read_text(encoding="utf-8").strip()

        # TOFU pin re-assertion: if a prior lock recorded an expected sha256,
        # compare before staging (conformance-fixtures.md §2.3.4 NORMATIVE).
        if p.expected_sha256 is not None:
            want = p.expected_sha256.removeprefix("sha256:")
            if want != archive_sha:
                raise MilpaError(
                    FETCH_SHA256_MISMATCH,
                    f"mocked fetch {name!r}: archive sha256 mismatch — "
                    f"expected {p.expected_sha256!r}, got {archive_sha!r} (URL {p.url})",
                    dep=name,
                    expected=p.expected_sha256,
                    actual=archive_sha,
                )

        dest.mkdir(parents=True, exist_ok=True)
        _stage_mock_content(name, key_dir, dest)
        return TarballReceipt(archive_sha256=archive_sha)


# ---------------------------------------------------------------------------
# MockedLocalFetcher
# ---------------------------------------------------------------------------


class MockedLocalFetcher(Fetcher):
    """Mocked local-path fetcher — stages content from the fixture tree.

    Local deps are identified by their path.  The mock key is
    ``url_key(path, "")`` (local paths have no ref; the ``path`` value is used
    as the ``url`` slot in the key encoder).

    Note: local fetches are NOT CAS-admitted (``LocalProvenance.cas_admissible
    = False``); ``CasAdmittingFetcher`` passes them through to a real directory.
    """

    def __init__(self, mocked_dir: Path) -> None:
        self._dir = mocked_dir

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, LocalProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> LocalReceipt:
        assert isinstance(p, LocalProvenance)  # narrowing

        key_dir = self._dir / url_key(str(p.path), "")
        if not key_dir.is_dir():
            raise MilpaError(
                FETCH_MOCK_MISSING,
                f"mocked fetch: no local fixture for path {p.path!r} "
                f"(expected dir: {key_dir})",
                dep=name,
                path=str(p.path),
            )

        dest.mkdir(parents=True, exist_ok=True)
        _stage_mock_content(name, key_dir, dest)
        return LocalReceipt(resolved_path=p.path)


# ---------------------------------------------------------------------------
# MockedOciFetcher (stub — no OCI fixtures defined at v1)
# ---------------------------------------------------------------------------


class MockedOciFetcher(Fetcher):
    """Mocked OCI fetcher — stub until OCI fixtures are defined at v1+.

    Raises ``FETCH-MOCK-MISSING`` for every OCI fetch attempt; no fixture
    layout is specified for OCI at v1.  This stub exists so ``mocked_registry``
    covers all four transport kinds and the registry's exclusive-dispatch
    invariant is satisfied for ``OciProvenance`` inputs.
    """

    def __init__(self, mocked_dir: Path) -> None:
        self._dir = mocked_dir

    def can_handle(self, p: Provenance) -> bool:
        return isinstance(p, OciProvenance)

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> OciReceipt:
        assert isinstance(p, OciProvenance)  # narrowing
        raise MilpaError(
            FETCH_MOCK_MISSING,
            f"mocked fetch: OCI fixtures are not defined at v1 — "
            f"no mock for {p.registry}/{p.repository}@{p.digest}",
            dep=name,
            registry=p.registry,
            repository=p.repository,
            digest=p.digest,
        )


# ---------------------------------------------------------------------------
# mocked_registry factory
# ---------------------------------------------------------------------------


def mocked_registry(mocked_dir: Path) -> FetcherRegistry:
    """Build a ``FetcherRegistry`` populated with per-kind mocked fetchers.

    Each of the four transport kinds (git, tarball, local, OCI) is covered by
    one fake fetcher that reads fixture content from ``mocked_dir``.  No network
    operations are performed; all content is staged from the fixture tree.

    The returned registry is a plain ``FetcherRegistry``; the conformance
    adapter wraps it in ``CasAdmittingFetcher`` for the in-process path
    (rfc-python-clean-room-rewrite.md §4.5).

    Parameters
    ----------
    mocked_dir:
        The ``mocked-fetches/`` directory from the fixture tree (or
        ``$MILPA_MOCKED_FETCHES``).  Each subdirectory under it is a
        per-URL fixture keyed by ``url_key`` (§2.3.1).
    """
    registry = FetcherRegistry()
    registry.register(MockedGitFetcher(mocked_dir))
    registry.register(MockedTarballFetcher(mocked_dir))
    registry.register(MockedLocalFetcher(mocked_dir))
    registry.register(MockedOciFetcher(mocked_dir))
    return registry


__all__ = [
    # SSOT key encoder
    "url_key",
    # Provenance kinds (re-exported from canonical transport modules)
    "GitProvenance",
    "TarballProvenance",
    "LocalProvenance",
    "OciProvenance",
    # Receipt types (re-exported from canonical transport modules)
    "GitReceipt",
    "TarballReceipt",
    "LocalReceipt",
    "OciReceipt",
    # Mocked fetchers
    "MockedGitFetcher",
    "MockedTarballFetcher",
    "MockedLocalFetcher",
    "MockedOciFetcher",
    # Factory
    "mocked_registry",
]
