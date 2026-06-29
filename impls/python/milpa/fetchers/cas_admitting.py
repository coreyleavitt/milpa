"""CAS-admitting fetcher wrapper — spec/plugin-contract.md §4, spec/identity.md §3.5.

Slice 7b per docs/rfc-python-clean-room-rewrite.md.

``CasAdmittingFetcher`` wraps a ``FetcherRegistry`` and gates CAS admission
on ``provenance.cas_admissible`` (plugin-contract.md §4 NORMATIVE):

- **Immutable sources** (``cas_admissible=True``): git, tarball, OCI, registry
  fetches are staged into a scratch directory via ``CAStore.scratch()`` (which
  allocates under ``<store.root>/_scratch/<uuid>/``), admitted atomically via
  ``CAStore.admit``, then symlinked at ``dest`` via ``CAStore.link``.  The
  symlink is relative so the tree remains valid under bind-mounts
  (identity.md §3.6).  ``CAStore.scratch()`` is the sole owner of the
  transient pre-admission staging area (C-stage).

- **Editable sources** (``cas_admissible=False``): local-path and workspace-
  member fetches write directly into ``dest`` as a real directory.  CAS
  admission is skipped — admitting would freeze user edits in place
  (plugin-contract.md §4, "editable sources MUST NOT be admitted").

This wrapper is the only place where ``cas_admissible`` is read; the plain
``FetcherRegistry`` (types.py) does not touch the CAS at all.  This mirrors
the Rust ``CasAdmittingFetcher<R>`` design (the canonical best-in-class
reference).

Public surface:
  - ``CasAdmittingFetcher`` — wraps a ``FetcherRegistry`` with CAS gating
"""

from __future__ import annotations

from pathlib import Path

from milpa.cas import CAStore
from milpa.errors import FETCH_DOWNLOAD_SIZE_EXCEEDED, MilpaError
from milpa.fetchers.safe_extract import Limits, _DEFAULT_LIMITS
from milpa.fetchers.types import FetcherRegistry, FetchResult, Provenance, _fetch_any


class CasAdmittingFetcher:
    """A ``FetcherRegistry``-compatible wrapper that gates CAS admission.

    Parameters
    ----------
    inner:
        The underlying ``FetcherRegistry`` that performs the actual fetch.
        Any registered fetcher is eligible; this wrapper adds the CAS
        admission layer on top.
    store:
        The ``CAStore`` instance to admit immutable sources into.

    Usage::

        registry = build_registry()
        store = default_store()
        cas_registry = CasAdmittingFetcher(registry, store)
        result = cas_registry.fetch("mypkg", git_prov, dest=deps_dir / "mypkg")
        # result.path is a symlink → store entry for cas_admissible provenances
        # result.path is a real dir for local/editable provenances
    """

    def __init__(
        self,
        inner: FetcherRegistry,
        store: CAStore,
        limits: Limits = _DEFAULT_LIMITS,
    ) -> None:
        self._inner = inner
        self._store = store
        self._limits = limits

    @property
    def inner(self) -> FetcherRegistry:
        """The underlying FetcherRegistry (no CAS, no side-effects).

        Used by ``milpa hash`` to fetch into a throwaway scratch directory
        and obtain the content identity without CAS admission.  The caller
        is responsible for discarding the scratch directory after use.
        """
        return self._inner

    def fetch(
        self,
        name: str,
        provenance: Provenance,
        *,
        dest: Path,
    ) -> FetchResult:
        """Fetch ``provenance`` and, if immutable, admit the result into the CAS.

        Steps for **cas-admissible** (immutable) provenances:

        1. Allocate a unique scratch directory via ``CAStore.scratch()`` under
           ``<store.root>/_scratch/<uuid>/`` (C-stage, identity.md §3.4).
           This directory is on the same filesystem as the CAS root, so the
           subsequent ``rename(2)`` in ``admit()`` is atomic (no EXDEV).
        2. Delegate to the inner registry with ``dest=scratch``.
        3. Admit the scratch tree via ``CAStore.admit(scratch, identity)``.
           (``admit`` verifies the hash before committing; a mismatch raises
           ``CAS-IDENTITY-MISMATCH`` — see note below.)
        4. Create a relative symlink at the original ``dest`` via
           ``CAStore.link(identity, dest)``.
        5. Return ``FetchResult`` with ``path=dest`` (the symlink) so callers
           see the canonical ``_deps/<name>`` location.

        ``CAStore.scratch()`` is the sole owner of transient staging space;
        it cleans up on both success and failure (C-stage rule: no leaked
        scratch after a successful admit).

        Steps for **non-admissible** (editable) provenances:

        1. Delegate directly to the inner registry with ``dest=dest``.
        2. Return the result unchanged (a real directory).

        Note on identity: ``CAStore.admit`` re-hashes the tree it receives to
        verify integrity before committing.  The ``FetchResult.identity`` from
        the inner registry and the hash computed by ``admit`` must agree; a
        mismatch raises ``CAS-IDENTITY-MISMATCH``.  This is a defence-in-depth
        check — under normal operation both traverse the same bytes.
        """
        if provenance.cas_admissible:
            # Immutable source: scratch → admit → symlink.
            # CAStore.scratch() allocates under <cas_root>/_scratch/<uuid>/ —
            # same filesystem as sha256/, guaranteeing atomic rename(2) in admit().
            with self._store.scratch() as scratch:
                result = self._inner.fetch(name, provenance, dest=scratch.path)

                # R1-07 — chokepoint stat (spec/plugin-contract.md §2.4.2 NORMATIVE):
                # Walk the staged tree, sum regular-file sizes, and reject before
                # hashing/admission if total exceeds the configured cap.
                # This is the uncompressed-tree analogue of the compressed-download cap
                # (FETCH-DOWNLOAD-SIZE-EXCEEDED is REUSED per finding R1-07: same slug,
                # second trigger site).
                _staged_total = sum(
                    f.stat().st_size
                    for f in scratch.path.rglob("*")
                    if f.is_file() and not f.is_symlink()
                )
                if _staged_total > self._limits.max_total_size:
                    raise MilpaError(
                        FETCH_DOWNLOAD_SIZE_EXCEEDED,
                        f"staged tree for {name!r} exceeds uncompressed size cap "
                        f"({_staged_total} bytes > {self._limits.max_total_size} bytes); "
                        f"rejected before CAS admission (plugin-contract.md §2.4.2)",
                        dep=name,
                        staged_total=_staged_total,
                        cap=self._limits.max_total_size,
                    )

                # admit() verifies hash + moves the scratch subdir atomically.
                # scratch() cleans up on exit (success or failure).
                self._store.admit(scratch.path, result.identity)

            # Create the relative CAS symlink at dest.
            self._store.link(result.identity, dest)

            # Return result with path=dest (the symlink), keeping identity
            # and receipt from the inner registry's fetch.
            return FetchResult(
                name=result.name,
                path=dest,
                identity=result.identity,
                receipt=result.receipt,
            )
        else:
            # Editable/local source: fetch directly into dest, no CAS.
            return self._inner.fetch(name, provenance, dest=dest)

    def fetch_any(
        self,
        name: str,
        candidates: list[Provenance],
        *,
        dest: Path,
        expected_identity: str | None = None,
    ) -> FetchResult:
        """Try each candidate provenance in order; admit the winner into the CAS.

        ``CasAdmittingFetcher`` is the single CAS-gating layer.  Every successful
        fetch through this wrapper MUST go through CAS admission (or the
        non-admissible fast path), regardless of whether it came from ``fetch`` or
        ``fetch_any``.  Bypassing this wrapper's gating and delegating directly to
        the inner registry would leave ``_deps/<name>`` as a plain directory with
        no CAS entry — an unsafe trap for future callers.

        Implementation: delegates to ``_fetch_any`` (the shared SSOT loop in
        types.py) passing ``self.fetch`` as ``fetch_one``.  This guarantees CAS
        admission is applied per-candidate, and that R1b (identity=None guard)
        and R7 (symlink-safe dest clearing) are enforced in one place.
        """
        return _fetch_any(
            name,
            candidates,
            dest=dest,
            expected_identity=expected_identity,
            fetch_one=self.fetch,
        )
