"""CAS-admitting fetcher wrapper — spec/plugin-contract.md §4, spec/identity.md §3.5.

Slice 7b per docs/rfc-python-clean-room-rewrite.md.

``CasAdmittingFetcher`` wraps a ``FetcherRegistry`` and gates CAS admission
on ``provenance.cas_admissible`` (plugin-contract.md §4 NORMATIVE):

- **Immutable sources** (``cas_admissible=True``): git, tarball, OCI, registry
  fetches are staged into a scratch directory inside the CAS root, admitted
  atomically via ``CAStore.admit``, then symlinked at ``dest`` via
  ``CAStore.link``.  The symlink is relative so the tree remains valid under
  bind-mounts (identity.md §3.6).

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

import shutil
import uuid
from pathlib import Path

from milpa.cas import CAStore
from milpa.fetchers.types import FetcherRegistry, FetchResult, Provenance


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

    def __init__(self, inner: FetcherRegistry, store: CAStore) -> None:
        self._inner = inner
        self._store = store

    def fetch(
        self,
        name: str,
        provenance: Provenance,
        *,
        dest: Path,
    ) -> FetchResult:
        """Fetch ``provenance`` and, if immutable, admit the result into the CAS.

        Steps for **cas-admissible** (immutable) provenances:

        1. Create a unique staging directory under ``<store.root>/_stage/``.
           This directory is on the same filesystem as the CAS root, so the
           subsequent ``rename(2)`` in ``admit()`` is atomic.
        2. Delegate to the inner registry with ``dest=staging``.
        3. Admit the staged tree via ``CAStore.admit(staging, identity)``.
           (``admit`` computes the hash itself; we pass the registry-computed
           hash to avoid a second traversal — see note below.)
        4. Create a relative symlink at the original ``dest`` via
           ``CAStore.link(identity, dest)``.
        5. Return ``FetchResult`` with ``path=dest`` (the symlink) so callers
           see the canonical ``_deps/<name>`` location.

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
            # Immutable source: stage → admit → symlink.
            # Staging dir is under the CAS root so rename(2) is atomic.
            staging_root = self._store.root / "_stage"
            staging_root.mkdir(parents=True, exist_ok=True)
            staging = staging_root / uuid.uuid4().hex
            staging.mkdir()

            try:
                result = self._inner.fetch(name, provenance, dest=staging)
            except BaseException:
                # Clean up staging on fetch failure.
                shutil.rmtree(staging, ignore_errors=True)
                raise

            try:
                # admit() verifies hash + moves staging atomically.
                self._store.admit(staging, result.identity)
            except BaseException:
                shutil.rmtree(staging, ignore_errors=True)
                raise

            # admit() moves staging on success; clean up any remnant.
            shutil.rmtree(staging, ignore_errors=True)

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
        """Delegate ``fetch_any`` to the inner registry.

        ``fetch_any`` implements the three-part ordered candidate list
        (resolver-semantics.md §8a); the inner ``FetcherRegistry`` handles the
        fallback logic.  This wrapper is not involved in candidate selection.

        Note: ``fetch_any`` uses the inner registry directly, bypassing the
        CAS admission gating in ``self.fetch``.  CAS admission for the winner
        is the caller's (resolver's) responsibility when using ``fetch_any``.
        If you want CAS admission on the winning candidate, call ``self.fetch``
        with the chosen provenance instead.
        """
        return self._inner.fetch_any(
            name, candidates, dest=dest, expected_identity=expected_identity
        )
