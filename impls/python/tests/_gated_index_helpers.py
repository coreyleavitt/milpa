"""Test-only ``GatedIndex`` construction — OUTSIDE the ``milpa`` package
(RFC ``docs/rfc-trusted-index-invariant.md`` §2.6, Python ``for_test``
containment).

Python has no ``#[cfg(test)]``: anything importable from ``milpa/`` is
callable by production code, so a ``for_test`` shipped inside the package
would make ``isinstance(x, GatedIndex)`` true for an object that never
passed the real gate — reducing the resolver's runtime assert (RFC §2.5)
to a type check, not a provenance check.

Containment is two-layered, mirroring the existing
``MILPA_INDEX_TRUST_MOCK_VERIFIER``-style production guard idiom:

1. Physical placement — this module lives under ``tests/``, never imported
   by anything under ``milpa/`` (enforced by
   ``tests/test_gated_index_containment.py``, which greps the ``milpa/``
   tree for both a forbidden ``_mint(`` call site and a forbidden import of
   this module).
2. It calls the privileged ``GatedIndex._mint`` — the same constructor the
   real gate (``milpa.index_cache``) uses — rather than reimplementing
   construction, so there is exactly ONE way to build a ``GatedIndex``.

Existing test fixtures build non-empty, name/version-bearing ``Index``
objects via ``parse_index`` and hand them to ``MilpaEnv(index=...)`` —
``GatedIndex.empty()`` cannot serve them, so a real test double is
unavoidable. Use ``for_test`` for exactly that: bypassing the real gate in
a test fixture, never in production code.
"""

from __future__ import annotations

from milpa.gated_index import GatedIndex
from milpa.index_trust import IndexBundleInfo, VerificationResult
from milpa.registry import Index


def for_test(
    index: Index,
    verification: VerificationResult | None = None,
    bundle_info: IndexBundleInfo | None = None,
) -> GatedIndex:
    """Wrap an arbitrary ``Index`` fixture as a ``GatedIndex``, bypassing the
    real index-trust gate. TEST USE ONLY — see the module docstring."""
    return GatedIndex._mint(index, verification, bundle_info)
