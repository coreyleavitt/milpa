"""Predicate — one conditional clause on a dep.

Extracted from ``manifest.py`` to a leaf module so ``dep_decl.py`` and
``lockfile.py`` can import it without creating an import cycle.

``manifest.py`` re-exports ``Predicate`` for back-compat so existing code
importing ``milpa.manifest.Predicate`` continues to work unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Predicate:
    """One conditional clause on a dep.

    ``name`` is the predicate key (``platform``, ``arch``, ``nim``,
    ``milpa``, ``flag``).  ``values`` is the tuple of match tokens.
    ``negated=False`` → satisfied if ANY value matches (OR); ``negated=True``
    → satisfied if NO value matches.

    Both inline form (single-value property on the dep node) and child-node
    form (multi-value child node, OR semantics) are represented identically
    here — the distinction is erased at parse time.
    """

    name: str
    values: tuple[str, ...]
    negated: bool = False
