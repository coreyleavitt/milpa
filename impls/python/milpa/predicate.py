"""Predicate — one conditional clause on a dep.

Extracted from ``manifest.py`` to a leaf module so ``dep_decl.py`` and
``lockfile.py`` can import it without creating an import cycle.

``manifest.py`` re-exports ``Predicate`` for back-compat so existing code
importing ``milpa.manifest.Predicate`` continues to work unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


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


def dep_passes_flag_predicates(
    predicates: Iterable[Predicate],
    active_flags: frozenset[str],
) -> bool:
    """Return True iff all ``flag`` predicates on a dep are satisfied.

    Non-flag predicates (``platform``, ``arch``, ``nim``, ``milpa``) are
    **ignored** — this function is the SSOT for the transitive-edge flag
    filter (S2.5 / RFC #23 §2.6).  It mirrors Rust's
    ``dep_passes_flag_predicates`` exactly:

    - Iterate predicates; skip any whose name is not ``"flag"``.
    - For each ``flag`` predicate: satisfied iff ``any(v in active_flags
      for v in pred.values)``; negated inverts the result.
    - All flag predicates must pass (conjunction).  Empty predicate list → True.

    Callers seed ``active_flags`` from the **dep's own manifest's
    default-true flags** (``{f.name for f in manifest.flags if f.default}``).
    This matches the S2.5 scope: only default-true flag filtering; no
    cross-package activation (that is S3/S4a territory).
    """
    for pred in predicates:
        if pred.name != "flag":
            continue
        any_match = any(v in active_flags for v in pred.values)
        satisfied = (not any_match) if pred.negated else any_match
        if not satisfied:
            return False
    return True
