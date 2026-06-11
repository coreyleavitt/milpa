"""Behavioral-class deduplication for the differential conformance harness (slice 3d).

Per RFC §2c: "at most one issue per distinct behavioral class"
Per RFC §2e: "summary grouped by (cmd, output_file, disagreement_shape) with a
count per class"

Implements:

    behavioral_class(divergence) -> tuple
        The 3-tuple (cmd, output_file, disagreement_shape) where
        disagreement_shape is a normalized signature of HOW impls disagree
        (sorted frozenset of per-impl outcome keys), NOT the fixture ID or
        specific package names. Two divergences with the same behavioral class
        represent the same *kind* of disagreement.

    DivergenceCollector
        Accumulates Divergence objects, dedups by behavioral class (keeping the
        FIRST / shrunk representative per class), and emits a summary
        { class_key: count } BEFORE the per-class records (the §2e ordering).

Stdlib only; no 3rd-party dependencies, no import milpa.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Behavioral class
# ---------------------------------------------------------------------------

def behavioral_class(divergence_impls: dict, cmd: str, output_file: str) -> tuple:
    """Compute the behavioral class tuple for a divergence.

    The behavioral class is:
        (cmd, output_file, disagreement_shape)

    where disagreement_shape is a frozenset of the per-impl outcome strings
    from divergence.impls. Using a frozenset normalizes:
    - Order of impl names (python vs rust vs broken — same shape regardless)
    - Specific fixture inputs (package names, versions) — the shape captures
      only the KIND of disagreement, not the specific values

    Examples of the same behavioral class:
        python="success", rust="error:SOLVE-CONFLICT"  → one fixture
        python="success", rust="error:SOLVE-CONFLICT"  → another fixture
    Both map to frozenset({"success", "error:SOLVE-CONFLICT"}).

    Different behavioral classes:
        python="success", rust="error:SOLVE-CONFLICT"  → class A
        python="error:SOLVE-CONFLICT", rust="crash"    → class B

    Parameters
    ----------
    divergence_impls  — the Divergence.impls dict: {impl_name: outcome_str}
    cmd               — the fixture cmd (e.g. "resolve")
    output_file       — the output_file field (e.g. "error-slug", "milpa.lock")

    Returns
    -------
    A tuple (cmd, output_file, frozenset(impl_outcomes)) suitable as a dict key.
    The frozenset captures only the SET of outcome strings, not which impl
    produced which — this is intentional: it collapses "python OK, rust wrong"
    and "rust OK, python wrong" into the same shape when the outcome strings are
    the same. If you need to distinguish direction, use the full impls dict.
    """
    outcome_set = frozenset(divergence_impls.values())
    return (cmd, output_file, outcome_set)


# ---------------------------------------------------------------------------
# DivergenceCollector
# ---------------------------------------------------------------------------

@dataclass
class _ClassRecord:
    """Internal: one behavioral class's accumulated data."""
    count: int
    # The representative divergence record dict (the FIRST / shrunk one seen)
    representative: dict


@dataclass
class DivergenceCollector:
    """Accumulate divergences, dedup by behavioral class, emit §2e summary.

    Usage:
        collector = DivergenceCollector()
        for divergence in found_divergences:
            collector.add(divergence.cmd, divergence.output_file, divergence.impls,
                          record=json.loads(divergence.to_json()))
        summary = collector.summary()       # { class_label: count } dict
        records = collector.records()       # one repr record per class

    The §2e ordering is: summary first, then one representative record per class.
    emit() returns both together.
    """

    _classes: dict = field(default_factory=dict)  # class_key -> _ClassRecord

    def add(
        self,
        cmd: str,
        output_file: str,
        impls: dict,
        record: dict | None = None,
    ) -> tuple:
        """Add a divergence to the collector.

        Parameters
        ----------
        cmd         — the fixture cmd
        output_file — the output_file (e.g. "error-slug")
        impls       — the per-impl outcome dict {impl_name: outcome_str}
        record      — optional JSON-serializable dict (the full §2e record);
                      used as the representative for the first seen of a class.
                      If None, a minimal record is synthesized.

        Returns
        -------
        The behavioral class tuple (for testing/introspection).
        """
        cls_key = behavioral_class(impls, cmd, output_file)

        if cls_key not in self._classes:
            # First occurrence — this becomes the representative
            if record is None:
                record = {
                    "cmd": cmd,
                    "output_file": output_file,
                    "impls": impls,
                }
            self._classes[cls_key] = _ClassRecord(count=1, representative=record)
        else:
            # Subsequent occurrence — increment count, keep original representative
            self._classes[cls_key].count += 1

        return cls_key

    def summary(self) -> dict:
        """Return a summary dict mapping class label → count.

        The class label is a stable human-readable string representation of the
        behavioral class tuple. Keys are ordered by insertion (first seen first).
        """
        result = {}
        for cls_key, rec in self._classes.items():
            label = _class_label(cls_key)
            result[label] = rec.count
        return result

    def records(self) -> list:
        """Return the representative record dict for each behavioral class.

        One record per class, in insertion order (first-seen first).
        """
        return [rec.representative for rec in self._classes.values()]

    def emit(self) -> dict:
        """Return the §2e combined output: summary first, then per-class records.

        Returns:
            {
                "summary": { class_label: count, ... },
                "findings": [ representative_record, ... ]
            }

        The summary collapses N same-shape divergences to 1 class with a count.
        The findings list has exactly one representative per distinct class.
        """
        return {
            "summary": self.summary(),
            "findings": self.records(),
        }

    def emit_json(self, indent: int = 2) -> str:
        """Return the §2e combined output as a JSON string."""
        return json.dumps(self.emit(), indent=indent)

    def __len__(self) -> int:
        """Return the number of distinct behavioral classes."""
        return len(self._classes)

    def total_count(self) -> int:
        """Return the total number of divergences added."""
        return sum(rec.count for rec in self._classes.values())


def _class_label(cls_key: tuple) -> str:
    """Produce a stable human-readable label for a behavioral class tuple.

    Format: "cmd=<cmd> file=<output_file> shape=<sorted outcomes>"

    The shape is the sorted list of outcome strings (sorted for determinism).
    """
    cmd, output_file, outcome_set = cls_key
    sorted_outcomes = sorted(outcome_set)
    shape = ",".join(sorted_outcomes)
    return f"cmd={cmd} file={output_file} shape={shape}"
