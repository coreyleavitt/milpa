"""CI/lint pin: ``GatedIndex`` construction stays contained to the gate
module (RFC ``docs/rfc-trusted-index-invariant.md`` §2.1, §2.6).

Python has no compile-time visibility enforcement (no ``pub(crate)``, no
``#[cfg(test)]``), so the containment invariant that Rust gets "for free"
from the compiler is enforced here by a static grep over the ``milpa/``
package tree — the Python analogue of Rust's compiler-enforced
``for_test``/``mint`` privacy (RFC §2.6).

Two independent violations are checked:

1. A forbidden mint call site: ``._mint(`` or a raw ``GatedIndex(`` outside
   the one module privileged to construct it (``milpa/gated_index.py``
   itself, and ``milpa/index_cache.py`` — the production gate that calls
   ``_mint`` after the index-trust + epoch-commitment gates have run).
2. A forbidden import of the test-only ``for_test`` helper
   (``tests/_gated_index_helpers.py``) from anywhere under ``milpa/`` — that
   helper exists specifically to bypass the gate for fixtures, so if
   production code could reach it, the whole containment story collapses.
"""

from __future__ import annotations

import re
from pathlib import Path

_MILPA_ROOT = Path(__file__).resolve().parent.parent / "milpa"

#: Files allowed to call ``GatedIndex._mint`` / construct ``GatedIndex(...)``
#: directly — the gate module's own implementation and the type's own
#: definition file. Nothing else under ``milpa/`` may appear here.
_ALLOWED_MINT_FILES = {"gated_index.py", "index_cache.py"}

_MINT_CALL_RE = re.compile(r"\._mint\s*\(")
_RAW_CONSTRUCT_RE = re.compile(r"(?<!class )\bGatedIndex\s*\(")
#: An actual import statement, not merely a prose mention (this file's own
#: docstrings legitimately reference the helper's name/purpose).
_HELPER_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+tests\._gated_index_helpers\s+import|import\s+tests\._gated_index_helpers)",
    re.MULTILINE,
)


def _milpa_py_files() -> list[Path]:
    return sorted(_MILPA_ROOT.rglob("*.py"))


def test_mint_call_sites_contained_to_gate_module() -> None:
    offenders: list[str] = []
    for path in _milpa_py_files():
        if path.name in _ALLOWED_MINT_FILES:
            continue
        text = path.read_text(encoding="utf-8")
        if _MINT_CALL_RE.search(text) or _RAW_CONSTRUCT_RE.search(text):
            offenders.append(str(path.relative_to(_MILPA_ROOT.parent)))

    assert not offenders, (
        "GatedIndex._mint(...) / raw GatedIndex(...) construction found "
        f"outside the gate module: {offenders}. Only "
        f"{sorted(_ALLOWED_MINT_FILES)} (under milpa/) may mint a "
        "GatedIndex — RFC rfc-trusted-index-invariant.md §2.1 ('the mint "
        "point is the production gate, not a leaf acquire') / §2.6 (Python "
        "for_test containment). Test fixtures must use "
        "tests/_gated_index_helpers.for_test instead."
    )


def test_for_test_helper_never_imported_from_milpa_package() -> None:
    offenders: list[str] = []
    for path in _milpa_py_files():
        text = path.read_text(encoding="utf-8")
        if _HELPER_IMPORT_RE.search(text):
            offenders.append(str(path.relative_to(_MILPA_ROOT.parent)))

    assert not offenders, (
        "tests/_gated_index_helpers.py (the for_test gate-bypass) must never "
        f"be imported from milpa/: {offenders}. If production code needs a "
        "GatedIndex, it must go through the real gate "
        "(milpa.index_cache.load_default_index / load_index_gated)."
    )
