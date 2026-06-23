"""Single source of truth for parsing slug headers from spec/errors.md.

Both ``harness/corpus_lint.py`` and ``impls/python/tests/test_errors.py``
need to enumerate the slugs defined in the normative error catalog.  This
module is the ONE implementation; both importers delegate here.

The normative line form in ``spec/errors.md`` is::

    ### `SLUG`

The regex below matches that form and captures the slug.
"""

from __future__ import annotations

import re
from pathlib import Path

_SLUG_HEADER_RE = re.compile(r"^### `([^`]+)`")


def parse_spec_slugs(errors_md: Path) -> frozenset[str]:
    """Parse every slug defined in *errors_md* (``spec/errors.md``).

    Reads the file, scans for lines matching ``### `<SLUG>```, and returns
    a frozenset of slug strings.  This is the single authoritative
    implementation; callers in ``corpus_lint.py`` and ``test_errors.py``
    import this function rather than maintaining their own copies.
    """
    text = errors_md.read_text(encoding="utf-8")
    slugs: set[str] = set()
    for line in text.splitlines():
        m = _SLUG_HEADER_RE.match(line)
        if m:
            slugs.add(m.group(1))
    return frozenset(slugs)
