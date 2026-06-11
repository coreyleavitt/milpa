"""conftest.py for the differential test package.

Ensures:
1. The repo root is on sys.path so `import harness.*` resolves (bridge).
2. The tests/differential/ parent is on sys.path so `import differential`
   resolves when modules do `import differential` for the side-effect.

pytest collects this conftest before importing the test module, so these
insertions are in place by the time any test file does `import differential`
or `import harness.*`.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
# tests/differential/ -> tests/ -> python/ -> impls/ -> <repo_root>
_REPO_ROOT = _HERE.parent.parent.parent.parent
# tests/ dir (parent of differential/), so `import differential` finds the package
_TESTS_DIR = _HERE.parent

for _p in [str(_REPO_ROOT), str(_TESTS_DIR)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)
