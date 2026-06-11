"""differential — Hypothesis-based differential generator for the milpa conformance harness.

This package lives in `impls/python/tests/differential/` because it needs
Hypothesis (a Python dev dep) for test generation. The neutral runner +
serializer live in the repo-root `harness/` package (pure stdlib).

Bridge: insert the repo root onto sys.path so `import harness.*` resolves.
The repo root is 4 levels up from this file:
  impls/python/tests/differential/__init__.py
  -> impls/python/tests/differential/
  -> impls/python/tests/
  -> impls/python/
  -> impls/
  -> <repo_root>/
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
# Walk 4 levels up: differential -> tests -> python -> impls -> repo_root
_REPO_ROOT = _HERE.parent.parent.parent.parent

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
