"""Fixture-input parsing — the canonical readers for harness control files.

Owns all fixture-INPUT parsing (distinct from runner.py's subprocess-driving
responsibility).  stdlib only; no import milpa; no import harness submodules.

Public API:
  read_env_file(fixture_dir) -> dict[str, str]
  env_flag(env, key) -> bool
  parse_cli_features(env) -> frozenset[str]
  resolve_project_dir(root, suffix) -> Path
"""

from __future__ import annotations

from pathlib import Path


def read_env_file(fixture_dir: Path) -> dict[str, str]:
    """Parse the optional ``env`` file into a dict (KEY=VALUE lines, # comments ignored).

    Returns an empty dict when the file is absent.  Skips blank lines and
    comment lines (starting with ``#``).  Values are stripped of leading/trailing
    whitespace at parse time so callers receive clean strings.
    """
    env_file = fixture_dir / "env"
    if not env_file.exists():
        return {}
    result: dict[str, str] = {}
    for raw_line in env_file.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


def env_flag(env: dict[str, str], key: str) -> bool:
    """A boolean env flag is true when present, non-empty, and not '0'/'false'.

    This is the CANONICAL definition used by both the black-box harness and
    the in-process adapter (test_conformance.py).  Both env-file parsers
    (read_env_file here and _fixture_env_vars in test_conformance.py) strip
    values at parse time, so a whitespace-only raw value arrives here as ''
    and is treated as absent (False).
    """
    v = env.get(key, "")
    return bool(v and v not in ("0", "false"))


def resolve_project_dir(root: Path, suffix: str) -> Path:
    """Resolve and confine a project-dir suffix to within ``root``.

    SINGLE DEFINITION for the confinement logic used by the black-box harness
    (runner.py) and the in-process adapter (test_conformance.py).

    Rules (spec/conformance-fixtures.md §2.8.1 NORMATIVE):
    - ``suffix`` MUST be relative (not an absolute path).
    - After joining and normalising, the result MUST NOT escape ``root``
      (no ``..`` traversal above the root).

    Raises ``ValueError`` on any violation.  Callers handle the "absent →
    use root" fallback before calling this function.
    """
    p = Path(suffix)
    if p.is_absolute():
        raise ValueError(
            f"project-dir MUST be relative, got absolute path: {suffix!r}"
        )
    resolved = (root / p).resolve()
    root_resolved = root.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError:
        raise ValueError(
            f"project-dir escapes fixture root: {suffix!r} resolves to "
            f"{resolved} which is outside {root_resolved}"
        )
    return resolved


def parse_cli_features(env: dict[str, str]) -> frozenset[str]:
    """Parse MILPA_CLI_FEATURES from a fixture env dict into a frozenset of names.

    SINGLE DEFINITION for the in-process adapter and any future callers.
    Each comma-separated token is stripped; empty tokens are dropped.

    Canonical whitespace rule: MILPA_CLI_FEATURES with a whitespace-only value
    (after stripping by the env-file parser) yields an empty frozenset.
    """
    raw = env.get("MILPA_CLI_FEATURES", "").strip()
    if not raw:
        return frozenset()
    return frozenset(name.strip() for name in raw.split(",") if name.strip())
