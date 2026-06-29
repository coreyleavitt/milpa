"""parse_source_spec — turn CLI tokens into a Provenance for ``milpa hash``.

This is the parser half of the ``milpa hash <source>`` sub-command (slice
A0-parse).  The CLI wrapper (A0-cmd) lives in ``cli.py`` and is a separate
slice; this module has no CLI dependency.

Accepted forms
--------------
- ``git=<url> ref=<value>``   → GitProvenance(url, ref, commit_sha=None)
- ``local=<path>``            → LocalProvenance(path=<abs path>)

``ref`` may be any string (branch, tag, or full commit SHA).  Enforcing that
``ref`` is a pinned SHA is the caller's responsibility — this parser does NOT
reject symbolic refs.  ``commit_sha`` is always left as ``None``; the fetcher
resolves it.

For ``local=``, relative paths are resolved against ``base_dir`` (defaults to
``Path.cwd()``).  Path existence is NOT checked — that is the fetcher's job.

All parse failures raise ``MilpaError(CLI_SOURCE_SPEC_INVALID, ...)``.
``LocalProvenance`` ``ValueError`` is translated rather than allowed to escape.
"""

from __future__ import annotations

from pathlib import Path

from milpa.errors import CLI_SOURCE_SPEC_INVALID, MilpaError
from milpa.fetchers.git import GitProvenance
from milpa.fetchers.local import LocalProvenance
from milpa.fetchers.types import Provenance

_KNOWN_KEYS: frozenset[str] = frozenset({"git", "ref", "local"})
_GIT_REQUIRED: frozenset[str] = frozenset({"git", "ref"})
_LOCAL_REQUIRED: frozenset[str] = frozenset({"local"})
_GIT_KEYS: frozenset[str] = frozenset({"git", "ref"})
_LOCAL_KEYS: frozenset[str] = frozenset({"local"})


def parse_source_spec(
    tokens: list[str],
    *,
    base_dir: Path | None = None,
) -> Provenance:
    """Parse CLI tokens into a Provenance for ``milpa hash``.

    Args:
        tokens:   List of ``key=value`` strings from the CLI (e.g.
                  ``["git=https://...", "ref=main"]``).
        base_dir: Base directory for resolving relative ``local=`` paths.
                  Defaults to ``Path.cwd()`` when ``None``.

    Returns:
        A ``GitProvenance`` or ``LocalProvenance`` instance.

    Raises:
        MilpaError(CLI_SOURCE_SPEC_INVALID): on any parse error.
    """
    if not tokens:
        raise MilpaError(
            CLI_SOURCE_SPEC_INVALID,
            "source spec requires at least one token (e.g. git=<url> ref=<ref> or local=<path>)",
        )

    resolved: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            raise MilpaError(
                CLI_SOURCE_SPEC_INVALID,
                f"malformed token {token!r}: expected key=value",
                token=token,
            )
        key, _, value = token.partition("=")
        if key not in _KNOWN_KEYS:
            raise MilpaError(
                CLI_SOURCE_SPEC_INVALID,
                f"unknown source-spec key {key!r}: expected one of git, ref, local",
                key=key,
            )
        if key in resolved:
            raise MilpaError(
                CLI_SOURCE_SPEC_INVALID,
                f"duplicate key {key!r} in source spec",
                key=key,
            )
        resolved[key] = value

    present = frozenset(resolved)

    # Detect mixed forms
    has_git_keys = bool(present & _GIT_KEYS)
    has_local_keys = bool(present & _LOCAL_KEYS)
    if has_git_keys and has_local_keys:
        raise MilpaError(
            CLI_SOURCE_SPEC_INVALID,
            "cannot mix git and local forms in a single source spec",
            keys=sorted(present),
        )

    if has_git_keys:
        missing = _GIT_REQUIRED - present
        if missing:
            raise MilpaError(
                CLI_SOURCE_SPEC_INVALID,
                f"git source spec requires both git= and ref=; missing: {sorted(missing)}",
                missing=sorted(missing),
            )
        return GitProvenance(url=resolved["git"], ref=resolved["ref"])

    # local form
    raw_path = resolved["local"]
    effective_base = base_dir if base_dir is not None else Path.cwd()
    path = Path(raw_path)
    if not path.is_absolute():
        path = effective_base / path

    try:
        return LocalProvenance(path=path)
    except ValueError as exc:
        raise MilpaError(
            CLI_SOURCE_SPEC_INVALID,
            f"invalid local path: {exc}",
            path=str(path),
        ) from exc
