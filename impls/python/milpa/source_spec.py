"""parse_source_spec — turn CLI tokens into a Provenance for ``milpa hash``.

This is the parser half of the ``milpa hash <source>`` sub-command (slice
A0-parse).  The CLI wrapper (A0-cmd) lives in ``cli.py`` and is a separate
slice; this module has no CLI dependency.

Accepted forms
--------------
- ``git=<url> ref=<value>``                          → GitProvenance(url, ref, commit_sha=None)
- ``local=<path>``                                   → LocalProvenance(path=<abs path>)
- ``oci=<registry>/<repository>@<digest>``           → OciProvenance(registry, repository, digest)

``ref`` may be any string (branch, tag, or full commit SHA).  Enforcing that
``ref`` is a pinned SHA is the caller's responsibility — this parser does NOT
reject symbolic refs.  ``commit_sha`` is always left as ``None``; the fetcher
resolves it.

For ``local=``, relative paths are resolved against ``base_dir`` (defaults to
``Path.cwd()``).  Path existence is NOT checked — that is the fetcher's job.

For ``oci=``, the value is split on the single ``@``: the left part is
``registry/repository`` (split on the first ``/``), the right part is the
digest kept verbatim (``sha256:<64-hex>`` form).  ``OciProvenance.__post_init__``
validation (``TNG-BAD-OCI-DIGEST`` / ``TNG-UNSAFE-OCI-FIELD``) is translated
to ``CLI-SOURCE-SPEC-INVALID`` so all parse errors from this module share one
error code.

All parse failures raise ``MilpaError(CLI_SOURCE_SPEC_INVALID, ...)``.
``LocalProvenance`` and ``OciProvenance`` ``ValueError``/``MilpaError``
construction errors are translated rather than allowed to escape.
"""

from __future__ import annotations

from pathlib import Path

from milpa.errors import CLI_SOURCE_SPEC_INVALID, MilpaError
from milpa.fetchers.git import GitProvenance
from milpa.fetchers.local import LocalProvenance
from milpa.fetchers.oci import OciProvenance
from milpa.fetchers.types import Provenance

_KNOWN_KEYS: frozenset[str] = frozenset({"git", "ref", "local", "oci"})
_GIT_REQUIRED: frozenset[str] = frozenset({"git", "ref"})
_LOCAL_REQUIRED: frozenset[str] = frozenset({"local"})
_GIT_KEYS: frozenset[str] = frozenset({"git", "ref"})
_LOCAL_KEYS: frozenset[str] = frozenset({"local"})
_OCI_KEYS: frozenset[str] = frozenset({"oci"})


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
        A ``GitProvenance``, ``LocalProvenance``, or ``OciProvenance`` instance.

    Raises:
        MilpaError(CLI_SOURCE_SPEC_INVALID): on any parse error.
    """
    if not tokens:
        raise MilpaError(
            CLI_SOURCE_SPEC_INVALID,
            "source spec requires at least one token "
            "(e.g. git=<url> ref=<ref>, local=<path>, or oci=<registry>/<repo>@<digest>)",
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
                f"unknown source-spec key {key!r}: expected one of git, ref, local, oci",
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
    has_oci_keys = bool(present & _OCI_KEYS)
    form_count = sum([has_git_keys, has_local_keys, has_oci_keys])
    if form_count > 1:
        raise MilpaError(
            CLI_SOURCE_SPEC_INVALID,
            "cannot mix source spec forms (git, local, oci) in a single spec",
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

    if has_oci_keys:
        raw_oci = resolved["oci"]
        # Split on '@': there MUST be exactly one '@'.
        at_parts = raw_oci.split("@")
        if len(at_parts) != 2:
            raise MilpaError(
                CLI_SOURCE_SPEC_INVALID,
                f"oci= value must contain exactly one '@'; got {raw_oci!r}",
                value=raw_oci,
            )
        ref_part, digest = at_parts
        if not digest:
            raise MilpaError(
                CLI_SOURCE_SPEC_INVALID,
                f"oci= value has empty digest (nothing after '@'); got {raw_oci!r}",
                value=raw_oci,
            )
        # Split the registry/repository on the first '/'.
        slash_pos = ref_part.find("/")
        if slash_pos == -1:
            raise MilpaError(
                CLI_SOURCE_SPEC_INVALID,
                f"oci= registry/repository reference must contain '/'; got {ref_part!r}",
                value=raw_oci,
            )
        registry = ref_part[:slash_pos]
        repository = ref_part[slash_pos + 1:]
        # Construct OciProvenance; translate any MilpaError from validation
        # (TNG-BAD-OCI-DIGEST / TNG-UNSAFE-OCI-FIELD) into CLI-SOURCE-SPEC-INVALID.
        try:
            return OciProvenance(registry=registry, repository=repository, digest=digest)
        except MilpaError as exc:
            raise MilpaError(
                CLI_SOURCE_SPEC_INVALID,
                f"invalid oci= spec: {exc.message}",
                value=raw_oci,
                inner_slug=exc.slug,
            ) from exc

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
