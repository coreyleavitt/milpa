"""`milpa verify` codes — conditions specific to the integrity-check
verb that are not raised by a typed domain exception. Codes use the
``VERIFY-*`` prefix.

`verify` answers "do the checked-out _deps/ match milpa.lock?". Its
failure conditions split into:
  - VERIFY-DEPS-DIR-MISSING — there is nothing to verify (no _deps/);
  - on-disk divergence — covered by the reused LOCK-GRAPH-MISMATCH code,
    since "deps diverge from the lockfile" is the same semantic whether
    the divergence is found against the resolved graph or the disk tree.

Importing this module populates the global ERROR_CATALOG with these
entries."""

from milpa.error_catalog import register


_CAT = "VERIFY"

DEPS_DIR_MISSING = register(
    slug="VERIFY-DEPS-DIR-MISSING", category=_CAT,
    description="`milpa verify` cannot run: there is no _deps/ directory.",
    when=(
        "cmd_verify finds no _deps/ under the project (or workspace) root — "
        "nothing has been fetched, so there is nothing to verify against the "
        "lockfile. The user is directed to run `milpa fetch` first."
    ),
)

# ---------------------------------------------------------------------------
# Graph-edge drift (rfc-content-addressed-metadata §3.7, S6)
# ---------------------------------------------------------------------------

EDGE_MISMATCH = register(
    slug="VERIFY-EDGE-MISMATCH", category=_CAT,
    description=(
        "The locked `dep_decl` pin no longer matches the current index pointer "
        "for a dep (§3.7, RFC content-addressed-metadata)."
    ),
    when=(
        "`milpa verify` loads the live index and finds that the `dep_decl` hash "
        "recorded in `milpa.lock` for a dep differs from the `dep_decl` pointer "
        "the index now carries for that version — the dependency graph has "
        "drifted since the lockfile was written. Also raised when the edge "
        "check is required but the index is offline and strict mode "
        "(`--require-attested-metadata`) is active."
    ),
)
