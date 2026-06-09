"""SolverError codes — the single user-facing solver error condition.
Codes use the `SOLVE-*` prefix.

Importing this module populates the global ERROR_CATALOG with these
entries.  Production code references the codes by their slug strings;
the registry guarantees the slug is defined."""

from milpa.error_catalog import register


_CAT = "SOLVE"

# ---------------------------------------------------------------------------
# Unsatisfiable constraints
# ---------------------------------------------------------------------------

CONFLICT = register(
    slug="SOLVE-CONFLICT", category=_CAT,
    description="No version solution exists — dep constraints are unsatisfiable.",
    when=(
        "PubGrub exhausts all backtracking options and finds no consistent "
        "assignment.  SolverError.chain carries the structured ConflictChain "
        "narrating why."
    ),
)
