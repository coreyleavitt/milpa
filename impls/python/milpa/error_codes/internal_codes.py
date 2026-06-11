"""Internal / catch-all error codes — the sentinels the CLI entry point
emits so that *every* failure carries a machine-readable slug on stderr
(RFC differential-conformance-harness, Gap-1 R1–R4).

Unlike the domain categories (MAN-*, LOCK-*, …) these are not raised by
a typed exception family; they are emitted by the outermost `main()`
wrapper for failures that escape every typed handler:

  MILPA-INTERNAL  : a Python exception escaped the typed handlers — the
                    entry point catches it, emits this slug, and exits 1.
  INTERNAL-PANIC  : a Rust panic reached the top-level handler — it emits
                    this slug before exiting 1 (an unhandled `panic!()`
                    that exits 101 is a *crash verdict* by R4, not this).

Both live in the shared catalog because `spec/errors.md` is the
cross-impl contract: the harness validates the emitted slug against the
catalog regardless of which impl produced it.

Importing this module populates the global ERROR_CATALOG with these
entries."""

from milpa.error_catalog import register


_CAT = "INTERNAL"

# ---------------------------------------------------------------------------
# Catch-all sentinels (emitted by the CLI entry point, not a typed raise)
# ---------------------------------------------------------------------------

MILPA_INTERNAL = register(
    slug="MILPA-INTERNAL", category=_CAT,
    description=(
        "An unexpected error escaped milpa's typed error handlers — an "
        "internal failure rather than a diagnosed condition."
    ),
    when=(
        "The outermost CLI entry-point wrapper catches an exception that no "
        "typed handler (ManifestError, SolverError, NotFrozen, …) accounted "
        "for, emits this sentinel slug to stderr, and exits 1.  Guarantees "
        "the R3 invariant — every exit-1 failure carries a `milpa-error:` "
        "line — is mechanically enforceable."
    ),
)

INTERNAL_PANIC = register(
    slug="INTERNAL-PANIC", category=_CAT,
    description=(
        "A Rust implementation's top-level panic handler fired — an internal "
        "failure that reached the panic boundary."
    ),
    when=(
        "A Rust impl installs a top-level panic handler that emits this slug "
        "to stderr before exiting 1.  An unhandled `panic!()` that exits 101 "
        "is a crash verdict under Gap-1 R4, not this coded error."
    ),
)
