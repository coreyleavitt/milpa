"""Per-category error-code modules. Importing any of these populates
the global ERROR_CATALOG in milpa.error_catalog."""

from . import manifest_codes  # noqa: F401 — side-effect import populates catalog
