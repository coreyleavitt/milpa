"""milpa — Nim dependency resolver."""

__version__ = "0.0.1"

# Populate the global ERROR_CATALOG (#14) with every defined error
# code. Side-effect import; safe because error_codes only imports
# from error_catalog (no circular).
from . import error_codes  # noqa: F401
