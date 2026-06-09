"""ExtractionError codes — every archive-extraction security violation
the safe_extract module can produce.  Codes use the ``EXTRACT-*`` prefix.

Importing this module populates the global ERROR_CATALOG with these
entries.  Production code references the codes by their slug strings;
the registry guarantees the slug is defined.

The three subclasses of ExtractionError each get their own code:
  ZipSlipError     → EXTRACT-ZIP-SLIP
  SymlinkEscapeError → EXTRACT-SYMLINK-ESCAPE
  SizeLimitError   → EXTRACT-SIZE-LIMIT

The base class ExtractionError is never directly raised; all raise
sites go through a subclass.
"""

from milpa.error_catalog import register


_CAT = "EXTRACT"

ZIP_SLIP = register(
    slug="EXTRACT-ZIP-SLIP", category=_CAT,
    description=(
        "An archive entry's resolved path escapes the destination directory "
        "(zip-slip attack)."
    ),
    when=(
        "extract_tar finds an entry whose path, after joining with dest, "
        "resolves outside the destination tree."
    ),
)

SYMLINK_ESCAPE = register(
    slug="EXTRACT-SYMLINK-ESCAPE", category=_CAT,
    description=(
        "A symlink entry's target resolves outside the destination directory "
        "(symlink-escape attack)."
    ),
    when=(
        "extract_tar finds a symlink entry whose target, when resolved "
        "from its parent directory, exits the destination tree."
    ),
)

SIZE_LIMIT = register(
    slug="EXTRACT-SIZE-LIMIT", category=_CAT,
    description=(
        "The archive exceeds a configured size or file-count limit "
        "(decompression bomb protection)."
    ),
    when=(
        "extract_tar finds a single-file size, total decompressed size, "
        "or file count exceeds the configured caps."
    ),
)
