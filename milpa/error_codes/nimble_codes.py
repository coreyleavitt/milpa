"""NimbleParseError codes — errors the .nimble file loader can produce.
Codes use the ``NIMBLE-*`` prefix.

Importing this module populates the global ERROR_CATALOG with these
entries.  Production code references the codes by their slug strings;
the registry guarantees the slug is defined.

Scope: load_nimble raise sites — file-not-found and OS read errors.
parse_nimble itself does not raise NimbleParseError (it is tolerant;
it warns on when-blocks but does not fail).

Layering: load_nimble is the single .nimble reader (SSOT). When a .nimble
is discovered as a manifest (load_or_discover_manifest →
_load_manifest_from_nimble), these nimble-layer codes are translated to the
manifest-discovery layer's MAN-FILE-UNREADABLE so the ManifestError contract
holds. They surface directly only to callers that use load_nimble's raw
NimbleManifest API.
"""

from milpa.error_catalog import register


_CAT = "NIMBLE"

FILE_NOT_FOUND = register(
    slug="NIMBLE-FILE-NOT-FOUND", category=_CAT,
    description="The .nimble file path does not exist.",
    when="load_nimble is called with a path that has no file on disk.",
)

FILE_UNREADABLE = register(
    slug="NIMBLE-FILE-UNREADABLE", category=_CAT,
    description="The .nimble file cannot be read (permissions, OS error).",
    when="OS denies reading the .nimble file.",
)
