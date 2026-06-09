"""FetchError codes — every error the fetchers can produce while
retrieving a source tree.  Codes use the ``FETCH-*`` prefix.

Importing this module populates the global ERROR_CATALOG with these
entries.  Production code references the codes by their slug strings;
the registry guarantees the slug is defined.

Scope: only user-facing raise sites — conditions reachable from
user-supplied input (manifest URL/ref, tarball URL + expected_sha256,
local path, OCI digest) without the user writing Python.

Intentionally UNCATALOGUED (programmer-invariant panics):
  - FetcherRegistry._select "ambiguous fetcher" — a registration bug,
    not a user-input condition.
  - FetcherRegistry._select "no registered fetcher" — same; a call-
    site misconfiguration, not caused by user manifest data.
  - LocalProvenance.__post_init__ ValueError — raised only when
    code constructs a LocalProvenance with a relative path, never
    from user input directly.
"""

from milpa.error_catalog import register


_CAT = "FETCH"

# ---------------------------------------------------------------------------
# Multi-candidate fetch
# ---------------------------------------------------------------------------

ALL_FAILED = register(
    slug="FETCH-ALL-FAILED", category=_CAT,
    description="Every candidate provenance failed — the dep cannot be fetched.",
    when=(
        "fetch_any() tries all candidate provenances in order and every one "
        "either raises or produces a mismatched identity.  Identity-mismatch "
        "candidates are folded into the composite failure message."
    ),
)

# ---------------------------------------------------------------------------
# Git fetcher
# ---------------------------------------------------------------------------

GIT_FAILED = register(
    slug="FETCH-GIT-FAILED", category=_CAT,
    description="A git subprocess (clone/fetch/checkout) exited non-zero.",
    when="_run_git receives a non-zero exit code from git.",
)

GIT_COMMIT_ABSENT = register(
    slug="FETCH-GIT-COMMIT-ABSENT", category=_CAT,
    description=(
        "The index-pinned commit SHA is absent even after a full history fetch."
    ),
    when=(
        "_ensure_commit_present cannot find commit_sha in the cloned repo "
        "after exhausting targeted + unshallow fetches."
    ),
)

# ---------------------------------------------------------------------------
# Tarball fetcher
# ---------------------------------------------------------------------------

DOWNLOAD_FAILED = register(
    slug="FETCH-DOWNLOAD-FAILED", category=_CAT,
    description="Could not download the tarball from the declared URL.",
    when=(
        "TarballFetcher._download raises URLError, FileNotFoundError, or OSError."
    ),
)

SHA256_MISMATCH = register(
    slug="FETCH-SHA256-MISMATCH", category=_CAT,
    description=(
        "Downloaded archive sha256 does not match the declared expected_sha256."
    ),
    when=(
        "TarballFetcher compares the archive's actual sha256 against "
        "TarballProvenance.expected_sha256 and finds a mismatch."
    ),
)

EXTRACT_FAILED = register(
    slug="FETCH-EXTRACT-FAILED", category=_CAT,
    description="Safe extraction of the tarball raised an ExtractionError.",
    when=(
        "TarballFetcher calls safe_extract.extract_tar and it raises "
        "ZipSlipError, SymlinkEscapeError, or SizeLimitError."
    ),
)

# ---------------------------------------------------------------------------
# Local fetcher
# ---------------------------------------------------------------------------

LOCAL_PATH_NOT_FOUND = register(
    slug="FETCH-LOCAL-PATH-NOT-FOUND", category=_CAT,
    description="The declared local source path does not exist.",
    when="LocalFetcher.fetch finds p.path does not exist on the filesystem.",
)

LOCAL_PATH_NOT_DIR = register(
    slug="FETCH-LOCAL-PATH-NOT-DIR", category=_CAT,
    description="The declared local source path is not a directory.",
    when="LocalFetcher.fetch finds p.path exists but is not a directory.",
)

# ---------------------------------------------------------------------------
# OCI fetcher
# ---------------------------------------------------------------------------

OCI_PULL_FAILED = register(
    slug="FETCH-OCI-PULL-FAILED", category=_CAT,
    description="oras pull exited non-zero.",
    when="OciFetcher.fetch runs `oras pull` and receives a non-zero exit code.",
)

OCI_NO_TARBALL = register(
    slug="FETCH-OCI-NO-TARBALL", category=_CAT,
    description="OCI artifact contained no *.tar.gz blob.",
    when=(
        "OciFetcher.fetch pulls the artifact but finds no *.tar.gz in the "
        "scratch directory."
    ),
)

OCI_AMBIGUOUS_TARBALL = register(
    slug="FETCH-OCI-AMBIGUOUS-TARBALL", category=_CAT,
    description="OCI artifact contained more than one *.tar.gz blob.",
    when=(
        "OciFetcher.fetch finds multiple *.tar.gz files; cannot determine "
        "which to extract."
    ),
)

# ---------------------------------------------------------------------------
# Receipt contract
# ---------------------------------------------------------------------------

RECEIPT_EMPTY = register(
    slug="FETCH-RECEIPT-EMPTY", category=_CAT,
    description=(
        "A fetcher returned a receipt whose transport_fields() is empty — "
        "no provenance evidence was recorded."
    ),
    when=(
        "FetcherRegistry.fetch calls receipt.transport_fields() after a "
        "successful fetch and the returned dict is empty, violating the "
        "spec §3.2 non-empty-receipt contract."
    ),
)
