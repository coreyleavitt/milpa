"""Error catalog — the normative spec of every milpa error (#14).

Each error condition carries a stable code (semantic-kebab format,
e.g. `MAN-NAME-MISSING`). Codes are categorized by a short prefix:

  MAN-*     : ManifestError (parser, validation)
  LOCK-*    : LockfileError
  RES-*     : ResolverError
  FETCH-*   : FetchError (fetchers)
  CAS-*     : CASError (content-addressed store)
  FROZEN-*  : NotFrozen (frozen fast path precondition failures)
  ID-*      : IdentityError (identity string parser)
  NIMBLE-*  : NimbleParseError (.nimble file loader)
  SOLVE-*   : SolverError
  WS-*      : WorkspaceError (workspace topology)
  EXTRACT-* : ExtractionError subclasses (archive extraction)

This module is the **single source of truth**. It generates the
normative spec at spec/errors.md. Tests enforce a bijection:
every code here has at least one trigger test; every raise in
production code references a code defined here.

See #14 for the design; #92 for the extension to non-ManifestError
categories.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ErrorCode:
    """One entry in the catalog. `slug` is the stable identifier
    (semantic-kebab, e.g. `MAN-NAME-MISSING`). `category` is the
    short prefix matching the exception class family. `description`
    is human-facing; `when` documents the trigger condition."""
    slug: str
    category: str
    description: str
    when: str


ERROR_CATALOG: dict[str, ErrorCode] = {}


def register(
    *,
    slug: str,
    category: str,
    description: str,
    when: str,
) -> ErrorCode:
    """Register a new error code in the global catalog. Returns the
    `ErrorCode` value. Raises ValueError if the slug is already
    defined — catalog integrity is enforced at definition time, not
    at the first conflicting raise."""
    if slug in ERROR_CATALOG:
        raise ValueError(
            f"duplicate error code registration: {slug!r} is already "
            f"defined (category={ERROR_CATALOG[slug].category!r})"
        )
    code = ErrorCode(
        slug=slug, category=category,
        description=description, when=when,
    )
    ERROR_CATALOG[slug] = code
    return code


def generate_errors_markdown(catalog: dict[str, ErrorCode] | None = None) -> str:
    """Render the catalog to a normative markdown spec. Entries are
    sorted by slug for deterministic output. Defaults to the global
    catalog when no argument is given."""
    if catalog is None:
        catalog = ERROR_CATALOG
    lines = [
        "# milpa error catalog",
        "",
        "Normative spec of every error milpa can produce. Each entry's",
        "`slug` is the conformance-stable identifier; consumers (CI",
        "scripts, IDE integrations, alternate implementations) MAY rely",
        "on slugs but MUST NOT rely on message wording.",
        "",
        "Generated from `milpa/error_catalog.py` — do not edit by hand.",
        "",
        "---",
        "",
        "## Normative surface",
        "",
        "Every catalog entry in this document is **normative**: a conformant",
        "milpa implementation MUST raise the exact slug shown for the exact",
        "condition described. The slug is the cross-implementation contract.",
        "",
        "The human-readable **message text** (the string passed to the",
        "exception constructor) is **incidental**: it is NOT byte-normative.",
        "A conformant implementation MAY differ in phrasing, language, or",
        "level of detail, provided the slug is correct.",
        "",
        "The **Triggered** field describes the reference Python implementation's",
        "raise site. Alternate implementations MUST produce the same slug for",
        "the same condition but MAY structure their internals differently.",
        "",
        "Bijection invariant: every slug in this catalog MUST have at least",
        "one raise site in the reference implementation; every raise site MUST",
        "reference a slug defined here. The test suite enforces both directions",
        "via `check_catalog_orphan_slugs` for each category prefix.",
        "",
        "---",
        "",
    ]
    by_category: dict[str, list[ErrorCode]] = {}
    for slug in sorted(catalog):
        c = catalog[slug]
        by_category.setdefault(c.category, []).append(c)
    for cat in sorted(by_category):
        lines.append(f"## {cat}")
        lines.append("")
        for code in by_category[cat]:
            lines.append(f"### `{code.slug}`")
            lines.append("")
            lines.append(code.description)
            lines.append("")
            lines.append(f"**Triggered:** {code.when}")
            lines.append("")
    return "\n".join(lines)
