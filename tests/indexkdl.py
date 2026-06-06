"""Synthetic tianguis Index builder for tests (milpa#97).

Routes through the real `parse_index`, so any KDL-format drift between
the test fixtures and the production parser is caught (per the RFC's
test-index decision — no hand-rolled string generator that could
silently diverge).

Most tests need a single git version per name; `content_hash` defaults
to empty, which disables the identity gate so a fake fetcher's arbitrary
bytes resolve. Tests that exercise the gate pass an explicit
`content_hash` (the recomputed hash of the bytes the fetcher writes).
"""

from milpa.tianguis_client import Index, parse_index


def make_index(specs) -> Index:
    """Build an Index from a list of per-version spec dicts.

    Each spec dict:
        name          (required) package name
        url           (required for git) git URL
        ref           git ref (default "main") — also the key a fake
                      (url, ref) fetcher matches on
        version       index version string (default "0.0.1")
        commit_sha    optional immutable pin
        content_hash  optional identity gate (default "" = no gate)

    Multiple specs sharing a `name` accumulate as multiple versions of
    that package.
    """
    by_name: dict[str, list[dict]] = {}
    for s in specs:
        by_name.setdefault(s["name"], []).append(s)

    lines: list[str] = []
    for name, versions in by_name.items():
        lines.append(f'package "{name}" {{')
        for s in versions:
            lines.append(f'    version "{s.get("version", "0.0.1")}" {{')
            ch = s.get("content_hash", "")
            if ch:
                lines.append(f'        content_hash "{ch}"')
            lines.append("        provenance {")
            lines.append('            kind "git"')
            lines.append(f'            url "{s["url"]}"')
            lines.append(f'            ref "{s.get("ref", "main")}"')
            if s.get("commit_sha"):
                lines.append(f'            commit_sha "{s["commit_sha"]}"')
            lines.append("        }")
            lines.append("    }")
        lines.append("}")
    return parse_index("\n".join(lines))
