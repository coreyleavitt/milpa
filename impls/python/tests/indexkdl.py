"""Synthetic tianguis Index builder for tests (milpa#97).

Routes through the real `parse_index`, so any KDL-format drift between
the test fixtures and the production parser is caught (per the RFC's
test-index decision — no hand-rolled string generator that could
silently diverge).

`content_hash` in each spec can be:
  - an explicit hash string (e.g. for Invariant 1 gate tests)
  - absent / falsy → auto-computed from a standard fake-fetch write so
    that the identity gate passes without requiring a probe round-trip.
    The standard write is `{name}.nimble` containing the default _Fake
    nimble `'srcDir = "src"\\n'`. Tests that supply their own _Fake nimble
    must pass the matching explicit hash (or use fake_content_hash()).
"""

import tempfile
from pathlib import Path

from milpa.identity import compute_content_hash
from milpa.tianguis_client import Index, parse_index


def fake_content_hash(name: str, nimble: str = 'srcDir = "src"\n') -> str:
    """Compute the content_hash that a _Fake fetcher writing `nimble` into
    `{name}.nimble` would produce. Use this when make_index needs a hash
    that the fake fetcher will actually satisfy, without a probe run."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / f"{name}.nimble").write_text(nimble)
        return compute_content_hash(p)


def make_index(specs) -> Index:
    """Build an Index from a list of per-version spec dicts.

    Each spec dict:
        name          (required) package name

        For a git provenance:
          url           (required) git URL
          ref           git ref (default "main")
          commit_sha    optional immutable pin

        For an OCI provenance:
          kind          "oci"  (triggers OCI provenance node)
          registry      OCI registry host (e.g. "ghcr.io")
          repository    OCI repository (e.g. "user/pkg")
          digest        OCI digest — must be "sha256:<64 hex>" (required)

        version       index version string (default "0.0.1")
        content_hash  optional identity gate hash. When absent or falsy,
                      auto-computed from fake_content_hash(name) so that
                      the standard _Fake fetcher satisfies the identity
                      gate. Tests exercising Invariant 1 mismatch must
                      pass an explicit wrong hash.

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
            ch = s.get("content_hash") or fake_content_hash(name)
            lines.append(f'        content_hash "{ch}"')
            lines.append("        provenance {")
            if s.get("kind") == "oci":
                lines.append('            kind "oci"')
                lines.append(f'            registry "{s["registry"]}"')
                lines.append(f'            repository "{s["repository"]}"')
                lines.append(f'            digest "{s["digest"]}"')
            else:
                lines.append('            kind "git"')
                lines.append(f'            url "{s["url"]}"')
                lines.append(f'            ref "{s.get("ref", "main")}"')
                if s.get("commit_sha"):
                    lines.append(f'            commit_sha "{s["commit_sha"]}"')
            lines.append("        }")
            lines.append("    }")
        lines.append("}")
    return parse_index("\n".join(lines))
