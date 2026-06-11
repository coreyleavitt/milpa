"""Structured value + serializer for the differential conformance harness (slice 3a).

This module is part of the standalone stdlib harness program — NO 3rd-party
dependencies. It defines the "single structured value" the RFC §2c mandates:

    manifest + index rows + dep→fetch map

and a `serialize()` function that projects that value to a fixture input
directory that `harness/runner.py` can drive.

The key encoding for mocked-fetches/ subdirectory names is defined here as
`url_key()` — the single source of truth within the harness for §2.3 of the
conformance-fixtures spec. Do NOT import an impl's copy; this is the neutral
re-statement.

TODO (slice 3b+):
  - Frozen-lock serialization: FixtureSpec currently writes the `cmd` file for
    `frozen` but does NOT emit a `milpa.lock`. Slice 3b will add `LockEntry`
    and a `milpa.lock` emitter to complete the frozen fixture path.
  - Named dep + index rows are modeled here (IndexRow / IndexVersionEntry);
    the index.kdl emitter is included. Named dep constraint syntax is modeled
    via DepSpec.named(). Both are exercised in test_spec.py S5.
  - Hypothesis strategies (slice 3b): will generate FixtureSpec values using
    @given and hypothesis.strategies, shrink on divergence, then call
    serialize() to write to a temp dir before running the impls.
"""

from __future__ import annotations

import hashlib
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Nimble requires parser — minimal, stdlib only, no import milpa
# ---------------------------------------------------------------------------

# Matches `requires "pkgname ..."` where pkgname is a name-only (not a URL).
# URL requires start with "https://" or "http://" — we skip those.
_REQUIRES_RE = re.compile(
    r'^requires\s+"([A-Za-z][A-Za-z0-9_-]*)',
    re.MULTILINE,
)


def _parse_nimble_requires_names(nimble_text: str) -> list[str]:
    """Extract named dep names from nimble requires lines.

    Returns the list of package names (not URLs) referenced by `requires`
    lines. Skips URL-style requires (starts with http:// or https://).
    Used by FixtureSpec.validate() for transitive completeness checks.
    """
    names = []
    for m in _REQUIRES_RE.finditer(nimble_text):
        name = m.group(1)
        names.append(name)
    return names


# ---------------------------------------------------------------------------
# Content hash (spec/identity.md) — stdlib re-implementation for the harness.
#
# This is NOT an import of milpa.identity — the harness is black-box stdlib.
# It re-states the normative algorithm from spec/identity.md:
#
#   For each entry under `path` (excluding .git/):
#     relpath_bytes + 0x00 + mode_marker + 0x00 + entry_content + 0x00
#   Entries sorted by POSIX relpath.
#   mode_marker: 0x00 = regular, 0x01 = executable, 0x80 = symlink.
#   Output: "sha256:<64-hex>"
#
# Used by the generator to compute correct content_hash values for the index.
# ---------------------------------------------------------------------------

_MODE_REGULAR = b"\x00"
_MODE_EXECUTABLE = b"\x01"
_MODE_SYMLINK = b"\x80"


def compute_content_hash_from_files(content_files: dict[str, bytes]) -> str:
    """Compute the spec/identity.md sha256 content hash from a files dict.

    content_files maps relative path strings → file bytes (same representation
    used in FetchEntry.content_files). All files are treated as regular
    non-executable files (mode_marker 0x00).

    Returns "sha256:<64-hex>" — the same form the index and lockfile expect.
    """
    h = hashlib.sha256()
    # Sort by POSIX relpath (lexicographic, forward slashes)
    for relpath in sorted(content_files.keys()):
        relpath_bytes = relpath.encode("utf-8")
        content = content_files[relpath]
        if isinstance(content, str):
            content = content.encode("utf-8")
        h.update(relpath_bytes)
        h.update(b"\x00")
        h.update(_MODE_REGULAR)
        h.update(b"\x00")
        h.update(content)
        h.update(b"\x00")
    return f"sha256:{h.hexdigest()}"


# ---------------------------------------------------------------------------
# §2.3.1  URL-key encoding — single source of truth within the harness
# ---------------------------------------------------------------------------

_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def url_key(url: str, ref: str) -> str:
    """Encode a (url, ref) pair to a mocked-fetches/ subdirectory name.

    Rule (§2.3.1 of conformance-fixtures.md):
      apply re.sub(r'[^A-Za-z0-9._-]', '_', url), then literal '@',
      then apply the same substitution to ref.

    The @ separator between url-part and ref-part is literal and preserved.
    A '@' *within* url or ref is NOT special: it is substituted to '_'.
    """
    return _SAFE.sub("_", url) + "@" + _SAFE.sub("_", ref)


# ---------------------------------------------------------------------------
# Structured value types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DepSpec:
    """One dependency declared in milpa.kdl.

    Use the factory class methods rather than constructing directly:
      DepSpec.git(name, git_url, ref, constraint=None)
      DepSpec.named(name, constraint)
    """

    name: str
    # git dep fields (None for named deps)
    git_url: Optional[str]
    ref: Optional[str]
    # version constraint (applies to both named and git deps; optional)
    constraint: Optional[str]

    @classmethod
    def git(
        cls,
        name: str,
        git_url: str,
        ref: str,
        constraint: Optional[str] = None,
    ) -> "DepSpec":
        """A URL/git dep: resolved via mocked-fetches transport."""
        return cls(name=name, git_url=git_url, ref=ref, constraint=constraint)

    @classmethod
    def named(cls, name: str, constraint: str) -> "DepSpec":
        """A named/index dep: resolved via the tianguis index."""
        return cls(name=name, git_url=None, ref=None, constraint=constraint)

    @property
    def is_git(self) -> bool:
        return self.git_url is not None

    @property
    def is_named(self) -> bool:
        return self.git_url is None


@dataclass
class FetchEntry:
    """Mocked content for one (url, ref) fetch round-trip.

    sha            — 40-char lowercase hex git commit SHA
    content_files  — mapping of relative path → file bytes (the content/ tree)
    nimble_text    — text of <name>.nimble, or None if the dep has no nimble file
    """

    sha: str
    content_files: dict[str, bytes]
    nimble_text: Optional[str]


@dataclass(frozen=True)
class IndexVersionEntry:
    """One version of a named package in the tianguis index."""

    version: str
    content_hash: str       # "sha256:<hex>"
    git_url: str
    ref: str
    commit_sha: str


@dataclass
class IndexRow:
    """One package entry in the tianguis index (index.kdl).

    TODO (slice 3b): add multi-provenance support (OCI, tarball) when the
    generator exercises those dep kinds.
    """

    name: str
    versions: list[IndexVersionEntry]


# ---------------------------------------------------------------------------
# FixtureSpec — the single structured value
# ---------------------------------------------------------------------------

_VALID_CMDS = frozenset({"resolve", "frozen", "parse-lockfile"})


@dataclass
class FixtureSpec:
    """The whole structured value for one differential test fixture.

    INVARIANTS:
    1. Every git DepSpec in `deps` MUST have a matching FetchEntry in
       `fetch_map` keyed by (dep.git_url, dep.ref). This invariant is what
       makes shrinking safe: drop a dep → drop its fetch entry atomically.
    2. Every IndexVersionEntry across all `index_rows` MUST have a matching
       FetchEntry in `index_fetch_map` keyed by (ve.git_url, ve.ref), AND
       the package name for that version must match the row's name
       (enforced by the (pkg_name, FetchEntry) value).
       This ensures every index version is resolvable by the mocked transport.
    3. Every named DepSpec in `deps` must name a package present in
       `index_rows`. This ensures the resolver can find named deps.
    4. For every IndexVersionEntry, every package named in the corresponding
       FetchEntry's nimble `requires` lines must appear in `index_rows` (or
       be resolvable as a URL dep). This ensures transitive deps are complete.

    Fields
    ------
    package_name       — the `name` node value in milpa.kdl
    kind               — the `kind` node value ("application" | "library")
    deps               — ordered list of DepSpec (manifest dep order)
    fetch_map          — (git_url, ref) → FetchEntry for each git dep
    index_rows         — optional list of IndexRow for named deps (serialized to index.kdl)
    index_fetch_map    — (git_url, ref) → (pkg_name, FetchEntry) for each index
                         version entry; the mocked-transport content for named deps.
    cmd                — fixture cmd ("resolve" | "frozen" | "parse-lockfile")

    TODO (slice 3b): add `lock_entries` for frozen fixtures that need a milpa.lock.
    """

    package_name: str
    kind: str
    deps: list[DepSpec]
    fetch_map: dict[tuple[str, str], FetchEntry]
    index_rows: list[IndexRow] = field(default_factory=list)
    index_fetch_map: dict[tuple[str, str], tuple[str, FetchEntry]] = field(default_factory=dict)
    cmd: str = "resolve"

    def __post_init__(self) -> None:
        if self.cmd not in _VALID_CMDS:
            raise ValueError(
                f"Unknown fixture cmd {self.cmd!r}; must be one of {sorted(_VALID_CMDS)}"
            )
        # Invariant 1: every git dep must have a FetchEntry
        for dep in self.deps:
            if dep.is_git:
                key = (dep.git_url, dep.ref)
                if key not in self.fetch_map:
                    raise ValueError(
                        f"git dep {dep.name!r} (url={dep.git_url!r} ref={dep.ref!r}) "
                        f"has no matching FetchEntry in fetch_map"
                    )

    def validate(self) -> list[str]:
        """Return a list of consistency violations (empty = valid).

        Checks invariants 2–4 that are too expensive for __post_init__ and
        that the generator must guarantee by construction:

        2. Every index version entry has a fetch entry in index_fetch_map.
        3. Every named DepSpec names a package present in index_rows.
        4. Every `requires "<name> ..."` line in an index version's nimble
           names a package present in index_rows (transitive completeness).

        This is called by the tier-2 Hypothesis generator to assert the
        generated FixtureSpec is self-consistent before running impls.
        """
        errors: list[str] = []
        index_names = {row.name for row in self.index_rows}

        # Invariant 2: every index version has a fetch entry
        for row in self.index_rows:
            for ve in row.versions:
                key = (ve.git_url, ve.ref)
                if key not in self.index_fetch_map:
                    errors.append(
                        f"index version {row.name!r} {ve.version!r} "
                        f"(url={ve.git_url!r} ref={ve.ref!r}) "
                        f"has no entry in index_fetch_map"
                    )

        # Invariant 3: every named dep names a known package
        for dep in self.deps:
            if dep.is_named and dep.name not in index_names:
                errors.append(
                    f"named dep {dep.name!r} is not present in index_rows"
                )

        # Invariant 4: transitive requires completeness
        for (url, ref), (pkg_name, entry) in self.index_fetch_map.items():
            if entry.nimble_text is None:
                continue
            for req_name in _parse_nimble_requires_names(entry.nimble_text):
                if req_name not in index_names:
                    errors.append(
                        f"index version {pkg_name!r} ({url!r}@{ref!r}) requires "
                        f"{req_name!r} which is not in index_rows"
                    )

        return errors


# ---------------------------------------------------------------------------
# Serializer
# ---------------------------------------------------------------------------

def serialize(spec: FixtureSpec, dest: Path) -> None:
    """Project a FixtureSpec to a fixture input directory.

    Creates `dest` if it does not exist. Writes:
      - cmd
      - milpa.kdl
      - mocked-fetches/<key>/{sha, content/<files>, <name>.nimble}
        (git deps from fetch_map + index version entries from index_fetch_map)
      - index.kdl  (only when spec.index_rows is non-empty)

    Does NOT write expected/ (not needed for differential loop fixtures).
    Does NOT write milpa.lock (TODO slice 3b — frozen fixtures).
    """
    dest.mkdir(parents=True, exist_ok=True)

    _write_cmd(spec, dest)
    _write_manifest(spec, dest)
    _write_mocked_fetches(spec, dest)
    if spec.index_rows:
        _write_index(spec, dest)


def _write_cmd(spec: FixtureSpec, dest: Path) -> None:
    (dest / "cmd").write_text(spec.cmd + "\n")


def _write_manifest(spec: FixtureSpec, dest: Path) -> None:
    """Emit milpa.kdl matching the manifest grammar (spec/manifest-grammar.md).

    Shape mirrors real corpus fixtures:
      name "<package_name>"
      kind "<kind>"
      deps {
          <name> git=(url)"<url>" ref="<ref>"   // for git deps
          <name> "<constraint>"                  // for named deps
      }
    """
    lines: list[str] = []
    lines.append(f'name "{spec.package_name}"')
    lines.append(f'kind "{spec.kind}"')
    if spec.deps:
        lines.append("deps {")
        for dep in spec.deps:
            if dep.is_git:
                dep_line = f'    {dep.name} git=(url)"{dep.git_url}" ref="{dep.ref}"'
                if dep.constraint is not None:
                    dep_line += f' constraint="{dep.constraint}"'
            else:
                # named dep: <name> "<constraint>"
                dep_line = f'    {dep.name} "{dep.constraint}"'
            lines.append(dep_line)
        lines.append("}")
    lines.append("")  # trailing newline
    (dest / "milpa.kdl").write_text("\n".join(lines))


def _write_mocked_fetches(spec: FixtureSpec, dest: Path) -> None:
    """Write mocked-fetches/<key>/{sha, content/<files>, <name>.nimble}.

    Writes two kinds of entries:
    1. Git DepSpec entries from spec.fetch_map (keyed by dep's git_url+ref).
    2. Index version entries from spec.index_fetch_map (keyed by each
       IndexVersionEntry's git_url+ref, with the package name from the map).
    """
    def _write_entry(key_dir: Path, pkg_name: str, entry: FetchEntry) -> None:
        key_dir.mkdir(parents=True, exist_ok=True)
        # sha — one line, no trailing whitespace beyond newline
        (key_dir / "sha").write_text(entry.sha + "\n")
        # content/ tree
        content_dir = key_dir / "content"
        content_dir.mkdir(exist_ok=True)
        for rel_path, data in entry.content_files.items():
            file_path = content_dir / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(data, str):
                file_path.write_text(data)
            else:
                file_path.write_bytes(data)
        # <name>.nimble (optional)
        if entry.nimble_text is not None:
            (key_dir / f"{pkg_name}.nimble").write_text(entry.nimble_text)

    # Git deps from fetch_map
    for dep in spec.deps:
        if not dep.is_git:
            continue
        key = url_key(dep.git_url, dep.ref)
        entry = spec.fetch_map[(dep.git_url, dep.ref)]
        _write_entry(dest / "mocked-fetches" / key, dep.name, entry)

    # Index version entries from index_fetch_map (named dep mocked transport)
    for (git_url, ref), (pkg_name, entry) in spec.index_fetch_map.items():
        key = url_key(git_url, ref)
        _write_entry(dest / "mocked-fetches" / key, pkg_name, entry)


def _write_index(spec: FixtureSpec, dest: Path) -> None:
    """Emit index.kdl matching the tianguis registry-protocol schema.

    Shape mirrors fixture-061-named-dep/index.kdl:
      schema_version 1
      package "<name>" {
          version "<ver>" {
              content_hash "<hash>"
              provenance {
                  kind "git"
                  url "<url>"
                  ref "<ref>"
                  commit_sha "<sha>"
              }
          }
      }
    """
    lines: list[str] = ["schema_version 1"]
    for row in spec.index_rows:
        lines.append(f'package "{row.name}" {{')
        for ve in row.versions:
            lines.append(f'    version "{ve.version}" {{')
            lines.append(f'        content_hash "{ve.content_hash}"')
            lines.append(f'        provenance {{')
            lines.append(f'            kind "git"')
            lines.append(f'            url "{ve.git_url}"')
            lines.append(f'            ref "{ve.ref}"')
            lines.append(f'            commit_sha "{ve.commit_sha}"')
            lines.append(f'        }}')
            lines.append(f'    }}')
        lines.append("}")
    lines.append("")  # trailing newline
    (dest / "index.kdl").write_text("\n".join(lines))
