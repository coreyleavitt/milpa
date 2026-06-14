"""Heuristic line-scanner for ``.nimble`` files.

``.nimble`` files are NimScript (Turing-complete Nim code); milpa does NOT
execute them.  Instead this module performs a **total** line-by-line scan that
extracts as much information as possible and silently ignores everything else.

Design: **scanner is total; EdgeSource validates** (mirrors the Rust reference).
  The scanner (``parse_nimble`` / ``_build_dep``) never raises ``MilpaError``
  for mal-formed input within the file.  A constraint that fails
  ``VersionSet.from_nimble_constraint`` is preserved as a raw string
  (``NamedDep.constraint`` set, ``NamedDep.constraint_set = None``) so the
  caller can inspect or escalate it.

  The validation decision — raise ``MAN-NIMBLE-CONSTRAINT`` or widen to
  ``VersionSet.full()`` — belongs to the **EdgeSource layer**:
  ``NimbleEdgeSource`` (in ``edge_sources.py``) raises for NimbleFallback
  sources; ``edgeset_to_terms`` widens for MilpaKdl/DepDecl sources.
  This mirrors the Rust reference (``resolver.rs`` ~line 1326-1348).

  File-read failures (not found / unreadable) are NOT handled here — that is
  the responsibility of ``workspace.py``'s ``_load_nimble_file`` helper, which
  raises ``MilpaError`` (``NIMBLE-FILE-NOT-FOUND`` / ``NIMBLE-FILE-UNREADABLE``)
  consistently with the rest of the error model.  This module is pure
  text↔value; no filesystem I/O lives here.

The result is a ``NimbleManifest`` whose ``deps`` are ``UrlDep | NamedDep``
instances.  For ``NamedDep`` entries with a malformed constraint,
``constraint_set`` is ``None`` and ``constraint`` holds the raw string.
``"nim"`` requirements are dropped per §5.4.

Entry point
-----------
``parse_nimble(text, *, src_path=None) -> NimbleManifest``
    Parse a raw ``.nimble`` text string.  Never raises for bad content.
    File I/O is the caller's responsibility (see ``workspace._load_nimble_file``).

Spec references
---------------
- ``spec/manifest-grammar.md`` §5 (`.nimble` compatibility parsing)
  - §5.1 Four ``requires`` forms
  - §5.2 ``srcDir``
  - §5.3 ``when``-block policy
  - §5.4 ``nim`` requirement filtering
  - §5.5 Error codes (raised by the file-I/O layer in workspace.py, not here)
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass
from pathlib import Path

from milpa.manifest import NamedDep, UrlDep
from milpa.version import VersionSet

# ---------------------------------------------------------------------------
# NimbleManifest — the scanner's output
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NimbleManifest:
    """The result of scanning a ``.nimble`` file.

    ``deps`` is an ordered tuple of ``UrlDep | NamedDep`` (the ``"nim"``
    entry is excluded per §5.4).  ``src_dir`` is ``None`` when not found.
    """

    deps: tuple[UrlDep | NamedDep, ...]
    src_dir: str | None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_URL_SCHEMES: tuple[str, ...] = (
    "http://",
    "https://",
    "ssh://",
    "git://",
    "file://",
)

# Spec §5.3: any line matching this pattern triggers the ``when`` warning.
_WHEN_RE: re.Pattern[str] = re.compile(r"^\s*when\b")

# ``requires`` keyword — everything after it (on the same line) is the tail.
_REQUIRES_RE: re.Pattern[str] = re.compile(r"^\s*requires\s+(.*)\s*$")

# ``srcDir = "..."`` or ``srcDir = ...`` (quotes optional per §5.2).
_SRCDIR_RE: re.Pattern[str] = re.compile(r'^\s*srcDir\s*=\s*"?([^"\s]+)"?\s*$')

# Extract all double-quoted strings from a line/continuation.
_QUOTED_RE: re.Pattern[str] = re.compile(r'"([^"]*)"')


# ---------------------------------------------------------------------------
# Public: parse_nimble
# ---------------------------------------------------------------------------


def parse_nimble(
    text: str,
    *,
    src_path: Path | None = None,
) -> NimbleManifest:
    """Parse a ``.nimble`` file's text into a ``NimbleManifest``.

    NimScript ``when`` blocks are not evaluated (Turing-complete; milpa
    does not run arbitrary code at resolve time).  If any ``when`` is
    detected the spec-mandated ``UserWarning`` is emitted and all
    ``requires`` are included unconditionally (over-inclusion is safe;
    under-inclusion would silently break builds — §5.3).

    This function is **total**: it never raises for bad file content.
    """
    raw_specs: list[str] = []
    src_dir: str | None = None
    has_when: bool = False

    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = _strip_comment(lines[i])

        # §5.3: detect ``when`` on any line.
        if _WHEN_RE.match(line):
            has_when = True

        # §5.2: ``srcDir`` — first match wins; single-line.
        srcdir_m = _SRCDIR_RE.match(line)
        if srcdir_m:
            if src_dir is None:  # first occurrence wins
                src_dir = srcdir_m.group(1)
            i += 1
            continue

        # §5.1 forms 1-4: ``requires`` — collect raw quoted strings.
        req_m = _REQUIRES_RE.match(line)
        if req_m:
            tail = req_m.group(1).rstrip()
            # Form 3: multi-line continuation — lines ending with a comma
            # (possibly with trailing whitespace/comment) are joined.
            while tail.rstrip(",") != tail or tail.endswith(","):
                # Tail ends with comma → consume the next line.
                i += 1
                if i >= len(lines):
                    break
                next_line = _strip_comment(lines[i]).strip()
                tail = tail + " " + next_line
            raw_specs.extend(_QUOTED_RE.findall(tail))

        i += 1

    # §5.3: emit the spec-mandated warning text verbatim.
    if has_when:
        warnings.warn(
            ".nimble contains `when` block(s); milpa does not evaluate nimscript, so\n"
            "all `requires` are included unconditionally. If this over-includes,\n"
            "consider expressing the conditionality in milpa.kdl with platform=/nim=\n"
            "predicates (#26).",
            UserWarning,
            stacklevel=2,
        )

    # Build typed deps; §5.4: drop ``"nim"`` requirements silently.
    deps: list[UrlDep | NamedDep] = []
    # Dedup key depends on dep kind:
    # - NamedDep: dedup by name (first occurrence wins).
    # - UrlDep: dedup by (name, git, ref) — identical provenance = duplicate.
    #   Two UrlDeps with the same name but DIFFERENT URLs are NOT deduplicated
    #   here; the resolver's provenance gate (resolver-semantics §10.3) detects
    #   the conflict and raises RES-PROVENANCE-CONFLICT.
    seen_named: set[str] = set()
    seen_url: set[tuple[str, str, str]] = set()
    for spec in raw_specs:
        dep = _build_dep(spec)
        if dep is None:
            # Empty spec or no package name → drop silently.
            # Note: malformed constraints are NOT dropped here; _build_dep
            # returns a NamedDep with constraint_set=None so the EdgeSource
            # layer can escalate (NimbleFallback) or widen (MilpaKdl).
            continue
        if isinstance(dep, NamedDep) and dep.name == "nim":
            # §5.4: Nim compiler is v2 toolchain territory; drop.
            continue
        if isinstance(dep, NamedDep):
            if dep.name in seen_named:
                continue
            seen_named.add(dep.name)
        else:
            # UrlDep: dedup by (name, git, ref) — same provenance = duplicate.
            url_key = (dep.name, dep.git, dep.ref)
            if url_key in seen_url:
                continue
            seen_url.add(url_key)
        deps.append(dep)

    return NimbleManifest(deps=tuple(deps), src_dir=src_dir)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _strip_comment(line: str) -> str:
    """Strip a ``# …`` comment from a line, respecting double-quoted strings.

    Walks the line tracking whether the cursor is inside a ``"…"`` string;
    breaks on ``#`` only when outside a string.  Sufficient for real-world
    ``.nimble`` files (the only place nimble puts deps/srcDir is in
    simple assignment/call forms, not inside multi-level escaping).
    """
    out: list[str] = []
    in_string = False
    for ch in line:
        if ch == '"':
            in_string = not in_string
            out.append(ch)
        elif ch == "#" and not in_string:
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def _build_dep(spec: str) -> UrlDep | NamedDep | None:
    """Classify and construct one dep from a raw spec string.

    Returns ``None`` only if the spec is empty or has no package name.
    Malformed constraints are NOT dropped here — the ``NamedDep`` is returned
    with ``constraint_set=None`` and the raw ``constraint`` string preserved,
    so the EdgeSource layer can decide: raise ``MAN-NIMBLE-CONSTRAINT``
    (NimbleFallback) or widen to ``VersionSet.full()`` (MilpaKdl/DepDecl).

    Spec §5.1 URL-vs-named classification:
      - Starts with one of the URL schemes → ``UrlDep`` (``#ref`` split off).
      - Otherwise → ``NamedDep`` (first token = name, rest = constraint).
    """
    spec = spec.strip()
    if not spec:
        return None

    # URL requirement
    if any(spec.startswith(scheme) for scheme in _URL_SCHEMES):
        url, _, ref = spec.partition("#")
        return UrlDep(
            name=_url_to_name(url),
            git=url,
            ref=ref if ref else "HEAD",
        )

    # Named requirement
    parts = spec.split(maxsplit=1)
    name = parts[0].strip()
    if not name:
        return None

    constraint_str: str | None = parts[1].strip() if len(parts) > 1 else None

    # Pre-type the constraint at parse time (§121 discipline).
    # On ValueError: preserve the raw string (constraint_set stays None) so
    # the EdgeSource layer can escalate (NimbleEdgeSource → MAN-NIMBLE-CONSTRAINT)
    # or widen (MilpaKdl/DepDecl → VersionSet.full()).  Mirrors Rust resolver.rs
    # ~line 1326-1348: scanner stores the raw string; EdgeSource validates.
    constraint_set = None
    if constraint_str is not None:
        try:
            constraint_set = VersionSet.from_nimble_constraint(constraint_str)
        except ValueError:
            # Malformed constraint: keep the dep with constraint_set=None.
            # NimbleEdgeSource detects dep.constraint is not None and
            # dep.constraint_set is None → raises MAN-NIMBLE-CONSTRAINT.
            pass

    # NamedDep.__post_init__ would re-parse the constraint if constraint_set
    # is None. Supply the already-parsed value directly via object.__setattr__
    # to avoid a second parse (and to preserve the constraint string for
    # round-trip / error messages).
    dep: NamedDep = object.__new__(NamedDep)
    # Use the dataclass __init__ but bypass __post_init__ re-parse by
    # constructing with constraint_set already filled.
    # NamedDep is a frozen dataclass; supply fields via object.__setattr__.
    object.__setattr__(dep, "name", name)
    object.__setattr__(dep, "constraint", constraint_str)
    object.__setattr__(dep, "constraint_set", constraint_set)
    return dep


def _url_to_name(url: str) -> str:
    """Derive a package name from a git URL.

    Strips the scheme, takes the last path component, and removes
    ``.git`` suffix if present.  This mirrors the convention used by
    nimble itself.  The result is the dep's logical name in ``NimbleManifest``.
    """
    # e.g. "https://github.com/user/pkg.git" → "pkg"
    # e.g. "ssh://github.com/user/repo" → "repo"
    last = url.rstrip("/").rsplit("/", 1)[-1]
    if last.endswith(".git"):
        last = last[:-4]
    return last if last else url
