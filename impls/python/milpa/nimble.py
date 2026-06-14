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
from milpa.predicate import Predicate
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


# ---------------------------------------------------------------------------
# parse_when_condition — RFC §3.1 S1
# ---------------------------------------------------------------------------

# Platform vocabulary: canonical token → canonical predicate value.
# Aliases normalize to the canonical name.
_PLATFORM_TOKENS: dict[str, str] = {
    "linux": "linux",
    "macosx": "macosx",
    "macos": "macosx",   # alias
    "windows": "windows",
    "win": "windows",    # alias
    "freebsd": "freebsd",
    "openbsd": "openbsd",
    "netbsd": "netbsd",
}

# Arch vocabulary (no aliases).
_ARCH_TOKENS: frozenset[str] = frozenset({"amd64", "arm64", "i386"})

# Recognized comparison operators for all Nim version forms.
_NIM_OPS: frozenset[str] = frozenset({">=", ">", "<", "<=", "=="})

# Regex: ``defined(token)`` — whitespace inside parens is tolerated.
_DEFINED_RE: re.Pattern[str] = re.compile(r"^defined\(\s*(\w+)\s*\)$")

# Regex: ``NimMajor OP X`` (no spaces required around operator).
_NIM_MAJOR_RE: re.Pattern[str] = re.compile(
    r"^NimMajor\s*(>=|>|<=|<|==)\s*(\d+)$"
)

# Regex: ``(NimMajor, NimMinor) OP (X, Y)`` — arbitrary internal spacing.
_NIM_TUPLE2_RE: re.Pattern[str] = re.compile(
    r"^\(\s*NimMajor\s*,\s*NimMinor\s*\)\s*(>=|>|<=|<|==)\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)$"
)

# Regex: ``(NimMajor, NimMinor, NimPatch) OP (X, Y, Z)``
_NIM_TUPLE3_RE: re.Pattern[str] = re.compile(
    r"^\(\s*NimMajor\s*,\s*NimMinor\s*,\s*NimPatch\s*\)\s*(>=|>|<=|<|==)\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)$"
)


def _parse_defined(cond: str) -> Predicate | None:
    """Try to parse ``defined(token)`` into a platform or arch Predicate.

    Returns ``None`` if the token is not in the recognized vocabulary
    (including the deliberate ``posix`` exclusion).
    """
    m = _DEFINED_RE.match(cond)
    if not m:
        return None
    token = m.group(1)
    if token in _PLATFORM_TOKENS:
        return Predicate(name="platform", values=(_PLATFORM_TOKENS[token],))
    if token in _ARCH_TOKENS:
        return Predicate(name="arch", values=(token,))
    return None


def _parse_nim_comparison(cond: str) -> Predicate | None:
    """Try to parse a NimMajor/tuple comparison into a single nim Predicate.

    Handles:
    - ``NimMajor OP X``
    - ``(NimMajor, NimMinor) OP (X, Y)``
    - ``(NimMajor, NimMinor, NimPatch) OP (X, Y, Z)``

    Returns ``None`` if the expression doesn't match any of these forms
    or if the operator is not in the recognized set.
    """
    m = _NIM_MAJOR_RE.match(cond)
    if m:
        op, major = m.group(1), m.group(2)
        if op not in _NIM_OPS:
            return None
        return Predicate(name="nim", values=(f"{op}{major}.0.0",))

    m = _NIM_TUPLE2_RE.match(cond)
    if m:
        op, major, minor = m.group(1), m.group(2), m.group(3)
        if op not in _NIM_OPS:
            return None
        return Predicate(name="nim", values=(f"{op}{major}.{minor}.0",))

    m = _NIM_TUPLE3_RE.match(cond)
    if m:
        op, major, minor, patch = m.group(1), m.group(2), m.group(3), m.group(4)
        if op not in _NIM_OPS:
            return None
        return Predicate(name="nim", values=(f"{op}{major}.{minor}.{patch}",))

    return None


def _parse_single(cond: str) -> Predicate | None:
    """Parse a single (non-compound, non-not) condition to a Predicate.

    Tries defined(token) first, then Nim comparison forms.
    Returns ``None`` if unrecognized.
    """
    p = _parse_defined(cond)
    if p is not None:
        return p
    return _parse_nim_comparison(cond)


def parse_when_condition(cond: str) -> tuple[Predicate, ...] | None:
    """Map a NimScript ``when``/``elif`` condition string to Predicates.

    Implements the normative grammar table from RFC §3.1.  Returns a
    non-empty tuple of ``Predicate`` instances when the condition is
    recognized, or ``None`` (UNRECOGNIZED) otherwise.

    Postcondition: a recognized condition ALWAYS yields a non-empty tuple.

    Recognized forms (§3.1 table):
    - ``defined(token)``              → platform or arch Predicate
    - ``not defined(token)``          → negated platform or arch Predicate
    - ``NimMajor OP X``               → nim Predicate ``"OPX.0.0"``
    - ``(NimMajor, NimMinor) OP (X, Y)``
    - ``(NimMajor, NimMinor, NimPatch) OP (X, Y, Z)``
    - ``<nim-tuple> OP1 <v1> and <nim-tuple> OP2 <v2>``  → two nim Predicates

    Deliberately NOT recognized (→ None):
    - ``defined(posix)``              — cross-platform abstraction, not stable
    - Any other ``defined(token)``    — unknown token
    - ``or`` / compound non-nim ``and``
    - Empty / blank input
    """
    stripped = cond.strip()
    if not stripped:
        return None

    # --- ``not <single>`` form ---
    # Accept "not " (one or more spaces) followed by a single recognized form.
    # The inner form must yield exactly 1 predicate; if it yields 0 or >1 → None.
    if stripped.startswith("not ") or stripped.startswith("not\t"):
        inner = stripped[3:].strip()
        inner_pred = _parse_single(inner)
        if inner_pred is None:
            return None
        return (Predicate(name=inner_pred.name, values=inner_pred.values, negated=True),)

    # --- Two-sided ``and`` form ---
    # Split on " and " (with surrounding spaces) to find the two halves.
    # Only recognized when BOTH halves are Nim-tuple comparisons.
    # We try splitting on every occurrence of " and " / "and" and take the
    # first that yields two valid Nim tuple comparisons.
    #
    # Strategy: find "and" token boundaries — split on all whitespace-bounded
    # "and" tokens, try each split point.
    and_parts = _split_on_and(stripped)
    if and_parts is not None:
        left_str, right_str = and_parts
        left_pred = _parse_nim_comparison(left_str)
        right_pred = _parse_nim_comparison(right_str)
        if left_pred is not None and right_pred is not None:
            result = (left_pred, right_pred)
            assert len(result) > 0  # postcondition
            return result
        # One or both sides are not Nim tuple comparisons → unrecognized.
        return None

    # --- Single predicate forms ---
    p = _parse_single(stripped)
    if p is None:
        return None
    result = (p,)
    assert len(result) > 0  # postcondition
    return result


def _split_on_and(cond: str) -> tuple[str, str] | None:
    """Split ``cond`` on the first occurrence of the ``and`` keyword token.

    Returns ``(left, right)`` both stripped, or ``None`` if no valid split.

    The ``and`` must appear as a standalone word (not inside parentheses or
    glued to identifiers).  We find the first occurrence of ``and`` where the
    surrounding characters are not word characters (or start/end of string).
    """
    # Find all positions of "and" as a standalone keyword.
    # Use regex to match word-boundary-like "and" tokens.
    pattern = re.compile(r"(?<!\w)and(?!\w)")
    for m in pattern.finditer(cond):
        left = cond[: m.start()].strip()
        right = cond[m.end() :].strip()
        if left and right:
            return left, right
    return None
