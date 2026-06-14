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

    ``dep_predicates`` is a tuple aligned by index with ``deps``.  Each
    element is the tuple of ``Predicate`` instances that apply to that dep
    (S3b — RFC ``rfc-conditional-requires.md`` §3.3).  An empty tuple
    means either the dep is unconditional or the branch was UNRECOGNIZED
    (over-include carries no annotation).  Defaults to an empty tuple of
    tuples for back-compat (old callers that ignore predicates are safe).

    NOTE: ``NamedDep``/``UrlDep`` are shared with the ``milpa.kdl`` path
    which MUST NOT gain predicates.  Predicates live here (scanner-local),
    not on the dep objects themselves.  The bridge ``edge_sources._nimble_edges``
    is the single crossing point that maps these onto ``NamedRequire``/
    ``UrlRequire`` (which DO carry predicates per spec §3.3).
    """

    deps: tuple[UrlDep | NamedDep, ...]
    src_dir: str | None
    dep_predicates: tuple[tuple[Predicate, ...], ...] = ()


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

# Maximum nesting depth for recursive ``when`` processing (M2 depth-DoS guard).
#
# IMPLEMENTATION NOTE — this is an impl-quality bound shared by the Python and
# Rust impls for DoS-bounding, NOT a normative spec cap on how deep a user is
# allowed to nest ``when`` blocks.  At depth ≥ _MAX_WHEN_DEPTH every branch is
# already forced to predicates=None (over-include) regardless, so further
# structure recognition carries zero predicate information.  Beyond this depth
# we switch to a linear scan (_linear_scan_requires) that collects all
# ``requires`` without structure recognition.  Value of 8 is conservative:
# real .nimble files rarely exceed 2-3 levels of nesting.
_MAX_WHEN_DEPTH: int = 8

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

    NimScript ``when`` blocks: recognized conditions (§5.3 / RFC §3.1–3.2) are
    translated to ``Predicate`` tuples and attached to each extracted require via
    ``NimbleManifest.dep_predicates`` (S3b).  Every requires is STILL included
    unconditionally (dep set is unchanged); predicates are metadata only.

    Warning policy (S3b flip):
    - Recognized branches → NO warning.
    - Any UNRECOGNIZED branch in any chain → emit the spec-mandated ``UserWarning``.
    This replaces the old "any ``when`` keyword → warn" rule.

    This function is **total**: it never raises for bad file content.
    """
    lines = text.splitlines()
    src_dir: str | None = None

    # --- Step 1: run the S3a branch tracker to get per-line predicate mapping ---
    branches = parse_when_branches(lines)

    # Build line→predicates map.  ``None`` = unrecognized branch.
    # A line can appear in at most one branch (parse_when_branches guarantees
    # non-overlapping require_lines across branches).
    line_preds: dict[int, tuple[Predicate, ...] | None] = {}
    has_unrecognized = any(b.predicates is None for b in branches)
    for branch in branches:
        for ln in branch.require_lines:
            line_preds[ln] = branch.predicates  # None = unrecognized

    # --- Step 2: scan for srcDir + collect (spec, line_index) pairs ---
    # srcDir: last assignment wins (spec §7.3 / dep-decl.md; NimScript semantics).
    # We need to track which source line each spec came from so we can look up
    # predicates.  For indented-block requires and the plain form the source
    # line is the ``requires`` keyword line.  For the colon-form tail
    # (``when …: requires "x"``) the source line is the header line itself
    # (matching what parse_when_branches records).
    raw_specs_with_lines: list[tuple[str, int]] = []  # (spec_string, source_line_idx)

    i = 0
    while i < len(lines):
        line = _strip_comment(lines[i])

        # §5.2: ``srcDir`` — last assignment wins (NimScript assignment semantics;
        # spec §7.3 / dep-decl.md).  Rust implements last-wins; Python must match.
        srcdir_m = _SRCDIR_RE.match(line)
        if srcdir_m:
            src_dir = srcdir_m.group(1)  # overwrite on every match (last wins)
            i += 1
            continue

        # §5.1 forms 1-4: plain ``requires`` statement.
        req_m = _REQUIRES_RE.match(line)
        if req_m:
            tail = req_m.group(1).rstrip()
            req_line = i
            # Form 3: multi-line continuation — lines ending with a comma are joined.
            while tail.rstrip(",") != tail or tail.endswith(","):
                i += 1
                if i >= len(lines):
                    break
                next_line = _strip_comment(lines[i]).strip()
                tail = tail + " " + next_line
            for spec in _QUOTED_RE.findall(tail):
                raw_specs_with_lines.append((spec, req_line))
            i += 1
            continue

        # Colon-form requires: ``when …: requires "x"`` / ``elif …: requires "x"``
        # The branch tracker already records these under the header line index.
        # We need to extract the specs from the tail here so they get the header
        # line as their source line (enabling predicate lookup).
        colon_specs = _extract_colon_form_requires(line, i)
        raw_specs_with_lines.extend(colon_specs)

        i += 1

    # §5.3: emit the spec-mandated warning text iff any branch is UNRECOGNIZED.
    if has_unrecognized:
        warnings.warn(
            ".nimble contains `when` block(s); milpa does not evaluate nimscript, so\n"
            "all `requires` are included unconditionally. If this over-includes,\n"
            "consider expressing the conditionality in milpa.kdl with platform=/nim=\n"
            "predicates (#26).",
            UserWarning,
            stacklevel=2,
        )

    # --- Step 3: build typed deps with aligned predicates ---
    # §5.4: drop ``"nim"`` requirements silently.
    # §7.1 (spec/dep-decl.md): NO deduplication — when the same dep name
    # appears in ≥2 ``when`` branches, ALL occurrences are preserved in
    # authored file order so that each carries its own predicate annotation.
    # Over-inclusion is safe; under-inclusion silently drops a dep or predicate.
    deps: list[UrlDep | NamedDep] = []
    dep_predicates: list[tuple[Predicate, ...]] = []

    for spec, source_line in raw_specs_with_lines:
        dep = _build_dep(spec)
        if dep is None:
            continue
        if isinstance(dep, NamedDep) and dep.name == "nim":
            # §5.4: Nim compiler is v2 toolchain territory; drop.
            continue

        # Predicate lookup: recognized branch → its predicates; unrecognized /
        # unconditional → empty tuple (over-include with no annotation).
        raw_preds = line_preds.get(source_line)
        preds: tuple[Predicate, ...] = raw_preds if raw_preds is not None else ()

        deps.append(dep)
        dep_predicates.append(preds)

    return NimbleManifest(
        deps=tuple(deps),
        src_dir=src_dir,
        dep_predicates=tuple(dep_predicates),
    )


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
            name=url_to_name(url),
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


def _extract_colon_form_requires(line: str, line_idx: int) -> list[tuple[str, int]]:
    """Extract specs from the colon-tail of a ``when``/``elif``/``else`` header.

    Handles: ``when <cond>: requires "x"`` and ``elif <cond>: requires "x"``.
    Returns a list of ``(spec_string, line_idx)`` pairs (empty if none found).

    The ``line_idx`` is the header line itself — matching what
    ``parse_when_branches`` records in ``WhenBranch.require_lines``.

    Only extracts when the tail (post-colon text) contains a ``requires``
    keyword followed by at least one quoted string.  The line must be a
    ``when``/``elif``/``else`` header (matched by ``_WHEN_HEADER_RE`` etc.).
    """
    # Match when/elif/else header with a non-empty tail.
    m = _WHEN_HEADER_RE.match(line) or _ELIF_HEADER_RE.match(line) or _ELSE_HEADER_RE.match(line)
    if m is None:
        return []
    # For when/elif: group(3) is the tail; for else: group(2) is the tail.
    # Both regexes capture tail as the last group.
    tail = m.group(m.lastindex).strip() if m.lastindex else ""
    if not tail:
        return []
    # Check the tail starts with (or contains) a ``requires`` keyword.
    req_m = _REQUIRES_RE.match(tail)
    if not req_m:
        return []
    req_tail = req_m.group(1).rstrip()
    specs = _QUOTED_RE.findall(req_tail)
    return [(spec, line_idx) for spec in specs]


def url_to_name(url: str) -> str:
    """Derive a package name from a git URL.

    Strips the scheme, takes the last path component, and removes
    ``.git`` suffix if present.  This mirrors the convention used by
    nimble itself.  The result is the dep's logical name in ``NimbleManifest``.

    This is the **single source of truth** for URL→name derivation (M3 SSOT).
    ``edge_sources._name_from_url`` wraps this function to add the None-drop
    behavior needed at the EdgeSet level.

    Returns a non-empty string on all inputs (worst-case: the full URL string
    is returned if no path component can be extracted — this preserves UrlDep
    round-trips even for degenerate inputs).
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


# ---------------------------------------------------------------------------
# parse_when_branches — RFC §3.2 S3a
# ---------------------------------------------------------------------------

# Header patterns (after comment-stripping).
_WHEN_HEADER_RE: re.Pattern[str] = re.compile(r"^(\s*)when\s+(.*?)\s*:\s*(.*?)\s*$")
_ELIF_HEADER_RE: re.Pattern[str] = re.compile(r"^(\s*)elif\s+(.*?)\s*:\s*(.*?)\s*$")
_ELSE_HEADER_RE: re.Pattern[str] = re.compile(r"^(\s*)else\s*:\s*(.*?)\s*$")

# Detects a ``requires`` keyword at the start of a (stripped) line.
_BRANCH_REQUIRES_RE: re.Pattern[str] = re.compile(r"^\s*requires\b")

# Detects a ``requires`` keyword appearing in the post-colon tail of a header.
_TAIL_REQUIRES_RE: re.Pattern[str] = re.compile(r"\brequires\b")


@dataclass(frozen=True)
class WhenBranch:
    """One branch of a ``when``/``elif``/``else`` chain that contains requires.

    ``predicates`` is the tuple of ``Predicate`` instances that apply to every
    ``requires`` in this branch.  ``None`` means the branch is UNRECOGNIZED
    (over-include + warn): either the chain was poisoned (unrecognized condition
    or multi-pred condition with siblings) or the branch is inside a nested
    ``when`` block (depth ≥ 1).

    ``require_lines`` is the tuple of 0-based line indices (into the input
    ``lines`` list) of the STARTING line of each ``requires`` statement in this
    branch.  For the single-line colon form (``when … : requires …``), the index
    is the header line itself.
    """

    predicates: tuple[Predicate, ...] | None
    require_lines: tuple[int, ...]


def _negate_predicate(p: Predicate) -> Predicate:
    """Return p with the ``negated`` flag flipped (RFC §3.2 negation rule)."""
    return Predicate(name=p.name, values=p.values, negated=not p.negated)


def _leading_spaces(line: str) -> int:
    """Count leading space characters (tabs count as one character each)."""
    count = 0
    for ch in line:
        if ch in (" ", "\t"):
            count += 1
        else:
            break
    return count


def parse_when_branches(lines: list[str]) -> list[WhenBranch]:
    """Parse ``when``/``elif``/``else`` chains from ``.nimble`` file lines.

    Returns a list of :class:`WhenBranch` instances, one per branch that
    contains at least one direct ``requires`` statement.  Branches with no
    direct requires are omitted.  ``requires`` outside any ``when`` chain are
    NOT reported.

    This function is **total**: it never raises on malformed or unexpected input.

    Semantics (RFC §3.2):
    - An indentation-aware state machine identifies chain headers (``when``,
      ``elif``, ``else``) and their body lines.
    - A chain is a ``when`` header followed by zero or more ``elif``/``else``
      headers at the SAME indent level.
    - Predicate computation per chain:
      - If ANY condition is unrecognized OR (the chain has >1 branch AND any
        condition has >1 predicate), the entire chain is poisoned: every branch
        gets ``predicates=None``.
      - Otherwise: ``when`` branch → its own predicates; ``elif`` → its
        predicates AND negations of all prior conditions; ``else`` → negations
        of all preceding conditions.
    - Branches inside a nested ``when`` block (depth ≥ 1) get ``predicates=None``
      regardless of their conditions.
    - Report order: branches in order of their header line index.
    """
    result: list[WhenBranch] = []

    # We collect chains level by level.  The outer loop scans for ``when``
    # headers; for each one it reads the full chain (``elif``/``else`` at the
    # same indent) and dispatches branches recursively for nested whens.
    _scan_region(lines, 0, len(lines), depth=0, result=result)
    # Sort by the header line of each branch's first require (already insertion-
    # ordered, but confirm stability across nested paths).
    # The recursive traversal already visits lines top-to-bottom; no re-sort
    # needed.
    return result


def _skip_continuation(lines: list[str], i: int, end: int, first_tail: str) -> int:
    """Advance ``i`` past a multi-line ``requires`` continuation, return new index.

    A continuation is a sequence of lines where the current accumulated tail
    ends with a comma — identical logic used by both ``_linear_scan_requires``
    and ``_collect_direct_requires``.

    ``first_tail`` is the already-stripped text of the current (starting) line.
    Returns the index of the LAST line consumed (the caller should then
    ``i += 1`` to move to the next statement).

    Only the STARTING line of the continuation is recorded as the require's
    source line; callers must append ``i`` to ``out``/``req_indices`` BEFORE
    calling this helper.
    """
    tail = first_tail.rstrip()
    while tail.endswith(","):
        i += 1
        if i >= end:
            break
        tail = _strip_comment(lines[i]).strip()
    return i


def _linear_scan_requires(
    lines: list[str],
    start: int,
    end: int,
    result: list[WhenBranch],
) -> None:
    """Collect ALL ``requires`` in lines[start:end] with ``predicates=None``.

    This is the depth-guard fallback: once nesting depth exceeds ``_MAX_WHEN_DEPTH``
    there is zero predicate information to carry, so we abandon structure recognition
    entirely and do a single linear pass.  This keeps M2 O(n) in the pathological case.

    All discovered requires are reported as a single ``WhenBranch(predicates=None)``.
    The ``require_lines`` list records the starting line of each ``requires`` statement
    in the same manner as ``_collect_direct_requires``.
    """
    req_indices: list[int] = []
    i = start
    while i < end:
        stripped = _strip_comment(lines[i])
        if stripped and _BRANCH_REQUIRES_RE.match(stripped):
            req_indices.append(i)
            # Skip multi-line continuation (shared helper; only start line recorded).
            i = _skip_continuation(lines, i, end, stripped)
        i += 1
    if req_indices:
        result.append(WhenBranch(predicates=None, require_lines=tuple(req_indices)))


def _scan_region(
    lines: list[str],
    start: int,
    end: int,
    *,
    depth: int,
    result: list[WhenBranch],
) -> None:
    """Scan lines[start:end] for ``when`` chains, appending to ``result``.

    ``depth`` is the nesting level (0 = top-level scan).  Any chain found
    at depth ≥ 1 has all its branches forced to ``predicates=None``.

    M2 depth guard: when ``depth >= _MAX_WHEN_DEPTH``, every nested branch
    already carries ``predicates=None`` and further structure recognition only
    adds O(n²) overhead per level.  Instead, do a single linear scan for
    ``requires`` statements (over-include with no annotation) and return.
    This bounds pathological worst-case from O(n³) to O(n).
    """
    # M2: depth guard — bail to linear scan for deep nesting.
    if depth >= _MAX_WHEN_DEPTH:
        _linear_scan_requires(lines, start, end, result)
        return

    i = start
    while i < end:
        raw = lines[i]
        stripped = _strip_comment(raw)

        m = _WHEN_HEADER_RE.match(stripped)
        if m is None:
            i += 1
            continue

        # Found a ``when`` header at this level.
        header_indent = len(m.group(1))
        when_cond = m.group(2).strip()
        when_tail = m.group(3).strip()
        when_line = i

        # Collect the full chain: this branch's body + any elif/else at same indent.
        # A "branch" is (kind, cond_or_None, tail, header_line, body_start, body_end).
        # kind: "when" | "elif" | "else"
        branches_raw: list[tuple[str, str | None, str, int, int, int]] = []

        # Body of the ``when`` branch: lines strictly more indented than header.
        body_start = i + 1
        j = body_start
        while j < end:
            braw = lines[j]
            bstripped = _strip_comment(braw)
            if bstripped == "":
                j += 1
                continue
            b_indent = _leading_spaces(bstripped)
            if b_indent <= header_indent:
                break
            j += 1
        body_end = j

        branches_raw.append(("when", when_cond, when_tail, when_line, body_start, body_end))

        # Now scan for elif/else at the same indent immediately after.
        k = body_end
        while k < end:
            kraw = lines[k]
            kstripped = _strip_comment(kraw)
            if kstripped == "":
                k += 1
                continue
            k_indent = _leading_spaces(kstripped)
            if k_indent != header_indent:
                break

            em = _ELIF_HEADER_RE.match(kstripped)
            if em:
                elif_cond = em.group(2).strip()
                elif_tail = em.group(3).strip()
                elif_line = k
                eb_start = k + 1
                ej = eb_start
                while ej < end:
                    ejraw = lines[ej]
                    ejstripped = _strip_comment(ejraw)
                    if ejstripped == "":
                        ej += 1
                        continue
                    ej_indent = _leading_spaces(ejstripped)
                    if ej_indent <= header_indent:
                        break
                    ej += 1
                eb_end = ej
                branches_raw.append(("elif", elif_cond, elif_tail, elif_line, eb_start, eb_end))
                k = eb_end
                continue

            esm = _ELSE_HEADER_RE.match(kstripped)
            if esm:
                else_tail = esm.group(2).strip() if esm.lastindex and esm.lastindex >= 2 else ""
                # else_tail: the remainder after "else:" on the same line
                # group(2) if the pattern has a capture for it
                else_line = k
                es_start = k + 1
                esj = es_start
                while esj < end:
                    esjraw = lines[esj]
                    esjstripped = _strip_comment(esjraw)
                    if esjstripped == "":
                        esj += 1
                        continue
                    esj_indent = _leading_spaces(esjstripped)
                    if esj_indent <= header_indent:
                        break
                    esj += 1
                es_end = esj
                branches_raw.append(("else", None, else_tail, else_line, es_start, es_end))
                k = es_end
                break  # ``else`` terminates the chain

            # Non-elif/else at the same indent → chain ends.
            break

        # Advance outer scan past the full chain.
        i = k

        # --- Predicate computation ---
        # Compute recognized predicates for each when/elif condition.
        conditions: list[tuple[Predicate, ...] | None] = []
        for kind, cond, _, _, _, _ in branches_raw:
            if kind in ("when", "elif") and cond is not None:
                conditions.append(parse_when_condition(cond))
            else:
                conditions.append(None)  # else has no condition

        # Poison test:
        # (a) any recognized condition is None → poison
        # (b) chain has >1 branch AND any recognized condition has >1 predicate → poison
        chain_has_siblings = len(branches_raw) > 1
        poisoned = False
        for idx, (kind, cond, _, _, _, _) in enumerate(branches_raw):
            if kind in ("when", "elif"):
                pk = conditions[idx]
                if pk is None:
                    poisoned = True
                    break
                if chain_has_siblings and len(pk) > 1:
                    poisoned = True
                    break

        # Assign per-branch predicates.
        branch_predicates: list[tuple[Predicate, ...] | None] = []
        if poisoned or depth >= 1:
            for _ in branches_raw:
                branch_predicates.append(None)
        else:
            # Accumulate negations of prior conditions.
            prior_negations: list[Predicate] = []
            for idx, (kind, cond, _, _, _, _) in enumerate(branches_raw):
                if kind == "when":
                    pk = conditions[idx]
                    assert pk is not None
                    branch_predicates.append(pk)
                    # Store negations for subsequent elif/else.
                    # Each predicate in pk negates independently (RFC §3.2).
                    # Since chain is non-poisoned and has siblings → each pk is
                    # exactly 1 predicate (guaranteed by the poison check above).
                    # For solo ``when`` (no siblings), negation is never needed.
                    for p in pk:
                        prior_negations.append(_negate_predicate(p))
                elif kind == "elif":
                    pk = conditions[idx]
                    assert pk is not None
                    # elif branch: (pk) + (negations of all prior conditions)
                    branch_predicates.append(pk + tuple(prior_negations))
                    for p in pk:
                        prior_negations.append(_negate_predicate(p))
                else:  # else
                    branch_predicates.append(tuple(prior_negations))

        # Collect direct requires from each branch's body and tail.
        for b_idx, (kind, cond, tail, header_line, body_start, body_end) in enumerate(
            branches_raw
        ):
            req_indices: list[int] = []

            # Single-line colon form: check the tail (text after "when …:").
            if tail and _TAIL_REQUIRES_RE.search(tail):
                req_indices.append(header_line)

            # Body: collect direct requires (skip nested when blocks).
            _collect_direct_requires(
                lines, body_start, body_end, header_indent, req_indices
            )

            if req_indices:
                result.append(
                    WhenBranch(
                        predicates=branch_predicates[b_idx],
                        require_lines=tuple(req_indices),
                    )
                )

            # Recurse into the body for nested ``when`` blocks.
            _scan_region(
                lines, body_start, body_end, depth=depth + 1, result=result
            )


def _collect_direct_requires(
    lines: list[str],
    start: int,
    end: int,
    outer_indent: int,
    out: list[int],
) -> None:
    """Collect line indices of ``requires`` statements in lines[start:end].

    Only collects requires that are NOT inside a deeper nested ``when`` block
    (i.e., direct requires of the enclosing branch).

    ``outer_indent`` is the indent of the enclosing ``when``/``elif``/``else``
    header.  Lines in this region are strictly more indented than ``outer_indent``.

    Multi-line continuation: only the starting line is recorded.
    """
    i = start
    while i < end:
        raw = lines[i]
        stripped = _strip_comment(raw)
        if stripped == "":
            i += 1
            continue

        line_indent = _leading_spaces(stripped)

        # If we hit a nested ``when``, skip its entire body.
        wm = _WHEN_HEADER_RE.match(stripped)
        if wm:
            nested_indent = len(wm.group(1))
            # Skip body lines of the nested when (and its elif/else).
            j = i + 1
            while j < end:
                js = _strip_comment(lines[j])
                if js == "":
                    j += 1
                    continue
                if _leading_spaces(js) <= nested_indent:
                    # Could be elif/else of the nested when — skip those too.
                    em = _ELIF_HEADER_RE.match(js)
                    esm = _ELSE_HEADER_RE.match(js)
                    if (em or esm) and _leading_spaces(js) == nested_indent:
                        # Skip this elif/else header and its body.
                        j += 1
                        while j < end:
                            ejs = _strip_comment(lines[j])
                            if ejs == "":
                                j += 1
                                continue
                            if _leading_spaces(ejs) <= nested_indent:
                                break
                            j += 1
                        continue
                    break
                j += 1
            i = j
            continue

        # Check for requires.
        if _BRANCH_REQUIRES_RE.match(stripped):
            out.append(i)
            # Skip multi-line continuation (shared helper; only start line recorded).
            i = _skip_continuation(lines, i, end, stripped)
            i += 1
            continue

        i += 1
