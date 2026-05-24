"""Heuristic parser for `.nimble` files.

nimble files are nimscript (Turing-complete Nim code), so a faithful
parse would require running Nim. We do not — instead we extract the
`requires` and `srcDir` lines via a line-by-line scan that handles
the four forms seen in real-world packages (single-line, comma-
separated, multi-line continuation, multiple requires statements).

Out of scope: when blocks, computed deps, escaped quotes. See backlog
issue #26 for the when-block extension when real consumers hit it.
"""

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(frozen=True)
class UrlRequirement:
    spec: str            # verbatim original (for round-trip + error msgs)
    url: str
    ref: str | None      # None if no `#ref` appended


@dataclass(frozen=True)
class NamedRequirement:
    spec: str
    name: str
    constraint: str | None   # e.g. '>= 0.5.0' or None for any version


Requirement = UrlRequirement | NamedRequirement


@dataclass(frozen=True)
class NimbleManifest:
    requires: tuple[Requirement, ...]
    src_dir: str | None


class NimbleParseError(Exception):
    """Raised when a .nimble file cannot be read or parsed."""


_URL_SCHEMES = ("http://", "https://", "ssh://", "git://", "file://")

_REQUIRES_RE = re.compile(r"^\s*requires\s+(.*)$")
_SRCDIR_RE = re.compile(r'^\s*srcDir\s*=\s*"?([^"\s]+)"?\s*$')
_QUOTED_RE = re.compile(r'"([^"]*)"')
_WHEN_RE = re.compile(r"^\s*when\b")


def parse_nimble(text: str) -> NimbleManifest:
    """Parse a .nimble file's text into a typed NimbleManifest.

    nimscript `when` blocks are not evaluated (the language is
    Turing-complete; we don't run arbitrary code at resolve time).
    If any `when` is detected, we emit a warning and conservatively
    include every `requires` we find — over-including is harmless to
    the resolver, under-including would silently break the build.
    See #26 Part B."""
    import warnings as _warnings
    specs: list[str] = []
    src_dir: str | None = None
    has_when = False
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = _strip_comment(lines[i])
        if _WHEN_RE.match(line):
            has_when = True
        # Try srcDir first — single-line, simple regex.
        srcdir_match = _SRCDIR_RE.match(line)
        if srcdir_match:
            src_dir = srcdir_match.group(1)
            i += 1
            continue
        # Try requires — handle continuation via trailing-comma rule.
        requires_match = _REQUIRES_RE.match(line)
        if requires_match:
            tail = requires_match.group(1).strip()
            while tail.endswith(","):
                i += 1
                if i >= len(lines):
                    break
                tail = tail + " " + _strip_comment(lines[i]).strip()
            specs.extend(_QUOTED_RE.findall(tail))
        i += 1
    if has_when:
        _warnings.warn(
            ".nimble contains `when` block(s); milpa does not evaluate "
            "nimscript, so all `requires` are included unconditionally. "
            "If this over-includes, consider expressing the conditionality "
            "in milpa.kdl with platform=/nim= predicates (#26).",
            UserWarning,
            stacklevel=2,
        )
    requires = tuple(_parse_spec(s) for s in specs)
    return NimbleManifest(requires=requires, src_dir=src_dir)


def load_nimble(path: Path) -> NimbleManifest:
    """Read a .nimble file from `path` and parse it.

    Raises NimbleParseError if the file is missing or unreadable.
    The error message includes the path so consumers can locate the
    offending file.
    """
    try:
        text = path.read_text()
    except FileNotFoundError as e:
        raise NimbleParseError(f".nimble file not found: {path}") from e
    except OSError as e:
        raise NimbleParseError(f"cannot read .nimble {path}: {e}") from e
    return parse_nimble(text)


def _strip_comment(line: str) -> str:
    """Strip a `# ...` comment from a line, ignoring `#` inside strings.

    Naive: walk the line tracking whether we're inside a double-quoted
    string. Sufficient for real-world .nimble files where escape
    sequences are rare in deps/srcDir lines.
    """
    out = []
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


def _parse_spec(spec: str) -> Requirement:
    """Parse a single requirement spec into the right Requirement variant."""
    if spec.startswith(_URL_SCHEMES):
        if "#" in spec:
            url, _, ref = spec.partition("#")
            return UrlRequirement(spec=spec, url=url, ref=ref)
        return UrlRequirement(spec=spec, url=spec, ref=None)
    parts = spec.split(maxsplit=1)
    name = parts[0]
    constraint = parts[1].strip() if len(parts) > 1 else None
    return NamedRequirement(spec=spec, name=name, constraint=constraint)
