"""Low-level KDL parsing helpers shared across milpa modules.

These utilities handle quirks of the kdl-py library that appear in
multiple call sites — keeping each site DRY and preventing divergence.
"""

from urllib.parse import ParseResult


def url_value_to_str(value: object) -> str:
    """Normalize a KDL scalar value to a plain URL string.

    The kdl-py library parses `(url)`-annotated values (e.g.
    `(url)"https://..."`) into a `urllib.parse.ParseResult` rather than
    a `str`. Both forms are accepted here; bare strings are returned
    unchanged. Any other type returns an empty string (matching the
    behaviour of the pre-extraction call sites)."""
    if isinstance(value, ParseResult):
        return value.geturl()
    if isinstance(value, str):
        return value
    return ""
