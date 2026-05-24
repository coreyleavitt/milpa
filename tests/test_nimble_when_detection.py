"""nimble `.nimble` parser detects `when` blocks around `requires`
(#26 Part B).

milpa cannot safely evaluate nimscript (which is Turing-complete and
arbitrary code). The honest answer is: detect the `when` block,
WARN the user, and conservatively INCLUDE all guarded requires.

Better to over-include (extra dep in the graph, harmless) than to
silently drop a dep the user actually needs.
"""

import warnings

import pytest

from milpa.nimble_parse import parse_nimble


def test_when_block_around_requires_emits_warning_and_keeps_reqs():
    """A nimble file with `when defined(release): requires "foo"`
    must include 'foo' and emit a warning about the unsafe-to-evaluate
    `when` block."""
    text = '''srcDir = "src"
requires "always_here"

when defined(release):
    requires "release_only"
else:
    requires "debug_only"
'''
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        nm = parse_nimble(text)

    names = {req.name for req in nm.requires}
    # All three requires were extracted (conservative over-include)
    assert "always_here" in names
    assert "release_only" in names
    assert "debug_only" in names

    # A warning was emitted naming the gate
    when_warnings = [w for w in caught if "when" in str(w.message).lower()]
    assert when_warnings, (
        f"expected a `when`-block warning; got: {[str(w.message) for w in caught]}"
    )
