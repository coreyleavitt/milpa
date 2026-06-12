"""Stage-0 scaffold smoke tests."""

import milpa


def test_version_present() -> None:
    """Package is importable and declares a version."""
    assert milpa.__version__ == "0.0.1"
