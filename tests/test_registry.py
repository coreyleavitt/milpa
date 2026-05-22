"""Registry resolver tests.

The pure-decision logic (parse_version, resolve_version, parse_registry)
is exercised directly with synthetic data. Constraint matching is
tested via VersionSet — single source of truth across milpa. I/O paths
(load_registry's cache + fetch, list_remote_tags) are exercised against
local fixtures. No network access required.
"""

from pathlib import Path

import pytest

from milpa.registry import (
    RegistryEntry,
    RegistryError,
    ResolvedRegistryDep,
    list_remote_tags,
    load_registry,
    parse_registry,
    parse_version,
    resolve_named,
    resolve_version,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "registry"


def test_parse_version_strips_v_prefix():
    assert parse_version("v0.5.1") == (0, 5, 1)


def test_parse_version_accepts_unprefixed():
    assert parse_version("0.5.1") == (0, 5, 1)
    assert parse_version("1.0.0") == (1, 0, 0)
    assert parse_version("10.20.30") == (10, 20, 30)


@pytest.mark.parametrize("tag", [
    "random",
    "v1.0.0-beta",
    "nimble-1.2.3",
    "1.0",          # missing patch
    "",
    "v1.0.0+build",
    "0.5.1-rc.1",
])
def test_parse_version_returns_none_for_unparseable(tag):
    assert parse_version(tag) is None


def test_resolve_version_picks_highest_matching():
    available = ["v0.4.0", "v0.5.0", "v0.5.1", "v0.6.0"]
    assert resolve_version(">= 0.5.0", available) == "v0.6.0"


def test_resolve_version_skips_unparseable_tags():
    available = ["v0.5.0", "nightly", "v1.0.0-beta", "v0.6.0"]
    assert resolve_version(">= 0.5.0", available) == "v0.6.0"


def test_resolve_version_no_match_raises():
    with pytest.raises(RegistryError) as exc:
        resolve_version(">= 2.0.0", ["v0.5.0", "v0.6.0"])
    assert ">= 2.0.0" in str(exc.value)
    assert "v0.5.0" in str(exc.value) or "v0.6.0" in str(exc.value)


def test_resolve_version_empty_available_raises():
    with pytest.raises(RegistryError):
        resolve_version(">= 0.5.0", [])


def test_parse_registry_loads_fixture():
    text = (_FIXTURES / "sample_packages.json").read_text()
    registry = parse_registry(text)
    assert "chronos" in registry
    assert registry["chronos"] == RegistryEntry(
        name="chronos",
        url="https://github.com/status-im/nim-chronos",
        method="git",
    )
    assert "results" in registry
    # method defaults to "git" when not specified
    assert registry["stew"].method == "git"
    assert registry["stew"].url == "https://github.com/status-im/nim-stew"


def test_load_registry_uses_cache_when_present(tmp_path):
    # Pre-populate the cache; load_registry should read it directly
    # without doing any HTTP fetch. We pass a deliberately unreachable
    # source_url to verify no fetch happens.
    cache = tmp_path / "packages_official.json"
    cache.write_text((_FIXTURES / "sample_packages.json").read_text())

    registry = load_registry(
        cache_path=cache,
        source_url="http://localhost:1/should-never-be-fetched",
    )
    assert "chronos" in registry
    assert registry["chronos"].url == "https://github.com/status-im/nim-chronos"


def test_resolve_named_picks_highest_matching_tag():
    """resolve_named threads registry + tag listing + version resolution.
    We inject the tag-list callable so the test doesn't need a real repo.
    """
    registry = {
        "stew": RegistryEntry(
            name="stew", url="https://example.com/stew.git", method="git"
        ),
    }
    fake_tags = {"https://example.com/stew.git": [
        "v0.4.0", "v0.5.0", "v0.5.1", "v0.6.0", "nightly",
    ]}

    resolved = resolve_named(
        "stew", ">= 0.5.0",
        registry=registry,
        list_tags=lambda url: fake_tags[url],
    )
    assert resolved == ResolvedRegistryDep(
        name="stew",
        url="https://example.com/stew.git",
        tag="v0.6.0",
        version="0.6.0",
    )


def test_resolve_named_missing_from_registry_raises():
    registry = {}   # empty
    with pytest.raises(RegistryError) as exc:
        resolve_named(
            "missingpkg", None,
            registry=registry,
            list_tags=lambda url: [],
        )
    assert "missingpkg" in str(exc.value)


def test_list_remote_tags_via_file_url(tmp_path):
    """list_remote_tags works against any URL git understands, including
    file://. We build a local repo with two tags and verify both appear.
    """
    import subprocess
    src = tmp_path / "src"
    src.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(src)], check=True)
    (src / "a.txt").write_text("alpha\n")
    run = lambda *a: subprocess.run(
        ["git", "-C", str(src), "-c", "user.email=t@e", "-c", "user.name=t", *a],
        check=True, capture_output=True, text=True,
    )
    run("add", ".")
    run("commit", "-q", "-m", "first")
    run("tag", "-m", "0.1.0 release", "v0.1.0")
    (src / "a.txt").write_text("alpha2\n")
    run("commit", "-qam", "second")
    run("tag", "-m", "0.2.0 release", "v0.2.0")

    tags = list_remote_tags(f"file://{src}")
    assert "v0.1.0" in tags
    assert "v0.2.0" in tags
