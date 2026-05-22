"""Property-based tests for milpa.identity.compute_content_hash.

Per docs/rfc-property-based-testing.md Tier B-3.

Properties verified:
  - Determinism: same tree → same hash, regardless of host path
  - .git exclusion: arbitrary .git/ contents don't affect the hash
  - Mode discrimination: exec bit changes produce different hashes
  - Symlink-vs-file discrimination: same bytes as file vs as link
    target produce different hashes (mode markers differ)
  - Content change: any byte change in any file flips the hash

Hypothesis generates trees as Python dicts:
    {relpath: ('file', content_bytes, executable_bool)}
    {relpath: ('symlink', target_string)}

Tests materialize the tree into a tmp directory, hash it, and assert
the property holds. Relpaths use a safe alphabet (alphanumeric + `/`)
to avoid filesystem-Unicode quirks; Hypothesis's input space stays
bounded for fast shrinking.
"""

import os
import stat
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, given, settings, strategies as st

from milpa.identity import compute_content_hash


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_PATH_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_-"


@st.composite
def path_segment(draw):
    """A single dir or file name — non-empty, safe alphabet."""
    return draw(st.text(alphabet=_PATH_ALPHABET, min_size=1, max_size=8))


@st.composite
def relpath(draw):
    """A POSIX relpath: 1-3 segments joined with `/`."""
    n = draw(st.integers(min_value=1, max_value=3))
    segs = [draw(path_segment()) for _ in range(n)]
    return "/".join(segs)


@st.composite
def file_entry(draw):
    """A regular file entry: (content_bytes, executable_bool)."""
    return (
        "file",
        draw(st.binary(min_size=0, max_size=200)),
        draw(st.booleans()),
    )


@st.composite
def symlink_entry(draw):
    """A symlink entry: (target_string,) — target need not exist."""
    return ("symlink", draw(st.text(alphabet=_PATH_ALPHABET + "/.", min_size=1, max_size=30)))


@st.composite
def tree(draw):
    """A source tree as {relpath: entry}, with no relpath being a
    prefix of another (which would be inconsistent on the filesystem).
    Empty trees are allowed."""
    n_entries = draw(st.integers(min_value=0, max_value=6))
    entries: dict[str, tuple] = {}
    attempts = 0
    while len(entries) < n_entries and attempts < n_entries * 4:
        attempts += 1
        rp = draw(relpath())
        # Reject if this relpath is a prefix of an existing one or vice versa
        if any(rp == k or k.startswith(rp + "/") or rp.startswith(k + "/")
               for k in entries):
            continue
        kind = draw(st.one_of(file_entry(), symlink_entry()))
        entries[rp] = kind
    return entries


def materialize(tree_dict: dict[str, tuple], root: Path) -> None:
    """Realize a generated tree under `root`."""
    for relpath_str, entry in tree_dict.items():
        target = root / relpath_str
        target.parent.mkdir(parents=True, exist_ok=True)
        if entry[0] == "file":
            _, content, executable = entry
            target.write_bytes(content)
            if executable:
                target.chmod(target.stat().st_mode | stat.S_IXUSR)
        else:  # symlink
            _, link_target = entry
            os.symlink(link_target, target)


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------

def _scratch_dirs(n: int) -> list[Path]:
    """Create n fresh, unique scratch directories. Used per Hypothesis
    example to avoid collisions across runs (each example needs its
    own clean state)."""
    return [Path(tempfile.mkdtemp(prefix="milpa-prop-")) for _ in range(n)]


@given(tree())
def test_content_hash_is_deterministic_across_directories(t):
    """Materializing the same tree into two different directories
    produces the same content_hash. The hash depends on the tree's
    relative structure, not on its absolute path."""
    a, b = _scratch_dirs(2)
    materialize(t, a)
    materialize(t, b)
    assert compute_content_hash(a) == compute_content_hash(b)


@given(tree(), st.binary(min_size=0, max_size=100))
def test_git_directory_contents_dont_affect_hash(t, git_blob):
    """Adding arbitrary .git/ content doesn't change the content_hash.
    Provenance lives in .git/; content lives in everything else."""
    a, b = _scratch_dirs(2)
    materialize(t, a)
    materialize(t, b)
    # Add fake .git/ to b only
    (b / ".git").mkdir(parents=True, exist_ok=True)
    (b / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (b / ".git" / "objects").mkdir(parents=True, exist_ok=True)
    (b / ".git" / "objects" / "fake_obj").write_bytes(git_blob)
    assert compute_content_hash(a) == compute_content_hash(b)


@given(tree())
def test_flipping_exec_bit_on_any_file_changes_hash(t):
    """For any tree containing at least one regular file: flipping
    its executable bit produces a different content_hash."""
    # Find a tree position holding a regular file
    file_entries = [(rp, entry) for rp, entry in t.items()
                    if entry[0] == "file"]
    if not file_entries:
        # Skip degenerate cases — only meaningful when at least one
        # regular file exists. Hypothesis will keep generating until it
        # finds non-degenerate trees.
        return

    rp, (_, content, executable) = file_entries[0]
    # Build two variants: with and without the exec bit on `rp`.
    t_off = dict(t); t_off[rp] = ("file", content, False)
    t_on  = dict(t); t_on[rp]  = ("file", content, True)
    a, b = _scratch_dirs(2)
    materialize(t_off, a)
    materialize(t_on, b)
    assert compute_content_hash(a) != compute_content_hash(b)


@given(
    relpath(),
    st.text(alphabet=_PATH_ALPHABET, min_size=1, max_size=20),
)
def test_symlink_and_file_with_same_content_discriminate(rp, target):
    """A regular file with bytes `X` and a symlink whose target string
    is `X` must hash differently — the mode marker discriminates."""
    a, b = _scratch_dirs(2)
    # a: regular file with content = target
    f_path = a / rp
    f_path.parent.mkdir(parents=True, exist_ok=True)
    f_path.write_text(target)
    # b: symlink whose link target string = target
    s_path = b / rp
    s_path.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, s_path)
    assert compute_content_hash(a) != compute_content_hash(b)


@given(tree(), st.binary(min_size=1, max_size=50))
def test_modifying_any_file_byte_changes_hash(t, extra_byte):
    """Appending bytes to any file in the tree flips the hash."""
    file_entries = [(rp, entry) for rp, entry in t.items()
                    if entry[0] == "file"]
    if not file_entries:
        return

    rp, (_, content, executable) = file_entries[0]
    t_modified = dict(t)
    t_modified[rp] = ("file", content + extra_byte, executable)
    a, b = _scratch_dirs(2)
    materialize(t, a)
    materialize(t_modified, b)
    assert compute_content_hash(a) != compute_content_hash(b)
