"""C-clean TDD slice — guard tests for ``milpa clean`` (Phase C).

The load-bearing invariant: ``clean`` removes ONLY the project-local build
view (``_deps/`` and ``nim.cfg``).  It MUST NEVER delete entries from the
content-addressed store (``~/.cache/milpa/cas``, overridden by
``MILPA_CACHE_DIR``).  ``_deps/<name>`` entries are SYMLINKS into the CAS;
a correct ``clean`` unlinks the symlinks, never descends into their targets.

Behaviors tested (mirrored in the Rust impl):
  1. THE CRITICAL GUARD: ``_deps/<name>`` is a symlink into a CAS dir that
     contains a known file.  After ``clean``, (a) ``_deps/`` is gone and
     (b) the CAS dir AND its file STILL EXIST — symlink unlinked, target
     untouched.
  2. ``clean`` removes ``nim.cfg``.
  3. ``clean`` leaves ``milpa.lock`` intact.
  4. ``clean`` on a project with no ``_deps/`` is a no-op success (idempotent).
"""

from __future__ import annotations

from pathlib import Path

from milpa.cli import cmd_clean


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(p: Path, text: str) -> None:
    p.write_text(text, encoding="utf-8")


def _minimal_manifest(proj: Path) -> None:
    _write(proj / "milpa.kdl", 'name "myapp"\nkind "application"\n')


# ---------------------------------------------------------------------------
# 1. THE CRITICAL GUARD: CAS is never touched
# ---------------------------------------------------------------------------


def test_clean_unlinks_symlink_never_deletes_cas_target(tmp_path: Path) -> None:
    """clean removes _deps/ by unlinking symlinks — the CAS target is untouched.

    Set up:
      - A fake CAS store dir with a known file inside it.
      - A project _deps/ containing a symlink pointing at that CAS dir.

    After cmd_clean:
      (a) _deps/ is gone (symlink removed with it).
      (b) The CAS dir and its file STILL EXIST — clean never followed the link.

    This is the single most important test in this slice.  A broken ``clean``
    that uses a follow-symlink recursive delete would fail assertion (b).
    """
    proj = tmp_path / "proj"
    proj.mkdir()
    _minimal_manifest(proj)

    # Build a fake CAS entry: tmp_path/cas/abc123/ with a sentinel file.
    cas_entry = tmp_path / "cas" / "abc123"
    cas_entry.mkdir(parents=True)
    sentinel = cas_entry / "mylib.nim"
    _write(sentinel, "# sentinel content — must survive clean\n")

    # Wire up _deps/ with a symlink pointing at the CAS entry.
    deps_dir = proj / "_deps"
    deps_dir.mkdir()
    (deps_dir / "mylib").symlink_to(cas_entry)

    rc = cmd_clean(proj)

    assert rc == 0, f"cmd_clean returned {rc}, expected 0"

    # (a) _deps/ is gone.
    assert not deps_dir.exists(), "_deps/ must be removed by clean"

    # (b) CAS entry and sentinel file are untouched.
    assert cas_entry.exists(), (
        "CAS store entry must NOT be deleted by clean — "
        "clean must unlink the symlink, not follow it"
    )
    assert sentinel.exists(), (
        "CAS sentinel file must NOT be deleted by clean — "
        "the store is shared across projects"
    )


# ---------------------------------------------------------------------------
# 2. clean removes nim.cfg
# ---------------------------------------------------------------------------


def test_clean_removes_nim_cfg(tmp_path: Path) -> None:
    """clean removes nim.cfg from the project root."""
    proj = tmp_path / "proj"
    proj.mkdir()
    _minimal_manifest(proj)
    nim_cfg = proj / "nim.cfg"
    _write(nim_cfg, "--path:_deps/foo\n")

    rc = cmd_clean(proj)

    assert rc == 0
    assert not nim_cfg.exists(), "nim.cfg must be removed by clean"


# ---------------------------------------------------------------------------
# 3. clean leaves milpa.lock intact
# ---------------------------------------------------------------------------


def test_clean_leaves_milpa_lock_intact(tmp_path: Path) -> None:
    """clean does NOT remove milpa.lock — the lockfile survives."""
    proj = tmp_path / "proj"
    proj.mkdir()
    _minimal_manifest(proj)
    lock = proj / "milpa.lock"
    lock_content = "# lockfile content\nversion 1\n"
    _write(lock, lock_content)
    # Also put a nim.cfg so clean has something to do.
    _write(proj / "nim.cfg", "--path:_deps/foo\n")

    rc = cmd_clean(proj)

    assert rc == 0
    assert lock.exists(), "milpa.lock must survive clean"
    assert lock.read_text(encoding="utf-8") == lock_content, (
        "milpa.lock content must be unchanged by clean"
    )


# ---------------------------------------------------------------------------
# 4. clean is idempotent — no _deps/ is a no-op success
# ---------------------------------------------------------------------------


def test_clean_idempotent_no_deps(tmp_path: Path) -> None:
    """clean on a project with no _deps/ succeeds (exit 0) — no crash."""
    proj = tmp_path / "proj"
    proj.mkdir()
    _minimal_manifest(proj)

    assert not (proj / "_deps").exists(), "precondition: _deps/ must not exist"

    rc = cmd_clean(proj)

    assert rc == 0, f"cmd_clean returned {rc}, expected 0 (idempotent no-op)"


def test_clean_idempotent_called_twice(tmp_path: Path) -> None:
    """clean called twice is safe — second call is a no-op success."""
    proj = tmp_path / "proj"
    proj.mkdir()
    _minimal_manifest(proj)
    deps_dir = proj / "_deps"
    deps_dir.mkdir()
    _write(proj / "nim.cfg", "--path:_deps/foo\n")

    rc1 = cmd_clean(proj)
    rc2 = cmd_clean(proj)

    assert rc1 == 0
    assert rc2 == 0, "second clean call must succeed (idempotent)"
