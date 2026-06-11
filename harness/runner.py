"""Per-(fixture, impl) runner — the fixture runner.

Drives one milpa impl as a black-box subprocess against one conformance fixture.
Returns a RunResult with everything the corpus runner needs to assert.

Design constraints:
- stdlib only; no import milpa.
- The subprocess env is constructed fresh each call (no shared state).
- Each call gets its own scratch dir AND its own MILPA_CACHE_DIR so that
  one impl's CAS can never warm another's.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from harness.descriptors import ImplDescriptor


# ---------------------------------------------------------------------------
# Slug pattern — from spec/cli-contract.md §3.1 R1
# ---------------------------------------------------------------------------

_SLUG_PATTERN = re.compile(
    r"^milpa-error: ([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)$",
    re.MULTILINE,
)


@dataclass
class RunResult:
    """Outcome of running one (fixture, impl) pair."""

    fixture_name: str
    impl_name: str
    returncode: int
    stdout: str
    stderr: str
    slug: Optional[str]           # None = no slug line found
    slug_error: Optional[str]     # non-None = protocol violation (2+ slug lines)
    scratch_dir: str              # path to the isolated scratch dir
    cas_dir: str                  # path to the isolated CAS dir


def _read_cmd(fixture_dir: Path) -> str:
    """Read the optional cmd file; default 'resolve'."""
    cmd_file = fixture_dir / "cmd"
    if cmd_file.exists():
        return cmd_file.read_text().strip()
    return "resolve"


def _read_env_file(fixture_dir: Path) -> dict[str, str]:
    """Parse the optional `env` file into a dict (KEY=VALUE lines, # comments ignored)."""
    env_file = fixture_dir / "env"
    if not env_file.exists():
        return {}
    result: dict[str, str] = {}
    for raw_line in env_file.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


# Files / dirs that are harness control inputs, not fixture inputs to copy.
_CONTROL_FILES = frozenset({"expected", "cmd", "env"})


def _copy_fixture_inputs(fixture_dir: Path, scratch: Path) -> None:
    """Deep-copy fixture inputs into scratch, excluding control files/dirs.

    Copies everything except: expected/, cmd, env.
    All other contents (milpa.kdl, index.kdl, mocked-fetches/, milpa.lock,
    member dirs, cas-seed/, ...) are included.
    """
    for entry in fixture_dir.iterdir():
        if entry.name in _CONTROL_FILES:
            continue
        dest = scratch / entry.name
        if entry.is_dir():
            shutil.copytree(entry, dest, symlinks=True)
        else:
            shutil.copy2(entry, dest)


def _build_env(
    scratch: Path,
    cas_dir: Path,
    fixture_env: dict[str, str],
    descriptor_env: dict[str, str],
) -> dict[str, str]:
    """Build the subprocess environment per spec §2.3 of the harness design.

    Order of precedence (last wins):
      1. os.environ (host), with all MILPA_* keys stripped.
      2. LC_ALL=C (stable locale).
      3. MILPA_CACHE_DIR=<iso cas abs path>.
      4. MILPA_INDEX_URL if scratch/index.kdl exists.
      5. MILPA_MOCKED_FETCHES if scratch/mocked-fetches exists.
      6. Fixture env file overrides (MILPA_TARGET_* etc).
      7. Descriptor static env.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("MILPA_")}
    env["LC_ALL"] = "C"
    env["MILPA_CACHE_DIR"] = str(cas_dir.resolve())

    index_kdl = scratch / "index.kdl"
    if index_kdl.exists():
        env["MILPA_INDEX_URL"] = f"file://{index_kdl.resolve()}"

    mocked = scratch / "mocked-fetches"
    if mocked.exists():
        env["MILPA_MOCKED_FETCHES"] = str(mocked.resolve())

    env.update(fixture_env)
    env.update(descriptor_env)
    return env


def _extract_slug(stderr: str) -> tuple[Optional[str], Optional[str]]:
    """Extract the milpa-error slug from stderr.

    Returns (slug, error):
      - (slug, None)     — exactly one slug line found; slug is the code.
      - (None, None)     — no slug line (crash or clean exit).
      - (None, err_msg)  — protocol violation: 2+ slug lines.
    """
    matches = _SLUG_PATTERN.findall(stderr)
    if len(matches) == 0:
        return None, None
    if len(matches) == 1:
        return matches[0], None
    return None, f"protocol violation: {len(matches)} milpa-error lines: {matches!r}"


def _cmd_to_cli(cmd: str) -> tuple[list[str], list[str]]:
    """Map a fixture cmd string to (global_flags, verb_argv).

    Returns a pair:
      global_flags — flags that go BEFORE the verb (e.g. ["--frozen"])
      verb_argv    — the verb and any verb-specific args (e.g. ["fetch"])

    Full invocation: descriptor.argv + ["-C", scratch] + global_flags + verb_argv

    Mutation / liveness selectors (conformance-fixtures §2.7.1 / §2.7.2) map the
    surface form to the real CLI argv:
      add <name> git=<url> ref=<ref>  → ["add", <name>, "--git", <url>, "--ref", <ref>]
      add <name> git=<url>            → ["add", <name>, "--git", <url>]  (mocked ref discovery)
      remove <name>                   → ["remove", <name>]
      update                          → ["update"]
      update <name>                   → ["update", <name>]
      show                            → ["show"]
      --version                       → []  (global flag; see note below)
    """
    tokens = cmd.split()
    if not tokens:
        raise ValueError("empty fixture cmd")
    head = tokens[0]

    if head == "resolve":
        return [], ["fetch"]
    if head == "frozen":
        return ["--frozen"], ["fetch"]
    if head == "parse-lockfile":
        return [], ["show"]
    if head == "show":
        return [], ["show"]
    if head == "--version":
        # --version is a global flag, not a verb; the impl prints + exits 0.
        return ["--version"], []
    if head == "add":
        return [], _add_argv(tokens[1:])
    if head == "remove":
        if len(tokens) != 2:
            raise ValueError(f"remove cmd needs exactly one name: {cmd!r}")
        return [], ["remove", tokens[1]]
    if head == "update":
        # update | update <name>
        return [], ["update", *tokens[1:]]
    raise ValueError(f"Unknown fixture cmd: {cmd!r}")


def _add_argv(args: list[str]) -> list[str]:
    """Parse the `add` surface tokens into the real CLI verb argv.

    `args` is everything after the `add` token, e.g.
    ["foo", "git=https://...", "ref=main"].
    """
    if not args:
        raise ValueError("add cmd needs a <name>")
    name = args[0]
    argv = ["add", name]
    git_url: Optional[str] = None
    ref: Optional[str] = None
    for tok in args[1:]:
        if tok.startswith("git="):
            git_url = tok[len("git="):]
        elif tok.startswith("ref="):
            ref = tok[len("ref="):]
        else:
            raise ValueError(f"unrecognized add token: {tok!r}")
    if git_url is None:
        raise ValueError("add cmd needs git=<url>")
    argv += ["--git", git_url]
    if ref is not None:
        argv += ["--ref", ref]
    return argv


def run_fixture(
    fixture_dir: Path,
    descriptor: ImplDescriptor,
    timeout: int = 180,
) -> RunResult:
    """Run one (fixture, impl) pair in isolation.

    Creates its own scratch dir and CAS dir (both cleaned up by the caller
    if needed — this function does NOT clean up). The scratch dir and CAS dir
    paths are returned in RunResult for assertions and cross-impl diff.
    """
    if descriptor.invoke_via == "Container":
        raise NotImplementedError("Container invoke_via is not yet implemented")

    fixture_name = fixture_dir.name
    cmd = _read_cmd(fixture_dir)
    fixture_env = _read_env_file(fixture_dir)
    global_flags, verb_argv = _cmd_to_cli(cmd)

    # Create isolated scratch + CAS dirs.
    scratch = Path(tempfile.mkdtemp(prefix=f"milpa-harness-{descriptor.name}-"))
    cas_dir = Path(tempfile.mkdtemp(prefix=f"milpa-harness-cas-{descriptor.name}-"))

    try:
        _copy_fixture_inputs(fixture_dir, scratch)

        env = _build_env(scratch, cas_dir, fixture_env, descriptor.env)

        argv = (
            descriptor.argv
            + ["-C", str(scratch)]
            + global_flags
            + verb_argv
        )

        cwd = descriptor.cwd if descriptor.cwd is not None else str(scratch)

        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        # Treat timeout as a crash result with a synthetic stderr.
        stderr = f"[harness] subprocess timed out after {timeout}s"
        return RunResult(
            fixture_name=fixture_name,
            impl_name=descriptor.name,
            returncode=-1,
            stdout="",
            stderr=stderr,
            slug=None,
            slug_error=None,
            scratch_dir=str(scratch),
            cas_dir=str(cas_dir),
        )

    slug, slug_error = _extract_slug(proc.stderr)

    return RunResult(
        fixture_name=fixture_name,
        impl_name=descriptor.name,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        slug=slug,
        slug_error=slug_error,
        scratch_dir=str(scratch),
        cas_dir=str(cas_dir),
    )
