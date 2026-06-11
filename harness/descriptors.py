"""ImplDescriptor — describes how to invoke a milpa implementation as a subprocess.

Design constraints:
- invoke_via="Direct": spawn argv as a subprocess (all current impls).
- invoke_via="Container": future escape hatch — not implemented; left as a
  clear extension point. Registering a descriptor with invoke_via="Container"
  will raise NotImplementedError at run time.

The two registered descriptors are built by build_descriptors(repo_root).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ImplDescriptor:
    """Describes how to invoke one milpa implementation.

    name          — short identifier used in reports ("python", "rust").
    argv          — the subprocess invocation prefix; harness appends global
                    flags and the verb.
    cwd           — working directory for the subprocess; None means the
                    scratch dir is used as cwd.
    env           — static extra env vars merged last (after host + fixture env).
    known_failing — fixture *directory names* (basename only) that this impl
                    is not yet expected to pass.  Adding a name here is only
                    legitimate for a real, reported, not-yet-fixed gap — never
                    as a silent skip.  Callers must document the reason.
    invoke_via    — "Direct" (spawn argv directly) or "Container" (future;
                    raises NotImplementedError).
    """

    name: str
    argv: list[str]
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    known_failing: set[str] = field(default_factory=set)
    invoke_via: str = "Direct"

    def __post_init__(self) -> None:
        if self.invoke_via not in ("Direct", "Container"):
            raise ValueError(f"Unknown invoke_via: {self.invoke_via!r}")


def build_descriptors(repo_root: str | Path) -> list[ImplDescriptor]:
    """Return the registered impl descriptors for this repo.

    Callers may filter the list (e.g. to run only the python descriptor during
    B2) before passing to the corpus runner.
    """
    root = Path(repo_root).resolve()
    python_dir = root / "impls" / "python"
    rust_bin = root / "impls" / "rust" / "target" / "release" / "milpa"

    # Python: prefer the venv python to avoid per-call uv overhead.
    venv_python = python_dir / ".venv" / "bin" / "python"
    if venv_python.exists():
        python_argv = [str(venv_python), "-m", "milpa"]
    else:
        python_argv = ["uv", "run", "python", "-m", "milpa"]

    # known_failing: real, reported CLI bugs not yet fixed.
    #
    # fixture-010/055-059/105 — FIXED (#119): find_workspace_root now
    # propagates ManifestError from workspace-shaped documents instead of
    # swallowing it. See kdl_has_workspace_block() in manifest.py.
    #
    # KDL-2.0-only syntax; Python stays KDL 1.0 until the Python rewrite (#123).
    # These fixtures use #true/#false boolean keywords (valid KDL 2.0, rejected
    # by Python's kdl-py 1.x parser as a syntax error before milpa-level checks).
    python_known_failing: set[str] = {
        "fixture-027-man-dep-flag-too-many-args",
        "fixture-038-man-flag-duplicate",
        "fixture-040-man-flag-unknown-props",
        "fixture-045-man-flag-undeclared-reference",
        # #5 mutation fixtures — these target the spec-conforming KDL-2.0 Rust
        # impl. Python is excluded for two reasons (both fixed at the Python
        # rewrite #6, NOT a Python fix now):
        #  1. Python's emitter writes KDL 1.0 (`git=...` plain, different node
        #     ordering) so expected/milpa.kdl byte-diffs.
        #  2. Python's CLI only wires MILPA_MOCKED_FETCHES into fetch/lock — the
        #     add/update verbs go through cmd_add/cmd_update which still take the
        #     real default_registry, so their fetch hits the network and fails.
        "fixture-120-add-git-dep",     # expected/milpa.kdl (2.0) + add lacks mock transport
        "fixture-121-remove-dep",      # expected/milpa.kdl (2.0 emitter layout)
        "fixture-123-update-all",      # update lacks mock transport (real-fetch fail)
        "fixture-124-update-scoped",   # scoped update: lacks mock transport (real-fetch fail)
                                       # + expected/milpa.kdl byte-compare needs the
                                       # KDL-1.0/2.0 split fixed (both at Python rewrite #6)
        # fixture-122-show-liveness is NOT here: it is liveness-only (exit 0 +
        # non-empty stdout, no byte-compare) and Python passes it.
    }

    python_desc = ImplDescriptor(
        name="python",
        argv=python_argv,
        cwd=str(python_dir),
        env={},
        known_failing=python_known_failing,
    )

    # known_failing: real, reported Rust CLI bugs not yet fixed.
    #
    # BLOCKER-R1 (FIXED): Rust CLI now routes MockedFetcher through
    # CasAdmittingFetcher so _deps/<name> is a CAS symlink (issue #118).
    rust_no_cas_symlinks: set[str] = set()
    #
    # BLOCKER-R2 (FIXED): maybe_index() now returns Result<Option<Index>, MilpaError>
    # and propagates TNG-* parse errors instead of swallowing them via .ok().
    # All 7 fixtures pass as of this fix (issue #118).
    rust_index_err_swallowed: set[str] = set()
    #
    # BLOCKER-R3 (FIXED): Rust CLI now reads MILPA_TARGET_* env vars and builds a
    # Profile, passing it to both single-package and workspace resolution so
    # conditional deps are filtered before the solver runs (issue #118).
    rust_no_predicate_filtering: set[str] = set()
    #
    # BLOCKER-R4 (FIXED): Rust CLI now detects frozen workspace error conditions:
    # FROZEN-MEMBER-NOT-IN-WORKSPACE and FROZEN-MEMBER-IDENTITY-DRIFT are
    # emitted correctly via resolve_workspace_frozen (issue #118).
    rust_frozen_workspace_gaps: set[str] = set()

    rust_known_failing = (
        rust_no_cas_symlinks
        | rust_index_err_swallowed
        | rust_no_predicate_filtering
        | rust_frozen_workspace_gaps
    )

    rust_desc = ImplDescriptor(
        name="rust",
        argv=[str(rust_bin)],
        cwd=None,
        env={},
        known_failing=rust_known_failing,
    )

    return [python_desc, rust_desc]
