"""ImplDescriptor — describes how to invoke a milpa implementation as a subprocess.

Design constraints:
- invoke_via="Direct": spawn argv as a subprocess (all current impls).
- invoke_via="Container": future escape hatch — not implemented; left as a
  clear extension point. Registering a descriptor with invoke_via="Container"
  will raise NotImplementedError at run time.

The registered descriptors are built by build_descriptors(repo_root).
"""

from __future__ import annotations

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

    # known_failing: real, reported Python CLI gaps not yet fixed.
    #
    # (127/128 previously listed here were stale — Python passes them.)
    # fixture-150 (check-certificate-strict-attestation-fail): FIXED — Python
    # cert-write intercept now writes kind:failure with empty refutation for
    # non-solver MilpaError failures (e.g. RES-UNATTESTED-METADATA), matching
    # Rust's FailureCert { message: "", refutation: [] } shape.
    python_known_failing: set[str] = set()

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

    # check-certificate fixtures: wired in batch 2 via --certificate CLI flag.
    # 127/128 now PASS via the black-box harness (Rust emits cert JSON).
    rust_check_certificate_pending: set[str] = set()

    # FETCH-REF-DISCOVERY-FAILED (fixture-163): FIXED — Rust cmd_add now returns
    # Err(MilpaError::Fetch(FetchError::Transport("FETCH-REF-DISCOVERY-FAILED", ...)))
    # when mocked ref-discovery finds no fixture entry for the URL (S11c swap).
    rust_ref_discovery_no_slug: set[str] = set()

    rust_known_failing = (
        rust_no_cas_symlinks
        | rust_index_err_swallowed
        | rust_no_predicate_filtering
        | rust_frozen_workspace_gaps
        | rust_check_certificate_pending
        | rust_ref_discovery_no_slug
    )

    rust_desc = ImplDescriptor(
        name="rust",
        argv=[str(rust_bin)],
        cwd=None,
        env={},
        known_failing=rust_known_failing,
    )

    return [python_desc, rust_desc]


def _all_fixture_names(conformance_root: Path) -> set[str]:
    """Return the basename of every fixture directory under conformance_root.

    Used to pre-populate known_failing so a stub impl does not cause unexpected
    failures while overall_passed() must stay meaningful.
    """
    names: set[str] = set()
    if not conformance_root.is_dir():
        return names
    for spec_dir in conformance_root.iterdir():
        if not spec_dir.is_dir() or not spec_dir.name.startswith("spec-v"):
            continue
        for fixture_dir in spec_dir.iterdir():
            if fixture_dir.is_dir() and fixture_dir.name.startswith("fixture-"):
                names.add(fixture_dir.name)
    return names
