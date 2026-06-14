"""ImplDescriptor — describes how to invoke a milpa implementation as a subprocess.

Design constraints:
- invoke_via="Direct": spawn argv as a subprocess (all current impls).
- invoke_via="Container": future escape hatch — not implemented; left as a
  clear extension point. Registering a descriptor with invoke_via="Container"
  will raise NotImplementedError at run time.

The registered descriptors are built by build_descriptors(repo_root).
python-ng is dormant by default; set MILPA_PYTHON_NG=1 to activate it.
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
        # #116 tarball TOFU fixtures — target the spec-conforming Rust impl.
        # Python is the frozen design vehicle: its MockedFetcher.can_handle()
        # returns False for TarballProvenance (only git is mocked), so a tarball
        # resolve cannot run offline. Wired at the Python rewrite #6, not now.
        "fixture-125-tarball-tofu-record",            # tarball mock transport not in frozen Python
        "fixture-126-tarball-tofu-refetch-mismatch",  # ditto + §8 refetch re-assertion
        # check-certificate fixtures — new-impl-only; frozen python does not
        # implement --certificate (wired at the Python rewrite #6, not now).
        "fixture-127-check-certificate-success",  # --certificate not in frozen Python
        "fixture-128-check-certificate-conflict",  # --certificate not in frozen Python
        # S3b DepDecl fixtures — frozen Python does not implement DepDeclStore /
        # DepDeclEdgeSource (wired in python-ng; lands in the Python rewrite #6).
        "fixture-131-depdecl-hash-mismatch",
        "fixture-132-depdecl-parse-error",
        "fixture-133-depdecl-schema-mismatch",
        "fixture-134-depdecl-schema-unsupported",
        # S4-ii DepDecl when-attested fixture — frozen Python falls back to
        # .nimble for qux (includes platform-conditional 'extra' unconditionally),
        # but 'extra' is not in the index for the attested arm (the DepDecl arm
        # intentionally excludes it). Frozen Python resolves from .nimble and
        # fails with TNG-NOT-FOUND. Wired at the Python rewrite #6.
        "fixture-137-depdecl-when-attested",
        # S5 attestation-policy fixtures — frozen Python does not implement
        # `attestation-policy` manifest field (→ MAN-UNKNOWN-TOP-LEVEL, fixture-140)
        # or `--require-attested-metadata` / MILPA_REQUIRE_ATTESTED_METADATA
        # flag/env-var (fixture-141 silently succeeds instead of raising
        # RES-UNATTESTED-METADATA). Both wired at the Python rewrite #6.
        "fixture-140-attestation-strict-manifest-fail",  # attestation-policy field unknown
        "fixture-141-attestation-strict-flag-fail",       # flag/env not in frozen Python
        # Workspace + strict attestation (§13.1 workspace rule) — frozen Python
        # does not enforce attestation policy in the workspace resolve path
        # (silently succeeds instead of raising RES-UNATTESTED-METADATA).
        # Wired at the Python rewrite #6.
        "fixture-145-ws-attestation-strict-flag-fail",    # workspace attestation not in frozen Python
        # S6 dep_decl pin emission — frozen Python does not emit `dep_decl` in
        # milpa.lock (DepDeclEdgeSource is python-ng only; lands at #6 rewrite).
        # Expected lockfiles for these fixtures now include dep_decl pins.
        "fixture-129-index-dep-decl-pointer",       # dep_decl pin not emitted by frozen Python
        "fixture-135-depdecl-clean-attested",       # dep_decl pin not emitted by frozen Python
        "fixture-136-depdecl-clean-fallback",       # dep_decl pin not emitted by frozen Python
        "fixture-138-depdecl-when-fallback",        # dep_decl pin not emitted by frozen Python
        # S6 verify fixtures — frozen Python's `milpa verify` does not implement
        # dep_decl edge checking (wired at the Python rewrite #6).
        "fixture-142-verify-edge-mismatch",         # dep_decl edge check not in frozen Python
        "fixture-143-verify-pin-missing",           # dep_decl edge check not in frozen Python
        "fixture-148-verify-edge-mismatch-manifest-strict",  # manifest attestation-policy "strict" not in frozen Python
        # S7 TNG-DEPDECL-FETCH-FAILED strict fixture — frozen Python does not
        # implement FileDepDeclStore or strict attestation policy
        # (wired at the Python rewrite #6, not now).
        "fixture-144-depdecl-fetch-failed",         # FileDepDeclStore not in frozen Python
        # S7 TNG-DEPDECL-FETCH-FAILED non-strict fixture — frozen Python does not
        # wire MILPA_DEP_DECL_DIR (FileDepDeclStore absent → fallback happens
        # unconditionally, so expected lockfile has no dep_decl pin, which frozen
        # Python would also produce — but the expected _deps_structure.txt uses CAS
        # symlinks which frozen Python does not emit). Wired at the Python rewrite #6.
        "fixture-146-depdecl-fetch-failed-nonstrict",  # FileDepDeclStore not in frozen Python
        # R3 overflow fixture — frozen Python does not implement DepDeclEdgeSource
        # (dep_decl field in index ignored by frozen Python → resolves successfully
        # instead of raising TNG-DEPDECL-SCHEMA-UNSUPPORTED). Wired at #6 rewrite.
        "fixture-147-depdecl-schema-unsupported-overflow",  # DepDeclEdgeSource not in frozen Python
        # R5 security fix — frozen Python's tianguis_client.py does not validate
        # dep_decl pointer format at parse time (no _validate_dep_decl_pointer
        # call). The fix lives in python-ng registry.py. Frozen Python silently
        # treats the malformed pointer as None (string parse falls back) and
        # resolves successfully instead of raising TNG-BAD-DEP-DECL.
        # Wired at the python-ng rewrite (#6).
        "fixture-149-tng-bad-dep-decl",  # dep_decl format validation not in frozen Python
        # --certificate + strict attestation (§2.5 + §13.1): frozen Python does not
        # implement --certificate (CLI binary only, wired at the Python rewrite #6)
        # and does not enforce MILPA_REQUIRE_ATTESTED_METADATA, so the cert path
        # would silently succeed instead of raising RES-UNATTESTED-METADATA.
        # Rust reference impl exercises this; wired at the Python rewrite (#6).
        "fixture-150-check-certificate-strict-attestation-fail",
        # Workspace verify + member strict (§13.1 workspace rule, Finding 2):
        # frozen Python does not consult member attestation-policy in `milpa verify`
        # (the fix is python-ng; wired at the Python rewrite #6).
        "fixture-151-ws-verify-edge-mismatch-member-strict",
        # FETCH-REF-DISCOVERY-FAILED (fixture-163): frozen Python's cmd_add()
        # does NOT check MILPA_MOCKED_FETCHES for ref discovery; it always calls
        # _git_default_branch() (real git ls-remote). With no network this exits 1
        # but emits no milpa-error: slug. The fix lives in python-ng cli.py
        # (_mocked_default_branch wiring). Wired at the Python rewrite (#6).
        "fixture-163-fetch-ref-discovery-failed",  # mocked ref-discovery not in frozen Python
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

    # check-certificate fixtures: wired in batch 2 via --certificate CLI flag.
    # 127/128 now PASS via the black-box harness (Rust emits cert JSON).
    rust_check_certificate_pending: set[str] = set()

    # FETCH-REF-DISCOVERY-FAILED (fixture-163): Rust's discover_default_branch()
    # exits 1 with a human-readable message but emits NO milpa-error: slug line
    # when mocked ref-discovery fails (cli-contract §5.6 comment "no slug").
    # The Python impl (and spec) require FETCH-REF-DISCOVERY-FAILED to be emitted.
    # Tracked as a Rust conformance gap to fix in the 11c swap.
    rust_ref_discovery_no_slug: set[str] = {
        "fixture-163-fetch-ref-discovery-failed",
    }

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

    descriptors = [python_desc, rust_desc]

    # python-ng: dormant by default; activated by MILPA_PYTHON_NG=1.
    #
    # A stub registered unconditionally would FAIL every corpus fixture not in
    # its known_failing set and break overall_passed() immediately.  The gate
    # keeps the green harness undisturbed until the new impl reaches parity.
    # The gate is removed at swap (S11c), when python-ng *is* python.
    if os.environ.get("MILPA_PYTHON_NG") == "1":
        python_ng_dir = root / "impls" / "python-ng"
        venv_python_ng = python_ng_dir / ".venv" / "bin" / "python"
        if venv_python_ng.exists():
            python_ng_argv = [str(venv_python_ng), "-m", "milpa"]
        else:
            python_ng_argv = ["uv", "run", "python", "-m", "milpa"]

        # known_failing: only the mutation stubs (slice 10e — not yet implemented).
        #
        # All other fixtures (10a-0 through 10c) are implemented and pass.
        # The add/remove/update verbs are wired as stubs in cli.py; they emit
        # MILPA-INTERNAL and exit 1.  The expected outputs require a fully
        # implemented add/remove/update with mocked transport + KDL 2.0 emitter
        # (both from the Python rewrite #6 / slice 10e).
        #
        # --certificate fixtures (127/128/150): python-ng does not implement
        # --certificate yet (CLI binary only; wired in a future slice).
        python_ng_known_failing: set[str] = {
            "fixture-127-check-certificate-success",
            "fixture-128-check-certificate-conflict",
            "fixture-150-check-certificate-strict-attestation-fail",
        }

        python_ng_desc = ImplDescriptor(
            name="python-ng",
            argv=python_ng_argv,
            cwd=str(python_ng_dir),
            env={},
            known_failing=python_ng_known_failing,
        )
        descriptors.append(python_ng_desc)

    return descriptors


def _all_fixture_names(conformance_root: Path) -> set[str]:
    """Return the basename of every fixture directory under conformance_root.

    Used to pre-populate python-ng's known_failing so the stub impl does not
    cause unexpected failures while overall_passed() must stay meaningful.
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
