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

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from harness.descriptors import ImplDescriptor
from harness.git_protocol_repo import _make_git_protocol_repo
from harness.inputs import env_flag, read_env_file, resolve_project_dir


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
    cert_path: Optional[str] = None  # path to the emitted certificate (check-certificate only)
    extra_dir: Optional[str] = None  # e.g. generated git-protocol repos; cleaned up too

    def cleanup(self) -> None:
        """Remove the scratch and CAS dirs created by run_fixture.

        Safe to call multiple times (ignore_errors=True).  Callers that need
        to keep the dirs for post-run assertions must call this AFTER they are
        done reading outputs.
        """
        dirs = [self.scratch_dir, self.cas_dir]
        if self.extra_dir is not None:
            dirs.append(self.extra_dir)
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)


def _read_cmd(fixture_dir: Path) -> str:
    """Read the optional cmd file; default 'resolve'."""
    cmd_file = fixture_dir / "cmd"
    if cmd_file.exists():
        return cmd_file.read_text().strip()
    return "resolve"


def _read_project_dir_suffix(fixture_dir: Path) -> Optional[str]:
    """Read the optional ``project-dir`` file.

    S11e (RFC: workspace-completion §3.G / D5): some fixtures invoke the
    CLI from a *sub-directory* of the scratch tree (e.g. a workspace member
    dir) rather than from the scratch root.  The ``project-dir`` control file
    contains a path *relative to scratch* (e.g. ``member-a``) that overrides
    the ``-C`` flag passed to the impl.

    Returns ``None`` when the file is absent (default: use scratch root).
    """
    pd_file = fixture_dir / "project-dir"
    if pd_file.exists():
        return pd_file.read_text().strip() or None
    return None



# Files / dirs that are harness control inputs, not fixture inputs to copy.
_CONTROL_FILES = frozenset({"expected", "cmd", "env", "project-dir"})


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
      4. MILPA_INDEX_URL — ALWAYS set (three-way semantics, cli-contract §8.1):
           - scratch/index.kdl present → file://<abs-path> (that fixture's index).
           - scratch/index.kdl absent  → "" (empty = explicitly no index;
             prevents the impl from falling back to the live tianguis network).
      5. MILPA_MOCKED_FETCHES if scratch/mocked-fetches exists.
      6. MILPA_DEP_DECL_DIR if scratch/dep-decl exists (S3a).
      7. Fixture env file overrides (MILPA_TARGET_* etc).
      8. Descriptor static env.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("MILPA_")}
    env["LC_ALL"] = "C"
    env["MILPA_CACHE_DIR"] = str(cas_dir.resolve())

    # Always set MILPA_INDEX_URL: file:// URL when index.kdl is present,
    # empty string when absent (= explicitly no index, no network fallback).
    index_kdl = scratch / "index.kdl"
    if index_kdl.exists():
        env["MILPA_INDEX_URL"] = f"file://{index_kdl.resolve()}"
    else:
        env["MILPA_INDEX_URL"] = ""

    mocked = scratch / "mocked-fetches"
    if mocked.exists():
        env["MILPA_MOCKED_FETCHES"] = str(mocked.resolve())

    dep_decl = scratch / "dep-decl"
    if dep_decl.exists():
        env["MILPA_DEP_DECL_DIR"] = str(dep_decl.resolve())

    env.update(fixture_env)
    env.update(descriptor_env)
    return env


def extract_slug(stderr: str) -> tuple[Optional[str], Optional[str]]:
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


# Verbs whose subparser accepts the S9 feature-selection flags (cli.py
# _add_feature_args is applied to fetch/lock/update).
_FEATURE_VERBS = frozenset({"fetch", "lock", "update"})

# Pairs each `dep "<name>"` with its identity field.
# [^}]*? stays within the current dep block — never crosses the closing `}` into
# the next block. This is safe because the lockfile format places `identity` as a
# single-line field inside its dep block, and nested blocks (provenance { })
# contain no `}` that would prematurely close the outer match. Deps that have no
# identity field (e.g. local deps) simply produce no match, which is correct.
# Capture the FULL ``<algo>:<64hex>`` identity — algorithm-generic, not just
# ``sha256:``. The store layout (spec/identity.md §3.1, cas.py path_for) keys on
# the algorithm prefix, so a ``dag-sha256:`` identity (origin-as-identity /
# DE-lattice deps) must round-trip through the seeder with its prefix intact.
_DEP_IDENTITY_RE = re.compile(
    r'dep "([^"]+)"\s*\{[^}]*?identity "([a-z0-9-]+:[0-9a-f]{64})"',
)


def _parse_lock_identities(lock_text: str) -> dict[str, str]:
    """Map each lockfile dep name to its recorded content identity."""
    return {m.group(1): m.group(2) for m in _DEP_IDENTITY_RE.finditer(lock_text)}


# Algorithm prefixes the CAS store keys on (spec/identity.md §3.1). A cas-seed
# subtree named after one of these is interpreted as store-layout
# (``cas-seed/<algo>/<hex>/``) rather than dep-name-keyed.
_CAS_ALGO_DIRS = ("sha256", "dag-sha256")


def _seed_cas_from_lock(scratch: Path, cas_dir: Path) -> None:
    """Seed the CAS for frozen fixtures, impl-neutrally (Slice C c3).

    Two cas-seed layouts are accepted; both are impl-neutral (the harness never
    re-implements the impl's content-hash — SSOT):

    1. **Dep-name-keyed** — ``cas-seed/<dep-name>/`` — the common case. Each tree
       is placed at ``<root>/<algo>/<hex>/`` using the identity the fixture's own
       ``milpa.lock`` records for that dep name. Faithful when the seed tree
       hashes to exactly the recorded identity (verified for the corpus).

    2. **Identity-keyed (store-layout)** — ``cas-seed/<algo>/<hex>/`` — mirrors
       the CAS store layout directly, so the seeder copies it in verbatim with
       no lock lookup. Required when dep-name keying is ambiguous: two deps that
       share one import name but differ in identity (import-slot collision), or a
       single content tree backing several deduped deps. The fixture author names
       the dir by the identity it already recorded in the lock.

    No-op when ``cas-seed/`` is absent (dep-name keying also needs ``milpa.lock``).
    """
    seed_root = scratch / "cas-seed"
    if not seed_root.is_dir():
        return
    lock = scratch / "milpa.lock"
    name_to_identity = _parse_lock_identities(lock.read_text()) if lock.exists() else {}
    for child in sorted(seed_root.iterdir()):
        if not child.is_dir():
            continue
        # Layout 2: identity-keyed store-layout subtree (cas-seed/<algo>/<hex>/).
        if child.name in _CAS_ALGO_DIRS:
            for hex_dir in sorted(child.iterdir()):
                if not hex_dir.is_dir():
                    continue
                dest = cas_dir / child.name / hex_dir.name
                if dest.exists():
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(hex_dir, dest)
            continue
        # Layout 1: dep-name-keyed.
        identity = name_to_identity.get(child.name)
        if not identity:
            continue
        # Algorithm-generic dest: <root>/<algo>/<hex>/ mirrors the impl's own
        # CAS layout (cas.py path_for, spec/identity.md §3.1). Do NOT hardcode
        # sha256 — a dag-sha256 identity keys under dag-sha256/. The store entry
        # is a verbatim tree copy for every algorithm (contains() = dir exists),
        # so copying the seed tree here is faithful without re-hashing.
        algo, _, hex_digest = identity.partition(":")
        dest = cas_dir / algo / hex_digest
        if dest.exists():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(child, dest)


def _feature_argv(fixture_env: dict[str, str]) -> list[str]:
    """Translate the MILPA_CLI_FEATURES family into verb-level CLI flags.

    The black-box runner calls this to drive the CLI with the same declared
    feature inputs that the in-process adapter reads.  The CLI reads these as
    ``--features`` / ``--no-default-features`` / ``--all-features`` on the
    fetch/lock/update subparser, NOT as environment variables — without this
    translation the env keys are set but silently ignored (Finding 3,
    docs/rfc-conformance-parity.baseline.md, RFC §4 Slice B).

    Uses ``env_flag`` from ``harness.inputs`` (the single definition of
    fixture env-flag semantics) for the two boolean flags.  ``MILPA_CLI_FEATURES``
    is read as a raw comma-string and forwarded verbatim — the CLI's
    ``--features`` expects ``a,b,c``, not a parsed set, so this path
    deliberately does NOT use ``parse_cli_features`` (that is for the
    in-process adapter, which needs a frozenset).
    """
    argv: list[str] = []
    feats = fixture_env.get("MILPA_CLI_FEATURES", "").strip()
    if feats:
        argv += ["--features", feats]
    if env_flag(fixture_env, "MILPA_NO_DEFAULT_FEATURES"):
        argv.append("--no-default-features")
    if env_flag(fixture_env, "MILPA_ALL_FEATURES"):
        argv.append("--all-features")
    return argv


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

    Global flags that may appear inline in the cmd (e.g. `resolve --no-index`)
    are extracted here and prepended to the returned global_flags, independent
    of the verb dispatch below.
    """
    tokens = cmd.split()
    if not tokens:
        raise ValueError("empty fixture cmd")

    # Extract recognized inline global flags (cli-contract §2). `--no-index`
    # (§2.6) can prefix any resolution cmd; it maps straight through.
    inline_global: list[str] = []
    rest: list[str] = []
    for t in tokens:
        if t == "--no-index":
            inline_global.append("--no-index")
        else:
            rest.append(t)
    if not rest:
        raise ValueError(f"fixture cmd has no verb: {cmd!r}")
    global_flags, verb_argv = _dispatch_cmd(rest, cmd)
    return inline_global + global_flags, verb_argv


def _dispatch_cmd(tokens: list[str], cmd: str) -> tuple[list[str], list[str]]:
    """Dispatch the verb tokens (inline global flags already stripped)."""
    head = tokens[0]

    if head == "resolve" or head == "fetch":
        # Preserve verb-level flags that follow the verb (e.g.
        # `resolve --strategy minver`). `--strategy` is a subparser flag on
        # fetch (cli.py _add_strategy_arg), so it must ride on the verb argv,
        # not be dropped — else resolution silently uses the default strategy.
        return [], ["fetch", *tokens[1:]]
    if head == "frozen":
        return ["--frozen"], ["fetch"]
    if head == "git-protocol":
        # H-infra fixtures: run_fixture materializes the declared repos and
        # synthesizes a manifest (see _prepare_git_protocol) before this verb
        # runs; the CLI-level dispatch is an ordinary fetch.
        return [], ["fetch"]
    if head == "index-trust":
        # S8: run_fixture translates the fixture's recipe env into a real
        # manifest + real CLI-recognized env vars (see _write_index_trust_manifest
        # / _translate_index_trust_env) before this verb runs.
        return [], ["fetch"]
    if head == "show-index-trust":
        return [], ["show", "--index-trust"]
    if head == "parse-lockfile":
        return [], ["show"]
    if head == "show":
        return [], ["show"]
    if head == "--version":
        # --version is a global flag, not a verb; the impl prints + exits 0.
        return ["--version"], []
    if head == "check-certificate":
        # "check-certificate" → verb=fetch; "check-certificate lock" → verb=lock
        verb = tokens[1] if len(tokens) >= 2 and tokens[1] in ("fetch", "lock") else "fetch"
        # --certificate flag goes in global_flags; the runner must provide a tmp path.
        # We use a sentinel that run_fixture replaces with a real path.
        return ["--certificate", "__CERT_PATH__"], [verb]
    if head == "add":
        return [], _add_argv(tokens[1:])
    if head == "remove":
        if len(tokens) != 2:
            raise ValueError(f"remove cmd needs exactly one name: {cmd!r}")
        return [], ["remove", tokens[1]]
    if head == "update":
        # update | update <name>
        return [], ["update", *tokens[1:]]
    if head == "clean":
        return [], ["clean"]
    if head == "verify":
        return [], ["verify"]
    if head == "workspace":
        # workspace add-member <path>
        # workspace remove-member <name|path>
        if len(tokens) < 3:
            raise ValueError(f"workspace cmd needs sub-verb and argument: {cmd!r}")
        sub = tokens[1]
        if sub == "add-member":
            return [], ["workspace", "add-member", tokens[2]]
        if sub == "remove-member":
            return [], ["workspace", "remove-member", tokens[2]]
        raise ValueError(f"Unknown workspace sub-verb: {sub!r}")
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


# ---------------------------------------------------------------------------
# git-protocol fixture support (H-infra, cmd=git-protocol)
# ---------------------------------------------------------------------------

# RFC 2606 reserved TLD host: guaranteed never to resolve on a real network.
# The manifest declares a git dep against this host (a real, spec-accepted
# https:// scheme — spec/manifest-grammar.md §git NORMATIVE rejects file://
# with MAN-GIT-URL-BAD-SCHEME, confirmed against both impls); the *real*
# transport target is substituted per-subprocess via GIT_CONFIG_* env vars
# (see _prepare_git_protocol).
_GIT_PROTOCOL_ORIGIN = "https://git-protocol.harness.invalid"


def _prepare_git_protocol(
    fixture_dir: Path,
    scratch: Path,
    repos_dir: Path,
) -> dict[str, str]:
    """Materialize a git-protocol fixture's repos + synthesize its manifest.

    Builds every repo declared in ``git-protocol.json`` under *repos_dir* via
    the shared ``_make_git_protocol_repo`` builder (SSOT with the in-process
    H-infra adapter in ``impls/python/tests/test_conformance.py``), writes a
    single-dep ``scratch/milpa.kdl`` declaring the fetch target, and returns
    the extra subprocess-env entries needed to route the manifest's
    (spec-required https/http/ssh/git-scheme) URL to the locally generated
    repo — WITHOUT touching any host or repo git config.

    Rewrite mechanism: milpa's manifest parser normatively rejects ``file://``
    git URLs (MAN-GIT-URL-BAD-SCHEME; verified empirically against both real
    binaries). So the manifest declares an ``https://`` URL under the
    reserved ``.invalid`` host above, and the real transport target is
    substituted PURELY via the child subprocess's environment using git's
    ``GIT_CONFIG_COUNT``/``GIT_CONFIG_KEY_n``/``GIT_CONFIG_VALUE_n``
    mechanism (``url.<target>.insteadOf <source>``) — no git config file, no
    host or repo mutation, isolated to this one subprocess invocation exactly
    like every other per-run env var this harness builds.

    Hostile-tree repos (EXTRACT-ZIP-SLIP fixtures) rewrite to a RAW filesystem
    path rather than a ``file://`` URL: git's pack-transfer fsck rejects a
    hostile tree over ``file://`` (or any transport URL) before the objects
    even reach milpa (verified empirically); only the raw-path "local clone"
    optimization (hardlink/copy of loose objects) skips fsck and lets milpa's
    OWN containment guard fire — mirrors ``_execute_git_protocol_fixture``'s
    ``uses_hostile_tree`` branch in the in-process adapter.

    Raises ``ValueError`` if the fixture pins an exact, non-ref commit
    (``fetch.commit_sha`` not null/absent): the manifest grammar has no
    ``commit_sha`` field distinct from ``ref`` (spec/manifest-grammar.md
    §git NORMATIVE: "In the manifest, git provenance is expressed as a
    UrlDep's ``git=``+``ref=`` properties" — ``commit_sha`` is lockfile/
    Provenance-only), so this cannot be expressed through a real manifest
    without silently substituting the WRONG code path (the mutable-ref-tip
    resolver, not the exact-commit-pin ``_ensure_commit_present`` path the
    fixture exists to exercise).
    """
    spec = json.loads((fixture_dir / "git-protocol.json").read_text(encoding="utf-8"))
    repos_spec: list = spec.get("repos", [])
    fetch_spec: dict = spec.get("fetch", {})

    commit_sha = fetch_spec.get("commit_sha")
    if commit_sha is not None:
        raise ValueError(
            f"git-protocol fixture pins an exact commit_sha {commit_sha!r}; "
            "the manifest grammar has no commit_sha field distinct from ref "
            "(spec/manifest-grammar.md §git) — not expressible via the CLI's "
            "fetch verb without exercising the wrong resolver code path"
        )

    extra_env: dict[str, str] = {}
    repo_paths: dict[str, Path] = {}
    repo_commit_shas: dict[str, list] = {}
    config_idx = 0
    for repo_spec in repos_spec:
        peer_shas = {n: shas[-1] for n, shas in repo_commit_shas.items() if shas}
        repo_dir, commit_shas_list = _make_git_protocol_repo(
            repos_dir, repo_spec, peer_shas=peer_shas
        )
        repo_name = repo_spec["name"]
        repo_paths[repo_name] = repo_dir
        repo_commit_shas[repo_name] = commit_shas_list

        source = f"{_GIT_PROTOCOL_ORIGIN}/{repo_name}"
        if repo_spec.get("hostile_tree"):
            target = str(repo_dir.resolve())
        else:
            target = f"file://{repo_dir.resolve()}"
        extra_env[f"GIT_CONFIG_KEY_{config_idx}"] = f"url.{target}.insteadOf"
        extra_env[f"GIT_CONFIG_VALUE_{config_idx}"] = source
        config_idx += 1

    if config_idx:
        extra_env["GIT_CONFIG_COUNT"] = str(config_idx)

    repo_name = fetch_spec.get("repo_name", "")
    if repo_name not in repo_paths:
        raise ValueError(f"fetch.repo_name {repo_name!r} not found in repos")
    dep_name = fetch_spec.get("dep_name", "smoke")
    ref = fetch_spec.get("ref", "main")

    manifest = (
        'name "harness-git-protocol-probe"\n'
        'kind "application"\n'
        "deps {\n"
        f'    "{dep_name}" git=(url)"{_GIT_PROTOCOL_ORIGIN}/{repo_name}" ref="{ref}"\n'
        "}\n"
    )
    (scratch / "milpa.kdl").write_text(manifest, encoding="utf-8")
    return extra_env


# ---------------------------------------------------------------------------
# index-trust / show-index-trust fixture support (S8, cmd=index-trust /
# cmd=show-index-trust — docs/rfc-attestation-v1-normative.md)
# ---------------------------------------------------------------------------

# Recipe-only env keys the in-process adapter reads directly (schema fields
# with no real CLI env-var equivalent). Consumed here and dropped from the
# subprocess env; everything else in the fixture's env file (MILPA_INDEX_TRUST,
# MILPA_SHOW_NOW, MILPA_INDEX_MAX_AGE, MILPA_INDEX_BUNDLE_URL, MILPA_INDEX_URL,
# ...) is already a real CLI-recognized env var and passes through verbatim
# via the existing fixture_env -> _build_env plumbing.
_INDEX_TRUST_RECIPE_KEYS = frozenset({
    "MILPA_INDEX_TRUST_MANIFEST",
    "MILPA_INDEX_TRUST_WS_ROOT",
    "MILPA_INDEX_TRUST_WS_MEMBER_ILLEGAL",
    "MILPA_REQUIRE_ATTESTED_INDEX",
    "mock_verifier_result",
})


def _translate_index_trust_env(fixture_env: dict[str, str]) -> dict[str, str]:
    """Translate the index-trust fixture recipe into real CLI-recognized env.

    ``mock_verifier_result`` becomes ``MILPA_INDEX_TRUST_MOCK_VERIFIER`` (a
    real, ``file://``-guarded env var the CLI reads). The remaining recipe
    keys (``MILPA_INDEX_TRUST_MANIFEST``, ``MILPA_INDEX_TRUST_WS_ROOT``,
    ``MILPA_INDEX_TRUST_WS_MEMBER_ILLEGAL``, ``MILPA_REQUIRE_ATTESTED_INDEX``)
    are consumed by ``_write_index_trust_manifest`` / the caller's flag
    handling, not passed through as env at all — they have no CLI env-var
    meaning and would otherwise leak into the subprocess as inert noise.
    """
    out = {k: v for k, v in fixture_env.items() if k not in _INDEX_TRUST_RECIPE_KEYS}
    mock_result = fixture_env.get("mock_verifier_result")
    if mock_result is not None:
        out["MILPA_INDEX_TRUST_MOCK_VERIFIER"] = mock_result
    return out


def _write_index_trust_manifest(scratch: Path, fixture_env: dict[str, str]) -> None:
    """Synthesize ``scratch/milpa.kdl`` (+ workspace member dirs) for an
    index-trust / show-index-trust fixture from its (untranslated) recipe env.

    Mirrors the shape of ``test_conformance.py``'s ``_write_single_package_manifest``
    / ``_write_workspace_root_index_trust`` / ``_write_workspace_member_illegal_index_trust``.
    Kept as an independent (not imported) implementation: this is a few lines
    of KDL scaffolding, not algorithmic logic — the SSOT concern that drove
    the git-protocol-repo-builder extraction doesn't apply here (see
    CLAUDE.md audit-for-duplication; the narrow test_conformance.py edit
    permission for this task is scoped to the git-protocol-repo import only).

    Three shapes, matching the fixture tier's three manifest recipes:
    - ``MILPA_INDEX_TRUST_WS_MEMBER_ILLEGAL`` truthy → workspace root
      (optionally declaring index-trust) + a member that illegally declares
      ``index-trust "strict"`` (WS-INDEX-TRUST-ON-MEMBER).
    - ``MILPA_INDEX_TRUST_WS_ROOT`` present → workspace root declaring
      ``index-trust "<policy>"`` directly (root-authority model) + a plain
      member.
    - otherwise → single-package manifest declaring
      ``index-trust "<MILPA_INDEX_TRUST_MANIFEST, default warn>"``.
    """
    manifest_policy = fixture_env.get("MILPA_INDEX_TRUST_MANIFEST", "warn")
    ws_root_policy = fixture_env.get("MILPA_INDEX_TRUST_WS_ROOT")
    ws_member_illegal = env_flag(fixture_env, "MILPA_INDEX_TRUST_WS_MEMBER_ILLEGAL")

    if ws_member_illegal:
        root_lines = []
        if manifest_policy:
            root_lines.append(f'index-trust "{manifest_policy}"')
        root_lines.append('workspace {\n    member "sub"\n}')
        (scratch / "milpa.kdl").write_text(
            "\n".join(root_lines) + "\n", encoding="utf-8",
        )
        sub_dir = scratch / "sub"
        sub_dir.mkdir(parents=True, exist_ok=True)
        (sub_dir / "milpa.kdl").write_text(
            'name "sub"\nkind "library"\nindex-trust "strict"\n', encoding="utf-8",
        )
        return

    if ws_root_policy is not None:
        (scratch / "milpa.kdl").write_text(
            f'index-trust "{ws_root_policy}"\nworkspace {{\n    member "sub"\n}}\n',
            encoding="utf-8",
        )
        sub_dir = scratch / "sub"
        sub_dir.mkdir(parents=True, exist_ok=True)
        (sub_dir / "milpa.kdl").write_text(
            'name "sub"\nkind "library"\n', encoding="utf-8",
        )
        return

    (scratch / "milpa.kdl").write_text(
        f'name "conformance-test"\nindex-trust "{manifest_policy}"\n', encoding="utf-8",
    )


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
    fixture_env = read_env_file(fixture_dir)
    project_dir_suffix = _read_project_dir_suffix(fixture_dir)

    # S8: index-trust / show-index-trust fixtures carry a recipe env (schema
    # fields the in-process adapter reads directly, no real CLI meaning).
    # _write_index_trust_manifest below needs the ORIGINAL recipe (it reads
    # MILPA_INDEX_TRUST_MANIFEST / _WS_ROOT / _WS_MEMBER_ILLEGAL to decide the
    # manifest shape), so it's captured before fixture_env is translated into
    # real CLI env vars. --require-attested-index is a global CLI FLAG, not an
    # env var, so it's extracted here rather than left in fixture_env.
    index_trust_recipe_env = fixture_env
    require_attested_index = False
    if cmd in ("index-trust", "show-index-trust"):
        require_attested_index = env_flag(fixture_env, "MILPA_REQUIRE_ATTESTED_INDEX")
        fixture_env = _translate_index_trust_env(fixture_env)

    global_flags, verb_argv = _cmd_to_cli(cmd)
    if require_attested_index:
        global_flags = ["--require-attested-index"] + global_flags

    # Slice B: translate the MILPA_CLI_FEATURES family into the verb-level
    # feature flags the CLI reads (fetch/lock/update only). The flags must
    # follow the verb (they live on the verb subparser), so append to verb_argv.
    if verb_argv and verb_argv[0] in _FEATURE_VERBS:
        verb_argv = verb_argv + _feature_argv(fixture_env)

    # Create isolated scratch + CAS dirs.
    scratch = Path(tempfile.mkdtemp(prefix=f"milpa-harness-{descriptor.name}-"))
    cas_dir = Path(tempfile.mkdtemp(prefix=f"milpa-harness-cas-{descriptor.name}-"))

    # H-infra: git-protocol fixtures materialize their declared repos into a
    # dedicated, separately-cleaned-up dir (see RunResult.extra_dir).
    repos_dir: Optional[Path] = None
    if cmd == "git-protocol":
        repos_dir = Path(tempfile.mkdtemp(prefix=f"milpa-harness-gitrepos-{descriptor.name}-"))

    # Resolve the __CERT_PATH__ sentinel for check-certificate fixtures.
    cert_path: Optional[str] = None
    if "__CERT_PATH__" in global_flags:
        cert_file = scratch / "_milpa_certificate.json"
        cert_path = str(cert_file)
        global_flags = [cert_path if f == "__CERT_PATH__" else f for f in global_flags]

    try:
        _copy_fixture_inputs(fixture_dir, scratch)

        # H-infra: build the git-protocol fixture's repos + synthetic manifest
        # now that scratch exists. S8: synthesize the index-trust /
        # show-index-trust manifest the same way.
        git_protocol_extra_env: Optional[dict[str, str]] = None
        if cmd == "git-protocol":
            assert repos_dir is not None
            git_protocol_extra_env = _prepare_git_protocol(fixture_dir, scratch, repos_dir)
        elif cmd in ("index-trust", "show-index-trust"):
            _write_index_trust_manifest(scratch, index_trust_recipe_env)

        env = _build_env(scratch, cas_dir, fixture_env, descriptor.env)

        if git_protocol_extra_env is not None:
            # Defensive: clear any host-inherited GIT_CONFIG_* before applying
            # this run's own mapping (_build_env only strips MILPA_* from the
            # host env, not GIT_CONFIG_*).
            for k in list(env.keys()):
                if k.startswith("GIT_CONFIG_"):
                    del env[k]
            env.update(git_protocol_extra_env)

        if cmd in ("index-trust", "show-index-trust"):
            # Isolate the index cache (XDG_CACHE_HOME/milpa/index) inside this
            # run's own CAS dir rather than the host's real cache — mirrors
            # MILPA_CACHE_DIR's per-run isolation for the CAS itself. Safe to
            # always set: every fixture in this tier uses a scratch-unique
            # MILPA_INDEX_URL, so there is no cross-run collision either way.
            env["XDG_CACHE_HOME"] = str(cas_dir / "xdg-cache")

        # Slice C c3: seed the CAS from cas-seed/ (frozen fixtures) before the run.
        # Verify fixtures warm the CAS via their own pre-fetch below, so an
        # explicit seed would mask the supply-chain mismatch they test for.
        if cmd != "verify":
            _seed_cas_from_lock(scratch, cas_dir)

        # For "verify" fixtures: run a regular (non-frozen) fetch first to
        # populate _deps/ and warm the CAS, then restore the pre-authored
        # milpa.lock (which carries the old dep_decl pins under test), then
        # run verify.  The pre-authored lock is the fixture's supply-chain
        # tripwire; the verify step checks it against the live index.
        #
        # Using a regular fetch (not frozen) avoids the need for the harness
        # to seed the CAS itself — the CLI does it naturally during resolution.
        if cmd == "verify":
            # Stash the pre-authored milpa.lock before fetch overwrites it.
            original_lock = scratch / "milpa.lock"
            lock_backup: Optional[bytes] = None
            if original_lock.exists():
                lock_backup = original_lock.read_bytes()

            pre_argv = descriptor.argv + ["-C", str(scratch), "fetch"]
            cwd = descriptor.cwd if descriptor.cwd is not None else str(scratch)
            subprocess.run(
                pre_argv,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            # Restore the pre-authored milpa.lock so verify checks the old pins.
            if lock_backup is not None:
                original_lock.write_bytes(lock_backup)
            # Pre-phase outcome is ignored — if fetch fails, verify will also
            # fail (no _deps/) with an appropriate error.

        # S11e: if the fixture specifies a project-dir sub-path, use it as
        # the -C argument (e.g. "member-a" → -C <scratch>/member-a).
        # resolve_project_dir confines the suffix to within scratch (L2).
        if project_dir_suffix:
            project_path = str(resolve_project_dir(scratch, project_dir_suffix))
        else:
            project_path = str(scratch)

        argv = (
            descriptor.argv
            + ["-C", project_path]
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
            cert_path=cert_path,
            extra_dir=str(repos_dir) if repos_dir is not None else None,
        )

    slug, slug_error = extract_slug(proc.stderr)

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
        cert_path=cert_path,
        extra_dir=str(repos_dir) if repos_dir is not None else None,
    )
