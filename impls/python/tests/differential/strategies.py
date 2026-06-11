"""Hypothesis strategies for tier-1 and tier-2 differential inputs.

Tier 1 = syntactic generators (malformed milpa.kdl) that surface parse +
error-slug divergence between impls.

The differential angle (distinct from test_parser_fuzz.py's in-process parser
fuzz): generate ONE malformed input, serialize it to a temp fixture dir, run it
through BOTH impls black-box (subprocess), assert they AGREE on the terminal
`milpa-error:` slug. Disagreement = bug or spec hole.

Because tier-1 inputs trigger parser failures before any fetch, NO FetchEntry
or index is needed. We use a lightweight `RawManifestInput` — a plain dataclass
that carries just the manifest text and the cmd — rather than a full FixtureSpec.
The serializer `write_raw_fixture()` writes cmd + milpa.kdl directly to a
caller-provided temp dir.

Design decision: raw bytes/text approach, NOT a full FixtureSpec.
  - FixtureSpec was designed for tier-2 semantic inputs that require mutually
    consistent deps + fetch entries + index rows.
  - Tier-1 inputs just need malformed milpa.kdl text; the consistency invariant
    of FixtureSpec would prevent generating the interesting "invalid dep block"
    inputs that exercise the parser.
  - The serializer is three lines: write cmd, write manifest text.
  - This is the "simpler" option the task description offered. We add nothing
    to harness/spec.py for this tier (no RawFixtureSpec in stdlib harness) —
    the write logic stays here in the Hypothesis-land package. If a RawFixtureSpec
    turns out useful across tiers, that's a later refactor.

Tier 2 = satisfiable semantic generator: `satisfiable_graph_st()`.

Construction-by-known-solution approach (RFC §2c; mirrors PBT methodology
"generation < parsing; oracle by construction"):

  1. Pick N packages (2–5), each with a designated "solution version".
  2. Build an acyclic dependency DAG (root manifest → subset of packages;
     some packages → others). For every edge A→B, emit a constraint on B
     that the chosen solution version SATISFIES (by construction).
  3. Add extra non-solution versions to the index so the solver has real
     choices; ensure the solution version remains the unique maxver pick.
  4. Project to a full FixtureSpec: manifest + index.kdl + mocked-fetches
     per (url, ref) with each version's .nimble encoding its own requires.
  5. Validate the FixtureSpec invariants before returning.

Key correctness invariant: every constraint in every .nimble requires line
for the chosen solution version of package A constrains package B such that
B's solution version satisfies it. Non-solution versions may have arbitrary
or even unsatisfiable requires (they won't be chosen).

Tier 2 = unsatisfiable semantic generator: `unsatisfiable_graph_st()`.

Construction-by-known-conflict approach (RFC §2c; §2c note: "The generator
should additionally record the reason for unsatisfiability (which constraint
pair creates the conflict) so a human reviewer can verify the slug is
SOLVE-CONFLICT"):

  The construction creates a guaranteed conflict via two paths from the root
  that impose disjoint constraints on a shared package C:

    root → A (requires C >= 2.0.0)
    root → B (requires C <  2.0.0)

  C's index contains versions from both < 2.0.0 and >= 2.0.0 (e.g. {1.0.0,
  2.0.0}). No single version of C satisfies BOTH constraints simultaneously:
    - C 1.0.0: satisfies C < 2.0.0 but NOT C >= 2.0.0
    - C 2.0.0: satisfies C >= 2.0.0 but NOT C < 2.0.0
  The intersection { v | v >= 2.0.0 AND v < 2.0.0 } is provably empty.

  The ConflictWitness records: the shared package name, both constraint
  strings, and which packages imposed them — enabling human-review of the
  SOLVE-CONFLICT slug per §2c.

  Important: A and B are well-formed packages in the index with valid fetch
  entries. The graph is structurally consistent — only the constraint
  intersection on C is empty. This ensures SOLVE-CONFLICT is genuinely the
  correct response, not a parse/fetch/index error.
"""

from __future__ import annotations

# Trigger the bridge so `import harness.*` resolves.
import differential  # noqa: F401 — side-effect: repo-root on sys.path

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hypothesis import strategies as st
from hypothesis.strategies import composite

from harness.spec import (
    DepSpec,
    FetchEntry,
    FixtureSpec,
    IndexRow,
    IndexVersionEntry,
    compute_content_hash_from_files,
)


# ---------------------------------------------------------------------------
# Tier-2 helpers — small stdlib-only utilities for construction by solution
# ---------------------------------------------------------------------------

def _fake_sha(seed: str) -> str:
    """Deterministic 40-char hex SHA from a seed string (NOT a real git SHA)."""
    return hashlib.sha256(seed.encode()).hexdigest()[:40]


def _nimble_text(
    pkg_name: str,
    version: str,
    requires: list[tuple[str, str]],
) -> str:
    """Generate a .nimble file body.

    requires is a list of (pkg_name, constraint_str) tuples. Each entry
    becomes a `requires "<pkg> <constraint>"` line.
    """
    lines = [
        "# Package",
        f'version = "{version}"',
        'author = "generated"',
        f'description = "{pkg_name}"',
        'license = "MIT"',
        'srcDir = "src"',
    ]
    for dep_name, constraint in requires:
        lines.append(f'requires "{dep_name} {constraint}"')
    return "\n".join(lines) + "\n"


def _version_constraint_containing(solution_version: str) -> st.SearchStrategy[str]:
    """Return a strategy that generates constraints guaranteed to contain
    the given solution_version.

    solution_version must be a clean semver string (e.g. "1.4.2").
    Generated constraints are simple range forms that milpa understands:
      ">= X.Y.Z"  where X.Y.Z <= solution_version
      ">= X.0.0"  (major-floor)
      ">= 0.0.1"  (wide open)
      "*"         (unconstrained, the empty/any constraint form)
    All of these are satisfied by solution_version.
    """
    parts = solution_version.split(".")
    major = int(parts[0]) if parts else 0
    minor = int(parts[1]) if len(parts) > 1 else 0
    patch = int(parts[2]) if len(parts) > 2 else 0

    # Build a set of valid floor constraints (<= solution_version).
    # All must use an operator prefix — bare version strings like "1.0.0"
    # are NOT valid milpa constraint syntax (rejected by VersionSet.from_constraint).
    options = [
        ">= 0.0.1",
        ">= 0.1.0",
        f">= {major}.0.0",
        f">= {major}.{minor}.0",
        f">= {major}.{minor}.{patch}",  # floor == exact solution: satisfies itself
    ]
    # De-duplicate while preserving order
    seen: set[str] = set()
    deduped = []
    for o in options:
        if o not in seen:
            seen.add(o)
            deduped.append(o)

    return st.sampled_from(deduped)


# ---------------------------------------------------------------------------
# Tier-2 SATISFIABLE graph generator
# ---------------------------------------------------------------------------

@composite
def satisfiable_graph_st(draw: Any) -> FixtureSpec:
    """Generate a fully consistent, satisfiable named-dep fixture.

    Construction method (RFC §2c "oracle by construction"):

    1. Draw N packages (2–5) each with an assigned solution version.
    2. Assign each package a set of additional non-solution versions in the
       index (0–2 extra versions), all strictly LOWER than the solution
       (maxver strategy will pick the solution).
    3. Build an acyclic dependency DAG:
       - The root manifest depends on a non-empty subset of packages as
         named deps. Each root dep gets a constraint containing the solution.
       - Some solution-version .nimble files carry requires on other packages
         (edges in the dag). Each edge gets a constraint containing the target
         package's solution version. Acyclicity is enforced by only allowing
         edges from package[i] to package[j] where j > i (topological order).
    4. Build the full FixtureSpec:
       - index_rows: all packages with all their versions.
       - index_fetch_map: every (url, ref) → (pkg_name, FetchEntry) mapping.
         The FetchEntry for a solution version includes its requires edges;
         non-solution versions have no requires (or requires that don't affect
         the outcome since they won't be picked by maxver).
       - deps: the root manifest deps with constraints.
    5. Assert FixtureSpec.validate() is empty.

    The returned FixtureSpec is the Hypothesis-shrinkable structured value.
    """
    # --- 1. Pick package names and solution versions -----------------------
    n_packages = draw(st.integers(min_value=2, max_value=5))
    pkg_names = [f"pkg{chr(ord('a') + i)}" for i in range(n_packages)]

    # Solution versions: each package gets a fixed version. We use a small
    # set of recognizable semver strings. The solution is always the "largest"
    # version — guaranteed by how we pick extra versions below (all lower).
    _VERSION_POOL = ["1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0", "3.0.0"]
    solution_versions: dict[str, str] = {}
    for name in pkg_names:
        solution_versions[name] = draw(st.sampled_from(_VERSION_POOL))

    # Base URL template — each package has a unique fake git URL.
    base_url = "https://example.com"

    # --- 2. Pick extra (non-solution) versions per package -----------------
    # Extra versions must all parse as semver < solution version so that
    # the maxver strategy selects the solution version.
    # We use a simple scheme: extra versions are always "0.x.0" (lower).
    _EXTRA_VERSIONS = ["0.1.0", "0.2.0", "0.3.0"]

    extra_versions: dict[str, list[str]] = {}
    for name in pkg_names:
        n_extra = draw(st.integers(min_value=0, max_value=2))
        # Pick n_extra distinct versions from the pool, all < solution
        sol = solution_versions[name]
        candidates = [v for v in _EXTRA_VERSIONS if v < sol]
        if n_extra > len(candidates):
            n_extra = len(candidates)
        extra = draw(
            st.lists(
                st.sampled_from(candidates) if candidates else st.just("0.1.0"),
                min_size=n_extra,
                max_size=n_extra,
                unique=True,
            )
        ) if candidates else []
        extra_versions[name] = extra

    # --- 3. Build the DAG edges --------------------------------------------
    # For each solution version of pkg[i], it may depend on pkg[j] for j > i.
    # This guarantees acyclicity.
    # We draw (for each pkg[i]) a subset of {i+1, ..., n-1} to depend on.
    edges: dict[str, list[int]] = {}  # pkg_name -> list of target pkg indices
    for i, name in enumerate(pkg_names):
        possible_targets = list(range(i + 1, n_packages))
        if not possible_targets:
            edges[name] = []
            continue
        n_edges = draw(st.integers(min_value=0, max_value=min(2, len(possible_targets))))
        chosen_indices = draw(
            st.lists(
                st.sampled_from(possible_targets),
                min_size=n_edges,
                max_size=n_edges,
                unique=True,
            )
        )
        edges[name] = chosen_indices

    # --- 4. For each DAG edge, choose a constraint containing the solution --
    edge_constraints: dict[tuple[str, str], str] = {}
    for src_name, target_indices in edges.items():
        for tgt_idx in target_indices:
            tgt_name = pkg_names[tgt_idx]
            tgt_solution = solution_versions[tgt_name]
            constraint = draw(_version_constraint_containing(tgt_solution))
            edge_constraints[(src_name, tgt_name)] = constraint

    # --- 5. Build root manifest deps (non-empty subset of packages) --------
    # The root manifest depends on at least one package.
    n_root_deps = draw(st.integers(min_value=1, max_value=min(n_packages, 3)))
    root_dep_indices = draw(
        st.lists(
            st.sampled_from(list(range(n_packages))),
            min_size=n_root_deps,
            max_size=n_root_deps,
            unique=True,
        )
    )
    root_dep_names = [pkg_names[i] for i in sorted(root_dep_indices)]

    root_constraints: dict[str, str] = {}
    for name in root_dep_names:
        constraint = draw(_version_constraint_containing(solution_versions[name]))
        root_constraints[name] = constraint

    # --- 6. Construct FixtureSpec fields -----------------------------------
    # index_rows: all packages, all versions (solution + extras)
    # index_fetch_map: every (url, ref) -> (pkg_name, FetchEntry)
    # The FetchEntry for the solution version encodes requires lines.

    index_rows: list[IndexRow] = []
    index_fetch_map: dict[tuple[str, str], tuple[str, FetchEntry]] = {}

    for name in pkg_names:
        sol_ver = solution_versions[name]
        extras = extra_versions[name]
        all_versions = extras + [sol_ver]  # solution is always last (highest)

        version_entries: list[IndexVersionEntry] = []
        for ver in all_versions:
            git_url = f"{base_url}/{name}.git"
            ref = f"v{ver}"
            commit_sha = _fake_sha(f"{name}:{ver}:sha")

            # Build the FetchEntry for this version.
            # Only the solution version carries requires edges; extras have none.
            if ver == sol_ver:
                requires_lines = [
                    (pkg_names[tgt_idx], edge_constraints[(name, pkg_names[tgt_idx])])
                    for tgt_idx in edges[name]
                ]
            else:
                requires_lines = []

            nimble = _nimble_text(name, ver, requires_lines)
            content_files: dict[str, bytes] = {
                f"{name}.nim": f"# {name} v{ver}\n".encode()
            }

            # Compute the REAL content hash over the same file set the impl will
            # see in the fetched directory (spec/identity.md).
            #
            # The mocked fetcher (fetchers/mocked.py) copies BOTH:
            #   - content/* (all files from content/)
            #   - <name>.nimble (sibling of content/)
            # into the dest directory before compute_content_hash is called.
            # So the hash must be computed over content_files PLUS the nimble file.
            nimble_bytes = nimble.encode("utf-8")
            hash_input_files = dict(content_files)
            hash_input_files[f"{name}.nimble"] = nimble_bytes
            content_hash = compute_content_hash_from_files(hash_input_files)

            version_entries.append(IndexVersionEntry(
                version=ver,
                content_hash=content_hash,
                git_url=git_url,
                ref=ref,
                commit_sha=commit_sha,
            ))

            entry = FetchEntry(
                sha=commit_sha,
                content_files=content_files,
                nimble_text=nimble,
            )
            index_fetch_map[(git_url, ref)] = (name, entry)

        index_rows.append(IndexRow(name=name, versions=version_entries))

    # Root manifest deps
    deps = [
        DepSpec.named(name, root_constraints[name])
        for name in root_dep_names
    ]

    spec = FixtureSpec(
        package_name="testapp",
        kind="application",
        deps=deps,
        fetch_map={},
        index_rows=index_rows,
        index_fetch_map=index_fetch_map,
        cmd="resolve",
    )

    # Validate consistency (construction invariants)
    violations = spec.validate()
    assert not violations, (
        f"Generator produced inconsistent FixtureSpec: {violations}\n"
        f"pkg_names={pkg_names}\n"
        f"solution_versions={solution_versions}\n"
        f"edges={edges}\n"
        f"root_dep_names={root_dep_names}"
    )

    return spec


# ---------------------------------------------------------------------------
# Tier-2 UNSATISFIABLE graph generator
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConflictWitness:
    """Records why an unsatisfiable_graph_st() output is genuinely unsatisfiable.

    package    — the shared package whose constraints have empty intersection
    constraint_a — first constraint (from imposer_a)
    imposer_a  — package name (or "root") that imposes constraint_a on package
    constraint_b — second constraint (from imposer_b)
    imposer_b  — package name (or "root") that imposes constraint_b on package
    reason     — human-readable explanation of why the intersection is empty
    """
    package: str
    constraint_a: str
    imposer_a: str
    constraint_b: str
    imposer_b: str
    reason: str


@composite
def unsatisfiable_graph_st(draw: Any) -> tuple[FixtureSpec, ConflictWitness]:
    """Generate a well-formed but unsatisfiable named-dep fixture.

    Construction method (RFC §2c "construct-by-known-conflict"):

    Fixed structure (minimized for guaranteed conflict, small shrink space):
      - Package A: one version (1.0.0). Root requires A >= 1.0.0.
        A's 1.0.0 version requires C >= 2.0.0.
      - Package B: one version (1.0.0). Root requires B >= 1.0.0.
        B's 1.0.0 version requires C < 2.0.0.
      - Package C: two versions (1.0.0 and 2.0.0).
        C 1.0.0 satisfies C < 2.0.0 but NOT C >= 2.0.0.
        C 2.0.0 satisfies C >= 2.0.0 but NOT C < 2.0.0.
        No version satisfies both — the intersection is empty by construction.

    The conflict is real: the solver must assign ONE version to C satisfying
    ALL constraints. Since { v | v >= 2.0.0 ∧ v < 2.0.0 } = ∅, no assignment
    exists → SOLVE-CONFLICT is the required outcome.

    The FixtureSpec is otherwise fully consistent: all packages are in the
    index, all versions have fetch entries, all requires edges name known
    packages. The graph is well-formed; only the constraint intersection is empty.

    Returns (FixtureSpec, ConflictWitness) — the witness records which package
    and which constraint pair creates the conflict (for human review per §2c).
    """
    # Introduce pkg-name variation so Hypothesis explores different names
    # while keeping the structural conflict identical.
    suffix = draw(st.sampled_from(["", "x", "y", "z"]))

    a_name = f"pkga{suffix}"
    b_name = f"pkgb{suffix}"
    c_name = f"pkgc{suffix}"

    base_url = "https://example.com"

    # The pivot version for C's conflict: "2.0.0"
    # Constraint A (imposed by A on C): >= 2.0.0
    # Constraint B (imposed by B on C): < 2.0.0
    # These two constraints have empty intersection over any semver ordering.
    c_constraint_from_a = ">= 2.0.0"
    c_constraint_from_b = "< 2.0.0"

    # C's index versions: 1.0.0 and 2.0.0.
    # 1.0.0 satisfies < 2.0.0 only; 2.0.0 satisfies >= 2.0.0 only.
    c_versions = ["1.0.0", "2.0.0"]

    # A's version (just one).
    a_ver = "1.0.0"
    # B's version (just one).
    b_ver = "1.0.0"

    # --- Build index entries for all packages ---

    def _build_pkg_entries(
        name: str,
        versions: list[str],
        nimble_requires_by_version: dict[str, list[tuple[str, str]]],
    ) -> tuple[list[IndexVersionEntry], dict[tuple[str, str], tuple[str, FetchEntry]]]:
        """Build version entries + fetch map for one package."""
        version_entries = []
        fetch_map = {}
        for ver in versions:
            git_url = f"{base_url}/{name}.git"
            ref = f"v{ver}"
            commit_sha = _fake_sha(f"{name}:{ver}:sha")
            requires = nimble_requires_by_version.get(ver, [])
            nimble = _nimble_text(name, ver, requires)
            content_files = {f"{name}.nim": f"# {name} v{ver}\n".encode()}
            nimble_bytes = nimble.encode("utf-8")
            hash_input = dict(content_files)
            hash_input[f"{name}.nimble"] = nimble_bytes
            content_hash = compute_content_hash_from_files(hash_input)
            version_entries.append(IndexVersionEntry(
                version=ver,
                content_hash=content_hash,
                git_url=git_url,
                ref=ref,
                commit_sha=commit_sha,
            ))
            fetch_map[(git_url, ref)] = (name, FetchEntry(
                sha=commit_sha,
                content_files=content_files,
                nimble_text=nimble,
            ))
        return version_entries, fetch_map

    # A: version 1.0.0, requires C >= 2.0.0 (the first arm of the conflict)
    a_versions, a_fetch = _build_pkg_entries(
        a_name, [a_ver],
        {a_ver: [(c_name, c_constraint_from_a)]},
    )

    # B: version 1.0.0, requires C < 2.0.0 (the second arm of the conflict)
    b_versions, b_fetch = _build_pkg_entries(
        b_name, [b_ver],
        {b_ver: [(c_name, c_constraint_from_b)]},
    )

    # C: versions 1.0.0 and 2.0.0, no further requires
    c_versions_entries, c_fetch = _build_pkg_entries(
        c_name, c_versions, {},
    )

    # --- Assemble FixtureSpec ---
    index_rows = [
        IndexRow(name=a_name, versions=a_versions),
        IndexRow(name=b_name, versions=b_versions),
        IndexRow(name=c_name, versions=c_versions_entries),
    ]

    index_fetch_map: dict[tuple[str, str], tuple[str, FetchEntry]] = {}
    index_fetch_map.update(a_fetch)
    index_fetch_map.update(b_fetch)
    index_fetch_map.update(c_fetch)

    # Root manifest: depends on A and B directly (both with wide-open constraints)
    deps = [
        DepSpec.named(a_name, ">= 1.0.0"),
        DepSpec.named(b_name, ">= 1.0.0"),
    ]

    spec = FixtureSpec(
        package_name="testconflict",
        kind="application",
        deps=deps,
        fetch_map={},
        index_rows=index_rows,
        index_fetch_map=index_fetch_map,
        cmd="resolve",
    )

    # Validate consistency invariants (the graph must be well-formed)
    violations = spec.validate()
    assert not violations, (
        f"unsatisfiable_graph_st produced inconsistent FixtureSpec: {violations}\n"
        f"a_name={a_name!r}, b_name={b_name!r}, c_name={c_name!r}"
    )

    witness = ConflictWitness(
        package=c_name,
        constraint_a=c_constraint_from_a,
        imposer_a=a_name,
        constraint_b=c_constraint_from_b,
        imposer_b=b_name,
        reason=(
            f"No version of {c_name!r} satisfies both "
            f"{c_constraint_from_a!r} (required by {a_name!r}) and "
            f"{c_constraint_from_b!r} (required by {b_name!r}) — "
            f"the intersection {{v | v >= 2.0.0 ∧ v < 2.0.0}} is empty."
        ),
    )

    return spec, witness


# ---------------------------------------------------------------------------
# The lightweight raw input value
# ---------------------------------------------------------------------------

@dataclass
class RawManifestInput:
    """Minimal input for a tier-1 syntactic differential run.

    text  — the raw milpa.kdl bytes (as a str; written as UTF-8 to disk)
    cmd   — the fixture cmd string (always "resolve" for tier-1; the manifest
            parser fires before any fetch so "fetch" is the relevant verb)
    """
    text: str
    cmd: str = "resolve"


def write_raw_fixture(inp: RawManifestInput, dest: Path) -> None:
    """Write a RawManifestInput to a fixture directory.

    Creates dest if needed. Writes:
      - cmd      (one line, e.g. "resolve\\n")
      - milpa.kdl (inp.text, UTF-8)

    No expected/, no mocked-fetches/ — tier-1 parse failures happen before
    any fetch transport is consulted.
    """
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "cmd").write_text(inp.cmd + "\n", encoding="utf-8")
    (dest / "milpa.kdl").write_text(inp.text, encoding="utf-8")


# ---------------------------------------------------------------------------
# KDL-flavored alphabet (matches test_parser_fuzz.py _KDL_CHARS + structural)
# ---------------------------------------------------------------------------

_IDENT_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
_STRUCTURAL = ["{", "}", '"', "=", "\n", " ", "/", "\\", "(", ")", ";", "[", "]"]

# Short identifier tokens (names, values, keyword fragments)
_ident_st = st.text(alphabet=_IDENT_CHARS, min_size=1, max_size=15)


# ---------------------------------------------------------------------------
# Strategy helpers
# ---------------------------------------------------------------------------

def _structural_noise() -> st.SearchStrategy[str]:
    """Structural noise tokens interleaved with identifier fragments."""
    return st.builds(
        lambda tokens, name: "".join(tokens + [name]),
        st.lists(st.sampled_from(_STRUCTURAL), min_size=0, max_size=20),
        st.text(alphabet=_IDENT_CHARS, max_size=15),
    )


def _mangled_node(name: str) -> st.SearchStrategy[str]:
    """A KDL node line with the given name + random garbage after it."""
    return st.builds(
        lambda noise: f'{name} {noise}',
        _structural_noise(),
    )


# ---------------------------------------------------------------------------
# Tier-1 input strategies
# ---------------------------------------------------------------------------

def malformed_manifest_st() -> st.SearchStrategy[RawManifestInput]:
    """Generate malformed milpa.kdl text as a RawManifestInput.

    Multiple flavors fused via st.one_of:

    1. pure_garbage      — completely random text (hits KDL syntax layer)
    2. missing_name      — valid KDL but no `name` node (MAN-MISSING-NAME)
    3. missing_kind      — has name but no `kind` (MAN-MISSING-KIND)
    4. bad_kind          — kind with an invalid value
    5. bad_deps_block    — name+kind present but deps block contains garbage
    6. structural_mix    — structural tokens mixed with identifier chars
    7. truncated_block   — unclosed braces (hits KDL parser depth/balance)
    8. unicode_garbage   — arbitrary unicode (hits text encoding edge cases)
    """
    # 1. pure garbage
    pure_garbage = st.text().map(lambda t: RawManifestInput(text=t))

    # 2. missing name node — kind is present but name is absent
    missing_name = st.builds(
        lambda kind_val: RawManifestInput(
            text=f'kind "{kind_val}"\ndeps {{\n}}\n'
        ),
        st.sampled_from(["application", "library", "garbage"]),
    )

    # 3. missing kind node
    missing_kind = _ident_st.map(
        lambda n: RawManifestInput(text=f'name "{n}"\ndeps {{\n}}\n')
    )

    # 4. bad kind value
    bad_kind = st.builds(
        lambda n, k: RawManifestInput(
            text=f'name "{n}"\nkind "{k}"\n'
        ),
        _ident_st,
        st.text(alphabet=_IDENT_CHARS, min_size=1, max_size=12),
    ).filter(lambda inp: '"application"' not in inp.text and '"library"' not in inp.text)

    # 5. garbage inside the deps block — name + kind valid, deps mangled
    bad_deps_block = st.builds(
        lambda n, noise: RawManifestInput(
            text=f'name "{n}"\nkind "library"\ndeps {{\n    {noise}\n}}\n'
        ),
        _ident_st,
        _structural_noise(),
    )

    # 6. structural mix — random KDL structural tokens
    structural_mix = _structural_noise().map(lambda s: RawManifestInput(text=s))

    # 7. truncated (unclosed braces)
    truncated = st.integers(min_value=1, max_value=100).map(
        lambda n: RawManifestInput(text="{" * n)
    )

    # 8. unicode garbage (default Hypothesis text — surrogates excluded)
    unicode_garbage = st.text(min_size=0, max_size=200).map(
        lambda t: RawManifestInput(text=t)
    )

    return st.one_of(
        pure_garbage,
        missing_name,
        missing_kind,
        bad_kind,
        bad_deps_block,
        structural_mix,
        truncated,
        unicode_garbage,
    )
