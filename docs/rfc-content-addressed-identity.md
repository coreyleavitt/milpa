# RFC: content addressing as the identity primitive

**Status**: Proposed (v0.x design commitment, phased migration)
**Author**: Corey Leavitt
**Date**: 2026-05-22

## Why this RFC exists

milpa v0 records both a commit SHA and a sha256 content hash for every
fetched dependency. The documentation and the resolver's behavior
treat the commit SHA as the primary identity (deduplication keys, the
unit of caching) and content_hash as parallel insurance.

That ordering is backwards. Every modern dependency system that has
done this rigorously — Nix, Bazel's remote cache, Cargo for registry
packages, IPFS — uses **content hash as identity** and **everything
else (URL, ref, commit SHA) as provenance**. The fields answer
different questions, and conflating them is the source of a large
class of bugs in existing resolvers.

This RFC:

1. Articulates the identity-vs-provenance distinction.
2. Surveys how existing tools handle it (and where they conflate).
3. Proposes milpa's commitment: content hash is the identity primitive;
   provenance is descriptive metadata.
4. Specifies the design changes required for milpa to actually live the
   model (today the data is there but the *use* of it is mixed).
5. Phases the work into v0.x and v1+ deliverables.
6. Enumerates open design questions (what to hash, hash agility,
   tooling boundaries).

## Background: identity vs provenance

A dependency record answers two distinct questions:

- **Identity**: *what are these bytes?*  An immutable, verifiable claim
  about the contents themselves. Trust-independent: given the bytes,
  anyone can recompute the identity.

- **Provenance**: *how do I get these bytes?*  A pointer into the
  infrastructure that delivers them — a URL, a git ref, a registry
  name, a commit SHA. Mutable. Trust-dependent (the git server may lie,
  the mirror may be stale, the ref may be force-pushed).

These are orthogonal:

| Scenario | identity changes? | provenance changes? |
|---|---|---|
| Force-push to a branch | yes | yes (commit SHA flips) |
| Rebase that preserves the tree | no | yes (commit SHA changes) |
| Mirror the same commit to a new URL | no | yes (URL changes) |
| Upstream republishes identical content via tarball | no | yes (transport changes) |
| Edit one byte in a source file | yes | yes (new commit) |

A resolver that treats provenance as identity sees four of these as
different packages when they aren't. A resolver that treats identity
as provenance can't refresh a mirror without losing pinned bytes.

## Prior art

**Nix** (most rigorous). A derivation's identity is the hash of its
input closure: the hashes of every source input plus the build script.
Two derivations with the same inputs are *the same derivation*; the
URL or git commit a source came from is provenance, recorded but not
part of identity. This is the high-water mark.

**Bazel remote cache**. Action cache is keyed by the content hash of
the action's inputs (source files, command line, env). Cross-machine,
cross-project, cross-CI sharing is safe by construction. The same
content-addressing principle, applied to build outputs.

**Cargo, asymmetrically**. Registry deps are content-addressed: every
`.crate` is identified by sha256 of its tarball, and the lockfile pins
that hash. Git deps are *not* content-addressed: identity is `(URL,
commit_sha)`. Cargo has the right primitive for half its dep types and
inherits legacy conflation for the other half. This is the most
instructive prior art for milpa because it shows the practical wins of
content addressing exist already, just not uniformly applied.

**IPFS / IPLD**. Content addressing taken to its logical end. There is
no URL concept; there is only the content identifier (CID). Provenance
is implicit ("any peer that has the bytes"). This is the model when
identity is fully primary and provenance is fully optional.

**ostree, casync, restic**. Content-addressed storage for OS images,
config trees, backups. Same principle, different domain.

The trend is unambiguous: when correctness, reproducibility, or cache
sharing matters, the field has consistently chosen content addressing.

## Where milpa is today

The data model already records the right fields:

```
LockedDep:
  source         # URL or "registry:<name>"   ← provenance
  ref            # git ref                    ← provenance
  tag            # registry tag               ← provenance
  sha            # commit SHA                 ← provenance
  content_hash   # sha256 of source tree      ← identity
  version
  src_dir
  requires
```

But the *behavior* doesn't live the model:

1. **Dedup is by `(URL, ref)`.** The resolver's BFS uses `seen_url`
   keyed by `(dep.git, dep.ref)`. Two URLs that fetch identical content
   produce two `_deps/` entries.

2. **Cache is per-project.** `_deps/` is scoped to one consumer. The
   same chronos checked out by fresco and amoxtli is fetched twice.

3. **Verification recomputes content_hash** (good) but the rest of the
   resolver treats commit SHA as primary (in nimble-style, in
   `_infer_ref`, in the cli's `show` output).

4. **Documentation says** "the dep-identity key" about content_hash but
   then operates on `(URL, ref)`. The model is right; the prose and the
   code drift past each other.

## Proposed model

### Definition

> The **identity** of a dependency is the sha256 of its source tree.
> Provenance is everything else and is multi-valued: a single identity
> may have one or more provenance records (URL+ref+commit_sha tuples)
> that all deliver bytes hashing to that identity.

Concretely, in a future milpa.lock:

```kdl
dep "chronos" {
    identity "sha256:e69bd0696a3ac88ce931dae1f1e5b2af7710c361d141e0724551a8afb382af32"
    version "0.0.1"
    src_dir ""
    requires "results" "stew" "bearssl" "httputils" "unittest2"

    // One or more ways to obtain the bytes. Resolver may use any;
    // identity claim does not change with provenance.
    provenance {
        kind "git"
        url "https://github.com/coreyleavitt/chronos.git"
        ref "feat/contextvars"
        commit_sha "90660858a9da783c6edf14c269d5b6165e7f6bb2"
    }
}
```

The current v0 single-line `content_hash "sha256:..."` becomes an
explicit `identity "sha256:..."` field that the schema documents as
the primary key. `sha` / `ref` / `source` move into a `provenance`
block. Multiple provenance blocks are permitted.

### Algebraic properties

The lockfile becomes a function `name → identity × provenances`:

- **Identity is a function of content** — given the bytes, recompute and verify.
- **Provenance is observation** — a list of places we've seen these
  bytes available. Adding a new mirror appends a provenance; it does
  not change identity.
- **Dedup is by identity** — two packages with the same identity are
  one entry, regardless of how many ways they arrived.

### What changes operationally

1. **Resolver dedup** keys by content_hash post-fetch. The
   `(URL, ref)` cache stays as an optimization (don't re-clone) but
   the *graph* unifies by identity.

2. **A global content-addressed store.** This already exists as
   `cas.py` (`CAStore`), default root `~/.cache/milpa/cas`
   (override: `MILPA_CACHE_DIR`), layout `<root>/sha256/<full-64-hex>/`
   — **flat, no fan-out** (the two-level `ab/cd/` fan-out git uses for
   20-byte SHAs is pointless for 64-char content hashes). Phase C builds
   on this module; it MUST NOT introduce a parallel store. The
   `CasAdmittingFetcher` already admits immutable fetches into the store
   and **already replaces `_deps/<name>` with a relative symlink** into
   it. The remaining Phase C work is therefore narrower than originally
   framed (see migration plan).

3. **Lockfile becomes the identity claim**, not the fetch instructions.
   Provenance records exist to *resolve identity to bytes*; identity
   exists to *verify the bytes are right*.

4. **Verification is round-trippable across providers**. If you've got
   the bytes (from anywhere — tarball, IPFS, USB stick), you can verify
   them against the lockfile without contacting the original provenance.

5. **CLI semantics**:
   - `milpa show` lists identity + provenance separately.
   - `milpa add <url>` records the URL as a *provenance* under whatever
     identity its content hashes to. Adding a known-content URL just
     appends a provenance to an existing dep.

### What the content hash actually covers

The identity hash covers `(relpath, content-bytes)` and nothing else
(Resolved Decision 1 — all mode bits, including the exec bit, are
excluded as non-identity metadata):

- Walk the cloned tree, exclude `.git/`, sort files by POSIX relpath.
- For each regular file: hash `(relpath, contents)`.
- Concatenate per-file hashes in sorted order, hash the result.

Specifically:
- **Include**: regular file contents, relative paths.
- **Exclude**: `.git/` (provenance, not content); all filesystem mode
  bits (exec bit, setuid, etc. — Resolved Decision 1); filesystem-specific
  metadata (mtime, owner, uid/gid); symlink targets *outside* the tree.
- **Symlinks within the tree**: hash the link target as the literal byte
  string stored in the symlink, with **no path normalization** — two
  equivalent-but-differently-spelled targets (`../bar/baz` vs
  `bar/../bar/baz`) hash differently *by design*. The symlink itself is
  treated as a "file" whose content is that target string.
- **Empty directories**: not hashed (they have no contents). Acceptable;
  Nim packages don't depend on empty-directory presence.

**Transport normalization (NORMATIVE).** Identity is transport-independent
only if the materialized bytes are. A git checkout under
`core.autocrlf=true` rewrites LF→CRLF, and `core.filemode` rewrites the
exec bit — either makes the same upstream tree hash differently per host.
The git fetcher MUST therefore invoke git with
`-c core.autocrlf=false -c core.filemode=false` so host git config cannot
perturb the byte stream. (Exec-bit exclusion already neutralizes the
`filemode` axis *for identity*, but pinning it keeps the working tree
itself stable.) `spec/identity.md` carries the normative clause; a
conformance fixture pins a CRLF-containing file to a fixed hash.

## Migration plan

> **Implementation-status reconciliation (2026-06-14).** A round-1
> architecture review found the codebase is materially ahead of this
> plan's original framing. The slices below are rewritten to reflect
> what is *actually shipped* versus what remains. Three pieces the plan
> originally listed as future work are already done:
>
> - **Multihash identity encoding** (`identity "sha256:<hex>"`) — done.
>   `identity.py` emits it; `lockfile.py` parses/validates it. There is
>   no legacy bare-hex lockfile format in the wild, so the "additive
>   parse of bare-hex" item is dropped (unfounded).
> - **The `provenance { }` lockfile schema** — done. `LockedDep.provenances`
>   is already `tuple[ProvenanceRecord, ...]`; the parser already loops
>   provenance blocks and the emitter already serializes N of them. What
>   is *not* done is the **resolver writing more than one** (it always
>   emits `(d.provenance,)`).
> - **The global store + symlink view** — `cas.py` (`CAStore`) +
>   `CasAdmittingFetcher` already admit fetches to `~/.cache/milpa/cas/sha256/<hex>/`
>   and symlink `_deps/<name>` into it.
>
> Consequence: the remaining work is **resolver-side dedup/merge logic,
> spec amendments, and the GC + observability surface** — not new
> storage or new schema fields. Effort estimates below are revised and
> **include the Rust impl + conformance corpus** (the original estimates
> were Python-only; the two-impl + corpus tax roughly doubles them).

### Phase A — clean up the data model (v0.x) — **DONE (#29–31), plus one corrective slice**

Shipped: identity-vs-provenance docs, exec-bit in the hash
(`spec/identity.md §1.7`), the `milpa verify` CLI command. Round-1
review found the exec-bit inclusion breaks cross-platform
transport-independence; it is **removed** from identity — see Resolved
Decision 1.

**A-exec-removal (gating precursor slice — must land before B/C/D).** The
identity algorithm must be byte-stable before any new hash is pinned, so
this is its own slice that lands atomically across both impls. Round-2
review mapped the blast radius:
- `spec/identity.md §1.2` (drop the `0x01` executable mode-marker row;
  regular files always marker `0x00`) and §1.7 (remove the NORMATIVE
  `stat.S_IXUSR` clause).
- `impls/python/milpa/identity.py` (`_MODE_EXECUTABLE` / `S_IXUSR` marker
  logic) and `impls/rust/crates/milpa-core/src/identity.rs`
  (`S_IXUSR` / `MODE_EXECUTABLE`).
- Test surgery: `test_identity.py::test_executable_bit_changes_hash` and
  `::test_only_owner_execute_bit_matters` assert the *opposite* and must
  be rewritten; the cross-impl oracle constant (`RUST_ORACLE_HASH` in both
  `test_identity.py` and `identity.rs`) must be **recomputed** by actually
  running both impls over the oracle tree.
- Conformance fixture audit: any `spec-v1/` fixture whose mocked tree
  contains an executable file (audit `fixture-118` first) gets its pinned
  `identity` / `_deps_structure.txt` hash recomputed in the same slice.
- **Migration note (user-facing):** after this lands, `milpa verify`
  against an *old* lockfile whose dep trees contain executable files will
  report identity divergence; `milpa fetch` / `milpa lock` regenerates the
  correct hashes. This is the expected one-time reconciliation, not a bug.

All other slices gate on `A-exec-removal` being green in both impls
simultaneously.

### Schema strategy (precedes B/C/D)

The original plan bumped the lockfile schema `v1 → v2`. Review flagged
this against [[spec_versioning_deferred]]: milpa is **pre-stabilization
with no external lockfile consumers**, and `spec/lockfile-schema.md §2.1`
hard-rejects any version ≠ 1 with no partial-parse path. Because the
multi-provenance wire format **already parses at v1** (the fields exist),
the changes in B/C/D are *additive within schema v1* — emitting a second
`provenance { }` block does not break a v1 parser. **Decision: evolve
schema v1 in place; do not introduce v2** (Resolved Decision 4). All
B/C/D slices target in-place v1.

### Phase B — dedup by identity in the resolver (v0.x)

Round-2 review found B-dedup is not one slice: it bundles an additive
schema change, a resolver behavior change, and a nim.cfg/symlink change
with a hard ordering between them. Split into three sequenced slices.

**B-schema (additive, spec-first).** Add an `aliases` representation to
the lockfile dep block: a KDL child carrying zero or more non-canonical
names, `aliases "nim-chronos" "chronos-fork"`, emitted in lexicographic
order, **omitted when empty** (same convention as `requires`). Add the
field to Python `LockedDep`, Rust `LockedDep`, and `ResolvedDep` in both
impls, plus a `spec/lockfile-schema.md §3` clause and a
parse→format→parse round-trip fixture. Independently testable before any
resolver change, and it gives the merge logic a place to put alias names.
The **SSOT cleanup lands here (Python-only)**: delete
`lockfile.py:_parse_identity_for_lockfile`, delegate to
`identity.py:parse_identity`, wrapping `MilpaError(ID-*)` →
`MilpaError(LOCK-DEP-IDENTITY-INVALID)`. Rust already delegates
(`lockfile.rs` calls `parse_identity` directly) — **no Rust work**.

**B-resolver (post-fetch collapse).** After fetch, the resolver computes
content_hash. Two candidates with the **same `identity`** collapse into
one graph node carrying **multiple provenance records** and the
non-canonical names as `aliases`; the lockfile emits one dep entry. Hard
requirements:

1. **Canonical-name selection is by BFS declaration order, NOT
   fetch-completion order.** Fetch runs on a `ThreadPoolExecutor` drained
   via `as_completed()`; keying the canonical name to arrival order is
   nondeterministic. Key it to the pre-fetch BFS queue position. In a
   **workspace** (multiple roots, no single BFS queue), the workspace
   manifest's own dep declarations win over member declarations; among
   members, lexicographic member name is the tiebreak. Spec this.
2. **`requires` must match before merge — from a single canonical parse
   path.** Byte-identical trees yield identical `requires` *only if parsed
   the same way*. Both candidates' `requires` MUST be (re-)derived from
   the **fetched tree** (the nimble-scanner / manifest parse over the
   materialized bytes), never one from the tianguis index and the other
   from a tree. With a single parse source, assert equality as an
   invariant (mismatch ⇒ internal-error, not a silent pick).
3. **Post-fetch collapse, not pre-fetch skip.** Two distinct `(URL,ref)`
   keys are still *fetched* (the `seen_url` BFS cache only skips an
   identical key); identity unification happens after both trees exist.
   Phase B therefore does **not** reduce network calls for
   identical-content mirrors — only the CAS hit-before-fetch (Phase C)
   does. Keep these wins distinct in prose and tests.
4. **named-dep vs URL-dep collision.** A tianguis named dep and a URL dep
   that hash to the same identity unify under the same BFS-order rule.
   `requires` come from the fetched tree for both (item 2); if the
   tianguis index's `requires` for the named dep disagree with the fetched
   tree, the **fetched tree wins** and the index disagreement is logged as
   a warning (the index may legitimately lag the tree), never an error.
5. **override (#50) interaction.** An override coerces a named dep to a
   URL provenance before resolution; it is subject to the same identity
   gate. If its content_hash **matches** an existing node, it is a second
   provenance under that identity. If it **differs**, override semantics
   apply: the override *replaces* the node for that name and the prior
   provenance is discarded — there is no "two nodes, one name" state (the
   PubGrub solver keys on name; that state is unrepresentable).

**B-nimcfg (compile-correctness + view rebuild).** `nim.cfg` MUST emit a
`--path:` line for the canonical name **and every alias** (Nim imports
resolve by name, not by hash; without this `import <alias>` fails to
compile), each pointing at the same store entry. `_deps/<alias>` MUST be
a relative symlink to that entry. Every `milpa lock` / `fetch` run
**atomically rebuilds the full `_deps/` view**: compute the expected set
(canonical names + all aliases), remove any `_deps/` entry not in it
(stale aliases from a prior lock where the alias set differed), then
create the expected symlinks. This prevents orphaned alias symlinks from
silently satisfying `verify` for a name no longer declared.

**Estimated effort:** 8–12 days across the three slices (both impls +
~10–15 conformance fixtures: same-content-two-URLs dedup, alias nim.cfg
emission with two `--path:` lines, alias lockfile round-trip,
multi-provenance lockfile round-trip).

### Phase C — finish the global store surface (v0.x)

The store and symlink view exist (see reconciliation note). Remaining:

1. **`milpa clean` removes only the per-project `_deps/` views**, never
   store entries (store eviction is exclusively `store gc`'s job).
2. **`milpa store ls` / `milpa store path <identity>` (read-only — land
   now, NOT gated on GC).** Trivially safe and immediately useful for
   scripting/debugging; do not block them behind the GC design. `store ls`
   prints one `<identity>` per line; `store path <identity>` prints the
   absolute store path to stdout (machine-readable for `$()`), exit 1 if
   absent. `store path` accepts a **≥16-char prefix** and resolves it
   unambiguously, failing with `STORE-AMBIGUOUS-PREFIX` if more than one
   entry matches — so a hash copy-pasted from `milpa show` is directly
   usable.
3. **Unify `_stage/` → `_scratch/` (must precede D-fallback).**
   `CasAdmittingFetcher` stages under `<root>/_stage/` while `cas.py` and
   `spec/identity.md §3.4` define `<root>/_scratch/`. Route staging
   through `CAStore.scratch()` and delete `_stage/` entirely. D-fallback's
   explicit admission (Phase D item 3) depends on a single canonical
   scratch path.
4. **`write_lockfile` must be atomic — in BOTH impls.** Python
   (`path.write_text`) and Rust (`std::fs::write`) are both
   open-truncate-write; a crash mid-write corrupts the sole identity
   claim. Use temp-write + `rename()` (Python: the pattern already in
   `manifest_writer.py`; Rust: `tempfile::NamedTempFile::persist`), each
   handling `EXDEV`. Sequence **first** among C-slices — it protects the
   real fresco integration-test lockfile.
5. **`admit()` is idempotent (NORMATIVE).** If `sha256/<hex>/` already
   exists, `admit()` returns the existing path without error; the caller
   discards the now-redundant scratch tree (no orphan left for GC). State
   this in `spec/identity.md §3` so the D-fallback CAS-hit path is
   well-defined.
6. **Verification under symlinks — four distinct states.**
   `verify_lockfile_against_deps` (both impls currently use `.exists()`,
   which follows symlinks and so conflates them) MUST distinguish:
   (a) symlink present + store readable ⇒ pass;
   (b) **dangling** symlink (`is_symlink()` true, `exists()` false) ⇒
   store entry GC'd / store not mounted — distinct actionable error;
   (c) symlink present but store read raises I/O (network mount offline) ⇒
   `CAS-STORE-IO-ERROR`, distinct from corrupt;
   (d) no `_deps/<name>` at all ⇒ genuinely missing.
   Plus alias checks (B-nimcfg / spec §6.4).
7. **`milpa store gc` — store-level GC. Own design note / mini-RFC; does
   NOT ride with the rest of C and blocks nothing else.** Safe GC needs a
   liveness predicate and a concurrency protocol; round-2 review found the
   originally-sketched protocol under-defined on three points the design
   note MUST settle before any GC slice:
   - **Liveness / "watched-project set":** the earlier sketch said
     "referenced by any lockfile in a configured watched-project set" but
     never defined how a project registers or where the set lives. The
     note specifies the registration mechanism (e.g.
     `~/.cache/milpa/projects.kdl` or per-project sentinel files) and the
     lockfile-path → identity-set predicate.
   - **Admit/GC race (corrected):** the in-use sentinel MUST be placed
     **before `admit()`**, not before `link()`. The window
     `admit() rename → [GC enumerates] → link()` otherwise lets GC evict a
     just-admitted entry the caller is about to link. Order:
     `place sentinel(uuid) → admit() → link() → clear sentinel`. Eviction
     of a sentinel-guarded or live-symlink'd entry raises
     `STORE-GC-ENTRY-IN-USE`.
   - **`_scratch/` staleness:** GC may sweep orphaned `_scratch/` entries
     (SIGKILL leftovers) only past a minimum age `T` (max expected
     single-fetch duration; suggested 1h, mtime-gated) so it never races a
     live fetch. `spec/identity.md §3.4` references the note for `T`.

**Estimated effort:** 4–6 days for items 1–6 (both impls + fixtures);
`store gc` (item 7) sized separately after its design note.

### Phase D — multi-provenance semantics (v0.x, in-place v1)

The schema parses N provenance blocks (reconciliation note). Remaining is
*behavior* + the origin discriminator.

1. **`milpa add <dep> --mirror <url>`** (note arg order: positional dep,
   then `--mirror` flag — matches the existing `milpa add <dep> --git
   <url>` and `spec/cli-contract.md §5.6`) mutates **`milpa.kdl`** (a
   manifest mirrors entry), **not** the lockfile directly. The current
   `spec/cli-contract.md §5.6` wording that the command writes
   `milpa.lock` directly is **in conflict with this RFC and must be
   amended**: a lockfile-direct provenance append would write an
   unverified record. Multi-provenance lockfile records are a
   **consequence** of `milpa lock` (item 2), not a direct CLI write.
2. **Declared-provenance lifecycle (NORMATIVE).** `milpa lock` reads the
   `mirrors` declared in `milpa.kdl` (and any dep's self-declared mirrors)
   and writes each as a `provenance { … origin "declared" }` block in the
   lockfile **without verifying it** (verification is deferred to use). A
   `declared` record that is never exercised legitimately persists in the
   lockfile. On first successful, identity-verified fetch via that
   provenance, its record is rewritten in place with `origin "observed"`.
   This two-phase write is the mirror→lockfile data-flow the earlier draft
   left implicit.
3. **Provenance fallback (D-fallback) distinguishes two failure modes:**
   - *transport failure* (network error, git non-zero exit, dead mirror)
     ⇒ try the next provenance. Intended resilience. (Two-state origin is
     deliberate: a dead mirror is simply retried next run — milpa does
     **not** persist a `failed` state, because the lockfile is a build
     artifact, not a runtime retry log; a timestamped failure record would
     break byte-determinism for no real gain on short mirror lists.)
   - *fetch succeeds but the tree hashes ≠ the locked identity* ⇒ a
     **supply-chain signal**, surfaced loudly as `FETCH-PROVENANCE-DIVERGENCE`.
     MUST NOT be swallowed as "try next." This is Acceptance criterion 3.
   - **Implement the loop with `env.fetcher.fetch()` per provenance, not
     `fetch_any`** — `CasAdmittingFetcher.fetch()` admits the winner into
     the store automatically, whereas `fetch_any` delegates and leaves
     admission to the caller. (This is why C-stage must precede
     D-fallback: admission needs the single canonical scratch path.)
4. **`self_mirrors` (#79) unified into `provenance`** (Resolved Decision
   3). The separate field is removed from both impls' `LockedDep` and from
   `spec/lockfile-schema.md §2.4`/§3.7; a v1 lockfile still carrying
   `self_mirrors` is read-compat — the **parser converts each
   `self_mirrors` URL to a `declared` provenance on parse** (no format
   break; the parser already accepts N provenance blocks), and the emitter
   never writes `self_mirrors` again. The origin discriminator is a field
   **on the `provenance { }` block itself** (`origin "observed" |
   "declared"`), not a wrapper enum — Python adds it to each provenance
   dataclass, Rust to each `ProvenanceRecord` variant. **`observed` /
   `declared` is a per-lockfile annotation, never a CAS-entry property:**
   the store holds bytes only (single concern), so concurrent projects
   promoting the same identity never race on store metadata.
5. **`milpa update` / `remove` preserve accumulated provenance and handle
   aliases.** `update <dep>` today drops the dep and re-resolves, emitting
   only the single provenance it fetched this run — silently discarding
   the other mirrors a user added for resilience. It MUST carry forward
   the prior lockfile's provenance records for that dep (append newly
   discovered, drop only those whose URL left the manifest). If `<dep>` is
   an **alias**, both `update` and `remove` resolve it to its canonical
   (else `LOCK-DEP-NOT-FOUND` fires spuriously). `remove` of a canonical
   that still has aliases required by a transitive dep MUST warn per alias
   and not silently drop `_deps/<alias>`.
6. **Frozen reconstruction preserves all provenances and aliases.**
   `frozen.py` (and Rust `frozen.rs`) currently reconstruct with
   `provenances[0]`, dropping N−1, and are alias-unaware — so a round-trip
   through the frozen path loses mirrors and alias symlinks. `ResolvedDep`
   must carry the full `provenances` tuple and `aliases`; the frozen path
   recreates every `_deps/<alias>` symlink. Spec this in
   `spec/resolver-semantics.md` ("frozen reconstruction preserves all
   provenances and aliases").
7. **Verification checks identity only**, never which provenance delivered
   the bytes or the `origin` field. Two deps with the same identity are
   interchangeable regardless of provenance history. State this normatively
   so no future implementer adds provenance-checking to `verify`.

**Estimated effort:** 7–10 days (both impls + fixtures), including the
`self_mirrors`→provenance unification + origin discriminator across both
impls (Rust has a `self_mirrors` field + tests to migrate).

### Phase E — verifiable claims (v2+)

1. Optional sigstore-style signatures over identity claims.
2. Lockfile verifies a *signed* identity claim, not just a content match.
3. SLSA-level attestation integration.

**Estimated effort:** open-ended. Research territory. Out of scope for
this pass.

## Open design questions

### 1. What exactly is "content"?

Source-tree content is mostly obvious (regular files + their bytes +
relative paths). The non-obvious cases:

- **File modes — RESOLVED: excluded from identity** (round-1 review;
  see Resolved Decision 1). Phase A shipped the exec bit read from the
  filesystem (`stat.S_IXUSR`, `spec/identity.md §1.7`), but on Windows /
  `core.filemode=false` no file carries it, so the same tree fetched on
  Windows vs Linux hashed differently — breaking transport-independence.
  The hash now covers `(relpath, content-bytes)` only; the exec bit (and
  all other mode bits) are non-identity metadata. Spec §1.7 + the mode
  marker are amended out.
- **Symlinks** — hash the link target string as if it were file content;
  treat the symlink itself as a "file" with mode `0777`.
- **Empty directories** — exclude. Counterargument: some build systems
  depend on directory presence. milpa is targeting Nim, where this
  doesn't matter. Revisit if it ever does.
- **Line endings (CRLF vs LF)** — hash bytes-as-they-are; the
  responsibility is on the source repo to be consistent. We do not
  normalize. (Cargo does normalize; this is a real trade-off.)
- **Vendored binaries** — included by default. A package that vendors a
  shared library counts those bytes as content. Same as everything else.

### 2. Hash algorithm agility

We hardcode sha256 today. When sha256 itself is weakened (decades from
now, hopefully), the lockfile needs a migration path:

- Use a multihash-style encoding: `<algorithm>:<hex>`. Today's
  `sha256:abc...` becomes future-proof against new algorithms.
- Lockfile schema version gates which algorithms are accepted.
- When migrating, recompute identities under the new algorithm during
  one transitional run; lockfile records both during transition.

This is a known pattern (IPFS multihash, OCI image manifests). Adopt it
as an additive v1 amendment alongside Phase B — the existing
`sha256:<hex>` encoding is already multihash-style; a future algorithm is
a new accepted prefix, not a schema-version bump (Resolved Decision 4).

### 3. Identity for packages with build outputs

Some Nim packages generate source code at build time (macro-driven, or
`task` blocks in nimble that produce files). Do those generated files
count as content?

Two positions:
- **Pure source identity**: only checked-in files are hashed. Generated
  files re-derive at build.
- **Build-output identity**: hash the post-build tree. Catches build
  determinism issues but couples identity to the toolchain.

milpa's position: **pure source identity.** Reproducibility of the
build is a separate concern (Nix solves it by hashing the toolchain
too; that's a bigger commitment than milpa wants today).

### 4. Tooling that wants commit_sha as primary key

Some workflows want "lock to a specific git commit" semantics (e.g.
audit logs that reference upstream commit SHAs). They get it: the
provenance records *include* the commit_sha. The identity claim is
about bytes; the provenance claim is about commits. Both are addressable.

What changes: tooling that wants "the identity of this dep" must read
the identity field, not the commit_sha. A linter could enforce this.

### 5. Cross-SCM identity

If chronos is also available via mercurial, fossil, or as a tarball,
the identity is the same as long as the source tree is. milpa's
current fetcher is git-only, but the identity model doesn't depend on
git. Adding a `kind "tarball"` or `kind "hg"` provenance is a
straightforward extension.

This is the cleanest forward-compat win: when one mainstream Nim
package moves to a non-git SCM (or pure tarball distribution), milpa
absorbs the change without lockfile breakage.

### 6. Dependency-level vs file-level identity

Could we hash *individual files* and identify the dep as a list of
file-identities (Merkle tree)? That's the Nix store / git tree model.
Benefits:
- Sub-package dedup (two packages sharing a file).
- Incremental rebuilds when only some files change.

Costs:
- Lockfile is larger (tree of hashes vs single hash).
- More complex storage / fetch semantics.

For v0.x: single hash per package. The Merkle-tree extension is
worth filing as a research direction (this RFC's Phase E or beyond).

## Spec amendments this RFC requires

Because milpa is multi-impl (Python + Rust + shared corpus), every
behavior below lands as a **normative spec change first**, then both
impls, then conformance fixtures — never impl-only.

- `spec/lockfile-schema.md`:
  - Replace §4 "exactly one `provenance { }` block" with "**one or more**,
    in a canonical sorted order." **Define the sort key here** so output is
    byte-identical across impls (round-2: leaving it to the impl breaks
    zero-divergence). The key is the total order
    **`(origin, kind, primary-field, secondary-field)`** where `origin`:
    `declared` < `observed`; `kind`: `git` < `tarball` < `oci` < `local`
    (< any future kind appended); and `(primary, secondary)` is per-kind —
    git `(url, ref)`, tarball `(url, "")`, oci `(registry+repository,
    digest)`, local `(path, "")`. All comparisons are bytewise over the
    post-escape KDL string form.
  - Add the **`origin` field** (`"observed"` | `"declared"`) on the
    provenance block (Resolved Decision 3, absorbing `self_mirrors` #79);
    **remove `self_mirrors`** from §2.4 and §3.7 with the parse-time
    read-compat conversion (declared provenance) specified in Phase D
    item 4.
  - Add the **`aliases`** dep-block field (B-schema): zero+ names,
    lexicographic, omitted when empty.
  - Add **§6.4 alias verification**: for each alias `a`, `verify` checks
    `_deps/<a>` is a symlink to the same store entry as the canonical;
    alias symlinks are not reported as "extra"; a missing/dangling alias
    symlink is `VERIFY-ALIAS-SYMLINK-MISSING`, distinct from a missing
    canonical.
- `spec/identity.md`:
  - **Remove the exec-bit / mode marker** from the hash (§1.2 `0x01` row +
    §1.7 NORMATIVE clause; Resolved Decision 1) — hash `(relpath, content)`
    only (A-exec-removal slice).
  - Add the **git transport-normalization** clause (`-c core.autocrlf=false
    -c core.filemode=false`) so checkout config can't perturb identity.
  - Add the **symlink-target no-normalization** clarification.
  - Name the staging directory canonically (`_scratch/`, Phase C item 3),
    state **`admit()` idempotency** (Phase C item 5), and reference the GC
    design note for the liveness / sentinel / `T` protocol (Phase C item 7).
- `spec/cli-contract.md`:
  - Add the `milpa store` surface: `store ls`, `store path <identity>`
    (read-only, land with Phase C), and `store gc` (after its design note).
  - **Amend §5.6** so `milpa add <dep> --mirror <url>` writes only
    `milpa.kdl` (not `milpa.lock`); fix the arg order in prose.
  - Specify `milpa update` / `remove` provenance-preservation + alias
    handling (Phase D item 5).
  - Extend `milpa show` (below).
- `spec/resolver-semantics.md` — frozen reconstruction preserves all
  provenances and aliases (Phase D item 6).
- `spec/errors.md` — add the new codes below (semantic-kebab, bijection
  lint per [[error_catalog_discipline]]).

### New error codes

| code | trigger |
|---|---|
| `FETCH-PROVENANCE-DIVERGENCE` | a fallback provenance fetches successfully but its tree hashes to ≠ the locked identity (supply-chain signal) |
| `ID-NON-UTF8-RELPATH` | a file path under the tree is not valid UTF-8 (today raises an uncoded Unicode error in `compute_content_hash`; distinct from the existing `ID-NON-UTF8-SYMLINK-TARGET`) |
| `CAS-ENTRY-CORRUPT` | an already-admitted store entry no longer hashes to its claimed identity (detected at `link`/`frozen`) |
| `CAS-STORE-IO-ERROR` | a `_deps/<name>` symlink resolves but reading the store entry raises I/O (e.g. network mount offline) — distinct from corrupt and from dangling |
| `STORE-GC-ENTRY-IN-USE` | GC attempts to evict an entry guarded by an in-use sentinel or a live `_deps/` symlink |
| `STORE-AMBIGUOUS-PREFIX` | `milpa store path <prefix>` matches more than one store entry |
| `CAS-ADMIT-IO-ERROR` | `admit()` rename fails for a reason other than "destination exists" (disk full, permissions, EXDEV) — today re-raised uncoded |
| `VERIFY-ALIAS-SYMLINK-MISSING` | an alias `_deps/<alias>` symlink is absent or points to a different store entry than its canonical |

### SSOT cleanup (Phase B slice)

`lockfile.py:_parse_identity_for_lockfile` reimplements the five ordered
checks in `identity.py:parse_identity`. They will drift when a new
algorithm joins `SUPPORTED_ALGORITHMS`. Delete the duplicate; delegate
to `parse_identity`, catching `ID-*` and re-raising as
`LOCK-DEP-IDENTITY-INVALID`. (Per [[feedback_audit_for_duplication]].)
**Python-only — Rust already delegates** (`lockfile.rs` calls
`parse_identity` directly); lands with the B-schema slice.

## Conformance fixture plan

Each acceptance criterion maps to a corpus fixture (impl-neutral),
landing alongside the slice that satisfies it:

- *same content, two URLs ⇒ one node, two provenances* (Phase B) —
  two mocked URLs with byte-identical `content/` trees; expected
  lockfile shows one dep, two provenance blocks; expected `nim.cfg`
  shows `--path:` for canonical **and** alias.
- *force-push, tree unchanged ⇒ lockfile still valid* (identity
  invariant) — same tree, different commit_sha; `verify` passes.
- *force-push, tree changed ⇒ loud, dep-named failure* — `verify`
  fails naming the dep.
- *cross-project store hit ⇒ no re-clone* (Phase C) — two project
  fixtures sharing a `MILPA_CACHE_DIR`; second resolve hits the store.
- *dangling symlink ⇒ distinct error* (Phase C item 5).
- *provenance divergence ⇒ `FETCH-PROVENANCE-DIVERGENCE`* (Phase D).

Test isolation: C-series fixtures MUST set `MILPA_CACHE_DIR` to a
tmp path (the seam exists in `cas.py`; confirm the Rust runner honors
it) so tests never touch `~/.cache/milpa`.

## Observability (`milpa show`)

Dedup and multi-provenance are invisible today. Phase B/D extend
`milpa show`:

- list **all** provenance blocks for a dep, marking the one used in the
  last fetch;
- surface aliases (which declared names collapsed into this identity);
- keep a readable **default truncation (12 hex chars)** for human
  scanning, and add **`milpa show -v` / `--verbose`** that emits the full
  `sha256:<64hex>` identity (round-2: widening to a fixed 16 is the wrong
  axis — a truncated hash is never round-trippable to `store path`, but a
  `-v` full hash is, and stays correct under a future longer algorithm).
  The full hash always stays in the lockfile.

## Round-1 review: resolved decisions

Four items surfaced that reverse a shipped or written decision. None is
an opinion fork — each is goal-determined once the identity model and
milpa's non-negotiables are held fixed. Resolved here, with the defense:

1. **Exec bit is EXCLUDED from identity.** Identity is *"what are these
   bytes?"*, recomputable from the bytes alone. A filesystem exec bit is
   not part of the bytes — it is metadata that varies by platform and
   git config, and *no* source of it is transport-independent (a
   tarball carries it in archive metadata, git in tree mode `100755`, a
   Windows checkout not at all). Including it from any source breaks
   transport-independence, the core promise. It is also not semantically
   "what Nim code is this": milpa is a dep resolver and never executes
   dep scripts (tasks are deferred to the v2 toolchain RFC). The hash
   covers `(relpath, content-bytes)` only. **Reverses shipped Phase A**
   (`spec/identity.md §1.7` and the `0x01` mode marker in §73) — amend
   the spec and recompute. The exec bit, if ever needed (v2 tasks),
   rides as declarative metadata, not identity.

2. **Link mechanism is a relative symlink.** Not a trade-off: hardlinks
   cannot cross filesystems (the store and a project routinely sit on
   different mounts) and directory hardlinks are not POSIX-portable.
   `CasAdmittingFetcher` already does this correctly. Ratified.

3. **`self_mirrors` (#79) is unified INTO provenance.** Two fields both
   meaning "other places to get this dep" is the duplication SSOT
   forbids ([[feedback_audit_for_duplication]]). The model is **one**
   provenance list whose records carry an origin discriminator:
   `observed` (milpa fetched and verified these bytes hash to the
   identity) vs `declared` (an author-claimed mirror from the dep's
   `milpa.kdl`, unverified until first use). A `self_mirror` is a
   `declared` provenance; D3 fallback verifies it on use (divergence ⇒
   `FETCH-PROVENANCE-DIVERGENCE`). One list, one fallback loop, one
   concept. **Reverses #79's separate field**; the lockfile invariant
   "every `observed` provenance delivers this identity" is preserved by
   the discriminator. (Spec: add the origin discriminator to the
   provenance record in `spec/lockfile-schema.md`.)

4. **Schema evolves in place at v1 — no `v2` bump.** A version epoch
   exists to *reject old readers* on a breaking change. This change is
   additive: old readers already parse N `provenance { }` blocks at v1.
   With zero external lockfile consumers ([[spec_versioning_deferred]]),
   manufacturing a v2 epoch + migration machinery + a `spec-v2/` corpus
   is ceremony, not rigor. **Reverses this RFC's earlier "versioned
   bump" language.** (`conformance-fixtures.md §1.3`'s format-break →
   `spec-v2/` rule is not triggered because there is no format break —
   the additions are backward-compatible v1.) The `version` epoch gets
   stamped at stabilization, not before.

## What this RFC commits milpa to

- **Identity is content_hash.** Commit SHA / URL / ref are provenance.
- **The lockfile schema evolves in place at v1** (Resolved Decision 4)
  through Phase B (dedup + aliases), Phase C (global store), Phase D
  (multi-provenance + origin discriminator); the additions are
  backward-compatible — no version bump.
- **The hash algorithm** is sha256 today, multihash-encoded
  (`sha256:<hex>`) for forward-compat.
- **Provenance is multi-valued in the schema today** (the parser/emitter
  already handle N blocks); Phase D completes the *behavior* — the
  resolver writes multiple provenances when dedup produces them, and the
  origin discriminator records observed-vs-declared.

## What this RFC does *not* commit milpa to

- A specific GC strategy for the global store.
- A specific signature / attestation scheme.
- Cross-SCM support beyond git in v0.x.
- File-level Merkle trees.
- Build-output identity.

Those are tractable extensions but each is its own design problem;
they get their own RFCs when they're picked up.

## Acceptance: how do we know this landed correctly?

The model is right when:

1. The same content fetched via two URLs appears once in the graph.
2. A force-push to a branch that doesn't change the tree (e.g., a
   rebase to fix commit messages) does *not* invalidate any lockfile.
3. A force-push that *does* change content invalidates the lockfile
   loudly, naming the dep.
4. Fetching the same content twice (across projects on one machine)
   hits the global store and does not re-clone.
5. The lockfile can be verified offline from the source-tree **bytes**
   (no git needed) — either via `_deps/<name>` symlinks when the store
   is present, or by re-hashing store entries directly. Note Phase C
   makes `_deps/` a *view*: a missing store yields dangling symlinks, so
   "offline" means "bytes on disk reachable," not "`_deps/` populated
   independent of the store." `milpa verify` distinguishes the four states
   in Phase C item 6 (pass / dangling / store-I/O-error / genuinely
   missing), so a GC'd entry, an offline network mount, and a never-fetched
   dep are not conflated.
6. Adding a mirror is a no-content-change operation that just appends
   provenance.

Each of those is a testable invariant.

## Issues this RFC will spawn

To be filed as GitHub issues, each implementing one slice of the
above:

- **Identity vs provenance documentation cleanup** (Phase A — done)
- **`milpa verify` CLI command** (Phase A — done)
- **A-exec-removal: remove exec bit from identity** (Phase A corrective —
  Resolved Decision 1; *not* the reverse)
- **B-schema: `aliases` lockfile field + SSOT delegate** (Phase B)
- **B-resolver: dedup by content_hash, BFS-canonical** (Phase B)
- **B-nimcfg: `--path:` per alias + `_deps/<alias>` symlink + atomic view
  rebuild** (Phase B)
- **C: `clean` views-only, `store ls`/`path`, `_scratch` unify, atomic
  write_lockfile, four-state verify** (Phase C)
- **`milpa store gc` command** (Phase C — own design note)
- **D-add: `milpa add <dep> --mirror`, declared lifecycle** (Phase D)
- **D-fallback: provenance fallback + `FETCH-PROVENANCE-DIVERGENCE`** (Phase D)
- **D-provenance: `self_mirrors`→provenance unification + origin
  discriminator + frozen/update/remove preservation** (Phase D)
- **Sigstore / SLSA attestation over identity** (Phase E — research)
- **File-level Merkle tree identity** (Phase F — research)

See backlog issues filed alongside this RFC for tracking.
