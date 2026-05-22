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

2. **A global content-addressed store**, default `~/.cache/milpa/store/`.
   Layout: `store/sha256/ab/cd/abcd...full-hash/`. Fetched packages
   land here once across all projects, hardlinked or symlinked into
   each project's `_deps/`.

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

This is an open design question (see below) but the v0.x proposal:

- Walk the cloned tree, exclude `.git/`, sort files by POSIX relpath.
- For each regular file: hash `(relpath, file_mode_canonical, contents)`.
- Concatenate per-file hashes in sorted order, hash the result.

Specifically:
- **Include**: regular file contents, relative paths, executable bit.
- **Exclude**: `.git/` (provenance, not content), filesystem-specific
  metadata (mtime, owner, uid/gid), symlink targets *outside* the tree.
- **Symlinks within the tree**: hash the link target string as content.
- **Empty directories**: not hashed (they have no contents). Acceptable;
  Nim packages don't depend on empty-directory presence.

This is more rigorous than what milpa does today (which only hashes
`(relpath, content)` and doesn't preserve the executable bit). The
refinement is necessary for `chmod +x foo.sh` to count as a content
change.

## Migration plan

### Phase A — clean up the data model (v0.x, near term)

1. Document that content_hash is identity, commit_sha is provenance.
   No code changes; just write the spec.
2. Refine the hash algorithm to include the executable bit.
3. Add a `milpa verify` CLI command that recomputes content_hash for
   every dep in `_deps/` and diffs against the lockfile. Today this is
   only available programmatically via `verify_against_graph`.

**Estimated effort:** 1-2 days. No breaking changes.

### Phase B — dedup by identity in the resolver (v0.x)

1. After fetching, compute content_hash. If two distinct (URL, ref)
   keys produce the same hash, unify them into one graph node.
2. The chosen "canonical name" for the unified node is the first
   manifest-declared name; subsequent references are aliases.
3. Lockfile records the identity once with all provenances.

**Estimated effort:** 3-5 days. Touches resolver internals, lockfile
format (additive — old lockfiles still parse), and the integration
test.

### Phase C — global content-addressed store (v0.x)

1. Add a global store at `~/.cache/milpa/store/sha256/...`.
2. After fetch, move the tree into the global store keyed by
   content_hash, replace `_deps/<name>/` with a hard link or a symlink.
3. Per-project `_deps/<name>` becomes a view into the global store.
4. `milpa clean` removes the symlinks; a separate `milpa store gc`
   command does store-level garbage collection.

**Estimated effort:** 5-7 days. New persistent state to manage;
permissions to think about; symlink-vs-hardlink trade-offs per OS.

### Phase D — multi-provenance lockfile (v1)

1. Lockfile grows `provenance { ... }` blocks; one or more per dep.
2. `milpa add` can append a new provenance to an existing dep without
   changing identity.
3. Resolver can try alternate provenances when one fails (transient
   network errors, dead mirrors).

**Estimated effort:** 4-6 days. Lockfile schema bump (v1 → v2). Need
to think about backward compatibility cleanly.

### Phase E — verifiable claims (v2+)

1. Optional sigstore-style signatures over identity claims.
2. Lockfile verifies a *signed* identity claim, not just a content
   match.
3. SLSA-level attestation integration.

**Estimated effort:** open-ended. Research territory.

## Open design questions

### 1. What exactly is "content"?

Source-tree content is mostly obvious (regular files + their bytes +
relative paths). The non-obvious cases:

- **File modes** — executable bit matters (run-script files), the rest
  (suid, sticky) shouldn't. We canonicalize to `0644` or `0755`.
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
explicitly in the Phase B lockfile schema bump.

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

## What this RFC commits milpa to

- **Identity is content_hash.** Commit SHA / URL / ref are provenance.
- **The lockfile schema will evolve** through Phase B (dedup),
  Phase C (global store), Phase D (multi-provenance), each as a versioned
  bump.
- **The hash algorithm** is sha256 today, multihash-encoded for
  forward-compat.
- **Provenance is multi-valued** — Phase D introduces this; before then
  each dep has exactly one provenance, recorded directly.

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
5. The lockfile can be verified offline from the source tree alone (no
   git needed).
6. Adding a mirror is a no-content-change operation that just appends
   provenance.

Each of those is a testable invariant.

## Issues this RFC will spawn

To be filed as GitHub issues, each implementing one slice of the
above:

- **Identity vs provenance documentation cleanup** (Phase A)
- **Refine content_hash to include executable bit** (Phase A)
- **`milpa verify` CLI command** (Phase A)
- **Dedup by content_hash in resolver** (Phase B)
- **Lockfile schema v2: explicit identity + provenance blocks** (Phase B+D)
- **Multihash encoding for identity** (Phase B)
- **Global content-addressed store at `~/.cache/milpa/`** (Phase C)
- **`milpa store gc` command** (Phase C)
- **Multi-provenance support + `milpa add` provenance append** (Phase D)
- **Sigstore / SLSA attestation over identity** (Phase E — research)
- **File-level Merkle tree identity** (Phase F — research)

See backlog issues filed alongside this RFC for tracking.
