# Identity and Provenance — milpa's data model

milpa records two distinct kinds of information about every dependency:

- **Identity**: *what are these bytes?* — sha256 of the source tree.
  Immutable. Trust-independent. Given the bytes, anyone can recompute
  and verify.

- **Provenance**: *how do I get these bytes?* — a pointer into
  infrastructure (URL, git ref, commit SHA, registry name + tag).
  Mutable. Trust-dependent (the git server may lie, the mirror may be
  stale, the ref may be force-pushed).

This page explains how the model works in milpa and why the distinction
matters. For the structural argument, see
[`rfc-content-addressed-identity.md`](rfc-content-addressed-identity.md).

## The question every resolver answers

> "Are these two things the same dependency?"

Resolvers need an answer to deduplicate, to detect conflicts, to
reproduce lockfile state, to cache fetched packages. Existing tools
(nimble, atlas, cargo-for-git) answer it with a tuple like
`(URL, commit SHA)` — fusing two distinct concepts. milpa answers it
with **the content hash**, treating URL and SHA as descriptive
metadata.

## What changes vs what doesn't

The orthogonality of identity and provenance is easiest to see in
common scenarios:

| Scenario | identity changes? | provenance changes? |
|---|---|---|
| Force-push to a branch | yes | yes (commit SHA flips) |
| Rebase that preserves the tree | **no** | yes (commit SHA changes) |
| Mirror the same commit to a new URL | **no** | yes (URL changes) |
| Upstream republishes identical content via tarball | **no** | yes (transport changes) |
| Edit one byte in a source file | yes | yes (new commit) |

A resolver that treats provenance as identity sees four of these as
different packages when they aren't. A resolver that treats identity
as provenance can't refresh a mirror without losing its pinned bytes.
milpa records both and answers the right question with the right one.

## How milpa uses each

### Lockfile (`milpa.lock`)

Each dep records both:

```kdl
dep "chronos" {
    source "https://github.com/coreyleavitt/chronos.git"   // provenance
    ref "feat/contextvars"                                  // provenance
    sha "90660858a9da783c6edf14c269d5b6165e7f6bb2"          // provenance receipt
    content_hash "sha256:e69bd0696a3ac88..."                // IDENTITY
    version "0.0.1"
    src_dir ""
    requires "results" "stew" ...
}
```

The `content_hash` line is the identity claim. Everything else is
descriptive — useful for reproducing the fetch, but not load-bearing
for "is this the right dep."

### Verification

`milpa verify` (Phase A — issue [#31](https://github.com/coreyleavitt/milpa/issues/31))
walks every dep in `_deps/`, recomputes its content_hash, and compares
to the lockfile. A mismatch means the bytes on disk diverged from
what was locked — even if the git SHA still matches, the content
has drifted (someone hand-edited a file, a force-push mutated the
ref, an attacker swapped bytes mid-flight).

### `milpa show`

The output explicitly labels both lanes:

```
chronos              0.0.1
  identity    sha256:e69bd069
  provenance  https://github.com/coreyleavitt/chronos.git @ feat/contextvars (sha 90660858)
  requires    results, stew, bearssl, httputils, unittest2
```

Truncated to 8 chars for readability; the full values are in `milpa.lock`.

### Resolution

For URL deps: milpa fetches via provenance (clone the URL at the ref),
then computes identity (hash the resulting tree). The lockfile records
both.

For registry-resolved deps: milpa picks a tag (per the resolution
strategy — see [`#49`](https://github.com/coreyleavitt/milpa/issues/49)),
fetches at that tag, then computes identity. The provenance is
`registry:<name>` plus the resolved tag and commit SHA.

For URL dedup (Phase B — issue [#32](https://github.com/coreyleavitt/milpa/issues/32)):
two URL+ref pairs that produce the same content_hash will be unified
into one resolved dep. Identity-keyed dedup, not URL-keyed.

## Why content hashing matters even when commit SHA seems enough

For the immediate "verify what I cloned" use case, commit SHA is
sufficient — git's tree-hash chain means `git checkout <sha>` is
deterministic over the working tree.

Content addressing wins on cases commit SHA misses:

1. **Cross-fork dedup.** Two mirrors of identical bytes have different
   commit SHAs (different metadata) but the same content hash.
   Content-addressing unifies them; SHA-keying doesn't.

2. **Substitutable provenance.** When a URL goes down, milpa can use
   any other provenance pointing at the same identity. The lockfile
   doesn't break because identity is provenance-independent.

3. **Trust-independent verification.** Verify the bytes without
   contacting any provenance source — a tarball on a USB stick, an
   IPFS CID, an offline backup. The identity claim stands.

4. **Cross-SCM identity.** When the future Nim package ecosystem moves
   some packages to non-git delivery (tarballs, IPFS — see
   [`rfc-pluggable-fetchers.md`](rfc-pluggable-fetchers.md)), identity
   doesn't need to migrate.

5. **Build-artifact caching.** A future milpa global content store
   (Phase C — issue [#35](https://github.com/coreyleavitt/milpa/issues/35))
   keys by identity, sharing fetched packages across projects safely.

6. **Supply-chain attestation.** A signature over an identity claim is
   transferable; a signature over `(URL, SHA)` is bound to one
   provenance and breaks when the package moves.

## What identity is not

- **It's not the git commit SHA.** Git's commit hash includes
  timestamps, author info, parent commits, and other metadata. Two
  identical source trees from different rebases have different commit
  SHAs but the same content hash. Identity is about the *bytes you
  build with*, not the *commit you fetched from*.

- **It's not a sufficient install instruction.** Identity tells you
  what bytes you have; provenance tells you where to get them.
  Bootstrapping a new checkout needs provenance (a clone target);
  verifying it needs identity.

- **It's not currently the resolver's dedup key.** As of v0.x, the
  resolver dedups by `(URL, ref)` for performance. Identity-keyed
  dedup is Phase B work ([#32](https://github.com/coreyleavitt/milpa/issues/32)).
  The data is recorded today; the dedup logic that uses it is the
  next phase.

## Org renames and registry identity (tianguis #36)

The tianguis registry derives a package's identity — `(namespace, name)` where
`namespace` is `host/org` — from each version's provenance anchor (git `provenance.url`
for vendored packages; OIDC `signed_by` SAN for author-signed packages). This derivation
runs once per version at ingest and is then immutable.

A consequence: when an author renames their GitHub org (or transfers a repo to a
different org), a new version's anchor now derives a *different* `host/org`. The
registry creates a **new `(namespace, name)` entry** for that new namespace. The old
entry is not updated or removed — it goes **stale**: it retains all historical versions
and remains valid for any lockfile that already references it, but new versions from the
renamed/transferred repo will not appear under it.

This is the correct behavior for a no-curation, attestation-anchored registry: identity
follows the attested publisher, not social continuity. The practical consequence is that
a consumer who upgrades to a version published from the new org needs to update their
`milpa.kdl` reference to the new qualified identity.

Automatic cross-identity continuity after a rename (an alias or supersede mechanism) is
deferred to **tianguis #36**. Until that lands, renames produce two distinct entries —
an accepted, documented property of the model, not silent corruption.

## See also

- [`rfc-content-addressed-identity.md`](rfc-content-addressed-identity.md) — the structural argument
- [`rfc-pluggable-fetchers.md`](rfc-pluggable-fetchers.md) — how the identity model survives cross-SCM transport
- [`rfc-toolchain-content-addressing.md`](rfc-toolchain-content-addressing.md) — extending identity to the compiler itself
