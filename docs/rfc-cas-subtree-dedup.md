# RFC: CAS subtree dedup — a Merkle object store (B-split)

**Status:** **Deferred by design.** Split out of `rfc-identity-conformance-authority.md`
§4 ("B-split — subtree dedup in the CAS"). Epoch-2 canonical Merkle-DAG **identity**
shipped; the **storage** payoff is intentionally *not* built now. This RFC records
*why it's deferred*, the *trigger condition* that would justify building it, and a
ready design (§A) for that day.

**Tracking:** #181 (spawned from #180). Gated on a real subtree-sharing consumer —
the v2 toolchain build-closure (`rfc-toolchain-content-addressing.md`). GC
interaction: `rfc-store-gc.md` (#141).

**Depends on:** epoch-2 identity (`spec/identity.md §1.8`). B-split changes only
*where bytes live on disk* — **no identity changes, no hash changes**. That
orthogonality is exactly why it can wait without holding anything back.

---

## 1. Thesis: don't build this yet

> The Merkle object store is **infrastructure for large-scale subtree sharing**,
> not a source-dep feature. Whole-dep cross-project dedup already ships; subtree
> dedup for source deps is marginal and high-blast-radius. Build the object store
> when a consumer actually needs subtree sharing — the **v2 toolchain
> build-closure** — and let source-dep dedup fall out for free.

This is a judgment call, not a TODO. The mechanics in §A are sound and ready; the
point of this document is that **shipping them now would be a speculative rewrite
of the CAS core for a rounding-error benefit**, which milpa's own discipline
forbids (`feedback_minimal_over_completeness`: don't speculatively rewrite cores;
grow on ≥2 proven needs).

---

## 2. Why deferred — the evidence

**2.1 The valuable dedup already ships.** `cas.py` *is* the global
content-addressed store (`rfc-content-addressed-identity.md`: "the global store +
symlink view"; `comparison-vs-nimble-atlas.md` lists "Global content-addressed
store — cross-project dedup" as a **shipped** differentiator). Two projects
depending on the same dep already share **one** CAS entry; `_deps/<name>` is a free
relative symlink into it. So **whole-dep, cross-project dedup is done.**

**2.2 B-split adds only *subtree* dedup, which is marginal for source deps.** On
top of whole-dep dedup, an object store additionally shares:
- two *different* deps containing an identical subdirectory — **rare**;
- two *versions* of one dep sharing unchanged files — **real, but bounded**:
  milpa pins one version per dep per project, so two versions coexist only across
  projects or transiently during updates. Savings: a few MB, not a category change.

**2.3 milpa already filed this as research.** `rfc-content-addressed-identity.md`
lists "Sub-package dedup (two packages sharing a file)" under "research direction —
Phase E or beyond." Promoting a Phase-E research item to a build-now CAS rewrite is
the inversion this RFC corrects.

**2.4 The blast radius is the whole CAS core.** §A rewrites `cas.py` + Rust
`store.rs` + the fetch→admit→link seam used by **every** fetch and the entire
conformance corpus (a B-cutover-scale regen). High cost, marginal proven benefit,
no consumer demanding it → defer.

**2.5 The "hydration tradeoff" is the design objecting.** Today `_deps/<name>` is a
*free symlink* into a contiguous whole-tree entry. An object store has no
contiguous tree to point at, so it must **hydrate** a real tree (reflink/hardlink/
copy) for the Nim compiler. Trading a zero-cost working tree for a deduplicated
*store* only nets positive when subtree sharing is large — which, for source deps,
it isn't (2.2). The friction is the model telling us the object store belongs under
a different consumer.

---

## 3. The trigger condition — when to build it

Build §A when **either** holds:

1. **The v2 toolchain build-closure lands** (`rfc-toolchain-content-addressing.md`):
   the build closure grows to include the Nim compiler + companion binaries +
   stdlib. Multiple pinned toolchain *versions* share **large** identical
   stdlib/lib subtrees (tens-to-hundreds of MB each, many files). Here subtree
   dedup saves real space *and* the object store enables sparse hydration (only the
   stdlib subtree a build touches). This is the natural, proven consumer; B-split
   should be designed **as part of** that RFC, scoped to the closure, with
   source-dep dedup as a free side-effect.
2. **≥2 concrete source-dep cases** surface where subtree sharing is large enough
   to matter (e.g. a widely-vendored common subtree across the registry, measured),
   independent of the toolchain.

Absent either, leave it deferred. The object store is not lost work — §A is the
spec-ready design to pick up on the trigger.

---

## 4. What we are NOT giving up by waiting

- **Identity correctness** — already shipped; B-split touches none of it.
- **Whole-dep dedup / global store** — already shipped (2.1).
- **Whole-dep transport efficiency** — `rfc-content-addressed-identity.md` Phase C
  (CAS hit-before-fetch) covers "don't refetch a dep already in the store" at dep
  granularity; object-level incremental fetch would only refine *partially-changed
  large* deps — again a toolchain-closure concern, not a source-dep one.

So deferral costs nothing today and keeps the CAS core simple until a real consumer
earns the complexity.

---

## Appendix A — design on ice (build on the §3 trigger)

> Preserved for the day the trigger fires. Not approved work. When picked up, this
> belongs **inside** the v2 toolchain RFC (or its own issue once §3.2 is met), with
> **D1 (hydration) as the load-bearing decision to settle first**.

### A.1 Object kinds & path grammar

Two object types, keyed by their §1.8 hashes (raw hex, no scheme prefix — matching
§1.8's raw child-digests):

```
<cas-root>/dag-sha256/blob/<64hex>     # H_blob = sha256(file-bytes | symlink-target)
<cas-root>/dag-sha256/tree/<64hex>     # H_tree = sha256(concat(canonical §1.8 entries))
```

Path grammar generalizes `<algo>/<hex>` → **`<algo>/<type>/<hex>`** (`type ∈
{blob,tree}`); the `<type>` segment domain-separates the two hash spaces on disk
(the mode byte already separates them inside the DAG). A blob object is the exact
bytes (no git-style `blob <len>\0` header — transport-neutral, §1.8). A tree object
is the canonical §1.8 tree-node byte stream — **the same encoding the identity
already hashes**, so the object store reuses the identity codec verbatim (no second
encoding, no drift surface). Child digests are stored raw; the parent's mode byte
says whether a child names a `blob/` or a `tree/`.

### A.2 Admission — per-object, bottom-up, idempotent

`admit_objects(dag)` replaces whole-tree `admit(src, identity)`: reuse
`compute_dag_identity`'s DAG; emit objects **deepest-first** (children before
parents → store always closed); per object, no-op if `<type>/<hex>` exists, else
stage in `_scratch/` and `rename(2)` into place (keeping the current atomicity +
TOCTOU race-fold guard, now per object). The root tree object's hex = the
identity's digest. Crash mid-admission leaves a closed prefix of orphans (GC-able),
never a dangling parent.

### A.3 Hydration — `_deps/<name>/` from objects (THE fork, D1)

The store has no contiguous tree to symlink, so `link()` → `hydrate(identity,
dest)`: walk the root tree, recreate dirs, place blobs by reflink → hardlink
(read-only, `chmod a-w`) → copy fallback (probe store-FS once). Symlink entries
(mode `0x80`) recreated from the blob's target string; exec bit (`0x01`) via chmod.

- **Option A** — `_deps/<name>` is a hydrated real tree (reflink/hardlink/copy).
- **Option B** — keep `_deps/<name>` a *symlink* to a store-side **view tree**
  (`<cas-root>/views/<root-hex>/`, hardlinked from objects), preserving the
  zero-cost symlink + container-rebind property at the cost of a view layer + its
  own GC.
- **Lean:** A + reflink/hardlink; spike B only if the `_deps`-symlink / `nim.cfg`
  relative-path + container-rebind invariant demands it.

### A.4 Resolution & the root-vs-subtree wrinkle

`path_for(identity)` returns the `tree/<root-hex>` object; materialization is
`hydrate()`. `contains(identity)` = closure present (cheap: root present ⇒ closure
present, by the bottom-up admission invariant — GC must preserve it). The object
store can't distinguish a root from an internal subtree, but `list_identities()` /
`milpa show` operate on **roots**: define roots = the union of lockfile `identity`
fields (**R1**, recommended — the lockfile is already the authority), not a store
scan; keep a `roots/` marker index (**R2**) only if a store-local root-set is
needed without a lockfile.

### A.5 Migration & GC

Read-through (`hydrate` accepts whole-tree *or* object closure) → re-admit on touch
→ a `store gc`/`store migrate` pass converts legacy whole-tree entries to objects
and prunes them plus the epoch-1 `sha256/` garbage. GC reachability = mark-and-sweep
from roots (R1) → tree objects → child trees + blobs; sweep unmarked. **`rfc-store-gc.md`
(#141) owns GC mechanics/locking/UX; this RFC owns only the reachability definition.**

### A.6 Verification

Deep mode: re-hash tree-object bytes to confirm `H_tree == <hex>` recursively — a
pure object-graph integrity check needing no working tree. Default stays the
materialized-tree verify.

### A.7 Slices (when triggered)

S1 spec object store → S2 object admission (both impls) → S3 hydration (settle D1)
→ S4 resolution/`show` over objects → {S5 migrate+GC with #141, S6 corpus regen +
dedup fixtures}. Same spec-first / cross-impl-byte-match shape as B-cutover.

### A.8 Open decisions (settle before S2, on trigger)

D1 hydration model (A vs B — load-bearing) · D2 root tracking (R1 lean) · D3
hardlink safety (`chmod a-w`, lean yes) · D4 migration trigger (lazy + `store gc`)
· D5 object-count blowup on huge flat deps (measure; possible whole-tree fast-path
or packing — itself a sign this belongs with the large-closure consumer).
