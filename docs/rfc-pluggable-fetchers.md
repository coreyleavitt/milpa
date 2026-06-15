# RFC: pluggable fetcher abstraction — diverse provenance kinds

**Status**: **Implemented (F1–F3 landed 2026-Q2); F4–F8 open.** Retained as
design rationale. For normative detail the source of truth is
`spec/plugin-contract.md` + `spec/manifest-grammar.md`, NOT this doc.
**Author**: Corey Leavitt
**Date**: 2026-05-22 (orig) · architect round 1 reconciliation 2026-06-15 · architect round 2 breadth/coverage 2026-06-15

## Implementation status (2026-06-15 — post-landing reconciliation)

F1 (git→`Fetcher` protocol), F2 (`TarballFetcher` + `SafeExtractor`), and F3
(`LocalFetcher`) are all **built in both impls** (`impls/python/milpa/fetchers/`,
`impls/rust/crates/milpa-core/src/fetchers.rs` + `safe_extract.rs`). The landed
design diverged from this RFC's sketch — in every case toward the better choice.
Corrections to the prose below (the doc is otherwise stale):

| RFC said | Reality (canonical) |
|---|---|
| registry dispatch is "first match wins" | **exclusive match**: `FetcherRegistry` collects all `can_handle` matches; >1 = registration error, 0 = no-handler error. Order is readability-only. (open-Q1 resolved) |
| module-level mutable `_REGISTRY` + `register()` | instance-owned `FetcherRegistry` built by `build_registry()`; no global state |
| `Fetcher.fetch(...) -> FetchResult` | `fetch(...) -> ProvenanceReceipt`; the **registry** computes identity and assembles `FetchResult` — a fetcher structurally cannot set `identity` |
| `Provenance` is a bare dataclass | carries `cas_admissible: ClassVar[bool]` (False for `LocalProvenance`); receipts are an ABC with `transport_fields()`, validated non-empty (`FETCH-RECEIPT-EMPTY`) |
| `strip_components` default = 1 | **default = 0** (both impls + spec). 1 would silently drop files from non-GitHub-style archives |
| manifest: "support both inline + explicit-`kind`-block" | **inline-only** (property-name dispatch). One unambiguous spelling per declarative-manifest minimalism. Phase-D mirrors use `mirror` child nodes, not a `kind` block |
| LocalFetcher "copy or symlink (flag)" | no flag; **the two impls diverge** — see Remaining Work below |
| `milpa verify` local drift "warns" | identity mismatch is a hard **divergence** (exit 1), same as any dep — no warn path exists |

**Open questions §1–§5 are all resolved** by the landed code/spec (exclusive
dispatch; `SafeExtractor` shipped; transport caching is black-box + CAS dedup;
`fetch_any` uses declaration order; milpa-identity-is-milpa-identity, transport
digests are receipts). They are retained below for history only.

### Remaining work (the actual F1–F3 finish line — see architect round 1)

These are real, mostly **un-fixtured** gaps the review surfaced. None are caught
by the conformance corpus today because the corpus exercises fetchers via mocks,
not real transport.

1. **[RESOLVED → symlink + no-identity] LocalFetcher semantics.** Decisions
   (2026-06-15):
   - **symlink is normative** (not copy). `local=` exists for live local
     development — edit-in-place with no re-fetch.
   - **local deps carry NO identity; `verify` checks liveness only.** A live tree
     has no immutable bytes ⇒ no `content_hash` (identity = hash-of-immutable-
     bytes is a category error for a live tree). The frozen path already rejects
     local deps (`FROZEN-LOCAL-DEP`), so local identity is not load-bearing for
     reproducibility, and a per-edit drift warning would be pure noise. `verify`
     dispatches on **provenance kind**: local → "symlink resolves to a directory"
     check, no hash compare. Want an immutable snapshot? Use `git=`/`tarball=`.
   Work: (a) `spec/manifest-grammar.md` §LocalDep "MUST copy" → "MUST symlink"
   (DONE round 2); (b) `spec/lockfile-schema.md` §4.3 — identity field **absent**
   for local provenance records; §6.2 — verify dispatches on kind, local =
   liveness-only; (c) Python lockfile writer + verify: stop recording/checking
   `content_hash` for local deps (behavior change); (d) align **Rust**
   `fetch_local` symlink (was copy) + same lockfile/verify changes; (e)
   conformance fixture: `_deps/<name>` is a symlink to source AND lockfile has no
   identity for it AND `verify` passes after the source tree is mutated. Identical
   both impls. **Sequence:** spec (b) → Python verify+lockfile (c) → Rust (d) →
   fixture (e).
2. **[RESOLVED → extend Rust] Tarball compression formats.** Decision
   (2026-06-15): **support gz/bz2/xz in both impls.** Python already does
   (`r:*`); add bz2 + xz decoders to **Rust** `fetch_tarball` (currently gzip-
   magic + raw-tar only). Work: (a) magic-byte detect bz2 (`42 5a 68`) and xz
   (`fd 37 7a 58 5a 00`); (b) wrap each in the same `.take(decomp_cap)` bomb
   guard as gzip; (c) note formats normatively in `spec/manifest-grammar.md`
   §TarballDep; (d) conformance fixtures: same tree as `.tar.gz`/`.tar.bz2`/
   `.tar.xz` ⇒ identical identity, both impls.
3. **[bug, shared — file issue] Hardlink extraction.** Both impls map hardlinks
   to symlinks with a parent-relative escape base and don't apply
   `strip_components` to the link target (`safe_extract.py:194`,
   `safe_extract.rs:108`). Identical in both ⇒ no byte-divergence, but a latent
   correctness bug for archives with hardlinks + strip. Either handle hardlinks
   properly or reject with `EXTRACT-HARDLINK-UNSUPPORTED`.
4. **[divergence — file issue] git commit reachability.** Python
   `_ensure_commit_present` has a 4-step fetch/unshallow fallback; Rust
   `commit_present` does a single `cat-file -e`. Diverges on shallow-clone pins
   where the commit isn't reachable from HEAD. Un-fixtured (needs a real-git
   fixture).
5. **[test gap] Cross-transport byte-identity fixture.** The RFC's headline
   invariant (#2: same tree via git vs tarball ⇒ same identity) has no fixture.
   Add one (two mocked candidates, same content, assert equal identity, both impls).
6. **[hygiene] minor:** sha256 compare not case-normalized (`tarball.py`,
   `fetchers.rs`); `CasAdmittingFetcher.fetch_any` duplicates the registry's
   candidate loop (SSOT — but note this was a deliberate split in the
   content-addressed review; revisit only if it drifts).

### Round 2 additions (architect round 2, 2026-06-15)

7. **[spec cascade — done] Spec docs updated for symlink + bz2/xz decisions.**
   The following spec docs were updated in architect round 2:
   - `spec/manifest-grammar.md` §LocalDep: "MUST copy" → "MUST symlink"
   - `spec/manifest-grammar.md` §TarballDep: normative compression formats table
     (gz/bz2/xz, magic-byte detection, bomb-guard requirement per format)
   - `spec/identity.md` §3.5: two-form symlink taxonomy (CAS vs editable)
   - `spec/lockfile-schema.md` §6.2: four-state verify taxonomy — "store entry"
     language replaced to include local dep symlinks (target = source dir, not
     CAS entry); `CAS-STORE-IO-ERROR` slug renamed in prose to "I/O error"
   - `spec/plugin-contract.md` §1.2 Materialize: two-form obligation (admissible
     = real dir; editable = symlink)
   - `spec/errors.md`: added `EXTRACT-HARDLINK-UNSUPPORTED`

8. **[spec gap] `spec/manifest-grammar.md` §4.3 `cas_admissible` table.**
   The `local` row still says "The fetcher MUST copy the source tree into
   `_deps/<name>/`" in the rationale column. Update to say "MUST symlink" to
   match §LocalDep fix. Also update `spec/manifest-grammar.md` §4.2 `local`
   provenance kind description: the NOTE currently says "Relative-to-project
   resolution … before constructing the provenance descriptor" but doesn't
   address the symlink materialization.

9. **[fixture gap] No `fetch` fixture for a local dep.** `fixture-082-frozen-local-dep`
   only exercises the *frozen* path (`frozen` command). There is no `fetch` fixture
   that asserts `_deps/<name>` is a symlink → source tree. Add:
   `fixture-NNN-fetch-local-dep`: cmd=`fetch`, asserts `_deps/locallib` is a
   symlink pointing to the mocked source path, identical both impls.
   Also: `fixture-082` only covers `FROZEN-LOCAL-DEP` (the frozen reject-case);
   it does NOT need updating because it never materializes `_deps/`.

10. **[fixture gap] Tarball multi-format byte-identity.** Round 1's item #2(d)
    asked for gz/bz2/xz fixtures. The fixture IDs are unassigned. Assign:
    `fixture-NNN-tarball-bz2-identity`: mocked `.tar.bz2`, same content, same
    identity as gz equivalent. `fixture-NNN-tarball-xz-identity`: same for xz.
    Both assert `expected/milpa.lock` `identity` field is identical across formats.
    The Rust magic-byte decoder (item #2a-b) must land before these fixtures can
    pass in Rust.

11. **[CLI gap] `milpa add` has no `--local` or `--tarball` subcommand.**
    Only `--git` and `--mirror` are implemented. `milpa add <dep> --local <path>`
    is a natural completion of the F3 work and the most common workspace setup
    operation. Similarly `milpa add <dep> --tarball <url> [--sha256 <hex>]`.
    File issues; defer to after Rust LocalFetcher symlink alignment.

12. **[CLI/spec gap] `milpa clean` and local dep symlinks — verified safe.**
    Python `cmd_clean` uses `_remove_if_exists → shutil.rmtree(_deps)` which
    only enters the tree when `_deps` itself is a directory (not when it is a
    symlink). Since `_deps/` is a real directory containing local-dep symlinks
    as children, `shutil.rmtree(_deps)` removes the directory and unlinks the
    symlinks (does NOT follow them to the source). Rust `remove_dir_all(_deps)`
    has the same platform semantics on Linux. **No spec text needed** — `clean`
    removes `_deps/` as a whole; spec §6.2 governs verify, not clean.
    HOWEVER: the spec should state that `milpa clean` MUST NOT follow symlinks
    into source trees or the CAS. Add a note to `spec/cli-contract.md` §clean.

13. **[spec/identity gap] `milpa verify` + local dep symlink target.**
    `spec/lockfile-schema.md §6.2` now correctly models the symlink-to-source
    form. But the Python `_classify_dep_path` code at `lockfile.py:1185` adds
    a comment "non-symlink directories/files fall through to state (a)" — this
    was written pre-symlink-decision and implies a plain dir is still OK. After
    the symlink decision, a plain dir at `_deps/<name>` for a local dep is a
    Rust-copy leftover. The spec §6.2 should say: a plain directory (non-symlink)
    at `_deps/<name>` is treated as state (d)-equivalent — missing the symlink
    form — so implementations SHOULD report it as "expected symlink, found
    directory" rather than silently hashing. File as a follow-up for after Rust
    alignment.

14. **[workspace #25 interaction.] `local=` is the mechanism for dev-linking**
    in the planned workspace feature (#25). The symlink decision makes the
    workspace model cleaner: a workspace member referenced as `local="../pkg"`
    would have `_deps/<name>` → source, which is the same as a cross-workspace
    dependency. The workspace RFC (#25) should explicitly reference this decision
    and note that workspace members accessed via `local=` deps already have the
    correct symlink structure.

15. **[F4–F8 inheritance.] Hardlink and compression norms apply to future fetchers.**
    HgFetcher (F4), FossilFetcher (F5), and OciFetcher (F6) all use tarballs
    internally (Hg can export tarballs; OCI artifact extraction is a tarball).
    The hardlink + bz2/xz decisions apply to any fetcher that internally
    decompresses a tarball. The `SafeExtractor` (`safe_extract.py`/`safe_extract.rs`)
    is already the shared primitive — no per-fetcher work needed, only the OCI
    fetcher's tarball extraction path MUST also gain bz2/xz support if it does
    not delegate to `fetch_tarball`.

## Why this RFC exists

milpa v0 supports exactly one delivery mechanism: `git clone` against
an HTTP/SSH URL. The content-addressed-identity RFC (`rfc-content-
addressed-identity.md`) commits milpa to identity-as-content-hash and
provenance-as-multi-valued — which naturally invites the question:
*what other provenance kinds should milpa support, and how?*

This RFC argues that the abstraction is **clean and generalizable**:
every transport is a separate `Fetcher` implementation, the resolver /
solver / lockfile / identity model don't care which fetcher was used,
and adding a new transport is bounded and self-contained.

It then surveys the transports worth supporting (tarball, mercurial,
fossil, local path, OCI registry, IPFS), specifies the abstraction's
shape, and phases the work.

## The abstraction

Every transport answers the same external question:

> Given a provenance descriptor, produce a local source tree (and a
> provenance receipt recording what was actually fetched).

The shape:

```python
@dataclass(frozen=True)
class Provenance:
    """Discriminated union over transport kinds. Each concrete
    provenance carries the fields its fetcher needs.
    """
    # See concrete subclasses below — GitProvenance, TarballProvenance,
    # HgProvenance, LocalProvenance, OciProvenance, IpfsProvenance.

@dataclass(frozen=True)
class FetchResult:
    name: str                    # consumer-facing dep name
    path: Path                   # where the tree was materialized
    identity: str                # sha256 of the tree (computed by milpa, not the fetcher)
    receipt: ProvenanceReceipt   # transport-specific record of what landed

class Fetcher(Protocol):
    """A transport-specific source-tree producer."""

    def can_handle(self, p: Provenance) -> bool:
        """Return True if this fetcher handles provenance kind `p`."""

    def fetch(self, name: str, p: Provenance, *, dest: Path) -> FetchResult:
        """Materialize the tree at `dest/`, return the result.
        Identity is computed by milpa post-fetch, not by the fetcher
        itself. Receipt is whatever the transport natively records
        (commit SHA, tarball checksum, OCI digest, etc.)."""
```

The key property: **identity is computed by milpa, uniformly, after
fetch.** Fetchers don't compute identity. They produce bytes; milpa
hashes them. This is the invariant that makes the abstraction work —
no fetcher can "lie" about identity, regardless of transport.

## Concrete fetchers

### GitFetcher (today, v0)

```python
@dataclass(frozen=True)
class GitProvenance(Provenance):
    url: str           # https://, ssh://, git://, file://
    ref: str           # branch / tag / sha

@dataclass(frozen=True)
class GitReceipt(ProvenanceReceipt):
    commit_sha: str    # resolved 40-char sha1 (or sha256 when git supports)
    ref_resolved: str  # the ref actually used (for sha-only provenance, this echoes back)
```

What we have today. No changes needed beyond fitting into the protocol.

### TarballFetcher

```python
@dataclass(frozen=True)
class TarballProvenance(Provenance):
    url: str           # https:// or file://
    expected_sha256: str | None  # optional pre-extraction integrity check
    strip_components: int = 1    # like tar --strip-components

@dataclass(frozen=True)
class TarballReceipt(ProvenanceReceipt):
    archive_sha256: str   # sha256 of the tarball bytes
    extracted_size: int   # uncompressed size in bytes
```

Verification is **before extraction**: download the tarball, sha256 it,
compare to `expected_sha256` if given, extract. This is a strictly
stronger guarantee than git's "clone and hope" — the integrity check
happens before any bytes touch the working tree.

Identity is *not* `archive_sha256`. Identity is computed from the
extracted tree, same as every other fetcher. (The same tree could be
delivered as zip, tar.gz, tar.xz — they'd all produce the same
identity.)

### HgFetcher (mercurial)

```python
@dataclass(frozen=True)
class HgProvenance(Provenance):
    url: str
    rev: str   # revision id (changeset hash, branch, tag, bookmark)

@dataclass(frozen=True)
class HgReceipt(ProvenanceReceipt):
    changeset: str   # full 40-char sha1 changeset hash
```

Mechanically equivalent to git, different commands (`hg clone`, `hg
update`). Worth doing once the demand surfaces.

### FossilFetcher

Same shape as git/hg. Fossil is a one-binary SCM with built-in tickets
and wiki — niche but a real Nim package or two uses it.

### LocalFetcher

```python
@dataclass(frozen=True)
class LocalProvenance(Provenance):
    path: Path   # absolute path to a source tree on disk

@dataclass(frozen=True)
class LocalReceipt(ProvenanceReceipt):
    source_path: Path   # what we copied from
    fingerprint: str    # the tree's identity at fetch time
```

For workspace deps and local development — "use the version of
intonaco at `../intonaco`." No network. The fetcher copies (or
symlinks, controlled by a flag) the tree into `_deps/`.

Identity still computed post-fetch. Local provenance is the *only*
case where identity might drift between fetches without milpa knowing
(the user edits files in place); we handle this by recomputing
identity on every `milpa verify` and warning when local provenance
content has drifted.

### OciProvenance (research)

```python
@dataclass(frozen=True)
class OciProvenance(Provenance):
    registry: str      # e.g. ghcr.io/coreyleavitt
    image: str         # e.g. nim-deps/chronos
    digest: str        # sha256:abc...

@dataclass(frozen=True)
class OciReceipt(ProvenanceReceipt):
    manifest_digest: str
    layers: tuple[str, ...]
```

OCI artifact registries (GHCR, Docker Hub, etc.) can store arbitrary
content addressed by digest. Pulling an OCI artifact by digest gives
you a content-addressed transport for free — the registry verifies the
digest before serving. milpa's identity computation after extraction
still applies; the OCI digest is a *provenance receipt* (this digest
delivered these bytes), not an identity (the identity is computed from
the bytes themselves).

### IpfsProvenance (research)

```python
@dataclass(frozen=True)
class IpfsProvenance(Provenance):
    cid: str   # IPFS CID (content identifier)

@dataclass(frozen=True)
class IpfsReceipt(ProvenanceReceipt):
    cid_resolved: str   # the CID actually served
```

IPFS is intrinsically content-addressed: the CID *is* the identity (in
IPFS's own algorithm, which may or may not match milpa's sha256).
milpa would recompute its own identity and either treat the CID as
provenance (separate from identity) or — if the CID's hash algorithm
matches milpa's — treat them as equivalent. The latter is a future
optimization once milpa supports multiple hash algorithms (see
`rfc-content-addressed-identity.md` §Hash algorithm agility).

## Verification semantics across transports

A useful taxonomy emerges:

| Fetcher | Verify before fetch? | Verify after fetch? |
|---|---|---|
| git | no (you have to clone first) | identity recomputed |
| tarball | yes (sha256 of archive bytes) | identity recomputed |
| hg | no | identity recomputed |
| fossil | no | identity recomputed |
| local | n/a (no fetch) | identity recomputed |
| oci | **yes (digest verified by registry)** | identity recomputed |
| ipfs | **yes (CID verified intrinsically)** | identity recomputed |

The post-fetch identity recomputation is **always** done by milpa,
regardless of transport. The pre-fetch checks are transport-specific
optimizations (verify cheap before doing expensive extraction).

A "best practices" recommendation falls out: for high-security
deployments, prefer transports with pre-fetch verification (tarball
with expected hash, OCI, IPFS). They eliminate a class of attacks
where the transport hands you malicious bytes that you then have to
discard. git can't do this — you have to clone before you can hash.

## Manifest grammar — declaring fetcher kinds

Today's milpa.kdl:

```kdl
deps {
    chronos git=(url)"https://github.com/x/y.git" ref="feat/contextvars"
}
```

Extension proposal: any provenance kind, structured the same way:

```kdl
deps {
    // git (today's shape, unchanged)
    chronos git=(url)"https://github.com/x/y.git" ref="feat/contextvars"

    // tarball
    libfoo tarball=(url)"https://example.com/foo-1.0.tar.gz" \
           sha256="abc123..." \
           strip_components=1

    // mercurial
    libbar hg=(url)"https://example.com/bar/" rev="2.0"

    // local path (workspace deps)
    intonaco local="../intonaco"

    // oci registry
    libquux oci="ghcr.io/coreyleavitt/quux" digest="sha256:def..."

    // ipfs
    sometree ipfs="bafybei..."
}
```

The first property-name (`git=`, `tarball=`, `hg=`, etc.) identifies
the fetcher kind. Subsequent properties are transport-specific.

Alternative shape worth considering: an explicit `kind` discriminator:

```kdl
deps {
    chronos {
        kind "git"
        url "https://github.com/x/y.git"
        ref "feat/contextvars"
    }
}
```

The block form is more verbose but cleaner when a single dep has
multiple alternate provenances (Phase D from the content-addressing
RFC). Decision: support both syntaxes; the inline form is a shortcut
for single-provenance simple cases.

## Implementation: the fetcher registry

```python
# milpa/fetchers/__init__.py

_REGISTRY: list[Fetcher] = []

def register(fetcher: Fetcher) -> None:
    """Register a Fetcher implementation. Order matters for can_handle
    dispatch: first match wins."""
    _REGISTRY.append(fetcher)

def fetch(name: str, p: Provenance, *, dest: Path) -> FetchResult:
    """Dispatch to the first registered fetcher that handles `p`."""
    for f in _REGISTRY:
        if f.can_handle(p):
            return f.fetch(name, p, dest=dest)
    raise FetchError(
        f"no registered fetcher handles provenance kind {type(p).__name__}"
    )
```

Built-in fetchers register themselves at module import. Third-party
fetchers can register via setuptools entry points (`milpa.fetchers`),
allowing experimental transports without modifying milpa core.

## Phasing

### Phase F1 — refactor the existing git fetcher to fit the protocol

The current `milpa/fetcher.py` has `fetch_url_dep(name, git, ref, *,
deps_dir)` as a top-level function. Refactor to:

1. Define the `Provenance` / `FetchResult` / `Fetcher` protocols in
   `milpa/fetchers/types.py`.
2. Wrap today's `fetch_url_dep` as `GitFetcher.fetch` implementing the
   protocol.
3. Keep `fetch_url_dep` as a backward-compat top-level alias for v0
   consumers.

**No new behavior.** This is structural refactor. Tests still pass.

**Estimated effort:** 1-2 days.

### Phase F2 — TarballFetcher

Implement tarball download + verify + extract. Manifest grammar
extension: `tarball=(url)"..." sha256="..."`. Test against a small
public tarball.

**Estimated effort:** 2-3 days.

### Phase F3 — LocalFetcher

Local path provenance for workspace deps. Closes backlog #25 (workspace
resolution) partially.

**Estimated effort:** 1-2 days.

### Phase F4 — HgFetcher

Mercurial support. Largely mechanical given Phase F1.

**Estimated effort:** 2-3 days.

### Phase F5 — FossilFetcher

Fossil support. Same shape.

**Estimated effort:** 2-3 days.

### Phase F6 — OciFetcher (research)

OCI registry support. Pre-fetch digest verification. Aligned with the
content-addressing RFC's identity model.

**Estimated effort:** 4-6 days, plus learning curve on OCI semantics.

### Phase F7 — IpfsFetcher (research)

IPFS / IPLD support. The most aligned transport with milpa's identity
model.

**Estimated effort:** 4-6 days, plus IPFS infrastructure dependency.

### Phase F8 — third-party fetcher entry points (post-v1)

Setuptools entry-point plumbing so external packages can register
fetchers without patching milpa.

**Estimated effort:** 1-2 days once the protocol stabilizes.

## What this RFC does *not* commit milpa to

- A specific manifest grammar (inline-property-name vs explicit-kind
  block — both will likely be supported eventually).
- A specific fetcher discovery mechanism (registry vs entry-points —
  registry first, entry-points later if there's demand).
- Network policy (proxy support, retry semantics, parallel fetches) —
  separate concerns layered on top of the fetcher protocol.
- Authentication / credential management — orthogonal, gets its own RFC.

## Open design questions

### 1. Fetcher dispatch when multiple fetchers can handle the same kind

What if there are two `git` fetchers — a built-in subprocess one and a
hypothetical libgit2-based one? Order matters; first match wins.
Acceptable for now; revisit if it becomes a real configuration
problem.

### 2. Sandboxing fetcher execution

Some fetchers (tarball extraction, OCI manifest parsing) deal with
untrusted input. Naive implementations are vulnerable to zip-slip,
symlink-escape, billion-laughs XML attacks. Each fetcher must:

- Reject relative paths escaping the dest directory.
- Reject symlinks pointing outside the dest tree.
- Limit decompression size (no zip bombs).
- Limit recursion depth in nested archives.

This is shared concern across multiple fetchers; worth factoring into a
`SafeExtractor` utility used by tarball + future archive fetchers.

### 3. Caching at the transport layer

Some transports have natural caching (git's `--reference` flag, OCI
layer cache, IPFS local store). Should milpa wire transport caches
into its own global content store (`rfc-content-addressed-identity`
Phase C), or treat them as black-box optimizations?

Recommendation: treat as black-box for v0.x; revisit when the global
store ships and we have data on dedup effectiveness across transports.

### 4. Provenance fallback policy

When a dep has multiple provenances (content-addressing RFC Phase D),
which order are they tried? Options:

- **Declaration order** (simple, predictable).
- **Locality preference** (prefer file:// > local cache > remote).
- **Speed history** (prefer the one that succeeded fastest last time).

For v0.x: declaration order. Speed-history caching is a v1+ refinement.

### 5. Hash algorithm alignment across transports

OCI and IPFS use their own content-addressing (sha256 manifest digest,
multihash CID respectively). Some align with milpa's sha256 source-tree
hash; others may use sha512 or different tree-hashing schemes.

The clean answer: **milpa's identity is milpa's identity**, computed
the same way regardless of transport. Transport-native digests are
recorded as provenance receipts but not treated as identity.

If/when milpa supports algorithm agility (content-addressing RFC), the
recommendation could shift toward "if the transport's hash matches our
algorithm and tree-hashing scheme, treat it as equivalent." For now,
recompute.

## Acceptance: testable invariants

The abstraction is right when:

1. Adding a new transport (e.g., tarball) requires no changes to
   resolver / solver / lockfile / identity code — only a new fetcher
   module + a manifest grammar extension.
2. The same source tree delivered via two transports produces the same
   identity. (Demonstrably: same chronos at the same commit, fetched
   via git URL OR via a tarball of the same commit's contents, has the
   same identity.)
3. Fetcher failures don't leak partial trees — same cleanup contract
   for every transport.
4. Pre-fetch verification (where the transport supports it) prevents
   malicious bytes from touching the working tree.
5. Identity computation is uniform — every transport produces a tree;
   milpa hashes the tree.

## Issues this RFC will spawn

- **Phase F1: refactor git fetcher into pluggable Fetcher protocol**
- **Phase F2: TarballFetcher**
- **Phase F3: LocalFetcher (workspace deps)**
- **Phase F4: HgFetcher**
- **Phase F5: FossilFetcher**
- **Phase F6: OciFetcher (research)**
- **Phase F7: IpfsFetcher (research)**
- **Phase F8: third-party fetcher entry points**
- **SafeExtractor utility** — shared sandboxing primitive used by
  archive-handling fetchers (cross-cutting; precondition for F2 + F6 + F7).
