# RFC: Resolve named deps via the tianguis index (replace nim-lang registry)

**Issue:** milpa#97 (closes the registry-swap; eventually closes #85 registry RFC).
**Status:** DRAFT (2026-06-06) — Stage 1 of `/flow`.
**Depends on:** `tianguis_client.py` + `fetchers/oci.py` (landed); one vendor-en-absentia
pass populating `index.kdl` (done — 2613 packages live).

## What this does

Replace the nim-lang/packages.json registry (`milpa/registry.py`) with the **tianguis
index** as the single source of truth for **named-dep resolution**. After this:
`milpa fetch <name>` looks the name up in the tianguis index, fetches the pinned version
via the provenance the index recorded, and verifies the fetched content against the
index's `content_hash`. `milpa/registry.py` is deleted.

URL-deps, local-deps, tarball-deps, and workspace members are **unchanged** — only the
*named* dep path (`NamedDep` → `_process_named`) is rerouted.

## The spec correction (settled — do not re-open)

The issue body says "replace `GitProvenance` with `OciProvenance` from `provenances[0]`."
**That assumption is stale.** The real `index.kdl` is **2613 git provenances, 1 OCI** —
the vendor-en-absentia bot records *git* provenance (`url` + `ref` + `commit_sha` +
`content_hash` + `attestation "milpa-vendored"`); OCI is only the author-publish path.
An OCI-only reading would make `milpa fetch <name>` fail on every real package.

**Settled design: the resolver is provenance-agnostic.** The index records a provenance
*kind* per version; milpa dispatches on it and fetches via the matching fetcher, with **no
privileged transport**. Git dominating the current index is an incidental fact about how
Nim packages happen to be distributed today (git forges) — the design does not lean on it.
The index can be **mixed**, and the git/OCI ratio shifts toward OCI over time (author
publishes; tianguis backfills popular packages) with **zero resolver change**.

What the index authoritatively supplies per named dep:
- **identity** — `content_hash` (the verification gate; `expected_identity`)
- **provenance** — git (`url`/`ref`/`commit_sha`) or oci (`registry`/`repository`/`digest`)
- **version set** — the enumerated `version` nodes (replaces `list_tags` entirely)

What it does **not** supply: **graph edges**. `tianguis_client.Version` has no `requires`;
transitive deps still come from parsing each fetched dep's `milpa.kdl`/`.nimble` (exactly
as the resolver does today). The index gives node identity+provenance, not edges.

## Invariants (the safety net)

1. **Identity gate unchanged.** `expected_identity = version.content_hash`; the
   `FetcherRegistry` recomputes the content hash post-fetch and a mismatch is a hard error.
   `compute_content_hash` returns `"sha256:<hex>"` — **byte-identical** to the index's
   `content_hash` format (verified), so the comparison is direct.
2. **Exact-commit pin for git.** Fetch git provenance at the immutable `commit_sha`, not
   the mutable `ref` field — a *stronger* pin than the old tag-resolution path. This requires
   `GitProvenance` to **carry both** (see the type-extension below): `ref` is recorded for
   provenance/debuggability (R3), `commit_sha` is what `GitFetcher` checks out. Collapsing
   them into a single `ref` field (round 1's tentative read) is rejected — it loses the human
   ref and leaves `GitFetcher` unable to distinguish "exact commit" from "branch tip".
3. **Provenance-agnostic dispatch.** Resolver passes `version.provenances` to
   `fetch_any`; the existing kind-keyed `FetcherRegistry._select` routes git→`GitFetcher`,
   oci→`OciFetcher`. No `isinstance` branching in the resolver.
4. **Named-only (behaviorally).** URL/local/tarball/member resolution *behavior* is
   unchanged; overrides that turn a `NamedDep` into a `UrlDep` still bypass the index. The
   S2.7 typed-dispatch refactor touches how those paths' provenance is *reconstructed* for the
   lockfile (string-prefix → type) but is behavior-preserving — same `*Record` out.
5. **No nim-lang fallback.** Name not in index = hard `TianguisError` (no silent
   degrade — bypassing an author's denylist opt-out would be actively wrong).

## Surface (grounded — file:line)

**Delete:** `milpa/registry.py` entirely (`RegistryEntry`, `ResolvedRegistryDep`,
`parse_registry`, `load_registry`, `resolve_named`, `list_remote_tags`, `resolve_version`).
Note: `resolve_version` routes through `VersionSet.from_constraint` — that algebra already
lives in `solver.py`; `tianguis_client.resolve_named` already uses it. No logic lost.

**`tianguis_client.py`** — make it provenance-agnostic (currently OCI-only):
- **Imports (do first):** add `from .fetchers.git import GitProvenance` and
  `from .fetchers.types import Provenance` (base type). See the **Provenance vocabulary**
  decision below — this reuses the fetcher provenance types rather than minting a third
  parallel vocabulary; the import direction (`tianguis_client → fetchers.types`) is
  acyclic (`fetchers/types.py` imports only `identity`/`cas`).
- `_parse_version_node` (lines 67–87): stop skipping non-OCI (lines 73–77). Parse git
  provenance → `GitProvenance(url, ref, commit_sha)` and oci → `OciProvenance(...)`, in
  index order. An **unknown** provenance `kind` is skipped (forward-compat), not fatal.
- `Version.provenances` (line 36): retype `tuple[OciProvenance, ...]` →
  `tuple[Provenance, ...]` (the fetcher base type; mixed kinds allowed). The tuple is
  **preference-ordered** — index order; first is canonical, the rest are mirrors. The
  identity gate (Invariant 1) makes any mirror yielding different bytes a hard error, so
  `fetch_any` fallback is safe.
- **Empty-provenance guard:** a `Version` whose `provenances` is `()` is a malformed index
  entry (carries identity but is unfetchable). `resolve_named` raises
  `TianguisError(code="TNG-NO-PROVENANCE", …)` naming the package + version **before**
  returning — never let an empty tuple reach `fetch_any` (which would raise an opaque
  `FetchError: no candidates provided`).
- **`schema_version` forward-compat:** `parse_index` (lines 90–116) currently ignores the
  document-level `schema_version` node. Define a module constant
  `TIANGUIS_INDEX_SCHEMA_VERSION: int = 1` (the only milpa-known version) and parse the node's
  value as an **integer** — KDL emits `schema_version 1` as a bare int, so `_scalar_child`
  (str-only, lines 57–64) returns `""` and the guard silently passes. Add a sibling
  `_scalar_child_int` (or accept both int/str) and compare `value >
  TIANGUIS_INDEX_SCHEMA_VERSION` → raise `TianguisError(code="TNG-SCHEMA-UNKNOWN", …)`. A
  *lower or equal* version is read normally (we are forward-compatible within a major). milpa
  must not silently misread a future breaking index format.
- **Error-catalog codes + bijection guard:** `TianguisError` gains a `code: str` field, and
  `tianguis_client` owns the **single** `_TNG_CODES` set (`TNG-NOT-FOUND`,
  `TNG-NO-SATISFYING-VERSION`, `TNG-NO-PROVENANCE`, `TNG-SCHEMA-UNKNOWN`, `TNG-BAD-VERSION`).
  `TianguisError.__init__` asserts `code in _TNG_CODES` (the bijection lint can then grep one
  place). `TNG-BAD-VERSION` is a **tianguis-domain** error (an *index* entry carries an
  unparseable version) — define and raise it from `tianguis_client`, not `resolver.py`, so the
  whole `TNG-*` surface lives in one module. The CLI top-level handler prints `code: message`
  (codes must be user-visible per the error-catalog discipline). Tests assert `e.code == …`,
  not just the message string.
- `resolve_named(idx, name, constraint) -> Version` (lines 194–225): already correct
  shape — returns the highest `Version` satisfying the constraint (maxver; strategy is
  **out of scope**, see Non-goals / #98), raises `TianguisError` if absent. Changes:
  the empty-provenance guard above, and `Version.version` is the **raw index string** — it
  is NOT guaranteed to be a clean `X.Y.Z` (see resolver `_process_named` below).
- **`Version.canonical_provenance` property** (makes the preference-order contract explicit):
  add `@property canonical_provenance(self) -> Provenance: return self.provenances[0]`,
  guarded by the empty-provenance check (`TNG-NO-PROVENANCE`). Document on `Version` that
  `provenances` is ordered by index position — first is the index's canonical source, the rest
  are mirrors — and **callers MUST NOT re-order**. Today the order is an undocumented
  dependency on KDL node iteration order; this names it.
- **`parse_index` sort sentinel** (lines ~111): the sort key `parse_version(v.version) or
  (-1,)` mixes a length-1 sentinel with the length-3 `Version` tuple — accidentally correct
  under `reverse=True` only because tuple comparison short-circuits on the first element.
  Replace with a partition: sort the *parseable* versions descending, then append the
  unparseable ones (stable) — no heterogeneous sentinel. Robust under any future sort-order
  change.
- **Duplicate version tolerance** (`_parse_version_node` accumulation): if an index entry
  carries the same `version "X"` twice, dedupe by version string (`seen: set[str]`), keep the
  first, and warn — do **not** raise (forward-compat tolerance, consistent with the
  unknown-kind skip).
- **`load_index` hardening** (lines 161–187): (1) the network GET drops the old registry's
  `timeout=30` — restore it (`urllib.request.urlopen(url, timeout=30)`); an un-timed-out
  resolver hangs forever on a wedged server. (2) the cache write is **non-atomic**
  (`Path.write_text`), so two concurrent `milpa` invocations can interleave a partial file
  that the other's `parse_index` then reads — write to a sibling temp file and `os.replace`
  (atomic rename, POSIX + Windows). (3) Define `DEFAULT_INDEX_URL` as a **module constant** in
  `tianguis_client` (the live tianguis `index.kdl` raw URL — confirm the exact URL at S5);
  `cli.py` imports it. A single constant is the federation (#8) seam — one place to grow to a
  URL list later.
- **Index cache location → global XDG** (`$XDG_CACHE_HOME/milpa/index/`, default
  `~/.cache/milpa/index/`), **not** the per-project `_deps/` the old registry used. The index
  is the *registry* — shared across every project, not project state — so it should not be
  wiped by `milpa clean` (which clears `_deps/`), and a global TTL'd cache is offline-tolerant
  across projects. `milpa clean` therefore does **not** touch the index cache (document this;
  a future `milpa fetch --refresh-index` can force-invalidate). *(Resolved this round —
  recorded in the report; the alternative, per-project, was rejected because a registry is not
  project state.)*

**`resolver.py`** — reroute the named path only:
- `_process_named` (lines 1311–1357): replace `resolve_named(name, constraint,
  registry=, list_tags=, strategy=)` + `GitProvenance(url=r.url, ref=r.tag)` construction with
  `version = tianguis_client.resolve_named(index, name, constraint)` then
  `fetch_any(list(version.provenances), expected_identity=version.content_hash)`. **Drop the
  `strategy=` argument** — tianguis `resolve_named` is maxver-only (`(index, name, constraint)`
  signature; strategy deferred to #98). Leaving `strategy=` in the call is a `TypeError`.
  - **Version-string parse (must fix — crash path).** The current code builds the
    `_Candidate` version via `int(parts[N])` on `r.version.split(".")` (lines ~1342). The
    index's `Version.version` is a **raw tag string** and may be `v1.2.3`, `1.2`, or
    `1.2.3.4`, which crashes `int(...)`. Use `parse_version(version.version)` (the one true
    parser in `solver.py`); on `None`, raise `TianguisError(code="TNG-BAD-VERSION", …)` —
    do not silently coerce to `(0,0,0)`.
  - **Record the typed provenance (Decision #6 / Option A).** Set
    `_Candidate.provenance` to the `Provenance` object `fetch_any` actually fetched from — the
    chosen element of `version.provenances` (the receipt identifies which candidate won; for
    the single-provenance common case it is `version.canonical_provenance`). The lockfile
    boundary then reconstructs the record by **type** (`GitProvenance → GitProvenanceRecord`,
    `OciProvenance → OciProvenanceRecord`) — no `"oci:"`/`"registry:"` string. `source` is set
    to a human descriptor (the git URL or `oci:{registry}/{repository}` for display only) and
    is never parsed back. This rides on the S2.7 typed-dispatch refactor.
- `_pin_for_named_dep` (lines 1005–1027): this is a **semantic rewrite**, not a cosmetic
  simplification. The old predicate matched a mutable tag (`RegistryProvenanceRecord.tag ==
  resolved.tag`). `Version` has **no `.tag`** — it has `.content_hash`. New predicate,
  stated exactly: **return the locked `identity` iff `locked.identity ==
  version.content_hash`**, where `version` is the `Version` already returned by
  `resolve_named` (no second index lookup). **Guard against identity collision:** since two
  unrelated packages with byte-identical source trees share a `content_hash`, the predicate
  must also confirm the locked record is a *named-dep provenance* —
  `locked.identity == version.content_hash and any(isinstance(p, (GitProvenanceRecord,
  OciProvenanceRecord)) for p in locked.provenances)` — so a local/tarball/member dep that
  happens to collide can't be pinned as a named dep. The `isinstance(p,
  RegistryProvenanceRecord)` branch becomes dead; **S4 also removes `RegistryProvenanceRecord`
  from this function's lazy import** (`resolver.py:1013`) — if S4 leaves it, S6's deletion of
  the class turns it into an `ImportError` that breaks every `resolver.py` test. See the
  **Re-lock pin semantics** decision below for the `lock`-vs-`update` policy this implements.
- `resolve` / `resolve_workspace` signatures (lines 256–267, 536–727): drop `registry` +
  `list_tags` params; add `index: Index` (injected, not loaded internally — keeps the pure
  resolver testable with a synthetic Index, matching today's `registry=` injection style).
- **Full signature chain (S0 — do first).** `registry`/`list_tags` are **dead params** that
  thread through the whole worker call graph even though only the old `_process_named` *uses*
  them. Two classes of site — S0 must treat them differently or it breaks mid-refactor:
  - **Dead (remove signature + every callsite):** `_build_terms` (1360–1406), `_process_url`
    (1034), `_process_tarball` (1226), `_process_local` (1271), and **`_extract_from_milpa_kdl`
    (1103)** — the last is easy to miss because it has **two** call sites: the fixpoint
    re-eval sweep (≈499) *and* the URL-dep transitive walk (≈1073), **both** of which pass
    `registry, list_tags` positionally. Remove from the signature *and* both calls atomically,
    or the suite throws `TypeError` the moment `test_conditional_deps.py`'s flag-propagation
    path fires. Drop the matching captures from the `submit()` closures at 397/407/430/499–500.
  - **Still live (leave untouched until S4):** `_process_named` (1316) genuinely uses them,
    and its `submit()` site at 443–446 passes them — keep both intact through S0; S4 swaps
    them for `index`. A partial S0 pass that strips `_process_named`'s submit args while
    leaving its signature (or vice-versa) crashes at submit time.

  S0 stays a pure green refactor; S4 then adds `index` to just the named path. This shrinks S4
  from ~4 cycles to ~1.

**`fetchers/git.py`** — two changes.

**(a) Extend `GitProvenance` (pre-S1 — structurally blocks everything else).** Today
`GitProvenance` is `(url, ref)` only — it has **no `commit_sha` field** (`fetchers/git.py:24–27`;
the SHA currently lives only on the `GitReceipt` *result*). The index parser cannot construct
`GitProvenance(url, ref, commit_sha)` as the RFC assumes — that call is a `TypeError`. Add
`commit_sha: str | None = None` to `GitProvenance` (purely additive; every existing
`GitProvenance(url=…, ref=…)` callsite keeps working, field defaults to `None`). This is the
*first* edit of S1; without it S1's unit test can't even build the expected provenance and
S2.5 has no field to branch on.

**(b) arbitrary-`commit_sha` checkout (was R1; now a required fix).**
`GitFetcher.fetch` does `git clone` (default refspec) + `git checkout <ref>`. It must learn to
honor `p.commit_sha` when set: `if p.commit_sha:` use the exact-commit path (clone → `git fetch
origin <commit_sha>` with unshallow/full fallback → `git checkout <commit_sha>`); else keep the
existing `git checkout p.ref` tip behavior (preserves all current callers). An index
`commit_sha` that is **not on the default branch tip / history**, or a shallow clone, makes a
plain `git checkout` fail (`reference is not a tree`) — hence the explicit `git fetch origin
<commit_sha>` step. Note the server-side requirement (`uploadpack.allowReachableSHA1InWant`;
GitHub/GitLab on, self-hosted may not) — the full-fetch fallback covers servers that reject it.
This is the **primary** path for 2613 vendored entries — its own slice (S2.5), validated
end-to-end by S7.

**`fetchers/__init__.py`** (lines 31–34): register `OciFetcher()` (currently absent — git,
local, tarball only). Provenance-agnostic dispatch needs it present. Order is irrelevant for
correctness (`_select` is first-match on **disjoint** `isinstance` types); place OCI after
git/local for readable specificity order.

**`lockfile.py`** — add an OCI provenance record variant + read-compat for old locks:
- New `OciProvenanceRecord(registry, repository, digest, kind="oci")` in the discriminated
  union (lines 58–105), mirroring `OciProvenance`. After the S2.7 typed-dispatch refactor,
  `_provenance_from_resolved` gains an `OciProvenance → OciProvenanceRecord` **type** arm
  (fields copied straight off the object — no string-split). **Round-trip completeness:** the
  lockfile **parser** `_parse_provenance_block` (≈317–360) must *also* gain a `kind "oci"`
  arm — without it, an `OciProvenanceRecord` written to disk fails to read back (`unknown
  provenance kind 'oci'`). Pin a write→parse round-trip test for the OCI record (S3).
- **`RegistryProvenanceRecord`: keep as its own read-compat record type, do not write, do not
  fabricate a git record.** The lockfile **parser** (line ~352) still accepts `kind "registry"`
  and returns a **`RegistryProvenanceRecord`** (preserving its `tag`) — *not*, as round 1
  proposed, a `GitProvenanceRecord(url="", …)`. That empty-URL remap is a latent corruption:
  `url=""` flows through `frozen.py`'s `_source_from_provenance` into a reconstructed
  `ResolvedDep(source="")`, which the writer re-emits as a `GitProvenanceRecord` with `url ""`
  — a syntactically-valid but unfetchable git record (a registry entry never recorded a URL).
  Keeping the distinct type avoids fabricating data the old lock never had. Existing user
  `milpa.lock`s (e.g. fresco's) may carry `kind "registry"`; deleting the class outright makes
  `load_lockfile` crash, and `frozen.py` / `cmd_show` / `test_lockfile_v2` all import it. Net:
  the **writer** never emits `registry` again (named deps now write git/oci records); the
  **reader** still yields `RegistryProvenanceRecord` with a one-time deprecation note; the
  dataclass is removed only once we accept regenerating straggler old locks (tracked, not in
  #97's critical path). See the **Migration** section for how `frozen`/`show`/`verify` each
  treat it.

**`frozen.py`** (`_source_from_provenance`, 203–221): two branches needed (S3). This function
is on the **CI fast-path** — `_resolved_from_locked` calls it for *every* locked dep when
reconstructing a `ResolvedGraph`, so a missing branch crashes `milpa fetch --frozen`, not just
`milpa show`. (1) Add an `OciProvenanceRecord` branch (return the `oci:` source descriptor),
or the first OCI dep in any lock crashes the frozen path. (2) The existing
`RegistryProvenanceRecord` branch currently returns `f"registry:{p.name}"`, which becomes
`GitProvenance(url="registry:foo")` → `git clone` failure. Since an old registry record has no
fetchable URL, the frozen path **cannot** honor it — raise `NotFrozen` (the existing
slow-path-fallback signal) with an actionable message ("lock entry `foo` uses the legacy
registry provenance; run `milpa update foo` to re-resolve via the tianguis index"). The slow
path then re-resolves `foo` through the index (its name is in the index), regenerating a
modern git/oci record. Do **not** fabricate a fetch URL.

**`cli.py`** — replace registry construction with index construction in `cmd_fetch`,
`cmd_lock`, `cmd_update`, `cmd_add`, `cmd_remove`, `_cmd_fetch_workspace`:
- `_default_registry_loader` (lines 157–158) → `_default_index_loader` using
  `tianguis_client.load_index(url=DEFAULT_INDEX_URL, cache_dir=)` (the constant from
  `tianguis_client`); overridable for tests/air-gap. **Type the loader seam with a
  `Protocol`**, not the existing untyped `Callable[..., …]` alias — the old `RegistryLoader`
  hid the `cache_path=` kwarg behind `**kwargs`, so a misnamed kwarg in a test fake fails only
  at runtime. Define `class IndexLoader(Protocol): def __call__(self, *, cache_dir: Path) ->
  Index: ...` and use it for every `index_loader:` param, catching kwarg drift at type-check
  time.
- Each `registry = registry_loader(cache_path=)` site (e.g. lines 348–349, 711–712) →
  `index = index_loader(cache_dir=)`, passed as `index=` to `resolve`/`resolve_workspace`.
- `_format_provenance_for_show` (`cmd_show`, 439–468): drop the `RegistryProvenanceRecord`
  branch (or route it through the read-compat alias) and **add an `OciProvenanceRecord`
  branch** — otherwise OCI deps print a raw dataclass repr. Co-locate this with S5's CLI
  changes, not the S6 delete.

**`manifest_writer.py`** (`apply_manifest_change_with_resolve`, 95–155): the single
orchestration point for `cmd_add` / `cmd_add_mirror` / `cmd_remove`. It takes
`registry_loader` + `list_tags` and passes them to `resolve()`. It must take `index_loader`
and thread `index=` instead — otherwise `milpa add`/`remove` still resolve via the dead path.
Covered in S4 (signature) + S5 (CLI wiring).

**Tests** — **9** files (not 6) touch `RegistryEntry` / `list_tags` / `RegistryProvenanceRecord`
or pass `registry=`/`list_tags=` to `resolve()`:
`test_registry.py` (delete — module is gone), `test_resolver.py`, `test_cli_commands.py`,
`test_workspace_resolver.py`, `test_nimble_compat.py`, `test_resolver_pins.py`,
**`test_conditional_deps.py`** (~42 `resolve(registry=, list_tags=)` call sites — every one
becomes a `TypeError` the moment S0/S4 changes the signature), **`test_manifest_mirrors.py`**,
**`test_lockfile_v2.py`** (round-trips `RegistryProvenanceRecord` explicitly), plus the gated
**`test_integration.py`** (imports `RegistryProvenanceRecord`). The `resolve()`-signature
call sites are fixed in **S0** (they pass empty `registry={}`/`list_tags=lambda …: []`, so
they migrate by simply dropping the kwargs); the genuine fixture migrations (synthetic
`Index`) land in S6.
**Test index primitive:** build synthetic indexes with `parse_index(inline_kdl_str)` — it is
already tested, network-free, and routes through the **real** parser, so KDL-format drift is
caught (unlike a hand-rolled string generator or a bespoke `make_index` that could silently
diverge). No new `make_index` helper unless a slice proves it ergonomically necessary.

## Design decisions

**Settled (architect round 1):**

1. **Index injection vs internal load → inject.** Resolver takes `index: Index`; the CLI
   loads. Keeps the resolver pure/network-free and testable with a synthetic `Index`,
   matching today's `registry=` injection.
2. **Provenance vocabulary → reuse the fetcher `Provenance` types** (`GitProvenance` /
   `OciProvenance`), NOT a new index-domain `IndexGitProvenance`/`IndexOciProvenance`
   vocabulary. *Reasoning:* milpa already has two provenance vocabularies — the fetcher
   types (canonical, transport-domain) and the lockfile `*Record` types (serialization,
   carry a `kind` discriminator). Minting a third, index-domain set would add a parallel
   `Git*`-shaped type triplet — the exact duplication CLAUDE.md's single-source-of-truth
   rule forbids — to buy a decoupling with **no second consumer today** (a read-only index
   linter is hypothetical). The import `tianguis_client → fetchers.types` is acyclic
   (`fetchers/types.py` imports only `identity`/`cas`, never the index), so there is no
   cycle to avoid. The translation happens implicitly: the index reader produces fetcher
   `Provenance` directly; the lockfile boundary already maps `Provenance → *Record`. *(This
   was the round-1 design fork; recorded as settled — see the report. Revisit only if a
   genuine second index-only consumer appears, at which point extract the index-domain
   types then, on a proven ≥2 need.)*
3. **Re-lock pin semantics → a lock is a lock.** `milpa lock` / `milpa fetch` honor the
   existing pin: `_pin_for_named_dep` returns the locked `identity` iff `locked.identity ==
   version.content_hash` (the version `resolve_named` already returned — no second lookup).
   `milpa update` re-resolves (calls `resolve` with `prior_lockfile=None`), advancing pins.
   *Interaction with the mutable-`ref` gap from the tianguis migration:* that friction came
   from a **mutable** `ref=main` pin that `milpa lock` wouldn't advance, forcing a manual
   lock edit. The index path **removes** that friction — the pin is now an **immutable
   `commit_sha`**, so "honor the pin" is unambiguously correct, and the supported way to
   move forward is `milpa update` (which re-queries the index for the new `commit_sha`).
   No silent re-resolution under `lock`.
4. **OCI registration ordering** — first-match `_select` on **disjoint** `isinstance`
   types; order is correctness-irrelevant. Place OCI after git/local for readability.
5. **Test index primitive** — `parse_index(inline_kdl_str)` (routes through the real
   parser; format drift is caught). No bespoke `make_index` unless a slice proves it needed.

6. **Provenance dispatch → typed `Provenance` carry (settled — Corey chose Option A,
   round 2).** Round 1's `source = <git url>` / `source = "oci:{registry}/{repository}@{digest}"`
   string-prefix dispatch is **replaced** by a typed one. The OCI leg made it not just
   inelegant but *ambiguous to parse* (an OCI repository path contains `/`, so splitting
   `registry`/`repository` out of the flat string is a heuristic — a textbook no-workaround
   violation). The fix:
   - Add **`provenance: Provenance | None`** to `_Candidate` and `ResolvedDep`. It is the
     **authoritative** record-reconstruction input (the resolved sha still comes from the
     receipt, as today). `None` only for synthetic root + workspace members (never fetched).
   - `source: str` is **retained** as a human-display / member-marker string but is **no
     longer parsed** to rebuild provenance records — it stops being load-bearing. (Keeping the
     stored field rather than a computed `@property` avoids churning the dozens of `.source`
     readers and the `member:`-prefix checks; the SSOT win — one typed reconstruction boundary,
     zero string-splitting — is realized either way.)
   - `_provenance_from_resolved` dispatches on `type(d.provenance)`: `GitProvenance →
     GitProvenanceRecord(url, ref, commit_sha=d.sha)`, `LocalProvenance → LocalProvenanceRecord`,
     `TarballProvenance → TarballProvenanceRecord`, `OciProvenance → OciProvenanceRecord` (fields
     read straight off the object — no string-split); `None` → the member/root arm (the lone
     surviving `source.startswith("member:")` check). The `registry:` and bare-git-URL string
     arms are deleted.
   - Lands as a **pure-refactor slice (S2.7) on the existing fetchers, before OCI/named work**,
     so the suite stays green and S3/S4 add their arms to an already-typed dispatch rather than
     to a string mechanism we'd immediately rewrite.

## Migration (existing lockfiles)

Existing `milpa.lock`s may carry `kind "registry"` provenance records (anything resolved
before #97). #97 must not break reading them — `load_lockfile` feeds `frozen.py`,
`cmd_show`, `cmd_verify`, and the prior-lockfile fetch/update paths.

- **Reader:** keep `kind "registry"` accepted; return a **`RegistryProvenanceRecord`** (its
  own type, preserving `tag`) with a one-line deprecation note. Do **not** remap to
  `GitProvenanceRecord(url="")` — a registry entry never recorded a URL, and the empty-URL
  fabrication silently corrupts the frozen/write path (see `frozen.py` above).
- **Each consumer's treatment of `RegistryProvenanceRecord`:**
  - `cmd_show` / `_format_provenance_for_show` → print `registry (legacy): <name> @ <tag>` (a
    human display arm; no fetch).
  - `cmd_verify` → works on **identity** (recomputed sha256 vs `locked.identity`); never
    touches provenance, so it passes unchanged. *(Confirmed: `verify_lockfile_against_deps` /
    `verify_workspace_against_disk` are provenance-blind.)*
  - `milpa fetch --frozen` → cannot fetch a URL-less record; raises `NotFrozen` → slow path
    re-resolves via the index (above).
- **Writer:** never emits `registry` again — named deps now write `GitProvenanceRecord` /
  `OciProvenanceRecord`. Re-locking an old file naturally rewrites it to the new shape.
- **Class removal:** `RegistryProvenanceRecord` the dataclass is removed only once we accept
  regenerating any straggler old locks; not on #97's critical path. Pin a test (in **S3**): an
  old-style `kind "registry"` lock round-trips through `milpa show` + `milpa verify` without
  crashing, and `milpa fetch --frozen` on it raises the actionable `NotFrozen` (not a
  `git clone` failure).

## Slices (`/tdd`-sized, each independently testable)

Resequenced after architect round 1 so **every slice leaves the suite green** (the original
S3 delete + single fat S4 would have been RED on arrival).

- **S0 — dead-param cleanup (pure refactor, no behavior change).** Remove the unused
  `registry`/`list_tags` params from `_build_terms`, `_process_url`, `_process_tarball`,
  `_process_local`, `_extract_from_milpa_kdl`, and the `submit()` closures — and drop the
  matching kwargs from every test `resolve()` call site that passes empty
  `registry={}`/`list_tags=lambda …: []` (≈42 in `test_conditional_deps.py`,
  `test_manifest_mirrors.py`, etc.). Suite stays green. This shrinks S4 to just the named
  path and removes its biggest blast-radius surprise.
- **S1 — `tianguis_client` provenance-agnostic.** *First:* add `commit_sha: str | None = None`
  to `GitProvenance` (additive; unblocks the whole RFC). Then: add the imports; parse git+oci
  provenance nodes → `GitProvenance(url, ref, commit_sha)`/`OciProvenance` (unknown kind
  skipped); `Version.provenances: tuple[Provenance, ...]` (preference-ordered) +
  `canonical_provenance` property. Add the empty-provenance guard (`TNG-NO-PROVENANCE`), the
  `schema_version` int check against `TIANGUIS_INDEX_SCHEMA_VERSION` (`TNG-SCHEMA-UNKNOWN`),
  the `TianguisError.code` field + `_TNG_CODES` validation, the partition-based sort (no
  `(-1,)` sentinel), duplicate-version dedupe-with-warn, and `load_index` hardening
  (`timeout=30`, atomic `os.replace` write, `DEFAULT_INDEX_URL` constant). Unit-test against a
  mixed inline `index.kdl` (git + oci entry): `resolve_named` returns the git `Version` with a
  populated `GitProvenance(commit_sha=…)`; empty-provenance and unknown-schema entries raise
  the coded errors (**assert `e.code`, not just the message**); a non-`X.Y.Z` index version
  sorts without crashing.
- **S2 — register `OciFetcher`** in `default_registry`; assert `_select` routes an
  `OciProvenance` to it and a `GitProvenance` to `GitFetcher`.
- **S2.5 — `GitFetcher` exact-commit checkout.** Make `GitFetcher.fetch` honor `p.commit_sha`
  when set (clone → `git fetch origin <sha>` with unshallow/full-fetch fallback → `git checkout
  <sha>`); fall through to the existing `p.ref` tip checkout when it's `None`. The existing
  single-commit `make_repo` fixture (`tests/test_git_fetcher.py:19`) can't express "commit not
  at tip" — add a `make_repo_with_history(path, commits)` helper alongside it. Unit-test: build
  a two-commit repo, capture the first SHA, then `fetch(GitProvenance(url, ref="main",
  commit_sha=<first_sha>))` checks out the **first** commit's content, not tip. (Primary path
  for the git majority; the former R1.)
- **S2.7 — typed provenance dispatch (pure refactor, Decision #6 / Option A; existing
  fetchers only, no index).** Add `provenance: Provenance | None` to `_Candidate` and
  `ResolvedDep`; populate it where url/local/tarball candidates are built (the `Provenance`
  object already constructed for `fetch_any` is carried onto the candidate). Rewrite
  `_provenance_from_resolved` to dispatch on `type(d.provenance)` (`GitProvenance`/
  `LocalProvenance`/`TarballProvenance` → matching `*Record`; `None` → the `member:`/root arm);
  delete the `registry:` and bare-git-URL string arms. `source` stays a stored display/marker
  string but is no longer parsed. Suite stays green — **no behavior change**, only the
  reconstruction path changes from string-prefix to type. (Lands before S3/S4 so they add
  typed arms, not string arms.) Tests: existing lockfile round-trip tests pass unchanged; add
  one asserting a git/local/tarball `ResolvedDep` reconstructs the same `*Record` it did before.
- **S3 — lockfile `OciProvenanceRecord` (add-only).** Add the record; teach **both** the
  writer (`_provenance_from_resolved`) and the parser (`_parse_provenance_block` — the
  `kind "oci"` arm) so OCI records survive a write→read round-trip. Add the `OciProvenanceRecord`
  branch to `cmd_show`'s `_format_provenance_for_show` *and* `frozen.py`'s
  `_source_from_provenance`; change `frozen.py`'s `RegistryProvenanceRecord` arm to raise the
  actionable `NotFrozen` (not fabricate a fetch URL); add the `cmd_show` legacy-registry
  display arm. **Do NOT delete `RegistryProvenanceRecord`** (that's S6). Tests: OCI record
  round-trips write→parse; an old `kind "registry"` lock still parses, round-trips through
  `milpa show` + `milpa verify` without crashing, and `milpa fetch --frozen` on it raises the
  actionable `NotFrozen`.
- **S4 — resolver `_process_named` swap** *(hard-depends on S3 — without the lockfile `oci`
  writer/parser, OCI-resolved deps silently corrupt the lockfile as `kind "git"`; do not
  reorder before S3).* `resolve`/`resolve_workspace`/`apply_manifest_change_with_resolve` take
  `index:`; `_process_named` calls `tianguis_client.resolve_named` (drop the `strategy=` arg) +
  `fetch_any(version.provenances, expected_identity=version.content_hash)`, parses the version
  via `parse_version` (coded error on `None`), and records the typed `provenance` on the
  candidate (Decision #6 / built on S2.7) — not an `oci:` string; `_pin_for_named_dep`
  rewritten to the identity predicate **with the provenance-kind guard**, and its lazy
  `RegistryProvenanceRecord` import (`resolver.py:1013`) removed. **Migrate the two named-dep
  tests that construct a real `RegistryEntry`/`RegistryProvenanceRecord`**
  (`test_resolver.py:139`, `test_resolver_pins.py:218`) **here, not S6** — they exercise the
  named path and must be rewritten to synthetic-`Index` form to test the new behavior (S6's
  migration is only the *fixture-passing* sites). Unit-test with a synthetic Index + fake
  fetcher (no network): a named dep resolves to the index's `commit_sha`, the `content_hash`
  becomes `expected_identity`, and a non-`X.Y.Z` index version (`v1.2`, `1.2.3.4`) resolves
  instead of crashing. **Add the hash-parity unit fixture** (R2): the canary tree's recomputed
  `compute_content_hash` equals the index value — at unit level, not only in gated S7.
- **S5 — CLI index loader.** `_default_index_loader` (typed via the `IndexLoader` Protocol,
  using `DEFAULT_INDEX_URL`); `cmd_fetch/lock/update/add/remove` + workspace + `manifest_writer`
  build an `Index` and pass `index=`. Confirm the live `DEFAULT_INDEX_URL` value here. Inject a
  fake loader in command tests. Note: `cmd_add_mirror`'s SHA-probe correctness depends on S2.5
  (after migration a named dep's `GitProvenanceRecord.ref` holds the commit SHA) — S2.5 lands
  first, so this is satisfied; update its now-misleading "falling back to 'main'" comment.
- **S6 — delete `registry.py`** + `test_registry.py`; migrate the remaining fixture-bearing
  test files (`test_resolver.py`, `test_resolver_pins.py`, `test_cli_commands.py`,
  `test_workspace_resolver.py`, `test_nimble_compat.py`, `test_lockfile_v2.py`, and the
  gated `test_integration.py` import) to synthetic `Index`/lockfile fixtures; grep-clean of
  `RegistryEntry`/`load_registry`/`parse_registry`/`list_tags`/`packages_official`. Update
  the stale `registry.py` references in `CLAUDE.md` (architecture table + provenance comment)
  and `docs/comparison-vs-nimble-atlas.md`. Full suite green. (Keep the
  `RegistryProvenanceRecord` read-compat alias per Migration — only `registry.py` proper and
  its tests go.)
- **S7 — live integration test** (gated by `MILPA_INTEGRATION_TESTS=1`): against live
  tianguis, resolve a **transitive** dep tree (not just the `nimkdl` canary), fetch via git
  at the pinned `commit_sha`, verify `content_hash`. End-to-end validation of S2.5's
  arbitrary-`commit_sha` checkout.

## Risks

- **R1 — arbitrary `commit_sha` checkout** *(promoted from risk to a required fix —
  S2.5).* `GitFetcher` does `git clone` (default refspec) + `git checkout p.ref`. An index
  `commit_sha` not at the default-branch tip — or a shallow clone — fails the checkout. This
  is not an edge case: it's the **primary** path for all 2613 git-vendored entries. Fixed in
  S2.5 (`git fetch origin <sha>` with unshallow/full-fetch fallback), validated end-to-end in
  S7. Server-side caveat: bare-SHA fetch needs `uploadpack.allowReachableSHA1InWant` (GitHub/
  GitLab on; self-hosted Gitea/Forgejo may not) — the full-fetch fallback covers those.
- **R2 — content_hash recompute parity.** The index's `content_hash` was produced by the
  vendor bot running *this same* `compute_content_hash`. Pin a test that a fetched tree's
  recomputed hash equals the index value for the canary. (If vendor and resolver ever
  diverge on the algorithm, identity breaks silently — guard it.)
- **R3 — `ref` field semantics.** Index git provenance carries `ref "HEAD"` for many
  vendored entries; we deliberately ignore it for checkout (use `commit_sha`). Record `ref`
  in the lockfile for provenance/debuggability but never fetch by it.

## Non-goals

- OCI-vendoring the git majority (separate tianguis infra project; this RFC makes milpa
  *ready* for it, not dependent on it).
- Changing the identity algorithm, the solver, or URL/local/tarball/member paths.
- `MILPA_INDEX_URLS` federation (#8) and `min_attestation` (#9) — separate issues; the
  index-loader constant is a single URL for now, structured so federation drops in later.
- **Resolution strategy (minver/semver) for index-resolved deps → #98.** Index resolution
  is maxver-only (the index is pre-sorted descending); strategy selection over the index is
  filed separately. `maxver` is the default and the only strategy the real trees exercise.
- **`milpa add <name>` (NamedDep manifest-editing path) → #99.** #97 reroutes *resolution*
  only; adding a named dep by name from the CLI is a separate manifest-editing feature.
- **Removing the `RegistryProvenanceRecord` dataclass.** Kept as a read-compat parse alias
  (see Migration); full removal waits until straggler old locks are regenerated.
- **Constraint accumulation for a named dep before resolving → #100** (pre-existing
  `seen_named`-dedups-by-name bug; #97 makes the failure less legible but doesn't introduce it).
- **Per-dep fetch observability → #101** (keep #97 output minimal; placement decision deferred).
- **`fetch_any` warn-on-identity-mismatch hardening → #102** (keep fallthrough; make it
  non-silent; isolated to `fetch_any`).
- **Index cache location is settled, not deferred:** global XDG (`~/.cache/milpa/index/`),
  untouched by `milpa clean`. A future `milpa fetch --refresh-index` force-invalidate is the
  natural follow-up but is out of scope here.
