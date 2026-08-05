# RFC: Native in-process HTTP transport — remove every consumer shell-out (`oras` + `curl`)

**Status**: Draft — Stage 2, architect round 2 applied (Corey 2026-08-05). Ready for `/tdd`.
**Scope**: **all consumer-side network fetches** — index / bundle / dep-decl / entry-bundle / tarball / OCI — converge onto one native in-process transport; the `oras` and `curl` shell-outs are deleted. Publish/push stays `oras` (CI-side).
**Impls**: Python + Rust (shared `conformance/spec-v1/` corpus + `harness/`).

## 0. Decisions of record (F1/F2 — resolved round 1; transport sub-decisions — resolved round 2)

Round 1 falsified the original "reuse the existing in-process HTTP client" premise:
milpa has *three* HTTP postures today and two of them already shell out —

| caller | Python transport | Rust transport |
|---|---|---|
| index / bundle / dep-decl / entry-bundle | stdlib `urllib.request` (in-process, **uncapped** — `index_cache.py::urllib_http_get`/`urllib_bundle_http_get` do a bare `resp.read()`) | **`curl` subprocess** (5 sites in `milpa-cli/src/main.rs` + `dep_decl_store.rs` + `entry_bundle_store.rs`) |
| tarball fetcher | **`curl` subprocess** (`fetchers/tarball.py::make_http_get`) | **`curl` subprocess** (`fetchers.rs::curl_streaming_transport`) |
| OCI fetcher | **`oras` subprocess** (`fetchers/oci.py::make_oras_pull`) | **`oras` subprocess** (`fetchers.rs::fetch_oci`, line 1910) |

Rust makes **no** first-class in-process HTTPS call: its `reqwest` is an inert,
`default-features=false`, **no-TLS-backend** transitive of the vendored sigstore
fork (temporary, pending sigstore-rs upstream). "No shell-out" therefore applies to
`curl` exactly as much as `oras`.

- **F1 → BROAD (decided round 1).** One native in-process transport (SSOT) for every
  consumer fetch; delete both `oras` and `curl`. This is the goal the motivation
  ("I hate shelling out") states, and it avoids milpa carrying a third HTTP posture
  against its own audit-for-duplication discipline.
- **F2 → `ureq` + `rustls` on Rust; stdlib `urllib` on Python (decided round 1).**
  `ureq`+`rustls` is pure-Rust TLS, blocking (milpa-core is not async), small tree.
  Python's index/bundle path is already native `urllib`, so Python's convergence is
  "move tarball + OCI off `curl`/`oras`, **and cap the uncapped urllib callers**."

### 0.1 Transport sub-decisions (round 2 — goal-determined, not forks)

Deleting `curl`/`oras` silently drops transport behaviors they provided for free. Each
is decided here so the native primitive reaches **parity**, not a regression:

- **Proxy env vars (`HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`) → honored, both impls.**
  `curl` honors these transparently; `ureq` does **not** auto-detect them and must be
  configured explicitly; Python's default opener chain includes `ProxyHandler` but a
  hand-built handler list can drop it. Losing proxy support is a silent connect
  failure for corporate/personal-proxy users, not an error. S1/S2 wire proxy-env
  detection into both primitives with a unit test.
- **TLS trust → `rustls-native-certs` on Rust (OS trust store), stdlib default on Python.**
  `curl` used the OS CA bundle; `webpki-roots` (compiled-in Mozilla set) would silently
  stop honoring enterprise/MITM-proxy roots and OS cert updates. `rustls-native-certs`
  reads the OS store at runtime — curl-parity, and additive with S11's later custom-CA
  work rather than a rewrite of the trust wiring. (Per-OS cert-store read differs on
  Windows/macOS/Linux; milpa ships a Rust binary, so this path is exercised by the
  smoke checkpoint.)
- **Crypto provider → pin `ureq`'s `rustls` to `aws-lc-rs`.** The vendored-sigstore graph
  already resolves `aws-lc-rs` (via `rustls-webpki/aws-lc-rs` under sigstore's `cert`
  feature); `ring` is present in the lock but unused by the default-target graph.
  Adding `ureq`+`rustls` with a *different* provider statically links two crypto
  backends (build-size/compile-time cost, not a hard failure). S2 pins the feature to
  reuse `aws-lc-rs` and verifies with `cargo tree -i aws-lc-sys` / `-i ring` — one
  deliberate `Cargo.toml` line, not a redesign.
- **Timeouts → conservative connect/read defaults (both impls).** Today's `curl` sites
  set no `--max-time`/`--connect-timeout`, so "no timeout" is technically parity — but a
  native in-process call with no timeout blocks a resolver worker thread **forever**
  with no subprocess to interrupt, which is strictly worse than the shell-out it
  replaces. Set conservative defaults (connect ≈30 s, read ≈300 s) on the primitive.
  **Accepted deviation (round 3 — code-review finding M3):** Rust's `ureq` exposes
  separate `timeout_connect`/`timeout_recv_response`/`timeout_recv_body` knobs
  (`DEFAULT_CONNECT_TIMEOUT` = 30 s, `DEFAULT_READ_TIMEOUT` = 300 s), but Python's
  `urllib.request.urlopen` exposes exactly ONE `timeout=` knob shared by connect and
  every blocking read — stdlib genuinely cannot cleanly split them without a fragile
  custom `HTTPConnection` subclass, which milpa declined to build (no workaround for a
  library limitation the RFC can instead just document). Python therefore uses one
  `DEFAULT_TIMEOUT_SECONDS = 300 s` timeout covering both phases: the safety-relevant
  hang this guards against — a stalled body transfer blocking a resolver worker forever
  — is still bounded by that single knob, and connect is additionally bounded by the
  OS's own TCP connect timeout underneath it. This is a documented, accepted asymmetry
  between the two impls, not a gap to close later.
- **Redirect hop cap → explicit `MAX_REDIRECT_HOPS = 10` (both impls, round 3 — code-
  review finding H2).** Rust's manual redirect loop (§3.8) bounds itself at 10 hops and
  raises `FETCH-DOWNLOAD-FAILED` when exceeded. Python's stdlib redirect handling has
  its own internal hop/repeat bookkeeping (`HTTPRedirectHandler.max_redirections`,
  pinned here to the same `10`), but on exhaustion it raises `HTTPError` carrying the
  LAST hop's stale 3xx status rather than a clean transport failure — left unhandled,
  the "HTTP status codes are data" rule (§3.4) would treat that as an ordinary
  response, so an infinite-redirect (or malicious looping) server would appear to
  "succeed" with zero bytes ever fetched. Python's `request()` recognizes this specific
  stdlib signal (`HTTPRedirectHandler.inf_msg`) and converts it to
  `FETCH-DOWNLOAD-FAILED`, fail-closed like Rust, without weakening the "status codes
  are data" rule for any genuine non-redirect status.
- **No rollback shim.** Once `curl`/`oras` are deleted there is no fallback path. Per
  milpa's no-legacy-support-pre-v1 discipline we do **not** build a dual-transport
  escape hatch; the real-network smoke checkpoint (§4) + pre-v1 user base + the
  existing `MILPA_MOCKED_FETCHES` injection are the mitigation.

The deep transport module (§3.3) is the foundation; every caller composes it. The
OCI-specific layer (auth challenge, manifest/blob, artifact-shape policy) sits above
it and is the same regardless — round 1's OCI findings all stand.

## 1. Motivation

milpa fetches an OCI-published dep (`ghcr.io/<repo>@sha256:…`) by shelling out to
`oras pull`. That is an ambient runtime dependency on every consumer's machine:
absent `oras` → `FETCH-OCI-PULL-FAILED` (observed live: `No such file or
directory: 'oras'`), then masked to `FETCH-ALL-FAILED` by the resolver (§3.4).
Shelling out is the coupling milpa otherwise refuses — same principle as not
evaluating nimscript, not emitting `config.nims`.

It is a **small, well-bounded** transport. milpa controls both ends; a milpa OCI
artifact is a fixed minimal shape (verified against the live softlink artifact):

```
artifactType: application/vnd.milpa.source.v1
config:  application/vnd.oci.empty.v1+json         (empty descriptor)
layers:  [ ONE: application/vnd.milpa.source.v1.tar+gzip ]   ← a single source.tar.gz
```

A native pull = acquire token → GET manifest **by digest** → select the one milpa
layer → GET that blob (capped, streamed) → verify its sha256 → hand the `.tar.gz`
to the **existing** `safe_extract`. No multi-arch index, no config-layer fetch, no
media-type zoo.

## 2. Non-goals

- **Publish/push stays `oras`** — it runs in GitHub Actions (controlled env). But
  see §3.7 (format-drift risk) — the hand-rolled puller must match what `oras
  push` emits, and that coupling needs a guard.
- **General OCI client** — no runnable-image support, no multi-arch index
  resolution, no tag→digest resolution (milpa always pulls the lockfile's pinned
  **manifest digest** — immutable + reproducible; verified against the provenance
  model in `lockfile.py`).
- **Git fetcher is out of scope.** milpa shells to `git` for git-sourced deps; git's
  wire protocol is not a bounded HTTP GET the way index/bundle/tarball/OCI are, so it
  stays a subprocess. Stated explicitly so the caller table (§0) is understood as
  complete, not silently incomplete.
- **Registry diversity is explicitly deferred and issue-filed** (not silently
  scoped out): Docker Hub (separate `auth.docker.io` token host + tight anon rate
  limits), AWS ECR / `public.ecr.aws` (non-standard credential exchange),
  self-hosted **plain-HTTP** registries, and custom-CA / corporate-proxy trust.
  v1 targets ghcr-style anonymous Bearer over HTTPS. **Consequence for the design:
  do NOT hardcode `https://`** — parameterize the scheme off the reference so the
  deferral is a config gap, not a rewrite (§3.2).
- **Private-registry credentials** — deferred to S11 (see the security note in §3.5:
  redirect-Authorization-stripping must land in v1 *because* S11 later carries real
  tokens).

## 3. Design

### 3.1 The seam does NOT exist yet — building it is the first deliverable

Round 1 corrected the original claim. Reality (re-verified round 2):
- **Python** — `OciFetcher` takes an injected `OciPull = Callable[[str, Path],
  list[Path]]` (`oci.py:165`). That is a **whole-pull** closure (designed to swap
  `oras` wholesale), the wrong altitude to unit-test the token/manifest/blob **state
  machine**, and it returns `list[Path]` for a contractually-singleton artifact. A
  finer transport seam must be built beneath it — and, per §3.2, the closure itself
  is then **removed**, not preserved.
- **Rust** — `fetch_oci` (`fetchers.rs`, ~lines 1875–1973) is a monolithic ~100-line
  free function that hardcodes `Command::new("oras")` (line 1910) **and** the
  tarball-selection/decompress/extract tail in one body, with **no injection point**.
  Its one test (`oci_pull_failure_is_pull_failed`) is a negative smoke (oras absent).
  Retrofitting it (S7) is *delete the oras head → call the new client; keep the
  extract tail* — bigger than "add an injection point," but contained to one function.
- **Rust unauthenticated GET callers** are NOT uniform: `index_cache.rs` already
  takes injected `HttpGet`/`BundleHttpGet`/`EpochCommitmentHttpGet` closures (the curl
  bodies live in `milpa-cli/src/main.rs` — 5 hand-rolled sites), but
  `dep_decl_store.rs::http_get_bytes` and `entry_bundle_store.rs::http_get_bytes` are
  **private free functions hardcoding `Command::new("curl")` with no seam** — the same
  wrong-altitude state as OCI. They need seam-building, not a drop-in swap.

So the migration **builds a transport seam before** the native calls, at several
sites — this is budgeted in the slice plan (§5), not free.

### 3.2 Two deep modules + a pure policy function — NOT a closure

Split the generic protocol from milpa's artifact policy (avoids a shallow monolith
and matches the codebase's own split instincts). Round 2 collapses the redundant
`OciPull` closure: `OciFetcher.fetch` **already** enforces "exactly one tarball"
(`oci.py:288–306`, a directory scan by `.tar.gz`/`.tgz` filename suffix). Putting the
same predicate inside a `make_native_oci_pull` closure (over manifest `layers[]`)
would leave **two** live copies of the one-tarball gate — a duplicate code path, which
milpa's non-negotiables classify as a bug. So:

- **OCI Distribution client** (`OciRegistryClient`, registry-/artifact-agnostic):
  `token → manifest → blob`, on the chosen native transport. Generic-OCI hygiene
  (manifest-**list** rejection, digest verification) lives **here**, not in the
  policy layer — a future non-milpa consumer wants it too.
- **milpa artifact policy** (`select_source_layer`, a **pure function** over a parsed
  `Manifest`, no I/O): the "exactly one layer of
  `application/vnd.milpa.source.v1.tar+gzip`" selection (the `FETCH-OCI-NO-TARBALL` /
  `FETCH-OCI-AMBIGUOUS-TARBALL` gates) — the **one** place this predicate lives.
- **`OciFetcher.fetch` composes them directly**, no intermediate closure. The
  `OciPull`/`make_oras_pull` types are **deleted**; the now-redundant filename-suffix
  scan in `OciFetcher.fetch` is removed (S6).

Illustrative Python shape:
```python
@dataclass(frozen=True)
class Manifest:                                 # parsed + generically validated
    media_type: str
    artifact_type: str | None
    layers: tuple[Layer, ...]

class OciRegistryClient:                        # generic OCI Distribution v2
    def __init__(self, http: OciHttpTransport,  # OciHttpTransport = bounded_http.BoundedHttpTransport (alias, §3.3)
                 token_cache: TokenCache) -> None: ...
    def token(self, registry, repository) -> str: ...
    def manifest(self, registry, repository, digest, token) -> Manifest:
        # verify sha256(bytes)==digest; reject a manifest LIST (`manifests[]`); parse.
        ...
    def blob(self, registry, repository, digest, size, token, *, dest: Path) -> None:
        # streamed to `dest` under the FIXED cap; verifies sha256==digest INTERNALLY
        # (the SOLE blob-digest check); raises FETCH-OCI-DIGEST-MISMATCH itself —
        # never returns an unverified file for a caller to check.
        ...

def select_source_layer(manifest: Manifest) -> Layer:   # milpa policy — the ONE tarball gate
    ...

class OciFetcher(Fetcher):
    def __init__(self, client: OciRegistryClient | None = None) -> None:
        self._client = client or OciRegistryClient(default_bounded_http(), TokenCache())
    def fetch(self, name, prov, *, dest) -> ProvenanceReceipt:
        token = self._client.token(prov.registry, prov.repository)
        manifest = self._client.manifest(prov.registry, prov.repository, prov.digest, token)
        layer = select_source_layer(manifest)           # the ONE gate
        blob = dest / "source.tar.gz"
        self._client.blob(prov.registry, prov.repository, layer.digest, layer.size, token, dest=blob)
        safe_extract(blob, dest); ...                    # unchanged extractor
```

Pull steps (per dep):
1. **Token** — `GET <scheme>://<registry>/v2/` → parse the RFC-7235
   `WWW-Authenticate` challenge → `GET <realm>?service&scope=repository:<repo>:pull`
   → read the token (accept **both** `token` and `access_token` JSON fields per the
   distribution spec). Anonymous for public; **mandatory even for public ghcr**.
   Cached per `(registry, scope)` for the resolve (§3.6). The token response is read
   under a small fixed cap (≈1 MiB) — never an unbounded stream (§3.5).

   **Challenge parsing is a specified tokenizer, fail-closed** (round 2): the header
   is an RFC-7235 list that may carry **multiple challenges**
   (`Basic realm="x", Bearer realm="y",service="z"`) with unordered, quoted params
   and possible `\"`-escapes / embedded commas inside quotes. The parser MUST: (a)
   split challenges by detecting a bare scheme token (word with no `=`) vs a
   continuing `key=value` at the same depth; (b) select the `Bearer` challenge; (c)
   if no `Bearer` challenge is present (e.g. a `Basic`-only self-hosted registry, out
   of scope for v1), fail with a **distinguishable "unsupported auth scheme"**
   `FETCH-OCI-PULL-FAILED phase="token"` — never run Bearer logic against `Basic`
   params; (d) if `realm` or `service` is missing/malformed, fail closed
   (`phase="token"`) — never forward a `None`/empty value into the next request URL.
2. **Manifest** — `GET …/manifests/<digest>` with `Authorization: Bearer` + the
   OCI+docker manifest `Accept` set, read under the same small fixed cap.
   **Verify `sha256(bytes) == <digest>`** (fetch is digest-pinned) *before* parsing.
   `manifest()` returns a parsed, generically-validated `Manifest` (not raw bytes).
3. **Positive shape check** — `manifest()` (generic) rejects a manifest **list/index**
   (`manifests[]` present instead of `layers[]`) outright — `FETCH-OCI-PULL-FAILED
   phase="manifest"`, never an uncaught `layers[0]` `KeyError`. `select_source_layer`
   (policy) then requires a single-manifest shape, `artifactType ==
   application/vnd.milpa.source.v1` (defense-in-depth), the empty-config descriptor
   (`config.mediaType == application/vnd.oci.empty.v1+json` — defense-in-depth on a
   format milpa fully owns), and **exactly one** layer of
   `application/vnd.milpa.source.v1.tar+gzip` (the NO-TARBALL / AMBIGUOUS-TARBALL
   gates); reads its `digest` + `size`. This is the first place in the codebase that
   asserts manifest shape → it needs a **normative pull-side contract** in
   `spec/registry-protocol.md` (S10), which today has **zero** WWW-Authenticate/Bearer/
   manifest-shape text; only the publish-only, non-conformance `cli-contract.md §10.3`
   mentions these media types.
4. **Blob** — `GET …/blobs/<layer-digest>`, following the registry's 307 to blob
   storage, **streamed to `dest` under the FIXED `MAX_COMPRESSED_BYTES` cap** (§3.5) —
   NOT the manifest's self-declared `size`. Use `size` only to *fail fast*
   (`min(size, MAX_COMPRESSED_BYTES)`) **when it is present and positive**; if `size`
   is absent, `0`, or negative, use `MAX_COMPRESSED_BYTES` alone (a publish-side bug
   emitting `size: 0` must not fail-fast-reject a legitimate pull). The hard ceiling
   is the same request-independent constant the tarball fetcher enforces, so an
   authentic-but-enormous (or size-lying) artifact is still bounded — and a lying-small
   `size` cannot smuggle different bytes past step 5's unconditional digest check.
5. **Verify** — done **inside** `client.blob()`: `sha256(blob) == <layer-digest>` else
   `FETCH-OCI-DIGEST-MISMATCH`. This is the **sole** blob-digest check and the only way
   `blob()` returns successfully — no caller can forget it (round 2: closes the "bytes
   reach `safe_extract` without a sha256 preimage" path structurally, in both impls).
6. **Extract** — hand `.tar.gz` to `safe_extract` (unchanged). Step 5 runs **before**
   extract, so adversarial bytes never reach the extractor without a sha256 preimage of
   the pinned digest; `safe_extract`'s zip-slip / symlink / two-layer decompression-bomb
   guards then handle a digest-matching-but-hostile archive. milpa then content-hashes
   the extracted tree vs the lockfile `content_hash`. These are **two independent,
   non-redundant checks over different hash domains** (§3.4).

### 3.3 The native transport primitive (SSOT foundation)

One `bounded_http` module per impl — the deep module every caller composes.

- **Interface — an explicit `(cap, sink)` request/response seam** (round 2 pins the
  shape; "streamed under a cap" was ambiguous and the real cap value forbids the
  obvious simplification). `MAX_COMPRESSED_BYTES` is **4 GiB** (`tarball.py:84`), so a
  primitive that always materializes the body as `bytes` is **not** safe — a 4 GiB
  in-memory buffer per concurrent blob worker is a real DoS. The body's **destination**
  is therefore a per-call parameter, not a fixed convention:

  ```python
  def request(method: str, url: str, *,
              headers: Mapping[str, str] | None = None,
              cap: int,                       # per-call: ≈1 MiB (token/manifest) vs 4 GiB (blob)
              sink: BinaryIO | Path,          # BytesIO for small/buffered callers; a Path streams to disk
              ) -> HttpResponse:              # status + response headers; body already landed in `sink`
      ...
  ```

  Small callers (index/bundle/dep-decl/entry-bundle/tarball metadata, OCI
  token/manifest) pass an in-memory `BytesIO`; the OCI blob (and tarball body) pass a
  file `Path`. One cap-enforcement implementation, one redirect handler (§3.8), one
  place tested — serving every caller without a second transport and without a 4 GiB
  buffer. The Rust `curl_streaming_transport` already has the cap-enforcing streaming
  engine; it is re-homed onto native TLS behind this signature.
- **Naming:** `OciHttpTransport` is a **local alias** for `bounded_http`'s transport
  type at OCI call sites (`OciHttpTransport = bounded_http.BoundedHttpTransport`), **not**
  a distinct OCI-only transport — there is exactly one native transport (F1).
- **Production backends**: Rust `ureq` + `rustls` (`aws-lc-rs`, `rustls-native-certs`,
  proxy-env, timeouts — §0.1); Python stdlib `urllib` (already the index/bundle
  backend, but built via `build_opener(...)` so the default `ProxyHandler` is retained
  — §0.1). Both strip `Authorization` on cross-origin redirect (§3.8) — one place,
  tested once.
- **One production backend per impl, consumed everywhere** (round 2, audit-for-
  duplication): Rust today has ~7 independent "curl a URL" reimplementations across
  `main.rs` (×5), `dep_decl_store.rs`, `entry_bundle_store.rs`, `fetchers.rs` with
  three different error-shape conventions; Python has three ad hoc `urllib` call sites
  (`index_cache.py`, `dep_decl_store.py`, `entry_bundle_store.py`, the first
  **uncapped**). Convergence is an **acceptance criterion**, not a side effect: after
  S3/S4 there is exactly **one** production HTTP function per impl, and every
  caller — CLI-layer and core-layer alike — is built from it.
- **Callers, each a thin typed adapter on top** (do NOT force one `(url)->bytes`
  signature to serve all — headers/auth/sink differ): index/bundle/dep-decl/entry-bundle
  (no auth, capped GET → `BytesIO`), tarball (capped GET → `Path` → `safe_extract`),
  OCI (Bearer + `Accept` + the manifest/blob/artifact-policy layer, §3.2).

Migrating index/bundle preserves their existing behaviors — most importantly the
index cache's **offline-fallback** (serve a stale cache when the network is down) and
the append-only ratchet reads — but "behavior-preserving" is an **enumerated contract,
not a blanket claim** (round 2): each migrated caller ships with (a) a short checklist
of the exact curl/urllib behavior being replaced (e.g. `main.rs::build_bundle_http_fn`
issues a **second** `curl -w "%{http_code}"` request purely to disambiguate 404 — a
native client exposes `status` on the first response, so that second request is
*deliberately removed*, a behavior change worth naming; `dep_decl_store.rs` uses curl's
`--max-filesize`; the Python urllib callers have **no cap today** and gain one), and
(b) characterization tests pinning the current behavior before the swap.

### 3.4 Error surface + the #198 OCI call-site (in scope)

- **Structured, not stringly:** every `FETCH-OCI-PULL-FAILED` raise carries
  `phase="token"|"manifest"|"blob"` as a **kwarg** (the codebase asserts on
  structured fields, not substrings), plus the HTTP status.
- **Digest mismatch is its own slug** (resolves original Open-Q1): mint
  **`FETCH-OCI-DIGEST-MISMATCH`** — matching the established `FETCH-SHA256-MISMATCH`
  precedent (a tampering signal, distinct remediation, not an outage; no collision
  with `TNG-BAD-OCI-DIGEST`, which is a parse-time *shape* gate, not a runtime
  content check). One `FETCH-OCI-PULL-FAILED` covers all transport phases (matching
  tarball's economy of one `FETCH-DOWNLOAD-FAILED`).
- **Two non-redundant integrity checks, different hash domains** — the blob digest
  (step 5) is `sha256` of the *compressed transported bytes* and catches a tampering
  registry/CDN pre-extract; the `content_hash` (post-extract) is `sha256` over the
  *canonicalized extracted source tree* (`spec/identity.md`) and catches a
  compromised *publisher* whose upload is self-consistent but drifts from what the
  lockfile recorded. Neither makes the other optional.
- **#198 is NOT orthogonal for OCI — it is 100%.** OCI deps have exactly one
  candidate (`_process_oci_worker`, `resolver.py:4578`; Rust `process_oci`,
  `resolver.rs:3448`), so that worker unconditionally rewraps *every* OCI error into
  `FETCH-ALL-FAILED`, and `cli.py` never surfaces the captured `inner_slug`. A
  conformance/harness fixture asserting `FETCH-OCI-DIGEST-MISMATCH` would observe
  `FETCH-ALL-FAILED`. **S9 fixes the OCI call site** (both impls): re-raise a
  definitive `MilpaError` unchanged instead of wrapping. Scoped and small (one call
  site, no mirror-candidate ambiguity); the general git-mirror #198 fix stays out.

### 3.5 Streaming cap + the stale normative exemption

`spec/plugin-contract.md §2.4.2` currently carries a NORMATIVE exemption (line 401):
*"OciFetcher downloads via `oras pull`, which does not route through milpa's HTTP layer.
The streaming compressed-byte cap does not apply."* Native pull **falsifies** this — the
OCI blob GET now routes through milpa's HTTP layer and MUST enforce the same **fixed**
`MAX_COMPRESSED_BYTES` streaming cap tarball has (an oversized-blob DoS is exactly what
§2.4.2 closes for tarball). **S10 strikes the exemption** and states the cap applies to
OCI blob fetch, and a small fixed cap to the token/manifest responses. (Under F1-broad
this is automatic — same shared engine.)

**Publish-side symmetry (S10):** `publishing.py::_extract_layer_digest` today only
reads `layers[0]["digest"]` — it does NOT reject `len(layers) != 1` or check the
media/artifact/config types. Tighten it to reject anything but the single-milpa-layer
shape, so the publisher's own tool cannot emit the ambiguous artifact the puller now
defensively rejects (defense in depth on both ends of a format milpa fully owns).

### 3.6 Concurrency: per-resolve token cache

OCI workers share the resolver's `ThreadPoolExecutor` with git/tarball workers. N OCI
deps from one registry would fire N concurrent token challenges (anon rate-limit risk —
Docker Hub is the sharp case). The cache is a **field on `OciRegistryClient`** (one
client instance per resolve), NOT a value threaded through a closure — under §3.2's
collapse there is no closure lifetime to reason about, only "one `OciRegistryClient`
lives one resolve."

- **Lock granularity is per-`(registry, scope)`, not one coarse mutex** (round 2). A
  single lock held across the token HTTP round-trip would serialize *all* OCI token
  acquisition across the resolve — including unrelated registries — defeating the
  concurrency §3.6 exists to preserve. Use lock striping / per-key double-checked
  locking (Python: `dict[(str,str), Lock]` guarded by one short-held outer lock to
  get-or-create the per-key lock; Rust: per-key `Arc<Mutex<CachedToken>>`), so
  concurrent misses on *different* keys proceed in parallel while same-key requests
  coalesce into one token fetch. Unit test: N workers on the identical `(registry,
  scope)` ⇒ exactly one token HTTP call (a stampede test).
- **Expiry is handled, not ignored** (round 2). Bearer tokens are short-lived; a token
  cached early in a long resolve can expire before a later manifest/blob GET reuses it,
  surfacing an opaque `phase=manifest` 401 that looks like an auth bug. Respect the
  token response's `expires_in` (treat an expired entry as a miss) **and** invalidate +
  refetch-once on a 401 for manifest/blob before failing. Unit test: token expires
  between manifest and blob GET ⇒ transparent refresh, not a hard failure.

Because this changes the client's construction/lifetime, it is decided in the OCI-client
slices (S5/S7), before the production swaps (S6/S8).

### 3.7 Cross-impl guarantee: the honest gap + how we close it

`MILPA_MOCKED_FETCHES` is a **whole-`Fetcher` replacement** (both impls), keyed by
`oci_key(registry,repository,digest)`, staging pre-extracted `content/` — it bypasses
`OciFetcher`/`fetch_oci` entirely. So:
- **Happy-path extract+identity** OCI conformance fixtures need **no new harness
  mechanism** (the `fixture-450` pattern already works) — S6's identity half is ~zero
  new work.
- **But** the token/manifest/blob state machine, phase-errors, and digest-mismatch are
  **structurally invisible to the shared corpus and the differential harness** — Python
  and Rust could drift there with no automatic catch. This is stated as a **known,
  accepted limitation**, not hidden.
- To recover cross-impl parity at the unit tier, the two OCI-client slices (S5/S7) both
  replay a **shared canned-transport contract fixture** — a checked-in ordered list of
  `{method,url,status,headers,body}` request/response pairs (a lower tier than
  `conformance/spec-v1/`) that both impls' unit tests drive through their injected
  transport. Same bytes on both sides → same behavior by construction. This is the only
  cross-impl guarantee the transport gets; the RFC commits to it explicitly.
- **The fixture is pinned infrastructure, not improvised** (round 2): it lives at
  `conformance/oci-transport/` (a sibling of, and explicitly **outside**,
  `conformance/spec-v1/` — it is a unit-tier contract, not a spec-conformance fixture),
  with a JSON schema fixed in **S0** so S5 (Python, first) does not invent an ad hoc
  shape that S7 (Rust) must reverse-engineer weeks later. It is authored once, read by
  both impls.
- The fixture is single-threaded replay and therefore **cannot** exercise the
  concurrent token-cache behavior (§3.6) — those (stampede, expiry) are impl-local
  concurrency unit tests, called out so the gap is not assumed-covered.

### 3.8 Redirect handling is a security BUILD, not a "confirm"

Verified against stdlib source: `urllib.request`'s default `HTTPRedirectHandler`
**forwards `Authorization` verbatim** to a redirect target; `reqwest`/`ureq` default the
same. ghcr 307s blob GETs to a CDN host — so the naive path **leaks the bearer token to
a third party** (materially worse once S11 carries a real `GITHUB_TOKEN`).

- **The strip predicate is origin equality — `(scheme, host, port)` — not host alone**
  (round 2). A host-only predicate misses a same-host **scheme downgrade**
  (`https://ghcr.io/…` → `http://ghcr.io/…`, identical host) which would forward the
  bearer token in cleartext, and misses a port change (`ghcr.io:443` →
  `ghcr.io:9443`).
- **The policy is MONOTONIC, not per-hop** (round 3 — code-review finding M2). Strip
  `Authorization` on the **first** hop whose target's `(scheme, host, port)` does not
  match the original request's origin, and **never restore it on a later hop**, even
  one whose origin happens to match the original again. A per-hop re-check (recompute
  origin equality against the original request on every redirect independently) would
  RESTORE `Authorization` on a 3+-hop chain A(original, carries the credential) →
  B(cross-origin, correctly stripped) → C(back on A's exact origin) — re-comparing C
  against A in isolation sees "same origin" and forwards the token, even though B's
  cross-origin hop already proved the chain left milpa's control once. Monotonic is
  strictly safer at negligible cost: both impls latch a "stripped" flag the first time
  any hop is cross-origin and never clear it for the remainder of that request's
  redirect chain.
- **Test matrix** (§4): cross-host redirect strips (the round-1 case), same-host-
  scheme-downgrade strips (round 2), **and** a 3-hop chain that returns to the original
  origin (round 3) — assert `Authorization` stays absent on the hop back at the
  original origin, not just on the intermediate cross-origin hop.
- **Why the strip is safe for the ghcr common case** (round 2, was implicit): ghcr's
  blob-redirect `Location` carries **self-contained query-string authentication** (a
  presigned CDN URL); the anonymous CDN GET after stripping succeeds independent of the
  original Bearer token. The real-network smoke checkpoint (§4) is the standing
  verification that this holds.

## 4. Testing

Two automated tiers + one manual checkpoint (they are NOT one fixture format):

- **Unit (impl-local, the ONLY place transport phases are covered):** drive the injected
  finer transport with the shared canned-transport fixture (§3.7). Assert (a) happy pull
  extracts; (b) each phase failure → the right structured slug/`phase=`; (c)
  manifest/blob digest mismatch → `FETCH-OCI-DIGEST-MISMATCH` fail-closed; (d)
  cross-host **and same-host-scheme-downgrade** redirect strips `Authorization`; (e) blob
  over the cap → the size-exceeded failure; (f) a manifest **list** is rejected; (g)
  WWW-Authenticate: multiple challenges, non-Bearer-only (unsupported-auth clean fail),
  missing realm/service (fail-closed); (h) `size` absent/0/negative → cap-alone, no
  spurious reject; (i) token-cache stampede (one HTTP call per key) and expiry
  (transparent refresh); (j) proxy-env honored.
- **Conformance (`conformance/spec-v1/` + `harness/`):** the existing whole-fetcher
  `oci_key` mock (fixture-450 pattern) for extract+identity + lockfile/resolution
  behavior. Gate on `harness/` (S4/S8 lesson). This tier does **not** and structurally
  cannot cover transport phases — do not claim it does.
- **Real-network smoke — a MANUAL, Corey-run checkpoint** (round 2: NOT a slice-
  completion criterion). `/tdd` slices must be hermetic and repeatable in an agent loop;
  a live pull against `ghcr.io/coreyleavitt/softlink@sha256:…` is neither (and this
  environment's outbound network is restricted). So, exactly like CLAUDE.md's "Real
  fresco verification": slice-complete = `pytest`/`cargo test` green (hermetic,
  agent-checkable); the smoke — pull the live softlink artifact, confirm `content_hash`
  matches, re-run the `goodtogo` project (softlink + proptest) that failed on absent
  `oras` — is a **separate manual checkpoint Corey runs before calling the swap
  shippable**. It is the only test exercising the real publish→pull round trip (§3.7).

## 5. Slices (tdd-sized) — F1-broad, transport-primitive-first, one impl per slice

Foundation first, then migrate each caller behavior-preservingly, then OCI's own layer
on top, then the swaps + spec. **One impl per slice** (multi-impl discipline: there is
no single RED-GREEN cycle across `pytest` + `cargo test`, so a "both impls" slice is two
cycles wearing one ID). Round 2 split the round-1 "both impls" S1/S2 accordingly.

- **S0 — spec-first + fixture infra (spec/infra-only, do first).** Add
  `FETCH-OCI-DIGEST-MISMATCH` to `spec/errors.md`. Record F1/F2 + the §0.1 transport
  sub-decisions in the spec. State the transport-phase unit-tier-only / no-harness-
  guarantee limitation (§3.7) as a deliberate decision. **Pin the canned-transport
  fixture**: create `conformance/oci-transport/` and fix its JSON schema
  (`{method,url,status,headers,body}` ordered list) so both OCI-client slices author
  against one shape.
- **S1 — Python `bounded_http` primitive.** The injectable capped `(cap, sink)`
  request/response transport (§3.3) built via `build_opener` (retains `ProxyHandler`),
  with the cross-origin `Authorization`-stripping redirect handler (§3.8), conservative
  timeouts, and the `BytesIO`/`Path` sink split. Unit tests incl. cap-exceeded,
  cross-host + same-host-downgrade redirect, proxy-env. No caller migrated yet.
- **S2 — Rust `bounded_http` primitive.** Introduce `ureq`+`rustls` (F2), pinned to
  `aws-lc-rs` + `rustls-native-certs` + proxy-env + timeouts (§0.1; verify with `cargo
  tree -i aws-lc-sys`/`-i ring`); the streaming cap re-homed from
  `curl_streaming_transport` onto native TLS behind the same `(cap, sink)` seam; the
  same redirect handler. Mirror S1's unit tests. No caller migrated yet.
- **S3 — migrate Python unauthenticated GET callers onto S1.** tarball fetcher (curl
  today) + the three urllib call sites (`index_cache`, `dep_decl_store`,
  `entry_bundle_store`) → the one primitive; **add caps to the uncapped urllib
  callers**; delete the curl shell-out. Acceptance: exactly one production Python HTTP
  function, consumed everywhere. Behavior-preserving per §3.3's enumerated checklist
  (offline-fallback + ratchet reads bit-identical); characterization tests first. Gate
  on `harness/`.
- **S4 — migrate Rust unauthenticated GET callers onto S2.** All 8 curl sites:
  `fetchers.rs::curl_streaming_transport` (tarball), the 5 `main.rs` closures (index
  ~4399, epoch-commitment ~3566, bundle ~3741 + its second status-check curl ~3749,
  index-candidate ~3382), and — **seam-first, they have none today** —
  `dep_decl_store.rs::http_get_bytes` + `entry_bundle_store.rs::http_get_bytes`. Collapse
  to **one** production `ureq` backend consumed by both `milpa-cli` and `milpa-core`;
  drop the bundle 404-disambiguation second request (native `status`). Delete every
  curl `Command`. Behavior-preserving per §3.3; gate on `harness/`. (May sub-slice by
  call site given the seam gap.)
- **S5 — Python OCI client on the primitive.** `OciRegistryClient`
  (token/manifest→`Manifest`/blob-verifies-internally); the WWW-Authenticate tokenizer
  (§3.2 step 1, all cases); `select_source_layer` pure policy fn; the per-`(registry,
  scope)` striped token cache with expiry/401-refresh (§3.6). Author + drive the shared
  canned-transport fixture; unit tests (all §4 cases). Not the default yet.
- **S6 — Python OCI swap.** `OciFetcher.fetch` composes the client + `select_source_layer`
  directly; **delete `OciPull`, `make_native_oci_pull`, `make_oras_pull`, and the
  redundant filename-suffix scan**. `impls/python` pytest green. Manual real-network
  smoke checkpoint (§4) before shippable.
- **S7 — Rust OCI client + retrofit.** Retrofit `fetch_oci`: delete the oras-invocation
  head, keep the decompress/extract tail; build the injectable `OciRegistryClient`
  mirroring S5 (separate impl per discipline) against the **same** canned-transport
  fixture; striped token cache; WWW-Auth parser; `select_source_layer`. Not default yet.
- **S8 — Rust OCI swap.** Native pull replaces `Command::new("oras")` (delete it).
  `./dev-rust test --workspace` green. Manual smoke checkpoint before shippable.
- **S9 — #198 OCI call-site + error taxonomy (both impls).** Fix `_process_oci_worker` /
  `process_oci` to re-raise definitive errors (§3.4); structured `phase=` +
  `FETCH-OCI-DIGEST-MISMATCH`; confirm the `oci_key` mocked-fetches happy-path fixtures
  still pass (regression-only — cannot cover transport logic).
- **S10 — spec + docs.** (a) Normative pull-side OCI manifest-shape section in
  `spec/registry-protocol.md` (§3.2 step 3) **that also names token/manifest/blob as the
  normative phase decomposition** (round 2 — forces both impls' `phase=` boundaries to
  align, not just the wire bytes). (b) Strike the `plugin-contract.md §2.4.2` oras
  cap-exemption; require the fixed cap on OCI blob + small cap on token/manifest (§3.5).
  (c) Rewrite the `TNG-BAD-OCI-DIGEST`/`TNG-UNSAFE-OCI-FIELD` rationale (threat is now
  malformed URL/header, not `oras` argv). (d) Tighten publish `_extract_layer_digest`
  (§3.5). (e) Fix the softlink/proptest/nim-z3 workflow "consumer oras pull" comments —
  and any spec text asserting milpa shells out to `curl`/`oras` on the consumer side.
  `spec/conformance-fixtures.md §2.3.5` is deliberately **unchanged** (§3.7). Spec-edit
  bar, not docs.
- **S11 (deferred) — private creds + registry diversity.** File the follow-up issue now
  (Docker Hub / ECR / self-hosted plain-HTTP / custom-CA / proxy), per defer-file-now.

## 6. Resolved open questions (was §6)

- **Q1 digest-mismatch slug** → **mint `FETCH-OCI-DIGEST-MISMATCH`** (§3.4).
- **Q2 shared HTTP seam** → **resolved as F1/F2 (§0)** — the load-bearing fork.
- **Q3 conformance transport injection** → resolved: whole-fetcher mock stays for
  identity; transport phases are **unit-tier + shared canned-transport fixture** (pinned
  at `conformance/oci-transport/`, §3.7), with the differential-harness gap stated.
- **Q4 redirect** → resolved: it is a **security build** — strip `Authorization` on
  cross-**origin** `(scheme,host,port)` redirect (§3.8), not a confirm.

## 7. Escalations — RESOLVED

- **F1 → BROAD** (Corey 2026-08-04). One native in-process transport for all consumer
  fetches; delete `oras` **and** `curl`.
- **F2 → `ureq`+`rustls` (Rust) / `urllib` (Python)** (Corey 2026-08-04).
- **Round 2 sub-decisions** (§0.1) — proxy-env, `rustls-native-certs`, `aws-lc-rs`,
  timeouts, no-rollback-shim — goal-determined under milpa's non-negotiables
  (audit-for-duplication, single-source-of-truth, no-legacy-pre-v1), applied directly.

**No open forks remain.** Both architect rounds are complete and their fixes are in the
document. The RFC is ready for `/tdd` (stage 3).
