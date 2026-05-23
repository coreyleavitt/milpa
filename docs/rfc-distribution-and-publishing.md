# RFC: distribution + publishing — OCI artifacts as the substrate

**Status**: Proposed (companion to `rfc-pluggable-fetchers.md` and `rfc-content-addressed-identity.md`)
**Author**: Corey Leavitt
**Date**: 2026-05-23

## Why this RFC exists

milpa v0 fetches packages exclusively via git clone against URLs
listed in `nim-lang/packages` (the existing Nim registry) or in
manifest-direct URL deps. That works for v0 but it inherits every
limitation of the nim-lang/packages model: a JSON pointer table
manually PR'd by maintainers, with no artifact hosting, no upload
API, no author identity beyond "whoever owns the git repo," no yank,
no signing, no immutability guarantee, no search.

The content-addressed-identity RFC commits milpa to identity-as-
content-hash and provenance-as-multi-valued metadata. The pluggable-
fetchers RFC commits milpa to transport extensibility (tarball,
mercurial, fossil, OCI, IPFS). Both RFCs imply a distribution story
richer than "git URL in a JSON file" — but neither commits milpa to
a specific publishing substrate.

This RFC closes that gap. It commits milpa to **OCI artifacts as the
canonical distribution substrate** for milpa-aware packages,
delegates registry infrastructure to existing OCI hosts (GHCR,
Docker Hub, Harbor, Zot, etc.), and defines an optional future UX
layer ("milpa registry frontend") that operates as a discovery
surface on top of that substrate. It explicitly does NOT commit
milpa to building or operating a from-scratch registry.

The bare-git nim-lang/packages model remains the bootstrap
discovery mechanism. milpa-aware packages are additive: they ship a
`milpa.kdl` alongside their `.nimble`, register on nim-lang/packages
as today, and additionally publish their tagged source as an OCI
artifact. Consumers who use nimble see no change; consumers who use
milpa benefit from content-addressing, attestation, and federation
at the artifact layer.

## What nim-lang/packages provides today

A single JSON file at `github.com/nim-lang/packages` whose entries
look like:

```json
{"name": "results", "url": "https://github.com/arnetheduck/nim-results", "method": "git"}
```

That is the entire registry surface. "Publishing" means submitting
a PR adding an entry. The actual "package" is whatever's at `git
clone <url> --branch <tag>`. Versions = git tags. No artifacts are
hosted by the registry; no upload API exists; no author identity
beyond git push rights to the listed repo.

The honest gap list, against modern dep-manager registries:

1. **Force-push to a tag rewrites bytes** — no immutability guarantee
2. **No namespace ownership** — flat global names; squatting possible
3. **PR curation latency** (weeks sometimes) — slows new package onboarding
4. **No mirror infrastructure** — upstream git URL dies → package vanishes
5. **No author attestation** — can't prove "this content was published by this person"
6. **No search / discovery** beyond grepping JSON
7. **No yank / recall** — bad releases can't be marked do-not-use
8. **Federation only via git mirroring** — corporate / sovereign / archival use cases require bespoke infrastructure

(1), (4), and (5) are addressable from milpa's client side via the
content-addressed-identity RFC + the multi-provenance lockfile
(Phase D). (2), (3), (6), (7), (8) require registry-side machinery
no client-side cleverness fixes.

## Prior art

**PyPI** hosts wheels and sdists, has an upload API (`twine upload`),
went through a multi-year migration from `setup.py` to
`pyproject.toml` because PyPI is a real artifact host with legacy
upload semantics. Operated by the PSF; donated infrastructure;
multimillion-dollar storage + bandwidth budget.

**crates.io** built by the Rust core team alongside the language.
Single source of authority; works because Rust was new at the time
and there was no incumbent registry to compete with. Hosts `.crate`
files; `cargo publish` uploads them.

**npm** built into the language ecosystem from the start, then
forked off as npm Inc., later acquired by GitHub (Microsoft) in 2020.
Hosts tarballs; massive operational scale; has had several supply-
chain incidents (event-stream, ua-parser-js, colors.js) that
reshaped how the JS ecosystem thinks about attestation.

**Helm** distributes charts as **OCI artifacts** since v3 (2021),
abandoning the per-language registry model for the OCI distribution
spec. Authors push to any OCI registry; consumers pull by name or
digest. This is the closest existing precedent for what this RFC
proposes — a language ecosystem (Kubernetes deployments) using OCI
as its distribution substrate.

**WASM** community via the `wasm-pkg-tools` project distributes
modules as OCI artifacts. Same pattern as Helm.

**ORAS** itself (the OCI Registry As Storage project) demonstrates
the general pattern: arbitrary artifact types stored as OCI manifests
with custom layer media types, distributed via existing OCI
registries. Used by CNCF projects for non-container assets across
the board.

The trend among newer ecosystems: stop building per-language
registries from scratch; use OCI Artifacts as a generic content-
addressed substrate and add only the discovery/UX layer specific to
your domain.

## The principle

> milpa's distribution substrate is **OCI artifacts**. Publishing
> means `oras push <registry>/<author-namespace>/<package>:<version>`
> to any OCI-compliant registry; fetching means pulling that artifact
> by digest. Author identity is the OIDC-verified namespace on the
> registry (e.g., the author's GitHub username on ghcr.io). Content-
> addressing, immutability, federation, and attestation are inherited
> from the OCI ecosystem rather than rebuilt.

A future optional UX layer ("milpa registry frontend") may add
search, package pages, READMEs, dependency-graph visualization, and
ecosystem conventions on top of the OCI substrate. The UX layer is
**separable** from the substrate decision and is deferred until
adoption justifies it.

The nim-lang/packages registry remains the bootstrap discovery
table. Its entries gain an optional `oci` field (convention proposed
via a PR to nim-lang/packages once F6 ships; no schema change
required on their side beyond adding a recognized key). When the
field is present, milpa fetches via OCI; otherwise it falls back to
the existing `method: "git"` path.

## Why OCI specifically

The decision space considered (and rejected, see next section):
GitHub Releases, a hash-index repo, a built-from-scratch hosted
registry. OCI wins on the structural axes that align with milpa's
existing commitments.

### Content-addressing at the protocol layer

Pulling `ghcr.io/author/pkg@sha256:abc...` is content-addressed in
the URL itself. The OCI distribution spec mandates that pulling by
digest serves bytes whose hash matches the digest — pre-fetch
integrity is a protocol-level guarantee, not a client-side
afterthought. For a system whose identity model rests on content
addressing (per `rfc-content-addressed-identity.md`), having the URL
**be** the hash is structural alignment, not cosmetic preference.

milpa's identity invariant still holds: identity is computed by
milpa from the extracted source tree, not taken from the registry's
digest. The OCI digest is provenance receipt; the recomputed
content_hash is identity. The two should agree for honest registries
(disagreement = registry served wrong bytes, which the protocol
prevents).

### Industry-standard supply-chain attestation

Cosign + Sigstore is the supply-chain-attestation stack for OCI
artifacts. The flow:

1. Author publishes artifact: `oras push ghcr.io/author/pkg:v1.0`
2. Author signs: `cosign sign ghcr.io/author/pkg@sha256:<digest>`
3. Cosign generates an ephemeral signing key bound to the author's
   OIDC identity (GitHub Actions OIDC token, Google OIDC email, etc.)
4. The signature lands in the Rekor transparency log (Sigstore
   public-good infrastructure)
5. The signature is itself stored as an OCI artifact alongside the
   signed one
6. Any consumer verifies: `cosign verify --certificate-identity=...
   ghcr.io/author/pkg@sha256:<digest>` — checks the signature, looks
   up the Rekor entry, validates the OIDC identity

This is the model used by `kubernetes/`, `prometheus/`, `helm/`, and
most CNCF projects. It is the basis for SLSA provenance attestations,
SBOM-via-OCI-referrer, in-toto layout verification. By choosing OCI
as the substrate, milpa inherits this entire ecosystem for free.

Phase E of the content-addressed-identity RFC anticipates sigstore
attestation; OCI is the natural substrate for that work. Choosing
any non-OCI distribution layer would require building a bespoke
attestation pipeline that doesn't interoperate with the broader
supply-chain-security ecosystem.

### Federation as a first-class concept

Corporate users behind firewalls already run OCI pull-through caches
(Harbor, Zot, JFrog Artifactory). When their CI pulls a dep, the
cache fetches from upstream once and serves from local thereafter.
With OCI as the substrate, this works the day they install milpa,
with zero coordination on our part.

Same story for:

- **Sovereign-cloud users** who can't reliably reach github.com or
  ghcr.io: regional OCI registries can mirror upstream artifacts
- **Users in regions with restricted access to upstream registries**:
  regional pull-through caches serve from local mirrors; bytes are
  bytes regardless of network topology
- **Archival mirrors**: `oras copy <upstream> <local>` is one
  command, preserves digests, gives byte-identical artifacts
- **Air-gapped environments**: bulk-download all needed artifacts to
  a local Zot instance, configure milpa to use it as the registry

None of these require any milpa-side infrastructure. They're
deployment patterns that already work for every OCI-using ecosystem.

### Multi-vendor portability

`crane copy ghcr.io/author/pkg docker.io/author/pkg` preserves the
digest. If a registry triples its pricing or shuts down, every
milpa package published there can migrate atomically — same digest,
same identity, same lockfile entries. No URL rewriting; no consumer-
side changes.

This matters less for individual authors and more for the long-term
health of the ecosystem. Locking nim's distribution layer to any
one vendor's goodwill (GitHub, AWS, etc.) for 10+ year horizons
would be a structural commitment we have no need to make.

### Bandwidth and DDoS resilience

GHCR sits behind GitHub's CDN. Docker Hub sits behind Akamai /
Cloudflare. ECR sits behind CloudFront. These eat traffic spikes
at scale that anything we'd operate ourselves would crater under.
We can't compete on infrastructure hardening; we should be
downstream of operators who have it.

### Author identity via existing OIDC infrastructure

Authors publish to their own namespace on their preferred registry.
On ghcr.io, the namespace is the author's GitHub username,
authenticated via GitHub Actions OIDC (in CI) or a personal access
token (locally). On Docker Hub, namespace = Docker Hub username.
On a corporate Harbor, namespace = corporate identity.

milpa is **not in the trust path** for author identity. The
registry verifies pushes against its own auth; consumers verify
artifacts against the author's signing identity (via cosign). milpa
is just a client that pulls bytes and computes identity.

This eliminates an entire class of "central registry compromised →
all packages compromised" risk that PyPI / npm have faced.

## Why not the alternatives

### Why not GitHub Releases

GitHub Releases would work for a github-only audience today. The
hard advantages favor OCI on the axes that compound long-term:

| Axis | GitHub Releases | OCI Artifacts | Winner |
|---|---|---|---|
| Free hosting at scale | yes | yes (GHCR / Docker Hub / ECR) | tie |
| Author auth | GitHub OIDC | GitHub OIDC (or any provider) | tie when both on GitHub |
| Immutability | release attachments stable; author can delete + reupload | cryptographic: pull-by-digest is unforgeable | OCI |
| URL contains the hash | no; bring-your-own sha256 | yes; `@sha256:...` is the URL | OCI |
| Pre-fetch integrity | client-side only | registry-level (protocol mandate) | OCI |
| Native attestation | bespoke (.sig file) or GitHub-specific "artifact attestations" only verifiable on GitHub | cosign + Sigstore, transparency-log-backed, verifiable by anyone | OCI |
| Federation / mirroring | GitHub-locked; if github is down, packages unreachable | standard pull-through caches; vendor-neutral | OCI |
| Multi-vendor portability | locked to one vendor | CNCF-standardized distribution spec | OCI |
| Supply-chain ecosystem alignment | weak; GitHub-specific tooling | strong; SBOM/SLSA/in-toto all assume OCI | OCI |
| Tooling friction for the author | zero (they already upload to releases) | learn `oras` (or thin `milpa publish` wrapper) | GitHub |
| Discoverability UX (today) | repo's Releases tab is source-shaped | container-registry UIs are container-shaped | GitHub |

The "OCI is container-shaped" objection is real but cosmetic. The
underlying semantics — digest-keyed immutable blob + cryptographic
attestation + namespace-owned-by-author — match source distribution
exactly. The mental-model friction for authors is one-time and
small; the structural advantages compound for the lifetime of the
ecosystem.

For an ecosystem that intends to make supply-chain claims (per the
content-addressed-identity RFC's Phase E and the multi-impl
strategy's verifiable-conformance work), GitHub Releases as the
substrate would require either skipping the modern attestation
stack or building bespoke layers that don't interoperate with the
broader ecosystem.

### Why not a hash-index repo

A "hash-index repo" — a JSON file in a git repo that augments nim-
lang/packages entries with content_hash per release — was an
intermediate option considered and rejected. Its problems on
inspection mirror nim-lang/packages's own:

- **Auth**: whoever has merge rights to the index repo decides what's
  true. Either centralized (us, no scaling) or PR-curated (same
  curation latency as nim-lang/packages).
- **Attestation**: a bot we operate computes hashes; trust = "do you
  trust the bot operator?" There's no cryptographic chain back to
  the actual package author. Just shifts the trust authority from
  the original registry to us.
- **DDoS**: GitHub raw-content URLs are rate-limited; at scale we'd
  need a CDN, which means operating infrastructure anyway.
- **Author identity**: still no verification that an entry was added
  by the rightful package owner. Recreates nimble's gap.
- **Federation**: index is one repo; mirrors have to mirror the
  whole repo.

This option provides marginal improvement (precomputed hashes) while
inheriting the architectural sameness of nim-lang/packages. It is
not "structurally cleaner because we don't operate a service" — it
silently re-centralizes the trust authority while adding little.
Discarded.

### Why not build a hosted PyPI-clone from scratch

Considered. The operational burden is the disqualifier: storage,
bandwidth, abuse handling, GDPR compliance, takedowns, terms of
service, namespace dispute policy, name-squatting policy, legal
exposure, ongoing curation labor. PyPI eats millions in storage
costs annually with the PSF backing it; crates.io operates within
the Rust Foundation; npm became GitHub's after IPO and exit. None
of these models are within reach of an individual project; building
one from scratch competing against nim-lang/packages as an incumbent
would be an uphill adoption fight with operational costs that
compound forever.

The right pypi-clone analogue, if we ever build one, is **a UX
frontend on top of an OCI substrate** — much smaller surface (web
app + metadata index + discovery), with storage / DDoS / attestation
delegated to OCI registries underneath. That option is captured in
the optional Phase 4 below; it is not in this RFC's near-term
commitments.

## The model

### Author side (publishing)

In a release CI step (GitHub Actions example, Sigstore-friendly):

```yaml
- uses: oras-project/setup-oras@v1
- uses: sigstore/cosign-installer@v3
- name: Publish to GHCR
  run: |
    # Pack the source tree into a tarball.
    tar -czf "$RUNNER_TEMP/${PACKAGE}-${TAG}.tar.gz" \
        --exclude=.git \
        -C "$GITHUB_WORKSPACE" .

    # Push as an OCI artifact under the author's namespace. The
    # manifest's artifactType is the milpa-specific kind; the layer's
    # media type carries the compression encoding.
    oras push "ghcr.io/${{ github.repository_owner }}/${PACKAGE}:${TAG}" \
        --artifact-type "application/vnd.milpa.source.v1" \
        "$RUNNER_TEMP/${PACKAGE}-${TAG}.tar.gz:application/vnd.milpa.source.v1.tar+gzip"

    # Sign via Sigstore keyless flow — OIDC identity from GitHub Actions
    DIGEST=$(oras resolve "ghcr.io/${{ github.repository_owner }}/${PACKAGE}:${TAG}")
    cosign sign --yes "ghcr.io/${{ github.repository_owner }}/${PACKAGE}@${DIGEST}"
```

A `milpa publish` thin wrapper bundles this as a one-liner. The
author runs `milpa publish` in CI; everything above is done for them
with reasonable defaults. Authors who want manual control can use
the `oras` + `cosign` tools directly.

Two media types appear in the push:

- `application/vnd.milpa.source.v1` — the manifest `artifactType`.
  Signals "this OCI artifact is a milpa source release," letting
  consumers distinguish from arbitrary OCI artifacts at the same
  registry path (a registry can host containers, Helm charts, and
  milpa source releases under the same namespace).
- `application/vnd.milpa.source.v1.tar+gzip` — the layer
  `mediaType`. Carries the compression encoding so the fetcher
  knows how to extract.

Both follow the `vnd.<vendor>.*` OCI/IANA convention for vendor-
specific types.

### Consumer side (fetching)

The pluggable-fetchers RFC (`rfc-pluggable-fetchers.md`) defines
F6 OciFetcher. The fetcher implements the existing Fetcher protocol:

```python
@dataclass(frozen=True)
class OciProvenance(Provenance):
    registry: str        # e.g. "ghcr.io"
    repository: str      # e.g. "author/package"
    digest: str          # "sha256:abc..." — content-addressed pin

@dataclass(frozen=True)
class OciReceipt(ProvenanceReceipt):
    manifest_digest: str   # what the registry served (matches the
                           # requested digest under honest operation)
    artifact_type: str     # for diagnostic / yank-aware tooling
    pulled_from: str       # which registry endpoint served the bytes
                           # (may differ from declared if a pull-through
                           # cache was used) — diagnostic only

class OciFetcher:
    def can_handle(self, p): return isinstance(p, OciProvenance)
    def fetch(self, name, p, *, dest) -> OciReceipt:
        # 1. Pull artifact by digest from registry (or any mirror in
        #    the OCI pull-through chain)
        # 2. SafeExtractor unpacks the tarball into dest
        # 3. Return receipt; registry computes content_hash from dest
```

Identity invariant from F1 is preserved: the fetcher returns only a
receipt; the registry computes content_hash from the extracted bytes.
The OCI digest is provenance; the recomputed content_hash is
identity. They agree under honest operation.

### Manifest grammar

```kdl
deps {
    chronos oci="ghcr.io/coreyleavitt/chronos" digest="sha256:abc..."
}
```

Two properties: `oci=` identifies the registry-and-repository pair
and selects the OCI fetcher; `digest=` is the content-addressed pin
and is required. Both follow the existing grammar shape from W1/F1
(`git=...`, `local=...`).

No human-readable `tag=` is carried in the manifest. The digest is
the canonical identifier; `oras` or registry web UIs let users
discover which tag-label a digest was published under. Carrying tag
in the manifest would create "did the dev write a stale tag?"
confusion without adding fetch capability. The digest is enough.

### Lockfile

LockedDep entries gain a new `source` format: `oci:<registry>/<repo>@<digest>`.
The lockfile schema is opaque to the source string (per F1), so no
schema bump. Future Phase D multi-provenance work naturally
expresses "this identity is available from OCI registry X, OCI
registry Y, and git URL Z" as multiple provenance entries.

### Attestation verification

Optional in v1; opt-in via a manifest-level setting:

```kdl
verification {
    require_attestation true
    trusted_identity_pattern "https://github.com/coreyleavitt/.*"
}
```

When enabled, `milpa fetch` invokes cosign verify against each OCI-
sourced artifact; rejects deps whose signatures don't match the
trusted identity pattern. Off by default in v1; eventual default-on
once the publishing ecosystem matures.

### nim-lang/packages integration

A proposed convention (to be PR'd to nim-lang/packages once F6
ships) adds an optional `oci` field to entries:

```json
{
    "name": "results",
    "url": "https://github.com/arnetheduck/nim-results",
    "method": "git",
    "oci": "ghcr.io/arnetheduck/nim-results"
}
```

When the field is present, milpa's registry path can resolve a name
to an OCI URL and fetch via F6. When absent, milpa falls back to
the existing git path. Packages that don't opt into OCI publishing
continue to work exactly as today via git fetch.

This requires no schema enforcement on nim-lang/packages's side —
unknown fields are tolerated. The convention is proposed via docs
and example PRs.

## Federation and mirroring

The OCI distribution spec defines pull-through caches as a standard
operating pattern. A corporate user wanting to mirror milpa
artifacts deploys (e.g.) a Zot or Harbor instance configured as a
pull-through cache against ghcr.io. milpa consumers configure their
registry endpoint via standard OCI client configuration
(`~/.docker/config.json` is the canonical location, used by `oras`,
`docker`, `podman`, and most OCI clients); milpa uses whichever
endpoint the client resolves to.

No milpa-side infrastructure is required. The mirroring story is
just "deploy any pull-through-cache OCI registry; configure your
OCI client to use it." This is well-understood deployment work.

For sovereign / air-gapped use cases:

```bash
# Mirror an upstream artifact to a local registry
oras copy ghcr.io/coreyleavitt/chronos:v0.5.0 \
         private-registry.corp.local/coreyleavitt/chronos:v0.5.0

# Then configure milpa to resolve the OCI host via standard OCI client
# auth/config — no milpa-specific config needed
```

## Phasing

Each phase is independently useful and shippable.

### Phase 1: F2 TarballFetcher (prerequisite)

Per `rfc-pluggable-fetchers.md` Phase F2 (#41). Generic tarball
fetcher with pre-fetch sha256 verification. Establishes the
SafeExtractor utility that F6 will reuse. Useful immediately for
non-OCI tarball deps and for the hash-index fallback path during
transition.

**Estimated effort**: 2-3 days. Already filed.

### Phase 2: F6 OciFetcher (#45)

Per `rfc-pluggable-fetchers.md` Phase F6, already filed as #45.
Pulls OCI artifacts by digest from any OCI-compliant registry.
Reuses SafeExtractor (#48) from F2. Returns an OciReceipt; registry
computes content_hash from the extracted bytes. Acceptance criteria
to be refined per this RFC (specifically, the milpa-source
artifactType convention and the dual-media-type push pattern).

**Estimated effort**: 4-6 days, plus an OCI-semantics learning
curve.

### Phase 3: `milpa publish` helper + manifest grammar extension

Thin wrapper around `oras push` + manifest generation. Defaults
target GHCR with the author's namespace (auto-detected from `git
remote` or explicit config). Optionally signs via cosign if cosign
is on PATH.

Manifest grammar extension: `oci="..."` and `digest="..."`
properties on dep nodes. Round-trips through format/parse.

**Estimated effort**: 3-5 days. To be filed.

### Phase 4 (OPTIONAL, deferred): milpa registry frontend

A web app + metadata index providing search, package pages, READMEs,
dependency-graph visualization, and ecosystem conventions on top of
the OCI substrate. Authors publish to their own OCI registry as in
Phase 3; the frontend indexes published packages (via OCI registry
catalog API or via opt-in registration) and provides the UX layer
that GHCR's container-shaped UI doesn't.

**Not committed by this RFC.** Deferred until adoption justifies
the operational investment. The substrate decision (OCI) is
correct regardless of whether the frontend ever ships.

If/when Phase 4 ships, the frontend operates as:

- **Metadata DB**: package name → known OCI URLs + versions +
  attestation status. Authors register via OIDC; verified against
  their OCI namespace.
- **Discovery**: search by name, by dependency, by attestation
  status, by recently-published.
- **Package pages**: README rendering, dep graph, version history,
  download counts.
- **Storage**: delegated to OCI registries underneath.
- **Authentication**: OIDC for publishing; anonymous for browsing.
- **DDoS**: same model as PyPI — CDN in front of the metadata
  service; artifact serving delegated to OCI hosts.

The frontend is a separable concern that can be added or replaced
without breaking the substrate.

### Phase 5: Attestation enforcement (Sigstore verification)

Manifest opt-in flag `verification.require_attestation`. When set,
`milpa fetch` runs cosign verify against every OCI-sourced dep;
rejects unsigned or mis-attested artifacts. Default off in v1;
eventual default on once the publishing ecosystem matures.

**Estimated effort**: 5-7 days, including the keyless verification
flow integration and trusted-identity-pattern grammar.

## What this RFC commits milpa to

- OCI artifacts as the canonical distribution substrate for milpa-
  aware packages.
- F6 OciFetcher as the consumer-side integration, following the
  Fetcher protocol from F1.
- A `milpa publish` thin wrapper (Phase 3) that defaults to GHCR
  with the author's GitHub namespace; authors retain full control
  via direct `oras` + `cosign` usage.
- Manifest grammar extension: `oci="..."` and `digest="..."`
  properties on dep nodes (Phase 3).
- Manifest grammar extension: new top-level `verification { ... }`
  block carrying `require_attestation` (bool) and
  `trusted_identity_pattern` (string) fields (Phase 5).
- Lockfile encoding for OCI sources as `oci:<registry>/<repo>@<digest>`
  (no schema bump; existing source-string field accepts the new
  format).
- An `oci` field convention proposal for nim-lang/packages entries.
- Federation and mirror substitution via standard OCI pull-through
  caches; no milpa-side mirror infrastructure.
- Sigstore-based attestation as a first-class verification path,
  opt-in initially (Phase 5).

## What this RFC does NOT commit milpa to

- Building or operating a from-scratch package registry. The
  substrate is OCI; existing OCI hosts handle storage / DDoS /
  uptime.
- Requiring authors to migrate from GitHub Releases or git-only
  publishing. The bare-git path via nim-lang/packages remains
  fully supported indefinitely.
- A timeline for Phase 4 (registry frontend). The substrate
  decision (OCI) is correct regardless of whether the frontend
  ever ships.
- A specific signing-policy default. v1 is opt-in. Default-on may
  arrive once enough of the ecosystem signs.
- Coordination with nim-lang/packages maintainers beyond a
  conventional `oci` field proposal. Their schema is permissive of
  unknown fields; the proposal is additive.
- Deprecation of the git-fetch path. URL/git deps remain a first-
  class transport (F1 / today).

## Open design questions

### 1. Artifact media type registration

`application/vnd.milpa.source.v1.tar+gzip` is the proposed media
type. Should this be registered with IANA (formal MIME type
registration) or kept as a milpa-controlled convention?

IANA registration is a few-month process but gives the type formal
standing. Milpa-controlled is faster but less "official." Helm and
WASM both use vendor-prefixed types informally; precedent is loose.

Recommendation: start unregistered (`vnd.milpa.*` is a recognized
vendor-prefix convention); pursue IANA registration if/when adoption
warrants. No blocker for any phase.

### 2. Default registry for `milpa publish`

GHCR is the obvious default for nim authors already on GitHub. But
forcing a default ties us to one vendor's terms-of-service for the
"easy path."

Options:
- (a) GHCR default; configurable via `MILPA_REGISTRY` env var
- (b) No default; require explicit registry URL on every publish
- (c) Read from `milpa.kdl` (publish hint field)

Recommendation: (a) for the one-line `milpa publish` UX. The env
var escape hatch is the standard pattern (cargo, npm, pip all have
similar). Phase 3 ships with GHCR default; Phase 4 may add per-
package publish-hint config.

### 3. Lockfile multi-source representation

A package published via both git URL and OCI is multi-provenance
under the content-addressed-identity Phase D model. The lockfile
should record both:

```kdl
dep "chronos" {
    identity "sha256:abc..."
    provenance {
        kind "oci"
        registry "ghcr.io"
        repository "coreyleavitt/chronos"
        digest "sha256:abc..."
    }
    provenance {
        kind "git"
        url "https://github.com/coreyleavitt/chronos.git"
        ref "v0.5.0"
        commit_sha "..."
    }
}
```

This is Phase D work in the content-addressed-identity RFC, not new
to this RFC. Noting it here as a forward-compatibility
consideration — the OCI provenance format proposed in Phase 3
should be a clean fit for the Phase D multi-provenance shape.

### 4. Signature distribution

Cosign signatures are themselves OCI artifacts stored alongside the
signed one (via the OCI referrer API). milpa's verification path
needs to fetch both. F6 should be aware of this dual-artifact
pattern even when attestation enforcement is disabled (so
verification can be toggled on without re-fetching).

Open question: cache signatures in the lockfile? Or fetch on every
verify? Fetching on verify is simpler; caching has the bandwidth
win but adds lockfile churn on signature rotation (rare).

Recommendation: don't cache signatures in v1; fetch on verify.
Revisit if bandwidth becomes a real concern.

### 5. Yank semantics

OCI registries support deleting tags but not always deleting digests
(retention policies vary). A "yanked" milpa package should remain
fetchable for existing lockfiles (immutable history) but be hidden
from new resolution.

The OCI-native model: delete the human-readable tag (`v1.0.3`) but
preserve the digest. Lockfiles already pin by digest; they continue
to work. The Phase 4 frontend (if/when built) tracks yank status
and excludes yanked digests from new resolution.

For v1 without a frontend: yanking is communicated out-of-band (a
nim-lang/packages entry update, a deprecation note in the README).
The lockfile-by-digest model means existing builds aren't disrupted
regardless.

### 6. `trusted_identity_pattern` matching semantics

The Phase 5 `verification { trusted_identity_pattern "<pattern>" }`
field needs a matching semantic. Options:

- (a) Glob (`https://github.com/coreyleavitt/*`) — familiar to most
  users; limited expressiveness
- (b) Regex (`https://github\.com/coreyleavitt/.*`) — full expressive
  power; easy to get wrong (escape issues, ReDoS risk)
- (c) URI-prefix-match (`https://github.com/coreyleavitt/` matches
  any identity starting with that string) — simplest; sufficient
  for the canonical "any package by this author" use case

Recommendation: (c) URI-prefix-match for v1. Sigstore's
`--certificate-identity-regexp` flag uses regex but is hard to use
correctly. Prefix-match handles the 95% case (`anything-from-this-
author`) without rope to hang yourself with. Multi-identity case
expressed as multiple `trusted_identity_pattern` entries (the field
becomes repeatable).

### 7. Reproducible builds and source tarball normalization

Two authors building from the same git tag may produce different
source tarballs (different `tar` versions, different file ordering,
different umask, different timestamps). For OCI publishing to be
deterministic, the tarball generation needs to be normalized.

Standard solutions exist (reproducible-builds.org guidelines: sort
file order, zero timestamps, strip user/group, etc.). `milpa
publish` should produce a normalized tarball by construction.

Open question: should `milpa verify` also re-pack-and-hash the
source against its declared identity? That would close the loop
(verify the on-disk source matches the published artifact, end-to-
end). Adds complexity but eliminates a class of "source drift
between repo and published artifact" bugs.

Recommendation: ship `milpa publish` with normalized tarball
generation; defer the verify-against-publish round-trip to Phase 5.

## Acceptance: testable invariants

The model is right when:

1. An author publishes a milpa package via `milpa publish` (Phase 3),
   another machine pulls it via `milpa fetch`, and the resolved
   content_hash matches the publisher's expectation.
2. A package fetched via OCI digest is byte-identical to the same
   package fetched directly via `oras pull` — no milpa-specific
   transformation of the bytes.
3. A pull-through cache (e.g., local Zot) configured against ghcr.io
   serves milpa packages transparently; no milpa config change
   required.
4. A signed package (Phase 5) with a trusted-identity-pattern
   matching the publisher's GitHub identity passes verification;
   the same package signed by a different identity fails.
5. The content-addressed-identity RFC's Phase D multi-provenance
   shape naturally accommodates OCI alongside git provenance for
   the same identity.
6. `milpa fetch` against a manifest with `oci="..."` deps does not
   require any milpa-team-operated infrastructure to function.

## Issues this RFC will spawn

To be filed under a new milestone "distribution + publishing
(rfc-distribution-and-publishing)":

- Phase 1: F2 TarballFetcher (already filed as #41 under pluggable-
  fetchers)
- Phase 2: F6 OciFetcher (already filed as #45 under pluggable-
  fetchers; refine acceptance per this RFC's media-type convention)
- Phase 3: `milpa publish` helper
- Phase 3: manifest grammar extension for `oci=` / `digest=` properties
- Phase 3: lockfile encoding for OCI sources (`oci:<registry>/<repo>@<digest>`)
- Phase 3: `oci` field convention proposal to nim-lang/packages
- Phase 4 (optional): milpa registry frontend — separate umbrella,
  file when adoption justifies
- Phase 5: Sigstore-based attestation verification
- Reproducible tarball generation in `milpa publish`
- IANA media type registration (low priority)

## Connections

- `rfc-content-addressed-identity.md` — identity model that the OCI
  digest aligns with structurally. Phase D multi-provenance work
  natively expresses OCI alongside git provenance.
- `rfc-pluggable-fetchers.md` — F6 OciFetcher is the consumer-side
  integration for this RFC.
- `rfc-toolchain-content-addressing.md` — the v2 toolchain RFC's
  GithubReleaseFetcher could be a natural extension to also publish
  compiler binaries as OCI artifacts. Future symmetry.
- `rfc-multi-impl-strategy.md` — a Rust implementation of milpa
  would consume the same OCI artifacts via standard OCI client
  libraries (oras-rs, ocidir, etc.). The distribution substrate is
  language-neutral.
- `docs/comparison-vs-nimble-atlas.md` — the OCI substrate is what
  closes the "trust + availability + attestation" gap against
  nimble's bare-git model. Tier 3 structural-differentiation
  item.

## A note on adoption sequencing

The substrate decision in this RFC is independent of adoption
pressure. F2 + F6 + `milpa publish` ship as soon as their
implementation work lands. Once F6 ships, any author can opt into
OCI publishing immediately, with zero coordination — `oras push`
to their preferred registry, add `oci="..."` to their nim-lang/
packages entry (PR), done.

Adoption flows naturally:

1. fresco / intonaco / sinopia (the Nim packages this project
   primarily serves) publish as OCI artifacts as the canonical
   dogfood examples
2. Documentation references OCI as the recommended publishing path
3. As authors of other Nim packages see the trust + immutability +
   attestation benefits, they opt in
4. The Phase 4 frontend (if ever built) becomes valuable once enough
   of the ecosystem publishes via OCI for discovery to matter

(milpa itself is a Python tool, distributed via uv / pip — not
something that publishes as an OCI source artifact. The Rust v2 impl
per `rfc-multi-impl-strategy.md` ships as pre-built binaries via
GitHub releases + cargo. Neither is a Nim package, so neither is the
natural dogfood for OCI publishing.)

The fallback path (git fetch via nim-lang/packages) remains
permanently supported. There is no flag day. Authors who never opt
into OCI continue to work; consumers who never see an `oci=` field
in their resolved deps see no change.
