# RFC: Consumer-side registry trust & federation (STUB)

Status: **stub** — triage grouping from the 2026-06-06 issue audit. Not yet designed.
Umbrella: (umbrella issue links here). Milestone: *registry trust & federation*.

## Problem

The *producer* side of the registry is settled and built: the registry design RFC
lives at `coreyleavitt/tianguis/docs/rfc-registry.md` (milpa#85, resolved), with
Sigstore keyless attestation as the publishing gatekeeper and vendor-en-absentia
backfill. What milpa lacks is the **consumer side of that trust model**: at
resolve time it trusts the fetched index on HTTPS transport alone, and a
publisher can't guarantee mirror availability on a consumer's *first* fetch.

## Issues unified

- **#103 — verify the index's signature / Rekor attestation at resolve time.**
  Today `tianguis_client.load_index` trusts `index.kdl` on transport alone; the
  stale-cache fallback even enables a poison-then-block pattern. The producer side
  already emits Rekor attestation — this is enforcing it on the consumer. A new
  trust subsystem with real forks (TOFU vs pinned key vs keyless/Fulcio; offline
  behavior; fail vs warn; whole-index vs per-entry). *(Also tracked under the
  content-addressed-identity milestone, theme-adjacent to #38 sigstore/SLSA.)*
- **#91 — publisher-side self-mirror declarations.** #79 shipped consumer-side
  self-mirror *harvest* (cached on first successful fetch). The gap: a library
  author declaring mirrors that downstream consumers benefit from on the **first**
  fetch (before any cache exists) — chicken-and-egg if the primary is down before
  the first successful fetch. Depends on the registry trust path (#85, done).

## Why one RFC

Both are "how a consumer establishes trust in, and resilient access to, the bytes
the registry points at": attestation verification (#103) is the integrity half;
publisher-declared mirrors delivered through the trusted index (#91) is the
availability half. They share the index-trust path and should be designed as one
consumer-trust story.

## Open questions

- Trust model for #103: TOFU, pinned key, or keyless/Fulcio identity? Offline?
- Where do publisher-declared mirrors live so they're available pre-first-fetch —
  in the index entry itself (so they ride the same attestation)? (cross-repo:
  tianguis schema.)
- Failure policy: hard-fail vs warn on missing/unverifiable attestation.

## Slices

TBD. Likely an attestation-verification design pass (#103) first, since #91's
mirror delivery rides whatever trusted-index channel that establishes.
