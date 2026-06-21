# RFC: Fetch & extraction hardening (STUB)

Status: **stub** — triage grouping from the 2026-06-21 issue audit. Not yet designed.
Umbrella: #170. Milestone: *v0.x / v1 — robustness*.
Related: `rfc-pluggable-fetchers.md` (most of these surfaced in its Stage-4 review;
this RFC may fold back in as a "hardening" phase rather than stand alone).

## Problem

A cluster of real correctness and security bugs in the fetch + archive-extraction
path, all surfaced by the pluggable-fetchers (F1–F3) Stage-4 code review. Each lands
incomplete or unsafe bytes in the CAS, which is the worst failure mode for a
content-addressed dep manager: the identity hash is computed over wrong/partial
content, so the lockfile records a hash that doesn't mean what it should.

## Issues unified

- **#140 — recurse git submodules.** Deps that vendor sources via a submodule (e.g.
  `bearssl-nim` vendoring C sources) land **incomplete** in the CAS; cold builds then
  fail on missing files. Labeled `bug`.
- **#143 — in-tree `.gitattributes` can override `core.autocrlf=false`.** The
  identity transport-normalization fix (`spec/identity.md §1.7`) injects
  `-c core.autocrlf=false`, but a repo's own `.gitattributes` can re-enable EOL
  munging, perturbing the content hash. (Security lens, identity RFC Stage-4 R2.)
- **#144 — hardlink extraction maps hardlinks to symlinks + mishandles
  strip_components.** Both impls have wrong escape-check geometry for tar hardlink
  entries. (Architect review of pluggable-fetchers F1–F3.)
- **#145 — git fetcher shallow-clone divergence.** Rust `commit_present` is
  single-step; Python has a 4-step fetch/unshallow fallback. Same pin can succeed on
  one impl and fail on the other.
- **#149 — download-size DoS.** The 4 GiB cap is enforced post-buffer;
  `curl --max-filesize` is bypassed by chunked / no-`Content-Length` responses.
  (Security lens, pluggable-fetchers Stage-4 R4 residual.)

## Why one RFC

These all live on the fetch→extract→hash path and share the same invariant: *bytes
admitted to the CAS must be complete, normalized, and bounded before the identity
hash is computed.* #144/#145/#149 also have a cross-impl-parity dimension (the fix
must converge Python and Rust), so they coordinate with
`rfc-conformance-parity.md` (corpus fixtures pin the converged behavior).

## Open questions

- Submodule recursion (#140): always, or opt-in per dep? Interaction with identity
  hash (submodule SHAs are provenance, not content).
- Is this a standalone RFC or a hardening phase appended to `rfc-pluggable-fetchers.md`?

## Slices

TBD. #140 (submodules) and #149 (DoS cap) are the highest-severity; likely first.
