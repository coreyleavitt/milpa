# milpa

A dependency manager for Nim. It reads a `milpa.kdl` manifest, fetches dependencies into `_deps/`, resolves the transitive graph with PubGrub, and emits a `nim.cfg` so `nim` builds directly — without nimble.

It resolves dependency graphs nimble's solver cannot (notably chained URL `requires` that share a transitive dependency), and adds content-addressed identity, a package registry, author-side publishing, and Sigstore-based supply-chain verification.

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv tool install "git+https://github.com/coreyleavitt/milpa.git#subdirectory=impls/python"
milpa --help
```

To run from a source checkout instead: `cd impls/python && uv sync && uv run python -m milpa …`.

## Usage

```bash
milpa -C <project> fetch    # resolve + fetch deps → _deps/, nim.cfg, milpa.lock
milpa -C <project> lock     # resolve → milpa.lock only
milpa -C <project> verify   # check _deps/ against the lockfile
milpa -C <project> show     # print the resolved graph
milpa -C <project> add …    # add a dependency to milpa.kdl
```

`fetch` writes `_deps/`, `nim.cfg`, and `milpa.lock`; `nim` then compiles from the emitted `--path:` lines. Dependencies may be git, tarball, OCI, local path, or named packages resolved through the [tianguis](https://github.com/coreyleavitt/tianguis) registry. Further commands (`hash`, `store`, `index`, `workspace`, `publish`) are listed by `milpa --help`.

## Features

- **PubGrub resolution** with selectable strategies, overrides, optional dependencies, and conditional `when` blocks.
- **Content-addressed identity** — a dependency's identity is a hash of its source tree, recorded separately from its provenance (URL/ref/commit, or OCI digest).
- **Registry** — named packages resolve through tianguis; `milpa publish` packs the git HEAD tree, pushes it to an OCI registry, and keyless-cosign-signs it.
- **Supply-chain trust** — per-entry Sigstore attestation and an append-only index ratchet, verified at resolve time.
- **Declarative** — `milpa.kdl` is pure data with no embedded scripting; the output is `nim.cfg`, never NimScript.
- **Two implementations** — a Python reference impl and a Rust impl, validated against a shared conformance corpus.

## Documentation

- [`docs/comparison-vs-nimble-atlas.md`](docs/comparison-vs-nimble-atlas.md) — feature comparison and roadmap
- [`docs/identity-and-provenance.md`](docs/identity-and-provenance.md) — the identity/provenance model
- [`docs/decision-config-nims.md`](docs/decision-config-nims.md) — why the output is `nim.cfg`, not `config.nims`
- `docs/rfc-*.md` — design records

## License

Apache 2.0.

---

*milpa is the Mesoamerican polyculture of corn, beans, and squash grown together.*
