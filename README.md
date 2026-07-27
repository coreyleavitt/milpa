# milpa

A dependency resolver for Nim projects.

## What it is

milpa reads a `milpa.kdl` manifest, clones URL-based and named-package dependencies into a local `_deps/` directory, resolves transitive deps, and emits a `nim.cfg` with `--path:` lines so `nim` compiles your project directly. No `nimble` involvement during builds.

Built because `nimble v0.22.2`'s vnext SAT solver cannot resolve two URL-based `requires` that share a transitive URL — a real-world case fresco hits (fresco requires intonaco URL, intonaco requires chronos URL, fresco also requires chronos URL → "Unsatisfiable dependencies"). milpa sidesteps the whole resolver layer; nimble stays useful for nim-lang-registered packages where its tooling works, but you don't have to be at its mercy for URL-based deps.

## Install

milpa is a Python tool (it *resolves* Nim projects; it is not itself written in Nim). The reference implementation lives in `impls/python/` and is managed with [uv](https://docs.astral.sh/uv/).

**Prerequisites**

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) — install with one of:
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh   # macOS / Linux
  # or: brew install uv   |   pipx install uv   |   winget install astral-sh.uv
  ```
- `git` (used by the fetcher to clone dependencies)

**Set up milpa**

```bash
git clone https://github.com/coreyleavitt/milpa
cd milpa/impls/python
uv sync                              # create the venv + install milpa and its deps
uv run python -m milpa --help
```

`uv sync` reads `impls/python/pyproject.toml`; nothing is installed globally.

Or install it as a standalone `milpa` command (the repo is public):

```bash
uv tool install "git+https://github.com/coreyleavitt/milpa.git#subdirectory=impls/python"
milpa --help
```

## Usage

Run milpa against any Nim project that has a `milpa.kdl` manifest (or a `.nimble` milpa can read). From your `milpa/impls/python` checkout, point `-C` at the project:

```bash
milpa -C /path/to/project fetch    # resolve + fetch deps into _deps/, emit nim.cfg + milpa.lock
milpa -C /path/to/project lock     # resolve + write milpa.lock only (no nim.cfg)
milpa -C /path/to/project verify   # check _deps/ matches the lockfile
milpa -C /path/to/project show     # print the resolved graph
milpa -C /path/to/project clean    # remove _deps/ and nim.cfg (keeps milpa.lock)
milpa -C /path/to/project add …    # add a dep (or a mirror provenance) to milpa.kdl
```

(From a source checkout, prefix with `uv run python -m` instead of the installed `milpa`.)

`fetch` writes `_deps/`, `nim.cfg`, and `milpa.lock` into the project; `nim` then compiles using the emitted `--path:` lines, with no `nimble` involvement. Dependencies can be URL-based (`git=`/`tarball=`), local path checkouts (`local=`), OCI artifacts (`oci=`), or **named packages** resolved through the [tianguis](https://github.com/coreyleavitt/tianguis) registry.

Beyond project resolution, milpa also provides `hash` (content identity of a source tree), `store` (inspect the content-addressed store), `index` (registry append-only-ratchet status/accept), `workspace` (cargo-style multi-member workspaces), and `publish` (pack the git HEAD tree → push to an OCI registry → keyless-cosign-sign it → emit a receipt, for publishing a package to a registry). Run `milpa --help` for the full list.

A Rust reference implementation (byte-identical lockfiles + `nim.cfg`) lives in `impls/rust/` and is run in a container via `./dev-rust`; both impls are validated against the shared conformance corpus in `conformance/`.

## Name

The Mesoamerican multi-crop polyculture: corn, beans, and squash grown together — each crop supporting the others (corn provides stalks, beans fix nitrogen, squash shades the ground). Apt for a dependency resolver: packages grow together; the tool's job is figuring out which combinations are stable.

## Status

Well past v0 (which unblocked fresco's hard split). Shipped since: `.nimble` compat, parallel fetch, resolution strategies + overrides, cargo-style workspaces, content-addressed identity, a Rust reference implementation validated against a shared conformance corpus, and integration with the [tianguis](https://github.com/coreyleavitt/tianguis) registry — named-package resolution, `milpa publish` for author-side publishing, and a Sigstore-based supply-chain trust model (per-entry author-signed attestation + append-only index ratchet). See `docs/comparison-vs-nimble-atlas.md` for the roadmap and the `docs/rfc-*.md` files for the design record.

## What's structurally distinct

milpa separates **identity** (sha256 of source tree) from **provenance** (URL, ref, commit SHA). Existing Nim resolvers conflate them by pinning commit SHA. milpa records both — identity for trust-independent verification, provenance for delivery — which enables cross-fork dedup, mirror substitution, offline lockfile verification, and (when Phase B-C land) a global content-addressed package store.

See [`docs/identity-and-provenance.md`](docs/identity-and-provenance.md) for the model and [`docs/rfc-content-addressed-identity.md`](docs/rfc-content-addressed-identity.md) for the structural argument.

## Why not fix nimble

Considered. nimble has ~3 active maintainers and the design issues are structural (Turing-complete nimscript manifests, URL not first-class, conflated PM+build+task-runner). Fixes reach users via Nim minor releases — months out. milpa solves the resolution problem in days, locally, with zero ecosystem-coordination cost. nimble continues to work fine for nim-lang-registered packages where you don't need URL-based deps.

## Scope

milpa began as *just* the resolver (the fresco-unblock charter) and has deliberately grown into a full Nim dependency manager: resolution, content-addressed identity, a package-registry client ([tianguis](https://github.com/coreyleavitt/tianguis)), author-side publishing, and a Sigstore-based supply-chain trust model. What it deliberately does **not** do is drive builds or run tasks — it emits a declarative `nim.cfg` (never a NimScript `config.nims`; see [`docs/decision-config-nims.md`](docs/decision-config-nims.md)) that any `nim` invocation consumes. That lane separation — dependency management vs. build/task-running — is intentional, and is what keeps milpa a manifest-is-pure-data tool rather than a `uv`-for-Nim that also owns the build and task-runner surface nimble conflates.

## License

Apache 2.0.
