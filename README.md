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

## Usage

Run milpa against any Nim project that has a `milpa.kdl` manifest (or a `.nimble` milpa can read). From your `milpa/impls/python` checkout, point `-C` at the project:

```bash
uv run python -m milpa -C /path/to/project fetch    # resolve + clone deps into _deps/, emit nim.cfg + milpa.lock
uv run python -m milpa -C /path/to/project lock      # resolve + write milpa.lock only (no nim.cfg)
uv run python -m milpa -C /path/to/project verify    # check _deps/ matches the lockfile
uv run python -m milpa -C /path/to/project show      # print the resolved graph
uv run python -m milpa -C /path/to/project clean     # remove _deps/ and generated files
```

`fetch` writes `_deps/`, `nim.cfg`, and `milpa.lock` into the project; `nim` then compiles using the emitted `--path:` lines, with no `nimble` involvement.

A Rust reference implementation (byte-identical lockfiles + `nim.cfg`) lives in `impls/rust/` and is run in a container via `./dev-rust`; both impls are validated against the shared conformance corpus in `conformance/`.

## Name

The Mesoamerican multi-crop polyculture: corn, beans, and squash grown together — each crop supporting the others (corn provides stalks, beans fix nitrogen, squash shades the ground). Apt for a dependency resolver: packages grow together; the tool's job is figuring out which combinations are stable.

## Status

v0 shipped — fresco's hard split unblocked. v0.x and v1 in progress on Tier 1+2 features (`.nimble` compat, parallel fetch, resolution strategies, content-addressed identity Phase A). See `docs/comparison-vs-nimble-atlas.md` for the roadmap.

## What's structurally distinct

milpa separates **identity** (sha256 of source tree) from **provenance** (URL, ref, commit SHA). Existing Nim resolvers conflate them by pinning commit SHA. milpa records both — identity for trust-independent verification, provenance for delivery — which enables cross-fork dedup, mirror substitution, offline lockfile verification, and (when Phase B-C land) a global content-addressed package store.

See [`docs/identity-and-provenance.md`](docs/identity-and-provenance.md) for the model and [`docs/rfc-content-addressed-identity.md`](docs/rfc-content-addressed-identity.md) for the structural argument.

## Why not fix nimble

Considered. nimble has ~3 active maintainers and the design issues are structural (Turing-complete nimscript manifests, URL not first-class, conflated PM+build+task-runner). Fixes reach users via Nim minor releases — months out. milpa solves the resolution problem in days, locally, with zero ecosystem-coordination cost. nimble continues to work fine for nim-lang-registered packages where you don't need URL-based deps.

## Why not full uv-for-nim

Considered. 8-12 weeks for a competent replacement covering resolver + build invoker + task runner. milpa intentionally scopes to *just* the resolver and emits paths that any `nim` invocation can consume — ~600 lines of Python instead of a multi-month project.

## License

Apache 2.0.
