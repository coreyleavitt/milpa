# milpa — Python implementation

The Python implementation of **milpa**, the Nim dependency resolver. This is
one of milpa's conformant implementations (see [`../../README.md`](../../README.md)
for the project overview and [`../../spec/`](../../spec/) for the normative
specification every implementation conforms to).

milpa reads `milpa.kdl`, fetches deps into `_deps/`, runs PubGrub-based
resolution, and emits `nim.cfg` + `milpa.lock`.

## Development

```bash
uv sync                 # install milpa + dev deps (pytest, hypothesis)
uv run pytest           # unit + property tests
uv run python -m milpa --help
```

The shared conformance corpus lives at the repository root in
[`../../conformance/`](../../conformance/) and is consumed by every
implementation's runner; it is not Python's private test data.
