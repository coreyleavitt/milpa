# `_oracle/` — frozen cross-impl reference for epoch-2 `dag-sha256:` identity

`dag_sha256_reference.py` is the **standalone reference oracle** for the milpa
epoch-2 canonical content Merkle-DAG identity (`spec/identity.md` §1.8; RFC
`rfc-identity-conformance-authority` slice B1).

## Why it exists

The whole point of the oracle is that both milpa implementations implement the
epoch-2 materializer (slice B2) against a **frozen, independently-computed
digest**, never against each other. An oracle that shares code with the impl
cannot catch a bug shared by both impls (the differential-test blind spot,
[[testing_differential_blind_spot]]). Therefore this script:

* **MUST NOT import milpa** — not `impls/python/milpa/identity.py`, not the Rust
  core, nothing under test. It transcribes the spec byte tables directly.
* Is intentionally tiny and auditable. Read it against `spec/identity.md` §1.8.

## What it pins

It computes the `dag-sha256:` identity for the `dag-oracle.json` fixtures:

| Fixture | Tree | Pinned identity |
|---|---|---|
| `fixture-329-dag-oracle-empty-root` | empty source tree | `dag-sha256:e3b0c442…b855` (= `sha256(b"")`) |
| `fixture-330-dag-oracle-nested-leafsort` | 2-level tree; leaf-name order ≠ full-path order | `dag-sha256:e3213019…316f` |

## Self-test

`impls/python/tests/test_dag_sha256_oracle.py` runs this reference and asserts it
reproduces BOTH pinned digests — proving the oracle is internally consistent and
frozen, without touching milpa's identity implementation.

## Usage

```
python3 conformance/spec-v1/_oracle/dag_sha256_reference.py <fixture-dir>
```

prints the computed `dag-sha256:` identity for that fixture's `dag-oracle.json`.

The `_oracle/` directory is NOT a fixture: discovery only walks `fixture-*`
directories, so the runners never treat it as a conformance case.
