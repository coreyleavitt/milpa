# fixture-329 — epoch-2 Merkle-DAG oracle: empty root

**Status: LIVE (epoch-2 DAG builder, RFC slice B2-git).** The `cmd: dag-oracle`
selector now feeds this staged seam input (`dag-oracle.json`) directly to each
impl's production DAG builder, which reproduces the frozen oracle value below.
The builder is independent of the standalone reference oracle, so the agreement
is the differential check.

## The tree this fixture encodes

The empty source tree — a zero-entry root tree node (`dag-oracle.json` has an
empty `entries` list).

Per `spec/identity.md` §1.8, a zero-entry tree node is the sha256 of the empty
byte string. The empty-directory-omission rule means this digest is only ever
the *identity of the whole tree* when the root itself is empty; it is never
spliced as a child-digest (empty subdirectories are omitted from their parents
before the parent is encoded).

## Pinned identity (frozen epoch-2 oracle)

```
dag-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

This is `dag-sha256:` + `sha256(b"")`. Verified by the standalone reference
`conformance/spec-v1/_oracle/dag_sha256_reference.py` and the oracle self-test.
