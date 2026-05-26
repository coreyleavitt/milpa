"""`milpa publish` — author-side publish pipeline.

The pipeline is: pack source → push as OCI artifact → cosign-sign →
POST tianguis dispatch. Tests build up vertically; each cycle exercises
one observable behavior of the publish module.
"""

import io
import tarfile
from pathlib import Path

import pytest

from milpa.publish import cosign_sign, pack_source, post_dispatch, publish, push_oci


# ---------------------------------------------------------------------------
# Cycle 1 — tracer: pack a source dir into a tarball
# ---------------------------------------------------------------------------


def test_pack_source_returns_a_tarball_containing_the_inputs(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "hello.nim").write_text("echo \"hi\"\n")
    (tmp_path / "README.md").write_text("# sample\n")

    blob = pack_source(tmp_path)

    # Sanity: we got bytes back, and they parse as a tar.gz holding our files.
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        names = sorted(tf.getnames())
    assert "README.md" in names
    assert "src/hello.nim" in names


# ---------------------------------------------------------------------------
# Cycle 2 — determinism: pack(x) == pack(x) byte-for-byte
#
# Without this, the OCI artifact digest drifts between runs, breaking
# reproducibility AND the eventual content_hash cross-check.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Cycle 3 — exclusions match identity.compute_content_hash
#
# The contract: the OCI artifact's bytes, once unpacked, must compute
# the same content_hash that an author's local milpa would compute. If
# tarball-exclusions don't match identity.py exclusions, the digest
# stored at publish time and the digest milpa later recomputes diverge,
# breaking the entire trust chain.
# ---------------------------------------------------------------------------


def test_pack_source_excludes_dot_git(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "real.nim").write_text("x\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (tmp_path / ".git" / "objects").mkdir()
    (tmp_path / ".git" / "objects" / "deadbeef").write_text("blob\n")

    blob = pack_source(tmp_path)

    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        names = tf.getnames()
    assert "src/real.nim" in names
    for name in names:
        assert not name.startswith(".git"), (
            f"tarball must not include .git contents; found {name!r}"
        )
        assert "/.git/" not in name, (
            f"tarball must not include nested .git contents; found {name!r}"
        )


def test_pack_then_unpack_preserves_content_hash(tmp_path: Path):
    """The cross-validation invariant. If the OCI artifact, once pulled
    and untarred, doesn't compute to the same content_hash that the
    author saw locally, every downstream verification breaks."""
    from milpa.identity import compute_content_hash

    src = tmp_path / "source"
    src.mkdir()
    (src / "src").mkdir()
    (src / "src" / "a.nim").write_text("a\n")
    (src / "src" / "sub").mkdir()
    (src / "src" / "sub" / "b.nim").write_text("b\n")
    (src / "README.md").write_text("# pkg\n")
    # Provenance-not-content: gets stripped.
    (src / ".git").mkdir()
    (src / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    # Mark a file executable to exercise the mode-bit preservation.
    script = src / "scripts" / "build.sh"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o755)

    expected = compute_content_hash(src)

    blob = pack_source(src)

    # Untar into a fresh location, then recompute. The hashes must agree.
    dest = tmp_path / "unpacked"
    dest.mkdir()
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        tf.extractall(dest)
    actual = compute_content_hash(dest)

    assert actual == expected, (
        f"unpacked content_hash {actual!r} differs from source {expected!r} — "
        "tarball exclusions or mode handling are misaligned with identity.py"
    )


def test_pack_source_is_byte_deterministic(tmp_path: Path):
    import os

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.nim").write_text("a\n")
    (tmp_path / "src" / "b.nim").write_text("b\n")
    (tmp_path / "README.md").write_text("doc\n")

    first = pack_source(tmp_path)

    # Touch every file to a different mtime than the originals — a tar
    # that records per-entry mtime will produce different bytes here.
    for p in tmp_path.rglob("*"):
        os.utime(p, (1_700_000_000, 1_700_000_000))

    second = pack_source(tmp_path)

    assert first == second, (
        "pack_source must be byte-deterministic across filesystem mtime "
        "changes — the OCI artifact digest depends on this"
    )


# ---------------------------------------------------------------------------
# Cycle 5 — OCI push: orchestrates `oras push` and returns the artifact's
# canonical OCI ref (registry/repo@sha256:<digest>).
#
# Subprocess is injected so we test orchestration without actually pushing.
# ---------------------------------------------------------------------------


def test_push_oci_invokes_oras_with_correct_args(tmp_path: Path):
    blob = b"deterministic tarball bytes"
    calls: list[list[str]] = []

    def fake_runner(argv: list[str], **kw) -> tuple[int, str, str]:
        calls.append(argv)
        # oras push prints the digest of the pushed manifest on stdout.
        return (0, "Digest: sha256:abc123def456\n", "")

    ref = push_oci(
        blob=blob,
        registry_ref="ghcr.io/coreyleavitt/sample:v1.0.0",
        runner=fake_runner,
    )

    assert ref == "ghcr.io/coreyleavitt/sample@sha256:abc123def456"
    assert len(calls) == 1
    argv = calls[0]
    assert argv[0] == "oras" and argv[1] == "push"
    # The target ref the registry should record (tag form acceptable for push).
    assert "ghcr.io/coreyleavitt/sample:v1.0.0" in argv


def test_push_oci_raises_on_nonzero_exit(tmp_path: Path):
    def failing_runner(argv: list[str], **kw) -> tuple[int, str, str]:
        return (1, "", "oras: unauthorized\n")

    with pytest.raises(RuntimeError, match="oras push failed"):
        push_oci(
            blob=b"x",
            registry_ref="ghcr.io/x/y:v1",
            runner=failing_runner,
        )


# ---------------------------------------------------------------------------
# Cycle 6 — cosign sign: orchestrates `cosign sign --yes <oci_ref>` against
# the published artifact. Uses ambient OIDC (the runner's env carries the
# CI's id-token). We just verify orchestration; cosign itself owns the
# crypto and the Rekor upload.
# ---------------------------------------------------------------------------


def test_cosign_sign_invokes_cosign_with_correct_args():
    oci_ref = "ghcr.io/coreyleavitt/sample@sha256:abc123def456"
    calls: list[list[str]] = []

    def fake_runner(argv: list[str], **kw) -> tuple[int, str, str]:
        calls.append(argv)
        return (0, "tlog entry created with index: 12345\n", "")

    cosign_sign(oci_ref=oci_ref, runner=fake_runner)

    assert len(calls) == 1
    argv = calls[0]
    assert argv[0] == "cosign" and argv[1] == "sign"
    assert "--yes" in argv  # non-interactive (no "are you sure?" prompt)
    assert oci_ref in argv


def test_cosign_sign_raises_on_nonzero_exit():
    def failing_runner(argv: list[str], **kw) -> tuple[int, str, str]:
        return (1, "", "cosign: no OIDC token in env\n")

    with pytest.raises(RuntimeError, match="cosign sign failed"):
        cosign_sign(oci_ref="ghcr.io/x/y@sha256:abc", runner=failing_runner)


# ---------------------------------------------------------------------------
# Cycle 7 — POST to tianguis dispatch with Bearer OIDC + JSON payload.
# HTTP client is injected; we verify URL, headers, and body.
# ---------------------------------------------------------------------------


def test_post_dispatch_sends_correct_payload_and_bearer():
    captured: dict[str, object] = {}

    def fake_http_post(url: str, *, headers: dict[str, str], json: dict[str, object]) -> tuple[int, dict[str, object]]:
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return (200, {"status": "accepted"})

    response = post_dispatch(
        dispatch_url="https://dispatch.tianguis.dev",
        oidc_token="eyJ.fake.token",
        payload={
            "name": "sample",
            "version": "v1.0.0",
            "oci_ref": "ghcr.io/coreyleavitt/sample@sha256:abc123",
            "provider": "github",
            "repo_url": "https://github.com/coreyleavitt/sample",
            "signed_by": "https://github.com/coreyleavitt/sample/.github/workflows/publish.yaml@refs/tags/v1.0.0",
        },
        http_post=fake_http_post,
    )

    assert captured["url"] == "https://dispatch.tianguis.dev/v1/publish"
    assert captured["headers"]["Authorization"] == "Bearer eyJ.fake.token"
    assert captured["headers"]["Content-Type"] == "application/json"
    assert captured["json"]["name"] == "sample"
    assert captured["json"]["oci_ref"] == "ghcr.io/coreyleavitt/sample@sha256:abc123"
    assert response == {"status": "accepted"}


def test_post_dispatch_raises_on_non_2xx():
    def fake_http_post(url: str, *, headers: dict, json: dict) -> tuple[int, dict]:
        return (403, {"error": "identity_mismatch", "detail": "..."})

    with pytest.raises(RuntimeError, match="dispatch rejected.*identity_mismatch"):
        post_dispatch(
            dispatch_url="https://dispatch.tianguis.dev",
            oidc_token="x",
            payload={"name": "y"},
            http_post=fake_http_post,
        )


# ---------------------------------------------------------------------------
# Cycle 8 — end-to-end orchestration: publish() wires pack → push → sign →
# POST and threads the digest through. --dry-run skips the POST step.
# ---------------------------------------------------------------------------


def _make_fakes():
    """Build a coherent set of fakes that record what they were called with."""
    state: dict[str, object] = {"runner_calls": [], "http_calls": []}

    def runner(argv, **kw):
        state["runner_calls"].append(argv)
        if argv[0] == "oras":
            return (0, "Digest: sha256:cafebabe1234567890abcdef\n", "")
        if argv[0] == "cosign":
            return (0, "tlog entry created with index: 99\n", "")
        return (1, "", f"unexpected tool {argv[0]}")

    def http_post(url, *, headers, json):
        state["http_calls"].append({"url": url, "headers": headers, "json": json})
        return (200, {"status": "accepted"})

    return state, runner, http_post


def test_publish_pipeline_threads_oci_digest_into_dispatch_payload(tmp_path: Path):
    (tmp_path / "main.nim").write_text("echo \"hi\"\n")

    state, runner, http_post = _make_fakes()

    publish(
        source_dir=tmp_path,
        name="sample",
        version="v1.0.0",
        registry_ref="ghcr.io/coreyleavitt/sample:v1.0.0",
        provider="github",
        repo_url="https://github.com/coreyleavitt/sample",
        signed_by="https://github.com/coreyleavitt/sample/.github/workflows/publish.yaml@refs/tags/v1.0.0",
        oidc_token="eyJ.test.token",
        dispatch_url="https://dispatch.tianguis.dev",
        runner=runner,
        http_post=http_post,
    )

    # Exactly one POST, with the digest from the oras step.
    assert len(state["http_calls"]) == 1
    payload = state["http_calls"][0]["json"]
    assert payload["oci_ref"] == "ghcr.io/coreyleavitt/sample@sha256:cafebabe1234567890abcdef"
    assert payload["name"] == "sample"
    assert payload["version"] == "v1.0.0"
    assert payload["provider"] == "github"
    assert payload["repo_url"] == "https://github.com/coreyleavitt/sample"
    assert payload["signed_by"].startswith("https://github.com/coreyleavitt/sample")
    # Tools called in the right order: oras, then cosign.
    tools = [c[0] for c in state["runner_calls"]]
    assert tools == ["oras", "cosign"]


def test_publish_dry_run_with_token_sends_dispatch_with_dry_run_flag(tmp_path: Path):
    """With an OIDC token available, dry-run still POSTs to dispatch so
    the CI-side smoke test exercises the full OIDC + identity chain.
    The `dry_run: true` flag tells dispatch to skip the commit step."""
    (tmp_path / "main.nim").write_text("x\n")
    state, runner, http_post = _make_fakes()

    publish(
        source_dir=tmp_path,
        name="sample", version="v1.0.0",
        registry_ref="ghcr.io/x/y:v1",
        provider="github", repo_url="https://github.com/x/y",
        signed_by="https://github.com/x/y/.github/workflows/p.yaml@refs/tags/v1",
        oidc_token="eyJ.real.token",
        dispatch_url="https://dispatch.tianguis.dev",
        dry_run=True,
        runner=runner, http_post=http_post,
    )

    assert len(state["http_calls"]) == 1
    payload = state["http_calls"][0]["json"]
    assert payload.get("dry_run") is True, "dispatch payload must carry dry_run=true"


def test_publish_dry_run_without_token_skips_dispatch_entirely(tmp_path: Path):
    """Without an OIDC token (local-dev path), dry-run skips the POST
    entirely — author can still inspect the OCI artifact + Rekor entry."""
    (tmp_path / "main.nim").write_text("x\n")

    state, runner, http_post = _make_fakes()

    publish(
        source_dir=tmp_path,
        name="sample",
        version="v1.0.0",
        registry_ref="ghcr.io/x/y:v1",
        provider="github",
        repo_url="https://github.com/x/y",
        signed_by="https://github.com/x/y/.github/workflows/p.yaml@refs/tags/v1",
        oidc_token="",
        dispatch_url="https://dispatch.tianguis.dev",
        dry_run=True,
        runner=runner,
        http_post=http_post,
    )

    # Pack + push + sign still ran (authors want to see the OCI artifact).
    tools = [c[0] for c in state["runner_calls"]]
    assert "oras" in tools and "cosign" in tools
    # But no dispatch POST.
    assert state["http_calls"] == []


# ---------------------------------------------------------------------------
# Cycle 9 — OIDC token retrieval with sigstore audience.
#
# GH Actions' ACTIONS_ID_TOKEN_REQUEST_TOKEN is NOT directly usable as a
# Sigstore-audience bearer — it's the bearer for the OIDC TOKEN REQUEST
# endpoint. The actual usable token comes from calling that endpoint
# with audience=sigstore. cosign does this internally; we have to do
# the same for the dispatch POST.
# ---------------------------------------------------------------------------


def test_fetch_sigstore_oidc_token_calls_gh_endpoint_with_audience(monkeypatch):
    """When ACTIONS_ID_TOKEN_REQUEST_{TOKEN,URL} are set, fetch the
    real OIDC token from GH's API with audience=sigstore."""
    from milpa.publish import fetch_sigstore_oidc_token

    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "gh-bearer-xxx")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.actions.githubusercontent.com/?...")

    captured = {}

    def fake_get(url, headers):
        captured["url"] = url
        captured["headers"] = headers
        return {"value": "eyJ.sigstore-audience.token"}

    token = fetch_sigstore_oidc_token("ACTIONS_ID_TOKEN_REQUEST_TOKEN", _http_get=fake_get)

    assert token == "eyJ.sigstore-audience.token"
    assert "audience=sigstore" in captured["url"]
    assert captured["headers"]["Authorization"] == "Bearer gh-bearer-xxx"


def test_fetch_sigstore_oidc_token_falls_back_to_direct_env(monkeypatch):
    """For non-GH CIs that expose the token directly in an env var
    (e.g. GitLab's CI_JOB_JWT_V2), use it as-is."""
    from milpa.publish import fetch_sigstore_oidc_token

    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)
    monkeypatch.setenv("CI_JOB_JWT_V2", "gitlab-sigstore-jwt")

    token = fetch_sigstore_oidc_token("CI_JOB_JWT_V2")
    assert token == "gitlab-sigstore-jwt"


def test_fetch_sigstore_oidc_token_returns_empty_when_no_source(monkeypatch):
    from milpa.publish import fetch_sigstore_oidc_token

    for k in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
              "CI_JOB_JWT_V2", "MY_TOKEN"):
        monkeypatch.delenv(k, raising=False)

    assert fetch_sigstore_oidc_token("MY_TOKEN") == ""
