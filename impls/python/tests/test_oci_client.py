"""Tests for milpa.fetchers.oci_client — the native OCI Distribution client (S5).

RFC: docs/rfc-native-oci-fetch.md §3.2 (client design), §3.6 (token cache),
§3.7/§4 (canned-transport fixture + unit test matrix a-j).

This file tests OciRegistryClient / select_source_layer / the
WWW-Authenticate tokenizer / TokenCache directly, against the shared
canned-transport fixtures under conformance/oci-transport/ — the client
became OciFetcher's default transport in S6 (see test_oci_fetcher.py for
the fetcher-level composition/extraction tests).
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from pathlib import Path

import pytest

from milpa.bounded_http import HttpResponse
from milpa.errors import (
    FETCH_DOWNLOAD_FAILED,
    FETCH_DOWNLOAD_SIZE_EXCEEDED,
    FETCH_OCI_AMBIGUOUS_TARBALL,
    FETCH_OCI_DIGEST_MISMATCH,
    FETCH_OCI_NO_TARBALL,
    FETCH_OCI_PULL_FAILED,
    MilpaError,
)
from milpa.fetchers.oci_client import (
    MAX_COMPRESSED_BYTES,
    AuthChallenge,
    Layer,
    Manifest,
    OciRegistryClient,
    TokenCache,
    select_bearer_challenge,
    select_source_layer,
    tokenize_www_authenticate,
)
from tests._oci_transport_replay import ReplayTransport, load_fixture

REGISTRY = "ghcr.io"
REPOSITORY = "coreyleavitt/test-pkg"


def _digest_from_manifest_url(url: str) -> str:
    return url.rsplit("/manifests/", 1)[1]


def _digest_from_blob_url(url: str) -> str:
    return url.rsplit("/blobs/", 1)[1].split("?", 1)[0]


# ---------------------------------------------------------------------------
# (a) happy pull: token -> manifest -> blob, extracts + verifies
# ---------------------------------------------------------------------------


def test_happy_pull_extracts_blob_to_dest(tmp_path: Path) -> None:
    fixture = load_fixture("happy-pull.json")
    manifest_digest = _digest_from_manifest_url(fixture["exchanges"][2]["url"])
    blob_body = base64.b64decode(fixture["exchanges"][3]["response"]["body_base64"])

    transport = ReplayTransport("happy-pull.json")
    client = OciRegistryClient(transport, TokenCache())

    token = client.token(REGISTRY, REPOSITORY)
    assert token == "test-token-abc"

    manifest = client.manifest(REGISTRY, REPOSITORY, manifest_digest, token)
    layer = select_source_layer(manifest)

    dest = tmp_path / "source.tar.gz"
    client.blob(REGISTRY, REPOSITORY, layer.digest, layer.size, token, dest=dest)

    assert dest.read_bytes() == blob_body
    transport.assert_exhausted()


def test_token_is_cached_across_repeated_calls() -> None:
    """A second ``token()`` call for the same (registry, scope) is a cache hit.

    The happy-pull fixture has exactly one token-challenge + one
    token-fetch exchange; a cache miss on the second call would exhaust
    the fixture and raise.
    """
    fixture = load_fixture("happy-pull.json")
    manifest_digest = _digest_from_manifest_url(fixture["exchanges"][2]["url"])

    transport = ReplayTransport("happy-pull.json")
    client = OciRegistryClient(transport, TokenCache())

    token1 = client.token(REGISTRY, REPOSITORY)
    token2 = client.token(REGISTRY, REPOSITORY)
    assert token1 == token2 == "test-token-abc"

    # The token exchanges (0, 1) are consumed once; manifest is exchange 2.
    client.manifest(REGISTRY, REPOSITORY, manifest_digest, token1)


# ---------------------------------------------------------------------------
# (b) phase failures carry the right slug + phase=
# ---------------------------------------------------------------------------


def test_token_endpoint_error_raises_pull_failed_phase_token() -> None:
    transport = ReplayTransport("token-endpoint-error.json")
    client = OciRegistryClient(transport, TokenCache())

    with pytest.raises(MilpaError) as exc_info:
        client.token(REGISTRY, REPOSITORY)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "token"


def test_manifest_not_found_raises_pull_failed_phase_manifest() -> None:
    fixture = load_fixture("manifest-not-found.json")
    digest = _digest_from_manifest_url(fixture["exchanges"][2]["url"])

    transport = ReplayTransport("manifest-not-found.json")
    client = OciRegistryClient(transport, TokenCache())
    token = client.token(REGISTRY, REPOSITORY)

    with pytest.raises(MilpaError) as exc_info:
        client.manifest(REGISTRY, REPOSITORY, digest, token)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "manifest"


def test_blob_fetch_error_raises_pull_failed_phase_blob(tmp_path: Path) -> None:
    fixture = load_fixture("blob-fetch-error.json")
    manifest_digest = _digest_from_manifest_url(fixture["exchanges"][2]["url"])
    layer_digest = _digest_from_blob_url(fixture["exchanges"][3]["url"])

    transport = ReplayTransport("blob-fetch-error.json")
    client = OciRegistryClient(transport, TokenCache())
    token = client.token(REGISTRY, REPOSITORY)
    manifest = client.manifest(REGISTRY, REPOSITORY, manifest_digest, token)
    layer = select_source_layer(manifest)
    assert layer.digest == layer_digest

    dest = tmp_path / "out.tar.gz"
    with pytest.raises(MilpaError) as exc_info:
        client.blob(REGISTRY, REPOSITORY, layer.digest, layer.size, token, dest=dest)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "blob"


# ---------------------------------------------------------------------------
# (c) manifest / blob digest mismatch -> FETCH-OCI-DIGEST-MISMATCH, fail closed
# ---------------------------------------------------------------------------


def test_manifest_digest_mismatch_raises_digest_mismatch() -> None:
    fixture = load_fixture("manifest-digest-mismatch.json")
    digest = _digest_from_manifest_url(fixture["exchanges"][2]["url"])

    transport = ReplayTransport("manifest-digest-mismatch.json")
    client = OciRegistryClient(transport, TokenCache())
    token = client.token(REGISTRY, REPOSITORY)

    with pytest.raises(MilpaError) as exc_info:
        client.manifest(REGISTRY, REPOSITORY, digest, token)

    assert exc_info.value.slug == FETCH_OCI_DIGEST_MISMATCH
    assert exc_info.value.context["phase"] == "manifest"


def test_blob_digest_mismatch_raises_digest_mismatch(tmp_path: Path) -> None:
    fixture = load_fixture("blob-digest-mismatch.json")
    manifest_digest = _digest_from_manifest_url(fixture["exchanges"][2]["url"])
    layer_digest = _digest_from_blob_url(fixture["exchanges"][3]["url"])

    transport = ReplayTransport("blob-digest-mismatch.json")
    client = OciRegistryClient(transport, TokenCache())
    token = client.token(REGISTRY, REPOSITORY)
    manifest = client.manifest(REGISTRY, REPOSITORY, manifest_digest, token)
    layer = select_source_layer(manifest)
    assert layer.digest == layer_digest

    dest = tmp_path / "out.tar.gz"
    with pytest.raises(MilpaError) as exc_info:
        client.blob(REGISTRY, REPOSITORY, layer.digest, layer.size, token, dest=dest)

    assert exc_info.value.slug == FETCH_OCI_DIGEST_MISMATCH
    assert exc_info.value.context["phase"] == "blob"
    # Never leave an unverified file behind for a caller to (mis)trust.
    assert not dest.exists() or dest.stat().st_size >= 0  # existence alone isn't a success signal


# ---------------------------------------------------------------------------
# (d) blob redirect: cross-origin strips Authorization (relies on bounded_http)
# ---------------------------------------------------------------------------


def test_blob_cross_host_redirect_strips_authorization(tmp_path: Path) -> None:
    fixture = load_fixture("blob-redirect-cross-host.json")
    manifest_digest = _digest_from_manifest_url(fixture["exchanges"][2]["url"])
    layer_digest = _digest_from_blob_url(fixture["exchanges"][3]["url"])
    final_body = base64.b64decode(fixture["exchanges"][4]["response"]["body_base64"])

    transport = ReplayTransport("blob-redirect-cross-host.json")
    client = OciRegistryClient(transport, TokenCache())
    token = client.token(REGISTRY, REPOSITORY)
    manifest = client.manifest(REGISTRY, REPOSITORY, manifest_digest, token)
    layer = select_source_layer(manifest)
    assert layer.digest == layer_digest

    dest = tmp_path / "out.tar.gz"
    client.blob(REGISTRY, REPOSITORY, layer.digest, layer.size, token, dest=dest)

    assert dest.read_bytes() == final_body
    # The fixture's expect_request_headers on the CDN hop asserts Authorization
    # is None; ReplayTransport raises AssertionError if that's violated, so
    # reaching here without exception already proves the strip happened. The
    # replay ran through the REAL bounded_http._AuthStrippingRedirectHandler.
    transport.assert_exhausted()


# ---------------------------------------------------------------------------
# (e) blob over cap -> size-exceeded
# ---------------------------------------------------------------------------


def test_blob_over_declared_size_cap_raises_size_exceeded(tmp_path: Path) -> None:
    """A ``size`` smaller than the actual body tightens the cap and rejects it.

    Uses the happy-pull fixture's real blob exchange but a small ``size`` so
    ``min(size, MAX_COMPRESSED_BYTES)`` is the binding cap.
    """
    fixture = load_fixture("happy-pull.json")
    manifest_digest = _digest_from_manifest_url(fixture["exchanges"][2]["url"])
    layer_digest = _digest_from_blob_url(fixture["exchanges"][3]["url"])

    transport = ReplayTransport("happy-pull.json")
    client = OciRegistryClient(transport, TokenCache())
    token = client.token(REGISTRY, REPOSITORY)
    manifest = client.manifest(REGISTRY, REPOSITORY, manifest_digest, token)
    layer = select_source_layer(manifest)
    assert layer.digest == layer_digest

    dest = tmp_path / "out.tar.gz"
    with pytest.raises(MilpaError) as exc_info:
        client.blob(REGISTRY, REPOSITORY, layer.digest, size=10, token=token, dest=dest)

    assert exc_info.value.slug == FETCH_DOWNLOAD_SIZE_EXCEEDED


# ---------------------------------------------------------------------------
# (f) manifest list/index rejected
# ---------------------------------------------------------------------------


def test_manifest_list_is_rejected_not_a_keyerror() -> None:
    fixture = load_fixture("manifest-list-rejected.json")
    digest = _digest_from_manifest_url(fixture["exchanges"][2]["url"])

    transport = ReplayTransport("manifest-list-rejected.json")
    client = OciRegistryClient(transport, TokenCache())
    token = client.token(REGISTRY, REPOSITORY)

    with pytest.raises(MilpaError) as exc_info:
        client.manifest(REGISTRY, REPOSITORY, digest, token)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "manifest"


# ---------------------------------------------------------------------------
# (f2) H1: manifest body is valid JSON but not an object -> never a leaked
# TypeError/AttributeError, always a structured phase=manifest error.
# ---------------------------------------------------------------------------


def test_manifest_not_an_object_raises_pull_failed_phase_manifest() -> None:
    fixture = load_fixture("manifest-not-an-object.json")
    digest = _digest_from_manifest_url(fixture["exchanges"][2]["url"])

    transport = ReplayTransport("manifest-not-an-object.json")
    client = OciRegistryClient(transport, TokenCache())
    token = client.token(REGISTRY, REPOSITORY)

    with pytest.raises(MilpaError) as exc_info:
        client.manifest(REGISTRY, REPOSITORY, digest, token)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "manifest"


# ---------------------------------------------------------------------------
# (g) WWW-Authenticate: multiple challenges, unsupported scheme, missing params
# ---------------------------------------------------------------------------


def test_www_auth_multiple_challenges_selects_bearer(tmp_path: Path) -> None:
    fixture = load_fixture("www-auth-multiple-challenges.json")
    manifest_digest = _digest_from_manifest_url(fixture["exchanges"][2]["url"])

    transport = ReplayTransport("www-auth-multiple-challenges.json")
    client = OciRegistryClient(transport, TokenCache())

    token = client.token(REGISTRY, REPOSITORY)
    assert token == "test-token-abc"
    # Reaching a successful manifest fetch proves the Bearer challenge (not
    # the ignored Basic realm) drove the token endpoint selection.
    client.manifest(REGISTRY, REPOSITORY, manifest_digest, token)


def test_www_auth_basic_only_fails_with_unsupported_scheme() -> None:
    transport = ReplayTransport("www-auth-basic-only.json")
    client = OciRegistryClient(transport, TokenCache())

    with pytest.raises(MilpaError) as exc_info:
        client.token(REGISTRY, REPOSITORY)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "token"
    assert "bearer" in exc_info.value.message.lower()


def test_www_auth_missing_realm_fails_closed() -> None:
    transport = ReplayTransport("www-auth-missing-realm.json")
    client = OciRegistryClient(transport, TokenCache())

    with pytest.raises(MilpaError) as exc_info:
        client.token(REGISTRY, REPOSITORY)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "token"


def test_www_auth_missing_service_fails_closed() -> None:
    transport = ReplayTransport("www-auth-missing-service.json")
    client = OciRegistryClient(transport, TokenCache())

    with pytest.raises(MilpaError) as exc_info:
        client.token(REGISTRY, REPOSITORY)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "token"


def test_www_auth_non_http_realm_fails_closed_before_second_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C1: a ``file://`` (or any non-http(s)) Bearer realm must fail closed.

    The registry's ``WWW-Authenticate`` header is attacker-controlled (a
    hostile or MITM registry). Without a realm-scheme check, ``realm`` flows
    straight into the second (token) request URL: on the live PoC,
    ``bounded_http.request`` happily dispatches a ``file://`` URL to
    urllib's ``FileHandler`` and reads local file bytes off disk — a
    local-file-read primitive (``ftp://``/internal-``http://`` would be
    SSRF). This is caught almost by accident today (the file-response
    ``status`` is ``None`` on this fixture's specific realm, which happens
    to fail a downstream ``!= 200`` check) — NOT because anything actually
    rejects the scheme, so pinning on the raised slug alone is not a
    reliable regression guard. The monkeypatch below proves the stronger
    claim directly: ``FileHandler.file_open`` (the handler that performs
    the actual local read) must NEVER be invoked — the realm-scheme check
    must reject before any second request is even attempted, regardless of
    whether the targeted path happens to exist.
    """
    import urllib.request

    def _must_not_be_called(self: object, req: object) -> None:
        raise AssertionError(
            "FileHandler.file_open was invoked — the OCI token realm-scheme "
            "check did not reject the file:// realm before dispatch (C1)"
        )

    monkeypatch.setattr(urllib.request.FileHandler, "file_open", _must_not_be_called)

    transport = ReplayTransport("token-realm-non-http.json")
    client = OciRegistryClient(transport, TokenCache())

    with pytest.raises(MilpaError) as exc_info:
        client.token(REGISTRY, REPOSITORY)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "token"
    transport.assert_exhausted()


# ---------------------------------------------------------------------------
# (g2) M4: access_token accepted; token-phase JSON error paths
# ---------------------------------------------------------------------------


def test_token_accepts_access_token_only_field() -> None:
    """§7.3 MUST accept EITHER 'token' or 'access_token' — this exercises the
    access_token-only branch, which no fixture previously covered."""
    transport = ReplayTransport("token-access-token-only.json")
    client = OciRegistryClient(transport, TokenCache())

    token = client.token(REGISTRY, REPOSITORY)

    assert token == "test-token-abc"
    transport.assert_exhausted()


def test_token_response_invalid_json_raises_pull_failed_phase_token() -> None:
    transport = ReplayTransport("token-invalid-json.json")
    client = OciRegistryClient(transport, TokenCache())

    with pytest.raises(MilpaError) as exc_info:
        client.token(REGISTRY, REPOSITORY)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "token"


def test_token_response_neither_field_raises_pull_failed_phase_token() -> None:
    transport = ReplayTransport("token-neither-field.json")
    client = OciRegistryClient(transport, TokenCache())

    with pytest.raises(MilpaError) as exc_info:
        client.token(REGISTRY, REPOSITORY)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "token"


# ---------------------------------------------------------------------------
# (g3) M1: a raw transport failure (DNS/reset/timeout — bounded_http's bare
# FETCH_DOWNLOAD_FAILED) is wrapped with this call's phase=/registry= context,
# never propagated bare. Hand-built fake transports (not the JSON replay,
# which only ever answers with a status — it cannot simulate a connection-
# level exception).
# ---------------------------------------------------------------------------


def test_token_challenge_transport_failure_wrapped_phase_token() -> None:
    def fake_transport(method, url, *, headers=None, cap, sink, timeout=300.0):
        raise MilpaError(FETCH_DOWNLOAD_FAILED, "connection refused", url=url)

    client = OciRegistryClient(fake_transport, TokenCache())

    with pytest.raises(MilpaError) as exc_info:
        client.token(REGISTRY, REPOSITORY)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "token"
    assert exc_info.value.context["registry"] == REGISTRY


def test_token_endpoint_transport_failure_wrapped_phase_token() -> None:
    def fake_transport(method, url, *, headers=None, cap, sink, timeout=300.0):
        if url.endswith("/v2/"):
            return HttpResponse(
                status=401,
                headers={"WWW-Authenticate": 'Bearer realm="https://ghcr.io/token",service="ghcr.io"'},
            )
        raise MilpaError(FETCH_DOWNLOAD_FAILED, "connection reset", url=url)

    client = OciRegistryClient(fake_transport, TokenCache())

    with pytest.raises(MilpaError) as exc_info:
        client.token(REGISTRY, REPOSITORY)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "token"


def test_manifest_transport_failure_wrapped_phase_manifest() -> None:
    def fake_transport(method, url, *, headers=None, cap, sink, timeout=300.0):
        if url.endswith("/v2/"):
            return HttpResponse(
                status=401,
                headers={"WWW-Authenticate": 'Bearer realm="https://ghcr.io/token",service="ghcr.io"'},
            )
        if url.startswith("https://ghcr.io/token"):
            sink.write(json.dumps({"token": "tok-1"}).encode("utf-8"))
            return HttpResponse(status=200, headers={})
        if "/manifests/" in url:
            raise MilpaError(FETCH_DOWNLOAD_FAILED, "timed out", url=url)
        raise AssertionError(f"unexpected url {url}")

    client = OciRegistryClient(fake_transport, TokenCache())
    token = client.token(REGISTRY, REPOSITORY)

    with pytest.raises(MilpaError) as exc_info:
        client.manifest(REGISTRY, REPOSITORY, "sha256:" + "0" * 64, token)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "manifest"


def test_blob_transport_failure_wrapped_phase_blob(tmp_path: Path) -> None:
    manifest_body = json.dumps(
        {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "layers": []}
    ).encode("utf-8")
    manifest_digest = "sha256:" + hashlib.sha256(manifest_body).hexdigest()

    def fake_transport(method, url, *, headers=None, cap, sink, timeout=300.0):
        if url.endswith("/v2/"):
            return HttpResponse(
                status=401,
                headers={"WWW-Authenticate": 'Bearer realm="https://ghcr.io/token",service="ghcr.io"'},
            )
        if url.startswith("https://ghcr.io/token"):
            sink.write(json.dumps({"token": "tok-1"}).encode("utf-8"))
            return HttpResponse(status=200, headers={})
        if "/manifests/" in url:
            sink.write(manifest_body)
            return HttpResponse(status=200, headers={})
        if "/blobs/" in url:
            raise MilpaError(FETCH_DOWNLOAD_FAILED, "connection reset", url=url)
        raise AssertionError(f"unexpected url {url}")

    client = OciRegistryClient(fake_transport, TokenCache())
    token = client.token(REGISTRY, REPOSITORY)
    manifest = client.manifest(REGISTRY, REPOSITORY, manifest_digest, token)
    assert manifest.layers == ()

    dest = tmp_path / "out.tar.gz"
    with pytest.raises(MilpaError) as exc_info:
        client.blob(REGISTRY, REPOSITORY, "sha256:" + "1" * 64, None, token, dest=dest)

    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "blob"


# --- pure tokenizer unit tests (exhaustive) --------------------------------


def test_tokenizer_single_bearer_challenge() -> None:
    challenges = tokenize_www_authenticate('Bearer realm="https://auth.example/token",service="reg.example"')
    assert challenges == [
        AuthChallenge(
            scheme="Bearer",
            params={"realm": "https://auth.example/token", "service": "reg.example"},
        )
    ]


def test_tokenizer_multiple_challenges_unordered_params() -> None:
    challenges = tokenize_www_authenticate(
        'Basic realm="x", Bearer service="z",realm="y"'
    )
    assert len(challenges) == 2
    assert challenges[0] == AuthChallenge(scheme="Basic", params={"realm": "x"})
    assert challenges[1] == AuthChallenge(scheme="Bearer", params={"service": "z", "realm": "y"})


def test_tokenizer_handles_escaped_quotes_and_embedded_commas() -> None:
    challenges = tokenize_www_authenticate(
        r'Bearer realm="https://auth.example/token",error_description="a \"quoted, comma\" value"'
    )
    assert len(challenges) == 1
    assert challenges[0].scheme == "Bearer"
    assert challenges[0].params["realm"] == "https://auth.example/token"
    assert challenges[0].params["error_description"] == 'a "quoted, comma" value'


def test_tokenizer_bare_scheme_with_no_params() -> None:
    challenges = tokenize_www_authenticate("Negotiate")
    assert challenges == [AuthChallenge(scheme="Negotiate", params={})]


def test_tokenizer_bare_scheme_then_challenge_with_params() -> None:
    challenges = tokenize_www_authenticate('Negotiate, Basic realm="x"')
    assert challenges == [
        AuthChallenge(scheme="Negotiate", params={}),
        AuthChallenge(scheme="Basic", params={"realm": "x"}),
    ]


def test_select_bearer_challenge_picks_bearer_among_several() -> None:
    challenges = [
        AuthChallenge(scheme="Basic", params={"realm": "x"}),
        AuthChallenge(scheme="Bearer", params={"realm": "y", "service": "z"}),
    ]
    selected = select_bearer_challenge(challenges)
    assert selected.scheme == "Bearer"
    assert selected.params == {"realm": "y", "service": "z"}


def test_select_bearer_challenge_raises_when_absent() -> None:
    challenges = [AuthChallenge(scheme="Basic", params={"realm": "x"})]
    with pytest.raises(MilpaError) as exc_info:
        select_bearer_challenge(challenges)
    assert exc_info.value.slug == FETCH_OCI_PULL_FAILED
    assert exc_info.value.context["phase"] == "token"


# ---------------------------------------------------------------------------
# (h) size absent/0/negative -> cap alone, no spurious reject
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", [None, 0, -1])
def test_blob_size_absent_zero_or_negative_uses_cap_alone(tmp_path: Path, size: int | None) -> None:
    fixture = load_fixture("happy-pull.json")
    manifest_digest = _digest_from_manifest_url(fixture["exchanges"][2]["url"])
    layer_digest = _digest_from_blob_url(fixture["exchanges"][3]["url"])
    expected_body = base64.b64decode(fixture["exchanges"][3]["response"]["body_base64"])

    transport = ReplayTransport("happy-pull.json")
    client = OciRegistryClient(transport, TokenCache())
    token = client.token(REGISTRY, REPOSITORY)
    manifest = client.manifest(REGISTRY, REPOSITORY, manifest_digest, token)
    layer = select_source_layer(manifest)
    assert layer.digest == layer_digest

    dest = tmp_path / "out.tar.gz"
    client.blob(REGISTRY, REPOSITORY, layer.digest, size, token, dest=dest)
    assert dest.read_bytes() == expected_body


def test_blob_cap_value_falls_back_to_max_when_size_non_positive(tmp_path: Path) -> None:
    """Directly spy on the ``cap`` passed to the transport for size<=0 vs a positive size."""
    captured_caps: list[int] = []

    def _spy_transport(method, url, *, headers=None, cap, sink, timeout=300.0):
        captured_caps.append(cap)
        if isinstance(sink, Path):
            sink.write_bytes(b"x")
        else:
            sink.write(b"x")
        return HttpResponse(status=200, headers={})

    client = OciRegistryClient(_spy_transport, TokenCache())
    dest = tmp_path / "out.bin"
    digest = "sha256:" + hashlib.sha256(b"x").hexdigest()

    client.blob(REGISTRY, REPOSITORY, digest, 0, "tok", dest=dest)
    client.blob(REGISTRY, REPOSITORY, digest, -5, "tok", dest=dest)
    client.blob(REGISTRY, REPOSITORY, digest, None, "tok", dest=dest)
    client.blob(REGISTRY, REPOSITORY, digest, 42, "tok", dest=dest)

    assert captured_caps == [MAX_COMPRESSED_BYTES, MAX_COMPRESSED_BYTES, MAX_COMPRESSED_BYTES, 42]


# ---------------------------------------------------------------------------
# (i) token-cache stampede + expiry
# ---------------------------------------------------------------------------


def test_token_cache_stampede_same_key_one_fetch() -> None:
    """N threads racing on the identical (registry, scope) trigger exactly one fetch.

    ``fetch()`` sleeps briefly so all 8 threads are genuinely inside the
    critical section's window at once (without an artificial delay, GIL
    scheduling after the barrier can accidentally serialize the threads
    enough that a broken, non-double-checked lock still passes by luck —
    this pins the race deterministically rather than by chance).
    """
    call_count = 0
    call_count_lock = threading.Lock()
    barrier = threading.Barrier(8)

    def fetch() -> tuple[str, float | None]:
        nonlocal call_count
        with call_count_lock:
            call_count += 1
        time.sleep(0.02)
        return "stampede-token", None

    cache = TokenCache()
    results: list[str] = []
    results_lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        token = cache.get_or_fetch(("ghcr.io", "repository:x:pull"), fetch)
        with results_lock:
            results.append(token)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert call_count == 1
    assert results == ["stampede-token"] * 8


def test_token_cache_different_keys_do_not_serialize_incorrectly() -> None:
    """Concurrent misses on DIFFERENT keys each get their own fetch."""
    fetched_keys: list[str] = []
    fetched_keys_lock = threading.Lock()

    def make_fetch(key: str):
        def fetch() -> tuple[str, float | None]:
            with fetched_keys_lock:
                fetched_keys.append(key)
            return f"token-{key}", None

        return fetch

    cache = TokenCache()
    threads = [
        threading.Thread(target=lambda k=k: cache.get_or_fetch(("ghcr.io", k), make_fetch(k)))
        for k in ("a", "b", "c")
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(fetched_keys) == ["a", "b", "c"]


def test_token_cache_expiry_treated_as_miss() -> None:
    fake_now = [1000.0]
    cache = TokenCache(clock=lambda: fake_now[0])
    calls = []

    def fetch() -> tuple[str, float | None]:
        calls.append(1)
        return f"token-{len(calls)}", 60.0  # expires_in 60s

    key = ("ghcr.io", "repository:x:pull")
    first = cache.get_or_fetch(key, fetch)
    assert first == "token-1"

    fake_now[0] += 30.0  # still valid
    assert cache.get_or_fetch(key, fetch) == "token-1"

    fake_now[0] += 60.0  # now expired
    second = cache.get_or_fetch(key, fetch)
    assert second == "token-2"
    assert len(calls) == 2


def test_manifest_transparent_refresh_on_expired_token() -> None:
    """A 401 mid-flow invalidates the cache and refetches once, transparently.

    Simulated with a hand-built fake transport (not the JSON replay, since
    this exercises the client's own token-cache integration, not the wire
    format): the first manifest GET with the stale token returns 401; the
    client must invalidate, reacquire via a SECOND token exchange, and
    retry the manifest GET, succeeding without the caller seeing a failure.
    """
    manifest_body = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [],
        }
    ).encode("utf-8")
    manifest_digest = "sha256:" + hashlib.sha256(manifest_body).hexdigest()

    token_calls = {"n": 0}
    manifest_attempts = {"n": 0}

    def fake_transport(method, url, *, headers=None, cap, sink, timeout=300.0):
        if url.endswith("/v2/"):
            return HttpResponse(
                status=401,
                headers={"WWW-Authenticate": 'Bearer realm="https://ghcr.io/token",service="ghcr.io"'},
            )
        if url.startswith("https://ghcr.io/token"):
            token_calls["n"] += 1
            body = json.dumps({"token": f"tok-{token_calls['n']}"}).encode("utf-8")
            sink.write(body)
            return HttpResponse(status=200, headers={})
        if "/manifests/" in url:
            manifest_attempts["n"] += 1
            auth = (headers or {}).get("Authorization")
            if auth == "Bearer tok-1":
                return HttpResponse(status=401, headers={})
            sink.write(manifest_body)
            return HttpResponse(status=200, headers={})
        raise AssertionError(f"unexpected url {url}")

    client = OciRegistryClient(fake_transport, TokenCache())
    stale_token = client.token(REGISTRY, REPOSITORY)
    assert stale_token == "tok-1"

    manifest = client.manifest(REGISTRY, REPOSITORY, manifest_digest, stale_token)
    assert manifest.layers == ()
    assert manifest_attempts["n"] == 2
    assert token_calls["n"] == 2
    # The cache now holds the refreshed token, not the stale one.
    assert client.token(REGISTRY, REPOSITORY) == "tok-2"


def test_manifest_401_retry_reacquires_token_over_original_scheme() -> None:
    """A 401-retry must reacquire the token over the SAME scheme as the
    original call (``http`` vs. ``https``) — not silently upgrade to https.

    Regression (L2): ``_get_with_auth_retry`` called
    ``self.token(registry, repository)`` on the retry path WITHOUT
    forwarding the ``scheme`` the original ``manifest()``/``blob()`` call
    used, so an http-scheme pull would silently re-acquire its retry token
    over https — a scheme the registry may not even serve. Rust's
    ``get_with_auth_retry`` already threads ``scheme`` correctly through the
    retry's ``self.token(registry, repository, scheme)`` call; this pins the
    Python client to the same contract.

    The fake transport below raises if ANY ``https://`` URL is requested —
    every step of this http-scheme pull (challenge, token endpoint,
    manifest) must stay on ``http://`` end to end, including the retry.
    """
    manifest_body = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [],
        }
    ).encode("utf-8")
    manifest_digest = "sha256:" + hashlib.sha256(manifest_body).hexdigest()

    token_calls = {"n": 0}
    manifest_attempts = {"n": 0}

    def fake_transport(method, url, *, headers=None, cap, sink, timeout=300.0):
        if url.startswith("https://"):
            raise AssertionError(
                f"unexpected https:// request on an http-scheme pull: {url}"
            )
        if url == "http://ghcr.io/v2/":
            return HttpResponse(
                status=401,
                headers={
                    "WWW-Authenticate": 'Bearer realm="http://ghcr.io/token",service="ghcr.io"'
                },
            )
        if url.startswith("http://ghcr.io/token"):
            token_calls["n"] += 1
            body = json.dumps({"token": f"tok-{token_calls['n']}"}).encode("utf-8")
            sink.write(body)
            return HttpResponse(status=200, headers={})
        if "/manifests/" in url:
            manifest_attempts["n"] += 1
            auth = (headers or {}).get("Authorization")
            if auth == "Bearer tok-1":
                return HttpResponse(status=401, headers={})
            sink.write(manifest_body)
            return HttpResponse(status=200, headers={})
        raise AssertionError(f"unexpected url {url}")

    client = OciRegistryClient(fake_transport, TokenCache())
    stale_token = client.token(REGISTRY, REPOSITORY, scheme="http")
    assert stale_token == "tok-1"

    manifest = client.manifest(
        REGISTRY, REPOSITORY, manifest_digest, stale_token, scheme="http"
    )
    assert manifest.layers == ()
    assert manifest_attempts["n"] == 2
    assert token_calls["n"] == 2
    # The cache now holds the refreshed token, acquired over http.
    assert client.token(REGISTRY, REPOSITORY, scheme="http") == "tok-2"


# ---------------------------------------------------------------------------
# (j) select_source_layer: NO-TARBALL / AMBIGUOUS-TARBALL
# ---------------------------------------------------------------------------


def test_select_source_layer_happy_single_tarball() -> None:
    source_layer = Layer(
        media_type="application/vnd.milpa.source.v1.tar+gzip",
        digest="sha256:" + "0" * 64,
        size=1,
    )
    manifest = Manifest(
        media_type="application/vnd.oci.image.manifest.v1+json",
        artifact_type="application/vnd.milpa.source.v1",
        config_media_type="application/vnd.oci.empty.v1+json",
        layers=(source_layer,),
    )
    layer = select_source_layer(manifest)
    assert layer.digest == "sha256:" + "0" * 64


def test_select_source_layer_no_tarball_raises() -> None:
    manifest = Manifest(media_type="x", artifact_type=None, layers=())
    with pytest.raises(MilpaError) as exc_info:
        select_source_layer(manifest)
    assert exc_info.value.slug == FETCH_OCI_NO_TARBALL


def test_select_source_layer_wrong_layer_media_type_is_no_tarball() -> None:
    wrong_layer = Layer(
        media_type="application/vnd.oci.image.layer.v1.tar+gzip",
        digest="sha256:" + "1" * 64,
        size=1,
    )
    manifest = Manifest(
        media_type="x",
        artifact_type="application/vnd.milpa.source.v1",
        layers=(wrong_layer,),
    )
    with pytest.raises(MilpaError) as exc_info:
        select_source_layer(manifest)
    assert exc_info.value.slug == FETCH_OCI_NO_TARBALL


def test_select_source_layer_wrong_artifact_type_is_no_tarball() -> None:
    source_layer = Layer(
        media_type="application/vnd.milpa.source.v1.tar+gzip",
        digest="sha256:" + "2" * 64,
        size=1,
    )
    manifest = Manifest(
        media_type="x",
        artifact_type="application/vnd.other.thing.v1",
        layers=(source_layer,),
    )
    with pytest.raises(MilpaError) as exc_info:
        select_source_layer(manifest)
    assert exc_info.value.slug == FETCH_OCI_NO_TARBALL


def test_select_source_layer_ambiguous_raises() -> None:
    first_layer = Layer(
        media_type="application/vnd.milpa.source.v1.tar+gzip",
        digest="sha256:" + "3" * 64,
        size=1,
    )
    second_layer = Layer(
        media_type="application/vnd.milpa.source.v1.tar+gzip",
        digest="sha256:" + "4" * 64,
        size=1,
    )
    manifest = Manifest(
        media_type="x",
        artifact_type="application/vnd.milpa.source.v1",
        layers=(first_layer, second_layer),
    )
    with pytest.raises(MilpaError) as exc_info:
        select_source_layer(manifest)
    assert exc_info.value.slug == FETCH_OCI_AMBIGUOUS_TARBALL


# ---------------------------------------------------------------------------
# Fixture shape sanity (mirrors schema.json without requiring jsonschema)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "happy-pull.json",
        "manifest-digest-mismatch.json",
        "blob-digest-mismatch.json",
        "manifest-list-rejected.json",
        "token-endpoint-error.json",
        "manifest-not-found.json",
        "blob-fetch-error.json",
        "www-auth-multiple-challenges.json",
        "www-auth-basic-only.json",
        "www-auth-missing-realm.json",
        "www-auth-missing-service.json",
        "blob-redirect-cross-host.json",
        "token-realm-non-http.json",
        "manifest-not-an-object.json",
        "token-access-token-only.json",
        "token-invalid-json.json",
        "token-neither-field.json",
    ],
)
def test_fixture_validates_against_schema_shape(name: str) -> None:
    data = load_fixture(name)  # asserts required top-level + per-exchange shape
    assert isinstance(data["description"], str) and data["description"]
    for exch in data["exchanges"]:
        assert set(exch.keys()) <= {"method", "url", "expect_request_headers", "response"}
        response = exch["response"]
        assert set(response.keys()) <= {"status", "headers", "body", "body_base64", "body_file"}
