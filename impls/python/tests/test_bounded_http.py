"""Tests for milpa.bounded_http — the native in-process HTTP transport primitive.

RFC: docs/rfc-native-oci-fetch.md §3.3 (the (cap, sink) primitive), §3.8
(redirect Authorization-stripping), §0.1 (proxy-env, timeouts).

This is S1: the Python foundation primitive only — no caller is migrated yet.
Tests drive real in-process HTTP servers bound to 127.0.0.1 (no network) so
the transport, cap enforcement, and redirect handling are exercised against
real sockets rather than fakes at the urllib boundary.
"""

from __future__ import annotations

import contextlib
import http.server
import io
import socket
import struct
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from milpa.bounded_http import request
from milpa.errors import FETCH_DOWNLOAD_FAILED, FETCH_DOWNLOAD_SIZE_EXCEEDED, MilpaError


@contextlib.contextmanager
def _serve(handler_cls: type[http.server.BaseHTTPRequestHandler]) -> Iterator[str]:
    """Start a threaded HTTP server on 127.0.0.1 with an ephemeral port.

    Yields the server's base URL (``http://127.0.0.1:<port>``); shuts the
    server down on exit.
    """
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@contextlib.contextmanager
def _serve_raw(conn_handler: object) -> Iterator[str]:
    """Start a bare TCP listener; ``conn_handler(conn)`` writes the response
    bytes itself over the raw socket — full control over headers, partial
    bodies, and how the connection ends (clean FIN vs. abortive RST), which
    ``http.server``'s framing does not expose.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _accept_one() -> None:
        try:
            conn, _addr = listener.accept()
        except OSError:
            return
        try:
            conn_handler(conn)  # type: ignore[operator]
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    thread = threading.Thread(target=_accept_one)
    thread.daemon = True
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        listener.close()
        thread.join(timeout=5)


def _drain_request_headers(conn: socket.socket) -> None:
    """Read and discard bytes through the end of the request's header block."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return
        buf += chunk


def _force_reset_on_close(conn: socket.socket) -> None:
    """Configure ``conn`` so closing it sends a TCP RST instead of a clean FIN.

    ``SO_LINGER`` with ``l_onoff=1, l_linger=0`` is the standard way to force
    an abortive close — verified empirically to raise ``ConnectionResetError``
    client-side even after some response bytes were already delivered.
    """
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


def test_get_small_body_into_bytesio_sink() -> None:
    """A 200 response with a small body lands its bytes in a BytesIO sink."""
    body = b"hello world"

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    with _serve(_Handler) as base_url:
        sink = io.BytesIO()
        resp = request("GET", f"{base_url}/x", cap=1024, sink=sink)

    assert resp.status == 200
    assert sink.getvalue() == body


def test_get_streams_body_into_path_sink(tmp_path: Path) -> None:
    """A 200 response streamed into a Path sink lands the exact bytes on disk."""
    body = b"a" * 1000

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    with _serve(_Handler) as base_url:
        dest = tmp_path / "out.bin"
        resp = request("GET", f"{base_url}/x", cap=len(body), sink=dest)

    assert resp.status == 200
    assert dest.read_bytes() == body


def test_body_exceeding_cap_raises_size_exceeded_mid_stream() -> None:
    """A body larger than ``cap`` raises FETCH-DOWNLOAD-SIZE-EXCEEDED.

    The cap must fire while streaming, not after buffering the whole
    oversized body: the server sends far more than the cap, so a
    buffer-then-check implementation would still pass this test, but
    combined with the boundary test below it pins the streaming contract.
    """
    body = b"x" * 200

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    with _serve(_Handler) as base_url:
        sink = io.BytesIO()
        with pytest.raises(MilpaError) as exc_info:
            request("GET", f"{base_url}/x", cap=50, sink=sink)

    assert exc_info.value.slug == FETCH_DOWNLOAD_SIZE_EXCEEDED


def test_body_exactly_at_cap_is_admitted() -> None:
    """A body of exactly ``cap`` bytes is admitted — the cap is inclusive."""
    body = b"y" * 64

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    with _serve(_Handler) as base_url:
        sink = io.BytesIO()
        resp = request("GET", f"{base_url}/x", cap=len(body), sink=sink)

    assert resp.status == 200
    assert sink.getvalue() == body


def test_404_response_returned_as_status_not_raised() -> None:
    """An HTTP error status is DATA at this layer, not an exception.

    Callers (e.g. the future OCI auth flow) branch on ``response.status``;
    only transport-level failures raise.
    """

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    with _serve(_Handler) as base_url:
        sink = io.BytesIO()
        resp = request("GET", f"{base_url}/missing", cap=1024, sink=sink)

    assert resp.status == 404


def test_connection_error_raises_download_failed() -> None:
    """A connection error (nobody listening) raises FETCH-DOWNLOAD-FAILED.

    Bind and immediately close a socket to get an ephemeral port on
    127.0.0.1 that is guaranteed to have nobody listening on it.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    sink = io.BytesIO()
    with pytest.raises(MilpaError) as exc_info:
        request("GET", f"http://127.0.0.1:{port}/x", cap=1024, sink=sink)

    assert exc_info.value.slug == FETCH_DOWNLOAD_FAILED


def test_cross_host_redirect_strips_authorization() -> None:
    """A redirect to a different host must NOT carry the Authorization header.

    ghcr blob GETs 307 to a CDN host; forwarding the bearer token there
    would leak it to a third party (RFC §3.8).
    """
    received_auth: dict[str, str | None] = {}

    class _HandlerB(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            received_auth["value"] = self.headers.get("Authorization")
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args: object) -> None:
            pass

    with _serve(_HandlerB) as base_b:

        class _HandlerA(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", f"{base_b}/target")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args: object) -> None:
                pass

        with _serve(_HandlerA) as base_a:
            sink = io.BytesIO()
            resp = request(
                "GET",
                f"{base_a}/start",
                cap=1024,
                sink=sink,
                headers={"Authorization": "Bearer secret-token"},
            )

    assert resp.status == 200
    assert sink.getvalue() == b"ok"
    assert received_auth["value"] is None


def test_redirect_loop_exceeding_hop_cap_raises_download_failed() -> None:
    """An infinite (>hop-cap) redirect chain fails CLOSED, not open.

    H2: urllib's OWN redirect-loop guard raises ``HTTPError`` carrying the
    LAST hop's stale 3xx status once a chain exceeds its hop cap.  Left
    unhandled, ``request()``'s "status codes are data" branch would return
    that as an ordinary ``HttpResponse(status=3xx)`` — verified empirically
    before this fix: the request "succeeded" with status=307 and zero
    bytes ever fetched.  Assert it now surfaces as FETCH-DOWNLOAD-FAILED,
    matching Rust's ``MAX_REDIRECT_HOPS`` behavior.
    """

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            # Every hop redirects to the NEXT distinct URL, forever — no
            # terminal response is ever reached.
            n = int(self.path.rsplit("/", 1)[-1])
            self.send_response(302)
            self.send_header("Location", f"/hop/{n + 1}")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    with _serve(_Handler) as base_url:
        sink = io.BytesIO()
        with pytest.raises(MilpaError) as exc_info:
            request("GET", f"{base_url}/hop/0", cap=1024, sink=sink)

    assert exc_info.value.slug == FETCH_DOWNLOAD_FAILED


def test_three_hop_redirect_keeps_authorization_stripped_after_returning_to_original_origin() -> None:
    """Monotonic strip (RFC §3.8, M2) — confirmed on the Python side.

    Chain: A (original request, carries Authorization) -> B (a different
    origin, so Authorization strips) -> C, which is back on A's exact
    origin. Once stripped at B, Authorization must stay absent at C even
    though C's origin matches the ORIGINAL request's origin — a policy
    that recomputed the strip fresh against the original at every hop
    would incorrectly restore it at C.
    """
    urls: dict[str, str] = {}
    received_at_final: dict[str, str | None] = {}

    class _HandlerA(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", f"{urls['b']}/mid")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                received_at_final["value"] = self.headers.get("Authorization")
                self.send_response(200)
                self.send_header("Content-Length", "5")
                self.end_headers()
                self.wfile.write(b"final")

        def log_message(self, *args: object) -> None:
            pass

    class _HandlerB(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", f"{urls['a']}/final")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    with _serve(_HandlerA) as base_a, _serve(_HandlerB) as base_b:
        urls["a"] = base_a
        urls["b"] = base_b
        sink = io.BytesIO()
        resp = request(
            "GET",
            f"{base_a}/start",
            cap=1024,
            sink=sink,
            headers={"Authorization": "Bearer secret-token"},
        )

    assert resp.status == 200
    assert sink.getvalue() == b"final"
    assert received_at_final["value"] is None


def test_same_origin_predicate_exhaustive() -> None:
    """``_same_origin`` — the origin-equality predicate driving the redirect strip.

    A real TLS socket is impractical to stand up in-process for the
    same-host scheme-downgrade case, so that case (and port changes,
    case-insensitivity) is pinned directly against the pure predicate
    (RFC §3.8 round 2).
    """
    from milpa.bounded_http import _same_origin

    # Identical origin (same scheme/host/port, different path) → same.
    assert _same_origin("https://ghcr.io/a", "https://ghcr.io/b") is True
    # Same-host scheme downgrade → cross-origin (the round-2 case).
    assert _same_origin("https://ghcr.io/a", "http://ghcr.io/a") is False
    # Different host → cross-origin.
    assert _same_origin("https://ghcr.io/a", "https://other.example/a") is False
    # Explicit default port matches the implicit default → same.
    assert _same_origin("https://ghcr.io:443/a", "https://ghcr.io/a") is True
    assert _same_origin("http://ghcr.io:80/a", "http://ghcr.io/a") is True
    # Non-default port change → cross-origin.
    assert _same_origin("https://ghcr.io/a", "https://ghcr.io:9443/a") is False
    # Scheme/host comparison is case-insensitive.
    assert _same_origin("HTTPS://GHCR.IO/a", "https://ghcr.io/a") is True


def test_request_headers_are_sent() -> None:
    """Headers passed via ``headers=`` are sent on the outgoing request."""
    received: dict[str, str | None] = {}

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            received["x-custom"] = self.headers.get("X-Custom")
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    with _serve(_Handler) as base_url:
        sink = io.BytesIO()
        request("GET", f"{base_url}/x", cap=1024, sink=sink, headers={"X-Custom": "hi"})

    assert received["x-custom"] == "hi"


def test_response_headers_are_case_insensitive() -> None:
    """``HttpResponse.headers`` lookups are case-insensitive."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.send_header("X-Test-Header", "value123")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    with _serve(_Handler) as base_url:
        sink = io.BytesIO()
        resp = request("GET", f"{base_url}/x", cap=1024, sink=sink)

    assert resp.headers["x-test-header"] == "value123"
    assert resp.headers["X-Test-Header"] == "value123"


def test_ftp_scheme_is_rejected_not_silently_followed() -> None:
    """``ftp://`` must fail closed with FETCH-DOWNLOAD-FAILED.

    C1 (confirmed critical finding): the opener used to be built via a bare
    ``urllib.request.build_opener(...)``, which installs the FULL default
    handler set — including ``FTPHandler``. Combined with an OCI registry
    controlling the token ``realm`` (RFC §3.2 step 1), that made an
    ``ftp://`` (or ``file://``, or ``data://``) realm a live transport
    primitive an attacker-controlled ``WWW-Authenticate`` header could
    steer ``request()`` into. ``ftp://`` must now fail closed instead of
    being silently dispatched (RFC §3.8 defense-in-depth).
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    sink = io.BytesIO()
    with pytest.raises(MilpaError) as exc_info:
        request("GET", f"ftp://127.0.0.1:{port}/nonexistent", cap=1024, sink=sink, timeout=5)

    assert exc_info.value.slug == FETCH_DOWNLOAD_FAILED


def test_data_scheme_is_rejected_not_silently_followed() -> None:
    """``data://`` must fail closed with FETCH-DOWNLOAD-FAILED (see above)."""
    sink = io.BytesIO()
    with pytest.raises(MilpaError) as exc_info:
        request("GET", "data:text/plain,hello", cap=1024, sink=sink)

    assert exc_info.value.slug == FETCH_DOWNLOAD_FAILED


def test_file_scheme_still_reads_local_files(tmp_path: Path) -> None:
    """``file://`` must keep working — it is a first-class scheme for the
    OTHER bounded_http callers (index_cache, dep_decl_store,
    entry_bundle_store, tarball fetcher — air-gapped/harness deployments;
    every conformance fixture uses a ``file://`` index). The fix must be
    scoped to excluding ftp/data/unknown, NOT a blanket non-http(s) reject.
    """
    target = tmp_path / "hello.txt"
    target.write_bytes(b"hello-file-scheme")

    sink = io.BytesIO()
    resp = request("GET", f"file://{target}", cap=1024, sink=sink)

    assert sink.getvalue() == b"hello-file-scheme"
    assert resp.status is None


def test_opener_honors_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The opener honors HTTP_PROXY — proxy-env parity with curl (RFC §0.1).

    ``ProxyHandler`` only registers itself with the opener when it has an
    actual proxy to route through (it derives its ``*_open`` methods from
    ``getproxies()`` at construction time), so with no proxy env set it is
    silently absent from ``opener.handlers`` even when correctly wired —
    that absence is not itself a bug.  Setting a proxy env var makes the
    handler's presence observable: a primitive built from a hand-rolled
    handler list that dropped ``ProxyHandler`` would never pick this up,
    no matter the environment; one built via ``build_opener(...)`` does.
    """
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:8080")
    import urllib.request as urllib_request

    from milpa.bounded_http import _build_opener

    opener = _build_opener()

    assert any(isinstance(h, urllib_request.ProxyHandler) for h in opener.handlers)


# ---------------------------------------------------------------------------
# Bug 1 (HIGH) — mid-stream transport failure must not escape unwrapped
# ---------------------------------------------------------------------------


def test_mid_stream_connection_reset_raises_download_failed() -> None:
    """A server that sends headers, then RSTs mid-body, must surface as
    ``MilpaError(FETCH_DOWNLOAD_FAILED)`` — not a raw ``ConnectionResetError``
    escaping ``request()`` unwrapped.

    Verified empirically: ``opener.open(...)`` succeeds (headers land fine),
    and the reset only fires on the body ``read()`` call inside
    ``_stream_capped`` — a phase the pre-fix ``try/except`` around
    ``request()`` did not cover.
    """

    def _conn_handler(conn: socket.socket) -> None:
        _drain_request_headers(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial-body")
        _force_reset_on_close(conn)

    with _serve_raw(_conn_handler) as base_url:
        sink = io.BytesIO()
        with pytest.raises(MilpaError) as exc_info:
            request("GET", f"{base_url}/x", cap=1024 * 1024, sink=sink)

    assert exc_info.value.slug == FETCH_DOWNLOAD_FAILED


def test_mid_stream_reset_does_not_masquerade_as_size_exceeded() -> None:
    """Guard the CRITICAL constraint: the mid-stream fix must not rewrap or
    swallow ``MilpaError(FETCH_DOWNLOAD_SIZE_EXCEEDED)`` — that is a distinct,
    already-structured error and must propagate unchanged. This test pins the
    OTHER branch (cap-exceeded, no reset at all) so a future change to the
    new try/except cannot accidentally widen it to catch ``MilpaError`` too.
    """
    body = b"x" * 200

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    with _serve(_Handler) as base_url:
        sink = io.BytesIO()
        with pytest.raises(MilpaError) as exc_info:
            request("GET", f"{base_url}/x", cap=50, sink=sink)

    assert exc_info.value.slug == FETCH_DOWNLOAD_SIZE_EXCEEDED


# ---------------------------------------------------------------------------
# Bug 2 (MEDIUM) — Content-Length completeness check
# ---------------------------------------------------------------------------


def test_truncated_body_with_content_length_raises_download_failed() -> None:
    """A peer that closes CLEANLY mid-body (no RST) after declaring a
    ``Content-Length`` it never delivers must NOT be reported as a 200
    success with a silently truncated body — that misclassifies a benign
    transport truncation as tampering downstream (OCI digest mismatch /
    tarball extract failure). Must raise FETCH-DOWNLOAD-FAILED instead.
    """

    def _conn_handler(conn: socket.socket) -> None:
        _drain_request_headers(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
        # Clean close (default SO_LINGER) — a plain FIN, no RST. The
        # underlying read() calls return the 5 bytes then a clean EOF, no
        # exception at all; only the completeness check catches this.

    with _serve_raw(_conn_handler) as base_url:
        sink = io.BytesIO()
        with pytest.raises(MilpaError) as exc_info:
            request("GET", f"{base_url}/x", cap=1024, sink=sink)

    assert exc_info.value.slug == FETCH_DOWNLOAD_FAILED


def test_full_length_body_matching_content_length_still_succeeds() -> None:
    """A correct, complete body (received bytes == declared Content-Length)
    must still succeed — the completeness check must not misfire on the
    happy path.
    """
    body = b"a complete, correctly-lengthed response body"

    def _conn_handler(conn: socket.socket) -> None:
        _drain_request_headers(conn)
        conn.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)

    with _serve_raw(_conn_handler) as base_url:
        sink = io.BytesIO()
        resp = request("GET", f"{base_url}/x", cap=1024, sink=sink)

    assert resp.status == 200
    assert sink.getvalue() == body


def test_response_without_content_length_is_not_length_checked() -> None:
    """No ``Content-Length`` header means there is no declared length to
    check against — an HTTP/1.0-style close-delimited body must not
    spuriously fail the (absent) completeness check.
    """

    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"hello")

        def log_message(self, *args: object) -> None:
            pass

    with _serve(_Handler) as base_url:
        sink = io.BytesIO()
        resp = request("GET", f"{base_url}/x", cap=1024, sink=sink)

    assert resp.status == 200
    assert sink.getvalue() == b"hello"


def test_chunked_response_is_not_length_checked() -> None:
    """A ``Transfer-Encoding: chunked`` response has no ``Content-Length`` at
    all — it must be unaffected by the completeness check regardless of how
    many bytes the dechunked body turns out to contain.
    """

    def _conn_handler(conn: socket.socket) -> None:
        _drain_request_headers(conn)
        conn.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\nhello\r\n"
            b"0\r\n\r\n"
        )

    with _serve_raw(_conn_handler) as base_url:
        sink = io.BytesIO()
        resp = request("GET", f"{base_url}/x", cap=1024, sink=sink)

    assert resp.status == 200
    assert sink.getvalue() == b"hello"
