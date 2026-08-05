"""Canned-transport fixture replay for OCI-client unit tests (RFC S5/S7).

Loads a ``conformance/oci-transport/*.json`` transcript (schema pinned in
S0) and drives it through the REAL ``milpa.bounded_http.request`` code path
— cap enforcement, HTTPError handling, and (crucially for the redirect
test) the real ``_AuthStrippingRedirectHandler`` — by monkeypatching only
``bounded_http._build_opener`` to return an opener wired to a fake urllib
handler that answers from the fixture instead of touching the network.

This means the OCI-client tests exercise the SAME redirect-stripping code
bounded_http's own test suite (S1) exercises, rather than a second,
test-only reimplementation of that security-critical predicate — the fake
only replaces the actual socket I/O.

Not collected as a test module (leading underscore; no ``test_`` prefix).
"""

from __future__ import annotations

import base64
import email.message
import io
import json
import urllib.error
import urllib.request
import urllib.response
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from milpa import bounded_http

FIXTURES_ROOT = Path(__file__).resolve().parents[3] / "conformance" / "oci-transport"


@dataclass
class _Exchange:
    method: str
    url: str
    expect_request_headers: dict[str, str | None]
    status: int
    headers: dict[str, str]
    body: bytes


@dataclass
class _ReplayState:
    exchanges: list[_Exchange]
    index: int = field(default=0)

    def next_response(self, req: urllib.request.Request) -> Any:
        if self.index >= len(self.exchanges):
            raise AssertionError(
                f"fixture exhausted after {self.index} exchange(s); "
                f"unexpected request {req.get_method()} {req.full_url}"
            )
        exch = self.exchanges[self.index]
        self.index += 1

        method = req.get_method()
        url = req.full_url
        if (method, url) != (exch.method, exch.url):
            raise AssertionError(
                f"exchange {self.index}: expected {exch.method} {exch.url!r}, "
                f"got {method} {url!r}"
            )

        for header_name, expected in exch.expect_request_headers.items():
            actual = _lookup_header(req, header_name)
            if expected is None:
                assert actual is None, (
                    f"exchange {self.index}: expected header {header_name!r} "
                    f"absent, got {actual!r}"
                )
            else:
                assert actual == expected, (
                    f"exchange {self.index}: expected header {header_name!r}="
                    f"{expected!r}, got {actual!r}"
                )

        msg = email.message.Message()
        for key, value in exch.headers.items():
            msg[key] = value
        fp = io.BytesIO(exch.body)
        resp = urllib.response.addinfourl(fp, msg, url, exch.status)
        resp.msg = _REASON_PHRASES.get(exch.status, "status")
        return resp

    def assert_exhausted(self) -> None:
        assert self.index == len(self.exchanges), (
            f"fixture had {len(self.exchanges) - self.index} unconsumed exchange(s)"
        )


_REASON_PHRASES = {200: "OK", 401: "Unauthorized", 404: "Not Found", 500: "Internal Server Error"}


def _lookup_header(req: urllib.request.Request, name: str) -> str | None:
    lname = name.lower()
    for key, value in req.header_items():
        if key.lower() == lname:
            return value
    return None


class _FakeHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, state: _ReplayState) -> None:
        super().__init__()
        self._state = state

    def http_open(self, req: urllib.request.Request) -> Any:
        return self._state.next_response(req)


class _FakeHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, state: _ReplayState) -> None:
        super().__init__()
        self._state = state

    def https_open(self, req: urllib.request.Request) -> Any:
        return self._state.next_response(req)


def load_fixture(name: str) -> dict[str, Any]:
    """Load + minimally shape-check a ``conformance/oci-transport/<name>`` fixture."""
    path = FIXTURES_ROOT / name
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "description" in data, f"{name}: missing 'description'"
    assert "exchanges" in data, f"{name}: missing 'exchanges'"
    for i, exch in enumerate(data["exchanges"]):
        assert exch["method"] in ("GET", "HEAD", "POST", "PUT"), f"{name}[{i}]: bad method"
        assert isinstance(exch["url"], str), f"{name}[{i}]: bad url"
        assert "status" in exch["response"], f"{name}[{i}]: response missing status"
        body_fields = [f for f in ("body", "body_base64", "body_file") if f in exch["response"]]
        assert len(body_fields) <= 1, f"{name}[{i}]: multiple body fields present"
    return data


def _exchanges_from_fixture(data: dict[str, Any], fixture_dir: Path) -> list[_Exchange]:
    exchanges: list[_Exchange] = []
    for exch in data["exchanges"]:
        response = exch["response"]
        if "body_base64" in response:
            body = base64.b64decode(response["body_base64"])
        elif "body_file" in response:
            body = (fixture_dir / response["body_file"]).read_bytes()
        elif "body" in response:
            body = response["body"].encode("utf-8")
        else:
            body = b""
        exchanges.append(
            _Exchange(
                method=exch["method"],
                url=exch["url"],
                expect_request_headers=exch.get("expect_request_headers", {}),
                status=response["status"],
                headers=response.get("headers", {}),
                body=body,
            )
        )
    return exchanges


class ReplayTransport:
    """A ``bounded_http.request``-shaped callable that replays a fixture.

    Satisfies ``milpa.fetchers.oci_client.OciHttpTransport`` structurally —
    it can be passed anywhere the real ``bounded_http.request`` is
    accepted.  Each call patches ``bounded_http._build_opener`` for the
    duration of exactly one request, so the real ``request()`` function
    (cap streaming, HTTPError-as-data handling, the real cross-origin
    ``Authorization``-stripping redirect handler) runs unmodified against
    the faked socket layer.
    """

    def __init__(self, fixture_name: str) -> None:
        data = load_fixture(fixture_name)
        self._state = _ReplayState(exchanges=_exchanges_from_fixture(data, FIXTURES_ROOT))

    def __call__(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cap: int,
        sink: Any,
        timeout: float = bounded_http.DEFAULT_TIMEOUT_SECONDS,
    ) -> bounded_http.HttpResponse:
        original_build_opener = bounded_http._build_opener

        def _fake_build_opener() -> urllib.request.OpenerDirector:
            return urllib.request.build_opener(
                _FakeHTTPHandler(self._state),
                _FakeHTTPSHandler(self._state),
                bounded_http._AuthStrippingRedirectHandler(),
            )

        bounded_http._build_opener = _fake_build_opener
        try:
            return bounded_http.request(
                method, url, headers=headers, cap=cap, sink=sink, timeout=timeout
            )
        finally:
            bounded_http._build_opener = original_build_opener

    def assert_exhausted(self) -> None:
        self._state.assert_exhausted()
