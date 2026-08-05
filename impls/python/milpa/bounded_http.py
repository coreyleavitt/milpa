"""bounded_http — the native in-process HTTP transport primitive.

RFC: docs/rfc-native-oci-fetch.md §3.3 (the deep ``(cap, sink)`` transport
seam), §3.8 (redirect ``Authorization``-stripping), §0.1 (proxy-env,
timeouts).

S1 builds this foundation primitive only — no caller is migrated onto it
yet (that is S3+). It exists so every future network caller (index/bundle/
dep-decl/entry-bundle, tarball, OCI) converges on ONE production HTTP
function instead of milpa's current three ad hoc `urllib` call sites plus
the `curl`/`oras` shell-outs the RFC removes.

Public surface:
    - ``HttpResponse`` — frozen dataclass: ``status`` + ``headers``. The
      body is never on the response.
    - ``request()``    — the transport entry point.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from milpa.errors import FETCH_DOWNLOAD_FAILED, FETCH_DOWNLOAD_SIZE_EXCEEDED, MilpaError

#: Chunk size for streaming reads.  Bounds process memory to at most
#: cap + _CHUNK_SIZE bytes from a response that exceeds the cap — mirrors
#: fetchers/tarball.py::_CHUNK_SIZE, the streaming discipline this module
#: generalizes for every native HTTP caller.
_CHUNK_SIZE: int = 65_536  # 64 KiB

#: Default socket timeout (seconds).  urllib exposes a single ``timeout=``
#: knob on ``urlopen`` shared by connect and every blocking read (no
#: separate connect/read timeouts are available) — conservative enough
#: that neither phase blocks a resolver worker forever (RFC §0.1: today's
#: curl/oras shell-outs set no ``--max-time``, so an in-process call with
#: no timeout at all would be a regression, not parity).
#:
#: RFC §0.1 documents this single-knob shape as an ACCEPTED DEVIATION from
#: Rust's split ``DEFAULT_CONNECT_TIMEOUT``/``DEFAULT_READ_TIMEOUT`` (M3):
#: stdlib's ``urlopen`` genuinely cannot cleanly separate connect from read
#: without a fragile custom ``HTTPConnection`` subclass, which milpa
#: declined to build. The safety-relevant hang (a stalled body transfer) is
#: still bounded by this one knob; connect is additionally bounded by the
#: OS's own TCP connect timeout.
DEFAULT_TIMEOUT_SECONDS: float = 300.0

#: Hard cap on redirect hops, matching Rust's ``MAX_REDIRECT_HOPS`` (RFC
#: §3.8, H2). ``urllib.request.HTTPRedirectHandler``'s own default already
#: equals this value; pinning it explicitly here — rather than relying on
#: stdlib's default happening to match — keeps the two impls' caps visibly
#: the same constant, not a coincidence one could drift out from under.
_MAX_REDIRECT_HOPS: int = 10

# ---------------------------------------------------------------------------
# HttpResponse
# ---------------------------------------------------------------------------


class _CaseInsensitiveHeaders(Mapping[str, str]):
    """Read-only, case-insensitive header mapping.

    HTTP header names are case-insensitive; lookups match regardless of
    casing while iteration preserves the first-seen casing.
    """

    def __init__(self, items: Mapping[str, str]) -> None:
        self._by_lower: dict[str, tuple[str, str]] = {}
        for key, value in items.items():
            self._by_lower.setdefault(key.lower(), (key, value))

    def __getitem__(self, key: str) -> str:
        return self._by_lower[key.lower()][1]

    def __iter__(self) -> Iterator[str]:
        return (orig for orig, _ in self._by_lower.values())

    def __len__(self) -> int:
        return len(self._by_lower)

    def __repr__(self) -> str:
        return f"_CaseInsensitiveHeaders({dict(self.items())!r})"


@dataclass(frozen=True)
class HttpResponse:
    """Status + headers from a completed request.

    The body is NOT here — it already landed in the caller's ``sink``
    (RFC §3.3: never buffer a body the caller didn't ask to buffer).
    ``headers`` lookup is case-insensitive.
    """

    status: int
    headers: Mapping[str, str]


# ---------------------------------------------------------------------------
# Redirect security (RFC §3.8) — strip Authorization on cross-origin redirect
# ---------------------------------------------------------------------------


def _origin(url: str) -> tuple[str, str, int]:
    """``(scheme, host, port)`` for ``url``, with scheme-default ports filled in."""
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme, -1)
    return (scheme, host, port)


def _same_origin(url_a: str, url_b: str) -> bool:
    """Origin equality per RFC §3.8: exact ``(scheme, host, port)`` match.

    A host-only check is insufficient: it misses a same-host scheme
    downgrade (``https://`` → ``http://``, identical host) and a port
    change, both of which must be treated as cross-origin.
    """
    return _origin(url_a) == _origin(url_b)


class _AuthStrippingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that strips ``Authorization`` on any cross-origin hop.

    urllib's default ``HTTPRedirectHandler`` forwards ``Authorization``
    verbatim to the redirect target (verified against stdlib source, RFC
    §3.8) — a bearer-token leak to a third-party CDN host on a registry's
    307 blob redirect.  Subclassing (not reimplementing) keeps the stock
    method/status-code validation and header-copy behavior; only the
    cross-origin case is special-cased.

    The strip is MONOTONIC (RFC §3.8, M2): each hop's ``redirect_request``
    call is built from the PREVIOUS hop's already-stripped ``Request``
    object (``req``), not from a separately stored original — so once
    ``Authorization`` is deleted at any hop it has nothing to be re-copied
    from on a later hop, even one that lands back on the original origin.
    No extra bookkeeping is needed to get this property; it falls out of
    reusing ``req`` as the copy source.

    ``max_redirections`` is pinned to ``_MAX_REDIRECT_HOPS`` (H2) — see
    that constant's docstring.
    """

    max_redirections = _MAX_REDIRECT_HOPS

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)  # type: ignore[arg-type]
        if new_req is None:
            return None
        if not _same_origin(req.full_url, newurl):
            for key in list(new_req.headers):
                if key.lower() == "authorization":
                    del new_req.headers[key]
        return new_req


def _is_redirect_loop_exhausted(exc: urllib.error.HTTPError) -> bool:
    """True if ``exc`` is urllib's OWN redirect-chain-exhausted signal.

    H2 (RFC §3.8): once a redirect chain exceeds ``HTTPRedirectHandler``'s
    internal bookkeeping (``max_redirections`` — pinned to
    ``_MAX_REDIRECT_HOPS`` above — or the separate same-URL
    ``max_repeats`` guard), stdlib's ``http_error_302`` (and its
    301/303/307/308 aliases) raises ``HTTPError(req.full_url, code,
    self.inf_msg + msg, ...)`` — an exception that carries the LAST hop's
    STALE 3xx status, not a real terminal response from the origin.  Left
    uncaught, ``request()``'s "HTTP status codes are data" branch (RFC
    §3.4) would return that as an ordinary ``HttpResponse(status=3xx)``
    instead of failing — an infinite-redirect (or >``_MAX_REDIRECT_HOPS``
    -hop) server would silently "succeed" with no bytes ever fetched.  Rust
    fails closed with ``FETCH-DOWNLOAD-FAILED`` at the same bound (its own
    ``MAX_REDIRECT_HOPS``); this predicate is what lets Python match it.

    ``HTTPRedirectHandler.inf_msg`` is a stable, documented stdlib class
    attribute reserved exactly for this signal (unchanged across Python 3
    since the handler's introduction) — checking the message prefix
    distinguishes "chain exhausted" from a genuine terminal 3xx (e.g. a
    302 with no ``Location``/``URI`` header, which ``http_error_302``
    handles by declining rather than raising, and which must still come
    back as data).
    """
    return exc.msg is not None and exc.msg.startswith(urllib.request.HTTPRedirectHandler.inf_msg)


def _build_opener() -> urllib.request.OpenerDirector:
    """Build the opener used by every ``request()`` call.

    Built from an EXPLICIT handler list — NOT ``build_opener(...)`` (C1,
    a confirmed critical finding). A bare ``build_opener(...)`` call
    unconditionally installs urllib's full default handler set —
    ``FTPHandler`` and ``DataHandler`` included, neither of which
    ``build_opener``'s "pass a subclass to override" mechanism can omit
    (it can only *replace* a default handler's instance, never drop the
    class from ``default_classes``). Combined with the OCI token flow,
    where the request URL is built from the registry's attacker-controlled
    ``WWW-Authenticate: Bearer realm="..."`` header (RFC §3.2 step 1), a
    hostile/MITM registry could steer ``request()`` at ``ftp://``/``data://``
    (and, before the §3.2 realm-scheme check landed, ``file://``) —
    local-file-read / SSRF / credential-exfiltration.

    The explicit list below keeps exactly: ``ProxyHandler`` (HTTP_PROXY/
    HTTPS_PROXY/NO_PROXY support, RFC §0.1), ``HTTPHandler``/``HTTPSHandler``,
    ``FileHandler`` (``file://`` is a first-class, intentional scheme for
    the OTHER bounded_http callers — index/dep-decl/entry-bundle stores,
    the tarball fetcher, air-gapped/harness deployments; every conformance
    fixture uses a ``file://`` index — so this is NOT a blanket non-http(s)
    reject), ``HTTPErrorProcessor`` + ``HTTPDefaultErrorHandler`` (together
    the pair that turns a 4xx/5xx status into the ``urllib.error.HTTPError``
    ``request()`` already catches and treats as data, RFC §3.4 — dropping
    either one leaves an unhandled ``None`` response, not a clean error),
    ``UnknownHandler`` (turns an unroutable scheme, e.g. ``ftp://``/
    ``data://`` with no handler registered, into ``URLError`` — the fail-
    closed path this module's ``except urllib.error.URLError`` already
    converts to ``FETCH-DOWNLOAD-FAILED``, rather than a silent ``None``
    response), and our own ``_AuthStrippingRedirectHandler`` (subclasses
    ``HTTPRedirectHandler``, so it is the only redirect handler present —
    do not ALSO pass a bare ``HTTPRedirectHandler``).  ``FTPHandler`` and
    ``DataHandler`` are excluded outright: an ``ftp://``/``data://`` request
    now fails closed via ``UnknownHandler`` instead of being dispatched.
    """
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler(),
        urllib.request.UnknownHandler(),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(),
        urllib.request.FileHandler(),
        urllib.request.HTTPErrorProcessor(),
        urllib.request.HTTPDefaultErrorHandler(),
        _AuthStrippingRedirectHandler(),
    ):
        opener.add_handler(handler)
    return opener


# ---------------------------------------------------------------------------
# Streaming cap enforcement
# ---------------------------------------------------------------------------


def _stream_capped(source: object, dest: BinaryIO, *, cap: int, url: str) -> int:
    """Copy ``source.read(n)`` chunks into ``dest``, enforcing ``cap``.

    Reads in bounded chunks and rejects as soon as the cumulative count
    exceeds ``cap`` — the full body is never buffered beyond the cap before
    the check fires (mirrors ``fetchers/tarball.py::make_http_get``).

    Returns the total number of bytes written to ``dest``, so the caller can
    cross-check it against a declared ``Content-Length`` (Bug 2 completeness
    check — a peer that closes cleanly mid-body yields progressively shorter
    reads then a silent EOF here, not an exception).
    """
    total = 0
    while True:
        chunk = source.read(_CHUNK_SIZE)  # type: ignore[attr-defined]
        if not chunk:
            return total
        total += len(chunk)
        if total > cap:
            raise MilpaError(
                FETCH_DOWNLOAD_SIZE_EXCEEDED,
                f"response body for {url!r} exceeded download cap ({cap} bytes)",
                url=url,
                cap=cap,
            )
        dest.write(chunk)


def _reject_if_truncated(headers: Mapping[str, str], received: int, *, cap: int, url: str) -> None:
    """Raise ``FETCH-DOWNLOAD-FAILED`` if a declared ``Content-Length`` was
    not fully received (Bug 2).

    A peer that closes CLEANLY mid-body (no reset) yields progressively
    shorter reads then EOF — no exception — so ``request()`` would otherwise
    return a normal ``HttpResponse(status=200)`` with a truncated body.
    Downstream that misclassifies a benign transport truncation as tampering
    (an OCI digest mismatch, or a tarball proceeding to extract a partial
    archive) instead of a retryable transport failure.

    Only enforced when ``Content-Length`` is present, parses as an integer,
    AND is ``<= cap``. Chunked-encoded and absent-length responses (e.g.
    ``file://`` bodies without one) have no declared length to check
    against, so they are left as-is. A declared length ABOVE the cap is
    likewise left unchecked — not merely for parity with the pre-existing
    "declared size is an untrusted, opportunistic hint, never an authority"
    posture this codebase already takes for OCI's manifest-declared blob
    ``size`` (RFC docs/rfc-native-oci-fetch.md §3.2 step 4: "a lying-small
    ``size`` cannot smuggle different bytes past step 5's unconditional
    digest check"), but because the check would be VACUOUS in that regime:
    once ``declared > cap``, a transfer that actually reached ``declared``
    bytes would already have raised ``FETCH_DOWNLOAD_SIZE_EXCEEDED`` inside
    ``_stream_capped`` before ever returning here, so ``received != declared``
    is trivially true on EVERY completed call in that regime — it carries no
    information about whether a genuine mid-transfer truncation occurred, so
    firing on it would reject e.g. a small, complete, hash-verified artifact
    served behind an oversized (or simply wrong) ``Content-Length`` header
    with no corresponding security or correctness benefit.
    """
    declared = headers.get("Content-Length")
    if declared is None:
        return
    try:
        declared_bytes = int(declared)
    except ValueError:
        return
    if declared_bytes > cap:
        return
    if received != declared_bytes:
        raise MilpaError(
            FETCH_DOWNLOAD_FAILED,
            f"response body for {url!r} truncated: received {received} bytes, "
            f"Content-Length declared {declared_bytes}",
            url=url,
            received=received,
            declared=declared_bytes,
        )


# ---------------------------------------------------------------------------
# request — the transport entry point
# ---------------------------------------------------------------------------


def request(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    cap: int,
    sink: BinaryIO | Path,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> HttpResponse:
    """Issue one HTTP request, streaming the body into ``sink`` under ``cap``.

    Args:
        method:  HTTP method (``"GET"``, ``"HEAD"``, ...).
        url:     Target URL.
        headers: Request headers to send.
        cap:     Maximum body bytes accepted before aborting —
                 ``FETCH-DOWNLOAD-SIZE-EXCEEDED`` fires mid-stream, never
                 after buffering past the cap.
        sink:    Where the body lands — a ``Path`` streams to a file; a
                 binary file-like (``BytesIO``, an open file) streams
                 directly into it.
        timeout: Socket timeout in seconds (connect + each blocking read
                 share urllib's single knob). Defaults to
                 ``DEFAULT_TIMEOUT_SECONDS``.

    Returns:
        ``HttpResponse`` — status and headers.

    Raises:
        MilpaError(FETCH_DOWNLOAD_SIZE_EXCEEDED): body exceeded ``cap``.
        MilpaError(FETCH_DOWNLOAD_FAILED): transport/network failure (DNS,
            connection refused, timeout, a mid-stream reset during body
            transfer), a redirect chain that exceeded ``_MAX_REDIRECT_HOPS``
            (H2), or a response whose actual body was shorter than its
            declared ``Content-Length`` (a clean-close truncation) — never
            for a genuine HTTP status code.
    """
    req = urllib.request.Request(url, method=method, headers=dict(headers) if headers else {})
    opener = _build_opener()
    try:
        raw_resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if _is_redirect_loop_exhausted(exc):
            # H2 (RFC §3.8): fail CLOSED, matching Rust's MAX_REDIRECT_HOPS
            # bound — do NOT fall through to "status codes are data" below,
            # or an infinite-redirect server "succeeds" with a stale 3xx
            # and no bytes ever fetched.
            raise MilpaError(
                FETCH_DOWNLOAD_FAILED,
                f"request to {url!r} exceeded the redirect hop limit "
                f"({_MAX_REDIRECT_HOPS}): {exc}",
                url=url,
            ) from exc
        # HTTPError IS the response for a 4xx/5xx status — it is file-like
        # (supports .read()) and carries .code/.headers.  HTTP status codes
        # are data at this layer, not a transport failure (RFC §3.4).  Note:
        # HTTPError subclasses URLError, so this branch must precede the
        # broader URLError/OSError handler below.
        raw_resp = exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise MilpaError(
            FETCH_DOWNLOAD_FAILED,
            f"request to {url!r} failed: {exc}",
            url=url,
        ) from exc

    # The streaming phase (header extraction + body read) is wrapped in the
    # SAME transport-failure except clause as the connect phase above: a
    # server that resets the connection or otherwise transport-fails AFTER
    # headers but DURING body transfer (e.g. `raw_resp.read(n)` raising a raw
    # `ConnectionResetError`) must surface as `FETCH-DOWNLOAD-FAILED` at this
    # one owning layer, not escape unwrapped. `MilpaError` (e.g.
    # FETCH_DOWNLOAD_SIZE_EXCEEDED, raised by `_stream_capped` itself) is NOT
    # a subclass of OSError/URLError, so it is never caught here — it
    # propagates unchanged, as it must (a distinct, already-structured
    # error, not a transport failure).
    try:
        with raw_resp:
            status = raw_resp.status if hasattr(raw_resp, "status") else raw_resp.getcode()
            response_headers = _CaseInsensitiveHeaders(dict(raw_resp.headers.items()))
            if isinstance(sink, Path):
                with open(sink, "wb") as f:
                    received = _stream_capped(raw_resp, f, cap=cap, url=url)
            else:
                received = _stream_capped(raw_resp, sink, cap=cap, url=url)
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise MilpaError(
            FETCH_DOWNLOAD_FAILED,
            f"request to {url!r} failed while streaming the response body: {exc}",
            url=url,
        ) from exc

    _reject_if_truncated(response_headers, received, cap=cap, url=url)

    return HttpResponse(status=status, headers=response_headers)
