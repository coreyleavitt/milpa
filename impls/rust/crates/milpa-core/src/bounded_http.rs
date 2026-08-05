//! `bounded_http` — the native in-process HTTP transport primitive.
//!
//! RFC: `docs/rfc-native-oci-fetch.md` §3.3 (the deep `(cap, sink)` transport
//! seam), §3.8 (redirect `Authorization`-stripping), §0.1 (proxy-env, TLS
//! trust, crypto-provider pin, timeouts).
//!
//! S2 built this foundation primitive; S4 migrated every unauthenticated-GET
//! consumer-side `curl` call site (index/bundle/epoch-commitment/dep-decl/
//! entry-bundle/tarball, across `milpa-core` and `milpa-cli`) onto it, so
//! they converge on ONE production HTTP function instead of independent
//! `curl` shell-outs. OCI's native client (`oci_client.rs`, composed by
//! `fetchers::fetch_oci`) is built on this same transport (S7/S8) — the
//! `oras` shell-out it replaced is gone. Mirrors the Python twin
//! (`milpa/bounded_http.py`) at the same altitude; the two are NOT required
//! to share an implementation (no shared runtime across impls), only the
//! same contract.
//!
//! Public surface:
//!     - [`HttpResponse`] — status + response headers (case-insensitive
//!       lookup via `http::HeaderMap`). The body is never on the response.
//!     - [`Sink`]         — where the body lands: an in-memory buffer for
//!       small callers (token/manifest, ≈1 MiB) or a file `Path` for large
//!       ones (the OCI blob / tarball body, up to `MAX_COMPRESSED_BYTES`).
//!     - [`request`]      — the transport entry point.
//!     - [`same_origin`]  — the pure origin-equality predicate the redirect
//!       loop uses to decide whether `Authorization` survives a hop.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use ureq::http::HeaderMap;
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
use ureq::{Agent, Body};

use crate::fetch::FetchError;

/// Chunk size for the streaming read loop (64 KiB). Bounds process memory to
/// at most `cap + CHUNK_SIZE` bytes from a response that exceeds the cap —
/// mirrors the former `fetchers::CURL_CHUNK_SIZE`, the streaming discipline
/// this module re-homes onto native TLS (RFC §3.3, S4).
const CHUNK_SIZE: usize = 65_536;

/// Max duration for establishing the connection (TCP + TLS handshake).
/// RFC §0.1: the `curl`/`oras` shell-outs this transport replaced set no
/// `--max-time`, so an in-process call with NO timeout would block a
/// resolver worker thread forever — strictly worse than the subprocess it
/// replaced.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Max duration for any single blocking read phase (response headers or
/// body). Generous enough for a slow registry/CDN serving a multi-GiB blob
/// in `CHUNK_SIZE` increments, conservative enough to bound a hung worker.
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// Hard ceiling on redirect hops. `ureq`'s own follower is disabled
/// (`max_redirects(0)`, see [`build_agent`]) so this loop can control
/// per-hop `Authorization` stripping (RFC §3.8); this bound keeps a
/// misbehaving/looping server from spinning forever.
const MAX_REDIRECT_HOPS: u32 = 10;

// ---------------------------------------------------------------------------
// HttpResponse / Sink
// ---------------------------------------------------------------------------

/// Status + headers from a completed request.
///
/// The body is NOT here — it already landed in the caller's [`Sink`] (RFC
/// §3.3: never buffer a body the caller didn't ask to buffer). `headers`
/// lookup is case-insensitive by construction (`http::HeaderMap` compares
/// header names case-insensitively).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HeaderMap,
}

/// Where a response body lands.
///
/// `Bytes` is for small/buffered callers (index/bundle/dep-decl/entry-bundle,
/// OCI token/manifest — ≈1 MiB); `File` streams directly to disk for large
/// bodies (the OCI blob / tarball archive — up to `MAX_COMPRESSED_BYTES`, 4
/// GiB) so a concurrent resolve never holds more than one blob in memory at
/// once (RFC §3.3: a 4 GiB in-memory buffer per worker is a real DoS).
pub enum Sink<'a> {
    Bytes(&'a mut Vec<u8>),
    File(&'a Path),
}

// ---------------------------------------------------------------------------
// Redirect security (RFC §3.8) — strip Authorization on cross-origin redirect
// ---------------------------------------------------------------------------

/// `(scheme, host, port)` for `url`, with scheme-default ports filled in.
/// Returns `None` for an unparsable URL — callers treat that as "not the
/// same origin" (fail closed, never forward a token past a URL we can't
/// even parse).
fn origin(url: &str) -> Option<(String, String, u16)> {
    let parsed = url::Url::parse(url).ok()?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    let host = parsed.host_str()?.to_ascii_lowercase();
    let port = parsed.port_or_known_default()?;
    Some((scheme, host, port))
}

/// Origin equality per RFC §3.8: exact `(scheme, host, port)` match — NOT a
/// host-only comparison. A host-only predicate would miss a same-host scheme
/// downgrade (`https://ghcr.io/…` → `http://ghcr.io/…`, identical host),
/// which would forward a bearer token in cleartext, and would miss a port
/// change (`ghcr.io:443` → `ghcr.io:9443`).
///
/// Pure function, no I/O — unit-tested exhaustively below.
pub fn same_origin(a: &str, b: &str) -> bool {
    match (origin(a), origin(b)) {
        (Some(oa), Some(ob)) => oa == ob,
        _ => false,
    }
}

/// Resolve a `Location` header value against the URL it was received from.
/// Registries typically send an absolute URL (ghcr's blob redirect included),
/// but a relative `Location` is legal HTTP and must be joined, not rejected.
fn resolve_redirect_target(current_url: &str, location: &str) -> Result<String, FetchError> {
    let base = url::Url::parse(current_url)
        .map_err(|e| transport("FETCH-DOWNLOAD-FAILED", format!("parsing {current_url:?}: {e}")))?;
    let target = base.join(location).map_err(|e| {
        transport(
            "FETCH-DOWNLOAD-FAILED",
            format!("resolving redirect Location {location:?} against {current_url:?}: {e}"),
        )
    })?;
    Ok(target.into())
}

// ---------------------------------------------------------------------------
// Agent construction (RFC §0.1)
// ---------------------------------------------------------------------------

fn transport(code: &'static str, message: impl Into<String>) -> FetchError {
    FetchError::Transport(code, message.into())
}

/// Load the OS trust store via `rustls-native-certs` (curl parity +
/// enterprise/MITM roots, RFC §0.1) as a `Vec` of ureq's `Certificate`
/// wrapper, ready for `TlsConfig::root_certs(RootCerts::Specific(...))`.
///
/// Deliberately NOT `ureq`'s compiled-in `webpki-roots` feature: a compiled
/// Mozilla set would silently stop honoring OS cert updates and would drop
/// enterprise/MITM-proxy roots the OS trust store carries.
fn native_root_certs() -> Result<Vec<ureq::tls::Certificate<'static>>, FetchError> {
    let result = rustls_native_certs::load_native_certs();
    // `load_native_certs` returns whatever certs it could parse alongside any
    // per-cert errors; a store with SOME unparsable entries is still usable
    // (this mirrors rustls-native-certs' own documented posture). Only an
    // EMPTY result — no certs at all — is treated as a transport failure,
    // since a client with no trust roots can validate nothing.
    if result.certs.is_empty() {
        let detail = result
            .errors
            .first()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no native certificates found".to_string());
        return Err(transport(
            "FETCH-DOWNLOAD-FAILED",
            format!("loading OS trust store: {detail}"),
        ));
    }
    Ok(result
        .certs
        .iter()
        .map(|der| ureq::tls::Certificate::from_der(der.as_ref()).to_owned())
        .collect())
}

/// Construct the native-TLS `Agent`. Called once, lazily, by [`shared_agent`],
/// which caches the result for the whole process — see that function for why
/// the agent (and, crucially, its proxy-env resolution) must NOT be rebuilt on
/// every `request()`.
///
/// `ureq`'s own redirect follower is disabled (`max_redirects(0)`) so
/// `request()` can run the redirect loop itself and strip `Authorization`
/// per hop (RFC §3.8) — `ureq` also ships a built-in
/// `redirect_auth_headers` policy, but neither of its two modes (`Never`,
/// which strips even same-origin; `SameHost`, which checks host+https but
/// not port) implements the RFC's exact `(scheme, host, port)` predicate, so
/// this module owns the loop instead of leaning on it.
fn build_agent() -> Result<Agent, FetchError> {
    let crypto = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let root_certs = native_root_certs()?;

    let tls_config = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(crypto)
        .root_certs(RootCerts::new_with_certs(&root_certs))
        .build();

    let config = Agent::config_builder()
        .tls_config(tls_config)
        // HTTP status codes are data, not a transport failure (RFC §3.4) —
        // the OCI auth flow branches on 401/404/307 explicitly.
        .http_status_as_error(false)
        // Manual redirect loop (see doc comment above).
        .max_redirects(0)
        .timeout_connect(Some(DEFAULT_CONNECT_TIMEOUT))
        .timeout_recv_response(Some(DEFAULT_READ_TIMEOUT))
        .timeout_recv_body(Some(DEFAULT_READ_TIMEOUT))
        .build();

    Ok(config.new_agent())
}

/// The process-wide shared [`Agent`], built once on first use and reused by
/// every `request()`.
///
/// Reused rather than rebuilt per call for two reasons:
///  1. It is the idiomatic `ureq` usage — an `Agent` owns the connection pool,
///     so a fresh agent per request forfeits connection reuse.
///  2. `ureq`'s default `Config` resolves the proxy from the environment
///     (`Proxy::try_from_env()`, reading `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`).
///     Doing that on EVERY call makes each request's env read race any
///     concurrent `set_var`/`remove_var` — process env is global and a per-call
///     read here does not participate in the mutex the test suites use to
///     serialize their own env mutation, so a request on one thread and an
///     env mutation on another is a data race (observed as a flaky failure).
///     Resolving once collapses that to a single early read. Proxy config is
///     process-scoped in practice, so reading it once is also functionally
///     correct (RFC §0.1).
///
/// A failed build (empty OS trust store) is NOT cached, so a transient
/// trust-store failure can be retried on a later call.
fn shared_agent() -> Result<&'static Agent, FetchError> {
    static AGENT: OnceLock<Agent> = OnceLock::new();
    if let Some(agent) = AGENT.get() {
        return Ok(agent);
    }
    // Fallible construction — build outside the cache, then publish. Under a
    // first-call race both threads build; `get_or_init` keeps the first and
    // drops the other (construction is idempotent), so exactly one is shared.
    let agent = build_agent()?;
    Ok(AGENT.get_or_init(|| agent))
}

// ---------------------------------------------------------------------------
// Streaming cap enforcement
// ---------------------------------------------------------------------------

/// Copy `reader` into `writer` in `CHUNK_SIZE` increments, rejecting as soon
/// as the cumulative byte count exceeds `cap`. The full body is never
/// buffered beyond `cap + CHUNK_SIZE` bytes before the check fires (mirrors
/// `fetchers::curl_streaming_transport`'s streaming discipline). Exactly
/// `cap` bytes is admitted; `cap + 1` is not.
fn stream_capped(
    mut reader: impl Read,
    mut writer: impl Write,
    cap: u64,
    url: &str,
) -> Result<(), FetchError> {
    let mut buf = [0u8; CHUNK_SIZE];
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| transport("FETCH-DOWNLOAD-FAILED", format!("reading response body for {url:?}: {e}")))?;
        if n == 0 {
            return Ok(());
        }
        total += n as u64;
        if total > cap {
            return Err(transport(
                "FETCH-DOWNLOAD-SIZE-EXCEEDED",
                format!("response body for {url:?} exceeded download cap ({cap} bytes)"),
            ));
        }
        writer
            .write_all(&buf[..n])
            .map_err(|e| transport("FETCH-DOWNLOAD-FAILED", format!("writing response body for {url:?}: {e}")))?;
    }
}

fn stream_body_into_sink(body: Body, cap: u64, sink: Sink<'_>, url: &str) -> Result<(), FetchError> {
    let reader = body.into_reader();
    match sink {
        Sink::Bytes(buf) => stream_capped(reader, buf, cap, url),
        Sink::File(path) => {
            let file = File::create(path).map_err(|e| {
                transport("FETCH-DOWNLOAD-FAILED", format!("creating {path:?}: {e}"))
            })?;
            stream_capped(reader, file, cap, url)
        }
    }
}

// ---------------------------------------------------------------------------
// request — the transport entry point
// ---------------------------------------------------------------------------

/// Reject any URL whose scheme is not `http`/`https` — C1 defense-in-depth.
/// Every REAL caller handles `file://` as a direct filesystem read BEFORE
/// reaching this function (dep_decl_store.rs, entry_bundle_store.rs,
/// fetchers.rs, milpa-cli/src/main.rs all `strip_prefix("file://")` first —
/// `ureq`'s `Agent` has no `file://` connector at all, so this scheme is not
/// otherwise reachable here). The guard exists for
/// `oci_client.rs::acquire_token`, which builds a URL directly from the
/// registry's attacker-controlled `WWW-Authenticate` realm (RFC §3.2 step
/// 1); `oci_client.rs` already validates that realm's scheme itself, but
/// this is the second, independent layer — reject any non-http(s) scheme
/// fail-closed rather than relying solely on the caller having done so.
///
/// SecF2: called BOTH before the redirect loop starts (against the original
/// `url`) AND on every hop inside the loop (against `current_url`, after
/// resolving each `Location`) — a `Location: file:///etc/passwd` (or any
/// other non-http(s) scheme) on a LATER hop is otherwise not rejected by
/// this guard at all; it used to fail only incidentally, via `ureq`'s own
/// internal `ensure_valid_url` rejecting the scheme when `agent.run` was
/// called — a third-party backstop, not milpa's own invariant.
fn ensure_http_scheme(url: &str) -> Result<(), FetchError> {
    let scheme = url::Url::parse(url).map(|u| u.scheme().to_string());
    if !matches!(scheme.as_deref(), Ok("http") | Ok("https")) {
        return Err(transport(
            "FETCH-DOWNLOAD-FAILED",
            format!("unsupported URL scheme for {url:?}: only http/https are permitted"),
        ));
    }
    Ok(())
}

/// Issue one logical HTTP request, streaming the body into `sink` under
/// `cap`, following redirects internally while stripping `Authorization` on
/// any cross-origin hop.
///
/// # Arguments
/// - `method`:  HTTP method (`"GET"`, `"HEAD"`, ...).
/// - `url`:     Target URL.
/// - `headers`: Request headers to send on the initial request. `Authorization`
///   strips MONOTONICALLY (RFC §3.8, M2): once any hop crosses origin from
///   the original request, `Authorization` is omitted on every later hop —
///   even one that lands back on the original origin — rather than being
///   recomputed fresh per hop (see [`same_origin`]).
/// - `cap`:     Maximum body bytes accepted before aborting —
///   `FETCH-DOWNLOAD-SIZE-EXCEEDED` fires mid-stream, never after buffering
///   past the cap.
/// - `sink`:    Where the body lands.
///
/// # Errors
/// - `FETCH-DOWNLOAD-SIZE-EXCEEDED`: body (or a redirect target's body)
///   exceeded `cap`.
/// - `FETCH-DOWNLOAD-FAILED`: transport/network failure (DNS, connection
///   refused, timeout, TLS setup, a mid-stream io error, or a truncated body
///   shorter than its declared `Content-Length`) — never for an HTTP status
///   code, which is reported on `HttpResponse.status` instead.
pub fn request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    cap: u64,
    sink: Sink<'_>,
) -> Result<HttpResponse, FetchError> {
    ensure_http_scheme(url)?;

    let agent = shared_agent()?;

    let mut current_url = url.to_string();
    let mut sink = Some(sink);
    // RFC §3.8 (M2): the strip is MONOTONIC, not recomputed per hop — once
    // any hop crosses origin from the ORIGINAL request, `stripped` latches
    // and Authorization is omitted on every later hop even if the chain
    // returns to the original origin. Recomputing `same_origin(url,
    // &current_url)` fresh on every iteration (the pre-M2 behavior) would
    // RESTORE Authorization on a 3+-hop chain A(orig,auth) ->
    // B(cross-origin,stripped) -> C(==A's origin) — strictly safer to
    // latch than to re-check.
    let mut stripped = false;

    for _hop in 0..=MAX_REDIRECT_HOPS {
        // SecF2: re-applied to `current_url` on EVERY hop, not just the
        // original `url` before the loop — see `ensure_http_scheme`'s doc
        // comment for why the pre-loop-only check was an incomplete
        // invariant.
        ensure_http_scheme(&current_url)?;

        if !same_origin(url, &current_url) {
            stripped = true;
        }
        let mut builder = ureq::http::Request::builder().method(method).uri(&current_url);
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("authorization") && stripped {
                // Cross-origin at this hop, or at any PRIOR hop (monotonic
                // latch) — never forward the credential (RFC §3.8).
                continue;
            }
            builder = builder.header(*name, *value);
        }
        let req = builder.body(()).map_err(|e| {
            transport("FETCH-DOWNLOAD-FAILED", format!("building request to {current_url:?}: {e}"))
        })?;

        let response = agent.run(req).map_err(|e| {
            transport("FETCH-DOWNLOAD-FAILED", format!("request to {current_url:?} failed: {e}"))
        })?;

        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            if let Some(location) = response
                .headers()
                .get(ureq::http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
            {
                current_url = resolve_redirect_target(&current_url, location)?;
                continue;
            }
        }

        let response_headers = response.headers().clone();
        let sink = sink
            .take()
            .expect("request() loop invariant: sink consumed only once, on the terminal response");
        stream_body_into_sink(response.into_body(), cap, sink, &current_url)?;
        return Ok(HttpResponse {
            status,
            headers: response_headers,
        });
    }

    Err(transport(
        "FETCH-DOWNLOAD-FAILED",
        format!("too many redirects ({MAX_REDIRECT_HOPS}) fetching {url:?}"),
    ))
}

#[cfg(test)]
#[path = "bounded_http_tests.rs"]
mod bounded_http_tests;
