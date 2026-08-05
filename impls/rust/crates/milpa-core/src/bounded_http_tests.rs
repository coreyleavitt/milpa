//! Unit/integration tests for `bounded_http` (RFC `rfc-native-oci-fetch.md`
//! §2/§4 test matrix, Rust half). Hermetic: every network-shaped test drives
//! a hand-rolled HTTP/1.1 listener bound to `127.0.0.1:0` (an ephemeral
//! port) in-process — no real remote host, no `MILPA_INTEGRATION_TESTS`.

use super::*;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Mutex;
use std::thread;

// ---------------------------------------------------------------------------
// Minimal in-process HTTP/1.1 test server
// ---------------------------------------------------------------------------

struct ReceivedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
}

struct TestResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl TestResponse {
    fn ok(body: impl Into<Vec<u8>>) -> Self {
        TestResponse {
            status: 200,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    fn status(status: u16) -> Self {
        TestResponse {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn redirect_to(location: &str) -> Self {
        TestResponse {
            status: 302,
            headers: vec![("Location".to_string(), location.to_string())],
            body: Vec::new(),
        }
    }
}

/// Spawn a listener on an ephemeral loopback port; `handler` computes the
/// response for every request the server receives (one thread per
/// connection, so a redirect chain across two servers works without
/// deadlocking a single-threaded accept loop).
fn spawn_server<F>(handler: F) -> SocketAddr
where
    F: Fn(ReceivedRequest) -> TestResponse + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let handler = Arc::new(handler);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let handler = Arc::clone(&handler);
            thread::spawn(move || serve_one(stream, &*handler));
        }
    });
    addr
}

fn serve_one(mut stream: TcpStream, handler: &dyn Fn(ReceivedRequest) -> TestResponse) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let response = handler(ReceivedRequest { method, path, headers });

    let mut out = format!("HTTP/1.1 {} X\r\n", response.status);
    for (key, value) in &response.headers {
        out.push_str(&format!("{key}: {value}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
    out.push_str("Connection: close\r\n\r\n");
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
}

// ---------------------------------------------------------------------------
// 1/2 — happy path: Bytes sink and File sink
// ---------------------------------------------------------------------------

#[test]
fn get_small_body_lands_in_memory_sink_with_status() {
    let addr = spawn_server(|_req| TestResponse::ok(b"hello world".to_vec()));
    let url = format!("http://{addr}/thing");

    let mut buf = Vec::new();
    let resp = request("GET", &url, &[], 1024, Sink::Bytes(&mut buf)).expect("request succeeds");

    assert_eq!(resp.status, 200);
    assert_eq!(buf, b"hello world");
}

#[test]
fn get_streams_body_into_file_sink_with_exact_bytes() {
    let addr = spawn_server(|_req| TestResponse::ok(vec![0xABu8; 4096]));
    let url = format!("http://{addr}/blob");

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("blob.bin");
    let resp = request("GET", &url, &[], 1_000_000, Sink::File(&dest)).expect("request succeeds");

    assert_eq!(resp.status, 200);
    let on_disk = std::fs::read(&dest).unwrap();
    assert_eq!(on_disk, vec![0xABu8; 4096]);
}

// ---------------------------------------------------------------------------
// 3/4 — cap enforcement, boundary
// ---------------------------------------------------------------------------

#[test]
fn body_exceeding_cap_is_rejected_mid_stream() {
    let addr = spawn_server(|_req| TestResponse::ok(vec![0u8; 100]));
    let url = format!("http://{addr}/big");

    let mut buf = Vec::new();
    let err = request("GET", &url, &[], 16, Sink::Bytes(&mut buf)).unwrap_err();

    assert_eq!(err.code(), "FETCH-DOWNLOAD-SIZE-EXCEEDED");
}

#[test]
fn body_exactly_at_cap_is_admitted() {
    let addr = spawn_server(|_req| TestResponse::ok(vec![7u8; 16]));
    let url = format!("http://{addr}/exact");

    let mut buf = Vec::new();
    let resp = request("GET", &url, &[], 16, Sink::Bytes(&mut buf)).expect("exactly-at-cap admitted");

    assert_eq!(resp.status, 200);
    assert_eq!(buf.len(), 16);
}

// ---------------------------------------------------------------------------
// 5 — HTTP status is data, not an error
// ---------------------------------------------------------------------------

#[test]
fn http_404_is_returned_as_status_not_error() {
    let addr = spawn_server(|_req| TestResponse::status(404));
    let url = format!("http://{addr}/missing");

    let mut buf = Vec::new();
    let resp = request("GET", &url, &[], 1024, Sink::Bytes(&mut buf)).expect("404 is not a transport error");

    assert_eq!(resp.status, 404);
}

#[test]
fn http_401_is_returned_as_status_not_error() {
    let addr = spawn_server(|_req| TestResponse::status(401));
    let url = format!("http://{addr}/auth");

    let mut buf = Vec::new();
    let resp = request("GET", &url, &[], 1024, Sink::Bytes(&mut buf)).expect("401 is not a transport error");

    assert_eq!(resp.status, 401);
}

// ---------------------------------------------------------------------------
// 6 — connection error
// ---------------------------------------------------------------------------

#[test]
fn connection_refused_is_download_failed() {
    // Bind to grab an ephemeral port, then drop the listener immediately —
    // nothing is listening on it, so the connection is refused.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let url = format!("http://{addr}/anything");
    let mut buf = Vec::new();
    let err = request("GET", &url, &[], 1024, Sink::Bytes(&mut buf)).unwrap_err();

    assert_eq!(err.code(), "FETCH-DOWNLOAD-FAILED");
}

// ---------------------------------------------------------------------------
// 7/8 — redirect Authorization stripping (RFC §3.8)
// ---------------------------------------------------------------------------

#[test]
fn cross_origin_redirect_strips_authorization() {
    // Two listeners on different ports = different origins under the exact
    // (scheme, host, port) predicate, even though both bind 127.0.0.1 — this
    // is the "port differs" leg of §3.8's cross-origin definition.
    let received_on_second_hop: Arc<Mutex<Option<HashMap<String, String>>>> = Arc::new(Mutex::new(None));
    let received_clone = Arc::clone(&received_on_second_hop);

    let second_addr = spawn_server(move |req| {
        *received_clone.lock().unwrap() = Some(req.headers);
        TestResponse::ok(b"final".to_vec())
    });
    let second_url = format!("http://{second_addr}/final");

    let first_addr = spawn_server(move |_req| TestResponse::redirect_to(&second_url));
    let first_url = format!("http://{first_addr}/start");

    let mut buf = Vec::new();
    let resp = request(
        "GET",
        &first_url,
        &[("Authorization", "Bearer secret-token")],
        1024,
        Sink::Bytes(&mut buf),
    )
    .expect("redirect chain succeeds");

    assert_eq!(resp.status, 200);
    assert_eq!(buf, b"final");

    let second_hop_headers = received_on_second_hop.lock().unwrap().take().expect("second hop was hit");
    assert!(
        !second_hop_headers.contains_key("authorization"),
        "Authorization must be stripped on a cross-origin redirect, got headers: {second_hop_headers:?}"
    );
}

#[test]
fn same_origin_redirect_keeps_authorization() {
    // One server, two paths: a redirect from /start to /final on the SAME
    // origin must keep Authorization.
    let received_on_final: Arc<Mutex<Option<HashMap<String, String>>>> = Arc::new(Mutex::new(None));
    let received_clone = Arc::clone(&received_on_final);

    let addr = spawn_server(move |req| {
        if req.path == "/start" {
            TestResponse::redirect_to("/final")
        } else {
            *received_clone.lock().unwrap() = Some(req.headers);
            TestResponse::ok(b"final".to_vec())
        }
    });
    let url = format!("http://{addr}/start");

    let mut buf = Vec::new();
    let resp = request(
        "GET",
        &url,
        &[("Authorization", "Bearer secret-token")],
        1024,
        Sink::Bytes(&mut buf),
    )
    .expect("redirect chain succeeds");

    assert_eq!(resp.status, 200);
    let final_headers = received_on_final.lock().unwrap().take().expect("final hop was hit");
    assert_eq!(
        final_headers.get("authorization").map(String::as_str),
        Some("Bearer secret-token"),
        "Authorization must survive a same-origin redirect"
    );
}

#[test]
fn redirect_authorization_strip_is_monotonic_across_a_return_to_original_origin() {
    // Three-hop chain: A (original, carries Authorization) -> B (a
    // DIFFERENT origin, so Authorization strips) -> C, back on A's exact
    // origin (addr_a is reused for the final hop, path "/final"). M2 (RFC
    // §3.8): the strip is MONOTONIC — once stripped at B, Authorization
    // must stay absent at C even though C's origin matches the ORIGINAL
    // request's origin. Recomputing same_origin(original, current) fresh
    // at every hop (the pre-M2 behavior) would incorrectly restore it at C.
    let received_at_final: Arc<Mutex<Option<HashMap<String, String>>>> = Arc::new(Mutex::new(None));
    let received_clone = Arc::clone(&received_at_final);

    // addr_b isn't known until AFTER server A is spawned (A's "/start"
    // handler needs to redirect to it), so thread it through a holder the
    // handler reads per-request rather than at spawn time.
    let addr_b_holder: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let addr_b_for_a = Arc::clone(&addr_b_holder);

    let addr_a = spawn_server(move |req| {
        if req.path == "/start" {
            let b = addr_b_for_a
                .lock()
                .unwrap()
                .expect("addr_b set before /start is requested");
            TestResponse::redirect_to(&format!("http://{b}/mid"))
        } else {
            *received_clone.lock().unwrap() = Some(req.headers);
            TestResponse::ok(b"final".to_vec())
        }
    });

    let addr_b = spawn_server(move |_req| TestResponse::redirect_to(&format!("http://{addr_a}/final")));
    *addr_b_holder.lock().unwrap() = Some(addr_b);

    let start_url = format!("http://{addr_a}/start");
    let mut buf = Vec::new();
    let resp = request(
        "GET",
        &start_url,
        &[("Authorization", "Bearer secret-token")],
        1024,
        Sink::Bytes(&mut buf),
    )
    .expect("three-hop redirect chain succeeds");

    assert_eq!(resp.status, 200);
    assert_eq!(buf, b"final");

    let final_headers = received_at_final.lock().unwrap().take().expect("final hop (C) was hit");
    assert!(
        !final_headers.contains_key("authorization"),
        "Authorization must stay stripped at C even though C is back on A's origin, got: {final_headers:?}"
    );
}

// ---------------------------------------------------------------------------
// 9 — request headers are sent
// ---------------------------------------------------------------------------

#[test]
fn request_headers_and_method_are_sent() {
    let received: Arc<Mutex<Option<ReceivedRequest>>> = Arc::new(Mutex::new(None));
    let received_clone = Arc::clone(&received);

    let addr = spawn_server(move |req| {
        *received_clone.lock().unwrap() = Some(req);
        TestResponse::ok(Vec::new())
    });
    let url = format!("http://{addr}/x");

    let mut buf = Vec::new();
    request(
        "GET",
        &url,
        &[("X-Milpa-Test", "present")],
        1024,
        Sink::Bytes(&mut buf),
    )
    .expect("request succeeds");

    let received = received.lock().unwrap().take().unwrap();
    assert_eq!(received.method, "GET");
    assert_eq!(
        received.headers.get("x-milpa-test").map(String::as_str),
        Some("present")
    );
}

// ---------------------------------------------------------------------------
// 10 — proxy-env honored (structural)
// ---------------------------------------------------------------------------

#[test]
fn proxy_env_is_honored_by_ureq() {
    // Structural check (RFC §0.1): `build_agent` relies on `ureq`'s own
    // `Config::default()`, which calls `Proxy::try_from_env()` — verified
    // directly here (no live proxy stub, no `request()` call) rather than by
    // routing traffic through one. Scoped tightly around the env mutation
    // (no I/O between set and restore) to minimize the window where this
    // process-global var could be observed by another concurrently running
    // test in the same binary.
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let previous = std::env::var("HTTPS_PROXY").ok();
    std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:1");
    let proxy = ureq::Proxy::try_from_env();
    match previous {
        Some(v) => std::env::set_var("HTTPS_PROXY", v),
        None => std::env::remove_var("HTTPS_PROXY"),
    }

    assert!(proxy.is_some(), "ureq must pick up HTTPS_PROXY from the environment");
}

// ---------------------------------------------------------------------------
// scheme guard (C1 defense-in-depth) — request() rejects non-http(s)
// ---------------------------------------------------------------------------
//
// Every REAL Rust caller handles `file://` as a direct filesystem read
// BEFORE reaching `bounded_http::request` (dep_decl_store.rs, entry_bundle_
// store.rs, fetchers.rs, milpa-cli/src/main.rs all `strip_prefix("file://")`
// first) — `ureq`'s `Agent` has no `file://` connector at all, so this is
// defense-in-depth, not a functional gap being closed. It exists because
// `oci_client.rs::acquire_token` builds a URL directly from the registry's
// attacker-controlled `WWW-Authenticate` realm (RFC §3.2 step 1); a scheme
// guard here is the second, independent layer behind `oci_client.rs`'s own
// realm-scheme check.

#[test]
fn request_rejects_ftp_scheme() {
    let mut buf = Vec::new();
    let err = request("GET", "ftp://127.0.0.1:1/x", &[], 1024, Sink::Bytes(&mut buf)).unwrap_err();
    assert_eq!(err.code(), "FETCH-DOWNLOAD-FAILED");
}

#[test]
fn request_rejects_file_scheme() {
    let mut buf = Vec::new();
    let err = request("GET", "file:///etc/hostname", &[], 1024, Sink::Bytes(&mut buf)).unwrap_err();
    assert_eq!(err.code(), "FETCH-DOWNLOAD-FAILED");
}

#[test]
fn request_rejects_data_scheme() {
    let mut buf = Vec::new();
    let err = request("GET", "data:text/plain,hello", &[], 1024, Sink::Bytes(&mut buf)).unwrap_err();
    assert_eq!(err.code(), "FETCH-DOWNLOAD-FAILED");
}

// ---------------------------------------------------------------------------
// same_origin — exhaustive pure-function coverage (RFC §3.8)
// ---------------------------------------------------------------------------

#[test]
fn same_origin_identical_url_is_same() {
    assert!(same_origin(
        "https://ghcr.io/v2/foo/manifests/sha256:abc",
        "https://ghcr.io/v2/foo/manifests/sha256:abc"
    ));
}

#[test]
fn same_origin_differs_only_by_path_is_still_same() {
    assert!(same_origin("https://ghcr.io/a", "https://ghcr.io/b/c"));
}

#[test]
fn same_origin_different_host_is_cross_origin() {
    assert!(!same_origin("https://ghcr.io/a", "https://evil.example/a"));
}

#[test]
fn same_origin_scheme_downgrade_same_host_is_cross_origin() {
    // The sharp case (RFC §3.8): identical host, https -> http must NOT be
    // treated as same-origin, or a bearer token leaks in cleartext.
    assert!(!same_origin("https://ghcr.io/a", "http://ghcr.io/a"));
}

#[test]
fn same_origin_different_port_same_host_scheme_is_cross_origin() {
    assert!(!same_origin("https://ghcr.io:443/a", "https://ghcr.io:9443/a"));
}

#[test]
fn same_origin_explicit_default_port_equals_implicit_default_port() {
    assert!(same_origin("https://ghcr.io/a", "https://ghcr.io:443/a"));
    assert!(same_origin("http://example.com/a", "http://example.com:80/a"));
}

#[test]
fn same_origin_host_case_is_insensitive() {
    assert!(same_origin("https://GHCR.io/a", "https://ghcr.io/a"));
}

#[test]
fn same_origin_unparsable_url_is_not_same_origin() {
    assert!(!same_origin("https://ghcr.io/a", "not a url"));
    assert!(!same_origin("not a url", "https://ghcr.io/a"));
}

// ---------------------------------------------------------------------------
// Raw-socket test server — full control over response framing (partial
// bodies, mid-body RST vs. clean FIN) that `spawn_server`'s auto-computed
// `Content-Length: {body.len()}` framing cannot produce. Used by the Bug 1 /
// Bug 2 tests below.
// ---------------------------------------------------------------------------

/// Spawn a listener where `handler` gets the raw accepted `TcpStream` and
/// writes (and closes) the response itself.
fn spawn_raw_server<F>(handler: F) -> SocketAddr
where
    F: Fn(TcpStream) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let handler = Arc::new(handler);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let handler = Arc::clone(&handler);
            thread::spawn(move || handler(stream));
        }
    });
    addr
}

/// Read and discard bytes through the end of the request's header block.
fn drain_request_headers(stream: &mut TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        if line == "\r\n" || line == "\n" {
            return;
        }
    }
}

/// Configure `stream` so closing it sends a TCP RST instead of a clean FIN
/// (`SO_LINGER` with `l_onoff=1, l_linger=0` — the standard abortive-close
/// mechanism). No new crate dependency (`libc`/`socket2`) is pulled in for
/// this one test-only syscall: the minimal FFI is declared directly.
/// `SOL_SOCKET`/`SO_LINGER` are the standard Linux `<sys/socket.h>` values,
/// which is the only platform this suite runs on (podman container, RFC
/// dev-workflow).
fn force_reset_on_close(stream: &TcpStream) {
    use std::os::unix::io::AsRawFd;

    #[repr(C)]
    struct Linger {
        l_onoff: i32,
        l_linger: i32,
    }

    extern "C" {
        fn setsockopt(sockfd: i32, level: i32, optname: i32, optval: *const std::ffi::c_void, optlen: u32) -> i32;
    }

    const SOL_SOCKET: i32 = 1;
    const SO_LINGER: i32 = 13;

    let linger = Linger { l_onoff: 1, l_linger: 0 };
    let rc = unsafe {
        setsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_LINGER,
            &linger as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<Linger>() as u32,
        )
    };
    assert_eq!(rc, 0, "setsockopt(SO_LINGER) failed: {}", std::io::Error::last_os_error());
}

// ---------------------------------------------------------------------------
// Bug 1 (HIGH) — mid-stream transport failure must not escape unwrapped.
// Confirms Rust ALREADY handles this: `stream_capped`'s `reader.read()` call
// already `.map_err`s any mid-stream `io::Error` (including a real TCP RST)
// into `FETCH-DOWNLOAD-FAILED` via `?` — unlike the Python twin, where the
// streaming phase sat outside the transport-failure `except` clause.
// ---------------------------------------------------------------------------

#[test]
fn mid_stream_reset_is_download_failed() {
    let addr = spawn_raw_server(|mut stream: TcpStream| {
        drain_request_headers(&mut stream);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial-body");
        force_reset_on_close(&stream);
    });
    let url = format!("http://{addr}/x");

    let mut buf = Vec::new();
    let err = request("GET", &url, &[], 1024 * 1024, Sink::Bytes(&mut buf)).unwrap_err();

    assert_eq!(err.code(), "FETCH-DOWNLOAD-FAILED");
}

// ---------------------------------------------------------------------------
// Bug 2 (MEDIUM) — Content-Length completeness check
// ---------------------------------------------------------------------------

#[test]
fn truncated_body_with_content_length_is_download_failed() {
    // A peer that closes CLEANLY mid-body (no RST) after declaring a
    // Content-Length it never delivers must NOT report a 200 success with a
    // silently truncated body — that misclassifies a benign transport
    // truncation as tampering downstream (OCI digest mismatch / tarball
    // extract failure) instead of a retryable transport failure.
    let addr = spawn_raw_server(|mut stream: TcpStream| {
        drain_request_headers(&mut stream);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort");
        // Clean close (default linger) — a plain FIN, no RST.
    });
    let url = format!("http://{addr}/x");

    let mut buf = Vec::new();
    let err = request("GET", &url, &[], 1024, Sink::Bytes(&mut buf)).unwrap_err();

    assert_eq!(err.code(), "FETCH-DOWNLOAD-FAILED");
}

#[test]
fn full_length_body_matching_content_length_still_succeeds() {
    let body: &[u8] = b"a complete, correctly-lengthed response body";
    let addr = spawn_raw_server(move |mut stream: TcpStream| {
        drain_request_headers(&mut stream);
        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(body);
    });
    let url = format!("http://{addr}/x");

    let mut buf = Vec::new();
    let resp = request("GET", &url, &[], 1024, Sink::Bytes(&mut buf)).expect("complete body succeeds");

    assert_eq!(resp.status, 200);
    assert_eq!(buf, body);
}

#[test]
fn chunked_response_is_not_length_checked() {
    let addr = spawn_raw_server(|mut stream: TcpStream| {
        drain_request_headers(&mut stream);
        let _ =
            stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
    });
    let url = format!("http://{addr}/x");

    let mut buf = Vec::new();
    let resp = request("GET", &url, &[], 1024, Sink::Bytes(&mut buf)).expect("chunked body succeeds");

    assert_eq!(resp.status, 200);
    assert_eq!(buf, b"hello");
}

// ---------------------------------------------------------------------------
// SecF2 (LOW) — redirect-target scheme guard must be milpa's OWN invariant,
// re-applied to `current_url` on every hop, not incidentally enforced by
// `ureq`'s internal `ensure_valid_url` as a third-party backstop.
// ---------------------------------------------------------------------------

#[test]
fn redirect_to_file_scheme_is_rejected_by_milpas_own_guard() {
    let addr = spawn_server(|_req| TestResponse::redirect_to("file:///etc/passwd"));
    let url = format!("http://{addr}/start");

    let mut buf = Vec::new();
    let err = request("GET", &url, &[], 1024, Sink::Bytes(&mut buf)).unwrap_err();

    assert_eq!(err.code(), "FETCH-DOWNLOAD-FAILED");
    // The outward CODE is the same either way (both milpa's guard and
    // ureq's own internal rejection map to FETCH-DOWNLOAD-FAILED), so the
    // code alone cannot distinguish "milpa's own invariant fired" from
    // "ureq's incidental backstop fired" — assert on the MESSAGE instead,
    // which only milpa's `ensure_http_scheme` produces verbatim.
    assert!(
        err.message().contains("only http/https are permitted"),
        "expected milpa's own scheme guard to reject the redirect target, got: {}",
        err.message()
    );
}

#[test]
fn redirect_to_ftp_scheme_is_rejected_by_milpas_own_guard() {
    let addr = spawn_server(|_req| TestResponse::redirect_to("ftp://127.0.0.1:1/x"));
    let url = format!("http://{addr}/start");

    let mut buf = Vec::new();
    let err = request("GET", &url, &[], 1024, Sink::Bytes(&mut buf)).unwrap_err();

    assert_eq!(err.code(), "FETCH-DOWNLOAD-FAILED");
    assert!(
        err.message().contains("only http/https are permitted"),
        "expected milpa's own scheme guard to reject the redirect target, got: {}",
        err.message()
    );
}
