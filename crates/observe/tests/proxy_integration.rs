//! End-to-end proxy integration + privacy tests.
//!
//! A local rustls "provider" stands in for a real API. A test client goes
//! through the proxy (which the client trusts via the Tethra CA), while the
//! proxy verifies the provider against a test root injected as `upstream_config`
//! (still FULL verification — just a local root). We assert the metadata is
//! captured and sanitized, and that distinctive payload canaries never appear
//! in any recorded metadata.

use api_tracker_core::runtime::model::ObservedRequest;
use api_tracker_observe::ca;
use api_tracker_observe::policy::AllowList;
use api_tracker_observe::proxy::{ObservationSink, ProxyConfig, RunningProxy};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::CertificateDer;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// --- collecting sink -------------------------------------------------------

#[derive(Default)]
struct CollectSink {
    events: Mutex<Vec<ObservedRequest>>,
    compat: Mutex<Vec<(String, String, String)>>,
    partial: AtomicBool,
}

impl ObservationSink for CollectSink {
    fn record(&self, o: ObservedRequest) {
        self.events.lock().unwrap().push(o);
    }
    fn note_compat(&self, c: &str, s: &str, d: &str) {
        self.compat
            .lock()
            .unwrap()
            .push((c.into(), s.into(), d.into()));
    }
    fn mark_partial(&self, _r: &str) {
        self.partial.store(true, Ordering::Relaxed);
    }
}

// --- test provider TLS -----------------------------------------------------

/// A test "provider" TLS config presenting a leaf for `host`, using the proven
/// CA + server-config path. Returns the ServerConfig and the provider CA DER
/// (which the proxy's upstream trust is pointed at).
fn provider_tls(host: &str) -> (Arc<ServerConfig>, Vec<u8>) {
    let g = ca::generate_ca("vault-provider0001").unwrap();
    let authority = ca::CertAuthority::load(
        "vault-provider0001",
        &g.cert_pem,
        &g.key_der,
        &g.fingerprint_sha256,
    )
    .unwrap();
    let ck = authority.certified_key_for(host).unwrap();
    let config = api_tracker_observe::tls::server_config_for(ck);
    (config, g.cert_der)
}

fn client_config_trusting(ca_der: &[u8]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.to_vec())).unwrap();
    let mut cfg =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

// --- test provider server --------------------------------------------------

struct Provider {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<u8>>>,
    stop: Arc<AtomicBool>,
}

fn start_provider(
    server_config: Arc<ServerConfig>,
    status_line: &'static str,
    body: &'static str,
) -> Provider {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let received2 = received.clone();
    let stop2 = stop.clone();
    std::thread::spawn(move || {
        while !stop2.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((tcp, _)) => {
                    tcp.set_nonblocking(false).ok();
                    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    let cfg = server_config.clone();
                    let recv = received2.clone();
                    std::thread::spawn(move || {
                        let conn = rustls::ServerConnection::new(cfg).unwrap();
                        let mut tls = rustls::StreamOwned::new(conn, tcp);
                        // read request head + content-length body
                        let mut buf = Vec::new();
                        let mut tmp = [0u8; 4096];
                        loop {
                            if let Some(pos) = find_double_crlf(&buf) {
                                let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                                let content_len: usize = head
                                    .lines()
                                    .find_map(|l| {
                                        l.to_lowercase()
                                            .strip_prefix("content-length:")
                                            .map(|v| v.trim().parse::<usize>().ok())
                                    })
                                    .flatten()
                                    .unwrap_or(0);
                                if buf.len() - pos >= content_len {
                                    break;
                                }
                            }
                            match tls.read(&mut tmp) {
                                Ok(0) => break,
                                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                Err(_) => break,
                            }
                        }
                        recv.lock().unwrap().extend_from_slice(&buf);
                        let resp = format!(
                            "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = tls.write_all(resp.as_bytes());
                        let _ = tls.flush();
                        tls.conn.send_close_notify();
                        let _ = tls.flush();
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    Provider {
        addr,
        received,
        stop,
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

// --- test client through the proxy -----------------------------------------

/// CONNECT through the proxy, TLS to the (intercepted) host, send `request`,
/// return the full response bytes.
fn through_proxy(
    proxy_addr: SocketAddr,
    token: &str,
    host: &str,
    port: u16,
    tethra_ca_der: &[u8],
    request: &[u8],
) -> Vec<u8> {
    let mut tcp = TcpStream::connect(proxy_addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let auth = RunningProxy::expected_auth(token);
    let connect = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: {auth}\r\n\r\n"
    );
    tcp.write_all(connect.as_bytes()).unwrap();
    // read the 200 Connection Established
    let mut head = Vec::new();
    let mut one = [0u8; 1];
    while find_double_crlf(&head).is_none() {
        let n = tcp.read(&mut one).unwrap();
        if n == 0 {
            break;
        }
        head.push(one[0]);
    }
    let head_str = String::from_utf8_lossy(&head);
    assert!(head_str.contains("200"), "expected tunnel, got: {head_str}");

    let cfg = client_config_trusting(tethra_ca_der);
    let server_name = host.to_string().try_into().unwrap();
    let conn = rustls::ClientConnection::new(cfg, server_name).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    tls.write_all(request).unwrap();
    tls.flush().unwrap();
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp); // provider sends Connection: close
    resp
}

const HOST: &str = "127.0.0.1";

// ---------------------------------------------------------------------------

#[test]
fn provider_tls_is_valid_directly() {
    let (server_config, provider_ca) = provider_tls("127.0.0.1");
    let provider = start_provider(server_config, "HTTP/1.1 200 OK", "{\"ok\":1}");
    let cfg = client_config_trusting(&provider_ca);
    let tcp = TcpStream::connect(provider.addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let sn = "127.0.0.1".try_into().unwrap();
    let conn = rustls::ClientConnection::new(cfg, sn).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    tls.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n")
        .unwrap();
    tls.flush().unwrap();
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp);
    assert!(
        String::from_utf8_lossy(&resp).contains("200"),
        "direct provider resp: {:?}",
        String::from_utf8_lossy(&resp)
    );
    provider.stop.store(true, Ordering::Relaxed);
}

#[test]
fn minted_leaf_completes_a_real_handshake() {
    let tethra = ca::generate_ca("vault-hs00000001").unwrap();
    let authority = ca::CertAuthority::load(
        "vault-hs00000001",
        &tethra.cert_pem,
        &tethra.key_der,
        &tethra.fingerprint_sha256,
    )
    .unwrap();
    let ck = authority.certified_key_for("127.0.0.1").unwrap();
    let server_config = api_tracker_observe::tls::server_config_for(ck);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let sc = server_config.clone();
    let jh = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let conn = rustls::ServerConnection::new(sc).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        let mut buf = [0u8; 64];
        let _ = tls.read(&mut buf);
        let _ = tls.write_all(b"OK");
        let _ = tls.flush();
        tls.conn.send_close_notify();
        let _ = tls.flush();
    });

    let client_cfg = client_config_trusting(&tethra.cert_der);
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let sn = "127.0.0.1".try_into().unwrap();
    let conn = rustls::ClientConnection::new(client_cfg, sn).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    tls.write_all(b"hi").unwrap();
    tls.flush().unwrap();
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp);
    assert_eq!(resp, b"OK", "minted leaf must complete a real handshake");
    let _ = jh.join();
}

#[test]
fn intercept_captures_sanitized_metadata_and_leaks_no_payload() {
    let (server_config, provider_ca) = provider_tls(HOST);
    let provider = start_provider(
        server_config,
        "HTTP/1.1 200 OK",
        "{\"reply\":\"RESPONSECANARY-9z\"}",
    );

    // Build the proxy trusting the provider CA upstream; capture the Tethra CA
    // for the client. We rebuild the tethra CA here to get its DER.
    let tethra = ca::generate_ca("vault-inttest00001").unwrap();
    let authority = Arc::new(
        ca::CertAuthority::load(
            "vault-inttest00001",
            &tethra.cert_pem,
            &tethra.key_der,
            &tethra.fingerprint_sha256,
        )
        .unwrap(),
    );
    let sink = Arc::new(CollectSink::default());
    let mut allow = AllowList::new();
    allow.insert(HOST, provider.addr.port());
    let token = "INTEGRATION-TEST-TOKEN-abc123".to_string();
    let cfg = ProxyConfig {
        mode: api_tracker_core::runtime::model::ObservationMode::Metadata,
        ca: Some(authority),
        token: token.clone(),
        allowlist: allow,
        max_connections: 16,
        sink: sink.clone(),
        upstream_config: Some(client_config_trusting(&provider_ca)),
    };
    let proxy = RunningProxy::start(cfg).unwrap();

    // A request whose path/query/headers/body are stuffed with canaries.
    let body = "{\"prompt\":\"AIPROMPTCANARY-7\",\"email\":\"canary@leak.test\"}";
    let request = format!(
        "GET /v1/users/123456/orders/98765?token=QUERYCANARY&api_key=sk-proj-LEAKCANARY HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         Authorization: Bearer sk-proj-AUTHCANARY-NOT-REAL\r\n\
         Cookie: session=COOKIECANARY-xyz\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let resp = through_proxy(
        proxy.local_addr(),
        &token,
        HOST,
        provider.addr.port(),
        &tethra.cert_der,
        request.as_bytes(),
    );
    let resp_str = String::from_utf8_lossy(&resp);

    // The provider received the body (proving streaming worked end to end)...
    let received = String::from_utf8_lossy(&provider.received.lock().unwrap()).to_string();
    assert!(
        received.contains("AIPROMPTCANARY-7"),
        "provider should have received the streamed body"
    );
    assert!(received.contains("canary@leak.test"));
    // ...and the client got the response body.
    assert!(
        resp_str.contains("RESPONSECANARY-9z"),
        "client should get the response body: {resp_str}"
    );

    proxy.shutdown();
    provider.stop.store(true, Ordering::Relaxed);

    // The event was recorded with SANITIZED metadata.
    let events = sink.events.lock().unwrap();
    assert_eq!(events.len(), 1, "exactly one request recorded");
    let ev = &events[0];
    assert_eq!(ev.host, "127.0.0.1");
    assert_eq!(ev.method, api_tracker_core::runtime::model::HttpMethod::Get);
    assert_eq!(
        ev.path_template, "/v1/users/:id/orders/:id",
        "identifiers templated"
    );
    assert_eq!(ev.status_code, Some(200));
    assert!(
        ev.had_authorization,
        "auth header presence noted (value never read)"
    );
    assert!(ev.latency_ms.is_some());
    assert!(ev.request_bytes.unwrap() > 0);
    assert!(ev.response_bytes.unwrap() > 0);

    // THE PRIVACY PROOF: no canary appears anywhere in the recorded metadata.
    let serialized = serde_metadata(&events);
    for canary in [
        "QUERYCANARY",
        "LEAKCANARY",
        "AUTHCANARY",
        "COOKIECANARY",
        "AIPROMPTCANARY",
        "canary@leak.test",
        "RESPONSECANARY",
        "123456",
        "98765",
        "Bearer",
        "session=",
    ] {
        assert!(
            !serialized.contains(canary),
            "canary '{canary}' LEAKED into recorded metadata: {serialized}"
        );
    }
}

/// Serialize the recorded events plus their Debug form — everything that could
/// carry a leak out of the observe layer.
fn serde_metadata(events: &[ObservedRequest]) -> String {
    let mut out = String::new();
    for e in events {
        out.push_str(&format!("{e:?}"));
        // ObservedRequest is not Serialize (it is an internal type); its DB row
        // form is the RuntimeEventRow, which we build from these fields. The
        // Debug form contains every stored field, so it is the right surface.
    }
    out
}

#[test]
fn ssrf_targets_are_blocked() {
    let sink = Arc::new(CollectSink::default());
    let tethra = ca::generate_ca("vault-ssrf00000001").unwrap();
    let authority = Arc::new(
        ca::CertAuthority::load(
            "vault-ssrf00000001",
            &tethra.cert_pem,
            &tethra.key_der,
            &tethra.fingerprint_sha256,
        )
        .unwrap(),
    );
    let cfg = ProxyConfig {
        mode: api_tracker_core::runtime::model::ObservationMode::Metadata,
        ca: Some(authority),
        token: "T".into(),
        allowlist: AllowList::new(), // nothing allowlisted
        max_connections: 16,
        sink: sink.clone(),
        upstream_config: None,
    };
    let proxy = RunningProxy::start(cfg).unwrap();

    for target in [
        "169.254.169.254:80",
        "127.0.0.1:5432",
        "10.0.0.5:443",
        "metadata.google.internal:80",
    ] {
        let mut tcp = TcpStream::connect(proxy.local_addr()).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let auth = RunningProxy::expected_auth("T");
        let (h, p) = target.rsplit_once(':').unwrap();
        let connect = format!(
            "CONNECT {h}:{p} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {auth}\r\n\r\n"
        );
        tcp.write_all(connect.as_bytes()).unwrap();
        let mut resp = Vec::new();
        let mut tmp = [0u8; 256];
        while let Ok(n) = tcp.read(&mut tmp) {
            if n == 0 {
                break;
            }
            resp.extend_from_slice(&tmp[..n]);
            if find_double_crlf(&resp).is_some() {
                break;
            }
        }
        let s = String::from_utf8_lossy(&resp);
        assert!(
            s.contains("403"),
            "SSRF target {target} must be blocked, got: {s}"
        );
    }
    proxy.shutdown();
    assert!(
        !sink.compat.lock().unwrap().is_empty(),
        "blocks recorded as compat notes"
    );
}

#[test]
fn missing_or_wrong_token_is_rejected_with_407() {
    let sink = Arc::new(CollectSink::default());
    let cfg = ProxyConfig {
        mode: api_tracker_core::runtime::model::ObservationMode::Connection,
        ca: None,
        token: "CORRECT-TOKEN".into(),
        allowlist: AllowList::new(),
        max_connections: 16,
        sink,
        upstream_config: None,
    };
    let proxy = RunningProxy::start(cfg).unwrap();

    // no proxy-authorization
    let mut tcp = TcpStream::connect(proxy.local_addr()).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.write_all(b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n")
        .unwrap();
    let mut resp = Vec::new();
    let mut tmp = [0u8; 256];
    while let Ok(n) = tcp.read(&mut tmp) {
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&tmp[..n]);
        if find_double_crlf(&resp).is_some() {
            break;
        }
    }
    assert!(
        String::from_utf8_lossy(&resp).contains("407"),
        "missing token must 407"
    );

    // wrong token
    let mut tcp = TcpStream::connect(proxy.local_addr()).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let auth = RunningProxy::expected_auth("WRONG-TOKEN");
    tcp.write_all(
        format!(
            "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: x\r\nProxy-Authorization: {auth}\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let mut resp = Vec::new();
    while let Ok(n) = tcp.read(&mut tmp) {
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&tmp[..n]);
        if find_double_crlf(&resp).is_some() {
            break;
        }
    }
    assert!(
        String::from_utf8_lossy(&resp).contains("407"),
        "wrong token must 407"
    );
    proxy.shutdown();
}

// --- Performance benchmark (run with `--ignored`) ---------------------------

/// A direct HTTPS request straight to the provider (baseline, no proxy).
fn direct_request(addr: SocketAddr, provider_ca: &[u8], request: &[u8]) {
    let cfg = client_config_trusting(provider_ca);
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let sn = HOST.to_string().try_into().unwrap();
    let conn = rustls::ClientConnection::new(cfg, sn).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    tls.write_all(request).unwrap();
    tls.flush().unwrap();
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp);
}

fn percentile(mut xs: Vec<u128>, p: f64) -> u128 {
    xs.sort_unstable();
    let idx = ((xs.len() as f64) * p).ceil() as usize;
    xs[idx.saturating_sub(1).min(xs.len() - 1)]
}

#[test]
#[ignore] // performance; run: cargo test -p api-tracker-observe --test proxy_integration -- --ignored --nocapture
fn bench_proxy_overhead() {
    const N: usize = 100;
    let (server_config, provider_ca) = provider_tls(HOST);
    let provider = start_provider(server_config, "HTTP/1.1 200 OK", "{\"ok\":true}");

    let tethra = ca::generate_ca("vault-bench00000001").unwrap();
    let authority = Arc::new(
        ca::CertAuthority::load(
            "vault-bench00000001",
            &tethra.cert_pem,
            &tethra.key_der,
            &tethra.fingerprint_sha256,
        )
        .unwrap(),
    );
    let sink = Arc::new(CollectSink::default());
    let mut allow = AllowList::new();
    allow.insert(HOST, provider.addr.port());
    let token = "BENCH-TOKEN".to_string();
    let proxy = RunningProxy::start(ProxyConfig {
        mode: api_tracker_core::runtime::model::ObservationMode::Metadata,
        ca: Some(authority),
        token: token.clone(),
        allowlist: allow,
        max_connections: 64,
        sink,
        upstream_config: Some(client_config_trusting(&provider_ca)),
    })
    .unwrap();

    let request = format!("GET /v1/models HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 0\r\n\r\n");
    let port = provider.addr.port();

    // Warm up (leaf minting, first handshakes).
    for _ in 0..10 {
        through_proxy(
            proxy.local_addr(),
            &token,
            HOST,
            port,
            &tethra.cert_der,
            request.as_bytes(),
        );
        direct_request(provider.addr, &provider_ca, request.as_bytes());
    }

    let mut proxied = Vec::with_capacity(N);
    for _ in 0..N {
        let t = std::time::Instant::now();
        through_proxy(
            proxy.local_addr(),
            &token,
            HOST,
            port,
            &tethra.cert_der,
            request.as_bytes(),
        );
        proxied.push(t.elapsed().as_micros());
    }
    let mut direct = Vec::with_capacity(N);
    for _ in 0..N {
        let t = std::time::Instant::now();
        direct_request(provider.addr, &provider_ca, request.as_bytes());
        direct.push(t.elapsed().as_micros());
    }

    let d50 = percentile(direct.clone(), 0.50);
    let d95 = percentile(direct.clone(), 0.95);
    let p50 = percentile(proxied.clone(), 0.50);
    let p95 = percentile(proxied.clone(), 0.95);
    eprintln!("BENCH per-request (new connection + handshake each), N={N}, loopback:");
    eprintln!(
        "  direct  p50={:.2}ms p95={:.2}ms",
        d50 as f64 / 1000.0,
        d95 as f64 / 1000.0
    );
    eprintln!(
        "  metadata proxy p50={:.2}ms p95={:.2}ms",
        p50 as f64 / 1000.0,
        p95 as f64 / 1000.0
    );
    eprintln!(
        "  overhead p50=+{:.2}ms p95=+{:.2}ms",
        (p50 - d50) as f64 / 1000.0,
        (p95.saturating_sub(d95)) as f64 / 1000.0
    );

    proxy.shutdown();
    provider.stop.store(true, Ordering::Relaxed);
}
